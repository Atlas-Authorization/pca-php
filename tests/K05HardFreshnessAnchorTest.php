<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** F3 enforce.freshness: the M3 freshness-anchor gate of the core verifier (check `freshness_anchor`). */
final class K05HardFreshnessAnchorTest extends TestCase
{
    private const NOW = 1800000000000;
    private const EPOCH_NOW = 30000000; // 30,000,000 x 60,000 ms == NOW

    /** The valid-in-plan-action vector with its freshness anchor replaced (the signature then fails; only the anchor check is read). */
    private function gate(?array $gate, mixed $anchor): array
    {
        $v = null;
        foreach (Vectors::load('vectors.json')->get('vectors') as $x) {
            if ($x->get('name') === 'valid-in-plan-action') {
                $v = $x;
            }
        }
        $p = \Atlas\Pca\Json::parseLax(\Atlas\Pca\Json::canonicalizeLenient($v->get('pcactn')));
        $p->set('freshness', $anchor);
        return Pca::verifyPcactnCore($p, $v->get('grant'), self::NOW, $v->get('context')->get('aud'), null, null, null, null, null, true, $gate);
    }

    private static function anchor(int $epoch, string $ref = 'b'): Obj
    {
        return Obj::of(['beacon_ref' => $ref, 'epoch' => new Num((string)$epoch), 'accumulator_witness' => '']);
    }

    private function anchorStatus(array $r): string
    {
        return !array_key_exists('freshness_anchor', $r['checks']) ? 'absent' : ($r['checks']['freshness_anchor'] ? 'pass' : 'fail');
    }

    public function testNotReportedWithoutTheGate(): void
    {
        $this->assertSame('absent', $this->anchorStatus($this->gate(null, self::anchor(1))));
    }

    public function testAMissingOrStubAnchorFails(): void
    {
        foreach ([self::anchor(0), self::anchor(-5), self::anchor(self::EPOCH_NOW, '')] as $i => $a) { // the wire form already refuses any other shape
            $r = $this->gate(['maxAgeMs' => 1e12], $a);
            $this->assertSame('fail', $this->anchorStatus($r), "anchor $i");
            $this->assertContains('freshness_anchor: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)', $r['reasons'], "anchor $i");
        }
    }

    public function testTheAgeBoundaries(): void
    {
        $now = self::EPOCH_NOW;
        $this->assertSame('pass', $this->anchorStatus($this->gate(['maxAgeMs' => 0], self::anchor($now))), 'age 0 at maxAge 0');
        $this->assertSame('pass', $this->anchorStatus($this->gate(['maxAgeMs' => 60000], self::anchor($now - 1))), 'age == maxAge');
        $r = $this->gate(['maxAgeMs' => 59999], self::anchor($now - 1));
        $this->assertSame('fail', $this->anchorStatus($r));
        $this->assertContains('freshness_anchor: freshness anchor is stale (older than 59999 ms)', $r['reasons']);
    }

    public function testTheFutureAndTheSkew(): void
    {
        $now = self::EPOCH_NOW;
        $r = $this->gate(['maxAgeMs' => 1e12], self::anchor($now + 1));
        $this->assertSame('fail', $this->anchorStatus($r));
        $this->assertContains('freshness_anchor: freshness anchor is in the future', $r['reasons']);
        $this->assertSame('pass', $this->anchorStatus($this->gate(['maxAgeMs' => 1e12, 'clockSkewMs' => 60000], self::anchor($now + 1))), 'skew == the lead');
        $this->assertSame('fail', $this->anchorStatus($this->gate(['maxAgeMs' => 1e12, 'clockSkewMs' => 59999], self::anchor($now + 1))));
        $this->assertSame('fail', $this->anchorStatus($this->gate(['maxAgeMs' => 1e12, 'clockSkewMs' => -60000], self::anchor($now + 1))), 'a negative skew is zero');
        $this->assertSame('pass', $this->anchorStatus($this->gate(['maxAgeMs' => 1e12, 'now' => self::NOW + 60000], self::anchor($now + 1))), 'the gate clock overrides');
    }

    public function testAMisconfiguredGateFailsClosed(): void
    {
        $why = 'freshness_anchor: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)';
        foreach ([[], ['maxAgeMs' => -1], ['maxAgeMs' => NAN], ['maxAgeMs' => INF], ['maxAgeMs' => '5'], ['maxAgeMs' => 5, 'epochMs' => 0], ['maxAgeMs' => 5, 'epochMs' => -1]] as $i => $g) {
            $r = $this->gate($g, self::anchor(self::EPOCH_NOW));
            $this->assertSame('fail', $this->anchorStatus($r), "gate $i");
            $this->assertContains($why, $r['reasons'], "gate $i");
        }
    }

    public function testEpochMsMapsTheEpochToTime(): void
    {
        // 1,800,000,000 epochs of 1000 ms are NOW
        $this->assertSame('pass', $this->anchorStatus($this->gate(['maxAgeMs' => 0, 'epochMs' => 1000], self::anchor(1800000000))));
        $this->assertSame('fail', $this->anchorStatus($this->gate(['maxAgeMs' => 0, 'epochMs' => 1000], self::anchor(1799999999))));
    }
}
