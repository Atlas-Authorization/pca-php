<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The plan-root default-deny of the two public verifiers, and the exact clock-skew rule of the freshness-anchor gate. */
final class PcaVerifyDefaultsKillTest extends TestCase
{
    private const NOW = 1800000000000;

    private static function vector(): Obj
    {
        foreach (Vectors::load('vectors.json')->get('vectors') as $v) {
            if ($v->get('name') === 'valid-in-plan-action') {
                return $v;
            }
        }
        throw new \RuntimeException('no vector valid-in-plan-action');
    }

    public function testTheCoreVerifierDeniesWithoutAPlanRootUnlessTheOptOutIsExplicit(): void
    {
        $v = self::vector();
        $now = $v->get('context')->get('now')->int();
        $aud = $v->get('context')->get('aud');
        $r = Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $now, $aud);
        $this->assertFalse($r['allow']);
        $this->assertSame('plan_root_authorized: no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)', $r['reason']);
        $skip = Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $now, $aud, null, null, null, null, null, true);
        $this->assertTrue($skip['allow'], $skip['reason']);
    }

    public function testTheJsonVerifierDeniesWithoutAPlanRootUnlessTheOptOutIsExplicit(): void
    {
        $v = self::vector();
        $now = $v->get('context')->get('now')->int();
        $aud = $v->get('context')->get('aud');
        $text = Json::canonicalizeStrict($v->get('pcactn'));
        $r = Pca::verifyJson($text, $v->get('grant'), $now, $aud);
        $this->assertFalse($r['allow']);
        $this->assertSame('plan_root_authorized: no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)', $r['reason']);
        $skip = Pca::verifyJson($text, $v->get('grant'), $now, $aud, null, null, null, null, null, true);
        $this->assertTrue($skip['allow'], $skip['reason']);
    }

    /** The vector with its freshness anchor replaced (the signature then fails; only the anchor check is read). */
    private function gate(array $gate, int $anchorEpoch): array
    {
        $v = self::vector();
        $p = Json::parseLax(Json::canonicalizeLenient($v->get('pcactn')));
        $p->set('freshness', Obj::of(['beacon_ref' => 'b', 'epoch' => new Num((string)$anchorEpoch), 'accumulator_witness' => '']));
        return Pca::verifyPcactnCore($p, $v->get('grant'), self::NOW, $v->get('context')->get('aud'), null, null, null, null, null, true,
            $gate + ['maxAgeMs' => 1e12, 'epochMs' => 1]);
    }

    private function statusOf(array $r): string
    {
        return $r['checks']['freshness_anchor'] ? 'pass' : 'fail';
    }

    /** @return array<string, array{0:array<string,mixed>, 1:int, 2:string}> */
    public static function skews(): array
    {
        return [
            'absent, on the clock' => [[], 0, 'pass'],
            'absent, 1 ms ahead' => [[], 1, 'fail'],
            'zero, on the clock' => [['clockSkewMs' => 0], 0, 'pass'],
            'zero, 1 ms ahead' => [['clockSkewMs' => 0], 1, 'fail'],
            'negative one, on the clock' => [['clockSkewMs' => -1], 0, 'pass'],
            'negative one, 1 ms ahead' => [['clockSkewMs' => -1], 1, 'fail'],
            'negative half, on the clock' => [['clockSkewMs' => -0.5], 0, 'pass'],
            'null, on the clock' => [['clockSkewMs' => null], 0, 'pass'],
            'null, 1 ms ahead' => [['clockSkewMs' => null], 1, 'fail'],
            'int 5, 5 ahead' => [['clockSkewMs' => 5], 5, 'pass'],
            'int 5, 6 ahead' => [['clockSkewMs' => 5], 6, 'fail'],
            'float 5.5, 5 ahead' => [['clockSkewMs' => 5.5], 5, 'pass'],
            'float 5.5, 6 ahead' => [['clockSkewMs' => 5.5], 6, 'fail'],
            'numeric string is no skew' => [['clockSkewMs' => '5'], 1, 'fail'],
            'bool is no skew' => [['clockSkewMs' => true], 1, 'fail'],
            'infinite is no skew' => [['clockSkewMs' => INF], 1, 'fail'],
            'nan is no skew' => [['clockSkewMs' => NAN], 1, 'fail'],
        ];
    }

    #[DataProvider('skews')]
    public function testTheClockSkewIsAFiniteNumberFlooredAtZero(array $gate, int $ahead, string $expect): void
    {
        $r = $this->gate($gate, self::NOW + $ahead);
        $this->assertSame($expect, $this->statusOf($r));
        if ($expect === 'fail') {
            $this->assertContains('freshness_anchor: freshness anchor is in the future', $r['reasons']);
        }
    }
}
