<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Dataflow.php';

use Atlas\Pca\Dataflow;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** detectorPolicyError / detectorSignal (detector-receipt.ts): the tighten-only fold of signed detector receipts. */
final class DetectorSignalTest extends TestCase
{
    private KeyPair $gw;
    private string $digest;

    protected function setUp(): void
    {
        $this->gw = new KeyPair(str_repeat("\4", 32));
        $this->digest = Dataflow::detectorInputDigest('hello');
    }

    private function policy(array $over = []): Obj
    {
        $d = Obj::of($over + ['id' => 'lakera', 'keys' => [Obj::of(['pk' => $this->gw->public])], 'on_suspicious' => 'deny', 'max_age_ms' => new Num('60000')]);
        return Obj::of(['detectors' => [$d]]);
    }

    private function receipt(string $verdict, array $cats = ['injection'], int $iat = 1000, ?KeyPair $key = null, ?string $digest = null): Obj
    {
        $b = Obj::of(['v' => new Num('1'), 'kind' => 'pca-detector-receipt', 'detector' => 'lakera', 'version' => '1', 'input_digest' => $digest ?? $this->digest,
            'verdict' => $verdict, 'categories' => $verdict === 'suspicious' ? $cats : [], 'iat' => new Num((string)$iat)]);
        return Dataflow::signDetectorReceipt($b, $key ?? $this->gw);
    }

    private function fold(array $receipts, ?Obj $policy = null, int $now = 2000): array
    {
        return Dataflow::detectorSignal(['receipts' => $receipts, 'policy' => $policy ?? $this->policy(), 'input_digests' => [$this->digest], 'now' => $now]);
    }

    public function testPolicyShape(): void
    {
        self::assertNull(Dataflow::detectorPolicyError($this->policy()));
        self::assertSame('policy must be {detectors}', Dataflow::detectorPolicyError(Obj::of([])));
        self::assertSame('detector ids must be distinct ids other than "invalid"', Dataflow::detectorPolicyError($this->policy(['id' => 'invalid'])));
        self::assertSame("detector 'lakera': on_suspicious must be escalate or deny", Dataflow::detectorPolicyError($this->policy(['on_suspicious' => 'allow'])));
        self::assertSame("detector 'lakera': keys must hold 1..8 pins", Dataflow::detectorPolicyError($this->policy(['keys' => []])));
        self::assertSame("detector 'lakera': max_age_ms must be 1..86400000", Dataflow::detectorPolicyError($this->policy(['max_age_ms' => new Num('0')])));
        self::assertSame("detector 'lakera': categories must be 1+ ids", Dataflow::detectorPolicyError($this->policy(['categories' => []])));
        self::assertSame(32, Dataflow::MAX_DETECTOR_RECEIPTS);
    }

    public function testNoReceiptAndNoFindingAreEquivalent(): void
    {
        $none = $this->fold([]);
        $clean = $this->fold([$this->receipt('no_finding')]);
        self::assertSame('ok', $none['signal']);
        self::assertSame('ok', $clean['signal']);
        self::assertSame([], $clean['flagged']);
        self::assertFalse($clean['env']->get('detect')->get('lakera'));
    }

    public function testSuspiciousLowersAndInvalidEscalates(): void
    {
        $r = $this->fold([$this->receipt('suspicious')]);
        self::assertSame('deny', $r['signal']);
        self::assertSame(['lakera'], $r['flagged']);
        self::assertTrue($r['env']->get('detect')->get('lakera'));
        $other = $this->fold([$this->receipt('no_finding', [], 1000, new KeyPair(str_repeat("\5", 32)))]);
        self::assertSame('escalate', $other['signal']);
        self::assertStringContainsString('no pinned key', $other['rejected'][0]['reason']);
        self::assertSame('escalate', $this->fold([$this->receipt('no_finding', [], 1000, null, Dataflow::detectorInputDigest('other'))])['signal']);
        self::assertSame('escalate', $this->fold([$this->receipt('no_finding', [], 5000)])['signal'], 'from the future');
        self::assertSame('escalate', $this->fold([$this->receipt('no_finding', [], 1000)], null, 1000 + 60001)['signal'], 'stale');
        self::assertSame('escalate', $this->fold(['junk'])['signal']);
        self::assertSame('escalate', $this->fold([], null, 0 + 1)['signal'] === 'ok' ? 'escalate' : 'x');
    }

    public function testCategoryFilterMalformedPolicyAndBadClock(): void
    {
        $p = $this->policy(['categories' => ['pii']]);
        self::assertSame('ok', $this->fold([$this->receipt('suspicious', ['injection'])], $p)['signal']);
        self::assertSame('deny', $this->fold([$this->receipt('suspicious', ['pii'])], $p)['signal']);
        self::assertSame('deny', Dataflow::detectorSignal(['receipts' => [], 'policy' => Obj::of([]), 'input_digests' => [], 'now' => 1])['signal']);
        self::assertSame('escalate', Dataflow::detectorSignal(['receipts' => [], 'policy' => $this->policy(), 'input_digests' => [], 'now' => 'x'])['signal']);
        $many = array_fill(0, 33, $this->receipt('no_finding'));
        self::assertSame('escalate', $this->fold($many)['signal']);
    }
}
