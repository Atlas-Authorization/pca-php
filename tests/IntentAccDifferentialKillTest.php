<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Rule 15 (accumulators, monitors, pre-states, reservation receipts, sequencer key sets, receipt-vs-holder verification)
 * differential tests against the TS reference intent-acc.ts: test-data/k042-intentacc.json is written by
 * tools/pca-audit/java-mutate/k042-intentacc-oracle.mjs. Every case asserts the EXACT reason / verdict / value (compared as
 * strict canonical JSON).
 */
final class IntentAccDifferentialKillTest extends TestCase
{
    /** @var ?list<Obj> */
    private static ?array $cases = null;

    /** @return list<Obj> */
    private static function cases(): array
    {
        return self::$cases ??= OracleData::raw('k042-intentacc.json');
    }

    /** The oracle passes the aggregate name where the PHP API takes the accumulator declaration. */
    private static function agg(mixed $agg): Obj
    {
        return Obj::of(['agg' => $agg]);
    }

    private static function int(mixed $n): int
    {
        return $n instanceof Num ? $n->int() : (int) $n;
    }

    /** @param callable(list<mixed>): mixed $f */
    private function check(string $fn, callable $f): void
    {
        $bad = [];
        $n = 0;
        foreach (self::cases() as $c) {
            if ($c->get('fn') !== $fn) {
                continue;
            }
            $n++;
            try {
                $got = $f($c->get('args'));
            } catch (\Throwable $e) {
                $got = 'THREW ' . $e::class . ': ' . $e->getMessage();
            }
            $want = Json::canonicalizeStrict($c->get('out'));
            $g = Json::canonicalizeStrict(OracleData::asJson($got));
            if ($want !== $g && !(OracleData::pqMissing() && OracleData::mentionsPq(json_encode(OracleData::plain($c->get('args'))) ?: ''))) {
                $bad[] = $c->get('name') . "\n    want $want\n    got  $g";
            }
        }
        $this->assertGreaterThan(0, $n, "no cases for $fn");
        $this->assertSame([], array_slice($bad, 0, 30), count($bad) . "/$n $fn cases differ from the TS reference");
    }

    public function testCorpusIsTheFullOracle(): void
    {
        $this->assertGreaterThan(1500, count(self::cases()));
    }

    public function testAccumulatorDeclError(): void
    {
        $this->check('accumulatorDeclError', fn($a) => IntentV2::accumulatorDeclError($a[0]));
    }

    public function testMonitorDeclError(): void
    {
        $this->check('monitorDeclError', fn($a) => IntentV2::monitorDeclError($a[0]));
    }

    public function testMonitorStates(): void
    {
        $this->check('monitorStates', fn($a) => IntentV2::monitorStates($a[0]));
    }

    public function testTrackedKeySetError(): void
    {
        $this->check('trackedKeySetError', fn($a) => IntentV2::trackedKeySetError($a[0]));
    }

    public function testPreState(): void
    {
        $this->check('preStateError', fn($a) => IntentV2::preStateError(self::agg($a[0]), $a[1]));
        $this->check('preValue', fn($a) => IntentV2::preValue(self::agg($a[0]), $a[1]));
        $this->check('combineAcc', fn($a) => IntentV2::combineAcc(self::agg($a[0]), $a[1], ['val' => self::int($a[2]->get('val')), 'key' => $a[2]->get('key')]));
    }

    public function testSelectionAndValues(): void
    {
        $this->check('accSelects', fn($a) => IntentV2::accSelects($a[0], $a[1], $a[2]));
        $this->check('accValueOf', function ($a) {
            $r = IntentV2::accValueOf($a[0], $a[1], $a[2], $a[3]);
            if ($r['ok']) {
                $r['key'] ??= null; // the reference spells an absent key as null
            }
            return $r;
        });
    }

    public function testReceiptArithmeticOk(): void
    {
        $this->check('receiptArithmeticOk', fn($a) => IntentV2::receiptArithmeticOk(self::agg($a[0]), $a[1], self::int($a[2])));
    }

    public function testReservationDigest(): void
    {
        $this->check('pcactnReservationDigest', fn($a) => IntentV2::pcactnReservationDigest($a[0]));
    }

    public function testReceiptShapeError(): void
    {
        $this->check('receiptShapeError', fn($a) => IntentV2::accReceiptShapeError($a[0]));
    }

    public function testKeySetShapeError(): void
    {
        $this->check('keySetShapeError', fn($a) => IntentV2::sequencerKeySetShapeError($a[0]));
    }

    public function testVerifyKeySet(): void
    {
        $this->check('verifyKeySet', fn($a) => IntentV2::verifySequencerKeySet($a[0], $a[1], $a[3] === true ? $a[2] : null));
    }

    public function testVerifyReceiptSignature(): void
    {
        $this->check('verifyReceiptSignature', function ($a) {
            $pinKey = null;
            $pinPq = null;
            $pins = $a[2]; // the oracle's pqPins map {signer: pq_pk}
            foreach ($pins instanceof Obj ? $pins->keys() : [] as $k) {
                $pinKey = $k;
                $pinPq = $pins->get($k);
            }
            return $a[0] instanceof Obj ? IntentV2::verifyAccReceiptSignature($a[0], $a[1], $pinKey, $pinPq) : false;
        });
    }

    public function testVerifyReceiptAgainstHolder(): void
    {
        $this->check('verifyReceiptAgainstHolder', fn($a) => IntentV2::verifyReceiptAgainstHolder(
            $a[0], $a[1], $a[2], $a[3], $a[4], $a[5], null, $a[6]) === 'valid');
    }
}
