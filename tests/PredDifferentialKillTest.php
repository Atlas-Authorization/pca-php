<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/**
 * Differential tests of Predicates.php against the TS reference (predicates.ts): path resolution over many contexts, every
 * leaf operator over fields x operands (value and ref forms), `like` globs, `matches`, `member_of` closures (incl. the
 * 10,000-node bound and own `__proto__` members), groupings, predicates and predicate lists. Golden data:
 * test-data/killPred.json.gz (tools/pca-audit/kotlin-mutate/killPred-oracle-gen.mjs). A context that is not an object
 * (null, array, string in the oracle's list) has no PHP spelling: the API types it Obj.
 */
final class PredDifferentialKillTest extends TestCase
{
    private static ?Obj $data = null;

    private static function data(): Obj
    {
        return self::$data ??= OracleData::raw('killPred.json.gz', true);
    }

    /** @return list<array<int,mixed>> */
    private static function sec(string $k): array
    {
        return self::data()->get($k);
    }

    private static function ctx(mixed $i): ?Obj
    {
        $c = self::data()->get('ctxs')[(int) $i->lexeme];
        return $c instanceof Obj ? $c : null;
    }

    private static function tri(string $s): string
    {
        return ['T' => 'true', 'F' => 'false'][$s] ?? 'unknown';
    }

    public function testResolvePathMatchesTheReference(): void
    {
        $bad = [];
        foreach (self::sec('rp') as $e) {
            $ctx = self::ctx($e[1]);
            if ($ctx === null) {
                continue;
            }
            $r = Predicates::resolvePath($ctx, $e[0]);
            if ($r['found'] !== $e[2] || ($e[2] && OracleData::ordered($r['value']) !== OracleData::ordered($e[3]))) {
                $bad[] = OracleData::ordered($e[0]) . ' @ctx' . $e[1]->lexeme;
            }
        }
        $this->assertGreaterThan(1000, count(self::sec('rp')));
        $this->assertSame([], array_slice($bad, 0, 20));
    }

    public function testConditionsMatchTheReference(): void
    {
        $bad = [];
        $n = 0;
        foreach (self::sec('cond') as $e) {
            $ctx = self::ctx($e[1]);
            if ($ctx === null) {
                continue;
            }
            $want = self::tri($e[2]);
            $n++;
            if (Predicates::evaluateConditionTri($e[0], $ctx) !== $want || Predicates::evaluateCondition($e[0], $ctx) !== ($want === 'true')) {
                $bad[] = substr(OracleData::ordered($e[0]), 0, 160) . ' @ctx' . $e[1]->lexeme . ' want ' . $want;
            }
        }
        $this->assertGreaterThan(100000, $n);
        $this->assertSame([], array_slice($bad, 0, 20), count($bad) . ' mismatches');
    }

    public function testPredicatesMatchTheReference(): void
    {
        $bad = [];
        foreach (self::sec('pred') as $e) {
            $ctx = self::ctx($e[1]);
            if ($ctx !== null && Predicates::predicateMatches($e[0], $ctx) !== $e[2]) {
                $bad[] = substr(OracleData::ordered($e[0]), 0, 160) . ' @ctx' . $e[1]->lexeme;
            }
        }
        $this->assertSame([], array_slice($bad, 0, 20));
    }

    public function testPredicateListsMatchTheReference(): void
    {
        $bad = [];
        foreach (self::sec('preds') as $e) {
            $ctx = self::ctx($e[1]);
            if ($ctx !== null && Predicates::evaluatePredicates($e[0], $ctx)['allowed'] !== $e[2]) {
                $bad[] = substr(OracleData::ordered($e[0]), 0, 160) . ' @ctx' . $e[1]->lexeme;
            }
        }
        $this->assertSame([], array_slice($bad, 0, 20));
    }
}
