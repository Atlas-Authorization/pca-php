<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/**
 * Differential tests of Predicates.php against the TS reference (predicates.ts), from the shared oracle
 * test-data/k042-predjs.json (tools/pca-audit/java-mutate/k042-predjs-oracle.mjs). Inputs are JSON text so both sides parse
 * identical lexemes. Not ported: jsonEquals / number spelling / UTF-8 helpers (Java IntentJs helpers with no PHP counterpart).
 */
final class PredJsDifferentialKillTest extends TestCase
{
    /** @return array<string,mixed> */
    private static function g(): array
    {
        return OracleData::load('k042-predjs.json');
    }

    /** The JSON-null context ("nullctx") is not expressible: the PHP API types the context as Obj. */
    private static function ctx(string $name): ?Obj
    {
        $c = Json::parseLax((string) self::g()['ctx'][$name]);
        return $c instanceof Obj ? $c : null;
    }

    public function testConditionsMatchTheReference(): void
    {
        $cases = self::g()['tri'];
        $this->assertGreaterThan(400, count($cases));
        $bad = [];
        foreach ($cases as $c) {
            if (self::ctx($c['ctx']) === null) {
                continue;
            }
            $cond = Json::parseLax($c['cond']);
            $got = Predicates::evaluateConditionTri($cond, self::ctx($c['ctx']));
            $gotB = Predicates::evaluateCondition($cond, self::ctx($c['ctx']));
            if ($got !== $c['tri'] || $gotB !== ($c['tri'] === 'true')) {
                $bad[] = $c['name'] . ': want ' . $c['tri'] . ' got ' . $got . '/' . var_export($gotB, true);
            }
        }
        $this->assertSame([], $bad);
    }

    public function testPredicatesMatchTheReference(): void
    {
        $cases = self::g()['preds'];
        $this->assertGreaterThan(50, count($cases));
        $bad = [];
        foreach ($cases as $c) {
            if (self::ctx($c['ctx']) === null) {
                continue;
            }
            $preds = Json::parseLax($c['preds']);
            $got = Predicates::evaluatePredicates($preds, self::ctx($c['ctx']));
            if ($got['allowed'] !== $c['allowed']) {
                $bad[] = $c['name'] . ': allowed want ' . var_export($c['allowed'], true);
            }
            if (is_array($preds)) {
                $this->assertCount(count($c['each']), $preds, $c['name']);
                foreach ($preds as $i => $p) {
                    if (Predicates::predicateMatches($p, self::ctx($c['ctx'])) !== $c['each'][$i]) {
                        $bad[] = $c['name'] . "[$i]";
                    }
                }
            }
        }
        $this->assertSame([], $bad);
    }

    private static function memberCond(string $v): Obj
    {
        return Json::parseLax(json_encode(['field' => 'subject.id', 'op' => 'member_of', 'collection' => 'subject.g', 'value' => $v]));
    }

    public function testMemberClosureIsCappedLikeTheReference(): void
    {
        $g = [];
        for ($i = 0; $i < 10005; $i++) {
            $g["n$i"] = 'n' . ($i + 1);
        }
        $cx = Json::parseLax(json_encode(['action' => ['verb' => 'v', 'resource' => 'r'], 'subject' => ['id' => 'n0', 'g' => $g]]));
        foreach (self::g()['chain'] as $v => $want) {
            $this->assertSame($want, Predicates::evaluateConditionTri(self::memberCond($v), $cx), $v);
        }
        $fan = [];
        $cs = [];
        for ($j = 0; $j < 100; $j++) {
            $cs[] = "c$j";
        }
        $s = [];
        for ($i = 0; $i < 100; $i++) {
            $s[] = "a$i";
            $fan["a$i"] = $cs;
        }
        $fan['s'] = $s;
        $fan['c0'] = 'e';
        $fan['e'] = 't';
        $fc = Json::parseLax(json_encode(['action' => ['verb' => 'v', 'resource' => 'r'], 'subject' => ['id' => 's', 'g' => $fan]]));
        foreach (self::g()['fan'] as $v => $want) {
            $this->assertSame($want, Predicates::evaluateConditionTri(self::memberCond($v), $fc), $v);
        }
    }
}
