<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Rule 14 (signed action schemas) differential tests against the TS reference: test-data/k042-actionschema.json is written by
 * tools/pca-audit/java-mutate/k042-actionschema-oracle.mts (actionSchemaShapeError / verifyActionSchema / paramValueViolation /
 * conformAction / accumulationParams / canonProjection at the boundary of every rule). Inputs are raw JSON text; reasons are
 * compared exactly.
 */
final class ActionSchemaDifferentialKillTest extends TestCase
{
    /** @return list<array<string,mixed>> */
    private static function cases(string $kind): array
    {
        return OracleData::load('k042-actionschema.json')[$kind];
    }

    /** @param list<string> $bad */
    private function report(array $bad, int $n): void
    {
        $this->assertGreaterThan(0, $n);
        $this->assertSame([], array_slice($bad, 0, 40), count($bad) . "/$n mismatches");
    }

    public function testShape(): void
    {
        $bad = [];
        foreach (self::cases('shape') as $c) {
            $got = IntentV2::actionSchemaShapeError(OracleData::j($c['doc']));
            if ($got !== $c['expect'] && !(OracleData::pqMissing() && str_contains((string) $got, 'unsupported_suite'))) {
                $bad[] = $c['name'] . ': want <' . var_export($c['expect'], true) . '> got <' . var_export($got, true) . '>';
            }
        }
        $this->report($bad, count(self::cases('shape')));
    }

    public function testParamValueViolation(): void
    {
        $bad = [];
        foreach (self::cases('pvv') as $c) {
            $got = IntentV2::paramValueViolation(OracleData::j($c['d']), OracleData::j($c['x']));
            if ($got !== $c['expect']) {
                $bad[] = $c['name'] . ': want ' . json_encode($c['expect']) . ' got ' . json_encode($got);
            }
        }
        $this->report($bad, count(self::cases('pvv')));
    }

    public function testConform(): void
    {
        $bad = [];
        foreach (self::cases('conform') as $c) {
            $r = IntentV2::conformAction(OracleData::j($c['doc']), $c['verb'], OracleData::j($c['params']));
            unset($r['verb']);
            if (!$r['ok']) {
                $r['path'] ??= null; // the reference spells an absent path as null
            }
            ksort($r);
            $w = $c['expect'];
            ksort($w);
            if ($r !== $w) {
                $bad[] = $c['name'] . ': want ' . json_encode($c['expect']) . ' got ' . json_encode($r);
            }
        }
        $this->report($bad, count(self::cases('conform')));
    }

    public function testVerify(): void
    {
        $bad = [];
        foreach (self::cases('verify') as $c) {
            $r = IntentV2::verifyActionSchema(OracleData::j($c['doc']), OracleData::j($c['keys']));
            $got = $r['ok'] ? null : $r['reason'];
            if ($got !== $c['expect'] && !(OracleData::pqMissing() && OracleData::mentionsPq($c['keys'] . $c['doc']))) {
                $bad[] = $c['name'] . ': want <' . var_export($c['expect'], true) . '> got <' . var_export($got, true) . '>';
            }
        }
        $this->report($bad, count(self::cases('verify')));
    }

    public function testAccumulationParams(): void
    {
        $bad = [];
        foreach (self::cases('acc') as $c) {
            $got = IntentV2::accumulationParams(OracleData::j($c['v']), $c['unit']);
            if ($got !== $c['expect']) {
                $bad[] = $c['name'] . ': want ' . json_encode($c['expect']) . ' got ' . json_encode($got);
            }
        }
        $this->report($bad, count(self::cases('acc')));
    }

    public function testCanonProjection(): void
    {
        $bad = [];
        foreach (self::cases('canon') as $c) {
            $want = $c['expect']['ok'] ? $c['expect']['out'] : 'threw';
            try {
                $got = OracleData::plain(IntentV2::canonProjection(OracleData::j($c['doc']), $c['verb'], OracleData::j($c['params'])));
            } catch (\Throwable) {
                $got = 'threw';
            }
            if ($got !== $want) {
                $bad[] = $c['name'] . ': want ' . json_encode($want) . ' got ' . json_encode($got);
            }
        }
        $this->report($bad, count(self::cases('canon')));
    }

    public function testUnknownVerbProjectsToAFreshEmptyObject(): void
    {
        $doc = OracleData::j('{"verbs":[{"verb":"v","kind":"read","params":{}}]}');
        foreach (['v', 'nope'] as $verb) {
            $out = IntentV2::canonProjection($doc, $verb, new Obj());
            $this->assertSame([], $out->keys());
            $out->set('x', 'y');
            $this->assertSame('y', $out->get('x'));
        }
    }
}
