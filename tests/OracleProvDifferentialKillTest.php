<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Rule 16 (facts, relational dimensions, offer sets) and rule 17 (provenance, label receipts, flows, read purpose)
 * differential tests against the TS reference (oracle-facts.ts, offer-set.ts, label-receipts.ts, param-provenance.ts):
 * test-data/k042-oracleprov.json.gz is written by tools/pca-audit/java-mutate/k042-oracleprov-oracle.mjs. Every case compares
 * the FULL result: validator reasons, refusal reasons, world / labels / classes / env WITH member order, friction, the
 * read-purpose lists, the activity verdict, ratio_ppm and the flow-rule choice.
 */
final class OracleProvDifferentialKillTest extends TestCase
{
    /** JSON-ish text keeping member ORDER (a reordered world / labels map differs), numbers by value. */
    private static function ser(mixed $v): string
    {
        if ($v === null) {
            return 'null';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (is_string($v)) {
            return json_encode($v, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?: bin2hex($v);
        }
        if ($v instanceof Num || is_int($v) || is_float($v)) {
            $f = $v instanceof Num ? $v->float() : (float) $v;
            return $f == floor($f) && abs($f) < 1e17 ? (string) (int) $f : (string) $f;
        }
        if ($v instanceof Obj) {
            $o = [];
            foreach ($v->keys() as $k) {
                $o[] = self::ser((string) $k) . ':' . self::ser($v->get($k));
            }
            return '{' . implode(',', $o) . '}';
        }
        if (is_array($v)) {
            if (!array_is_list($v)) {
                $o = [];
                foreach ($v as $k => $x) {
                    $o[] = self::ser((string) $k) . ':' . self::ser($x);
                }
                return '{' . implode(',', $o) . '}';
            }
            return '[' . implode(',', array_map(self::ser(...), $v)) . ']';
        }
        return '<' . get_debug_type($v) . '>';
    }

    /** @return list<Obj> */
    private static function cases(): array
    {
        static $cs = null;
        return $cs ??= OracleData::raw('k042-oracleprov.json.gz')->get('cases');
    }

    private const VALIDATORS = [
        'validateFactWire', 'validateWorldPolicy', 'validateOfferPolicy', 'validateOfferSetWire', 'validateLabelsWire',
        'validateFlowRules', 'validateProvenancePolicy', 'validateProvWire',
    ];

    /** @return array{0: string, 1: string} [got, want] */
    private static function one(Obj $c): array
    {
        switch ($c->get('kind')) {
            case 'fn':
                $fn = $c->get('fn');
                self::assertContains($fn, self::VALIDATORS);
                return [self::ser(IntentWb::$fn($c->get('arg'))), self::ser($c->get('want'))];
            case 'ratio':
                return [self::ser(IntentWb::ratioPpm((int) $c->get('a')->lexeme, (int) $c->get('b')->lexeme)), self::ser($c->get('want'))];
            case 'flowRule':
                return [self::ser(IntentWb::flowRuleFor($c->get('rules'), $c->get('cls'))), self::ser($c->get('want'))];
            case 'flowAllowed':
                return [self::ser(IntentWb::flowAllowed($c->get('rules'), $c->get('cls'), $c->get('origin'), $c->get('aud'))), self::ser($c->get('want'))];
            case 'active':
                return [self::ser(IntentWb::intentWorldActive(Obj::of(['committed' => $c->get('committed'), 'policy' => $c->get('policy')]))),
                    self::ser($c->get('expect'))];
            case 'read':
                $r = IntentWb::decideReadPurpose($c->get('input'));
                $e = $c->get('expect');
                return [self::ser(['outcome' => $r['outcome'], 'minimise' => $r['minimise'], 'uncovered' => $r['uncovered']]),
                    self::ser(['outcome' => $e->get('outcome'), 'minimise' => $e->get('minimise'), 'uncovered' => $e->get('uncovered')])];
            case 'world':
                $r = IntentWb::decideIntentWorld($c->get('input'));
                $e = $c->get('expect');
                $got = $r['ok'] ? 'ok ' . self::ser($r['world']) . ' ' . self::ser($r['single_source']) . ' ' . self::ser($r['reason'] ?? null)
                    : 'fail ' . self::ser($r['reason'] ?? null) . ' null null';
                $want = $e->get('ok') === true ? 'ok ' . self::ser($e->get('world')) . ' ' . self::ser($e->get('single_source')) . ' null'
                    : 'fail ' . self::ser($e->get('reason')) . ' null null';
                return [$got, $want];
            case 'prov':
                $r = IntentWb::decideParamProvenance($c->get('input'));
                $e = $c->get('expect');
                return [
                    implode(' | ', [$r['outcome'], self::ser($r['reason'] ?? null), self::ser($r['friction'] ?? null), self::ser($r['labels']), self::ser($r['classes']), self::ser($r['env'])]),
                    implode(' | ', [$e->get('outcome'), self::ser($e->get('reason')), self::ser($e->get('friction')), self::ser($e->get('labels')), self::ser($e->get('classes')), self::ser($e->get('env'))]),
                ];
        }
        self::fail('unknown kind ' . $c->get('kind'));
    }

    public function testOracle(): void
    {
        $cs = self::cases();
        $this->assertGreaterThan(1900, count($cs));
        $errs = [];
        foreach ($cs as $c) {
            try {
                [$got, $want] = self::one($c);
            } catch (\Throwable $t) {
                $errs[] = $c->get('name') . ' threw ' . $t->getMessage();
                continue;
            }
            if ($got !== $want) {
                $errs[] = $c->get('name') . "\n    got  $got\n    want $want";
            }
        }
        $this->assertSame([], array_slice($errs, 0, 40), count($errs) . ' mismatches');
    }
}
