<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * The W-B unit (rules 16-18; IntentWb::decideIntentWb) against the TS reference decideIntentWB: every case of
 * test-data/k042-wbmisc.json.gz (tools/pca-audit/java-mutate/k042-wbmisc-oracle.mjs) compares the FULL result: outcome, checks
 * in order, exact reason, friction, world / prov / class env members and single_source. The oracle's DENY form clears
 * friction / env / single_source (the Java Result contract; the reference keeps what earlier checks reported and the PHP
 * result does too, pinned in IntentWbKillTest), so the comparison clears them on a deny.
 */
final class WbMiscDifferentialKillTest extends TestCase
{
    /** @return list<Obj> */
    private static function cases(): array
    {
        static $cs = null;
        return $cs ??= OracleData::raw('k042-wbmisc.json.gz')->get('cases');
    }

    /** @return array<string,mixed> the oracle's result form */
    private static function got(array $r): array
    {
        $checks = [];
        foreach ($r['checks'] as $k => $v) {
            $checks[] = [(string) $k, $v];
        }
        $deny = $r['outcome'] === 'deny';
        $env = $deny ? [] : $r['env'];
        return ['outcome' => $r['outcome'], 'checks' => $checks, 'reason' => $r['reason'] ?? null, 'friction' => $deny ? null : ($r['friction'] ?? null),
            'world' => $env['world'] ?? null, 'prov' => $env['prov'] ?? null, 'class' => $env['class'] ?? null,
            'single_source' => $deny ? null : ($r['single_source'] ?? null)];
    }

    public function testEveryCaseAgreesWithTheReference(): void
    {
        $cs = self::cases();
        $this->assertGreaterThan(900, count($cs));
        $bad = [];
        foreach ($cs as $c) {
            $r = IntentWb::decideIntentWb($c->get('input'));
            $e = $c->get('expect');
            if ($e->get('reason') === 'classes: evaluation error (fail closed): canonicalize: nesting too deep') {
                // documented text divergence: the strict canonicalizer's own message has no "canonicalize: " prefix here
                $e->set('reason', 'classes: evaluation error (fail closed): nesting too deep');
            }
            $want = OracleData::ordered($e);
            $have = OracleData::ordered(self::got($r));
            if ($want !== $have) {
                $bad[] = $c->get('name') . "\n   want $want\n   have $have";
            }
        }
        $this->assertSame([], array_slice($bad, 0, 25), count($bad) . ' mismatches');
    }
}
