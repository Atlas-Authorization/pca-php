<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Rule 13 (the intent_session wire member, the grant caveat, the signed session root, session revocation) differential
 * tests against the TS reference: test-data/k042-sessrevoc-cases.json is written by
 * tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts. Exact reasons are compared; a reason ending in "(fail closed): " is
 * a thrown-internal-error reason, compared up to that prefix.
 */
final class SessRevocDifferentialKillTest extends TestCase
{
    private const FAIL_CLOSED = '(fail closed): ';

    /** @return list<array<string,mixed>> */
    private static function cases(string $kind): array
    {
        return OracleData::load('k042-sessrevoc-cases.json')[$kind];
    }

    private function same(string $name, mixed $want, ?string $got): void
    {
        if ($got !== null && $got !== $want && OracleData::pqMissing() && str_contains($got, 'unsupported_suite')) {
            return; // the runtime lacks the post-quantum suite this case needs
        }
        if (is_string($want) && str_ends_with($want, self::FAIL_CLOSED)) {
            $this->assertNotNull($got, $name);
            $this->assertStringStartsWith($want, $got, $name);
        } else {
            $this->assertSame($want, $got, $name);
        }
    }

    public function testWire(): void
    {
        $cs = self::cases('wire');
        $this->assertGreaterThanOrEqual(60, count($cs));
        foreach ($cs as $c) {
            $this->same('wire ' . $c['name'], $c['reason'], IntentV2::validateIntentSessionWire(OracleData::j($c['v'])));
        }
    }

    public function testCaveat(): void
    {
        $cs = self::cases('caveat');
        $this->assertGreaterThanOrEqual(17, count($cs));
        foreach ($cs as $c) {
            $this->same('caveat ' . $c['name'], $c['reason'], IntentV2::intentSessionCaveatError(OracleData::j($c['c'])));
        }
    }

    public function testRoot(): void
    {
        $cs = self::cases('root');
        $this->assertGreaterThanOrEqual(150, count($cs));
        foreach ($cs as $c) {
            $s = OracleData::j($c['s']);
            $this->same('shape ' . $c['name'], $c['shape'], IntentV2::sessionRootShapeError($s));
            $pins = array_key_exists('pq_pins', $c) && $c['pq_pins'] !== null ? OracleData::j($c['pq_pins']) : null;
            $r = IntentV2::verifySessionRoot($s, $pins);
            $this->same('verify ' . $c['name'], $c['verify'], $r['ok'] ? null : $r['reason']);
        }
    }

    public function testRevocation(): void
    {
        $cs = self::cases('rev');
        $this->assertGreaterThanOrEqual(100, count($cs));
        foreach ($cs as $c) {
            $ev = $c['ev'] === null ? null : OracleData::j($c['ev']);
            $arg = ['session' => $c['session'], 'authority' => OracleData::j($c['authority']),
                'ids' => $c['ids'] === null ? null : OracleData::j($c['ids']),
                'now' => OracleData::j($c['now']), 'maxAgeMs' => OracleData::j($c['maxAge'])];
            if ($c['scope'] !== null) {
                $arg['scope'] = $c['scope'];
            }
            if ($c['last'] !== null) {
                $arg['last'] = OracleData::j($c['last']);
            }
            $r = IntentV2::checkSessionRevocation($ev, $arg);
            $this->same('rev ' . $c['name'], $c['reason'], $r['ok'] ? null : $r['reason']);
        }
    }

    public function testPrimitive(): void
    {
        $cs = self::cases('prim');
        $this->assertGreaterThanOrEqual(27, count($cs));
        foreach ($cs as $c) {
            $out = IntentV2::primitive('intent_revocation', OracleData::j($c['text']));
            $this->assertNotNull($out, $c['name']);
            $this->same('prim ' . $c['name'], $c['reason'], $out[1]);
            $this->assertSame($c['reason'] === null, $out[0]->get('ok'), 'prim ok ' . $c['name']);
        }
    }
}
