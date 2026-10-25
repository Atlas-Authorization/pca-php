<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Differential tests of IntentV2::decideIntentV2 / intentV2Active against the TS reference decideIntentV2.
 * test-data/k042-intentv2-cases.json.gz is the shared oracle (tools/pca-audit/java-mutate/k042-intentv2-oracle.mts; the Java
 * and Python suites run the same file): every case asserts the EXACT check list (name, ok, reason, in order), the canonical
 * env and `active`. A thrown-internal-error reason is compared up to its prefix "<check> error (fail closed): ".
 */
final class IntentV2DifferentialKillTest extends TestCase
{
    private const FAIL_CLOSED = '(fail closed): ';
    /** @var ?list<array<string,mixed>> */
    private static ?array $cases = null;

    /** @return list<array<string,mixed>> */
    private static function cases(): array
    {
        if (self::$cases === null) {
            $doc = json_decode((string) gzdecode((string) file_get_contents(__DIR__ . '/../test-data/k042-intentv2-cases.json.gz')), true, 512, JSON_THROW_ON_ERROR);
            self::$cases = $doc['cases'];
        }
        return self::$cases;
    }

    /** @return iterable<string, array{array<string,mixed>}> */
    public static function provide(): iterable
    {
        foreach (self::cases() as $c) {
            yield $c['name'] => [$c];
        }
    }

    public function testCorpusIsTheFullOracle(): void
    {
        $this->assertGreaterThan(1000, count(self::cases()));
    }

    /** @param array<string,mixed> $cs */
    #[DataProvider('provide')]
    public function testCaseMatchesTheReference(array $cs): void
    {
        $p = Json::parseLax($cs['p']);
        $grant = Json::parseLax($cs['grant']);
        $ctx = array_key_exists('ctx', $cs) ? Json::parseLax($cs['ctx']) : null;
        if (array_key_exists('ctx', $cs) && $ctx === null) {
            // PHP API: a null context IS the absent one (documented: "null = none"); a JSON-null context (malformed in
            // TS) has no separate spelling here. No conformance vector uses one.
            $this->markTestSkipped('JSON-null v2 context: not expressible in the PHP API (null = none)');
        }
        if (array_key_exists('wp', $cs) && $ctx instanceof Obj) {
            $ctx = clone $ctx;
            $ctx->set('params', Json::parseLax($cs['wp']));
        }
        $out = IntentV2::decideIntentV2($p, $grant, $ctx, (int) $cs['now']);
        $want = $cs['checks'];
        $got = [];
        foreach ($out['checks'] as $i => $c) {
            $r = $c['reason'] ?? null;
            if (str_contains((string) $r, 'unsupported_suite')) {
                $this->markTestSkipped('PQ suite unavailable on this host');
            }
            $w = $want[$i] ?? null;
            if ($r !== null && is_array($w) && ($w['prefix'] ?? false) === true && ($k = strpos($r, self::FAIL_CLOSED)) !== false) {
                $r = substr($r, 0, $k + strlen(self::FAIL_CLOSED));
            }
            $got[] = [$c['name'], $c['ok'], $r];
        }
        $this->assertSame(array_map(fn($w) => [$w['name'], $w['ok'], $w['reason'] ?? null], $want), $got);
        $env = $out['env'] ?? null;
        $this->assertSame($cs['env'] ?? '{}', $env === null ? '{}' : Json::canonicalizeStrict($env));
        $this->assertSame($cs['active'] === true || $cs['active'] === 'true', IntentV2::intentV2Active($p, $ctx));
    }
}
