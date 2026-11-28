<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentAttest.php';

use Atlas\Pca\IntentAttest;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The Intent Map attestation and the intent anchor receipt against the TS reference: every case of test-data/ref-intent-attest.json.gz.
 * A secret is sha256("atlas-pca-conformance/" . label); a suite {alg, pqSeed} is ML-DSA-65 from that seed (deterministic signatures,
 * compared byte for byte). The text after "malformed intent map attestation" / "malformed anchor receipt" is engine text and is cut.
 */
final class RefIntentAttestDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-attest.json.gz';
    private const TOTAL = 134;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function raw(mixed $v): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$bytes')->get('$seed'), true);
    }

    /** @return array{0:?string,1:?PqKeyPair} */
    private static function suite(mixed $s): array
    {
        if (!($s instanceof Obj)) {
            return [null, null];
        }
        return [$s->get('alg'), $s->has('pqSeed') ? new PqKeyPair('ML-DSA-65', self::raw($s->get('pqSeed'))) : null];
    }

    private static function un(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::un(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if ($v->keys() === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::un($v->get($k)));
        }
        return $o;
    }

    private static function cut(mixed $verdict): mixed
    {
        if ($verdict instanceof Obj) {
            $r = $verdict->get('reason');
            if (is_string($r)) {
                $verdict->set('reason', preg_replace('/\A(malformed (?:intent map attestation|anchor receipt)): .*\z/s', '$1', $r));
            }
            return $verdict;
        }
        if (is_array($verdict) && isset($verdict['reason'])) {
            $verdict['reason'] = preg_replace('/\A(malformed (?:intent map attestation|anchor receipt)): .*\z/s', '$1', $verdict['reason']);
        }
        return $verdict;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['INTENT_MAP_SIG_DOMAIN' => IntentAttest::INTENT_MAP_SIG_DOMAIN, 'INTENT_ANCHOR_DOMAIN' => IntentAttest::INTENT_ANCHOR_DOMAIN,
                'INTENT_ANCHOR_LOG' => IntentAttest::INTENT_ANCHOR_LOG, 'INTENT_ANCHOR_KINDS' => IntentAttest::INTENT_ANCHOR_KINDS],
            'signIntentMapAttestation' => static fn(array $a) => IntentAttest::signIntentMapAttestation(self::un($a[0]), new KeyPair(self::raw($a[1])), self::un($a[2]), ...self::suite($a[3])),
            'verifyIntentMapAttestation' => static function (array $a, Obj $c) {
                $c->set('out', self::cut($c->get('out')));
                return self::cut(IntentAttest::verifyIntentMapAttestation($a[0], $a[1] === '$absent' ? IntentAttest::NO_MAP : $a[1], $a[2]));
            },
            'intentAnchorCommit' => static fn(array $a) => IntentAttest::intentAnchorCommit($a[0], $a[1]),
            'verifyIntentAnchor' => static fn(array $a) => self::cut(IntentAttest::verifyIntentAnchor($a[0], $a[1], $a[2], $a[3])),
        ]);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
    }
}
