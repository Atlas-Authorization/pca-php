<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\SigstoreBundle;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Offline Sigstore bundle verification against the TS reference: test-data/k05-sigstore.json.gz (k05-oracles/sigstore-oracle.mts):
 * a deterministic synthetic PKI (every check targeted by a re-signed knob), the published vectors, structural and blind DER
 * mutations. Roots: every `parseTrustedRoot/<id>` case is a root; other cases name one as {"$root": id}. A refusal's code and
 * detail are compared exactly, except a "fail closed: <engine error>" detail, whose tail is the engine's own text.
 */
final class K05SigstoreDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-sigstore.json.gz';
    private const FAIL_CLOSED = 'fail closed: ';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    /** @return array the PHP pinned roots of a {$root: id} reference */
    private static function roots(mixed $ref): array
    {
        static $docs = null;
        static $parsed = [];
        if ($docs === null) {
            $docs = [];
            for ($k = 0; ($cs = K05::cases(self::FILE, 'parseTrustedRoot', $k)) !== []; $k++) {
                foreach ($cs as $c) {
                    $docs[substr((string) $c->get('name'), strlen('parseTrustedRoot/'))] = $c->get('args')[0];
                }
            }
        }
        $id = $ref instanceof Obj ? $ref->get('$root') : null;
        if (!is_string($id) || !array_key_exists($id, $docs)) {
            throw new \RuntimeException('bad root ref');
        }
        return $parsed[$id] ??= SigstoreBundle::parseTrustedRoot($docs[$id]);
    }

    /** The oracle's summary of a parsed root. */
    private static function summary(array $r): array
    {
        $end = static fn($e) => is_float($e) && is_infinite($e) ? null : $e;
        $lg = static fn(array $l) => ['keyId' => base64_encode($l['keyId']), 'start' => $l['valid'][0], 'end' => $end($l['valid'][1]), 'v2' => $l['v2']];
        $ca = static fn(array $c) => ['chain' => count($c['chain']), 'start' => $c['valid'][0], 'end' => $end($c['valid'][1])];
        return ['tlogs' => array_map($lg, $r['tlogs']), 'ctlogs' => array_map($lg, $r['ctlogs']), 'cas' => array_map($ca, $r['cas']), 'tsas' => array_map($ca, $r['tsas'])];
    }

    /** A refusal: {ok, code, detail} with an engine-specific "fail closed: ..." detail cut to its prefix on both sides. */
    private static function verdict(array $r, Obj $c, string $okKey): array
    {
        $w = $c->get('out');
        if ($w instanceof Obj && is_string($w->get('detail')) && str_starts_with($w->get('detail'), self::FAIL_CLOSED)) {
            $w->set('detail', self::FAIL_CLOSED);
        }
        if ($r['ok']) {
            return ['ok' => true, $okKey => $r[$okKey]];
        }
        $d = $r['detail'];
        return ['ok' => false, 'code' => $r['code'], 'detail' => is_string($d) && str_starts_with($d, self::FAIL_CLOSED) ? self::FAIL_CLOSED : $d];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'parseTrustedRoot' => fn(array $a) => self::summary(SigstoreBundle::parseTrustedRoot($a[0])),
            'verifySigstoreBundleCore' => fn(array $a, Obj $c) => self::verdict(SigstoreBundle::verifyCore($a[0], self::roots($a[1])), $c, 'core'),
            'verifySigstoreBundle' => fn(array $a, Obj $c) => self::verdict(SigstoreBundle::verify($a[0], self::roots($a[1])), $c, 'facts'),
            'verifyRfc3161' => fn(array $a) => SigstoreBundle::verifyRfc3161((string) base64_decode((string) $a[0]), (string) base64_decode((string) $a[1]),
                self::roots($a[2])['tsas']),
            'dssePae' => fn(array $a) => K05::outBytes(SigstoreBundle::dssePae($a[0], (string) base64_decode($a[1]))),
        ]);
    }
}
