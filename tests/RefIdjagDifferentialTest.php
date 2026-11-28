<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Idjag;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Oidc;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The ID-JAG bridge against the TS reference: test-data/ref-idjag.json.gz (verification, principal / capability projection,
 * caveat guards and readers, XAA request shapes). consumeJti {mode} is a single-use store that answers fresh / truthy (1) /
 * used / throws; key {jwks} a local JWK-Set resolver; fetch {responses} a reply sequence.
 */
final class RefIdjagDifferentialTest extends TestCase
{
    private const FILE = 'ref-idjag.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function adapt(mixed $opts): mixed
    {
        if (!($opts instanceof Obj)) {
            return $opts;
        }
        $a = [];
        foreach ($opts->keys() as $k) {
            $a[$k] = $opts->get($k);
        }
        $c = $opts->get('consumeJti');
        if ($c instanceof Obj && $c->has('mode')) {
            $mode = $c->get('mode');
            $a['consumeJti'] = static function () use ($mode): mixed {
                if ($mode === 'throw') {
                    throw new \RuntimeException('store down');
                }
                return $mode === 'fresh' ? true : ($mode === 'truthy' ? 1 : false);
            };
        }
        $k = $opts->get('key');
        if ($k instanceof Obj && $k->has('jwks')) {
            $a['key'] = Oidc::createLocalJwkSet($k->get('jwks'));
        } elseif ($k instanceof Obj && $k->keys() === ['$bytes']) {
            $a['key'] = Base::bytes($k);
        }
        $f = $opts->get('fetch');
        if ($f instanceof Obj) {
            $rs = $f->get('responses');
            $i = 0;
            $a['fetch'] = static function () use (&$i, $rs): array {
                $r = $rs[min($i, count($rs) - 1)];
                $i++;
                if ($r->get('throws') === true) {
                    throw new \RuntimeException('boom');
                }
                $h = [];
                $hs = $r->get('headers');
                foreach ($hs instanceof Obj ? $hs->keys() : [] as $hk) {
                    $h[$hk] = $hs->get($hk);
                }
                $st = $r->get('status');
                $n = Js::num($st);
                return ['status' => $n !== null && floor($n) === $n ? (int)$n : $st, 'body' => $r->get('body') ?? '', 'headers' => $h];
            };
        }
        return $a === [] ? new Obj() : $a;
    }

    private static function capOpts(mixed $opts): mixed
    {
        $a = self::adapt($opts);
        if (is_array($a) && array_key_exists('principalSecret', $a)) {
            $s = $a['principalSecret'];
            // a {"$bytes"} secret is key material; any other value (a JS string, a number) is not and must be refused
            $a['principalSecret'] = $s instanceof Obj && $s->keys() === ['$bytes'] ? Base::bytes($s) : ($s === null ? null : new \stdClass());
        }
        return $a;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'verifyIdJag' => fn(array $a, Obj $c) => Idjag::verifyIdJag($a[0] ?? null, self::adapt(Base::withClock(self::FILE, $c, $a[1] ?? null, 'now', 1000))),
            'idJagToPcaPrincipal' => fn(array $a) => Idjag::idJagToPcaPrincipal($a[0] ?? null, array_key_exists(1, $a) ? self::adapt($a[1]) : null),
            'idJagToCapability' => fn(array $a) => Idjag::idJagToCapability($a[0] ?? null, self::capOpts($a[1] ?? null)),
            'isIdJagAuthorityCaveat' => fn(array $a) => Idjag::isIdJagAuthorityCaveat($a[0] ?? null),
            'isIdJagProvenanceCaveat' => fn(array $a) => Idjag::isIdJagProvenanceCaveat($a[0] ?? null),
            'readIdJagAuthority' => fn(array $a) => Idjag::readIdJagAuthority($a[0] ?? null),
            'readIdJagProvenance' => fn(array $a) => Idjag::readIdJagProvenance($a[0] ?? null),
            'tokenExchangeRequest' => fn(array $a) => Idjag::tokenExchangeRequest(self::adapt($a[0] ?? null)),
            'jwtBearerAssertion' => fn(array $a) => Idjag::jwtBearerAssertion(self::adapt($a[0] ?? null)),
            'constants' => fn() => ['MAX_ID_JAG_CHARS' => Idjag::MAX_ID_JAG_CHARS, 'IDJAG_AUTHORITY_CAVEAT' => Idjag::IDJAG_AUTHORITY_CAVEAT,
                'IDJAG_PROVENANCE_CAVEAT' => Idjag::IDJAG_PROVENANCE_CAVEAT, 'GRANT_TYPE_TOKEN_EXCHANGE' => Idjag::GRANT_TYPE_TOKEN_EXCHANGE,
                'GRANT_TYPE_JWT_BEARER' => Idjag::GRANT_TYPE_JWT_BEARER, 'TOKEN_TYPE_ID_JAG' => Idjag::TOKEN_TYPE_ID_JAG,
                'TOKEN_TYPE_ID_TOKEN' => Idjag::TOKEN_TYPE_ID_TOKEN, 'TOKEN_TYPE_ACCESS_TOKEN' => Idjag::TOKEN_TYPE_ACCESS_TOKEN,
                'TOKEN_TYPE_JWT' => Idjag::TOKEN_TYPE_JWT, 'CLIENT_ASSERTION_TYPE_JWT_BEARER' => Idjag::CLIENT_ASSERTION_TYPE_JWT_BEARER],
        ]);
    }
}
