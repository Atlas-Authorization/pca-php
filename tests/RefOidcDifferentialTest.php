<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Oidc;
use Atlas\Pca\OidcVerificationError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The OIDC bridge against the TS reference: test-data/ref-oidc.json.gz (discovery, ID-token verification across algorithms
 * and key forms, the caching JWKS resolver, the principal mapping). Function-valued options travel as JSON specs: key
 * {jwks: <set>} is a local JWK-Set resolver, key {resolver: {...}} a createOidcJwks, fetch {responses: [...]} a reply
 * sequence (the last repeats); a {"$bytes"} key is an HMAC secret.
 */
final class RefOidcDifferentialTest extends TestCase
{
    private const FILE = 'ref-oidc.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** @param ?list<string> $calls */
    private static function fetch(Obj $spec, ?array &$calls = null): \Closure
    {
        $i = 0;
        $rs = $spec->get('responses');
        return static function (string $url) use (&$i, &$calls, $rs): array {
            if ($calls !== null) {
                $calls[] = $url;
            }
            $r = $rs[min($i, count($rs) - 1)];
            $i++;
            if ($r->get('throws') === true) {
                throw new \RuntimeException('boom');
            }
            $h = [];
            $hs = $r->get('headers');
            foreach ($hs instanceof Obj ? $hs->keys() : [] as $k) {
                $h[strtolower($k)] = $hs->get($k);
            }
            return ['status' => self::jsonStatus($r->get('status')),
                'body' => $r->get('body'), 'headers' => $h];
        };
    }

    /** A JSON status number as the fetch would report it: an integral value is an int, anything else stays as it is. */
    private static function jsonStatus(mixed $st): mixed
    {
        $n = Js::num($st);
        return $n !== null && is_finite($n) && floor($n) === $n ? (int)$n : $st;
    }

    private static function arr(mixed $o): array
    {
        $a = [];
        foreach ($o instanceof Obj ? $o->keys() : [] as $k) {
            $a[$k] = $o->get($k);
        }
        return $a;
    }

    private static function resolver(Obj $spec): \Closure
    {
        $o = self::arr($spec);
        $o['fetch'] = self::fetch($spec->get('fetch'));
        return Oidc::createOidcJwks($o);
    }

    private static function adapt(mixed $opts): mixed
    {
        if (!($opts instanceof Obj)) {
            return $opts;
        }
        $a = self::arr($opts);
        $k = $opts->get('key');
        if ($k instanceof Obj) {
            if ($k->has('jwks')) {
                $a['key'] = Oidc::createLocalJwkSet($k->get('jwks'));
            } elseif ($k->has('resolver')) {
                $a['key'] = self::resolver($k->get('resolver'));
            } else {
                $a['key'] = Base::bytes($k);
            }
        }
        if ($opts->get('fetch') instanceof Obj) {
            $a['fetch'] = self::fetch($opts->get('fetch'));
        }
        return $a === [] ? new Obj() : $a;
    }

    private static function pick(mixed $j): array
    {
        $o = [];
        foreach (['kty', 'crv', 'x', 'y', 'n', 'e'] as $k) {
            if (Js::has($j, $k)) {
                $o[$k] = Js::opt($j, $k);
            }
        }
        return $o;
    }

    private static function errOf(\Throwable $e): string
    {
        return $e instanceof OidcVerificationError && $e->codeName === 'keys' ? 'keys' : 'other';
    }

    private static function seq(Obj $s): array
    {
        $clock = 0;
        $fetches = 0;
        $f = self::fetch($s->get('fetch'));
        $o = array_merge(['jwksUri' => $s->get('jwksUri')], self::arr($s->get('opts')));
        $o['fetch'] = static function (string $u) use (&$fetches, $f): array {
            $fetches++;
            return $f($u);
        };
        $o['now'] = static function () use (&$clock): mixed {
            return $clock;
        };
        $r = Oidc::createOidcJwks($o);
        $steps = [];
        foreach ($s->get('steps') as $st) {
            $clock = $st->get('atMs');
            try {
                $steps[] = ['ok' => self::pick($r($st->get('header')))];
            } catch (\Throwable $e) {
                $steps[] = ['err' => self::errOf($e)];
            }
        }
        return ['steps' => $steps, 'fetches' => $fetches];
    }

    private static function fromIssuer(Obj $s): array
    {
        $urls = [];
        $o = self::arr($s->get('opts'));
        $o['fetch'] = self::fetch($s->get('fetch'), $urls);
        $r = Oidc::createOidcJwksFromIssuer($s->get('issuer'), $o);
        try {
            $out = ['ok' => self::pick($r($s->get('header')))];
        } catch (\Throwable $e) {
            $out = ['err' => self::errOf($e)];
        }
        return ['out' => $out, 'urls' => $urls];
    }

    private static function calls(mixed $issuer, Obj $op): array
    {
        $urls = [];
        $o = self::arr($op);
        $o['fetch'] = self::fetch($op->get('fetch'), $urls);
        $outcome = 'ok';
        try {
            Oidc::discoverOidc($issuer, $o);
        } catch (\Throwable) {
            $outcome = 'error';
        }
        return ['urls' => $urls, 'outcome' => $outcome];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn() => ['DEFAULT_ID_TOKEN_ALGS' => Oidc::DEFAULT_ID_TOKEN_ALGS, 'DEFAULT_MAX_DISCOVERY_BYTES' => Oidc::DEFAULT_MAX_DISCOVERY_BYTES,
                'DEFAULT_JWKS_TIMEOUT_MS' => Oidc::DEFAULT_JWKS_TIMEOUT_MS, 'OIDC_SUBJECT_CAVEAT' => Oidc::OIDC_SUBJECT_CAVEAT],
            'verifyIdToken' => function (array $a, Obj $c) use ($file) {
                $out = $c->get('out');
                if (!\Atlas\Pca\OpensslEd448::available() && str_contains(Base::text($c->get('args')), '"Ed448"') && !($out instanceof Obj && $out->has('$throws'))) {
                    return [Base::SKIP, 'Ed448 is not available (no ext-ffi / OpenSSL libcrypto)'];
                }
                return Oidc::verifyIdToken($a[0] ?? null, self::adapt(Base::withClock($file, $c, $a[1] ?? null, 'now', 1000)));
            },
            'discoveryUrl' => fn(array $a) => Oidc::discoveryUrl($a[0] ?? null),
            'discoverOidc' => fn(array $a) => array_key_exists(1, $a) ? Oidc::discoverOidc($a[0], self::adapt($a[1])) : Oidc::discoverOidc($a[0] ?? null),
            'discoverOidcCalls' => fn(array $a) => self::calls($a[0], $a[1]),
            'createOidcJwks' => fn(array $a) => self::seq($a[0]),
            'createOidcJwksFromIssuer' => fn(array $a) => self::fromIssuer($a[0]),
            'oidcPrincipal' => fn(array $a) => array_key_exists(1, $a) ? Oidc::oidcPrincipal($a[0], self::adapt($a[1])) : Oidc::oidcPrincipal($a[0] ?? null),
            'isOidcSubjectCaveat' => fn(array $a) => Oidc::isOidcSubjectCaveat($a[0] ?? null),
        ]);
    }

    public static function provideDeterministic(): array
    {
        return Base::datasets('ref-oidc-java.json.gz');
    }

    /** JWKS resolver scenarios driven by a clock and a reply queue (one reply per step; absent or "throw": the fetch fails). */
    private static function scenario(mixed $opts, array $steps): array
    {
        $cur = 0;
        $fetches = 0;
        $queue = null;
        $o = array_merge(['jwksUri' => 'https://idp.example.com/jwks'], self::arr($opts));
        $o['fetch'] = static function () use (&$fetches, &$queue): array {
            $fetches++;
            if (!($queue instanceof Obj)) {
                throw new \RuntimeException('net');
            }
            return ['status' => self::jsonStatus($queue->get('status')), 'body' => $queue->get('text'), 'headers' => []];
        };
        $o['now'] = static function () use (&$cur): mixed {
            return $cur;
        };
        $r = Oidc::createOidcJwks($o);
        $out = [];
        foreach ($steps as $s) {
            $cur = $s->get('t');
            $queue = $s->get('resp');
            try {
                $r($s->get('header'));
                $out[] = ['fetches' => $fetches, 'ok' => true];
            } catch (\Throwable $e) {
                $out[] = ['fetches' => $fetches, 'ok' => false, 'code' => $e instanceof OidcVerificationError ? $e->codeName : 'other'];
            }
        }
        return $out;
    }

    #[DataProvider('provideDeterministic')]
    public function testAgreesWithTheDeterministicKeyOracle(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'verifyIdToken' => function (array $a, Obj $c) use ($file) {
                $opts = Base::withClock($file, $c, $a[1] ?? null, 'now', 1000);
                if (!($opts instanceof Obj)) {
                    return Oidc::verifyIdToken($a[0] ?? null, $opts);
                }
                $o = self::arr($opts);
                unset($o['jwks']);
                if ($opts->has('jwks')) {
                    $o['key'] = Oidc::createLocalJwkSet($opts->get('jwks'));
                }
                return Oidc::verifyIdToken($a[0] ?? null, $o === [] ? new Obj() : $o);
            },
            'discoveryUrl' => fn(array $a) => Oidc::discoveryUrl($a[0] ?? null),
            'discoverOidc' => function (array $a) {
                $resp = $a[2];
                $o = self::arr($a[1]);
                $o['fetch'] = static function () use ($resp): array {
                    if ($resp->get('throws') === true) {
                        throw new \RuntimeException('net');
                    }
                    return ['status' => self::jsonStatus($resp->get('status')), 'body' => $resp->get('text'),
                        'headers' => $resp->has('contentLength') ? ['content-length' => $resp->get('contentLength')] : []];
                };
                return Oidc::discoverOidc($a[0], $o === [] ? new Obj() : $o);
            },
            'oidcPrincipal' => fn(array $a) => array_key_exists(1, $a) ? Oidc::oidcPrincipal($a[0], self::adapt($a[1])) : Oidc::oidcPrincipal($a[0] ?? null),
            'isOidcSubjectCaveat' => fn(array $a) => Oidc::isOidcSubjectCaveat($a[0] ?? null),
            'jwksScenario' => fn(array $a) => self::scenario($a[0], $a[1]),
        ]);
    }

    public function testAStaleJwkSetIsNeverServedWhenTheRefetchFails(): void
    {
        $clock = 0;
        $n = 0;
        $r = Oidc::createOidcJwks(['jwksUri' => 'https://idp.example/jwks', 'now' => function () use (&$clock) {
            return $clock;
        }, 'fetch' => function () use (&$n) {
            if ($n++ > 0) {
                throw new \RuntimeException('down');
            }
            return ['status' => 200, 'body' => '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w","kid":"k1"}]}'];
        }]);
        $hdr = Obj::of(['alg' => 'EdDSA', 'kid' => 'k1']);
        self::assertSame('OKP', Js::opt($r($hdr), 'kty'));
        $clock = 600000;
        try {
            $r($hdr);
            self::fail('a stale set was served');
        } catch (OidcVerificationError $e) {
            self::assertSame('keys', $e->codeName);
        }
    }
}
