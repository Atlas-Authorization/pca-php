<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\JoseError;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\OidcCodedError;
use Atlas\Pca\Oidc;
use Atlas\Pca\Pca;
use Atlas\Pca\Spiffe;
use Atlas\Pca\SpiffeError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * SPIFFE against the TS reference, two corpora: test-data/ref-spiffe-svid.json.gz (per-function cases plus trust-bundle and
 * revocation cache scenarios) and test-data/ref-spiffe.json.gz (DER facts over fixtures, truncations and byte flips; chain, JWT,
 * holder, cache and admission sessions, where a non-SPIFFE refusal is reported as code `jose`). Revocation callbacks are the
 * generators' scripted modes and record the subjects they are asked about.
 */
final class RefSpiffeDifferentialTest extends TestCase
{
    private const SUB = 'spiffe://example.org/workload/db';
    private const JAVA_NOW_MS = 1_800_000_060_000;

    public static function provideSvid(): array
    {
        return Base::datasets('ref-spiffe-svid.json.gz');
    }

    public static function provideSessions(): array
    {
        return Base::datasets('ref-spiffe.json.gz');
    }

    private static function rev(mixed $v): mixed
    {
        return $v instanceof Obj && $v->keys() === ['$bytes'] ? new Bytes((string)Pca::unb64u($v->get('$bytes'))) : $v;
    }

    private static function revAll(mixed $v): mixed
    {
        return is_array($v) ? array_map(self::rev(...), $v) : self::rev($v);
    }

    private static function arr(mixed $o): array
    {
        return $o instanceof Obj ? array_combine($o->keys(), array_map($o->get(...), $o->keys())) ?: [] : (is_array($o) ? $o : []);
    }

    private static function idOut(Obj $i): array
    {
        return ['id' => $i->get('id'), 'trustDomain' => $i->get('trustDomain'), 'path' => $i->get('path')];
    }

    private static function code(\Throwable $e): ?string
    {
        if ($e instanceof SpiffeError || $e instanceof OidcCodedError) {
            return $e->codeName;
        }
        return $e instanceof JoseError ? Spiffe::joseCode($e) : null;
    }

    // ---- ref-spiffe-svid --------------------------------------------------------------------------------------------------

    /** The svid generator's scripted revocation check. */
    private static function mkRev(mixed $mode, array &$calls): ?\Closure
    {
        if ($mode === null) {
            return null;
        }
        $at = is_string($mode) && str_starts_with($mode, 'at:') ? (int)substr($mode, 3) : -1;
        return function (Obj $s) use ($mode, $at, &$calls): mixed {
            $calls[] = Js::parse(Js::stringify($s));
            return match (true) {
                $mode === 'throw' => throw new \RuntimeException('backend down'),
                $mode === 'nonbool' => 'no',
                $mode === 'true' => true,
                $at >= 0 => $s->get('position') === $at,
                default => false,
            };
        };
    }

    private static function xo(Obj $v, array &$calls): array
    {
        $r = ['trustDomain' => $v->get('trustDomain'), 'roots' => array_map(self::rev(...), $v->get('roots') ?? [])];
        foreach (['nowMs', 'maxChainLength'] as $k) {
            if ($v->has($k)) {
                $r[$k] = $v->get($k);
            }
        }
        if ($v->has('revocation')) {
            $r['revocation'] = self::mkRev($v->get('revocation'), $calls);
        }
        return $r;
    }

    private static function jo(Obj $v, array &$calls): array
    {
        $r = ['audience' => $v->get('audience'), 'trustDomain' => $v->get('trustDomain')];
        $key = $v->get('key');
        if (Js::opt($key, 'jwk') !== null) {
            $r['key'] = Js::opt($key, 'jwk');
        } elseif (Js::opt($key, 'jwks') !== null) {
            $r['key'] = Oidc::createLocalJwkSet(Js::opt($key, 'jwks'));
        }
        if ($v->has('currentSec')) {
            $r['nowMs'] = Js::num($v->get('currentSec')) * 1000;
        }
        foreach (['algorithms', 'clockTolerance'] as $k) {
            if ($v->has($k)) {
                $r[$k] = $v->get($k);
            }
        }
        if ($v->has('revocation')) {
            $r['revocation'] = self::mkRev($v->get('revocation'), $calls);
        }
        return $r;
    }

    private static function verifyX509(mixed $chain, Obj $vo): array
    {
        $calls = [];
        $s = Spiffe::verifyX509Svid(self::revAll($chain), self::xo($vo, $calls));
        return self::idOut($s->spiffeId) + ['publicKeyDer' => $s->publicKeyDer, 'calls' => $calls];
    }

    private static function verifyJwt(mixed $token, Obj $vo): array
    {
        $calls = [];
        $s = Spiffe::verifyJwtSvid($token, self::jo($vo, $calls));
        return ['spiffeId' => self::idOut($s->spiffeId), 'claims' => $s->claims, 'audience' => $s->audience, 'expiresAt' => $s->expiresAt, 'calls' => $calls];
    }

    private static function x509Verified(mixed $chain, Obj $vo): object
    {
        $calls = [];
        return Spiffe::verifyX509Svid(self::revAll($chain), self::xo($vo, $calls));
    }

    private static function jwtVerified(mixed $token, Obj $vo): object
    {
        $calls = [];
        return Spiffe::verifyJwtSvid($token, self::jo($vo, $calls));
    }

    private static function unverified(string $kind, mixed $c): Obj
    {
        $v = match ($kind) {
            'string' => self::SUB,
            'object' => Obj::of(['spiffeId' => Spiffe::parseSpiffeId(self::SUB), 'certificate' => new Obj(), 'publicKeyDer' => 'x']),
            'null' => null,
            'number' => 5,
            'parsed jwt-like' => Obj::of(['spiffeId' => Spiffe::parseSpiffeId(self::SUB), 'claims' => new Obj(), 'audience' => [], 'expiresAt' => 1]),
            default => Spiffe::parseX509Svid($c),
        };
        return Spiffe::svidToHolder($v, str_repeat('A', 43), []);
    }

    private static function admission(Obj $e, mixed $key): Obj
    {
        $calls = [];
        $ee = $e->get('kind') === 'x509'
            ? ['kind' => 'x509', 'chain' => self::revAll($e->get('chain')), 'verify' => self::xo($e->get('verify'), $calls)]
            : ['kind' => 'jwt', 'token' => $e->get('token'), 'verify' => self::jo($e->get('verify'), $calls)];
        if ($e->has('bind')) {
            $ee['bind'] = $e->get('bind');
        }
        return Spiffe::spiffeAdmissionEvidence($ee, $key);
    }

    /** A scripted fetch: {$throw} throws, {$spiffe} throws that SPIFFE code, anything else is returned. */
    private static function scriptedFetch(mixed &$cur, int &$fetches): \Closure
    {
        return function () use (&$cur, &$fetches): mixed {
            $fetches++;
            if (Js::truthy(Js::opt($cur, '$throw'))) {
                throw new \RuntimeException((string)Js::opt($cur, '$throw'));
            }
            if (Js::truthy(Js::opt($cur, '$spiffe'))) {
                throw new SpiffeError((string)Js::opt($cur, '$spiffe'), 'x');
            }
            return $cur;
        };
    }

    private static function tbScenario(Obj $opts, array $steps): array
    {
        $t = 0;
        $cur = null;
        $fetches = 0;
        try {
            $src = Spiffe::createTrustBundleSource(['fetch' => self::scriptedFetch($cur, $fetches)] + self::arr($opts) + ['now' => function () use (&$t) {
                return $t;
            }]);
        } catch (\Throwable $e) {
            return ['ctor' => self::code($e)];
        }
        $out = [];
        foreach ($steps as $s) {
            $t = Js::num($s->get('at'));
            $cur = $s->get('fetch');
            $fetches = 0;
            try {
                if ($s->get('op') === 'x509Roots') {
                    $out[] = ['ok' => $src->x509Roots(), 'fetches' => $fetches];
                } else {
                    ($src->jwtKey)($s->get('header') ?? Obj::of(['alg' => 'ES256']));
                    $out[] = ['ok' => 'key', 'fetches' => $fetches];
                }
            } catch (\Throwable $e) {
                $out[] = ['code' => self::code($e), 'fetches' => $fetches];
            }
        }
        return ['steps' => $out];
    }

    private static function rvScenario(Obj $opts, array $steps): array
    {
        $t = 0;
        $cur = null;
        $fetches = 0;
        try {
            $src = Spiffe::createRevocationSource(['fetch' => self::scriptedFetch($cur, $fetches)] + self::arr($opts) + ['now' => function () use (&$t) {
                return $t;
            }]);
        } catch (\Throwable $e) {
            return ['ctor' => self::code($e)];
        }
        $out = [];
        foreach ($steps as $s) {
            $t = Js::num($s->get('at'));
            $cur = $s->get('fetch');
            $fetches = 0;
            try {
                $v = null;
                match ($s->get('op')) {
                    'ensureFresh' => $src->ensureFresh(),
                    'refresh' => $src->refresh(),
                    'x509' => $v = $src->x509($s->get('subject')),
                    default => $v = $src->jwt($s->get('subject')),
                };
                $out[] = ['ok' => $v, 'fetches' => $fetches];
            } catch (\Throwable $e) {
                $out[] = ['code' => self::code($e), 'fetches' => $fetches];
            }
        }
        return ['steps' => $out];
    }

    #[DataProvider('provideSvid')]
    public function testSvidAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'parseSpiffeId' => fn(array $a) => self::idOut(Spiffe::parseSpiffeId($a[0])),
            'parseX509Svid' => function (array $a) {
                $s = Spiffe::parseX509Svid(self::rev($a[0]));
                return ['spiffeId' => self::idOut($s->spiffeId), 'publicKeyDer' => $s->publicKeyDer];
            },
            'verifyX509Svid' => fn(array $a) => self::verifyX509($a[0], $a[1]),
            'verifyJwtSvid' => fn(array $a) => self::verifyJwt($a[0], $a[1]),
            'svidToHolderX509' => fn(array $a) => Spiffe::svidToHolder(self::x509Verified($a[0], $a[1]), self::rev($a[2]), $a[3] ?? []),
            'svidToHolderJwt' => fn(array $a) => Spiffe::svidToHolder(self::jwtVerified($a[0], $a[1]), self::rev($a[2]), $a[3] ?? []),
            'svidToHolderUnverified' => fn(array $a) => self::unverified($a[0], $a[1]),
            'spiffeIdForHolder' => fn(array $a) => Spiffe::spiffeIdForHolder(self::x509Verified($a[0], $a[1]), $a[2], $a[3] ?? []),
            'workloadDischargePin' => fn(array $a) => Spiffe::workloadDischargePin($a[0], self::x509Verified($a[1], $a[2])),
            'holderToSpiffeId' => fn(array $a) => Spiffe::holderToSpiffeId($a[0]),
            'holderBindingMessage' => fn(array $a) => Base::outBytes(Spiffe::holderBindingMessage($a[0], $a[1])),
            'spiffeAdmissionEvidence' => fn(array $a) => self::admission($a[0], $a[1]),
            'trustBundleScenario' => fn(array $a) => self::tbScenario($a[0], $a[1]),
            'revocationScenario' => fn(array $a) => self::rvScenario($a[0], $a[1]),
            'constants' => fn() => ['jwtSvidAlgorithms' => Spiffe::JWT_SVID_ALGORITHMS],
        ]);
    }

    // ---- ref-spiffe (sessions) ---------------------------------------------------------------------------------------------

    /** The session generator reports every non-SPIFFE refusal as code `jose`. */
    private static function tsErr(callable $f): mixed
    {
        try {
            return $f();
        } catch (SpiffeError $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new SpiffeError('jose', $e->getMessage());
        }
    }

    /** The session generator's scripted revocation check (undefined = not set, notfn = null). */
    private static function sessRev(mixed $mode, array &$calls, bool $async): mixed
    {
        if ($mode === 'notfn') {
            return null;
        }
        return function (Obj $s) use ($mode, &$calls, $async): mixed {
            $calls[] = Js::parse(Js::stringify($s));
            return match (true) {
                $mode === 'false', $async && $mode === 'async-false' => false,
                $mode === 'true', $async && in_array($mode, ['async-true', 'promise'], true) => true,
                $mode === 'throw', $async && $mode === 'async-throw' => throw new \RuntimeException('boom'),
                is_string($mode) && str_starts_with($mode, 'true@') => $s->get('position') === (int)substr($mode, 5),
                $mode === 'one' => 1,
                $mode === 'promise' => new \stdClass(), // a pending Promise is not a boolean
                default => null,
            };
        };
    }

    private static function sessX509(mixed $chain, Obj $o): array
    {
        $calls = [];
        $opts = ['trustDomain' => $o->get('trustDomain'), 'roots' => self::revAll($o->get('roots'))];
        foreach (['nowMs', 'maxChainLength'] as $k) {
            if ($o->has($k) && $o->get($k) !== null) {
                $opts[$k] = $o->get($k);
            }
        }
        if ($o->has('revocation')) {
            $opts['revocation'] = self::sessRev($o->get('revocation'), $calls, false);
        }
        $r = Spiffe::verifyX509Svid(self::revAll($chain), $opts);
        return ['spiffeId' => self::idOut($r->spiffeId), 'publicKeyDer' => $r->publicKeyDer, 'calls' => $calls];
    }

    private static function bundleKey(Obj $s): \Closure
    {
        $jwks = Js::opt(Js::opt($s->get('key'), 'bundle'), 'jwks');
        return Spiffe::createTrustBundleSource(['fetch' => fn() => Obj::of(['jwks' => $jwks]), 'refreshMs' => 1000, 'maxStaleMs' => 5000, 'now' => fn() => 0])->jwtKey;
    }

    private static function sessJwt(Obj $s): array
    {
        $calls = [];
        $opts = ['audience' => $s->get('audience'), 'trustDomain' => $s->get('trustDomain')];
        if ($s->has('currentDateMs')) {
            $opts['nowMs'] = $s->get('currentDateMs');
        }
        foreach (['algorithms', 'clockTolerance'] as $k) {
            if ($s->has($k)) {
                $opts[$k] = $s->get($k);
            }
        }
        if ($s->has('revocation')) {
            $opts['revocation'] = self::sessRev($s->get('revocation'), $calls, true);
        }
        $opts['key'] = Js::opt($s->get('key'), 'jwk') ?? self::bundleKey($s);
        $r = Spiffe::verifyJwtSvid($s->get('token'), $opts);
        return ['spiffeId' => self::idOut($r->spiffeId), 'claims' => $r->claims, 'audience' => $r->audience, 'expiresAt' => $r->expiresAt, 'calls' => $calls];
    }

    /** An absent holderKey is undefined (derive it); an explicit null is JavaScript null, which is no key. */
    private static function keyArg(Obj $s): mixed
    {
        $k = self::rev($s->get('holderKey'));
        return $s->has('holderKey') && $k === null ? new Obj() : $k;
    }

    private static function holderSession(Obj $s): array
    {
        $svid = match ($s->get('svid')) {
            'x509' => Spiffe::verifyX509Svid($s->get('chain'), ['trustDomain' => 'example.org', 'roots' => $s->get('roots'), 'nowMs' => $s->get('nowMs')]),
            'x509-parsed' => Spiffe::parseX509Svid($s->get('chain')),
            'jwt' => Spiffe::verifyJwtSvid(Js::opt($s->get('jwt'), 'token'), ['audience' => Js::opt($s->get('jwt'), 'audience'), 'key' => Js::opt($s->get('jwt'), 'jwk'),
                'trustDomain' => Js::opt($s->get('jwt'), 'trustDomain'), 'nowMs' => Js::opt($s->get('jwt'), 'currentDateMs')]),
            'string' => self::SUB,
            'parsed-id' => Spiffe::parseSpiffeId(self::SUB),
            'hand-built' => Obj::of(['spiffeId' => Spiffe::parseSpiffeId(self::SUB), 'claims' => new Obj(), 'audience' => [], 'expiresAt' => 1]),
            default => null,
        };
        $opts = [];
        if ($s->has('proof')) {
            $opts['proof'] = $s->get('proof');
        }
        if ($s->has('acceptUnbound')) {
            $opts['acceptUnboundJwtHolder'] = $s->get('acceptUnbound');
        }
        return match ($s->get('op')) {
            'holder' => ['holder' => Spiffe::svidToHolder($svid, self::keyArg($s), $opts)],
            'forHolder' => ['spiffeId' => Spiffe::spiffeIdForHolder($svid, $s->has('holderKey') && $s->get('holderKey') === null ? new Obj() : $s->get('holderKey'), $opts)],
            default => ['pin' => Spiffe::workloadDischargePin($s->get('label'), $svid)],
        };
    }

    private static function cacheSession(string $kind, Obj $s): array
    {
        $t = Js::num($s->get('start'));
        $calls = 0;
        $fetches = $s->get('fetches');
        $fetch = function () use (&$calls, $fetches): mixed {
            $f = $fetches[min($calls, count($fetches) - 1)];
            $calls++;
            if (Js::truthy(Js::opt($f, 'throw'))) {
                throw new \RuntimeException('fetch failed');
            }
            return Js::opt($f, 'list');
        };
        $o = ['fetch' => $fetch, 'refreshMs' => $s->get('refreshMs'), 'maxStaleMs' => $s->get('maxStaleMs'), 'now' => function () use (&$t) {
            return $t;
        }];
        $src = $kind === 'revocation' ? Spiffe::createRevocationSource($o) : Spiffe::createTrustBundleSource($o);
        $out = [];
        foreach ($s->get('steps') as $st) {
            try {
                $op = $st->get('op');
                if ($op === 'adv') {
                    $t += Js::num($st->get('ms'));
                    $out[] = ['v' => $t];
                    continue;
                }
                $v = match ($op) {
                    'x509' => $src->x509($st->get('subject')),
                    'jwt' => $src->jwt($st->get('subject')),
                    'refresh' => $src->refresh(),
                    'ensureFresh' => $src->ensureFresh(),
                    'x509Roots' => array_map(static fn(mixed $r) => $r instanceof Bytes ? Base::outBytes($r->raw) : $r, $src->x509Roots()),
                    default => self::keyView(($src->jwtKey)($st->get('header'))),
                };
                $out[] = ['v' => $v];
            } catch (\Throwable $e) {
                $out[] = ['code' => $e instanceof SpiffeError ? $e->codeName : 'jose'];
            }
        }
        return ['steps' => $out, 'fetchCalls' => $calls];
    }

    private static function keyView(mixed $jwk): array
    {
        $v = ['kty' => Js::opt($jwk, 'kty')];
        foreach (['crv', 'x', 'n'] as $k) {
            if (Js::truthy(Js::opt($jwk, $k))) {
                $v[$k] = Js::opt($jwk, $k);
            }
        }
        return $v;
    }

    private const KNOWN = ['malformed_spiffe_id', 'empty_trust_domain', 'trust_domain_too_long', 'invalid_trust_domain', 'invalid_path', 'id_too_long', 'missing_audience',
        'missing_exp', 'malformed_token', 'invalid_subject', 'trust_domain_mismatch', 'no_uri_san', 'multiple_uri_san', 'invalid_holder_key', 'unverified_svid', 'missing_trust_domain',
        'holder_binding_failed', 'malformed_certificate', 'leaf_is_ca', 'leaf_no_digital_signature', 'leaf_cert_sign', 'leaf_crl_sign', 'leaf_root_path', 'unsupported_critical_extension',
        'forbidden_algorithm', 'invalid_typ', 'chain_empty', 'chain_trust_domain_mismatch', 'chain_signature', 'chain_not_ca', 'chain_no_key_cert_sign', 'chain_path_len', 'chain_expired',
        'chain_untrusted_root', 'chain_too_long', 'trust_bundle_unavailable', 'trust_bundle_invalid', 'svid_revoked', 'chain_revoked', 'revocation_unavailable', 'SVID is bound to a different key'];

    private static function sessAdmission(Obj $s): Obj
    {
        $ev = $s->get('kind') === 'x509'
            ? ['kind' => 'x509', 'chain' => $s->get('chain'), 'verify' => ['trustDomain' => 'example.org', 'roots' => $s->get('roots'), 'nowMs' => $s->get('nowMs')]]
            : ['kind' => 'jwt', 'token' => $s->get('token'), 'verify' => ['audience' => 'api', 'trustDomain' => 'example.org', 'nowMs' => self::JAVA_NOW_MS, 'key' => $s->get('jwk')]];
        if (Js::truthy($s->get('bind'))) {
            $ev['bind'] = $s->get('bind');
        }
        $r = Spiffe::spiffeAdmissionEvidence($ev, $s->get('instanceKey'));
        if ($r->has('reason') && !in_array($r->get('reason'), self::KNOWN, true)) {
            $r->set('reason', 'other');
        }
        return $r;
    }

    #[DataProvider('provideSessions')]
    public function testSessionsAgreeWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn() => ['JWT_SVID_ALGORITHMS' => Spiffe::JWT_SVID_ALGORITHMS],
            'parseSpiffeId' => fn(array $a) => Spiffe::parseSpiffeId($a[0]),
            'holderBindingMessage' => fn(array $a) => Base::outBytes(Spiffe::holderBindingMessage($a[0], $a[1])),
            'holderToSpiffeId' => fn(array $a) => Spiffe::holderToSpiffeId($a[0]),
            'readCertFacts' => fn(array $a) => Spiffe::readCertFacts((string)base64_decode(strtr((string)$a[0], '-_', '+/'))),
            'parseX509Svid' => function (array $a) {
                $s = Spiffe::parseX509Svid(self::rev($a[0]));
                return ['spiffeId' => self::idOut($s->spiffeId), 'publicKeyDer' => $s->publicKeyDer];
            },
            'verifyX509Svid' => fn(array $a) => self::tsErr(fn() => self::sessX509($a[0], $a[1])),
            'jwtSession' => fn(array $a) => self::tsErr(fn() => self::sessJwt($a[0])),
            'holderSession' => fn(array $a) => self::tsErr(fn() => self::holderSession($a[0])),
            'revocationSession' => fn(array $a) => self::tsErr(fn() => self::cacheSession('revocation', $a[0])),
            'bundleSession' => fn(array $a) => self::tsErr(fn() => self::cacheSession('bundle', $a[0])),
            'admission' => fn(array $a) => self::sessAdmission($a[0]),
        ]);
    }
}
