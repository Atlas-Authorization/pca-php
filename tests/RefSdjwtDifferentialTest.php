<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Audience;
use Atlas\Pca\Bytes;
use Atlas\Pca\Jose;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sdjwt;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * SD-JWT of a PCActn against the TS reference: test-data/ref-sdjwt.json.gz. Issuance compares a normalized form (salts are
 * random); presentation compares exact strings (Ed25519 KB-JWT signatures are deterministic); a verification refusal compares
 * its reason exactly only when the reason is this package's own (or the canonical gate's), a JOSE-library wording only has to
 * be a refusal; verifyRecovered compares `allow` and this package's own reasons.
 */
final class RefSdjwtDifferentialTest extends TestCase
{
    private const FILE = 'ref-sdjwt.json.gz';
    private const OWN = ['pca-sdjwt:', 'non-canonical compact JWS', 'required disclosure', 'KB-JWT ', 'cnf key does not', 'key binding required',
        'duplicate disclosure', 'unsupported _sd_alg', 'a presented disclosure', 'a digest appears', 'an array', 'an object-property', 'disclosure claim', '_sd must be', "'"];
    private const CAMEL = ['required_disclosures' => 'requiredDisclosures', 'expected_audience' => 'expectedAudience', 'expected_kb_audience' => 'expectedKbAudience',
        'expected_nonce' => 'expectedNonce', 'require_key_binding' => 'requireKeyBinding', 'algorithms' => 'algorithms', 'kb_algorithms' => 'kbAlgorithms',
        'now' => 'now', 'kb_max_age_sec' => 'kbMaxAgeSec', 'clock_tolerance_sec' => 'clockToleranceSec', 'key_binding_key' => 'keyBindingKey'];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** {"$bytes": b64u} at any depth becomes the raw bytes. */
    private static function rev(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return new Bytes((string)Pca::unb64u($v->get('$bytes')));
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::rev($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::rev(...), $v) : $v;
    }

    private static function raw(mixed $v): string
    {
        return (string)Bytes::of(self::rev($v));
    }

    private static function dec(string $seg): mixed
    {
        return Js::parse(Jose::lenientB64d($seg));
    }

    /** The reference harness's normalized view of an issued SD-JWT. */
    private static function normalizeIssued(string $sd, string $seed): array
    {
        $parts = explode('~', $sd);
        $ds = array_slice($parts, 1, -1);
        [$h, $p] = array_map(self::dec(...), array_slice(explode('.', $parts[0]), 0, 2));
        $dig = array_map(static fn(string $d) => Jose::b64u(hash('sha256', $d, true)), $ds);
        sort($dig, SORT_STRING);
        $sdl = $p->get('_sd') ?? [];
        sort($sdl, SORT_STRING);
        $disc = array_map(static fn(string $d) => array_slice(self::dec($d), 1, 2), $ds);
        usort($disc, static fn(array $a, array $b) => strcmp((string)$a[0], (string)$b[0]));
        $pub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $ver = Sdjwt::verifyPcaSdJwt($sd, ['issuerKey' => Sdjwt::importEd25519PublicKey($pub), 'now' => Js::num($p->get('iat')) * 1000]);
        return ['end' => $parts[count($parts) - 1], 'header' => $h, 'payload' => $p->without('_sd'), 'n' => count($ds), 'digestsOk' => $dig === $sdl,
            'disclosures' => $disc, 'verified' => $ver->get('ok')];
    }

    private static function issue(array $a): array
    {
        $opt = $a[1];
        $seed = self::raw($opt->get('issuer_seed'));
        $m = ['issuerKey' => Sdjwt::importEd25519PrivateKey($seed)];
        foreach (['disclosable', 'iss', 'sub', 'typ'] as $k) {
            if ($opt->has($k)) {
                $m[$k] = $opt->get($k);
            }
        }
        if ($opt->has('signing_alg')) {
            $m['signingAlg'] = $opt->get('signing_alg');
        }
        if ($opt->has('key_binding')) {
            $kb = $opt->get('key_binding');
            $m['keyBinding'] = $kb instanceof Obj && $kb->has('holder_public_key') ? ['holderPublicKey' => self::rev($kb->get('holder_public_key'))] : $kb;
        }
        return self::normalizeIssued(Sdjwt::issuePcaSdJwt($a[0], $m), $seed);
    }

    private static function present(array $a): string
    {
        $m = [];
        $opt = $a[2] ?? null;
        if ($opt instanceof Obj && $opt->has('key_binding')) {
            $kb = $opt->get('key_binding');
            $k = ['holderKey' => Sdjwt::importEd25519PrivateKey(self::raw($kb->get('holder_seed')))];
            foreach (['audience', 'nonce', 'iat', 'alg'] as $n) {
                if ($kb->has($n)) {
                    $k[$n] = $kb->get($n);
                }
            }
            $m['keyBinding'] = $k;
        }
        return Sdjwt::present($a[0], $a[1], $m);
    }

    /** The harness's importJWK: a key object without the JWK's metadata (`d`, `alg`, `use`, `key_ops` play no part). */
    private static function importJwk(Obj $jwk): mixed
    {
        $pub = new Obj();
        foreach (['kty', 'crv', 'x', 'y', 'n', 'e'] as $k) {
            if ($jwk->has($k)) {
                $pub->set($k, $jwk->get($k));
            }
        }
        return Jose::publicKeyFromJwk($pub)[1];
    }

    private static function verify(array $a): Obj
    {
        $opt = $a[1];
        $ik = self::rev($opt->get('issuer_key'));
        $m = ['issuerKey' => $ik instanceof Bytes ? Sdjwt::importEd25519PublicKey($ik) : self::importJwk($ik)];
        foreach (self::CAMEL as $k => $c) {
            if ($opt->has($k)) {
                $m[$c] = self::rev($opt->get($k));
            }
        }
        return Sdjwt::verifyPcaSdJwt($a[0], $m);
    }

    private static function clip(string $r): string
    {
        return str_starts_with($r, 'non-canonical compact JWS: bad-json') ? explode(' (', $r)[0] : $r;
    }

    /** A refusal in the JOSE library's wording only has to be a refusal: the expectation is reduced to the native's reason. */
    private static function verifyCase(array $a, Obj $c): Obj
    {
        $r = self::verify($a);
        $want = $c->get('out');
        if ($want instanceof Obj && $want->get('ok') === false && $r->get('ok') === false) {
            $wr = (string)$want->get('reason');
            $hr = (string)$r->get('reason');
            $own = false;
            foreach (self::OWN as $p) {
                $own = $own || str_starts_with($wr, $p);
            }
            if (str_starts_with($wr, 'KB-JWT signature/claims invalid')) {
                $same = str_starts_with($hr, 'KB-JWT signature/claims invalid');
            } else {
                $same = !$own || self::clip($wr) === self::clip($hr);
            }
            if ($same) {
                $c->set('out', $r);
            }
        }
        return $r;
    }

    private static function recovered(array $a, Obj $c): array
    {
        $opt = $a[1];
        $co = ['grant' => $opt->get('grant')];
        if ($opt->has('audience')) {
            // the reference spells "accept any audience" as null; the native API refuses null and takes Audience::Any
            $co['audience'] = $opt->get('audience') ?? Audience::Any;
        }
        if ($opt->has('now')) {
            $co['nowEpoch'] = $opt->get('now');
        }
        if ($opt->has('insecure_skip_plan_root_check')) {
            $co['insecureSkipPlanRootCheck'] = $opt->get('insecure_skip_plan_root_check');
        }
        $r = Sdjwt::verifyRecovered($a[0], $co);
        $out = ['allow' => $r['allow']];
        if (($r['reason'] ?? '') !== '') { // an allow carries no reason (the core's empty text is not one)
            $out['reason'] = $r['reason'];
        }
        $want = $c->get('out');
        $wr = $want instanceof Obj ? $want->get('reason') : null;
        if (!(is_string($wr) && str_starts_with($wr, 'pca-sdjwt:')) && isset($out['reason'])) {
            $out['reason'] = $wr; // a core reason is the core's wording; only `allow` must agree
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn() => ['SD_ALG' => Sdjwt::SD_ALG, 'PCA_SD_JWT_TYP' => Sdjwt::PCA_SD_JWT_TYP, 'KB_JWT_TYP' => Sdjwt::KB_JWT_TYP,
                'DEFAULT_SIGNING_ALG' => Sdjwt::DEFAULT_SIGNING_ALG, 'PCA_CAPABILITY_CLAIMS' => Sdjwt::PCA_CAPABILITY_CLAIMS],
            'ed25519PublicJwk' => fn(array $a) => Sdjwt::ed25519PublicJwk(self::rev($a[0])),
            'importEd25519PrivateKey' => function (array $a) {
                Sdjwt::importEd25519PrivateKey(self::rev($a[0]));
                return 'ok';
            },
            'importEd25519PublicKey' => function (array $a) {
                Sdjwt::importEd25519PublicKey(self::rev($a[0]));
                return 'ok';
            },
            'issuePcaSdJwt' => fn(array $a) => self::issue($a),
            'present' => fn(array $a) => self::present($a),
            'verifyPcaSdJwt' => fn(array $a, Obj $c) => self::verifyCase($a, $c),
            'verifyRecovered' => fn(array $a, Obj $c) => self::recovered($a, $c),
        ]);
    }
}
