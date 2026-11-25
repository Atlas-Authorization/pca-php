<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Signed runtime observations (the trust ramp's input): a labelled outcome against an Intent Map, signed by whoever observed it.
 * `y = 0` says the outcome should NOT have been allowed (it vetoes the cell on replay), `y = 1` confirms it. Values are the
 * parsed-JSON model; options are an Obj or an assoc array (`expectedSigner`, `pqPins`). Only Ed25519 signing is native.
 */
final class IntentObservation
{
    public const SIG_DOMAIN = "atlas-pca/intent-obs/v1\0";
    public const SOURCES = ['runtime', 'witness', 'elicitation', 'import'];

    private const BODY_KEYS = ['v', 'map_digest', 'verb', 'values', 'y', 'source', 'observed_at', 'pcactn_digest', 'signer'];

    /** The signed body: suite fields and signatures excluded. */
    public static function body(mixed $o): Obj
    {
        $b = new Obj();
        foreach (self::BODY_KEYS as $k) {
            if (Js::has($o, $k)) {
                $b->set($k, Js::opt($o, $k));
            }
        }
        return $b;
    }

    private static function bin(mixed $x): bool
    {
        return Js::isNum($x) && in_array(Js::num($x), [0.0, 1.0], true);
    }

    private static function shapeError(mixed $o): ?string
    {
        if (!($o instanceof Obj) || !Js::isNum($o->get('v') ?? null) || Js::num($o->get('v')) !== 1.0) {
            return 'not an intent observation v1';
        }
        $md = Js::opt($o, 'map_digest');
        if (!is_string($md) || Pca::unb64u($md, 32) === null) {
            return 'map_digest is not canonical base64url (32 bytes)';
        }
        $verb = Js::opt($o, 'verb');
        if (!is_string($verb) || $verb === '') {
            return 'verb must be a non-empty string';
        }
        $values = Js::opt($o, 'values');
        $okValues = $values instanceof Obj;
        foreach ($okValues ? $values->keys() : [] as $k) {
            $x = $values->get($k);
            $okValues = $okValues && (is_string($x) || (Js::isNum($x) && is_finite((float)Js::num($x))));
        }
        if (!$okValues) {
            return 'values must map paths to numbers or strings';
        }
        if (!self::bin(Js::opt($o, 'y'))) {
            return 'y must be 0 or 1';
        }
        if (!in_array(Js::opt($o, 'source'), self::SOURCES, true)) {
            return 'unknown observation source';
        }
        $at = Js::opt($o, 'observed_at');
        if (!IntentWb::isSafeInt($at) || Js::num($at) < 0) {
            return 'observed_at must be a non-negative safe integer';
        }
        if ($o->has('pcactn_digest') && (!is_string($o->get('pcactn_digest')) || Pca::unb64u($o->get('pcactn_digest'), 32) === null)) {
            return 'pcactn_digest is not canonical base64url (32 bytes)';
        }
        $signer = Js::opt($o, 'signer');
        if (!is_string($signer) || Pca::unb64u($signer, 32) === null) {
            return 'signer is not canonical base64url (32 bytes)';
        }
        return null;
    }

    private static function message(Obj $body, Obj $s): string
    {
        $alg = $s->has('alg') ? $s->get('alg') : 'ed25519';
        if ($alg !== 'ed25519') { // a non-ed25519 suite signs `alg` and `pq_pk` too (an absent pq_pk throws, as in the reference)
            if (!$s->has('pq_pk')) {
                throw new \InvalidArgumentException('pq_pk is missing');
            }
            $body = self::body($body);
            $body->set('alg', $alg);
            $body->set('pq_pk', $s->get('pq_pk'));
        }
        return self::SIG_DOMAIN . Json::canonicalizeNative($body);
    }

    /** Sign an observation (without `v` / `signer`) with an Ed25519 32-byte seed; the signer is the key of the seed. */
    public static function sign(mixed $o, string $signerSecret, mixed $suite = null): Obj
    {
        $alg = Js::opt($suite, 'alg');
        if ($alg !== null && $alg !== 'ed25519') {
            throw new \InvalidArgumentException('signIntentObservation: only Ed25519 signing is supported natively');
        }
        $kp = sodium_crypto_sign_seed_keypair($signerSecret);
        $in = self::body($o);
        $in->set('v', 1);
        $in->set('signer', Pca::b64u(sodium_crypto_sign_publickey($kp)));
        $body = self::body($in);
        $bad = self::shapeError($body);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signIntentObservation: $bad");
        }
        $out = self::body($body);
        $out->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::message($body, $body), sodium_crypto_sign_secretkey($kp))));
        return $out;
    }

    /**
     * Verify a signed observation (shape, signer, suite signature; a PQ key must be pinned via `pqPins`). Never throws.
     * @return array{ok:bool,reason?:string}
     */
    public static function verify(mixed $o, mixed $opts = null): array
    {
        try {
            $bad = self::shapeError($o);
            if ($bad !== null) {
                return ['ok' => false, 'reason' => $bad];
            }
            /** @var Obj $o */
            if (Js::has($opts, 'expectedSigner') && $o->get('signer') !== Js::opt($opts, 'expectedSigner')) {
                return ['ok' => false, 'reason' => 'signer mismatch'];
            }
            $alg = $o->has('alg') ? $o->get('alg') : null;
            if ($o->has('alg') && (!is_string($alg) || !in_array($alg, Pca::REGISTERED_SUITES, true))) {
                return ['ok' => false, 'reason' => 'unknown signature suite'];
            }
            if ((!$o->has('alg') || $alg === 'ed25519') && ($o->has('pq_pk') || $o->has('pq_sig'))) {
                return ['ok' => false, 'reason' => 'an ed25519 artifact must not carry pq_pk / pq_sig'];
            }
            $signer = (string)$o->get('signer');
            $msg = self::message(self::body($o), $o);
            $pin = null;
            $pqPins = Js::opt($opts, 'pqPins');
            if ($pqPins instanceof Obj && $pqPins->has($signer)) {
                $p = $pqPins->get($signer);
                $pin = is_string($p) ? $p : "\0\0not-a-string";
            }
            $ok = Pca::verifyPinnedSuite($alg, $signer, $o->has('pq_pk') ? $o->get('pq_pk') : null, $msg,
                $o->has('sig') ? $o->get('sig') : null, $o->has('pq_sig') ? $o->get('pq_sig') : null, $pin);
            return $ok === true ? ['ok' => true] : ['ok' => false, 'reason' => 'bad signature'];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'malformed intent observation: ' . $e->getMessage()];
        }
    }
}
