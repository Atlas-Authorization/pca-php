<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Approval.php';
require_once __DIR__ . '/Attest/Common.php';

use Atlas\Pca\Attest\Common;

/**
 * WebAuthn / FIDO2 assertion verification as the PCA step-up human co-sign. The WebAuthn challenge is the PCA step-up
 * challenge (sha256(thresholdMessage(pcactn)), the FROST action digest), so a valid assertion proves a human holding a
 * hardware-bound credential approved THIS action. Server side only: ES256 (P-256, OpenSSL) and strict Ed25519 (libsodium,
 * prime-order points). Every public entry point except the challenge builders and coseKeyToJwk fails closed without throwing.
 *
 * Bytes: a Bytes instance or a PHP string where the reference takes a Uint8Array; where it takes Uint8Array | string (the
 * challenge inputs) a PHP string is the base64url text and Bytes the raw bytes.
 */
final class Webauthn
{
    public const MAX_AUTHENTICATOR_DATA_BYTES = 4096;
    public const MAX_CLIENT_DATA_BYTES = 8192;
    public const MAX_SIGNATURE_BYTES = 1024;
    private const P256_N = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';

    // ---- COSE_Key (a flat CBOR map with integer labels: uint, nint, bstr, map; 1/2/4-byte arguments) -----------------------

    /** @return array{0:mixed,1:int} [value (int | Bytes | array<int,mixed> map), next offset] */
    private static function cborItem(string $b, int $p): array
    {
        if ($p >= strlen($b)) {
            throw new \RangeException('Offset is outside the bounds of the DataView');
        }
        $ib = ord($b[$p]);
        $major = $ib >> 5;
        $ai = $ib & 0x1f;
        $p++;
        if ($ai < 24) {
            $arg = $ai;
        } elseif ($ai <= 26) {
            $n = [24 => 1, 25 => 2, 26 => 4][$ai];
            if ($p + $n > strlen($b)) {
                throw new \RangeException('Offset is outside the bounds of the DataView');
            }
            $arg = (int)hexdec(bin2hex(substr($b, $p, $n)));
            $p += $n;
        } else {
            throw new \RuntimeException('cose: unsupported CBOR argument encoding (8-byte or indefinite length)');
        }
        switch ($major) {
            case 0:
                return [$arg, $p];
            case 1:
                return [-1 - $arg, $p];
            case 2:
                if ($p + $arg > strlen($b)) {
                    throw new \RuntimeException('cose: byte string length out of range');
                }
                return [new Bytes(substr($b, $p, $arg)), $p + $arg];
            case 5:
                $map = [];
                for ($i = 0; $i < $arg; $i++) {
                    [$k, $p] = self::cborItem($b, $p);
                    if (!is_int($k)) {
                        throw new \RuntimeException('cose: non-integer map key');
                    }
                    [$v, $p] = self::cborItem($b, $p);
                    $map[$k] = $v; // a repeated label keeps the last value, as the reference's Map does
                }
                return [$map, $p];
            default:
                throw new \RuntimeException("cose: unsupported CBOR major type $major");
        }
    }

    /**
     * Decode a raw COSE_Key into a JWK: ES256 (EC2 / P-256) or EdDSA (OKP / Ed25519). Throws on malformed input or another
     * key type. Like the reference, bytes after the map are ignored.
     * @return array<string,string>
     */
    public static function coseKeyToJwk(mixed $bytes): array
    {
        $raw = Bytes::of($bytes);
        if ($raw === null) {
            throw new \TypeError('coseKeyToJwk: expected a Uint8Array');
        }
        [$m] = self::cborItem($raw, 0);
        if (!is_array($m)) {
            throw new \RuntimeException('coseKeyToJwk: COSE_Key is not a CBOR map');
        }
        $kty = $m[1] ?? null;
        $crv = $m[-1] ?? null;
        $x = $m[-2] ?? null;
        if ($kty === 2) {
            $y = $m[-3] ?? null;
            if ($crv !== 1) {
                throw new \RuntimeException('coseKeyToJwk: EC2 key is not P-256 (crv != 1)');
            }
            if (!($x instanceof Bytes) || !($y instanceof Bytes)) {
                throw new \RuntimeException('coseKeyToJwk: EC2 key missing an x/y coordinate');
            }
            if (strlen($x->raw) !== 32 || strlen($y->raw) !== 32) {
                throw new \RuntimeException('coseKeyToJwk: EC2 coordinate is not 32 bytes');
            }
            return ['kty' => 'EC', 'crv' => 'P-256', 'x' => Pca::b64u($x->raw), 'y' => Pca::b64u($y->raw), 'alg' => 'ES256'];
        }
        if ($kty === 1) {
            if ($crv !== 6) {
                throw new \RuntimeException('coseKeyToJwk: OKP key is not Ed25519 (crv != 6)');
            }
            if (!($x instanceof Bytes)) {
                throw new \RuntimeException('coseKeyToJwk: OKP key missing its public key');
            }
            if (strlen($x->raw) !== 32) {
                throw new \RuntimeException('coseKeyToJwk: Ed25519 public key is not 32 bytes');
            }
            return ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Pca::b64u($x->raw), 'alg' => 'EdDSA'];
        }
        $k = $kty instanceof Bytes ? '[object Uint8Array]' : (is_array($kty) ? '[object Map]' : Js::str($kty));
        throw new \RuntimeException('coseKeyToJwk: unsupported COSE key type (kty=' . ($kty === null ? 'undefined' : $k) . ')');
    }

    /** Tolerant base64url: '=' padding stripped, + / mapped to - _, then the canonical decode. Null when undecodable. */
    private static function b64urlBytes(mixed $s): ?string
    {
        if (!is_string($s)) {
            return null;
        }
        $t = strtr((string)preg_replace('/=+\z/', '', $s), '+/', '-_');
        return preg_match('/\A[A-Za-z0-9_-]*\z/', $t) === 1 ? Pca::unb64u($t) : null;
    }

    /** @return array{0:string,1:string} [alg, raw key: 04||X||Y for ES256, the 32-byte key for EdDSA] */
    private static function resolveKey(mixed $pub): array
    {
        $jwk = Bytes::of($pub) !== null ? self::coseKeyToJwk($pub) : $pub;
        $kty = Js::get($jwk, 'kty');
        if ($kty === 'EC') {
            if (Js::opt($jwk, 'crv') !== 'P-256') {
                throw new \RuntimeException('resolveKey: EC JWK is not P-256');
            }
            $x = self::b64urlBytes(Js::opt($jwk, 'x'));
            $y = self::b64urlBytes(Js::opt($jwk, 'y'));
            if ($x === null || $y === null || strlen($x) !== 32 || strlen($y) !== 32) {
                throw new \RuntimeException('resolveKey: invalid EC JWK coordinates');
            }
            return ['ES256', "\x04$x$y"];
        }
        if ($kty === 'OKP') {
            if (Js::opt($jwk, 'crv') !== 'Ed25519') {
                throw new \RuntimeException('resolveKey: OKP JWK is not Ed25519');
            }
            $x = self::b64urlBytes(Js::opt($jwk, 'x'));
            if ($x === null || strlen($x) !== 32) {
                throw new \RuntimeException('resolveKey: invalid OKP JWK public key');
            }
            return ['EdDSA', $x];
        }
        throw new \RuntimeException('resolveKey: unsupported public key');
    }

    // ---- authenticatorData ----------------------------------------------------------------------------------------------

    /**
     * The fixed 37-byte header (rpIdHash ‖ flags ‖ signCount); null when shorter or not bytes. The tail is not decoded.
     * @return ?array{rpIdHash:Bytes,flags:array<string,bool>,signCount:int}
     */
    public static function parseAuthenticatorData(mixed $authData): ?array
    {
        $b = Bytes::of($authData);
        if ($b === null || strlen($b) < 37) {
            return null;
        }
        $f = ord($b[32]);
        return [
            'rpIdHash' => new Bytes(substr($b, 0, 32)),
            'flags' => ['up' => ($f & 0x01) !== 0, 'uv' => ($f & 0x04) !== 0, 'be' => ($f & 0x08) !== 0, 'bs' => ($f & 0x10) !== 0, 'at' => ($f & 0x40) !== 0, 'ed' => ($f & 0x80) !== 0],
            'signCount' => unpack('N', substr($b, 33, 4))[1],
        ];
    }

    // ---- challenges -----------------------------------------------------------------------------------------------------

    /**
     * The WebAuthn challenge for a step-up: sha256(thresholdMessage(pcactn)), or a given digest (32 raw Bytes, or its canonical
     * base64url string). Throws on a digest of the wrong size / form.
     */
    public static function buildStepUpChallenge(mixed $pcActnOrDigest): string
    {
        if ($pcActnOrDigest instanceof Bytes) {
            if (strlen($pcActnOrDigest->raw) !== 32) {
                throw new \RangeException('buildStepUpChallenge: digest bytes must be 32 bytes');
            }
            return $pcActnOrDigest->raw;
        }
        if (is_string($pcActnOrDigest)) {
            return Pca::unb64u($pcActnOrDigest, 32) ?? throw new \RangeException('buildStepUpChallenge: digest is not a canonical base64url 32-byte value');
        }
        if ($pcActnOrDigest === null) {
            throw new \TypeError("Cannot destructure property 'sig' of 'p' as it is null.");
        }
        // the reference's object rest over a non-object: an array keeps its indices, a scalar has no members
        if ($pcActnOrDigest instanceof Obj) {
            $o = $pcActnOrDigest;
        } elseif (is_array($pcActnOrDigest)) {
            $o = new Obj();
            foreach ($pcActnOrDigest as $k => $v) {
                $o->set((string)$k, $v);
            }
        } else {
            $o = new Obj();
        }
        return hash('sha256', Pca::thresholdMessage($o), true);
    }

    /** SHA-256(domain || action_digest || H(R)): the approval challenge that commits to the canonical render. */
    public static function buildApprovalChallenge(mixed $pcActnOrDigest, mixed $renderDigest): string
    {
        return (string)Pca::unb64u(Approval::challenge(Pca::b64u(self::buildStepUpChallenge($pcActnOrDigest)), $renderDigest));
    }

    public static function approvalChallengeForActn(mixed $pcActnOrDigest, mixed $renderDigest): string
    {
        return Pca::b64u(self::buildApprovalChallenge($pcActnOrDigest, $renderDigest));
    }

    /** The base64url step-up challenge (== the FROST action_digest). */
    public static function stepUpChallengeB64u(mixed $pcActnOrDigest): string
    {
        return Pca::b64u(self::buildStepUpChallenge($pcActnOrDigest));
    }

    // ---- Secure Payment Confirmation ------------------------------------------------------------------------------------

    /** JS `a[k] !== b[l]` over parsed JSON: absent (undefined) differs from null; objects compare by identity (never equal). */
    private static function differs(mixed $a, string $ka, mixed $b, string $kb): bool
    {
        $ha = Js::has($a, $ka);
        $hb = Js::has($b, $kb);
        if (!$ha || !$hb) {
            return $ha !== $hb;
        }
        $x = Js::opt($a, $ka);
        $y = Js::opt($b, $kb);
        if (Js::isNum($x) && Js::isNum($y)) {
            return !(Js::num($x) == Js::num($y));
        }
        return !(($x === null || is_scalar($x)) && $x === $y);
    }

    private static function record(mixed $v): bool
    {
        return $v instanceof Obj || (is_array($v) && $v !== [] && !array_is_list($v));
    }

    /** Null when the signed clientData.payment equals the expectation {topOrigin, total {currency, value}, payeeName?, payeeOrigin?}. */
    public static function spcPaymentError(mixed $payment, mixed $e, mixed $rpId): ?string
    {
        if (!self::record($payment)) {
            return 'clientData.payment is missing';
        }
        if ($e === null) {
            throw new \TypeError("Cannot read properties of null (reading 'payeeName')");
        }
        if (!Js::has($e, 'payeeName') && !Js::has($e, 'payeeOrigin')) {
            return 'the expectation names no payee (refused: a payment approval must bind the payee)';
        }
        if (self::differs($payment, 'rpId', ['rpId' => $rpId], 'rpId')) {
            return 'clientData.payment.rpId is not the verifier rpId';
        }
        if (self::differs($payment, 'topOrigin', $e, 'topOrigin')) {
            return 'clientData.payment.topOrigin is not the verifier approval origin';
        }
        $total = Js::opt($payment, 'total');
        if (!self::record($total)) {
            return 'clientData.payment.total does not equal the canonical render';
        }
        $et = Js::get($e, 'total');
        if ($et === null) {
            throw new \TypeError("Cannot read properties of undefined (reading 'currency')");
        }
        if (self::differs($total, 'currency', $et, 'currency') || self::differs($total, 'value', $et, 'value')) {
            return 'clientData.payment.total does not equal the canonical render';
        }
        foreach (['payeeName', 'payeeOrigin'] as $k) {
            if (Js::has($e, $k) && self::differs($payment, $k, $e, $k)) {
                return "clientData.payment.$k does not equal the canonical render";
            }
        }
        return null;
    }

    // ---- assertion verification ---------------------------------------------------------------------------------------

    private static function fail(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    /** A strict DER integer (noble's rules: no sign bit, no needless leading zero) as GMP; null when malformed. */
    private static function derInt(string $v): ?\GMP
    {
        if ($v === '' || (ord($v[0]) & 0x80) !== 0 || (strlen($v) > 1 && $v[0] === "\0" && (ord($v[1]) & 0x80) === 0)) {
            return null;
        }
        return gmp_import($v);
    }

    /** A strict DER TLV of `$tag` at the start of `$d`: [value, rest] or null (minimal lengths only). */
    private static function tlv(int $tag, string $d): ?array
    {
        if (strlen($d) < 2 || ord($d[0]) !== $tag) {
            return null;
        }
        $l = ord($d[1]);
        $p = 2;
        if ($l & 0x80) {
            $n = $l & 0x7f;
            if ($n === 0 || $n > 4 || strlen($d) < 2 + $n || $d[2] === "\0") {
                return null;
            }
            $l = (int)hexdec(bin2hex(substr($d, 2, $n)));
            if ($l < 128) {
                return null;
            }
            $p += $n;
        }
        if (strlen($d) - $p < $l) {
            return null;
        }
        return [substr($d, $p, $l), substr($d, $p + $l)];
    }

    /** ECDSA P-256 over SHA-256(signedData): DER (strict) or 64-byte r||s; r, s in [1, n-1]; optional low-S. */
    private static function es256Verify(string $point, string $sig, string $signedData, bool $lowS): bool
    {
        $isDer = $sig !== '' && $sig[0] === "\x30" && strlen($sig) !== 64;
        if ($isDer) {
            $seq = self::tlv(0x30, $sig);
            $ri = $seq !== null && $seq[1] === '' ? self::tlv(0x02, $seq[0]) : null;
            $si = $ri !== null ? self::tlv(0x02, $ri[1]) : null;
            if ($si === null || $si[1] !== '') {
                return false;
            }
            $r = self::derInt($ri[0]);
            $s = self::derInt($si[0]);
        } else {
            if (strlen($sig) !== 64) {
                return false;
            }
            $r = gmp_import(substr($sig, 0, 32));
            $s = gmp_import(substr($sig, 32));
        }
        $n = gmp_init(self::P256_N, 16);
        if ($r === null || $s === null || gmp_cmp($r, 1) < 0 || gmp_cmp($r, $n) >= 0 || gmp_cmp($s, 1) < 0 || gmp_cmp($s, $n) >= 0) {
            return false;
        }
        if ($lowS && gmp_cmp($s, gmp_div_q($n, 2)) > 0) {
            return false;
        }
        try {
            $key = Common::ecKeyFromPoint('P-256', $point); // off the curve throws: not a valid signature
        } catch (\Throwable) {
            return false;
        }
        $enc = static function (\GMP $i): string {
            $b = gmp_export($i);
            if ((ord($b[0]) & 0x80) !== 0) {
                $b = "\0$b";
            }
            return "\x02" . chr(strlen($b)) . $b;
        };
        $body = $enc($r) . $enc($s);
        return Common::ecdsaVerifyDer($key, "\x30" . chr(strlen($body)) . $body, $signedData, 'sha256');
    }

    /**
     * Verify a WebAuthn assertion {authenticatorData, clientDataJSON, signature (bytes), publicKey (JWK or COSE_Key bytes)}
     * against {expectedChallenge, rpId, origins, requireUV, storedSignCount (required), requireLowS?, rejectCrossOrigin?
     * (default true), payment? (SPC), onSignCountRegression? (callable(array{storedSignCount, reportedSignCount}))}.
     * Order: inputs; clientDataJSON type / challenge / origin; rpIdHash, UP, UV; the signature over
     * authenticatorData ‖ sha256(clientDataJSON); then the signature counter. Never throws.
     * @return array{ok:true,alg:string,signCount:int,flags:array<string,bool>}|array{ok:false,reason:string}
     */
    public static function verifyAssertion(mixed $assertion, mixed $expect): array
    {
        try {
            $ad = Bytes::of(Js::get($assertion, 'authenticatorData'));
            $cd = Bytes::of(Js::opt($assertion, 'clientDataJSON'));
            $sig = Bytes::of(Js::opt($assertion, 'signature'));
            $publicKey = Js::opt($assertion, 'publicKey');
            if ($ad === null) {
                return self::fail('authenticatorData is not bytes');
            }
            if ($cd === null) {
                return self::fail('clientDataJSON is not bytes');
            }
            if ($sig === null) {
                return self::fail('signature is not bytes');
            }
            if (strlen($ad) > self::MAX_AUTHENTICATOR_DATA_BYTES) {
                return self::fail('authenticatorData is too large');
            }
            if (strlen($cd) > self::MAX_CLIENT_DATA_BYTES) {
                return self::fail('clientDataJSON is too large');
            }
            if (strlen($sig) > self::MAX_SIGNATURE_BYTES) {
                return self::fail('signature is too large');
            }
            $rpId = Js::get($expect, 'rpId');
            if (!is_string($rpId) || $rpId === '') {
                return self::fail('rpId is required');
            }
            $origins = Js::opt($expect, 'origins');
            if (!is_array($origins) || !array_is_list($origins) || $origins === []) {
                return self::fail('origins allowlist is empty');
            }
            if (!Js::has($expect, 'storedSignCount')) {
                return self::fail('storedSignCount is required (use 0 for a credential never used)');
            }

            // --- clientDataJSON (TextDecoder fatal: a leading BOM is dropped, invalid UTF-8 refused)
            $text = str_starts_with($cd, "\xEF\xBB\xBF") ? substr($cd, 3) : $cd;
            if (!mb_check_encoding($text, 'UTF-8')) {
                return self::fail('clientDataJSON is not valid UTF-8');
            }
            try {
                $client = Js::parseNoDuplicates($text);
            } catch (\Throwable) {
                return self::fail('clientDataJSON is not valid JSON');
            }
            if (!($client instanceof Obj)) {
                return self::fail('clientDataJSON is not a JSON object');
            }
            $spc = Js::has($expect, 'payment');
            $wantType = $spc ? 'payment.get' : 'webauthn.get';
            if ($client->get('type') !== $wantType) {
                return self::fail("clientData.type is not \"$wantType\" (" . ($client->has('type') ? Js::str($client->get('type')) : 'undefined') . ')');
            }
            if ($spc) {
                $pe = self::spcPaymentError($client->get('payment'), Js::opt($expect, 'payment'), $rpId);
                if ($pe !== null) {
                    return self::fail($pe);
                }
            }
            $got = Pca::unb64u($client->get('challenge'));
            if ($got === null) {
                return self::fail('clientData.challenge is missing or not canonical base64url');
            }
            $ec = Js::opt($expect, 'expectedChallenge');
            $exp = $ec instanceof Bytes ? $ec->raw : Pca::unb64u($ec);
            if ($exp === null) {
                return self::fail('expectedChallenge is not decodable');
            }
            if (!hash_equals($exp, $got)) {
                return self::fail('clientData.challenge does not match the step-up challenge');
            }
            if (Js::opt($expect, 'rejectCrossOrigin') !== false && $client->has('crossOrigin') && $client->get('crossOrigin') !== false) {
                return self::fail($client->get('crossOrigin') === true ? 'clientData.crossOrigin is true' : 'clientData.crossOrigin is not a boolean');
            }
            $origin = $client->get('origin');
            if (!is_string($origin)) {
                return self::fail('clientData.origin is missing');
            }
            if (!in_array($origin, $origins, true)) {
                return self::fail("clientData.origin \"$origin\" is not in the allowlist");
            }

            // --- authenticatorData
            $parsed = self::parseAuthenticatorData($ad);
            if ($parsed === null) {
                return self::fail('authenticatorData is too short (< 37 bytes)');
            }
            if (!hash_equals(hash('sha256', Js::utf8($rpId), true), $parsed['rpIdHash']->raw)) {
                return self::fail('rpIdHash does not match sha256(rpId)');
            }
            if (!$parsed['flags']['up']) {
                return self::fail('User Present (UP) flag is not set');
            }
            if (Js::truthy(Js::opt($expect, 'requireUV')) && !$parsed['flags']['uv']) {
                return self::fail('User Verified (UV) flag is required but not set');
            }

            // --- the signature over authenticatorData ‖ sha256(clientDataJSON)
            $signed = $ad . hash('sha256', $cd, true);
            try {
                [$alg, $raw] = self::resolveKey($publicKey);
            } catch (\Throwable $e) {
                return self::fail('public key could not be resolved: ' . $e->getMessage());
            }
            $valid = $alg === 'ES256'
                ? self::es256Verify($raw, $sig, $signed, Js::opt($expect, 'requireLowS') === true)
                // strict RFC 8032: canonical encodings, S < L, no small-order / mixed-order key or R
                : Pca::verifyEd25519B64u(Pca::b64u($raw), $signed, Pca::b64u($sig));
            if (!$valid) {
                return self::fail('assertion signature did not verify');
            }

            // --- the signature counter (clone detection), only after the signature verified
            $st = Js::opt($expect, 'storedSignCount');
            $sf = Js::num($st);
            if ($sf === null || !is_finite($sf) || floor($sf) !== $sf || $sf < 0 || ($sf === 0.0 && fdiv(1, $sf) < 0) || $sf > 0xffffffff) {
                return self::fail('storedSignCount is not a uint32');
            }
            $stored = (int)$sf;
            $reported = $parsed['signCount'];
            if (($reported !== 0 || $stored !== 0) && $reported <= $stored) {
                $hook = Js::opt($expect, 'onSignCountRegression');
                if (is_callable($hook)) {
                    $hook(['storedSignCount' => $stored, 'reportedSignCount' => $reported]);
                }
                return self::fail('signCount did not increase (possible cloned authenticator)');
            }
            return ['ok' => true, 'alg' => $alg, 'signCount' => $reported, 'flags' => $parsed['flags']];
        } catch (\Throwable $e) {
            return self::fail('verification error (fail closed): ' . $e->getMessage());
        }
    }
}
