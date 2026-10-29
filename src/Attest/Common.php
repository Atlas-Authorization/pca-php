<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/../Pca.php';
require_once __DIR__ . '/../IntentWb.php';

use Atlas\Pca\IntentWb;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;

/** A JavaScript exception whose message the reference embeds in a reason string. */
final class JsError extends \RuntimeException
{
}

/** The factory refused a configuration (accept-all, a missing pin, an unknown mode). */
final class AttestConstructError extends \InvalidArgumentException
{
}

/** A structural DER problem (the message is part of the conformance contract). */
final class DerError extends \RuntimeException
{
}

/** An X.509 parse failure (the text mirrors the kind of message OpenSSL raises). */
final class CertError extends \RuntimeException
{
}

/** A compact JWS segment that is not strictly canonical. */
final class CanonicalJwsError extends \RuntimeException
{
    public function __construct(string $reason, ?string $detail = null)
    {
        parent::__construct('non-canonical compact JWS: ' . $reason . ($detail !== null && $detail !== '' ? " ($detail)" : ''));
    }
}

/**
 * An RSA / EC public key loaded from SubjectPublicKeyInfo DER (OpenSSL through PHP's openssl extension).
 */
final class PubKey
{
    /** @param array<string,mixed> $details */
    public function __construct(
        public readonly \OpenSSLAsymmetricKey $key,
        public readonly string $spki,
        public readonly string $type,
        public readonly ?string $curve,
        public readonly array $details,
        public readonly ?string $rsaN = null,
        public readonly ?string $rsaE = null,
    ) {
    }

    public function bits(): int
    {
        return (int)($this->details['bits'] ?? 0);
    }
}

/**
 * Shared plumbing of the native hardware-attestation verifiers: the report_data binding, JavaScript-faithful JSON / base64
 * helpers (the conformance vectors pin the reference's exact reason strings) and the OpenSSL glue. Needs the `openssl` and
 * `gmp` extensions (u64 policy values are held as GMP integers, as the reference holds them as BigInt).
 */
final class Common
{
    public const BIND_DOMAIN = "atlas-pca/attest-bind/v1\0";
    public const MAX_SAFE = 9007199254740991;

    // ---- JSON value access (Obj / list / scalar; absent = null) ------------------------------------------------------------

    public static function g(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        return is_array($o) ? ($o[$k] ?? null) : null;
    }

    public static function has(mixed $o, string $k): bool
    {
        return $o instanceof Obj ? $o->has($k) : (is_array($o) && array_key_exists($k, $o));
    }

    public static function isObj(mixed $o): bool
    {
        return $o instanceof Obj || (is_array($o) && !array_is_list($o));
    }

    public static function isList(mixed $o): bool
    {
        return is_array($o) && array_is_list($o);
    }

    /** A JSON number (Num or native) as a float; null for anything else (a bool or numeric string is not a number). */
    public static function numOf(mixed $v): ?float
    {
        $f = $v instanceof Num ? $v->float() : (is_int($v) ? (float)$v : (is_float($v) ? $v : null));
        return $f !== null && is_finite($f) ? $f : null;
    }

    public static function isNum(mixed $v): bool
    {
        return self::numOf($v) !== null;
    }

    public static function isInt(mixed $v): bool
    {
        $f = self::numOf($v);
        return $f !== null && floor($f) === $f;
    }

    /** The members of an object as [key => value] (an Obj or a PHP assoc array). @return array<string,mixed> */
    public static function members(mixed $o): array
    {
        if ($o instanceof Obj) {
            $out = [];
            foreach ($o->keys() as $k) {
                $out[$k] = $o->get($k);
            }
            return $out;
        }
        return is_array($o) && !array_is_list($o) ? $o : [];
    }

    /** String(v) for the values that reach a reason text (an absent value is `undefined`). */
    public static function jsStr(mixed $v): string
    {
        if ($v === null) {
            return 'undefined';
        }
        return IntentWb::jsStr($v instanceof Obj ? '[object Object]' : $v);
    }

    public static function numStr(float $f): string
    {
        return IntentWb::jsNumStr($f);
    }

    // ---- the binding ---------------------------------------------------------------------------------------------------------

    private static function utf8(string $s): string
    {
        // a lone surrogate (WTF-8) encodes as U+FFFD in JavaScript
        return preg_replace('/\xED[\xA0-\xBF][\x80-\xBF]/', "\xEF\xBF\xBD", $s) ?? $s;
    }

    private static function lp(string $s): string
    {
        $b = self::utf8($s);
        return pack('N', strlen($b)) . $b;
    }

    /** SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)), the report_data / quote-bound value. Throws AttestException. */
    public static function attestationBinding(mixed $exp): string
    {
        $holder = self::g($exp, 'holderPub') ?? self::g($exp, 'holder_pub');
        $grant = self::g($exp, 'grantRef') ?? self::g($exp, 'grant_ref');
        $epoch = self::g($exp, 'epoch');
        $nonce = self::g($exp, 'nonce');
        if (!self::isObj($exp) || !is_string($holder) || $holder === '') {
            throw new \TypeError('binding: holderPub required');
        }
        if (!is_string($grant) || $grant === '') {
            throw new \TypeError('binding: grantRef required');
        }
        if (!is_string($nonce) || $nonce === '') {
            throw new \TypeError('binding: nonce required');
        }
        $f = self::numOf($epoch);
        if ($f === null || floor($f) !== $f || $f < 0 || $f > self::MAX_SAFE) {
            throw new \TypeError('binding: epoch must be a non-negative safe integer');
        }
        return hash('sha512', self::BIND_DOMAIN . self::lp($holder) . self::lp($grant) . pack('J', (int)$f) . self::lp($nonce), true);
    }

    /** The 32-byte SPDM challenge that carries the PCA binding: SHA-256(attestationBinding(expected)). */
    public static function challengeSha256(mixed $exp): string
    {
        return hash('sha256', self::attestationBinding($exp), true);
    }

    // ---- JS-faithful helpers ---------------------------------------------------------------------------------------------------

    public static function toHex(string $b): string
    {
        return bin2hex($b);
    }

    /** Node's lenient Buffer.from(s, 'base64'): both alphabets, illegal characters skipped, stops at '='. */
    public static function nodeB64Decode(string $s): string
    {
        $out = '';
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $ch = $s[$i];
            if ($ch === '=') {
                break;
            }
            if ($ch === '-') {
                $ch = '+';
            } elseif ($ch === '_') {
                $ch = '/';
            }
            if (ctype_alnum($ch) || $ch === '+' || $ch === '/') {
                $out .= $ch;
            }
        }
        if (strlen($out) % 4 === 1) {
            $out = substr($out, 0, -1);
        }
        $out .= str_repeat('=', (4 - strlen($out) % 4) % 4);
        $d = base64_decode($out, false);
        return $d === false ? '' : $d;
    }

    public static function jsTrim(string $s): string
    {
        $c = '[\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]+';
        return @preg_replace("/\\A$c|$c\\z/u", '', $s) ?? trim($s);
    }

    /** Number(string) for the values the reference converts (a measurement index). */
    public static function jsNumber(string $s): float
    {
        $t = self::jsTrim($s);
        if ($t === '') {
            return 0.0;
        }
        if (preg_match('/\A0[xX][0-9a-fA-F]+\z/', $t)) {
            return (float)hexdec(substr($t, 2));
        }
        if (preg_match('/\A0[oO][0-7]+\z/', $t)) {
            return (float)octdec(substr($t, 2));
        }
        if (preg_match('/\A0[bB][01]+\z/', $t)) {
            return (float)bindec(substr($t, 2));
        }
        if (preg_match('/\A[+-]?Infinity\z/', $t)) {
            return $t[0] === '-' ? -INF : INF;
        }
        if (preg_match('/\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/', $t)) {
            return (float)$t;
        }
        return NAN;
    }

    /** BigInt(v) for a decimal string or an integer (JavaScript's text on anything else). */
    public static function bigInt(mixed $v): \GMP
    {
        if (!extension_loaded('gmp')) {
            throw new \RuntimeException('the attestation verifiers need the gmp extension');
        }
        if ($v === null) {
            throw new JsError('Cannot convert null to a BigInt');
        }
        if (is_bool($v)) {
            return gmp_init($v ? 1 : 0);
        }
        if ($v instanceof Num || is_int($v) || is_float($v)) {
            $f = self::numOf($v);
            if ($f !== null && floor($f) === $f) {
                return $v instanceof Num && $v->isInt() ? gmp_init($v->lexeme) : gmp_init(sprintf('%.0f', $f));
            }
            throw new JsError('The number ' . self::jsStr($v) . ' cannot be converted to a BigInt because it is not an integer');
        }
        if (is_string($v)) {
            $t = self::jsTrim($v);
            if ($t === '') {
                return gmp_init(0);
            }
            if (preg_match('/\A[+-]?\d+\z/', $t)) {
                return gmp_init(ltrim($t, '+'));
            }
            if (preg_match('/\A0[xX][0-9a-fA-F]+\z/', $t)) {
                return gmp_init(substr($t, 2), 16);
            }
            if (preg_match('/\A0[oO][0-7]+\z/', $t)) {
                return gmp_init(substr($t, 2), 8);
            }
            if (preg_match('/\A0[bB][01]+\z/', $t)) {
                return gmp_init(substr($t, 2), 2);
            }
            throw new JsError("Cannot convert $v to a BigInt");
        }
        throw new JsError('Cannot convert ' . self::jsStr($v) . ' to a BigInt');
    }

    public static function isHex(string $s): bool
    {
        return $s !== '' && strlen($s) % 2 === 0 && preg_match('/\A[0-9a-fA-F]+\z/', $s) === 1;
    }

    /** A byte-carrying claim: hex (optionally 0x-prefixed), else base64url, else base64; null when it decodes to nothing. */
    public static function decodeClaimBytes(string $value): ?string
    {
        $trimmed = self::jsTrim($value);
        $hx = str_starts_with($trimmed, '0x') || str_starts_with($trimmed, '0X') ? substr($trimmed, 2) : $trimmed;
        if (self::isHex($hx)) {
            return (string)hex2bin($hx);
        }
        $out = self::nodeB64Decode($trimmed);
        return $out !== '' ? $out : null;
    }

    // ---- strict base64url / compact JWS --------------------------------------------------------------------------------------

    public static function decodeCanonicalB64url(string $seg): string
    {
        if (preg_match('/\A[A-Za-z0-9_-]*\z/', $seg) !== 1) {
            throw new CanonicalJwsError('bad-character');
        }
        if (strlen($seg) % 4 === 1) {
            throw new CanonicalJwsError('non-canonical-base64url', 'impossible length');
        }
        $raw = (string)base64_decode(strtr($seg, '-_', '+/') . str_repeat('=', (4 - strlen($seg) % 4) % 4), true);
        if (rtrim(strtr(base64_encode($raw), '+/', '-_'), '=') !== $seg) {
            throw new CanonicalJwsError('non-canonical-base64url');
        }
        return $raw;
    }

    public static function asStr(mixed $v): ?string
    {
        return is_string($v) ? $v : null;
    }

    /** @return list<string>|null */
    public static function asStrList(mixed $v): ?array
    {
        if (!self::isList($v)) {
            return null;
        }
        foreach ($v as $x) {
            if (!is_string($x)) {
                return null;
            }
        }
        return $v;
    }

    /** The first present, non-empty string claim across candidate keys. */
    public static function firstString(mixed $rec, array $keys): ?string
    {
        foreach ($keys as $k) {
            $v = self::asStr(self::g($rec, $k));
            if ($v !== null && $v !== '') {
                return $v;
            }
        }
        return null;
    }

    /**
     * A compact JWS into {header, payload, signingInput, signature}. Throws \TypeError with the reference's messages; verifies nothing.
     * @return array{header: array<string,mixed>, payload: mixed, signingInput: string, signature: string}
     */
    public static function parseJws(mixed $token, string $fn): array
    {
        if (!is_string($token) || $token === '') {
            throw new \TypeError("$fn: empty token");
        }
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new \TypeError("$fn: a compact JWS has exactly three dot-separated parts");
        }
        [$h, $p, $s] = $parts;
        if ($h === '' || $p === '' || $s === '') {
            throw new \TypeError("$fn: empty JWS segment");
        }
        try {
            $headerObj = JsJson::parse(self::scrubUtf8(self::decodeCanonicalB64url($h)));
            $payloadObj = JsJson::parse(self::scrubUtf8(self::decodeCanonicalB64url($p)));
        } catch (JsError | CanonicalJwsError $e) {
            throw new \TypeError("$fn: malformed JSON segment: " . $e->getMessage());
        }
        if (!($headerObj instanceof Obj)) {
            throw new \TypeError("$fn: header is not a JSON object");
        }
        if (!($payloadObj instanceof Obj)) {
            throw new \TypeError("$fn: payload is not a JSON object");
        }
        $alg = self::asStr($headerObj->get('alg'));
        if ($alg === null || $alg === '') {
            throw new \TypeError("$fn: header has no alg");
        }
        $header = ['alg' => $alg];
        foreach (['kid', 'jku', 'typ'] as $k) {
            if (self::asStr($headerObj->get($k)) !== null) {
                $header[$k] = $headerObj->get($k);
            }
        }
        $x5c = self::asStrList($headerObj->get('x5c'));
        if ($x5c !== null) {
            $header['x5c'] = $x5c;
        }
        try {
            $signature = self::decodeCanonicalB64url($s);
        } catch (CanonicalJwsError $e) {
            throw new \TypeError("$fn: malformed signature segment: " . $e->getMessage());
        }
        if ($signature === '') {
            throw new \TypeError("$fn: empty signature");
        }
        return ['header' => $header, 'payload' => $payloadObj, 'signingInput' => $h . '.' . $p, 'signature' => $signature];
    }

    /** UTF-8 decode with replacement (U+FFFD) of invalid sequences, as a lenient TextDecoder does. */
    private static function scrubUtf8(string $s): string
    {
        if (preg_match('//u', $s) === 1) {
            return $s;
        }
        return (string)mb_convert_encoding($s, 'UTF-8', 'UTF-8');
    }

    public static function transformBinding(string $binding, mixed $mode): string
    {
        if ($mode === 'sha256') {
            return hash('sha256', $binding, true);
        }
        if ($mode === 'sha512') {
            return hash('sha512', $binding, true);
        }
        return $binding;
    }

    // ---- PEM -----------------------------------------------------------------------------------------------------------------------

    /** @return list<string> */
    public static function pemBlocks(string $pem): array
    {
        preg_match_all('/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/', $pem, $m);
        return $m[0];
    }

    public static function pemToDer(string $pem): string
    {
        if (preg_match('/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/', $pem, $m) !== 1 || $m[1] === '') {
            throw new \InvalidArgumentException('pemToDer: no certificate found');
        }
        return self::nodeB64Decode(preg_replace('/\s+/', '', $m[1]) ?? '');
    }

    // ---- OpenSSL glue --------------------------------------------------------------------------------------------------------------

    /** The last OpenSSL error text (the queue is drained). */
    public static function opensslError(): string
    {
        $last = '';
        while (($e = openssl_error_string()) !== false) {
            $last = $e;
        }
        return $last;
    }

    private static function pemOfSpki(string $spki): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** Load a public key from SubjectPublicKeyInfo DER. Throws CertError. */
    public static function loadPublicKey(string $spki): PubKey
    {
        self::opensslError();
        $k = @openssl_pkey_get_public(self::pemOfSpki($spki));
        if ($k === false) {
            $why = self::opensslError();
            throw new CertError($why !== '' ? $why : 'error:1E08010C:DECODER routines::unsupported');
        }
        $d = openssl_pkey_get_details($k) ?: [];
        $type = match ($d['type'] ?? -1) {
            OPENSSL_KEYTYPE_EC => 'ec',
            OPENSSL_KEYTYPE_RSA => 'rsa',
            OPENSSL_KEYTYPE_DSA => 'dsa',
            OPENSSL_KEYTYPE_DH => 'dh',
            default => 'unknown',
        };
        $n = $e = null;
        // the SPKI algorithm decides, not PHP's report: RSASSA-PSS-restricted keys come back as 'unknown' (8.3+) or even 'ec' (8.1 / 8.2)
        $ne = self::rsaNe($spki);
        if ($ne !== null) {
            [$n, $e] = $ne;
            $type = 'rsa';
        }
        return new PubKey($k, $spki, $type, $type === 'ec' ? ($d['ec']['curve_name'] ?? null) : null, $d, $n, $e);
    }

    /** One DER element at `$off`: [tag, contentStart, contentEnd] or null. */
    private static function tlv(string $b, int $off): ?array
    {
        if ($off + 2 > strlen($b)) {
            return null;
        }
        $tag = ord($b[$off]);
        $ln = ord($b[$off + 1]);
        $p = $off + 2;
        if (($ln & 0x80) !== 0) {
            $n = $ln & 0x7F;
            if ($n < 1 || $n > 4 || $p + $n > strlen($b)) {
                return null;
            }
            $ln = 0;
            for ($i = 0; $i < $n; $i++) {
                $ln = ($ln << 8) | ord($b[$p + $i]);
            }
            $p += $n;
        }
        return $p + $ln <= strlen($b) ? [$tag, $p, $p + $ln] : null;
    }

    /** The modulus and exponent (big-endian bytes) of an rsaEncryption / RSASSA-PSS SubjectPublicKeyInfo, else null. @return array{0:string,1:string}|null */
    private static function rsaNe(string $spki): ?array
    {
        $seq = self::tlv($spki, 0);
        if ($seq === null || $seq[0] !== 0x30) {
            return null;
        }
        $alg = self::tlv($spki, $seq[1]);
        if ($alg === null || $alg[0] !== 0x30) {
            return null;
        }
        $oid = self::tlv($spki, $alg[1]);
        if ($oid === null || $oid[0] !== 0x06 || !in_array(bin2hex(substr($spki, $oid[1], $oid[2] - $oid[1])), ['2a864886f70d010101', '2a864886f70d01010a'], true)) {
            return null;
        }
        $bits = self::tlv($spki, $alg[2]);
        if ($bits === null || $bits[0] !== 0x03) {
            return null;
        }
        $inner = substr($spki, $bits[1] + 1, $bits[2] - $bits[1] - 1);
        $rs = self::tlv($inner, 0);
        if ($rs === null || $rs[0] !== 0x30) {
            return null;
        }
        $n = self::tlv($inner, $rs[1]);
        $e = $n === null ? null : self::tlv($inner, $n[2]);
        if ($n === null || $e === null || $n[0] !== 0x02 || $e[0] !== 0x02) {
            return null;
        }
        return [ltrim(substr($inner, $n[1], $n[2] - $n[1]), "\0"), ltrim(substr($inner, $e[1], $e[2] - $e[1]), "\0")];
    }

    /** The OpenSSL name of an EC key's curve (prime256v1, secp384r1, ...), null for a non-EC key. */
    public static function nodeCurve(PubKey $k): ?string
    {
        return $k->curve;
    }

    /** The JWK name of an EC key's curve (P-256, P-384, P-521). */
    public static function jwkCurve(PubKey $k): ?string
    {
        return match ($k->curve) {
            'prime256v1' => 'P-256', 'secp384r1' => 'P-384', 'secp521r1' => 'P-521', null => null, default => $k->curve,
        };
    }

    public static function spkiSha(PubKey $k, string $algo): string
    {
        return hash($algo, $k->spki);
    }

    /** The uncompressed SEC1 point of an EC key on exactly `$curve` ('P-256' | 'P-384'). Throws \TypeError otherwise. */
    public static function ecPoint(PubKey $k, string $curve): string
    {
        $coord = ['P-256' => 32, 'P-384' => 48][$curve];
        if ($k->type !== 'ec') {
            throw new \TypeError('public key is not EC (got ' . $k->type . ')');
        }
        if (self::jwkCurve($k) !== $curve) {
            throw new \TypeError("public key is not on $curve (got " . self::jwkCurve($k) . ')');
        }
        $ec = $k->details['ec'];
        return "\x04" . str_pad($ec['x'], $coord, "\0", STR_PAD_LEFT) . str_pad($ec['y'], $coord, "\0", STR_PAD_LEFT);
    }

    /** Validate and load an uncompressed SEC1 point on `$curve`; throws \ValueError off the curve. */
    public static function ecKeyFromPoint(string $curve, string $point): PubKey
    {
        $oid = $curve === 'P-256' ? "\x2A\x86\x48\xCE\x3D\x03\x01\x07" : "\x2B\x81\x04\x00\x22";
        $alg = "\x30" . chr(strlen("\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06" . chr(strlen($oid)) . $oid) + 0) . "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06" . chr(strlen($oid)) . $oid;
        $bits = "\x03" . chr(strlen($point) + 1) . "\x00" . $point;
        $body = $alg . $bits;
        $spki = "\x30" . chr(strlen($body)) . $body;
        try {
            return self::loadPublicKey($spki);
        } catch (CertError $e) {
            throw new \ValueError($e->getMessage());
        }
    }

    private static function derSeq(string $body, int $tag = 0x30): string
    {
        return chr($tag) . self::derLen(strlen($body)) . $body;
    }

    /** SubjectPublicKeyInfo DER of an RSA key from big-endian modulus and exponent. */
    public static function rsaSpki(string $n, string $e): string
    {
        $alg = self::derSeq("\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00");
        $key = self::derSeq(self::derInt($n) . self::derInt($e));
        return self::derSeq($alg . self::derSeq("\x00" . $key, 0x03));
    }

    /** SubjectPublicKeyInfo DER of an EC key (P-256 / P-384 / P-521) from big-endian coordinates. */
    public static function ecSpki(string $crv, string $x, string $y): string
    {
        $c = ['P-256' => [32, "\x2A\x86\x48\xCE\x3D\x03\x01\x07"], 'P-384' => [48, "\x2B\x81\x04\x00\x22"], 'P-521' => [66, "\x2B\x81\x04\x00\x23"]][$crv];
        $alg = self::derSeq("\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01" . "\x06" . chr(strlen($c[1])) . $c[1]);
        $pt = "\x04" . str_pad(ltrim($x, "\0"), $c[0], "\0", STR_PAD_LEFT) . str_pad(ltrim($y, "\0"), $c[0], "\0", STR_PAD_LEFT);
        return self::derSeq($alg . self::derSeq("\x00" . $pt, 0x03));
    }

    /** ECDSA over a DER signature. False for a non-EC key or an invalid signature (never throws). */
    public static function ecdsaVerifyDer(PubKey $k, string $sigDer, string $data, string $hash): bool
    {
        if ($k->type !== 'ec') {
            return false;
        }
        self::opensslError();
        $r = @openssl_verify($data, $sigDer, $k->key, $hash);
        self::opensslError();
        return $r === 1;
    }

    /** ECDSA over an IEEE P1363 signature (r || s, equal halves). */
    public static function ecdsaVerifyRaw(PubKey $k, string $sig, string $data, string $hash): bool
    {
        if ($k->type !== 'ec') {
            return false;
        }
        $half = intdiv($k->bits() + 7, 8);
        if (strlen($sig) !== 2 * $half) {
            return false;
        }
        $r = substr($sig, 0, $half);
        $s = substr($sig, $half);
        if (trim($r, "\0") === '' || trim($s, "\0") === '') {
            return false;
        }
        return self::ecdsaVerifyDer($k, self::dssSignature($r, $s), $data, $hash);
    }

    private static function derInt(string $be): string
    {
        $be = ltrim($be, "\0");
        if ($be === '') {
            $be = "\0";
        }
        if ((ord($be[0]) & 0x80) !== 0) {
            $be = "\0" . $be;
        }
        return "\x02" . self::derLen(strlen($be)) . $be;
    }

    public static function derLen(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $b = ltrim(pack('N', $n), "\0");
        return chr(0x80 | strlen($b)) . $b;
    }

    /** DER Ecdsa-Sig-Value from big-endian r and s. */
    public static function dssSignature(string $r, string $s): string
    {
        $body = self::derInt($r) . self::derInt($s);
        return "\x30" . self::derLen(strlen($body)) . $body;
    }

    public static function rsaPkcs1Verify(PubKey $k, string $sig, string $data, string $hash): bool
    {
        if ($k->type !== 'rsa') {
            return false;
        }
        self::opensslError();
        $r = @openssl_verify($data, $sig, $k->key, $hash);
        self::opensslError();
        return $r === 1;
    }

    private static function mgf1(string $seed, int $len, string $hash): string
    {
        $out = '';
        for ($c = 0; strlen($out) < $len; $c++) {
            $out .= hash($hash, $seed . pack('N', $c), true);
        }
        return substr($out, 0, $len);
    }

    /** RSASSA-PSS verification (EMSA-PSS-VERIFY over the raw public-key operation), exact salt length. */
    public static function rsaPssVerify(PubKey $k, string $sig, string $msg, string $hash, string $mgfHash, int $salt): bool
    {
        if ($k->type !== 'rsa') {
            return false;
        }
        if ($k->rsaN === null || $k->rsaE === null || $k->rsaN === '') {
            return false;
        }
        $modBits = strlen(gmp_strval(gmp_import($k->rsaN), 2));
        $kLen = intdiv($modBits + 7, 8);
        if (strlen($sig) !== $kLen || $salt < 0) {
            return false;
        }
        $c = gmp_import($sig);
        $nn = gmp_import((string)$k->rsaN);
        if ($k->rsaN === null || $k->rsaE === null || gmp_cmp($c, $nn) >= 0) {
            return false;
        }
        $dec = gmp_export(gmp_powm($c, gmp_import($k->rsaE), $nn));
        $emBits = $modBits - 1;
        $emLen = intdiv($emBits + 7, 8);
        $em = substr(str_pad($dec, $kLen, "\0", STR_PAD_LEFT), $kLen - $emLen);
        $hLen = strlen(hash($hash, '', true));
        $mHash = hash($hash, $msg, true);
        if ($emLen < $hLen + $salt + 2 || ord($em[$emLen - 1]) !== 0xBC) {
            return false;
        }
        $maskedDb = substr($em, 0, $emLen - $hLen - 1);
        $h = substr($em, $emLen - $hLen - 1, $hLen);
        $zeroBits = 8 * $emLen - $emBits;
        if ((ord($maskedDb[0]) & (0xFF << (8 - $zeroBits)) & 0xFF) !== 0 && $zeroBits > 0) {
            return false;
        }
        $db = $maskedDb ^ self::mgf1($h, strlen($maskedDb), $mgfHash);
        if ($zeroBits > 0) {
            $db[0] = chr(ord($db[0]) & (0xFF >> $zeroBits));
        }
        $padLen = $emLen - $hLen - $salt - 2;
        for ($i = 0; $i < $padLen; $i++) {
            if ($db[$i] !== "\0") {
                return false;
            }
        }
        if ($db[$padLen] !== "\x01") {
            return false;
        }
        $saltBytes = $salt > 0 ? substr($db, -$salt) : '';
        return hash_equals($h, hash($hash, str_repeat("\0", 8) . $mHash . $saltBytes, true));
    }
}
