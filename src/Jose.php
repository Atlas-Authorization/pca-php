<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Attest/Common.php';

use Atlas\Pca\Attest\CanonicalJwsError;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\PubKey;

/** A refusal of the JOSE layer (bad header, algorithm not allowed, bad key, signature or claim failure). */
/** A TypeError that carries the reference runtime's error code (ERR_INVALID_ARG_TYPE, ERR_INVALID_URL). */
final class NodeTypeError extends \TypeError
{
    public function __construct(string $message, public readonly string $codeName)
    {
        parent::__construct($message);
    }
}

/** An InvalidArgumentException that carries the reference runtime's error code. */
final class NodeArgError extends \InvalidArgumentException
{
    public function __construct(string $message, public readonly string $codeName)
    {
        parent::__construct($message);
    }
}

final class JoseError extends \RuntimeException
{
    /** The reference library's stable error code for the same failure, picked by the failure text (null when it has none). */
    public readonly ?string $codeName;

    private const CODES = [
        ['/\A"exp" claim timestamp check failed\z/', 'ERR_JWT_EXPIRED'],
        ['/\AJWTs MUST NOT use unencoded payload|\AJWT Claims Set must be/', 'ERR_JWT_INVALID'],
        ['/ claim (must be a number|timestamp check failed)|\Amissing required ".*" claim\z|\Aunexpected ".*" (claim|JWT header) value\z/', 'ERR_JWT_CLAIM_VALIDATION_FAILED'],
        ['/\Asignature verification failed\z/', 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'],
        ['/\A"alg" \(Algorithm\) Header Parameter value not allowed\z/', 'ERR_JOSE_ALG_NOT_ALLOWED'],
        ['/\AJWS |\A"crit" \(Critical\) Header Parameter MUST|\AThe "b64" /', 'ERR_JWS_INVALID'],
        ['/is not recognized\z|is not supported either by JOSE|"kty" \(Key Type\) Parameter missing or unsupported/', 'ERR_JOSE_NOT_SUPPORTED'],
        ['/\Ano applicable key found in the JSON Web Key Set/', 'ERR_JWKS_NO_MATCHING_KEY'],
        ['/\Amultiple matching keys found/', 'ERR_JWKS_MULTIPLE_MATCHING_KEYS'],
        ['/\AJSON Web Key Set/', 'ERR_JWKS_INVALID'],
        ['/Parameter missing or invalid\z/', 'ERR_JWK_INVALID'],
        ['/\AInvalid key for this operation(: raw bytes are only an Ed25519 public key.*)?\z/', 'ERR_OSSL_INVALID_DIGEST'], // an Ed25519 key under an ES256 / RS256 algorithm
    ];

    public function __construct(string $message = '', int $code = 0, ?\Throwable $previous = null, ?string $codeName = null)
    {
        parent::__construct($message, $code, $previous);
        $name = $codeName;
        foreach ($codeName !== null ? [] : self::CODES as [$re, $c]) {
            if (preg_match($re, $message) === 1) {
                $name = $c;
                break;
            }
        }
        $this->codeName = $name;
    }
}

/**
 * The JOSE layer the protocol bridges share: the canonical compact-JWS gate (one accepted spelling per token, run BEFORE any
 * signature check) and JWS / JWT sign + verify with the reference JOSE library's semantics (check order and messages): crit,
 * alg allow-list, signature, typ, required claims, iss / sub / aud, iat / nbf / exp with clock tolerance. Verification keys: a
 * raw 32-byte Ed25519 public key (binary string), a public JWK (Obj or array: OKP Ed25519, EC P-256/384/521, RSA >= 2048 bits),
 * a loaded PubKey or an OpenSSL key. Ed25519 is libsodium, Ed448 is OpenSSL over ext-ffi (OpensslEd448), everything else OpenSSL.
 */
final class Jose
{
    public const DEFAULT_MAX_JWS_BYTES = 65536;
    /** Pass as the key to verify under the protected header's own `jwk` (jose EmbeddedJWK). */
    public const EMBEDDED_JWK = "\0embedded-jwk";
    /** alg => [kind, hash, coordinate bytes] */
    private const ALGS = [
        'EdDSA' => ['ed', null, 0],
        'ES256' => ['P-256', 'sha256', 32], 'ES384' => ['P-384', 'sha384', 48], 'ES512' => ['P-521', 'sha512', 66],
        'RS256' => ['rsa', 'sha256', 0], 'RS384' => ['rsa', 'sha384', 0], 'RS512' => ['rsa', 'sha512', 0],
        'PS256' => ['pss', 'sha256', 0], 'PS384' => ['pss', 'sha384', 0], 'PS512' => ['pss', 'sha512', 0],
    ];

    public static function b64u(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /** The JOSE library's lenient base64url decoder: padding and whitespace ignored, the standard alphabet tolerated. */
    public static function lenientB64d(mixed $s): string
    {
        $t = str_replace(['=', ' ', "\t", "\n", "\r"], '', strtr(is_string($s) ? $s : '', '-_', '+/'));
        $r = strlen($t) % 4 === 1 ? false : base64_decode($t . str_repeat('=', (4 - strlen($t) % 4) % 4), true);
        if ($r === false) {
            throw new JoseError('Failed to base64url decode');
        }
        return $r;
    }

    /** The bytes of a private JWK member; an undecodable one is the runtime's invalid-JWK refusal. */
    private static function jwkPrivateBytes(mixed $s): string
    {
        try {
            return self::lenientB64d($s);
        } catch (JoseError) {
            throw new JoseError('Invalid JWK OKP key', 0, null, 'ERR_CRYPTO_INVALID_JWK');
        }
    }

    // ---- canonical gate ----

    public static function decodeCanonicalBase64url(string $seg): string
    {
        return Common::decodeCanonicalB64url($seg);
    }

    /** Strict-JSON document from bytes: no BOM, valid UTF-8, the strict profile (no duplicate keys, canonical numbers). */
    public static function parseJsonBytes(string $bytes): mixed
    {
        if (str_starts_with($bytes, "\xEF\xBB\xBF")) {
            throw new CanonicalJwsError('bom');
        }
        if (preg_match('//u', $bytes) !== 1) {
            throw new CanonicalJwsError('bad-utf8');
        }
        try {
            return Json::parseStrict($bytes);
        } catch (JsonError $e) {
            throw new CanonicalJwsError('bad-json', $e->getMessage());
        }
    }

    public static function decodeCanonicalJsonSegment(string $seg): mixed
    {
        return self::parseJsonBytes(self::decodeCanonicalBase64url($seg));
    }

    private static function asObject(mixed $v): Obj
    {
        if (!($v instanceof Obj)) {
            throw new CanonicalJwsError('not-an-object');
        }
        return $v;
    }

    /**
     * The one canonical spelling of a compact JWS (parts 3) / JWE (parts 5). Throws CanonicalJwsError otherwise.
     * @return array{segments: list<string>, header: Obj, payload?: Obj}
     */
    public static function assertCanonicalCompactJws(mixed $token, int $parts = 3, int $maxBytes = self::DEFAULT_MAX_JWS_BYTES, string $payload = 'json'): array
    {
        if (!is_string($token)) {
            throw new CanonicalJwsError('not-a-string');
        }
        if (Js::len($token) > $maxBytes) {
            throw new CanonicalJwsError('too-long');
        }
        $segments = explode('.', $token);
        if (count($segments) !== $parts) {
            throw new CanonicalJwsError('bad-segment-count', count($segments) . " != $parts");
        }
        $bytes = [];
        foreach ($segments as $i => $seg) {
            if ($seg === '') {
                if ($parts === 5 && $i === 1) {
                    $bytes[] = '';
                    continue;
                }
                throw new CanonicalJwsError('empty-segment', "segment $i");
            }
            $bytes[] = self::decodeCanonicalBase64url($seg);
        }
        $out = ['segments' => $segments, 'header' => self::asObject(self::parseJsonBytes($bytes[0]))];
        if ($parts === 3 && $payload === 'json') {
            $out['payload'] = self::asObject(self::parseJsonBytes($bytes[1]));
        }
        return $out;
    }

    public static function isCanonicalCompactJws(mixed $token, int $parts = 3): bool
    {
        try {
            self::assertCanonicalCompactJws($token, $parts);
            return true;
        } catch (CanonicalJwsError) {
            return false;
        }
    }

    /** The protected header of a flattened / detached JWS (payload out of band), through the same gate. */
    public static function assertCanonicalJwsSegments(mixed $protected, mixed $signature, int $maxBytes = self::DEFAULT_MAX_JWS_BYTES): Obj
    {
        if (!is_string($protected) || !is_string($signature)) {
            throw new CanonicalJwsError('not-a-string');
        }
        if (strlen($protected) + strlen($signature) > $maxBytes) {
            throw new CanonicalJwsError('too-long');
        }
        if ($protected === '' || $signature === '') {
            throw new CanonicalJwsError('empty-segment');
        }
        $h = self::asObject(self::parseJsonBytes(self::decodeCanonicalBase64url($protected)));
        self::decodeCanonicalBase64url($signature);
        return $h;
    }

    // ---- keys ----

    private static function bytesOf(mixed $s): string
    {
        if (!is_string($s)) {
            throw new JoseError('JWK member must be a string');
        }
        return self::lenientB64d($s);
    }

    /** A verification key from a PUBLIC JWK: ['ed', 32-byte key] or ['pk', PubKey]. */
    public static function publicKeyFromJwk(mixed $jwk): array
    {
        $kty = Js::opt($jwk, 'kty');
        if (!Js::isObj($jwk) || !is_string($kty) || Js::opt($jwk, 'd') !== null) {
            throw new JoseError('JSON Web Key for this operation must be a public JWK');
        }
        if ($kty === 'OKP') {
            $crv = Js::opt($jwk, 'crv');
            if (($crv !== 'Ed25519' && $crv !== 'Ed448') || !is_string(Js::opt($jwk, 'x'))) {
                throw new JoseError('unsupported OKP key');
            }
            // the runtime's base64url decoder skips characters outside the alphabet
            $x = self::lenientB64d((string)preg_replace('/[^A-Za-z0-9_\-+\/=]/', '', Js::opt($jwk, 'x')));
            if ($crv === 'Ed448') { // verified through OpenSSL (ext-ffi): OpensslEd448
                if (strlen($x) !== OpensslEd448::KEY_BYTES) {
                    throw new JoseError('invalid Ed448 public key');
                }
                return ['ed448', $x];
            }
            if (strlen($x) !== 32) {
                throw new JoseError('invalid Ed25519 public key');
            }
            return ['ed', $x];
        }
        try {
            if ($kty === 'EC') {
                $crv = Js::opt($jwk, 'crv');
                $size = ['P-256' => 32, 'P-384' => 48, 'P-521' => 66][is_string($crv) ? $crv : ''] ?? null;
                if ($size === null) {
                    throw new JoseError('unsupported EC curve');
                }
                $x = ltrim(self::bytesOf(Js::opt($jwk, 'x')), "\0");
                $y = ltrim(self::bytesOf(Js::opt($jwk, 'y')), "\0");
                if (strlen($x) > $size || strlen($y) > $size) {
                    throw new JoseError('invalid EC public key');
                }
                return ['pk', Common::loadPublicKey(Common::ecSpki($crv, $x, $y))];
            }
            if ($kty === 'RSA') {
                if (Js::has($jwk, 'oth')) {
                    throw new JoseError('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
                }
                return ['pk', Common::loadPublicKey(Common::rsaSpki(self::bytesOf(Js::opt($jwk, 'n')), self::bytesOf(Js::opt($jwk, 'e'))))];
            }
        } catch (JoseError $e) {
            throw $e;
        } catch (\Throwable) {
            throw new JoseError("invalid $kty public key");
        }
        throw new JoseError('Unsupported "kty" (Key Type) Parameter value');
    }

    private static function jwkMatches(string $alg, mixed $k): void
    {
        if (Js::opt($k, 'use') !== null && Js::opt($k, 'use') !== 'sig') {
            throw new JoseError('Invalid key for this operation, when present its use must be sig');
        }
        $ops = Js::opt($k, 'key_ops');
        if ($ops !== null && !(is_array($ops) && in_array('verify', $ops, true))) {
            throw new JoseError('Invalid key for this operation, when present its key_ops must include verify');
        }
        if (Js::opt($k, 'alg') !== null && Js::opt($k, 'alg') !== $alg) {
            throw new JoseError("Invalid key for this operation, when present its alg must be $alg");
        }
    }

    /** Normalize a caller key to ['ed', raw] or ['pk', PubKey] valid for `$alg`. */
    public static function verifyKey(string $alg, mixed $key, bool $embedded = false): array
    {
        $a = self::ALGS[$alg] ?? null;
        if ($a === null) {
            throw new JoseError('Unsupported "alg" value for a JSON Web Signature Algorithm');
        }
        if (is_string($key)) {
            if ($alg !== 'EdDSA') {
                throw new JoseError('Invalid key for this operation: raw bytes are only an Ed25519 public key');
            }
            if (strlen($key) !== 32) {
                throw new JoseError('invalid Ed25519 public key');
            }
            return ['ed', $key];
        }
        if (Js::isObj($key)) {
            if (Js::opt($key, 'kty') === 'oct') {
                throw new JoseError('Invalid key for this operation: a symmetric key');
            }
            if (!$embedded) {
                self::jwkMatches($alg, $key);
            }
            // a private JWK verifies through its public part, as the runtime's key import does
            $k = self::publicKeyFromJwk($key instanceof Obj ? $key->without('d', 'p', 'q', 'dp', 'dq', 'qi') : $key);
        } elseif ($key instanceof PubKey) {
            $k = ['pk', $key];
        } elseif ($key instanceof \OpenSSLAsymmetricKey) {
            $d = openssl_pkey_get_details($key);
            $pem = is_array($d) ? ($d['key'] ?? '') : '';
            if (preg_match('/-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/', $pem, $m) !== 1) {
                throw new JoseError('Invalid key for this operation');
            }
            $k = ['pk', Common::loadPublicKey((string)base64_decode((string)preg_replace('/\s+/', '', $m[1])))];
        } else {
            throw new JoseError('Invalid key for this operation');
        }
        if ($alg === 'EdDSA') {
            if ($k[0] !== 'ed' && $k[0] !== 'ed448') {
                throw new JoseError('Invalid key for this operation: EdDSA needs an Ed25519 or Ed448 key');
            }
            return $k;
        }
        if ($k[0] !== 'pk') {
            throw new JoseError("Invalid key for this operation: $alg needs an " . ($a[0] === 'rsa' || $a[0] === 'pss' ? 'RSA' : 'EC') . ' key');
        }
        $pk = $k[1];
        if ($a[0] === 'rsa' || $a[0] === 'pss') {
            if ($pk->type !== 'rsa') {
                throw new JoseError("Invalid key for this operation: $alg needs an RSA key");
            }
            if (strlen(gmp_strval(gmp_import((string)$pk->rsaN), 2)) < 2048) {
                throw new JoseError("$alg requires key modulusLength to be 2048 bits or larger");
            }
        } elseif ($pk->type !== 'ec' || Common::jwkCurve($pk) !== $a[0]) {
            throw new JoseError("Invalid key for this operation: $alg needs an EC {$a[0]} key");
        }
        return $k;
    }

    /** Signature check only. Throws JoseError for an unusable key / algorithm; false for a bad signature. */
    public static function jwsVerify(string $alg, mixed $key, string $sig, string $data, bool $embedded = false): bool
    {
        $k = self::verifyKey($alg, $key, $embedded);
        [$kind, $h] = self::ALGS[$alg];
        if ($kind === 'ed') {
            if ($k[0] === 'ed448') {
                return OpensslEd448::verify($k[1], $sig, $data);
            }
            try {
                return strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES && sodium_crypto_sign_verify_detached($sig, $data, $k[1]);
            } catch (\SodiumException) {
                return false;
            }
        }
        if ($kind === 'rsa') {
            return Common::rsaPkcs1Verify($k[1], $sig, $data, $h);
        }
        if ($kind === 'pss') {
            return Common::rsaPssVerify($k[1], $sig, $data, $h, $h, strlen(hash($h, '', true)));
        }
        if (strlen($sig) !== 2 * self::ALGS[$alg][2]) {
            return false;
        }
        return Common::ecdsaVerifyRaw($k[1], $sig, $data, $h);
    }

    /**
     * Sign `$data`. EdDSA takes a 32-byte seed (binary string), an OKP JWK with `d`, or a 64-byte libsodium secret key;
     * ES* / RS* take an OpenSSL private key.
     * PS* signing goes through phpseclib/phpseclib 3.x (PHP's openssl_sign has no PSS padding); without it PS* signing fails closed.
     * An RSA key is an OpenSSL private key or a private RSA JWK (2048 bits or more).
     */
    public static function jwsSign(mixed $alg, mixed $key, string $data, bool $nodeCrypto = false): string
    {
        if (!is_string($alg) || $alg === '') {
            throw new JoseError('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if (in_array($alg, ['HS256', 'HS384', 'HS512'], true)) {
            throw new JoseError('KeyObject instances for symmetric algorithms must be of type "secret"');
        }
        $a = self::ALGS[$alg] ?? null;
        if ($a === null) {
            throw new JoseError("alg $alg is not supported either by JOSE or your javascript runtime");
        }
        if ($alg === 'EdDSA') {
            $sk = null;
            if (is_string($key) && strlen($key) === 32) {
                $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($key));
            } elseif (is_string($key) && strlen($key) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                $sk = $key;
            } elseif (Js::isObj($key) && Js::opt($key, 'kty') === 'OKP' && in_array(Js::opt($key, 'crv'), ['Ed25519', 'Ed448'], true) && Js::has($key, 'd') && !is_string(Js::opt($key, 'd'))) {
                throw new JoseError('Invalid JWK OKP key', 0, null, 'ERR_CRYPTO_INVALID_JWK'); // the runtime refuses a private JWK whose d is not a string
            } elseif (Js::isObj($key) && Js::opt($key, 'kty') === 'OKP' && Js::opt($key, 'crv') === 'Ed25519' && is_string(Js::opt($key, 'd'))) {
                $seed = self::jwkPrivateBytes(Js::opt($key, 'd'));
                if (strlen($seed) === 32) {
                    $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
                } else {
                    throw new JoseError('Invalid JWK OKP key', 0, null, 'ERR_CRYPTO_INVALID_JWK'); // the runtime refuses a private JWK whose d is the wrong length
                }
            }
            if ($sk === null && Js::isObj($key) && Js::opt($key, 'kty') === 'OKP' && Js::opt($key, 'crv') === 'Ed448' && is_string(Js::opt($key, 'd'))) {
                $d = self::lenientB64d(Js::opt($key, 'd'));
                if (strlen($d) === OpensslEd448::KEY_BYTES) {
                    try {
                        return OpensslEd448::sign($d, $data);
                    } catch (\RuntimeException $e) {
                        throw new JoseError('Invalid key for this operation: ' . $e->getMessage());
                    }
                }
            }
            if ($sk === null) {
                throw new JoseError('Invalid key for this operation: EdDSA needs an Ed25519 or Ed448 private key');
            }
            return sodium_crypto_sign_detached($data, $sk);
        }
        if (Js::isObj($key) && Js::opt($key, 'kty') === 'EC' && $a[2] > 0) {
            $key = self::ecPrivateFromJwk($key, $a[0], $a[2]);
        }
        if ($a[0] === 'pss') {
            return self::pssSign($alg, $key, $data, $a[1]);
        }
        // the JOSE library names the key type it needs; a direct node:crypto signature (the EAT builder) reports the digest error with no text
        $wrongKey = static fn(): JoseError => new JoseError($nodeCrypto ? 'Invalid key for this operation'
            : 'Invalid key for this operation, its asymmetricKeyType must be ' . ($a[0] === 'rsa' || $a[0] === 'pss' ? 'rsa' : 'ec'));
        if (!($key instanceof \OpenSSLAsymmetricKey)) {
            throw $wrongKey();
        }
        $det = openssl_pkey_get_details($key) ?: [];
        $okType = $a[0] === 'rsa' ? ($det['type'] ?? -1) === OPENSSL_KEYTYPE_RSA
            : ($det['type'] ?? -1) === OPENSSL_KEYTYPE_EC && ($det['ec']['curve_name'] ?? '') === ['P-256' => 'prime256v1', 'P-384' => 'secp384r1', 'P-521' => 'secp521r1'][$a[0]];
        if (!$okType) { // the key must be of the alg's type and curve, never signed with whatever the key happens to be
            throw $wrongKey();
        }
        $sig = '';
        if (!openssl_sign($data, $sig, $key, $a[1])) {
            throw new JoseError('Invalid key for this operation');
        }
        if ($a[0] === 'rsa') {
            return $sig;
        }
        // DER Ecdsa-Sig-Value -> r || s
        $rs = self::derIntegers($sig);
        if ($rs === null) {
            throw new JoseError('Invalid key for this operation');
        }
        return str_pad(ltrim($rs[0], "\0"), $a[2], "\0", STR_PAD_LEFT) . str_pad(ltrim($rs[1], "\0"), $a[2], "\0", STR_PAD_LEFT);
    }

    /** RSASSA-PSS (salt length = hash length, MGF1 over the same hash) through phpseclib; refuses a weak or non-private key. */
    private static function pssSign(string $alg, mixed $key, string $data, string $hash): string
    {
        if (!class_exists(\phpseclib3\Crypt\RSA::class)) {
            throw new JoseError("$alg signing needs phpseclib/phpseclib 3.x (composer require phpseclib/phpseclib)");
        }
        try {
            if ($key instanceof \OpenSSLAsymmetricKey) {
                $pem = '';
                if (!openssl_pkey_export($key, $pem)) {
                    throw new JoseError('Invalid key for this operation');
                }
                $rsa = \phpseclib3\Crypt\PublicKeyLoader::load($pem);
            } elseif (Js::isObj($key) && Js::opt($key, 'kty') === 'RSA' && is_string(Js::opt($key, 'd'))) {
                $rsa = \phpseclib3\Crypt\PublicKeyLoader::load(Js::stringify($key));
            } else {
                throw new JoseError('Invalid key for this operation');
            }
        } catch (JoseError $e) {
            throw $e;
        } catch (\Throwable) {
            throw new JoseError('Invalid key for this operation');
        }
        if (!($rsa instanceof \phpseclib3\Crypt\RSA\PrivateKey)) {
            throw new JoseError('Invalid key for this operation');
        }
        if ($rsa->getLength() < 2048) {
            throw new JoseError("$alg requires key modulusLength to be 2048 bits or larger");
        }
        return $rsa->withPadding(\phpseclib3\Crypt\RSA::SIGNATURE_PSS)->withHash($hash)->withMGFHash($hash)
            ->withSaltLength(strlen(hash($hash, '', true)))->sign($data);
    }

    /** An OpenSSL EC private key from a private JWK on `$crv` (SEC1 ECPrivateKey DER). */
    private static function ecPrivateFromJwk(mixed $jwk, string $crv, int $size): \OpenSSLAsymmetricKey
    {
        $oid = ['P-256' => "\x2A\x86\x48\xCE\x3D\x03\x01\x07", 'P-384' => "\x2B\x81\x04\x00\x22", 'P-521' => "\x2B\x81\x04\x00\x23"][$crv];
        if (Js::opt($jwk, 'crv') !== $crv) {
            throw new JoseError('Invalid key for this operation');
        }
        $pad = static fn(string $b): string => str_pad(ltrim($b, "\0"), $size, "\0", STR_PAD_LEFT);
        $d = $pad(self::bytesOf(Js::opt($jwk, 'd')));
        $pt = "\x04" . $pad(self::bytesOf(Js::opt($jwk, 'x'))) . $pad(self::bytesOf(Js::opt($jwk, 'y')));
        $tlv = static fn(int $tag, string $body): string => chr($tag) . Common::derLen(strlen($body)) . $body;
        $der = $tlv(0x30, "\x02\x01\x01" . $tlv(0x04, $d) . $tlv(0xA0, $tlv(0x06, $oid)) . $tlv(0xA1, $tlv(0x03, "\0" . $pt)));
        $k = @openssl_pkey_get_private("-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n");
        if ($k === false) {
            throw new JoseError('invalid private JWK');
        }
        return $k;
    }

    /** @return ?array{0:string,1:string} the two INTEGERs of a DER SEQUENCE */
    private static function derIntegers(string $d): ?array
    {
        $p = 2;
        if (strlen($d) < 2 || ord($d[0]) !== 0x30) {
            return null;
        }
        if (ord($d[1]) & 0x80) {
            $p += ord($d[1]) & 0x7f;
        }
        $out = [];
        for ($i = 0; $i < 2; $i++) {
            if ($p + 2 > strlen($d) || ord($d[$p]) !== 0x02) {
                return null;
            }
            $n = ord($d[$p + 1]);
            $out[] = substr($d, $p + 2, $n);
            $p += 2 + $n;
        }
        return [$out[0], $out[1]];
    }

    /** SignJWT(payload).setProtectedHeader(header).sign(key): JSON in insertion order (JSON.stringify), compact. */
    public static function signJwt(mixed $payload, mixed $header, mixed $key): string
    {
        $alg = Js::opt($header, 'alg');
        if (!is_string($alg) || $alg === '') {
            throw new JoseError('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        $input = self::b64u(Js::stringify($header)) . '.' . self::b64u(Js::stringify($payload));
        return $input . '.' . self::b64u(self::jwsSign($alg, $key, $input));
    }

    // ---- verify ----

    private const SECS_RE = '/\A([+-])? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?\z/i';

    /** The JOSE library's time-span parser ("5m", "2 hours", "-1d"): whole seconds. */
    public static function secs(string $str): int
    {
        if (preg_match(self::SECS_RE, $str, $m) !== 1 || (($m[4] ?? '') !== '' && $m[1] !== '')) {
            throw new \TypeError('Invalid time period format');
        }
        $u = strtolower($m[3]);
        $unit = 1;
        foreach (['y' => 31557600, 'w' => 604800, 'd' => 86400, 'h' => 3600, 'm' => 60] as $c => $n) {
            if (str_starts_with($u, $c)) {
                $unit = $n;
                break;
            }
        }
        $n = (int)floor((float)$m[2] * $unit + 0.5);
        return $m[1] === '-' || ($m[4] ?? '') === 'ago' ? -$n : $n;
    }

    /** epoch(new Date(ms)): an out-of-range clock is an Invalid Date (NaN: every time comparison is false). */
    public static function epochOfMs(mixed $ms): float
    {
        $t = Js::num($ms);
        if ($t === null) {
            throw new \TypeError('clock must be a number of milliseconds');
        }
        if (!is_finite($t) || abs($t) > 8.64e15) {
            return NAN;
        }
        return floor((float)(int)$t / 1000.0);
    }

    private static function normalizeTyp(string $t): string
    {
        return (string)preg_replace('#\Aapplication/#', '', strtolower($t));
    }

    /**
     * jwtVerify(jwt, key, options) -> [payload Obj, protected header Obj]. Options (assoc array): algorithms, typ,
     * requiredClaims, issuer, subject, audience, clockTolerance, nowMs (currentDate), maxTokenAge, crit (extra recognized
     * extensions, name => true). Throws JoseError on any refusal.
     * @return array{0: Obj, 1: Obj}
     */
    public static function jwtVerify(mixed $jwt, mixed $key, array $o = []): array
    {
        [$payload, $header] = self::compactVerify($jwt, $key, $o['algorithms'] ?? null, $o['crit'] ?? []);
        $crit = $header->get('crit');
        if (is_array($crit) && in_array('b64', $crit, true) && $header->get('b64') === false) {
            throw new JoseError('JWTs MUST NOT use unencoded payload');
        }
        return [self::claimsCheck($payload, $header, $o), $header];
    }

    /**
     * compactVerify: [payload bytes, protected header]. Throws JoseError on any refusal.
     * @param ?list<string> $algorithms @param array<string,bool> $crit
     * @return array{0: string, 1: Obj}
     */
    public static function compactVerify(mixed $jws, mixed $key, ?array $algorithms = null, array $crit = []): array
    {
        if (!is_string($jws)) {
            throw new JoseError('Compact JWS must be a string or Uint8Array');
        }
        $parts = explode('.', $jws);
        if (count($parts) !== 3) {
            throw new JoseError('Invalid Compact JWS');
        }
        [$prot, $pay, $sig] = $parts;
        try {
            $h = Json::parseLax(self::lenientB64d($prot));
        } catch (\Throwable) {
            throw new JoseError('JWS Protected Header is invalid');
        }
        if (!($h instanceof Obj)) {
            throw new JoseError('JWS Protected Header is invalid');
        }
        $b64 = true;
        if ($h->has('crit')) {
            $c = $h->get('crit');
            if (!is_array($c) || !array_is_list($c) || $c === [] || array_filter($c, static fn(mixed $x): bool => !is_string($x) || $x === '') !== []) {
                throw new JoseError('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
            }
            $recognized = ['b64' => true] + $crit;
            foreach ($c as $p) {
                if (!array_key_exists($p, $recognized)) {
                    throw new JoseError("Extension Header Parameter \"$p\" is not recognized");
                }
                if (!$h->has($p)) {
                    throw new JoseError("Extension Header Parameter \"$p\" is missing");
                }
            }
            if (in_array('b64', $c, true)) {
                $b64 = $h->get('b64');
                if (!is_bool($b64)) {
                    throw new JoseError('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
                }
            }
        }
        $alg = $h->get('alg');
        if (!is_string($alg) || $alg === '') {
            throw new JoseError('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if ($algorithms !== null) {
            if (!Js::isStrList($algorithms)) {
                throw new \TypeError('"algorithms" option must be an array of strings');
            }
            if (!in_array($alg, $algorithms, true)) {
                throw new JoseError('"alg" (Algorithm) Header Parameter value not allowed');
            }
        }
        if ($key instanceof \Closure) {
            $key = $key($h); // a key resolver (a JWKS) runs after the crit and alg checks, as in the reference
        }
        $embedded = $key === self::EMBEDDED_JWK;
        if ($embedded) {
            // jose EmbeddedJWK: the header's `jwk` must be a JSON object holding a public key
            $key = $h->get('jwk');
            if (!($key instanceof Obj)) {
                throw new JoseError('"jwk" (JSON Web Key) Header Parameter must be a JSON object');
            }
            if ($key->get('kty') === 'oct' || $key->has('d')) {
                throw new JoseError('"jwk" (JSON Web Key) Header Parameter must be a public key');
            }
        }
        if (!self::jwsVerify($alg, $key, self::lenientB64d($sig), "$prot.$pay", $embedded)) {
            throw new JoseError('signature verification failed');
        }
        return [$b64 ? self::lenientB64d($pay) : $pay, $h];
    }

    private static function audienceOk(mixed $value, array $opt): bool
    {
        if (is_string($value)) {
            return in_array($value, $opt, true);
        }
        if (is_array($value) && array_is_list($value)) {
            foreach ($value as $v) {
                if (in_array($v, $opt, true)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** The JWT claims-set validation over the raw payload bytes (options as jwtVerify); returns the claims. */
    public static function claimsCheck(string $bytes, Obj $header, array $o = []): Obj
    {
        try {
            $payload = Json::parseLax($bytes);
        } catch (\Throwable) {
            $payload = null;
        }
        if (!($payload instanceof Obj)) {
            throw new JoseError('JWT Claims Set must be a top-level JSON object');
        }
        $typ = $o['typ'] ?? null;
        if (Js::truthy($typ)) {
            $ht = $header->get('typ');
            if (!is_string($ht) || self::normalizeTyp($ht) !== self::normalizeTyp($typ)) {
                throw new JoseError('unexpected "typ" JWT header value');
            }
        }
        $issuer = $o['issuer'] ?? null;
        $subject = $o['subject'] ?? null;
        $hasAud = array_key_exists('audience', $o);
        $audience = $o['audience'] ?? null;
        $maxAge = $o['maxTokenAge'] ?? null;
        $presence = $o['requiredClaims'] ?? [];
        if ($maxAge !== null) {
            $presence[] = 'iat';
        }
        if ($hasAud) {
            $presence[] = 'aud';
        }
        if ($subject !== null) {
            $presence[] = 'sub';
        }
        if ($issuer !== null) {
            $presence[] = 'iss';
        }
        foreach (array_unique(array_reverse($presence)) as $c) {
            if (!$payload->has($c)) {
                throw new JoseError("missing required \"$c\" claim");
            }
        }
        if (Js::truthy($issuer) && !in_array($payload->get('iss'), is_array($issuer) ? $issuer : [$issuer], true)) {
            throw new JoseError('unexpected "iss" claim value');
        }
        if (Js::truthy($subject) && $payload->get('sub') !== $subject) {
            throw new JoseError('unexpected "sub" claim value');
        }
        if ($hasAud && Js::truthy($audience) && !self::audienceOk($payload->get('aud'), is_string($audience) ? [$audience] : (array)$audience)) {
            throw new JoseError('unexpected "aud" claim value');
        }
        $ct = $o['clockTolerance'] ?? null;
        if ($ct === null) {
            $tol = 0.0;
        } elseif (is_string($ct)) {
            $tol = (float)self::secs($ct);
        } elseif (Js::isNum($ct)) {
            $tol = (float)Js::num($ct);
        } else {
            throw new \TypeError('Invalid clockTolerance option type');
        }
        $now = array_key_exists('nowMs', $o) && $o['nowMs'] !== null ? self::epochOfMs($o['nowMs']) : (float)time();
        if (($payload->has('iat') || Js::truthy($maxAge)) && !Js::isNum($payload->get('iat'))) {
            throw new JoseError('"iat" claim must be a number');
        }
        if ($payload->has('nbf')) {
            if (!Js::isNum($payload->get('nbf'))) {
                throw new JoseError('"nbf" claim must be a number');
            }
            if (Js::num($payload->get('nbf')) > $now + $tol) {
                throw new JoseError('"nbf" claim timestamp check failed');
            }
        }
        if ($payload->has('exp')) {
            if (!Js::isNum($payload->get('exp'))) {
                throw new JoseError('"exp" claim must be a number');
            }
            if (Js::num($payload->get('exp')) <= $now - $tol) {
                throw new JoseError('"exp" claim timestamp check failed');
            }
        }
        if (Js::truthy($maxAge)) {
            $age = $now - Js::num($payload->get('iat'));
            $max = Js::isNum($maxAge) ? Js::num($maxAge) : (float)self::secs((string)$maxAge);
            if ($age - $tol > $max) {
                throw new JoseError('"iat" claim timestamp check failed (too far in the past)');
            }
            if ($age < 0 - $tol) {
                throw new JoseError('"iat" claim timestamp check failed (it should not be in the future)');
            }
        }
        return $payload;
    }
}
