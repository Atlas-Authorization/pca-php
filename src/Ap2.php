<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Risk.php';
require_once __DIR__ . '/Payments.php';

/** Every failure raised while parsing or verifying carries a human-readable reason. */
final class Ap2Error extends \RuntimeException
{
    public function __construct(string $message = '', public readonly ?string $codeName = null)
    {
        parent::__construct($message);
    }
}

/** Thrown by verifyPcaBinding when the server-held state the policy decision needs is missing (codeName: mandate_required | charge_history_required). */
final class PcaBindingError extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/** An ES256 (P-256) key pair: the public JWK (never carries `d`) and the OpenSSL private key. */
final class Ap2KeyPair
{
    public function __construct(public readonly Obj $publicJwk, public readonly \OpenSSLAsymmetricKey $privateKey)
    {
    }
}

/** Durable purchase state for open mandates: reserve is one atomic step (see Ap2::redeemPurchase). */
interface PurchaseLedger
{
    /** @return mixed a usage context {totalAmount, totalUses, lastUsedDate?} (Obj or array), or the string "replayed" */
    public function reserve(string $openMandateHash, string $transactionId, mixed $amountMinor): mixed;

    public function release(string $openMandateHash, string $transactionId): void;
}

/** Collects selective-disclosure disclosures while a mandate is built. */
final class Ap2DisclosureBuilder
{
    /** @var list<string> */
    public array $disclosures = [];

    public function __construct(private string $alg, private \Closure $salt)
    {
    }

    /** Array-element disclosure for `$value`; returns the `{"...": digest}` placeholder. */
    public function element(mixed $value): Obj
    {
        $raw = Ap2::b64uEncode(Js::stringify([($this->salt)(), $value]));
        $this->disclosures[] = $raw;
        return Obj::of(['...' => Ap2::sdDigest($raw, $this->alg)]);
    }

    /** Property disclosure; returns the digest to put into the parent's `_sd`. */
    public function property(string $name, mixed $value): string
    {
        $raw = Ap2::b64uEncode(Js::stringify([($this->salt)(), $name, $value]));
        $this->disclosures[] = $raw;
        return Ap2::sdDigest($raw, $this->alg);
    }
}

/**
 * AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a PCA grant. Mirrors @atlasauth/pca-ap2: strict
 * compact parsing and disclosure processing (RFC 9901), ES256 over P-256 (OpenSSL), the mandate validators, the open-mandate
 * constraint evaluation, issuing / presenting / verifying delegation chains, purchases and the redeem ledger, the PCA terms
 * bridge, and the x402 / Stripe Shared Payment Token settlement payloads.
 *
 * Values are the parsed-JSON model (Obj, lists, strings, Num / int / float, bool, null); options accept an Obj or a PHP
 * associative array with the reference's names. Callbacks are Closures (`resolveIssuerKey(Obj $header): ?Obj`, `salt(): string`).
 * The charge decision of verifyPcaBinding takes the PCA policy engine as an injected Closure.
 */
final class Ap2
{
    public const VCT_CHECKOUT = 'mandate.checkout.1';
    public const VCT_CHECKOUT_OPEN = 'mandate.checkout.open.1';
    public const VCT_PAYMENT = 'mandate.payment.1';
    public const VCT_PAYMENT_OPEN = 'mandate.payment.open.1';
    public const PCA_CLAIM = 'x_pca';
    public const FREQUENCIES = ['ON_DEMAND', 'DAILY', 'WEEKLY', 'BIWEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUALLY'];
    public const AP2_COMMIT = 'e1ea56db72a6385bce3e5c1112b3a56ce60acb43';
    public const PCA_BINDING_VERSION = 1;
    public const TYP_TERMINAL = ['kb+sd-jwt', 'kb-sd-jwt'];
    public const TYP_INTERMEDIATE = ['kb+sd-jwt+kb', 'kb-sd-jwt+kb'];
    private const MAX_HOPS = 8;
    private const ROOT_TYP = 'dc+sd-jwt';
    private const U = Payments::UNDEF;
    private const ZERO_DECIMAL = ['BIF', 'CLP', 'DJF', 'GNF', 'ISK', 'JPY', 'KMF', 'KRW', 'PYG', 'RWF', 'UGX', 'UYI', 'VND', 'VUV', 'XAF', 'XOF', 'XPF'];
    private const THREE_DECIMAL = ['BHD', 'IQD', 'JOD', 'KWD', 'LYD', 'OMR', 'TND'];
    private const FOUR_DECIMAL = ['CLF', 'UYW'];

    // ---- small JavaScript-semantics helpers ---------------------------------------------------------------------------------

    private static function p(mixed $o, string $k): mixed
    {
        return Payments::p($o, $k);
    }

    /** typeof v === 'string' (UNDEF is the absent member, not a string). */
    private static function isStr(mixed $v): bool
    {
        return is_string($v) && $v !== self::U;
    }

    private static function isNonEmptyStr(mixed $v): bool
    {
        return self::isStr($v) && $v !== '';
    }

    private static function isInt(mixed $v): bool
    {
        return Payments::safeInt($v) && !(Payments::n($v) === 0.0 && fdiv(1.0, Payments::n($v)) < 0);
    }

    private static function isNonNegInt(mixed $v): bool
    {
        return self::isInt($v) && Payments::n($v) >= 0;
    }

    private static function isObject(mixed $v): bool
    {
        return $v instanceof Obj;
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function currencyOk(mixed $v): bool
    {
        return self::isStr($v) && preg_match('/\A[A-Z]{3}\z/', $v) === 1;
    }

    /** o[k] of an option bag (an Obj or a PHP associative array); null when absent. */
    private static function opt(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    private static function now(): int
    {
        return (int)floor(microtime(true));
    }

    // ---- base64url + JSON ---------------------------------------------------------------------------------------------------

    public static function b64uEncode(mixed $data): string
    {
        if ($data instanceof Bytes) {
            return Pca::b64u($data->raw);
        }
        if (!is_string($data)) {
            throw new \TypeError('b64uEncode: bytes or a string are required');
        }
        return Pca::b64u(Js::utf8($data));
    }

    /** Strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip. */
    public static function b64uDecode(mixed $s, string $what): string
    {
        if (!is_string($s) || preg_match('/\A[A-Za-z0-9_-]*\z/', $s) !== 1) {
            throw new Ap2Error("$what: not base64url");
        }
        $buf = strlen($s) % 4 === 1 ? false : base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
        if ($buf === false || Pca::b64u($buf) !== $s) {
            throw new Ap2Error("$what: non-canonical base64url");
        }
        return $buf;
    }

    /** Reject an object that repeats a key (JSON.parse silently keeps the last one). Runs on text that already parsed. */
    private static function assertNoDuplicateKeys(string $text, string $what): void
    {
        $stack = [];
        $expectKey = false;
        $n = strlen($text);
        for ($i = 0; $i < $n; $i++) {
            $c = $text[$i];
            if ($c === '"') {
                $j = $i + 1;
                while ($text[$j] !== '"') {
                    $j += $text[$j] === '\\' ? 2 : 1;
                }
                $top = $stack === [] ? null : $stack[count($stack) - 1];
                if ($expectKey && $top !== null) {
                    $key = Js::parse(substr($text, $i, $j - $i + 1));
                    if (isset($stack[count($stack) - 1]["k$key"])) {
                        throw new Ap2Error("$what: duplicate key " . Js::stringify($key));
                    }
                    $stack[count($stack) - 1]["k$key"] = true;
                    $expectKey = false;
                }
                $i = $j;
            } elseif ($c === '{') {
                $stack[] = [];
                $expectKey = true;
            } elseif ($c === '[') {
                $stack[] = null;
                $expectKey = false;
            } elseif ($c === '}' || $c === ']') {
                array_pop($stack);
                $expectKey = false;
            } elseif ($c === ',') {
                $expectKey = $stack !== [] && is_array($stack[count($stack) - 1]);
            }
        }
    }

    /** JSON.parse that rejects duplicate keys. Numbers are parsed as written (`1000.0` is accepted). */
    public static function parseJson(mixed $text, string $what): mixed
    {
        if (!is_string($text)) {
            throw new \TypeError('parseJson: text must be a string');
        }
        try {
            $v = Js::parse($text);
        } catch (\Throwable $e) {
            throw new Ap2Error("$what: invalid JSON (" . $e->getMessage() . ')');
        }
        self::assertNoDuplicateKeys($text, $what);
        return $v;
    }

    private static function utf8Text(string $bytes, string $what): string
    {
        if (!mb_check_encoding($bytes, 'UTF-8')) {
            throw new Ap2Error("$what: not valid UTF-8");
        }
        return $bytes;
    }

    private static function decodeJsonSegment(string $segment, string $what): Obj
    {
        $v = self::parseJson(self::utf8Text(self::b64uDecode($segment, $what), $what), $what);
        if (!($v instanceof Obj)) {
            throw new Ap2Error("$what: must be a JSON object");
        }
        return $v;
    }

    // ---- hashing ------------------------------------------------------------------------------------------------------------

    public static function isSdAlg(mixed $v): bool
    {
        return $v === 'sha-256' || $v === 'sha-384' || $v === 'sha-512';
    }

    /** base64url(hash(ascii(value))): the digest used for disclosures, `sd_hash` and `checkout_hash`. */
    public static function sdDigest(mixed $value, mixed $alg = 'sha-256'): string
    {
        if (!is_string($value) || preg_match('/\A[\x20-\x7e]*\z/', $value) !== 1) {
            throw new Ap2Error('digest input must be ASCII');
        }
        if (!self::isSdAlg($alg)) {
            throw new NodeArgError('unsupported hash algorithm', 'ERR_INVALID_ARG_TYPE');
        }
        return Pca::b64u(hash(str_replace('-', '', $alg), $value, true));
    }

    // ---- ES256 keys (P-256) -------------------------------------------------------------------------------------------------

    private static function pem(string $type, string $der): string
    {
        return "-----BEGIN $type-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $type-----\n";
    }

    private static function lenientB64u(string $s): string
    {
        return (string)base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4));
    }

    private static function pad32(string $b): string
    {
        return str_pad(ltrim($b, "\0"), 32, "\0", STR_PAD_LEFT);
    }

    private static function publicKeyObject(Obj $jwk): ?\OpenSSLAsymmetricKey
    {
        $x = self::pad32(self::lenientB64u((string)$jwk->get('x')));
        $y = self::pad32(self::lenientB64u((string)$jwk->get('y')));
        $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y;
        $k = @openssl_pkey_get_public(self::pem('PUBLIC KEY', $der));
        return $k === false ? null : $k;
    }

    private static function privateKeyObject(string $d): ?\OpenSSLAsymmetricKey
    {
        if (strlen($d) > 32) {
            return null;
        }
        $der = hex2bin('30310201010420') . str_pad($d, 32, "\0", STR_PAD_LEFT) . hex2bin('a00a06082a8648ce3d030107');
        $k = @openssl_pkey_get_private(self::pem('EC PRIVATE KEY', $der));
        return $k === false ? null : $k;
    }

    /** @return array{0:string,1:string} the raw 32-byte x and y of an OpenSSL EC key */
    private static function xy(\OpenSSLAsymmetricKey $k): array
    {
        $ec = openssl_pkey_get_details($k)['ec'] ?? [];
        return [self::pad32((string)($ec['x'] ?? '')), self::pad32((string)($ec['y'] ?? ''))];
    }

    /** Validate a public JWK against `types/jwk.json` and prove the point is on the curve. Returns the JWK itself. */
    public static function assertP256Jwk(mixed $jwk, string $what): Obj
    {
        if (!($jwk instanceof Obj)) {
            throw new Ap2Error("$what: JWK must be an object");
        }
        if ($jwk->get('kty') !== 'EC' || $jwk->get('crv') !== 'P-256') {
            throw new Ap2Error("$what: JWK must be EC P-256");
        }
        foreach (['x', 'y'] as $c) {
            $v = $jwk->get($c);
            if (!is_string($v) || preg_match('/\A[A-Za-z0-9_-]{43}\z/', $v) !== 1) {
                throw new Ap2Error("$what: bad JWK $c");
            }
        }
        if ($jwk->has('d')) {
            throw new Ap2Error("$what: JWK carries private material");
        }
        if ($jwk->has('alg') && $jwk->get('alg') !== 'ES256') {
            throw new Ap2Error("$what: JWK alg must be ES256");
        }
        if (self::publicKeyObject($jwk) === null) {
            throw new Ap2Error("$what: JWK is not a valid P-256 point");
        }
        return $jwk;
    }

    public static function generateAp2KeyPair(?string $kid = null): Ap2KeyPair
    {
        $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($k === false) {
            throw new Ap2Error('cannot generate a P-256 key');
        }
        [$x, $y] = self::xy($k);
        $jwk = Obj::of(['kty' => 'EC', 'crv' => 'P-256', 'x' => Pca::b64u($x), 'y' => Pca::b64u($y)]);
        if ($kid !== null) {
            $jwk->set('kid', $kid);
        }
        return new Ap2KeyPair($jwk, $k);
    }

    /** Rebuild a key pair from a private JWK (`d` present), e.g. for fixtures. A JWK whose x / y do not match `d` is refused. */
    public static function ap2KeyPairFromPrivateJwk(mixed $jwk): Ap2KeyPair
    {
        $bad = new Ap2Error('Invalid JWK EC key', 'ERR_CRYPTO_INVALID_JWK');
        if (!Js::isObj($jwk) || Js::opt($jwk, 'kty') !== 'EC' || Js::opt($jwk, 'crv') !== 'P-256') {
            throw $bad;
        }
        foreach (['d', 'x', 'y'] as $k) {
            if (!is_string(Js::opt($jwk, $k))) {
                throw $bad;
            }
        }
        $key = self::privateKeyObject(self::lenientB64u((string)Js::opt($jwk, 'd')));
        if ($key === null) {
            throw $bad;
        }
        [$x, $y] = self::xy($key);
        if (self::pad32(self::lenientB64u((string)Js::opt($jwk, 'x'))) !== $x || self::pad32(self::lenientB64u((string)Js::opt($jwk, 'y'))) !== $y) {
            throw $bad;
        }
        $pub = Obj::of(['kty' => 'EC', 'crv' => 'P-256', 'x' => Pca::b64u($x), 'y' => Pca::b64u($y)]);
        $kid = Js::opt($jwk, 'kid');
        if (is_string($kid)) {
            $pub->set('kid', $kid);
        }
        return new Ap2KeyPair($pub, $key);
    }

    /** RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 key. */
    public static function jwkThumbprint(mixed $jwk): string
    {
        $canonical = '{"crv":"P-256","kty":"EC","x":"' . Payments::s(self::p($jwk, 'x')) . '","y":"' . Payments::s(self::p($jwk, 'y')) . '"}';
        return Pca::b64u(hash('sha256', Js::utf8($canonical), true));
    }

    private static function es256Sign(\OpenSSLAsymmetricKey $key, string $input): string
    {
        if (!openssl_sign($input, $der, $key, OPENSSL_ALGO_SHA256)) {
            throw new Ap2Error('ES256 signing failed');
        }
        // DER SEQUENCE { INTEGER r, INTEGER s } -> the 64-byte r || s
        $o = 2 + ((ord($der[1]) & 0x80) ? (ord($der[1]) & 0x7f) : 0);
        $rl = ord($der[$o + 1]);
        $r = substr($der, $o + 2, $rl);
        $sl = ord($der[$o + 2 + $rl + 1]);
        $s = substr($der, $o + 2 + $rl + 2, $sl);
        return Pca::b64u(self::pad32($r) . self::pad32($s));
    }

    private static function derInt(string $b): string
    {
        $b = ltrim($b, "\0");
        $b = $b === '' ? "\0" : $b;
        $b = (ord($b[0]) & 0x80) ? "\0" . $b : $b;
        return "\x02" . chr(strlen($b)) . $b;
    }

    private static function es256Verify(Obj $jwk, string $input, string $signature): bool
    {
        if (strlen($signature) !== 64) {
            return false;
        }
        [$r, $s] = [substr($signature, 0, 32), substr($signature, 32)];
        if (ltrim($r, "\0") === '' || ltrim($s, "\0") === '') {
            return false;
        }
        $pub = self::publicKeyObject($jwk);
        if ($pub === null) {
            return false;
        }
        $body = self::derInt($r) . self::derInt($s);
        return openssl_verify($input, "\x30" . chr(strlen($body)) . $body, $pub, OPENSSL_ALGO_SHA256) === 1;
    }

    // ---- compact JWT / SD-JWT parsing ---------------------------------------------------------------------------------------

    /** The hop's `~`-joined serialisation: what `sd_hash` is computed over. */
    public static function hopSdJwt(mixed $hop): string
    {
        $out = (string)self::p($hop, 'jwt') . '~';
        foreach (self::p($hop, 'disclosures') as $d) {
            $out .= $d . '~';
        }
        return $out;
    }

    /**
     * Parse one SD-JWT (`jwt~d1~...~dn~`; it must end with `~`). Returns {raw, jwt, header, payload, disclosures, sdAlg, signingInput,
     * signature} (the signature as raw bytes).
     */
    public static function parseSdJwtHop(mixed $token): Obj
    {
        if (!is_string($token) || $token === '') {
            throw new Ap2Error('SD-JWT: empty');
        }
        if ($token[0] === '~') {
            throw new Ap2Error('SD-JWT: empty issuer JWT');
        }
        if (!str_ends_with($token, '~')) {
            throw new Ap2Error('SD-JWT: must end with "~" (a trailing KB-JWT is not an AP2 form)');
        }
        $parts = explode('~', substr($token, 0, -1));
        $jwt = $parts[0];
        $disclosures = array_slice($parts, 1);
        foreach ($disclosures as $d) {
            if ($d === '') {
                throw new Ap2Error('SD-JWT: empty disclosure segment');
            }
        }
        $seg = explode('.', $jwt);
        if (count($seg) !== 3 || in_array('', $seg, true)) {
            throw new Ap2Error('SD-JWT: issuer JWT must be header.payload.signature');
        }
        [$h, $p, $s] = $seg;
        $header = self::decodeJsonSegment($h, 'JWT header');
        $payload = self::decodeJsonSegment($p, 'JWT payload');
        $signature = self::b64uDecode($s, 'JWT signature');
        $hasAlg = $payload->has('_sd_alg');
        $rawAlg = $payload->get('_sd_alg');
        if ($hasAlg && !self::isSdAlg($rawAlg)) {
            throw new Ap2Error('SD-JWT: unsupported _sd_alg ' . Js::stringify($rawAlg));
        }
        return Obj::of(['raw' => $token, 'jwt' => $jwt, 'header' => $header, 'payload' => $payload, 'disclosures' => $disclosures,
            'sdAlg' => self::isSdAlg($rawAlg) ? $rawAlg : 'sha-256', 'signingInput' => "$h.$p", 'signature' => $signature]);
    }

    /** `sd_hash` of a hop: the digest of `<jwt>~<d1>~...~` (the on-wire form of the preceding hop). */
    public static function sdHashOf(mixed $hop, mixed $alg = null): string
    {
        return self::sdDigest(self::hopSdJwt($hop), $alg ?? self::p($hop, 'sdAlg'));
    }

    /** `issuer_jwt_hash` of a hop: the digest of the issuer-signed JWT alone. */
    public static function issuerJwtHashOf(mixed $hop, mixed $alg = null): string
    {
        return self::sdDigest(self::p($hop, 'jwt'), $alg ?? self::p($hop, 'sdAlg'));
    }

    /** Verify the issuer JWT's ES256 signature. Anything other than `alg: ES256` is rejected. */
    public static function verifyHopSignature(mixed $hop, mixed $key): bool
    {
        if (self::p(self::p($hop, 'header'), 'alg') !== 'ES256') {
            return false;
        }
        return self::es256Verify(self::assertP256Jwk($key, 'verification key'), (string)self::p($hop, 'signingInput'), (string)self::p($hop, 'signature'));
    }

    /** Parse a compact JWT: {header, payload, signingInput, signature (raw bytes)}. */
    public static function parseJwt(mixed $jwt, string $what): Obj
    {
        if (!is_string($jwt)) {
            throw new \TypeError('jwt.split is not a function');
        }
        $seg = explode('.', $jwt);
        if (count($seg) !== 3 || in_array('', $seg, true)) {
            throw new Ap2Error("$what: must be header.payload.signature");
        }
        [$h, $p, $s] = $seg;
        return Obj::of(['header' => self::decodeJsonSegment($h, "$what header"), 'payload' => self::decodeJsonSegment($p, "$what payload"),
            'signingInput' => "$h.$p", 'signature' => self::b64uDecode($s, "$what signature")]);
    }

    public static function verifyJwtEs256(mixed $parsed, mixed $key): bool
    {
        if (self::p(self::p($parsed, 'header'), 'alg') !== 'ES256') {
            return false;
        }
        return self::es256Verify(self::assertP256Jwk($key, 'verification key'), (string)self::p($parsed, 'signingInput'), (string)self::p($parsed, 'signature'));
    }

    // ---- disclosure processing (RFC 9901 section 7) -------------------------------------------------------------------------

    /** @return array{kind:string,name?:string,value:mixed} */
    private static function decodeDisclosure(string $raw): array
    {
        $arr = self::parseJson(self::utf8Text(self::b64uDecode($raw, 'disclosure'), 'disclosure'), 'disclosure');
        if (!self::isList($arr)) {
            throw new Ap2Error('disclosure: must be a JSON array');
        }
        if (!isset($arr[0]) || !is_string($arr[0]) || $arr[0] === '') {
            throw new Ap2Error('disclosure: salt must be a non-empty string');
        }
        if (count($arr) === 3) {
            $name = $arr[1];
            if (!is_string($name)) {
                throw new Ap2Error('disclosure: claim name must be a string');
            }
            if ($name === '_sd' || $name === '...') {
                throw new Ap2Error("disclosure: claim name $name is reserved");
            }
            return ['kind' => 'property', 'name' => $name, 'value' => $arr[2]];
        }
        if (count($arr) === 2) {
            return ['kind' => 'element', 'value' => $arr[1]];
        }
        throw new Ap2Error('disclosure: array must have 2 or 3 elements');
    }

    /**
     * Resolve every selectively-disclosable claim in `$payload` using `$disclosures`; `_sd`, `...` markers and `_sd_alg` are removed.
     * Throws if a disclosure is duplicated, not referenced from the payload, collides with an existing claim, or is in the wrong position.
     * @param list<string> $disclosures
     */
    public static function processDisclosures(mixed $payload, mixed $disclosures, mixed $alg): mixed
    {
        $byDigest = [];
        foreach ($disclosures as $raw) {
            $d = self::decodeDisclosure($raw);
            $digest = 'd' . self::sdDigest($raw, $alg);
            if (isset($byDigest[$digest])) {
                throw new Ap2Error('SD-JWT: duplicate disclosure');
            }
            $byDigest[$digest] = $d;
        }
        $used = [];
        $take = static function (string $digest, string $want) use (&$byDigest, &$used): ?array {
            $d = $byDigest["d$digest"] ?? null;
            if ($d === null) {
                return null; // a decoy digest, or a disclosure the holder chose not to reveal
            }
            if (isset($used["d$digest"])) {
                throw new Ap2Error('SD-JWT: a digest is referenced more than once');
            }
            if ($d['kind'] !== $want) {
                throw new Ap2Error("SD-JWT: a {$d['kind']} disclosure is referenced from a $want position");
            }
            $used["d$digest"] = true;
            return $d;
        };
        $walk = static function (mixed $node, int $depth) use (&$walk, $take): mixed {
            if ($depth > 32) {
                throw new Ap2Error('SD-JWT: nesting too deep');
            }
            if (is_array($node)) {
                $out = [];
                foreach ($node as $el) {
                    if ($el instanceof Obj && $el->has('...')) {
                        if (count($el->keys()) !== 1 || !is_string($el->get('...'))) {
                            throw new Ap2Error('SD-JWT: malformed array digest placeholder');
                        }
                        $d = $take($el->get('...'), 'element');
                        if ($d !== null) {
                            $out[] = $walk($d['value'], $depth + 1);
                        }
                    } else {
                        $out[] = $walk($el, $depth + 1);
                    }
                }
                return $out;
            }
            if ($node instanceof Obj) {
                $out = new Obj();
                foreach (Js::ownKeys($node->keys()) as $k) {
                    if ($k === '_sd' || $k === '_sd_alg') {
                        continue;
                    }
                    if ($k === '...') {
                        throw new Ap2Error('SD-JWT: "..." is only valid as the sole key of an array element');
                    }
                    $out->set($k, $walk($node->get($k), $depth + 1));
                }
                if ($node->has('_sd')) {
                    $sd = $node->get('_sd');
                    if (!self::isList($sd) || array_filter($sd, static fn($x): bool => !is_string($x)) !== []) {
                        throw new Ap2Error('SD-JWT: _sd must be an array of strings');
                    }
                    foreach ($sd as $digest) {
                        $d = $take($digest, 'property');
                        if ($d === null || $d['kind'] !== 'property') {
                            continue;
                        }
                        if ($out->has($d['name'])) {
                            throw new Ap2Error("SD-JWT: disclosed claim {$d['name']} collides with an existing claim");
                        }
                        $out->set($d['name'], $walk($d['value'], $depth + 1));
                    }
                }
                return $out;
            }
            return $node;
        };
        $result = $walk($payload, 0);
        if (count($used) !== count($byDigest)) {
            throw new Ap2Error('SD-JWT: a disclosure is not referenced by the signed payload');
        }
        return $result;
    }

    // ---- issuing ------------------------------------------------------------------------------------------------------------

    public static function newSalt(): string
    {
        return Pca::b64u(random_bytes(16));
    }

    public static function disclosureBuilder(mixed $alg = null, ?\Closure $salt = null): Ap2DisclosureBuilder
    {
        return new Ap2DisclosureBuilder($alg ?? 'sha-256', $salt ?? static fn(): string => self::newSalt());
    }

    private static function key(mixed $k): \OpenSSLAsymmetricKey
    {
        if (!($k instanceof \OpenSSLAsymmetricKey)) {
            throw new \TypeError('privateKey must be an ES256 key');
        }
        return $k;
    }

    /** `{...base, ...spread(extra)}` */
    private static function merged(Obj $base, mixed $extra): Obj
    {
        foreach (Payments::spreadObj($extra)->keys() as $k) {
            $base->set($k, Payments::spreadObj($extra)->get($k));
        }
        return $base;
    }

    /** Sign `payload` as an ES256 JWT and append `disclosures`: `<jwt>~<d1>~...~<dn>~`. `$args`: header, payload, disclosures, privateKey. */
    public static function signSdJwt(mixed $args): string
    {
        $header = self::b64uEncode(Js::stringify(self::merged(Obj::of(['alg' => 'ES256']), self::p($args, 'header'))));
        $payload = self::b64uEncode(Js::stringify(self::p($args, 'payload')));
        $jwt = "$header.$payload." . self::es256Sign(self::key(self::p($args, 'privateKey')), "$header.$payload");
        $out = $jwt . '~';
        foreach (self::p($args, 'disclosures') as $d) {
            $out .= $d . '~';
        }
        return $out;
    }

    /** Sign an arbitrary compact JWT (used for merchant-signed `checkout_jwt`). `$args`: header, payload, privateKey. */
    public static function signJwtEs256(mixed $args): string
    {
        $header = self::b64uEncode(Js::stringify(self::merged(Obj::of(['alg' => 'ES256', 'typ' => 'JWT']), self::p($args, 'header'))));
        $payload = self::b64uEncode(Js::stringify(self::p($args, 'payload')));
        return "$header.$payload." . self::es256Sign(self::key(self::p($args, 'privateKey')), "$header.$payload");
    }

    // ---- currencies and minor units -----------------------------------------------------------------------------------------

    /** ISO 4217 minor-unit exponent for `$currency` (2 for any code not in the 0/3/4-digit tables). */
    public static function currencyExponent(mixed $currency): int
    {
        $text = is_string($currency) ? $currency : Payments::s($currency);
        if (preg_match('/\A[A-Z]{3}\z/', $text) !== 1) {
            throw new Ap2Error('currency must be an ISO 4217 alpha-3 code, got ' . ($currency === self::U ? 'undefined' : Js::stringify($currency)));
        }
        if (is_string($currency)) {
            if (in_array($currency, self::ZERO_DECIMAL, true)) {
                return 0;
            }
            if (in_array($currency, self::THREE_DECIMAL, true)) {
                return 3;
            }
            if (in_array($currency, self::FOUR_DECIMAL, true)) {
                return 4;
            }
        }
        return 2;
    }

    /** A major-unit amount (`120.5` USD) to integer minor units (`12050`). Float drift (`0.1 + 0.2`) is refused rather than rounded away. */
    public static function toMinorUnits(mixed $major, mixed $currency): int|float
    {
        $e = self::currencyExponent($currency);
        if (!Js::isNum($major) || !is_finite(Payments::n($major)) || Payments::n($major) < 0) {
            throw new Ap2Error('amount must be a finite non-negative number, got ' . Payments::s($major));
        }
        $m = Payments::n($major);
        $fixed = sprintf('%.' . $e . 'f', $m);
        if ((float)$fixed !== $m) {
            throw new Ap2Error('amount ' . Payments::s($major) . ' is not exactly representable in ' . Payments::s($currency) . ' minor units');
        }
        $minor = (float)str_replace('.', '', $fixed);
        if (!Payments::safeInt($minor)) {
            throw new Ap2Error('amount ' . Payments::s($major) . ' is outside the safe integer range in minor units');
        }
        return Payments::num($minor);
    }

    /** Integer minor units to the major-unit number PCA budgets use (exact for any safe integer). */
    public static function fromMinorUnits(mixed $minor, mixed $currency): int|float
    {
        $e = self::currencyExponent($currency);
        if (!self::isNonNegInt($minor)) {
            throw new Ap2Error('minor-unit amount must be a non-negative safe integer, got ' . Payments::s($minor));
        }
        return Payments::num(Payments::n($minor) / (10 ** $e));
    }

    // ---- mandate validators: each returns the list of problems (empty = valid) ----------------------------------------------

    /** @return list<string> */
    private static function merchantProblems(mixed $v, string $at): array
    {
        if (!self::isObject($v)) {
            return ["$at: not an object"];
        }
        $p = [];
        if (!self::isNonEmptyStr(self::p($v, 'id'))) {
            $p[] = "$at.id: required string";
        }
        if (!self::isNonEmptyStr(self::p($v, 'name'))) {
            $p[] = "$at.name: required string";
        }
        if (self::p($v, 'website') !== self::U && !self::isStr(self::p($v, 'website'))) {
            $p[] = "$at.website: must be a string";
        }
        return $p;
    }

    private static function amountProblems(mixed $v, string $at): array
    {
        if (!self::isObject($v)) {
            return ["$at: not an object"];
        }
        $p = [];
        if (!self::isNonNegInt(self::p($v, 'amount'))) {
            $p[] = "$at.amount: must be a non-negative integer (minor units)";
        }
        if (!self::currencyOk(self::p($v, 'currency'))) {
            $p[] = "$at.currency: must be an ISO 4217 alpha-3 code";
        }
        return $p;
    }

    private static function instrumentProblems(mixed $v, string $at): array
    {
        if (!self::isObject($v)) {
            return ["$at: not an object"];
        }
        $p = [];
        if (!self::isNonEmptyStr(self::p($v, 'id'))) {
            $p[] = "$at.id: required string";
        }
        if (!self::isNonEmptyStr(self::p($v, 'type'))) {
            $p[] = "$at.type: required string";
        }
        if (self::p($v, 'description') !== self::U && !self::isStr(self::p($v, 'description'))) {
            $p[] = "$at.description: must be a string";
        }
        return $p;
    }

    private static function pispProblems(mixed $v, string $at): array
    {
        if (!self::isObject($v)) {
            return ["$at: not an object"];
        }
        $p = [];
        foreach (['legal_name', 'brand_name', 'domain_name'] as $k) {
            if (!self::isNonEmptyStr(self::p($v, $k))) {
                $p[] = "$at.$k: required string";
            }
        }
        return $p;
    }

    private static function timeProblems(Obj $v): array
    {
        $p = [];
        foreach (['iat', 'exp'] as $k) {
            if (self::p($v, $k) !== self::U && !self::isNonNegInt(self::p($v, $k))) {
                $p[] = "$k: must be an integer epoch-seconds";
            }
        }
        return $p;
    }

    private static function cnfProblems(mixed $v): array
    {
        if (!self::isObject($v) || !self::isObject(self::p($v, 'jwk'))) {
            return ['cnf: must be { jwk }'];
        }
        try {
            self::assertP256Jwk(self::p($v, 'jwk'), 'cnf.jwk');
            return [];
        } catch (\Throwable $e) {
            return [$e->getMessage()];
        }
    }

    private static function pcaClaimProblems(Obj $v): array
    {
        $c = self::p($v, self::PCA_CLAIM);
        return $c !== self::U && !self::isObject($c) ? [self::PCA_CLAIM . ': must be an object'] : [];
    }

    private static function listProblems(mixed $v, string $at, \Closure $each): array
    {
        if (!self::isList($v)) {
            return ["$at: must be an array"];
        }
        $out = [];
        foreach ($v as $i => $x) {
            array_push($out, ...$each($x, $at . '[' . $i . ']'));
        }
        return $out;
    }

    private static function paymentConstraintProblems(mixed $c, string $at): array
    {
        if (!self::isObject($c) || !self::isStr(self::p($c, 'type'))) {
            return ["$at: constraint must be an object with a string type"];
        }
        $g = static fn(string $k): mixed => self::p($c, $k);
        switch ($g('type')) {
            case 'payment.agent_recurrence':
                $p = [];
                if (!self::isStr($g('frequency')) || !in_array($g('frequency'), self::FREQUENCIES, true)) {
                    $p[] = "$at.frequency: not a known frequency";
                }
                if ($g('max_occurrences') !== self::U && !(self::isInt($g('max_occurrences')) && Payments::n($g('max_occurrences')) > 0)) {
                    $p[] = "$at.max_occurrences: must be a positive integer";
                }
                return $p;
            case 'payment.allowed_payees':
                return self::listProblems($g('allowed'), "$at.allowed", static fn($x, $a) => self::merchantProblems($x, $a));
            case 'payment.allowed_payment_instruments':
                return self::listProblems($g('allowed'), "$at.allowed", static fn($x, $a) => self::instrumentProblems($x, $a));
            case 'payment.allowed_pisps':
                return self::listProblems($g('allowed'), "$at.allowed", static fn($x, $a) => self::pispProblems($x, $a));
            case 'payment.amount_range':
                $p = [];
                if (!self::currencyOk($g('currency'))) {
                    $p[] = "$at.currency: must be an ISO 4217 alpha-3 code";
                }
                if (!self::isNonNegInt($g('max'))) {
                    $p[] = "$at.max: must be a non-negative integer (minor units)";
                }
                if ($g('min') !== self::U && !self::isNonNegInt($g('min'))) {
                    $p[] = "$at.min: must be a non-negative integer (minor units)";
                }
                if (self::isInt($g('max')) && self::isInt($g('min')) && Payments::n($g('min')) > Payments::n($g('max'))) {
                    $p[] = "$at: min exceeds max";
                }
                return $p;
            case 'payment.budget':
                $p = [];
                if (!self::currencyOk($g('currency'))) {
                    $p[] = "$at.currency: must be an ISO 4217 alpha-3 code";
                }
                if (!Js::isNum($g('max')) || !Payments::fin($g('max')) || Payments::n($g('max')) < 0) {
                    $p[] = "$at.max: must be a non-negative number (major units)";
                }
                return $p;
            case 'payment.execution_date':
                $p = [];
                foreach (['not_before', 'not_after'] as $k) {
                    if ($g($k) !== self::U && !self::isStr($g($k))) {
                        $p[] = "$at.$k: must be a string";
                    }
                }
                return $p;
            case 'payment.reference':
                return self::isNonEmptyStr($g('conditional_transaction_id')) ? [] : ["$at.conditional_transaction_id: required string"];
            default:
                return ["$at: unknown constraint type " . Payments::s($g('type'))];
        }
    }

    private static function acceptableItemProblems(mixed $x, string $ax): array
    {
        if (!self::isObject($x)) {
            return ["$ax: not an object"];
        }
        $p = [];
        foreach (['id', 'title'] as $k) {
            if (!self::isNonEmptyStr(self::p($x, $k))) {
                $p[] = "$ax.$k: required string";
            }
        }
        return $p;
    }

    private static function checkoutConstraintProblems(mixed $c, string $at): array
    {
        if (!self::isObject($c) || !self::isStr(self::p($c, 'type'))) {
            return ["$at: constraint must be an object with a string type"];
        }
        $type = self::p($c, 'type');
        if ($type === 'checkout.allowed_merchants') {
            return self::listProblems(self::p($c, 'allowed'), "$at.allowed", static fn($x, $a) => self::merchantProblems($x, $a));
        }
        if ($type === 'checkout.line_items') {
            $items = self::p($c, 'items');
            if (!self::isList($items) || $items === []) {
                return ["$at.items: must be a non-empty array"];
            }
            $out = [];
            foreach ($items as $i => $it) {
                $a = "$at.items[$i]";
                if (!self::isObject($it)) {
                    array_push($out, "$a: not an object");
                    continue;
                }
                $p = [];
                if (!self::isNonEmptyStr(self::p($it, 'id'))) {
                    $p[] = "$a.id: required string";
                }
                if (!self::isInt(self::p($it, 'quantity')) || !(Payments::n(self::p($it, 'quantity')) > 0)) {
                    $p[] = "$a.quantity: must be a positive integer";
                }
                array_push($p, ...self::listProblems(self::p($it, 'acceptable_items'), "$a.acceptable_items", static fn($x, $ax) => self::acceptableItemProblems($x, $ax)));
                array_push($out, ...$p);
            }
            return $out;
        }
        return ["$at: unknown constraint type " . Payments::s($type)];
    }

    private static function vctProblem(Obj $v, string $want): array
    {
        return self::p($v, 'vct') === $want ? [] : ["vct: must be $want"];
    }

    private static function hasType(mixed $constraints, string $t): bool
    {
        foreach ($constraints as $c) {
            if (self::isObject($c) && self::p($c, 'type') === $t) {
                return true;
            }
        }
        return false;
    }

    /** @return list<string> */
    public static function openPaymentMandateProblems(mixed $v): array
    {
        if (!self::isObject($v)) {
            return ['mandate: not an object'];
        }
        $p = [...self::vctProblem($v, self::VCT_PAYMENT_OPEN), ...self::timeProblems($v), ...self::cnfProblems(self::p($v, 'cnf')), ...self::pcaClaimProblems($v)];
        array_push($p, ...self::listProblems(self::p($v, 'constraints'), 'constraints', static fn($c, $a) => self::paymentConstraintProblems($c, $a)));
        if (self::isList(self::p($v, 'constraints')) && !self::hasType(self::p($v, 'constraints'), 'payment.reference')) {
            $p[] = 'constraints: must contain a payment.reference constraint';
        }
        if (self::p($v, 'payee') !== self::U) {
            array_push($p, ...self::merchantProblems(self::p($v, 'payee'), 'payee'));
        }
        if (self::p($v, 'payment_amount') !== self::U) {
            array_push($p, ...self::amountProblems(self::p($v, 'payment_amount'), 'payment_amount'));
        }
        if (self::p($v, 'payment_instrument') !== self::U) {
            array_push($p, ...self::instrumentProblems(self::p($v, 'payment_instrument'), 'payment_instrument'));
        }
        if (self::p($v, 'pisp') !== self::U) {
            array_push($p, ...self::pispProblems(self::p($v, 'pisp'), 'pisp'));
        }
        if (self::p($v, 'execution_date') !== self::U && !self::isStr(self::p($v, 'execution_date'))) {
            $p[] = 'execution_date: must be a string';
        }
        if (self::p($v, 'risk_data') !== self::U && !self::isObject(self::p($v, 'risk_data'))) {
            $p[] = 'risk_data: must be an object';
        }
        return $p;
    }

    /** @return list<string> */
    public static function paymentMandateProblems(mixed $v): array
    {
        if (!self::isObject($v)) {
            return ['mandate: not an object'];
        }
        $p = [...self::vctProblem($v, self::VCT_PAYMENT), ...self::timeProblems($v), ...self::pcaClaimProblems($v)];
        if (!self::isNonEmptyStr(self::p($v, 'transaction_id'))) {
            $p[] = 'transaction_id: required string';
        }
        array_push($p, ...self::merchantProblems(self::p($v, 'payee'), 'payee'), ...self::amountProblems(self::p($v, 'payment_amount'), 'payment_amount'),
            ...self::instrumentProblems(self::p($v, 'payment_instrument'), 'payment_instrument'));
        if (self::p($v, 'pisp') !== self::U) {
            array_push($p, ...self::pispProblems(self::p($v, 'pisp'), 'pisp'));
        }
        if (self::p($v, 'execution_date') !== self::U && !self::isStr(self::p($v, 'execution_date'))) {
            $p[] = 'execution_date: must be a string';
        }
        if (self::p($v, 'risk_data') !== self::U && !self::isObject(self::p($v, 'risk_data'))) {
            $p[] = 'risk_data: must be an object';
        }
        return $p;
    }

    /** @return list<string> */
    public static function openCheckoutMandateProblems(mixed $v): array
    {
        if (!self::isObject($v)) {
            return ['mandate: not an object'];
        }
        $p = [...self::vctProblem($v, self::VCT_CHECKOUT_OPEN), ...self::timeProblems($v), ...self::cnfProblems(self::p($v, 'cnf')), ...self::pcaClaimProblems($v)];
        array_push($p, ...self::listProblems(self::p($v, 'constraints'), 'constraints', static fn($c, $a) => self::checkoutConstraintProblems($c, $a)));
        if (self::isList(self::p($v, 'constraints')) && !self::hasType(self::p($v, 'constraints'), 'checkout.line_items')) {
            $p[] = 'constraints: must contain a checkout.line_items constraint';
        }
        return $p;
    }

    /** @return list<string> */
    public static function checkoutMandateProblems(mixed $v): array
    {
        if (!self::isObject($v)) {
            return ['mandate: not an object'];
        }
        $p = [...self::vctProblem($v, self::VCT_CHECKOUT), ...self::timeProblems($v), ...self::pcaClaimProblems($v)];
        if (!self::isNonEmptyStr(self::p($v, 'checkout_jwt'))) {
            $p[] = 'checkout_jwt: required string';
        }
        if (!self::isNonEmptyStr(self::p($v, 'checkout_hash'))) {
            $p[] = 'checkout_hash: required string';
        }
        return $p;
    }

    /** @param \Closure(mixed):list<string> $problems */
    public static function assertValid(mixed $v, \Closure $problems, string $what): mixed
    {
        $p = $problems($v);
        if ($p !== []) {
            throw new Ap2Error("$what: " . implode('; ', $p));
        }
        return $v;
    }

    // ---- constraint evaluation ----------------------------------------------------------------------------------------------

    public static function merchantMatches(mixed $candidate, mixed $target): bool
    {
        $cid = self::p($candidate, 'id');
        $tid = self::p($target, 'id');
        if (Payments::truthy($cid) && Payments::truthy($tid)) {
            return Payments::seq($cid, $tid);
        }
        return Payments::truthy(self::p($candidate, 'name')) && Payments::truthy(self::p($candidate, 'website'))
            && Payments::seq(self::p($candidate, 'name'), self::p($target, 'name')) && Payments::seq(self::p($candidate, 'website'), self::p($target, 'website'));
    }

    private static function sortKeys(mixed $v): mixed
    {
        if (self::isList($v)) {
            return array_map(static fn($x) => self::sortKeys($x), $v);
        }
        if ($v instanceof Obj) {
            $keys = $v->keys();
            usort($keys, 'strcmp');
            $o = new Obj();
            foreach ($keys as $k) {
                $o->set($k, self::sortKeys($v->get($k)));
            }
            return $o;
        }
        return $v;
    }

    /** JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b)); two undefined values are equal. */
    private static function sameJson(mixed $a, mixed $b): bool
    {
        $sa = $a === self::U ? null : Js::stringify(self::sortKeys($a));
        $sb = $b === self::U ? null : Js::stringify(self::sortKeys($b));
        return $sa === $sb;
    }

    private static function floorDiv(int $a, int $b): int
    {
        $q = intdiv($a, $b);
        return ($a % $b !== 0 && (($a < 0) !== ($b < 0))) ? $q - 1 : $q;
    }

    private static function daysFromCivil(int $y, int $m, int $d): int
    {
        $y -= $m <= 2 ? 1 : 0;
        $era = self::floorDiv($y, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    /** @return array{0:int,1:int,2:int} */
    private static function civilFromDays(int $z): array
    {
        $z += 719468;
        $era = self::floorDiv($z, 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $y = $yoe + $era * 400;
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $m = $mp + ($mp < 10 ? 3 : -9);
        return [$y + ($m <= 2 ? 1 : 0), $m, $d];
    }

    private static function daysInMonth(int $y, int $m): int
    {
        if ($m === 2) {
            return (($y % 4 === 0 && $y % 100 !== 0) || $y % 400 === 0) ? 29 : 28;
        }
        return in_array($m, [4, 6, 9, 11], true) ? 30 : 31;
    }

    /**
     * Epoch ms of an RFC 3339 instant, or null. STRICT and independent of the host time zone: `YYYY-MM-DD` (UTC midnight) or
     * `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`, with every component in range.
     */
    private static function parseInstant(mixed $s): ?int
    {
        if (!self::isStr($s) || preg_match('/\A(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2})))?\z/', $s, $m) !== 1) {
            return null;
        }
        [$y, $mo, $d] = [(int)$m[1], (int)$m[2], (int)$m[3]];
        if (!($mo >= 1 && $mo <= 12 && $d >= 1 && $d <= self::daysInMonth($y, $mo))) {
            return null;
        }
        $day = self::daysFromCivil($y, $mo, $d) * 86400000;
        if (!isset($m[4]) || $m[4] === '') {
            return $day;
        }
        [$h, $mi, $se] = [(int)$m[4], (int)$m[5], (int)$m[6]];
        if ($h > 23 || $mi > 59 || $se > 59) {
            return null;
        }
        $ms = isset($m[7]) && $m[7] !== '' ? (int)str_pad(substr($m[7], 0, 3), 3, '0') : 0;
        $offset = 0;
        if ($m[8] !== 'Z') {
            [$oh, $om] = [(int)$m[10], (int)$m[11]];
            if ($oh > 23 || $om > 59) {
                return null;
            }
            $offset = ($m[9] === '+' ? 1 : -1) * ($oh * 60 + $om) * 60000;
        }
        return $day + (($h * 60 + $mi) * 60 + $se) * 1000 + $ms - $offset;
    }

    private static function dateUtc(int $y, int $month0, int $d): int
    {
        if ($y >= 0 && $y <= 99) {
            $y += 1900; // Date.UTC maps the years 0..99 to 1900..1999
        }
        $y += self::floorDiv($month0, 12);
        return self::daysFromCivil($y, $month0 - self::floorDiv($month0, 12) * 12 + 1, $d) * 86400000;
    }

    /** Start (epoch ms, UTC) of the calendar period of `$frequency` that contains `$ms`; null for an unknown frequency or an invalid date. */
    private static function periodStart(float $ms, mixed $frequency): ?int
    {
        if (!is_finite($ms) || abs($ms) > 8.64e15) {
            return null;
        }
        $t = (int)$ms; // TimeClip truncates
        $days = self::floorDiv($t, 86400000);
        [$y, $mo, $d] = self::civilFromDays($days);
        $day = self::dateUtc($y, $mo - 1, $d);
        $DAY = 86400000;
        $wd = (($days % 7) + 7 + 4) % 7; // getUTCDay, 0 = Sunday
        switch ($frequency) {
            case 'ON_DEMAND':
                return 0;
            case 'DAILY':
                return $day;
            case 'WEEKLY':
                return $day - (($wd + 6) % 7) * $DAY;
            case 'BIWEEKLY':
                $weekStart = $day - (($wd + 6) % 7) * $DAY;
                $week = 7 * $DAY;
                $epochMonday = -3 * $DAY;
                return $epochMonday + self::floorDiv($weekStart - $epochMonday, 2 * $week) * 2 * $week;
            case 'MONTHLY':
                return self::dateUtc($y, $mo - 1, 1);
            case 'QUARTERLY':
                return self::dateUtc($y, intdiv($mo - 1, 3) * 3, 1);
            case 'ANNUALLY':
                return self::dateUtc($y, 0, 1);
        }
        return null;
    }

    private static function lt(mixed $a, mixed $b): bool
    {
        if (self::isStr($a) && self::isStr($b)) {
            return strcmp($a, $b) < 0;
        }
        return Payments::n($a) < Payments::n($b);
    }

    private static function ge(mixed $a, mixed $b): bool
    {
        if (self::isStr($a) && self::isStr($b)) {
            return strcmp($a, $b) >= 0;
        }
        return Payments::n($a) >= Payments::n($b);
    }

    private static function le(mixed $a, mixed $b): bool
    {
        if (self::isStr($a) && self::isStr($b)) {
            return strcmp($a, $b) <= 0;
        }
        return Payments::n($a) <= Payments::n($b);
    }

    private static function contextProblem(mixed $c): ?string
    {
        $last = self::p($c, 'lastUsedDate');
        if (!self::isNonNegInt(self::p($c, 'totalAmount')) || !self::isNonNegInt(self::p($c, 'totalUses')) || ($last !== self::U && !self::isNonNegInt($last))) {
            return 'mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate';
        }
        return null;
    }

    private static function iter(mixed $x): array
    {
        if (!self::isList($x)) {
            throw new \TypeError('x is not iterable');
        }
        return $x;
    }

    private static function evaluatePayment(mixed $c, mixed $closed, mixed $o): array
    {
        $amt = self::p($closed, 'payment_amount');
        $t = self::p($c, 'type');
        $ctx = Js::opt($o, 'context');
        $S = static fn(mixed $v): string => Payments::s($v);
        if ($t === 'payment.amount_range') {
            $v = [];
            if (!Payments::seq(self::p($amt, 'currency'), self::p($c, 'currency'))) {
                $v[] = 'currency mismatch: expected ' . $S(self::p($c, 'currency')) . ', got ' . $S(self::p($amt, 'currency'));
            }
            $mn = self::p($c, 'min');
            if (!is_finite(Payments::n(self::p($amt, 'amount')))) {
                $v[] = 'amount ' . $S(self::p($amt, 'amount')) . ' is not finite';
            }
            if ($mn !== self::U && !self::ge(self::p($amt, 'amount'), $mn)) {
                $v[] = 'amount ' . $S(self::p($amt, 'amount')) . ' below minimum ' . $S($mn);
            }
            if (!self::le(self::p($amt, 'amount'), self::p($c, 'max'))) {
                $v[] = 'amount ' . $S(self::p($amt, 'amount')) . ' exceeds maximum ' . $S(self::p($c, 'max'));
            }
            return $v;
        }
        if ($t === 'payment.allowed_payees') {
            foreach (self::iter(self::p($c, 'allowed')) as $m) {
                if (self::merchantMatches($m, self::p($closed, 'payee'))) {
                    return [];
                }
            }
            return ['payee ' . $S(self::p(self::p($closed, 'payee'), 'name')) . ' is not in the allowed list'];
        }
        if ($t === 'payment.allowed_payment_instruments') {
            $inst = self::p(self::p($closed, 'payment_instrument'), 'id');
            foreach (self::iter(self::p($c, 'allowed')) as $i) {
                if (Payments::seq(self::p($i, 'id'), $inst)) {
                    return [];
                }
            }
            return ['payment instrument ' . $S($inst) . ' is not in the allowed list'];
        }
        if ($t === 'payment.allowed_pisps') {
            $p = self::p($closed, 'pisp');
            if (!Payments::truthy($p)) {
                return ['missing PISP in the closed mandate'];
            }
            foreach (self::iter(self::p($c, 'allowed')) as $a) {
                if (Payments::seq(self::p($a, 'legal_name'), self::p($p, 'legal_name')) && Payments::seq(self::p($a, 'brand_name'), self::p($p, 'brand_name'))
                    && Payments::seq(self::p($a, 'domain_name'), self::p($p, 'domain_name'))) {
                    return [];
                }
            }
            return ['PISP is not in the allowed list'];
        }
        if ($t === 'payment.reference') {
            $h = Js::opt($o, 'openCheckoutHash');
            if (!Payments::truthy($h)) {
                return ['openCheckoutHash is required to evaluate a payment.reference constraint'];
            }
            return Payments::seq($h, self::p($c, 'conditional_transaction_id')) ? [] : ['payment.reference does not match the open checkout mandate hash'];
        }
        if ($t === 'payment.budget') {
            if (!Payments::seq(self::p($amt, 'currency'), self::p($c, 'currency'))) {
                return ['budget currency mismatch: expected ' . $S(self::p($c, 'currency')) . ', got ' . $S(self::p($amt, 'currency'))];
            }
            // the official SDK converts the budget with `int(max * 100)` for every currency; this reads it the same way
            if (!Payments::truthy($ctx)) {
                return ['mandate context is required to evaluate a budget'];
            }
            $bad = self::contextProblem($ctx);
            if ($bad !== null) {
                return [$bad];
            }
            $scaled = Payments::n(self::p($c, 'max')) * 100;
            $maxMinor = Payments::jsRound($scaled);
            if (!(abs($scaled - $maxMinor) <= 1e-6)) { // NaN or infinite max: refused
                return ['budget.max is not a whole number of minor units'];
            }
            $spend = Payments::n(self::p($ctx, 'totalAmount')) + Payments::n(self::p($amt, 'amount'));
            if (!(is_finite($spend) && $spend <= $maxMinor)) {
                return ['cumulative spend ' . Js::str(Payments::num($spend)) . ' exceeds budget ' . Js::str(Payments::num($maxMinor)) . ' (past spend ' . $S(self::p($ctx, 'totalAmount')) . ')'];
            }
            return [];
        }
        if ($t === 'payment.agent_recurrence') {
            $v = [];
            if (!in_array(self::p($c, 'frequency'), self::FREQUENCIES, true)) {
                return ['unknown recurrence frequency']; // strict: with or without a last-used date
            }
            if (Payments::truthy($ctx)) {
                $bad = self::contextProblem($ctx);
                if ($bad !== null) {
                    return [$bad];
                }
            }
            $mo = self::p($c, 'max_occurrences');
            if ($mo !== self::U) {
                if (!Payments::truthy($ctx)) {
                    return ['mandate context is required to evaluate recurrence limits'];
                }
                if (!self::lt(self::p($ctx, 'totalUses'), $mo)) {
                    $v[] = 'maximum occurrences exceeded: ' . $S(self::p($ctx, 'totalUses')) . ' >= ' . $S($mo);
                }
            }
            if (!Payments::seq(self::p($c, 'frequency'), 'ON_DEMAND')) {
                if (!Payments::truthy($ctx)) {
                    return ['mandate context is required to evaluate recurrence frequency'];
                }
                $last = self::p($ctx, 'lastUsedDate');
                if ($last !== self::U) {
                    $start = self::periodStart(Payments::n(Js::opt($o, 'now')) * 1000, self::p($c, 'frequency'));
                    if ($start === null || !(Payments::n($last) * 1000 < $start)) {
                        $v[] = 'already used in the current ' . $S(self::p($c, 'frequency')) . ' period';
                    }
                }
            }
            return $v;
        }
        if ($t === 'payment.execution_date') {
            $ed = self::p($closed, 'execution_date');
            $at = $ed !== self::U ? self::parseInstant($ed) : Payments::n(Js::opt($o, 'now')) * 1000;
            if ($at === null || !is_finite((float)$at)) {
                return ['execution_date ' . $S($ed) . ' is not a valid instant'];
            }
            $v = [];
            foreach ([['not_before', self::p($c, 'not_before'), true], ['not_after', self::p($c, 'not_after'), false]] as [$key, $bound, $before]) {
                if ($bound === self::U) {
                    continue;
                }
                $b = self::parseInstant($bound);
                if ($b === null) {
                    $v[] = "$key " . $S($bound) . ' is not a valid instant';
                } elseif ($before ? !($at >= $b) : !($at <= $b)) {
                    $v[] = 'execution date is ' . ($before ? 'before' : 'after') . " the allowed window ($key " . $S($bound) . ')';
                }
            }
            return $v;
        }
        return ['unknown constraint type ' . $S($t)];
    }

    /**
     * Violations of the open payment mandate's constraints and pre-set claims by `$closed` (empty = satisfied). `$o`: openCheckoutHash?,
     * context? ({totalAmount, totalUses, lastUsedDate?}), now (epoch seconds).
     * @return list<string>
     */
    public static function checkPaymentConstraints(mixed $open, mixed $closed, mixed $o): array
    {
        $v = [];
        $S = static fn(mixed $x): string => Payments::s($x);
        if (self::p($open, 'payee') !== self::U && !self::merchantMatches(self::p($open, 'payee'), self::p($closed, 'payee'))) {
            $v[] = 'pre-set payee mismatch: expected ' . $S(self::p(self::p($open, 'payee'), 'name')) . ', got ' . $S(self::p(self::p($closed, 'payee'), 'name'));
        }
        if (self::p($open, 'payment_amount') !== self::U && !self::sameJson(self::p($open, 'payment_amount'), self::p($closed, 'payment_amount'))) {
            $v[] = 'pre-set payment_amount mismatch';
        }
        if (self::p($open, 'payment_instrument') !== self::U && !self::sameJson(self::p($open, 'payment_instrument'), self::p($closed, 'payment_instrument'))) {
            $v[] = 'pre-set payment_instrument mismatch';
        }
        if (self::p($open, 'pisp') !== self::U && !self::sameJson(self::p($open, 'pisp'), self::p($closed, 'pisp'))) {
            $v[] = 'pre-set pisp mismatch';
        }
        if (self::p($open, 'execution_date') !== self::U && !Payments::seq(self::p($open, 'execution_date'), self::p($closed, 'execution_date'))) {
            $v[] = 'pre-set execution_date mismatch';
        }
        $constraints = self::iter(self::p($open, 'constraints'));
        $types = array_map(static fn($c) => self::p($c, 'type'), $constraints);
        if (in_array('payment.agent_recurrence', $types, true)) {
            if (!in_array('payment.amount_range', $types, true)) {
                $v[] = 'payment.agent_recurrence requires a payment.amount_range constraint';
            }
            if (!in_array('payment.budget', $types, true)) {
                $v[] = 'payment.agent_recurrence requires a payment.budget constraint';
            }
        }
        foreach ($constraints as $c) {
            array_push($v, ...self::evaluatePayment($c, $closed, $o));
        }
        return $v;
    }

    // ---- checkout side ------------------------------------------------------------------------------------------------------

    /** Validate and project the checkout payload (`checkout_jwt`); throws a descriptive message when malformed. */
    public static function projectCheckout(mixed $payload): Obj
    {
        $bad = static function (string $m): never {
            throw new Ap2Error("checkout_jwt payload: $m");
        };
        $id = self::p($payload, 'id');
        $cur = self::p($payload, 'currency');
        $lis = self::p($payload, 'line_items');
        $totals = self::p($payload, 'totals');
        if (!self::isStr($id) || $id === '') {
            $bad('id is required');
        }
        if (!self::currencyOk($cur)) {
            $bad('currency must be ISO 4217');
        }
        if (!self::isList($lis) || $lis === []) {
            $bad('line_items must be a non-empty array');
        }
        if (!self::isList($totals)) {
            $bad('totals must be an array');
        }
        $lines = [];
        foreach ($lis as $i => $li) {
            if (!self::isObject($li) || !self::isStr(self::p($li, 'id')) || !self::isObject(self::p($li, 'item'))) {
                $bad("line_items[$i] is malformed");
            }
            $item = self::p($li, 'item');
            $price = self::p($item, 'price');
            if (!self::isStr(self::p($item, 'id')) || !self::isStr(self::p($item, 'title')) || !Payments::safeInt($price) || Payments::n($price) < 0 || !self::isInt($price)) {
                $bad("line_items[$i].item needs id, title and integer minor-unit price");
            }
            $qty = self::p($li, 'quantity');
            if (!Payments::safeInt($qty) || Payments::n($qty) < 1) {
                $bad("line_items[$i].quantity must be a positive integer");
            }
            $lines[] = Obj::of(['id' => self::p($li, 'id'), 'item' => Obj::of(['id' => self::p($item, 'id'), 'title' => self::p($item, 'title'), 'price' => $price]), 'quantity' => $qty]);
        }
        $tt = [];
        foreach ($totals as $i => $t) {
            if (!self::isObject($t) || !self::isStr(self::p($t, 'type')) || !Payments::safeInt(self::p($t, 'amount')) || !self::isInt(self::p($t, 'amount'))) {
                $bad("totals[$i] is malformed");
            }
            $tt[] = Obj::of(['type' => self::p($t, 'type'), 'amount' => self::p($t, 'amount')]);
        }
        $out = Obj::of(['id' => $id, 'currency' => $cur, 'line_items' => $lines, 'totals' => $tt]);
        if (self::p($payload, 'merchant') !== self::U) {
            $m = self::p($payload, 'merchant');
            if (!self::isObject($m) || !self::isStr(self::p($m, 'id')) || !self::isStr(self::p($m, 'name'))) {
                $bad('merchant needs id and name');
            }
            $merchant = Obj::of(['id' => self::p($m, 'id'), 'name' => self::p($m, 'name')]);
            if (self::isStr(self::p($m, 'website'))) {
                $merchant->set('website', self::p($m, 'website'));
            }
            $out->set('merchant', $merchant);
        }
        return $out;
    }

    /** The checkout's single `total` entry in minor units, or null if absent / ambiguous. */
    public static function checkoutTotal(mixed $c): mixed
    {
        $t = array_values(array_filter(self::p($c, 'totals'), static fn($x): bool => self::p($x, 'type') === 'total'));
        return count($t) === 1 ? self::p($t[0], 'amount') : null;
    }

    /** @return list<string> */
    private static function lineItemViolations(array $cart, mixed $reqs): array
    {
        $reqs = self::iter($reqs);
        $qty = [];
        $skus = [];
        foreach ($cart as $li) {
            $k = (string)self::p(self::p($li, 'item'), 'id');
            if (!isset($qty["k$k"])) {
                $skus[] = $k;
                $qty["k$k"] = 0.0;
            }
            $qty["k$k"] += Payments::n(self::p($li, 'quantity'));
        }
        $S = 0;
        $T = 1 + count($skus) + count($reqs);
        $cap = array_fill(0, $T + 1, []);
        $add = static function (int $u, int $v, float $c) use (&$cap): void {
            $cap[$u][$v] = ($cap[$u][$v] ?? 0.0) + $c;
            $cap[$v][$u] = $cap[$v][$u] ?? 0.0;
        };
        $INF = 9007199254740991.0;
        foreach ($skus as $i => $s) {
            $add($S, 1 + $i, $qty["k$s"]);
        }
        foreach ($reqs as $j => $r) {
            $add(1 + count($skus) + $j, $T, Payments::n(self::p($r, 'quantity')));
            $ok = [];
            foreach (self::iter(self::p($r, 'acceptable_items')) as $a) {
                $ok[] = self::p($a, 'id');
            }
            foreach ($skus as $i => $s) {
                foreach ($ok as $x) {
                    if (Payments::seq($s, $x)) {
                        $add(1 + $i, 1 + count($skus) + $j, $INF);
                        break;
                    }
                }
            }
        }
        $flow = 0.0;
        while (true) {
            $parent = [$S => $S];
            $queue = [$S];
            for ($h = 0; $h < count($queue) && !isset($parent[$T]); $h++) {
                $u = $queue[$h];
                foreach ($cap[$u] as $v => $c) {
                    if ($c > 0 && !isset($parent[$v])) {
                        $parent[$v] = $u;
                        $queue[] = $v;
                    }
                }
            }
            if (!isset($parent[$T])) {
                break;
            }
            $push = $INF;
            for ($v = $T; $v !== $S; $v = $parent[$v]) {
                $push = min($push, $cap[$parent[$v]][$v]);
            }
            for ($v = $T; $v !== $S; $v = $parent[$v]) {
                $u = $parent[$v];
                $cap[$u][$v] -= $push;
                $cap[$v][$u] += $push;
            }
            $flow += $push;
        }
        $required = 0.0;
        foreach ($reqs as $r) {
            $required += Payments::n(self::p($r, 'quantity'));
        }
        $carted = array_sum($qty);
        if ($flow === $required && $flow === (float)$carted) {
            return [];
        }
        return ['line items do not satisfy the constraint: assigned ' . Js::str(Payments::num($flow)) . ' of ' . Js::str(Payments::num($required)) . ' required and '
            . Js::str(Payments::num((float)$carted)) . ' carted units'];
    }

    private static function evaluateCheckout(mixed $c, mixed $checkout): array
    {
        $t = self::p($c, 'type');
        if ($t === 'checkout.allowed_merchants') {
            $m = self::p($checkout, 'merchant');
            if (!Payments::truthy($m)) {
                return ['missing merchant in the checkout'];
            }
            foreach (self::iter(self::p($c, 'allowed')) as $a) {
                if (self::merchantMatches($a, $m)) {
                    return [];
                }
            }
            return ['merchant ' . Payments::s(self::p($m, 'name')) . ' is not in the allowed list'];
        }
        if ($t !== 'checkout.line_items') {
            return ['unknown constraint type ' . Payments::s($t)];
        }
        $items = self::p($checkout, 'line_items');
        return $items === [] ? ['empty cart does not satisfy a line_items constraint'] : self::lineItemViolations($items, self::p($c, 'items'));
    }

    /** Violations of the open checkout mandate's constraints by `$checkout` (empty = satisfied). @return list<string> */
    public static function checkCheckoutConstraints(mixed $open, mixed $checkout): array
    {
        $out = [];
        foreach (self::iter(self::p($open, 'constraints')) as $c) {
            array_push($out, ...self::evaluateCheckout($c, $checkout));
        }
        return $out;
    }

    // ---- issuing open mandates ----------------------------------------------------------------------------------------------

    private static function signRoot(mixed $c, Obj $mandate, Ap2DisclosureBuilder $b): string
    {
        $element = $b->element($mandate);
        $issuer = self::p($c, 'issuer');
        $typ = Js::opt($c, 'typ');
        $header = Obj::of(['typ' => $typ ?? self::ROOT_TYP]);
        if (self::p($issuer, 'kid') !== self::U) {
            $header->set('kid', self::p($issuer, 'kid'));
        }
        if (Payments::truthy(self::p($issuer, 'x5c'))) {
            $header->set('x5c', self::p($issuer, 'x5c'));
        }
        return self::signSdJwt(['header' => $header, 'payload' => Obj::of(['delegate_payload' => [$element], '_sd_alg' => Js::opt($c, 'sdAlg') ?? 'sha-256']),
            'disclosures' => $b->disclosures, 'privateKey' => self::p($issuer, 'privateKey')]);
    }

    private static function commonClaims(mixed $c): Obj
    {
        $jwk = self::assertP256Jwk(self::p($c, 'agentJwk'), 'agentJwk');
        $iat = self::p($c, 'iat');
        $exp = self::p($c, 'exp');
        if (!Payments::safeInt($iat) || !Payments::safeInt($exp) || !(Payments::n($exp) > Payments::n($iat))) {
            throw new Ap2Error('open mandate: need integer iat < exp (epoch seconds)');
        }
        $out = Obj::of(['cnf' => Obj::of(['jwk' => Obj::of(['crv' => 'P-256', 'kty' => 'EC', 'x' => $jwk->get('x'), 'y' => $jwk->get('y')])]), 'iat' => $iat, 'exp' => $exp]);
        if (Payments::truthy(self::p($c, 'pca'))) {
            $out->set(self::PCA_CLAIM, self::p($c, 'pca'));
        }
        return $out;
    }

    private static function sdPaymentConstraint(mixed $c, Ap2DisclosureBuilder $b): mixed
    {
        $t = self::p($c, 'type');
        if ($t === 'payment.allowed_payees' || $t === 'payment.allowed_payment_instruments') {
            return Obj::of(['type' => $t, 'allowed' => array_map(static fn($x) => $b->element($x), self::iter(self::p($c, 'allowed')))]);
        }
        return $c;
    }

    private static function sdCheckoutConstraint(mixed $c, Ap2DisclosureBuilder $b): mixed
    {
        $t = self::p($c, 'type');
        if ($t === 'checkout.allowed_merchants') {
            return Obj::of(['type' => $t, 'allowed' => array_map(static fn($x) => $b->element($x), self::iter(self::p($c, 'allowed')))]);
        }
        $items = [];
        foreach (self::iter(self::p($c, 'items')) as $it) {
            $items[] = Payments::obj(['id' => self::p($it, 'id'), 'acceptable_items' => array_map(static fn($x) => $b->element($x), self::iter(self::p($it, 'acceptable_items'))),
                'quantity' => self::p($it, 'quantity')]);
        }
        return Payments::obj(['type' => $t, 'items' => $items]);
    }

    private static function assertWellFormed(Obj $wrapped, \Closure $problems, string $what, mixed $plainConstraints): void
    {
        $plain = Payments::spreadObj($wrapped);
        $plain->set('constraints', $plainConstraints);
        $p = $problems($plain);
        if ($p !== []) {
            throw new Ap2Error("$what: " . implode('; ', $p));
        }
    }

    private static function builderOf(mixed $input): Ap2DisclosureBuilder
    {
        $salt = Js::opt($input, 'salt');
        return self::disclosureBuilder(Js::opt($input, 'sdAlg'), $salt instanceof \Closure ? $salt : null);
    }

    /**
     * Issue an open Payment Mandate (`mandate.payment.open.1`) as a signed SD-JWT. `$input`: issuer ({privateKey, kid?, x5c?}), agentJwk,
     * iat, exp, constraints, payee?, paymentAmount?, paymentInstrument?, pisp?, executionDate?, pca?, sdAlg?, salt?, typ?.
     */
    public static function issueOpenPaymentMandate(mixed $input): string
    {
        $b = self::builderOf($input);
        $mandate = Obj::of(['vct' => self::VCT_PAYMENT_OPEN, 'constraints' => array_map(static fn($c) => self::sdPaymentConstraint($c, $b), self::iter(self::p($input, 'constraints')))]);
        foreach ([['payee', 'payee'], ['payment_amount', 'paymentAmount'], ['payment_instrument', 'paymentInstrument'], ['pisp', 'pisp']] as [$member, $key]) {
            if (Payments::truthy(self::p($input, $key))) {
                $mandate->set($member, self::p($input, $key));
            }
        }
        if (self::p($input, 'executionDate') !== self::U) {
            $mandate->set('execution_date', self::p($input, 'executionDate'));
        }
        $common = self::commonClaims($input);
        foreach ($common->keys() as $k) {
            $mandate->set($k, $common->get($k));
        }
        self::assertWellFormed($mandate, static fn($v) => self::openPaymentMandateProblems($v), 'open payment mandate', self::p($input, 'constraints'));
        return self::signRoot($input, $mandate, $b);
    }

    /** Issue an open Checkout Mandate (`mandate.checkout.open.1`) as a signed SD-JWT (same `$input`; `constraints` are checkout constraints). */
    public static function issueOpenCheckoutMandate(mixed $input): string
    {
        $b = self::builderOf($input);
        $mandate = Obj::of(['vct' => self::VCT_CHECKOUT_OPEN, 'constraints' => array_map(static fn($c) => self::sdCheckoutConstraint($c, $b), self::iter(self::p($input, 'constraints')))]);
        $common = self::commonClaims($input);
        foreach ($common->keys() as $k) {
            $mandate->set($k, $common->get($k));
        }
        self::assertWellFormed($mandate, static fn($v) => self::openCheckoutMandateProblems($v), 'open checkout mandate', self::p($input, 'constraints'));
        return self::signRoot($input, $mandate, $b);
    }

    // ---- presenting closed mandates (KB-SD-JWT hops) ------------------------------------------------------------------------

    private static function presentHop(mixed $c, \Closure $build): string
    {
        if (!Payments::truthy(self::p($c, 'aud')) || !Payments::truthy(self::p($c, 'nonce'))) {
            throw new Ap2Error('closed mandate: aud and nonce are required');
        }
        if (!Payments::safeInt(self::p($c, 'iat'))) {
            throw new Ap2Error('closed mandate: iat must be an integer');
        }
        $prev = self::parseSdJwtHop(self::p($c, 'open'));
        $salt = Js::opt($c, 'salt');
        $b = self::disclosureBuilder($prev->get('sdAlg'), $salt instanceof \Closure ? $salt : null);
        $mandate = $build($b);
        $element = $b->element($mandate);
        $mode = Js::opt($c, 'hashMode') ?? 'sd_hash';
        $payload = Obj::of(['delegate_payload' => [$element], 'iat' => self::p($c, 'iat'), 'aud' => self::p($c, 'aud'), 'nonce' => self::p($c, 'nonce')]);
        $payload->set(Payments::s($mode), $mode === 'sd_hash' ? self::sdHashOf($prev) : self::issuerJwtHashOf($prev));
        $payload->set('_sd_alg', $prev->get('sdAlg'));
        $agentKey = self::p($c, 'agentKey');
        $hop = self::signSdJwt(['header' => Obj::of(['typ' => 'kb+sd-jwt']), 'payload' => $payload, 'disclosures' => $b->disclosures,
            'privateKey' => $agentKey instanceof Ap2KeyPair ? $agentKey->privateKey : self::p($agentKey, 'privateKey')]);
        // hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~"
        return self::p($c, 'open') . '~' . $hop;
    }

    /**
     * Present a closed Payment Mandate (`mandate.payment.1`) on top of an open payment mandate. `$input`: open, agentKey (Ap2KeyPair), aud,
     * nonce, iat, transactionId, payee, paymentAmount, paymentInstrument, pisp?, executionDate?, riskData?, exp?, pca?, hashMode?, salt?.
     */
    public static function presentClosedPayment(mixed $input): string
    {
        return self::presentHop($input, static function (Ap2DisclosureBuilder $b) use ($input): Obj {
            $mandate = Payments::obj(['vct' => self::VCT_PAYMENT, 'transaction_id' => self::p($input, 'transactionId'), 'payee' => self::p($input, 'payee'),
                'payment_amount' => self::p($input, 'paymentAmount'), 'payment_instrument' => self::p($input, 'paymentInstrument')]);
            if (Payments::truthy(self::p($input, 'pisp'))) {
                $mandate->set('pisp', self::p($input, 'pisp'));
            }
            if (self::p($input, 'executionDate') !== self::U) {
                $mandate->set('execution_date', self::p($input, 'executionDate'));
            }
            if (Payments::truthy(self::p($input, 'riskData'))) {
                $mandate->set('risk_data', self::p($input, 'riskData'));
            }
            if (self::p($input, 'exp') !== self::U) {
                $mandate->set('exp', self::p($input, 'exp'));
            }
            if (Payments::truthy(self::p($input, 'pca'))) {
                $mandate->set(self::PCA_CLAIM, self::p($input, 'pca'));
            }
            $p = self::paymentMandateProblems($mandate);
            if ($p !== []) {
                throw new Ap2Error('closed payment mandate: ' . implode('; ', $p));
            }
            return $mandate;
        });
    }

    /** Present a closed Checkout Mandate (`mandate.checkout.1`) on top of an open checkout mandate (`$input` as above, with `checkoutJwt`). */
    public static function presentClosedCheckout(mixed $input): string
    {
        return self::presentHop($input, static function (Ap2DisclosureBuilder $b) use ($input): Obj {
            $prevAlg = self::p(self::parseSdJwtHop(self::p($input, 'open')), 'sdAlg');
            $jwt = self::p($input, 'checkoutJwt');
            $mandate = Obj::of(['_sd' => [$b->property('checkout_jwt', $jwt === self::U ? null : $jwt)], 'vct' => self::VCT_CHECKOUT, 'checkout_hash' => self::sdDigest($jwt, $prevAlg)]);
            if (self::p($input, 'exp') !== self::U) {
                $mandate->set('exp', self::p($input, 'exp'));
            }
            if (Payments::truthy(self::p($input, 'pca'))) {
                $mandate->set(self::PCA_CLAIM, self::p($input, 'pca'));
            }
            $check = Payments::spreadObj($mandate);
            $check->set('checkout_jwt', $jwt);
            $p = self::checkoutMandateProblems($check);
            if ($p !== []) {
                throw new Ap2Error('closed checkout mandate: ' . implode('; ', $p));
            }
            return $mandate;
        });
    }

    // ---- verifying a delegation chain ---------------------------------------------------------------------------------------

    /** Split a `~~`-joined chain into hops, each restored to `<jwt>~<d>...~`. @return list<string> */
    public static function splitChain(mixed $token): array
    {
        if (!is_string($token) || $token === '') {
            throw new Ap2Error('chain: empty');
        }
        $parts = explode('~~', $token);
        if (count($parts) > self::MAX_HOPS) {
            throw new Ap2Error('chain: more than ' . self::MAX_HOPS . ' hops');
        }
        $n = count($parts);
        return array_map(static fn($p, $i) => $i === $n - 1 ? $p : "$p~", $parts, array_keys($parts));
    }

    private static function checkTimes(string $label, mixed $o, mixed $now, mixed $skew): void
    {
        $exp = self::p($o, 'exp');
        $iat = self::p($o, 'iat');
        if ($exp !== self::U) {
            if (!self::isInt($exp)) {
                throw new Ap2Error("$label: exp must be an integer");
            }
            if (!(is_finite(Payments::n($now)) && is_finite(Payments::n($skew)) && Payments::n($now) <= Payments::n($exp) + Payments::n($skew))) {
                throw new Ap2Error("$label: expired at " . Payments::s($exp));
            }
        }
        if ($iat !== self::U) {
            if (!self::isInt($iat)) {
                throw new Ap2Error("$label: iat must be an integer");
            }
            if (!(is_finite(Payments::n($now)) && is_finite(Payments::n($skew)) && Payments::n($iat) <= Payments::n($now) + Payments::n($skew))) {
                throw new Ap2Error("$label: iat is in the future");
            }
        }
    }

    private static function delegateMandate(mixed $claims, string $label): Obj
    {
        $dp = self::p($claims, 'delegate_payload');
        if (!self::isList($dp)) {
            throw new Ap2Error("$label: delegate_payload missing");
        }
        if (count($dp) !== 1 || !self::isObject($dp[0])) {
            throw new Ap2Error("$label: delegate_payload must disclose exactly one mandate (got " . count($dp) . ')');
        }
        return $dp[0];
    }

    private static function cnfJwk(mixed $mandate, string $label): Obj
    {
        $cnf = self::p($mandate, 'cnf');
        if (!self::isObject($cnf) || !self::isObject(self::p($cnf, 'jwk'))) {
            throw new Ap2Error("$label: no cnf.jwk to delegate to");
        }
        return self::assertP256Jwk(self::p($cnf, 'jwk'), "$label cnf.jwk");
    }

    /**
     * Verify one key-binding hop against its predecessor (signature, typ, binding hash, times, aud/nonce). `$prev`: {hop, mandate};
     * `$o`: {terminal, expectedAudience?, expectedNonce?, now, skew}. Returns {index: -1, kind, hop, claims, mandate}.
     */
    public static function verifyKbHop(mixed $hop, mixed $prev, mixed $o, string $label): Obj
    {
        $typ = self::p(self::p($hop, 'header'), 'typ');
        $terminal = Js::opt($o, 'terminal') === true;
        $allowed = $terminal ? self::TYP_TERMINAL : self::TYP_INTERMEDIATE;
        if (!self::isStr($typ) || !in_array($typ, $allowed, true)) {
            throw new Ap2Error("$label: typ must be one of " . implode(', ', $allowed));
        }
        if (self::p(self::p($hop, 'header'), 'crit') !== self::U) {
            throw new Ap2Error("$label: crit headers are not supported");
        }
        $key = self::cnfJwk(Js::opt($prev, 'mandate'), 'preceding mandate');
        if (!self::verifyHopSignature($hop, $key)) {
            throw new Ap2Error("$label: signature does not verify under the preceding mandate's cnf.jwk");
        }
        $claims = self::processDisclosures(self::p($hop, 'payload'), self::p($hop, 'disclosures'), self::p($hop, 'sdAlg'));
        $hasSd = $claims->has('sd_hash');
        $hasIss = $claims->has('issuer_jwt_hash');
        if ($hasSd === $hasIss) {
            throw new Ap2Error("$label: exactly one of sd_hash / issuer_jwt_hash is required");
        }
        $expected = $hasSd ? self::sdHashOf(Js::opt($prev, 'hop')) : self::issuerJwtHashOf(Js::opt($prev, 'hop'));
        $actual = $hasSd ? $claims->get('sd_hash') : $claims->get('issuer_jwt_hash');
        if (!Payments::seq($actual, $expected)) {
            throw new Ap2Error("$label: " . ($hasSd ? 'sd_hash' : 'issuer_jwt_hash') . ' does not match the preceding hop');
        }
        if (!$claims->has('iat')) {
            throw new Ap2Error("$label: iat is required");
        }
        $now = Js::opt($o, 'now');
        $skew = Js::opt($o, 'skew');
        self::checkTimes($label, $claims, $now, $skew);
        $mandate = self::delegateMandate($claims, $label);
        self::checkTimes("$label mandate", $mandate, $now, $skew);
        $hasCnf = self::isObject($mandate->get('cnf'));
        if ($terminal && $hasCnf) {
            throw new Ap2Error("$label: a terminal hop must not carry cnf");
        }
        if (!$terminal && !$hasCnf) {
            throw new Ap2Error("$label: an intermediate hop requires cnf");
        }
        if ($terminal) {
            $aud = Js::opt($o, 'expectedAudience');
            if ($aud === null || !Payments::seq(self::p($claims, 'aud'), $aud)) {
                throw new Ap2Error("$label: aud mismatch");
            }
            $nonce = Js::opt($o, 'expectedNonce');
            if ($nonce === null || !Payments::seq(self::p($claims, 'nonce'), $nonce)) {
                throw new Ap2Error("$label: nonce mismatch");
            }
        }
        return Obj::of(['index' => -1, 'kind' => $terminal ? 'terminal' : 'intermediate', 'hop' => $hop, 'claims' => $claims, 'mandate' => $mandate]);
    }

    private static function fail(\Throwable $e): Obj
    {
        return Obj::of(['ok' => false, 'reason' => $e->getMessage()]);
    }

    /**
     * Verify a whole chain: root signature, then every hop in order. Never throws; reports the reason. `$o`: resolveIssuerKey(header) ->
     * public JWK or null, expectedAudience and expectedNonce (both required), now?, clockSkewSeconds? (default 60).
     * Returns {ok: true, hops} or {ok: false, reason}.
     */
    public static function verifyDelegationChain(mixed $token, mixed $o): Obj
    {
        try {
            if (!Payments::truthy(Js::opt($o, 'expectedAudience')) || !Payments::truthy(Js::opt($o, 'expectedNonce'))) {
                throw new Ap2Error('verify: expectedAudience and expectedNonce are required');
            }
            $now = Js::opt($o, 'now') ?? self::now();
            $skew = Js::opt($o, 'clockSkewSeconds') ?? 60;
            $segments = array_map(static fn($s) => self::parseSdJwtHop($s), self::splitChain($token));
            $root = $segments[0];
            if (self::p($root->get('header'), 'crit') !== self::U) {
                throw new Ap2Error('root: crit headers are not supported');
            }
            $resolve = Js::opt($o, 'resolveIssuerKey');
            $issuerKey = $resolve($root->get('header'));
            if (!Payments::truthy($issuerKey)) {
                throw new Ap2Error('root: no issuer key for this header');
            }
            if (!self::verifyHopSignature($root, $issuerKey)) {
                throw new Ap2Error('root: signature does not verify under the issuer key');
            }
            $rootClaims = self::processDisclosures($root->get('payload'), $root->get('disclosures'), $root->get('sdAlg'));
            self::checkTimes('root', $rootClaims, $now, $skew);
            $rootMandate = self::delegateMandate($rootClaims, 'root');
            self::checkTimes('root mandate', $rootMandate, $now, $skew);
            $hops = [Obj::of(['index' => 0, 'kind' => 'root', 'hop' => $root, 'claims' => $rootClaims, 'mandate' => $rootMandate])];
            $n = count($segments);
            for ($i = 1; $i < $n; $i++) {
                $v = self::verifyKbHop($segments[$i], $hops[$i - 1], ['terminal' => $i === $n - 1, 'expectedAudience' => Js::opt($o, 'expectedAudience'),
                    'expectedNonce' => Js::opt($o, 'expectedNonce'), 'now' => $now, 'skew' => $skew], "hop $i");
                $v->set('index', $i);
                $hops[] = $v;
            }
            return Obj::of(['ok' => true, 'hops' => $hops]);
        } catch (\Throwable $e) {
            return self::fail($e);
        }
    }

    private static function pair(Obj $r): array
    {
        $hops = $r->get('hops');
        if (count($hops) !== 2) {
            throw new Ap2Error('expected an open mandate followed by one closed mandate, got ' . count($hops) . ' hop(s)');
        }
        return [$hops[0], $hops[1]];
    }

    private static function requireOpenExpiry(mixed $m, string $label): void
    {
        if (!Payments::safeInt(self::p($m, 'exp'))) {
            throw new Ap2Error("$label: an open mandate must carry exp");
        }
    }

    /** Verify an open+closed checkout chain, the merchant-signed checkout, its hash, and the open constraints. `$o`: chain options + resolveMerchantKey(header). */
    public static function verifyCheckoutChain(mixed $token, mixed $o): Obj
    {
        $r = self::verifyDelegationChain($token, $o);
        if ($r->get('ok') !== true) {
            return $r;
        }
        try {
            [$openHop, $closedHop] = self::pair($r);
            $open = $openHop->get('mandate');
            $closed = $closedHop->get('mandate');
            $op = self::openCheckoutMandateProblems($open);
            if ($op !== []) {
                throw new Ap2Error('open checkout mandate: ' . implode('; ', $op));
            }
            self::requireOpenExpiry($open, 'open checkout mandate');
            $cp = self::checkoutMandateProblems($closed);
            if ($cp !== []) {
                throw new Ap2Error('closed checkout mandate: ' . implode('; ', $cp));
            }
            $alg = $closedHop->get('hop')->get('sdAlg');
            if (!Payments::seq(self::sdDigest(self::p($closed, 'checkout_jwt'), $alg), self::p($closed, 'checkout_hash'))) {
                throw new Ap2Error('checkout_hash does not match checkout_jwt');
            }
            $jwt = self::parseJwt(self::p($closed, 'checkout_jwt'), 'checkout_jwt');
            $resolve = Js::opt($o, 'resolveMerchantKey');
            $key = $resolve($jwt->get('header'));
            if (!Payments::truthy($key)) {
                throw new Ap2Error('checkout_jwt: no merchant key for this header');
            }
            if (!self::verifyJwtEs256($jwt, $key)) {
                throw new Ap2Error('checkout_jwt: merchant signature does not verify');
            }
            $checkout = self::projectCheckout($jwt->get('payload'));
            $violations = self::checkCheckoutConstraints($open, $checkout);
            if ($violations !== []) {
                return Obj::of(['ok' => false, 'reason' => 'open checkout constraints violated: ' . implode('; ', $violations), 'violations' => $violations]);
            }
            return Obj::of(['ok' => true, 'open' => $open, 'closed' => $closed, 'checkoutJwt' => self::p($closed, 'checkout_jwt'), 'checkout' => $checkout,
                'openHash' => self::sdHashOf($openHop->get('hop')), 'hops' => $r->get('hops')]);
        } catch (\Throwable $e) {
            return self::fail($e);
        }
    }

    /** Verify an open+closed payment chain and every open payment constraint. `$o`: chain options + openCheckoutHash, context?, expectedTransactionId?. */
    public static function verifyPaymentChain(mixed $token, mixed $o): Obj
    {
        $r = self::verifyDelegationChain($token, $o);
        if ($r->get('ok') !== true) {
            return $r;
        }
        try {
            [$openHop, $closedHop] = self::pair($r);
            $open = $openHop->get('mandate');
            $closed = $closedHop->get('mandate');
            $op = self::openPaymentMandateProblems($open);
            if ($op !== []) {
                throw new Ap2Error('open payment mandate: ' . implode('; ', $op));
            }
            self::requireOpenExpiry($open, 'open payment mandate');
            $cp = self::paymentMandateProblems($closed);
            if ($cp !== []) {
                throw new Ap2Error('closed payment mandate: ' . implode('; ', $cp));
            }
            $expected = Js::opt($o, 'expectedTransactionId');
            if ($expected !== null && !Payments::seq(self::p($closed, 'transaction_id'), $expected)) {
                throw new Ap2Error('transaction_id does not match the checkout being settled');
            }
            $opts = ['openCheckoutHash' => Js::opt($o, 'openCheckoutHash'), 'now' => Js::opt($o, 'now') ?? self::now()];
            if (Payments::truthy(Js::opt($o, 'context'))) {
                $opts['context'] = Js::opt($o, 'context');
            }
            $violations = self::checkPaymentConstraints($open, $closed, $opts);
            if ($violations !== []) {
                return Obj::of(['ok' => false, 'reason' => 'open payment constraints violated: ' . implode('; ', $violations), 'violations' => $violations]);
            }
            return Obj::of(['ok' => true, 'open' => $open, 'closed' => $closed, 'openHash' => self::sdHashOf($openHop->get('hop')), 'hops' => $r->get('hops')]);
        } catch (\Throwable $e) {
            return self::fail($e);
        }
    }

    /** @return array<string,mixed> the members of an Obj / array option bag */
    private static function bag(mixed $o): array
    {
        $out = [];
        if ($o instanceof Obj) {
            foreach ($o->keys() as $k) {
                $out[$k] = $o->get($k);
            }
        } elseif (is_array($o) && !array_is_list($o)) {
            $out = $o;
        }
        return $out;
    }

    /**
     * Verify a complete purchase: the checkout chain, then the payment chain bound to it, and that the payment settles what the merchant
     * quoted (payee, currency, total). `$o`: resolveIssuerKey, resolveMerchantKey, checkout and payment ({expectedAudience, expectedNonce}),
     * context?, now?, clockSkewSeconds?.
     */
    public static function verifyPurchase(mixed $checkoutToken, mixed $paymentToken, mixed $o): Obj
    {
        $base = ['resolveIssuerKey' => Js::opt($o, 'resolveIssuerKey')];
        if (Js::opt($o, 'now') !== null) {
            $base['now'] = Js::opt($o, 'now');
        }
        if (Js::opt($o, 'clockSkewSeconds') !== null) {
            $base['clockSkewSeconds'] = Js::opt($o, 'clockSkewSeconds');
        }
        $copts = [...$base, ...self::bag(Js::opt($o, 'checkout')), 'resolveMerchantKey' => Js::opt($o, 'resolveMerchantKey')];
        $co = self::verifyCheckoutChain($checkoutToken, $copts);
        if ($co->get('ok') !== true) {
            return Obj::of(['ok' => false, 'reason' => 'checkout: ' . $co->get('reason')]);
        }
        $popts = [...$base, ...self::bag(Js::opt($o, 'payment')), 'openCheckoutHash' => $co->get('openHash'), 'expectedTransactionId' => self::p($co->get('closed'), 'checkout_hash')];
        if (Payments::truthy(Js::opt($o, 'context'))) {
            $popts['context'] = Js::opt($o, 'context');
        }
        $pay = self::verifyPaymentChain($paymentToken, $popts);
        if ($pay->get('ok') !== true) {
            return Obj::of(['ok' => false, 'reason' => 'payment: ' . $pay->get('reason')]);
        }
        $total = self::checkoutTotal($co->get('checkout'));
        if ($total === null) {
            return Obj::of(['ok' => false, 'reason' => 'checkout: needs exactly one total entry']);
        }
        $amt = self::p($pay->get('closed'), 'payment_amount');
        if (!Payments::seq(self::p($amt, 'currency'), self::p($co->get('checkout'), 'currency'))) {
            return Obj::of(['ok' => false, 'reason' => 'payment currency differs from the checkout currency']);
        }
        if (!Payments::seq(self::p($amt, 'amount'), $total)) {
            return Obj::of(['ok' => false, 'reason' => 'payment amount ' . Payments::s(self::p($amt, 'amount')) . ' differs from the checkout total ' . Payments::s($total)]);
        }
        $merchant = self::p($co->get('checkout'), 'merchant');
        if (!Payments::truthy($merchant)) {
            return Obj::of(['ok' => false, 'reason' => 'checkout: no merchant to compare the payee with']);
        }
        if (!Payments::seq(self::p($merchant, 'id'), self::p(self::p($pay->get('closed'), 'payee'), 'id'))) {
            return Obj::of(['ok' => false, 'reason' => 'payee differs from the checkout merchant']);
        }
        return Obj::of(['ok' => true, 'checkout' => $co, 'payment' => $pay]);
    }

    /**
     * verifyPurchase plus single use and server-owned cumulative state. The usage context comes from `$ledger`, never from the caller,
     * and the purchase's transaction id can be redeemed once. A missing or failing ledger denies. `$o` is the verifyPurchase options without `context`.
     */
    public static function redeemPurchase(mixed $checkoutToken, mixed $paymentToken, mixed $o, mixed $ledger): Obj
    {
        if (!($ledger instanceof PurchaseLedger)) {
            return Obj::of(['ok' => false, 'reason' => 'ledger_required']);
        }
        // a zero context is the most permissive one for budget and recurrence, so a failure here is final
        $first = self::verifyPurchase($checkoutToken, $paymentToken, [...self::bag($o), 'context' => Obj::of(['totalAmount' => 0, 'totalUses' => 0])]);
        if ($first->get('ok') !== true) {
            return $first;
        }
        $payment = $first->get('payment');
        $openHash = $payment->get('openHash');
        $txId = self::p($payment->get('closed'), 'transaction_id');
        $amount = self::p(self::p($payment->get('closed'), 'payment_amount'), 'amount');
        try {
            $ctx = $ledger->reserve($openHash, $txId, $amount);
        } catch (\Throwable) {
            return Obj::of(['ok' => false, 'reason' => 'ledger_unavailable']);
        }
        if ($ctx === 'replayed') {
            return Obj::of(['ok' => false, 'reason' => 'replayed']);
        }
        $final = self::verifyPurchase($checkoutToken, $paymentToken, [...self::bag($o), 'context' => $ctx]);
        if ($final->get('ok') !== true) {
            try {
                $ledger->release($openHash, $txId);
            } catch (\Throwable) {
                // the reservation stays: a failed release only ever over-counts spend
            }
        }
        return $final;
    }

    // ---- PCA terms -> AP2 open mandates -------------------------------------------------------------------------------------

    /** A PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused. */
    private static function minorTerm(mixed $v, string $name): mixed
    {
        if (!Payments::safeInt($v) || Payments::n($v) < 0 || !self::isInt($v)) {
            throw new Ap2Error("PCA term $name must be a non-negative integer in minor units, got " . Payments::s($v));
        }
        return $v;
    }

    private static function toJson(mixed $v): mixed
    {
        if ($v === self::U) {
            throw new \TypeError('JSON.parse: undefined is not valid JSON');
        }
        return Js::parse(Js::stringify($v));
    }

    /** The `x_pca` claim of an open mandate: the principal-signed grant and the terms it was minted from. */
    public static function pcaOpenClaim(mixed $mandate): Obj
    {
        return Obj::of(['v' => self::PCA_BINDING_VERSION, 'grant' => self::toJson(self::p($mandate, 'grant')), 'terms' => self::toJson(self::p($mandate, 'terms'))]);
    }

    private static function openExpiry(mixed $terms, mixed $o): mixed
    {
        $pe = self::p($terms, 'periodEnd');
        $periodEnd = $pe === self::U ? null : Payments::num(floor(Payments::n($pe) / 1000));
        $exp = Js::opt($o, 'exp') ?? $periodEnd;
        if ($exp === null) {
            throw new Ap2Error('exp is required when the PCA terms have no period end');
        }
        if ($periodEnd !== null && !(Payments::n($exp) <= Payments::n($periodEnd))) {
            throw new Ap2Error('exp must not exceed the PCA period end');
        }
        return $exp;
    }

    private static function merchantsFor(mixed $terms, mixed $merchants): array
    {
        $out = [];
        foreach (self::iter(self::p($terms, 'merchants')) as $id) {
            $found = null;
            foreach (self::iter($merchants) as $x) {
                if (Payments::seq(self::p($x, 'id'), $id)) {
                    $found = $x;
                    break;
                }
            }
            if ($found === null) {
                throw new Ap2Error('no merchant descriptor supplied for PCA merchant ' . Payments::s($id));
            }
            $out[] = $found;
        }
        return $out;
    }

    private static function nextUp(float $x): float
    {
        $bits = unpack('J', pack('E', $x))[1] + 1;
        return unpack('E', pack('J', $bits))[1];
    }

    /**
     * The value of AP2 `payment.budget.max` for a PCA cap in integer minor units. The official AP2 SDK reads it as `int(max * 100)` whatever
     * the currency, a major-unit reader as `max * 10^exponent`: the value emitted never lets EITHER read more than the cap (nudged up by at
     * most a few ulps when `cap / divisor` falls just under the exact decimal). Throws when no exact representation exists.
     */
    public static function ap2BudgetMax(mixed $capMinor, mixed $currency): int|float
    {
        $cap = Payments::n(self::minorTerm($capMinor, 'cumulativeCap'));
        $e = self::currencyExponent($currency);
        $sdkTarget = $e <= 2 ? $cap : floor($cap / (10 ** ($e - 2)));
        $d = $cap / (10 ** max($e, 2));
        for ($i = 0; $i < 8 && $d > 0 && floor($d * 100) < $sdkTarget; $i++) {
            $d = self::nextUp($d);
        }
        if (floor($d * 100) !== (float)$sdkTarget || Payments::jsRound($d * (10 ** $e)) > $cap) {
            throw new Ap2Error('cumulativeCap ' . Js::str(Payments::num($cap)) . ' ' . Payments::s($currency) . ' has no exact AP2 budget.max representation');
        }
        return Payments::num($d);
    }

    /** What the two readers of an AP2 `budget.max` read, in minor units of `$currency`: the SDK (`int(max * 100)`) and a major-unit reader. */
    public static function ap2BudgetReads(mixed $max, mixed $currency): Obj
    {
        $e = self::currencyExponent($currency);
        if (!Js::isNum($max) || !Payments::fin($max) || Payments::n($max) < 0) {
            throw new Ap2Error('budget.max must be a finite non-negative number, got ' . Payments::s($max));
        }
        return Obj::of(['sdk' => Payments::num(floor(Payments::n($max) * 100)), 'major' => Payments::num(Payments::jsRound(Payments::n($max) * (10 ** $e)))]);
    }

    /** The AP2 open payment constraints a set of PCA terms denotes (PCA terms are integer minor units of the mandate currency). @return list<Obj> */
    public static function paymentConstraintsFromTerms(mixed $terms, mixed $merchants, mixed $checkoutReference): array
    {
        $cur = self::p($terms, 'currency');
        $perTx = self::minorTerm(self::p($terms, 'perTransactionCap'), 'perTransactionCap');
        $budgetMax = self::ap2BudgetMax(self::p($terms, 'cumulativeCap'), $cur);
        $recurrence = Obj::of(['type' => 'payment.agent_recurrence', 'frequency' => 'ON_DEMAND']);
        if (self::p($terms, 'maxTransactionsPerPeriod') !== self::U) {
            $recurrence->set('max_occurrences', self::p($terms, 'maxTransactionsPerPeriod'));
        }
        return [
            Payments::obj(['type' => 'payment.amount_range', 'currency' => $cur, 'min' => 0, 'max' => $perTx]),
            Obj::of(['type' => 'payment.allowed_payees', 'allowed' => self::merchantsFor($terms, $merchants)]),
            Payments::obj(['type' => 'payment.reference', 'conditional_transaction_id' => $checkoutReference]),
            Payments::obj(['type' => 'payment.budget', 'currency' => $cur, 'max' => $budgetMax]),
            $recurrence,
        ];
    }

    /** @return array<string,mixed> */
    private static function fromPcaInput(mixed $mandate, mixed $o, \Closure $constraints): array
    {
        $out = ['issuer' => self::p($o, 'issuer'), 'agentJwk' => self::p($o, 'agentJwk'), 'iat' => self::p($o, 'iat')];
        $out['exp'] = self::openExpiry(self::p($mandate, 'terms'), $o);
        $out['pca'] = self::pcaOpenClaim($mandate);
        $out['constraints'] = $constraints();
        if (Js::opt($o, 'salt') instanceof \Closure) {
            $out['salt'] = Js::opt($o, 'salt');
        }
        return $out;
    }

    /** Issue the open payment mandate for a PCA mandate (grant + terms), chained to `checkoutReference`. `$o`: issuer, agentJwk, merchants, iat, exp?, salt?, checkoutReference. */
    public static function openPaymentMandateFromPca(mixed $mandate, mixed $o): string
    {
        return self::issueOpenPaymentMandate(self::fromPcaInput($mandate, $o, static fn() => self::paymentConstraintsFromTerms(self::p($mandate, 'terms'), self::p($o, 'merchants'), self::p($o, 'checkoutReference'))));
    }

    /** Issue the open checkout mandate for a PCA mandate: the merchant allowlist and the acceptable line items (`$o['lineItems']`). */
    public static function openCheckoutMandateFromPca(mixed $mandate, mixed $o): string
    {
        return self::issueOpenCheckoutMandate(self::fromPcaInput($mandate, $o, static fn() => [
            Payments::obj(['type' => 'checkout.line_items', 'items' => self::p($o, 'lineItems')]),
            Obj::of(['type' => 'checkout.allowed_merchants', 'allowed' => self::merchantsFor(self::p($mandate, 'terms'), self::p($o, 'merchants'))]),
        ]));
    }

    // ---- the closed payment: PCActn bound to the AP2 mandate ----------------------------------------------------------------

    /** The value the PCActn's signed `nonce` must equal for these AP2 facts (transactionId, payeeId, amount, currency, instrumentId, openHash, agentJkt). */
    public static function pcaBindingNonce(mixed $f): string
    {
        $o = Obj::of(['v' => self::PCA_BINDING_VERSION]);
        $s = Payments::spreadObj($f);
        foreach ($s->keys() as $k) {
            $o->set($k, $s->get($k));
        }
        return 'ap2:' . Payments::hash($o);
    }

    /**
     * amount / cap, clamped to [0, 1] and rounded UP to 12 decimals (PCA's canonical encoding refuses numbers with more than 15
     * significant digits; rounding up can only raise the risk the threshold policy sees).
     */
    public static function riskRatio(mixed $amount, mixed $cap): int|float
    {
        $r = Payments::n($cap) > 0 ? fdiv(Payments::n($amount), Payments::n($cap)) : 1.0;
        return Payments::num(Payments::jsMin(1.0, Payments::jsMax(0.0, ceil($r * 1e12 - 1e-6) / 1e12)));
    }

    /** A 32-byte Ed25519 seed from Bytes or a raw string; anything else is refused. */
    private static function seedBytes(mixed $s): string
    {
        $raw = $s instanceof Bytes ? $s->raw : $s;
        if (!is_string($raw) || $raw === self::U) {
            throw new \TypeError('a 32-byte Ed25519 seed is required');
        }
        return $raw;
    }

    /**
     * Build the `x_pca` claim of a closed payment mandate: a PCActn authorising exactly this charge. `$i`: mandate (grant + terms), open (the
     * open payment mandate token), agentJwk, agentSecret (the grant holder's 32-byte seed), audience, counter, transactionId, payee,
     * amount ({amount, currency}), instrumentId, category?, now? (epoch ms), cosign? (Closure over the built PCActn returning the threshold shares).
     */
    public static function buildPcaPaymentBinding(mixed $i): Obj
    {
        $amount = self::p($i, 'amount');
        $major = self::minorTerm(self::p($amount, 'amount'), 'amount');
        $payee = self::p($i, 'payee');
        $charge = Obj::of(['merchant' => self::p($payee, 'id'), 'amount' => $major, 'currency' => self::p($amount, 'currency')]);
        if (self::p($i, 'category') !== self::U) {
            $charge->set('category', self::p($i, 'category'));
        }
        $mandate = self::p($i, 'mandate');
        $factsIn = ['transactionId' => self::p($i, 'transactionId'), 'payeeId' => self::p($payee, 'id'), 'amount' => self::p($amount, 'amount'),
            'currency' => self::p($amount, 'currency'), 'instrumentId' => self::p($i, 'instrumentId'),
            'openHash' => self::sdHashOf(self::parseSdJwtHop(self::p($i, 'open'))), 'agentJkt' => self::jwkThumbprint(self::p($i, 'agentJwk'))];
        $facts = Payments::obj($factsIn);
        $risk = self::riskRatio($major, self::p(self::p($mandate, 'terms'), 'perTransactionCap'));
        $nodeId = 'ap2:' . Payments::s(self::p($i, 'transactionId'));
        $node = Payments::chargePlanNode($mandate, $charge, $nodeId);
        $params = Payments::chargeParams($mandate, $charge);
        $inputs = Payments::spreadObj($params);
        $inputs->set('blastRadius', $risk);
        $grant = self::p($mandate, 'grant');
        $now = self::p($i, 'now');
        $counter = self::p($i, 'counter');
        $aud = self::p($i, 'audience');
        if (!Payments::safeInt($counter) || !self::isStr($aud) || !($grant instanceof Obj)) {
            throw new Ap2Error('buildPcaPaymentBinding: counter, audience and grant are required');
        }
        if (in_array(Payments::UNDEF, $factsIn, true)) { // the binding nonce canonicalizes the facts, and the canonical form has no undefined
            throw new \TypeError('canonicalize: unsupported type undefined');
        }
        $built = Sign::buildPcactn($grant, [$grant], [$node], $nodeId, (int)Payments::n($counter), new KeyPair(self::seedBytes(self::p($i, 'agentSecret'))), $aud, $params,
            Payments::nullish($now) ? null : (int)Payments::n($now), null, Sign::DEFAULT_TTL_MS,
            ['nonce' => self::pcaBindingNonce($facts), 'risk_claim' => Obj::of(['r' => $risk, 'inputs' => $inputs])]);
        $cosign = Js::opt($i, 'cosign');
        if ($cosign instanceof \Closure) {
            $built->set('threshold', $cosign($built));
        }
        $claim = Obj::of(['amount' => $major, 'currency' => self::p($amount, 'currency')]);
        if (self::p($i, 'category') !== self::U) {
            $claim->set('category', self::p($i, 'category'));
        }
        return Obj::of(['v' => self::PCA_BINDING_VERSION, 'charge' => $claim, 'pcactn' => self::toJson($built)]);
    }

    // ---- verification of the PCA side of a verified AP2 chain ---------------------------------------------------------------

    private static function includes(mixed $list, mixed $v): bool
    {
        if (self::isList($list)) {
            foreach ($list as $x) {
                if (Payments::seq($x, $v)) {
                    return true;
                }
            }
            return false;
        }
        return self::isStr($list) && self::isStr($v) && str_contains($list, $v);
    }

    private static function findType(mixed $constraints, string $t): mixed
    {
        foreach (self::iter($constraints) as $c) {
            if (self::p($c, 'type') === $t) {
                return $c;
            }
        }
        return self::U;
    }

    /** Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant). */
    private static function constraintsWithinTerms(mixed $open, mixed $terms): ?string
    {
        $cur = self::p($terms, 'currency');
        $perTx = self::minorTerm(self::p($terms, 'perTransactionCap'), 'perTransactionCap');
        $constraints = self::p($open, 'constraints');
        $rng = self::findType($constraints, 'payment.amount_range');
        if ($rng === self::U) {
            return 'open mandate has no amount_range to compare with the PCA per-transaction cap';
        }
        if (!Payments::seq(self::p($rng, 'currency'), $cur)) {
            return 'amount_range currency differs from the PCA terms';
        }
        if (!Payments::le(self::p($rng, 'max'), $perTx)) {
            return 'amount_range.max ' . Payments::s(self::p($rng, 'max')) . ' exceeds the PCA per-transaction cap ' . Payments::s($perTx);
        }
        $payees = self::findType($constraints, 'payment.allowed_payees');
        if ($payees !== self::U) {
            foreach (self::iter(self::p($payees, 'allowed')) as $m) {
                if (!self::includes(self::p($terms, 'merchants'), self::p($m, 'id'))) {
                    return 'allowed_payees names a merchant outside the PCA allowlist';
                }
            }
        }
        if ($payees === self::U) {
            return 'open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side';
        }
        $budget = self::findType($constraints, 'payment.budget');
        if ($budget === self::U) {
            return 'open mandate has no budget to compare with the PCA cumulative cap';
        }
        if (!Payments::seq(self::p($budget, 'currency'), $cur)) {
            return 'budget exceeds the PCA cumulative cap';
        }
        $reads = self::ap2BudgetReads(self::p($budget, 'max'), $cur);
        $capMinor = self::minorTerm(self::p($terms, 'cumulativeCap'), 'cumulativeCap');
        if (Payments::n($reads->get('sdk')) > Payments::n($capMinor) || Payments::n($reads->get('major')) > Payments::n($capMinor)) {
            return 'budget exceeds the PCA cumulative cap';
        }
        $rec = self::findType($constraints, 'payment.agent_recurrence');
        $maxTx = self::p($terms, 'maxTransactionsPerPeriod');
        if ($maxTx !== self::U && ($rec === self::U || self::p($rec, 'max_occurrences') === self::U || !Payments::le(self::p($rec, 'max_occurrences'), $maxTx))) {
            return 'max_occurrences is missing or exceeds the PCA transaction limit';
        }
        $periodEnd = self::p($terms, 'periodEnd');
        if ($periodEnd !== self::U && (self::p($open, 'exp') === self::U || !Payments::le(self::p($open, 'exp'), floor(Payments::n($periodEnd) / 1000)))) {
            return 'open mandate outlives the PCA period';
        }
        return null;
    }

    /**
     * Verify the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the expected principal, consistent with
     * the terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for this audience,
     * committing to exactly this AP2 charge). Run it after verifyPaymentChain. `$decide` is the PCA policy engine (the decision runs on the
     * server-held mandate, never skipped). `$i`: open, closed, openHash, expectedPrincipal, audience, mandate (REQUIRED), recentChargeTimes
     * (REQUIRED when the mandate limits the charge count), pqPins?, now?, hooks? ({attestation?, threshold?, revocation?: Closure(ctx) ->
     * {enforced, ok, reason?, t?}}), enforce? ({freshness?: {maxAgeMs, epochMs?, now?, clockSkewMs?}}; the taint gate is refused here).
     * Returns {ok: true, pcactn, grant, terms} or {ok: false, reason}; throws PcaBindingError when the mandate or history is missing.
     * @param \Closure(Obj):mixed $decide
     */
    public static function verifyPcaBinding(mixed $i, \Closure $decide): Obj
    {
        $mandate = Js::opt($i, 'mandate');
        if (!self::isObject($mandate)) {
            throw new PcaBindingError('mandate_required', 'verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped');
        }
        $maxTxM = Js::opt(Js::opt($mandate, 'terms'), 'maxTransactionsPerPeriod');
        $recent = Js::opt($i, 'recentChargeTimes');
        if ($maxTxM !== null) {
            $okHistory = self::isList($recent);
            foreach ($okHistory ? $recent : [] as $t) {
                $okHistory = $okHistory && Js::isNum($t) && Payments::fin($t);
            }
            if (!$okHistory) {
                throw new PcaBindingError('charge_history_required', 'the mandate limits the charge count: pass recentChargeTimes from your own records');
            }
        }
        $fail = static fn(string $reason): Obj => Obj::of(['ok' => false, 'reason' => $reason]);
        try {
            $open = Js::opt($i, 'open');
            $oc = self::p($open, self::PCA_CLAIM);
            if (!self::isObject($oc) || !Payments::seq(self::p($oc, 'v'), self::PCA_BINDING_VERSION) || !self::isObject(self::p($oc, 'grant')) || !self::isObject(self::p($oc, 'terms'))) {
                return $fail('open mandate carries no x_pca grant');
            }
            $grant = $oc->get('grant');
            $terms = $oc->get('terms');
            $principal = Js::opt($i, 'expectedPrincipal');
            [$why, $chainOk] = Pca::verifyChain([$grant], $principal, is_string($principal), null, Js::opt($i, 'pqPins'));
            if (!$chainOk) {
                return $fail('PCA grant: ' . ($why === '' ? 'invalid' : $why));
            }
            $env = Authorize::readEnvelope($grant);
            if ($env === null) {
                return $fail('PCA grant has no envelope');
            }
            if (Payments::hash($env->get('predicates')) !== Payments::hash(Payments::mandatePredicates($terms))
                || Payments::hash($env->get('caveats')) !== Payments::hash(Payments::mandateCaveats($terms))) {
                return $fail('x_pca terms do not match the grant envelope');
            }
            $rp = $env->get('risk_policy');
            if (!Payments::seq(self::p($rp, 'kappa'), self::p($terms, 'perTransactionCap')) || !Payments::seq(self::p($rp, 'bMax'), self::p($terms, 'cumulativeCap'))) {
                return $fail('x_pca terms do not match the grant risk policy');
            }
            $within = self::constraintsWithinTerms($open, $terms);
            if ($within !== null) {
                return $fail($within);
            }
            $closed = Js::opt($i, 'closed');
            $cc = self::p($closed, self::PCA_CLAIM);
            if (!self::isObject($cc) || !Payments::seq(self::p($cc, 'v'), self::PCA_BINDING_VERSION) || !self::isObject(self::p($cc, 'pcactn')) || !self::isObject(self::p($cc, 'charge'))) {
                return $fail('closed mandate carries no x_pca PCActn');
            }
            $pcactn = $cc->get('pcactn');
            $charge = $cc->get('charge');
            $amt = self::p($closed, 'payment_amount');
            $payee = self::p($closed, 'payee');
            if (!Payments::seq(self::p($charge, 'currency'), self::p($amt, 'currency')) || !Payments::seq(self::p($charge, 'amount'), self::p($amt, 'amount'))) {
                return $fail('x_pca charge differs from the mandate payment_amount');
            }
            $cats = self::p($terms, 'categories');
            $catLen = Payments::length($cats);
            $category = self::p($charge, 'category');
            if (Payments::n($catLen === Payments::UNDEF ? NAN : $catLen) > 0 && (!self::isStr($category) || !self::includes($cats, $category))) {
                return $fail('x_pca charge lacks an allowed category');
            }
            // the t the threshold hook REPORTS it enforced: a hook built for a smaller t cannot satisfy a charge that needs more
            $hooks = Js::opt($i, 'hooks');
            $enforce = Js::opt($i, 'enforce');
            $enforceKeys = $enforce instanceof Obj ? $enforce->keys() : (is_array($enforce) ? array_keys($enforce) : []);
            foreach ($enforceKeys as $k) {
                if ($k !== 'freshness') {
                    return $fail('PCActn: an enforce gate other than freshness is not supported by this verifier (fail closed)');
                }
            }
            $enforcedT = self::U;
            $nowOpt = Js::opt($i, 'now');
            $nowMs = $nowOpt === null ? (int)(microtime(true) * 1000) : (int)Payments::n($nowOpt);
            $fresh = Js::opt($enforce, 'freshness');
            $freshArr = null;
            if ($fresh !== null) {
                $freshArr = Js::isObj($fresh) ? self::bag($fresh) : null;
                if ($freshArr === null) {
                    return $fail('PCActn: enforce.freshness must be an object');
                }
            }
            $audience = Js::opt($i, 'audience');
            $core = Pca::verifyPcactnCore($pcactn, $grant, $nowMs, is_string($audience) ? $audience : null, null, null, null, null, null, true, $freshArr);
            if (($core['allow'] ?? false) !== true) {
                return $fail('PCActn: ' . VerifyVerdict::text(preg_replace('/\Afreshness_anchor: /', 'freshness: ', (string)($core['reason'] ?? 'rejected'))));
            }
            $hookCtx = Obj::of(['pcactn' => $pcactn, 'grant' => $grant]);
            if ($nowOpt !== null) {
                $hookCtx->set('nowEpoch', $nowOpt);
            }
            foreach (['attestation', 'threshold', 'revocation'] as $name) {
                $hook = Js::opt($hooks, $name);
                if ($hook === null) {
                    continue;
                }
                $res = $hook($hookCtx);
                if ($name === 'threshold' && Payments::truthy(Js::opt($res, 'enforced')) && Payments::truthy(Js::opt($res, 'ok')) && Js::isNum(Js::opt($res, 't'))) {
                    $enforcedT = Js::opt($res, 't');
                }
                if (Payments::truthy(Js::opt($res, 'enforced')) && !Payments::truthy(Js::opt($res, 'ok'))) {
                    $why = Js::opt($res, 'reason');
                    return $fail("PCActn: $name: " . ($why === null ? 'rejected' : Payments::s($why)));
                }
            }
            $action = self::p($pcactn, 'action');
            if (!Payments::seq(self::p($action, 'verb'), 'charge') || !Payments::seq(self::p($action, 'resource'), 'merchant:' . Payments::s(self::p($payee, 'id')))) {
                return $fail('PCActn action is not a charge at this payee');
            }
            $params = Payments::obj(['amount' => self::p($charge, 'amount'), 'currency' => self::p($charge, 'currency')]);
            if (self::isStr($category)) {
                $params->set('category', $category);
            }
            if (self::p($charge, 'amount') === self::U || self::p($charge, 'currency') === self::U) {
                throw new Ap2Error('canonical JSON cannot encode an undefined charge member');
            }
            if (!Payments::seq(self::p($action, 'params_digest'), Pca::paramsDigest($params))) {
                return $fail('PCActn params do not commit to the x_pca charge');
            }
            $agentJwk = self::p(self::p($open, 'cnf'), 'jwk');
            $f = ['transactionId' => self::p($closed, 'transaction_id'), 'payeeId' => self::p($payee, 'id'), 'amount' => self::p($amt, 'amount'),
                'currency' => self::p($amt, 'currency'), 'instrumentId' => self::p(self::p($closed, 'payment_instrument'), 'id'),
                'openHash' => Js::opt($i, 'openHash') ?? self::U, 'agentJkt' => self::jwkThumbprint($agentJwk)];
            if (in_array(self::U, $f, true)) {
                throw new Ap2Error('canonical JSON cannot encode an undefined binding fact');
            }
            if (!Payments::seq(self::p($pcactn, 'nonce'), self::pcaBindingNonce($f))) {
                return $fail('PCActn nonce does not bind this AP2 transaction, open mandate and agent key');
            }
            $perTx = self::minorTerm(self::p($terms, 'perTransactionCap'), 'perTransactionCap');
            if (!(is_finite(Payments::n(self::p($amt, 'amount'))) && Payments::le(self::p($amt, 'amount'), $perTx))) {
                return $fail('payment exceeds the PCA per-transaction cap');
            }
            // the agent may not understate the risk of its own charge; a charge whose risk needs a human co-sign (t > 1) needs a threshold verifier
            $recomputed = Payments::n(self::riskRatio(self::p($amt, 'amount'), self::p($terms, 'perTransactionCap')));
            $claimed = self::p(self::p($pcactn, 'risk_claim'), 'r');
            if (!(Js::isNum($claimed) && Payments::n($claimed) >= $recomputed - 1e-9)) {
                return $fail('PCActn understates the risk of this charge');
            }
            $need = Risk::requiredThreshold(Payments::n($claimed), Payments::n(self::p($rp, 'theta1')), Payments::n(self::p($rp, 'theta2')))['t'];
            if ($need > 1 && Js::opt($hooks, 'threshold') === null) {
                return $fail("this charge needs a threshold of $need (human co-sign); supply hooks.threshold to verify it");
            }
            if ($need > 1 && !(Js::isNum($enforcedT) && Payments::n($enforcedT) >= $need)) {
                return $fail("this charge needs a threshold of $need but the threshold hook enforced t=" . ($enforcedT === self::U ? 'unreported' : Payments::s($enforcedT))
                    . "; build it with createThresholdVerifier({ t: $need })");
            }
            if (!Payments::seq(self::p($amt, 'currency'), self::p($terms, 'currency')) || !self::includes(self::p($terms, 'merchants'), self::p($payee, 'id'))) {
                return $fail('payment currency or payee is outside the PCA terms');
            }
            if (Payments::hash(self::p($mandate, 'grant')) !== Payments::hash($grant)) {
                return $fail('the supplied PCA mandate is not the one in the open mandate');
            }
            // `grant` was verified above under the caller-pinned principal; the decision is bound to it
            $spend = Obj::of(['merchant' => self::p($payee, 'id'), 'amount' => self::p($amt, 'amount'), 'currency' => self::p($amt, 'currency')]);
            if (self::isStr($category)) {
                $spend->set('category', $category);
            }
            $spend->set('recentChargeTimes', $recent ?? []);
            if ($nowOpt !== null) {
                $spend->set('now', $nowOpt);
            }
            $decision = Payments::authorizeCharge($mandate, $spend, $grant, $decide);
            if ($decision->get('outcome') === 'deny') {
                return $fail('PCA denies this charge: ' . implode('; ', array_map(static fn($r) => Payments::s($r), $decision->get('reasons'))));
            }
            if ($decision->get('outcome') === 'step_up' && !(Js::isNum($enforcedT) && Payments::n($enforcedT) >= 2)) {
                return $fail('PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced');
            }
            return Obj::of(['ok' => true, 'pcactn' => $pcactn, 'grant' => $grant, 'terms' => $terms]);
        } catch (\Throwable $e) {
            return $fail($e->getMessage());
        }
    }

    // ---- settlement backends (structural only, no network) ------------------------------------------------------------------

    /**
     * Integer minor units to an integer string of atomic units: scales by `10 ** (decimals - exponent)` exactly; when the asset has fewer
     * decimals than the currency the division must be exact. Throws otherwise (fail closed).
     */
    public static function toAtomicUnits(mixed $amount, mixed $decimals): string
    {
        if (!Js::isNum($decimals) || !is_finite(Payments::n($decimals)) || floor(Payments::n($decimals)) !== Payments::n($decimals) || Payments::n($decimals) < 0 || Payments::n($decimals) > 18) {
            throw new \RangeException('x402: decimals must be an integer in 0..18, got ' . Payments::s($decimals));
        }
        $amt = self::p($amount, 'amount');
        if (!self::isNonNegInt($amt)) {
            throw new \RangeException('x402: amount ' . Payments::s($amt) . ' cannot be expressed in atomic units with ' . Payments::s($decimals) . ' decimals');
        }
        $dec = (int)Payments::n($decimals);
        $exp = self::currencyExponent(self::p($amount, 'currency'));
        $minor = (int)Payments::n($amt);
        if ($dec >= $exp) {
            return $minor === 0 ? '0' : (string)$minor . str_repeat('0', $dec - $exp);
        }
        $div = 10 ** ($exp - $dec);
        if ($minor % $div !== 0) {
            throw new \RangeException('x402: amount ' . Payments::s($amt) . ' cannot be expressed in atomic units with ' . Payments::s($decimals) . ' decimals');
        }
        return (string)intdiv($minor, $div);
    }

    private static function ctx(mixed $ctx, string $k): mixed
    {
        return Js::isObj($ctx) ? Js::opt($ctx, $k) : null;
    }

    /**
     * Coinbase x402 adapter: the HTTP 402 `Payment Required` challenge (`accepts`) plus the `X-PAYMENT` request header (standard base64 of the
     * JSON payment payload). The payload is a placeholder envelope, not a signed authorization: the real rail settles on-chain.
     */
    public static function x402Settlement(mixed $payment, mixed $ctx = null): Obj
    {
        $network = self::ctx($ctx, 'network') ?? 'base-sepolia';
        $amt = self::p($payment, 'payment_amount');
        $requirement = Obj::of(['scheme' => 'exact', 'network' => $network,
            'maxAmountRequired' => self::toAtomicUnits($amt, self::ctx($ctx, 'decimals') ?? 6),
            'resource' => self::ctx($ctx, 'resourceUrl') ?? '',
            'description' => 'AP2 payment mandate ' . Payments::s(self::p($payment, 'transaction_id')),
            'payTo' => self::ctx($ctx, 'payTo') ?? self::p(self::p($payment, 'payee'), 'id'),
            'asset' => self::ctx($ctx, 'asset') ?? self::p($amt, 'currency'),
            'mimeType' => 'application/json',
            'maxTimeoutSeconds' => self::ctx($ctx, 'maxTimeoutSeconds') ?? 60]);
        $xPayment = base64_encode(Js::utf8(Js::stringify(Obj::of(['x402Version' => 1, 'scheme' => 'exact', 'network' => $network,
            'payload' => Payments::obj(['transactionId' => self::p($payment, 'transaction_id'), 'amount' => self::p($amt, 'amount'), 'currency' => self::p($amt, 'currency')])]))));
        return Obj::of(['rail' => 'x402', 'amount' => $amt, 'merchant' => self::p(self::p($payment, 'payee'), 'id'),
            'payload' => Obj::of(['httpStatus' => 402, 'x402Version' => 1, 'error' => 'X-PAYMENT header is required', 'accepts' => [$requirement],
                'header' => Obj::of(['X-PAYMENT' => $xPayment])])]);
    }

    /**
     * Stripe Shared Payment Token adapter: a shared token the buyer's agent grants the merchant to pull a bounded amount. The token is the
     * mandate's payment instrument id, never a raw PAN.
     */
    public static function stripeSptSettlement(mixed $payment, mixed $ctx = null): Obj
    {
        $inst = self::p($payment, 'payment_instrument');
        if (self::p($inst, 'type') !== 'shared_payment_token') {
            throw new Ap2Error('stripe-spt: the payment instrument must be of type shared_payment_token, got ' . Payments::s(self::p($inst, 'type')));
        }
        $amt = self::p($payment, 'payment_amount');
        $cur = self::p($amt, 'currency');
        if (!self::isStr($cur)) {
            throw new \TypeError('currency.toLowerCase is not a function');
        }
        $payload = Obj::of(['shared_payment_token' => self::p($inst, 'id'), 'amount' => self::p($amt, 'amount'), 'currency' => mb_strtolower($cur, 'UTF-8')]);
        if (Payments::truthy(self::ctx($ctx, 'payTo'))) {
            $payload->set('on_behalf_of', self::ctx($ctx, 'payTo'));
        }
        return Obj::of(['rail' => 'stripe-spt', 'amount' => $amt, 'merchant' => self::p(self::p($payment, 'payee'), 'id'), 'payload' => $payload]);
    }
}
