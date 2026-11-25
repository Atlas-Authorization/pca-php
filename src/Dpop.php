<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/WhatwgUrl.php';

/** A refusal of a DPoP proof (or a misconfiguration) with a stable code. */
final class DpopVerificationError extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/** A reference-library refusal outside the DPoP checks, with its stable code (ERR_INVALID_URL, ERR_JWK_INVALID, ERR_JOSE_NOT_SUPPORTED). */
final class DpopCodedError extends \InvalidArgumentException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/** A DPoP jti replay store: addIfAbsent(key, expiresAtSec, nowSec) is true on first sight (or after expiry), atomically. */
interface DpopReplayStore
{
    public function addIfAbsent(string $key, int|float $expiresAtSec, int|float $nowSec): bool;
}

/** In-memory replay store. When full, expired entries are evicted; a store still full refuses (throws) rather than forget a live entry. */
final class InMemoryDpopReplayStore implements DpopReplayStore
{
    /** @var array<string,int|float> */
    private array $seen = [];
    private int $max;

    public function __construct(mixed $maxEntries = Dpop::INMEMORY_MAX_ENTRIES)
    {
        if (!K3Sig::anySafeInt($maxEntries) || Js::num($maxEntries) < 1) {
            throw new DpopVerificationError('misconfigured', 'maxEntries must be a positive integer');
        }
        $this->max = (int)Js::num($maxEntries);
    }

    public function addIfAbsent(string $key, int|float $expiresAtSec, int|float $nowSec): bool
    {
        if (!is_finite($nowSec)) {
            return false; // a non-finite clock admits nothing
        }
        $held = $this->seen[$key] ?? null;
        if ($held !== null && !($nowSec >= $held)) {
            return false;
        }
        if ($held === null && count($this->seen) >= $this->max) {
            $this->seen = array_filter($this->seen, static fn(int|float $exp): bool => $nowSec < $exp);
            if (count($this->seen) >= $this->max) {
                throw new \RuntimeException('replay store is full');
            }
        }
        $this->seen[$key] = $expiresAtSec;
        return true;
    }
}

/** Server nonces: 8-byte big-endian issue time + the first 16 bytes of HMAC-SHA256(secret, "dpop-nonce\0" || ts), base64url. */
final class DpopNonceIssuer
{
    private float $ttl;

    public function __construct(private readonly mixed $secret, mixed $ttlSec = null)
    {
        if (!is_string($secret) || strlen($secret) < 32) {
            throw new DpopVerificationError('misconfigured', 'nonce secret must be at least 32 bytes');
        }
        $t = Js::num($ttlSec ?? 300);
        if ($t === null || !is_finite($t) || $t <= 0) {
            throw new DpopVerificationError('misconfigured', 'nonce ttlSec must be positive');
        }
        $this->ttl = $t;
    }

    private function mac(string $ts): string
    {
        return substr(hash_hmac('sha256', "dpop-nonce\0" . $ts, $this->secret, true), 0, 16);
    }

    public function issue(mixed $nowSec = null): string
    {
        $n = $nowSec ?? time();
        if (!K3Sig::anySafeInt($n) || Js::num($n) < 0) {
            throw new \RangeException('nonce time must be an integer');
        }
        $ts = pack('J', (int)Js::num($n));
        return Pca::b64u($ts . $this->mac($ts));
    }

    public function check(mixed $nonce, mixed $nowSec = null): bool
    {
        $raw = is_string($nonce) ? Pca::unb64u($nonce) : null;
        if ($raw === null || strlen($raw) !== 24) {
            return false;
        }
        $ts = substr($raw, 0, 8);
        if (!hash_equals($this->mac($ts), substr($raw, 8))) {
            return false;
        }
        $issued = unpack('J', $ts)[1];
        if ($issued < 0) { // above 2^63: never a time this verifier issued
            return false;
        }
        $now = (float)(Js::num($nowSec) ?? time());
        return $issued <= $now + Dpop::CLOCK_SKEW_SEC && $now - $issued <= $this->ttl;
    }
}

/**
 * RFC 9449 DPoP proofs (create / verify with replay detection and server nonces), RFC 7638 JWK thumbprints, RFC 8705 mTLS
 * certificate confirmation and the PCActn <-> DPoP binding (the proof key must be the leaf holder key). Mirrors
 * @atlasauth/pca-dpop. Keys are JWKs (Obj or array); a certificate is DER or PEM. Every refusal of a proof is a
 * DpopVerificationError with a stable codeName.
 * Ed448 proofs verify and sign through OpenSSL over ext-ffi (OpensslEd448); RSA (PS256) proof creation needs phpseclib/phpseclib 3.x
 * (Jose::jwsSign). Without either, such a proof is refused or fails to be created, never accepted.
 */
final class Dpop
{
    public const ALLOWED_ALGS = ['EdDSA', 'ES256', 'ES384', 'ES512', 'PS256', 'RS256'];
    public const JWT_TYP = 'dpop+jwt';
    public const DEFAULT_MAX_AGE_SEC = 300;
    public const CLOCK_SKEW_SEC = 5;
    public const INMEMORY_MAX_ENTRIES = 100000;
    public const MAX_PROOF_BYTES = 8192;
    private const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

    private static function err(string $code, string $msg): DpopVerificationError
    {
        return new DpopVerificationError($code, $msg);
    }

    /**
     * The names of the failed checks of a replay store factory (empty when the store conforms; single-process subset).
     * @param callable(): DpopReplayStore $make @return list<string>
     */
    public static function runReplayStoreConformance(callable $make): array
    {
        $fail = [];
        $check = static function (bool $ok, string $name) use (&$fail): void {
            if (!$ok) {
                $fail[] = $name;
            }
        };
        $s = $make();
        $check($s->addIfAbsent('a', 200, 100) === true, 'first sight of a key returns true');
        $check($s->addIfAbsent('a', 200, 101) === false, 'second sight of the same key returns false');
        $check($s->addIfAbsent('b', 200, 101) === true, 'a different key is independent');
        $check($s->addIfAbsent('a', 200, 199) === false, 'still seen one second before expiry');
        $t = $make();
        $t->addIfAbsent('c', 200, 100);
        $check($t->addIfAbsent('c', 400, 200) === true, 'an expired entry may be added again (nowSec >= expiresAtSec)');
        // shortcut: PHP has no threads here, so the 16 "concurrent" adds run in sequence; a shared store needs its own race test
        $u = $make();
        $wins = 0;
        for ($i = 0; $i < 16; $i++) {
            $wins += $u->addIfAbsent('race', 200, 100) === true ? 1 : 0;
        }
        $check($wins === 1, "16 concurrent adds of one key: exactly one wins (got $wins)");
        return $fail;
    }

    /** RFC 7638 thumbprint (base64url of the digest of the required members in lexicographic order). */
    public static function jwkThumbprint(mixed $jwk, string $digest = 'sha256'): string
    {
        if (!Js::isObj($jwk)) {
            throw new \TypeError('JWK must be an object');
        }
        if (!in_array($digest, ['sha256', 'sha384', 'sha512'], true)) {
            throw new \TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
        }
        $req = static function (string $k, string $d) use ($jwk): string {
            $v = Js::opt($jwk, $k);
            if (!is_string($v) || $v === '') {
                throw new DpopCodedError('ERR_JWK_INVALID', "$d missing or invalid");
            }
            return $v;
        };
        $c = match (Js::opt($jwk, 'kty')) {
            'EC' => ['crv' => $req('crv', '"crv" (Curve) Parameter'), 'kty' => 'EC', 'x' => $req('x', '"x" (X Coordinate) Parameter'), 'y' => $req('y', '"y" (Y Coordinate) Parameter')],
            'OKP' => ['crv' => $req('crv', '"crv" (Subtype of Key Pair) Parameter'), 'kty' => 'OKP', 'x' => $req('x', '"x" (Public Key) Parameter')],
            'RSA' => ['e' => $req('e', '"e" (Exponent) Parameter'), 'kty' => 'RSA', 'n' => $req('n', '"n" (Modulus) Parameter')],
            'oct' => ['k' => $req('k', '"k" (Key Value) Parameter'), 'kty' => 'oct'],
            default => throw new DpopCodedError('ERR_JOSE_NOT_SUPPORTED', '"kty" (Key Type) Parameter missing or unsupported'),
        };
        return Pca::b64u(hash($digest, Js::utf8(Js::stringify($c)), true));
    }

    public static function algForJwk(mixed $jwk): string
    {
        $kty = Js::get($jwk, 'kty');
        $crv = Js::get($jwk, 'crv');
        if ($kty === 'OKP') {
            if ($crv === 'Ed25519' || $crv === 'Ed448') {
                return 'EdDSA';
            }
            throw self::err('unsupported_key', "unsupported OKP curve '" . IntentWb::jsStr($crv) . "' for DPoP");
        }
        if ($kty === 'EC') {
            $a = ['P-256' => 'ES256', 'P-384' => 'ES384', 'P-521' => 'ES512'][is_string($crv) ? $crv : ''] ?? null;
            if ($a !== null) {
                return $a;
            }
            throw self::err('unsupported_key', "unsupported EC curve '" . IntentWb::jsStr($crv) . "' for DPoP");
        }
        if ($kty === 'RSA') {
            return 'PS256';
        }
        throw self::err('unsupported_key', "unsupported key type '" . IntentWb::jsStr($kty) . "' for DPoP");
    }

    /** An unknown alg is false without reading the key (a null key throws only for a known alg, as the reference). */
    public static function algMatchesJwk(mixed $alg, mixed $jwk): bool
    {
        return match ($alg) {
            'EdDSA' => Js::get($jwk, 'kty') === 'OKP' && in_array(Js::get($jwk, 'crv'), ['Ed25519', 'Ed448'], true),
            'ES256' => Js::get($jwk, 'kty') === 'EC' && Js::get($jwk, 'crv') === 'P-256',
            'ES384' => Js::get($jwk, 'kty') === 'EC' && Js::get($jwk, 'crv') === 'P-384',
            'ES512' => Js::get($jwk, 'kty') === 'EC' && Js::get($jwk, 'crv') === 'P-521',
            'PS256', 'RS256' => Js::get($jwk, 'kty') === 'RSA',
            default => false,
        };
    }

    private static function toPublicJwk(mixed $jwk): Obj
    {
        $pub = Obj::of(['kty' => Js::get($jwk, 'kty')]);
        foreach (['crv', 'x', 'y', 'n', 'e'] as $k) {
            if (Js::has($jwk, $k)) {
                $pub->set($k, Js::opt($jwk, $k));
            }
        }
        return $pub;
    }

    /** `${protocol}//${host}${pathname}` of the WHATWG parse (query and fragment dropped). Throws on an invalid URL. */
    public static function normalizeHtu(mixed $url): string
    {
        $u = WhatwgUrl::parse(IntentWb::jsStr($url));
        if ($u === null) {
            throw new DpopCodedError('ERR_INVALID_URL', 'Invalid URL');
        }
        return $u['htu'];
    }

    public static function athFor(mixed $accessToken): string
    {
        return Pca::b64u(hash('sha256', Js::utf8(IntentWb::jsStr($accessToken)), true));
    }

    private static function upper(mixed $s): string
    {
        if (!is_string($s)) {
            throw new \TypeError('toUpperCase is not a function');
        }
        return function_exists('mb_strtoupper') ? mb_strtoupper($s, 'UTF-8') : strtoupper($s);
    }

    private static function uuid4(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /** A signed DPoP proof. Input: method, url, privateKey (private JWK, or an OpenSSL key), publicJwk, nonce, ath, iat, jti. */
    public static function createDpopProof(mixed $input): string
    {
        $pub = self::toPublicJwk(Js::opt($input, 'publicJwk'));
        $alg = self::algForJwk($pub);
        $claims = Obj::of(['htm' => self::upper(Js::opt($input, 'method')), 'htu' => self::normalizeHtu(Js::opt($input, 'url')),
            'iat' => Js::opt($input, 'iat') ?? time(), 'jti' => Js::opt($input, 'jti') ?? self::uuid4()]);
        foreach (['nonce', 'ath'] as $k) {
            if (Js::has($input, $k)) {
                $claims->set($k, Js::opt($input, $k));
            }
        }
        return Jose::signJwt($claims, Obj::of(['typ' => self::JWT_TYP, 'alg' => $alg, 'jwk' => $pub]), Js::opt($input, 'privateKey'));
    }

    /**
     * Verify a DPoP proof: {claims, jwk, jkt}. Options: method, url, maxAgeSec, expectedJkt, seenJti (an \ArrayObject of seen
     * ids), replayStore (DpopReplayStore), requireReplayStore, nonceIssuer, nowSec, expectedNonce, accessToken. A replay store
     * (or seenJti) is required unless requireReplayStore is false.
     */
    public static function verifyDpopProof(mixed $proof, mixed $o): array
    {
        $opt = static fn(string $k): mixed => Js::opt($o, $k);
        // An absent max age means the default, never "no limit"; an infinite one would disable the stale check.
        $maxAge = $opt('maxAgeSec') ?? self::DEFAULT_MAX_AGE_SEC;
        $maxN = Js::num($maxAge);
        if ($maxN !== null && (!is_finite($maxN) || $maxN < 0)) {
            throw self::err('max_age', 'maxAgeSec must be a finite, non-negative number of seconds');
        }
        if ($opt('requireReplayStore') !== false && $opt('replayStore') === null && $opt('seenJti') === null) {
            throw self::err('replay_store_required', 'no replay store configured; replay cannot be detected');
        }
        if (!is_string($proof) || Js::len($proof) > self::MAX_PROOF_BYTES) {
            throw self::err('oversize', 'proof is not a string or exceeds ' . self::MAX_PROOF_BYTES . ' bytes');
        }
        try {
            $header = Jose::assertCanonicalCompactJws($proof)['header'];
        } catch (\Throwable $e) {
            throw self::err('malformed', 'not a JWS: ' . $e->getMessage());
        }
        if ($header->get('typ') !== self::JWT_TYP) {
            throw self::err('typ', "header typ must be '" . self::JWT_TYP . "', got '" . IntentWb::jsStr($header->get('typ')) . "'");
        }
        if (!$header->has('jwk')) {
            throw self::err('no_jwk', 'proof header has no embedded jwk');
        }
        $hj = $header->get('jwk');
        if ($hj instanceof Obj && array_intersect(self::PRIVATE_MEMBERS, $hj->keys()) !== []) {
            throw self::err('private_jwk', 'proof header jwk contains private key material');
        }
        $alg = $header->get('alg');
        if (is_string($alg) && in_array($alg, self::ALLOWED_ALGS, true) && !self::algMatchesJwk($alg, $hj)) {
            throw self::err('alg_jwk_mismatch', "alg '$alg' does not match the embedded jwk key type");
        }
        try {
            [$payload, $ph] = Jose::jwtVerify($proof, Jose::EMBEDDED_JWK, ['algorithms' => self::ALLOWED_ALGS, 'typ' => self::JWT_TYP]);
            if (!$ph->has('jwk')) {
                throw self::err('no_jwk', 'verified header has no embedded jwk');
            }
            $jwk = $ph->get('jwk');
        } catch (DpopVerificationError $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw self::err('signature', 'DPoP signature did not verify: ' . $e->getMessage());
        }
        [$htm, $htu, $iat, $jti] = [$payload->get('htm'), $payload->get('htu'), $payload->get('iat'), $payload->get('jti')];
        if (!is_string($htm)) {
            throw self::err('htm', 'htm is missing or not a string');
        }
        if (!is_string($htu)) {
            throw self::err('htu', 'htu is missing or not a string');
        }
        $iatN = Js::num($iat);
        if ($iatN === null || !is_finite($iatN)) {
            throw self::err('iat', 'iat is missing or not a number');
        }
        if (!is_string($jti) || $jti === '') {
            throw self::err('jti', 'jti is missing or empty');
        }
        if ($htm !== self::upper($opt('method'))) {
            throw self::err('htm', "htm '$htm' does not match request method");
        }
        if ($htu !== self::normalizeHtu($opt('url'))) {
            throw self::err('htu', "htu '$htu' does not match request URL");
        }
        $nowO = $opt('nowSec');
        $now = $nowO === null ? (float)time() : Js::num($nowO);
        if ($now === null || !is_finite($now)) {
            throw self::err('now', 'nowSec must be a finite number');
        }
        if ($iatN > $now + self::CLOCK_SKEW_SEC) {
            throw self::err('iat_future', 'iat is in the future');
        }
        // `now - iat > maxAgeSec`: a non-number bound never compares true in the reference, so it is refused here instead
        if ($maxN === null || is_nan($maxN) || $now - $iatN > $maxN) {
            throw self::err('iat_stale', 'proof is older than ' . IntentWb::jsStr($maxAge) . 's');
        }
        $jkt = self::jwkThumbprint($jwk);
        if (Js::has($o, 'expectedJkt') && $jkt !== $opt('expectedJkt')) {
            throw self::err('jkt', 'embedded key thumbprint does not match expected jkt');
        }
        if (Js::has($o, 'expectedNonce') && $payload->get('nonce') !== $opt('expectedNonce')) {
            throw self::err('nonce', 'proof nonce is missing or does not match the expected nonce');
        }
        $ni = $opt('nonceIssuer');
        if ($ni instanceof DpopNonceIssuer && !$ni->check($payload->get('nonce'), $now)) {
            throw self::err('nonce', 'proof nonce is missing, forged or expired');
        }
        if (Js::has($o, 'accessToken') && $payload->get('ath') !== self::athFor($opt('accessToken'))) {
            throw self::err('ath', 'proof ath is missing or does not match the access token');
        }
        $seen = $opt('seenJti');
        if ($seen instanceof \ArrayObject) {
            if (in_array($jti, (array)$seen, true)) {
                throw self::err('jti_replay', "jti '$jti' has already been seen");
            }
            $seen->append($jti);
        }
        $rs = $opt('replayStore');
        if ($rs !== null) {
            try {
                $fresh = $rs->addIfAbsent("$jkt.$jti", $iatN + $maxN + self::CLOCK_SKEW_SEC, $now);
            } catch (\Throwable $e) {
                throw self::err('replay_store_error', 'replay store failed: ' . $e->getMessage());
            }
            if ($fresh !== true) {
                throw self::err('jti_replay', "jti '$jti' has already been seen");
            }
        }
        return ['claims' => $payload, 'jwk' => $jwk, 'jkt' => $jkt];
    }

    /** Node's lenient base64 of a PEM body: characters outside the alphabet are skipped and decoding stops at the first '='. */
    private static function pemToDer(string $pem): string
    {
        $body = preg_match('/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/', $pem, $m) === 1 ? $m[1] : $pem;
        $body = explode('=', (string)preg_replace('#[^A-Za-z0-9+/=]#', '', $body), 2)[0];
        if (strlen($body) % 4 === 1) { // a lone trailing sextet carries no whole byte
            $body = substr($body, 0, -1);
        }
        return (string)base64_decode($body . str_repeat('=', (4 - strlen($body) % 4) % 4));
    }

    /** {x5t#S256} of a certificate given as DER bytes or PEM text (no parse: the reference hashes the bytes it is given). */
    public static function mtlsCnf(string $cert): array
    {
        $der = str_contains($cert, '-----BEGIN') || preg_match('/\A[\x09\x0A\x0D\x20-\x7E]*\z/', $cert) === 1 ? self::pemToDer($cert) : $cert;
        return ['x5t#S256' => Pca::b64u(hash('sha256', $der, true))];
    }

    /** x5t#S256 of a parsed X.509 certificate (DER bytes or PEM text). */
    public static function mtlsThumbprint(string $cert): string
    {
        $pem = str_contains($cert, '-----BEGIN CERTIFICATE-----') ? $cert
            : "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($cert), 64, "\n") . "-----END CERTIFICATE-----\n";
        $x = @openssl_x509_read($pem);
        $out = '';
        if ($x === false || !openssl_x509_export($x, $out)) {
            throw self::err('cert', 'not an X.509 certificate: ' . (openssl_error_string() ?: 'parse failed'));
        }
        return Pca::b64u(hash('sha256', self::pemToDer($out), true));
    }

    /** The client certificate must match the token's cnf x5t#S256 (constant-time compare). */
    public static function assertMtlsBound(string $cert, mixed $cnf): array
    {
        $want = Js::opt($cnf, 'x5t#S256');
        if (!is_string($want) || $want === '') {
            throw self::err('x5t_missing', "cnf has no 'x5t#S256' thumbprint");
        }
        $got = self::mtlsThumbprint($cert);
        if (!hash_equals($got, $want)) {
            throw self::err('x5t', 'client certificate thumbprint does not match cnf x5t#S256');
        }
        return ['x5t#S256' => $got];
    }

    /**
     * The leaf holder key of a PCActn's chain (cap_chain[length - 1]) as an Ed25519 JWK; JS property-read semantics on a
     * malformed chain (an absent holder leaves x out, a null hop throws).
     */
    public static function leafHolderJwk(mixed $p): array
    {
        $chain = Js::get($p, 'cap_chain');
        if ($chain === null) {
            throw new \TypeError("Cannot read properties of null (reading 'length')");
        }
        $none = new \stdClass();
        if (is_array($chain) && array_is_list($chain)) {
            $leaf = $chain === [] ? $none : $chain[count($chain) - 1];
        } elseif (is_string($chain)) {
            $chars = Js::spread($chain);
            $leaf = $chars === [] ? $none : $chars[count($chars) - 1];
        } elseif ($chain instanceof Obj) {
            $n = $chain->get('length');
            $k = Js::isNum($n) ? IntentWb::jsStr(Js::num($n) - 1) : 'NaN';
            $leaf = $chain->has($k) ? $chain->get($k) : $none;
        } else {
            $leaf = $none;
        }
        if ($leaf === $none) {
            throw self::err('no_leaf', 'PCActn capability chain is empty; no bound holder key');
        }
        if ($leaf === null) {
            throw new \TypeError("Cannot read properties of null (reading 'holder')");
        }
        $jwk = ['kty' => 'OKP', 'crv' => 'Ed25519'];
        if (Js::has($leaf, 'holder')) {
            $jwk['x'] = Js::opt($leaf, 'holder');
        }
        return $jwk;
    }

    public static function bindPcaToDpop(mixed $p): array
    {
        return ['jkt' => self::jwkThumbprint(self::leafHolderJwk($p))];
    }

    /** Verify a DPoP proof whose key must be the PCActn's leaf holder key (maxAgeSec defaults to 300). */
    public static function assertPcaDpop(mixed $p, mixed $proof, mixed $o): array
    {
        $jkt = self::bindPcaToDpop($p)['jkt'];
        $v = [];
        foreach (['method', 'url', 'seenJti', 'replayStore', 'requireReplayStore', 'nonceIssuer', 'nowSec', 'expectedNonce', 'accessToken'] as $k) {
            if (Js::has($o, $k)) {
                $v[$k] = Js::opt($o, $k);
            }
        }
        $v['maxAgeSec'] = Js::opt($o, 'maxAgeSec') ?? self::DEFAULT_MAX_AGE_SEC;
        $v['expectedJkt'] = $jkt;
        return self::verifyDpopProof($proof, $v);
    }
}
