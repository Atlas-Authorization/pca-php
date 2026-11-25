<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/WhatwgUrl.php';

use Atlas\Pca\Attest\CanonicalJwsError;

/** Any ID-token verification failure; codeName is one of config, invalid_token, signature, issuer, audience, expired, issued_at, not_before, nonce, azp, at_hash, c_hash, keys, claims. */
final class OidcVerificationError extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/** Any discovery failure (network, non-2xx, bad JSON, issuer mismatch). */
final class OidcDiscoveryError extends \RuntimeException
{
}

/** A refusal that carries the reference runtime's code (ERR_JWKS_INVALID, ERR_INVALID_ARG_TYPE). */
final class OidcCodedError extends \InvalidArgumentException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/** The JOSE library's claim-set failures: the claim (and expiry vs validation) decides the mapped code. */
final class OidcClaimFailed extends \RuntimeException
{
    public function __construct(public readonly string $claim, string $message, public readonly bool $expired = false)
    {
        parent::__construct($message);
    }
}

final class OidcSignatureFailed extends \RuntimeException
{
}

/**
 * Root a PCA grant in an OpenID Connect-authenticated human: discovery, ID-token verification (signature + iss / aud / exp /
 * iat / nonce / azp / at_hash / c_hash), a fail-closed caching JWKS resolver and the claims -> principal mapping. Mirrors
 * @atlasauth/pca-oidc (check order and error codes of the reference and its JOSE library).
 *
 * Options use the reference's camelCase names (Obj or assoc array). A `fetch` is a callable(string $url, array $headers,
 * ?int $timeoutMs): array{status:int, body:string, headers?:array} that throws on a network failure. Keys: a public JWK
 * (Obj / array), an HMAC secret (a byte string, HS* only), or a resolver (a callable object: header Obj -> JWK) such as
 * createLocalJwkSet / createOidcJwks.
 * Ed448 ID tokens verify through OpenSSL over ext-ffi (OpensslEd448); without it they are refused as a bad signature.
 */
final class Oidc
{
    public const OIDC_SUBJECT_CAVEAT = 'oidc_subject';
    public const DEFAULT_MAX_DISCOVERY_BYTES = 1024 * 1024;
    public const DEFAULT_JWKS_TIMEOUT_MS = 5000;
    public const DEFAULT_ID_TOKEN_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];
    private const WELL_KNOWN = '/.well-known/openid-configuration';
    private const CRV_FOR_ALG = ['ES256' => ['P-256'], 'ES256K' => ['secp256k1'], 'ES384' => ['P-384'], 'ES512' => ['P-521'],
        'Ed25519' => ['Ed25519'], 'EdDSA' => ['Ed25519', 'Ed448']];
    private const EC_SIZE = ['P-256' => 32, 'P-384' => 48, 'P-521' => 66];
    private const HS = ['HS256' => 'sha256', 'HS384' => 'sha384', 'HS512' => 'sha512'];
    private const CURVE_ALG = ['ES256' => 'P-256', 'ES384' => 'P-384', 'ES512' => 'P-521'];
    private const CLAIM_CODE = ['iss' => 'issuer', 'aud' => 'audience', 'iat' => 'issued_at', 'nbf' => 'not_before'];

    private static function str(mixed $v): ?string
    {
        return is_string($v) && $v !== '' ? $v : null;
    }

    private static function finite(mixed $v): mixed
    {
        $n = Js::num($v);
        return $n !== null && is_finite($n) ? $v : null;
    }

    /** ToNumber of a JSON value for a relational comparison. */
    private static function toNum(mixed $v): float
    {
        return match (true) {
            Js::isNum($v) => (float)Js::num($v),
            $v === true => 1.0,
            $v === false => 0.0,
            is_string($v) => IntentWb::jsNumber($v),
            is_array($v) && array_is_list($v) => IntentWb::jsNumber(IntentWb::jsStr($v)),
            default => NAN,
        };
    }

    private static function isHttps(mixed $u): bool
    {
        $p = is_string($u) ? WhatwgUrl::parse($u) : null;
        return $p !== null && $p['scheme'] === 'https';
    }

    /** The default fetch: an HTTP GET through PHP streams (TLS peer verification on). */
    public static function defaultFetch(string $url, array $headers, ?int $timeoutMs): array
    {
        $h = [];
        foreach ($headers as $k => $v) {
            $h[] = "$k: $v";
        }
        $ctx = stream_context_create(['http' => ['method' => 'GET', 'header' => $h, 'ignore_errors' => true, 'follow_location' => 0,
            'timeout' => $timeoutMs === null ? (float)ini_get('default_socket_timeout') : $timeoutMs / 1000]]);
        $body = @file_get_contents($url, false, $ctx);
        $raw = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
        if ($body === false || $raw === [] || preg_match('#^HTTP/\S+\s+(\d{3})#', $raw[0], $m) !== 1) {
            throw new \RuntimeException("fetch of $url failed");
        }
        $out = [];
        foreach (array_slice($raw, 1) as $line) {
            $i = strpos($line, ':');
            if ($i !== false) {
                $out[strtolower(trim(substr($line, 0, $i)))] = trim(substr($line, $i + 1));
            }
        }
        return ['status' => (int)$m[1], 'body' => $body, 'headers' => $out];
    }

    private static function fetcher(mixed $f): callable
    {
        return is_callable($f) && !is_string($f) ? $f : self::defaultFetch(...);
    }

    /** The response body as text (invalid UTF-8 becomes U+FFFD, as a decoder does). */
    private static function bodyText(mixed $res): string
    {
        $b = (string)(Js::opt($res, 'body') ?? '');
        return mb_check_encoding($b, 'UTF-8') ? $b : htmlspecialchars_decode(htmlspecialchars($b, ENT_SUBSTITUTE | ENT_NOQUOTES, 'UTF-8'), ENT_NOQUOTES);
    }

    private static function ok(mixed $res): bool
    {
        $s = Js::opt($res, 'status');
        return is_int($s) && $s >= 200 && $s <= 299;
    }

    // ---- discovery ----

    /** The issuer + "/.well-known/openid-configuration" (one trailing slash of the issuer is not doubled). */
    public static function discoveryUrl(mixed $issuer): string
    {
        if (!is_string($issuer)) {
            throw new \TypeError('Cannot read properties of ' . IntentWb::jsStr($issuer) . " (reading 'endsWith')");
        }
        return (str_ends_with($issuer, '/') ? substr($issuer, 0, -1) : $issuer) . self::WELL_KNOWN;
    }

    /** Fetch and parse the issuer's discovery document (an Obj). Options: fetch, maxBytes, requireHttps (default true). */
    public static function discoverOidc(mixed $issuer, mixed $opts = []): Obj
    {
        if (!is_string($issuer) || $issuer === '') {
            throw new OidcDiscoveryError('discoverOidc: issuer must be a non-empty string');
        }
        if ($opts === null) {
            throw new \TypeError("Cannot read properties of null (reading 'requireHttps')");
        }
        $requireHttps = Js::opt($opts, 'requireHttps') !== false;
        if ($requireHttps && !self::isHttps($issuer)) {
            throw new OidcDiscoveryError("discoverOidc: issuer '$issuer' is not an https URL");
        }
        $fetch = self::fetcher(Js::opt($opts, 'fetch'));
        $url = self::discoveryUrl($issuer);
        try {
            $res = $fetch($url, ['accept' => 'application/json'], null);
        } catch (\Throwable) {
            throw new OidcDiscoveryError("discoverOidc: fetch of $url failed");
        }
        if (!self::ok($res)) {
            throw new OidcDiscoveryError("discoverOidc: $url returned HTTP " . IntentWb::jsStr(Js::opt($res, 'status')));
        }
        $maxBytes = Js::opt($opts, 'maxBytes') ?? self::DEFAULT_MAX_DISCOVERY_BYTES;
        $cap = self::toNum($maxBytes);
        $cl = null;
        $hs = Js::opt($res, 'headers');
        $hs = $hs instanceof Obj ? array_combine($hs->keys(), array_map($hs->get(...), $hs->keys())) : (is_array($hs) ? $hs : []);
        foreach ($hs as $k => $v) {
            if (strtolower((string)$k) === 'content-length') {
                $cl = $v;
                break;
            }
        }
        $declared = $cl === null ? 0.0 : IntentWb::jsNumber(IntentWb::jsStr($cl));
        $tooBig = "discoverOidc: $url response exceeds " . IntentWb::jsStr($maxBytes) . ' bytes';
        if (is_finite($declared) && $declared > $cap) {
            throw new OidcDiscoveryError($tooBig);
        }
        $text = self::bodyText($res);
        if (strlen(Js::utf8($text)) > $cap) {
            throw new OidcDiscoveryError($tooBig);
        }
        try {
            $body = Js::parse($text);
        } catch (\Throwable) {
            throw new OidcDiscoveryError("discoverOidc: $url did not return valid JSON");
        }
        $meta = self::asMetadata($body);
        if ($meta->get('issuer') !== $issuer) {
            throw new OidcDiscoveryError("discoverOidc: metadata issuer '" . $meta->get('issuer') . "' does not match requested '$issuer'");
        }
        if ($requireHttps && !self::isHttps($meta->get('jwks_uri'))) {
            throw new OidcDiscoveryError("discoverOidc: jwks_uri '" . $meta->get('jwks_uri') . "' is not an https URL");
        }
        return $meta;
    }

    private static function asMetadata(mixed $body): Obj
    {
        if (!($body instanceof Obj)) {
            throw new OidcDiscoveryError('discoverOidc: metadata is not a JSON object');
        }
        if (self::str($body->get('issuer')) === null) {
            throw new OidcDiscoveryError('discoverOidc: metadata is missing a string "issuer"');
        }
        if (self::str($body->get('jwks_uri')) === null) {
            throw new OidcDiscoveryError('discoverOidc: metadata is missing a string "jwks_uri"');
        }
        $m = Obj::of(['issuer' => $body->get('issuer'), 'jwks_uri' => $body->get('jwks_uri')]);
        foreach ($body->keys() as $k) {
            if ($k !== 'issuer' && $k !== 'jwks_uri') {
                $m->set($k, $body->get($k));
            }
        }
        return $m;
    }

    // ---- JWK sets ----

    private static function ktyFromAlg(mixed $alg): string
    {
        return match (is_string($alg) ? substr($alg, 0, 2) : null) {
            'RS', 'PS' => 'RSA',
            'ES' => 'EC',
            'Ed' => 'OKP',
            default => throw new JoseError('Unsupported "alg" value for a JSON Web Key Set'),
        };
    }

    /**
     * The JOSE library's createLocalJWKSet: a resolver (header -> the one matching public JWK) over a fixed set. Throws an
     * OidcCodedError ERR_JWKS_INVALID for a malformed set; resolution failures are JoseError.
     */
    public static function createLocalJwkSet(mixed $jwks): \Closure
    {
        $keys = Js::opt($jwks, 'keys');
        $ok = Js::isObj($jwks) && is_array($keys) && array_is_list($keys);
        foreach ($ok ? $keys : [] as $k) {
            $ok = $ok && Js::isObj($k);
        }
        if (!$ok) {
            throw new OidcCodedError('ERR_JWKS_INVALID', 'JSON Web Key Set malformed');
        }
        $keys = unserialize(serialize($keys)); // a private copy: later edits of the caller's set do not change the resolver
        return static function (mixed $header) use ($keys): mixed {
            $alg = Js::opt($header, 'alg');
            $kid = Js::opt($header, 'kid');
            $kty = self::ktyFromAlg($alg);
            $found = [];
            foreach ($keys as $j) {
                $m = $kty === Js::opt($j, 'kty');
                $m = $m && (!is_string($kid) || $kid === Js::opt($j, 'kid'));
                $m = $m && (!is_string(Js::opt($j, 'alg')) || $alg === Js::opt($j, 'alg'));
                $m = $m && (!is_string(Js::opt($j, 'use')) || Js::opt($j, 'use') === 'sig');
                $ops = Js::opt($j, 'key_ops');
                $m = $m && (!(is_array($ops) && array_is_list($ops)) || in_array('verify', $ops, true));
                $m = $m && (!isset(self::CRV_FOR_ALG[$alg]) || in_array(Js::opt($j, 'crv'), self::CRV_FOR_ALG[$alg], true));
                if ($m) {
                    $found[] = $j;
                }
            }
            if ($found === []) {
                throw new JoseError('no applicable key found in the JSON Web Key Set');
            }
            if (count($found) !== 1) {
                throw new JoseError('multiple matching keys found in the JSON Web Key Set');
            }
            $jwk = $found[0];
            if (Js::has($jwk, 'd')) {
                throw new JoseError('JSON Web Key Set members must be public keys');
            }
            if (!self::loadable($jwk)) {
                throw new JoseError('invalid JWK in the JSON Web Key Set');
            }
            return $jwk;
        };
    }

    /**
     * The fail-closed caching JWKS resolver. Options: jwksUri (required), fetch, cacheMaxAgeSec (600), cooldownSec (30),
     * maxBytes (1 MiB), requireHttps (true), timeoutMs (5000), now (callable -> epoch ms). A stale set is refetched and never
     * served when the refetch fails (code 'keys'); an unknown kid refetches at most once per cooldown.
     */
    public static function createOidcJwks(mixed $opts): \Closure
    {
        $uri = Js::opt($opts, 'jwksUri');
        if (!is_string($uri) || $uri === '') {
            throw new \TypeError('createOidcJwks: jwksUri is required');
        }
        if (Js::truthy(Js::opt($opts, 'requireHttps') ?? true) && preg_match('#\Ahttps://#i', $uri) !== 1) {
            throw new \TypeError('createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)');
        }
        $nowF = Js::opt($opts, 'now');
        $now = is_callable($nowF) && !is_string($nowF) ? $nowF : static fn(): int => (int)floor(microtime(true) * 1000);
        foreach (['cacheMaxAgeSec', 'cooldownSec', 'maxBytes', 'timeoutMs'] as $k) {
            if (Js::has($opts, $k)) {
                $v = Js::num(Js::opt($opts, $k));
                if ($v === null || !is_finite($v) || $v < 0) {
                    throw new \TypeError("createOidcJwks: $k must be a finite number >= 0");
                }
            }
        }
        $maxAgeMs = (Js::num(Js::opt($opts, 'cacheMaxAgeSec')) ?? 600) * 1000;
        $cooldownMs = (Js::num(Js::opt($opts, 'cooldownSec')) ?? 30) * 1000;
        $maxBytes = Js::num(Js::opt($opts, 'maxBytes')) ?? 1024 * 1024;
        $timeoutRaw = Js::num(Js::opt($opts, 'timeoutMs')) ?? (float)self::DEFAULT_JWKS_TIMEOUT_MS;
        $timeoutMs = (int)$timeoutRaw;
        $timeoutOk = $timeoutRaw == floor($timeoutRaw); // AbortSignal.timeout takes whole milliseconds: a fraction fails before any request
        $fetch = self::fetcher(Js::opt($opts, 'fetch'));
        $cache = null;
        $lastFetch = -INF;
        $refetch = static function () use (&$cache, &$lastFetch, $now, $fetch, $uri, $timeoutMs, $maxBytes, $timeoutOk): void {
            $lastFetch = $now();
            try {
                if (!$timeoutOk) {
                    throw new \TypeError('timeoutMs must be a whole number of milliseconds');
                }
                $res = $fetch($uri, ['accept' => 'application/json'], $timeoutMs);
                if (!self::ok($res)) {
                    throw new \RuntimeException('HTTP ' . IntentWb::jsStr(Js::opt($res, 'status')));
                }
                $text = self::bodyText($res);
                if (strlen(Js::utf8($text)) > $maxBytes) {
                    throw new \RuntimeException("response exceeds $maxBytes bytes");
                }
                $jwks = Js::parse($text);
                $keys = Js::opt($jwks, 'keys');
                if (!($jwks instanceof Obj) || !is_array($keys) || !array_is_list($keys)) {
                    throw new \RuntimeException('not a JWK Set');
                }
                $resolve = self::createLocalJwkSet($jwks);
            } catch (\Throwable) {
                throw new OidcVerificationError('keys', "could not fetch the issuer signing keys from $uri");
            }
            $kids = [];
            foreach ($keys as $k) {
                if (is_string(Js::opt($k, 'kid'))) {
                    $kids[Js::opt($k, 'kid')] = true;
                }
            }
            $cache = ['at' => (float)Js::num($now()), 'resolve' => $resolve, 'kids' => $kids];
        };
        return static function (mixed $header) use (&$cache, &$lastFetch, $now, $refetch, $maxAgeMs, $cooldownMs): mixed {
            $t = Js::num($now());
            if ($t === null || !is_finite($t)) {
                throw new OidcVerificationError('keys', 'the clock returned a non-finite time');
            }
            $kid = Js::opt($header, 'kid');
            if ($cache === null || $t - $cache['at'] >= $maxAgeMs) {
                $cache = null; // never serve a stale set, even if the refetch below fails
                $refetch();
            } elseif (is_string($kid) && !isset($cache['kids'][$kid]) && $t - Js::num($lastFetch) >= $cooldownMs) {
                $refetch();
            }
            return ($cache['resolve'])($header);
        };
    }

    /** Discover the issuer's jwks_uri, then build createOidcJwks over it (the same options). */
    public static function createOidcJwksFromIssuer(mixed $issuer, mixed $opts = []): \Closure
    {
        $meta = self::discoverOidc($issuer, ['requireHttps' => Js::opt($opts, 'requireHttps'), 'fetch' => Js::opt($opts, 'fetch')]);
        $o = [];
        foreach ($opts instanceof Obj ? $opts->keys() : array_keys((array)$opts) as $k) {
            $o[$k] = Js::opt($opts, (string)$k);
        }
        $o['jwksUri'] = $meta->get('jwks_uri');
        return self::createOidcJwks($o);
    }

    // ---- verification ----

    private static function invalid(string $msg): OidcVerificationError
    {
        return new OidcVerificationError('invalid_token', $msg);
    }

    private static function b64(mixed $jwk, string $name): string
    {
        $v = Js::opt($jwk, $name);
        if (!is_string($v)) {
            throw new JoseError("JWK member $name is missing");
        }
        return Jose::lenientB64d($v);
    }

    /** The key family of a JWK for an algorithm check (an OKP key must be Ed25519 / Ed448). */
    private static function jwkType(mixed $jwk): string
    {
        return match (Js::opt($jwk, 'kty')) {
            'RSA' => 'rsa',
            'EC' => 'ec',
            'OKP' => match (Js::opt($jwk, 'crv')) {
                'Ed25519' => 'ed25519',
                'Ed448' => 'ed448',
                default => throw self::invalid('Invalid key for this operation, its crv must be Ed25519 or Ed448'),
            },
            default => throw self::invalid('Invalid key for this operation, its kty must be RSA, OKP, or EC'),
        };
    }

    /** Whether the JWK's key material imports (exact coordinate sizes; an EC point must be on its curve). */
    private static function loadable(mixed $jwk): bool
    {
        try {
            switch (self::jwkType($jwk)) {
                case 'ed25519':
                    return strlen(self::b64($jwk, 'x')) === 32;
                case 'ed448':
                    return strlen(self::b64($jwk, 'x')) === 57;
                case 'ec':
                    $size = self::EC_SIZE[Js::opt($jwk, 'crv')] ?? null;
                    if ($size === null || strlen(self::b64($jwk, 'x')) !== $size || strlen(self::b64($jwk, 'y')) !== $size) {
                        return false;
                    }
                    Jose::publicKeyFromJwk($jwk);
                    return true;
                default:
                    if (self::b64($jwk, 'n') === '' || self::b64($jwk, 'e') === '') {
                        return false;
                    }
                    Jose::publicKeyFromJwk($jwk);
                    return true;
            }
        } catch (\Throwable) {
            return false;
        }
    }

    private static function isJwk(mixed $k): bool
    {
        return Js::isObj($k) && is_string(Js::opt($k, 'kty'));
    }

    private static function isResolver(mixed $k): bool
    {
        return is_object($k) && !($k instanceof Obj) && is_callable($k);
    }

    /** The JOSE key-type check: the key suits the algorithm family and, as a JWK, is public and usable for sig. */
    private static function checkKeyType(string $alg, mixed $key): void
    {
        $matchesOp = static function (mixed $k) use ($alg): void {
            if (Js::has($k, 'use') && Js::opt($k, 'use') !== 'sig') {
                throw self::invalid('Invalid key for this operation, when present its use must be sig');
            }
            $ops = Js::opt($k, 'key_ops');
            if (Js::has($k, 'key_ops') && !(is_array($ops) && array_is_list($ops) && in_array('verify', $ops, true))) {
                throw self::invalid('Invalid key for this operation, when present its key_ops must include verify');
            }
            if (Js::has($k, 'alg') && Js::opt($k, 'alg') !== $alg) {
                throw self::invalid("Invalid key for this operation, when present its alg must be $alg");
            }
        };
        if (str_starts_with($alg, 'HS')) {
            if (is_string($key)) {
                return;
            }
            if (self::isJwk($key) && Js::opt($key, 'kty') === 'oct' && is_string(Js::opt($key, 'k'))) {
                $matchesOp($key);
                return;
            }
            throw self::invalid('Invalid key for a symmetric algorithm');
        }
        if (self::isJwk($key) && Js::opt($key, 'kty') !== 'oct' && !Js::has($key, 'd')) {
            $matchesOp($key);
            return;
        }
        throw self::invalid('Invalid key for this operation: a public JWK is required');
    }

    /** The runtime verify: a key unfit for the alg throws invalid_token; bad key material or a bad signature is false. */
    private static function verifySig(string $alg, mixed $key, string $sig, string $data): bool
    {
        if (str_starts_with($alg, 'HS')) {
            if (!isset(self::HS[$alg])) {
                throw self::invalid("alg $alg is not supported");
            }
            try {
                $secret = is_string($key) ? $key : Jose::lenientB64d(Js::opt($key, 'k'));
            } catch (\Throwable) {
                return false;
            }
            return hash_equals(hash_hmac(self::HS[$alg], $data, $secret, true), $sig);
        }
        $t = self::jwkType($key);
        $fam = substr($alg, 0, 2);
        if ($alg === 'EdDSA') {
            if ($t !== 'ed25519' && $t !== 'ed448') {
                throw self::invalid('Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448');
            }
        } elseif (($fam === 'RS' || $fam === 'PS') && in_array(substr($alg, 2), ['256', '384', '512'], true)) {
            if ($t !== 'rsa') {
                throw self::invalid('Invalid key for this operation, its asymmetricKeyType must be rsa');
            }
            try {
                $bits = strlen(self::b64($key, 'n')) * 8;
            } catch (\Throwable) {
                $bits = 0;
            }
            if ($bits < 2048) {
                throw self::invalid("$alg requires key modulusLength to be 2048 bits or larger");
            }
        } elseif (isset(self::CURVE_ALG[$alg])) {
            if ($t !== 'ec') {
                throw self::invalid('Invalid key for this operation, its asymmetricKeyType must be ec');
            }
            if (Js::opt($key, 'crv') !== self::CURVE_ALG[$alg]) {
                throw self::invalid('Invalid key curve for the algorithm');
            }
        } else {
            throw self::invalid("alg $alg is not supported either by JOSE or your javascript runtime");
        }
        if (!self::loadable($key)) {
            return false;
        }
        try {
            return Jose::jwsVerify($alg, $key, $sig, $data, true);
        } catch (\Throwable) {
            return false; // includes Ed448 without ext-ffi / libcrypto: never accepted
        }
    }

    /** jwtVerify in the reference's order: crit, alg, allow-list, key, signature, unencoded payload, then the claim set. */
    private static function jwtVerify(Obj $header, Obj $payload, array $segments, mixed $key, mixed $algs, mixed $o): void
    {
        if ($header->has('crit')) {
            $crit = $header->get('crit');
            $okCrit = is_array($crit) && array_is_list($crit) && $crit !== [];
            foreach ($okCrit ? $crit : [] as $c) {
                $okCrit = $okCrit && is_string($c) && $c !== '';
            }
            if (!$okCrit) {
                throw new JoseError('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
            }
            foreach ($crit as $p) {
                if ($p !== 'b64') {
                    throw new JoseError("Extension Header Parameter \"$p\" is not recognized");
                }
                if (!$header->has('b64')) {
                    throw new JoseError('Extension Header Parameter "b64" is missing');
                }
            }
            if (!is_bool($header->get('b64'))) {
                throw new JoseError('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
            }
        }
        $alg = $header->get('alg');
        if (!is_string($alg) || $alg === '') {
            throw new JoseError('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if (!Js::isStrList($algs)) {
            throw new \TypeError('"algorithms" option must be an array of strings');
        }
        if (!in_array($alg, $algs, true)) {
            throw new JoseError('"alg" (Algorithm) Header Parameter value not allowed');
        }
        $resolved = self::isResolver($key);
        if ($resolved) {
            $key = $key($header);
        }
        self::checkKeyType($alg, $key);
        $sig = Jose::decodeCanonicalBase64url($segments[2]);
        if ($resolved && self::isJwk($key) && !str_starts_with($alg, 'HS') && !self::loadable($key)) {
            throw self::invalid('invalid JWK');
        }
        if (!self::verifySig($alg, $key, $sig, $segments[0] . '.' . $segments[1])) {
            throw new OidcSignatureFailed('signature verification failed');
        }
        $crit = $header->get('crit');
        if (is_array($crit) && in_array('b64', $crit, true) && $header->get('b64') === false) {
            throw new JoseError('JWTs MUST NOT use unencoded payload');
        }
        self::claimsCheck($payload, $o);
    }

    private static function claimsCheck(Obj $payload, mixed $o): void
    {
        $audience = Js::opt($o, 'audience');
        $maxAge = Js::opt($o, 'maxTokenAgeSec');
        $presence = Js::has($o, 'maxTokenAgeSec') ? ['iss', 'aud', 'iat'] : ['iss', 'aud'];
        foreach ($presence as $c) {
            if (!$payload->has($c)) {
                throw new OidcClaimFailed($c, "missing required \"$c\" claim");
            }
        }
        if ($payload->get('iss') !== Js::opt($o, 'issuer')) {
            throw new OidcClaimFailed('iss', 'unexpected "iss" claim value');
        }
        if (Js::truthy($audience)) {
            $want = is_string($audience) ? [$audience] : $audience;
            $aud = $payload->get('aud');
            $present = false;
            if (is_string($aud)) {
                $present = in_array($aud, $want, true);
            } elseif (is_array($aud) && array_is_list($aud)) {
                foreach ($aud as $a) {
                    $present = $present || in_array($a, $want, true);
                }
            }
            if (!$present) {
                throw new OidcClaimFailed('aud', 'unexpected "aud" claim value');
            }
        }
        $ct = Js::opt($o, 'clockToleranceSec');
        $tol = match (true) {
            !Js::has($o, 'clockToleranceSec') => 0.0,
            is_string($ct) => (float)Jose::secs($ct),
            Js::isNum($ct) => (float)Js::num($ct),
            default => throw new \TypeError('Invalid clockTolerance option type'),
        };
        $nowOpt = Js::num(Js::opt($o, 'now'));
        $now = floor($nowOpt ?? (float)time());
        if (($payload->has('iat') || Js::truthy($maxAge)) && !Js::isNum($payload->get('iat'))) {
            throw new OidcClaimFailed('iat', '"iat" claim must be a number');
        }
        if ($payload->has('nbf')) {
            if (!Js::isNum($payload->get('nbf'))) {
                throw new OidcClaimFailed('nbf', '"nbf" claim must be a number');
            }
            if (!(is_finite($now) && is_finite($tol) && Js::num($payload->get('nbf')) <= $now + $tol)) {
                throw new OidcClaimFailed('nbf', '"nbf" claim timestamp check failed');
            }
        }
        if ($payload->has('exp')) {
            if (!Js::isNum($payload->get('exp'))) {
                throw new OidcClaimFailed('exp', '"exp" claim must be a number');
            }
            if (!(is_finite($now) && is_finite($tol) && Js::num($payload->get('exp')) > $now - $tol)) {
                throw new OidcClaimFailed('exp', '"exp" claim timestamp check failed', true);
            }
        }
        if (!Js::truthy($maxAge)) {
            return;
        }
        $age = $now - Js::num($payload->get('iat'));
        $max = Js::isNum($maxAge) ? (float)Js::num($maxAge) : (float)Jose::secs(IntentWb::jsStr($maxAge));
        if (!(is_finite($age) && is_finite($tol) && $age - $tol <= $max)) {
            throw new OidcClaimFailed('iat', '"iat" claim timestamp check failed (too far in the past)', true);
        }
        if (!($age >= 0 - $tol)) {
            throw new OidcClaimFailed('iat', '"iat" claim timestamp check failed (it should be in the past)');
        }
    }

    private static function mapError(\Throwable $e): OidcVerificationError
    {
        return match (true) {
            $e instanceof OidcVerificationError => $e,
            $e instanceof OidcClaimFailed && $e->expired => $e->claim === 'iat'
                ? new OidcVerificationError('issued_at', 'id token is older than the maximum accepted age')
                : new OidcVerificationError('expired', 'id token has expired'),
            $e instanceof OidcClaimFailed => new OidcVerificationError(self::CLAIM_CODE[$e->claim] ?? 'claims', $e->getMessage()),
            $e instanceof OidcSignatureFailed => new OidcVerificationError('signature', 'id token signature verification failed'),
            $e instanceof JoseError, $e instanceof CanonicalJwsError => self::invalid($e->getMessage()),
            default => self::invalid('id token verification failed'),
        };
    }

    private static function resolveKey(mixed $o): mixed
    {
        if (Js::has($o, 'key')) {
            return Js::opt($o, 'key');
        }
        $rh = Js::opt($o, 'requireHttps');
        $uri = Js::opt($o, 'jwksUri');
        if (!Js::has($o, 'jwksUri') && Js::opt($o, 'discover') === true) {
            $uri = self::discoverOidc(Js::opt($o, 'issuer'), ['requireHttps' => $rh, 'fetch' => Js::opt($o, 'fetch')])->get('jwks_uri');
        }
        if ($uri === null && !Js::has($o, 'jwksUri')) {
            throw new OidcVerificationError('config', 'verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)');
        }
        try {
            return self::createOidcJwks(['jwksUri' => $uri, 'requireHttps' => $rh]);
        } catch (\TypeError $e) {
            throw new OidcVerificationError('config', 'verifyIdToken: ' . $e->getMessage());
        }
    }

    private static function projectClaims(Obj $payload, mixed $o): array
    {
        $iss = self::str($payload->get('iss'));
        if ($iss === null) {
            throw new OidcVerificationError('issuer', 'id token is missing the "iss" claim');
        }
        $sub = self::str($payload->get('sub'));
        if ($sub === null) {
            throw new OidcVerificationError('claims', 'id token is missing the "sub" claim');
        }
        if (!$payload->has('aud')) {
            throw new OidcVerificationError('audience', 'id token is missing the "aud" claim');
        }
        $aud = $payload->get('aud');
        $iat = self::finite($payload->get('iat'));
        if ($iat === null) {
            throw new OidcVerificationError('issued_at', 'id token is missing a numeric "iat" claim');
        }
        $exp = self::finite($payload->get('exp'));
        if ($exp === null) {
            throw new OidcVerificationError('expired', 'id token is missing a numeric "exp" claim');
        }
        $nonce = self::str($payload->get('nonce'));
        $azp = self::str($payload->get('azp'));
        if (Js::has($o, 'nonce') && $nonce !== Js::opt($o, 'nonce')) {
            throw new OidcVerificationError('nonce', $nonce === null ? 'id token is missing the expected nonce' : 'id token nonce does not match the expected value');
        }
        $audList = is_array($aud) && array_is_list($aud) ? $aud : [$aud];
        $ap = Js::opt($o, 'authorizedParty');
        $audOpt = Js::opt($o, 'audience');
        $expectedAzp = $ap ?? (is_string($audOpt) ? $audOpt : null);
        if (count($audList) > 1 && $azp === null) {
            throw new OidcVerificationError('azp', 'id token has multiple audiences but no azp (authorized party)');
        }
        if ($azp !== null && $expectedAzp !== null && $azp !== $expectedAzp) {
            throw new OidcVerificationError('azp', 'id token azp does not match the authorized party');
        }
        $out = ['iss' => $iss, 'sub' => $sub, 'aud' => $aud, 'iat' => $iat, 'exp' => $exp];
        if ($nonce !== null) {
            $out['nonce'] = $nonce;
        }
        if ($azp !== null) {
            $out['azp'] = $azp;
        }
        foreach (['at_hash', 'c_hash'] as $k) {
            if (self::str($payload->get($k)) !== null) {
                $out[$k] = $payload->get($k);
            }
        }
        if (self::finite($payload->get('auth_time')) !== null) {
            $out['auth_time'] = $payload->get('auth_time');
        }
        if (self::str($payload->get('email')) !== null) {
            $out['email'] = $payload->get('email');
        }
        if (is_bool($payload->get('email_verified'))) {
            $out['email_verified'] = $payload->get('email_verified');
        }
        foreach (['name', 'preferred_username', 'given_name', 'family_name', 'picture'] as $k) {
            if (self::str($payload->get($k)) !== null) {
                $out[$k] = $payload->get($k);
            }
        }
        if ($payload->get('cnf') instanceof Obj) {
            $out['cnf'] = unserialize(serialize($payload->get('cnf')));
        }
        return $out;
    }

    /** Node's 'ascii' encoding: the low byte of each UTF-16 code unit (a WTF-8 lone surrogate is one unit, bad bytes U+FFFD). */
    private static function asciiBytes(string $s): string
    {
        preg_match_all('/[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF4][\x80-\xBF]{3}|[\x80-\xFF]/s', $s, $m);
        $out = '';
        foreach ($m[0] as $c) {
            $n = strlen($c);
            $b = array_values(unpack('C*', $c));
            $cp = match ($n) {
                1 => $b[0] < 0x80 ? $b[0] : 0xFFFD,
                2 => (($b[0] & 0x1F) << 6) | ($b[1] & 0x3F),
                3 => (($b[0] & 0x0F) << 12) | (($b[1] & 0x3F) << 6) | ($b[2] & 0x3F),
                default => (($b[0] & 0x07) << 18) | (($b[1] & 0x3F) << 12) | (($b[2] & 0x3F) << 6) | ($b[3] & 0x3F),
            };
            $out .= $cp > 0xFFFF ? chr((0xD800 + (($cp - 0x10000) >> 10)) & 0xFF) . chr((0xDC00 + ($cp & 0x3FF)) & 0xFF) : chr($cp & 0xFF);
        }
        return $out;
    }

    /** OIDC Core 3.1.3.6: base64url(left half of H(value)), H chosen by the ID token's alg (EdDSA = SHA-512). */
    private static function checkHalfHash(string $name, mixed $actual, mixed $value, mixed $alg): void
    {
        if ($actual === null) {
            throw new OidcVerificationError($name, "id token is missing the expected $name");
        }
        $bits = $alg === 'EdDSA' ? '512' : (is_string($alg) && preg_match('/(256|384|512)\z/', $alg, $m) === 1 ? $m[1] : null);
        if ($bits === null) {
            throw new OidcVerificationError($name, "cannot compute $name for alg " . IntentWb::jsStr($alg));
        }
        if (!is_string($value)) {
            throw new OidcCodedError('ERR_INVALID_ARG_TYPE', 'The "data" argument must be of type string or an instance of Buffer, TypedArray, or DataView');
        }
        $d = hash("sha$bits", self::asciiBytes($value), true);
        if ($actual !== Pca::b64u(substr($d, 0, intdiv(strlen($d), 2)))) {
            throw new OidcVerificationError($name, "id token $name does not match the supplied value");
        }
    }

    /**
     * Verify an ID token; its verified claims. Options: issuer, audience (string | list) required; nonce, authorizedParty,
     * accessToken, code, clockToleranceSec, maxTokenAgeSec, algorithms, now (epoch seconds; default the clock), and a key
     * source: key | jwksUri | discover (+ fetch), requireHttps. Throws OidcVerificationError (codeName) on any refusal.
     */
    public static function verifyIdToken(mixed $idToken, mixed $o): array
    {
        if (!is_string($idToken) || $idToken === '') {
            throw self::invalid('verifyIdToken: idToken must be a non-empty string');
        }
        if (!($o instanceof Obj) && !(is_array($o) && ($o === [] || !array_is_list($o)))) {
            throw new OidcVerificationError('config', 'verifyIdToken: opts is required');
        }
        if (self::str(Js::opt($o, 'issuer')) === null) {
            throw new OidcVerificationError('config', 'verifyIdToken: opts.issuer is required');
        }
        $aud = Js::opt($o, 'audience');
        if (!is_string($aud) && !(is_array($aud) && array_is_list($aud))) {
            throw new OidcVerificationError('config', 'verifyIdToken: opts.audience is required');
        }
        // a non-finite skew tolerance would make every expiry comparison pass; a NaN age limit would disable the age check
        if (Js::has($o, 'clockToleranceSec')) {
            $ct = Js::opt($o, 'clockToleranceSec');
            if (!(Js::isNum($ct) && is_finite((float)Js::num($ct)) && (float)Js::num($ct) >= 0)) {
                throw new OidcVerificationError('config', 'verifyIdToken: clockToleranceSec must be a finite number >= 0');
            }
        }
        if (Js::has($o, 'maxTokenAgeSec')) {
            // JS `x >= 0` coerces: booleans, "", [] and numeric strings pass here (the verifier refuses them later); NaN, objects and other strings are config errors
            $ma = Js::opt($o, 'maxTokenAgeSec');
            $ok = match (true) {
                is_bool($ma) => true,
                Js::isNum($ma) => (float)Js::num($ma) >= 0,
                is_string($ma) => trim($ma) === '' || (is_numeric(trim($ma)) && (float)trim($ma) >= 0),
                is_array($ma) => $ma === [],
                default => false,
            };
            if (!$ok) {
                throw new OidcVerificationError('config', 'verifyIdToken: maxTokenAgeSec must be a number >= 0');
            }
        }
        try {
            $jws = Jose::assertCanonicalCompactJws($idToken);
        } catch (CanonicalJwsError $e) {
            throw self::invalid($e->getMessage());
        }
        $key = self::resolveKey($o);
        $algs = Js::spread(Js::opt($o, 'algorithms') ?? self::DEFAULT_ID_TOKEN_ALGS);
        try {
            self::jwtVerify($jws['header'], $jws['payload'], $jws['segments'], $key, $algs, $o);
        } catch (\Throwable $e) {
            throw self::mapError($e);
        }
        $claims = self::projectClaims($jws['payload'], $o);
        $alg = $jws['header']->get('alg');
        if (Js::has($o, 'accessToken')) {
            self::checkHalfHash('at_hash', $claims['at_hash'] ?? null, Js::opt($o, 'accessToken'), $alg);
        }
        if (Js::has($o, 'code')) {
            self::checkHalfHash('c_hash', $claims['c_hash'] ?? null, Js::opt($o, 'code'), $alg);
        }
        return $claims;
    }

    // ---- principal ----

    private static function canonicalEd25519B64u(mixed $s): ?string
    {
        return is_string($s) && $s !== '' && Pca::unb64u($s, 32) !== null ? $s : null;
    }

    private static function ed25519PublicFromCnf(mixed $c): ?string
    {
        if (!Js::has($c, 'cnf')) {
            return null;
        }
        $cnf = Js::opt($c, 'cnf');
        if ($cnf === null) {
            throw new \TypeError("Cannot read properties of null (reading 'jwk')");
        }
        $jwk = Js::isObj($cnf) ? Js::opt($cnf, 'jwk') : null;
        if (!Js::isObj($jwk) || Js::opt($jwk, 'kty') !== 'OKP' || Js::opt($jwk, 'crv') !== 'Ed25519' || !is_string(Js::opt($jwk, 'x'))) {
            return null;
        }
        return self::canonicalEd25519B64u(Js::opt($jwk, 'x'));
    }

    /**
     * Verified claims -> {iss, sub, principalId ("<iss>#<sub>"), subjectCaveat, claims, principalPublic?, email?, emailVerified?,
     * name?, preferredUsername?, authTime?}. principalPublic is the cnf-bound Ed25519 key or opts principalPublic (they must
     * agree). Throws TypeError on a missing iss / sub or a bad key, InvalidArgumentException on a cnf mismatch.
     */
    public static function oidcPrincipal(mixed $claims, mixed $opts = []): array
    {
        if ($claims === null) {
            throw new \TypeError("Cannot read properties of null (reading 'iss')");
        }
        if ($opts === null) {
            throw new \TypeError("Cannot read properties of null (reading 'principalPublic')");
        }
        $c = Js::isObj($claims) ? $claims : [];
        $iss = Js::opt($c, 'iss');
        $sub = Js::opt($c, 'sub');
        if (self::str($iss) === null) {
            throw new \TypeError('oidcPrincipal: claims.iss is required');
        }
        if (self::str($sub) === null) {
            throw new \TypeError('oidcPrincipal: claims.sub is required');
        }
        $fromToken = self::ed25519PublicFromCnf($c);
        $pp = $fromToken;
        if (Js::has($opts, 'principalPublic')) {
            $provided = self::canonicalEd25519B64u(Js::opt($opts, 'principalPublic'));
            if ($provided === null) {
                throw new \TypeError('oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key');
            }
            if ($fromToken !== null && $fromToken !== $provided) {
                throw new \InvalidArgumentException('oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token');
            }
            $pp = $provided;
        }
        $out = ['iss' => $iss, 'sub' => $sub, 'principalId' => "$iss#$sub",
            'subjectCaveat' => ['type' => self::OIDC_SUBJECT_CAVEAT, 'iss' => $iss, 'sub' => $sub], 'claims' => $claims];
        if ($pp !== null) {
            $out['principalPublic'] = $pp;
        }
        foreach (['email' => 'email', 'email_verified' => 'emailVerified', 'name' => 'name', 'preferred_username' => 'preferredUsername',
            'auth_time' => 'authTime'] as $src => $dst) {
            if (Js::has($c, $src)) {
                $out[$dst] = Js::opt($c, $src);
            }
        }
        return $out;
    }

    public static function isOidcSubjectCaveat(mixed $cv): bool
    {
        return Js::isObj($cv) && Js::opt($cv, 'type') === self::OIDC_SUBJECT_CAVEAT && self::str(Js::opt($cv, 'iss')) !== null
            && self::str(Js::opt($cv, 'sub')) !== null;
    }
}
