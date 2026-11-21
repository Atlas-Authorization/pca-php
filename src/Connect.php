<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Escalation.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/WhatwgUrl.php';
require_once __DIR__ . '/Explain.php';
require_once __DIR__ . '/Siem.php';
require_once __DIR__ . '/ConnectReplay.php';

// ---- errors (the typed refusals of the vault; branch on `errorCode`) -------------------------------------------------------------

/** Base class of every typed refusal of the vault. */
class VaultError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }

    public function code(): string
    {
        return $this->errorCode;
    }
}

/** The PCActn is not a valid, provider-bound authorization for this connection. `$checks` is the verifier's per-check verdict map. */
final class NotAuthorizedError extends VaultError
{
    /** @param array<string,mixed>|null $checks */
    public function __construct(string $message, public readonly ?array $checks = null)
    {
        parent::__construct('not_authorized', $message);
    }
}

final class ScopeExceededError extends VaultError
{
    /** @var list<mixed> */
    public readonly array $requested;
    /** @var list<mixed> */
    public readonly array $granted;
    /** @var list<mixed> */
    public readonly array $missing;

    /** @param list<mixed> $requested @param list<mixed> $granted @param list<mixed> $missing */
    public function __construct(public readonly mixed $provider, array $requested, array $granted, array $missing)
    {
        parent::__construct('scope_exceeded', "requested scopes exceed the capability's grant for '" . Jsx::str($provider) . "': not granted ["
            . implode(', ', array_map(Jsx::str(...), $missing)) . ']');
        $this->requested = array_values($requested);
        $this->granted = array_values($granted);
        $this->missing = array_values($missing);
    }
}

final class ExpiredNoRefreshError extends VaultError
{
    public function __construct(public readonly mixed $provider, public readonly mixed $connectionId)
    {
        parent::__construct('expired_no_refresh', "connection '" . Jsx::str($provider) . '/' . Jsx::str($connectionId) . "' token is expired and has no refresh token");
    }
}

final class RefreshFailedError extends VaultError
{
    public function __construct(public readonly mixed $provider, string $detail, public readonly mixed $status = null)
    {
        parent::__construct('refresh_failed', "refresh for '" . Jsx::str($provider) . "' failed: " . $detail);
    }
}

final class UnknownConnectionError extends VaultError
{
    public function __construct(public readonly mixed $agentId, public readonly mixed $provider, public readonly mixed $connectionId)
    {
        parent::__construct('unknown_connection', "no connection for agent '" . Jsx::str($agentId) . "' provider '" . Jsx::str($provider)
            . "' id '" . Jsx::str($connectionId) . "'");
    }
}

final class StoreError extends VaultError
{
    public function __construct(string $message = 'the connection store failed')
    {
        parent::__construct('store_error', $message);
    }
}

final class UnknownActionError extends VaultError
{
    public function __construct(string $verb)
    {
        parent::__construct('unknown_action', "no pinned action definition for verb '$verb': refusing to release a credential");
    }
}

final class UnconfirmedActionError extends VaultError
{
    public function __construct(mixed $verb)
    {
        parent::__construct('unconfirmed_action', "the definition of '" . Jsx::str($verb) . "' has no valid signed confirmation: refusing to release a credential");
    }
}

final class RequestMismatchError extends VaultError
{
    public function __construct(string $message)
    {
        parent::__construct('request_mismatch', $message);
    }
}

final class BearerReleaseDisabledError extends VaultError
{
    public function __construct()
    {
        parent::__construct('bearer_release_disabled', 'this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)');
    }
}

final class ProxyFailedError extends VaultError
{
    public function __construct(string $message)
    {
        parent::__construct('proxy_failed', $message);
    }
}

// ---- stored connections ----------------------------------------------------------------------------------------------------------

/**
 * Process-local connection store. Records (Obj) are cloned in and out so callers cannot mutate vault state. A key is an Obj
 * {agentId, provider, connectionId}. Any store the vault uses has these three methods (`get` returns an Obj or null).
 */
final class InMemoryConnectionStore
{
    /** @var array<string,Obj> */
    private array $map = [];

    private static function keyString(mixed $key): string
    {
        return Jsx::str(Jsx::rd($key, 'agentId')) . "\0" . Jsx::str(Jsx::rd($key, 'provider')) . "\0" . Jsx::str(Jsx::rd($key, 'connectionId'));
    }

    public function get(mixed $key): ?Obj
    {
        $found = $this->map[self::keyString($key)] ?? null;
        return $found === null ? null : Connect::cloneConnection($found);
    }

    public function set(mixed $connection): void
    {
        $this->map[self::keyString($connection)] = Connect::cloneConnection($connection);
    }

    public function delete(mixed $key): void
    {
        unset($this->map[self::keyString($key)]);
    }
}

/** A key ring held in process memory (production keys belong behind a KMS implementing `wrap` and `unwrap`). Keys are 32 raw bytes. */
final class LocalKeyWrapper
{
    /** @var array<string,string> */
    private array $keys = [];
    private string $active;

    /** @param array<string,string> $keys key id => 32 raw bytes */
    public function __construct(array $keys, string $activeId)
    {
        foreach ($keys as $id => $k) {
            $this->addKey((string)$id, $k);
        }
        if (!array_key_exists($activeId, $this->keys)) {
            throw new \InvalidArgumentException('LocalKeyWrapper: the active key id is not in the key ring');
        }
        $this->active = $activeId;
    }

    public function addKey(string $keyId, mixed $key): void
    {
        if ($keyId === '') {
            throw new \InvalidArgumentException('LocalKeyWrapper: key id must not be empty');
        }
        $raw = Bytes::of($key);
        if ($raw === null || strlen($raw) !== 32) {
            throw new \InvalidArgumentException('LocalKeyWrapper: keys must be 32 bytes');
        }
        $this->keys[$keyId] = $raw;
    }

    public function setActive(string $keyId): void
    {
        if (!array_key_exists($keyId, $this->keys)) {
            throw new \InvalidArgumentException('LocalKeyWrapper: the active key id is not in the key ring');
        }
        $this->active = $keyId;
    }

    public function removeKey(string $keyId): void
    {
        if ($keyId === $this->active) {
            throw new \InvalidArgumentException('LocalKeyWrapper: cannot remove the active key');
        }
        unset($this->keys[$keyId]);
    }

    public function destroy(): void
    {
        foreach ($this->keys as $id => $k) {
            sodium_memzero($k);
            $this->keys[$id] = '';
        }
        $this->keys = [];
    }

    /** @return array{keyId:string,wrapped:string} */
    public function wrap(string $dek, string $aad): array
    {
        $k = $this->keys[$this->active] ?? null;
        if ($k === null) {
            throw new \RuntimeException('no active key');
        }
        return ['keyId' => $this->active, 'wrapped' => Connect::seal($k, $aad, $dek)];
    }

    public function unwrap(string $keyId, string $wrapped, string $aad): string
    {
        $k = $this->keys[$keyId] ?? null;
        if ($k === null) {
            throw new \RuntimeException('unknown key id');
        }
        return Connect::open($k, $aad, $wrapped);
    }
}

/**
 * Wraps a connection store so `accessToken` and `refreshToken` are envelope-encrypted (AES-256-GCM, per-field data key wrapped under the
 * key ring, record key bound as AAD) before they reach it. Fails closed: a stored token that is not an envelope, fails authentication or
 * was sealed under an unknown key makes `get` throw a StoreError (no detail).
 */
final class EncryptedConnectionStore
{
    public bool $encrypted = true;

    public function __construct(private readonly mixed $inner, private readonly mixed $wrapper)
    {
    }

    public function get(mixed $key): ?Obj
    {
        $raw = $this->inner->get($key);
        if ($raw === null) {
            return null;
        }
        try {
            $out = Connect::cloneConnection($raw);
            $k = Obj::of(['agentId' => $raw->get('agentId'), 'provider' => $raw->get('provider'), 'connectionId' => $raw->get('connectionId')]);
            if ($k->get('agentId') !== Jsx::rd($key, 'agentId') || $k->get('provider') !== Jsx::rd($key, 'provider') || $k->get('connectionId') !== Jsx::rd($key, 'connectionId')) {
                throw new \InvalidArgumentException('record key mismatch');
            }
            $out->set('accessToken', Connect::decryptField($this->wrapper, $k, 'access', $raw->get('accessToken')));
            if ($raw->has('refreshToken')) {
                $out->set('refreshToken', Connect::decryptField($this->wrapper, $k, 'refresh', $raw->get('refreshToken')));
            }
            return $out;
        } catch (\Throwable) {
            throw new StoreError('a stored token could not be decrypted');
        }
    }

    public function set(mixed $connection): void
    {
        $k = Obj::of(['agentId' => Jsx::rd($connection, 'agentId'), 'provider' => Jsx::rd($connection, 'provider'), 'connectionId' => Jsx::rd($connection, 'connectionId')]);
        $sealed = Connect::cloneConnection($connection);
        try {
            $sealed->set('accessToken', Connect::encryptField($this->wrapper, $k, 'access', $connection->get('accessToken')));
            if ($connection->has('refreshToken')) {
                $sealed->set('refreshToken', Connect::encryptField($this->wrapper, $k, 'refresh', $connection->get('refreshToken')));
            }
        } catch (\Throwable) {
            throw new StoreError('a token could not be encrypted; nothing was stored');
        }
        $this->inner->set($sealed);
    }

    public function delete(mixed $key): void
    {
        $this->inner->delete($key);
    }

    /** Re-encrypt one record under the wrapper's active key (run after rotating the key ring). */
    public function reencrypt(mixed $key): bool
    {
        $c = $this->get($key);
        if ($c === null) {
            return false;
        }
        $this->set($c);
        return true;
    }
}

/**
 * The outbound connection / token vault's building blocks: the `oauth_scope` caveat, the proxy-mode request extractor, signed release
 * receipts, token refresh and the envelope encryption of stored tokens (the reference's pca-connect). The vault itself is {@see TokenVault}.
 * Values are the parsed-JSON model; injected transports are PHP callables (see each function).
 */
final class Connect
{
    public const OAUTH_SCOPE_CAVEAT = 'oauth_scope';
    public const DEFAULT_PROXY_HEADERS = ['content-type', 'accept', 'idempotency-key'];
    public const RELEASE_RECEIPT_DOMAIN = "atlas-pca/connect-release-receipt/v1\0";
    private const PLACEHOLDER = '/\{([A-Za-z0-9_]+)\}/';
    private const PREFIX = 'pca1';

    // ---- the oauth_scope caveat ----------------------------------------------------------------------------------------------

    /** An `oauth_scope` caveat granting `$scopes` on `$provider`; duplicate scopes are collapsed (first occurrence kept). */
    public static function oauthScopeCaveat(mixed $provider, mixed $scopes): Obj
    {
        $list = [];
        foreach (Js::spread($scopes) as $s) {
            if (!in_array($s, $list, true)) {
                $list[] = $s;
            }
        }
        return Obj::of(['type' => self::OAUTH_SCOPE_CAVEAT, 'provider' => $provider, 'scopes' => $list]);
    }

    public static function isOAuthScopeCaveat(mixed $cv): bool
    {
        return $cv instanceof Obj && $cv->get('type') === self::OAUTH_SCOPE_CAVEAT && is_string($cv->get('provider')) && Js::isStrList($cv->get('scopes'));
    }

    /**
     * The INTERSECTION of every `oauth_scope` caveat naming `$provider` in the chain's leaf, or null when the chain grants nothing for it
     * (so the vault can tell "not covered" from "covered but too narrow"). Run the chain verifier first. A null leaf throws (TypeError).
     *
     * @return list<string>|null
     */
    public static function grantedOAuthScopes(mixed $chain, mixed $provider): ?array
    {
        if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
            return null;
        }
        $leaf = $chain[count($chain) - 1];
        if ($leaf === null) {
            throw new \TypeError('Cannot read properties of null');
        }
        $cvs = $leaf instanceof Obj ? $leaf->get('caveats') : null;
        if (!is_array($cvs) || !array_is_list($cvs)) {
            return null;
        }
        $effective = null;
        foreach ($cvs as $cv) {
            if (!self::isOAuthScopeCaveat($cv) || $cv->get('provider') !== $provider) {
                continue;
            }
            $here = array_values(array_unique($cv->get('scopes')));
            $effective = $effective === null ? $here : array_values(array_filter($effective, static fn($s) => in_array($s, $here, true)));
        }
        return $effective;
    }

    // ---- stored connections --------------------------------------------------------------------------------------------------

    private static function putDefined(Obj $o, string $k, mixed $v): void
    {
        if (!Jsx::isUndef($v)) {
            $o->set($k, $v);
        }
    }

    /** A copy of a stored connection (the scopes lists are copied; optional members stay optional). */
    public static function cloneConnection(mixed $c): Obj
    {
        $a = Jsx::rd($c, 'authority');
        $auth = new Obj();
        self::putDefined($auth, 'provider', Jsx::rd($a, 'provider'));
        self::putDefined($auth, 'principal', Jsx::rd($a, 'principal'));
        $auth->set('scopes', Js::spread(Jsx::rd($a, 'scopes')));
        $aud = Jsx::rd($a, 'audience');
        self::putDefined($auth, 'audience', $aud);
        $out = new Obj();
        foreach (['agentId', 'provider', 'connectionId', 'accessToken', 'expiresAt'] as $k) {
            self::putDefined($out, $k, Jsx::rd($c, $k));
        }
        $out->set('scopes', Js::spread(Jsx::rd($c, 'scopes')));
        $out->set('authority', $auth);
        self::putDefined($out, 'createdAt', Jsx::rd($c, 'createdAt'));
        self::putDefined($out, 'useCount', Jsx::rd($c, 'useCount'));
        self::putDefined($out, 'refreshToken', Jsx::rd($c, 'refreshToken'));
        self::putDefined($out, 'lastUsedAt', Jsx::rd($c, 'lastUsedAt'));
        return $out;
    }

    /** A JS number as a Num (so it can sit in a record that is later hashed or compared). */
    public static function num(float $f): Num
    {
        return new Num(is_finite($f) && floor($f) === $f && abs($f) < 1e15 ? (string)(int)$f : IntentWb::jsNumStr($f));
    }

    // ---- the proxy-mode request extractor ----------------------------------------------------------------------------------

    private static function mismatch(string $m): never
    {
        throw new RequestMismatchError('outbound request refused: ' . $m);
    }

    private static function lower(string $s): string
    {
        return mb_strtolower($s, 'UTF-8');
    }

    public static function jsTrim(string $s): string
    {
        $ws = Siem::WS;
        return (string)preg_replace('/\A' . $ws . '+|' . $ws . '+\z/', '', $s);
    }

    /** @return array{0:bool,1:bool} [the URL carries a non-empty username or password, its fragment is non-empty] */
    public static function urlFacts(string $text): array
    {
        $s = (string)preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', $text);
        $s = str_replace(["\t", "\n", "\r"], '', $s);
        $h = strpos($s, '#');
        $hash = $h !== false && $h + 1 < strlen($s);
        if ($h !== false) {
            $s = substr($s, 0, $h);
        }
        $q = strpos($s, '?');
        if ($q !== false) {
            $s = substr($s, 0, $q);
        }
        $c = strpos($s, ':');
        $rest = $c === false ? '' : (string)preg_replace('#\A[/\\\\]+#', '', substr($s, $c + 1));
        $auth = preg_match('#\A[^/\\\\]*#', $rest, $m) === 1 ? $m[0] : '';
        $at = strrpos($auth, '@');
        if ($at === false) {
            return [false, $hash];
        }
        $info = substr($auth, 0, $at);
        $colon = strpos($info, ':');
        $user = $colon === false ? $info : substr($info, 0, $colon);
        $pass = $colon === false ? '' : substr($info, $colon + 1);
        return [$user !== '' || $pass !== '', $hash];
    }

    /** UTF-8 text of percent-decoded bytes, an invalid sequence becoming U+FFFD. */
    private static function utf8Replace(string $b): string
    {
        return mb_check_encoding($b, 'UTF-8') ? $b : htmlspecialchars_decode(htmlspecialchars($b, ENT_SUBSTITUTE | ENT_NOQUOTES, 'UTF-8'), ENT_NOQUOTES);
    }

    private static function formDecode(string $s): string
    {
        return self::utf8Replace(rawurldecode(str_replace('+', ' ', $s)));
    }

    /** application/x-www-form-urlencoded parse (URLSearchParams): '+' is a space, a bad percent escape stays literal. @return list<array{0:string,1:string}> */
    private static function formPairs(string $s): array
    {
        $out = [];
        foreach (explode('&', $s) as $seq) {
            if ($seq === '') {
                continue;
            }
            $eq = strpos($seq, '=');
            $k = $eq === false ? $seq : substr($seq, 0, $eq);
            $v = $eq === false ? '' : substr($seq, $eq + 1);
            $out[] = [self::formDecode($k), self::formDecode($v)];
        }
        return $out;
    }

    /** decodeURIComponent: throws on a malformed escape or a result that is not UTF-8. */
    private static function decodeUriComponent(string $s): string
    {
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $s) === 1) {
            throw new \InvalidArgumentException('URI malformed');
        }
        $d = rawurldecode($s);
        if (!mb_check_encoding($d, 'UTF-8')) {
            throw new \InvalidArgumentException('URI malformed');
        }
        return $d;
    }

    /**
     * The extractor of one operation: maps an outbound request back to the action's parameters and refuses anything the pinned spec does
     * not carry (an extra query key, body member, header or redirect target). `$spec`: {method, url, query?, body?: 'json'|'form', fixed?}.
     * Throws TypeError on a malformed spec; the returned closure takes the request ({method, url, headers?, body?}) and returns the params Obj.
     */
    public static function httpExtractor(mixed $spec): \Closure
    {
        $specUrl = Js::opt($spec, 'url');
        $specMethod = Js::opt($spec, 'method');
        if (!is_string($specUrl) || !is_string($specMethod)) {
            throw new \TypeError('httpExtractor: url and method must be strings');
        }
        $replaced = (string)preg_replace(self::PLACEHOLDER, 'x', $specUrl);
        $u = WhatwgUrl::parse($replaced);
        if ($u === null) {
            throw new NodeTypeError('Invalid URL', 'ERR_INVALID_URL');
        }
        [$userinfo, $hash] = self::urlFacts($replaced);
        if (($u['scheme'] ?? '') !== 'https' || ($u['search'] ?? '') !== '' || $hash || $userinfo) {
            throw new \TypeError('httpExtractor: url must be https without query, fragment or userinfo');
        }
        if ($specMethod !== mb_strtoupper($specMethod, 'UTF-8')) {
            throw new \TypeError('httpExtractor: method must be upper case');
        }
        $names = [];
        $origin = $u['origin'];
        $template = substr($specUrl, strlen($origin));
        $pat = '';
        foreach (preg_split(self::PLACEHOLDER, $template, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [] as $i => $part) {
            if ($i % 2 === 1) {
                $names[] = $part;
                $pat .= '([A-Za-z0-9._~%-]+)';
            } else {
                $pat .= preg_quote($part, '#');
            }
        }
        $rx = '#\A' . $pat . '\z#';
        $query = Js::opt($spec, 'query');
        $allowedQuery = is_array($query) ? $query : [];
        $bodyKind = Js::opt($spec, 'body');
        if ($bodyKind !== null && $bodyKind !== 'json' && $bodyKind !== 'form') {
            throw new \TypeError("httpExtractor: body must be 'json' or 'form'");
        }
        $ctype = $bodyKind === 'json' ? 'application/json' : ($bodyKind === 'form' ? 'application/x-www-form-urlencoded' : null);
        $fixedSpec = Js::opt($spec, 'fixed');

        return static function (mixed $req) use ($specMethod, $origin, $rx, $names, $allowedQuery, $bodyKind, $ctype, $fixedSpec): Obj {
            $method = Jsx::rd($req, 'method');
            if ($method !== $specMethod) {
                self::mismatch('method ' . Jsx::str($method) . ' is not ' . $specMethod);
            }
            $urlText = Jsx::str(Jsx::get($req, 'url'));
            $r = WhatwgUrl::parse($urlText);
            if ($r === null) {
                self::mismatch('the url does not parse');
            }
            [$userinfo, $hash] = self::urlFacts($urlText);
            if (($r['origin'] ?? null) !== $origin || $userinfo || $hash) {
                self::mismatch('the url is not on the pinned origin');
            }
            if (preg_match($rx, $r['pathname'], $m) !== 1) {
                self::mismatch('the path does not match the pinned template');
            }
            $params = new Obj();
            $put = static function (string $k, mixed $v) use ($params): void {
                if ($params->has($k)) {
                    self::mismatch("parameter '$k' is carried twice");
                }
                $params->set($k, $v);
            };
            foreach ($names as $i => $n) {
                try {
                    $v = self::decodeUriComponent($m[$i + 1]);
                } catch (\InvalidArgumentException) {
                    self::mismatch('a path segment is not valid percent-encoding');
                }
                $put($n, $v);
            }
            $seen = [];
            $search = (string)($r['search'] ?? '');
            foreach (self::formPairs($search === '' ? '' : substr($search, 1)) as [$k, $v]) {
                if (!in_array($k, $allowedQuery, true)) {
                    self::mismatch("query key '$k' is not allowed");
                }
                if (isset($seen["k$k"])) {
                    self::mismatch("query key '$k' is repeated");
                }
                $seen["k$k"] = true;
                $put($k, $v);
            }
            $hdrs = Jsx::get($req, 'headers');
            $ct = null;
            $ctSet = false;
            foreach (Jsx::keys($hdrs) as $h) {
                if (self::lower($h) === 'content-type') {
                    $ct = Jsx::get($hdrs, $h);
                    $ctSet = true;
                    break;
                }
            }
            $body = Jsx::get($req, 'body');
            if ($bodyKind === null) {
                if (!Jsx::isUndef($body) && $body !== '') {
                    self::mismatch('this operation carries no body');
                }
                return $params;
            }
            if (!is_string($body) || $body === '') {
                self::mismatch('the body is missing');
            }
            if ($ctSet && !is_string($ct)) {
                throw new \TypeError('content-type is not a string');
            }
            if (!$ctSet || self::lower(self::jsTrim(explode(';', (string)$ct)[0])) !== $ctype) {
                self::mismatch("content-type must be $ctype");
            }
            $fixedKeys = $fixedSpec instanceof Obj ? $fixedSpec->keys() : [];
            $takeFixed = static function (string $k) use (&$fixedKeys): bool {
                $i = array_search($k, $fixedKeys, true);
                if ($i === false) {
                    return false;
                }
                array_splice($fixedKeys, (int)$i, 1);
                return true;
            };
            if ($bodyKind === 'json') {
                try {
                    $b = Json::parseStrict($body);
                } catch (\Throwable) {
                    self::mismatch('the body is not strict JSON');
                }
                if (!$b instanceof Obj) {
                    self::mismatch('the body must be a JSON object');
                }
                foreach (Js::ownKeys($b->keys()) as $k) {
                    $v = $b->get($k);
                    if (in_array($k, $fixedKeys, true)) {
                        if (Pca::hashCanonical($v) !== Pca::hashCanonical($fixedSpec->get($k))) {
                            self::mismatch("fixed member '$k' has another value");
                        }
                        $takeFixed($k);
                    } else {
                        $put($k, $v);
                    }
                }
            } else {
                $keys = [];
                foreach (self::formPairs(str_starts_with($body, '?') ? substr($body, 1) : $body) as [$k, $v]) {
                    if (isset($keys["k$k"])) {
                        self::mismatch("form key '$k' is repeated");
                    }
                    $keys["k$k"] = true;
                    if (in_array($k, $fixedKeys, true)) {
                        if ($v !== $fixedSpec->get($k)) {
                            self::mismatch("fixed member '$k' has another value");
                        }
                        $takeFixed($k);
                    } else {
                        $put($k, $v);
                    }
                }
            }
            if ($fixedKeys !== []) {
                self::mismatch('fixed member(s) ' . implode(', ', $fixedKeys) . ' missing');
            }
            return $params;
        };
    }

    /** The request headers the agent may set (the vault sets Authorization itself); anything else is refused. @param list<string> $allow */
    public static function checkProxyHeaders(mixed $headers, mixed $allow): Obj
    {
        $out = new Obj();
        foreach (Jsx::keys($headers) as $k) {
            $v = Jsx::get($headers, $k);
            $n = self::lower($k);
            if (!in_array($n, is_array($allow) ? $allow : [], true)) {
                self::mismatch("header '$k' is not allowed");
            }
            if ($out->has($n)) {
                self::mismatch("header '$k' is repeated");
            }
            if (!is_string($v) || preg_match('/[\r\n\x00]/', $v) === 1) {
                self::mismatch("header '$k' has an invalid value");
            }
            $out->set($n, $v);
        }
        return $out;
    }

    // ---- release receipts ----------------------------------------------------------------------------------------------------

    public static function outboundRequestDigest(mixed $method, mixed $url, mixed $headers, mixed $body): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/connect-request/v1', 'method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body ?? null]));
    }

    /** The receipt body plus an Ed25519 signature of the vault key over domain || canonical(body). `$secretKey`: a 32-byte seed (or seed || public key) as Bytes / string. */
    public static function signReleaseReceipt(mixed $body, mixed $secretKey): Obj
    {
        $raw = Bytes::of($secretKey);
        if ($raw === null || (strlen($raw) !== 32 && strlen($raw) !== 64)) {
            throw new \InvalidArgumentException('signReleaseReceipt: the vault key is a 32-byte Ed25519 seed');
        }
        return Sign::signArtifact(self::RELEASE_RECEIPT_DOMAIN, $body, new KeyPair(substr($raw, 0, 32)));
    }

    /** True iff the receipt is signed by the pinned vault key (a base64url Ed25519 public key). */
    public static function verifyReleaseReceipt(mixed $r, mixed $vaultPk): bool
    {
        return IntentWb::verifyArtifactSig(self::RELEASE_RECEIPT_DOMAIN, $r, $vaultPk);
    }

    public static function receiptActionDigest(mixed $p): string
    {
        if (!$p instanceof Obj) {
            throw new \TypeError('receiptActionDigest: the PCActn must be an object');
        }
        return Escalation::actionDigest($p);
    }

    // ---- token refresh -------------------------------------------------------------------------------------------------------

    private static function redact(string $text, array $secrets): string
    {
        foreach ($secrets as $s) {
            if (is_string($s) && $s !== '') {
                $text = str_replace($s, '[redacted]', $text);
            }
        }
        return $text;
    }

    /** @return array{accessToken:string,expiresInSecs?:float,refreshToken?:string,scopes?:list<string>} */
    private static function parseTokenResponse(mixed $body, mixed $provider): array
    {
        if (!$body instanceof Obj) {
            throw new RefreshFailedError($provider, 'token endpoint returned a non-object body');
        }
        $at = $body->get('access_token');
        if (!is_string($at) || $at === '') {
            throw new RefreshFailedError($provider, 'token endpoint response has no access_token');
        }
        $out = ['accessToken' => $at];
        $ex = Js::num($body->get('expires_in'));
        if ($ex !== null && is_finite($ex) && $ex > 0) {
            $out['expiresInSecs'] = $ex;
        }
        $rt = $body->get('refresh_token');
        if (is_string($rt) && $rt !== '') {
            $out['refreshToken'] = $rt;
        }
        $scope = $body->get('scope');
        if (is_string($scope)) {
            $t = self::jsTrim($scope);
            if ($t !== '') {
                $out['scopes'] = preg_split('/' . Siem::WS . '+/', $t) ?: [];
            }
        }
        return $out;
    }

    /** Epoch-ms expiry claimed by a JWT access token; null for an opaque (non-JWT) token. */
    private static function jwtExpiryMs(string $token): ?float
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3 || preg_match('/\A[A-Za-z0-9_-]*\z/', $parts[1]) !== 1) {
                return null;
            }
            $b = base64_decode(strtr($parts[1], '-_', '+/') . str_repeat('=', (4 - strlen($parts[1]) % 4) % 4), true);
            if ($b === false) {
                return null;
            }
            $claims = Js::parse($b);
            $exp = $claims instanceof Obj ? Js::num($claims->get('exp')) : null;
            return $exp !== null && is_finite($exp) ? $exp * 1000 : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Refresh `$connection`'s access token at its provider's token endpoint. `$fetch` is `callable(string $url, Obj $init): object` returning an
     * object with `ok` (bool), `status`, `json()` and `text()`. Returns the fields to apply to the connection (accessToken, expiresAt, scopes,
     * refreshToken) as an Obj; throws RefreshFailedError on any transport or parse failure. No secret reaches an error.
     *
     * @param list<string> $requested
     */
    public static function refreshConnection(mixed $connection, mixed $config, mixed $refreshToken, mixed $requested, mixed $fetch, mixed $now, mixed $defaultTokenLifetimeMs): Obj
    {
        $provider = Jsx::rd($connection, 'provider');
        $extra = Js::opt($config, 'extraParams');
        $secrets = [$refreshToken, Jsx::rd($connection, 'accessToken'), Js::opt($config, 'clientSecret')];
        if ($extra instanceof Obj) {
            foreach ($extra->keys() as $k) {
                $secrets[] = $extra->get($k);
            }
        }
        if ($config === null || Jsx::isUndef($config)) {
            throw new RefreshFailedError($provider, 'no provider token-endpoint config');
        }
        if ($fetch === null) {
            throw new RefreshFailedError($provider, 'no fetch transport configured');
        }
        $params = Obj::of(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken, 'client_id' => Js::opt($config, 'clientId')]);
        if (Js::has($config, 'clientSecret')) {
            $params->set('client_secret', Js::opt($config, 'clientSecret'));
        }
        if ($extra instanceof Obj) {
            foreach ($extra->keys() as $k) {
                $params->set($k, $extra->get($k));
            }
        }
        $requestedList = is_array($requested) ? array_values($requested) : [];
        $narrowing = Js::opt($config, 'supportsScopeNarrowing') === true;
        if ($narrowing && count($requestedList) > 0) {
            $params->set('scope', implode(' ', array_map(Jsx::str(...), $requestedList)));
        }
        $enc = [];
        foreach (Js::ownKeys($params->keys()) as $k) {
            $enc[] = Js::encodeURIComponent($k) . '=' . Js::encodeURIComponent(Jsx::str($params->get($k)));
        }
        try {
            $res = $fetch(Js::opt($config, 'tokenEndpoint'), Obj::of([
                'method' => 'POST',
                'headers' => Obj::of(['content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json']),
                'body' => implode('&', $enc),
            ]));
        } catch (\Throwable $e) {
            throw new RefreshFailedError($provider, 'transport error: ' . self::redact($e->getMessage(), $secrets));
        }
        if (!$res->ok) {
            try {
                $detail = self::redact(Explain::slice16($res->text(), 0, 256), $secrets);
            } catch (\Throwable) {
                $detail = '<unreadable body>';
            }
            throw new RefreshFailedError($provider, 'token endpoint ' . Jsx::str($res->status) . ': ' . $detail, $res->status);
        }
        try {
            $json = $res->json();
        } catch (\Throwable) {
            throw new RefreshFailedError($provider, 'unparseable JSON body');
        }
        $parsed = self::parseTokenResponse($json, $provider);
        $nowF = (float)Js::num($now);
        if (isset($parsed['expiresInSecs'])) {
            $expiresAt = $nowF + $parsed['expiresInSecs'] * 1000;
        } else {
            $jwt = self::jwtExpiryMs($parsed['accessToken']);
            $expiresAt = $jwt ?? $nowF + (float)Js::num($defaultTokenLifetimeMs);
        }
        if (isset($parsed['scopes'])) {
            $scopes = $parsed['scopes'];
        } elseif ($narrowing && count($requestedList) > 0) {
            $scopes = $requestedList;
        } else {
            $scopes = Js::spread(Jsx::rd($connection, 'scopes'));
        }
        return Obj::of(['accessToken' => $parsed['accessToken'], 'expiresAt' => self::num($expiresAt), 'scopes' => $scopes,
            'refreshToken' => $parsed['refreshToken'] ?? $refreshToken]);
    }

    // ---- envelope encryption of stored tokens ---------------------------------------------------------------------------------

    private static function needOpenssl(): void
    {
        if (!function_exists('openssl_encrypt')) {
            throw new \RuntimeException('the encrypted connection store needs ext-openssl');
        }
    }

    /** iv(12) || ciphertext || tag(16), AES-256-GCM. */
    public static function seal(string $key, string $aad, string $plain, ?string $iv = null): string
    {
        self::needOpenssl();
        $iv ??= random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
        if ($ct === false || strlen($tag) !== 16) {
            throw new \RuntimeException('encryption failed');
        }
        return $iv . $ct . $tag;
    }

    public static function open(string $key, string $aad, string $sealed): string
    {
        self::needOpenssl();
        if (strlen($sealed) < 12 + 16) {
            throw new \InvalidArgumentException('short ciphertext');
        }
        $p = openssl_decrypt(substr($sealed, 12, -16), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($sealed, 0, 12), substr($sealed, -16), $aad);
        if ($p === false) {
            throw new \RuntimeException('authentication failed');
        }
        return $p;
    }

    private static function unb64uChars(string $s): string
    {
        if (preg_match('/\A[A-Za-z0-9_-]*\z/', $s) !== 1) {
            throw new \InvalidArgumentException('bad encoding');
        }
        $r = base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
        if ($r === false) {
            throw new \InvalidArgumentException('bad encoding');
        }
        return $r;
    }

    private static function aadFor(mixed $key, string $field): string
    {
        $parts = ['pca-connect/v1', $field, Jsx::rd($key, 'agentId'), Jsx::rd($key, 'provider'), Jsx::rd($key, 'connectionId')];
        $out = [];
        foreach ($parts as $p) {
            if (!is_string($p)) {
                throw new \TypeError('the record key is not made of strings');
            }
            $out[] = strlen($p) . ':' . Js::utf8($p);
        }
        return implode('|', $out);
    }

    public static function encryptField(mixed $w, mixed $key, string $field, mixed $plain): string
    {
        if (!is_string($plain)) {
            throw new \TypeError('token is not a string');
        }
        $aad = self::aadFor($key, $field);
        $dek = random_bytes(32);
        $wr = $w->wrap($dek, $aad);
        $sealed = self::seal($dek, $aad, Js::utf8($plain));
        return implode('.', [self::PREFIX, Pca::b64u(Js::utf8($wr['keyId'])), Pca::b64u($wr['wrapped']), Pca::b64u($sealed)]);
    }

    public static function decryptField(mixed $w, mixed $key, string $field, mixed $value): string
    {
        if (!is_string($value)) {
            throw new \TypeError('not an envelope');
        }
        $parts = explode('.', $value);
        if (count($parts) !== 4 || $parts[0] !== self::PREFIX) {
            throw new \InvalidArgumentException('not an envelope');
        }
        $aad = self::aadFor($key, $field);
        $dek = $w->unwrap(self::unb64uChars($parts[1]), self::unb64uChars($parts[2]), $aad);
        $p = self::open($dek, $aad, self::unb64uChars($parts[3]));
        if (!mb_check_encoding($p, 'UTF-8')) {
            throw new \InvalidArgumentException('not UTF-8');
        }
        return $p;
    }
}

require_once __DIR__ . '/ConnectVault.php';
