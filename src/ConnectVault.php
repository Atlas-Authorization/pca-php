<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Connect.php';

/**
 * Holds an agent's third-party OAuth tokens and releases a fresh access token only for a verified PCActn (the reference's TokenVault).
 *
 * Options (an Obj or an assoc array keyed by the reference's names): store, providers ({provider: {tokenEndpoint, clientId, clientSecret?,
 * supportsScopeNarrowing?, extraParams?}}), fetch (`callable(string $url, Obj $init): object` with ok / status / json() / text()), now
 * (`callable(): int`), audience, pqPins ({rootIssuer: pqPublicKey}), authorizedPlanRoots, insecureSkipPlanRootCheck, expiryLeewayMs,
 * defaultConnectionId, requireActionBinding, resourceFor (`callable(provider, connectionId): string`), useVerb, defaultTokenLifetimeMs,
 * replay (an object with `consumeOnce`, see {@see InMemoryReplayStore}), isRevoked (`callable(Obj $pcactn): bool`), strict (default true),
 * actions (`callable(string $verb): Obj|array|null` returning {verb, def_digest, confirmed, upstream: {provider, scopes_min}, extract?:
 * Closure}), insecureBearerRelease, proxyFetch (`callable(Obj $req): Obj|array` returning {status, headers, body}), proxyHeaders,
 * maxProxyResponseBytes, receipts ({secretKey, sink?}). Synchronous: the reference's async calls return their values.
 * A PQ root is accepted only under a server-side pin (pqPins[root.issuer] equal to the root's pq_pk); a classical root whose issuer has a
 * pin is refused.
 */
final class TokenVault
{
    private readonly mixed $store;
    private readonly mixed $providers;
    private readonly mixed $fetch;
    private readonly \Closure $nowFn;
    private readonly ?string $audience;
    private readonly mixed $pqPins;
    private readonly ?array $planRoots;
    private readonly bool $skipPlanRoot;
    private readonly mixed $leeway;
    private readonly string $defaultCid;
    private readonly bool $requireBinding;
    private readonly \Closure $resourceFor;
    private readonly ?string $useVerb;
    private readonly mixed $defaultLifetime;
    private readonly mixed $replay;
    private readonly mixed $isRevoked;
    private readonly mixed $actions;
    private readonly bool $bearer;
    private readonly mixed $proxyFetch;
    /** @var list<string> */
    private readonly array $proxyHeaders;
    private readonly float $maxProxy;
    private readonly mixed $receipts;

    public function __construct(mixed $options = null)
    {
        $store = Js::opt($options, 'store');
        if (Js::opt($options, 'strict') !== false) {
            $missing = [];
            if (!is_object($store) || ($store->encrypted ?? null) !== true) {
                $missing[] = 'an encrypting store';
            }
            if (Js::opt($options, 'replay') === null) {
                $missing[] = 'replay';
            }
            if (Js::opt($options, 'isRevoked') === null) {
                $missing[] = 'isRevoked';
            }
            $aud = Js::opt($options, 'audience');
            if (!is_string($aud) || $aud === '') {
                $missing[] = 'audience';
            }
            if ($missing !== []) {
                throw new \InvalidArgumentException('TokenVault strict mode requires ' . implode(', ', $missing));
            }
        } elseif ($store === null) {
            throw new \InvalidArgumentException('TokenVault requires a store');
        }
        $this->actions = Js::opt($options, 'actions');
        $this->bearer = Js::opt($options, 'insecureBearerRelease') === true;
        $this->proxyFetch = Js::opt($options, 'proxyFetch');
        $ph = Js::opt($options, 'proxyHeaders');
        $this->proxyHeaders = array_map(static fn($h) => mb_strtolower((string)$h, 'UTF-8'), is_array($ph) ? array_values($ph) : Connect::DEFAULT_PROXY_HEADERS);
        $this->maxProxy = (float)(Js::num(Js::opt($options, 'maxProxyResponseBytes') ?? 4 * 1024 * 1024) ?? 4 * 1024 * 1024);
        $this->receipts = Js::opt($options, 'receipts');
        $this->replay = Js::opt($options, 'replay');
        $this->isRevoked = Js::opt($options, 'isRevoked');
        $this->store = $store;
        $this->providers = Js::opt($options, 'providers') ?? new Obj();
        $this->fetch = Js::opt($options, 'fetch');
        $now = Js::opt($options, 'now');
        $this->nowFn = $now instanceof \Closure ? $now : (is_callable($now) ? \Closure::fromCallable($now) : static fn() => (int)(microtime(true) * 1000));
        $a = Js::opt($options, 'audience');
        $this->audience = is_string($a) ? $a : null;
        $this->pqPins = Js::opt($options, 'pqPins');
        $roots = Js::opt($options, 'authorizedPlanRoots');
        $this->planRoots = is_array($roots) ? $roots : null;
        $this->skipPlanRoot = Js::opt($options, 'insecureSkipPlanRootCheck') === true;
        $this->leeway = Js::opt($options, 'expiryLeewayMs') ?? 30_000;
        $cid = Js::opt($options, 'defaultConnectionId');
        $this->defaultCid = is_string($cid) ? $cid : 'default';
        $this->requireBinding = Js::opt($options, 'requireActionBinding') !== false;
        $rf = Js::opt($options, 'resourceFor');
        $this->resourceFor = $rf !== null && is_callable($rf) ? \Closure::fromCallable($rf) : static fn($provider, $connectionId) => 'oauth:' . Jsx::str($provider);
        $uv = Js::has($options, 'useVerb') ? Js::opt($options, 'useVerb') : 'use_connection';
        $this->useVerb = is_string($uv) ? $uv : null;
        $this->defaultLifetime = Js::opt($options, 'defaultTokenLifetimeMs') ?? 300_000;
    }

    private function now(): mixed
    {
        return ($this->nowFn)();
    }

    /**
     * Store (or replace) an agent's connection; `$authority` {principal, scopes?, audience?} binds which capability may use it.
     * Throws TypeError on a malformed argument.
     */
    public function putConnection(mixed $agentId, mixed $provider, mixed $accessToken, mixed $expiresAt, mixed $scopes, mixed $authority, mixed $connectionId = null, mixed $refreshToken = null): Obj
    {
        $cid = $connectionId ?? $this->defaultCid;
        $principal = Js::opt($authority, 'principal');
        foreach ([['agentId', $agentId], ['provider', $provider], ['connectionId', $cid], ['accessToken', $accessToken], ['principal', $principal]] as [$k, $val]) {
            if (!is_string($val) || $val === '') {
                throw new \TypeError("putConnection: $k must be a non-empty string");
            }
        }
        $ef = Js::num($expiresAt);
        if ($ef === null || !is_finite($ef)) {
            throw new \TypeError('putConnection: expiresAt must be a finite number');
        }
        if ($refreshToken !== null && (!is_string($refreshToken) || $refreshToken === '')) {
            throw new \TypeError('putConnection: refreshToken must be a non-empty string when given');
        }
        if (!Js::isStrList($scopes)) {
            throw new \TypeError('putConnection: scopes must be a list of strings');
        }
        $auth = Obj::of(['provider' => $provider, 'principal' => $principal, 'scopes' => Js::spread(Js::opt($authority, 'scopes') ?? $scopes)]);
        if (Js::has($authority, 'audience')) {
            $auth->set('audience', Js::opt($authority, 'audience'));
        }
        $conn = Obj::of(['agentId' => $agentId, 'provider' => $provider, 'connectionId' => $cid, 'accessToken' => $accessToken, 'expiresAt' => $expiresAt,
            'scopes' => array_values($scopes), 'authority' => $auth, 'createdAt' => $this->now(), 'useCount' => new Num('0')]);
        if ($refreshToken !== null) {
            $conn->set('refreshToken', $refreshToken);
        }
        $this->storeSet($conn);
        return $conn;
    }

    /**
     * A FRESH access token iff `$pcactn` verifies against the connection's bound principal and the chain's grant covers the requested
     * provider and scopes. Disabled unless the vault was built with insecureBearerRelease (prefer {@see proxyCall}).
     *
     * @param list<string>|null $scopes
     * @return Obj {provider, connectionId, accessToken, scopes, expiresAt, refreshed}
     */
    public function getConnectionToken(mixed $pcactn, mixed $provider, mixed $connectionId = null, mixed $scopes = null): Obj
    {
        if (!$this->bearer) {
            throw new BearerReleaseDisabledError();
        }
        $a = $this->authorize($pcactn, $provider, $connectionId, $scopes, false, null);
        [$token, $refreshed] = $this->freshToken($a);
        $done = $this->recordUse($a, $token);
        $this->issueReceipt($pcactn, $a, 'bearer', null, null, 'released', $done->get('scopes'));
        $expiresAt = $done->get('expiresAt');
        $exp = Js::num(Jsx::get($pcactn, 'exp'));
        $cur = Js::num($expiresAt);
        if ($a['action'] !== null && $exp !== null && is_finite($exp) && $cur !== null) {
            $expiresAt = Connect::num(min($cur, $exp));
        }
        return Obj::of(['provider' => $a['provider'], 'connectionId' => $a['connectionId'], 'accessToken' => $done->get('accessToken'),
            'scopes' => array_values($done->get('scopes')), 'expiresAt' => $expiresAt, 'refreshed' => $refreshed]);
    }

    /**
     * Proxy mode: the vault makes the outbound call itself (the agent never holds the credential). The request {method, url, headers?, body?}
     * must re-derive exactly the params the PCActn signed; the action is spent first; redirects are not followed; a receipt links release to
     * effect. Returns {response: {status, headers, body}, receipt?}.
     */
    public function proxyCall(mixed $pcactn, mixed $request, mixed $provider, mixed $connectionId = null, mixed $scopes = null): Obj
    {
        if ($this->actions === null) {
            throw new \TypeError('proxyCall requires the vault to be constructed with `actions`');
        }
        if ($this->proxyFetch === null) {
            throw new \TypeError('proxyCall requires the vault to be constructed with `proxyFetch`');
        }
        $sendHeaders = Connect::checkProxyHeaders(Jsx::get($request, 'headers'), $this->proxyHeaders);
        $a = $this->authorize($pcactn, $provider, $connectionId, $scopes, true, $request);
        [$token] = $this->freshToken($a);
        $done = $this->recordUse($a, $token);
        $headers = new Obj();
        foreach ($sendHeaders->keys() as $k) {
            $headers->set($k, $sendHeaders->get($k));
        }
        $headers->set('authorization', 'Bearer ' . $done->get('accessToken'));
        $body = Jsx::get($request, 'body');
        $reqDigest = Connect::outboundRequestDigest(Jsx::get($request, 'method'), Jsx::get($request, 'url'), $sendHeaders, Jsx::isUndef($body) ? null : $body);
        $call = Obj::of(['method' => Jsx::get($request, 'method'), 'url' => Jsx::get($request, 'url'), 'headers' => $headers, 'redirect' => 'manual']);
        if (!Jsx::isUndef($body)) {
            $call->set('body', $body);
        }
        try {
            $response = ($this->proxyFetch)($call);
        } catch (\Throwable) {
            $this->issueReceipt($pcactn, $a, 'proxy', $reqDigest, null, 'failed', $done->get('scopes'));
            throw new ProxyFailedError('the outbound call failed before a response');
        }
        $rbody = Js::opt($response, 'body');
        $status = Js::opt($response, 'status');
        $size = is_string($rbody) ? (float)strlen($rbody) : INF;
        $sf = Js::num($status);
        $okStatus = $sf !== null && is_finite($sf) && floor($sf) === $sf && abs($sf) <= 9007199254740991.0;
        $receipt = $this->issueReceipt($pcactn, $a, 'proxy', $reqDigest, $okStatus ? new Num((string)(int)$sf) : null, 'executed', $done->get('scopes'));
        if ($size > $this->maxProxy) {
            throw new ProxyFailedError('the response is larger than maxProxyResponseBytes (the call was made and the action is spent)');
        }
        // the credential must never travel back: a response header or body that echoes it is redacted
        $tok = (string)$done->get('accessToken');
        $rb = str_replace($tok, '[redacted]', (string)$rbody);
        $rh = new Obj();
        $src = Js::opt($response, 'headers');
        $keys = $src instanceof Obj ? Js::ownKeys($src->keys()) : (is_array($src) && !array_is_list($src) ? array_map('strval', array_keys($src)) : []);
        foreach ($keys as $k) {
            if (mb_strtolower($k, 'UTF-8') !== 'set-cookie') {
                $rh->set($k, str_replace($tok, '[redacted]', Js::str($src instanceof Obj ? $src->get($k) : $src[$k])));
            }
        }
        $out = Obj::of(['response' => Obj::of(['status' => $status, 'headers' => $rh, 'body' => $rb])]);
        if ($receipt !== null) {
            $out->set('receipt', $receipt);
        }
        return $out;
    }

    /**
     * Steps 1-5b of a release: resolve, anchor and verify, revoke, bind, derive scopes, least-privilege, spend. Shared by both release modes.
     *
     * @param list<string>|null $scopes
     * @return array{agentId:mixed,provider:mixed,connectionId:string,connection:Obj,requested:list<mixed>,now:mixed,nowInt:int,action:mixed}
     */
    private function authorize(mixed $pcactn, mixed $provider, mixed $connectionId, mixed $scopes, bool $needAction, mixed $request): array
    {
        $cid = $connectionId ?? $this->defaultCid;
        if ($pcactn === null) {
            throw new \TypeError("Cannot read properties of null (reading 'cap_chain')");
        }
        $chain = Jsx::get($pcactn, 'cap_chain');
        if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
            throw new NotAuthorizedError('PCActn has no capability chain');
        }
        $leaf = $chain[count($chain) - 1];
        $root = $chain[0];
        $agentId = Jsx::rd($leaf, 'holder');

        // 1. Resolve the connection: it carries the trust anchor (bound principal), so it is looked up before verification is anchored.
        $connection = $this->storeGet(Obj::of(['agentId' => $agentId, 'provider' => $provider, 'connectionId' => $cid]));
        if ($connection === null) {
            throw new UnknownConnectionError($agentId, $provider, $cid);
        }

        // 2. Anchor + verify: the chain must be rooted at the connection's bound principal, else a self-minted chain would verify against itself.
        $authority = Jsx::rd($connection, 'authority');
        $issuer = Jsx::rd($root, 'issuer');
        if ($issuer !== Jsx::rd($authority, 'principal')) {
            throw new NotAuthorizedError("capability chain is not rooted at the connection's bound principal");
        }
        // The root comes from the presented artifact, not from the verifier's own store: a PQ root is trusted only under a server-side
        // pin, and a classical root of a pinned issuer is a downgrade (R4-01).
        [$hasPin, $pin] = self::ownEntry($this->pqPins, $issuer);
        $classical = !($root instanceof Obj) || !$root->has('alg') || $root->get('alg') === 'ed25519';
        if ($classical) {
            if ($hasPin) {
                throw new NotAuthorizedError('the root issuer is pinned to a post-quantum key; a classical root is refused');
            }
        } elseif (!$hasPin || !is_string($pin) || $pin !== Jsx::get($root, 'pq_pk')) {
            throw new NotAuthorizedError('a post-quantum root needs a server-side PQ pin for its issuer');
        }
        $now = $this->now();
        $nowF = Js::num($now);
        if ($nowF === null || !is_finite($nowF) || floor($nowF) !== $nowF || abs($nowF) > 9007199254740991.0) {
            throw new NotAuthorizedError('PCActn verification failed: the verifier clock is not an integer epoch-ms');
        }
        $nowInt = (int)$nowF;
        $audience = Js::opt($authority, 'audience') ?? $this->audience;
        // null audience accepts any audience (the reference's undefined); a non-string one can never match
        $aud = $audience === null ? Audience::Any : (is_string($audience) ? $audience : null);
        $v = Pca::verifyPcactnCore($pcactn, $root, $nowInt, $aud, null, null, null, null, $this->planRoots, $this->skipPlanRoot);
        if (!$v['allow']) {
            throw new NotAuthorizedError('PCActn verification failed: ' . ($v['reason'] ?? 'rejected'), $v['checks'] ?? null);
        }

        // 2b. Revocation: no source configured means no check (opt in; `strict` makes it mandatory).
        if ($this->isRevoked !== null) {
            try {
                $revoked = ($this->isRevoked)($pcactn) !== false;
            } catch (\Throwable) {
                throw new NotAuthorizedError('revocation source unavailable');
            }
            if ($revoked) {
                throw new NotAuthorizedError('the capability chain is revoked');
            }
        }

        // 3. Bind the action. Derived mode: the verb resolves to a pinned, CONFIRMED action for this provider, and the scopes come from it.
        $act = Jsx::get($pcactn, 'action');
        $action = null;
        $min = [];
        if ($this->actions !== null) {
            $verb = Jsx::get($act, 'verb');
            $action = ($this->actions)($verb);
            if ($action === null || Js::opt($action, 'verb') !== $verb) {
                throw new UnknownActionError(Jsx::str($verb));
            }
            if (Js::opt($action, 'confirmed') !== true) {
                throw new UnconfirmedActionError($verb);
            }
            $up = Js::opt($action, 'upstream');
            if (Js::opt($up, 'provider') !== $provider) {
                throw new NotAuthorizedError("the action '" . Jsx::str($verb) . "' is not for provider '" . Jsx::str($provider) . "'");
            }
            $smin = Js::opt($up, 'scopes_min');
            if (!is_array($smin) || !array_is_list($smin) || $smin === []) {
                throw new NotAuthorizedError("the action '" . Jsx::str($verb) . "' declares no upstream scopes (nothing to release)");
            }
            $min = array_values($smin);
        } elseif ($needAction) {
            throw new UnknownActionError(Jsx::str(Jsx::get($act, 'verb')));
        } elseif ($this->requireBinding) {
            $expected = ($this->resourceFor)($provider, $cid);
            if (Jsx::get($act, 'resource') !== $expected) {
                throw new NotAuthorizedError("PCActn action resource '" . Jsx::str(Jsx::get($act, 'resource')) . "' is not for this connection (expected '" . Jsx::str($expected) . "')");
            }
            if ($this->useVerb !== null && Jsx::get($act, 'verb') !== $this->useVerb) {
                throw new NotAuthorizedError("PCActn action verb '" . Jsx::str(Jsx::get($act, 'verb')) . "' is not a connection-use verb (expected '" . $this->useVerb . "')");
            }
        }

        // 4. Authority coverage: null means the capability grants nothing for this provider.
        $granted = Connect::grantedOAuthScopes($chain, $provider);
        if ($granted === null) {
            throw new NotAuthorizedError("capability grants no authority for provider '" . Jsx::str($provider) . "'");
        }

        // 5. Least privilege. Legacy: requested scopes default to the connection's bound authority scopes. Derived: they ARE the action's
        //    scopes_min (a caller may ask for fewer, never more), and the stored connection must hold them.
        $connScopes = array_values((array)$connection->get('scopes'));
        $authScopes = array_values((array)Jsx::rd($authority, 'scopes'));
        $given = is_array($scopes) ? array_values($scopes) : null;
        $notIn = static fn(array $of, array $list): array => array_values(array_filter($of, static fn($s) => !in_array($s, $list, true)));
        if ($action !== null) {
            $requested = $given ?? $min;
            $beyond = $notIn($requested, $min);
            if ($beyond !== []) {
                throw new ScopeExceededError($provider, $requested, $min, $beyond);
            }
            $unheld = array_values(array_filter($min, static fn($s) => !in_array($s, $connScopes, true) || !in_array($s, $authScopes, true)));
            if ($unheld !== []) {
                throw new ScopeExceededError($provider, $min, $connScopes, $unheld);
            }
            // a bare bearer token cannot be narrowed after issue: it may carry nothing beyond the action's scopes
            if (!$needAction) {
                $extra = $notIn($connScopes, $min);
                if ($extra !== []) {
                    throw new ScopeExceededError($provider, $min, $connScopes, $extra);
                }
            }
            $ungranted = $notIn($min, $granted);
            if ($ungranted !== []) {
                throw new ScopeExceededError($provider, $min, $granted, $ungranted);
            }
        } else {
            $requested = $given ?? $authScopes;
        }
        $missing = $notIn($requested, $granted);
        if ($missing !== []) {
            throw new ScopeExceededError($provider, $requested, $granted, $missing);
        }

        // 5a. Proxy mode: the outbound request must re-derive EXACTLY the params the PCActn signed.
        if ($needAction && $action !== null) {
            $extract = Js::opt($action, 'extract');
            if ($request === null || $extract === null) {
                throw new RequestMismatchError('the action has no request extractor: proxy mode cannot bind the outbound request');
            }
            try {
                $params = $extract($request);
            } catch (RequestMismatchError $e) {
                throw $e;
            } catch (\Throwable) {
                throw new RequestMismatchError('the outbound request could not be mapped to the action parameters');
            }
            try {
                $d = Pca::paramsDigest($params);
            } catch (\Throwable) {
                throw new RequestMismatchError('the outbound request parameters are not canonical');
            }
            if ($d !== Jsx::get($act, 'params_digest')) {
                throw new RequestMismatchError('the outbound request does not carry the parameters the PCActn signed');
            }
        }

        // 5b. One-time use, last of the authorization checks so a refused request does not burn the action.
        if ($this->replay !== null) {
            $verdict = ConnectReplay::guardPcactnReplay($this->replay, $pcactn, Jsx::get($pcactn, 'aud'), $nowInt);
            if (!$verdict['ok']) {
                throw new NotAuthorizedError('replay guard refused the action: ' . $verdict['reason']);
            }
        }
        return ['agentId' => $agentId, 'provider' => $provider, 'connectionId' => $cid, 'connection' => $connection, 'requested' => $requested,
            'now' => $now, 'nowInt' => $nowInt, 'action' => $action];
    }

    /** @return array{0:bool,1:mixed} [the pins hold an own entry for the issuer, that entry] */
    private static function ownEntry(mixed $pins, mixed $issuer): array
    {
        if (!is_string($issuer)) {
            return [false, null];
        }
        if ($pins instanceof Obj) {
            return $pins->has($issuer) ? [true, $pins->get($issuer)] : [false, null];
        }
        if (is_array($pins) && !array_is_list($pins) && array_key_exists($issuer, $pins)) {
            return [true, $pins[$issuer]];
        }
        return [false, null];
    }

    private static function copy(Obj $o): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $o->get($k));
        }
        return $c;
    }

    /**
     * Step 6: refresh a stale token, else use it as is. A token whose expiry or clock is not a finite number can never be shown fresh.
     *
     * @return array{0:Obj,1:bool}
     */
    private function freshToken(array $a): array
    {
        $conn = $a['connection'];
        $token = $conn;
        $refreshed = false;
        $ea = Js::num($conn->get('expiresAt'));
        $nowF = Js::num($a['now']);
        if ($ea === null || !is_finite($ea) || $nowF === null || !is_finite($nowF) || $ea - $nowF <= (float)Js::num($this->leeway)) {
            if (!$conn->has('refreshToken')) {
                throw new ExpiredNoRefreshError($a['provider'], $a['connectionId']);
            }
            $updated = Connect::refreshConnection($conn, Js::opt($this->providers, (string)$a['provider']), $conn->get('refreshToken'), $a['requested'],
                $this->fetch, $a['now'], $this->defaultLifetime);
            $token = self::copy($conn);
            foreach ($updated->keys() as $k) {
                $token->set($k, $updated->get($k));
            }
            $refreshed = true;
        }
        return [$token, $refreshed];
    }

    /** Step 7: record usage and persist. */
    private function recordUse(array $a, Obj $token): Obj
    {
        $t = self::copy($token);
        $t->set('lastUsedAt', $a['now']);
        $t->set('useCount', Connect::num((float)Js::num($token->get('useCount')) + 1));
        $this->storeSet($t);
        return $t;
    }

    private static function u16(string $s): string
    {
        return (string)mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
    }

    /** @param mixed $scopes list<string> */
    private function issueReceipt(mixed $pcactn, array $a, string $mode, ?string $requestDigest, ?Num $httpStatus, string $outcome, mixed $scopes): ?Obj
    {
        if ($this->receipts === null) {
            return null;
        }
        $sorted = array_values((array)$scopes);
        usort($sorted, static fn($x, $y) => strcmp(self::u16((string)$x), self::u16((string)$y)));
        $receipt = Connect::signReleaseReceipt(Obj::of([
            'v' => new Num('1'), 'kind' => 'pca-release-receipt', 'action_digest' => Connect::receiptActionDigest($pcactn), 'provider' => $a['provider'],
            'connection_id' => $a['connectionId'], 'mode' => $mode, 'scopes_released' => $sorted, 'request_digest' => $requestDigest,
            'http_status' => $httpStatus, 'outcome' => $outcome, 'ts' => new Num((string)$a['nowInt']),
        ]), Js::opt($this->receipts, 'secretKey'));
        $sink = Js::opt($this->receipts, 'sink');
        if ($sink !== null) {
            try {
                $sink($receipt);
            } catch (\Throwable) {
                // a failing sink must not turn a made call into an error the caller retries; the receipt is still returned
            }
        }
        return $receipt;
    }

    /** Remove a stored connection. */
    public function deleteConnection(mixed $agentId, mixed $provider, mixed $connectionId = null): void
    {
        try {
            $this->store->delete(Obj::of(['agentId' => $agentId, 'provider' => $provider, 'connectionId' => $connectionId ?? $this->defaultCid]));
        } catch (VaultError $e) {
            throw $e;
        } catch (\Throwable) { // the store's own error text can quote a record
            throw new StoreError();
        }
    }

    private function storeGet(Obj $key): ?Obj
    {
        try {
            return $this->store->get($key);
        } catch (VaultError $e) {
            throw $e;
        } catch (\Throwable) {
            throw new StoreError();
        }
    }

    private function storeSet(Obj $c): void
    {
        try {
            $this->store->set($c);
        } catch (VaultError $e) {
            throw $e;
        } catch (\Throwable) {
            throw new StoreError();
        }
    }
}
