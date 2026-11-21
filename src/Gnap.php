<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/SignersMore.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/WhatwgUrl.php';
require_once __DIR__ . '/Ciba.php';

/** Thrown by the GNAP issuance paths on a malformed request (the verify paths fail closed instead). */
final class GnapError extends \RuntimeException
{
    public function __construct(string $message = '', public readonly ?string $codeName = null)
    {
        parent::__construct($message);
    }
}

/** A GNAP interaction failure with a stable code (invalid_interaction, unknown_interaction, too_many_attempts, ...). */
final class InteractionError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * GNAP (RFC 9635) bridge, the Agent-GNAP profile (mirrors @atlasauth/pca-gnap): GNAP `access` rights map onto policy predicates
 * (resource `gnap:<type>:<location>`), a grant request becomes a root grant (mintGrant) or an attenuated delegated hop carrying a
 * `gnap_access` caveat, the access token is the capability chain itself, requests are key-bound with `jwsd` detached JWS, and a
 * continuation resolves through a threshold co-signature folded into the PCActn. Interaction modes (RFC 9635 2.5, 3.3, 4, 5.1)
 * are below, with InteractionServer. Every verification fails closed. Values are the parsed-JSON model; options use the
 * reference's camelCase names (Obj or assoc array). Secrets are 32-byte Ed25519 seeds (raw bytes).
 */
final class Gnap
{
    public const GNAP_GRANT_CAVEAT = 'gnap_grant';
    public const GNAP_ACCESS_CAVEAT = 'gnap_access';
    public const MAX_DETACHED_JWS_CHARS = 8192;
    public const START_MODES = ['redirect', 'app', 'user_code', 'user_code_uri'];
    public const FINISH_METHODS = ['redirect', 'push'];
    /** Named Information hash names (IANA) -> PHP hash algorithm. */
    public const HASH_METHODS = ['sha-256' => 'sha256', 'sha-384' => 'sha384', 'sha-512' => 'sha512', 'sha3-256' => 'sha3-256', 'sha3-512' => 'sha3-512'];
    private const JWSD_TYP = 'gnap-binding-jwsd';
    private const REQUEST_DOMAIN = 'atlas-pca/gnap/request/v1';
    private const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    /** Names a JavaScript `in` test on the reference's method table also finds (inherited from Object.prototype). */
    private const OBJECT_PROTO = ['constructor', '__defineGetter__', '__defineSetter__', 'hasOwnProperty', '__lookupGetter__', '__lookupSetter__',
        'isPrototypeOf', 'propertyIsEnumerable', 'toString', 'valueOf', '__proto__', 'toLocaleString'];
    private const ROLES = ['agent', 'guardian', 'principal'];

    // ---- small guards ----------------------------------------------------------------------------------------------------

    private static function isRecord(mixed $x): bool
    {
        return $x instanceof Obj;
    }

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** The string members of a list, or null when `$u` is not a list. @return ?list<string> */
    private static function strArr(mixed $u): ?array
    {
        return self::isList($u) ? array_values(array_filter($u, 'is_string')) : null;
    }

    /** A canonical, unpadded base64url Ed25519 public key (exactly 32 bytes), or null. */
    private static function asEd25519(mixed $x): ?string
    {
        return is_string($x) && Pca::unb64u($x, 32) !== null ? $x : null;
    }

    /** The reference's `x.k` read on a JSON value: null / undefined throws, a non-object has no members. */
    private static function member(mixed $o, string $k): mixed
    {
        return Js::get($o, $k);
    }

    public static function gnapActionResource(string $type, string $location): string
    {
        return "gnap:$type:$location";
    }

    // ---- access rights ---------------------------------------------------------------------------------------------------

    private static function tryNormalizeAccessItem(mixed $item): ?Obj
    {
        if (is_string($item)) {
            return $item !== '' ? Obj::of(['type' => $item]) : null;
        }
        if (!self::isRecord($item)) {
            return null;
        }
        $type = $item->get('type');
        if (!is_string($type) || $type === '') {
            return null;
        }
        $out = Obj::of(['type' => $type]);
        foreach (['actions', 'locations', 'datatypes'] as $k) {
            $a = self::strArr($item->get($k));
            if ($a !== null && $a !== []) {
                $out->set($k, $a);
            }
        }
        if (is_string($item->get('identifier'))) {
            $out->set('identifier', $item->get('identifier'));
        }
        $p = self::strArr($item->get('privileges'));
        if ($p !== null && $p !== []) {
            $out->set('privileges', $p);
        }
        return $out;
    }

    /** Normalize an access array for issuance (throws GnapError on any malformed entry). @return list<Obj> */
    public static function normalizeAccess(mixed $items): array
    {
        if (!self::isList($items)) {
            throw new GnapError('access must be an array');
        }
        return array_map(static fn(mixed $i): Obj => self::tryNormalizeAccessItem($i)
            ?? throw new GnapError('malformed access item (needs a non-empty string `type`)'), $items);
    }

    /** Total read of a stored access array (signed caveats): malformed entries are skipped. @return list<Obj> */
    private static function readAccessArray(mixed $u): array
    {
        if (!self::isList($u)) {
            return [];
        }
        $out = [];
        foreach ($u as $item) {
            $n = self::tryNormalizeAccessItem($item);
            if ($n !== null) {
                $out[] = $n;
            }
        }
        return $out;
    }

    /** One predicate per location: `type` namespaces the resource, actions become verbs, datatypes / identifier `where` conditions. @return list<Obj> */
    public static function accessToPredicates(Obj $access): array
    {
        $actions = $access->get('actions');
        $verb = self::isList($actions) && $actions !== [] ? $actions : '*';
        $locs = $access->get('locations');
        $locations = self::isList($locs) && $locs !== [] ? $locs : ['*'];
        $where = [];
        $dt = $access->get('datatypes');
        if (self::isList($dt) && $dt !== []) {
            $where[] = ['field' => 'action.params.datatype', 'op' => 'in', 'value' => $dt];
        }
        if (is_string($access->get('identifier'))) {
            $where[] = ['field' => 'action.params.identifier', 'op' => 'eq', 'value' => $access->get('identifier')];
        }
        $type = Js::str($access->get('type'));
        return array_map(static function (mixed $loc) use ($verb, $type, $where): Obj {
            $p = Obj::of(['verb' => $verb, 'resource' => self::gnapActionResource($type, Js::str($loc))]);
            if ($where !== []) {
                $p->set('where', array_map(static fn(array $c): Obj => Obj::of($c), $where));
            }
            return $p;
        }, $locations);
    }

    /** @param list<Obj> $access @return list<Obj> */
    private static function accessArrayToPredicates(array $access): array
    {
        return array_merge([], ...array_map(self::accessToPredicates(...), $access));
    }

    private static function coversStrings(Obj $g, Obj $r, string $k): bool
    {
        if (!$g->has($k)) {
            return true; // issuer allows all
        }
        if (!$r->has($k)) {
            return false; // request wants all, issuer has a concrete set
        }
        $sup = Js::spread($g->get($k));
        foreach (Js::spread($r->get($k)) as $s) {
            if (!in_array($s, $sup, true)) {
                return false;
            }
        }
        return true;
    }

    private static function coversLocations(Obj $g, Obj $r): bool
    {
        if (!$g->has('locations')) {
            return true;
        }
        $sup = Js::spread($g->get('locations'));
        if (!$r->has('locations')) {
            return in_array('*', $sup, true);
        }
        foreach (Js::spread($r->get('locations')) as $s) {
            $ok = false;
            foreach ($sup as $gl) {
                if ($gl === $s || $gl === '*' || (is_string($gl) && is_string($s) && str_ends_with($gl, '*') && str_starts_with($s, substr($gl, 0, -1)))) {
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                return false;
            }
        }
        return true;
    }

    /** Does the issuer's granted right `g` fully contain the requested right `r`? */
    public static function accessContains(Obj $g, Obj $r): bool
    {
        if ($g->get('type') !== $r->get('type')) {
            return false;
        }
        if (!self::coversStrings($g, $r, 'actions') || !self::coversLocations($g, $r) || !self::coversStrings($g, $r, 'datatypes')) {
            return false;
        }
        return !($r->has('identifier') && $g->has('identifier') && $g->get('identifier') !== $r->get('identifier'));
    }

    /** @param list<Obj> $granted */
    public static function accessWithin(array $granted, Obj $r): bool
    {
        foreach ($granted as $g) {
            if (self::accessContains($g, $r)) {
                return true;
            }
        }
        return false;
    }

    /** @param list<Obj> $issuerGranted @param list<Obj> $requested @return array{granted: list<Obj>, dropped: list<Obj>} */
    public static function clampAccess(array $issuerGranted, array $requested): array
    {
        $out = ['granted' => [], 'dropped' => []];
        foreach ($requested as $r) {
            $out[self::accessWithin($issuerGranted, $r) ? 'granted' : 'dropped'][] = $r;
        }
        return $out;
    }

    // ---- provenance caveats ------------------------------------------------------------------------------------------------

    private static function readGnapGrant(mixed $root): ?Obj
    {
        $env = Authorize::readEnvelope($root);
        if ($env === null) {
            return null;
        }
        $cv = null;
        foreach ($env->get('caveats') as $c) {
            if ($c instanceof Obj && $c->get('type') === self::GNAP_GRANT_CAVEAT) {
                $cv = $c;
                break;
            }
        }
        if ($cv === null || !is_string($cv->get('client_id')) || !is_string($cv->get('request_digest'))) {
            return null;
        }
        return Obj::of(['type' => self::GNAP_GRANT_CAVEAT, 'client_id' => $cv->get('client_id'), 'granted_access' => self::readAccessArray($cv->get('granted_access')),
            'request_digest' => $cv->get('request_digest'), 'interacted' => $cv->get('interacted') === true, 'ts' => Js::isNum($cv->get('ts')) ? $cv->get('ts') : 0]);
    }

    /** The effective access of a chain: the leaf's last recorded `gnap_access`, else the root grant's recorded rights. @return list<Obj> */
    public static function grantedAccessOf(mixed $chain): array
    {
        if (!self::isList($chain) || $chain === []) {
            return [];
        }
        $leaf = $chain[count($chain) - 1];
        $cs = self::member($leaf, 'caveats');
        $caveats = self::isList($cs) ? $cs : [];
        for ($i = count($caveats) - 1; $i >= 0; $i--) {
            $cv = $caveats[$i];
            if ($cv instanceof Obj && $cv->get('type') === self::GNAP_ACCESS_CAVEAT) {
                return self::readAccessArray($cv->get('access'));
            }
        }
        $g = self::readGnapGrant($chain[0]);
        return $g === null ? [] : $g->get('granted_access');
    }

    // ---- holders -----------------------------------------------------------------------------------------------------------

    /**
     * The holder key (b64u Ed25519) of a grant request: its client key's OKP/Ed25519 JWK, or `$override` when one is passed
     * (`$hasOverride`; an explicit null override is refused). Only the `jwsd` proof method is supported.
     */
    public static function resolveHolder(mixed $req, mixed $override = null, bool $hasOverride = false): string
    {
        $client = self::member($req, 'client');
        $declared = $client instanceof Obj ? $client->get('key') : null;
        if ($declared instanceof Obj || is_array($declared)) { // a JS array is a truthy object with no `proof` member
            $proof = $declared instanceof Obj ? $declared->get('proof') : null;
            $method = is_string($proof) ? $proof : ($proof instanceof Obj ? $proof->get('method') : null);
            if ($method !== 'jwsd') {
                throw new GnapError('unsupported client key proof method: ' . (is_string($method) ? $method : 'none') . ' (only jwsd is supported)');
            }
        }
        if ($hasOverride) {
            return self::asEd25519($override) ?? throw new GnapError('holder override is not a canonical base64url Ed25519 public key');
        }
        $jwk = $declared instanceof Obj ? $declared->get('jwk') : null;
        if ($jwk instanceof Obj && $jwk->get('kty') === 'OKP' && $jwk->get('crv') === 'Ed25519') {
            $x = self::asEd25519($jwk->get('x'));
            if ($x !== null) {
                return $x;
            }
        }
        throw new GnapError('cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override');
    }

    public static function holderJwk(string $holder): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $holder, 'use' => 'sig', 'alg' => 'EdDSA']);
    }

    private static function accessOf(mixed $req): mixed
    {
        $at = self::member($req, 'access_token');
        if ($at instanceof Obj && self::isList($at->get('access'))) {
            return $at->get('access');
        }
        throw new GnapError('grant request must carry access_token.access (single-token request)');
    }

    // ---- grant request -> capability ---------------------------------------------------------------------------------------

    /**
     * A GNAP grant request as a capability bound to the client key. Without `parent` it MINTS a root grant whose envelope
     * predicates are the requested rights; with one it DELEGATES a hop recording the (clamped) rights as a `gnap_access` caveat.
     * Options: issuerSecret (seed), issuerPublic, parent, issuerChain, clampToIssuer (default true), holder, interacted, now
     * (ms), goal, riskPolicy, agentBinding, salt.
     * @return array{grant: Obj, chain: list<mixed>, holder: string, grantedAccess: list<Obj>, droppedAccess: list<Obj>, provenance: Obj}
     */
    public static function grantRequestToCapability(mixed $req, mixed $opts): array
    {
        $holder = self::resolveHolder($req, Js::opt($opts, 'holder'), Js::has($opts, 'holder'));
        $requested = self::normalizeAccess(self::accessOf($req));
        $nowO = Js::opt($opts, 'now');
        $now = (int)floor($nowO === null ? microtime(true) * 1000 : (float)Js::num($nowO));
        $parent = Js::opt($opts, 'parent');
        $granted = $requested;
        $dropped = [];
        $issuerChain = null;
        if (Js::truthy($parent)) {
            $ic = Js::opt($opts, 'issuerChain');
            $issuerChain = $ic ?? [$parent];
            if (Js::opt($opts, 'clampToIssuer') !== false) {
                $split = self::clampAccess(self::grantedAccessOf($issuerChain), $requested);
                [$granted, $dropped] = [$split['granted'], $split['dropped']];
            }
        }
        $interact = self::member($req, 'interact');
        $digest = Pca::hashCanonical(Sign::n(Obj::of(['d' => self::REQUEST_DOMAIN, 'client_id' => $holder, 'access' => $granted, 'interact' => $interact])));
        $secret = Bytes::of(Js::opt($opts, 'issuerSecret'));
        if ($secret === null) {
            throw new GnapError("signWithSuite: 'ed25519' requires edSecret");
        }
        $key = new KeyPair($secret);
        if ($issuerChain !== null) {
            $prov = Obj::of(['type' => self::GNAP_ACCESS_CAVEAT, 'access' => $granted, 'predicates' => self::accessArrayToPredicates($granted),
                'request_digest' => $digest, 'client_id' => $holder, 'ts' => $now]);
            if (!($parent instanceof Obj)) {
                throw new GnapError('delegate: parent must be a capability');
            }
            $child = Sign::delegate($parent, $key, $holder, [Sign::n($prov)]);
            return ['grant' => $child, 'chain' => [...Js::spread($issuerChain), $child], 'holder' => $holder, 'grantedAccess' => $granted,
                'droppedAccess' => $dropped, 'provenance' => $prov];
        }
        $prov = Obj::of(['type' => self::GNAP_GRANT_CAVEAT, 'client_id' => $holder, 'granted_access' => $granted, 'request_digest' => $digest,
            'interacted' => Js::opt($opts, 'interacted') === true, 'ts' => $now]);
        $rp = Js::opt($opts, 'riskPolicy');
        $ab = Js::opt($opts, 'agentBinding');
        $goal = Js::opt($opts, 'goal');
        $salt = Js::opt($opts, 'salt');
        $minted = Sign::mintGrant($key, $holder, [
            'predicates' => Sign::n(self::accessArrayToPredicates($granted)),
            'caveats' => [Sign::n($prov)],
            'agent_binding' => $ab ?? new Obj(),
            'risk_policy' => $rp === null ? Sign::defaultRiskPolicy() : Sign::plain($rp),
        ], $goal === null ? "gnap:grant:$holder" : Js::str($goal), $salt === null ? null : Js::str($salt));
        return ['grant' => $minted['grant'], 'chain' => [$minted['grant']], 'holder' => $holder, 'grantedAccess' => $granted, 'droppedAccess' => [], 'provenance' => $prov];
    }

    // ---- action authorization ---------------------------------------------------------------------------------------------

    /**
     * May `action` ({verb, resource, params?, reversibility_class?}) run under this GNAP-issued chain? The chain must verify, the
     * root envelope must permit it, and every recorded `gnap_access` hop must permit it too. Options: expectedRootIssuer, pqPins.
     * @return array{allowed: bool, reason?: string}
     */
    public static function authorizeGnapAction(mixed $chain, mixed $action, mixed $opts = null): array
    {
        if (!self::isList($chain) || $chain === []) {
            return ['allowed' => false, 'reason' => 'empty chain'];
        }
        [$why, $ok] = Pca::verifyChain($chain, Js::opt($opts, 'expectedRootIssuer'), Js::has($opts, 'expectedRootIssuer'), null, Js::opt($opts, 'pqPins'));
        if (!$ok) {
            return ['allowed' => false, 'reason' => 'capability chain invalid: ' . ($why === '' ? 'unknown' : $why)];
        }
        $env = Authorize::readEnvelope($chain[0]);
        if ($env === null) {
            return ['allowed' => false, 'reason' => 'root grant carries no policy envelope'];
        }
        $a = Obj::of(['verb' => self::member($action, 'verb'), 'resource' => self::member($action, 'resource')]);
        foreach (['params', 'reversibility_class'] as $k) {
            if (Js::has($action, $k)) {
                $a->set($k, Js::opt($action, $k));
            }
        }
        $ctx = Obj::of(['action' => $a]);
        $root = Predicates::evaluatePredicates($env->get('predicates'), $ctx);
        if ($root['allowed'] !== true) {
            return ['allowed' => false, 'reason' => 'root authority denies: ' . ($root['reason'] ?? 'no predicate matched')];
        }
        $leaf = $chain[count($chain) - 1];
        $cs = self::member($leaf, 'caveats');
        foreach (self::isList($cs) ? $cs : [] as $cv) {
            if (!($cv instanceof Obj) || $cv->get('type') !== self::GNAP_ACCESS_CAVEAT) {
                continue;
            }
            $hop = Predicates::evaluatePredicates(Sign::n(self::accessArrayToPredicates(self::readAccessArray($cv->get('access')))), $ctx);
            if ($hop['allowed'] !== true) {
                return ['allowed' => false, 'reason' => 'delegated hop denies: ' . ($hop['reason'] ?? 'no predicate matched')];
            }
        }
        return ['allowed' => true];
    }

    // ---- bound tokens -----------------------------------------------------------------------------------------------------

    /** base64url(UTF-8(JSON.stringify(chain))): the access-token value carries the chain, re-verified on use. */
    public static function encodeBoundToken(mixed $chain): string
    {
        return Pca::b64u(Js::utf8(Js::stringify($chain)));
    }

    private static function isCapabilityShape(mixed $x): bool
    {
        if (!($x instanceof Obj)) {
            return false;
        }
        foreach (['id', 'issuer', 'holder', 'body_digest', 'sig'] as $k) {
            if (!is_string($x->get($k))) {
                return false;
            }
        }
        if (!self::isList($x->get('caveats'))) {
            return false;
        }
        foreach (['parent', 'alg', 'pq_pk', 'pq_sig'] as $k) {
            if ($x->has($k) && !is_string($x->get($k))) {
                return false;
            }
        }
        return true;
    }

    /** @return ?list<Obj> */
    private static function decodeBoundToken(string $value): ?array
    {
        $raw = Pca::unb64u($value);
        if ($raw === null || preg_match('//u', $raw) !== 1) {
            return null; // TextDecoder fatal: invalid UTF-8 refuses
        }
        if (str_starts_with($raw, "\xEF\xBB\xBF")) {
            $raw = substr($raw, 3); // TextDecoder strips one leading BOM
        }
        try {
            $parsed = Json::parseStrict($raw);
        } catch (\Throwable) {
            return null;
        }
        if (!self::isList($parsed)) {
            return null;
        }
        foreach ($parsed as $hop) {
            if (!self::isCapabilityShape($hop)) {
                return null;
            }
        }
        return $parsed;
    }

    /** A (verified) chain as a GNAP grant response with a bound access token. Options: expiresIn, bearer, instanceId, manageUri, continue. */
    public static function capabilityToGrantResponse(mixed $chain, mixed $opts = null): Obj
    {
        if (!self::isList($chain) || $chain === []) {
            throw new GnapError('capabilityToGrantResponse: empty chain');
        }
        $leaf = $chain[count($chain) - 1];
        $token = Obj::of(['value' => self::encodeBoundToken($chain), 'access' => self::grantedAccessOf($chain),
            'key' => Js::opt($opts, 'bearer') === true ? false : self::holderJwk(Js::str(self::member($leaf, 'holder')))]);
        if (Js::has($opts, 'expiresIn')) {
            $token->set('expires_in', Js::opt($opts, 'expiresIn'));
        }
        if (Js::has($opts, 'manageUri')) {
            $token->set('manage', Obj::of(['uri' => Js::opt($opts, 'manageUri')]));
        }
        $res = Obj::of(['access_token' => $token]);
        if (Js::has($opts, 'continue')) {
            $res->set('continue', Js::opt($opts, 'continue'));
        }
        if (Js::has($opts, 'instanceId')) {
            $res->set('instance_id', Js::opt($opts, 'instanceId'));
        }
        return $res;
    }

    /**
     * Verify a bound token back to its principal (the root issuer) and capability (the leaf). Fails closed. Options:
     * expectedRootIssuer, pqPins.
     * @return array{ok: bool, reason?: string, principal?: string, capability?: Obj, chain?: list<Obj>, access?: list<Obj>}
     */
    public static function verifyGnapToken(mixed $value, mixed $opts = null): array
    {
        if (!is_string($value) || $value === '') {
            return ['ok' => false, 'reason' => 'token value is empty'];
        }
        $chain = self::decodeBoundToken($value);
        if ($chain === null || $chain === []) {
            return ['ok' => false, 'reason' => 'token is not a decodable PCA capability chain'];
        }
        [$why, $ok] = Pca::verifyChain($chain, Js::opt($opts, 'expectedRootIssuer'), Js::has($opts, 'expectedRootIssuer'), null, Js::opt($opts, 'pqPins'));
        if (!$ok) {
            return ['ok' => false, 'reason' => 'capability chain invalid: ' . ($why === '' ? 'unknown' : $why)];
        }
        return ['ok' => true, 'principal' => $chain[0]->get('issuer'), 'capability' => $chain[count($chain) - 1], 'chain' => $chain,
            'access' => self::grantedAccessOf($chain)];
    }

    // ---- jwsd detached JWS ------------------------------------------------------------------------------------------------

    private static function athOf(string $v): string
    {
        return Pca::b64u(hash('sha256', Js::utf8($v), true));
    }

    /**
     * The jwsd JWS payload (RFC 9635 7.3.3): SHA-256 of the request content; empty for no content (`$hasBody` false). A
     * string is text (UTF-8), Bytes are the exact bytes, any other value is hashed as its strict canonical JSON.
     */
    public static function gnapContentDigest(mixed $body = null, bool $hasBody = true): string
    {
        if (!$hasBody) {
            return '';
        }
        if (is_string($body)) {
            return hash('sha256', Js::utf8($body), true);
        }
        if ($body instanceof Bytes) {
            return hash('sha256', $body->raw, true);
        }
        return hash('sha256', Json::canonicalizeNative(Js::parse(Js::stringify($body))), true); // JSON.parse(JSON.stringify(x)) first
    }

    /**
     * Sign a GNAP request with a `jwsd` detached JWS. Args: body (absent = no content; Bytes for raw bytes), key {secretKey (seed),
     * publicKey}, htm, uri, created (epoch s, default now), kid, accessTokenValue.
     * @return array{detachedJws: string, header: Obj, holder: string}
     */
    public static function signGnapRequest(mixed $args): array
    {
        $key = self::member($args, 'key');
        $pub = Bytes::of(self::member($key, 'publicKey')) ?? throw new GnapError('key.publicKey must be bytes');
        $holder = Pca::b64u($pub);
        $createdO = Js::opt($args, 'created');
        $htm = self::member($args, 'htm');
        if (!is_string($htm)) {
            throw new \TypeError('htm must be a string');
        }
        $header = Obj::of(['alg' => 'EdDSA', 'typ' => self::JWSD_TYP, 'htm' => mb_strtoupper($htm), 'uri' => self::member($args, 'uri'),
            'created' => $createdO ?? (int)floor(microtime(true))]);
        if (Js::has($args, 'kid')) {
            $header->set('kid', Js::opt($args, 'kid'));
        }
        if (Js::has($args, 'accessTokenValue')) {
            $header->set('ath', self::athOf(Js::str(Js::opt($args, 'accessTokenValue'))));
        }
        $payload = self::gnapContentDigest(Js::opt($args, 'body'), Js::has($args, 'body'));
        $secret = Bytes::of(self::member($key, 'secretKey')) ?? throw new GnapError('key.secretKey must be bytes');
        if (strlen($secret) !== 32) {
            throw new GnapError('private key of length 32 expected, got ' . strlen($secret), 'ERR_CRYPTO_INVALID_JWK');
        }
        $prot = Pca::b64u(Js::stringify($header));
        $sig = (new KeyPair($secret))->sign("$prot." . Pca::b64u($payload));
        return ['detachedJws' => "$prot.." . Pca::b64u($sig), 'header' => $header, 'holder' => $holder];
    }

    /**
     * Verify a `jwsd` proof and bind the request to `holder`. Args: detachedJws, body (absent = no content), holder, htm, uri,
     * maxAgeSec (default 300), now (epoch ms), accessTokenValue, seenProof (callable(string $proofId, $expiresSec): bool, true =
     * replayed; REQUIRED unless replayCheck is 'unchecked', else GnapError). Fails closed on any deviation.
     * @return array{ok: bool, reason?: string, holder?: string, header?: Obj}
     */
    public static function verifyGnapRequest(mixed $args): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        $seen = Js::opt($args, 'seenProof');
        $seen = is_callable($seen) ? $seen : null;
        if ($seen === null && Js::opt($args, 'replayCheck') !== 'unchecked') {
            throw new GnapError("verifyGnapRequest: supply args.seenProof (a replay store) or set args.replayCheck to 'unchecked'");
        }
        $jws = Js::opt($args, 'detachedJws');
        if (is_string($jws) && Js::len($jws) > self::MAX_DETACHED_JWS_CHARS) {
            return $fail('detached JWS exceeds the size limit');
        }
        try {
            if (!is_string($jws)) {
                throw new \TypeError('detachedJws.split is not a function');
            }
            $parts = explode('.', $jws);
            if (count($parts) !== 3) {
                return $fail('not a compact JWS (expected three dot-separated parts)');
            }
            [$prot, $mid, $sig] = $parts;
            $holder = self::asEd25519(Js::opt($args, 'holder'));
            if ($holder === null) {
                return $fail('holder is not a canonical base64url Ed25519 public key');
            }
            $payloadB64u = Pca::b64u(self::gnapContentDigest(Js::opt($args, 'body'), Js::has($args, 'body')));
            if ($mid !== '' && $mid !== $payloadB64u) {
                return $fail('not a DETACHED compact JWS');
            }
            try {
                Jose::assertCanonicalJwsSegments($prot, $sig); // canonical-spelling gate before the signature check
            } catch (\Throwable $e) {
                return $fail('non-canonical detached JWS: ' . $e->getMessage());
            }
            try {
                [, $header] = Jose::compactVerify("$prot.$payloadB64u.$sig", Pca::unb64u($holder, 32));
            } catch (\Throwable) {
                return $fail('jwsd signature does not verify under the holder key (or body was tampered)');
            }
            if ($header->get('typ') !== self::JWSD_TYP) {
                return $fail('unexpected typ (not gnap-binding-jwsd)');
            }
            if ($header->get('alg') !== 'EdDSA') {
                return $fail('unexpected alg (not EdDSA)');
            }
            $htm = $header->get('htm');
            if (!is_string($htm)) {
                return $fail('htm does not match the request method');
            }
            $want = Js::opt($args, 'htm');
            if (!is_string($want)) {
                throw new \TypeError('args.htm.toUpperCase is not a function');
            }
            if (mb_strtoupper($htm) !== mb_strtoupper($want)) {
                return $fail('htm does not match the request method');
            }
            $uri = $header->get('uri');
            if (!is_string($uri) || $uri !== Js::opt($args, 'uri')) {
                return $fail('uri does not match the request target');
            }
            $created = $header->get('created');
            $c = Js::num($created);
            if ($c === null || !is_finite($c)) {
                return $fail('missing or malformed created');
            }
            $nowO = Js::opt($args, 'now');
            $nowSec = floor(($nowO === null ? microtime(true) * 1000 : (float)Js::num($nowO)) / 1000);
            $maxAgeO = Js::opt($args, 'maxAgeSec');
            $maxAge = $maxAgeO === null ? 300.0 : Js::num($maxAgeO);
            if ($maxAge === null || !is_finite($maxAge)) {
                return $fail('jwsd proof is stale'); // a non-number or infinite bound never admits
            }
            if (!(is_finite($nowSec) && $c <= $nowSec + 60)) {
                return $fail('created is in the future');
            }
            if (!($nowSec - $c <= $maxAge)) {
                return $fail('jwsd proof is stale');
            }
            $ath = $header->get('ath');
            if (Js::has($args, 'accessTokenValue')) {
                if (!is_string($ath) || $ath !== self::athOf(Js::str(Js::opt($args, 'accessTokenValue')))) {
                    return $fail('ath does not bind the named access token');
                }
            }
            if ($seen !== null) {
                $exp = $c + $maxAge;
                try {
                    $replayed = $seen(self::athOf($jws), $exp == floor($exp) && abs($exp) < 9.0e15 ? (int)$exp : $exp) !== false;
                } catch (\Throwable) {
                    $replayed = true;
                }
                if ($replayed) {
                    return $fail('jwsd proof replayed (or the replay store failed)');
                }
            }
            $out = Obj::of(['alg' => 'EdDSA', 'typ' => self::JWSD_TYP, 'htm' => $htm, 'uri' => $uri, 'created' => $created]);
            if (is_string($header->get('kid'))) {
                $out->set('kid', $header->get('kid'));
            }
            if (is_string($ath)) {
                $out->set('ath', $ath);
            }
            return ['ok' => true, 'holder' => $holder, 'header' => $out];
        } catch (\Throwable) {
            return $fail('malformed jwsd request');
        }
    }

    // ---- continuation -> step-up ------------------------------------------------------------------------------------------

    /**
     * Does a grant request need a continuation? Yes when interaction is requested, an explicit tier > 1 is asked for, or (given
     * `issuerChain`) it asks for rights beyond the issuer's authority. Options: issuerChain, tier.
     * @return array{required: bool, reason: string, beyond: list<Obj>, tier: mixed}
     */
    public static function gnapRequestRequiresStepUp(mixed $req, mixed $opts = null): array
    {
        $beyond = [];
        $ic = Js::opt($opts, 'issuerChain');
        if (Js::truthy($ic)) {
            $g = self::grantedAccessOf($ic);
            foreach (self::normalizeAccess(self::accessOf($req)) as $r) {
                if (!self::accessWithin($g, $r)) {
                    $beyond[] = $r;
                }
            }
        }
        $interact = false;
        $iv = self::member($req, 'interact');
        if (Js::has($req, 'interact')) { // `req.interact !== undefined`: an explicit null then throws reading `start`, as in the reference
            $start = self::member($iv, 'start');
            $interact = self::isList($start) && $start !== [];
        }
        $tierO = Js::opt($opts, 'tier');
        $required = $interact || $beyond !== [] || ($tierO !== null && (float)Js::num($tierO) > 1);
        $tier = $tierO ?? ($beyond !== [] ? 3 : 2);
        $reason = !$required ? 'no step-up required'
            : ($beyond !== [] ? "requested rights exceed the issuer's authority (" . count($beyond) . ' right(s) beyond)'
                : ($interact ? 'GNAP interaction requested' : 'tier ' . Js::str($tier) . ' step-up required'));
        return ['required' => $required, 'reason' => $reason, 'beyond' => $beyond, 'tier' => $tier];
    }

    /** Begin a continuation: the `continue` handle plus the step-up it resolves through. Args: signerSet, t, tier, continueUri, continueToken, wait, reason. */
    public static function beginGnapContinuation(mixed $args): array
    {
        $cont = Obj::of(['uri' => Js::opt($args, 'continueUri'), 'access_token' => Obj::of(['value' => Js::opt($args, 'continueToken'), 'bound' => true])]);
        if (Js::has($args, 'wait')) {
            $cont->set('wait', Js::opt($args, 'wait'));
        }
        $tier = Js::opt($args, 'tier');
        return ['response' => Obj::of(['continue' => $cont]), 'stepUp' => Obj::of(['tier' => $tier, 't' => Js::opt($args, 't'), 'signerSet' => Js::opt($args, 'signerSet'),
            'reason' => Js::opt($args, 'reason') ?? 'tier ' . Js::str($tier) . ' co-signature required to continue', 'continueToken' => Js::opt($args, 'continueToken')])];
    }

    /** t exactly 1, 2 or 3 (a JSON integer). */
    private static function validT(mixed $t): ?int
    {
        $f = Js::num($t);
        return $f !== null && in_array($f, [1.0, 2.0, 3.0], true) ? (int)$f : null;
    }

    /** The reference signerSetHash: sha256(domain || canonical(sorted [{publicKey, role, pq_pk?}])), a non-list is the empty set. */
    private static function signerSetHash(mixed $set): string
    {
        $rows = [];
        foreach (self::isList($set) ? $set : [] as $s) {
            $str = static fn(string $k): string => Js::has($s, $k) ? Js::str(Js::opt($s, $k)) : 'undefined'; // String(s?.k)
            $pk = Js::opt($s, 'pq_pk');
            $rows[] = [$str('role'), $str('publicKey'), is_string($pk) ? $pk : null];
        }
        usort($rows, static fn(array $a, array $b): int => strcmp($a[0], $b[0]) ?: strcmp($a[1], $b[1]));
        $list = array_map(static fn(array $r): Obj => Obj::of(['publicKey' => $r[1], 'role' => $r[0]] + ($r[2] !== null ? ['pq_pk' => $r[2]] : [])), $rows);
        return hash('sha256', Pca::SIGNERSET_DOMAIN . Json::canonicalizeNative($list), true);
    }

    /** signShare: the role's share over "atlas-pca/share/<role>\0" || sha256(message) || signerSetHash || t. */
    private static function signShare(string $role, string $secret, string $message, mixed $signerSet, mixed $t): Obj
    {
        $tv = self::validT($t) ?? throw new \RangeException('shareMessage: t must be 1, 2 or 3');
        $msg = Pca::SHARE_DOMAIN_PREFIX . $role . "\0" . hash('sha256', $message, true) . self::signerSetHash($signerSet) . chr($tv);
        if (strlen($secret) !== 32) {
            throw new GnapError('private key of length 32 expected, got ' . strlen($secret));
        }
        return SignersMore::signPreparedShare($role, new KeyPair($secret), $msg);
    }

    /** One role's step-up co-signature share over the PCActn body (bound to the signer set and `t`). `$secret` is the seed. */
    public static function gnapStepUpShare(Obj $body, string $role, string $secret, mixed $signerSet, mixed $t): Obj
    {
        return self::signShare($role, $secret, Pca::thresholdMessage($body), $signerSet, $t);
    }

    /**
     * Resolve a continuation: build the PCActn (agent leaf signature), fold the agent share and every co-signature share into
     * its `threshold`, and verify `t` is reached. Args: grant, chain, plan, nodeId, params, counter, aud, now, ttlMs,
     * agentLeafSecret (seed), signerSet, t, cosignSecrets [{role, secret (seed)}].
     * @return array{pcactn: Obj, threshold: Obj, verdict: array}
     */
    public static function completeGnapContinuation(mixed $args): array
    {
        $chain = Js::opt($args, 'chain');
        if (!self::isList($chain) || $chain === []) {
            throw new GnapError('completeGnapContinuation: empty chain');
        }
        $leafSecret = Bytes::of(Js::opt($args, 'agentLeafSecret')) ?? throw new GnapError('agentLeafSecret must be bytes');
        $nowO = Js::opt($args, 'now');
        $ttlO = Js::opt($args, 'ttlMs');
        $pcactn = Sign::buildPcactn(Js::opt($args, 'grant'), $chain, Js::opt($args, 'plan'), Js::str(Js::opt($args, 'nodeId')), (int)Js::num(Js::opt($args, 'counter')),
            new KeyPair($leafSecret), Js::str(Js::opt($args, 'aud') ?? ''), Js::has($args, 'params') ? Js::opt($args, 'params') : null,
            $nowO === null ? null : (int)Js::num($nowO), null, $ttlO === null ? Sign::DEFAULT_TTL_MS : (int)Js::num($ttlO));
        $message = Pca::thresholdMessage($pcactn);
        $set = Js::opt($args, 'signerSet');
        $t = Js::opt($args, 't');
        $cos = Js::opt($args, 'cosignSecrets');
        if (!self::isList($cos)) {
            throw new \TypeError("Cannot read properties of undefined (reading 'map')");
        }
        $shares = [self::signShare('agent', $leafSecret, $message, $set, $t)];
        foreach ($cos as $c) {
            $shares[] = self::signShare(Js::str(Js::opt($c, 'role')), Bytes::of(Js::opt($c, 'secret')) ?? '', $message, $set, $t);
        }
        $threshold = Obj::of(['shares' => $shares]);
        $verdict = SignersMore::verifyThreshold($threshold, $message, $set, $t);
        $out = $pcactn->without('threshold');
        $out->set('threshold', $threshold);
        return ['pcactn' => $out, 'threshold' => $threshold, 'verdict' => $verdict];
    }

    // ---- the profile ------------------------------------------------------------------------------------------------------

    /** The machine-readable Agent-GNAP profile. */
    public static function agentGnapProfile(): array
    {
        $m = static fn(string $g, string $p, string $n): array => ['gnap' => $g, 'pca' => $p, 'note' => $n];
        return [
            'name' => 'agent-gnap',
            'version' => '1.0',
            'rfc' => 'RFC 9635',
            'summary' => 'A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is '
                . 'issued as an attenuated, key-bound PCA capability, never wider than the issuing agent.',
            'mapping' => [
                $m('access[].type', 'predicate resource namespace gnap:<type>:<location>', 'the resource family the rights live in'),
                $m('access[].actions', 'predicate.verb (list, or * for any)', 'the operations permitted'),
                $m('access[].locations', 'predicate.resource (exact or trailing-* prefix)', 'the resource targets'),
                $m('access[].datatypes / identifier', 'predicate.where on action.params.*', 'value-level constraints'),
                $m('client.key.jwk (OKP/Ed25519)', 'capability.holder (cnf-bound key)', 'the proof-of-possession key'),
                $m('grant request (no prior grant)', "mintGrant \u{2192} root capability", 'envelope predicates = requested access'),
                $m('grant request (delegated hop)', "delegate \u{2192} child capability + gnap_access caveat", 'append-only attenuation'),
                $m("access_token (\u{a7}3.2)", 'a verifiable PCA capability chain (encodeBoundToken)', 'bound, self-verifying token'),
                $m("continue (\u{a7}3.1) + interact (\u{a7}3.3)", 'PCA step-up: FROST/threshold co-signature folded into a PCActn', 'tier-2/3 escalation'),
                $m("jwsd detached JWS (\u{a7}7.3.4)", 'request proof binding the body to capability.holder', 'verified with jose'),
            ],
            'proofMethods' => ['jwsd'],
            'multiHop' => 'An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, '
                . 'recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the '
                . 'intersection of the root policy envelope and every hop; PCA caveats are conjunctive and '
                . "append-only, so no hop can widen \u{2014} \"never wider than the issuer\" holds across any depth.",
            'stepUp' => 'A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue '
                . 'handle instead of a token. The client returns with the action PCActn plus a guardian/principal '
                . 'co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or '
                . 'multi-signature) before the action is admitted.',
            'security' => [
                'Attenuation is structural and append-only: a delegated hop can only ever narrow authority.',
                'Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.',
                'All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.',
                'Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).',
                'Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant.',
            ],
        ];
    }

    // ---- interaction modes (RFC 9635 2.5, 3.3, 4, 5.1) --------------------------------------------------------------------

    private static function startName(mixed $e): ?string
    {
        if (is_string($e)) {
            return $e;
        }
        $m = ($e instanceof Obj || is_array($e)) ? Js::opt($e, 'mode') : null;
        return is_string($m) ? $m : null;
    }

    /** RFC 9635 2.5.2: absolute URI, no fragment; HTTPS, loopback http, or an application-specific scheme. */
    public static function callbackUriOk(mixed $uri): bool
    {
        if (!is_string($uri) || Js::len($uri) > 2048) {
            return false;
        }
        $u = WhatwgUrl::parse($uri);
        if ($u === null || str_contains($uri, '#')) {
            return false;
        }
        $s = $u['scheme'];
        if ($s === 'https') {
            return true;
        }
        if ($s === 'http') {
            $hostname = str_ends_with($u['host'], ']') ? $u['host'] : (string)preg_replace('/:[0-9]+\z/', '', $u['host']);
            return in_array($hostname, ['localhost', '127.0.0.1', '[::1]'], true);
        }
        return !in_array($s, ['javascript', 'data', 'file', 'blob'], true);
    }

    /** `name in HASH_METHODS` with JavaScript semantics (the key is String(name); Object.prototype names are found too). */
    private static function hashKnown(mixed $m): bool
    {
        $k = Js::str($m);
        return isset(self::HASH_METHODS[$k]) || in_array($k, self::OBJECT_PROTO, true);
    }

    /** The problems of an `interact` request (empty = valid). Unknown start modes are tolerated (the registry is open). @return list<string> */
    public static function validateInteractRequest(mixed $r): array
    {
        if (!($r instanceof Obj)) {
            return ['interact must be an object'];
        }
        $e = [];
        $start = $r->get('start');
        if (!self::isList($start) || $start === [] || count($start) > 16) {
            $e[] = 'start must be a non-empty array of modes';
        } else {
            foreach ($start as $s) {
                if (self::startName($s) === null) {
                    $e[] = 'each start entry is a mode name or an object with a mode';
                }
            }
        }
        if ($r->has('finish')) {
            $f = $r->get('finish');
            if (!($f instanceof Obj) && !self::isList($f)) {
                $e[] = 'finish must be an object';
            } else {
                $fo = $f instanceof Obj ? $f : new Obj(); // an array is an object without these members
                if (!in_array($fo->get('method'), self::FINISH_METHODS, true)) {
                    $e[] = 'finish.method must be redirect or push';
                }
                if (!self::callbackUriOk($fo->get('uri'))) {
                    $e[] = 'finish.uri must be an absolute https, loopback or app-scheme URI without a fragment';
                }
                $n = $fo->get('nonce');
                if (!is_string($n) || Js::len($n) < 8 || Js::len($n) > 256 || preg_match('/\A[\x21-\x7e]+\z/', $n) !== 1) {
                    $e[] = 'finish.nonce must be 8..256 printable ASCII characters';
                }
                if ($fo->has('hash_method') && !self::hashKnown($fo->get('hash_method'))) {
                    $e[] = 'finish.hash_method is not a supported Named Information hash';
                }
            }
        }
        return $e;
    }

    /** Node's 'ascii' string encoding: the low byte of every UTF-16 code unit. */
    private static function asciiBytes(string $s): string
    {
        $u = mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
        $out = '';
        for ($i = 1, $n = strlen($u); $i < $n; $i += 2) {
            $out .= $u[$i];
        }
        return $out;
    }

    /**
     * RFC 9635 4.2.3: base64url(HASH(clientNonce \n asNonce \n interactRef \n grantEndpoint)). `$a`: clientNonce, asNonce,
     * interactRef, grantEndpoint, hashMethod (default sha-256).
     */
    public static function interactionHash(mixed $a): string
    {
        $m = Js::opt($a, 'hashMethod') ?? 'sha-256';
        if (!self::hashKnown($m)) {
            throw new InteractionError('unsupported_hash', 'hash_method ' . Js::str($m) . ' is not supported');
        }
        $algo = self::HASH_METHODS[Js::str($m)] ?? throw new NodeTypeError('hash algorithm is not a string', 'ERR_INVALID_ARG_TYPE'); // an Object.prototype name
        $f = static fn(string $k): string => Js::has($a, $k) ? Js::str(Js::opt($a, $k)) : 'undefined';
        return Pca::b64u(hash($algo, self::asciiBytes($f('clientNonce') . "\n" . $f('asNonce') . "\n" . $f('interactRef') . "\n" . $f('grantEndpoint')), true));
    }

    /** Client side: does the callback's hash match? Constant time. */
    public static function verifyInteractionHash(mixed $received, mixed $a): bool
    {
        if (!is_string($received)) {
            return false;
        }
        return hash_equals(self::interactionHash($a), Js::utf8($received));
    }

    /** A 6..12 character user code from an alphabet without look-alikes (32 symbols: no modulo bias). */
    public static function newUserCode(mixed $len = 8): string
    {
        $n = Js::num($len);
        if ($n === null || is_nan($n) || $n < 6 || $n > 12) {
            throw new \RangeException('user code length 6..12');
        }
        $n = (int)ceil($n);
        $b = random_bytes($n);
        $s = '';
        for ($i = 0; $i < $n; $i++) {
            $s .= self::CODE_ALPHABET[ord($b[$i]) % 32];
        }
        return $s;
    }

    /** Client side: validate a finish callback; returns the interact_ref to send, or throws unknown_interaction. */
    public static function acceptFinish(mixed $cb, mixed $ctx): string
    {
        $ref = Js::opt($cb, 'interact_ref');
        $hash = Js::opt($cb, 'hash');
        if (!is_string($ref) || $ref === '' || !is_string($hash)) {
            throw new InteractionError('unknown_interaction', 'hash and interact_ref are required');
        }
        $a = Obj::of(['interactRef' => $ref]);
        foreach (['clientNonce', 'asNonce', 'grantEndpoint', 'hashMethod'] as $k) {
            if (Js::has($ctx, $k)) {
                $a->set($k, Js::opt($ctx, $k));
            }
        }
        if (!self::verifyInteractionHash($hash, $a)) {
            throw new InteractionError('unknown_interaction', 'the callback hash does not validate');
        }
        return $ref;
    }

    /** One need {verb, resource} per (action, location); a right without explicit actions and locations is refused. @return list<Obj> */
    public static function accessToNeeds(mixed $access): array
    {
        $out = [];
        foreach (Js::spread($access) as $a) {
            $type = Js::has($a, 'type') ? Js::str(Js::opt($a, 'type')) : 'undefined';
            $acts = self::member($a, 'actions');
            $locs = Js::opt($a, 'locations');
            if (!self::isList($acts) || $acts === [] || !self::isList($locs) || $locs === []) {
                throw new InteractionError('invalid_request', 'access "' . $type . '" needs explicit actions and locations to become a need');
            }
            foreach ($acts as $verb) {
                foreach ($locs as $loc) {
                    $out[] = Obj::of(['verb' => $verb, 'resource' => "gnap:$type:" . Js::str($loc)]);
                }
            }
        }
        return $out;
    }

    /** @internal the start-mode names of a request (null for an entry without one). */
    public static function startNames(array $start): array
    {
        return array_map(self::startName(...), $start);
    }

    /** @internal the redirect finish URL: `$uri` with `hash` and `interact_ref` set the URLSearchParams way. */
    public static function finishUrl(string $uri, string $hash, string $ref): string
    {
        $p = WhatwgUrl::parse($uri) ?? throw new NodeTypeError('Invalid URL', 'ERR_INVALID_URL');
        $s = (string)preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', $uri);
        $s = str_replace(["\t", "\n", "\r"], '', $s);
        $f = strpos($s, '#');
        $noFrag = $f === false ? $s : substr($s, 0, $f);
        $q = strpos($noFrag, '?');
        $query = $q === false ? '' : substr($noFrag, $q + 1);
        $pairs = [];
        foreach ($query === '' ? [] : explode('&', $query) as $seg) {
            if ($seg === '') {
                continue;
            }
            $e = strpos($seg, '=');
            [$k, $v] = $e === false ? [$seg, ''] : [substr($seg, 0, $e), substr($seg, $e + 1)];
            $pairs[] = [urldecode($k), urldecode($v)];
        }
        foreach (['hash' => $hash, 'interact_ref' => $ref] as $name => $value) {
            $at = null;
            foreach ($pairs as $i => $pr) {
                if ($pr[0] === $name) {
                    if ($at === null) {
                        $at = $i;
                        $pairs[$i][1] = $value;
                    } else {
                        unset($pairs[$i]);
                    }
                }
            }
            $pairs = array_values($pairs);
            if ($at === null) {
                $pairs[] = [$name, $value];
            }
        }
        $scheme = $p['scheme'];
        $afterScheme = substr($noFrag, strlen($scheme) + 1);
        // shortcut: userinfo (user:pw@) is dropped from the serialized URL; callback URIs carrying credentials are not supported
        $base = isset($p['origin']) ? $p['origin'] . $p['pathname'] : (str_starts_with($afterScheme, '//') ? $p['htu'] : "$scheme:" . $p['pathname']);
        return $base . '?' . CibaClient::form($pairs);
    }
}

/** One GNAP interaction (AS side). */
final class Interaction implements \JsonSerializable
{
    public string $state = 'pending';
    public ?string $userCode = null;
    /** @var ?array{method: string, uri: string, clientNonce: string, asNonce: string, hashMethod: mixed} */
    public ?array $finish = null;
    public ?string $interactRef = null;
    public bool $refUsed = false;

    /** @param list<string> $modes */
    public function __construct(public readonly string $id, public readonly string $grantEndpoint, public readonly array $modes, public readonly float|int $expiresAt)
    {
    }

    public function jsonSerialize(): array
    {
        $o = ['id' => $this->id, 'state' => $this->state, 'grantEndpoint' => $this->grantEndpoint, 'modes' => $this->modes, 'refUsed' => $this->refUsed, 'expiresAt' => $this->expiresAt];
        if ($this->userCode !== null) {
            $o['userCode'] = $this->userCode;
        }
        if ($this->finish !== null) {
            $o['finish'] = $this->finish;
        }
        if ($this->interactRef !== null) {
            $o['interactRef'] = $this->interactRef;
        }
        return $o;
    }
}

/**
 * The authorization-server side of GNAP interaction: a response never includes a mode the client did not ask for nor one the
 * AS does not support, and each interaction's `interact_ref` is single use (a second presentation is `too_many_attempts` and
 * finalizes the grant). Options: grantEndpoint, supports (modes), redirectUri (callable id => uri), appUri (callable), userCodeUri,
 * ttlSec (default 600), now (callable => epoch s).
 */
final class InteractionServer
{
    /** @var array<string, Interaction> */
    private array $byId = [];
    /** @var array<string, string> */
    private array $byCode = [];
    /** @var array<string, string> */
    private array $byRef = [];

    public function __construct(private readonly array $o)
    {
    }

    private function now(): float|int
    {
        return ($this->o['now'])();
    }

    /** @return array{interaction: Interaction, response: array} */
    public function start(mixed $req): array
    {
        $problems = Gnap::validateInteractRequest($req);
        if ($problems !== []) {
            throw new InteractionError('invalid_request', implode('; ', $problems));
        }
        /** @var Obj $req */
        $asked = Gnap::startNames($req->get('start'));
        $app = $this->o['appUri'] ?? null;
        $ucu = $this->o['userCodeUri'] ?? null;
        $modes = array_values(array_filter($this->o['supports'], static fn(string $m): bool => in_array($m, $asked, true)
            && ($m !== 'app' || $app !== null) && ($m !== 'user_code_uri' || Js::truthy($ucu))));
        $finish = $req->has('finish') ? $req->get('finish') : null;
        if ($modes === [] && !Js::truthy($finish)) {
            throw new InteractionError('invalid_interaction', 'no requested interaction mode is supported');
        }
        $id = Pca::b64u(random_bytes(16));
        $ttl = $this->o['ttlSec'] ?? 600;
        $it = new Interaction($id, $this->o['grantEndpoint'], $modes, $this->now() + $ttl);
        $res = ['expires_in' => $ttl];
        if (in_array('redirect', $modes, true)) {
            $res['redirect'] = ($this->o['redirectUri'])($id);
        }
        if (in_array('app', $modes, true)) {
            $res['app'] = $app($id);
        }
        if (in_array('user_code', $modes, true) || in_array('user_code_uri', $modes, true)) {
            $it->userCode = Gnap::newUserCode();
            $this->byCode[$it->userCode] = $id;
            if (in_array('user_code', $modes, true)) {
                $res['user_code'] = $it->userCode;
            }
            if (in_array('user_code_uri', $modes, true)) {
                $res['user_code_uri'] = ['code' => $it->userCode, 'uri' => $ucu];
            }
        }
        if (Js::truthy($finish)) {
            $asNonce = Pca::b64u(random_bytes(24));
            $it->finish = ['method' => $finish->get('method'), 'uri' => $finish->get('uri'), 'clientNonce' => $finish->get('nonce'), 'asNonce' => $asNonce,
                'hashMethod' => $finish->get('hash_method') ?? 'sha-256'];
            $res['finish'] = $asNonce;
        }
        $this->byId[$id] = $it;
        return ['interaction' => $it, 'response' => $res];
    }

    /** The resource owner typed a code (case-insensitive; spaces and hyphens ignored). The caller MUST rate-limit this lookup. */
    public function lookupUserCode(string $code): ?Interaction
    {
        $id = $this->byCode[strtoupper((string)preg_replace('/[\s-]/u', '', $code))] ?? null;
        $it = $id !== null ? ($this->byId[$id] ?? null) : null;
        if ($it === null || $it->state !== 'pending' || $this->now() > $it->expiresAt) {
            return null;
        }
        return $it;
    }

    public function get(string $id): ?Interaction
    {
        return $this->byId[$id] ?? null;
    }

    /** The resource owner approved: returns {interactRef, finish?} (a redirect URL or a push body). */
    public function approve(string $id): array
    {
        $it = $this->live($id);
        if ($it->state !== 'pending') {
            throw new InteractionError('wrong_state', "interaction is {$it->state}");
        }
        $it->state = 'approved';
        $it->interactRef = Pca::b64u(random_bytes(18));
        $this->byRef[$it->interactRef] = $id;
        if ($it->userCode !== null) {
            unset($this->byCode[$it->userCode]);
        }
        if ($it->finish === null) {
            return ['interactRef' => $it->interactRef];
        }
        $f = $it->finish;
        $hash = Gnap::interactionHash(['clientNonce' => $f['clientNonce'], 'asNonce' => $f['asNonce'], 'interactRef' => $it->interactRef,
            'grantEndpoint' => $it->grantEndpoint, 'hashMethod' => $f['hashMethod']]);
        if ($f['method'] === 'push') {
            return ['interactRef' => $it->interactRef, 'finish' => ['method' => 'push', 'uri' => $f['uri'], 'body' => ['hash' => $hash, 'interact_ref' => $it->interactRef]]];
        }
        return ['interactRef' => $it->interactRef, 'finish' => ['method' => 'redirect', 'url' => Gnap::finishUrl($f['uri'], $hash, $it->interactRef)]];
    }

    /** Continuation (RFC 9635 5.1): present the interact_ref once; a replay finalizes the grant and is too_many_attempts. */
    public function consume(string $interactRef): Interaction
    {
        $id = $this->byRef[$interactRef] ?? null;
        $it = $id !== null ? ($this->byId[$id] ?? null) : null;
        if ($it === null) {
            throw new InteractionError('unknown_interaction', 'no such interaction reference');
        }
        if ($it->refUsed || $it->state === 'finalized') {
            $it->state = 'finalized';
            throw new InteractionError('too_many_attempts', 'the interaction reference was already used');
        }
        if ($this->now() > $it->expiresAt) {
            throw new InteractionError('expired', 'the interaction expired');
        }
        if ($it->state !== 'approved') {
            throw new InteractionError('wrong_state', "interaction is {$it->state}");
        }
        $it->refUsed = true;
        return $it;
    }

    public function finalize(string $id): void
    {
        if (isset($this->byId[$id])) {
            $this->byId[$id]->state = 'finalized';
        }
    }

    private function live(string $id): Interaction
    {
        $it = $this->byId[$id] ?? throw new InteractionError('unknown_interaction', 'no such interaction');
        if ($this->now() > $it->expiresAt) {
            throw new InteractionError('expired', 'the interaction expired');
        }
        return $it;
    }
}
