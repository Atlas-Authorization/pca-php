<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Execution.php';
require_once __DIR__ . '/AnalyzerNarrowing.php';

/** What presentedProvenance returns when the request presents no bundle (a JSON null is a presented, malformed one). */
enum GatewayAbsent
{
    case Absent;
}

/**
 * In-process single-use store. State is per process: use a shared store for more than one instance. A claim stays live through its
 * expiry inclusive. Fails closed (throws) when `$maxEntries` unexpired claims are held.
 */
final class GatewayReplayGuard
{
    /** @var array<string,float> */
    private array $seen = [];
    private \Closure $now;

    /** @param ?\Closure(): mixed $now the clock in milliseconds (a Num / int / float) */
    public function __construct(private readonly int $maxEntries = 100000, ?\Closure $now = null)
    {
        $this->now = $now ?? static fn() => (int)floor((Gateway::$clockHook !== null ? (Gateway::$clockHook)() : microtime(true)) * 1000);
    }

    /** True for the first claim of `$key`; false while an earlier claim is live. */
    public function claim(string $key, mixed $expiresAtMs, mixed $nowMs = null): bool
    {
        $t = Js::num($nowMs ?? ($this->now)()) ?? NAN;
        $exp = Js::num($expiresAtMs) ?? NAN;
        // a clock or expiry that is not finite cannot say whether a claim is still live: refuse
        if (!is_finite($t) || !is_finite($exp)) {
            throw new \RuntimeException('replay guard: the clock and the claim expiry must be finite numbers');
        }
        if (count($this->seen) >= $this->maxEntries) {
            foreach ($this->seen as $k => $exp) {
                if ($exp < $t) {
                    unset($this->seen[$k]);
                }
            }
            if (count($this->seen) >= $this->maxEntries) {
                throw new \RuntimeException('replay guard full');
            }
        }
        if (array_key_exists($key, $this->seen) && !($this->seen[$key] < $t)) {
            return false;
        }
        $this->seen[$key] = $exp;
        return true;
    }
}

/** The gateway's per-session record of untrusted content it relayed: at most `$maxSessions` sessions (oldest dropped first), 256 observations each. */
final class GatewayProvenanceLog
{
    /** @var array<string|int,list<Obj>> */
    private array $m = [];

    public function __construct(private readonly int $maxSessions = 10000)
    {
    }

    /** @return list<Obj> */
    public function seen(string $session): array
    {
        $out = [];
        foreach ($this->m[$session] ?? [] as $x) {
            $out[] = self::copy($x);
        }
        return $out;
    }

    public function add(string $session, mixed $o): void
    {
        $cur = $this->m[$session] ?? [];
        unset($this->m[$session]);
        $origin = Js::has($o, 'origin') ? Js::opt($o, 'origin') : GatewayAbsent::Absent;
        $source = Js::has($o, 'source') ? Js::opt($o, 'source') : GatewayAbsent::Absent;
        $dup = false;
        foreach ($cur as $x) {
            if (self::same($x->has('origin') ? $x->get('origin') : GatewayAbsent::Absent, $origin)
                && self::same($x->has('source') ? $x->get('source') : GatewayAbsent::Absent, $source)) {
                $dup = true;
                break;
            }
        }
        if (!$dup && count($cur) < 256) {
            $e = new Obj();
            if ($origin !== GatewayAbsent::Absent) {
                $e->set('origin', $origin);
            }
            if ($source !== GatewayAbsent::Absent) {
                $e->set('source', $source);
            }
            $cur[] = $e;
        }
        $this->m[$session] = $cur;
        while (count($this->m) > $this->maxSessions) {
            unset($this->m[array_key_first($this->m)]);
        }
    }

    private static function copy(Obj $o): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $o->get($k));
        }
        return $c;
    }

    /** JavaScript `===` over JSON values (objects and arrays by identity, no bool / number mixing). */
    private static function same(mixed $a, mixed $b): bool
    {
        if ($a instanceof GatewayAbsent || $b instanceof GatewayAbsent) {
            return $a === $b;
        }
        if ($a instanceof Obj || $b instanceof Obj) {
            return $a === $b;
        }
        if (is_array($a) || is_array($b)) {
            return false; // a list is its own identity; two reads never share one
        }
        if (is_bool($a) || is_bool($b)) {
            return is_bool($a) && is_bool($b) && $a === $b;
        }
        if (Js::isNum($a) || Js::isNum($b)) {
            return Js::isNum($a) && Js::isNum($b) && Js::num($a) == Js::num($b);
        }
        return $a === $b;
    }
}

/**
 * The decision logic of a deny-by-default Proof-Carrying Authority enforcement point, as pure functions over request values (the
 * reference's pca-gateway).
 *
 * A request is {method, path, query?, authority?, bodySha256?, body?, headers} (an Obj or an assoc array). The proof travels as the
 * `PCA-Action` header; the gateway's own audience and a route -> capability map are configured once. Every step denies by default.
 * The Envoy HTTP and gRPC ext_authz shapes and the AWS Lambda authorizers are plain functions over event values; `gatewayProxy` joins
 * a gateway to an injected upstream closure. `cloudflareWorker` is the runtime-free core of the Worker adapter (the request, `next` and
 * `respond` are injected; no Workers runtime is involved).
 *
 * Options (an assoc array keyed by the reference's names, or an Obj): audience, routes, resolveGrant (closure (ref, pcactn) -> grant|null),
 * authorizedPlanRoots, insecureSkipPlanRootCheck, unmatchedRoute, replayGuard (object with claim(key, expMs, nowMs)), bindRequest
 * (null | false | {authority?, body?}), hooks {revocation: closure (ctx) -> {enforced, ok?, reason?}}, enforce {freshness?: array},
 * requireChecks, checkProof (closure (ctx) -> bool | {allow, reason?}), pathPolicy, now (closure -> ms), realm, policy.
 *
 * Not supported (refused at construction, never silently ignored): full policy mode (the grant limits / state store / budget pipeline),
 * hooks other than `revocation`, the attestation and taint enforcement gates. A decision is an assoc array
 * {allow, status, code, reason, headers: Obj, verdict?, pcactn?, matched?}.
 */
final class Gateway
{
    public const PCA_HEADER = 'PCA-Action';
    public const PCA_INJECTED_HEADERS = ['x-pca-verdict', 'x-pca-verb', 'x-pca-grant'];
    public const DEFAULT_REQUIRE_CHECKS = ['revocation'];
    public const ABSENT = GatewayAbsent::Absent;

    public const GRPC_OK = 0;
    public const GRPC_UNAUTHENTICATED = 16;
    public const GRPC_PERMISSION_DENIED = 7;
    public const GRPC_UNAVAILABLE = 14;
    public const OVERWRITE_IF_EXISTS_OR_ADD = 2;

    private const ERROR_TOKEN = [
        'no-proof' => 'missing_proof', 'invalid-proof' => 'invalid_proof', 'unknown-grant' => 'invalid_proof',
        'verify-failed' => 'invalid_proof', 'wrong-audience' => 'invalid_resource', 'insufficient-capability' => 'insufficient_capability',
        'unmapped-route' => 'access_denied', 'invalid-path' => 'invalid_request', 'replayed-proof' => 'replayed_proof',
        'replay-guard-unavailable' => 'temporarily_unavailable', 'request-mismatch' => 'proof_not_bound_to_request',
        'proof-rejected' => 'access_denied',
    ];

    // ---- small helpers -------------------------------------------------------------------------------------------------------

    /** The (key, value) members of an Obj (JS own-key order) or an assoc array; nothing for any other value. @return list<array{0:string,1:mixed}> */
    private static function entries(mixed $o): array
    {
        $r = [];
        if ($o instanceof Obj) {
            foreach (Js::ownKeys($o->keys()) as $k) {
                $r[] = [$k, $o->get($k)];
            }
        } elseif (is_array($o) && !array_is_list($o)) {
            foreach ($o as $k => $v) {
                $r[] = [(string)$k, $v];
            }
        }
        return $r;
    }

    private static function first(mixed ...$vs): mixed
    {
        foreach ($vs as $v) {
            if ($v !== null) {
                return $v;
            }
        }
        return null;
    }

    private static function str(mixed $v, string $what): string
    {
        if (!is_string($v)) {
            throw new \TypeError("$what is not a string");
        }
        return $v;
    }

    private static function ms(mixed $v): int
    {
        $f = Js::num($v);
        if ($f === null || !is_finite($f)) {
            throw new \TypeError('the clock did not return a number');
        }
        return (int)floor($f);
    }

    private static function upper(string $s): string
    {
        return mb_strtoupper($s, 'UTF-8');
    }

    private static function lower(string $s): string
    {
        return mb_strtolower($s, 'UTF-8');
    }

    // ---- canonical query / binding -------------------------------------------------------------------------------------------

    /** JavaScript decodeURIComponent: a '%' without two hex digits, or bytes that are not UTF-8, throw. */
    private static function decodeUriComponent(string $s): string
    {
        if (preg_match('/%(?![0-9a-fA-F]{2})/', $s) === 1) {
            throw new \InvalidArgumentException('URI malformed');
        }
        $r = preg_replace_callback('/(?:%[0-9a-fA-F]{2})+/', static function (array $m): string {
            preg_match_all('/%([0-9a-fA-F]{2})/', $m[0], $h);
            $bytes = '';
            foreach ($h[1] as $x) {
                $bytes .= chr((int)hexdec($x));
            }
            if (preg_match('//u', $bytes) !== 1) {
                throw new \InvalidArgumentException('URI malformed');
            }
            return $bytes;
        }, $s);
        return $r ?? throw new \InvalidArgumentException('URI malformed');
    }

    /**
     * Strip a leading '?', drop empty pairs, sort the raw pairs (UTF-16 code unit order) and join with '&'. Throws on a query that is
     * ambiguous across upstream parsers: a repeated parameter name (percent-decoded, '+' as space, case-insensitive), a ';' separator, or a
     * malformed percent escape in a name (the gateway turns it into a request-mismatch deny). A null query is the empty query.
     */
    public static function canonicalQuery(?string $query): string
    {
        if ($query === null) {
            return '';
        }
        $q = str_starts_with($query, '?') ? substr($query, 1) : $query;
        if (str_contains($q, ';')) {
            throw new \InvalidArgumentException("query contains ';' (parsers disagree on it as a separator)");
        }
        $pairs = array_values(array_filter(explode('&', $q), static fn(string $x): bool => $x !== ''));
        $seen = [];
        foreach ($pairs as $pair) {
            $eq = strpos($pair, '=');
            $rawKey = $eq === false ? $pair : substr($pair, 0, $eq);
            try {
                $key = self::lower(self::decodeUriComponent(str_replace('+', ' ', $rawKey)));
            } catch (\InvalidArgumentException) {
                throw new \InvalidArgumentException('query parameter name has a malformed percent escape');
            }
            if (isset($seen[$key])) {
                throw new \InvalidArgumentException("duplicate query parameter '$key'");
            }
            $seen[$key] = true;
        }
        $u16 = static fn(string $s): string => (string)mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
        usort($pairs, static fn(string $a, string $b): int => strcmp($u16($a), $u16($b)));
        return implode('&', $pairs);
    }

    /**
     * The canonical binding of a request an agent signs as its action params: upper-cased method, path, canonical query and optionally the
     * authority and body hash. `$opts` {authority?, body?}: body true binds the hash, an explicit other value does not, absent binds it when supplied.
     */
    public static function requestBinding(mixed $req, mixed $opts = null): Obj
    {
        $sha = Js::opt($req, 'bodySha256');
        $b = new Obj();
        $b->set('v', new Num('2'));
        $b->set('method', self::upper(self::str(Js::opt($req, 'method'), 'method')));
        $b->set('path', self::str(Js::opt($req, 'path'), 'path'));
        $b->set('query', self::canonicalQuery(Js::opt($req, 'query')));
        if (Js::truthy(Js::opt($opts, 'authority'))) {
            $a = Js::opt($req, 'authority');
            $b->set('authority', self::lower(self::str(Js::truthy($a) ? $a : '', 'authority')));
        }
        $hasBody = Js::has($opts, 'body');
        if (Js::opt($opts, 'body') === true || (!$hasBody && $sha !== null)) {
            $b->set('body_sha256', self::lower(self::str($sha ?? '', 'bodySha256')));
        }
        return $b;
    }

    /** The params an agent signs for a request binding: the params plus the binding as a `binding` member (params unchanged when there is none). */
    public static function bindParams(mixed $params, mixed $binding = null): mixed
    {
        if ($binding === null) {
            return $params;
        }
        if (Js::has($params, 'binding')) {
            throw new \InvalidArgumentException("params already have a 'binding' member");
        }
        $o = new Obj();
        foreach (self::entries($params) as [$k, $v]) {
            $o->set($k, $v);
        }
        $o->set('binding', $binding);
        return $o;
    }

    /** Why `$path` is ambiguous for route matching (the upstream may route a different path), or null when canonical. */
    public static function ambiguousPathReason(string $path): ?string
    {
        if (preg_match('/[\x00-\x1f\x7f\\\\]/', $path) === 1) {
            return 'control character or backslash in path';
        }
        if (str_contains($path, '//')) {
            return 'repeated slash in path';
        }
        if (str_contains($path, ';')) {
            return 'path parameter (;) in path';
        }
        foreach (explode('/', $path) as $seg) {
            if ($seg === '.' || $seg === '..') {
                return 'dot segment in path';
            }
        }
        if (preg_match_all('/%([0-9a-fA-F]{2})/', $path, $m) > 0) {
            foreach ($m[1] as $hx) {
                $code = (int)hexdec($hx);
                $ch = chr($code);
                if ($code < 0x20 || $code === 0x7F) {
                    return 'percent-encoded control character in path';
                }
                if ($ch === '/' || $ch === '\\') {
                    return 'percent-encoded slash in path';
                }
                if ($ch === ';') {
                    return 'percent-encoded path parameter delimiter in path';
                }
                if ($code < 0x80 && preg_match('/\A[A-Za-z0-9\-._~]\z/', $ch) === 1) {
                    return 'non-canonical percent-encoding in path';
                }
            }
        }
        if (preg_match('/%(?![0-9a-fA-F]{2})/', $path) === 1) {
            return 'malformed percent-encoding in path';
        }
        return null;
    }

    // ---- replay guard / provenance log ---------------------------------------------------------------------------------------

    public static function memoryReplayGuard(int $maxEntries = 100000, ?\Closure $now = null): GatewayReplayGuard
    {
        return new GatewayReplayGuard($maxEntries, $now);
    }

    public static function memoryProvenanceLog(int $maxSessions = 10000): GatewayProvenanceLog
    {
        return new GatewayProvenanceLog($maxSessions);
    }

    // ---- headers / extraction ------------------------------------------------------------------------------------------------

    /** Case-insensitive single-value lookup over a header map: the first key that matches; a list reads as its first element. */
    public static function getHeader(mixed $headers, string $name): mixed
    {
        $lower = self::lower($name);
        foreach (self::entries($headers) as [$key, $v]) {
            if (self::lower($key) !== $lower) {
                continue;
            }
            if (is_array($v) && array_is_list($v)) {
                return $v[0] ?? null;
            }
            return $v;
        }
        return null;
    }

    /** `PCA-Action` header value -> the PCActn JSON text (strict unpadded base64url, valid UTF-8); throws with the reference's messages. */
    private static function decodeHeader(mixed $value): string
    {
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException('PCA-Action header is empty');
        }
        $raw = Pca::unb64u($value);
        if ($raw === null) {
            throw new \InvalidArgumentException('PCA-Action header is not strict unpadded base64url');
        }
        if (preg_match('//u', $raw) !== 1) {
            throw new \InvalidArgumentException('PCA-Action header does not decode to UTF-8 text');
        }
        return $raw;
    }

    /** @return array{pcactn?:Obj,code?:string,reason?:string} */
    private static function extractPcactn(mixed $headers): array
    {
        $raw = self::getHeader($headers, self::PCA_HEADER);
        if ($raw === null || $raw === '') {
            return ['code' => 'no-proof', 'reason' => 'no ' . self::PCA_HEADER . ' header'];
        }
        try {
            return ['pcactn' => Pca::decodePcactn(self::decodeHeader($raw))];
        } catch (\Throwable $e) { // undecodable is a deny
            return ['code' => 'invalid-proof', 'reason' => 'undecodable ' . self::PCA_HEADER . ' header: ' . $e->getMessage()];
        }
    }

    private static function bodyObject(mixed $req): ?Obj
    {
        $body = Js::opt($req, 'body');
        if (is_string($body) && $body !== '') {
            try {
                $b = Json::parseStrict($body);
            } catch (\Throwable) { // not JSON: no body form
                return null;
            }
            return $b instanceof Obj ? $b : null;
        }
        return null;
    }

    private static function paramsIsFn(mixed $policy): bool
    {
        return Js::opt($policy, 'params') instanceof \Closure;
    }

    /**
     * The provenance bundle a request presents: header `PCA-Provenance` (strict base64url JSON), else body member `pca_provenance` when
     * the body is not the signed params. {@see ABSENT} when none; null when presented but unreadable.
     */
    public static function presentedProvenance(mixed $req, mixed $policy): mixed
    {
        try {
            $h = self::getHeader(Js::opt($req, 'headers'), 'pca-provenance');
            if ($h !== null && $h !== '') {
                return Json::parseStrict(self::decodeHeader($h));
            }
        } catch (\Throwable) { // presented but malformed: the gate denies it
            return null;
        }
        if (self::paramsIsFn($policy)) {
            $b = self::bodyObject($req);
            if ($b !== null && $b->has('pca_provenance')) {
                return $b->get('pca_provenance');
            }
        }
        return self::ABSENT;
    }

    /** The discharges and narrow block a request presents (headers, then body members when the body is not the signed params). */
    public static function presentedArtifacts(mixed $req, mixed $policy): Obj
    {
        $out = new Obj();
        $headers = Js::opt($req, 'headers');
        try {
            $d = self::getHeader($headers, 'pca-discharges');
            if ($d !== null && $d !== '') {
                $arr = Json::parseStrict(self::decodeHeader($d));
                if (is_array($arr) && array_is_list($arr)) {
                    $out->set('discharges', $arr);
                }
            }
        } catch (\Throwable) { // unreadable: no discharges
        }
        try {
            $n = self::getHeader($headers, 'pca-narrow');
            if ($n !== null && $n !== '') {
                $out->set('narrow', Json::parseStrict(self::decodeHeader($n)));
            }
        } catch (\Throwable) { // unreadable: no narrow block
        }
        if (self::paramsIsFn($policy)) {
            $b = self::bodyObject($req);
            if ($b !== null) {
                $pd = $b->get('pca_discharges');
                if (!$out->has('discharges') && is_array($pd) && array_is_list($pd)) {
                    $out->set('discharges', $pd);
                }
                if (!$out->has('narrow') && $b->has('pca_narrow')) {
                    $out->set('narrow', $b->get('pca_narrow'));
                }
            }
        }
        return $out;
    }

    // ---- routes / decisions --------------------------------------------------------------------------------------------------

    private static function matchMethod(mixed $rule, string $method): bool
    {
        $m = Js::opt($rule, 'method');
        if ($m === null || $m === '*' || self::upper($m) === 'ANY') {
            return true;
        }
        return self::upper($m) === self::upper($method);
    }

    private static function matchPath(string $pattern, string $path): bool
    {
        if ($pattern === '*' || $pattern === '/*') {
            return true;
        }
        if (str_ends_with($pattern, '/*')) {
            $prefix = substr($pattern, 0, -2);
            return $path === $prefix || str_starts_with($path, $prefix . '/');
        }
        if (str_ends_with($pattern, '*')) {
            return str_starts_with($path, substr($pattern, 0, -1));
        }
        return $path === $pattern;
    }

    private static function matchRoute(mixed $routes, string $method, string $path): mixed
    {
        foreach (is_array($routes) ? $routes : [] as $r) {
            if (self::matchMethod($r, $method) && self::matchPath(self::str(Js::opt($r, 'path'), 'route path'), $path)) {
                return $r;
            }
        }
        return null;
    }

    /** @param array<string,mixed> $extra @return array<string,mixed> */
    private static function deny(string $code, int $status, string $reason, string $realm, array $extra = []): array
    {
        return array_merge([
            'allow' => false, 'status' => $status, 'code' => $code, 'reason' => $reason,
            'headers' => Obj::of(['www-authenticate' => 'PCA realm="' . $realm . '", error="' . self::ERROR_TOKEN[$code] . '"']),
        ], array_filter($extra, static fn($x): bool => $x !== null));
    }

    /** @param array<string,mixed> $extra @return array<string,mixed> */
    private static function allow(string $reason, array $extra = []): array
    {
        $extra = array_filter($extra, static fn($x): bool => $x !== null);
        $headers = new Obj();
        if (isset($extra['verdict'])) {
            $headers->set('x-pca-verdict', Js::stringify($extra['verdict']));
        }
        if (isset($extra['pcactn'])) {
            $headers->set('x-pca-verb', $extra['pcactn']->get('action')->get('verb'));
            $headers->set('x-pca-grant', $extra['pcactn']->get('grant_ref'));
        }
        return array_merge(['allow' => true, 'status' => 200, 'code' => 'allow', 'reason' => $reason, 'headers' => $headers], $extra);
    }

    private static function policyMode(mixed $opts): mixed
    {
        return Js::opt(Js::opt($opts, 'policy'), 'mode');
    }

    /** @param list<string> $missing */
    private static function missingText(mixed $opts, array $missing): string
    {
        $mode = self::policyMode($opts);
        return ($mode === null || $mode === 'signature-only' ? 'the gateway' : 'full policy mode') . ' is missing ' . implode(', ', $missing);
    }

    /** @return list<string> */
    private static function missingPolicy(mixed $opts): array
    {
        $p = Js::opt($opts, 'policy');
        if ($p === null) {
            return ["policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })"];
        }
        $mode = Js::opt($p, 'mode');
        if ($mode === 'signature-only') {
            $m = [];
            if (Js::opt($opts, 'replayGuard') === null) {
                $m[] = 'replayGuard (signature-only mode needs a single-use guard)';
            }
            $rc = Js::opt($opts, 'requireChecks');
            $rc = is_array($rc) ? $rc : self::DEFAULT_REQUIRE_CHECKS;
            if (in_array('revocation', $rc, true) && !(Js::opt(Js::opt($opts, 'hooks'), 'revocation') instanceof \Closure)) {
                $m[] = "hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)";
            }
            return $m;
        }
        if ($mode !== 'full') {
            return ["a known policy mode (got '" . (Js::has($p, 'mode') ? Js::str($mode) : 'undefined') . "')"];
        }
        $missing = [];
        $aud = Js::opt($opts, 'audience');
        if (!is_string($aud) || $aud === '') {
            $missing[] = 'audience';
        }
        if (!(Js::opt($opts, 'resolveGrant') instanceof \Closure)) {
            $missing[] = 'resolveGrant';
        }
        $store = Js::opt($p, 'state');
        $hasClaim = is_object($store) && method_exists($store, 'claim');
        if (!$hasClaim) {
            $missing[] = 'state';
        }
        if (!(Js::opt($p, 'isRevoked') instanceof \Closure)) {
            $missing[] = 'isRevoked';
        }
        if ($hasClaim && !(method_exists($store, 'budget') && method_exists($store, 'claimWithBudget'))) {
            $missing[] = 'state.claimWithBudget (the trust budget is decided and debited with the replay claim)';
        }
        $params = Js::opt($p, 'params');
        if ($params !== 'body' && !($params instanceof \Closure)) {
            $missing[] = "params ('body' or a function)";
        }
        return $missing;
    }

    // ---- core verification ---------------------------------------------------------------------------------------------------

    /** @return array{verdict:array<string,mixed>,wire:bool,aud:bool} */
    private static function verify(Obj $pcactn, mixed $grant, mixed $opts, int $now): array
    {
        $roots = Js::opt($opts, 'authorizedPlanRoots');
        $rootsArr = $roots === null ? null : (is_array($roots) ? array_values($roots) : []);
        $skip = Js::opt($opts, 'insecureSkipPlanRootCheck') === true;
        $fresh = Js::opt(Js::opt($opts, 'enforce'), 'freshness');
        if ($fresh !== null && !is_array($fresh)) {
            throw new \InvalidArgumentException('pca-gateway: enforce.freshness must be an array');
        }
        $aud = Js::opt($opts, 'audience');
        $v = Pca::verifyPcactnCore($pcactn, $grant, $now, is_string($aud) ? $aud : null, null, null, null, null, $rootsArr, $skip, $fresh);
        $allow = $v['allow'] === true;
        $reason = ($v['reason'] ?? '') === '' ? null : $v['reason'];
        $revocation = 'not-enforced';
        $wire = ($v['checks']['wire'] ?? false) === true;
        $hook = Js::opt(Js::opt($opts, 'hooks'), 'revocation');
        if ($hook instanceof \Closure && $wire) {
            try {
                $res = $hook(Obj::of(['pcactn' => $pcactn, 'grant' => $grant, 'nowEpoch' => new Num((string)$now)]));
                $enforced = Js::truthy(Js::opt($res, 'enforced'));
                $ok = Js::truthy(Js::opt($res, 'ok'));
                if (!$enforced) {
                    $revocation = 'not-enforced';
                } elseif ($ok) {
                    $revocation = 'pass';
                } else {
                    $revocation = 'fail';
                    if ($allow || $reason === null) {
                        $rr = Js::opt($res, 'reason');
                        $reason = 'revocation: ' . ($rr !== null ? Js::str($rr) : 'rejected');
                    }
                    $allow = false;
                }
            } catch (\Throwable $e) { // a hook that throws refuses the proof
                $revocation = 'fail';
                if ($allow || $reason === null) {
                    $reason = 'malformed PCActn: ' . $e->getMessage();
                }
                $allow = false;
            }
        }
        $st = new Obj();
        foreach ($v['checks'] as $k => $ok) {
            $st->set($k === 'chain' ? 'cap_chain' : (string)$k, $ok ? 'pass' : 'fail');
        }
        foreach ($v['not_enforced'] ?? [] as $k) {
            $st->set((string)$k, 'not-enforced');
        }
        $st->set('attestation', 'not-enforced');
        $st->set('threshold', 'not-enforced');
        $st->set('revocation', $revocation);
        if (!$st->has('taint_gate')) {
            $st->set('taint_gate', 'not-enforced');
        }
        $verdict = ['allow' => $allow, 'checks' => $st];
        if ($reason !== null) {
            $verdict['reason'] = $reason;
        }
        return ['verdict' => $verdict, 'wire' => $wire, 'aud' => ($v['checks']['audience'] ?? false) === true];
    }

    /**
     * The framework-agnostic core: extract the PCActn, map the request to the capability its route requires, verify (fail closed), enforce
     * audience, capability, request binding, required checks, the proof hook and single use. Returns a decision array
     * {allow, status, code, reason, headers, verdict?, pcactn?, matched?}.
     *
     * @return array<string,mixed>
     */
    public static function authorize(mixed $req, mixed $opts, ?GatewayProvenanceLog $defaultLog = null): array
    {
        $aud = Js::opt($opts, 'audience');
        $realmOpt = Js::opt($opts, 'realm');
        $realm = $realmOpt !== null ? Js::str($realmOpt) : (is_string($aud) ? $aud : Js::str($aud));
        $um = Js::opt($opts, 'unmatchedRoute');
        $unmatched = Js::truthy($um) ? $um : 'deny';
        $pp = Js::opt($opts, 'pathPolicy');
        $path = self::str(Js::opt($req, 'path'), 'path');
        $method = self::str(Js::opt($req, 'method'), 'method');

        // 0. an ambiguous request target is never matched against the route map
        if ((Js::truthy($pp) ? $pp : 'strict') === 'strict') {
            $bad = self::ambiguousPathReason($path);
            if ($bad !== null) {
                return self::deny('invalid-path', 400, $bad, $realm);
            }
        }

        // 1. route -> required capability; an unmapped route follows unmatchedRoute (default deny)
        $rule = self::matchRoute(Js::opt($opts, 'routes'), $method, $path);
        if ($rule === null) {
            if ($unmatched === 'allow') {
                return self::allow("route $method $path is unmapped (unmatchedRoute=allow)");
            }
            if ($unmatched === 'deny') {
                return self::deny('unmapped-route', 403, "no capability mapping for $method $path (deny-by-default)", $realm);
            }
        }
        $required = $rule !== null ? Js::opt($rule, 'capability') : null;

        // 2. the proof (fail closed)
        $extracted = self::extractPcactn(Js::opt($req, 'headers'));
        if (!isset($extracted['pcactn'])) {
            return self::deny($extracted['code'], 401, $extracted['reason'], $realm);
        }
        $pcactn = $extracted['pcactn'];

        // 3. the grant the chain must root in
        $grantRef = $pcactn->get('grant_ref');
        $resolve = Js::opt($opts, 'resolveGrant');
        if (!($resolve instanceof \Closure)) {
            throw new \TypeError('pca-gateway: resolveGrant is not a function');
        }
        $grant = $resolve($grantRef, $pcactn);
        if (!Js::truthy($grant)) {
            return self::deny('unknown-grant', 401, 'unknown grant_ref ' . ($pcactn->has('grant_ref') ? Js::str($grantRef) : 'undefined'), $realm, ['pcactn' => $pcactn]);
        }

        // 3b. a configuration with a missing component denies every request (fail closed)
        $missingCfg = self::missingPolicy($opts);
        if ($missingCfg !== []) {
            return self::deny('proof-rejected', 403, self::missingText($opts, $missingCfg) . ' (fail closed)', $realm, ['pcactn' => $pcactn]);
        }
        // 4. offline verification, the audience bound to THIS gateway
        $nowFn = Js::opt($opts, 'now');
        $now = $nowFn instanceof \Closure ? self::ms($nowFn()) : (int)floor(self::clock() * 1000);
        $r = self::verify($pcactn, $grant, $opts, $now);
        $verdict = $r['verdict'];
        if (!$verdict['allow']) {
            $audienceFailed = $r['wire'] && !$r['aud'];
            $why = $verdict['reason'] ?? '';
            return self::deny($audienceFailed ? 'wrong-audience' : 'verify-failed', $audienceFailed ? 403 : 401,
                $why !== '' ? $why : 'PCActn verification failed', $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
        }

        // 5. capability enforcement: the verified proof carries the verb (+ resource) the route requires
        $action = $pcactn->get('action');
        if ($required !== null) {
            $rv = Js::opt($required, 'verb');
            if ($action->get('verb') !== $rv) {
                return self::deny('insufficient-capability', 403, "route requires capability '" . Js::str($rv) . "' but the proof authorizes '" . Js::str($action->get('verb')) . "'",
                    $realm, ['verdict' => $verdict, 'pcactn' => $pcactn, 'matched' => $required]);
            }
            $rr = Js::opt($required, 'resource');
            if ($rr !== null && $action->get('resource') !== $rr) {
                return self::deny('insufficient-capability', 403, "route is bound to resource '" . Js::str($rr) . "' but the proof targets '" . Js::str($action->get('resource')) . "'",
                    $realm, ['verdict' => $verdict, 'pcactn' => $pcactn, 'matched' => $required]);
            }
        }

        $policy = self::policyMode($opts) === 'full' ? Js::opt($opts, 'policy') : null;
        $bind = Js::opt($opts, 'bindRequest');
        $fullParams = null;
        if ($policy !== null) {
            // 5b (full). the agent signed the real params plus the request binding: rebuild them from THIS request
            $sp = self::signedParams($req, $policy, $bind);
            if (isset($sp['error'])) {
                return self::deny('request-mismatch', 403, $sp['error'], $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
            if ($action->get('params_digest') !== Pca::paramsDigest($sp['params'])) {
                return self::deny('request-mismatch', 403, 'the proof is not bound to this request (params/method/path/query/authority)',
                    $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
            $fullParams = $sp['params'];
        } elseif ($bind !== false) {
            // 5b. request binding: the signed params digest must be the digest of THIS request
            if ((Js::truthy(Js::opt($bind, 'authority')) && !Js::truthy(Js::opt($req, 'authority')))
                || (Js::opt($bind, 'body') === true && !Js::truthy(Js::opt($req, 'bodySha256')))) {
                return self::deny('request-mismatch', 403, 'request lacks an attribute the proof must bind (authority / body hash)',
                    $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
            try {
                $bound = Pca::paramsDigest(self::requestBinding($req, $bind));
            } catch (\Throwable $e) {
                return self::deny('request-mismatch', 403, 'the request cannot be bound: ' . $e->getMessage(), $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
            if ($action->get('params_digest') !== $bound) {
                return self::deny('request-mismatch', 403, 'the proof is not bound to this request (method/path/query/authority/body)',
                    $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
        }

        // 5c. required checks must have PASSED (not merely "not-enforced")
        $rcOpt = Js::opt($opts, 'requireChecks');
        foreach (is_array($rcOpt) ? $rcOpt : ($policy === null ? self::DEFAULT_REQUIRE_CHECKS : []) as $c) {
            $c = Js::str($c);
            $have = $verdict['checks']->has($c) ? $verdict['checks']->get($c) : null;
            if ($have !== 'pass') {
                return self::deny('proof-rejected', 403, "required check '$c' is " . ($have ?? 'absent'), $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
        }

        // 5d. per-proof policy hook (limits, budgets, revocation lists); a throw denies
        $cp = Js::opt($opts, 'checkProof');
        if ($cp instanceof \Closure) {
            try {
                $ctx = ['pcactn' => $pcactn, 'grant' => $grant, 'verdict' => $verdict, 'request' => $req];
                if ($required !== null) {
                    $ctx['required'] = $required;
                }
                $res = $cp($ctx);
                $ok = is_bool($res) ? $res : Js::truthy(Js::opt($res, 'allow'));
                if (!$ok) {
                    $rsn = Js::isObj($res) ? Js::opt($res, 'reason') : null;
                    return self::deny('proof-rejected', 403, Js::truthy($rsn) ? Js::str($rsn) : 'rejected by checkProof', $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
                }
            } catch (\Throwable $e) {
                return self::deny('proof-rejected', 403, 'checkProof failed: ' . $e->getMessage(), $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
        }

        // 5e. full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget
        $policyVerdict = null;
        if ($policy !== null && $fullParams !== null) {
            $full = self::fullPolicy($req, $opts, $policy, $pcactn, $grant, $required, $fullParams, $verdict, $realm, $now, $defaultLog);
            if (isset($full['decision'])) {
                return $full['decision'];
            }
            $policyVerdict = $full['policyVerdict'];
        }

        // 6. single use, only for a proof that would otherwise be allowed (a denied attempt never burns it)
        $guard = Js::opt($opts, 'replayGuard');
        if ($guard !== null) {
            try {
                $first = $guard->claim(Js::str($grantRef) . ':' . Js::str($pcactn->get('sig')), $pcactn->get('exp'), $now);
            } catch (\Throwable $e) {
                return self::deny('replay-guard-unavailable', 503, 'replay guard unavailable: ' . $e->getMessage(), $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
            if (!Js::truthy($first)) {
                return self::deny('replayed-proof', 403, 'this proof has already been used', $realm, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
        }

        return self::allow($policyVerdict !== null ? 'proof-carrying action authorized (full policy)' : 'proof-carrying action verified',
            ['verdict' => $verdict, 'pcactn' => $pcactn, 'matched' => $required, 'policyVerdict' => $policyVerdict]);
    }

    /** Full-policy mode: the params the agent must have signed for this request, or why they cannot be built. @return array{params?:Obj,error?:string} */
    private static function signedParams(mixed $req, mixed $policy, mixed $bind): array
    {
        $src = Js::opt($policy, 'params');
        if ($src === 'body') {
            $body = Js::opt($req, 'body');
            if (!is_string($body)) {
                return ['error' => 'full policy mode reads the params from the body, and the request carries none'];
            }
            try {
                $params = Json::parseStrict($body);
            } catch (\Throwable $e) {
                return ['error' => 'the body is not strict JSON: ' . $e->getMessage()];
            }
        } else {
            $params = $src($req);
            if (is_array($params) && !array_is_list($params)) {
                $params = AnalyzerNarrowing::modelOf(Obj::of($params));
            }
        }
        if (!($params instanceof Obj)) {
            return ['error' => 'the request params are not a JSON object'];
        }
        if ($bind === false) {
            return ['params' => $params];
        }
        if ($params->has('binding')) {
            return ['error' => "the request params carry a 'binding' member (reserved for the request binding)"];
        }
        if ((Js::truthy(Js::opt($bind, 'authority')) && !Js::truthy(Js::opt($req, 'authority')))
            || (Js::opt($bind, 'body') === true && !Js::truthy(Js::opt($req, 'bodySha256')))) {
            return ['error' => 'request lacks an attribute the proof must bind (authority / body hash)'];
        }
        try {
            // the params carry the body, so its hash is bound only when asked for explicitly (bindRequest.body === true)
            $o = [];
            if (Js::truthy(Js::opt($bind, 'authority'))) {
                $o['authority'] = true;
            }
            $o['body'] = Js::opt($bind, 'body') === true;
            $out = new Obj();
            foreach ($params->keys() as $k) {
                $out->set($k, $params->get($k));
            }
            $out->set('binding', self::requestBinding($req, $o));
            return ['params' => $out];
        } catch (\Throwable $e) {
            return ['error' => 'the request cannot be bound: ' . $e->getMessage()];
        }
    }

    /** The policy members forwarded to the core pipeline, and the ones this port refuses. */
    private const FULL_KEYS = ['mode', 'params', 'k1', 'provenanceLog', 'state', 'isRevoked', 'require', 'allowedSuites', 'pqPins', 'usesStore',
        'requireAssurance', 'risk', 'seedBudget', 'requireRiskInputs', 'thresholdHook', 'enforceFreshness', 'isPlanAuthorized', 'provenance', 'plans',
        'resolvePrincipal', 'requireVerifiedPrincipal'];

    /** The risk the server prices from a verified `amount`: blastRadius = amount / kappa of the grant's own risk policy. */
    private static function amountRisk(mixed $grant, Obj $params): ?array
    {
        return Execution::amountRisk($grant, $params);
    }

    /**
     * Full-policy mode: the core `authorize` pipeline with the gateway's own audience, grant and clock, fed the params rebuilt from
     * the request. @return array{decision?:array<string,mixed>,policyVerdict?:array<string,mixed>}
     */
    private static function fullPolicy(mixed $req, mixed $opts, mixed $policy, Obj $pcactn, mixed $grant, mixed $required, Obj $params, array $verdict,
                                       string $realm, int $now, ?GatewayProvenanceLog $defaultLog): array
    {
        $fail = static fn(string $why): array => ['decision' => self::deny('proof-rejected', 403, $why, $realm, ['verdict' => $verdict, 'pcactn' => $pcactn])];
        $k1 = null;
        $k1Opt = Js::opt($policy, 'k1');
        if ($k1Opt !== null) {
            try {
                $own = $k1Opt instanceof \Closure ? $k1Opt($req, $pcactn) : $k1Opt;
                $k1 = new Obj();
                foreach ([self::presentedArtifacts($req, $policy), $own] as $part) {
                    foreach (self::entries($part) as [$k, $v]) {
                        $k1->set($k, $v);
                    }
                }
            } catch (\Throwable $e) {
                return $fail('k1 input failed: ' . $e->getMessage() . ' (fail closed)');
            }
        }
        try {
            $bundle = self::presentedProvenance($req, $policy);
            $logOpt = Js::opt($policy, 'provenanceLog');
            $log = $logOpt === false ? null : ($logOpt ?? $defaultLog ?? new GatewayProvenanceLog());
            $chain = $pcactn->get('cap_chain');
            $leaf = is_array($chain) && $chain !== [] && end($chain) instanceof Obj ? end($chain)->get('holder') : null;
            $receipts = $bundle instanceof Obj ? $bundle->get('receipts') : null;
            $first = is_array($receipts) && $receipts !== [] && $receipts[0] instanceof Obj ? $receipts[0]->get('session') : null;
            $logKey = Js::str($pcactn->get('grant_ref')) . "\n" . ($leaf === null ? 'undefined' : Js::str($leaf)) . "\n" . (is_string($first) ? $first : '-');
            $prov = Js::opt($policy, 'provenance');
            $userObserved = Js::opt($prov, 'observed');
            $observed = $log === null && $userObserved === null ? null : static function (mixed ...$a) use ($userObserved, $log, $logKey): array {
                return array_merge($userObserved instanceof \Closure ? array_values((array)$userObserved(...$a)) : [], $log !== null ? $log->seen($logKey) : []);
            };
            $action = $pcactn->get('action');
            $operation = Obj::of(['verb' => $required !== null ? Js::opt($required, 'verb') : $action->get('verb'),
                'resource' => $required !== null && Js::opt($required, 'resource') !== null ? Js::opt($required, 'resource') : $action->get('resource'),
                'params' => $params]);
            $isPlan = Js::opt($policy, 'isPlanAuthorized');
            $riskFn = Js::opt($policy, 'risk');
            $args = [
                'audience' => Js::opt($opts, 'audience'), 'resolveGrant' => static fn($ref = null, $p = null) => $grant, 'stateStore' => Js::opt($policy, 'state'),
                'isRevoked' => Js::opt($policy, 'isRevoked'), 'now' => $now, 'allowedSuites' => Js::opt($policy, 'allowedSuites') ?? ['ed25519'],
                'require' => array_merge(['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound',
                    'params_digest', 'policy'], (array)(Js::opt($policy, 'require') ?? [])),
                'requireAssurance' => Js::opt($policy, 'requireAssurance'), 'k1' => $k1, 'usesStore' => Js::opt($policy, 'usesStore'),
                'provenance' => $bundle === self::ABSENT ? null : ($bundle === null ? '{unreadable' : $bundle),
                'provenanceMediators' => Js::opt($prov, 'mediators'), 'provenanceActions' => Js::opt($prov, 'actions'),
                'provenanceObserved' => $observed, 'pqPins' => Js::opt($policy, 'pqPins'), 'plans' => Js::opt($policy, 'plans'),
                'resolvePrincipal' => Js::opt($policy, 'resolvePrincipal'), 'requireVerifiedPrincipal' => Js::opt($policy, 'requireVerifiedPrincipal') === true,
                'enforceFreshness' => Js::opt($policy, 'enforceFreshness'),
                'hard' => ['seedBudget' => Js::opt($policy, 'seedBudget') !== false, 'requireRiskInputs' => Js::opt($policy, 'requireRiskInputs'),
                    'thresholdHook' => Js::opt($policy, 'thresholdHook'),
                    'risk' => static fn(mixed $op, mixed $g, mixed $pc): mixed => $riskFn instanceof \Closure ? $riskFn($g, $params, $pc) : self::amountRisk($g, $params)],
            ];
            if ($isPlan instanceof \Closure) {
                $args['context'] = static function (Obj $pc) use ($isPlan, $params): Obj {
                    $a = $pc->get('action');
                    $node = Obj::of(['id' => $pc->get('plan')->get('node_id'), 'verb' => $a->get('verb'), 'resource' => $a->get('resource'),
                        'params_digest' => $a->get('params_digest'), 'reversibility_class' => $a->get('reversibility_class')]);
                    return Obj::of(['plan' => [$node], 'plan_authorized' => $isPlan($pc->get('grant_ref'), $pc->get('plan')->get('root')) === true]);
                };
            } else {
                $args['plan'] = Authorize::SINGLE_STEP;
            }
            $d = Authorize::authorize($pcactn, $operation, ...$args);
        } catch (\Throwable $e) {
            return $fail('full policy failed: ' . $e->getMessage() . ' (fail closed)');
        }
        // what this call returns flows back into the agent's context: the session has now seen untrusted content
        if ($d->allow && $log !== null) {
            $log->add($logKey, Obj::of(['origin' => 'tool', 'source' => $action->get('verb')]));
        }
        $checks = Obj::of($d->checks);
        if (!$d->allow) {
            $code = ($d->checks['replay'] ?? null) === 'fail' ? 'replayed-proof' : (($d->checks['operation'] ?? null) === 'fail' ? 'insufficient-capability'
                : ($d->status === 401 ? 'verify-failed' : 'proof-rejected'));
            return ['decision' => self::deny($code, $d->status, $d->reason ?? 'rejected', $realm,
                ['verdict' => $verdict, 'pcactn' => $pcactn, 'policyVerdict' => Obj::of(['allow' => false, 'checks' => $checks, 'reason' => $d->reason])])];
        }
        return ['policyVerdict' => Obj::of(['allow' => true, 'checks' => $checks])];
    }

    /**
     * A reusable authorizer bound to one configuration. Throws \TypeError when a component is missing and \InvalidArgumentException for a
     * mode, hook or gate this port cannot run (it would otherwise be silently ignored).
     *
     * @return \Closure(mixed): array<string,mixed>
     */
    public static function createGateway(mixed $opts): \Closure
    {
        $missing = self::missingPolicy($opts);
        if ($missing !== []) {
            throw new \TypeError('pca-gateway: ' . self::missingText($opts, $missing));
        }
        $extra = [];
        foreach (self::entries(Js::opt($opts, 'hooks')) as [$k]) {
            if ($k !== 'revocation') {
                $extra[] = $k;
            }
        }
        $enf = self::entries(Js::opt($opts, 'enforce'));
        foreach ($enf as [$k]) {
            if ($k !== 'freshness') {
                throw new \InvalidArgumentException("pca-gateway: the $k enforcement gate is not supported by this port");
            }
        }
        if ($extra !== []) {
            throw new \InvalidArgumentException('pca-gateway: hooks ' . implode(', ', $extra) . ' are not supported by this port');
        }
        if (self::policyMode($opts) === 'full') {
            foreach (self::entries(Js::opt($opts, 'policy')) as [$k]) {
                if (!in_array($k, self::FULL_KEYS, true)) { // an option this port cannot run would otherwise be silently ignored
                    throw new \InvalidArgumentException("pca-gateway: the full-policy option '$k' is not supported by this port");
                }
            }
        }
        $log = new GatewayProvenanceLog();
        return static fn(mixed $req): array => self::authorize($req, $opts, $log);
    }

    /**
     * Join a gateway to an injected upstream closure: on allow, `$upstream(request, decision)` is called with every client-supplied
     * x-pca-* header removed and the decision's headers set; on deny the 401 / 403 response array is returned and the upstream is never called.
     *
     * @param \Closure(mixed, array<string,mixed>): mixed $upstream
     * @return \Closure(mixed): mixed
     */
    public static function gatewayProxy(mixed $opts, \Closure $upstream): \Closure
    {
        $gateway = self::createGateway($opts);
        return static function (mixed $req) use ($gateway, $upstream): mixed {
            $d = $gateway($req);
            if (!$d['allow']) {
                return self::denyResponse($d);
            }
            $hdrs = new Obj();
            foreach (self::entries(Js::opt($req, 'headers')) as [$k, $v]) {
                if (!in_array(self::lower($k), self::PCA_INJECTED_HEADERS, true)) {
                    $hdrs->set($k, $v);
                }
            }
            foreach ($d['headers']->keys() as $k) {
                $hdrs->set($k, $d['headers']->get($k));
            }
            if ($req instanceof Obj) {
                $copy = new Obj();
                foreach ($req->keys() as $k) {
                    $copy->set($k, $req->get($k));
                }
                $copy->set('headers', $hdrs);
                return $upstream($copy, $d);
            }
            return $upstream(array_merge(is_array($req) ? $req : [], ['headers' => $hdrs]), $d);
        };
    }

    /** @param array<string,mixed> $d @return array<string,mixed> */
    private static function denyResponse(array $d): array
    {
        $h = Obj::of(['content-type' => 'application/json']);
        foreach ($d['headers']->keys() as $k) {
            $h->set($k, $d['headers']->get($k));
        }
        return ['status' => $d['status'], 'headers' => $h, 'body' => Js::stringify(['error' => $d['code'], 'reason' => $d['reason']])];
    }

    // ---- Cloudflare Worker (fetch-style middleware) --------------------------------------------------------------------------

    /** The path, authority and query of a request URL string, without a URL parser. @return array{path:string,authority:string,query:string} */
    private static function workerPath(string $url): array
    {
        $rest = $url;
        $authority = '';
        $scheme = strpos($rest, '://');
        if ($scheme !== false) {
            $rest = substr($rest, $scheme + 3);
            $slash = strpos($rest, '/');
            if ($slash === false) {
                $authority = $rest;
                $rest = '/';
            } else {
                $authority = substr($rest, 0, $slash);
                $rest = substr($rest, $slash);
            }
        }
        $mark = strcspn($rest, '?#');
        $path = substr($rest, 0, $mark);
        return ['path' => $path === '' ? '/' : $path, 'authority' => $authority, 'query' => self::queryOfTarget($rest)];
    }

    /** Lower-case names of the inbound x-pca-* headers a client sent. @return list<string> */
    private static function workerInboundPcaHeaders(mixed $request): array
    {
        $hdrs = Js::opt($request, 'headers');
        $found = [];
        foreach (self::entries($hdrs) as [$k]) {
            $n = self::lower($k);
            if (str_starts_with($n, 'x-pca-') && !in_array($n, $found, true)) {
                $found[] = $n;
            }
        }
        sort($found, SORT_STRING); // a Fetch Headers iterates in sorted order
        foreach (self::PCA_INJECTED_HEADERS as $n) {
            if (self::getHeader($hdrs, $n) !== null && !in_array($n, $found, true)) {
                $found[] = $n;
            }
        }
        return $found;
    }

    /** The request with the named (lower-case) headers removed. @param list<string> $drop */
    private static function workerDefaultRewrite(mixed $request, array $drop): mixed
    {
        $kept = new Obj();
        foreach (self::entries(Js::opt($request, 'headers')) as [$k, $v]) {
            if (!in_array(self::lower($k), $drop, true)) {
                $kept->set($k, $v);
            }
        }
        if ($request instanceof Obj) {
            $copy = new Obj();
            foreach ($request->keys() as $k) {
                $copy->set($k, $request->get($k));
            }
            $copy->set('headers', $kept);
            return $copy;
        }
        return array_merge(is_array($request) ? $request : [], ['headers' => $kept]);
    }

    /**
     * Cloudflare Worker middleware core: a closure over a request ({method, url, headers, body?}, an Obj or an assoc array) that verifies
     * the inbound PCActn. On allow it calls `$next($request)` with every inbound x-pca-* header removed (`$rewriteRequest` 'default' drops
     * them; a closure `(request, names) -> request|null` replaces that; null opts out, and a request carrying one is then refused 400); on
     * deny it returns `$respond(jsonBody, ['status' => int, 'headers' => array])` with the WWW-Authenticate challenge and a JSON error
     * body, and the upstream is never reached. A full-policy gateway with params 'body' reads the request's `body`.
     *
     * @param \Closure(mixed): mixed $next
     * @param \Closure(string, array<string,mixed>): mixed $respond
     * @param \Closure|string|null $rewriteRequest
     * @return \Closure(mixed): mixed
     */
    public static function cloudflareWorker(mixed $opts, \Closure $next, \Closure $respond, \Closure|string|null $rewriteRequest = 'default'): \Closure
    {
        $gateway = self::createGateway($opts);
        return static function (mixed $request) use ($gateway, $opts, $next, $respond, $rewriteRequest): mixed {
            $loc = self::workerPath(self::str(Js::opt($request, 'url'), 'url'));
            $hdrs = Js::opt($request, 'headers');
            $headers = new Obj();
            $pca = self::getHeader($hdrs, self::PCA_HEADER);
            if ($pca !== null) {
                $headers->set(self::lower(self::PCA_HEADER), $pca);
            }
            foreach (['pca-discharges', 'pca-narrow'] as $h) {
                $v = self::getHeader($hdrs, $h);
                if ($v !== null) {
                    $headers->set($h, $v);
                }
            }
            $req = Obj::of(['method' => Js::opt($request, 'method'), 'path' => $loc['path'], 'query' => $loc['query'], 'authority' => $loc['authority'], 'headers' => $headers]);
            if (self::policyMode($opts) === 'full' && Js::opt(Js::opt($opts, 'policy'), 'params') === 'body' && Js::opt($request, 'body') !== null) {
                $req->set('body', Js::opt($request, 'body'));
            }
            $d = $gateway($req);
            if ($d['allow']) {
                $forged = self::workerInboundPcaHeaders($request);
                if ($forged === []) {
                    return $next($request);
                }
                $clean = $rewriteRequest === 'default' ? self::workerDefaultRewrite($request, $forged) : ($rewriteRequest === null ? null : $rewriteRequest($request, $forged));
                if ($clean !== null) {
                    return $next($clean);
                }
                return $respond(Js::stringify(['error' => 'forged-pca-header', 'reason' => 'inbound x-pca-* header cannot be removed']),
                    ['status' => 400, 'headers' => ['content-type' => 'application/json']]);
            }
            $h = ['content-type' => 'application/json'];
            foreach ($d['headers']->keys() as $k) {
                $h[$k] = $d['headers']->get($k);
            }
            return $respond(Js::stringify(['error' => $d['code'], 'reason' => $d['reason']]), ['status' => $d['status'], 'headers' => $h]);
        };
    }

    // ---- Envoy HTTP ext_authz ------------------------------------------------------------------------------------------------

    private static function queryOfTarget(string $target): string
    {
        $q = strpos($target, '?');
        if ($q === false) {
            return '';
        }
        $rest = substr($target, $q + 1);
        $h = strpos($rest, '#');
        return $h !== false ? substr($rest, 0, $h) : $rest;
    }

    /** @return array<string,mixed> */
    private static function envoyRequest(mixed $check): array
    {
        $headers = self::first(Js::opt($check, 'headers'), new Obj());
        $method = self::first(Js::opt($check, 'method'), Js::opt($headers, ':method'), '*');
        $target = self::str(self::first(Js::opt($check, 'path'), Js::opt($headers, ':path'), '/'), 'path');
        $m = preg_match('/[?#]/', $target, $mm, PREG_OFFSET_CAPTURE) === 1 ? $mm[0][1] : null;
        $rawPath = $m !== null ? substr($target, 0, $m) : $target;
        $authority = self::first(Js::opt($check, 'authority'), Js::opt($headers, ':authority'));
        $req = ['method' => $method, 'path' => $rawPath === '' ? '/' : $rawPath, 'query' => self::queryOfTarget($target), 'headers' => $headers];
        if ($authority !== null) {
            $req['authority'] = $authority;
        }
        if (Js::opt($check, 'body') !== null) {
            $req['body'] = Js::opt($check, 'body');
        }
        return $req;
    }

    /**
     * Envoy HTTP ext_authz handler: 200 plus the verified verdict headers on allow (every injected header is overwritten, the unset ones
     * blank), the guard's 401 / 403 with a WWW-Authenticate challenge and a JSON body on deny.
     *
     * @return \Closure(mixed): array<string,mixed>
     */
    public static function envoyExtAuthz(mixed $opts): \Closure
    {
        $gateway = self::createGateway($opts);
        return static function (mixed $c) use ($gateway): array {
            $d = $gateway(self::envoyRequest($c));
            if ($d['allow']) {
                $h = new Obj();
                foreach (self::PCA_INJECTED_HEADERS as $k) {
                    $h->set($k, '');
                }
                foreach ($d['headers']->keys() as $k) {
                    $h->set($k, $d['headers']->get($k));
                }
                return ['status' => 200, 'headers' => $h, 'body' => ''];
            }
            return self::denyResponse($d);
        };
    }

    // ---- Envoy gRPC ext_authz ------------------------------------------------------------------------------------------------

    /** @return list<array<string,mixed>> */
    private static function headerOptions(Obj $h): array
    {
        $out = [];
        foreach ($h->keys() as $k) {
            $out[] = ['header' => ['key' => $k, 'value' => $h->get($k)], 'appendAction' => self::OVERWRITE_IF_EXISTS_OR_ADD];
        }
        return $out;
    }

    /**
     * Envoy gRPC ext_authz `Check` handler over a decoded CheckRequest (camelCase). On allow it also lists every x-pca-* header it did not
     * set in `headersToRemove`, so a client cannot smuggle a forged verdict through an unmapped-route allow.
     *
     * @return \Closure(mixed): array<string,mixed>
     */
    public static function envoyGrpcExtAuthz(mixed $opts): \Closure
    {
        $gateway = self::createGateway($opts);
        return static function (mixed $c) use ($gateway): array {
            $http = Js::opt(Js::opt(Js::opt($c, 'attributes'), 'request'), 'http');
            if (!Js::truthy($http)) {
                return [
                    'status' => ['code' => self::GRPC_PERMISSION_DENIED, 'message' => 'no http request attributes'],
                    'deniedResponse' => ['status' => ['code' => 403], 'headers' => [],
                        'body' => Js::stringify(['error' => 'invalid-request', 'reason' => 'CheckRequest carried no HTTP attributes'])],
                ];
            }
            $headers = self::first(Js::opt($http, 'headers'), new Obj());
            $req = ['headers' => $headers];
            $method = self::first(Js::opt($http, 'method'), Js::opt($headers, ':method'));
            if ($method !== null) {
                $req['method'] = $method;
            }
            $path = self::first(Js::opt($http, 'path'), Js::opt($headers, ':path'));
            if ($path !== null) {
                $req['path'] = $path;
            }
            $authority = self::first(Js::opt($http, 'host'), Js::opt($headers, ':authority'));
            if ($authority !== null) {
                $req['authority'] = $authority;
            }
            if (Js::opt($http, 'body') !== null) {
                $req['body'] = Js::opt($http, 'body');
            }
            $d = $gateway(self::envoyRequest($req));
            if ($d['allow']) {
                $remove = [];
                foreach (self::PCA_INJECTED_HEADERS as $h) {
                    if (!$d['headers']->has($h)) {
                        $remove[] = $h;
                    }
                }
                return [
                    'status' => ['code' => self::GRPC_OK, 'message' => ''],
                    'okResponse' => ['headers' => self::headerOptions($d['headers']), 'headersToRemove' => $remove],
                ];
            }
            $code = $d['status'] === 401 ? self::GRPC_UNAUTHENTICATED : ($d['status'] === 503 ? self::GRPC_UNAVAILABLE : self::GRPC_PERMISSION_DENIED);
            $h = Obj::of(['content-type' => 'application/json']);
            foreach ($d['headers']->keys() as $k) {
                $h->set($k, $d['headers']->get($k));
            }
            return [
                'status' => ['code' => $code, 'message' => $d['reason']],
                'deniedResponse' => ['status' => ['code' => $d['status']], 'headers' => self::headerOptions($h),
                    'body' => Js::stringify(['error' => $d['code'], 'reason' => $d['reason']])],
            ];
        };
    }

    // ---- AWS Lambda authorizers ----------------------------------------------------------------------------------------------

    private static function lambdaResource(mixed $event): mixed
    {
        return self::first(Js::opt($event, 'methodArn'), Js::opt($event, 'routeArn'), '*');
    }

    /** @return array{method:mixed,path:mixed} */
    private static function lambdaMethodPath(mixed $event): array
    {
        $http = Js::opt(Js::opt($event, 'requestContext'), 'http');
        $method = self::first(Js::opt($http, 'method'), Js::opt($event, 'httpMethod'));
        $path = self::first(Js::opt($event, 'rawPath'), Js::opt($event, 'path'), Js::opt($http, 'path'));
        if ($method !== null && $path !== null) {
            return ['method' => $method, 'path' => $path];
        }
        $arn = self::first(Js::opt($event, 'methodArn'), Js::opt($event, 'routeArn'));
        if ($arn !== null) {
            $parts = explode('/', implode(':', array_slice(explode(':', self::str($arn, 'arn')), 5)));
            $armMethod = count($parts) > 2 ? explode(' ', $parts[2])[0] : null;
            return ['method' => self::first($method, $armMethod, '*'), 'path' => self::first($path, '/' . implode('/', array_slice($parts, 3)))];
        }
        return ['method' => self::first($method, '*'), 'path' => self::first($path, '/')];
    }

    private static function lambdaQuery(mixed $event): string
    {
        $raw = Js::opt($event, 'rawQueryString');
        if (is_string($raw)) {
            return $raw;
        }
        $multi = Js::opt($event, 'multiValueQueryStringParameters');
        $single = Js::opt($event, 'queryStringParameters');
        $pairs = [];
        if (Js::truthy($multi) && Js::isObj($multi)) {
            foreach (self::entries($multi) as [$k, $vs]) {
                foreach (Js::spread($vs ?? []) as $v) {
                    $pairs[] = Js::encodeURIComponent($k) . '=' . Js::encodeURIComponent(Js::str($v));
                }
            }
        } elseif (Js::truthy($single) && Js::isObj($single)) {
            foreach (self::entries($single) as [$k, $v]) {
                $pairs[] = Js::encodeURIComponent($k) . '=' . Js::encodeURIComponent(Js::str($v));
            }
        }
        return implode('&', $pairs);
    }

    /** @return array<string,mixed> */
    private static function lambdaRequest(mixed $event): array
    {
        $mp = self::lambdaMethodPath($event);
        return ['method' => $mp['method'], 'path' => $mp['path'], 'query' => self::lambdaQuery($event), 'headers' => self::first(Js::opt($event, 'headers'), new Obj())];
    }

    /** @param array<string,mixed> $d */
    private static function lambdaContext(array $d): Obj
    {
        if ($d['allow']) {
            return isset($d['verdict']) ? Obj::of(['pcaVerdict' => Js::stringify($d['verdict'])]) : new Obj();
        }
        return Obj::of(['pcaDenied' => 'true', 'pcaCode' => $d['code'], 'pcaReason' => $d['reason'], 'pcaStatus' => (string)$d['status']]);
    }

    /**
     * AWS API Gateway REQUEST authorizer: an Allow IAM policy (verdict on context.pcaVerdict) on a valid proof, else a Deny policy. REST
     * (`methodArn`) and HTTP-API (`routeArn`) payloads.
     *
     * @return \Closure(mixed): array<string,mixed>
     */
    public static function lambdaAuthorizer(mixed $opts): \Closure
    {
        $gateway = self::createGateway($opts);
        return static function (mixed $event) use ($gateway): array {
            $d = $gateway(self::lambdaRequest($event));
            return [
                'principalId' => self::first(Js::opt($d['pcactn'] ?? null, 'grant_ref'), 'anonymous'),
                'policyDocument' => ['Version' => '2012-10-17', 'Statement' => [
                    ['Action' => 'execute-api:Invoke', 'Effect' => $d['allow'] ? 'Allow' : 'Deny', 'Resource' => self::lambdaResource($event)]]],
                'context' => self::lambdaContext($d),
            ];
        };
    }

    /**
     * HTTP-API simple-response variant: {isAuthorized, context} instead of an IAM policy.
     *
     * @return \Closure(mixed): array<string,mixed>
     */
    public static function lambdaSimpleAuthorizer(mixed $opts): \Closure
    {
        $gateway = self::createGateway($opts);
        return static function (mixed $event) use ($gateway): array {
            $d = $gateway(self::lambdaRequest($event));
            return ['isAuthorized' => $d['allow'], 'context' => self::lambdaContext($d)];
        };
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
