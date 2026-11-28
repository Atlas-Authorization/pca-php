<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/WhatwgUrl.php';
require_once __DIR__ . '/A2a.php';
require_once __DIR__ . '/PcaGrant.php';

/**
 * OAuth 2.1 / MCP-authorization interop bridge: RFC 9728 Protected Resource Metadata, the RFC 6750 / RFC 7235 WWW-Authenticate
 * challenge, RFC 8707 resource indicators and token-audience binding, the 401 / discovery glue, the pca_grant token gate and
 * scopes derived from the confirmed action. Mirrors the TypeScript reference (@atlasauth/pca-oauth). Options are an Obj or an
 * assoc array with the reference's camelCase names (authorizationServers, errorDescription, pcaChallenge, ...). Pure, I/O-free;
 * every refusal throws \InvalidArgumentException (fail closed).
 */
final class Oauth
{
    public const WELL_KNOWN_OAUTH_PRM = '/.well-known/oauth-protected-resource';
    public const WELL_KNOWN_PCA_PATH = '/.well-known/pca-configuration';
    public const DEFAULT_PCA_HINT = 'send PCA-Action: <base64url PCActn> or JSON body {pcactn}';
    public const DEFAULT_SUITES = ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'];
    public const DEFAULT_REQUIRED = ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];
    public const PCA_NEED_MAX_ENCODED = 2048;
    private const SCOPE_TOKEN = '/\A[\x21\x23-\x5b\x5d-\x7e]+\z/';

    private static function fail(string $m): never
    {
        throw new \InvalidArgumentException($m);
    }

    private static function nonEmpty(mixed $s): bool
    {
        return is_string($s) && $s !== '';
    }

    /** RFC 9728 section 1.2: the reason `$resource` is not an https URL without a fragment, or null when it is valid. */
    public static function resourceIdentifierProblem(mixed $resource): ?string
    {
        if (!self::nonEmpty($resource)) {
            return 'resource identifier must be a non-empty string';
        }
        $u = WhatwgUrl::parse($resource);
        if ($u === null) {
            return 'resource identifier is not an absolute URL';
        }
        if ($u['scheme'] !== 'https') {
            return 'resource identifier must use the https scheme';
        }
        if (str_contains($resource, '#')) {
            return 'resource identifier must not contain a fragment';
        }
        return null;
    }

    /** RFC 9728 section 3.1: the well-known suffix goes between host and path/query. Throws on an invalid identifier. */
    public static function prmPathForResource(mixed $resource): string
    {
        $problem = self::resourceIdentifierProblem($resource);
        if ($problem !== null) {
            self::fail("prmPathForResource: $problem");
        }
        $u = WhatwgUrl::parse($resource);
        return self::WELL_KNOWN_OAUTH_PRM . ($u['pathname'] === '/' ? '' : $u['pathname']) . $u['search'];
    }

    /** The absolute metadata URL for a resource identifier (the `resource_metadata` value). */
    public static function prmUrlForResource(mixed $resource): string
    {
        $u = WhatwgUrl::parse($resource);
        if ($u === null || !isset($u['origin'])) {
            self::fail('prmUrlForResource: invalid resource identifier');
        }
        return $u['origin'] . self::prmPathForResource($resource);
    }

    /**
     * The PCA discovery document (buildDiscoveryDocument of the core package). Options: audience, pcaVersions, signatureSuites,
     * actionHeader, requiredChecks, endpoints, trustedRoots, metadata.
     */
    public static function buildDiscoveryDocument(mixed $o): Obj
    {
        $aud = Js::opt($o, 'audience');
        if (!self::nonEmpty($aud)) {
            self::fail('buildDiscoveryDocument: audience is required');
        }
        $doc = Obj::of([
            'audience' => $aud,
            'pca_versions' => Js::opt($o, 'pcaVersions') ?? [2],
            'signature_suites' => Js::opt($o, 'signatureSuites') ?? self::DEFAULT_SUITES,
            'action_header' => Js::opt($o, 'actionHeader') ?? 'PCA-Action',
            'required_checks' => Js::opt($o, 'requiredChecks') ?? self::DEFAULT_REQUIRED,
        ]);
        foreach (['endpoints' => 'endpoints', 'trustedRoots' => 'trusted_roots', 'metadata' => 'metadata'] as $k => $w) {
            if (Js::truthy(Js::opt($o, $k))) {
                $doc->set($w, Js::opt($o, $k));
            }
        }
        if (Js::truthy(Js::opt($o, 'intent'))) {
            $doc->set('intent', self::parseDiscoveryIntent(Js::opt($o, 'intent')));
        }
        if (Js::truthy(Js::opt($o, 'obligationsSupported'))) {
            $doc->set('obligations_supported', array_values(Js::spread(Js::opt($o, 'obligationsSupported'))));
        }
        return $doc;
    }

    private static function isObjLike(mixed $v): bool
    {
        return $v instanceof Obj || is_array($v); // typeof x === 'object' && x !== null: an array is one
    }

    private static function isStrList(mixed $v): bool
    {
        if (!is_array($v) || !array_is_list($v)) {
            return false;
        }
        foreach ($v as $x) {
            if (!is_string($x)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validate an `intent` discovery block (parseDiscoveryIntent): `{versions: [1|2...], actions_uri?, schema_keys?: [{kid, alg, pk, pq_pk?}],
     * question_relay?, tiers?: {verb: 0..4}, evidence_uri?}`. Throws on anything malformed (fail closed). Returns a fresh Obj.
     */
    public static function parseDiscoveryIntent(mixed $v): Obj
    {
        if (!($v instanceof Obj)) {
            self::fail('parseDiscoveryDocument: intent must be an object');
        }
        foreach ($v->keys() as $k) {
            if (!in_array($k, ['versions', 'actions_uri', 'schema_keys', 'question_relay', 'tiers', 'evidence_uri'], true)) {
                self::fail("parseDiscoveryDocument: intent has unknown member '$k'");
            }
        }
        $vs = $v->get('versions');
        $ok = is_array($vs) && array_is_list($vs) && count($vs) > 0;
        foreach ($ok ? $vs : [] as $n) {
            $ok = $ok && Js::isNum($n) && (Js::num($n) === 1.0 || Js::num($n) === 2.0);
        }
        if (!$ok) {
            self::fail('parseDiscoveryDocument: intent.versions must list 1 and/or 2');
        }
        $out = Obj::of(['versions' => array_values($vs)]);
        foreach (['actions_uri', 'evidence_uri'] as $k) {
            if ($v->has($k)) {
                if (!is_string($v->get($k)) || $v->get($k) === '') {
                    self::fail("parseDiscoveryDocument: intent.$k must be a non-empty string");
                }
                $out->set($k, $v->get($k));
            }
        }
        if ($v->has('schema_keys')) {
            $sk = $v->get('schema_keys');
            if (!is_array($sk) || !array_is_list($sk)) {
                self::fail('parseDiscoveryDocument: intent.schema_keys must be an array');
            }
            $keys = [];
            foreach ($sk as $e) {
                if (!($e instanceof Obj) || !is_string($e->get('kid')) || !is_string($e->get('alg')) || !is_string($e->get('pk'))
                    || ($e->has('pq_pk') && !is_string($e->get('pq_pk')))) {
                    self::fail('parseDiscoveryDocument: intent.schema_keys entries are {kid, alg, pk, pq_pk?}');
                }
                $n = Obj::of(['kid' => $e->get('kid'), 'alg' => $e->get('alg'), 'pk' => $e->get('pk')]);
                if ($e->has('pq_pk')) {
                    $n->set('pq_pk', $e->get('pq_pk'));
                }
                $keys[] = $n;
            }
            $out->set('schema_keys', $keys);
        }
        if ($v->has('question_relay')) {
            if (!is_bool($v->get('question_relay'))) {
                self::fail('parseDiscoveryDocument: intent.question_relay must be a boolean');
            }
            $out->set('question_relay', $v->get('question_relay'));
        }
        if ($v->has('tiers')) {
            $t = $v->get('tiers');
            if (!($t instanceof Obj)) {
                self::fail('parseDiscoveryDocument: intent.tiers must be an object');
            }
            $copy = new Obj();
            foreach ($t->keys() as $k) {
                $n = $t->get($k);
                if (!Js::isNum($n) || Js::num($n) !== floor(Js::num($n)) || Js::num($n) < 0 || Js::num($n) > 4 || ($n instanceof Num && str_starts_with($n->lexeme, '-'))) {
                    self::fail('parseDiscoveryDocument: intent.tiers values must be integers 0..4');
                }
                $copy->set($k, $n);
            }
            $out->set('tiers', $copy);
        }
        return $out;
    }

    /**
     * Validate and narrow an untrusted value into a discovery document (parseDiscoveryDocument). Throws on anything malformed. Optional
     * members of the wrong type are dropped, as in the reference; `intent` and `obligations_supported` are refused when malformed.
     */
    public static function parseDiscoveryDocument(mixed $value): Obj
    {
        if (!($value instanceof Obj)) {
            self::fail('parseDiscoveryDocument: not an object');
        }
        $v = $value;
        if (!self::nonEmpty($v->get('audience'))) {
            self::fail('parseDiscoveryDocument: missing audience');
        }
        $pv = $v->get('pca_versions');
        $okv = is_array($pv) && array_is_list($pv);
        foreach ($okv ? $pv : [] as $n) {
            $okv = $okv && Js::isNum($n);
        }
        if (!$okv) {
            self::fail('parseDiscoveryDocument: pca_versions must be a number[]');
        }
        if (!self::isStrList($v->get('signature_suites'))) {
            self::fail('parseDiscoveryDocument: signature_suites must be a string[]');
        }
        if (!self::nonEmpty($v->get('action_header'))) {
            self::fail('parseDiscoveryDocument: missing action_header');
        }
        $doc = Obj::of(['audience' => $v->get('audience'), 'pca_versions' => $pv, 'signature_suites' => $v->get('signature_suites'), 'action_header' => $v->get('action_header')]);
        if (self::isStrList($v->get('required_checks'))) {
            $doc->set('required_checks', $v->get('required_checks'));
        }
        if (self::isObjLike($v->get('endpoints'))) {
            $doc->set('endpoints', $v->get('endpoints'));
        }
        if (self::isStrList($v->get('trusted_roots'))) {
            $doc->set('trusted_roots', $v->get('trusted_roots'));
        }
        if (self::isObjLike($v->get('metadata'))) {
            $doc->set('metadata', $v->get('metadata'));
        }
        if ($v->has('intent')) {
            $doc->set('intent', self::parseDiscoveryIntent($v->get('intent')));
        }
        if ($v->has('obligations_supported')) {
            if (!self::isStrList($v->get('obligations_supported'))) {
                self::fail('parseDiscoveryDocument: obligations_supported must be a string[]');
            }
            $doc->set('obligations_supported', $v->get('obligations_supported'));
        }
        return $doc;
    }

    /** True iff this server (per its discovery document) accepts the signature suite. */
    public static function acceptsSuite(mixed $doc, string $suite): bool
    {
        $s = $doc instanceof Obj ? $doc->get('signature_suites') : null;
        return is_array($s) && in_array($suite, $s, true);
    }

    /**
     * Fetch and parse a resource server's discovery document: `$baseUrl` is the origin, the well-known path is appended. `$fetch` is
     * `callable(string $url, array $headers): array{ok:bool,status:int,body:string}` (inject one to use your HTTP client); the default is a
     * plain GET with a DISCOVERY_TIMEOUT_SEC (5 second) timeout that follows no redirect. Throws on a non-2xx response or a malformed document.
     */
    public static function fetchDiscovery(string $baseUrl, ?callable $fetch = null): Obj
    {
        $url = rtrim($baseUrl, '/') . self::WELL_KNOWN_PCA_PATH;
        $fetch ??= static function (string $u, array $headers): array {
            $ctx = stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", $headers), 'timeout' => self::DISCOVERY_TIMEOUT_SEC, 'follow_location' => 0, 'ignore_errors' => true]]);
            $body = @file_get_contents($u, false, $ctx);
            $status = 0;
            foreach (function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []) as $h) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m) === 1) {
                    $status = (int)$m[1];
                }
            }
            return ['ok' => $body !== false && $status >= 200 && $status < 300, 'status' => $status, 'body' => $body === false ? '' : $body];
        };
        $res = $fetch($url, ['accept: application/json']);
        if (($res['ok'] ?? false) !== true) {
            self::fail("fetchDiscovery: $url returned " . ($res['status'] ?? 0));
        }
        try {
            $parsed = Json::parseStrict((string)($res['body'] ?? ''));
        } catch (\Throwable) {
            self::fail('fetchDiscovery: the response is not JSON');
        }
        return self::parseDiscoveryDocument($parsed);
    }

    /** RFC 9728 Protected Resource Metadata plus the PCA block (the discovery document embedded). Throws on a bad resource. */
    public static function protectedResourceMetadata(mixed $o): Obj
    {
        $resource = Js::opt($o, 'resource');
        if (!self::nonEmpty($resource)) {
            self::fail('protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required');
        }
        if (Js::opt($o, 'strict') !== false) {
            $problem = self::resourceIdentifierProblem($resource);
            if ($problem !== null) {
                self::fail("protectedResourceMetadata: $problem");
            }
        }
        $d = ['audience' => $resource];
        foreach (['signatureSuites', 'pcaVersions', 'actionHeader', 'requiredChecks', 'endpoints', 'trustedRoots', 'metadata'] as $k) {
            $d[$k] = Js::opt($o, $k);
        }
        $discovery = self::buildDiscoveryDocument($d);
        $cfg = Js::opt($o, 'pcaConfigurationEndpoint')
            ?? rtrim(explode('?', $resource, 2)[0], '/') . self::WELL_KNOWN_PCA_PATH;
        $doc = Obj::of([
            'resource' => $resource,
            'bearer_methods_supported' => Js::opt($o, 'bearerMethodsSupported') ?? ['header'],
            'pca_action_header' => $discovery->get('action_header'),
            'pca_signature_suites' => Js::spread($discovery->get('signature_suites')),
            'pca_versions' => Js::spread($discovery->get('pca_versions')),
            'pca_configuration_endpoint' => $cfg,
            'pca' => $discovery,
        ]);
        foreach ([
            'authorizationServers' => ['authorization_servers', true], 'resourceDocumentation' => ['resource_documentation', false],
            'scopesSupported' => ['scopes_supported', true], 'resourceName' => ['resource_name', false],
            'resourceSigningAlgValuesSupported' => ['resource_signing_alg_values_supported', true],
            'authorizationDetailsTypesSupported' => ['authorization_details_types_supported', true],
        ] as $k => [$w, $spread]) {
            $v = Js::opt($o, $k);
            if (Js::truthy($v)) {
                $doc->set($w, $spread ? Js::spread($v) : $v);
            }
        }
        return $doc;
    }

    /** Validate and narrow an untrusted PRM document. Options: expectedResource, strict. Throws on anything malformed. */
    public static function parseProtectedResourceMetadata(mixed $v, mixed $opts = null): Obj
    {
        $p = 'parseProtectedResourceMetadata: ';
        if (!($v instanceof Obj) && !is_array($v)) {
            self::fail("{$p}not an object");
        }
        $g = static fn(string $k): mixed => Js::opt($v, $k);
        if (!self::nonEmpty($g('resource'))) {
            self::fail("{$p}missing `resource`");
        }
        if (!Js::isStrList($g('bearer_methods_supported'))) {
            self::fail("{$p}bearer_methods_supported must be a string[]");
        }
        if (!self::nonEmpty($g('pca_action_header'))) {
            self::fail("{$p}missing pca_action_header");
        }
        if (!Js::isStrList($g('pca_signature_suites'))) {
            self::fail("{$p}pca_signature_suites must be a string[]");
        }
        $vers = $g('pca_versions');
        if (!is_array($vers) || !array_is_list($vers) || array_filter($vers, static fn(mixed $n): bool => !Js::isNum($n)) !== []) {
            self::fail("{$p}pca_versions must be a number[]");
        }
        $pca = $g('pca');
        if (!($pca instanceof Obj) && !is_array($pca)) {
            self::fail("{$p}missing embedded `pca` discovery document");
        }
        if (!self::nonEmpty(Js::opt($pca, 'audience'))) {
            self::fail("{$p}embedded pca.audience is required");
        }
        $expected = Js::opt($opts, 'expectedResource');
        if ($expected !== null) {
            if ($g('resource') !== $expected) {
                self::fail("{$p}`resource` does not match the expected resource identifier");
            }
            if (Js::opt($pca, 'audience') !== $expected) {
                self::fail("{$p}embedded pca.audience does not match the expected resource identifier");
            }
        }
        if (Js::opt($opts, 'strict') !== false) {
            if ($expected === null) {
                self::fail("{$p}expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip");
            }
            $problem = self::resourceIdentifierProblem($g('resource'));
            if ($problem !== null) {
                self::fail($p . $problem);
            }
            foreach ($g('bearer_methods_supported') as $m) {
                if (!in_array($m, ['header', 'body', 'query'], true)) {
                    self::fail("{$p}bearer_methods_supported has a value outside header/body/query");
                }
            }
        }
        $doc = Obj::of([
            'resource' => $g('resource'), 'bearer_methods_supported' => $g('bearer_methods_supported'),
            'pca_action_header' => $g('pca_action_header'), 'pca_signature_suites' => $g('pca_signature_suites'),
            'pca_versions' => $vers, 'pca' => $pca,
        ]);
        foreach (['pca_configuration_endpoint' => false, 'authorization_servers' => true, 'resource_documentation' => false,
            'scopes_supported' => true, 'resource_name' => false, 'resource_signing_alg_values_supported' => true] as $k => $list) {
            $x = $g($k);
            if ($list ? Js::isStrList($x) : is_string($x)) {
                $doc->set($k, $x);
            }
        }
        return $doc;
    }

    /** String(v) of a value that reaches a quoted auth-param (RFC 7235): a quote, backslash or control character is refused. */
    private static function quotedParam(mixed $value): string
    {
        $s = is_string($value) ? $value : IntentWb::jsStr($value);
        if (preg_match('/["\\\\\x00-\x1f\x7f]/', $s) === 1) {
            self::fail('pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline');
        }
        return $s;
    }

    /** encodePcaNeed: the unpadded base64url of the need's strict-canonical JSON. Throws on a malformed or over-long need. */
    public static function encodePcaNeed(mixed $need): string
    {
        $code = A2a::needError($need);
        if ($code !== null) {
            self::fail("encodePcaNeed: malformed need ($code)");
        }
        $enc = Pca::b64u(Json::canonicalizeNative($need));
        if (strlen($enc) > self::PCA_NEED_MAX_ENCODED) {
            self::fail('encodePcaNeed: the need is too large for a header');
        }
        return $enc;
    }

    /**
     * The WWW-Authenticate value of a 401: the MCP `Bearer resource_metadata` challenge plus (by default) the PCA challenge.
     * Options: error, errorDescription, scope, pcaNeed, includePca, pcaChallenge, realm, hint.
     */
    public static function wwwAuthenticate(mixed $prmUrl, mixed $o = null): string
    {
        if (!self::nonEmpty($prmUrl)) {
            self::fail('wwwAuthenticate: prmUrl is required');
        }
        $params = ['resource_metadata="' . self::quotedParam($prmUrl) . '"'];
        foreach (['error' => 'error', 'errorDescription' => 'error_description', 'scope' => 'scope'] as $k => $w) {
            if (Js::truthy(Js::opt($o, $k))) {
                $params[] = "$w=\"" . self::quotedParam(Js::opt($o, $k)) . '"';
            }
        }
        if (Js::truthy(Js::opt($o, 'pcaNeed'))) {
            $params[] = 'pca_need="' . self::quotedParam(self::encodePcaNeed(Js::opt($o, 'pcaNeed'))) . '"';
        }
        $challenges = ['Bearer ' . implode(', ', $params)];
        $pc = Js::opt($o, 'pcaChallenge');
        if (Js::truthy($pc)) {
            $pc = is_string($pc) ? $pc : IntentWb::jsStr($pc);
            if (preg_match('/[\x00-\x08\x0a-\x1f\x7f]/', $pc) === 1) {
                self::fail('pca-oauth: pcaChallenge may not contain control characters or newlines');
            }
            $challenges[] = $pc;
        } elseif (Js::truthy(Js::opt($o, 'includePca') ?? true)) {
            $hint = Js::opt($o, 'hint') ?? self::DEFAULT_PCA_HINT;
            $pca = 'PCA realm="' . self::quotedParam(Js::opt($o, 'realm') ?? 'pca') . '"';
            if (Js::truthy($hint)) {
                $pca .= ', hint="' . self::quotedParam($hint) . '"';
            }
            $challenges[] = $pca;
        }
        return implode(', ', $challenges);
    }

    /**
     * RFC 8707: the OAuth-layer echo of the audience (an early reject, never the security boundary; the signed `aud` is).
     * @return array{ok:bool, matched?:string, reason?:string}
     */
    public static function checkResourceIndicator(mixed $resourceParam, mixed $expectedAudience): array
    {
        if (!self::nonEmpty($expectedAudience)) {
            self::fail('checkResourceIndicator: expectedAudience is required');
        }
        if ($resourceParam === null) {
            return ['ok' => false, 'reason' => 'no resource indicator presented'];
        }
        $values = is_array($resourceParam) && array_is_list($resourceParam) ? $resourceParam : [$resourceParam];
        if ($values === []) {
            return ['ok' => false, 'reason' => 'empty resource indicator'];
        }
        foreach ($values as $r) {
            if (self::nonEmpty($r) && $r === $expectedAudience) {
                return ['ok' => true, 'matched' => $r];
            }
        }
        return ['ok' => false, 'reason' => 'resource indicator ' . Js::stringify($values) . ' does not match audience ' . Js::stringify($expectedAudience)];
    }

    /**
     * The `aud` of a verified token must be, or contain, exactly this resource identifier. No prefix or case tolerance.
     * @return array{ok:bool, matched?:string, reason?:string}
     */
    public static function checkTokenAudience(mixed $aud, mixed $expectedResource): array
    {
        if (!self::nonEmpty($expectedResource)) {
            self::fail('checkTokenAudience: expectedResource is required');
        }
        if ($aud === null) {
            return ['ok' => false, 'reason' => 'token has no audience'];
        }
        $values = is_array($aud) && array_is_list($aud) ? $aud : [$aud];
        if ($values === []) {
            return ['ok' => false, 'reason' => 'token has an empty audience'];
        }
        if (in_array($expectedResource, $values, true)) {
            return ['ok' => true, 'matched' => $expectedResource];
        }
        return ['ok' => false, 'reason' => 'token audience ' . Js::stringify($aud) . ' does not include resource ' . Js::stringify($expectedResource)];
    }

    /** @return array{path:string, body:Obj, rfcPath:string} the path and body to serve the RFC 9728 document */
    public static function oauthDiscoveryHandler(mixed $o): array
    {
        $body = self::protectedResourceMetadata($o);
        $r = Js::opt($o, 'resource');
        $path = self::resourceIdentifierProblem($r) === null ? self::prmPathForResource($r) : self::WELL_KNOWN_OAUTH_PRM;
        return ['path' => $path, 'body' => $body, 'rfcPath' => $path];
    }

    /** The complete MCP / OAuth 401: status, the WWW-Authenticate header and a JSON body echoing the error and the PRM pointer. */
    public static function mcpUnauthorized(mixed $prmUrl, mixed $o = null): array
    {
        $body = ['error' => Js::opt($o, 'error') ?? 'invalid_request', 'resource_metadata' => $prmUrl];
        if (Js::truthy(Js::opt($o, 'errorDescription'))) {
            $body['error_description'] = Js::opt($o, 'errorDescription');
        }
        return ['status' => 401, 'headers' => ['WWW-Authenticate' => self::wwwAuthenticate($prmUrl, $o)], 'body' => $body];
    }

    /**
     * Upgrade a verifier deny result's 401: its existing PCA challenge (`wwwAuthenticate`) is kept verbatim and the Bearer
     * resource_metadata challenge is prepended. Every other member is preserved.
     */
    public static function upgradeUnauthorizedChallenge(Obj|array $result, mixed $prmUrl, mixed $o = null): Obj|array
    {
        $existing = Js::opt($result, 'wwwAuthenticate');
        $opts = $o;
        if (Js::truthy($existing)) {
            if ($o instanceof Obj) {
                $opts = $o->without();
                $opts->set('pcaChallenge', $existing);
            } else {
                $opts = is_array($o) ? $o : [];
                $opts['pcaChallenge'] = $existing;
            }
        }
        $header = self::wwwAuthenticate($prmUrl, $opts);
        if ($result instanceof Obj) {
            $r = $result->without();
            $r->set('wwwAuthenticate', $header);
            return $r;
        }
        $result['wwwAuthenticate'] = $header;
        return $result;
    }

    // ---- pca_grant (RFC 9396) ----

    /** A validated `pca_grant` detail. Options: chainIds (root first), chainRef, bundleRevision, locations. */
    public static function buildPcaGrantDetail(mixed $o): Obj
    {
        $ids = Js::opt($o, 'chainIds');
        if (!Js::isStrList($ids)) {
            self::fail('buildPcaGrantDetail: chainIds must be a string[]');
        }
        $d = Obj::of(['type' => PcaGrant::TYPE, 'chain_digest' => PcaGrant::chainDigest($ids), 'chain_len' => count($ids)]);
        foreach (['chainRef' => 'chain_ref', 'bundleRevision' => 'bundle_revision'] as $k => $w) {
            if (Js::opt($o, $k) !== null) {
                $d->set($w, Js::opt($o, $k));
            }
        }
        if (Js::opt($o, 'locations') !== null) {
            $d->set('locations', Js::spread(Js::opt($o, 'locations')));
        }
        $code = PcaGrant::validate($d);
        if ($code !== null) {
            self::fail("buildPcaGrantDetail: refused ($code)");
        }
        return $d;
    }

    /** The form-encoded value of the `authorization_details` request parameter (RFC 9396 section 3). */
    public static function pcaGrantRequestParam(array $details): string
    {
        return Js::encodeURIComponent(Js::stringify($details));
    }

    /**
     * Gate an access token carrying pca_grant details. Options: authorizationDetails, resource, chainIds, proofVerified.
     * Allow only with well-formed details naming a prefix of the presented chain and this resource AND a verified proof.
     * A token alone is never sufficient. This does not authenticate the token.
     */
    public static function authorizePcaGrantToken(mixed $o): array
    {
        [$details, $code] = PcaGrant::parse(Js::opt($o, 'authorizationDetails'));
        if ($code !== null) {
            return ['allow' => false, 'status' => 401, 'error' => 'invalid_token', 'code' => $code];
        }
        $resource = Js::opt($o, 'resource');
        $chain = Js::opt($o, 'chainIds');
        if (!is_string($resource) || !Js::isStrList($chain)) {
            self::fail('authorizePcaGrantToken: resource and chainIds are required');
        }
        [$idx, $code] = PcaGrant::check($details, $resource, $chain, Js::opt($o, 'proofVerified'));
        if ($code === null) {
            return ['allow' => true, 'detail' => $details[$idx]];
        }
        $loc = $code === 'wrong_location';
        return ['allow' => false, 'status' => $loc ? 403 : 401, 'error' => $loc ? 'insufficient_scope' : 'invalid_token', 'code' => $code];
    }

    // ---- scopes derived from the confirmed action ----

    /** deriveActionScopes: upstream.scopes_min of a confirmed action, inside `granted` when given; else a refusal code. */
    public static function deriveActionScopes(mixed $action, mixed $o = null): array
    {
        if (!($action instanceof Obj) && !is_array($action)) {
            return ['ok' => false, 'code' => 'unknown_action'];
        }
        if (Js::opt($action, 'confirmed') !== true) {
            return ['ok' => false, 'code' => 'unconfirmed'];
        }
        $up = Js::opt($action, 'upstream');
        $provider = Js::opt($o, 'provider');
        if ($provider !== null && Js::opt($up, 'provider') !== $provider) {
            return ['ok' => false, 'code' => 'provider_mismatch'];
        }
        $min = Js::opt($up, 'scopes_min');
        if (!is_array($min) || !array_is_list($min) || $min === []) {
            return ['ok' => false, 'code' => 'no_scopes'];
        }
        foreach ($min as $s) {
            if (!is_string($s) || Js::len($s) > 256 || preg_match(self::SCOPE_TOKEN, $s) !== 1) {
                return ['ok' => false, 'code' => 'bad_scope'];
            }
        }
        $scopes = array_values(array_unique($min));
        sort($scopes, SORT_STRING); // the tokens are ASCII: byte order is the JS UTF-16 order
        $granted = Js::opt($o, 'granted');
        if ($granted !== null) {
            $g = is_array($granted) ? $granted : [];
            foreach ($scopes as $s) {
                if (!in_array($s, $g, true)) {
                    return ['ok' => false, 'code' => 'exceeds_grant'];
                }
            }
        }
        return ['ok' => true, 'scopes' => $scopes, 'provider' => Js::opt($up, 'provider'), 'def_digest' => Js::opt($action, 'def_digest')];
    }

    /** The `scope` (and RFC 8707 `resource`) an OAuth client should request for one action. Options: provider, granted, resource. */
    public static function oauthScopeForAction(mixed $action, mixed $o): array
    {
        $d = self::deriveActionScopes($action, ['provider' => Js::opt($o, 'provider'), 'granted' => Js::opt($o, 'granted')]);
        if ($d['ok'] !== true) {
            return ['ok' => false, 'code' => $d['code']];
        }
        $r = ['ok' => true, 'scope' => implode(' ', $d['scopes']), 'scopes' => $d['scopes']];
        if (Js::opt($o, 'resource') !== null) {
            $r['resource'] = Js::opt($o, 'resource');
        }
        return $r;
    }

    /** The default fetchDiscovery transport's timeout, in seconds. */
    public const DISCOVERY_TIMEOUT_SEC = 5;
}
