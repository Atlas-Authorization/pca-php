<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/WhatwgUrl.php';
require_once __DIR__ . '/Explain.php';
require_once __DIR__ . '/SafeRegex.php';
require_once __DIR__ . '/Siem.php';
require_once __DIR__ . '/Connect.php';
require_once __DIR__ . '/ConnectorsProviders.php';

/** Base class of every runtime refusal of the connector catalog. */
class ConnectorError extends \RuntimeException
{
}

/** A manifest failed structural validation; `issues` lists every problem found. */
final class ManifestValidationError extends ConnectorError
{
    /** @var list<string> */
    public readonly array $issues;

    /** @param list<string> $issues */
    public function __construct(array $issues)
    {
        parent::__construct('invalid provider manifest: ' . implode('; ', $issues));
        $this->issues = array_values($issues);
    }
}

/** No manifest is registered for the requested provider id. */
final class UnknownProviderError extends ConnectorError
{
    public function __construct(public readonly mixed $providerId)
    {
        parent::__construct("no connector registered for provider '" . Jsx::str($providerId) . "'");
    }
}

/** A mutable collection of provider manifests, keyed by id; a manifest is validated on the way in. */
final class ProviderRegistry
{
    /** @var array<string,Obj> 'k'.id => manifest */
    private array $byId = [];

    /**
     * Validate and register a manifest. A duplicate id needs `replace: true`; `expectedDigest` pins the manifest you reviewed.
     * `$opts` is an Obj or an assoc array {replace?, expectedDigest?}. Returns the validated manifest.
     */
    public function register(mixed $manifest, mixed $opts = null): Obj
    {
        $valid = Connectors::assertManifest($manifest);
        $id = (string)$valid->get('id');
        $expected = Js::opt($opts, 'expectedDigest');
        if ($expected !== null && Connectors::manifestDigest($valid) !== $expected) {
            throw new ConnectorError("manifest '$id' does not match the pinned digest");
        }
        if (isset($this->byId['k' . $id]) && Js::opt($opts, 'replace') !== true) {
            throw new ConnectorError("provider '$id' is already registered; pass { replace: true } to replace it deliberately");
        }
        $this->byId['k' . $id] = $valid;
        return $valid;
    }

    public function get(mixed $id): ?Obj
    {
        return is_string($id) ? ($this->byId['k' . $id] ?? null) : null;
    }

    public function require(mixed $id): Obj
    {
        return $this->get($id) ?? throw new UnknownProviderError($id);
    }

    public function has(mixed $id): bool
    {
        return $this->get($id) !== null;
    }

    /** @return list<Obj> every manifest in ascending id order (UTF-16 code units) */
    public function list(): array
    {
        $all = array_values($this->byId);
        usort($all, static fn(Obj $a, Obj $b) => strcmp((string)mb_convert_encoding((string)$a->get('id'), 'UTF-16BE', 'UTF-8'),
            (string)mb_convert_encoding((string)$b->get('id'), 'UTF-16BE', 'UTF-8')));
        return $all;
    }

    /** @return list<string> */
    public function ids(): array
    {
        return array_map(static fn(Obj $m) => (string)$m->get('id'), $this->list());
    }
}

/**
 * A declarative catalog of outbound OAuth connectors for the token vault (the reference's pca-connectors): manifest validation and
 * digests, the provider registry, the authorize URL with PKCE and URL variables, access-token placement, authorization-code exchange and
 * refresh into the vault ({@see TokenVault}), and the manifest-to-vault-provider mapping. Manifests and option bags are Obj values (or
 * assoc arrays) with the reference's member names; injected transports are callables (`fetch(string $url, Obj $init)` returning an object
 * with `ok`, `status`, `json()` and `text()`).
 */
final class Connectors
{
    public const RESERVED_AUTHORIZE_PARAMS = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'code_challenge', 'code_challenge_method'];
    public const RESERVED_TOKEN_PARAMS = ['grant_type', 'code', 'redirect_uri', 'client_id', 'client_secret', 'code_verifier', 'refresh_token'];
    private const ID_SOURCE = '^[a-z0-9][a-z0-9._-]*$';
    private const TOKEN_PLACEMENTS = ['bearer', 'header', 'query'];
    private const REFRESH_MODES = ['refresh_token', 'none'];
    private const CLIENT_AUTHS = ['post', 'basic'];
    private const FORBIDDEN_HEADERS = ['host', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'cookie', 'set-cookie'];
    private const VAR = '/\{([A-Za-z0-9_]+)\}/';
    private const DEFAULT_TOKEN_LIFETIME_MS = 3_600_000;
    private const MIN_STATE_CHARS = 16;

    private static ?ProviderRegistry $default = null;

    private static function undef(): Undef
    {
        Jsx::init();
        return Jsx::$U;
    }

    /** Own property `k` of a record; the sentinel for an absent member. */
    private static function prop(mixed $o, string $k): mixed
    {
        return Jsx::get($o, $k);
    }

    private static function nonEmpty(mixed $v): bool
    {
        return is_string($v) && $v !== '';
    }

    private static function strRecord(mixed $v): bool
    {
        if (!$v instanceof Obj) {
            return false;
        }
        foreach ($v->keys() as $k) {
            if (!is_string($v->get($k))) {
                return false;
            }
        }
        return true;
    }

    private static function lower(string $s): string
    {
        return mb_strtolower($s, 'UTF-8');
    }

    private static function wsOrComma(string $s): bool
    {
        return preg_match('/' . Siem::WS . '|,/', $s) === 1;
    }

    private static function isHttpsUrl(mixed $v): bool
    {
        if (!is_string($v) || !str_starts_with($v, 'https://')) {
            return false;
        }
        $replaced = (string)preg_replace(self::VAR, 'x', $v);
        $u = WhatwgUrl::parse($replaced);
        if ($u === null) {
            return false;
        }
        [$userinfo, $hash] = Connect::urlFacts($replaced);
        if (($u['scheme'] ?? '') !== 'https' || $userinfo || $hash) {
            return false;
        }
        $rawHost = (preg_split('~[/?#]~', substr($v, 8), 2) ?: [''])[0];
        return preg_match('/\A\{[A-Za-z0-9_]+\}(?::[0-9]+)?\z/', $rawHost) !== 1;
    }

    /** @return list<string> */
    private static function urlVars(string $url): array
    {
        preg_match_all(self::VAR, $url, $m);
        return $m[1];
    }

    /** @return list<mixed> */
    private static function unique(array $list): array
    {
        $out = [];
        foreach ($list as $x) {
            if (!in_array($x, $out, true)) {
                $out[] = $x;
            }
        }
        return $out;
    }

    // ---- manifest -------------------------------------------------------------------------------------------------------------

    /**
     * Structurally validate an untrusted value as a provider manifest: every problem is collected, no partial acceptance.
     *
     * @return array{ok:true,manifest:Obj}|array{ok:false,issues:list<string>}
     */
    public static function validateManifest(mixed $input): array
    {
        $issues = [];
        if (!$input instanceof Obj) {
            return ['ok' => false, 'issues' => ['manifest must be an object']];
        }
        $id = self::prop($input, 'id');
        if (!self::nonEmpty($id)) {
            $issues[] = 'id must be a non-empty string';
        } elseif (preg_match('/\A[a-z0-9][a-z0-9._-]*\z/', $id) !== 1) {
            $issues[] = "id '$id' must be lowercase and match " . self::ID_SOURCE;
        }
        if (!self::nonEmpty(self::prop($input, 'displayName'))) {
            $issues[] = 'displayName must be a non-empty string';
        }
        $authorizeUrl = self::prop($input, 'authorizeUrl');
        if (!self::isHttpsUrl($authorizeUrl)) {
            $issues[] = 'authorizeUrl must be an https:// URL';
        }
        $tokenUrl = self::prop($input, 'tokenUrl');
        if (!self::isHttpsUrl($tokenUrl)) {
            $issues[] = 'tokenUrl must be an https:// URL';
        }
        $scopesAvailable = self::prop($input, 'scopesAvailable');
        if (!Js::isStrList($scopesAvailable)) {
            $issues[] = 'scopesAvailable must be an array of strings';
        }
        $defaultScopes = self::prop($input, 'defaultScopes');
        if (!Js::isStrList($defaultScopes)) {
            $issues[] = 'defaultScopes must be an array of strings';
        }
        foreach ([['scopesAvailable', $scopesAvailable], ['defaultScopes', $defaultScopes]] as [$name, $list]) {
            if (Js::isStrList($list)) {
                foreach ($list as $s) {
                    if ($s === '' || self::wsOrComma($s)) {
                        $issues[] = "$name entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)";
                        break;
                    }
                }
                if (count(self::unique($list)) !== count($list)) {
                    $issues[] = "$name must not contain duplicates";
                }
            }
        }
        if (Js::isStrList($scopesAvailable) && Js::isStrList($defaultScopes) && count($scopesAvailable) > 0) {
            $missing = array_values(array_filter($defaultScopes, static fn($s) => !in_array($s, $scopesAvailable, true)));
            if ($missing !== []) {
                $issues[] = 'defaultScopes must be a subset of scopesAvailable (unknown: ' . implode(', ', $missing) . ')';
            }
        }

        $refresh = self::prop($input, 'refresh');
        if (!$refresh instanceof Obj) {
            $issues[] = 'refresh must be an object';
        } else {
            $mode = self::prop($refresh, 'mode');
            if (!is_string($mode) || !in_array($mode, self::REFRESH_MODES, true)) {
                $issues[] = 'refresh.mode must be one of ' . implode(' | ', self::REFRESH_MODES);
            }
            $te = self::prop($refresh, 'tokenEndpoint');
            if (!Jsx::isUndef($te) && !self::isHttpsUrl($te)) {
                $issues[] = 'refresh.tokenEndpoint, when present, must be an https:// URL';
            }
            $sn = self::prop($refresh, 'supportsScopeNarrowing');
            if (!Jsx::isUndef($sn) && !is_bool($sn)) {
                $issues[] = 'refresh.supportsScopeNarrowing must be a boolean';
            }
            $ep = self::prop($refresh, 'extraParams');
            if (!Jsx::isUndef($ep) && !self::strRecord($ep)) {
                $issues[] = 'refresh.extraParams must be a string→string map';
            } elseif (self::strRecord($ep)) {
                foreach (Js::ownKeys($ep->keys()) as $k) {
                    if (in_array($k, self::RESERVED_TOKEN_PARAMS, true)) {
                        $issues[] = "refresh.extraParams may not set '$k': the request builder owns it";
                    }
                }
            }
        }

        $placement = self::prop($input, 'tokenPlacement');
        if (!is_string($placement) || !in_array($placement, self::TOKEN_PLACEMENTS, true)) {
            $issues[] = 'tokenPlacement must be one of ' . implode(' | ', self::TOKEN_PLACEMENTS);
        } elseif ($placement === 'header' && !self::nonEmpty(self::prop($input, 'headerName'))) {
            $issues[] = "tokenPlacement 'header' requires a non-empty headerName";
        } elseif ($placement === 'query' && !self::nonEmpty(self::prop($input, 'queryParam'))) {
            $issues[] = "tokenPlacement 'query' requires a non-empty queryParam";
        }
        $headerName = self::prop($input, 'headerName');
        if (is_string($headerName) && (preg_match('/\A[A-Za-z0-9][A-Za-z0-9-]*\z/', $headerName) !== 1 || in_array(self::lower($headerName), self::FORBIDDEN_HEADERS, true))) {
            $issues[] = "headerName '$headerName' must be an HTTP token and not a protocol header";
        }
        $queryParam = self::prop($input, 'queryParam');
        if (is_string($queryParam) && preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]*\z/', $queryParam) !== 1) {
            $issues[] = "queryParam '$queryParam' must be a plain parameter name";
        }
        $sepRaw = self::prop($input, 'scopeSeparator');
        if (is_string($sepRaw) && $sepRaw === '') {
            $issues[] = 'scopeSeparator must not be empty';
        }
        $pkce = self::prop($input, 'pkce');
        if (!Jsx::isUndef($pkce) && !is_bool($pkce)) {
            $issues[] = 'pkce must be a boolean';
        }
        $scopeSeparator = self::prop($input, 'scopeSeparator');
        if (!Jsx::isUndef($scopeSeparator) && !is_string($scopeSeparator)) {
            $issues[] = 'scopeSeparator must be a string';
        }
        $authParams = self::prop($input, 'authParams');
        if (!Jsx::isUndef($authParams) && !self::strRecord($authParams)) {
            $issues[] = 'authParams must be a string→string map';
        } elseif (self::strRecord($authParams)) {
            foreach (Js::ownKeys($authParams->keys()) as $k) {
                if (in_array($k, self::RESERVED_AUTHORIZE_PARAMS, true)) {
                    $issues[] = "authParams may not set '$k': the request builder owns it";
                }
            }
        }
        $clientAuth = self::prop($input, 'clientAuth');
        if (!Jsx::isUndef($clientAuth) && (!is_string($clientAuth) || !in_array($clientAuth, self::CLIENT_AUTHS, true))) {
            $issues[] = 'clientAuth must be one of ' . implode(' | ', self::CLIENT_AUTHS);
        }
        $requiredVars = self::prop($input, 'requiredVars');
        if (!Jsx::isUndef($requiredVars) && !Js::isStrList($requiredVars)) {
            $issues[] = 'requiredVars must be an array of strings';
        }
        // every `{var}` that appears in a URL must be declared, and vice versa, so substitution never leaves a placeholder in a live request
        if (self::isHttpsUrl($authorizeUrl) && self::isHttpsUrl($tokenUrl)) {
            $declared = self::unique(Js::isStrList($requiredVars) ? $requiredVars : []);
            $used = self::unique([...self::urlVars($authorizeUrl), ...self::urlVars($tokenUrl)]);
            foreach ($used as $v) {
                if (!in_array($v, $declared, true)) {
                    $issues[] = "url uses '{" . $v . "}' but requiredVars does not declare it";
                }
            }
            foreach ($declared as $v) {
                if (!in_array($v, $used, true)) {
                    $issues[] = "requiredVars declares '$v' but no URL uses '{" . $v . "}'";
                }
            }
        }
        $docsUrl = self::prop($input, 'docsUrl');
        if (!Jsx::isUndef($docsUrl) && !is_string($docsUrl)) {
            $issues[] = 'docsUrl must be a string';
        }
        if ($issues !== []) {
            return ['ok' => false, 'issues' => $issues];
        }
        return ['ok' => true, 'manifest' => self::freezeManifest($input)];
    }

    private static function copyObj(Obj $o): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $o->get($k));
        }
        return $c;
    }

    private static function freezeManifest(Obj $input): Obj
    {
        $raw = self::prop($input, 'refresh');
        $rr = $raw instanceof Obj ? $raw : new Obj();
        $refresh = Obj::of(['mode' => self::prop($rr, 'mode') === 'none' ? 'none' : 'refresh_token']);
        $te = self::prop($rr, 'tokenEndpoint');
        if (is_string($te)) {
            $refresh->set('tokenEndpoint', $te);
        }
        $sn = self::prop($rr, 'supportsScopeNarrowing');
        if (is_bool($sn)) {
            $refresh->set('supportsScopeNarrowing', $sn);
        }
        $ep = self::prop($rr, 'extraParams');
        if (self::strRecord($ep)) {
            $refresh->set('extraParams', self::copyObj($ep));
        }
        $str = static fn(mixed $v): string => is_string($v) ? $v : '';
        $list = static fn(mixed $v): array => Js::isStrList($v) ? array_values($v) : [];
        $tp = self::prop($input, 'tokenPlacement');
        $m = Obj::of([
            'id' => $str(self::prop($input, 'id')), 'displayName' => $str(self::prop($input, 'displayName')),
            'authorizeUrl' => $str(self::prop($input, 'authorizeUrl')), 'tokenUrl' => $str(self::prop($input, 'tokenUrl')),
            'scopesAvailable' => $list(self::prop($input, 'scopesAvailable')), 'defaultScopes' => $list(self::prop($input, 'defaultScopes')),
            'refresh' => $refresh, 'tokenPlacement' => $tp === 'header' ? 'header' : ($tp === 'query' ? 'query' : 'bearer'),
        ]);
        $pkce = self::prop($input, 'pkce');
        if (is_bool($pkce)) {
            $m->set('pkce', $pkce);
        }
        $sep = self::prop($input, 'scopeSeparator');
        if (is_string($sep)) {
            $m->set('scopeSeparator', $sep);
        }
        $ap = self::prop($input, 'authParams');
        if (self::strRecord($ap)) {
            $m->set('authParams', self::copyObj($ap));
        }
        $ca = self::prop($input, 'clientAuth');
        if ($ca === 'post' || $ca === 'basic') {
            $m->set('clientAuth', $ca);
        }
        $hn = self::prop($input, 'headerName');
        if (is_string($hn)) {
            $m->set('headerName', $hn);
        }
        $qp = self::prop($input, 'queryParam');
        if (is_string($qp)) {
            $m->set('queryParam', $qp);
        }
        $rv = self::prop($input, 'requiredVars');
        if (Js::isStrList($rv)) {
            $m->set('requiredVars', array_values($rv));
        }
        $du = self::prop($input, 'docsUrl');
        if (is_string($du)) {
            $m->set('docsUrl', $du);
        }
        return $m;
    }

    /** Validate `$input`, returning the manifest or throwing {@see ManifestValidationError}. */
    public static function assertManifest(mixed $input): Obj
    {
        $r = self::validateManifest($input);
        if (!$r['ok']) {
            throw new ManifestValidationError($r['issues']);
        }
        return $r['manifest'];
    }

    /** The content address of a validated manifest: a pinned digest detects a swapped endpoint. */
    public static function manifestDigest(mixed $manifest): string
    {
        return Pca::hashCanonical($manifest);
    }

    // ---- registry -------------------------------------------------------------------------------------------------------------

    public static function createDefaultRegistry(): ProviderRegistry
    {
        $r = new ProviderRegistry();
        foreach (ConnectorsProviders::manifests() as $m) {
            $r->register($m);
        }
        return $r;
    }

    public static function defaultRegistry(): ProviderRegistry
    {
        return self::$default ??= self::createDefaultRegistry();
    }

    public static function registerProvider(mixed $manifest, mixed $opts = null): Obj
    {
        return self::defaultRegistry()->register($manifest, $opts);
    }

    public static function getProvider(mixed $id): ?Obj
    {
        return self::defaultRegistry()->get($id);
    }

    /** @return list<Obj> */
    public static function listProviders(): array
    {
        return self::defaultRegistry()->list();
    }

    /** One digest over the whole catalog (id and manifest digest, in id order). */
    public static function catalogDigest(?ProviderRegistry $registry = null): string
    {
        $rows = [];
        foreach (($registry ?? self::defaultRegistry())->list() as $m) {
            $rows[] = [$m->get('id'), self::manifestDigest($m)];
        }
        return Pca::hashCanonical($rows);
    }

    private static function registryOf(mixed $o): ProviderRegistry
    {
        $r = Js::opt($o, 'registry');
        return $r instanceof ProviderRegistry ? $r : self::defaultRegistry();
    }

    // ---- authorize URL, PKCE, URL variables and token placement ------------------------------------------------------------

    /** The PKCE challenge of a verifier: S256 (base64url of its SHA-256), or the verifier itself for "plain". */
    public static function pkceChallenge(mixed $verifier, mixed $method = 'S256'): mixed
    {
        if ($method === 'plain') {
            return $verifier;
        }
        return Pca::b64u(hash('sha256', Js::utf8(Jsx::str($verifier)), true));
    }

    /** Fill `{name}` placeholders from `$vars`; each value must be a single DNS label so a value can never change the host. */
    public static function substituteVars(mixed $url, mixed $vars = null): string
    {
        if (func_num_args() < 2) {
            $vars = self::undef();
        }
        return (string)preg_replace_callback(self::VAR, static function (array $m) use ($vars): string {
            if ($vars === null) {
                throw new \TypeError('Cannot convert undefined or null to object');
            }
            $v = Jsx::isUndef($vars) ? $vars : Jsx::get($vars, $m[1]);
            if (Jsx::isUndef($v)) {
                throw new ConnectorError("missing URL variable '{" . $m[1] . "}'");
            }
            if (!is_string($v) || preg_match('/\A[A-Za-z0-9][A-Za-z0-9-]{0,62}\z/', $v) !== 1) {
                throw new ConnectorError("URL variable '{" . $m[1] . "}' must be a single DNS label (letters, digits and hyphens)");
            }
            return $v;
        }, Js::str($url));
    }

    /** @param list<array{0:mixed,1:mixed}> $pairs */
    private static function encodeForm(array $pairs): string
    {
        $out = [];
        foreach ($pairs as [$k, $v]) {
            $out[] = Js::encodeURIComponent(Jsx::str($k)) . '=' . Js::encodeURIComponent(Jsx::str($v));
        }
        return implode('&', $out);
    }

    /** Object.entries of a record as [key, value] pairs (JS own-key order). @return list<array{0:string,1:mixed}> */
    private static function entries(mixed $o): array
    {
        $out = [];
        foreach (Jsx::keys($o) as $k) {
            $out[] = [$k, Jsx::get($o, $k)];
        }
        return $out;
    }

    /** @return array{hash:bool,creds:bool,protocol:string,hostname:string} */
    private static function urlInfo(string $text): array
    {
        $s = (string)preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', $text);
        $s = str_replace(["\t", "\n", "\r"], '', $s);
        if (preg_match('/\A([A-Za-z][A-Za-z0-9+.\-]*):/', $s, $m) !== 1) {
            throw new ConnectorError('buildAuthorizeUrl: redirectUri must be an absolute URL');
        }
        $scheme = strtolower($m[1]);
        if (in_array($scheme, ['http', 'https', 'ftp', 'ws', 'wss'], true)) {
            $u = WhatwgUrl::parse($s);
            if ($u === null) {
                throw new ConnectorError('buildAuthorizeUrl: redirectUri must be an absolute URL');
            }
            [$creds, $hash] = Connect::urlFacts($s);
            $host = (string)($u['host'] ?? '');
            $hostname = str_starts_with($host, '[') ? substr($host, 0, (int)strpos($host, ']') + 1) : (explode(':', $host, 2)[0]);
            return ['hash' => $hash, 'creds' => $creds, 'protocol' => $scheme . ':', 'hostname' => $hostname];
        }
        $rest = substr($s, strlen($m[0]));
        $h = strpos($rest, '#');
        $frag = $h === false ? '' : substr($rest, $h + 1);
        $creds = false;
        if (str_starts_with($rest, '//')) {
            $auth = (preg_split('~[/?#]~', substr($rest, 2), 2) ?: [''])[0];
            $at = strrpos($auth, '@');
            if ($at !== false) {
                $info = substr($auth, 0, $at);
                $c = strpos($info, ':');
                $creds = ($c === false ? $info : substr($info, 0, $c)) !== '' || ($c !== false && substr($info, $c + 1) !== '');
            }
        }
        return ['hash' => $frag !== '', 'creds' => $creds, 'protocol' => $scheme . ':', 'hostname' => ''];
    }

    private static function checkRedirectUri(mixed $uri): void
    {
        $u = self::urlInfo(Jsx::str($uri));
        if ($u['hash']) {
            throw new ConnectorError('buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)');
        }
        if ($u['creds']) {
            throw new ConnectorError('buildAuthorizeUrl: redirectUri must not carry credentials');
        }
        $local = in_array($u['hostname'], ['localhost', '127.0.0.1', '[::1]'], true);
        if ($u['protocol'] !== 'https:' && !($u['protocol'] === 'http:' && $local)) {
            throw new ConnectorError('buildAuthorizeUrl: redirectUri must be https (http only for localhost)');
        }
    }

    /** Every scope must be one token the manifest lists: a scope containing the separator would smuggle in another one. */
    private static function checkScopes(Obj $manifest, mixed $scopes, bool $allowUnlisted): void
    {
        if (!is_array($scopes) || !array_is_list($scopes)) {
            throw new ConnectorError('buildAuthorizeUrl: scopes must be a list');
        }
        $sepRaw = $manifest->get('scopeSeparator');
        $sep = $sepRaw ?? ' ';
        $seen = [];
        $available = $manifest->get('scopesAvailable');
        foreach ($scopes as $s) {
            if (!is_string($s) || $s === '' || self::wsOrComma($s) || str_contains($s, (string)$sep)) {
                throw new ConnectorError('buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator');
            }
            if (isset($seen['k' . $s])) {
                throw new ConnectorError("buildAuthorizeUrl: scope '$s' is listed twice");
            }
            $seen['k' . $s] = true;
            if (!$allowUnlisted && count($available) > 0 && !in_array($s, $available, true)) {
                throw new ConnectorError("buildAuthorizeUrl: scope '$s' is not offered by provider '" . $manifest->get('id') . "'");
            }
        }
    }

    /**
     * The authorization URL (RFC 6749 3.1, RFC 7636) for a registered provider: {url, state, pkce?}. `$options` (Obj or assoc array) carries
     * clientId, redirectUri, scopes, state, pkce (false, true or {verifier, method}), vars, registry, extraParams, allowUnlistedScopes and
     * allowPlainPkce. A random state / PKCE verifier is generated when none is given.
     */
    public static function buildAuthorizeUrl(mixed $providerId, mixed $options): Obj
    {
        $manifest = self::registryOf($options)->require($providerId);
        $scopes = Jsx::get($options, 'scopes');
        if ($scopes === null || Jsx::isUndef($scopes)) {
            $scopes = $manifest->get('defaultScopes');
        }
        $separator = $manifest->get('scopeSeparator') ?? ' ';
        $state = Jsx::get($options, 'state');
        if ($state === null || Jsx::isUndef($state)) {
            $state = Pca::b64u(random_bytes(32));
        }
        $clientId = Jsx::get($options, 'clientId');
        if (!is_string($clientId) || $clientId === '') {
            throw new ConnectorError('buildAuthorizeUrl: clientId must be a non-empty string');
        }
        $redirect = Jsx::get($options, 'redirectUri');
        self::checkRedirectUri($redirect);
        if (!is_string($state) || SafeRegex::utf16Len($state) < self::MIN_STATE_CHARS) {
            throw new ConnectorError('buildAuthorizeUrl: state must be at least ' . self::MIN_STATE_CHARS . ' characters (omit it to get a random one)');
        }
        self::checkScopes($manifest, $scopes, Js::opt($options, 'allowUnlistedScopes') === true);
        $extra = Jsx::get($options, 'extraParams');
        if ($extra === null || Jsx::isUndef($extra)) {
            $extra = new Obj();
        } elseif (is_string($extra)) { // Object.keys / Object.entries of a string are its character indexes
            $chars = new Obj();
            $i = 0;
            // Object.entries of a string walks UTF-16 code units: an astral character is two lone surrogates (WTF-8 here), which the form encoder refuses
            preg_match_all('/\xED[\xA0-\xBF][\x80-\xBF]|[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF4][\x80-\xBF]{3}|[\x80-\xFF]/', $extra, $units);
            foreach ($units[0] as $ch) {
                if (strlen($ch) === 4) {
                    $cp = ((ord($ch[0]) & 7) << 18) | ((ord($ch[1]) & 63) << 12) | ((ord($ch[2]) & 63) << 6) | (ord($ch[3]) & 63);
                    $cp -= 0x10000;
                    foreach ([0xD800 | ($cp >> 10), 0xDC00 | ($cp & 0x3FF)] as $u) {
                        $chars->set((string)$i++, chr(0xE0 | ($u >> 12)) . chr(0x80 | (($u >> 6) & 0x3F)) . chr(0x80 | ($u & 0x3F)));
                    }
                } else {
                    $chars->set((string)$i++, $ch);
                }
            }
            $extra = $chars;
        }
        foreach (Jsx::keys($extra) as $k) {
            if (in_array($k, self::RESERVED_AUTHORIZE_PARAMS, true)) {
                throw new ConnectorError("buildAuthorizeUrl: extraParams may not set '$k'");
            }
        }
        $params = [['response_type', 'code'], ['client_id', $clientId], ['redirect_uri', $redirect]];
        if (count($scopes) > 0) {
            $params[] = ['scope', implode((string)$separator, $scopes)];
        }
        $params[] = ['state', $state];

        $pk = Jsx::get($options, 'pkce');
        $want = $pk === false ? false : (!Jsx::isUndef($pk) ? true : $manifest->get('pkce') === true);
        $pkce = null;
        if ($want) {
            if ($pk === null) {
                throw new \TypeError('Cannot read properties of null');
            }
            if ($pk instanceof Obj || (is_array($pk))) { // typeof 'object'
                $verifier = Jsx::get($pk, 'verifier');
                $method = Jsx::get($pk, 'method');
                $method = $method === null || Jsx::isUndef($method) ? 'S256' : $method;
            } else {
                $verifier = Pca::b64u(random_bytes(32));
                $method = 'S256';
            }
            if (preg_match('/\A[A-Za-z0-9._~-]{43,128}\z/', Jsx::str($verifier)) !== 1) {
                throw new ConnectorError('buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)');
            }
            if ($method !== 'S256' && !($method === 'plain' && Js::opt($options, 'allowPlainPkce') === true)) {
                throw new ConnectorError("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')");
            }
            $challenge = self::pkceChallenge($verifier, $method);
            $params[] = ['code_challenge', $challenge];
            $params[] = ['code_challenge_method', $method];
            $pkce = Obj::of(['verifier' => $verifier, 'challenge' => $challenge, 'method' => $method]);
        }
        $ap = $manifest->get('authParams');
        foreach (self::entries($ap ?? new Obj()) as $kv) {
            $params[] = $kv;
        }
        foreach (self::entries($extra) as $kv) {
            $params[] = $kv;
        }
        $base = self::substituteVars($manifest->get('authorizeUrl'), Jsx::get($options, 'vars'));
        $out = Obj::of(['url' => $base . (str_contains($base, '?') ? '&' : '?') . self::encodeForm($params), 'state' => $state]);
        if ($pkce !== null) {
            $out->set('pkce', $pkce);
        }
        return $out;
    }

    /** How to present an access token: {kind: "header" | "query", name, value}. The token must be printable ASCII without spaces. */
    public static function applyAccessToken(mixed $manifest, mixed $accessToken): ?Obj
    {
        if (!is_string($accessToken) || $accessToken === '' || preg_match('/[^\x21-\x7e]/', $accessToken) === 1) {
            throw new ConnectorError('applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces');
        }
        $placement = Jsx::rd($manifest, 'tokenPlacement');
        if ($placement === 'bearer') {
            return Obj::of(['kind' => 'header', 'name' => 'Authorization', 'value' => "Bearer $accessToken"]);
        }
        if ($placement === 'header') {
            $hn = Jsx::get($manifest, 'headerName');
            if (Jsx::isUndef($hn)) {
                throw new ConnectorError("manifest '" . Jsx::str(Jsx::get($manifest, 'id')) . "' is header-placed but has no headerName");
            }
            return Obj::of(['kind' => 'header', 'name' => $hn, 'value' => $accessToken]);
        }
        if ($placement === 'query') {
            $qp = Jsx::get($manifest, 'queryParam');
            if (Jsx::isUndef($qp)) {
                throw new ConnectorError("manifest '" . Jsx::str(Jsx::get($manifest, 'id')) . "' is query-placed but has no queryParam");
            }
            return Obj::of(['kind' => 'query', 'name' => $qp, 'value' => $accessToken]);
        }
        return null;
    }

    // ---- code exchange, refresh and the vault bridge ------------------------------------------------------------------------

    private static function redact(string $text, array $secrets): string
    {
        foreach ($secrets as $s) {
            if (is_string($s) && $s !== '') {
                $text = str_replace($s, '[redacted]', $text);
            }
        }
        return $text;
    }

    private static function checkExtraParams(mixed $extra, string $what): void
    {
        foreach (Jsx::keys($extra ?? new Obj()) as $k) {
            if (in_array($k, self::RESERVED_TOKEN_PARAMS, true)) {
                throw new ConnectorError("$what: extraParams may not set '$k'");
            }
        }
    }

    /** @return array{accessToken:string,refreshToken?:string,expiresInSecs?:float,scopes?:list<string>} */
    private static function parseTokenResponse(mixed $body, mixed $provider): array
    {
        if (!$body instanceof Obj) {
            throw new ConnectorError("[$provider] token endpoint returned a non-object body");
        }
        $at = $body->get('access_token');
        if (!is_string($at) || $at === '') {
            throw new ConnectorError("[$provider] token endpoint response has no access_token");
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
            $t = Connect::jsTrim($scope);
            if ($t !== '') {
                $out['scopes'] = preg_split('/(?:' . Siem::WS . '|,)+/', $t) ?: [];
            }
        }
        return $out;
    }

    /** POST a form to a token endpoint via the injectable transport and parse the response (fail-closed). */
    private static function postToken(Obj $manifest, mixed $tokenEndpoint, Obj $params, mixed $clientSecret, mixed $fetch): array
    {
        $id = (string)$manifest->get('id');
        $headers = Obj::of(['content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json']);
        $body = self::copyObj($params);
        if ($manifest->get('clientAuth') === 'basic') {
            // client credentials move to the Authorization header; they must not also appear in the body
            if (Jsx::isUndef($clientSecret)) {
                throw new ConnectorError("[$id] clientAuth 'basic' requires a clientSecret");
            }
            $clientId = $body->has('client_id') ? $body->get('client_id') : self::undef();
            if (Jsx::isUndef($clientId)) {
                throw new ConnectorError("[$id] missing client_id for basic auth");
            }
            $headers->set('authorization', 'Basic ' . base64_encode(Js::utf8(Jsx::str($clientId) . ':' . Jsx::str($clientSecret))));
            $body = $body->without('client_id', 'client_secret');
        }
        $secrets = [$clientSecret, $params->get('code'), $params->get('code_verifier'), $params->get('refresh_token'), $headers->get('authorization')];
        try {
            if (!is_callable($fetch)) {
                throw new \TypeError('fetchImpl is not a function');
            }
            $res = $fetch($tokenEndpoint, Obj::of(['method' => 'POST', 'headers' => $headers, 'body' => self::encodeForm(self::entries($body))]));
        } catch (\Throwable $e) {
            throw new ConnectorError("[$id] token transport error: " . self::redact($e->getMessage(), $secrets));
        }
        if (!$res->ok) {
            try {
                $detail = self::redact(Explain::slice16($res->text(), 0, 256), $secrets);
            } catch (\Throwable) {
                $detail = '<unreadable body>';
            }
            throw new ConnectorError("[$id] token endpoint " . Jsx::str($res->status) . ': ' . $detail);
        }
        try {
            $json = $res->json();
        } catch (\Throwable) {
            throw new ConnectorError("[$id] unparseable token JSON");
        }
        return self::parseTokenResponse($json, $id);
    }

    /** Store the token result in the vault, bound to the PCA capability authority. */
    private static function storeConnection(Obj $manifest, array $parsed, mixed $requested, mixed $bind, mixed $now, mixed $priorRefreshToken = null): Obj
    {
        $nowF = (float)Js::num($now);
        $expiresAt = Connect::num(isset($parsed['expiresInSecs']) ? $nowF + $parsed['expiresInSecs'] * 1000 : $nowF + self::DEFAULT_TOKEN_LIFETIME_MS);
        $granted = $parsed['scopes'] ?? $requested;
        $refreshToken = $parsed['refreshToken'] ?? $priorRefreshToken;
        $a = Jsx::rd($bind, 'authority');
        $authority = Obj::of(['principal' => Jsx::get($a, 'principal'), 'scopes' => Js::opt($a, 'scopes') ?? $requested]);
        $aud = Jsx::get($a, 'audience');
        if (!Jsx::isUndef($aud)) {
            $authority->set('audience', $aud);
        }
        $cid = Jsx::get($bind, 'connectionId');
        return Jsx::rd($bind, 'vault')->putConnection(Jsx::get($bind, 'agentId'), $manifest->get('id'), $parsed['accessToken'], $expiresAt, $granted, $authority,
            Jsx::isUndef($cid) ? null : $cid, $refreshToken);
    }

    private static function nowOf(mixed $args): mixed
    {
        return Js::opt($args, 'now') ?? (int)(self::clock() * 1000);
    }

    /**
     * Exchange an authorization code for tokens at the provider's token endpoint and store the connection in the vault. `$args` (Obj or assoc
     * array): providerId, clientId, clientSecret?, code, redirectUri, codeVerifier?, scopes?, fetch, bind {vault, agentId, connectionId?,
     * authority {principal, scopes?, audience?}}, now?, registry?, vars?, extraParams?. Returns the stored connection.
     */
    public static function exchangeCode(mixed $args): Obj
    {
        $manifest = self::registryOf($args)->require(Jsx::get($args, 'providerId'));
        $id = (string)$manifest->get('id');
        $now = self::nowOf($args);
        $requested = Js::opt($args, 'scopes') ?? $manifest->get('defaultScopes');
        $code = Jsx::get($args, 'code');
        if (!is_string($code) || $code === '') {
            throw new ConnectorError("[$id] an authorization code is required");
        }
        self::checkExtraParams(Js::opt($args, 'extraParams'), "[$id] exchangeCode");
        if ($manifest->get('pkce') === true && !Js::has($args, 'codeVerifier')) {
            throw new ConnectorError("[$id] provider uses PKCE; a codeVerifier is required to exchange the code");
        }
        $params = Obj::of(['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => Jsx::get($args, 'redirectUri'), 'client_id' => Jsx::get($args, 'clientId')]);
        if (Js::has($args, 'clientSecret')) {
            $params->set('client_secret', Js::opt($args, 'clientSecret'));
        }
        if (Js::has($args, 'codeVerifier')) {
            $params->set('code_verifier', Js::opt($args, 'codeVerifier'));
        }
        $extra = Js::opt($args, 'extraParams');
        if ($extra !== null) {
            foreach (self::entries($extra) as [$k, $v]) {
                $params->set($k, $v);
            }
        }
        $endpoint = self::substituteVars($manifest->get('tokenUrl'), Jsx::get($args, 'vars'));
        $parsed = self::postToken($manifest, $endpoint, $params, Jsx::get($args, 'clientSecret'), Js::opt($args, 'fetch'));
        return self::storeConnection($manifest, $parsed, $requested, Jsx::get($args, 'bind'), $now);
    }

    /**
     * Refresh a connection's tokens at the provider and store the result in the vault (the refresh token is kept unless the provider
     * rotates it). `$args` as for {@see exchangeCode}, with refreshToken in place of code, redirectUri and codeVerifier.
     */
    public static function refresh(mixed $args): Obj
    {
        $manifest = self::registryOf($args)->require(Jsx::get($args, 'providerId'));
        $id = (string)$manifest->get('id');
        $refresh = $manifest->get('refresh');
        if ($refresh->get('mode') === 'none') {
            throw new ConnectorError("[$id] provider does not support token refresh");
        }
        $now = self::nowOf($args);
        $requested = Js::opt($args, 'scopes') ?? $manifest->get('defaultScopes');
        $rt = Jsx::get($args, 'refreshToken');
        if (!is_string($rt) || $rt === '') {
            throw new ConnectorError("[$id] a refresh token is required");
        }
        self::checkExtraParams(Js::opt($args, 'extraParams'), "[$id] refresh");
        $params = Obj::of(['grant_type' => 'refresh_token', 'refresh_token' => $rt, 'client_id' => Jsx::get($args, 'clientId')]);
        if (Js::has($args, 'clientSecret')) {
            $params->set('client_secret', Js::opt($args, 'clientSecret'));
        }
        $mx = $refresh->get('extraParams');
        if ($mx instanceof Obj) {
            foreach ($mx->keys() as $k) {
                $params->set($k, $mx->get($k));
            }
        }
        $extra = Js::opt($args, 'extraParams');
        if ($extra !== null) {
            foreach (self::entries($extra) as [$k, $v]) {
                $params->set($k, $v);
            }
        }
        if ($refresh->get('supportsScopeNarrowing') === true && count($requested) > 0) {
            $params->set('scope', implode((string)($manifest->get('scopeSeparator') ?? ' '), $requested));
        }
        $endpoint = self::substituteVars($refresh->get('tokenEndpoint') ?? $manifest->get('tokenUrl'), Jsx::get($args, 'vars'));
        $parsed = self::postToken($manifest, $endpoint, $params, Jsx::get($args, 'clientSecret'), Js::opt($args, 'fetch'));
        return self::storeConnection($manifest, $parsed, $requested, Jsx::get($args, 'bind'), $now, $rt);
    }

    /** The vault's token-endpoint configuration for a refreshable manifest (`$creds`: clientId, clientSecret?, vars?). */
    public static function manifestToProviderConfig(mixed $manifest, mixed $creds): Obj
    {
        $refresh = Jsx::rd($manifest, 'refresh');
        if (Jsx::rd($refresh, 'mode') === 'none') {
            throw new ConnectorError('[' . Jsx::str(Jsx::get($manifest, 'id')) . '] provider does not support token refresh; no ProviderConfig');
        }
        $te = Jsx::get($refresh, 'tokenEndpoint');
        $config = new Obj();
        $config->set('tokenEndpoint', self::substituteVars(Jsx::isUndef($te) ? Jsx::get($manifest, 'tokenUrl') : $te, Jsx::get($creds, 'vars')));
        $cid = Jsx::get($creds, 'clientId');
        if (!Jsx::isUndef($cid)) {
            $config->set('clientId', $cid);
        }
        if (Js::has($creds, 'clientSecret')) {
            $config->set('clientSecret', Js::opt($creds, 'clientSecret'));
        }
        if (Js::has($refresh, 'supportsScopeNarrowing')) {
            $config->set('supportsScopeNarrowing', Js::opt($refresh, 'supportsScopeNarrowing'));
        }
        $ep = Js::opt($refresh, 'extraParams');
        if ($ep instanceof Obj) {
            $config->set('extraParams', self::copyObj($ep));
        }
        return $config;
    }

    /** The `providers` option of a TokenVault from per-provider credentials; non-refreshable providers are skipped. */
    public static function buildVaultProviders(mixed $credsById, ?ProviderRegistry $registry = null): Obj
    {
        $registry ??= self::defaultRegistry();
        $out = new Obj();
        foreach (self::entries($credsById) as [$id, $creds]) {
            $manifest = $registry->require($id);
            if ($manifest->get('refresh')->get('mode') === 'none') {
                continue;
            }
            $out->set($id, self::manifestToProviderConfig($manifest, $creds));
        }
        return $out;
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
