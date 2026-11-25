<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Grants.php';

/**
 * A grant-management refusal with a stable `errorCode`: not_found, conflict, bad_request, not_narrower, signature_required,
 * bad_signature, step_up_required, not_active, need_not_lowered_only, need_not_adjustable, forbidden.
 */
final class GrantError extends \RuntimeException
{
    public const MESSAGES = [
        'not_found' => 'no such grant', 'conflict' => 'conflict', 'bad_request' => 'malformed request', 'not_narrower' => 'a narrow amendment must be strictly narrower',
        'signature_required' => 'the amendment is signed (by the principal when it widens)', 'bad_signature' => 'the signature does not verify for this grant revision',
        'step_up_required' => 'widening needs a satisfied step-up', 'not_active' => 'grant is not active',
        'need_not_lowered_only' => 'an approval may only lower amounts of the requested needs', 'need_not_adjustable' => 'the need is not adjustable',
        'forbidden' => 'not authorised',
    ];
    public const STATUS = ['not_found' => 404, 'conflict' => 409, 'bad_request' => 400, 'not_narrower' => 422, 'signature_required' => 401, 'bad_signature' => 401,
        'step_up_required' => 403, 'not_active' => 409, 'need_not_lowered_only' => 422, 'need_not_adjustable' => 422, 'forbidden' => 403];

    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }

    public static function of(string $code): self
    {
        return new self($code, self::MESSAGES[$code] ?? $code);
    }
}

/** A non-2xx answer of the grant management resource. */
final class GrantApiError extends \RuntimeException
{
    public function __construct(public readonly int $status, public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/** In-process grant store (forgets everything on restart). Grants and needs are Obj; every read is a deep copy. */
final class MemoryGrantStore
{
    /** @var array<string,Obj> */
    private array $g = [];
    /** @var array<string,Obj> */
    private array $n = [];

    public function get(string $id): ?Obj
    {
        return isset($this->g['k' . $id]) ? Grants::deepCopy($this->g['k' . $id]) : null;
    }

    public function put(Obj $g): void
    {
        $this->g['k' . $g->get('id')] = Grants::deepCopy($g);
    }

    /** @return list<Obj> */
    public function list(): array
    {
        return array_map(Grants::deepCopy(...), array_values($this->g));
    }

    public function getNeed(string $id): ?Obj
    {
        return isset($this->n['k' . $id]) ? Grants::deepCopy($this->n['k' . $id]) : null;
    }

    public function putNeed(Obj $n): void
    {
        $this->n['k' . $n->get('id')] = Grants::deepCopy($n);
    }

    /** @return list<Obj> */
    public function listNeeds(string $grantId): array
    {
        return array_values(array_map(Grants::deepCopy(...), array_filter($this->n, static fn(Obj $x): bool => $x->get('grant_id') === $grantId)));
    }
}

/**
 * The grant management resource: list / inspect / amend / revoke and incremental authorization for principals, nothing widening in
 * place. Runs over a grant store ({@see MemoryGrantStore} is for tests and single-process use). Options (assoc array): store, now
 * (callable), newId (callable(kind) with kind `grant` or `need`), and optional providers (`usage`, `remaining_budget`, `policy_card`,
 * `residual`: each callable(Obj grant)), verifyStepUp (callable(ref, grant): bool; absent: widening is refused), onRevoke, onChange,
 * validateNeed (callable(Obj): ?string). The authority comparison is {@see K3::compareAuthority} (not pluggable here).
 */
final class GrantService
{
    public readonly object $store;
    private \Closure $now;
    private \Closure $newId;
    private ?array $providers;
    private ?\Closure $verifyStepUp;
    private ?\Closure $onRevoke;
    private ?\Closure $onChange;
    private ?\Closure $validateNeed;

    public function __construct(array $o)
    {
        $this->store = $o['store'];
        $this->now = \Closure::fromCallable($o['now']);
        $this->newId = \Closure::fromCallable($o['newId']);
        $this->providers = $o['providers'] ?? null;
        foreach (['verifyStepUp', 'onRevoke', 'onChange', 'validateNeed'] as $k) {
            $this->$k = isset($o[$k]) ? \Closure::fromCallable($o[$k]) : null;
        }
    }

    private function histEntry(mixed $rev, mixed $authority, mixed $at, string $action): Obj
    {
        return Obj::of(['rev' => $rev, 'authority_digest' => K3::authorityDigest($authority), 'at' => $at, 'action' => $action]);
    }

    /** Create a grant record (the host calls this when a grant is registered). */
    public function register(Obj $g): Obj
    {
        if (!K3::authorityOk($g->get('authority'))) {
            throw new GrantError('bad_request', 'malformed authority');
        }
        if ($this->store->get($g->get('id')) !== null) {
            throw new GrantError('conflict', 'grant id exists');
        }
        $now = ($this->now)();
        $rec = Grants::copy($g);
        $rec->set('status', $g->get('status') ?? 'active');
        $rec->set('rev', 1);
        $rec->set('created_at', $now);
        $rec->set('history', [$this->histEntry(1, $g->get('authority'), $now, 'create')]);
        $this->store->put($rec);
        return $rec;
    }

    private static function idLess(string $a, string $b): bool
    {
        return K3Sig::sortedUtf16([$a, $b])[0] !== $b && $a !== $b;
    }

    /** @param Obj|array|null $f {principal?, agent?, status?, limit?, cursor?} */
    public function list(mixed $f = null): Obj
    {
        $lim = Js::opt($f, 'limit');
        $limit = min(max($lim === null ? 50.0 : (float)Js::num($lim), 1.0), 200.0);
        $all = [];
        foreach ($this->store->list() as $g) {
            foreach (['principal', 'agent', 'status'] as $k) {
                if (Js::opt($f, $k) !== null && $g->get($k) !== Js::opt($f, $k)) {
                    continue 2;
                }
            }
            $all[] = $g;
        }
        usort($all, static fn(Obj $a, Obj $b): int => self::idLess($a->get('id'), $b->get('id')) ? -1 : (self::idLess($b->get('id'), $a->get('id')) ? 1 : 0));
        $cursor = Js::opt($f, 'cursor');
        if ($cursor !== null) {
            $all = array_values(array_filter($all, static fn(Obj $g): bool => self::idLess($cursor, $g->get('id'))));
        }
        $page = array_slice($all, 0, (int)$limit);
        $out = Obj::of(['grants' => array_map(fn(Obj $g) => $this->view($g, false), $page)]);
        if (count($all) > $limit) {
            $out->set('next_cursor', $page[count($page) - 1]->get('id'));
        }
        return $out;
    }

    public function inspect(string $gid): Obj
    {
        return $this->view($this->must($gid), true);
    }

    private function view(Obj $g, bool $rich): Obj
    {
        $view = $g->without('history');
        $view->set('authority_digest', K3::authorityDigest($g->get('authority')));
        $view->set('pending_needs', array_map(static fn(Obj $n) => $n->get('id'), array_values(array_filter($this->store->listNeeds($g->get('id')), static fn(Obj $n): bool => $n->get('status') === 'pending'))));
        if ($rich && $this->providers) {
            foreach (['usage', 'remaining_budget', 'policy_card', 'residual'] as $name) {
                if (!empty($this->providers[$name])) {
                    $view->set($name, ($this->providers[$name])($g));
                }
            }
        }
        return $view;
    }

    private function must(string $gid): Obj
    {
        return $this->store->get($gid) ?? throw new GrantError('not_found', 'no such grant');
    }

    private function changed(string $kind, Obj $g): void
    {
        if ($this->onChange !== null) {
            ($this->onChange)($kind, $g);
        }
    }

    /** @return array{grant:Obj, created:bool} */
    public function amend(string $gid, mixed $req): array
    {
        $cur = $this->must($gid);
        $v = K3::verifyAmendment($cur, $req, false);
        // evaluate the (possibly consuming) step-up only when everything else already passed
        if (!$v['ok'] && $v['code'] === 'step_up_required' && Js::truthy($req->get('step_up_ref')) && $this->verifyStepUp !== null && ($this->verifyStepUp)($req->get('step_up_ref'), $cur)) {
            $v = K3::verifyAmendment($cur, $req, true);
        }
        if (!$v['ok']) {
            throw GrantError::of($v['code']);
        }
        $now = ($this->now)();
        if (!$v['widens']) {
            $cur->set('authority', $v['next']);
            $cur->set('rev', (int)K3Sig::num($cur->get('rev')) + 1);
            $h = $cur->get('history');
            $h[] = $this->histEntry($cur->get('rev'), $v['next'], $now, $req->get('action'));
            $cur->set('history', $h);
            $this->store->put($cur);
            $this->changed('amend', $cur);
            return ['grant' => $this->view($cur, true), 'created' => false];
        }
        $nid = ($this->newId)('grant');
        $fresh = $this->successor($cur, $v['next'], $nid, $now, 'supersedes:' . $cur->get('id'));
        $cur->set('status', 'superseded');
        $cur->set('superseded_by', $nid);
        $this->store->put($fresh);
        $this->store->put($cur);
        $this->changed('supersede', $fresh);
        return ['grant' => $this->view($fresh, true), 'created' => true];
    }

    private function successor(Obj $cur, mixed $authority, string $nid, mixed $now, string $action): Obj
    {
        $fresh = $cur->without('superseded_by');
        $fresh->set('id', $nid);
        $fresh->set('authority', $authority);
        $fresh->set('rev', 1);
        $fresh->set('status', 'active');
        $fresh->set('supersedes', $cur->get('id'));
        $fresh->set('created_at', $now);
        $fresh->set('history', [$this->histEntry(1, $authority, $now, $action)]);
        return $fresh;
    }

    /**
     * Authorised by the principal's signature over `{grant id, scope}` (`['sig' => ..]`) or by a host-authenticated admin
     * (`['admin' => true]`). `agent` revokes every grant of the grant's agent and principal; `subtree` the grant and every descendant.
     *
     * @return Obj `{revoked: [id]}`
     */
    public function revoke(string $gid, mixed $scope, array $auth): Obj
    {
        if (!in_array($scope, ['grant', 'agent', 'subtree'], true)) {
            throw new GrantError('bad_request', 'unknown scope');
        }
        $root = $this->must($gid);
        if (array_key_exists('sig', $auth)) {
            $rv = K3::verifyRevokeSignature($root, $scope, $auth['sig']);
            if (!$rv['ok']) {
                throw GrantError::of($rv['code']);
            }
        } elseif (($auth['admin'] ?? null) !== true) {
            throw new GrantError('forbidden', 'not authorised');
        }
        $all = $this->store->list();
        if ($scope === 'grant') {
            $hit = [$root];
        } elseif ($scope === 'agent') {
            $hit = array_values(array_filter($all, static fn(Obj $g): bool => $g->get('agent') === $root->get('agent') && $g->get('principal') === $root->get('principal')));
        } else {
            $ids = [$gid => true];
            do {
                $grew = false;
                foreach ($all as $g) {
                    $p = $g->get('parent');
                    if ($p !== null && isset($ids[$p]) && !isset($ids[$g->get('id')])) {
                        $ids[$g->get('id')] = true;
                        $grew = true;
                    }
                }
            } while ($grew);
            $hit = array_values(array_filter($all, static fn(Obj $g): bool => isset($ids[$g->get('id')])));
        }
        $revoked = [];
        foreach ($hit as $g) {
            if ($g->get('status') === 'revoked') {
                continue;
            }
            $g->set('status', 'revoked');
            $h = $g->get('history');
            $h[] = $this->histEntry($g->get('rev'), $g->get('authority'), ($this->now)(), 'revoke:' . $scope);
            $g->set('history', $h);
            $this->store->put($g);
            $revoked[] = $g->get('id');
        }
        if ($this->onRevoke !== null) {
            ($this->onRevoke)($revoked, $scope, $root);
        }
        $this->changed('revoke', $root);
        return Obj::of(['revoked' => $revoked]);
    }

    /** Agent side: ask for more. Typed needs only (validated); no authority changes until the principal approves. */
    public function requestNeeds(string $grantId, mixed $needs): Obj
    {
        $g = $this->must($grantId);
        if ($g->get('status') !== 'active') {
            throw new GrantError('not_active', 'grant is ' . Js::str($g->get('status')));
        }
        if (!K3Sig::isList($needs) || count($needs) < 1 || count($needs) > 32) {
            throw new GrantError('bad_request', '1..32 needs');
        }
        foreach ($needs as $n) {
            $bad = !($n instanceof Obj) || !K3Sig::isStr($n->get('verb'), 128) || !K3Sig::isStr($n->get('resource'), 512);
            if (!$bad && $n->has('limits')) {
                $l = $n->get('limits');
                $bad = !($l instanceof Obj);
                foreach ($bad ? [] : $l->keys() as $k) {
                    $x = K3Sig::num($l->get($k));
                    $bad = $bad || $x === null || $x < 0;
                }
            }
            if ($bad) {
                throw new GrantError('bad_request', 'malformed need');
            }
            $e = $this->validateNeed !== null ? ($this->validateNeed)($n) : null;
            if (Js::truthy($e)) {
                throw new GrantError('bad_request', (string)$e);
            }
        }
        $nr = Obj::of(['id' => ($this->newId)('need'), 'grant_id' => $grantId, 'needs' => Grants::deepCopy($needs), 'status' => 'pending', 'created_at' => ($this->now)()]);
        $this->store->putNeed($nr);
        $this->changed('need', $g);
        return $nr;
    }

    /** Principal side: approve the delta (amounts may only be LOWERED, and only when the need is `adjustable`); the result is a widening merge. */
    public function approveNeeds(string $needId, mixed $approved, mixed $sig, ?string $stepUpRef = null): array
    {
        $nr = $this->store->getNeed($needId) ?? throw new GrantError('not_found', 'no such need request');
        if ($nr->get('status') !== 'pending') {
            throw new GrantError('conflict', 'need request is ' . Js::str($nr->get('status')));
        }
        $g = $this->must($nr->get('grant_id'));
        $v = K3::verifyNeedApproval($nr, $g, $approved, $sig, false);
        if (!$v['ok'] && $v['code'] === 'step_up_required' && Js::truthy($stepUpRef) && $this->verifyStepUp !== null && ($this->verifyStepUp)($stepUpRef, $g)) {
            $v = K3::verifyNeedApproval($nr, $g, $approved, $sig, true);
        }
        if (!$v['ok']) {
            throw GrantError::of($v['code']);
        }
        $nid = ($this->newId)('grant');
        $now = ($this->now)();
        $fresh = $this->successor($g, $v['authority'], $nid, $now, 'needs:' . $needId);
        $g->set('status', 'superseded');
        $g->set('superseded_by', $nid);
        $nr->set('status', 'approved');
        $nr->set('result_grant_id', $nid);
        $this->store->put($fresh);
        $this->store->put($g);
        $this->store->putNeed($nr);
        $this->changed('supersede', $fresh);
        return ['grant' => $this->view($fresh, true), 'created' => true];
    }

    /** The grant a need request belongs to (the HTTP binding uses it to scope a caller to its own grants). */
    public function needGrantId(string $needId): string
    {
        return $this->store->getNeed($needId)?->get('grant_id') ?? throw new GrantError('not_found', 'no such need request');
    }

    public function denyNeeds(string $needId): void
    {
        $nr = $this->store->getNeed($needId) ?? throw new GrantError('not_found', 'no such need request');
        if ($nr->get('status') !== 'pending') {
            throw new GrantError('conflict', 'need request is ' . Js::str($nr->get('status')));
        }
        $nr->set('status', 'denied');
        $this->store->putNeed($nr);
    }
}

/** HTTP bindings (framework-neutral handlers over a request `{method, path, query?, body?}` returning `['status' => int, 'body' => ..]`), and the client. */
final class GrantHttp
{
    public const GRANTS_PATH = '/pca/grants';
    public const NEEDS_PATH = '/pca/needs';
    public const LEASES_PATH = '/pca/leases';
    private const LEASE_STATUS = ['bad_record' => 400, 'bad_seq' => 409, 'stale_seq' => 409, 'lease_fork' => 409, 'renewal_mismatch' => 422, 'over_max_ttl' => 422,
        'ttl_ceiling' => 422, 'not_extending' => 422, 'stale_justification' => 422, 'expired_lease' => 409, 'revoked' => 409, 'sod' => 403, 'unknown_authority' => 403,
        'store_unreachable' => 503];

    /** Discovery fragment for `/.well-known/pca-configuration`. */
    public static function grantManagementMetadata(string $base): Obj
    {
        return Obj::of(['grant_management' => Obj::of(['grants_endpoint' => $base . self::GRANTS_PATH, 'needs_endpoint' => $base . self::NEEDS_PATH,
            'amend_actions' => ['narrow', 'merge', 'replace'], 'revoke_scopes' => ['grant', 'agent', 'subtree'], 'widening' => 'new_grant_id_with_supersedes'])]);
    }

    public static function leaseManagementMetadata(string $base): Obj
    {
        return Obj::of(['leases' => Obj::of(['leases_endpoint' => $base . self::LEASES_PATH, 'revoke_targets' => ['lease', 'prefix', 'grant']])]);
    }

    /** JavaScript `Number(string)`: trimmed, empty is 0, decimal / Infinity / 0x 0o 0b forms, anything else NaN. */
    public static function jsNumber(string $s): float
    {
        $t = preg_replace('/^[\s\x{FEFF}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]+|[\s\x{FEFF}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]+$/u', '', $s) ?? $s;
        if ($t === '') {
            return 0.0;
        }
        if (preg_match('/\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/', $t) === 1) {
            return (float)$t;
        }
        if (preg_match('/\A([+-]?)Infinity\z/', $t, $m) === 1) {
            return $m[1] === '-' ? -INF : INF;
        }
        if (preg_match('/\A0([xXoObB])([0-9a-fA-F]+)\z/', $t, $m) === 1) {
            $base = ['x' => 16, 'o' => 8, 'b' => 2][strtolower($m[1])];
            return preg_match($base === 16 ? '/\A[0-9a-fA-F]+\z/' : ($base === 8 ? '/\A[0-7]+\z/' : '/\A[01]+\z/'), $m[2]) === 1 ? (float)self::parseBase($m[2], $base) : NAN;
        }
        return NAN;
    }

    private static function parseBase(string $digits, int $base): float
    {
        $v = 0.0;
        foreach (str_split(strtolower($digits)) as $c) {
            $v = $v * $base + hexdec($c);
        }
        return $v;
    }

    /** @return list<string> */
    private static function segments(mixed $path): array
    {
        return array_values(array_filter(explode('/', Js::str($path)), static fn(string $s): bool => $s !== ''));
    }

    private static function err(\Throwable $e): array
    {
        return $e instanceof GrantError
            ? ['status' => GrantError::STATUS[$e->errorCode], 'body' => Obj::of(['error' => $e->errorCode, 'message' => $e->getMessage()])]
            : ['status' => 500, 'body' => Obj::of(['error' => 'server_error'])];
    }

    private static function res(int $status, mixed $body): array
    {
        return ['status' => $status, 'body' => $body];
    }

    private static function nf(): array
    {
        return self::res(404, Obj::of(['error' => 'not_found']));
    }

    /**
     * `$authenticate(request): Obj|array|null` says who is calling, as the host authenticated them (`{principal?, admin?}`);
     * `principal` limits every read and write to that principal's grants.
     *
     * @param callable(mixed):mixed $authenticate @return \Closure(mixed):array
     */
    public static function grantResourceHandler(GrantService $svc, callable $authenticate): \Closure
    {
        return static function (mixed $req) use ($svc, $authenticate): array {
            try {
                $who = $authenticate($req);
                $admin = Js::truthy(Js::opt($who, 'admin'));
                $principal = Js::opt($who, 'principal');
                if (!Js::truthy($who) || (!$admin && !Js::truthy($principal))) {
                    return self::res(401, Obj::of(['error' => 'unauthenticated']));
                }
                $seg = self::segments(Js::opt($req, 'path'));
                $q = Js::opt($req, 'query');
                $b = Js::opt($req, 'body') instanceof Obj ? Js::opt($req, 'body') : new Obj();
                $method = Js::opt($req, 'method');
                $own = static function (string $gid) use ($svc, $admin, $principal): void {
                    $g = $svc->inspect($gid);
                    if (!$admin && $g->get('principal') !== $principal) {
                        throw new GrantError('not_found', 'no such grant');
                    }
                };
                if ($seg === [] || $seg[0] !== 'pca') {
                    return self::nf();
                }
                $kind = $seg[1] ?? null;
                $n = count($seg);
                if ($kind === 'grants') {
                    if ($n === 2 && $method === 'GET') {
                        $status = Js::opt($q, 'status');
                        if ($status !== null && !in_array($status, ['active', 'revoked', 'superseded'], true)) {
                            throw new GrantError('bad_request', 'bad status');
                        }
                        $p = $admin ? Js::opt($q, 'principal') : $principal;
                        $lq = Js::opt($q, 'limit');
                        $limit = $lq !== null ? self::jsNumber(Js::str($lq)) : null;
                        $f = [];
                        if (Js::truthy($p)) {
                            $f['principal'] = $p;
                        }
                        if (Js::truthy(Js::opt($q, 'agent'))) {
                            $f['agent'] = Js::opt($q, 'agent');
                        }
                        if (Js::truthy($status)) {
                            $f['status'] = $status;
                        }
                        if ($limit !== null && is_finite($limit)) {
                            $f['limit'] = $limit;
                        }
                        if (Js::truthy(Js::opt($q, 'cursor'))) {
                            $f['cursor'] = Js::opt($q, 'cursor');
                        }
                        return self::res(200, $svc->list($f));
                    }
                    $gid = $seg[2] ?? null;
                    if ($gid === null || $gid === '') {
                        return self::nf();
                    }
                    $own($gid);
                    if ($n === 3 && $method === 'GET') {
                        return self::res(200, $svc->inspect($gid));
                    }
                    if ($n === 3 && $method === 'DELETE') {
                        $scope = Js::opt($q, 'scope') ?? 'grant';
                        $sig = is_string($b->get('sig')) ? $b->get('sig') : null;
                        // a principal-scoped caller must still sign; only an admin may revoke without a principal signature
                        return self::res(200, $svc->revoke($gid, $scope, $admin && !Js::truthy($sig) ? ['admin' => true] : ['sig' => $sig ?? '']));
                    }
                    if ($n === 4 && $seg[3] === 'amend' && $method === 'POST') {
                        $r = $svc->amend($gid, Js::opt($req, 'body'));
                        return self::res($r['created'] ? 201 : 200, $r['grant']);
                    }
                    if ($n === 4 && $seg[3] === 'needs' && $method === 'POST') {
                        return self::res(201, $svc->requestNeeds($gid, $b->get('needs')));
                    }
                }
                if ($kind === 'needs' && $n > 3 && $seg[3] === 'approve' && $method === 'POST') {
                    $own($svc->needGrantId($seg[2]));
                    if (!is_string($b->get('sig')) || !K3Sig::isList($b->get('approved'))) {
                        throw new GrantError('bad_request', 'sig and approved are required');
                    }
                    $r = $svc->approveNeeds($seg[2], $b->get('approved'), $b->get('sig'), is_string($b->get('step_up_ref')) ? $b->get('step_up_ref') : null);
                    return self::res(201, $r['grant']);
                }
                if ($kind === 'needs' && $n > 3 && $seg[3] === 'deny' && $method === 'POST') {
                    $own($svc->needGrantId($seg[2]));
                    $svc->denyNeeds($seg[2]);
                    return self::res(200, Obj::of(['status' => 'denied']));
                }
                return self::nf();
            } catch (\Throwable $e) { // a handler never throws
                return self::err($e);
            }
        };
    }

    /**
     * Hosted lease routes. The server only stores records the lease authority already signed; it never mints one. POST /pca/leases
     * `{lease, chain?}` issues or renews; GET /pca/leases/:id; POST /pca/leases/:id/check `{lease}`; POST /pca/leases/revoke
     * `{revocation}`. `$authenticate(request)` returns `{admin?, principal?}` or null.
     *
     * @param callable(mixed):mixed $authenticate @param ?callable():mixed $now @return \Closure(mixed):array
     */
    public static function leaseResourceHandler(LeaseRegistry $reg, callable $authenticate, ?callable $now = null): \Closure
    {
        $clock = $now ?? static fn(): int => (int)(microtime(true) * 1000);
        return static function (mixed $req) use ($reg, $authenticate, $clock): array {
            try {
                $who = $authenticate($req);
                $admin = Js::truthy(Js::opt($who, 'admin'));
                $principal = Js::opt($who, 'principal');
                if (!Js::truthy($who) || (!$admin && !Js::truthy($principal))) {
                    return self::res(401, Obj::of(['error' => 'unauthenticated']));
                }
                $seg = self::segments(Js::opt($req, 'path'));
                $b = Js::opt($req, 'body') instanceof Obj ? Js::opt($req, 'body') : new Obj();
                $method = Js::opt($req, 'method');
                if (count($seg) < 2 || $seg[0] !== 'pca' || $seg[1] !== 'leases') {
                    return self::nf();
                }
                $visible = static fn(mixed $holder): bool => Js::opt($who, 'admin') === true || $principal === $holder;
                $n = count($seg);
                if ($n === 2 && $method === 'POST') {
                    if (!$admin) {
                        return self::res(403, Obj::of(['error' => 'forbidden']));
                    }
                    $c = $b->get('chain');
                    $chain = K3Sig::isList($c) && count(array_filter($c, 'is_string')) === count($c) ? $c : [];
                    $r = $reg->accept($b->get('lease'), $chain);
                    if ($r['ok']) {
                        return self::res(($r['replaced'] ?? false) ? 201 : 200, $r);
                    }
                    return self::res(self::LEASE_STATUS[$r['code']] ?? 400, Obj::of(['error' => $r['code']] + (Js::truthy($r['reason'] ?? null) ? ['message' => $r['reason']] : [])));
                }
                if ($n === 3 && $seg[2] === 'revoke' && $method === 'POST') {
                    if (!$admin) {
                        return self::res(403, Obj::of(['error' => 'forbidden']));
                    }
                    $r = $reg->revoke($b->get('revocation'));
                    if ($r['ok']) {
                        return self::res(200, $r);
                    }
                    return self::res($r['code'] === 'store_unreachable' ? 503 : ($r['code'] === 'unknown_authority' ? 403 : 400), Obj::of(['error' => $r['code']]));
                }
                $lid = $seg[2] ?? null;
                if ($lid === null || $lid === '') {
                    return self::nf();
                }
                if ($n === 3 && $method === 'GET') {
                    $cur = $reg->current($lid);
                    if ($cur === null || !$visible($cur->get('holder'))) {
                        return self::nf();
                    }
                    return self::res(200, Obj::of(['lease' => $cur, 'history' => $reg->history($lid)]));
                }
                if ($n === 4 && $seg[3] === 'check' && $method === 'POST') {
                    $cur = $reg->current($lid);
                    if ($cur === null || !$visible($cur->get('holder'))) {
                        return self::nf();
                    }
                    $d = Lease::check($b->get('lease'), $reg, $clock());
                    return self::res($d['decision'] === 'allow' ? 200 : 403, $d);
                }
                return self::nf();
            } catch (\Throwable) {
                return self::res(500, Obj::of(['error' => 'server_error']));
            }
        };
    }
}

/**
 * Client for the grant management resource over an injected transport: `$fetch(['method','url','headers','body']): ['status','headers','body']`
 * where `body` is the response text (or an already parsed value) and `headers` an assoc array (looked up case-insensitively). The
 * client carries the newest `pca-fresh-at` token it has seen: attached to later requests, and with `$freshSigner` set a header that
 * does not verify is ignored.
 */
final class GrantClient
{
    private ?Obj $latest = null;
    private readonly string $base;
    private readonly \Closure $fetch;
    private readonly ?\Closure $headers;

    public function __construct(string $baseUrl, callable $fetch, private readonly ?string $freshSigner = null, ?callable $headers = null)
    {
        $this->base = str_ends_with($baseUrl, '/') ? substr($baseUrl, 0, -1) : $baseUrl;
        $this->fetch = \Closure::fromCallable($fetch);
        $this->headers = $headers === null ? null : \Closure::fromCallable($headers);
    }

    /** The newest consistency token seen on any response: attach it to later requests to make them read-your-writes. */
    public function freshAt(): ?Obj
    {
        return $this->latest;
    }

    public function foldFreshAt(Obj $s): ?Obj
    {
        return $this->latest !== null ? Grants::mergeFreshAt($this->latest, $s) : null;
    }

    private function call(string $method, string $path, mixed $body = null): mixed
    {
        $hdrs = ['content-type' => 'application/json'];
        if ($this->latest !== null) {
            $hdrs['pca-fresh-at'] = Js::stringify($this->latest);
        }
        if ($this->headers !== null) {
            $hdrs = ($this->headers)() + $hdrs;
        }
        $req = ['method' => $method, 'url' => $this->base . $path, 'headers' => $hdrs];
        if ($body !== null) {
            $req['body'] = Js::stringify($body);
        }
        $res = ($this->fetch)($req);
        $rh = [];
        foreach ($res['headers'] ?? [] as $k => $v) {
            $rh[strtolower((string)$k)] = $v;
        }
        $tok = $rh['pca-fresh-at'] ?? null;
        if (Js::truthy($tok)) {
            try {
                $t = Js::parse($tok);
                if (!($t instanceof Obj) || ($this->freshSigner !== null && !FreshAt::verify($t, $this->freshSigner))) {
                    throw new \InvalidArgumentException('unverified');
                }
                $lt = $this->latest;
                // monotone fold: never replace a fresher token with an older one
                $ok = $lt === null;
                if (!$ok) {
                    $ok = true;
                    foreach (['revocation_epoch', 'policy_revision', 'ledger_tree_size', 'budget_version'] as $k) {
                        $a = Js::num($t->get($k)); // read raw: a non-number or NaN field never reads as 0 and so never folds
                        $b = Js::num($lt->get($k));
                        $ok = $ok && $a !== null && $b !== null && $a >= $b;
                    }
                }
                if ($ok) {
                    $this->latest = $t;
                }
            } catch (\Throwable) { // freshness is only ever tightened by a valid token
            }
        }
        $raw = $res['body'] ?? null;
        try {
            $data = is_string($raw) ? Js::parse($raw) : ($raw ?? new Obj());
        } catch (\Throwable) {
            $data = new Obj();
        }
        $status = (int)$res['status'];
        if (!($status >= 200 && $status < 300)) {
            $d = $data instanceof Obj ? $data : new Obj();
            throw new GrantApiError($status, Js::truthy($d->get('error')) ? Js::str($d->get('error')) : 'error', Js::truthy($d->get('message')) ? Js::str($d->get('message')) : (string)($res['reason'] ?? $status));
        }
        return $data;
    }

    private static function form(array $q): string
    {
        $parts = [];
        foreach ($q as $k => $v) {
            if ($v !== null) {
                $enc = static fn(string $s): string => str_replace('%2A', '*', urlencode($s));
                $parts[] = $enc((string)$k) . '=' . $enc(is_bool($v) ? ($v ? 'true' : 'false') : (string)$v);
            }
        }
        return implode('&', $parts);
    }

    private static function comp(string $s): string
    {
        return Js::encodeURIComponent($s);
    }

    public function list(array $q = []): mixed
    {
        $s = self::form($q);
        return $this->call('GET', GrantHttp::GRANTS_PATH . ($s !== '' ? '?' . $s : ''));
    }

    public function inspect(string $gid): mixed
    {
        return $this->call('GET', GrantHttp::GRANTS_PATH . '/' . self::comp($gid));
    }

    public function amend(string $gid, mixed $req): mixed
    {
        return $this->call('POST', GrantHttp::GRANTS_PATH . '/' . self::comp($gid) . '/amend', $req);
    }

    public function revoke(string $gid, string $scope = 'grant', ?string $sig = null): mixed
    {
        return $this->call('DELETE', GrantHttp::GRANTS_PATH . '/' . self::comp($gid) . '?scope=' . $scope, Js::truthy($sig) ? Obj::of(['sig' => $sig]) : null);
    }

    public function requestNeeds(string $gid, array $needs): mixed
    {
        return $this->call('POST', GrantHttp::GRANTS_PATH . '/' . self::comp($gid) . '/needs', Obj::of(['needs' => $needs]));
    }

    public function approveNeeds(string $needId, array $approved, string $sig, ?string $stepUpRef = null): mixed
    {
        $b = Obj::of(['approved' => $approved, 'sig' => $sig]);
        if (Js::truthy($stepUpRef)) {
            $b->set('step_up_ref', $stepUpRef);
        }
        return $this->call('POST', GrantHttp::NEEDS_PATH . '/' . self::comp($needId) . '/approve', $b);
    }

    public function denyNeeds(string $needId): mixed
    {
        return $this->call('POST', GrantHttp::NEEDS_PATH . '/' . self::comp($needId) . '/deny');
    }
}
