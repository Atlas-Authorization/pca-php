<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Blueprint.php';
require_once __DIR__ . '/BreakGlass.php';
require_once __DIR__ . '/FreshAt.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/K3.php';
require_once __DIR__ . '/Lease.php';

/**
 * The producing side of the operational plane (the reference's pca-grants): domain-separated Ed25519 signing, the signers for
 * leases, revocations, blueprints and break-glass records, policy bundle signing and assembly, the decision log (hash chain, Merkle
 * commitment, signed heads, inclusion proofs, streaming batches), replay tooling, consistency-token issuing, lease renewal, group
 * kill and attestation-gated blueprint admission. The verification side is {@see K3}, {@see Lease}, {@see Blueprint},
 * {@see BreakGlass} and {@see FreshAt}. Records are parsed JSON (Obj, lists, Num); secrets are {@see KeyPair}. A signer throws
 * exactly where the reference throws (a malformed record).
 */
final class Grants
{
    /** JS object spread of a record: an Obj copies; anything else adds nothing. */
    public static function copy(mixed $x): Obj
    {
        $o = new Obj();
        if ($x instanceof Obj) {
            foreach ($x->keys() as $k) {
                $o->set($k, $x->get($k));
            }
        }
        return $o;
    }

    private static function key(mixed $secret): KeyPair
    {
        if (!($secret instanceof KeyPair)) {
            throw new \TypeError('expected a KeyPair secret key');
        }
        return $secret;
    }

    public static function signerOf(mixed $secret): string
    {
        return self::key($secret)->public;
    }

    /** Domain-separated Ed25519 signature over strict-canonical JSON (throws on a body outside the strict profile). */
    public static function signBody(string $domain, mixed $body, mixed $secret): string
    {
        return Pca::b64u(self::key($secret)->sign($domain . Json::canonicalizeNative($body)));
    }

    public static function verifyBody(string $domain, mixed $body, mixed $signer, mixed $sig): bool
    {
        return K3Sig::verifyBody($domain, $body, $signer, $sig);
    }

    /** The members of `$o` named by `$keys`, in that order (absent ones skipped). */
    private static function pick(Obj $o, array $keys, bool $present = false): Obj
    {
        $b = new Obj();
        foreach ($keys as $k) {
            if (!$present || $o->has($k)) {
                $b->set($k, $o->get($k));
            }
        }
        return $b;
    }

    private static function withSig(Obj $base, string $domain, Obj $body, mixed $secret): Obj
    {
        $base->set('sig', self::signBody($domain, $body, $secret));
        return $base;
    }

    // ---- signers ------------------------------------------------------------------------------------------------------

    private static function leaseBase(mixed $secret, mixed $l): Obj
    {
        $base = new Obj();
        $base->set('v', 1);
        foreach (self::copy($l)->keys() as $k) {
            $base->set($k, $l->get($k));
        }
        $base->set('authority', self::signerOf($secret));
        return $base;
    }

    /** Sign a lease record. Throws on a malformed record or one that outlives its cap. */
    public static function signLease(mixed $secret, mixed $l): Obj
    {
        $base = self::leaseBase($secret, $l);
        if (!Lease::wellFormed($base) || (float)K3Sig::num($base->get('expires_at')) > Lease::cap($base)) {
            throw new \InvalidArgumentException('signLease: a malformed lease, or one past issued_at + max_ttl');
        }
        return self::withSig($base, Lease::DOMAIN, self::pick($base, Lease::BODY_KEYS), $secret);
    }

    /** Conformance-vector builder only: signs a record that outlives its cap, to prove verifiers refuse it. */
    public static function signLeaseUnsafeOverCap(mixed $secret, mixed $l): Obj
    {
        $base = self::leaseBase($secret, $l);
        if (!Lease::wellFormed($base)) {
            throw new \InvalidArgumentException('signLeaseUnsafeOverCap: malformed');
        }
        return self::withSig($base, Lease::DOMAIN, self::pick($base, Lease::BODY_KEYS), $secret);
    }

    public static function signLeaseRevocation(mixed $secret, mixed $r): Obj
    {
        $base = self::leaseBase($secret, $r);
        if (!Lease::revocationWellFormed($base)) {
            throw new \InvalidArgumentException('signLeaseRevocation: malformed');
        }
        return self::withSig($base, Lease::REVOKE_DOMAIN, self::pick($base, Lease::REVOKE_KEYS), $secret);
    }

    /** Sign a blueprint record with the operator's secret. Throws on a malformed record. */
    public static function signBlueprint(mixed $secret, mixed $b): Obj
    {
        $base = new Obj();
        $base->set('v', 1);
        foreach (self::copy($b)->keys() as $k) {
            $base->set($k, $b->get($k));
        }
        $base->set('operator', self::signerOf($secret));
        if (!Blueprint::wellFormed($base)) {
            throw new \InvalidArgumentException('signBlueprint: a malformed blueprint');
        }
        return self::withSig($base, Blueprint::DOMAIN, self::pick($base, Blueprint::BODY_KEYS, true), $secret);
    }

    public static function signBreakGlass(mixed $secret, mixed $b): Obj
    {
        $base = self::leaseBase($secret, $b);
        if (!BreakGlass::wellFormed($base)) {
            throw new \InvalidArgumentException('signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16');
        }
        return self::withSig($base, BreakGlass::DOMAIN, self::pick($base, BreakGlass::BODY_KEYS), $secret);
    }

    public static function signBreakGlassReview(mixed $secret, mixed $r): Obj
    {
        $base = new Obj();
        $base->set('v', 1);
        foreach (self::copy($r)->keys() as $k) {
            $base->set($k, $r->get($k));
        }
        $base->set('reviewer', self::signerOf($secret));
        if (!BreakGlass::reviewWellFormed($base)) {
            throw new \InvalidArgumentException('signBreakGlassReview: malformed');
        }
        return self::withSig($base, BreakGlass::REVIEW_DOMAIN, self::pick($base, BreakGlass::REVIEW_KEYS), $secret);
    }

    // ---- policy bundles -----------------------------------------------------------------------------------------------

    private static function shadowError(mixed $b): ?string
    {
        if (!($b instanceof Obj) || !$b->has('shadow')) {
            return null;
        }
        $s = $b->get('shadow');
        if (!K3Sig::isList($s) || count($s) === 0 || count($s) > 16) {
            return 'bad shadow';
        }
        foreach ($s as $g) {
            if (!K3Sig::isStr($g, 128)) {
                return 'bad shadow';
            }
        }
        if (count(array_unique($s)) !== count($s)) {
            return 'bad shadow';
        }
        return null;
    }

    /** The complete bundle shape check: {@see K3::bundleShapeError} plus the `shadow` member (1 to 16 distinct digests). */
    public static function bundleShapeErrorFull(mixed $b): ?string
    {
        return K3::bundleShapeError($b) ?? self::shadowError($b);
    }

    /** One signer's signature over the bundle body: `{signer, sig}`. Collect k of them and call {@see assembleBundle}. */
    public static function signBundle(mixed $body, mixed $secret): Obj
    {
        $e = self::bundleShapeErrorFull($body);
        if ($e !== null) {
            throw new \InvalidArgumentException('signBundle: ' . $e);
        }
        return Obj::of(['signer' => self::signerOf($secret), 'sig' => self::signBody(K3::BUNDLE_DOMAIN, $body->without('sigs'), $secret)]);
    }

    public static function assembleBundle(mixed $body, mixed $sigs): Obj
    {
        $o = $body->without('sigs');
        $o->set('sigs', $sigs);
        return $o;
    }

    // ---- decision records ---------------------------------------------------------------------------------------------

    /** Mask by data CLASS: every detail field whose class is in `$maskClasses` becomes a commitment. */
    public static function maskRecord(mixed $r, array $maskClasses): mixed
    {
        $detail = $r->get('detail');
        $classes = $r->get('classes');
        if (!Js::truthy($detail) || !Js::truthy($classes)) {
            return $r;
        }
        $entries = [];
        if ($detail instanceof Obj) {
            foreach ($detail->keys() as $k) {
                $entries[] = [$k, $detail->get($k)];
            }
        } elseif (is_array($detail)) {
            foreach ($detail as $i => $v) {
                $entries[] = [(string)$i, $v];
            }
        }
        $out = new Obj();
        foreach ($entries as [$k, $v]) {
            $cls = $classes instanceof Obj ? $classes->get($k) : null;
            $out->set($k, $cls !== null && in_array($cls, $maskClasses, true)
                ? 'masked:' . Js::str($cls) . ':' . Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/mask/v1', 'k' => $k, 'v' => $v]))
                : $v);
        }
        $o = self::copy($r);
        $o->set('detail', $out);
        return $o;
    }

    private static function leaf(mixed $x): string
    {
        return hash('sha256', "\x00" . Json::canonicalizeNative($x), true);
    }

    private static function node(string $l, string $r): string
    {
        return hash('sha256', "\x01" . $l . $r, true);
    }

    private static function split(int $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $k;
    }

    private static function build(array $hs): string
    {
        if (count($hs) === 1) {
            return $hs[0];
        }
        $k = self::split(count($hs));
        return self::node(self::build(array_slice($hs, 0, $k)), self::build(array_slice($hs, $k)));
    }

    /** RFC 6962 audit path of leaf `$index`: `{index, size, path: [{side, hash}]}`. Throws on an index out of range. */
    public static function merkleProof(array $leaves, mixed $index): Obj
    {
        $f = Js::num($index);
        if ($f === null || !is_finite($f) || floor($f) !== $f || $f < 0 || $f >= count($leaves)) {
            throw new \RangeException('merkleProof: index out of range');
        }
        $path = [];
        $prove = function (array $hs, int $idx) use (&$prove, &$path): void {
            if (count($hs) === 1) {
                return;
            }
            $k = self::split(count($hs));
            if ($idx < $k) {
                $prove(array_slice($hs, 0, $k), $idx);
                $path[] = Obj::of(['side' => 'R', 'hash' => Pca::b64u(self::build(array_slice($hs, $k)))]);
            } else {
                $prove(array_slice($hs, $k), $idx - $k);
                $path[] = Obj::of(['side' => 'L', 'hash' => Pca::b64u(self::build(array_slice($hs, 0, $k)))]);
            }
        };
        $prove(array_map(self::leaf(...), array_values($leaves)), (int)$f);
        // the proof is a wire value: its numbers are Num, which is what the verifier's strict integer check reads
        return Obj::of(['index' => $index instanceof Num ? $index : new Num((string)(int)$f), 'size' => new Num((string)count($leaves)), 'path' => $path]);
    }

    public static function gt(?int $a, ?int $b): bool
    {
        return $a !== null && $b !== null && $a > $b;
    }

    /** A deep copy of a parsed JSON value. */
    public static function deepCopy(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::deepCopy($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::deepCopy(...), $v) : $v;
    }

    public static function recordCommit(mixed $r): string
    {
        return Pca::hashCanonical(Obj::of(['d' => K3::RECORD_DOMAIN, 'r' => $r]));
    }

    public static function isSafeInt(mixed $x): bool
    {
        return K3Sig::anySafeInt($x);
    }

    // ---- replay tooling -----------------------------------------------------------------------------------------------

    private const RANK = ['deny' => 0, 'escalate' => 1, 'allow' => 2];

    public static function rank(mixed $x): ?int
    {
        return is_string($x) ? (self::RANK[$x] ?? null) : null;
    }

    /**
     * "What would have changed": re-run the pure decision function over recorded traffic under two revisions. `$cases`: Obj
     * `{action_digest, input}`; the decide functions map an input to a decision.
     *
     * @return list<Obj>
     */
    public static function semanticDiff(array $cases, callable $oldDecide, callable $newDecide): array
    {
        $out = [];
        foreach ($cases as $c) {
            $before = $oldDecide($c->get('input'));
            $after = $newDecide($c->get('input'));
            if ($before !== $after) {
                $ra = self::rank($after);
                $rb = self::rank($before);
                $o = new Obj();
                $o->set('action_digest', $c->get('action_digest'));
                if ($before !== null) {
                    $o->set('before', $before);
                }
                if ($after !== null) {
                    $o->set('after', $after);
                }
                $o->set('direction', $ra !== null && $rb !== null && $ra > $rb ? 'widened' : 'tightened');
                $out[] = $o;
            }
        }
        return $out;
    }

    /**
     * Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift).
     *
     * @param callable(mixed, mixed):mixed $decide
     * @return list<Obj>
     */
    public static function auditReplay(array $records, array $cases, callable $decide): array
    {
        $by = [];
        foreach ($cases as $c) {
            $by['k' . $c->get('action_digest')] = $c->get('input');
        }
        $out = [];
        foreach ($records as $r) {
            $k = 'k' . $r->get('action_digest');
            if (array_key_exists($k, $by) && $decide($by[$k], $r->get('bundle_revision')) !== $r->get('decision')) {
                $out[] = $r;
            }
        }
        return $out;
    }

    // ---- consistency tokens (issuing side) -----------------------------------------------------------------------------

    public static function signFreshAt(mixed $secret, mixed $scope, mixed $state, mixed $issuedAt): Obj
    {
        $ok = K3Sig::isStr($scope, 256) && $state instanceof Obj && K3Sig::isStr($state->get('policy_digest'), 128) && K3Sig::isSafeInt($issuedAt);
        foreach (FreshAt::NUMERIC as $k) {
            $ok = $ok && $state instanceof Obj && K3Sig::isSafeInt($state->get($k));
        }
        if (!$ok) {
            throw new \InvalidArgumentException('signFreshAt: a malformed state');
        }
        $base = Obj::of(['v' => 1, 'scope' => $scope]);
        foreach ($state->keys() as $k) {
            $base->set($k, $state->get($k));
        }
        $base->set('issued_at', $issuedAt);
        $base->set('signer', self::signerOf($secret));
        $body = self::pick($base, ['v', 'scope', 'revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision', 'policy_digest', 'issued_at', 'signer']);
        return self::withSig($base, FreshAt::DOMAIN, $body, $secret);
    }

    private static function fnum(mixed $o, string $k): float
    {
        $v = $o instanceof Obj ? K3Sig::num($o->get($k)) : null;
        if ($v === null) {
            throw new \InvalidArgumentException("freshAt: $k is not a number");
        }
        return $v;
    }

    /** Field-wise maximum of two states (the client-side fold). Equal revisions with different digests keep `$a`'s digest. */
    public static function mergeFreshAt(mixed $a, mixed $b): Obj
    {
        $o = new Obj();
        foreach (['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision'] as $k) {
            $o->set($k, self::fnum($a, $k) >= self::fnum($b, $k) ? $a->get($k) : $b->get($k));
        }
        $o->set('policy_digest', self::fnum($b, 'policy_revision') > self::fnum($a, 'policy_revision') ? $b->get('policy_digest') : $a->get('policy_digest'));
        return $o;
    }

    /** Compose a freshness verdict into a decision: it can only tighten (allow -> escalate/deny), never loosen. */
    public static function gateDecision(mixed $decision, mixed $v): mixed
    {
        $d = $v instanceof Obj ? $v->get('decision') : null;
        if ($decision === 'deny' || $d === 'deny') {
            return 'deny';
        }
        return $d === 'escalate' ? 'escalate' : $decision;
    }

    // ---- leases: renewal ----------------------------------------------------------------------------------------------

    /**
     * Authority side: sign and register the next record of a lease. `$veto(current) === true` refuses a renewal; it can never
     * lengthen one.
     *
     * @param ?callable(Obj):mixed $veto @return array<string,mixed>
     */
    public static function renewLease(mixed $secret, LeaseRegistry $registry, string $leaseId, mixed $now, mixed $increment, mixed $justificationDigest,
        ?array $approvers = null, ?callable $veto = null, ?array $chain = null): array
    {
        if (!K3Sig::isSafeInt($now) || !K3Sig::isSafeInt($increment) || (float)K3Sig::num($increment) < 1.0) {
            return ['ok' => false, 'code' => 'bad_input'];
        }
        $cur = $registry->current($leaseId);
        if ($cur === null) {
            return ['ok' => false, 'code' => 'unknown_lease'];
        }
        if ($veto !== null && $veto($cur) === true) {
            return ['ok' => false, 'code' => 'vetoed'];
        }
        $n = (float)K3Sig::num($now);
        $expires = min($n + (float)K3Sig::num($increment), Lease::cap($cur));
        $rec = $cur->without('v', 'sig', 'authority');
        $rec->set('seq', (int)K3Sig::num($cur->get('seq')) + 1);
        $rec->set('renewed_at', $now);
        $rec->set('expires_at', (int)$expires);
        $rec->set('justification_digest', $justificationDigest);
        $rec->set('approvers', $approvers ?? $cur->get('approvers'));
        try {
            $record = self::signLease($secret, $rec);
        } catch (\Throwable) {
            return ['ok' => false, 'code' => $expires <= $n ? 'expired_lease' : 'bad_input'];
        }
        $r = $registry->accept($record, $chain ?? []);
        return $r['ok'] ? ['ok' => true, 'record' => $record] : ['ok' => false, 'code' => $r['code']];
    }

    // ---- blueprints: group kill and attestation-gated admission ---------------------------------------------------------

    /**
     * GROUP KILL: the operator signs the blueprint as `disabled` at the next epoch; the registry accepts it and, given
     * `$revocation` (an object with `revoke(array)`), also revokes the blueprint key as an issuer; given `$freshAt` (a
     * {@see FreshAtIssuer}) its `revocation_epoch` advances to the record's epoch and the token is returned.
     *
     * @return array<string,mixed>
     */
    public static function groupKill(mixed $secret, BlueprintRegistry $registry, string $key, mixed $now, ?string $reason = null, ?object $revocation = null,
        ?FreshAtIssuer $freshAt = null): array
    {
        $cur = $registry->get($key);
        if ($cur === null) {
            return ['ok' => false, 'code' => 'unknown_blueprint'];
        }
        $rec = $cur->without('sig', 'operator', 'v');
        $rec->set('status', 'disabled');
        $rec->set('epoch', (int)K3Sig::num($cur->get('epoch')) + 1);
        $rec->set('issued_at', $now);
        $record = self::signBlueprint($secret, $rec);
        $r = $registry->accept($record);
        if (!$r['ok']) {
            return $r;
        }
        if ($revocation !== null) {
            $revocation->revoke(['kind' => 'issuer', 'value' => $key, 'reason' => $reason ?? 'blueprint disabled (group kill)', 'revokedAt' => $now]);
        }
        $out = ['ok' => true, 'record' => $record];
        if ($freshAt !== null) {
            $out['freshAt'] = $freshAt->advance(Obj::of(['revocation_epoch' => $record->get('epoch')]), $now);
        }
        return $out;
    }

    private static function pinMatches(mixed $pin, mixed $ident): bool
    {
        if (!($pin instanceof Obj) || $pin->keys() === []) {
            return false;
        }
        foreach ($pin->keys() as $k) {
            $v = $pin->get($k);
            if ($v === null || !($ident instanceof Obj) || !$ident->has($k) || $ident->get($k) !== $v) {
                return false;
            }
        }
        return true;
    }

    /**
     * Admit from adapter evidence `{ok, bound, identity?, reason?}`: `ok` and `bound` must both be exactly true, and the identity
     * the adapter established must match one runtime pin. A thrown error or malformed result denies.
     *
     * @param callable():mixed $getEvidence @return array<string,mixed>
     */
    public static function admitWithEvidence(mixed $blueprint, callable $getEvidence): array
    {
        $pins = $blueprint->get('runtime_pins');
        if ($pins === null || !is_array($pins) || count($pins) === 0) {
            return ['admitted' => false, 'code' => 'no_pins'];
        }
        try {
            $r = $getEvidence();
        } catch (\Throwable $e) {
            return ['admitted' => false, 'code' => 'verifier_error', 'reason' => (new \ReflectionClass($e))->getShortName()];
        }
        $g = static fn(string $k): mixed => Js::opt($r, $k);
        if ($g('ok') !== true) {
            return ['admitted' => false, 'code' => 'not_ok'] + (is_string($g('reason')) ? ['reason' => $g('reason')] : []);
        }
        if ($g('bound') !== true) {
            return ['admitted' => false, 'code' => 'not_bound'];
        }
        $ident = $g('identity');
        if (!($ident instanceof Obj) && !is_array($ident)) {
            return ['admitted' => false, 'code' => 'no_identity'];
        }
        foreach ($pins as $p) {
            if (self::pinMatches($p, $ident)) {
                return ['admitted' => true, 'identity' => $ident, 'pin' => $p];
            }
        }
        return ['admitted' => false, 'code' => 'no_matching_pin'];
    }

    /**
     * Admit through a hardware attestation verifier: `$verifier(['document','ctx','nowMs','expected'])` returns
     * `{ok, bound, measured?, reason?}`. No pins or no evidence is a denial.
     *
     * @param callable(array):mixed $verifier @return array<string,mixed>
     */
    public static function admitBlueprintInstance(mixed $blueprint, mixed $document, callable $verifier, mixed $nowMs, mixed $ctx = null, mixed $expected = null): array
    {
        $pins = $blueprint->get('runtime_pins');
        if ($pins === null || !is_array($pins) || count($pins) === 0) {
            return ['admitted' => false, 'code' => 'no_pins'];
        }
        if ($document === null) {
            return ['admitted' => false, 'code' => 'not_ok', 'reason' => 'no evidence'];
        }
        return self::admitWithEvidence($blueprint, static function () use ($verifier, $document, $ctx, $nowMs, $expected): Obj {
            $h = $verifier(['document' => $document, 'ctx' => $ctx, 'nowMs' => $nowMs, 'expected' => $expected]);
            $g = static fn(string $k): mixed => Js::opt($h, $k);
            $out = Obj::of(['ok' => $g('ok') === true, 'bound' => $g('bound') === true]);
            if (Js::truthy($g('measured'))) {
                $out->set('identity', $g('measured'));
            }
            if (is_string($g('reason'))) {
                $out->set('reason', $g('reason'));
            }
            return $out;
        });
    }
}

/** Decision log: append-only, hash-chained, Merkle-committed, with signed heads and inclusion proofs. */
final class DecisionLog
{
    /** @var list<Obj> */
    private array $recs = [];

    /** @param list<string> $maskClasses */
    public function __construct(private readonly KeyPair $secret, private readonly array $maskClasses = [])
    {
    }

    public function size(): int
    {
        return count($this->recs);
    }

    public function signer(): string
    {
        return $this->secret->public;
    }

    public function append(mixed $r): Obj
    {
        $masked = Grants::maskRecord($r, $this->maskClasses);
        $rec = Obj::of(['v' => 1]);
        foreach ($masked->keys() as $k) {
            $rec->set($k, $masked->get($k));
        }
        $rec->set('seq', count($this->recs));
        $rec->set('prev', $this->recs === [] ? '' : Grants::recordCommit($this->recs[count($this->recs) - 1]));
        $this->recs[] = $rec;
        return $rec;
    }

    private function commits(): array
    {
        return array_map(Grants::recordCommit(...), $this->recs);
    }

    public function head(mixed $now): Obj
    {
        $base = Obj::of(['v' => 1, 'size' => count($this->recs), 'root' => Pca::merkleRoot($this->commits()),
            'last_commit' => $this->recs === [] ? '' : Grants::recordCommit($this->recs[count($this->recs) - 1]), 'issued_at' => $now, 'signer' => $this->secret->public]);
        $base->set('sig', Grants::signBody(K3::LOG_HEAD_DOMAIN, $base, $this->secret));
        return $base;
    }

    public function proof(mixed $seq): Obj
    {
        return Grants::merkleProof($this->commits(), $seq);
    }

    /** @return list<Obj> */
    public function slice(int $start, int $end): array
    {
        return array_slice($this->recs, $start, max(0, $end - $start));
    }

    /** The next batch of at most `$max` records starting at `$from` (the stream cursor) with a freshly signed head. */
    public function nextBatch(mixed $from, mixed $max, mixed $now): Obj
    {
        if (!K3Sig::anySafeInt($from) || (float)K3Sig::num($from) < 0 || !K3Sig::anySafeInt($max) || (float)K3Sig::num($max) < 1) {
            throw new \InvalidArgumentException('nextBatch: bad cursor or size');
        }
        $f = (int)K3Sig::num($from);
        return Obj::of(['from' => $from, 'records' => $this->slice($f, $f + (int)K3Sig::num($max)), 'head' => $this->head($now)]);
    }
}

/** Verifier-side freshness state holder: advance on every write, mint the token for the write, check incoming tokens. */
final class FreshAtIssuer
{
    private Obj $state;

    public function __construct(private readonly KeyPair $secret, private readonly string $scope, mixed $initial)
    {
        $this->state = Grants::copy($initial);
    }

    public function current(): Obj
    {
        return Grants::copy($this->state);
    }

    /** Apply a write (any subset of counters; each only moves forward) and return its token. */
    public function advance(mixed $patch, mixed $now): Obj
    {
        $next = Grants::copy($this->state);
        foreach ($patch instanceof Obj ? $patch->keys() : [] as $k) {
            $next->set($k, $patch->get($k));
        }
        $this->state = Grants::mergeFreshAt($this->state, $next);
        return Grants::signFreshAt($this->secret, $this->scope, $this->state, $now);
    }

    public function check(mixed $token, mixed $now, mixed $maxTokenAgeMs = null): array
    {
        $o = Obj::of(['signer' => $this->secret->public, 'scope' => $this->scope, 'now' => $now]);
        if ($maxTokenAgeMs !== null) {
            $o->set('maxTokenAgeMs', $maxTokenAgeMs);
        }
        return FreshAt::check($token, $this->state, $o);
    }
}

/** Holds admissions by instance key, blueprint key and the blueprint EPOCH they were made under; plug `checker($now)` in as `admitted`. */
final class AdmissionRegistry
{
    /** @var array<string,array{epoch:mixed,until:mixed}> */
    private array $m = [];

    private static function k(string $bpKey, string $instanceKey): string
    {
        return $bpKey . "\0" . $instanceKey;
    }

    public function admit(string $instanceKey, Obj $bp, mixed $until): void
    {
        $this->m[self::k($bp->get('key'), $instanceKey)] = ['epoch' => $bp->get('epoch'), 'until' => $until];
    }

    public function revoke(string $instanceKey, string $bpKey): bool
    {
        $k = self::k($bpKey, $instanceKey);
        $had = isset($this->m[$k]);
        unset($this->m[$k]);
        return $had;
    }

    /** @return \Closure(string, Obj):bool */
    public function checker(mixed $now): \Closure
    {
        return function (string $instanceKey, Obj $bp) use ($now): bool {
            $a = $this->m[self::k($bp->get('key'), $instanceKey)] ?? null;
            $t = K3Sig::num($now); // null for a non-finite or non-number clock: refuse (it must not read as epoch 0)
            $until = $a === null ? null : Js::num($a['until']); // +INF is a legitimate unbounded admission
            return $a !== null && Js::num($a['epoch']) === Js::num($bp->get('epoch')) && $t !== null && $until !== null && $t < $until;
        };
    }
}
