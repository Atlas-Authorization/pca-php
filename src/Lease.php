<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/KvDoc.php';

/**
 * Leases (verification side): a time-boxed, renewable record with a hard max_ttl, separation of duties and revoke by id, path prefix
 * or grant. {@see LeaseRegistry} keeps the newest record per lease_id on a durable {@see AtomicKv}. Total. Replays
 * packages/pca/conformance/lease-vectors.json. Records are parsed JSON (Obj, lists, Num).
 */
final class Lease
{
    public const DOMAIN = "atlas-pca/lease/v1\0";
    public const REVOKE_DOMAIN = "atlas-pca/lease-revoke/v1\0";
    private const BODY_KEYS = ['v', 'lease_id', 'path', 'grant_ref', 'holder', 'requester', 'approvers', 'justification_digest', 'seq', 'issued_at', 'renewed_at', 'expires_at', 'max_ttl', 'authority'];
    private const REVOKE_KEYS = ['v', 'target', 'value', 'revoked_at', 'authority'];
    private const PATH_RE = '~\A[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}\z~D';

    private static function n(Obj $l, string $k): float
    {
        return (float)K3Sig::num($l->get($k));
    }

    public static function wellFormed(mixed $l): bool
    {
        if (!($l instanceof Obj) || !K3Sig::isNumber($l->get('v'), 1.0)) {
            return false;
        }
        foreach (['lease_id' => 128, 'grant_ref' => 256, 'holder' => 128, 'requester' => 128, 'authority' => 128, 'justification_digest' => 128] as $k => $max) {
            if (!K3Sig::isStr($l->get($k), $max)) {
                return false;
            }
        }
        $p = $l->get('path');
        if (!is_string($p) || preg_match(self::PATH_RE, $p) !== 1) {
            return false;
        }
        foreach (['seq', 'issued_at', 'renewed_at', 'expires_at', 'max_ttl'] as $k) {
            if (!K3Sig::isSafeInt($l->get($k))) {
                return false;
            }
        }
        if (self::n($l, 'seq') < 1.0 || self::n($l, 'max_ttl') < 1.0) {
            return false;
        }
        if (self::n($l, 'renewed_at') < self::n($l, 'issued_at') || self::n($l, 'expires_at') <= self::n($l, 'renewed_at')
            || (self::n($l, 'seq') === 1.0 && self::n($l, 'renewed_at') !== self::n($l, 'issued_at'))) {
            return false;
        }
        $a = $l->get('approvers');
        if (!K3Sig::isList($a) || count($a) > 16) {
            return false;
        }
        foreach ($a as $x) {
            if (!K3Sig::isStr($x, 128)) {
                return false;
            }
        }
        return true;
    }

    public static function cap(Obj $l): float
    {
        return self::n($l, 'issued_at') + self::n($l, 'max_ttl');
    }

    private static function body(Obj $o, array $keys): Obj
    {
        $b = new Obj();
        foreach ($keys as $k) {
            $b->set($k, $o->get($k));
        }
        return $b;
    }

    /** Well formed and signed by its authority over exactly its content. Does NOT check the cap. */
    public static function verify(mixed $l): bool
    {
        return self::wellFormed($l) && K3Sig::verifyBody(self::DOMAIN, self::body($l, self::BODY_KEYS), $l->get('authority'), $l->get('sig'));
    }

    public static function revocationWellFormed(mixed $r): bool
    {
        if (!($r instanceof Obj) || !K3Sig::isNumber($r->get('v'), 1.0) || !K3Sig::isStr($r->get('value'), 256) || !K3Sig::isStr($r->get('authority'), 128) || !K3Sig::isSafeInt($r->get('revoked_at'))) {
            return false;
        }
        if (!in_array($r->get('target'), ['lease', 'prefix', 'grant'], true)) {
            return false;
        }
        return $r->get('target') !== 'prefix' || preg_match(self::PATH_RE, $r->get('value')) === 1;
    }

    public static function verifyRevocation(mixed $r): bool
    {
        return self::revocationWellFormed($r) && K3Sig::verifyBody(self::REVOKE_DOMAIN, self::body($r, self::REVOKE_KEYS), $r->get('authority'), $r->get('sig'));
    }

    /** `prefix` covers `path` iff equal or `path` continues it at a segment boundary. */
    public static function pathUnder(string $path, string $prefix): bool
    {
        return $path === $prefix || str_starts_with($path, $prefix . '/');
    }

    public static function covers(Obj $r, Obj $l): bool
    {
        if (self::n($l, 'issued_at') > self::n($r, 'revoked_at')) {
            return false;
        }
        return match ($r->get('target')) {
            'lease' => $l->get('lease_id') === $r->get('value'),
            'grant' => $l->get('grant_ref') === $r->get('value'),
            default => self::pathUnder($l->get('path'), $r->get('value')),
        };
    }

    /**
     * Separation of duties over one record. $policy: ['minApprovals' => ?int, 'eligibleApprovers' => ?list<string>]. A reason or null.
     * @param list<string> $chain
     */
    public static function sodError(Obj $l, array $policy = [], array $chain = []): ?string
    {
        $k = $policy['minApprovals'] ?? 1;
        if (!is_int($k) || $k < 1 || $k > 9007199254740991) {
            return 'minApprovals must be a positive integer';
        }
        $eligible = $policy['eligibleApprovers'] ?? null;
        $seen = [];
        foreach ($l->get('approvers') as $a) {
            if (isset($seen[$a])) {
                return 'an approver is listed twice';
            }
            $seen[$a] = true;
            if ($a === $l->get('requester')) {
                return 'the requester may not approve their own request';
            }
            if ($a === $l->get('holder')) {
                return 'the holder may not approve its own lease';
            }
            if (in_array($a, $chain, true)) {
                return "an approver appears in the holder's delegation chain";
            }
            if ($eligible !== null && !in_array($a, $eligible, true)) {
                return 'an approver is not eligible';
            }
        }
        $c = count($l->get('approvers'));
        return $c < $k ? "$c approver(s), need $k" : null;
    }

    /**
     * Take a lease decision against a registry.
     * @return array<string,mixed> ['decision' => 'allow', 'lease_id', 'expires_at'] or ['decision' => 'deny', 'code'[, 'lease_id']]
     */
    public static function check(mixed $presented, LeaseRegistry $registry, mixed $now): array
    {
        if (!K3Sig::isSafeInt($now)) {
            return ['decision' => 'deny', 'code' => 'bad_input'];
        }
        if (!self::verify($presented)) {
            return ['decision' => 'deny', 'code' => 'bad_record'];
        }
        $id = $presented->get('lease_id');
        $deny = static fn (string $code): array => ['decision' => 'deny', 'code' => $code, 'lease_id' => $id];
        $nowMs = (float)K3Sig::num($now);
        try {
            $found = $registry->lookup($id);
        } catch (\Throwable) {
            return $deny('store_unreachable');
        }
        if ($found === null) {
            return $deny('unknown_lease');
        }
        $cur = $found['current'];
        if ($cur->get('sig') !== $presented->get('sig')) {
            return $deny('superseded');
        }
        if ($found['revoked']) {
            return $deny('revoked');
        }
        if ($nowMs < self::n($cur, 'renewed_at')) {
            return $deny('not_yet_valid');
        }
        if ($nowMs >= self::cap($cur)) {
            return $deny('past_max_ttl');
        }
        if ($nowMs >= self::n($cur, 'expires_at')) {
            return $deny('expired');
        }
        return ['decision' => 'allow', 'lease_id' => $id, 'expires_at' => (int)self::n($cur, 'expires_at')];
    }
}

/**
 * The newest record per lease_id, the revocation list and the renewal ledger, on a durable {@see AtomicKv} (a registry holds
 * revocations: a process-local default would forget them on restart, so the store is required; {@see MemoryLeaseKv} is for tests and one
 * process). Each lease lives in the shard its id hashes to, so an issue, a renewal and a check read and write one small document; a
 * path-prefix or grant revocation is written to EVERY shard (it can cover leases anywhere), a revocation of one lease id only to that
 * lease's shard. Within a shard each operation is one atomic `update`; any store failure is `store_unreachable`.
 */
final class LeaseRegistry
{
    private const META_KEY = 'lease/meta';
    private readonly int $shards;
    private readonly \Closure $clock;
    private ?bool $metaOk = null;

    /**
     * @param array{authorities: list<string>, minApprovals?: ?int, eligibleApprovers?: ?list<string>, freshJustification?: ?bool, maxTtlCeiling?: ?int} $policy
     * @param array{shards?: int, clock?: callable} $options `shards` (default 16, fixed for the life of the store), `clock` (ms) for revocation pruning
     */
    public function __construct(private readonly array $policy, private readonly mixed $kv = null, array $options = [])
    {
        if (!($kv instanceof AtomicKv)) {
            throw new \TypeError('LeaseRegistry: a durable key-value store is required (MemoryLeaseKv is for tests and single-process use)');
        }
        $this->shards = KvDoc::checkShards('LeaseRegistry', $options['shards'] ?? null);
        $c = $policy['maxTtlCeiling'] ?? null;
        if ($c !== null && !(K3Sig::isSafeInt($c) && K3Sig::num($c) >= 1.0)) {
            throw new \RangeException('LeaseRegistry: maxTtlCeiling must be a positive integer');
        }
        $clock = $options['clock'] ?? static fn(): int => (int)(microtime(true) * 1000);
        $this->clock = \Closure::fromCallable($clock);
    }

    public function shardCount(): int
    {
        return $this->shards;
    }

    private function shardKey(int $i): string
    {
        return 'lease/' . $this->shards . '/' . $i;
    }

    private function ready(): bool
    {
        return $this->metaOk ??= KvDoc::ready($this->kv, self::META_KEY, $this->shards);
    }

    /** @return array{leases: array<string,array{current:Obj,history:list<Obj>}>, revocations: list<Obj>} 'k'.lease_id => entry */
    private static function load(?string $raw): array
    {
        $st = ['leases' => [], 'revocations' => []];
        $d = KvDoc::dec($raw);
        if ($d === null || !($d->get('leases') instanceof Obj) || !is_array($d->get('revocations'))) {
            return $st;
        }
        foreach ($d->get('leases')->keys() as $id) {
            $e = $d->get('leases')->get($id);
            if ($e instanceof Obj && $e->get('current') instanceof Obj && is_array($e->get('history'))) {
                $st['leases']['k' . $id] = ['current' => $e->get('current'), 'history' => $e->get('history')];
            }
        }
        $st['revocations'] = array_values(array_filter($d->get('revocations'), static fn($r): bool => $r instanceof Obj));
        return $st;
    }

    /** @param array{leases: array<string,array{current:Obj,history:list<Obj>}>, revocations: list<Obj>} $st */
    private static function encode(array $st): string
    {
        $leases = new Obj();
        foreach ($st['leases'] as $k => $e) {
            $leases->set(substr($k, 1), Obj::of(['current' => $e['current'], 'history' => $e['history']]));
        }
        return KvDoc::enc(Obj::of(['leases' => $leases, 'revocations' => $st['revocations']]));
    }

    private function prune(array &$st): void
    {
        $c = $this->policy['maxTtlCeiling'] ?? null;
        if ($c === null) {
            return;
        }
        $now = ($this->clock)();
        $st['revocations'] = array_values(array_filter($st['revocations'], static fn(Obj $r): bool => (float)K3Sig::num($r->get('revoked_at')) + (float)K3Sig::num($c) >= $now));
    }

    private function shard(string $id): array
    {
        if (!$this->ready()) {
            throw new \RuntimeException('shard count mismatch');
        }
        return self::load($this->kv->get($this->shardKey(KvDoc::shardOf($id, $this->shards))));
    }

    /** The newest record of a lease and whether a stored revocation covers it (null: unknown lease). Throws when the store fails. @return array{current: Obj, revoked: bool}|null */
    public function lookup(string $id): ?array
    {
        $st = $this->shard($id);
        $cur = $st['leases']['k' . $id]['current'] ?? null;
        if ($cur === null) {
            return null;
        }
        $revoked = false;
        foreach ($st['revocations'] as $r) {
            $revoked = $revoked || Lease::covers($r, $cur);
        }
        return ['current' => $cur, 'revoked' => $revoked];
    }

    public function current(string $id): ?Obj
    {
        return $this->shard($id)['leases']['k' . $id]['current'] ?? null;
    }

    /** Every stored revocation (the union over the shards, by signature). @return list<Obj> */
    public function revocations(): array
    {
        if (!$this->ready()) {
            throw new \RuntimeException('shard count mismatch');
        }
        $out = [];
        for ($i = 0; $i < $this->shards; $i++) {
            foreach (self::load($this->kv->get($this->shardKey($i)))['revocations'] as $r) {
                $out[(string)$r->get('sig')] = $r;
            }
        }
        return array_values($out);
    }

    /** @return list<array<string,mixed>> */
    public function history(string $id): array
    {
        $h = $this->shard($id)['leases']['k' . $id]['history'] ?? [];
        return array_map(static fn(Obj $e): array => ['seq' => $e->get('seq')->int(), 'renewed_at' => $e->get('renewed_at')->int(), 'expires_at' => $e->get('expires_at')->int(),
            'justification_digest' => $e->get('justification_digest')], $h);
    }

    /**
     * Take an issue (seq 1) or a renewal (seq = current + 1). $chain: the keys in the holder's delegation chain.
     * @param list<string> $chain
     * @return array{ok: bool, replaced?: bool, seq?: int, code?: string, reason?: string}
     */
    public function accept(mixed $rec, array $chain = []): array
    {
        try {
            if (!Lease::verify($rec)) {
                return ['ok' => false, 'code' => 'bad_record'];
            }
            if (!in_array($rec->get('authority'), $this->policy['authorities'], true)) {
                return ['ok' => false, 'code' => 'unknown_authority'];
            }
            $sod = Lease::sodError($rec, $this->policy, $chain);
            if ($sod !== null) {
                return ['ok' => false, 'code' => 'sod', 'reason' => $sod];
            }
            if ((float)K3Sig::num($rec->get('expires_at')) > Lease::cap($rec)) {
                return ['ok' => false, 'code' => 'over_max_ttl'];
            }
            $ceiling = $this->policy['maxTtlCeiling'] ?? null;
            if ($ceiling !== null && K3Sig::num($rec->get('max_ttl')) > K3Sig::num($ceiling)) {
                return ['ok' => false, 'code' => 'ttl_ceiling'];
            }
            if (!$this->ready()) {
                return ['ok' => false, 'code' => 'store_unreachable'];
            }
            $out = ['ok' => false, 'code' => 'store_unreachable'];
            $this->kv->update($this->shardKey(KvDoc::shardOf($rec->get('lease_id'), $this->shards)), function (?string $prev) use ($rec, &$out): ?string {
                $st = self::load($prev);
                $fail = static function (string $code) use (&$out): ?string {
                    $out = ['ok' => false, 'code' => $code];
                    return null;
                };
                foreach ($st['revocations'] as $r) {
                    if (Lease::covers($r, $rec)) {
                        return $fail('revoked');
                    }
                }
                $num = static fn (Obj $o, string $k): float => (float)K3Sig::num($o->get($k));
                $seq = $num($rec, 'seq');
                $id = $rec->get('lease_id');
                $cur = $st['leases']['k' . $id]['current'] ?? null;
                if ($cur === null) {
                    if ($seq !== 1.0) {
                        return $fail('bad_seq');
                    }
                } else {
                    $cs = $num($cur, 'seq');
                    if ($seq < $cs) {
                        return $fail('stale_seq');
                    }
                    if ($seq === $cs) {
                        if ($cur->get('sig') === $rec->get('sig')) {
                            $out = ['ok' => true, 'replaced' => false, 'seq' => (int)$seq];
                            return null;
                        }
                        return $fail('lease_fork');
                    }
                    if ($seq !== $cs + 1.0) {
                        return $fail('bad_seq');
                    }
                    foreach (['authority', 'path', 'grant_ref', 'holder', 'requester'] as $k) {
                        if ($rec->get($k) !== $cur->get($k)) {
                            return $fail('renewal_mismatch');
                        }
                    }
                    if ($num($rec, 'max_ttl') !== $num($cur, 'max_ttl') || $num($rec, 'issued_at') !== $num($cur, 'issued_at')) {
                        return $fail('renewal_mismatch');
                    }
                    if ($num($rec, 'renewed_at') >= $num($cur, 'expires_at')) {
                        return $fail('expired_lease');
                    }
                    if ($num($rec, 'renewed_at') < $num($cur, 'renewed_at') || $num($rec, 'expires_at') <= $num($cur, 'expires_at')) {
                        return $fail('not_extending');
                    }
                    if (($this->policy['freshJustification'] ?? true) && $rec->get('justification_digest') === $cur->get('justification_digest')) {
                        return $fail('stale_justification');
                    }
                }
                $entry = Obj::of(['seq' => (int)$seq, 'renewed_at' => (int)$num($rec, 'renewed_at'), 'expires_at' => (int)$num($rec, 'expires_at'),
                    'justification_digest' => $rec->get('justification_digest')]);
                $st['leases']['k' . $id] = ['current' => $rec, 'history' => [...($st['leases']['k' . $id]['history'] ?? []), $entry]];
                $this->prune($st);
                $out = ['ok' => true, 'replaced' => true, 'seq' => (int)$seq];
                return self::encode($st);
            });
            return $out;
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'store_unreachable'];
        }
    }

    /** Take a signed revocation. Idempotent. A prefix or grant revocation is written to every shard; the count is the leases covered across them. @return array{ok: bool, revoked?: int, code?: string} */
    public function revoke(mixed $rec): array
    {
        try {
            if (!Lease::verifyRevocation($rec)) {
                return ['ok' => false, 'code' => 'bad_record'];
            }
            if (!in_array($rec->get('authority'), $this->policy['authorities'], true)) {
                return ['ok' => false, 'code' => 'unknown_authority'];
            }
            if (!$this->ready()) {
                return ['ok' => false, 'code' => 'store_unreachable'];
            }
            $targets = $rec->get('target') === 'lease' ? [KvDoc::shardOf($rec->get('value'), $this->shards)] : range(0, $this->shards - 1);
            $n = 0;
            foreach ($targets as $i) {
                $cnt = 0;
                $this->kv->update($this->shardKey($i), function (?string $prev) use ($rec, &$cnt): string {
                    $cnt = 0; // a contended update may call this more than once
                    $st = self::load($prev);
                    $known = false;
                    foreach ($st['revocations'] as $r) {
                        $known = $known || $r->get('sig') === $rec->get('sig');
                    }
                    $known || $st['revocations'][] = $rec;
                    foreach ($st['leases'] as $e) {
                        $cnt += Lease::covers($rec, $e['current']) ? 1 : 0;
                    }
                    $this->prune($st);
                    return self::encode($st);
                });
                $n += $cnt;
            }
            return ['ok' => true, 'revoked' => $n];
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'store_unreachable'];
        }
    }
}
