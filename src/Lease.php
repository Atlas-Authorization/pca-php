<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';

/**
 * Leases (verification side): a time-boxed, renewable record with a hard max_ttl, separation of duties and revoke by id, path prefix
 * or grant. {@see LeaseRegistry} keeps the newest record per lease_id (in memory). Total. Replays
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
        $cur = $registry->current($id);
        if ($cur === null) {
            return $deny('unknown_lease');
        }
        if ($cur->get('sig') !== $presented->get('sig')) {
            return $deny('superseded');
        }
        foreach ($registry->revocations() as $r) {
            if (self::covers($r, $cur)) {
                return $deny('revoked');
            }
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

/** The newest record per lease_id, the revocation list and the renewal ledger, in memory. */
final class LeaseRegistry
{
    /** @var array<string,Obj> 'k'.lease_id => newest record */
    private array $leases = [];
    /** @var array<string,list<array<string,mixed>>> */
    private array $history = [];
    /** @var list<Obj> */
    private array $revocations = [];

    /** @param array{authorities: list<string>, minApprovals?: ?int, eligibleApprovers?: ?list<string>, freshJustification?: ?bool} $policy */
    public function __construct(private readonly array $policy)
    {
    }

    public function current(string $id): ?Obj
    {
        return $this->leases['k' . $id] ?? null;
    }

    /** @return list<Obj> */
    public function revocations(): array
    {
        return $this->revocations;
    }

    /** @return list<array<string,mixed>> */
    public function history(string $id): array
    {
        return $this->history['k' . $id] ?? [];
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
            foreach ($this->revocations as $r) {
                if (Lease::covers($r, $rec)) {
                    return ['ok' => false, 'code' => 'revoked'];
                }
            }
            $num = static fn (Obj $o, string $k): float => (float)K3Sig::num($o->get($k));
            $seq = $num($rec, 'seq');
            $cur = $this->current($rec->get('lease_id'));
            if ($cur === null) {
                if ($seq !== 1.0) {
                    return ['ok' => false, 'code' => 'bad_seq'];
                }
            } else {
                $cs = $num($cur, 'seq');
                if ($seq < $cs) {
                    return ['ok' => false, 'code' => 'stale_seq'];
                }
                if ($seq === $cs) {
                    return $cur->get('sig') === $rec->get('sig') ? ['ok' => true, 'replaced' => false, 'seq' => (int)$seq] : ['ok' => false, 'code' => 'lease_fork'];
                }
                if ($seq !== $cs + 1.0) {
                    return ['ok' => false, 'code' => 'bad_seq'];
                }
                foreach (['authority', 'path', 'grant_ref', 'holder', 'requester'] as $k) {
                    if ($rec->get($k) !== $cur->get($k)) {
                        return ['ok' => false, 'code' => 'renewal_mismatch'];
                    }
                }
                if ($num($rec, 'max_ttl') !== $num($cur, 'max_ttl') || $num($rec, 'issued_at') !== $num($cur, 'issued_at')) {
                    return ['ok' => false, 'code' => 'renewal_mismatch'];
                }
                if ($num($rec, 'renewed_at') >= $num($cur, 'expires_at')) {
                    return ['ok' => false, 'code' => 'expired_lease'];
                }
                if ($num($rec, 'renewed_at') < $num($cur, 'renewed_at') || $num($rec, 'expires_at') <= $num($cur, 'expires_at')) {
                    return ['ok' => false, 'code' => 'not_extending'];
                }
                if (($this->policy['freshJustification'] ?? true) && $rec->get('justification_digest') === $cur->get('justification_digest')) {
                    return ['ok' => false, 'code' => 'stale_justification'];
                }
            }
            $id = $rec->get('lease_id');
            $this->leases['k' . $id] = $rec;
            $this->history['k' . $id][] = ['seq' => (int)$seq, 'renewed_at' => (int)$num($rec, 'renewed_at'), 'expires_at' => (int)$num($rec, 'expires_at'), 'justification_digest' => $rec->get('justification_digest')];
            return ['ok' => true, 'replaced' => true, 'seq' => (int)$seq];
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'store_unreachable'];
        }
    }

    /** Take a signed revocation. Idempotent. @return array{ok: bool, revoked?: int, code?: string} */
    public function revoke(mixed $rec): array
    {
        try {
            if (!Lease::verifyRevocation($rec)) {
                return ['ok' => false, 'code' => 'bad_record'];
            }
            if (!in_array($rec->get('authority'), $this->policy['authorities'], true)) {
                return ['ok' => false, 'code' => 'unknown_authority'];
            }
            $known = false;
            foreach ($this->revocations as $r) {
                $known = $known || $r->get('sig') === $rec->get('sig');
            }
            $known || $this->revocations[] = $rec;
            $n = 0;
            foreach ($this->leases as $l) {
                $n += Lease::covers($rec, $l) ? 1 : 0;
            }
            return ['ok' => true, 'revoked' => $n];
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'store_unreachable'];
        }
    }
}
