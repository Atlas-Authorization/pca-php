<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';

/** A refusal of the fenced signer: `reason` is `stale`, `expired`, `store-error` or `no-lease`. */
final class FenceError extends \RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct("fenced: $reason");
    }
}

/**
 * The persistence contract of the leader lease. `cas` replaces the record iff the stored one equals `$expected` (`Jsx::$U` = none),
 * atomically and linearizably, and returns whether it did; `now` is the STORE's clock: every expiry decision uses it.
 */
interface LeaseStore
{
    /** @return mixed the stored record, or `Jsx::$U` when none; throws on a corrupt one */
    public function read(): mixed;

    public function cas(mixed $expected, Obj $next): bool;

    public function now(): int|float;
}

/** The reference {@see LeaseStore} over an {@see AtomicKv} (its `update` is the compare-and-swap). */
final class KvLeaseStore implements LeaseStore
{
    /** @param ?callable():(int|float) $now the store clock (default: wall-clock milliseconds) */
    public function __construct(private readonly AtomicKv $kv, private readonly string $key = 'ha/lease', private readonly mixed $clock = null)
    {
    }

    public function read(): mixed
    {
        $raw = $this->kv->get($this->key);
        $v = $raw === null ? Jsx::$U : Json::parseLax($raw);
        if (!($v instanceof Undef) && !Ha::validRecord($v)) {
            throw new \RuntimeException('corrupt lease state');
        }
        return $v;
    }

    public function cas(mixed $expected, Obj $next): bool
    {
        if (!Ha::validRecord($next)) {
            throw new \RuntimeException('invalid lease record');
        }
        $matched = false;
        $this->kv->update($this->key, function (?string $raw) use ($expected, $next, &$matched): ?string {
            $prev = $raw === null ? Jsx::$U : Json::parseLax($raw);
            if (!($prev instanceof Undef) && !Ha::validRecord($prev)) {
                return null;
            }
            $pe = $prev instanceof Undef ? 0 : Js::num(Jsx::get($prev, 'epoch'));
            if (!Ha::sameLease($prev, $expected) || Js::num($next->get('epoch')) < $pe) {
                return null;
            }
            $matched = true;
            return Json::canonicalizeLenient($next);
        });
        return $matched;
    }

    public function now(): int|float
    {
        return $this->clock !== null ? ($this->clock)() : (int)(self::wallClock() * 1000);
    }

    /** @internal Test seam: when set, the default wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;
    private static function wallClock(): float { return self::$clockHook !== null ? (self::$clockHook)() : microtime(true); }
}

/** Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write). */
final class FenceGuard
{
    private float $hi;

    public function __construct(mixed $initial = 0)
    {
        $this->hi = Ha::safeInt($initial) && Js::num($initial) > 0 ? (float)Js::num($initial) : 0.0;
    }

    public function admit(mixed $epoch): bool
    {
        if (!Ha::safeInt($epoch) || Js::num($epoch) < 1 || Js::num($epoch) < $this->hi) {
            return false;
        }
        $this->hi = (float)Js::num($epoch);
        return true;
    }

    public function highest(): int|float
    {
        return $this->hi;
    }
}

/**
 * Guardian-set high availability: which guardians are live, whether a co-sign quorum is available, the degrade mode when it is lost
 * (read-only or halt, never fail open), signer selection and failover order, and a durable fenced leader lease (acquire, renew,
 * release, a monotonically increasing fencing epoch, a fence check and a fenced signer). A guardian set is
 * `{guardians: [{id, healthy, lastSeen, weight?}], quorum}`, a lease `{holder, epoch, expiresAt}`. Values are the parsed-JSON model.
 */
final class Ha
{
    public const MAX_LEASE_TTL_MS = 3600000;
    public const DEFAULT_LEASE_SKEW_MS = 1000;
    private const MAX_HOLDER_LEN = 256;

    // ---- number helpers (Number.isFinite / isInteger / isSafeInteger take no coercion) --------------------------------------

    private static function fin(mixed $x): ?float
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) ? $f : null;
    }

    private static function isInt(mixed $x): bool
    {
        $f = self::fin($x);
        return $f !== null && $f == floor($f);
    }

    public static function safeInt(mixed $x): bool
    {
        $f = self::fin($x);
        return $f !== null && $f == floor($f) && abs($f) <= 9007199254740991.0;
    }

    private static function isObject(mixed $x): bool
    {
        return $x instanceof Obj || (is_array($x) && array_is_list($x));
    }

    // ---- guardian liveness ------------------------------------------------------------------------------------------------

    /**
     * Guardians that are flagged healthy AND have a fresh heartbeat at `$now`. Fails closed: a malformed set, a non-finite clock or
     * stale window, a non-finite or future-dated heartbeat, or a non-boolean `healthy` counts as down. `$opts`: `{staleMs?}`.
     * @return list<mixed>
     */
    public static function liveGuardians(mixed $set, mixed $now, mixed $opts = null): array
    {
        $sm = Jsx::get($opts, 'staleMs');
        $stale = $sm === null || $sm instanceof Undef ? 30000.0 : self::fin($sm);
        $n = self::fin($now);
        $gs = Jsx::get($set, 'guardians');
        if ($n === null || $stale === null || $stale < 0 || !is_array($gs) || !array_is_list($gs)) {
            return [];
        }
        foreach ($gs as $g) {
            if (!self::isObject($g)) {
                return [];
            }
        }
        $out = [];
        foreach ($gs as $g) {
            $ls = self::fin(Jsx::get($g, 'lastSeen'));
            if (Jsx::get($g, 'healthy') === true && $ls !== null && $ls <= $n && $n - $ls <= $stale) {
                $out[] = $g;
            }
        }
        return $out;
    }

    private static function weightOf(mixed $g): float
    {
        return self::fin(Jsx::get($g, 'weight')) ?? 0.0;
    }

    /** The preference order: higher weight, fresher heartbeat, then the id in the default locale collation. @param list<mixed> $live @return list<mixed> */
    private static function preferred(array $live): array
    {
        static $collator = null;
        $collator ??= new \Collator('en-US');
        usort($live, static function ($a, $b) use ($collator): int {
            $w = self::weightOf($b) <=> self::weightOf($a);
            if ($w !== 0) {
                return $w;
            }
            $l = (float)self::fin(Jsx::get($b, 'lastSeen')) <=> (float)self::fin(Jsx::get($a, 'lastSeen'));
            if ($l !== 0) {
                return $l;
            }
            $x = Jsx::get($a, 'id');
            $y = Jsx::get($b, 'id');
            if (!is_string($x) || !is_string($y)) {
                throw new \TypeError('guardian id is not a string');
            }
            return $collator->compare($x, $y);
        });
        return $live;
    }

    /** The quorum status: `{total, live, quorum?, available, degraded}`. */
    public static function quorumStatus(mixed $set, mixed $now, mixed $opts = null): Obj
    {
        $live = count(self::liveGuardians($set, $now, $opts));
        $gs = Jsx::get($set, 'guardians');
        $q = Jsx::get($set, 'quorum');
        $o = Obj::of(['total' => is_array($gs) && array_is_list($gs) ? count($gs) : 0, 'live' => $live]);
        if (!($q instanceof Undef)) {
            $o->set('quorum', $q);
        }
        $o->set('available', self::isInt($q) && Js::num($q) >= 1 && $live >= Js::num($q));
        $o->set('degraded', $live > 0 && Jsx::lt($live, Jsx::rd($set, 'quorum')));
        return $o;
    }

    /** `normal` with a quorum, `read-only` below quorum with some guardians live (unless `{allowReadOnly: false}`), else `halt`. */
    public static function degradeMode(mixed $status, mixed $policy = null): string
    {
        if (Jsx::truthy(Jsx::rd($status, 'available'))) {
            return 'normal';
        }
        if (Jsx::gt(Jsx::get($status, 'live'), 0) && Jsx::get($policy, 'allowReadOnly') !== false) {
            return 'read-only';
        }
        return 'halt';
    }

    /** The `quorum` freshest and highest-weight live guardians; empty when a quorum is not available. @return list<mixed> */
    public static function selectSigners(mixed $set, mixed $now, mixed $opts = null): array
    {
        $live = self::liveGuardians($set, $now, $opts);
        $q = Jsx::rd($set, 'quorum');
        if (!self::isInt($q) || Js::num($q) < 1 || count($live) < Js::num($q)) {
            return [];
        }
        return array_map(static fn($g) => ($v = Jsx::get($g, 'id')) instanceof Undef ? null : $v, array_slice(self::preferred($live), 0, (int)Js::num($q))); // undefined in an array is null in JSON
    }

    /** A primary (or null) and the standbys in preference order. */
    public static function failoverPlan(mixed $set, mixed $now, mixed $opts = null): Obj
    {
        $live = self::preferred(self::liveGuardians($set, $now, $opts));
        $id = static fn($g) => ($v = Jsx::get($g, 'id')) instanceof Undef ? null : $v;
        return Obj::of(['primary' => $live === [] ? null : $id($live[0]), 'standbys' => array_map($id, array_slice($live, 1))]);
    }

    /** The reason a guardian set is malformed (quorum out of range, empty or duplicate ids), or null. */
    public static function validateGuardianSet(mixed $set): ?string
    {
        if (!self::isObject($set)) {
            return 'guardian set is not an object';
        }
        $gs = Jsx::get($set, 'guardians');
        if (!is_array($gs) || !array_is_list($gs) || $gs === []) {
            return 'guardian set is empty';
        }
        $q = Jsx::get($set, 'quorum');
        if (!self::isInt($q) || Js::num($q) < 1) {
            return 'quorum must be an integer ≥ 1';
        }
        if (Js::num($q) > count($gs)) {
            return 'quorum exceeds guardian count';
        }
        $ids = [];
        foreach ($gs as $g) {
            $id = self::isObject($g) ? Jsx::get($g, 'id') : null;
            if (!is_string($id) || $id === '') {
                return 'guardian id must be a non-empty string';
            }
            $ids[$id] = true;
        }
        return count($ids) !== count($gs) ? 'duplicate guardian ids' : null;
    }

    // ---- the fenced leader lease --------------------------------------------------------------------------------------------

    /** A well-formed lease record: a string holder, a safe-integer epoch of at least 1, a finite non-negative expiry. */
    public static function validRecord(mixed $r): bool
    {
        if (!self::isObject($r)) {
            return false;
        }
        $e = self::fin(Jsx::get($r, 'expiresAt'));
        return is_string(Jsx::get($r, 'holder')) && self::safeInt(Jsx::get($r, 'epoch')) && Js::num(Jsx::get($r, 'epoch')) >= 1 && $e !== null && $e >= 0;
    }

    /** Equality of two lease values by holder, epoch and expiry (extra members ignored); two absent values are equal. */
    public static function sameLease(mixed $a, mixed $b): bool
    {
        if ($a instanceof Undef || $b instanceof Undef) {
            return $a instanceof Undef && $b instanceof Undef;
        }
        foreach (['holder', 'epoch', 'expiresAt'] as $k) {
            if (!self::same(Jsx::rd($a, $k), Jsx::rd($b, $k))) {
                return false;
            }
        }
        return true;
    }

    private static function same(mixed $x, mixed $y): bool
    {
        $fx = Js::num($x);
        $fy = Js::num($y);
        return $fx !== null || $fy !== null ? $fx !== null && $fy !== null && $fx == $fy : $x === $y;
    }

    /** @return array{ttl:float,skew:float}|null */
    private static function leaseOpts(mixed $holder, mixed $o): ?array
    {
        if (!is_string($holder) || $holder === '' || Js::len($holder) > self::MAX_HOLDER_LEN) {
            return null;
        }
        $sk = Jsx::get($o, 'skewMs');
        $skew = $sk === null || $sk instanceof Undef ? (float)self::DEFAULT_LEASE_SKEW_MS : self::fin($sk);
        $ttl = Jsx::get($o, 'ttlMs');
        if (!self::isInt($ttl) || Js::num($ttl) < 2 || Js::num($ttl) > self::MAX_LEASE_TTL_MS) {
            return null;
        }
        if ($skew === null || $skew < 0 || $skew >= Js::num($ttl)) {
            return null;
        }
        return ['ttl' => (float)Js::num($ttl), 'skew' => $skew];
    }

    /** @return array{0:mixed,1:float} the record and the store clock; a corrupt record or clock is an error, never "free" */
    private static function snapshot(LeaseStore $store): array
    {
        $cur = $store->read();
        $now = self::fin($store->now());
        if ($now === null || (!($cur instanceof Undef) && !self::validRecord($cur))) {
            throw new \RuntimeException('corrupt lease state');
        }
        return [$cur, $now];
    }

    private static function lease(string $holder, mixed $epoch, float $expiresAt): Obj
    {
        return Obj::of(['holder' => $holder, 'epoch' => $epoch, 'expiresAt' => $expiresAt]);
    }

    private static function storeError(\Throwable $e): array
    {
        return ['ok' => false, 'reason' => 'store-error', 'detail' => $e instanceof \RuntimeException || $e instanceof \Error ? $e->getMessage() : 'unknown'];
    }

    private static function swap(LeaseStore $store, mixed $cur, Obj $next): array
    {
        return $store->cas($cur, $next) ? ['ok' => true, 'lease' => $next] : ['ok' => false, 'reason' => 'lost-race'];
    }

    /**
     * Take the lease when it is free (never held, released, or expired past the skew); the epoch increments on every takeover.
     * @param mixed $o `{ttlMs, skewMs?}` @return array<string,mixed> `{ok: true, lease}` or `{ok: false, reason, detail?}`
     */
    public static function acquireLease(LeaseStore $store, mixed $holder, mixed $o): array
    {
        $p = self::leaseOpts($holder, $o);
        if ($p === null) {
            return ['ok' => false, 'reason' => 'invalid'];
        }
        try {
            [$cur, $now] = self::snapshot($store);
            if (!($cur instanceof Undef) && !(Js::num($cur->get('expiresAt')) + $p['skew'] <= $now) && Js::num($cur->get('expiresAt')) != 0) {
                return ['ok' => false, 'reason' => 'held'];
            }
            $epoch = ($cur instanceof Undef ? 0 : (int)Js::num($cur->get('epoch'))) + 1;
            return self::swap($store, $cur, self::lease($holder, $epoch, $now + $p['ttl']));
        } catch (\Throwable $e) {
            return self::storeError($e);
        }
    }

    /** Extend a lease the caller still holds; refused once the holder's own safe window (expiry minus skew) has passed or after a takeover. */
    public static function renewLease(LeaseStore $store, mixed $lease, mixed $o): array
    {
        $p = self::validRecord($lease) ? self::leaseOpts(Jsx::get($lease, 'holder'), $o) : null;
        if ($p === null) {
            return ['ok' => false, 'reason' => 'invalid'];
        }
        try {
            [$cur, $now] = self::snapshot($store);
            if ($cur instanceof Undef || $cur->get('holder') !== Jsx::get($lease, 'holder') || !self::same($cur->get('epoch'), Jsx::get($lease, 'epoch'))) {
                return ['ok' => false, 'reason' => 'stale'];
            }
            if (!(Js::num($cur->get('expiresAt')) - $p['skew'] > $now)) {
                return ['ok' => false, 'reason' => 'expired'];
            }
            return self::swap($store, $cur, self::lease($cur->get('holder'), $cur->get('epoch'), $now + $p['ttl']));
        } catch (\Throwable $e) {
            return self::storeError($e);
        }
    }

    /** Give the lease up early (`expiresAt` 0, epoch kept); only the current holder at the current epoch can. */
    public static function releaseLease(LeaseStore $store, mixed $lease): array
    {
        if (!self::validRecord($lease)) {
            return ['ok' => false, 'reason' => 'invalid'];
        }
        try {
            [$cur] = self::snapshot($store);
            if ($cur instanceof Undef || $cur->get('holder') !== Jsx::get($lease, 'holder') || !self::same($cur->get('epoch'), Jsx::get($lease, 'epoch')) || Js::num($cur->get('expiresAt')) == 0) {
                return ['ok' => false, 'reason' => 'stale'];
            }
            return self::swap($store, $cur, self::lease($cur->get('holder'), $cur->get('epoch'), 0.0));
        } catch (\Throwable $e) {
            return self::storeError($e);
        }
    }

    /** Is this exact (holder, epoch) still the leader, with its safe window open, per the store? Any error answers no. @param mixed $skewMs null = the default */
    public static function assertFence(LeaseStore $store, mixed $token, mixed $skewMs = null): array
    {
        $skew = $skewMs === null ? (float)self::DEFAULT_LEASE_SKEW_MS : self::fin($skewMs);
        try {
            if (!Jsx::truthy($token) || $skew === null || $skew < 0) {
                return ['ok' => false, 'reason' => 'stale'];
            }
            [$cur, $now] = self::snapshot($store);
            if ($cur instanceof Undef || $cur->get('holder') !== Jsx::get($token, 'holder') || !self::same($cur->get('epoch'), Jsx::get($token, 'epoch'))) {
                return ['ok' => false, 'reason' => 'stale'];
            }
            return Js::num($cur->get('expiresAt')) - $skew > $now ? ['ok' => true] : ['ok' => false, 'reason' => 'expired'];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'store-error'];
        }
    }

    /**
     * Wrap a co-sign function so it runs only while the caller is the fenced leader: the fence is checked before AND after the
     * signature, and a leader that lost the lease mid-signature gets a {@see FenceError} and the signature is discarded.
     * @param callable():mixed $getLease the held lease or `Jsx::$U` @param callable(mixed...):mixed $sign
     * @return callable(mixed...):array{result:mixed,epoch:mixed}
     */
    public static function fencedSigner(LeaseStore $store, callable $getLease, callable $sign, mixed $skewMs = null): callable
    {
        return static function (mixed ...$a) use ($store, $getLease, $sign, $skewMs): array {
            $lease = $getLease();
            if (!Jsx::truthy($lease)) {
                throw new FenceError('no-lease');
            }
            $pre = self::assertFence($store, $lease, $skewMs);
            if (!$pre['ok']) {
                throw new FenceError($pre['reason']);
            }
            $result = $sign(...$a);
            $post = self::assertFence($store, $lease, $skewMs);
            if (!$post['ok']) {
                throw new FenceError($post['reason']);
            }
            return ['result' => $result, 'epoch' => Jsx::get($lease, 'epoch')];
        };
    }
}
