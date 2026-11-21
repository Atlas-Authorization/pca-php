<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/KvDoc.php';

/**
 * Break-glass grants (verification side): time-boxed, loud, auto-revoked, with a mandatory signed review. {@see BreakGlassRegistry}
 * keeps state grouped by holder (in memory). Total. Replays packages/pca/conformance/break-glass-vectors.json. Records are parsed
 * JSON (Obj, lists, Num).
 */
final class BreakGlass
{
    public const DOMAIN = "atlas-pca/break-glass/v1\0";
    public const REVIEW_DOMAIN = "atlas-pca/break-glass-review/v1\0";
    public const MAX_WINDOW_MS = 86400000;
    public const MAX_USES = 16;
    public const MAX_REVIEW_WITHIN_MS = 30 * 86400000;
    private const BODY_KEYS = ['v', 'id', 'holder', 'grant_ref', 'reason_digest', 'max_uses', 'issued_at', 'expires_at', 'review_within', 'notify_to', 'authority'];
    private const REVIEW_KEYS = ['v', 'id', 'outcome', 'notes_digest', 'at', 'reviewer'];

    public static function n(Obj $o, string $k): float
    {
        return (float)K3Sig::num($o->get($k));
    }

    public static function wellFormed(mixed $b): bool
    {
        if (!($b instanceof Obj) || !K3Sig::isNumber($b->get('v'), 1.0)) {
            return false;
        }
        foreach (['id' => 128, 'holder' => 128, 'grant_ref' => 256, 'reason_digest' => 128, 'notify_to' => 256, 'authority' => 128] as $k => $max) {
            if (!K3Sig::isStr($b->get($k), $max)) {
                return false;
            }
        }
        foreach (['max_uses', 'issued_at', 'expires_at', 'review_within'] as $k) {
            if (!K3Sig::isSafeInt($b->get($k))) {
                return false;
            }
        }
        if (self::n($b, 'max_uses') < 1.0 || self::n($b, 'max_uses') > self::MAX_USES) {
            return false;
        }
        if (self::n($b, 'expires_at') <= self::n($b, 'issued_at') || self::n($b, 'expires_at') - self::n($b, 'issued_at') > self::MAX_WINDOW_MS) {
            return false;
        }
        return self::n($b, 'review_within') >= 1.0 && self::n($b, 'review_within') <= self::MAX_REVIEW_WITHIN_MS;
    }

    private static function body(Obj $o, array $keys): Obj
    {
        $b = new Obj();
        foreach ($keys as $k) {
            $b->set($k, $o->get($k));
        }
        return $b;
    }

    public static function verify(mixed $b): bool
    {
        return self::wellFormed($b) && K3Sig::verifyBody(self::DOMAIN, self::body($b, self::BODY_KEYS), $b->get('authority'), $b->get('sig'));
    }

    public static function reviewWellFormed(mixed $r): bool
    {
        return $r instanceof Obj && K3Sig::isNumber($r->get('v'), 1.0) && K3Sig::isStr($r->get('id'), 128)
            && in_array($r->get('outcome'), ['justified', 'unjustified'], true) && K3Sig::isStr($r->get('notes_digest'), 128)
            && K3Sig::isSafeInt($r->get('at')) && K3Sig::isStr($r->get('reviewer'), 128);
    }

    public static function verifyReview(mixed $r): bool
    {
        return self::reviewWellFormed($r) && K3Sig::verifyBody(self::REVIEW_DOMAIN, self::body($r, self::REVIEW_KEYS), $r->get('reviewer'), $r->get('sig'));
    }
}

/**
 * Break-glass state grouped by holder on a durable {@see AtomicKv} ({@see MemoryLeaseKv} is for tests and one process): a use budget or a
 * freeze that a restart forgot would be fail-open, so the store is required. Each holder's grants live in the shard the holder hashes to;
 * every operation is one atomic `update` of that shard, and a store failure is `store_unreachable`.
 */
final class BreakGlassRegistry
{
    private const META_KEY = 'breakglass/meta';
    private readonly int $shards;
    private ?bool $metaOk = null;

    /**
     * @param array{authorities: list<string>, reviewers: list<string>} $policy
     * @param array{shards?: int} $options
     */
    public function __construct(private readonly array $policy, private readonly mixed $kv = null, array $options = [])
    {
        if (!($kv instanceof AtomicKv)) {
            throw new \TypeError('BreakGlassRegistry: a durable key-value store is required (MemoryLeaseKv is for tests and single-process use)');
        }
        $this->shards = KvDoc::checkShards('BreakGlassRegistry', $options['shards'] ?? null);
    }

    private function shardKey(string $holder): string
    {
        return 'breakglass/' . $this->shards . '/' . KvDoc::shardOf($holder, $this->shards);
    }

    private function ready(): bool
    {
        return $this->metaOk ??= KvDoc::ready($this->kv, self::META_KEY, $this->shards);
    }

    /** @return array<string,array<string,array{rec:Obj,uses:list<array<string,mixed>>,review:?Obj}>> 'k'.holder => 'k'.id => entry */
    private static function load(?string $raw): array
    {
        $out = [];
        $d = KvDoc::dec($raw);
        if ($d === null || !($d->get('holders') instanceof Obj)) {
            return $out;
        }
        foreach ($d->get('holders')->keys() as $h) {
            $ids = $d->get('holders')->get($h);
            foreach ($ids instanceof Obj ? $ids->keys() : [] as $id) {
                $e = $ids->get($id);
                if (!($e instanceof Obj) || !($e->get('rec') instanceof Obj) || !is_array($e->get('uses'))) {
                    continue;
                }
                $uses = array_map(static fn(Obj $u): array => ['n' => $u->get('n')->int(), 'action_digest' => $u->get('action_digest'), 'at' => (float)K3Sig::num($u->get('at'))],
                    array_values(array_filter($e->get('uses'), static fn($u): bool => $u instanceof Obj)));
                $out['k' . $h]['k' . $id] = ['rec' => $e->get('rec'), 'uses' => $uses, 'review' => $e->get('review') instanceof Obj ? $e->get('review') : null];
            }
        }
        return $out;
    }

    /** @param array<string,array<string,array{rec:Obj,uses:list<array<string,mixed>>,review:?Obj}>> $st */
    private static function encode(array $st): string
    {
        $holders = new Obj();
        foreach ($st as $hk => $ids) {
            $o = new Obj();
            foreach ($ids as $ik => $e) {
                $o->set(substr($ik, 1), Obj::of(['rec' => $e['rec'], 'review' => $e['review'],
                    'uses' => array_map(static fn(array $u): Obj => Obj::of(['n' => $u['n'], 'action_digest' => $u['action_digest'], 'at' => (int)$u['at']]), $e['uses'])]));
            }
            $holders->set(substr($hk, 1), $o);
        }
        return KvDoc::enc(Obj::of(['holders' => $holders]));
    }

    /**
     * One atomic update of a holder's shard. `$fn(&$state)` returns true to store the changed state, false to leave it; it may call
     * `$state` freely and its result is whatever it captured. Throws when the store fails (every caller turns that into store_unreachable).
     */
    private function mutate(string $holder, callable $fn): void
    {
        if (!$this->ready()) {
            throw new \RuntimeException('shard count mismatch');
        }
        $this->kv->update($this->shardKey($holder), function (?string $prev) use ($fn): ?string {
            $st = self::load($prev);
            return $fn($st) === true ? self::encode($st) : null;
        });
    }

    private function read(string $holder): array
    {
        if (!$this->ready()) {
            throw new \RuntimeException('shard count mismatch');
        }
        return self::load($this->kv->get($this->shardKey($holder)));
    }

    /** @param array<string,array{rec:Obj,uses:list<array<string,mixed>>,review:?Obj}> $st */
    private static function frozenIn(array $st, string $holder, float $now): bool
    {
        foreach ($st as $e) {
            if ($e['rec']->get('holder') !== $holder) {
                continue;
            }
            if ($e['review'] !== null ? $e['review']->get('outcome') === 'unjustified'
                : ($e['uses'] !== [] && $now >= $e['uses'][0]['at'] + BreakGlass::n($e['rec'], 'review_within'))) {
                return true;
            }
        }
        return false;
    }

    /** @return array{ok: bool, replaced?: bool, code?: string} */
    public function accept(mixed $rec, mixed $now): array
    {
        try {
            if (!BreakGlass::verify($rec) || !K3Sig::isSafeInt($now)) {
                return ['ok' => false, 'code' => 'bad_record'];
            }
            if (!in_array($rec->get('authority'), $this->policy['authorities'], true)) {
                return ['ok' => false, 'code' => 'unknown_authority'];
            }
            $out = ['ok' => false, 'code' => 'store_unreachable'];
            $this->mutate($rec->get('holder'), function (array &$all) use ($rec, $now, &$out): bool {
                $hk = 'k' . $rec->get('holder');
                $ik = 'k' . $rec->get('id');
                $st = $all[$hk] ?? [];
                if (isset($st[$ik])) {
                    $out = $st[$ik]['rec']->get('sig') === $rec->get('sig') ? ['ok' => true, 'replaced' => false] : ['ok' => false, 'code' => 'id_conflict'];
                    return false;
                }
                if (self::frozenIn($st, $rec->get('holder'), (float)K3Sig::num($now))) {
                    $out = ['ok' => false, 'code' => 'holder_frozen'];
                    return false;
                }
                $all[$hk][$ik] = ['rec' => $rec, 'uses' => [], 'review' => null];
                $out = ['ok' => true, 'replaced' => true];
                return true;
            });
            return $out;
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'store_unreachable'];
        }
    }

    /** @return array<string,mixed> ['decision' => 'allow', id, use, remaining, review_due] or ['decision' => 'deny', code[, id]] */
    public function use(mixed $id, mixed $holder, mixed $actionDigest, mixed $now, mixed $notified): array
    {
        try {
            if (!K3Sig::isStr($id, 128) || !K3Sig::isStr($holder, 128) || !K3Sig::isStr($actionDigest, 128) || !K3Sig::isSafeInt($now) || !is_bool($notified)) {
                return ['decision' => 'deny', 'code' => 'bad_input'];
            }
            $out = ['decision' => 'deny', 'code' => 'store_unreachable', 'id' => $id];
            $this->mutate($holder, function (array &$all) use ($id, $holder, $actionDigest, $now, $notified, &$out): bool {
                $deny = static function (string $code) use ($id, &$out): bool {
                    $out = ['decision' => 'deny', 'code' => $code, 'id' => $id];
                    return false;
                };
                $t = (float)K3Sig::num($now);
                $st = $all['k' . $holder] ?? [];
                $e = $st['k' . $id] ?? null;
                if ($e === null) {
                    return $deny('unknown_break_glass');
                }
                $rec = $e['rec'];
                if (self::frozenIn($st, $holder, $t)) {
                    return $deny('holder_frozen');
                }
                if ($e['review'] !== null && $e['review']->get('outcome') === 'unjustified') {
                    return $deny('revoked');
                }
                if ($t < BreakGlass::n($rec, 'issued_at')) {
                    return $deny('not_yet_valid');
                }
                if ($t >= BreakGlass::n($rec, 'expires_at')) {
                    return $deny('expired');
                }
                $used = count($e['uses']);
                if ($used >= BreakGlass::n($rec, 'max_uses')) {
                    return $deny('budget_exhausted');
                }
                if (!$notified) {
                    return $deny('not_notified');
                }
                $all['k' . $holder]['k' . $id]['uses'][] = ['n' => $used + 1, 'action_digest' => $actionDigest, 'at' => $t];
                $first = $e['uses'][0]['at'] ?? $t;
                $out = ['decision' => 'allow', 'id' => $id, 'use' => $used + 1, 'remaining' => (int)BreakGlass::n($rec, 'max_uses') - $used - 1,
                    'review_due' => (int)($first + BreakGlass::n($rec, 'review_within'))];
                return true;
            });
            return $out;
        } catch (\Throwable) {
            return ['decision' => 'deny', 'code' => 'store_unreachable', 'id' => is_string($id) ? $id : null];
        }
    }

    /** @return array{ok: bool, replaced?: bool, code?: string} */
    public function review(mixed $rec, mixed $holder, mixed $now): array
    {
        try {
            if (!BreakGlass::verifyReview($rec) || !K3Sig::isStr($holder, 128) || !K3Sig::isSafeInt($now)) {
                return ['ok' => false, 'code' => 'bad_record'];
            }
            if (!in_array($rec->get('reviewer'), $this->policy['reviewers'], true)) {
                return ['ok' => false, 'code' => 'unknown_reviewer'];
            }
            $out = ['ok' => false, 'code' => 'store_unreachable'];
            $this->mutate($holder, function (array &$all) use ($rec, $holder, $now, &$out): bool {
                $e = $all['k' . $holder]['k' . $rec->get('id')] ?? null;
                if ($e === null) {
                    $out = ['ok' => false, 'code' => 'unknown_break_glass'];
                    return false;
                }
                if ($rec->get('reviewer') === $e['rec']->get('holder') || $rec->get('reviewer') === $e['rec']->get('authority')) {
                    $out = ['ok' => false, 'code' => 'sod'];
                    return false;
                }
                if ($e['review'] !== null) {
                    $out = $e['review']->get('sig') === $rec->get('sig') ? ['ok' => true, 'replaced' => false] : ['ok' => false, 'code' => 'already_reviewed'];
                    return false;
                }
                if ($e['uses'] === []) {
                    $out = ['ok' => false, 'code' => 'nothing_to_review'];
                    return false;
                }
                $at = BreakGlass::n($rec, 'at');
                if ($at < $e['uses'][0]['at'] || $at > (float)K3Sig::num($now)) {
                    $out = ['ok' => false, 'code' => 'bad_time'];
                    return false;
                }
                $all['k' . $holder]['k' . $rec->get('id')]['review'] = $rec;
                $out = ['ok' => true, 'replaced' => true];
                return true;
            });
            return $out;
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'store_unreachable'];
        }
    }

    public function frozen(mixed $holder, mixed $now): bool
    {
        if (!K3Sig::isStr($holder, 128) || !K3Sig::isSafeInt($now)) {
            return true; // fail closed
        }
        try {
            return self::frozenIn($this->read($holder)['k' . $holder] ?? [], $holder, (float)K3Sig::num($now));
        } catch (\Throwable) {
            return true;
        }
    }
}
