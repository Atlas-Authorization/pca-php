<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/KvDoc.php';

/**
 * Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop issued
 * by that key. {@see Blueprint::accept} keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the same
 * epoch with different content is a fork). A non-empty ceiling is never evaluated here: it denies (`ceiling_unevaluable`); neither is
 * instance admission unless the host passes `admitted`: a record with `runtime_pins` denies (`admission_required`, or `not_admitted` when the hook says no). Total.
 * Records and chains are parsed JSON (Obj, lists). The pure functions take the registry as an array<string,Obj>; {@see BlueprintRegistry} runs them over a durable {@see BlueprintStore} (required).
 */
final class Blueprint
{
    public const DOMAIN = "atlas-pca/agent-blueprint/v1\0";
    private const BODY_KEYS = ['v', 'id', 'key', 'ceiling', 'max_depth', 'expires_at', 'runtime_pins', 'epoch', 'status', 'issued_at', 'operator'];

    private const PIN_KEYS = ['runtime_measurement', 'model_id', 'weights_digest', 'operator', 'spiffe_id'];

    private static function pinsOk(mixed $p): bool
    {
        if (!K3Sig::isList($p) || count($p) === 0 || count($p) > 16) {
            return false;
        }
        foreach ($p as $x) {
            if (!($x instanceof Obj) || $x->keys() === []) {
                return false;
            }
            foreach ($x->keys() as $k) {
                if (!in_array($k, self::PIN_KEYS, true) || !K3Sig::isStr($x->get($k), 256)) {
                    return false;
                }
            }
        }
        return true;
    }

    public static function wellFormed(mixed $b): bool
    {
        if (!($b instanceof Obj) || !K3Sig::isNumber($b->get('v'), 1.0)) {
            return false;
        }
        foreach (['id', 'key', 'operator'] as $k) {
            if (!K3Sig::isStr($b->get($k), 128)) {
                return false;
            }
        }
        if (!K3Sig::isSafeInt($b->get('epoch')) || !K3Sig::isSafeInt($b->get('issued_at')) || !in_array($b->get('status'), ['active', 'disabled'], true)) {
            return false;
        }
        if ($b->has('max_depth') && !(K3Sig::isSafeInt($b->get('max_depth')) && K3Sig::num($b->get('max_depth')) >= 1.0)) {
            return false;
        }
        if ($b->has('expires_at') && !K3Sig::isSafeInt($b->get('expires_at'))) {
            return false;
        }
        if ($b->has('runtime_pins') && !self::pinsOk($b->get('runtime_pins'))) {
            return false;
        }
        $c = $b->get('ceiling');
        if (!K3Sig::isList($c) || count($c) > 32) {
            return false;
        }
        foreach ($c as $x) {
            if (!($x instanceof Obj) || !is_string($x->get('type'))) {
                return false;
            }
        }
        return true;
    }

    public static function verify(mixed $b): bool
    {
        if (!self::wellFormed($b)) {
            return false;
        }
        $body = new Obj();
        foreach (self::BODY_KEYS as $k) {
            if ($b->has($k)) {
                $body->set($k, $b->get($k));
            }
        }
        return K3Sig::verifyBody(self::DOMAIN, $body, $b->get('operator'), $b->get('sig'));
    }

    /**
     * @param array<string,Obj> $store the registry (updated on success)
     * @param list<string> $operators
     * @return array{ok: bool, replaced?: bool, code?: string}
     */
    public static function accept(array &$store, array $operators, mixed $b): array
    {
        if (!self::verify($b)) {
            return ['ok' => false, 'code' => 'bad_record'];
        }
        if (!in_array($b->get('operator'), $operators, true)) {
            return ['ok' => false, 'code' => 'unknown_operator'];
        }
        $key = $b->get('key');
        if (isset($store[$key])) {
            $cur = $store[$key];
            if ($cur->get('operator') !== $b->get('operator')) {
                return ['ok' => false, 'code' => 'operator_changed'];
            }
            $ce = K3Sig::num($cur->get('epoch'));
            $be = K3Sig::num($b->get('epoch'));
            if ($be < $ce) {
                return ['ok' => false, 'code' => 'stale_epoch'];
            }
            if ($be === $ce) {
                return $cur->get('sig') === $b->get('sig') ? ['ok' => true, 'replaced' => false] : ['ok' => false, 'code' => 'epoch_fork'];
            }
        }
        $store[$key] = $b;
        return ['ok' => true, 'replaced' => true];
    }

    /** @param array<string,Obj> $store */
    public static function epoch(array $store): int
    {
        $m = 0;
        foreach ($store as $r) {
            $m = max($m, (int)K3Sig::num($r->get('epoch')));
        }
        return $m;
    }

    /**
     * @param array<string,Obj> $store
     * @param (callable(string, Obj): bool)|null $admitted the admission hook for blueprints with `runtime_pins` (instance holder key, record)
     * @return array<string,mixed>
     */
    public static function check(mixed $chain, array $store, mixed $now, string $mode, ?int $minEpoch = null, ?callable $admitted = null, ?int $haveEpoch = null): array
    {
        $deny = static fn (string $code, ?string $bp = null): array => ['decision' => 'deny', 'code' => $code] + ($bp !== null ? ['blueprint' => $bp] : []);
        if (!K3Sig::isList($chain) || count($chain) === 0 || !K3Sig::isSafeInt($now)) {
            return $deny('bad_input');
        }
        foreach ($chain as $h) {
            if (!($h instanceof Obj) || !K3Sig::isStr($h->get('issuer'), 128) || !K3Sig::isStr($h->get('holder'), 128)) {
                return $deny('bad_input');
            }
        }
        $nowMs = K3Sig::num($now);
        $have = $haveEpoch ?? self::epoch($store);
        if ($minEpoch !== null && $have < $minEpoch) {
            return ['decision' => 'escalate', 'code' => 'stale_blueprint_state', 'have' => $have, 'need' => $minEpoch];
        }
        $governed = [];
        foreach ($chain as $i => $hop) {
            $bp = $store[$hop->get('issuer')] ?? null;
            if ($bp === null) {
                continue;
            }
            $id = $bp->get('id');
            if ($i === 0 || $chain[$i - 1]->get('holder') !== $bp->get('key')) {
                return $deny('broken_link', $id);
            }
            if ($bp->get('status') !== 'active') {
                return $deny('blueprint_disabled', $id);
            }
            if ($bp->has('expires_at') && $nowMs >= K3Sig::num($bp->get('expires_at'))) {
                return $deny('blueprint_expired', $id);
            }
            if ($bp->has('max_depth') && count($chain) - $i > K3Sig::num($bp->get('max_depth'))) {
                return $deny('too_deep', $id);
            }
            // instance admission is the host's: `admitted($instanceKey, $blueprint)` must return true. A pinned blueprint without the hook
            // denies (admission_required); a false answer, anything but true, or a throw denies (not_admitted); it never falls through
            if ($bp->has('runtime_pins')) {
                if ($admitted === null) {
                    return $deny('admission_required', $id);
                }
                try {
                    $ok = $admitted($hop->get('holder'), $bp) === true;
                } catch (\Throwable) {
                    $ok = false;
                }
                if (!$ok) {
                    return $deny('not_admitted', $id);
                }
            }
            if (count($bp->get('ceiling')) > 0) {
                return $deny('ceiling_unevaluable', $id);
            }
            $governed[] = $id;
        }
        if ($governed === [] && $mode === 'require') {
            return $deny('no_blueprint');
        }
        return ['decision' => 'allow', 'governed' => $governed];
    }
}

/** Durable storage of blueprint records: the newest per key and the highest epoch across all (0 when empty). */
interface BlueprintStore
{
    public function get(string $key): ?Obj;

    public function put(Obj $b): void;

    public function maxEpoch(): int;
}

/** Process-local {@see BlueprintStore} for tests and one process: it forgets a disabled blueprint on restart, so a registry only runs over it when named. */
final class MemoryBlueprintStore implements BlueprintStore
{
    /** @var array<string,Obj> */
    private array $m = [];

    public function get(string $key): ?Obj
    {
        return $this->m['k' . $key] ?? null;
    }

    public function put(Obj $b): void
    {
        $this->m['k' . $b->get('key')] = $b;
    }

    public function maxEpoch(): int
    {
        $e = 0;
        foreach ($this->m as $b) {
            $e = max($e, (int)K3Sig::num($b->get('epoch')));
        }
        return $e;
    }
}

/** {@see BlueprintStore} on an {@see AtomicKv}: one document per key and a monotone maximum epoch. */
final class KvBlueprintStore implements BlueprintStore
{
    private const EPOCH_KEY = 'blueprint/epoch';

    public function __construct(private readonly AtomicKv $kv)
    {
    }

    public function get(string $key): ?Obj
    {
        return KvDoc::dec($this->kv->get('blueprint/rec/' . $key));
    }

    public function put(Obj $b): void
    {
        $epoch = (int)K3Sig::num($b->get('epoch'));
        // never lowers a record: another process sharing the store may have stored a newer epoch since this one read it
        $this->kv->update('blueprint/rec/' . $b->get('key'), static function (?string $prev) use ($b, $epoch): ?string {
            $d = KvDoc::dec($prev);
            return $d !== null && $d->get('epoch') instanceof Num && $d->get('epoch')->int() >= $epoch ? null : KvDoc::enc($b);
        });
        $this->kv->update(self::EPOCH_KEY, static function (?string $prev) use ($epoch): ?string {
            $d = KvDoc::dec($prev);
            $cur = $d !== null && $d->get('epoch') instanceof Num ? $d->get('epoch')->int() : 0;
            return $epoch > $cur ? KvDoc::enc(Obj::of(['epoch' => $epoch])) : null;
        });
    }

    public function maxEpoch(): int
    {
        $d = KvDoc::dec($this->kv->get(self::EPOCH_KEY));
        return $d !== null && $d->get('epoch') instanceof Num ? $d->get('epoch')->int() : 0;
    }
}

/**
 * The blueprint registry on a durable {@see BlueprintStore} (a disabled blueprint must stay disabled across a restart, so the store is
 * required). Same rules as {@see Blueprint::accept} / {@see Blueprint::check}; any store failure is `store_unreachable`.
 */
final class BlueprintRegistry
{
    /** @param list<string> $operators the operator keys whose records this verifier accepts */
    public function __construct(private readonly array $operators, private readonly mixed $store = null)
    {
        if (!($store instanceof BlueprintStore)) {
            throw new \TypeError('BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintStore is for tests and single-process use)');
        }
    }

    /** @return array{ok: bool, replaced?: bool, code?: string} */
    public function accept(mixed $b): array
    {
        try {
            if (!Blueprint::verify($b)) {
                return ['ok' => false, 'code' => 'bad_record'];
            }
            $tmp = [];
            $cur = $this->store->get($b->get('key'));
            if ($cur !== null) {
                $tmp[$b->get('key')] = $cur;
            }
            $r = Blueprint::accept($tmp, $this->operators, $b);
            if ($r['ok'] && ($r['replaced'] ?? false)) {
                $this->store->put($b);
            }
            return $r;
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'store_unreachable'];
        }
    }

    public function get(string $key): ?Obj
    {
        return $this->store->get($key);
    }

    /** The highest blueprint epoch this verifier has accepted: its contribution to a `fresh_at` `revocation_epoch`. */
    public function epoch(): int
    {
        return $this->store->maxEpoch();
    }

    /** @param (callable(string, Obj): bool)|null $admitted @return array<string,mixed> */
    public function check(mixed $chain, mixed $now, string $mode, ?int $minEpoch = null, ?callable $admitted = null): array
    {
        try {
            $map = [];
            foreach (K3Sig::isList($chain) ? $chain : [] as $hop) {
                if ($hop instanceof Obj && is_string($hop->get('issuer')) && ($bp = $this->store->get($hop->get('issuer'))) !== null) {
                    $map[$hop->get('issuer')] = $bp;
                }
            }
            return Blueprint::check($chain, $map, $now, $mode, $minEpoch, $admitted, $this->store->maxEpoch());
        } catch (\Throwable) {
            return ['decision' => 'deny', 'code' => 'store_unreachable'];
        }
    }
}
