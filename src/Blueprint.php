<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';

/**
 * Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop issued
 * by that key. {@see Blueprint::accept} keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the same
 * epoch with different content is a fork). A non-empty ceiling is never evaluated here: it denies (`ceiling_unevaluable`). Total.
 * Records and chains are parsed JSON (Obj, lists). The registry is an array<string,Obj> held by the caller.
 */
final class Blueprint
{
    public const DOMAIN = "atlas-pca/agent-blueprint/v1\0";
    private const BODY_KEYS = ['v', 'id', 'key', 'ceiling', 'max_depth', 'expires_at', 'epoch', 'status', 'issued_at', 'operator'];

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
     * @return array<string,mixed>
     */
    public static function check(mixed $chain, array $store, mixed $now, string $mode, ?int $minEpoch = null): array
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
        if ($minEpoch !== null && self::epoch($store) < $minEpoch) {
            return ['decision' => 'escalate', 'code' => 'stale_blueprint_state', 'have' => self::epoch($store), 'need' => $minEpoch];
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
