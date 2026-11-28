<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Sandbox.php';

/**
 * A per-sandbox capability table: indices are small integers meaningful only inside one table, like file descriptors. A slot exists
 * only because a verified PCActn authorized exactly that operation, derivation is monotone (a child can only hold what the parent
 * gave up) and revoking a slot revokes everything derived from it. `$executors` maps a verb to `fn(Obj $op): Bytes|mixed` (the op
 * is a private copy; anything but Bytes is an executor error); the executor gets the signed params, never the guest's.
 */
final class SandboxHandleTable
{
    /** @var list<SandboxSlot> */
    private array $slots = [];
    private \Closure $now;

    /** @param array<string,callable> $executors */
    public function __construct(public readonly string $runtimeClass, private readonly SandboxReceiptLog $log, private readonly array $executors, ?\Closure $now = null)
    {
        $this->now = $now ?? static fn() => new Num((string)(int)floor(microtime(true) * 1000));
    }

    private static function isInt(mixed $v): bool
    {
        $f = K3Sig::num($v);
        return $f !== null && floor($f) === $f;
    }

    private static function deepCopy(mixed $x): mixed
    {
        if ($x instanceof Obj) {
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::deepCopy($x->get($k)));
            }
            return $o;
        }
        return is_array($x) ? array_map(self::deepCopy(...), $x) : $x;
    }

    /** Mint a handle for the operation `$result` allowed. Throws (fail closed) if `$result` does not allow exactly `$operation`. */
    public function mint(mixed $result, mixed $operation, mixed $opts = null): int
    {
        $requires = Js::opt($opts, 'requires');
        if ($requires !== null && !Sandbox::satisfiesRuntimeClass($this->runtimeClass, $requires)) {
            throw new \InvalidArgumentException('runtime_class_too_weak: table is ' . $this->runtimeClass . ', grant requires ' . Js::str($requires));
        }
        if (!Sandbox::isAuthorizedFor($result, $operation)) {
            throw new \InvalidArgumentException('not_authorized: result does not allow exactly this operation');
        }
        $bound = Jsx::get($result, 'operation');
        $usesRaw = Js::opt($opts, 'uses');
        $uses = $usesRaw === null ? 1.0 : (float)K3Sig::num($usesRaw);
        if ($usesRaw !== null && (!self::isInt($usesRaw) || $uses < 1 || $uses > 1000000)) {
            throw new \InvalidArgumentException('bad_uses');
        }
        $op = Obj::of(['verb' => $operation->get('verb'), 'resource' => $operation->get('resource'), 'params' => self::deepCopy($operation->get('params'))]);
        $bid = Jsx::get($bound, 'id');
        $exp = Js::opt($opts, 'expiresAt');
        return $this->push(new SandboxSlot($op, Pca::hashCanonical($op->get('params')), ($bid === null || $bid instanceof Undef) ? '' : $bid, $uses,
            $exp === null ? INF : (K3Sig::num($exp) ?? NAN)));
    }

    /** Derive a narrower handle: takes `uses` from the parent (never more than it has) and an expiry no later than its. */
    public function attenuate(mixed $index, mixed $narrower = null): int
    {
        $p = $this->live($index);
        if ($p === null) {
            throw new \InvalidArgumentException('unknown_handle');
        }
        $u = Js::opt($narrower, 'uses');
        $uses = $u === null ? $p->uses : (K3Sig::num($u) ?? NAN);
        if ($u !== null && !self::isInt($u) || $uses < 1 || $uses > $p->uses) {
            throw new \InvalidArgumentException('attenuate_widens');
        }
        $e = Js::opt($narrower, 'expiresAt');
        $expires = $e === null ? $p->expiresAt : (Js::num($e) ?? NAN);
        if (!($expires <= $p->expiresAt)) {
            throw new \InvalidArgumentException('attenuate_widens');
        }
        $p->uses -= $uses;
        $child = $this->push(new SandboxSlot(self::deepCopy($p->op), $p->paramsDigest, $p->opId, $uses, $expires));
        $p->children[] = $child;
        return $child;
    }

    /** Revoke a handle and, transitively, every handle derived from it. */
    public function revoke(mixed $index): void
    {
        $s = $this->slot($index);
        if ($s === null || $s->revoked) {
            return;
        }
        $s->revoked = true;
        foreach ($s->children as $c) {
            $this->revoke($c);
        }
    }

    public function size(): int
    {
        return count($this->slots);
    }

    public function verbOf(mixed $index): ?string
    {
        $s = $this->slot($index);
        return $s === null ? null : $s->op->get('verb');
    }

    /**
     * Run the executor on the authorized operation and record a receipt. A use is consumed before the executor runs and stays
     * consumed if it throws (a failed side effect needs a new authorization, not a retry on the old one).
     */
    public function use(mixed $index): Obj
    {
        $s = $this->slot($index);
        if ($s === null) {
            $this->log->append($this->runtimeClass, Obj::of(['kind' => 'handle_use', 'subject' => Obj::of(['op_id' => '', 'verb' => '', 'resource' => '', 'params_digest' => '']),
                'outcome' => 'refused', 'reason' => 'unknown_handle']));
            return Obj::of(['ok' => false, 'reason' => 'unknown_handle']);
        }
        $live = $this->live($index);
        if ($live === null) {
            return $this->finish($s, false, 'spent');
        }
        $ex = $this->executors[$s->op->get('verb')] ?? null;
        if (!$ex) {
            return $this->finish($s, false, 'no_executor');
        }
        $live->uses -= 1;
        try {
            $result = $ex(self::deepCopy($s->op));
            if (!($result instanceof Bytes)) {
                return $this->finish($s, false, 'executor_error');
            }
            return $this->finish($s, true, null, $result);
        } catch (\Throwable) {
            return $this->finish($s, false, 'executor_error');
        }
    }

    private function finish(SandboxSlot $s, bool $ok, ?string $reason, ?Bytes $bytes = null): Obj
    {
        $outcome = $ok ? 'ok' : ($reason === 'executor_error' ? 'error' : 'refused');
        $this->log->append($this->runtimeClass, Obj::of(['kind' => 'handle_use', 'subject' => Obj::of(['op_id' => $s->opId, 'verb' => $s->op->get('verb'),
            'resource' => $s->op->get('resource'), 'params_digest' => $s->paramsDigest]), 'outcome' => $outcome, 'reason' => $ok ? 'used' : $reason]));
        return $ok ? Obj::of(['ok' => true, 'result' => $bytes]) : Obj::of(['ok' => false, 'reason' => $reason]);
    }

    private function slot(mixed $index): ?SandboxSlot
    {
        $f = K3Sig::num($index);
        if ($f !== null && floor($f) === $f && $f >= 1 && $f <= count($this->slots)) {
            return $this->slots[(int)$f - 1];
        }
        return null;
    }

    private function live(mixed $index): ?SandboxSlot
    {
        $s = $this->slot($index);
        $now = K3Sig::num(($this->now)()); // a non-finite clock is no time: the handle is not live (never epoch 0)
        return ($s !== null && !$s->revoked && $s->uses > 0 && $now !== null && $now < $s->expiresAt) ? $s : null;
    }

    private function push(SandboxSlot $s): int
    {
        $this->slots[] = $s;
        return count($this->slots);
    }
}
