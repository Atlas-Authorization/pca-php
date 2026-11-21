<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/StateStore.php';
require_once __DIR__ . '/Operations.php';

/** The outcome of one conformance check: `status` is `pass`, `fail` or `skip`. */
final class ConformanceCheck
{
    public function __construct(public readonly string $name, public readonly string $status, public readonly string $note = '')
    {
    }
}

/** The outcome of a conformance run. */
final class ConformanceReport
{
    /** @var list<ConformanceCheck> */
    public array $checks = [];

    public function __construct(public readonly string $name)
    {
    }

    public function ok(): bool
    {
        foreach ($this->checks as $c) {
            if ($c->status === 'fail') {
                return false;
            }
        }
        return true;
    }

    public function status(string $check): string
    {
        foreach ($this->checks as $c) {
            if ($c->name === $check) {
                return $c->status;
            }
        }
        return 'absent';
    }

    public function __toString(): string
    {
        $s = 'store conformance: ' . $this->name . ' -> ' . ($this->ok() ? 'PASS' : 'FAIL') . "\n";
        foreach ($this->checks as $c) {
            $s .= sprintf("  [%s] %-20s %s\n", strtoupper($c->status), $c->name, $c->note);
        }
        return $s;
    }

    /** @param callable():?string $f returns the failure (null: pass) */
    public function add(string $name, callable $f, string $note = ''): void
    {
        try {
            $err = $f();
        } catch (\Throwable $e) {
            $err = get_class($e) . ': ' . $e->getMessage();
        }
        $this->checks[] = $err === null ? new ConformanceCheck($name, 'pass', $note) : new ConformanceCheck($name, 'fail', $err);
    }

    public function skip(string $name, string $why): void
    {
        $this->checks[] = new ConformanceCheck($name, 'skip', $why);
    }
}

/**
 * Store conformance: run your {@see StateStore} (the replay store behind {@see Authorize}) and your {@see OperationStore} through
 * the invariants the guards rely on, from a test in your own repository:
 *
 *     $rep = StoreConformance::runStateStore(['name' => 'postgres', 'open' => fn () => new PdoStateStore(connect()), 'shared' => true,
 *                                             'durable' => true, 'processes' => true]);
 *     self::assertTrue($rep->ok(), (string)$rep);
 *
 * Configuration (both runners): `open` (REQUIRED) returns a NEW handle onto the SAME backend each call (one handle = one verifier
 * instance's connection); `restart` (optional) crashes and restarts the backend between closing the handles and reopening;
 * `durable`: state survives dropping every handle (and `restart`), false skips the durability checks; `shared`: several handles can
 * share the backend, false runs the race checks on one handle; `processes`: the handles reach a backend shared between OS processes
 * (a database), so the race checks run in forked processes (needs ext-pcntl; without it they run as sequential interleavings and the
 * note says so); `rounds` (10), `copies` (16) and `handles` (4) size the race checks.
 *
 * StateStore checks: claim-burst (strictly increasing counters admitted once each, repeats and older counters refused),
 * claim-concurrent (N copies of one counter: exactly one admitted, every round; distinct counters in a race never admit the same one
 * twice and always admit the highest), claim-durability, crash-after-claim (admitted, then the instance dies without closing: the same
 * counter stays refused) and retry-after-timeout (the claim commits but its answer is lost: the retry is refused, the next counter
 * admitted). OperationStore checks: create-once, transition-once, wrong-state, get-missing, shared, durability. A check the store
 * declares it cannot meet (not durable, not shared) is skipped, never passed.
 */
final class StoreConformance
{
    private static int $seq = 0;

    /** TEST SEAM: stands in for pcntl_fork() in race() (a test makes the fork fail or watches the gate). Always null in production. */
    public static ?\Closure $forkHook = null;

    private static function key(string $prefix): string
    {
        return sprintf('conf:%d:%d:%s', getmypid(), ++self::$seq, $prefix) . ':' . bin2hex(random_bytes(4));
    }

    private static function canFork(array $c): bool
    {
        return ($c['processes'] ?? false) === true && function_exists('pcntl_fork') && function_exists('pcntl_waitpid');
    }

    /**
     * Run `$child(int $i)` `$copies` times at (nearly) the same instant and return each result code in 0..255. With forked
     * processes each child opens its own handle inside `$child`; otherwise they run one after another in this process.
     *
     * @param callable(int):int $child
     * @return list<int>
     */
    private static function race(array $c, int $copies, callable $child): array
    {
        $copies = max(1, $copies); // range(0, -1) would be [0, -1]: a count of zero or less still runs one copy
        if (!self::canFork($c)) {
            return array_map($child, range(0, $copies - 1));
        }
        $gateFile = tempnam(sys_get_temp_dir(), 'pcagate');
        $gate = fopen($gateFile, 'c');
        flock($gate, LOCK_EX);
        $pids = [];
        $parent = getmypid();
        for ($i = 0; $i < $copies; $i++) {
            $pid = self::$forkHook !== null ? (self::$forkHook)() : pcntl_fork();
            if ($pid === 0) {
                exit(self::child($gateFile, $child, $i));
            }
            if (getmypid() !== $parent) {
                exit; // a forked child never runs the parent's fork loop (one bad branch must not become a fork bomb)
            }
            if ($pid < 0) {
                throw new \RuntimeException('conformance: fork failed'); // unwinding frees $gate, which opens the gate
            }
            $pids[] = $pid;
        }
        flock($gate, LOCK_UN);
        $codes = [];
        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
            $codes[] = pcntl_wifexited($status) ? pcntl_wexitstatus($status) : 255;
        }
        fclose($gate);
        @unlink($gateFile);
        return $codes;
    }

    /** One forked copy: wait at the gate (the parent opens it once every copy is forked), then run it; a throw is code 12. */
    private static function child(string $gateFile, callable $child, int $i): int
    {
        $g = fopen($gateFile, 'r');
        flock($g, LOCK_SH); // blocks until the parent opens the gate
        try {
            return $child($i);
        } catch (\Throwable) {
            return 12;
        }
    }

    private static function claim(object $s, string $key, int $n): ?bool
    {
        try {
            $r = $s->claim($key, $n);
        } catch (\Throwable) {
            return null;
        }
        $r = is_bool($r) ? new ClaimResult($r) : $r;
        return $r instanceof ClaimResult ? $r->ok : null;
    }

    /** @param array<string,mixed> $c see the class doc */
    public static function runStateStore(array $c): ConformanceReport
    {
        $rep = new ConformanceReport((string)($c['name'] ?? 'state store'));
        if (!is_callable($c['open'] ?? null)) {
            $rep->add('configuration', static fn() => 'open is required');
            return $rep;
        }
        $c += ['rounds' => 10, 'copies' => 16, 'handles' => 4, 'shared' => true, 'durable' => true];
        $c['copies'] = max(1, (int)$c['copies']);
        if (!$c['shared']) {
            $c['handles'] = 1;
        }
        $rep->add('claim-burst', fn() => self::claimBurst($c));
        $rep->add('claim-concurrent', fn() => self::claimConcurrent($c),
            sprintf('%d rounds x %d copies over %d handle(s)%s', $c['rounds'], $c['copies'], $c['handles'], self::canFork($c) ? ', forked processes' : ', sequential interleavings'));
        if ($c['durable']) {
            $rep->add('claim-durability', fn() => self::claimDurability($c));
            $rep->add('crash-after-claim', fn() => self::crashAfterClaim($c));
        } else {
            $rep->skip('claim-durability', 'durable is false (state dies with the process)');
            $rep->skip('crash-after-claim', 'durable is false (state dies with the process)');
        }
        $rep->add('retry-after-timeout', fn() => self::retryAfterTimeout($c));
        return $rep;
    }

    private static function claimBurst(array $c): ?string
    {
        $s = ($c['open'])();
        $key = self::key('burst');
        $n = 25;
        for ($i = 1; $i <= $n; $i++) {
            if (self::claim($s, $key, $i) !== true) {
                return "counter $i was not admitted on first use";
            }
        }
        for ($i = $n; $i >= 1; $i--) {
            $r = self::claim($s, $key, $i);
            if ($r === null) {
                return "replay of counter $i errored";
            }
            if ($r) {
                return "counter $i was admitted twice (or an older counter was admitted after a newer one)";
            }
        }
        if (self::claim($s, $key, $n + 1) !== true) {
            return 'the next counter after refusals was not admitted';
        }
        // keys are independent streams
        return self::claim($s, self::key('burst-other'), 1) === true ? null : 'a fresh key refused counter 1';
    }

    private static function claimConcurrent(array $c): ?string
    {
        $open = $c['open'];
        $key = self::key('concurrent');
        $handles = [];
        for ($i = 0; $i < $c['handles']; $i++) {
            $handles[] = $open();
        }
        $forked = self::canFork($c);
        // copy $i claims counter $n($i) on $key: 10 admitted, 11 refused, 12 errored
        $race = static function (string $key, \Closure $n) use ($c, $forked, $open, $handles): array {
            return self::race($c, $c['copies'], static function (int $i) use ($forked, $open, $handles, $key, $n): int {
                $r = self::claim($forked ? $open() : $handles[$i % count($handles)], $key, $n($i));
                return $r === null ? 12 : ($r ? 10 : 11);
            });
        };
        for ($round = 1; $round <= $c['rounds']; $round++) {
            $codes = $race($key, static fn(int $i): int => $round);
            $wins = count(array_filter($codes, static fn(int $x): bool => $x === 10));
            if ($wins !== 1) {
                return "round $round: $wins of {$c['copies']} copies of one counter were admitted (want exactly 1; "
                    . count(array_filter($codes, static fn(int $x): bool => $x === 12)) . ' errors)';
            }
        }
        // distinct counters racing on one key: the highest is always admitted and nothing is admitted twice
        $base = $c['rounds'];
        $key2 = self::key('concurrent-distinct');
        $codes = $race($key2, static fn(int $i): int => $base + $i + 1);
        if (($codes[$c['copies'] - 1] ?? 0) !== 10) {
            return "the highest of {$c['copies']} racing counters was not admitted";
        }
        for ($i = 1; $i <= $c['copies']; $i++) {
            if (self::claim($handles[0], $key2, $base + $i) !== false) {
                return 'counter ' . ($base + $i) . ' is admitted again after the race';
            }
        }
        return null;
    }

    private static function claimDurability(array $c): ?string
    {
        $s = ($c['open'])();
        $key = self::key('durability');
        for ($i = 1; $i <= 3; $i++) {
            if (self::claim($s, $key, $i) !== true) {
                return "counter $i was not admitted";
            }
        }
        unset($s);
        if (is_callable($c['restart'] ?? null)) {
            ($c['restart'])();
        }
        return self::afterReopen($c, $key, 3, 4, 'dropping every handle');
    }

    private static function afterReopen(array $c, string $key, int $used, int $next, string $what): ?string
    {
        $s = ($c['open'])();
        if (self::claim($s, $key, $used) !== false) {
            return "counter $used was admitted again after $what";
        }
        return self::claim($s, $key, $next) === true ? null : "counter $next was not admitted after $what";
    }

    private static function crashAfterClaim(array $c): ?string
    {
        // the instance dies after the claim and before its handler ran: its handle is abandoned, never closed
        $abandoned = ($c['open'])();
        $key = self::key('crash');
        if (self::claim($abandoned, $key, 1) !== true) {
            return 'counter 1 was not admitted';
        }
        if (is_callable($c['restart'] ?? null)) {
            ($c['restart'])();
        }
        return self::afterReopen($c, $key, 1, 2, 'the instance died');
    }

    private static function retryAfterTimeout(array $c): ?string
    {
        $first = ($c['open'])();
        // commits the claim, then loses the answer once; an unshared store retries through it (the same instance)
        $lossy = new class($first) {
            private bool $lost;

            public function __construct(private readonly object $inner)
            {
                $this->lost = false;
            }

            public function claim(string $k, int $n): mixed
            {
                $r = $this->inner->claim($k, $n);
                if (!$this->lost) {
                    $this->lost = true;
                    throw new \RuntimeException('timeout (answer lost after commit)');
                }
                return $r;
            }
        };
        $other = $c['shared'] ? ($c['open'])() : $lossy;
        $key = self::key('retry');
        if (self::claim($lossy, $key, 1) !== null) {
            return 'the lossy wrapper must lose the first answer';
        }
        if (self::claim($other, $key, 1) !== false) {
            return 'the retry of a claim whose answer was lost was admitted: the commit had already landed';
        }
        return self::claim($other, $key, 2) === true ? null : 'the next counter after the retry was not admitted';
    }

    private static function rec(string $id, string $state = OperationRecord::PENDING): OperationRecord
    {
        return new OperationRecord($id, $state, 'v', '/r', 'd', 'reversible', 1);
    }

    /** @param array<string,mixed> $c see the class doc */
    public static function runOperationStore(array $c): ConformanceReport
    {
        $rep = new ConformanceReport((string)($c['name'] ?? 'operation store'));
        if (!is_callable($c['open'] ?? null)) {
            $rep->add('configuration', static fn() => 'open is required');
            return $rep;
        }
        $c += ['copies' => 16, 'shared' => true, 'durable' => true];
        $c['copies'] = max(1, (int)$c['copies']);
        $open = $c['open'];
        $forked = self::canFork($c);

        $rep->add('create-once', function () use ($c, $open, $forked): ?string {
            $a = $open();
            $b = $c['shared'] ? $open() : $a;
            $id = self::key('create');
            $codes = self::race($c, $c['copies'], static function (int $i) use ($forked, $open, $a, $b, $id): int {
                $s = $forked ? $open() : ($i % 2 === 0 ? $a : $b);
                [$created, $existing] = $s->create(self::rec($id));
                return $created ? 10 : (($existing->id ?? null) === $id ? 11 : 13);
            });
            $made = count(array_filter($codes, static fn(int $x): bool => $x === 10));
            // a copy that threw (code 12 on the forked path) fails the check exactly like the in-process path, where the throw propagates
            return $made === 1 && !in_array(13, $codes, true) && !in_array(12, $codes, true) ? null
                : "$made concurrent creates of one id reported created (want exactly 1; a loser must be handed the existing record" . (in_array(12, $codes, true) ? '; a copy threw' : '') . ')';
        });
        $rep->add('transition-once', function () use ($c, $open, $forked): ?string {
            $a = $open();
            $b = $c['shared'] ? $open() : $a;
            $id = self::key('transition');
            if (!$a->create(self::rec($id))[0]) {
                return 'create failed';
            }
            $codes = self::race($c, $c['copies'], static function (int $i) use ($forked, $open, $a, $b, $id): int {
                $s = $forked ? $open() : ($i % 2 === 0 ? $a : $b);
                return $s->transition($id, OperationRecord::PENDING, self::rec($id, OperationRecord::EXECUTING)) ? 10 : 11;
            });
            $won = count(array_filter($codes, static fn(int $x): bool => $x === 10));
            return $won === 1 && !in_array(12, $codes, true) ? null
                : "$won concurrent transitions out of pending won (want exactly 1" . (in_array(12, $codes, true) ? '; a copy threw' : '') . ')';
        });
        $rep->add('wrong-state', function () use ($open): ?string {
            $s = $open();
            $id = self::key('wrong');
            if (!$s->create(self::rec($id))[0]) {
                return 'create failed';
            }
            $next = self::rec($id, OperationRecord::COMMITTED);
            if ($s->transition($id, OperationRecord::EXECUTING, $next)) {
                return 'a transition from the wrong state applied';
            }
            if (($got = $s->get($id)) === null || $got->state !== OperationRecord::PENDING) {
                return 'the record changed after a refused transition';
            }
            return $s->transition(self::key('missing'), OperationRecord::PENDING, $next) ? 'a transition of an unknown id applied' : null;
        });
        $rep->add('get-missing', function () use ($open): ?string {
            return $open()->get(self::key('never')) === null ? null : 'an unknown id returned a record';
        });
        if ($c['shared']) {
            $rep->add('shared', function () use ($open): ?string {
                $a = $open();
                $b = $open();
                $id = self::key('shared');
                if (!$a->create(self::rec($id))[0]) {
                    return 'create failed';
                }
                return ($b->get($id)->id ?? null) === $id ? null : 'another handle does not see the record';
            });
        } else {
            $rep->skip('shared', 'shared is false');
        }
        if ($c['durable']) {
            $rep->add('durability', function () use ($c, $open): ?string {
                $a = $open();
                $id = self::key('durable');
                if (!$a->create(self::rec($id))[0]) {
                    return 'create failed';
                }
                unset($a);
                if (is_callable($c['restart'] ?? null)) {
                    ($c['restart'])();
                }
                $got = $open()->get($id);
                return $got !== null && $got->state === OperationRecord::PENDING ? null : 'the record did not survive dropping every handle';
            });
        } else {
            $rep->skip('durability', 'durable is false');
        }
        return $rep;
    }

    // ---- F11: the stores the registries and the guard stand on (an atomic kv, the trust-budget side, the monotone pins) ------------------

    /** @param array<string,mixed> $c `open` (returns an {@see AtomicKv}), `shared`, `durable`, `copies`, `processes` as for the other kits */
    public static function runAtomicKv(array $c): ConformanceReport
    {
        $rep = new ConformanceReport((string)($c['name'] ?? 'atomic kv'));
        if (!is_callable($c['open'] ?? null)) {
            $rep->add('configuration', static fn() => 'open is required');
            return $rep;
        }
        $c += ['copies' => 16, 'shared' => true, 'durable' => true];
        $c['copies'] = max(1, (int)$c['copies']);
        $open = $c['open'];
        $rep->add('get-missing', static fn(): ?string => $open()->get(self::key('kv-missing')) === null ? null : 'a missing key returned a value');
        $rep->add('update-stores-and-reads-back', static function () use ($open): ?string {
            $s = $open();
            $k = self::key('kv-set');
            $s->update($k, static fn(?string $prev): ?string => $prev === null ? 'a' : 'x');
            return $s->get($k) === 'a' ? null : 'the first update did not store its value (or saw a previous one)';
        });
        $rep->add('update-sees-the-previous-value', static function () use ($open): ?string {
            $s = $open();
            $k = self::key('kv-prev');
            $s->update($k, static fn(?string $prev): string => 'a');
            $s->update($k, static fn(?string $prev): string => ($prev ?? '?') . 'b');
            return $s->get($k) === 'ab' ? null : 'an update did not see the stored value';
        });
        $rep->add('update-returning-null-leaves-the-value', static function () use ($open): ?string {
            $s = $open();
            $k = self::key('kv-null');
            $s->update($k, static fn(?string $prev): string => 'a');
            $s->update($k, static fn(?string $prev): ?string => null);
            $absent = self::key('kv-null-absent');
            $s->update($absent, static fn(?string $prev): ?string => null);
            return $s->get($k) === 'a' && $s->get($absent) === null ? null : 'a null result changed the store';
        });
        $rep->add('a-throwing-update-changes-nothing', static function () use ($open): ?string {
            $s = $open();
            $k = self::key('kv-throw');
            $s->update($k, static fn(?string $prev): string => 'a');
            try {
                $s->update($k, static function (?string $prev): string {
                    throw new \RuntimeException('boom');
                });
                return 'a throwing update did not propagate';
            } catch (\RuntimeException) {
                return $s->get($k) === 'a' ? null : 'a throwing update changed the value';
            }
        });
        $rep->add('concurrent-updates-lose-nothing', function () use ($c, $open): ?string {
            $forked = self::canFork($c);
            $a = $open();
            $b = $c['shared'] ? $open() : $a;
            $k = self::key('kv-race');
            self::race($c, $c['copies'], static function (int $i) use ($forked, $open, $a, $b, $k): int {
                $s = $forked ? $open() : ($i % 2 === 0 ? $a : $b);
                $s->update($k, static fn(?string $prev): string => (string)((int)$prev + 1));
                return 10;
            });
            $got = $open()->get($k);
            return $got === (string)$c['copies'] ? null : "{$c['copies']} concurrent increments ended at " . var_export($got, true) . ' (an update was lost)';
        });
        if ($c['durable']) {
            $rep->add('values-survive-a-reopen', static function () use ($open): ?string {
                $k = self::key('kv-durable');
                $open()->update($k, static fn(?string $prev): string => 'kept');
                return $open()->get($k) === 'kept' ? null : 'a value did not survive reopening the store';
            });
        } else {
            $rep->skip('values-survive-a-reopen', 'durable is false (state dies with the process)');
        }
        return $rep;
    }

    /** @param array<string,mixed> $c `open` returns a {@see BudgetStateStore} (and the claim side of the state store) */
    public static function runBudgetStore(array $c): ConformanceReport
    {
        $rep = new ConformanceReport((string)($c['name'] ?? 'budget store'));
        if (!is_callable($c['open'] ?? null)) {
            $rep->add('configuration', static fn() => 'open is required');
            return $rep;
        }
        $c += ['copies' => 16, 'shared' => true, 'durable' => true];
        $c['copies'] = max(1, (int)$c['copies']);
        $open = $c['open'];
        $b = static fn(float $v): array => ['B' => $v, 'tau' => 1000.0, 'asOf' => null];
        $rep->add('no-budget-is-null', static fn(): ?string => $open()->budget(self::key('b-none')) === null ? null : 'a missing key returned a budget');
        $rep->add('claim-stores-the-counter-and-the-budget', static function () use ($open, $b): ?string {
            $s = $open();
            $k = self::key('b-claim');
            $r = $s->claimWithBudget($k, 1, null, $b(0.9));
            if (!$r->ok) {
                return 'the first claim was refused';
            }
            return $s->budget($k) === $b(0.9) ? null : 'the stored budget is not the one claimed';
        });
        $rep->add('a-replay-spends-nothing', static function () use ($open, $b): ?string {
            $s = $open();
            $k = self::key('b-replay');
            $s->claimWithBudget($k, 5, null, $b(0.9));
            $r = $s->claimWithBudget($k, 5, $b(0.9), $b(0.5));
            if ($r->ok || $r->conflict || $r->lastCounter !== 5) {
                return 'a replayed counter was not refused as a replay with the last counter';
            }
            $r = $s->claimWithBudget($k, 4, $b(0.9), $b(0.5));
            if ($r->ok) {
                return 'an older counter was admitted';
            }
            return $s->budget($k) === $b(0.9) ? null : 'a refused claim changed the budget';
        });
        $rep->add('a-stale-read-is-a-conflict-and-claims-nothing', static function () use ($open, $b): ?string {
            $s = $open();
            $k = self::key('b-conflict');
            $s->claimWithBudget($k, 1, null, $b(0.9));
            $r = $s->claimWithBudget($k, 2, $b(0.8), $b(0.7));
            if ($r->ok || !$r->conflict) {
                return 'a claim made on a budget the store no longer holds was not a conflict';
            }
            if (!$s->claimWithBudget($k, 2, $b(0.9), $b(0.7))->ok) {
                return 'the conflict consumed the counter';
            }
            return $s->budget($k) === $b(0.7) ? null : 'the budget after a good claim is wrong';
        });
        $rep->add('a-null-budget-keeps-the-stored-one', static function () use ($open, $b): ?string {
            $s = $open();
            $k = self::key('b-keep');
            $s->claimWithBudget($k, 1, null, $b(0.9));
            $s->claimWithBudget($k, 2, $b(0.9), null);
            return $s->budget($k) === $b(0.9) ? null : 'claiming without a budget changed the stored one';
        });
        $rep->add('concurrent-claims-admit-exactly-one', function () use ($c, $open, $b): ?string {
            $forked = self::canFork($c);
            $a = $open();
            $o = $c['shared'] ? $open() : $a;
            $k = self::key('b-race');
            $a->claimWithBudget($k, 1, null, $b(0.9));
            $codes = self::race($c, $c['copies'], static function (int $i) use ($forked, $open, $a, $o, $k, $b): int {
                $s = $forked ? $open() : ($i % 2 === 0 ? $a : $o);
                $r = $s->claimWithBudget($k, 2, $b(0.9), $b(0.5));
                return $r->ok ? 10 : 11;
            });
            $won = count(array_filter($codes, static fn(int $x): bool => $x === 10));
            return $won === 1 ? null : "$won of {$c['copies']} claims of one counter on one budget were admitted (want exactly 1)";
        });
        return $rep;
    }

    /** @param array<string,mixed> $c `open` returns a {@see PinStateStore} */
    public static function runPinStore(array $c): ConformanceReport
    {
        $rep = new ConformanceReport((string)($c['name'] ?? 'pin store'));
        if (!is_callable($c['open'] ?? null)) {
            $rep->add('configuration', static fn() => 'open is required');
            return $rep;
        }
        $c += ['copies' => 16, 'shared' => true, 'durable' => true];
        $c['copies'] = max(1, (int)$c['copies']);
        $open = $c['open'];
        $rep->add('no-pin-is-null', static fn(): ?string => $open()->pin(self::key('pin-none')) === null ? null : 'a missing key returned a pin');
        $rep->add('a-pin-never-goes-down', static function () use ($open): ?string {
            $s = $open();
            $k = self::key('pin-mono');
            $s->raisePin($k, 7);
            $s->raisePin($k, 6);
            if ($s->pin($k) !== 7) {
                return 'a lower value lowered the pin';
            }
            $s->raisePin($k, 7);
            $s->raisePin($k, 9);
            return $s->pin($k) === 9 ? null : 'a higher value did not raise the pin';
        });
        $rep->add('pins-are-independent-per-key', static function () use ($open): ?string {
            $s = $open();
            [$a, $b] = [self::key('pin-a'), self::key('pin-b')];
            $s->raisePin($a, 3);
            return $s->pin($b) === null && $s->pin($a) === 3 ? null : 'a pin leaked into another key';
        });
        $rep->add('concurrent-raises-end-at-the-highest', function () use ($c, $open): ?string {
            $forked = self::canFork($c);
            $a = $open();
            $o = $c['shared'] ? $open() : $a;
            $k = self::key('pin-race');
            self::race($c, $c['copies'], static function (int $i) use ($c, $forked, $open, $a, $o, $k): int {
                $s = $forked ? $open() : ($i % 2 === 0 ? $a : $o);
                $s->raisePin($k, ($i + intdiv($c['copies'], 2)) % $c['copies'] + 1); // the highest value mid-sequence: a store that keeps the first or the last write ends below the top
                return 10;
            });
            $got = $open()->pin($k);
            return $got === $c['copies'] ? null : "racing raises ended at " . var_export($got, true) . " (want {$c['copies']})";
        });
        if ($c['durable']) {
            $rep->add('a-pin-survives-a-reopen', static function () use ($open): ?string {
                $k = self::key('pin-durable');
                $open()->raisePin($k, 4);
                return $open()->pin($k) === 4 ? null : 'a pin did not survive reopening the store';
            });
        } else {
            $rep->skip('a-pin-survives-a-reopen', 'durable is false (state dies with the process)');
        }
        return $rep;
    }
}
