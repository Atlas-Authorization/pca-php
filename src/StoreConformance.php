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
        if (!self::canFork($c)) {
            return array_map($child, range(0, $copies - 1));
        }
        $gateFile = tempnam(sys_get_temp_dir(), 'pcagate');
        $gate = fopen($gateFile, 'c');
        flock($gate, LOCK_EX);
        $pids = [];
        for ($i = 0; $i < $copies; $i++) {
            $pid = pcntl_fork();
            if ($pid === 0) {
                $g = fopen($gateFile, 'r');
                flock($g, LOCK_SH); // blocks until the parent opens the gate
                try {
                    $code = $child($i);
                } catch (\Throwable) {
                    $code = 12;
                }
                exit($code & 0xFF);
            }
            if ($pid < 0) {
                flock($gate, LOCK_UN);
                throw new \RuntimeException('conformance: fork failed');
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
        $c += ['rounds' => 10, 'copies' => 16, 'handles' => 4, 'shared' => false, 'durable' => false];
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
        for ($round = 1; $round <= $c['rounds']; $round++) {
            $codes = self::race($c, $c['copies'], static function (int $i) use ($forked, $open, $handles, $key, $round): int {
                $r = self::claim($forked ? $open() : $handles[$i % count($handles)], $key, $round);
                return $r === null ? 12 : ($r ? 10 : 11);
            });
            $wins = count(array_filter($codes, static fn(int $x): bool => $x === 10));
            if ($wins !== 1) {
                return "round $round: $wins of {$c['copies']} copies of one counter were admitted (want exactly 1; "
                    . count(array_filter($codes, static fn(int $x): bool => $x === 12)) . ' errors)';
            }
        }
        // distinct counters racing on one key: the highest is always admitted and nothing is admitted twice
        $base = $c['rounds'];
        $key2 = self::key('concurrent-distinct');
        $codes = self::race($c, $c['copies'], static function (int $i) use ($forked, $open, $handles, $key2, $base): int {
            $r = self::claim($forked ? $open() : $handles[$i % count($handles)], $key2, $base + $i + 1);
            return $r === null ? 12 : ($r ? 10 : 11);
        });
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
        $other = $c['shared'] ? ($c['open'])() : $first;
        // commits the claim, then loses the answer once
        $lossy = new class($first) {
            public bool $lose = true;

            public function __construct(private readonly object $inner)
            {
            }

            public function claim(string $k, int $n): mixed
            {
                $r = $this->inner->claim($k, $n);
                if ($this->lose) {
                    $this->lose = false;
                    throw new \RuntimeException('timeout (answer lost after commit)');
                }
                return $r;
            }
        };
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
        $c += ['copies' => 16, 'shared' => false, 'durable' => false];
        $open = $c['open'];
        $forked = self::canFork($c);

        $rep->add('create-once', function () use ($c, $open, $forked): ?string {
            $a = $open();
            $b = $c['shared'] ? $open() : $a;
            $id = self::key('create');
            $codes = self::race($c, $c['copies'], static function (int $i) use ($forked, $open, $a, $b, $id): int {
                $s = $forked ? $open() : ($i % 2 === 0 ? $a : $b);
                [$created, $existing] = $s->create(self::rec($id));
                return $created ? 10 : (($existing?->id ?? null) === $id ? 11 : 13);
            });
            $made = count(array_filter($codes, static fn(int $x): bool => $x === 10));
            return $made === 1 && !in_array(13, $codes, true) ? null
                : "$made concurrent creates of one id reported created (want exactly 1; a loser must be handed the existing record)";
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
            return $won === 1 ? null : "$won concurrent transitions out of pending won (want exactly 1)";
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
                return ($b->get($id)?->id ?? null) === $id ? null : 'another handle does not see the record';
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
}
