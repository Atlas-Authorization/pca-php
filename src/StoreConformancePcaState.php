<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The `pca-state` profile (the reference's pca-state): run the replay store behind the REAL guard ({@see Authorize::authorize}, the full
 * default-deny pipeline) with REAL signed PCActns, and check the replay-state invariant: one action id (grant, leaf holder, counter) goes from
 * unconsumed to consumed at most once, however many copies arrive, on however many instances or processes, across crashes after the claim and
 * retries after a timeout.
 *
 *   claim-burst / claim-concurrent / claim-durability  the store's claim contract ({@see StoreConformance::runStateStore})
 *   one-instance         N copies of one proof to one guard, every round: exactly one admitted
 *   instances            the copies spread over K guards on separate handles, built with multiInstance: true (a process-scoped store is refused)
 *   processes            the same race across K child PHP processes (real concurrency; needs the adapter spec)
 *   crash-after-claim    admitted, then the instance dies before its handler: the same proof is denied afterwards, the next counter admitted;
 *                        with a spec the instance is a child process that SIGKILLs itself right after the admission
 *   retry-after-timeout  the commit lands but its answer is lost (the guard fails closed) and the retry is denied
 *
 * shortcut: PHP runs one request at a time, so one-instance / instances interleave the copies sequentially (the processes test is the real race),
 * and the "retry while the first commit is still in flight" half of retry-after-timeout is covered by the processes test instead.
 *
 * An adapter is an array: name (string), open (callable returning a store with claim(), or ['store' => store, 'close' => callable]),
 * durable / shared (bool, default true), restart / crash / teardown (callables), and spec ('builtin:<name>' or a PHP file returning
 * `fn(array $options): array`) with options, so child processes can load the same adapter.
 */
final class StoreConformancePcaState
{
    public const AUDIENCE = 'pca-store-conformance';
    public const TESTS = ['claim-burst', 'claim-concurrent', 'claim-durability', 'one-instance', 'instances', 'processes', 'crash-after-claim', 'retry-after-timeout'];

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/pca-state/' . $label, true);
    }

    private static function operation(): Obj
    {
        return Obj::of(['verb' => 'read', 'resource' => 'doc:1', 'params' => new Obj()]);
    }

    /** A grant plus pre-signed PCActns (counters 1..n) from one agent. @return array{grant:Obj,proofs:list<Obj>} */
    public static function fixture(int $n): array
    {
        // fresh keys per fixture (the reference does the same): a store shared across tests must not see one counter stream twice
        $principal = new KeyPair(random_bytes(32));
        $key = new KeyPair(random_bytes(32));
        $env = ['predicates' => [['verb' => 'read', 'resource' => 'doc:*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'store conformance', 'c2FsdA')['grant'];
        $agent = new Agent($key, $grant, self::AUDIENCE);
        $proofs = [];
        for ($i = 0; $i < $n; $i++) {
            $proofs[] = $agent->act('read', 'doc:1', new Obj())->pcactn;
        }
        return ['grant' => $grant, 'proofs' => $proofs];
    }

    /** admitted / replay (the counter check failed) / error (any other denial, e.g. a store error: fail closed). */
    private static function outcome(AuthorizeResult $r): string
    {
        $storeFailed = false;
        foreach ($r->reasons as $why) { // a store that threw is refused under the replay check too, but it is an error, not a replay
            $storeFailed = $storeFailed || str_contains($why, 'the replay store failed');
        }
        $o = $r->allow ? 'admitted' : (($r->checks['replay'] ?? null) === 'fail' && !$storeFailed ? 'replay' : 'error');
        if ($o === 'error') {
            self::$lastDenial = implode(' | ', $r->reasons);
        }
        return $o;
    }

    /** The reasons of the last denial that was not a replay: a failure note names why a claim was refused. */
    private static string $lastDenial = '';

    /**
     * One guard over `$store`: `(int $counter): string`. With `$multiInstance` the guard is built through AuthorizeOptions, which refuses a
     * process-scoped store (throws InvalidArgumentException).
     * @param array{grant:Obj,proofs:list<Obj>} $fx
     * @return \Closure(int): string
     */
    public static function guard(array $fx, object $store, bool $multiInstance = false): \Closure
    {
        if ($multiInstance) {
            new AuthorizeOptions(stateStore: $store, isRevoked: static fn() => false, plan: 'single-step', multiInstance: true);
        }
        $grant = $fx['grant'];
        $mediator = new ProvenanceRecorder('pca-state-harness', 'k1', new KeyPair(self::seed('mediator')));
        $pin = $mediator->pin;
        return static function (int $counter) use ($fx, $grant, $store, $pin): string {
            $op = self::operation();
            $rec = new ProvenanceRecorder('pca-state-harness', 'k1', new KeyPair(self::seed('mediator')));
            $r = Authorize::authorize($fx['proofs'][$counter - 1], $op, self::AUDIENCE, static fn($ref) => $ref === $grant->get('id') ? $grant : null,
                $store, static fn() => false, (int)(microtime(true) * 1000), 'single-step',
                provenance: ArgProvenance::principalDirect($rec, $op), provenanceMediators: [$pin],
                hard: ['risk' => static fn(): array => ['reversibility' => 1, 'blastRadius' => 0, 'confidence' => 1, 'semanticDistance' => 0, 'taint' => 0]]); // the server's own risk read of a plain read: a claim is refused only for the state it tests
            return self::outcome($r);
        };
    }

    /** @return array{store:object,close:?callable} */
    private static function open(array $a): array
    {
        $h = ($a['open'])();
        return is_array($h) ? ['store' => $h['store'], 'close' => $h['close'] ?? null] : ['store' => $h, 'close' => method_exists($h, 'close') ? $h->close(...) : null];
    }

    private static function closeAll(array $hs): void
    {
        foreach ($hs as $h) {
            try {
                if ($h['close'] !== null) {
                    ($h['close'])();
                }
            } catch (\Throwable) {
                // a close that fails is not a verdict
            }
        }
    }

    /** @return array<string,mixed> */
    private static function exactlyOne(string $test, array $admitted, ?string $note = null): array
    {
        return ['test' => $test, 'status' => array_filter($admitted, static fn(int $n): bool => $n !== 1) === [] ? 'pass' : 'fail', 'admitted' => $admitted, 'note' => $note];
    }

    private static function skip(string $test, string $note): array
    {
        return ['test' => $test, 'status' => 'skip', 'note' => $note];
    }

    /** @param list<\Closure(int): string> $guards */
    private static function race(array $guards, int $counter, int $copies): int
    {
        $n = 0;
        for ($i = 0; $i < $copies; $i++) {
            $n += $guards[$i % count($guards)]($counter) === 'admitted' ? 1 : 0;
        }
        return $n;
    }

    // ---- the tests ---------------------------------------------------------------------------------------------------------

    private static function oneInstance(array $a, int $rounds, int $copies): array
    {
        $fx = self::fixture($rounds);
        $h = self::open($a);
        try {
            $g = self::guard($fx, $h['store']);
            $admitted = [];
            for ($r = 1; $r <= $rounds; $r++) {
                $admitted[] = self::race([$g], $r, $copies);
            }
            return self::exactlyOne('one-instance', $admitted);
        } finally {
            self::closeAll([$h]);
        }
    }

    private static function instances(array $a, int $rounds, int $copies, int $k): array
    {
        if (($a['shared'] ?? true) === false) {
            return self::skip('instances', 'the adapter declares shared: false (one instance only)');
        }
        $fx = self::fixture($rounds);
        $hs = [];
        try {
            for ($i = 0; $i < $k; $i++) {
                $hs[] = self::open($a);
            }
            try {
                $gs = array_map(static fn(array $h): \Closure => self::guard($fx, $h['store'], true), $hs);
            } catch (\Throwable $e) {
                return ['test' => 'instances', 'status' => 'fail', 'note' => 'refused in multi-instance mode: ' . $e->getMessage()];
            }
            $admitted = [];
            for ($r = 1; $r <= $rounds; $r++) {
                $admitted[] = self::race($gs, $r, $copies);
            }
            return self::exactlyOne('instances', $admitted, "$k instances");
        } finally {
            self::closeAll($hs);
        }
    }

    private static function retryAfterTimeout(array $a): array
    {
        $fx = self::fixture(4);
        $shared = ($a['shared'] ?? true) !== false;
        $h0 = self::open($a);
        $h1 = $shared ? self::open($a) : $h0;
        try {
            $lossy = new class ($h0['store']) {
                private bool $lose = true;

                public function __construct(private readonly object $inner)
                {
                }

                public function claim(string $key, int $counter): ClaimResult
                {
                    $r = $this->inner->claim($key, $counter);
                    if ($this->lose) {
                        $this->lose = false;
                        throw new \RuntimeException('timeout (answer lost after commit)');
                    }
                    return $r;
                }

                public function scope(): string
                {
                    return method_exists($this->inner, 'scope') ? $this->inner->scope() : 'shared';
                }
            };
            $first = self::guard($fx, $lossy)(1);
            $retry = self::guard($fx, $h1['store'])(1);
            $next = self::guard($fx, $h1['store'])(2);
            $ok = $first === 'error' && $retry === 'replay' && $next === 'admitted';
            return ['test' => 'retry-after-timeout', 'status' => $ok ? 'pass' : 'fail', 'admitted' => [$first === 'admitted' || $retry === 'admitted' ? 1 : 0],
                'note' => "lost answer: first=$first, retry=$retry, next counter=$next" . ($ok || self::$lastDenial === '' ? '' : '; last denial: ' . self::$lastDenial)];
        } finally {
            self::closeAll($shared ? [$h0, $h1] : [$h0]);
        }
    }

    private static function crashAfterClaim(array $a): array
    {
        if (($a['durable'] ?? true) === false) {
            return self::skip('crash-after-claim', 'the adapter declares durable: false (state dies with the process)');
        }
        $fx = self::fixture(4);
        $h1 = self::open($a);
        $first = self::guard($fx, $h1['store'])(1);
        if (isset($a['crash'])) {
            ($a['crash'])();
        }
        if (isset($a['restart'])) {
            ($a['restart'])();
        }
        $h2 = self::open($a);
        $g = self::guard($fx, $h2['store']);
        $after = [$g(1), $g(2)];
        self::closeAll([$h1, $h2]);
        $ok = $first === 'admitted' && $after[0] === 'replay' && $after[1] === 'admitted';
        $notes = ["in process: admitted=$first, same proof after restart={$after[0]}, next counter={$after[1]}"];
        if (isset($a['spec'])) {
            $dir = self::tmpdir('pcasc-pstate-crash-');
            $file = $dir . '/fixture.json';
            PrivateFile::write($file, Js::stringify(Obj::of(['grant' => $fx['grant'], 'proofs' => $fx['proofs']])));
            $base = ['spec' => $a['spec'], 'options' => $a['options'] ?? new \stdClass(), 'fixture' => $file, 'copies' => 1, 'instances' => 1];
            $killed = self::runWorker($base + ['mode' => 'admit-then-die', 'out' => $dir . '/a.jsonl', 'counter' => 3]);
            if (isset($a['restart'])) {
                ($a['restart'])();
            }
            $retried = self::runWorker($base + ['mode' => 'race', 'out' => $dir . '/b.jsonl', 'counter' => 3]);
            $fresh = self::runWorker($base + ['mode' => 'race', 'out' => $dir . '/c.jsonl', 'counter' => 4]);
            $ok = $ok && $killed['killed'] && $killed['admitted'] === 1 && $retried['admitted'] === 0 && $retried['replays'] === 1 && $fresh['admitted'] === 1;
            $notes[] = 'child process: killed after admission=' . var_export($killed['killed'] && $killed['admitted'] === 1, true)
                . ", retry in a new process admitted {$retried['admitted']}, next counter admitted {$fresh['admitted']}";
        } else {
            $notes[] = 'process half skipped (needs the adapter spec)';
        }
        return ['test' => 'crash-after-claim', 'status' => $ok ? 'pass' : 'fail', 'note' => implode('; ', $notes)];
    }

    // ---- child processes ---------------------------------------------------------------------------------------------------

    private static function tmpdir(string $prefix): string
    {
        $d = sys_get_temp_dir() . '/' . $prefix . bin2hex(random_bytes(4));
        PrivateFile::mkdir($d, true);
        return $d;
    }

    /** @return list<array<string,mixed>> */
    private static function lines(string $file): array
    {
        return is_file($file) ? array_map(static fn(string $l): array => json_decode($l, true), array_values(array_filter(explode("\n", (string)file_get_contents($file))))) : [];
    }

    /** Start a worker; returns the process handle for {@see finishWorker}. @return array{proc:mixed,cfg:array<string,mixed>,pipes:array} */
    private static function startWorker(array $cfg): array
    {
        $null = PrivateFile::nullDevice();
        $proc = proc_open([PHP_BINARY, __DIR__ . '/../bin/pca-state-worker', json_encode($cfg, JSON_UNESCAPED_SLASHES)], [0 => ['file', $null, 'r'], 1 => ['file', $null, 'w'], 2 => ['file', $null, 'w']], $pipes);
        if (!is_resource($proc)) {
            throw new \RuntimeException('pca-state: cannot start a worker process');
        }
        return ['proc' => $proc, 'cfg' => $cfg, 'pipes' => $pipes];
    }

    /** @return array{lines:list<array<string,mixed>>,killed:bool,signaled:bool,admitted:int,replays:int,errors:int} */
    private static function finishWorker(array $w): array
    {
        $signaled = false;
        $killed = false;
        while (true) {
            $st = proc_get_status($w['proc']);
            if (!$st['running']) {
                $signaled = $st['signaled'];
                // POSIX: SIGKILL. Windows has no signals: the worker ended itself with TerminateProcess and the exit code 137 (a clean end is 0)
                $killed = ($st['signaled'] && $st['termsig'] === 9) || (PrivateFile::isWindows() && $st['exitcode'] === 137);
                break;
            }
            usleep(20000);
        }
        proc_close($w['proc']);
        $lines = self::lines($w['cfg']['out']);
        $sum = static fn(string $k): int => array_sum(array_map(static fn(array $l): int => (int)$l[$k], $lines));
        return ['lines' => $lines, 'killed' => $killed, 'signaled' => $signaled, 'admitted' => $sum('admitted'), 'replays' => $sum('replays'), 'errors' => $sum('errors')];
    }

    private static function runWorker(array $cfg): array
    {
        return self::finishWorker(self::startWorker($cfg));
    }

    private static function processes(array $a, int $rounds, int $copies, int $n): array
    {
        if (($a['shared'] ?? true) === false) {
            return self::skip('processes', 'the adapter declares shared: false (one instance only)');
        }
        if (!isset($a['spec'])) {
            return self::skip('processes', 'needs the adapter spec (the guards run in child processes)');
        }
        $fx = self::fixture($rounds);
        $dir = self::tmpdir('pcasc-pstate-');
        $file = $dir . '/fixture.json';
        PrivateFile::write($file, Js::stringify(Obj::of(['grant' => $fx['grant'], 'proofs' => $fx['proofs']])));
        $origin = (int)(microtime(true) * 1000) + 3000; // time for every process to start and open its handles
        $ws = [];
        for ($p = 0; $p < $n; $p++) {
            $ws[] = self::startWorker(['spec' => $a['spec'], 'options' => $a['options'] ?? new \stdClass(), 'mode' => 'race', 'fixture' => $file, 'out' => "$dir/p$p.jsonl",
                'rounds' => $rounds, 'origin' => $origin, 'round_ms' => 150, 'copies' => $copies, 'instances' => 2]);
        }
        $outs = array_map(self::finishWorker(...), $ws);
        $admitted = [];
        for ($c = 1; $c <= $rounds; $c++) {
            $admitted[] = array_sum(array_map(static fn(array $w): int => array_sum(array_map(static fn(array $l): int => $l['counter'] === $c ? (int)$l['admitted'] : 0, $w['lines'])), $outs));
        }
        $errors = array_sum(array_column($outs, 'errors'));
        $crashed = count(array_filter($outs, static fn(array $w): bool => $w['signaled'] || count($w['lines']) !== $rounds));
        $r = self::exactlyOne('processes', $admitted, "$n processes x 2 instances x $copies copies per round; $errors fail-closed errors" . ($crashed > 0 ? "; $crashed worker(s) did not finish" : ''));
        return $crashed > 0 ? ['status' => 'fail'] + $r : $r;
    }

    /** Entry of one child process (bin/pca-state-worker). @param list<string> $argv */
    public static function workerMain(array $argv): int
    {
        $cfg = json_decode($argv[1] ?? '', true);
        $a = self::loadAdapter($cfg['spec'], (array)($cfg['options'] ?? []));
        $fxj = Json::parseStrict((string)file_get_contents($cfg['fixture']));
        $fx = ['grant' => $fxj->get('grant'), 'proofs' => $fxj->get('proofs')];
        $hs = [];
        for ($i = 0; $i < (int)$cfg['instances']; $i++) {
            $hs[] = self::open($a);
        }
        $gs = array_map(static fn(array $h): \Closure => self::guard($fx, $h['store'], (int)$cfg['instances'] > 1 || $cfg['mode'] === 'race'), $hs);
        $record = static function (int $counter, array $rs) use ($cfg): void {
            $c = array_count_values($rs);
            PrivateFile::create($cfg['out']);
            file_put_contents($cfg['out'], json_encode(['counter' => $counter, 'admitted' => $c['admitted'] ?? 0, 'replays' => $c['replay'] ?? 0, 'errors' => $c['error'] ?? 0]) . "\n", FILE_APPEND | LOCK_EX);
        };
        if ($cfg['mode'] === 'admit-then-die') {
            $record((int)$cfg['counter'], [$gs[0]((int)$cfg['counter'])]);
            // the instance dies after the claim committed and before any handler ran
            PrivateFile::killSelf(137);
        }
        for ($r = 0; $r < (int)($cfg['rounds'] ?? 1); $r++) {
            $counter = (int)($cfg['counter'] ?? $r + 1);
            $at = (int)($cfg['origin'] ?? 0) + $r * (int)($cfg['round_ms'] ?? 0);
            while ((int)(microtime(true) * 1000) < $at) {
                usleep(2000);
            }
            $rs = [];
            for ($i = 0; $i < (int)$cfg['copies']; $i++) {
                $rs[] = $gs[$i % count($gs)]($counter);
            }
            $record($counter, $rs);
        }
        self::closeAll($hs);
        if (isset($a['teardown'])) {
            ($a['teardown'])();
        }
        return 0;
    }

    // ---- adapters ----------------------------------------------------------------------------------------------------------

    /** The reference adapters: in-memory, durable-file (SQLite), bad-read-then-write-claim, bad-volatile, bad-unshared. @return array<string,mixed> */
    public static function builtin(string $name, array $options = []): array
    {
        switch ($name) {
            case 'in-memory':
                $s = new MemoryStateStore();
                return ['name' => 'in-memory (MemoryStateStore)', 'durable' => false, 'shared' => false, 'open' => static fn() => $s];
            case 'durable-file':
                $dir = (string)($options['dir'] ?? self::tmpdir('pcasc-pstate-durable-'));
                $open = static function () use ($dir): array {
                    $pdo = new \PDO('sqlite:' . $dir . '/state.db');
                    $pdo->exec('PRAGMA busy_timeout = 10000');
                    $s = new PdoStateStore($pdo);
                    $s->createTable();
                    return ['store' => $s, 'close' => static function () use (&$pdo, &$s): void {
                        $s = null;
                        $pdo = null;
                    }];
                };
                return ['name' => "durable SQLite file store ($dir)", 'durable' => true, 'shared' => true, 'open' => $open];
            case 'bad-read-then-write-claim':
                $shared = new \ArrayObject();
                return ['name' => 'BAD claim as read, wait, write', 'durable' => false, 'shared' => true, 'open' => static fn() => new class ($shared) {
                    public function __construct(private readonly \ArrayObject $m)
                    {
                    }

                    public function claim(string $key, int $counter): ClaimResult
                    {
                        $last = $this->m[$key] ?? null;
                        usleep(1000);
                        if ($last !== null && $counter <= $last) {
                            return new ClaimResult(false, $last);
                        }
                        $this->m[$key] = $counter;
                        return new ClaimResult(true);
                    }

                    public function scope(): string
                    {
                        return 'shared';
                    }
                }];
            case 'bad-volatile':
                $holder = new \ArrayObject(['s' => new MemoryStateStore()]);
                $shared = static fn(): object => new class ($holder['s']) {
                    public function __construct(private readonly MemoryStateStore $inner)
                    {
                    }

                    public function claim(string $key, int $counter): ClaimResult
                    {
                        return $this->inner->claim($key, $counter);
                    }

                    public function scope(): string
                    {
                        return 'shared';
                    }
                };
                return ['name' => 'BAD volatile atomic store (claims lost on restart)', 'durable' => true, 'shared' => true, 'open' => $shared,
                    'restart' => static function () use ($holder): void {
                        $holder['s'] = new MemoryStateStore();
                    }];
            case 'bad-unshared':
                return ['name' => 'BAD per-handle state passed off as shared', 'durable' => false, 'shared' => true, 'open' => static fn() => new class (new MemoryStateStore()) {
                    public function __construct(private readonly MemoryStateStore $inner)
                    {
                    }

                    public function claim(string $key, int $counter): ClaimResult
                    {
                        return $this->inner->claim($key, $counter);
                    }

                    public function scope(): string
                    {
                        return 'shared';
                    }
                }];
        }
        throw new \InvalidArgumentException("unknown built-in pca-state adapter '$name' (known: in-memory, durable-file, bad-read-then-write-claim, bad-volatile, bad-unshared)");
    }

    /** @param array<string,mixed> $options @return array<string,mixed> */
    public static function loadAdapter(string $spec, array $options = []): array
    {
        if (str_starts_with($spec, 'builtin:')) {
            $a = self::builtin(substr($spec, 8), $options);
        } else {
            $f = require $spec;
            $a = is_callable($f) ? $f($options) : $f;
            if (!is_array($a) || !is_string($a['name'] ?? null) || !is_callable($a['open'] ?? null)) {
                throw new \TypeError("$spec: does not return a pca-state adapter (an array with a string name and an open callable)");
            }
        }
        return ['spec' => $spec, 'options' => $options] + $a;
    }

    // ---- the run -----------------------------------------------------------------------------------------------------------

    /**
     * Run the profile. Options: tests, rounds (10), copies (16), instances (4), processes (3).
     * @param array<string,mixed> $a an adapter @param array<string,mixed> $o
     * @return array{adapter:string,status:string,tests:list<array<string,mixed>>}
     */
    public static function run(array $a, array $o = []): array
    {
        $rounds = (int)($o['rounds'] ?? 10);
        $copies = (int)($o['copies'] ?? 16);
        $claim = null;
        $out = [];
        try {
            foreach ($o['tests'] ?? self::TESTS as $t) {
                if (in_array($t, ['claim-burst', 'claim-concurrent', 'claim-durability'], true)) {
                    $claim ??= StoreConformance::runStateStore(['name' => $a['name'], 'open' => static fn() => self::open($a)['store'], 'durable' => ($a['durable'] ?? true) !== false,
                        'shared' => ($a['shared'] ?? true) !== false, 'processes' => false]);
                    $out[] = ['test' => $t, 'status' => $claim->status($t), 'note' => null];
                } elseif ($t === 'one-instance') {
                    $out[] = self::oneInstance($a, $rounds, $copies);
                } elseif ($t === 'instances') {
                    $out[] = self::instances($a, $rounds, $copies, (int)($o['instances'] ?? 4));
                } elseif ($t === 'processes') {
                    $out[] = self::processes($a, $rounds, $copies, (int)($o['processes'] ?? 3));
                } elseif ($t === 'crash-after-claim') {
                    $out[] = self::crashAfterClaim($a);
                } elseif ($t === 'retry-after-timeout') {
                    $out[] = self::retryAfterTimeout($a);
                } else {
                    throw new \InvalidArgumentException("unknown test $t");
                }
            }
        } finally {
            if (isset($a['teardown'])) {
                ($a['teardown'])();
            }
        }
        return ['adapter' => $a['name'], 'status' => array_filter($out, static fn(array $x): bool => $x['status'] === 'fail') === [] ? 'pass' : 'fail', 'tests' => $out];
    }

    /** @param array{adapter:string,status:string,tests:list<array<string,mixed>>} $r */
    public static function format(array $r): string
    {
        $lines = ["pca-store-conformance (pca-state): {$r['adapter']} -> " . strtoupper($r['status'])];
        foreach ($r['tests'] as $t) {
            $adm = isset($t['admitted']) ? 'admitted per round [' . implode(',', $t['admitted']) . ']' : '';
            $lines[] = '  [' . strtoupper($t['status']) . '] ' . str_pad($t['test'], 20) . ' ' . implode('; ', array_filter([$adm, (string)($t['note'] ?? '')], static fn(string $s): bool => $s !== ''));
        }
        return implode("\n", $lines);
    }
}
