<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ClaimResult;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\PrivateFile;
use Atlas\Pca\StoreConformancePcaState as P;
use PHPUnit\Framework\TestCase;

/** A replay store for the worker tests: correct claim semantics over shared memory, a declared scope, optionally failing every claim. */
final class K27PcaStateStore
{
    public function __construct(private readonly \ArrayObject $m, private readonly string $scope, private readonly bool $fail)
    {
    }

    public function claim(string $key, int $counter): ClaimResult
    {
        if ($this->fail) {
            throw new \RuntimeException('store down');
        }
        $last = $this->m[$key] ?? null;
        if ($last !== null && $counter <= $last) {
            return new ClaimResult(false, $last);
        }
        $this->m[$key] = $counter;
        return new ClaimResult(true);
    }

    public function scope(): string
    {
        return $this->scope;
    }
}

final class K27Killed extends \RuntimeException
{
}

/** pca-state worker entry, adapter loading, the planted-bug claim store, and the run/crash/retry harness paths (worker wait loop through clock/sleep seams). */
final class CoreSurvivorKill27StoreConformancePcaStateTest extends TestCase
{
    /** @var list<array> what the adapter saw: ['options', o] / ['open'] / ['close'] / ['teardown'] / ['crash'] / ['restart'] */
    public static array $log = [];
    /** @var array{scope?:string, maxOpens?:int, fail?:bool} */
    public static array $cfg = [];
    private static ?\ArrayObject $mem = null;
    private string $dir;
    private int $ms = 0;
    private int $reads = 0;
    /** @var list<int> */
    private array $slept = [];

    /** The adapter a spec file returns (it records every call). */
    public static function adapter(array $o): array
    {
        self::$log[] = ['options', $o];
        $mem = self::$mem ??= new \ArrayObject();
        return ['name' => 'k27', 'durable' => true, 'shared' => true,
            'open' => static function () use ($mem): array {
                $opens = count(array_filter(self::$log, static fn(array $e): bool => $e[0] === 'open'));
                if ($opens >= (self::$cfg['maxOpens'] ?? 1000)) {
                    throw new \RuntimeException('too many opens');
                }
                self::$log[] = ['open'];
                return ['store' => new K27PcaStateStore($mem, self::$cfg['scope'] ?? 'shared', self::$cfg['fail'] ?? false), 'close' => static function (): void {
                    self::$log[] = ['close'];
                }];
            },
            'teardown' => static function (): void {
                self::$log[] = ['teardown'];
            },
            'crash' => static function (): void {
                self::$log[] = ['crash'];
            },
            'restart' => static function (): void {
                self::$log[] = ['restart'];
            }];
    }

    protected function setUp(): void
    {
        self::$log = [];
        self::$cfg = [];
        self::$mem = null;
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k27-ps-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
    }

    protected function tearDown(): void
    {
        P::$clockHook = null;
        P::$sleepHook = null;
        P::$procOpenHook = null;
        PrivateFile::$exitHook = null;
        foreach (scandir($this->dir) ?: [] as $f) {
            if ($f !== '.' && $f !== '..') {
                @unlink($this->dir . DIRECTORY_SEPARATOR . $f);
            }
        }
        @rmdir($this->dir);
    }

    private static function eventCount(string $what): int
    {
        return count(array_filter(self::$log, static fn(array $e): bool => $e[0] === $what));
    }

    private function file(string $name, string $text): string
    {
        $p = $this->dir . DIRECTORY_SEPARATOR . $name;
        file_put_contents($p, $text);
        return $p;
    }

    private function spec(): string
    {
        return $this->file('adapter.php', "<?php\nreturn static fn(array \$o): array => \\Atlas\\Pca\\Tests\\CoreSurvivorKill27StoreConformancePcaStateTest::adapter(\$o);\n");
    }

    /** The clock reads $this->ms (milliseconds, half a millisecond in so the cast never rounds across); each sleep advances it 1 ms. */
    private function seams(int $startMs): void
    {
        $this->ms = $startMs;
        P::$clockHook = function (): float {
            if (++$this->reads > 5000) {
                throw new \RuntimeException('runaway wait');
            }
            return ($this->ms + ($this->ms < 0 ? -0.5 : 0.5)) / 1000;
        };
        P::$sleepHook = function (int $us): void {
            $this->slept[] = $us;
            $this->ms++;
        };
    }

    /** Runs workerMain in this process with $cfg; any PHP warning becomes an exception. @return array{0:int,1:string} exit code, output file */
    private function worker(array $cfg, int $proofs = 2): array
    {
        $fx = P::fixture($proofs);
        $cfg += ['spec' => $this->spec(), 'options' => new \stdClass(), 'fixture' => $this->file('fixture.json', Js::stringify(Obj::of(['grant' => $fx['grant'], 'proofs' => $fx['proofs']]))),
            'out' => $this->dir . DIRECTORY_SEPARATOR . 'out.jsonl'];
        set_error_handler(static function (int $no, string $msg): bool {
            if ((error_reporting() & $no) === 0) {
                return false; // silenced with @ on purpose
            }
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            $rc = P::workerMain(['pca-state-worker', json_encode($cfg, JSON_UNESCAPED_SLASHES)]);
        } finally {
            restore_error_handler();
        }
        return [$rc, is_file($cfg['out']) ? (string)file_get_contents($cfg['out']) : ''];
    }

    private static function line(int $counter, int $admitted, int $replays, int $errors): string
    {
        return json_encode(['counter' => $counter, 'admitted' => $admitted, 'replays' => $replays, 'errors' => $errors]) . "\n";
    }

    /** The race worker opens one handle per instance, waits for each round's start, spreads the copies over its guards and appends one owner-only line per round. */
    public function testRaceWorker(): void
    {
        self::$cfg = ['maxOpens' => 2];
        $this->seams(999);
        [$rc, $out] = $this->worker(['options' => ['k' => 'v'], 'mode' => 'race', 'instances' => 2, 'copies' => 3, 'rounds' => 2, 'origin' => 1000.5, 'round_ms' => 50.5]);
        $this->assertSame(0, $rc);
        $this->assertSame(self::line(1, 1, 2, 0) . self::line(2, 1, 2, 0), $out);
        $this->assertSame([['options', ['k' => 'v']], ['open'], ['open'], ['close'], ['close'], ['teardown']], self::$log);
        $this->assertSame(2000, P::WORKER_POLL_US);
        $this->assertSame(array_fill(0, 51, 2000), $this->slept); // 999 -> 1000 for round 0, then 1000 -> 1050 for round 1
        if (!PrivateFile::isWindows()) {
            $this->assertSame(0600, fileperms($this->dir . DIRECTORY_SEPARATOR . 'out.jsonl') & 0777);
        }
    }

    /** Sizes given as fractions are whole numbers (one instance, one round, one copy), a fractional counter is an integer, and one plain instance is not multi-instance. */
    public function testFractionalSizesAreTruncated(): void
    {
        self::$cfg = ['maxOpens' => 1, 'scope' => 'process'];
        [, $out] = $this->worker(['mode' => 'plain', 'instances' => 1.5, 'copies' => 1.5, 'rounds' => 1.5, 'counter' => 2.0]);
        $this->assertSame(self::line(2, 1, 0, 0), $out);
        $this->assertSame(1, self::eventCount('open'));
    }

    /** Without rounds/counter the worker runs one round for counter 1; a scalar options value reaches the adapter as a one-element array. */
    public function testDefaults(): void
    {
        [, $out] = $this->worker(['options' => 'x', 'mode' => 'plain', 'instances' => 1, 'copies' => 1]);
        $this->assertSame(self::line(1, 1, 0, 0), $out);
        $this->assertSame(['options', ['x']], self::$log[0]);
    }

    /** Without an origin or round length every round starts at time 0 (rounds count up from counter 1). */
    public function testDefaultStartTimes(): void
    {
        $this->seams(-1);
        [, $out] = $this->worker(['mode' => 'plain', 'instances' => 1, 'copies' => 1, 'rounds' => 2]);
        $this->assertSame(self::line(1, 1, 0, 0) . self::line(2, 1, 0, 0), $out);
        $this->assertSame([2000], $this->slept);
    }

    /** A store that fails every claim is counted as errors (fail closed), never as admissions. */
    public function testErrorsAreCounted(): void
    {
        self::$cfg = ['fail' => true];
        [, $out] = $this->worker(['mode' => 'plain', 'instances' => 1, 'copies' => 2]);
        $this->assertSame(self::line(1, 0, 0, 2), $out);
    }

    /** A race worker is multi-instance even with one instance, so a process-scoped store is refused. */
    public function testRaceRefusesAProcessScopedStore(): void
    {
        self::$cfg = ['scope' => 'process'];
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('multiInstance requires a shared state store');
        $this->worker(['mode' => 'race', 'instances' => 1, 'copies' => 1]);
    }

    /** admit-then-die records its one admission, then kills itself with exit code 137 before anything else runs. */
    public function testAdmitThenDie(): void
    {
        $calls = [];
        PrivateFile::$exitHook = static function (string $op, int $code) use (&$calls): void {
            $calls[] = [$op, $code];
            if ($op === 'exit') {
                throw new K27Killed('killed');
            }
        };
        $out = $this->dir . DIRECTORY_SEPARATOR . 'out.jsonl';
        try {
            $this->worker(['mode' => 'admit-then-die', 'instances' => 1, 'copies' => 1, 'counter' => 1.0]);
            $this->fail('the worker did not die');
        } catch (K27Killed) {
        }
        $this->assertSame(self::line(1, 1, 0, 0), (string)file_get_contents($out));
        $this->assertSame(['exit', 137], end($calls));
    }

    /** A missing fixture fails with the strict parser's refusal of empty input. */
    public function testMissingFixture(): void
    {
        $w = [];
        set_error_handler(static function (int $no, string $msg) use (&$w): bool {
            $w[] = $msg;
            return true;
        });
        try {
            P::workerMain(['pca-state-worker', json_encode(['spec' => $this->spec(), 'options' => new \stdClass(), 'fixture' => $this->dir . '/none.json', 'out' => $this->dir . '/o', 'mode' => 'plain', 'instances' => 1, 'copies' => 1])]);
            $this->fail('no refusal');
        } catch (\Throwable $e) {
            $this->assertSame('Atlas\Pca\JsonError', get_class($e));
        } finally {
            restore_error_handler();
        }
    }

    /** The planted-bug store is named, volatile and shared; it waits between read and write; it admits only a counter above the last one. */
    public function testBadReadThenWriteClaim(): void
    {
        $slept = [];
        P::$sleepHook = static function (int $us) use (&$slept): void {
            $slept[] = $us;
        };
        $a = P::builtin('bad-read-then-write-claim');
        $this->assertSame(['BAD claim as read, wait, write', false, true], [$a['name'], $a['durable'], $a['shared']]);
        $s = ($a['open'])();
        $r = [$s->claim('k', 2), $s->claim('k', 2), $s->claim('k', 1), $s->claim('k', 3)];
        $this->assertSame([[true, null], [false, 2], [false, 2], [true, null]], array_map(static fn(ClaimResult $c): array => [$c->ok, $c->lastCounter], $r));
        $this->assertSame(1000, P::BAD_CLAIM_WAIT_US);
        $this->assertSame([1000, 1000, 1000, 1000], $slept);
    }

    /** An unknown built-in adapter is refused with the list of known ones. */
    public function testUnknownBuiltin(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("unknown built-in pca-state adapter 'nope' (known: in-memory, durable-file, bad-read-then-write-claim, bad-volatile, bad-unshared)");
        P::builtin('nope');
    }

    /** A spec file may return a factory or an adapter; anything without a string name and a callable open is refused. */
    public function testLoadAdapterSpecFiles(): void
    {
        $f = $this->file('f.php', "<?php\nreturn static fn(array \$o): array => ['name' => 'n:' . count(\$o), 'open' => 'strlen'];\n");
        $this->assertSame('n:1', P::loadAdapter($f, ['a' => 1])['name']);
        $arr = $this->file('a.php', "<?php\nreturn ['name' => 'plain', 'open' => 'strlen'];\n");
        $this->assertSame(['spec' => $arr, 'options' => [], 'name' => 'plain', 'open' => 'strlen'], P::loadAdapter($arr));
        foreach (["['name' => 5, 'open' => 'strlen']", "['name' => 'n', 'open' => 5]", "'not-an-adapter-k27'"] as $i => $body) {
            $bad = $this->file("b$i.php", "<?php\nreturn $body;\n");
            try {
                P::loadAdapter($bad);
                $this->fail("accepted $body");
            } catch (\TypeError $e) {
                $this->assertSame("$bad: does not return a pca-state adapter (an array with a string name and an open callable)", $e->getMessage());
            }
        }
    }

    /** run refuses an unknown test name and still tears the adapter down. */
    public function testRunUnknownTestTearsDown(): void
    {
        try {
            P::run(P::loadAdapter($this->spec()), ['tests' => ['nope']]);
            $this->fail('no refusal');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('unknown test nope', $e->getMessage());
        }
        $this->assertSame(1, self::eventCount('teardown'));
    }

    /** retry-after-timeout passes for a correct shared store: the first answer is lost, the retry is a replay, the next counter is admitted. */
    public function testRetryAfterTimeoutPasses(): void
    {
        P::$sleepHook = static function (int $us): void {
        };
        $r = P::run(P::builtin('bad-read-then-write-claim'), ['tests' => ['retry-after-timeout']]);
        $this->assertSame('pass', $r['tests'][0]['status'], P::format($r));
        $this->assertSame('lost answer: first=error, retry=replay, next counter=admitted', $r['tests'][0]['note']);
    }

    /** crash-after-claim crashes and restarts the adapter in process, and restarts it again between the killed worker and its retry. */
    public function testCrashAfterClaimCallsCrashAndRestart(): void
    {
        $n = 0;
        P::$procOpenHook = static function (array $cmd, array $spec, &$pipes) use (&$n) {
            if ($n++ === 0) {
                return proc_open([PHP_BINARY, '-n', '-r', ''], $spec, $pipes);
            }
            $pipes = [];
            throw new \RuntimeException('stop');
        };
        try {
            P::run(P::loadAdapter($this->spec()), ['tests' => ['crash-after-claim']]);
            $this->fail('no stop');
        } catch (\RuntimeException $e) {
            $this->assertSame('stop', $e->getMessage());
        }
        $this->assertSame([1, 2, 1], [self::eventCount('crash'), self::eventCount('restart'), self::eventCount('teardown')]);
    }

    /** A worker process that cannot be started is an error, not a silent pass. */
    public function testWorkerThatCannotStart(): void
    {
        P::$procOpenHook = static function (array $cmd, array $spec, &$pipes) {
            $pipes = [];
            return false;
        };
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('pca-state: cannot start a worker process');
        P::run(P::loadAdapter($this->spec()), ['tests' => ['processes'], 'rounds' => 1, 'processes' => 1]);
    }
}
