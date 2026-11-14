<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/StoreConformance.php';
require_once __DIR__ . '/../src/AtomicKv.php';

use Atlas\Pca\AtomicKv;
use Atlas\Pca\BudgetStateStore;
use Atlas\Pca\ClaimResult;
use Atlas\Pca\ConformanceReport;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\PinStateStore;
use Atlas\Pca\StoreConformance;
use PHPUnit\Framework\TestCase;

/** The call log shared by every handle of one kit run. */
final class SkLog
{
    /** @var list<string> */
    public array $lines = [];
    public int $opens = 0;

    /** conf:<pid>:<seq>:<label>:<8 hex> -> <label> */
    public static function label(string $key): string
    {
        return (string)preg_replace('/\Aconf:\d+:\d+:(.+):[0-9a-f]{8}\z/D', '$1', $key);
    }

    public static function opener(SkLog $log, \Closure $make): \Closure
    {
        return static function () use ($log, $make): object {
            $id = ++$log->opens;
            $log->lines[] = "open h$id";
            return $make($id);
        };
    }

    public function countContaining(string $part): int
    {
        return count(array_filter($this->lines, static fn(string $l): bool => str_contains($l, $part)));
    }

    public function count(string $suffix): int
    {
        return count(array_filter($this->lines, static fn(string $l): bool => str_ends_with($l, $suffix)));
    }
}

/** An AtomicKv handle that logs every call and forwards to the shared store. */
final class SkKvHandle implements AtomicKv
{
    public function __construct(private readonly SkLog $log, private readonly int $id, private readonly AtomicKv $inner)
    {
    }

    public function get(string $key): ?string
    {
        $this->log->lines[] = "h{$this->id} get " . SkLog::label($key);
        return $this->inner->get($key);
    }

    public function update(string $key, callable $fn): void
    {
        $this->log->lines[] = "h{$this->id} update " . SkLog::label($key);
        $this->inner->update($key, $fn);
    }
}

/** A budget + pin store handle that logs every call; `$override` may answer a claim instead of the store. */
final class SkStateHandle implements BudgetStateStore, PinStateStore
{
    public function __construct(private readonly SkLog $log, private readonly int $id, private readonly MemoryStateStore $inner, private readonly ?\Closure $override = null)
    {
    }

    public function budget(string $key): ?array
    {
        $this->log->lines[] = "h{$this->id} budget " . SkLog::label($key);
        return $this->inner->budget($key);
    }

    public function claimWithBudget(string $key, int $counter, ?array $before, ?array $after): ClaimResult
    {
        $f = static fn(?array $x): string => $x === null ? 'null' : (string)$x['B'];
        $this->log->lines[] = sprintf('h%d claim %s %d %s %s', $this->id, SkLog::label($key), $counter, $f($before), $f($after));
        $o = $this->override === null ? null : ($this->override)($counter, $before, $after);
        return $o ?? $this->inner->claimWithBudget($key, $counter, $before, $after);
    }

    public function pin(string $key): ?int
    {
        $this->log->lines[] = "h{$this->id} pin " . SkLog::label($key);
        return $this->inner->pin($key);
    }

    public function raisePin(string $key, int $value): void
    {
        $this->log->lines[] = "h{$this->id} raise " . SkLog::label($key) . " $value";
        $this->inner->raisePin($key, $value);
    }
}

/** A kv with one deliberate defect, chosen by `$mode`. */
final class SkBadKv implements AtomicKv
{
    /** @var array<string,string> */
    private array $m = [];

    /** @param string $mode 'one': every update stores "1"; 'noop': nothing is stored; 'null-existing' / 'null-absent': a null result writes "" to an existing / an absent key; 'empty-prev': a missing key reads as "" in update */
    public function __construct(private readonly string $mode)
    {
    }

    public function get(string $key): ?string
    {
        return $this->m[$key] ?? null;
    }

    public function update(string $key, callable $fn): void
    {
        if ($this->mode === 'noop') {
            return;
        }
        if ($this->mode === 'one') {
            $this->m[$key] = '1';
            return;
        }
        $prev = $this->m[$key] ?? null;
        $next = $fn($this->mode === 'empty-prev' ? ($prev ?? '') : $prev);
        if ($next !== null) {
            $this->m[$key] = $next;
        } elseif ($this->mode === 'null-existing' ? $prev !== null : $prev === null) {
            $this->m[$key] = '';
        }
    }
}

/** A pin store with one deliberate defect: 'leak' (one pin for every key), 'deaf' (never stores) or 'first' (the first raise sticks). */
final class SkBadPins implements PinStateStore
{
    private ?int $global = null;
    /** @var array<string,int> */
    private array $firsts = [];

    public function __construct(private readonly string $mode)
    {
    }

    public function pin(string $key): ?int
    {
        return $this->mode === 'first' ? ($this->firsts[$key] ?? null) : $this->global;
    }

    public function raisePin(string $key, int $value): void
    {
        if ($this->mode === 'leak') {
            $this->global = max($this->global ?? $value, $value);
        } elseif ($this->mode === 'first') {
            $this->firsts[$key] ??= $value;
        }
    }
}

/** The F11 kits (atomic kv, budget store, pin store): exact reports, exact call sequences, defaults, notes and broken stores. */
final class StoreKitsMutationTest extends TestCase
{
    private const NOT_DURABLE = 'durable is false (state dies with the process)';

    /** @return list<array{string,string,string}> */
    private static function checks(ConformanceReport $r): array
    {
        return array_map(static fn($c): array => [$c->name, $c->status, $c->note], $r->checks);
    }

    private static function statusOf(ConformanceReport $r, string $name): string
    {
        return $r->status($name);
    }

    private static function note(ConformanceReport $r, string $name): string
    {
        foreach ($r->checks as $c) {
            if ($c->name === $name) {
                return $c->note;
            }
        }
        return '(absent)';
    }

    /** @return array{ConformanceReport, SkLog} */
    private static function kv(array $cfg, ?AtomicKv $inner = null): array
    {
        $log = new SkLog();
        $inner ??= new MemoryAtomicKv();
        $r = StoreConformance::runAtomicKv(['open' => SkLog::opener($log, static fn(int $id): object => new SkKvHandle($log, $id, $inner))] + $cfg);
        return [$r, $log];
    }

    /** @return array{ConformanceReport, SkLog} */
    private static function budget(array $cfg, ?\Closure $override = null): array
    {
        $log = new SkLog();
        $inner = new MemoryStateStore();
        $r = StoreConformance::runBudgetStore(['open' => SkLog::opener($log, static fn(int $id): object => new SkStateHandle($log, $id, $inner, $override))] + $cfg);
        return [$r, $log];
    }

    /** @return array{ConformanceReport, SkLog} */
    private static function pins(array $cfg): array
    {
        $log = new SkLog();
        $inner = new MemoryStateStore();
        $r = StoreConformance::runPinStore(['open' => SkLog::opener($log, static fn(int $id): object => new SkStateHandle($log, $id, $inner))] + $cfg);
        return [$r, $log];
    }

    public function testWithoutAnOpenCallableEveryKitReportsAConfigurationFailure(): void
    {
        foreach (['runAtomicKv' => 'atomic kv', 'runBudgetStore' => 'budget store', 'runPinStore' => 'pin store'] as $kit => $name) {
            foreach ([[], ['open' => 'no_such_function_for_conformance']] as $cfg) {
                $r = StoreConformance::$kit($cfg);
                $this->assertSame($name, $r->name);
                $this->assertSame([['configuration', 'fail', 'open is required']], self::checks($r));
                $this->assertFalse($r->ok());
            }
        }
    }

    public function testTheReportNameIsTheConfiguredNameAsAString(): void
    {
        foreach (['runAtomicKv', 'runBudgetStore', 'runPinStore'] as $kit) {
            $this->assertSame('5', StoreConformance::$kit(['name' => 5])->name);
            $this->assertSame('custom', StoreConformance::$kit(['name' => 'custom'])->name);
        }
    }

    public function testAtomicKvExactReportAndCallSequenceWithDefaultCapabilities(): void
    {
        [$r, $log] = self::kv(['copies' => 4]);
        $this->assertSame([
            ['get-missing', 'pass', ''],
            ['update-stores-and-reads-back', 'pass', ''],
            ['update-sees-the-previous-value', 'pass', ''],
            ['update-returning-null-leaves-the-value', 'pass', ''],
            ['a-throwing-update-changes-nothing', 'pass', ''],
            ['concurrent-updates-lose-nothing', 'pass', ''],
            ['values-survive-a-reopen', 'pass', ''],
        ], self::checks($r));
        $this->assertSame([
            'open h1', 'h1 get kv-missing',
            'open h2', 'h2 update kv-set', 'h2 get kv-set',
            'open h3', 'h3 update kv-prev', 'h3 update kv-prev', 'h3 get kv-prev',
            'open h4', 'h4 update kv-null', 'h4 update kv-null', 'h4 update kv-null-absent', 'h4 get kv-null', 'h4 get kv-null-absent',
            'open h5', 'h5 update kv-throw', 'h5 update kv-throw', 'h5 get kv-throw',
            'open h6', 'open h7', 'h6 update kv-race', 'h7 update kv-race', 'h6 update kv-race', 'h7 update kv-race', 'open h8', 'h8 get kv-race',
            'open h9', 'h9 update kv-durable', 'open h10', 'h10 get kv-durable',
        ], $log->lines);
    }

    public function testAtomicKvUnsharedAndNotDurable(): void
    {
        [$r, $log] = self::kv(['shared' => false, 'durable' => false, 'copies' => 3]);
        $this->assertSame([
            ['get-missing', 'pass', ''],
            ['update-stores-and-reads-back', 'pass', ''],
            ['update-sees-the-previous-value', 'pass', ''],
            ['update-returning-null-leaves-the-value', 'pass', ''],
            ['a-throwing-update-changes-nothing', 'pass', ''],
            ['concurrent-updates-lose-nothing', 'pass', ''],
            ['values-survive-a-reopen', 'skip', self::NOT_DURABLE],
        ], self::checks($r));
        $this->assertSame([
            'open h1', 'h1 get kv-missing',
            'open h2', 'h2 update kv-set', 'h2 get kv-set',
            'open h3', 'h3 update kv-prev', 'h3 update kv-prev', 'h3 get kv-prev',
            'open h4', 'h4 update kv-null', 'h4 update kv-null', 'h4 update kv-null-absent', 'h4 get kv-null', 'h4 get kv-null-absent',
            'open h5', 'h5 update kv-throw', 'h5 update kv-throw', 'h5 get kv-throw',
            'open h6', 'h6 update kv-race', 'h6 update kv-race', 'h6 update kv-race', 'open h7', 'h7 get kv-race',
        ], $log->lines);
    }

    public function testAtomicKvCopiesDefaultAndAreCastToAnInteger(): void
    {
        [$r, $log] = self::kv([]);
        $this->assertTrue($r->ok(), (string)$r);
        $this->assertSame(16, $log->count(' update kv-race'));
        foreach ([['4', 4], [4, 4], [1, 1], [0, 1]] as [$copies, $runs]) {
            [$r, $log] = self::kv(['copies' => $copies]);
            $this->assertSame('pass', self::statusOf($r, 'concurrent-updates-lose-nothing'), (string)$r);
            $this->assertSame($runs, $log->count(' update kv-race'), "copies " . var_export($copies, true));
        }
    }

    public function testAtomicKvRaceNoteNamesTheCountAndTheValueReached(): void
    {
        $note = static fn(array $cfg, string $mode): string => self::note(self::kv($cfg, new SkBadKv($mode))[0], 'concurrent-updates-lose-nothing');
        $this->assertSame("16 concurrent increments ended at NULL (an update was lost)", $note([], 'noop'));
        $this->assertSame("4 concurrent increments ended at '1' (an update was lost)", $note(['copies' => 4], 'one'));
        $this->assertSame("1 concurrent increments ended at NULL (an update was lost)", $note(['copies' => 1], 'noop'));
        $this->assertSame("1 concurrent increments ended at NULL (an update was lost)", $note(['copies' => 0], 'noop'));
        $this->assertSame("3 concurrent increments ended at '1' (an update was lost)", $note(['copies' => '3'], 'one'));
    }

    public function testAtomicKvIncrementReadsAnEmptyPreviousValueAsZero(): void
    {
        [$r] = self::kv(['copies' => 3], new SkBadKv('empty-prev'));
        $this->assertSame('pass', self::statusOf($r, 'concurrent-updates-lose-nothing'), (string)$r);
    }

    public function testAtomicKvNullResultMustChangeNothingForEveryKey(): void
    {
        foreach (['null-existing', 'null-absent'] as $mode) {
            [$r] = self::kv([], new SkBadKv($mode));
            $this->assertSame('fail', self::statusOf($r, 'update-returning-null-leaves-the-value'), $mode);
            $this->assertSame('a null result changed the store', self::note($r, 'update-returning-null-leaves-the-value'), $mode);
        }
    }

    public function testBudgetStoreExactReportAndCallSequenceWithDefaultCapabilities(): void
    {
        [$r, $log] = self::budget(['copies' => 4]);
        $this->assertSame([
            ['no-budget-is-null', 'pass', ''],
            ['claim-stores-the-counter-and-the-budget', 'pass', ''],
            ['a-replay-spends-nothing', 'pass', ''],
            ['a-stale-read-is-a-conflict-and-claims-nothing', 'pass', ''],
            ['a-null-budget-keeps-the-stored-one', 'pass', ''],
            ['concurrent-claims-admit-exactly-one', 'pass', ''],
        ], self::checks($r));
        $this->assertSame(array_merge(self::budgetPrefix(), [
            'open h6', 'open h7', 'h6 claim b-race 1 null 0.9',
            'h6 claim b-race 2 0.9 0.5', 'h7 claim b-race 2 0.9 0.5', 'h6 claim b-race 2 0.9 0.5', 'h7 claim b-race 2 0.9 0.5',
        ]), $log->lines);
    }

    /** @return list<string> the calls of the five sequential budget checks */
    private static function budgetPrefix(): array
    {
        return [
            'open h1', 'h1 budget b-none',
            'open h2', 'h2 claim b-claim 1 null 0.9', 'h2 budget b-claim',
            'open h3', 'h3 claim b-replay 5 null 0.9', 'h3 claim b-replay 5 0.9 0.5', 'h3 claim b-replay 4 0.9 0.5', 'h3 budget b-replay',
            'open h4', 'h4 claim b-conflict 1 null 0.9', 'h4 claim b-conflict 2 0.8 0.7', 'h4 claim b-conflict 2 0.9 0.7', 'h4 budget b-conflict',
            'open h5', 'h5 claim b-keep 1 null 0.9', 'h5 claim b-keep 2 0.9 null', 'h5 budget b-keep',
        ];
    }

    public function testBudgetStoreUnshared(): void
    {
        [$r, $log] = self::budget(['shared' => false, 'durable' => false, 'copies' => 3]);
        $this->assertTrue($r->ok(), (string)$r);
        $this->assertSame(array_merge(self::budgetPrefix(), [
            'open h6', 'h6 claim b-race 1 null 0.9',
            'h6 claim b-race 2 0.9 0.5', 'h6 claim b-race 2 0.9 0.5', 'h6 claim b-race 2 0.9 0.5',
        ]), $log->lines);
    }

    public function testBudgetStoreCopiesDefaultAndAreCastToAnInteger(): void
    {
        [$r, $log] = self::budget([]);
        $this->assertTrue($r->ok(), (string)$r);
        $this->assertSame(16, $log->count(' claim b-race 2 0.9 0.5'));
        foreach ([['4', 4], [1, 1], [0, 1]] as [$copies, $runs]) {
            [$r, $log] = self::budget(['copies' => $copies]);
            $this->assertSame('pass', self::statusOf($r, 'concurrent-claims-admit-exactly-one'), (string)$r);
            $this->assertSame($runs, $log->count(' claim b-race 2 0.9 0.5'), "copies " . var_export($copies, true));
        }
    }

    public function testBudgetStoreRaceNoteNamesTheCopyCount(): void
    {
        $refuseRace = static fn(int $counter, ?array $before, ?array $after): ?ClaimResult => $counter === 2 && $before !== null ? new ClaimResult(false) : null;
        $note = static fn(array $cfg): string => self::note(self::budget($cfg, $refuseRace)[0], 'concurrent-claims-admit-exactly-one');
        $this->assertSame('0 of 16 claims of one counter on one budget were admitted (want exactly 1)', $note([]));
        $this->assertSame('0 of 1 claims of one counter on one budget were admitted (want exactly 1)', $note(['copies' => 1]));
        $this->assertSame('0 of 1 claims of one counter on one budget were admitted (want exactly 1)', $note(['copies' => 0]));
        $this->assertSame('0 of 3 claims of one counter on one budget were admitted (want exactly 1)', $note(['copies' => 3]));
    }

    public function testBudgetReplayCheckRefusesAStoreThatAdmitsOrConflictsOnAReplay(): void
    {
        $admits = static fn(int $counter, ?array $before, ?array $after): ?ClaimResult => $counter === 5 && $before !== null ? new ClaimResult(true, 5) : null;
        $conflicts = static fn(int $counter, ?array $before, ?array $after): ?ClaimResult => $counter === 5 && $before !== null ? new ClaimResult(false, 5, true) : null;
        $wrongLast = static fn(int $counter, ?array $before, ?array $after): ?ClaimResult => $counter === 5 && $before !== null ? new ClaimResult(false, 4) : null;
        foreach (['admits' => $admits, 'conflicts' => $conflicts, 'wrong last counter' => $wrongLast] as $why => $override) {
            [$r] = self::budget([], $override);
            $this->assertSame('fail', self::statusOf($r, 'a-replay-spends-nothing'), $why);
            $this->assertSame('a replayed counter was not refused as a replay with the last counter', self::note($r, 'a-replay-spends-nothing'), $why);
        }
    }

    public function testBudgetStaleReadCheckRefusesAStoreThatNeverReportsAConflict(): void
    {
        $never = static fn(int $counter, ?array $before, ?array $after): ?ClaimResult => $counter === 2 && $before !== null && $before['B'] === 0.8 ? new ClaimResult(false) : null;
        [$r] = self::budget([], $never);
        $this->assertSame('fail', self::statusOf($r, 'a-stale-read-is-a-conflict-and-claims-nothing'));
        $this->assertSame('a claim made on a budget the store no longer holds was not a conflict', self::note($r, 'a-stale-read-is-a-conflict-and-claims-nothing'));
    }

    public function testPinStoreExactReportAndCallSequenceWithDefaultCapabilities(): void
    {
        [$r, $log] = self::pins(['copies' => 4]);
        $this->assertSame([
            ['no-pin-is-null', 'pass', ''],
            ['a-pin-never-goes-down', 'pass', ''],
            ['pins-are-independent-per-key', 'pass', ''],
            ['concurrent-raises-end-at-the-highest', 'pass', ''],
            ['a-pin-survives-a-reopen', 'pass', ''],
        ], self::checks($r));
        $this->assertSame([
            'open h1', 'h1 pin pin-none',
            'open h2', 'h2 raise pin-mono 7', 'h2 raise pin-mono 6', 'h2 pin pin-mono', 'h2 raise pin-mono 7', 'h2 raise pin-mono 9', 'h2 pin pin-mono',
            'open h3', 'h3 raise pin-a 3', 'h3 pin pin-b', 'h3 pin pin-a',
            'open h4', 'open h5', 'h4 raise pin-race 3', 'h5 raise pin-race 4', 'h4 raise pin-race 1', 'h5 raise pin-race 2', 'open h6', 'h6 pin pin-race',
            'open h7', 'h7 raise pin-durable 4', 'open h8', 'h8 pin pin-durable',
        ], $log->lines);
    }

    public function testPinStoreUnsharedAndNotDurable(): void
    {
        [$r, $log] = self::pins(['shared' => false, 'durable' => false, 'copies' => 3]);
        $this->assertSame([
            ['no-pin-is-null', 'pass', ''],
            ['a-pin-never-goes-down', 'pass', ''],
            ['pins-are-independent-per-key', 'pass', ''],
            ['concurrent-raises-end-at-the-highest', 'pass', ''],
            ['a-pin-survives-a-reopen', 'skip', self::NOT_DURABLE],
        ], self::checks($r));
        $this->assertSame([
            'open h1', 'h1 pin pin-none',
            'open h2', 'h2 raise pin-mono 7', 'h2 raise pin-mono 6', 'h2 pin pin-mono', 'h2 raise pin-mono 7', 'h2 raise pin-mono 9', 'h2 pin pin-mono',
            'open h3', 'h3 raise pin-a 3', 'h3 pin pin-b', 'h3 pin pin-a',
            'open h4', 'h4 raise pin-race 2', 'h4 raise pin-race 3', 'h4 raise pin-race 1', 'open h5', 'h5 pin pin-race',
        ], $log->lines);
    }

    public function testPinStoreCopiesDefaultAndAreCastToAnInteger(): void
    {
        [$r, $log] = self::pins([]);
        $this->assertTrue($r->ok(), (string)$r);
        $this->assertSame(16, $log->countContaining(' raise pin-race '));
        foreach ([['4', 4], [1, 1], [0, 1]] as [$copies, $runs]) {
            [$r, $log] = self::pins(['copies' => $copies]);
            $this->assertSame('pass', self::statusOf($r, 'concurrent-raises-end-at-the-highest'), (string)$r);
            $this->assertSame($runs, $log->countContaining(' raise pin-race '), "copies " . var_export($copies, true));
        }
    }

    public function testPinStoreRaceNoteNamesTheValueReachedAndTheCount(): void
    {
        $note = static function (array $cfg, string $mode): string {
            $store = new SkBadPins($mode);
            return self::note(StoreConformance::runPinStore(['open' => static fn() => $store] + $cfg), 'concurrent-raises-end-at-the-highest');
        };
        $this->assertSame('racing raises ended at NULL (want 16)', $note([], 'deaf'));
        $this->assertSame('racing raises ended at 3 (want 4)', $note(['copies' => 4], 'first'));
        $this->assertSame('racing raises ended at NULL (want 1)', $note(['copies' => 0], 'deaf'));
        $this->assertSame('racing raises ended at NULL (want 1)', $note(['copies' => 1], 'deaf'));
    }

    public function testPinStoreIndependenceCheckRefusesALeakingOrDeafStore(): void
    {
        foreach (['leak', 'deaf'] as $mode) {
            $store = new SkBadPins($mode);
            $r = StoreConformance::runPinStore(['open' => static fn() => $store]);
            $this->assertSame('fail', self::statusOf($r, 'pins-are-independent-per-key'), $mode);
            $this->assertSame('a pin leaked into another key', self::note($r, 'pins-are-independent-per-key'), $mode);
        }
    }
}
