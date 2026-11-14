<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** What {@see StateStore::claim} returns. `ok` is true only when THIS call consumed the counter. */
final class ClaimResult
{
    /** @param bool $conflict the stored trust budget was not the one the caller read (another instance spent first): nothing was claimed, retry */
    public function __construct(public readonly bool $ok, public readonly ?int $lastCounter = null, public readonly bool $conflict = false)
    {
    }
}

/**
 * The optional trust-budget side of a replay store (F2). The guard reads a holder's budget with `budget($key)` (null = none yet), decides on
 * it, and then settles ONE action with `claimWithBudget`: atomically, a stored counter that is not below `$counter` is a replay
 * (`ClaimResult(false, last)`), a stored budget different from `$before` (both absent counts as equal) is a conflict
 * (`ClaimResult(false, null, true)`), otherwise the counter and `$after` (or the stored budget when `$after` is null) are stored.
 * A store without it cannot persist a budget: the guard then seeds the full budget on every call, so nothing depletes.
 * A budget is `['B' => float, 'tau' => float, 'asOf' => ?float]`.
 */
interface BudgetStateStore
{
    public function budget(string $key): ?array;

    public function claimWithBudget(string $key, int $counter, ?array $before, ?array $after): ClaimResult;
}

/**
 * The replay store of {@see Authorize::authorize}: ONE atomic operation of your backend. If a counter is stored for `$key`
 * and `$counter` is not strictly greater, return `new ClaimResult(false, $stored)`; otherwise store `$counter` and return
 * `new ClaimResult(true)`. A claim that cannot decide must return `ok = false` or throw (authorize then denies).
 * Implementations need not implement this interface: any object with a `claim(string, int)` method is accepted.
 */
interface StateStore
{
    public function claim(string $key, int $counter): ClaimResult;
}

/**
 * The optional scope of a replay store: `'process'` (its state lives in this process only: a PCActn replays once per instance, so
 * `multiInstance` refuses it) or `'shared'` (every instance sees one state). A store without `scope()` is treated as shared, as in the
 * reference.
 */
interface ScopedStateStore
{
    /** @return 'process'|'shared' */
    public function scope(): string;
}

/**
 * The optional monotone pins of a store (rollback protection of the revocation epoch): `raisePin` stores a value only when it is greater
 * than the stored one (never lowers; atomic across instances) and `pin` reads it (null = none yet). Revocation staleness needs a store
 * that implements it.
 */
interface PinStateStore
{
    public function pin(string $key): ?int;

    public function raisePin(string $key, int $value): void;
}

/**
 * The optional read side of a replay store: the last admitted counter of a stream (null = none yet). It binds an
 * EscalationAnswer to the holder's history ({@see Escalation::historyHead}); a store without `last` cannot admit an answered
 * escalation (the middleware refuses to be built with escalation principals over one).
 */
interface LastStateStore extends StateStore
{
    public function last(string $key): ?int;
}

/**
 * The optional TTL'd consume-once side of a store (`max_uses` slots). `consumeOnce` returns true iff this call is the first
 * to consume `$key` with no live record (a live record has `retain_until >= now`); it remembers the key at least until
 * `$retainUntilMs` (the maximum over repeats) and THROWS `\InvalidArgumentException` for an empty key or `$retainUntilMs <
 * $nowMs`, leaving nothing behind. A store without it is used through `claim` (slots then never expire).
 */
interface ConsumeOnceStore
{
    public function consumeOnce(string $key, int $retainUntilMs, int $nowMs): bool;
}

/**
 * In-process reference store. PHP shares nothing between requests: under PHP-FPM / mod_php this store lives for ONE
 * request (every request starts empty, so it never refuses a replay across requests). Use it for tests and for a single
 * long-lived worker process only; use {@see PdoStateStore} or your own database otherwise.
 */
final class MemoryStateStore implements LastStateStore, ConsumeOnceStore, ScopedStateStore, PinStateStore, BudgetStateStore
{
    /** @var array<string,array{B:float,tau:float,asOf:?float}> */
    private array $budgets = [];

    public function budget(string $key): ?array
    {
        return $this->budgets[$key] ?? null;
    }

    public function claimWithBudget(string $key, int $counter, ?array $before, ?array $after): ClaimResult
    {
        if (array_key_exists($key, $this->last) && !($counter > $this->last[$key])) {
            return new ClaimResult(false, $this->last[$key]);
        }
        if (self::sameBudget($this->budgets[$key] ?? null, $before) === false) {
            return new ClaimResult(false, null, true);
        }
        $this->last[$key] = $counter;
        if ($after !== null) {
            $this->budgets[$key] = $after;
        }
        return new ClaimResult(true);
    }

    /** @internal */
    public static function sameBudget(?array $a, ?array $b): bool
    {
        return $a === null || $b === null ? $a === $b : ($a['B'] === $b['B'] && $a['tau'] === $b['tau'] && ($a['asOf'] ?? null) === ($b['asOf'] ?? null));
    }

    /** @var array<string,int> */
    private array $pins = [];

    public function pin(string $key): ?int
    {
        return $this->pins[$key] ?? null;
    }

    public function raisePin(string $key, int $value): void
    {
        $this->pins[$key] = max($this->pins[$key] ?? $value, $value);
    }

    public function scope(): string
    {
        return 'process';
    }

    /** @var array<string,int> key => retain_until */
    private array $once = [];

    /** @var array<string,int> */
    private array $last = [];

    public function claim(string $key, int $counter): ClaimResult
    {
        if (array_key_exists($key, $this->last) && !($counter > $this->last[$key])) {
            return new ClaimResult(false, $this->last[$key]);
        }
        $this->last[$key] = $counter;
        return new ClaimResult(true);
    }

    public function last(string $key): ?int
    {
        return $this->last[$key] ?? null;
    }

    public function consumeOnce(string $key, int $retainUntilMs, int $nowMs): bool
    {
        if ($key === '' || $retainUntilMs < $nowMs) {
            throw new \InvalidArgumentException('consumeOnce: invalid key or retention horizon');
        }
        $until = $this->once[$key] ?? null;
        $live = $until !== null && $until >= $nowMs;
        $this->once[$key] = max($retainUntilMs, $until ?? 0);
        if (count($this->once) > 10000) { // drop only records whose retention has fully elapsed
            $this->once = array_filter($this->once, static fn(int $u): bool => $u >= $nowMs);
        }
        return !$live;
    }
}

/**
 * Durable reference store on PDO (SQLite 3.24+ or PostgreSQL 9.5+): one row per counter stream, `key` is the PRIMARY KEY.
 *
 * The claim is ONE statement, `INSERT ... ON CONFLICT (key) DO UPDATE SET last_counter = excluded.last_counter WHERE
 * excluded.last_counter > <table>.last_counter`, and its row count decides: 1 = this call consumed the counter, 0 = an
 * equal or greater counter was already stored. The database serializes the statement on the key (SQLite's write lock,
 * PostgreSQL's unique index), so concurrent processes sharing the database can never both consume the same counter. The
 * connection must be in autocommit mode (no open transaction) so the claim is durable when it returns.
 */
final class PdoStateStore implements LastStateStore, ConsumeOnceStore, ScopedStateStore, PinStateStore, BudgetStateStore
{
    public function budget(string $key): ?array
    {
        $q = $this->pdo->prepare('SELECT b FROM ' . $this->table . '_budget WHERE key = ?');
        $q->execute([$key]);
        $v = $q->fetchColumn();
        return is_string($v) ? self::decodeBudget($v) : null;
    }

    /** One transaction: the budget compared, the counter claimed, the budget stored. A busy database throws (the guard then denies). */
    public function claimWithBudget(string $key, int $counter, ?array $before, ?array $after): ClaimResult
    {
        $this->pdo->beginTransaction();
        try {
            if (!MemoryStateStore::sameBudget($this->budget($key), $before)) {
                $this->pdo->rollBack();
                return new ClaimResult(false, null, true);
            }
            $r = $this->claim($key, $counter);
            if (!$r->ok) {
                $this->pdo->rollBack();
                return $r;
            }
            if ($after !== null) {
                $st = $this->pdo->prepare('INSERT INTO ' . $this->table . '_budget (key, b) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET b = excluded.b');
                $st->execute([$key, json_encode($after)]);
            }
            $this->pdo->commit();
            return $r;
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    private static function decodeBudget(string $v): ?array
    {
        $d = json_decode($v, true);
        return is_array($d) && isset($d['B'], $d['tau']) ? ['B' => (float)$d['B'], 'tau' => (float)$d['tau'], 'asOf' => isset($d['asOf']) ? (float)$d['asOf'] : null] : null;
    }

    private const PIN_PREFIX = 'pca-pin:';

    /** A pin is a counter stream of its own: `claim` stores a value only when it is greater, atomically, which is exactly a monotone raise. */
    public function raisePin(string $key, int $value): void
    {
        $this->claim(self::PIN_PREFIX . $key, $value);
    }

    public function pin(string $key): ?int
    {
        return $this->last(self::PIN_PREFIX . $key);
    }

    public function scope(): string
    {
        return 'shared';
    }

    public const DEFAULT_TABLE = 'pca_replay';
    private const MAX_COUNTER = 9007199254740991;

    private readonly string $table;

    /**
     * @param \PDO   $pdo   a connection to SQLite or PostgreSQL (its error mode is set to exceptions)
     * @param string $table the table name (letters, digits and `_`, not starting with a digit)
     */
    public function __construct(private readonly \PDO $pdo, string $table = self::DEFAULT_TABLE)
    {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]{0,62}\z/D', $table) !== 1) {
            throw new \InvalidArgumentException('PdoStateStore: invalid table name');
        }
        $this->table = $table;
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /** Create the table when it does not exist (idempotent). Run it once at deployment, or at start-up. */
    public function createTable(): void
    {
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS ' . $this->table
            . ' (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)');
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS ' . $this->table . '_once'
            . ' (key TEXT NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS ' . $this->table . '_once_until ON ' . $this->table . '_once (retain_until)');
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS ' . $this->table . '_budget (key TEXT NOT NULL PRIMARY KEY, b TEXT NOT NULL)');
    }

    public function claim(string $key, int $counter): ClaimResult
    {
        if ($counter < 0 || $counter > self::MAX_COUNTER) {
            return new ClaimResult(false);
        }
        $st = $this->pdo->prepare('INSERT INTO ' . $this->table . ' (key, last_counter) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET '
            . 'last_counter = excluded.last_counter WHERE excluded.last_counter > ' . $this->table . '.last_counter');
        $st->bindValue(1, $key, \PDO::PARAM_STR);
        $st->bindValue(2, $counter, \PDO::PARAM_INT);
        $st->execute();
        if ($st->rowCount() === 1) {
            return new ClaimResult(true);
        }
        $q = $this->pdo->prepare('SELECT last_counter FROM ' . $this->table . ' WHERE key = ?');
        $q->execute([$key]);
        $last = $q->fetchColumn();
        return new ClaimResult(false, $last === false || $last === null ? null : (int)$last);
    }

    public function last(string $key): ?int
    {
        $q = $this->pdo->prepare('SELECT last_counter FROM ' . $this->table . ' WHERE key = ?');
        $q->execute([$key]);
        $last = $q->fetchColumn();
        return $last === false || $last === null ? null : (int)$last;
    }

    /**
     * ONE statement decides: insert, or take over a record whose retention elapsed (`retain_until < now`); a live record
     * leaves the row untouched (0 rows). A live repeat then only raises the horizon (never lowers it). Expired rows are pruned.
     */
    public function consumeOnce(string $key, int $retainUntilMs, int $nowMs): bool
    {
        if ($key === '' || $retainUntilMs < $nowMs || $retainUntilMs > self::MAX_COUNTER || $nowMs < 0) {
            throw new \InvalidArgumentException('consumeOnce: invalid key or retention horizon');
        }
        $t = $this->table . '_once';
        $this->bindAll($this->pdo->prepare('DELETE FROM ' . $t . ' WHERE retain_until < ?'), [$nowMs])->execute();
        $st = $this->bindAll($this->pdo->prepare('INSERT INTO ' . $t . ' (key, retain_until) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET '
            . 'retain_until = excluded.retain_until WHERE ' . $t . '.retain_until < ?'), [$key, $retainUntilMs, $nowMs]);
        $st->execute();
        if ($st->rowCount() === 1) {
            return true;
        }
        $this->bindAll($this->pdo->prepare('UPDATE ' . $t . ' SET retain_until = ? WHERE key = ? AND retain_until < ?'),
            [$retainUntilMs, $key, $retainUntilMs])->execute();
        return false;
    }

    /** @param list<string|int> $vals */
    private function bindAll(\PDOStatement $st, array $vals): \PDOStatement
    {
        foreach ($vals as $i => $v) {
            $st->bindValue($i + 1, $v, is_int($v) ? \PDO::PARAM_INT : \PDO::PARAM_STR);
        }
        return $st;
    }
}
