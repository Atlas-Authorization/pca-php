<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** What {@see StateStore::claim} returns. `ok` is true only when THIS call consumed the counter. */
final class ClaimResult
{
    public function __construct(public readonly bool $ok, public readonly ?int $lastCounter = null)
    {
    }
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
 * In-process reference store. PHP shares nothing between requests: under PHP-FPM / mod_php this store lives for ONE
 * request (every request starts empty, so it never refuses a replay across requests). Use it for tests and for a single
 * long-lived worker process only; use {@see PdoStateStore} or your own database otherwise.
 */
final class MemoryStateStore implements StateStore
{
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
final class PdoStateStore implements StateStore
{
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
}
