<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * An atomic key/value store of strings (JSON documents): the storage of the {@see PlanRegistry}. `update` MUST be atomic across
 * every process and node that shares the store: it reads the current value (null = none), calls `$fn` with it and stores what
 * `$fn` returns (null = leave the value as it is). A call that cannot decide MUST throw.
 */
interface AtomicKv
{
    public function get(string $key): ?string;

    /** @param callable(?string):?string $fn pure: a contended update may call it more than once */
    public function update(string $key, callable $fn): void;
}

/** In-process {@see AtomicKv} (tests, one worker): PHP shares nothing between requests, so under FPM it lives for one request. */
final class MemoryAtomicKv implements AtomicKv
{
    /** @var array<string,string> */
    private array $m = [];

    public function get(string $key): ?string
    {
        return $this->m[$key] ?? null;
    }

    public function update(string $key, callable $fn): void
    {
        $next = $fn($this->m[$key] ?? null);
        if ($next !== null) {
            $this->m[$key] = $next;
        }
    }
}

/**
 * {@see AtomicKv} on PDO (SQLite 3.24+ or PostgreSQL 9.5+). `update` is a compare-and-swap loop of single statements: read the
 * value, compute the next one, then `INSERT ... ON CONFLICT DO NOTHING` (no value yet) or `UPDATE ... WHERE value = <the one
 * read>` (a value exists); a statement that changed no row means another writer won, and the loop re-reads. The database
 * serializes each statement on the key, so concurrent processes sharing it cannot both apply the same transition. The
 * connection must be in autocommit mode (no open transaction).
 */
final class PdoAtomicKv implements AtomicKv
{
    public const DEFAULT_TABLE = 'pca_kv';
    private const MAX_ATTEMPTS = 64;

    private readonly string $table;

    public function __construct(private readonly \PDO $pdo, string $table = self::DEFAULT_TABLE)
    {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]{0,62}\z/D', $table) !== 1) {
            throw new \InvalidArgumentException('PdoAtomicKv: invalid table name');
        }
        $this->table = $table;
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /** Create the table when it does not exist (idempotent). */
    public function createTable(): void
    {
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS ' . $this->table . ' (k TEXT NOT NULL PRIMARY KEY, v TEXT NOT NULL)');
    }

    public function get(string $key): ?string
    {
        $q = $this->pdo->prepare('SELECT v FROM ' . $this->table . ' WHERE k = ?');
        $q->execute([$key]);
        $v = $q->fetchColumn();
        return is_string($v) ? $v : null;
    }

    public function update(string $key, callable $fn): void
    {
        for ($i = 0; $i < self::MAX_ATTEMPTS; $i++) {
            $prev = $this->get($key);
            $next = $fn($prev);
            if ($next === null) {
                return;
            }
            if ($prev === null) {
                $st = $this->pdo->prepare('INSERT INTO ' . $this->table . ' (k, v) VALUES (?, ?) ON CONFLICT (k) DO NOTHING');
                $st->execute([$key, $next]);
            } else {
                $st = $this->pdo->prepare('UPDATE ' . $this->table . ' SET v = ? WHERE k = ? AND v = ?');
                $st->execute([$next, $key, $prev]);
            }
            if ($st->rowCount() === 1) {
                return;
            }
        }
        throw new \RuntimeException('PdoAtomicKv: the update did not settle (contention)');
    }
}
