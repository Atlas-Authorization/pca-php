<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Undo.php';
require_once __DIR__ . '/AtomicKv.php';

/** An undo-ledger error (UndoError of the reference): `code` is not_durable, store_missing, store_corrupt, invalid, conflict_exhausted, signer_missing or config. */
final class UndoError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct("$errorCode: $message");
    }
}

/**
 * The persistence contract of the undo ledger (UndoStore). Records are Obj trees (the undo record of the specification). Implement it over a
 * database (a row per record with a unique id and a version column: `UPDATE ... WHERE id = :id AND ver = :ver`) or use {@see KvUndoStore}.
 *
 * `list($q)`: `$q['state']` (required) and optional `windowEndedBy`, `grantRef`, `bondRef`, `limit`.
 */
interface UndoStore
{
    /** True ONLY when acknowledged writes survive a restart or crash. The coordinator refuses a store that does not say so. */
    public function durable(): bool;

    public function get(string $id): ?Obj;

    /** Atomically insert if no record with this id exists; otherwise return the stored one unchanged. @return array{created:bool,record?:Obj} */
    public function create(Obj $rec): array;

    /** Atomically replace the record iff its stored `ver` is `$expectedVer`. */
    public function replace(string $id, int $expectedVer, Obj $next): bool;

    /** @param array<string,mixed> $q @return list<Obj> */
    public function list(array $q): array;
}

/** Shared helpers of the reference stores. */
final class UndoStores
{
    /** True for an object that implements the store contract (isUndoStore). */
    public static function isUndoStore(mixed $s): bool
    {
        return $s instanceof UndoStore;
    }

    /** @param array<string,mixed> $q */
    public static function matches(Obj $r, array $q): bool
    {
        $we = $r->get('window_end');
        return $r->get('state') === ($q['state'] ?? null)
            && (!isset($q['windowEndedBy']) || (Js::num($we) ?? INF) <= $q['windowEndedBy'])
            && (!isset($q['grantRef']) || $r->get('grant_ref') === $q['grantRef'])
            && (!isset($q['bondRef']) || $r->get('bond_ref') === $q['bondRef']);
    }

    public static function idCheck(mixed $id): string
    {
        if (!Undo::idOk($id)) {
            throw new UndoError('invalid', 'an undo record id is a non-empty string without control characters');
        }
        return $id;
    }

    /** The stored record of a raw document, or null; a document of the wrong shape is store_corrupt. */
    public static function decode(?string $raw): ?Obj
    {
        if ($raw === null) {
            return null;
        }
        try {
            $r = Json::parseLax($raw);
        } catch (\Throwable) {
            throw new UndoError('store_corrupt', 'an undo record is not JSON');
        }
        if (!($r instanceof Obj) || !($r->get('v') instanceof Num) || $r->get('v')->lexeme !== '1' || !Undo::idOk($r->get('id'))
            || !in_array($r->get('state'), Undo::STATES, true) || !K3Sig::anySafeInt($r->get('ver')) || !is_array($r->get('receipts'))) {
            throw new UndoError('store_corrupt', 'an undo record has the wrong shape');
        }
        return $r;
    }

    private static function ver(Obj $r): int
    {
        return (int)Js::num($r->get('ver'));
    }

    public static function verOf(Obj $r): int
    {
        return self::ver($r);
    }
}

/**
 * A process-memory {@see UndoStore}: `durable()` is false, so the coordinator refuses it unless the caller says, for a test, that it accepts losing
 * every open window on restart. Never use it in production.
 */
final class MemoryUndoStore implements UndoStore
{
    /** @var array<string,string> */
    private array $m = [];

    public function durable(): bool
    {
        return false;
    }

    public function get(string $id): ?Obj
    {
        return isset($this->m[$id]) ? Json::parseLax($this->m[$id]) : null;
    }

    public function create(Obj $rec): array
    {
        $id = UndoStores::idCheck($rec->get('id'));
        if (isset($this->m[$id])) {
            return ['created' => false, 'record' => Json::parseLax($this->m[$id])];
        }
        $this->m[$id] = Json::canonicalizeLenient($rec);
        return ['created' => true];
    }

    public function replace(string $id, int $expectedVer, Obj $next): bool
    {
        if ($next->get('id') !== $id) {
            throw new UndoError('invalid', 'replace: the record id cannot change');
        }
        if (!isset($this->m[$id]) || UndoStores::verOf(Json::parseLax($this->m[$id])) !== $expectedVer) {
            return false;
        }
        $this->m[$id] = Json::canonicalizeLenient($next);
        return true;
    }

    public function list(array $q): array
    {
        $out = [];
        $ids = array_map('strval', array_keys($this->m));
        sort($ids, SORT_STRING);
        foreach ($ids as $id) {
            $r = Json::parseLax($this->m[$id]);
            if (UndoStores::matches($r, $q)) {
                $out[] = $r;
            }
        }
        return isset($q['limit']) ? array_slice($out, 0, (int)$q['limit']) : $out;
    }
}

/**
 * The reference {@see UndoStore} over any {@see AtomicKv} (one JSON document per record, every write one atomic read-modify-write). `$durable` is
 * declared by the caller because a kv cannot tell: true only over a persistent kv ({@see PdoAtomicKv}), false over an in-memory one.
 * shortcut: `list` reads an id index document that grows with every record (fine for one host's backlog); a database store indexes (state, window_end).
 */
final class KvUndoStore implements UndoStore
{
    private const PREFIX = 'pca-undo/v1/';
    private const INDEX = 'pca-undo/v1-index';

    public function __construct(private readonly AtomicKv $kv, private readonly bool $isDurable)
    {
    }

    public function durable(): bool
    {
        return $this->isDurable;
    }

    public function get(string $id): ?Obj
    {
        return UndoStores::decode($this->kv->get(self::PREFIX . UndoStores::idCheck($id)));
    }

    public function create(Obj $rec): array
    {
        $id = UndoStores::idCheck($rec->get('id'));
        $existing = null;
        $this->kv->update(self::PREFIX . $id, static function (?string $prev) use ($rec, &$existing): ?string {
            $existing = UndoStores::decode($prev);
            return $existing !== null ? null : Json::canonicalizeLenient($rec);
        });
        if ($existing !== null) {
            return ['created' => false, 'record' => $existing];
        }
        $this->kv->update(self::INDEX, static function (?string $prev) use ($id): ?string {
            $ids = $prev === null ? [] : (json_decode($prev, true) ?: []);
            return in_array($id, $ids, true) ? null : json_encode([...$ids, $id], JSON_THROW_ON_ERROR);
        });
        return ['created' => true];
    }

    public function replace(string $id, int $expectedVer, Obj $next): bool
    {
        if ($next->get('id') !== $id) {
            throw new UndoError('invalid', 'replace: the record id cannot change');
        }
        $done = false;
        $this->kv->update(self::PREFIX . UndoStores::idCheck($id), static function (?string $prev) use ($expectedVer, $next, &$done): ?string {
            $cur = UndoStores::decode($prev);
            $done = $cur !== null && UndoStores::verOf($cur) === $expectedVer;
            return $done ? Json::canonicalizeLenient($next) : null;
        });
        return $done;
    }

    public function list(array $q): array
    {
        $raw = $this->kv->get(self::INDEX);
        $ids = $raw === null ? [] : (json_decode($raw, true) ?: []);
        sort($ids, SORT_STRING);
        $out = [];
        foreach ($ids as $id) {
            $r = UndoStores::decode($this->kv->get(self::PREFIX . $id));
            if ($r !== null && UndoStores::matches($r, $q)) {
                $out[] = $r;
            }
            if (isset($q['limit']) && count($out) >= (int)$q['limit']) {
                break;
            }
        }
        return $out;
    }
}
