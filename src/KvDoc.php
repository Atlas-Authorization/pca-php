<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/Json.php';

/** Process-local {@see AtomicKv} for tests and a single process (TS `memoryLeaseKv()`): it forgets everything on restart, so a registry only runs over it when the host names it. */
final class MemoryLeaseKv implements AtomicKv
{
    private MemoryAtomicKv $m;

    public function __construct()
    {
        $this->m = new MemoryAtomicKv();
    }

    public function get(string $key): ?string
    {
        return $this->m->get($key);
    }

    public function update(string $key, callable $fn): void
    {
        $this->m->update($key, $fn);
    }
}

/** Shared plumbing of the kv-backed lease / break-glass registries: stable shard of an id, the pinned shard count and JSON documents. @internal */
final class KvDoc
{
    public const DEFAULT_SHARDS = 16;
    public const MAX_SHARDS = 4096;

    /** The shard an id lives in: the first four bytes of SHA-256 of the id (big endian), modulo the shard count. Stable across processes. */
    public static function shardOf(string $id, int $shards): int
    {
        return unpack('N', substr(hash('sha256', $id, true), 0, 4))[1] % $shards;
    }

    public static function dec(?string $raw): ?Obj
    {
        if ($raw === null) {
            return null;
        }
        $v = Json::parseLax($raw);
        return $v instanceof Obj ? $v : null;
    }

    public static function enc(Obj $o): string
    {
        return Json::canonicalizeLenient($o);
    }

    /** Pin the shard count in the store on first use; a different count would make existing records invisible, so it is refused (false). */
    public static function ready(AtomicKv $kv, string $metaKey, int $shards): bool
    {
        $kv->update($metaKey, static fn(?string $prev): ?string => $prev === null ? self::enc(Obj::of(['v' => 1, 'shards' => $shards])) : null);
        $m = self::dec($kv->get($metaKey));
        return $m !== null && $m->get('shards') instanceof Num && $m->get('shards')->int() === $shards;
    }

    public static function checkShards(string $who, mixed $n): int
    {
        $n ??= self::DEFAULT_SHARDS;
        if (!is_int($n) || $n < 1 || $n > self::MAX_SHARDS) {
            throw new \RangeException("$who: shards must be an integer from 1 to 4096");
        }
        return $n;
    }
}
