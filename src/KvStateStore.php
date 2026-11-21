<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/StateStore.php';
require_once __DIR__ . '/AtomicKv.php';

/**
 * The replay / budget / pin / consume-once store over any {@see AtomicKv} (durablePcaStateStore of the reference): one JSON document
 * `{lastCounter?, budget?, lastEpoch?, lastBeaconSeq?}` per key, changed only through the kv's atomic `update`, so it is correct across
 * every process and node that shares the backend (`PdoAtomicKv`, or your own). `$scope` is 'shared' by default; pass 'process' for a
 * process-local kv so `multiInstance` refuses it. `$prefix` namespaces the keys.
 */
final class KvStateStore implements LastStateStore, ConsumeOnceStore, ScopedStateStore, PinStateStore, BudgetStateStore
{
    public function __construct(private readonly AtomicKv $kv, private readonly string $prefix = 'pca-state:', private readonly string $scope = 'shared')
    {
        if ($scope !== 'process' && $scope !== 'shared') {
            throw new \InvalidArgumentException("KvStateStore: scope is 'process' or 'shared'");
        }
    }

    public function scope(): string
    {
        return $this->scope;
    }

    /** @return array<string,mixed>|null */
    private function read(?string $raw): ?array
    {
        if ($raw === null) {
            return null;
        }
        $v = json_decode($raw, true);
        return is_array($v) && !array_is_list($v) ? $v : null;
    }

    private function enc(array $doc): string
    {
        return json_encode($doc, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION);
    }

    /** The stored document (or null) of `$key`. @return array<string,mixed>|null */
    private function doc(string $key): ?array
    {
        return $this->read($this->kv->get($this->prefix . $key));
    }

    public function budget(string $key): ?array
    {
        $b = $this->doc($key)['budget'] ?? null;
        return is_array($b) && isset($b['B'], $b['tau']) ? ['B' => (float)$b['B'], 'tau' => (float)$b['tau'], 'asOf' => isset($b['asOf']) ? (float)$b['asOf'] : null] : null;
    }

    public function last(string $key): ?int
    {
        $c = $this->doc($key)['lastCounter'] ?? null;
        return is_int($c) ? $c : null;
    }

    public function pin(string $key): ?int
    {
        $v = $this->doc($key)['lastEpoch'] ?? null;
        return is_int($v) ? $v : null;
    }

    /** `lastEpoch` is the revocation-epoch pin; the beacon sequence pin is {@see raiseBeaconSeq}. */
    public function raisePin(string $key, int $value): void
    {
        $this->raise($key, 'lastEpoch', $value);
    }

    public function raiseBeaconSeq(string $key, int $value): void
    {
        $this->raise($key, 'lastBeaconSeq', $value);
    }

    private function raise(string $key, string $pin, int $value): void
    {
        $this->kv->update($this->prefix . $key, function (?string $prev) use ($pin, $value): ?string {
            $cur = $this->read($prev) ?? [];
            if (isset($cur[$pin]) && is_int($cur[$pin]) && $cur[$pin] >= $value) {
                return null;
            }
            $cur[$pin] = $value;
            return $this->enc($cur);
        });
    }

    public function claim(string $key, int $counter): ClaimResult
    {
        return $this->claimWithBudget($key, $counter, null, null, false);
    }

    public function claimWithBudget(string $key, int $counter, ?array $before, ?array $after, bool $checkBudget = true): ClaimResult
    {
        $result = new ClaimResult(false, null, true);
        $this->kv->update($this->prefix . $key, function (?string $prev) use ($counter, $before, $after, $checkBudget, &$result): ?string {
            $cur = $this->read($prev);
            $last = $cur['lastCounter'] ?? null;
            if (is_int($last) && !($counter > $last)) {
                $result = new ClaimResult(false, $last);
                return null;
            }
            if ($checkBudget) {
                $stored = isset($cur['budget']['B'], $cur['budget']['tau'])
                    ? ['B' => (float)$cur['budget']['B'], 'tau' => (float)$cur['budget']['tau'], 'asOf' => isset($cur['budget']['asOf']) ? (float)$cur['budget']['asOf'] : null] : null;
                if (MemoryStateStore::sameBudget($stored, $before) === false) {
                    $result = new ClaimResult(false, null, true);
                    return null;
                }
            }
            $next = $cur ?? [];
            $next['lastCounter'] = $counter;
            if ($after !== null) {
                $next['budget'] = ['B' => $after['B'], 'tau' => $after['tau'], 'asOf' => $after['asOf'] ?? null];
            }
            $result = new ClaimResult(true);
            return $this->enc($next);
        });
        return $result;
    }

    public function consumeOnce(string $key, int $retainUntilMs, int $nowMs): bool
    {
        if ($key === '' || $retainUntilMs < $nowMs) {
            throw new \InvalidArgumentException('consumeOnce: invalid key or retention horizon');
        }
        $won = false;
        $this->kv->update($this->prefix . 'once:' . $key, static function (?string $prev) use ($retainUntilMs, $nowMs, &$won): ?string {
            $until = $prev !== null && ctype_digit($prev) ? (int)$prev : null;
            $won = $until === null || $until < $nowMs;
            return (string)max($retainUntilMs, $until ?? 0);
        });
        return $won;
    }
}

/** The state-store helpers of the reference's require-pca module, over this package's stores. */
final class PcaStateStores
{
    /** The in-process reference store (memoryPcaStore / atomicMemoryPcaStore): scope 'process', atomic within the process. */
    public static function memory(): MemoryStateStore
    {
        return new MemoryStateStore();
    }

    /** The durable store over any atomic kv (durablePcaStateStore). */
    public static function durable(AtomicKv $kv, string $prefix = 'pca-state:', string $scope = 'shared'): KvStateStore
    {
        return new KvStateStore($kv, $prefix, $scope);
    }

    /** True for a store that claims in one atomic step and holds monotone pins (isAtomicPcaStateStore): claim, budget claim and pins. */
    public static function isAtomic(mixed $store): bool
    {
        return $store instanceof StateStore && $store instanceof BudgetStateStore && $store instanceof PinStateStore;
    }
}
