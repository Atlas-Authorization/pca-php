<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\BudgetRelease;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\KvBondStore;
use Atlas\Pca\KvBudgetLedger;
use Atlas\Pca\KvLedgerStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use Atlas\Pca\StoreErrors;
use Atlas\Pca\StoredLedger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/KvDoc.php';
require_once __DIR__ . '/../src/LedgerStore.php';
require_once __DIR__ . '/../src/BondStore.php';
require_once __DIR__ . '/../src/BudgetLedger.php';
require_once __DIR__ . '/RefCoreMeshDifferentialTest.php';

/**
 * The durable stores against the TS reference (ref-core-stores-java): the ledger store, the stored ledger with its checkpoint
 * verification, the bond store, the budget ledger with signed releases and aggregate admission, and the mesh witness. Every failure is
 * compared by its stable code (`RangeError` for an argument error).
 */
final class RefCoreStoresDifferentialTest extends TestCase
{
    private const FILE = 'ref-core-stores-java.json.gz';
    private const FNS = ['ledgerStore', 'storedLedger', 'bondStore', 'budgetLedger', 'meshWitness'];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => in_array($d[1], self::FNS, true));
    }

    private static function key(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $label, true));
    }

    /** @param list<mixed> $ops @param callable(mixed):mixed $f */
    private static function script(array $ops, callable $f): array
    {
        $out = [];
        foreach ($ops as $op) {
            try {
                $out[] = $f($op);
            } catch (\Throwable $e) {
                $out[] = ['$err' => StoreErrors::codeOf($e)];
            }
        }
        return $out;
    }

    private static function put(MemoryAtomicKv $kv, string $key, mixed $value): mixed
    {
        $kv->update($key, static fn(?string $prev): string => Json::canonicalizeLenient($value));
        return null;
    }

    private static function get(MemoryAtomicKv $kv, string $key): mixed
    {
        $raw = $kv->get($key);
        return $raw === null ? null : Json::parseLax($raw);
    }

    private static function ledgerStore(array $ops): array
    {
        $kv = new MemoryAtomicKv();
        $s = new KvLedgerStore($kv);
        return self::script($ops, static function (array $op) use ($kv, $s): mixed {
            return match ($op[0]) {
                'size' => $s->size(),
                'read' => $s->read($op[1], $op[2]),
                'append' => $s->append($op[1], $op[2]),
                'cpCount' => $s->checkpointCount(),
                'cps' => $s->checkpoints($op[1]),
                'appendCp' => $s->appendCheckpoint($op[1], $op[2]),
                'kvSet' => self::put($kv, 'pca-ledger-store/v1', $op[1]),
                default => throw new \InvalidArgumentException('op'),
            };
        });
    }

    private static function storedLedger(array $ops): array
    {
        $kv = new MemoryAtomicKv();
        $store = new KvLedgerStore($kv);
        $handles = [];
        $calls = 0;
        $gkey = self::key('stored-ledger-guardian');
        $clock = static function () use (&$calls): int {
            return 1_800_000_000_000 + 1000 * $calls++;
        };
        return self::script($ops, static function (array $op) use ($kv, $store, &$handles, $clock, $gkey): mixed {
            $head = $op[0];
            if ($head === 'open') {
                $g = ($op[2] ?? null) === 'other-key' ? self::key('other') : $gkey;
                $h = StoredLedger::open($store, $g, ($op[3] ?? null) ?? 'inst', 'pr', $clock);
                $handles[$op[1]] = $h;
                return ['size' => $h->size(), 'guardian' => $h->guardian()];
            }
            if ($head === 'kvSet') {
                return self::put($kv, 'pca-ledger-store/v1', $op[1]);
            }
            if ($head === 'kvGet') {
                return self::get($kv, 'pca-ledger-store/v1');
            }
            $h = $handles[$head];
            return match ($op[1]) {
                'append' => $h->append($op[2]),
                'checkpoint' => $h->checkpoint(),
                'catchUp' => $h->catchUp(),
                'head' => $h->head(),
                'size' => $h->size(),
                'incl' => $h->inclusionProof($op[2]),
                'consFrom' => $h->consistencyProofFrom($op[2]),
                'commits' => $h->commits(),
                'latest' => $h->latestCheckpoint(),
                'chain' => $h->checkpointChain(),
                'guardian' => $h->guardian(),
                default => throw new \InvalidArgumentException('op'),
            };
        });
    }

    private static function bondStore(array $ops): array
    {
        $kv = new MemoryAtomicKv();
        $s = new KvBondStore($kv);
        return self::script($ops, static function (array $op) use ($kv, $s): mixed {
            return match ($op[0]) {
                'read' => $s->read($op[1], $op[2] ?? null),
                'commit' => $s->commit($op[1], $op[2]),
                'deposit' => $s->deposit($op[1], $op[2]),
                'kvSet' => self::put($kv, 'pca-bond-store/v1', $op[1]),
                'kvGet' => self::get($kv, 'pca-bond-store/v1'),
                default => throw new \InvalidArgumentException('op'),
            };
        });
    }

    private static function budgetLedger(array $ops): array
    {
        $rkey = self::key('release-signer');
        $kv = new MemoryAtomicKv();
        $ledger = null;
        $log = new KvLedgerStore(new MemoryAtomicKv());
        return self::script($ops, static function (array $op) use ($rkey, $kv, &$ledger, $log): mixed {
            switch ($op[0]) {
                case 'new':
                    $ledger = new KvBudgetLedger($kv, $op[1]);
                    return $ledger->durable();
                case 'snapshot':
                    return $ledger->snapshot($op[1]);
                case 'reserve':
                    return $ledger->reserve($op[1], $op[2]);
                case 'start':
                    return $ledger->start($op[1], $op[2]);
                case 'commit':
                    return $ledger->commit($op[1], $op[2]);
                case 'release':
                    return $ledger->release($op[1], $op[2], $op[3]);
                case 'expire':
                    return $ledger->expire($op[1], $op[2]);
                case 'signRelease':
                    return BudgetRelease::signRelease($op[1], $op[2], $op[3], $op[4], $rkey);
                case 'verifyRelease':
                    return BudgetRelease::verifyRelease($op[1], $op[2] === 'signer' ? $rkey->public : $op[2]);
                case 'releaseCommit':
                    return [BudgetRelease::releaseDigest($op[1]), BudgetRelease::releaseCommit($op[1])];
                case 'anchor':
                    return [BudgetRelease::anchorRelease($log, $op[1]), $log->size()];
                case 'scopeKey':
                    return \Atlas\Pca\BudgetLedgerDoc::scopeKey($op[1], $op[2]);
                case 'kvSet':
                    return self::put($kv, $op[1], $op[2]);
                case 'admit':
                    $ad = $op[1];
                    $allow = $ad->get('allow');
                    return BudgetRelease::admitAggregateAction($ledger, $ad->get('ids'), $ad->get('accumulators'), null, $ad->get('event'),
                        static fn($state): array => ['allow' => $allow, 'state' => $state], $ad->get('expiresAt'), $ad->get('maxAttempts'));
                case 'startAgg':
                    return BudgetRelease::startAggregate($ledger, $op[1]);
                case 'settleAgg':
                    return BudgetRelease::settleAggregate($ledger, $op[1], $op[2], null);
                default:
                    throw new \InvalidArgumentException('op');
            }
        });
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'ledgerStore' => fn(array $a) => self::ledgerStore($a[0]),
            'storedLedger' => fn(array $a) => self::storedLedger($a[0]),
            'bondStore' => fn(array $a) => self::bondStore($a[0]),
            'budgetLedger' => fn(array $a) => self::budgetLedger($a[0]),
            'meshWitness' => fn(array $a) => RefCoreMeshDifferentialTest::witnessScript($a[0]),
        ]);
    }

    public function testEveryFunctionOfTheCorpusIsCovered(): void
    {
        $fns = [];
        foreach (Base::datasets(self::FILE) as $d) {
            $fns[$d[1]] = true;
        }
        $this->assertSame(self::FNS, array_values(array_intersect(self::FNS, array_keys($fns))));
        $this->assertSame([], array_values(array_diff(array_keys($fns), self::FNS)));
    }
}
