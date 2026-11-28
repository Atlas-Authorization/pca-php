<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ChainCompact.php';
require_once __DIR__ . '/../src/Receipts.php';
require_once __DIR__ . '/../src/BudgetTree.php';
require_once __DIR__ . '/../src/Approvals.php';
require_once __DIR__ . '/../src/BondSettlement.php';
require_once __DIR__ . '/../src/Reputation.php';

use Atlas\Pca\Approvals;
use Atlas\Pca\BudgetTree;
use Atlas\Pca\ChainCompact;
use Atlas\Pca\ChainMemo;
use Atlas\Pca\ChainView;
use Atlas\Pca\InsuranceCapitalPool;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Receipts;
use Atlas\Pca\Reputation;
use Atlas\Pca\Sign;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The core exports of test-data/ref-core-sweep-java.json.gz that are not the reputation or forecast ones (those replay in their own
 * tests): chain compaction and its verifier memo, the receipt log, the multi-agent budget algebra, standing class approvals with the
 * co-sign recharge, and the insurance capital pool. The four frontier-signal functions of that file replay in RefFrontierSignalsDifferentialTest. Op-script functions return one
 * result per op; an op that throws is `{"$err": "Error"}`.
 */
final class RefCoreSweepDifferentialTest extends TestCase
{
    private const FILE = 'ref-core-sweep-java.json.gz';
    private const FNS = ['hopLeaf' => 5, 'hopsRoot' => 14, 'compactChain' => 14, 'compactChainShapeError' => 27, 'chainMemo' => 8, 'receiptFor' => 60,
        'receiptChain' => 21, 'subBudget' => 117, 'debitConsolidated' => 288, 'debitConsolidatedPath' => 72, 'rechargeFull' => 28, 'approveClass' => 75,
        'classApprovalCovers' => 675, 'coveredByAny' => 36, 'recordDecision' => 2, 'pendingRequests' => 5, 'applyCosign' => 48, 'pool' => 9];

    public static function provide(): array
    {
        $out = [];
        foreach (Base::datasets(self::FILE) as $k => $v) {
            if (isset(self::FNS[$v[1]])) {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    private static function err(): Obj
    {
        return Obj::of(['$err' => 'Error']);
    }

    private static function int(mixed $n): ?int
    {
        return $n === null ? null : $n->int();
    }

    private static function clock(mixed $n): ?int
    {
        return $n instanceof Num && $n->isInt() ? $n->int() : null;
    }

    private static function viewOut(ChainView $v): Obj
    {
        $hashes = [];
        $counts = [];
        for ($i = 0; $i < $v->n; $i++) {
            $hashes[] = $v->hash($i);
            $counts[] = $v->count($i);
        }
        return Obj::of(['n' => $v->n, 'hashes' => $hashes, 'counts' => $counts, 'leaf' => $v->leaf]);
    }

    private static function memo(array $ops): array
    {
        $m = null;
        $out = [];
        foreach ($ops as $op) {
            try {
                $out[] = match ($op[0]) {
                    'new' => (function () use ($op, &$m) {
                        $o = $op[1] ?? new Obj();
                        $m = new ChainMemo($o->has('maxEntries') ? $o->get('maxEntries')->int() : null, $o->has('ttlMs') ? $o->get('ttlMs')->int() : null);
                        return null;
                    })(),
                    'remember' => (function () use ($op, $m) {
                        $now = self::clock($op[3]);
                        return $now === null ? throw new \InvalidArgumentException('the clock is not a safe integer') : $m->rememberVerified($op[1], $op[2], $now);
                    })(),
                    'resolve' => (function () use ($op, $m) {
                        $now = self::clock($op[2]);
                        if ($now === null) {
                            return Obj::of(['ok' => false, 'reason' => 'the verifier clock is not a safe integer (fail closed)']);
                        }
                        $r = $m->resolve($op[1], $now);
                        return $r['ok'] ? Obj::of(['ok' => true, 'view' => self::viewOut($r['view'])]) : Obj::of(['ok' => false, 'reason' => $r['reason']]);
                    })(),
                    'prune' => (function () use ($op, $m) {
                        $m->prune($op[1]->int());
                        return null;
                    })(),
                    'forget' => $m->forget($op[1]),
                    'size' => $m->size(),
                    default => throw new \LogicException('op'),
                };
            } catch (\Throwable) {
                $out[] = self::err();
            }
        }
        return $out;
    }

    private static function copy(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::copy($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::copy(...), $v) : $v;
    }

    private static function receipts(array $ops): array
    {
        $log = [];
        $out = [];
        foreach ($ops as $op) {
            try {
                $v = null;
                switch ($op[0]) {
                    case 'append':
                        $log = Receipts::appendReceipt($log, $op[1], $op[2], self::int($op[3]));
                        $v = $log[count($log) - 1];
                        break;
                    case 'head':
                        $v = Receipts::receiptHead($log);
                        break;
                    case 'verify':
                        $v = Receipts::verifyReceiptChain($log);
                        break;
                    case 'set':
                        $log = self::copy($op[1]);
                        break;
                    case 'tamper':
                        $log = self::copy($log);
                        $e = $log[$op[1]->int()] ?? throw new \TypeError('no such entry');
                        if ($op[3] === '$del') {
                            $log[$op[1]->int()] = $e->without($op[2]);
                        } else {
                            $e->set($op[2], $op[3]);
                        }
                        break;
                    case 'swap':
                        $l = self::copy($log);
                        [$i, $j] = [$op[1]->int(), $op[2]->int()];
                        [$l[$i], $l[$j]] = [$l[$j], $l[$i]];
                        $log = $l;
                        break;
                    case 'drop':
                        $log = array_values(array_filter($log, static fn($_, $i) => $i !== $op[1]->int(), ARRAY_FILTER_USE_BOTH));
                        break;
                    case 'truncate':
                        $log = array_slice($log, 0, $op[1]->int());
                        break;
                    default:
                        throw new \LogicException('op');
                }
                $out[] = $v;
            } catch (\Throwable) {
                $out[] = self::err();
            }
        }
        return $out;
    }

    private static function pool(array $ops): array
    {
        $pool = null;
        $out = [];
        foreach ($ops as $op) {
            try {
                $out[] = match ($op[0]) {
                    'new' => (function () use ($op, &$pool) {
                        $pool = new InsuranceCapitalPool($op[1]);
                        return $pool->state();
                    })(),
                    'quote' => Reputation::priceCoverage($op[1], $op[2], $op[3]),
                    'collect' => $pool->collectPremium(Reputation::priceCoverage($op[1], $op[2], $op[3])),
                    'canCover' => $pool->canCover($op[1]),
                    'pay' => $pool->payClaim($op[1]),
                    'state' => $pool->state(),
                    default => throw new \LogicException('op'),
                };
            } catch (\Throwable) {
                $out[] = self::err();
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $p = static fn(mixed $v): mixed => Sign::plain($v);
        Base::run($file, $fn, $k, [
            'hopLeaf' => static fn(array $a) => ChainCompact::hopLeaf($a[0]),
            'hopsRoot' => static fn(array $a) => ChainCompact::hopsRoot($a[0]),
            'compactChain' => static fn(array $a) => ChainCompact::compactChain($a[0]),
            'compactChainShapeError' => static fn(array $a) => ChainCompact::compactChainShapeError($a[0]),
            'chainMemo' => static fn(array $a) => self::memo($a[0]),
            'receiptFor' => static fn(array $a) => Receipts::receiptFor($a[0], $a[1]->int(), $a[2], $a[3], self::int($a[4])),
            'receiptChain' => static fn(array $a) => self::receipts($a[0]),
            'subBudget' => static fn(array $a) => BudgetTree::subBudget($a[0], $a[1]),
            'debitConsolidated' => static fn(array $a) => BudgetTree::debitConsolidated($a[0], $a[1], $a[2]),
            'debitConsolidatedPath' => static fn(array $a) => BudgetTree::debitConsolidatedPath($a[0], $a[1]),
            'rechargeFull' => static fn(array $a) => BudgetTree::rechargeFull($a[0], $a[1]),
            'approveClass' => static fn(array $a) => Approvals::approveClass($a[0], $a[1]->int(), $a[2], $a[3]->int(), $a[4]),
            'classApprovalCovers' => static fn(array $a) => Approvals::classApprovalCovers($p($a[0]), $a[1], $a[2], $a[3]->int()),
            'coveredByAny' => static fn(array $a) => Approvals::coveredByAny($p($a[0]), $a[1], $a[2], $a[3]->int()),
            'recordDecision' => static fn(array $a) => Approvals::recordDecision($p($a[0]), $a[1], $a[2], $a[3]->int()),
            'pendingRequests' => static fn(array $a) => Approvals::pendingRequests($p($a[0])),
            'applyCosign' => static fn(array $a) => Approvals::applyCosign($p($a[0]), $p($a[1]), $a[2]->int(), $a[3]),
            'pool' => static fn(array $a) => self::pool($a[0]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
