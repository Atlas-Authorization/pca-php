<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ChainCompact;
use Atlas\Pca\ChainMemo;
use Atlas\Pca\ChainView;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ChainCompact.php';

/** Chain compaction (hop leaves, hops root, compact chain and its shape check, the verifier memo, the chain view) against the TS reference: test-data/ref-core-chain-compact.json.gz. */
final class RefCoreChainCompactDifferentialTest extends TestCase
{
    private const FILE = 'ref-core-chain-compact.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function viewOut(ChainView $v): Obj
    {
        $hashes = [];
        $counts = [];
        for ($i = 0; $i < $v->n; $i++) {
            $hashes[] = $v->hash($i);
            $counts[] = $v->count($i);
        }
        return Obj::of(['n' => $v->n, 'leaf' => $v->leaf, 'hashes' => $hashes, 'counts' => $counts]);
    }

    /** A clock the reference takes only when it is a safe integer (the PHP API takes an int). */
    private static function clock(mixed $n): ?int
    {
        return $n instanceof Num && $n->isInt() ? $n->int() : null;
    }

    private static function memoSeq(?Obj $opts, array $steps): array
    {
        $m = new ChainMemo($opts !== null && $opts->has('maxEntries') ? $opts->get('maxEntries')->int() : null, $opts !== null && $opts->has('ttlMs') ? $opts->get('ttlMs')->int() : null);
        $out = [];
        foreach ($steps as $s) {
            switch ($s[0]) {
                case 'remember':
                    try {
                        $now = self::clock($s[3]);
                        if ($now === null) {
                            throw new \InvalidArgumentException('the clock is not a safe integer');
                        }
                        $out[] = Obj::of(['ok' => true, 'compact' => $m->rememberVerified($s[1], $s[2], $now)]);
                    } catch (\Throwable) {
                        $out[] = Obj::of(['ok' => false]);
                    }
                    break;
                case 'resolve':
                    $now = self::clock($s[2]);
                    if ($now === null) {
                        $out[] = Obj::of(['ok' => false, 'reason' => 'the verifier clock is not a safe integer (fail closed)']);
                        break;
                    }
                    $r = $m->resolve($s[1], $now);
                    $out[] = $r['ok'] ? Obj::of(['ok' => true, 'view' => self::viewOut($r['view'])]) : Obj::of(['ok' => false, 'reason' => $r['reason']]);
                    break;
                case 'prune':
                    $m->prune($s[1]->int());
                    $out[] = null;
                    break;
                case 'forget':
                    $out[] = $m->forget($s[1]);
                    break;
                default:
                    $out[] = $m->size();
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'hopLeaf' => fn(array $a) => ChainCompact::hopLeaf($a[0]),
            'hopsRoot' => fn(array $a) => ChainCompact::hopsRoot($a[0]),
            'compactChain' => fn(array $a) => ChainCompact::compactChain($a[0]),
            'compactChainShapeError' => fn(array $a) => ChainCompact::compactChainShapeError($a[0]),
            'viewOfChain' => fn(array $a) => self::viewOut(ChainCompact::viewOfChain($a[0], $a[1])),
            'memoSeq' => fn(array $a) => self::memoSeq($a[0], $a[1]),
        ]);
    }
}
