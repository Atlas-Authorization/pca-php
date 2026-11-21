<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/UndoStore.php';

use Atlas\Pca\Json;
use Atlas\Pca\KvUndoStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryUndoStore;
use Atlas\Pca\Obj;
use Atlas\Pca\UndoError;
use Atlas\Pca\UndoStore;
use Atlas\Pca\UndoStores;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The undo ledger store contract (undo.ts) over both reference stores. */
final class UndoStoreTest extends TestCase
{
    /** @return array<string,array{0:\Closure():UndoStore,1:bool}> */
    public static function stores(): array
    {
        return ['memory' => [static fn() => new MemoryUndoStore(), false], 'kv' => [static fn() => new KvUndoStore(new MemoryAtomicKv(), true), true]];
    }

    private static function rec(string $id, string $state = 'open', int $ver = 0, int $windowEnd = 1000, ?string $grant = 'g1'): Obj
    {
        return Json::parseLax('{"v":1,"id":"' . $id . '","state":"' . $state . '","ver":' . $ver . ',"window_end":' . $windowEnd . ',"grant_ref":"' . ($grant ?? '') . '","receipts":[]}');
    }

    #[DataProvider('stores')]
    public function testCreateGetReplaceCompareAndSwap(\Closure $make, bool $durable): void
    {
        $s = $make();
        self::assertSame($durable, $s->durable());
        self::assertNull($s->get('a'));
        self::assertSame(['created' => true], $s->create(self::rec('a')));
        $again = $s->create(self::rec('a', 'finalized', 7));
        self::assertFalse($again['created']);
        self::assertSame('open', $again['record']->get('state'));
        self::assertSame('open', $s->get('a')->get('state'));
        self::assertFalse($s->replace('a', 1, self::rec('a', 'vetoed', 2)), 'a stale version loses');
        self::assertTrue($s->replace('a', 0, self::rec('a', 'vetoed', 1)));
        self::assertSame('vetoed', $s->get('a')->get('state'));
        self::assertFalse($s->replace('zz', 0, self::rec('zz')), 'no such record');
    }

    #[DataProvider('stores')]
    public function testListFiltersAndOrders(\Closure $make): void
    {
        $s = $make();
        foreach ([['b', 'open', 500, 'g2'], ['a', 'open', 900, 'g1'], ['c', 'open', 2000, 'g1'], ['d', 'finalized', 100, 'g1']] as [$id, $st, $we, $g]) {
            $s->create(self::rec($id, $st, 0, $we, $g));
        }
        self::assertSame(['a', 'b', 'c'], array_map(fn(Obj $r) => $r->get('id'), $s->list(['state' => 'open'])));
        self::assertSame(['a', 'b'], array_map(fn(Obj $r) => $r->get('id'), $s->list(['state' => 'open', 'windowEndedBy' => 1000])));
        self::assertSame(['a', 'c'], array_map(fn(Obj $r) => $r->get('id'), $s->list(['state' => 'open', 'grantRef' => 'g1'])));
        self::assertSame(['a'], array_map(fn(Obj $r) => $r->get('id'), $s->list(['state' => 'open', 'limit' => 1])));
        self::assertSame([], $s->list(['state' => 'vetoed']));
    }

    #[DataProvider('stores')]
    public function testInvalidIds(\Closure $make): void
    {
        $this->expectException(UndoError::class);
        $this->expectExceptionMessage('invalid: an undo record id');
        $r = self::rec('a');
        $r->set('id', "bad\nid");
        $make()->create($r);
    }

    public function testCorruptDocumentsAndHelpers(): void
    {
        $kv = new MemoryAtomicKv();
        $kv->update('pca-undo/v1/x', static fn() => '{"v":2,"id":"x"}');
        try {
            (new KvUndoStore($kv, true))->get('x');
            self::fail('a record of the wrong shape is refused');
        } catch (UndoError $e) {
            self::assertSame('store_corrupt', $e->errorCode);
        }
        self::assertTrue(UndoStores::isUndoStore(new MemoryUndoStore()));
        self::assertFalse(UndoStores::isUndoStore(new \stdClass()));
    }
}
