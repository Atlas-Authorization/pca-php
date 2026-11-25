<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/KvDoc.php';

use Atlas\Pca\KvDoc;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Shard hashing, document decoding and the pinned shard count of the kv-backed registries. */
final class KvDocMutationTest extends TestCase
{
    public function testShardOfIsTheFirstFourBytesOfSha256BigEndianModTheShardCount(): void
    {
        // the first four bytes of sha256("L1") read big endian are 3757999510; bytes 1..4 would give 1602 mod 4096
        $this->assertSame(1430, KvDoc::shardOf('L1', 4096));
        $this->assertSame(6, KvDoc::shardOf('L1', 16));
        $this->assertSame(274, KvDoc::shardOf('a', 4096));
        $this->assertSame(0, KvDoc::shardOf('lease-7', 16));
        $this->assertSame(1090, KvDoc::shardOf('', 4096));
        $this->assertSame(0, KvDoc::shardOf('anything', 1));
    }

    public function testDecOnlyReturnsAnObject(): void
    {
        $this->assertNull(KvDoc::dec(null));
        $this->assertNull(KvDoc::dec('[1,2]'));
        $this->assertNull(KvDoc::dec('5'));
        $this->assertNull(KvDoc::dec('"x"'));
        $this->assertNull(KvDoc::dec('null'));
        $o = KvDoc::dec('{"a":"b"}');
        $this->assertInstanceOf(Obj::class, $o);
        $this->assertSame('b', $o->get('a'));
    }

    public function testEncIsCanonical(): void
    {
        $this->assertSame('{"a":2,"b":1}', KvDoc::enc(Obj::of(['b' => 1, 'a' => 2])));
    }

    public function testReadyPinsTheShardCountOnFirstUseAndRefusesAnother(): void
    {
        $kv = new MemoryAtomicKv();
        $this->assertTrue(KvDoc::ready($kv, 'meta', 16));
        $this->assertSame('{"shards":16,"v":1}', $kv->get('meta'));
        $this->assertTrue(KvDoc::ready($kv, 'meta', 16));
        $this->assertFalse(KvDoc::ready($kv, 'meta', 8));
        $this->assertSame('{"shards":16,"v":1}', $kv->get('meta'), 'a refused count leaves the pin untouched');
    }

    public function testReadyRefusesAMetaDocumentThatIsNotAnObjectWithANumericShardCount(): void
    {
        foreach (['[1]' => 'not an object', '{"v":1}' => 'no shards', '{"shards":"16","v":1}' => 'shards is a string', '{"shards":null}' => 'shards is null'] as $meta => $why) {
            $kv = new MemoryAtomicKv();
            $kv->update('meta', static fn(?string $prev): string => $meta);
            $this->assertFalse(KvDoc::ready($kv, 'meta', 16), $why);
        }
    }
}
