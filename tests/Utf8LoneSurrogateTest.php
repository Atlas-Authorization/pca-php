<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\KvDoc;
use Atlas\Pca\MpcNetCodec;
use Atlas\Pca\MpcNetOffline;
use PHPUnit\Framework\TestCase;

/**
 * PHP strings are bytes: the lenient JSON parser writes a lone surrogate escape as WTF-8 (ED A0 80), the reference TextEncoder writes
 * U+FFFD (EF BF BD). Every hash input built from a parsed string goes through Js::utf8.
 */
final class Utf8LoneSurrogateTest extends TestCase
{
    public function testUtf8WritesFffdForWtf8LoneSurrogatesOnly(): void
    {
        $this->assertSame("a\xEF\xBF\xBDb", Js::utf8("a\xED\xA0\x80b"));
        $this->assertSame("a\xEF\xBF\xBDb", Js::utf8("a\xED\xBF\xBFb"));
        $this->assertSame("a\xF0\x9F\x98\x80", Js::utf8("a\xF0\x9F\x98\x80"));
    }

    public function testSessionIdHashInputUsesFffdNotWtf8(): void
    {
        $seeds = [str_repeat("\x01", 32), str_repeat("\x02", 32)];
        $a = MpcNetOffline::gadgetFromSeeds("s\xED\xA0\x80", $seeds);
        $b = MpcNetOffline::gadgetFromSeeds("s\xEF\xBF\xBD", $seeds);
        $this->assertEquals(array_map('gmp_strval', $b), array_map('gmp_strval', $a));
    }

    public function testShardAndGadgetCommitUseFffd(): void
    {
        $this->assertSame(KvDoc::shardOf("x\xEF\xBF\xBD", 16), KvDoc::shardOf("x\xED\xA0\x80", 16));
        $this->assertSame(MpcNetCodec::gadgetCommit("s\xEF\xBF\xBD", 1, 'k'), MpcNetCodec::gadgetCommit("s\xED\xA0\x80", 1, 'k'));
    }
}
