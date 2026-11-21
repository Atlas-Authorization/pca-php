<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PcaGrant.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\PcaGrant;
use PHPUnit\Framework\TestCase;

/** Mutation kills for PcaGrant (https URL predicate, chain digest, presentation check). */
final class K05KillPcaGrantTest extends TestCase
{
    public function testIsHttpsUrl(): void
    {
        $this->assertTrue(PcaGrant::isHttpsUrl('https://a.b/' . str_repeat('a', 2048 - 12)));
        $this->assertFalse(PcaGrant::isHttpsUrl('https://a.b/' . str_repeat('a', 2049 - 12)));
        $this->assertTrue(PcaGrant::isHttpsUrl('https://a.b/~!'));
        $this->assertTrue(PcaGrant::isHttpsUrl('https://a'));
        $this->assertFalse(PcaGrant::isHttpsUrl('https://@a.b/'));
    }

    public function testChainDigestReindexes(): void
    {
        $this->assertSame(PcaGrant::chainDigest(['a', 'b']), PcaGrant::chainDigest([5 => 'a', 7 => 'b']));
    }

    public function testCheckScansEveryDetail(): void
    {
        $ids = ['i1', 'i2'];
        $d = static fn(array $chain, array $over = []): Obj => Obj::of(array_merge(['type' => PcaGrant::TYPE,
            'chain_digest' => PcaGrant::chainDigest($chain), 'chain_len' => new Num((string)count($chain))], $over));
        $good = $d($ids);
        // a detail at the wrong location, then a matching one: the later one is taken
        $this->assertSame([1, null], PcaGrant::check([$d(['i1'], ['locations' => ['https://other']]), $good], 'https://r', $ids, true));
        // a detail for another chain, then a matching one
        $this->assertSame([1, null], PcaGrant::check([$d(['i1'], ['chain_digest' => 'zz']), $good], 'https://r', $ids, true));
        $this->assertSame([null, 'wrong_location'], PcaGrant::check([$d(['i1'], ['locations' => ['https://other']])], 'https://r', $ids, true));
    }
}
