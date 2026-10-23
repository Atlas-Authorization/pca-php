<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Round r9 mutation kills for src/IntentV2Map.php (the RFC 9162-shaped Merkle helpers). */
final class R9MapKillTest extends TestCase
{
    /** @return list<string> */
    private static function leaves(int $n): array
    {
        $o = [];
        for ($i = 0; $i < $n; $i++) {
            $o[] = hash('sha256', "leaf$i", true);
        }
        return $o;
    }

    /** RFC 9162 §2.1.3.1 audit path of leaf m in the tree over $hs (independent of the implementation). */
    private static function auditPath(int $m, array $hs): array
    {
        $n = count($hs);
        if ($n <= 1) {
            return [];
        }
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        if ($m < $k) {
            return [...self::auditPath($m, array_slice($hs, 0, $k)), IntentV2::mapTreeRoot(array_slice($hs, $k))];
        }
        return [...self::auditPath($m - $k, array_slice($hs, $k)), IntentV2::mapTreeRoot(array_slice($hs, 0, $k))];
    }

    public function testHelpersArePublicAndExact(): void
    {
        self::assertTrue((new \ReflectionMethod(IntentV2::class, 'mapNodeHash'))->isPublic());
        self::assertTrue((new \ReflectionMethod(IntentV2::class, 'mapTreeRoot'))->isPublic());
        self::assertSame(hash('sha256', IntentV2::MAP_TAG_NODE . 'ab', true), IntentV2::mapNodeHash('a', 'b'));
        $h = self::leaves(1);
        self::assertSame($h[0], IntentV2::mapTreeRoot($h));
    }

    public function testRootFromPathMatchesTheTreeForEveryIndexAndSize(): void
    {
        foreach ([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 16, 17, 31, 33] as $size) {
            $hs = self::leaves($size);
            $root = IntentV2::mapTreeRoot($hs);
            for ($i = 0; $i < $size; $i++) {
                $path = self::auditPath($i, $hs);
                self::assertSame($root, IntentV2::mapRootFromPath($i, $size, $hs[$i], $path), "size $size index $i");
                // a path one element short or one too long is refused
                if ($path !== []) {
                    self::assertNull(IntentV2::mapRootFromPath($i, $size, $hs[$i], array_slice($path, 0, -1)), "short: size $size index $i");
                }
                self::assertNull(IntentV2::mapRootFromPath($i, $size, $hs[$i], [...$path, $hs[0]]), "long: size $size index $i");
                // a wrong sibling changes the root
                if ($path !== []) {
                    $bad = $path;
                    $bad[0] = hash('sha256', 'x', true);
                    self::assertNotSame($root, IntentV2::mapRootFromPath($i, $size, $hs[$i], $bad));
                }
            }
            self::assertNull(IntentV2::mapRootFromPath($size, $size, $hs[0], []), "index = size $size");
            self::assertNull(IntentV2::mapRootFromPath(-1, $size, $hs[0], []));
        }
    }

    public function testThrowingContracts(): void
    {
        $salt = str_repeat("\x07", 32);
        try {
            IntentV2::mapLeafHash('nope', $salt, Json::parseLax('1'));
            self::fail('unknown kind');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('mapLeafHash: unknown leaf kind', $e->getMessage());
        }
        try {
            IntentV2::mapLeafHash('header', str_repeat("\x07", 31), Json::parseLax('1'));
            self::fail('salt length');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('mapLeafHash: the salt is 32 bytes', $e->getMessage());
        }
        try {
            IntentV2::mapTreeRoot([]);
            self::fail('empty tree');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('mapTree: empty', $e->getMessage());
        }
        foreach ([null, 'x', Json::parseLax('{}'), []] as $bad) {
            try {
                IntentV2::mapCommitOfLeaves($bad);
                self::fail('leaves must be a non-empty array');
            } catch (\InvalidArgumentException $e) {
                self::assertSame('leaves must be a non-empty array', $e->getMessage());
            }
        }
        $sx = rtrim(strtr(base64_encode($salt), '+/', '-_'), '=');
        foreach ([
            '[5]', '["x"]', '[{"kind":"header","salt":"' . $sx . '"}]', '[{"kind":1,"salt":"' . $sx . '","leaf":1}]',
            '[{"kind":"header","salt":"short","leaf":1}]', '[{"kind":"header","leaf":1}]',
        ] as $json) {
            try {
                IntentV2::mapCommitOfLeaves(Json::parseLax($json));
                self::fail("entry $json");
            } catch (\InvalidArgumentException $e) {
                self::assertSame('a leaf entry is {kind, salt, leaf}', $e->getMessage(), $json);
            }
        }
    }

    private static function header(string $dims): Obj
    {
        $h = Json::parseLax('{"verb":"v","first":1,"cells":1,"dims":' . $dims . '}');
        self::assertInstanceOf(Obj::class, $h);
        return $h;
    }

    private static function cat(string $values): string
    {
        return '[{"kind":"cat","path":"action.resource","values":' . $values . '}]';
    }

    public function testCellOfCategoricalLookup(): void
    {
        $other = '{"kind":"other","value":"⊥"}';
        // an exact match wins at once: a later prefix must not displace it
        $h = self::header(self::cat('[{"kind":"exact","value":"ab"},{"kind":"prefix","value":"a"},' . $other . ']'));
        self::assertSame(['cell' => [0], 'flat' => 0], IntentV2::mapCellOf($h, 'ab', new Obj()));
        self::assertSame(['cell' => [1], 'flat' => 1], IntentV2::mapCellOf($h, 'ax', new Obj()));
        self::assertSame(['cell' => [2], 'flat' => 2], IntentV2::mapCellOf($h, 'zz', new Obj()));
        // the longest prefix wins, wherever it is listed
        $h = self::header(self::cat('[{"kind":"prefix","value":"a"},{"kind":"prefix","value":"abc"},{"kind":"prefix","value":"ab"},' . $other . ']'));
        self::assertSame(['cell' => [1], 'flat' => 1], IntentV2::mapCellOf($h, 'abcd', new Obj()));
        // an empty prefix (outside the header shape) still matches anything, as the longest of length zero
        $h = self::header(self::cat('[{"kind":"prefix","value":""},' . $other . ']'));
        self::assertSame(['cell' => [0], 'flat' => 0], IntentV2::mapCellOf($h, 'zz', new Obj()));
        // two identical prefixes (outside the header shape): the first listed one wins
        $h = self::header(self::cat('[{"kind":"prefix","value":"a"},{"kind":"prefix","value":"a"},' . $other . ']'));
        self::assertSame(['cell' => [0], 'flat' => 0], IntentV2::mapCellOf($h, 'ab', new Obj()));
    }

    public function testCellOfNumericFirstMatchWins(): void
    {
        // overlapping cells (cuts out of order, outside the header shape): the first cell containing x is the answer
        $h = self::header('[{"kind":"num","path":"action.params.t","lo":0,"hi":100,"cuts":[10,5]}]');
        $p = Json::parseLax('{"t":5}');
        self::assertSame(['cell' => [0], 'flat' => 0], IntentV2::mapCellOf($h, 'r', $p));
    }

    public function testMapOpensIsFalseOnAMalformedEntry(): void
    {
        $m = new \ReflectionMethod(IntentV2::class, 'mapOpens');
        $e = Json::parseLax('{"index":0,"salt":"zz","leaf":1,"path":[]}');
        self::assertFalse($m->invoke(null, 'header', $e, 4, 'x'));
    }
}
