<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * R6-05 totality (no exception escapes a public verdict entry point on hostile input, whatever its JSON type) and the
 * MAX_JSON_DEPTH (32, same counting as the TS reference: the outermost container is depth 1) boundary at limit-1,
 * limit, limit+1 and far beyond (must be a clean refusal, never a stack overflow).
 */
final class TotalityDepthTest extends TestCase
{
    /**
     * Depth of the trees built directly in PHP (not via the parser). The Zend engine frees nested arrays/objects
     * recursively and segfaults freeing a ~100000-deep tree (an engine limit, independent of this library: no parser here
     * can produce one, the strict profile stops at 32 and the lax loader at 512); 10000 still proves no recursion runs
     * past the cap. Text inputs are exercised at 100000.
     */
    private const BUILT = 10000;

    private static function arr(int $n): string
    {
        return str_repeat('[', $n) . str_repeat(']', $n);
    }

    private static function obj(int $n): string
    {
        return str_repeat('{"a":', $n) . '1' . str_repeat('}', $n);
    }

    /** A PHP value nested $n containers deep, built without the parser (callers can hand any tree to the API). */
    private static function deepValue(int $n, bool $objects = false): mixed
    {
        $v = $objects ? Obj::of(['a' => true]) : [];
        for ($i = 1; $i < $n; $i++) {
            $v = $objects ? Obj::of(['a' => $v]) : [$v];
        }
        return $v;
    }

    public function testStrictParseDepthBoundary(): void
    {
        foreach ([[31, true], [32, true], [33, false], [100000, false]] as [$n, $ok]) {
            foreach ([self::arr($n), self::obj($n)] as $text) {
                try {
                    Json::parseStrict($text);
                    $this->assertTrue($ok, "depth $n accepted");
                } catch (JsonError $e) {
                    $this->assertFalse($ok, "depth $n refused: " . $e->getMessage());
                    $this->assertStringStartsWith('nesting too deep', $e->getMessage());
                }
            }
        }
    }

    public function testLaxParseIsBoundedToo(): void
    {
        $this->assertIsArray(Json::parseLax(self::arr(512)));
        foreach ([self::arr(513), self::arr(100000), self::obj(100000)] as $text) {
            try {
                Json::parseLax($text);
                $this->fail('a 100000-deep document must be refused by the lax loader as well');
            } catch (JsonError $e) {
                $this->assertStringStartsWith('nesting too deep', $e->getMessage());
            }
        }
    }

    public function testCanonicalizeDepthBoundaryOnBuiltTrees(): void
    {
        foreach ([false, true] as $objects) {
            $this->assertIsString(Json::canonicalizeStrict(self::deepValue(31, $objects)));
            $this->assertIsString(Json::canonicalizeStrict(self::deepValue(32, $objects)));
            foreach ([33, self::BUILT] as $n) {
                try {
                    Json::canonicalizeStrict(self::deepValue($n, $objects));
                    $this->fail("depth $n canonicalized");
                } catch (JsonError $e) {
                    $this->assertSame('nesting too deep', $e->getMessage());
                }
            }
        }
    }

    public function testVerifyJsonDeepTextIsACleanWireDeny(): void
    {
        foreach ([33, 100000] as $n) {
            $v = Pca::verifyJson('{"ver":2,"x":' . self::arr($n) . '}', null, 0, 'rs');
            $this->assertFalse($v['allow']);
            $this->assertSame(['wire' => false], $v['checks']);
            $this->assertStringContainsString('nesting too deep', $v['reason']);
        }
    }

    public function testDeepTreesAtEveryEntryPointAreCleanDenies(): void
    {
        foreach ([33, self::BUILT] as $n) {
            $deep = self::deepValue($n, true);
            $this->assertFalse(Pca::verifyPcactnCore(Obj::of(['ver' => $deep]), null, 0, 'rs')['allow']);
            $this->assertIsString(Pca::validateWire(Obj::of(['action' => $deep])));
            [$why, $ok] = Pca::verifyChain([Obj::of(['caveats' => [Obj::of(['type' => 'x', 'v' => $deep])]])], 'x', true);
            $this->assertFalse($ok);
            $this->assertFalse(Pca::verifyThresholdShare(Obj::of(['role' => 'agent', 't' => $deep, 'signer_set' => $deep, 'share' => $deep])));
            $this->assertNull(Pca::signerSetHashRaw([$deep]));
            $this->assertNull(Pca::signerSetHashRaw($deep));
            $this->assertFalse(Pca::verifyArtifact($deep, 'm'));
            $this->assertFalse(Pca::verifyInclusion('r', $deep, $deep));
        }
    }

    /** R6-05: the chain verifier is total over ANY JSON value, not only PHP arrays (a JSON object / scalar chain is a deny). */
    public function testVerifyChainAcceptsAnyJsonValueAndDenies(): void
    {
        foreach ([null, 5, 'x', true, Obj::of(['0' => 'x']), Json::parseLax('{"a":[1]}')] as $chain) {
            [$why, $ok] = Pca::verifyChain($chain, 'x', true);
            $this->assertFalse($ok);
            $this->assertIsString($why);
        }
        $this->assertFalse(Pca::caveatLimitExceeded(Obj::of(['caveats' => []])));
        $this->assertFalse(Pca::caveatLimitExceeded(null));
    }

    /** signerSetHashRaw is documented fail-closed (null): a role / key the strict profile refuses is null, not a JsonError. */
    public function testSignerSetHashRawIsTotal(): void
    {
        $this->assertNull(Pca::signerSetHashRaw(Json::parseLax('[{"role":"\ud800","publicKey":"x"}]')));
        $this->assertNull(Pca::signerSetHashRaw(Json::parseLax('[{"role":"agent","publicKey":"\udc00"}]')));
        $this->assertNull(Pca::signerSetHashRaw(Json::parseLax('[{"role":"agent","publicKey":"x","pq_pk":"\ud800"}]')));
        $this->assertIsString(Pca::signerSetHashRaw(Json::parseLax('[{"role":"agent","publicKey":"x"}]')));
    }
}
