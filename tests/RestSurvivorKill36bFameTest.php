<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bls12;
use Atlas\Pca\Fame;
use PHPUnit\Framework\TestCase;

/** Fame: the keygen sigma check, the public span-program and Lagrange helpers, and fail-closed decryption on degenerate (t = 0) gates. */
final class RestSurvivorKill36bFameTest extends TestCase
{
    private function needBlst(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst built with the GT shim)');
        }
    }

    /** @return list<\GMP> */
    private static function g(int ...$v): array
    {
        return array_map(static fn(int $x): \GMP => gmp_init($x), $v);
    }

    private static function leaf(string $a): array
    {
        return ['leaf' => true, 'attr' => $a];
    }

    private static function gate(int $t, array $of): array
    {
        return ['leaf' => false, 't' => $t, 'of' => $of];
    }

    /** keygen refuses fewer sigmas than attributes before any group work. */
    public function testKeygenNeedsOneSigmaPerAttribute(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('fame keygen: one sigma per attribute is required');
        Fame::keygen([], ['a', 'b'], self::g(1, 2), self::g(3), gmp_init(4));
    }

    /** buildRows is public: a single leaf is one row with the secret column 1. */
    public function testBuildRowsIsPublic(): void
    {
        $rows = Fame::buildRows(self::leaf('a'));
        self::assertCount(1, $rows);
        self::assertSame('a', $rows[0]['attr']);
        self::assertSame(['0' => '1'], array_map('gmp_strval', $rows[0]['vec']));
    }

    /** lagrangeAtZero is public; it refuses a zero point and coinciding points, and interpolates distinct ones. */
    public function testLagrangeAtZero(): void
    {
        self::assertNull(Fame::lagrangeAtZero(self::g(0)));
        self::assertNull(Fame::lagrangeAtZero(self::g(1, 1)));
        self::assertNull(Fame::lagrangeAtZero([]));
        $l = Fame::lagrangeAtZero(self::g(1, 2));
        self::assertSame(['2', gmp_strval(Bls12::sub(gmp_init(0), gmp_init(1)))], array_map('gmp_strval', $l));
    }

    /** keygen pairs sigmas with attributes by position, whatever the keys of the attribute list. */
    public function testKeygenAttributeKeysIgnored(): void
    {
        $this->needBlst();
        [, $msk] = Fame::setup(self::g(2, 3), self::g(5, 7), self::g(11, 13, 17));
        $k1 = Fame::keygen($msk, [1 => 'a'], self::g(19, 23), self::g(29), gmp_init(31));
        $k2 = Fame::keygen($msk, ['a'], self::g(19, 23), self::g(29), gmp_init(31));
        self::assertSame(['a'], array_keys($k1['attrs']));
        $c = static fn(array $tri): array => array_map(static fn(\FFI\CData $p): string => Bls12::compress(1, $p), $tri);
        self::assertSame($c($k2['attrs']['a']), $c($k1['attrs']['a']));
    }

    /** A degenerate t = 0 gate never yields a key: decryption fails closed, wherever the gate sits; a sound tree still decrypts. */
    public function testDegenerateGatesFailClosed(): void
    {
        $this->needBlst();
        [$mpk, $msk] = Fame::setup(self::g(2, 3), self::g(5, 7), self::g(11, 13, 17));
        $key = Fame::keygen($msk, ['a'], self::g(19, 23), self::g(29), gmp_init(31));
        $s = self::g(37, 41);
        $ok = self::gate(1, [self::leaf('a')]);
        [$ct, $k] = Fame::encrypt($mpk, $ok, $s);
        self::assertSame($k, Fame::decrypt($key, $ok, $ct));
        foreach ([
            'after a leaf' => self::gate(2, [self::leaf('a'), self::gate(0, [self::leaf('b')])]),
            'unsatisfied first' => self::gate(0, [self::leaf('b'), self::leaf('a')]),
        ] as $name => $tree) {
            [$ct] = Fame::encrypt($mpk, $tree, $s);
            self::assertNull(Fame::decrypt($key, $tree, $ct), $name);
        }
    }
}
