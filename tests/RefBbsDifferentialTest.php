<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bbs;
use Atlas\Pca\BbsCredential;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * BBS signatures (BLS12-381-SHA-256) and the capability-credential layer against the TS reference: test-data/ref-bbs.json.gz. Needs a built libblst (PCA_BLST_LIB; the
 * pairing CI workflow builds it). The corpus carries secret keys as labels ({"$bbssk": n}); the key is derived here: KeyGen over 32 bytes of n with empty key info.
 * A keyGen result equal to such a key is compared as its label, so the corpus never holds a secret scalar. The proof-generation blinding scalars are the reference's fixed test-hook values (not keys).
 */
final class RefBbsDifferentialTest extends TestCase
{
    private const FILE = 'ref-bbs.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    protected function setUp(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst)');
        }
    }

    private static function int(mixed $v): int
    {
        return $v instanceof Num ? $v->int() : (int) $v;
    }

    /** {"$bytes"} to raw bytes, {"$bbssk"} to the derived secret scalar (\GMP), lists recursively. */
    private static function dec(mixed $v): mixed
    {
        if ($v instanceof Obj && $v->keys() === ['$bytes']) {
            return Pca::unb64u($v->get('$bytes'));
        }
        if ($v instanceof Obj && $v->keys() === ['$bbssk']) {
            return Bbs::keyGen(str_repeat(chr(self::int($v->get('$bbssk'))), 32), '');
        }
        return is_array($v) ? array_map(self::dec(...), $v) : $v;
    }

    /** The corpus holds no signing key: a key equal to KeyGen(32 bytes of n), n = 1..3, is written {"$bbssk": n}; any other value is its hex. */
    private static function keyLabel(string $hex): mixed
    {
        foreach ([1, 2, 3] as $n) {
            if ($hex === self::hex(Bbs::keyGen(str_repeat(chr($n), 32), ''))) {
                return Obj::of(['$bbssk' => $n]);
            }
        }
        return $hex;
    }

    private static function hex(\GMP $n): string
    {
        return str_pad(gmp_strval($n, 16), 64, '0', STR_PAD_LEFT);
    }

    /** @return list<int> */
    private static function ints(array $v): array
    {
        return array_map(self::int(...), $v);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'hashToScalar' => static fn(array $a) => self::hex(Bbs::hashToScalar(self::dec($a[0]), $a[1])),
            'mapMessageToScalarAsHash' => static fn(array $a) => self::hex(Bbs::mapMessageToScalarAsHash(self::dec($a[0]))),
            'createGenerators' => static fn(array $a) => array_map(static fn(string $g) => Base::outBytes($g), Bbs::createGenerators(self::int($a[0]))),
            'keyGen' => static fn(array $a) => self::keyLabel(self::hex(Bbs::keyGen(self::dec($a[0]), self::dec($a[1])))),
            'skToPk' => static fn(array $a) => Base::outBytes(Bbs::skToPk(self::dec($a[0]))),
            'sign' => static fn(array $a) => Base::outBytes(Bbs::sign(self::dec($a[0]), self::dec($a[1]), self::dec($a[2]), self::dec($a[3]))),
            'verifyDetailed' => static fn(array $a) => Bbs::verifyDetailed(self::dec($a[0]), self::dec($a[1]), self::dec($a[2]), self::dec($a[3])),
            'proofGen' => static fn(array $a) => Base::outBytes(Bbs::proofGen(
                self::dec($a[0]),
                self::dec($a[1]),
                self::dec($a[2]),
                self::dec($a[3]),
                self::dec($a[4]),
                self::ints($a[5]),
                array_map(static fn(string $h) => gmp_init($h, 16), $a[6]),
            )),
            'capabilityAttributes' => static fn(array $a) => BbsCredential::capabilityAttributes($a[0]),
            'issueCapabilityCredential' => static fn(array $a) => BbsCredential::issueCapabilityCredential($a[0], self::dec($a[1]), self::dec($a[2]), self::dec($a[3])),
            'verifyCredential' => static fn(array $a) => BbsCredential::verifyCredential($a[0]),
            'verifyPresentation' => static fn(array $a) => BbsCredential::verifyPresentation(
                $a[0],
                $a[1]->has('pk') ? self::dec($a[1]->get('pk')) : null,
                $a[1]->has('disclosed') ? $a[1]->get('disclosed') : null,
                $a[1]->has('presentationHeader') ? self::dec($a[1]->get('presentationHeader')) : null,
            ),
            'proofVerifyDetailed' => static fn(array $a) => Bbs::proofVerifyDetailed(self::dec($a[0]), self::dec($a[1]), self::dec($a[2]), self::dec($a[3]), self::dec($a[4]), self::ints($a[5])),
        ]);
    }
}
