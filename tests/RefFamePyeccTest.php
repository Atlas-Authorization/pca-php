<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AbePolicy;
use Atlas\Pca\Bls12;
use Atlas\Pca\Fame;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * FAME group elements against an independent implementation (py_ecc): setup, keygen and encrypt with fixed scalars, byte for byte.
 * The fixture's scalars are throwaway known-answer inputs generated for this comparison, not keys of any deployment.
 */
final class RefFamePyeccTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst built with the GT shim)');
        }
    }

    /** @return list<\GMP> */
    private static function scalars(mixed $l): array
    {
        return array_map(static fn(string $h): \GMP => gmp_init($h, 16), $l);
    }

    /** @param list<\FFI\CData> $p @return list<string> */
    private static function hex(int $g, array $p): array
    {
        return array_map(static fn(\FFI\CData $x): string => bin2hex(Bls12::compress($g, $x)), $p);
    }

    public function testMatchesPyEcc(): void
    {
        $doc = Json::parseLax((string) file_get_contents(__DIR__ . '/../test-data/fame-pyecc/fame-pyecc.json'));
        foreach ($doc->get('cases') as $c) {
            $name = $c->get('name');
            $n = AbePolicy::normalize($c->get('policy'));
            $this->assertNotNull($n['tree'], $name);
            $attrs = $c->get('attrs');
            $s = $c->get('scalars');
            [$mpk, $msk] = Fame::setup(self::scalars($s->get('a')), self::scalars($s->get('b')), self::scalars($s->get('d')));
            $key = Fame::keygen($msk, $attrs, self::scalars($s->get('r')), self::scalars($s->get('sigma')), gmp_init($s->get('sigmaPrime'), 16));
            [$ct, $k] = Fame::encrypt($mpk, $n['tree'], self::scalars($s->get('s')));
            $this->assertSame($c->get('h'), self::hex(2, $mpk['h']), "$name h");
            $this->assertSame($c->get('mskg'), self::hex(1, $msk['g']), "$name mskg");
            $this->assertSame($c->get('k0'), self::hex(2, $key['k0']), "$name k0");
            $this->assertSame($c->get('kp'), self::hex(1, $key['kp']), "$name kp");
            $want = $c->get('key');
            $this->assertInstanceOf(Obj::class, $want);
            foreach ($want->keys() as $attr) {
                $this->assertSame($want->get($attr), self::hex(1, $key['attrs'][$attr]), "$name key $attr");
            }
            $this->assertSame($c->get('ct0'), self::hex(2, $ct['ct0']), "$name ct0");
            $this->assertSame($c->get('rows'), array_map(static fn(array $r): array => self::hex(1, $r), $ct['rows']), "$name rows");
            // the reference decrypted these with the attribute set it was issued; so must the native
            $set = array_flip($attrs);
            if (AbePolicy::satisfies($n['tree'], static fn(string $a): bool => isset($set[$a]))) {
                $this->assertSame($k, Fame::decrypt($key, $n['tree'], $ct), "$name decrypt");
            }
        }
    }
}
