<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Vdf;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The Wesolowski VDF and the PCA timelock against the TS reference: test-data/ref-vdf.json.gz (big integers cross as decimal strings). */
final class RefVdfDifferentialTest extends TestCase
{
    private const FILE = 'ref-vdf.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function b(mixed $s): \GMP
    {
        if (!is_string($s)) {
            throw new \TypeError('bigint arg');
        }
        return gmp_init($s, 10);
    }

    /** A JSON number in a proof is not a bigint: a float, as in the reference. */
    private static function big(mixed $v): mixed
    {
        return is_string($v) ? gmp_init($v, 10) : ($v instanceof Num ? $v->float() : $v);
    }

    private static function pf(array $p): Obj
    {
        return Obj::of(['y' => gmp_strval($p['y']), 'pi' => gmp_strval($p['pi'])]);
    }

    private static function proofIn(mixed $p): mixed
    {
        if (!($p instanceof Obj)) {
            return $p;
        }
        $o = new Obj();
        foreach ($p->keys() as $k) {
            $o->set($k, ($k === 'y' || $k === 'pi') ? self::big($p->get($k)) : $p->get($k));
        }
        return $o;
    }

    private static function num(int $i): Num
    {
        return new Num((string)$i);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'isProbablePrime' => fn(array $a) => Vdf::isProbablePrime(self::b($a[0])),
            'isMillerRabinProbablePrime' => fn(array $a) => Vdf::isMillerRabinProbablePrime(self::b($a[0])),
            'isStrongLucasProbablePrime' => fn(array $a) => Vdf::isStrongLucasProbablePrime(self::b($a[0])),
            'modpow' => fn(array $a) => gmp_strval(Vdf::modpow(self::b($a[0]), self::b($a[1]), self::b($a[2]))),
            'gcd' => fn(array $a) => gmp_strval(Vdf::gcd(self::b($a[0]), self::b($a[1]))),
            'canonicalVdfOutput' => fn(array $a) => gmp_strval(Vdf::canonicalVdfOutput(self::b($a[0]), self::b($a[1]))),
            'bigIntToBytes' => fn(array $a) => Base::outBytes(Vdf::bigIntToBytes(self::b($a[0]))),
            'bytesRoundTrip' => fn(array $a) => Base::outBytes(Vdf::bigIntToBytes(Vdf::bytesToBigInt(\Atlas\Pca\Pca::unb64u($a[0])))),
            'hashToPrime' => fn(array $a) => gmp_strval(Vdf::hashToPrime(self::b($a[0]), self::b($a[1]), $a[2], self::b($a[3]), ...array_slice($a, 4, 1))),
            'sequentialSquare' => fn(array $a) => gmp_strval(Vdf::sequentialSquare(self::b($a[0]), $a[1], self::b($a[2]))),
            'vdfEval' => fn(array $a) => self::pf(Vdf::vdfEval(self::b($a[0]), $a[1], self::b($a[2]))),
            'vdfEvalCanonical' => fn(array $a) => self::pf(Vdf::vdfEvalCanonical(self::b($a[0]), $a[1], self::b($a[2]))),
            'vdfVerifyDetailed' => static fn(array $a) => Obj::of(Vdf::vdfVerifyDetailed(self::b($a[0]), self::b($a[1]), self::b($a[2]), $a[3], self::b($a[4]))),
            'vdfVerifyCanonicalDetailed' => static fn(array $a) => Obj::of(Vdf::vdfVerifyCanonicalDetailed(self::b($a[0]), self::b($a[1]), self::b($a[2]), $a[3], self::b($a[4]))),
            'checkProductionModulus' => fn(array $a) => Obj::of(Vdf::checkProductionModulus(self::b($a[0]))),
            'deriveTimelockInput' => fn(array $a) => gmp_strval(Vdf::deriveTimelockInput($a[0], self::b($a[1]), $a[2])),
            'requireTimelock' => function (array $a): Obj {
                $o = $a[1];
                $q = Vdf::requireTimelock($a[0], $o->get('steps'), self::b($o->get('N')), $o->get('beacon'), $o->get('allowInsecureDevModulus'));
                return Obj::of(['kind' => $q['kind'], 'x' => gmp_strval($q['x']), 'steps' => self::num($q['steps']), 'N' => gmp_strval($q['N']), 'actionDigest' => $q['actionDigest']]);
            },
            'proveTimelockElapsed' => function (array $a): Obj {
                $o = $a[3];
                $p = Vdf::proveTimelockElapsed($a[0], $a[1], self::b($a[2]), $o->get('beacon'), $o->get('allowInsecureDevModulus'));
                return Obj::of(['kind' => $p['kind'], 'y' => gmp_strval($p['y']), 'pi' => gmp_strval($p['pi']), 'steps' => self::num($p['steps'])]);
            },
            'verifyTimelock' => function (array $a): bool {
                $o = $a[2];
                return Vdf::verifyTimelock($a[0], self::proofIn($a[1]), $o->get('steps'), self::b($o->get('N')), $o->get('beacon'), $o->get('allowInsecureDevModulus'));
            },
        ]);
    }

    public function testDevModulusIsRefusedByTheProductionScreen(): void
    {
        $this->assertFalse(Vdf::checkProductionModulus(Vdf::insecureDevSetup(64)['N'])['ok']);
    }
}
