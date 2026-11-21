<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Aggsig;
use Atlas\Pca\KeyRegistry;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * BLS12-381 aggregation (PoP ciphersuite, key registry, aggregated capability chain, witness cosignatures) against the TS reference:
 * test-data/ref-aggsig.json.gz. Needs a built libblst (PCA_BLST_LIB; the pairing CI workflow builds it). The corpus carries secret-key
 * labels ({"$blssk": label}); the key is derived here as the generator does: (sha256(sha256("atlas-pca-conformance/" + label)) mod (r - 1)) + 1.
 */
final class RefAggsigDifferentialTest extends TestCase
{
    private const FILE = 'ref-aggsig.json.gz';

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

    private static function sk(string $label): string
    {
        $n = gmp_add(gmp_mod(gmp_init(bin2hex(hash('sha256', hash('sha256', 'atlas-pca-conformance/' . $label, true), true)), 16), gmp_sub(gmp_init(Aggsig::R_HEX, 16), 1)), 1);
        return hex2bin(str_pad(gmp_strval($n, 16), 64, '0', STR_PAD_LEFT));
    }

    /** {"$bytes"} and {"$blssk"} to raw bytes, recursively. */
    private static function dec(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return Pca::unb64u($v->get('$bytes'));
            }
            if ($v->keys() === ['$blssk']) {
                return self::sk($v->get('$blssk'));
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::dec($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::dec(...), $v) : $v;
    }

    /** Register every {pk, pop} pair; null when any fails (the reference result is then {"registerFailed": true}). */
    private static function regAll(array $keys): ?array
    {
        $out = [];
        foreach ($keys as $k) {
            $r = Aggsig::registerKey($k->get('pk'), $k->get('pop'));
            if (!$r['ok']) {
                return null;
            }
            $out[] = $r['key'];
        }
        return $out;
    }

    private static function registry(array $keys): KeyRegistry
    {
        $reg = new KeyRegistry();
        foreach ($keys as $k) {
            if (!$reg->register($k->get('pk'), $k->get('pop'))['ok']) {
                break; // the reference harness stops at the first failure
            }
        }
        return $reg;
    }

    private static function withKeys(array $keys, \Closure $f): mixed
    {
        $ks = self::regAll($keys);
        return $ks === null ? Obj::of(['registerFailed' => true]) : $f($ks);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $bytes = static fn(string $b): Obj => Base::outBytes($b);
        $d = static fn(array $a): array => self::dec($a);
        Base::run($file, $fn, $k, [
            'publicKeyOf' => static fn(array $a) => $bytes(Aggsig::publicKeyOf(self::dec($a[0]))),
            'sign' => static fn(array $a) => $bytes(Aggsig::sign(self::dec($a[0]), self::dec($a[1]))),
            'popProve' => static fn(array $a) => $bytes(Aggsig::popProve(self::dec($a[0]))),
            'verify' => static fn(array $a) => Aggsig::verify(...$d($a)),
            'keyValidate' => static fn(array $a) => Aggsig::keyValidate(self::dec($a[0])),
            'registerKey' => static function (array $a) use ($d) {
                $r = Aggsig::registerKey(...$d($a));
                return $r['ok'] ? Obj::of(['ok' => true]) : Obj::of(['ok' => false, 'reason' => $r['reason']]);
            },
            'aggregate' => static fn(array $a) => $bytes(Aggsig::aggregate(self::dec($a[0]))),
            'aggregateVerify' => static fn(array $a) => self::withKeys(self::dec($a[0]), static fn(array $ks) => Aggsig::aggregateVerify($ks, self::dec($a[1]), self::dec($a[2]))),
            'fastAggregateVerify' => static fn(array $a) => self::withKeys(self::dec($a[0]), static fn(array $ks) => Aggsig::fastAggregateVerify($ks, self::dec($a[1]), self::dec($a[2]))),
            'mintBlsRoot' => static fn(array $a) => Aggsig::mintBlsRoot(...$d($a)),
            'chainDelegate' => static fn(array $a) => Aggsig::blsDelegate(...$d($a)),
            'chainAttenuate' => static fn(array $a) => Aggsig::blsAttenuate(...$d($a)),
            'capHash' => static fn(array $a) => Aggsig::capHash($a[0]),
            'aggregateChainSignatures' => static fn(array $a) => $bytes(Aggsig::aggregateChainSignatures($a[0])),
            'verifyAggregatedChain' => static function (array $a) {
                $reg = self::registry(self::dec($a[2]));
                $r = Aggsig::verifyAggregatedChain($a[0], self::dec($a[1]), $reg, $a[3] ?? null);
                return Obj::of($r);
            },
            'cosignTreeHead' => static fn(array $a) => Aggsig::cosignTreeHead($a[0], self::dec($a[1])),
            'verifyWitnessCosignature' => static fn(array $a) => Aggsig::verifyWitnessCosignature($a[0], $a[1]),
            'aggregateWitnessCosignatures' => static fn(array $a) => $bytes(Aggsig::aggregateWitnessCosignatures($a[0])),
            'verifyAggregatedWitnessCosignatures' => static fn(array $a) => self::withKeys(self::dec($a[1]), static fn(array $ks) => Aggsig::verifyAggregatedWitnessCosignatures($a[0], $ks, self::dec($a[2]))),
        ]);
    }
}
