<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Abe;
use Atlas\Pca\AbePolicy;
use Atlas\Pca\Bls12;
use Atlas\Pca\Fame;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * FAME ciphertext-policy ABE against the TS reference: test-data/ref-abe.json.gz. Needs a built libblst with the GT shim
 * (PCA_BLST_LIB; the pairing CI workflow builds it). The corpus carries no key bytes: master and user keys are recipes
 * ({"$abeMsk": label}, {"$abeKey": {msk, attrs, id}}, optionally edited by "$patch" / "$edits" or merged by "$pool"). Every scalar is
 * sha512("abe-oracle/" + label + name) mod r (1 for 0), so the keys are re-derived here exactly as the reference derives them.
 */
final class RefAbeDifferentialTest extends TestCase
{
    private const FILE = 'ref-abe.json.gz';

    public static function provide(): array
    {
        return Base::datasetsWithGen(self::FILE);
    }

    protected function setUp(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst built with the GT shim)');
        }
    }

    // ---- seeded keys ----

    private static function sc(string $label): \GMP
    {
        $v = Bls12::mod(Bls12::os2ip(hash('sha512', 'abe-oracle/' . $label, true)));
        return gmp_sign($v) === 0 ? gmp_init(1) : $v;
    }

    private static function seedMsk(string $label): Obj
    {
        $s = static fn(string $n): \GMP => self::sc($label . '/' . $n);
        return Abe::setup([$s('a1'), $s('a2'), $s('b1'), $s('b2'), $s('d1'), $s('d2'), $s('d3')])[1];
    }

    private static function seedKey(Obj $spec): Obj
    {
        $id = (string) $spec->get('id');
        $names = [];
        foreach (self::strs($spec->get('attrs')) as $a) {
            if (!in_array($a, $names, true) && $a !== '' && !AbePolicy::illFormed($a)) {
                $names[] = $a;
            }
        }
        $sigmas = [];
        foreach ($names as $i => $_) {
            $sigmas[] = self::sc($id . '/sg' . $i);
        }
        return Abe::issue(self::seedMsk((string) $spec->get('msk')), $spec->get('attrs'), [
            'r' => [self::sc($id . '/r1'), self::sc($id . '/r2')], 'sigmas' => $sigmas, 'sigmaPrime' => self::sc($id . '/sgp'),
        ])[0];
    }

    private static function at(mixed $v, array $path): mixed
    {
        foreach ($path as $p) {
            $v = $v instanceof Obj ? $v->get((string) $p) : (is_array($v) ? ($v[self::idx($p)] ?? null) : null);
        }
        return $v;
    }

    private static function idx(mixed $p): int
    {
        return $p instanceof Num ? $p->int() : (int) $p;
    }

    private static function setAt(mixed $v, array $path, mixed $val, bool $del): mixed
    {
        if ($path === []) {
            return $val;
        }
        $rest = array_slice($path, 1);
        if ($v instanceof Obj) {
            $k = (string) $path[0];
            if ($rest === [] && $del) {
                return $v->without($k);
            }
            $o = new Obj();
            foreach ($v->keys() as $key) {
                $o->set($key, $v->get($key));
            }
            $o->set($k, self::setAt($v->get($k), $rest, $val, $del));
            return $o;
        }
        if (is_array($v)) {
            $i = self::idx($path[0]);
            $v[$i] = self::setAt($v[$i] ?? null, $rest, $val, $del);
            return $v;
        }
        throw new \LogicException('setAt: path through a scalar');
    }

    /** every key recipe inside v replaced by the derived key */
    private static function resolve(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::resolve(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if (is_string($v->get('$abeMsk'))) {
            return self::seedMsk($v->get('$abeMsk'));
        }
        if ($v->get('$abeKey') instanceof Obj) {
            return self::seedKey($v->get('$abeKey'));
        }
        if (is_array($v->get('$pool'))) {
            $pool = $v->get('$pool');
            $base = self::resolve($pool[0]);
            $attrs = $base->get('attrs');
            foreach (array_slice($pool, 1) as $o) {
                $extra = self::resolve($o)->get('attrs');
                foreach ($extra->keys() as $n) {
                    $attrs->set($n, $extra->get($n));
                }
            }
            return $base;
        }
        if ($v->has('$patch')) {
            $base = self::resolve($v->get('$patch'));
            $edits = $v->get('$edits');
            $vals = [];
            foreach ($edits as $e) { // a $ref reads the base as it was before any edit
                $val = $e->get('value');
                $vals[] = $val instanceof Obj && is_array($val->get('$ref')) ? self::at($base, $val->get('$ref')) : $val;
            }
            foreach ($edits as $i => $e) {
                $base = self::setAt($base, $e->get('path'), $vals[$i], $vals[$i] instanceof Obj && $vals[$i]->has('$undefined'));
            }
            return $base;
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::resolve($v->get($k)));
        }
        return $o;
    }

    /** @return list<string> */
    private static function strs(mixed $v): array
    {
        return array_values(array_filter(is_array($v) ? $v : [], 'is_string'));
    }

    private static function opts(mixed $v): ?Obj
    {
        return $v instanceof Obj ? $v : null;
    }

    private static function bytes(string $raw): Obj
    {
        return Base::outBytes($raw);
    }

    /** @param list<\FFI\CData> $pts @return list<Obj> */
    private static function pts(int $g, array $pts): array
    {
        return array_map(static fn(\FFI\CData $p): Obj => self::bytes(Bls12::compress($g, $p)), $pts);
    }

    /** setup, keygen, encrypt and decrypt with the scalars derived from a seed label; every group element and the KEM key. */
    private static function fame(mixed $policy, array $attrs, string $label): mixed
    {
        $r = AbePolicy::normalize($policy);
        if ($r['tree'] === null) {
            throw new \InvalidArgumentException($r['reason']);
        }
        $tree = $r['tree'];
        $s = static fn(string $n): \GMP => self::sc($label . $n);
        [$mpk, $msk] = Fame::setup([$s('a1'), $s('a2')], [$s('b1'), $s('b2')], [$s('d1'), $s('d2'), $s('d3')]);
        $sigmas = [];
        foreach ($attrs as $i => $_) {
            $sigmas[] = $s('sg' . $i);
        }
        $key = Fame::keygen($msk, $attrs, [$s('r1'), $s('r2')], $sigmas, $s('sgp'));
        [$ct, $k] = Fame::encrypt($mpk, $tree, [$s('s1'), $s('s2')]);
        $dec = Fame::decrypt($key, $tree, $ct);
        $ka = new Obj();
        foreach ($key['attrs'] as $n => $c) {
            $ka->set((string) $n, self::pts(1, $c));
        }
        return Obj::of([
            'h' => self::pts(2, $mpk['h']), 't' => array_map(self::bytes(...), $mpk['t']), 'mskg' => self::pts(1, $msk['g']),
            'k0' => self::pts(2, $key['k0']), 'kp' => self::pts(1, $key['kp']), 'key' => $ka,
            'ct0' => self::pts(2, $ct['ct0']), 'rows' => array_map(static fn(array $r): array => self::pts(1, $r), $ct['rows']),
            'k' => self::bytes($k), 'dec' => $dec === null ? null : self::bytes($dec),
        ]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        if ($fn === '') {
            Base::missingGen($file);
        }
        $bytes = static fn(string $b): Obj => self::bytes($b);
        $res = static fn(array $a): array => self::resolve($a);
        // every entry point sees its arguments with the key recipes already derived
        $map = [
            'fame' => static fn(array $a) => self::fame($a[0], self::strs($a[1]), (string) $a[2]->get('$seed')),
            'gtIsElement' => static fn(array $a) => Bls12::gtIsElement(Base::bytes($a[0])),
            'gtPow' => static fn(array $a) => $bytes(Bls12::gtPow(Base::bytes($a[0]), gmp_init($a[1], 16))),
            'gtMul' => static fn(array $a) => $bytes(Bls12::gtMul(Base::bytes($a[0]), Base::bytes($a[1]))),
            'pairingProduct' => static fn(array $a) => $bytes(Bls12::gtPairingProduct(
                array_map(static fn($b) => Bls12::decode(1, Base::bytes($b)), $a[0]),
                array_map(static fn($b) => Bls12::decode(2, Base::bytes($b)), $a[1]),
            )),
            'normalizePolicy' => static fn(array $a) => AbePolicy::normalizeJson($a[0]),
            'satisfies' => static fn(array $a) => AbePolicy::treeSatisfies($a[0], self::strs($a[1])),
            'policyAttributes' => static fn(array $a) => AbePolicy::policyAttributes($a[0]),
            'parseCiphertext' => static fn(array $a) => Abe::parseCiphertext($a[0]),
            'decrypt' => static function (array $a) use ($bytes) {
                $pt = Abe::decrypt(...$a);
                return $pt === null ? null : $bytes($pt);
            },
            'decryptText' => static fn(array $a) => Abe::decryptText(...$a),
            'decryptWithCapability' => static fn(array $a) => Abe::decryptWithCapability(...$a),
            'encryptAccepts' => static function (array $a) {
                Abe::encryptForPolicy($a[0], $a[1], 'x');
                return true;
            },
            'keygenForAttributes' => static fn(array $a) => Abe::issue($a[0], self::strs($a[1]))[1],
            'keygenForCapability' => static function (array $a) {
                [$key, $names] = Abe::issueForCapability($a[0], $a[1], self::strs($a[2]), self::opts($a[3] ?? null));
                return Obj::of(['holder' => $key->get('holder'), 'attrs' => $names]);
            },
            'capabilityAttributes' => static fn(array $a) => Abe::capabilityAttributes($a[0], self::opts($a[1] ?? null)),
        ];
        Base::run($file, $fn, $k, array_map(static fn(callable $f): \Closure => static fn(array $a) => $f($res($a)), $map));
    }

    public function testRoundTrip(): void
    {
        [$mpk, $msk] = Abe::setup();
        $policy = Obj::of(['allOf' => [Obj::of(['attr' => 'a']), Obj::of(['attr' => 'b'])]]);
        $ct = Abe::encryptForPolicy($mpk, $policy, 'hello');
        $both = Abe::keygenForAttributes($msk, ['a', 'b']);
        $one = Abe::keygenForAttributes($msk, ['a']);
        $this->assertSame('hello', Abe::decrypt($both, $ct));
        $this->assertNull(Abe::decrypt($one, $ct), 'a key missing an attribute must not decrypt');
        $this->assertSame(['a', 'b'], AbePolicy::policyAttributes($ct->get('tree')));
        $this->assertSame(Pca::b64u(Pca::unb64u($ct->get('salt'))), $ct->get('salt'));
    }
}
