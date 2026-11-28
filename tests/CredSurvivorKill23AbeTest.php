<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Abe;
use Atlas\Pca\Bls12;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** ABE: master key / public key parse refusals, deterministic hooks, ciphertext parse, AEAD tag length, text decoding and capability attributes. */
final class CredSurvivorKill23AbeTest extends TestCase
{
    /** The pairing tests need ext-ffi and PCA_BLST_LIB (a libblst built with the GT shim); the attribute tests are pure PHP. */
    private function needBlst(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst built with the GT shim)');
        }
    }

    private function throws(callable $f, string $class, string $msg): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail("expected $class: $msg");
    }

    /** @return list<\GMP> */
    private static function s(): array
    {
        return array_map(static fn(int $i) => gmp_init($i + 2), range(0, 6));
    }

    private static function policy(): Obj
    {
        return Obj::of(['attr' => 'a']);
    }

    private static function enc(\GMP $k): string
    {
        return Pca::b64u(Bls12::i2osp($k, 32));
    }

    /** setup($fixed) places a1, a2, b1, b2 in msk.a / msk.b, d1..d3 as d_i * G1 in msk.g and a_i * H in mpk.h. */
    public function testSetupFixed(): void
    {
        $this->needBlst();
        $s = self::s();
        [$mpk, $msk] = Abe::setup($s);
        $g1 = static fn(\GMP $k): string => Pca::b64u(Bls12::compress(1, Bls12::pMul(1, Bls12::generator(1), $k)));
        $g2 = static fn(\GMP $k): string => Pca::b64u(Bls12::compress(2, Bls12::pMul(2, Bls12::generator(2), $k)));
        $this->assertSame([self::enc($s[0]), self::enc($s[1])], $msk->get('a'));
        $this->assertSame([self::enc($s[2]), self::enc($s[3])], $msk->get('b'));
        $this->assertSame([$g1($s[4]), $g1($s[5]), $g1($s[6])], $msk->get('g'));
        $this->assertSame([$g2($s[0]), $g2($s[1])], $mpk->get('h'));
    }

    /** A master secret key that is not an object, has a non-list scalar pair, a zero or >= r scalar, or a non-base64url point is refused. */
    public function testMskRefusals(): void
    {
        $this->needBlst();
        [, $msk] = Abe::setup(self::s());
        $m = 'invalid master secret key';
        $ia = \InvalidArgumentException::class;
        $with = static function (string $k, mixed $v) use ($msk): Obj {
            $o = $msk->without();
            $o->set($k, $v);
            return $o;
        };
        $b1 = $msk->get('b')[1];
        $this->throws(fn() => Abe::issue(5, []), $ia, $m);
        $this->throws(fn() => Abe::issue($with('a', 'x'), []), $ia, $m);
        $this->throws(fn() => Abe::issue($with('b', [Pca::b64u(str_repeat("\0", 32)), $b1]), []), $ia, $m);
        $this->throws(fn() => Abe::issue($with('b', [self::enc(Bls12::r()), $b1]), []), $ia, $m);
        $g = $msk->get('g');
        $this->throws(fn() => Abe::issue($with('g', ['!!!', $g[1], $g[2]]), []), $ia, $m);
        $this->assertSame([], Abe::issue($msk, [])[1]);
    }

    /** A master public key that is not an object, has a malformed h (not a 2-list, or either point invalid) is refused. */
    public function testMpkRefusals(): void
    {
        $this->needBlst();
        [$mpk] = Abe::setup(self::s());
        $h = $mpk->get('h');
        $with = static function (mixed $v) use ($mpk): Obj {
            $o = $mpk->without();
            $o->set('h', $v);
            return $o;
        };
        $ia = \InvalidArgumentException::class;
        $m = 'invalid master public key';
        $this->throws(fn() => Abe::encryptForPolicy(5, self::policy(), 'x'), $ia, $m);
        $this->throws(fn() => Abe::encryptForPolicy($with('x'), self::policy(), 'x'), $ia, $m);
        $this->throws(fn() => Abe::encryptForPolicy($with([$h[0], $h[1], $h[1]]), self::policy(), 'x'), $ia, $m);
        $this->throws(fn() => Abe::encryptForPolicy($with([$h[0], '!!!']), self::policy(), 'x'), $ia, $m);
        $this->throws(fn() => Abe::encryptForPolicy($with(['!!!', $h[1]]), self::policy(), 'x'), $ia, $m);
    }

    /** The fixed hooks of issue and encryptForPolicy make the key and the ciphertext's group elements deterministic. */
    public function testFixedHooks(): void
    {
        $this->needBlst();
        [$mpk, $msk] = Abe::setup(self::s());
        $this->assertSame(Json::canonicalizeLenient(Abe::setup(self::s())[1]), Json::canonicalizeLenient($msk));
        $fixed = ['r' => [gmp_init(3), gmp_init(4)], 'sigmas' => [gmp_init(5)], 'sigmaPrime' => gmp_init(6)];
        $this->assertSame(Json::canonicalizeLenient(Abe::issue($msk, ['a'], $fixed)[0]), Json::canonicalizeLenient(Abe::issue($msk, ['a'], $fixed)[0]));
        $c1 = Abe::encryptForPolicy($mpk, self::policy(), 'x', [gmp_init(3), gmp_init(4)]);
        $c2 = Abe::encryptForPolicy($mpk, self::policy(), 'x', [gmp_init(3), gmp_init(4)]);
        $this->assertSame([$c1->get('ct0'), $c1->get('rows')], [$c2->get('ct0'), $c2->get('rows')]);
    }

    /** An invalid policy and a repeated attribute are refused with their exact reasons. */
    public function testPolicyRefusals(): void
    {
        $this->needBlst();
        [$mpk] = Abe::setup(self::s());
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Abe::encryptForPolicy($mpk, 5, 'x'), $ia, 'invalid policy: policy: not an object');
        $dup = Obj::of(['allOf' => [Obj::of(['attr' => 'a']), Obj::of(['attr' => 'a'])]]);
        $this->throws(fn() => Abe::encryptForPolicy($mpk, $dup, 'x'), $ia, 'invalid policy: attribute "a" is named by more than one leaf (single-use attributes only)');
    }

    /** Ciphertext parse refuses a non-list or non-base64url ct0; a tag shorter than 16 bytes never decrypts. */
    public function testCiphertextParseAndTag(): void
    {
        $this->needBlst();
        [$mpk, $msk] = Abe::setup(self::s());
        $key = Abe::keygenForAttributes($msk, ['a']);
        $ct = Abe::encryptForPolicy($mpk, self::policy(), 'hello');
        $this->assertSame('hello', Abe::decrypt($key, $ct));
        $this->assertInstanceOf(Obj::class, Abe::parseCiphertext($ct));
        $with = static function (string $k, mixed $v) use ($ct): Obj {
            $o = $ct->without();
            $o->set($k, $v);
            return $o;
        };
        $ct0 = $ct->get('ct0');
        $this->assertNull(Abe::parseCiphertext($with('ct0', 'x')));
        $this->assertNull(Abe::parseCiphertext($with('ct0', [$ct0[0], $ct0[1], '!!'])));
        $short = Pca::b64u(substr((string)Pca::unb64u($ct->get('tag')), 0, 12));
        $this->assertNull(Abe::decrypt($key, $with('tag', $short)));
    }

    /** decryptText replaces invalid UTF-8 with U+FFFD, drops a leading BOM and restores the caller's substitute character. */
    public function testDecryptText(): void
    {
        $this->needBlst();
        [$mpk, $msk] = Abe::setup(self::s());
        $key = Abe::keygenForAttributes($msk, ['a']);
        $ct = Abe::encryptForPolicy($mpk, self::policy(), "\xEF\xBB\xBFh\xFF");
        $saved = mb_substitute_character();
        mb_substitute_character(63);
        try {
            $this->assertSame("h\u{FFFD}", Abe::decryptText($key, $ct));
            $this->assertSame(63, mb_substitute_character());
        } finally {
            mb_substitute_character($saved);
        }
    }

    /** A payload that is not valid UTF-8 is not JSON even when the parser would read it; encryptToolPayload is public. */
    public function testDecryptWithCapability(): void
    {
        $this->needBlst();
        [$mpk, $msk] = Abe::setup(self::s());
        $key = Abe::keygenForAttributes($msk, ['a']);
        $bad = Abe::decryptWithCapability($key, Abe::encryptForPolicy($mpk, self::policy(), "\"\xFF\""));
        $this->assertSame([false, 'decrypted payload is not valid JSON'], [$bad->get('ok'), $bad->get('reason')]);
        $good = Abe::decryptWithCapability($key, Abe::encryptToolPayload($mpk, self::policy(), Obj::of(['k' => 'v'])));
        $this->assertSame([true, 'v'], [$good->get('ok'), $good->get('payload')->get('k')]);
    }

    /** The holder is recorded only for an Obj capability with a string holder; keygenForCapability is public and returns the key. */
    public function testCapabilityKeys(): void
    {
        $this->needBlst();
        [, $msk] = Abe::setup(self::s());
        $this->assertFalse(Abe::issueForCapability($msk, 5)[0]->has('holder'));
        $this->assertFalse(Abe::issueForCapability($msk, Obj::of(['id' => 'c']))[0]->has('holder'));
        $k = Abe::keygenForCapability($msk, Obj::of(['id' => 'c', 'holder' => 'h']));
        $this->assertSame('h', $k->get('holder'));
    }

    /** Non-object capabilities and malformed chains name no attributes. */
    public function testCapabilityAttributesChainShape(): void
    {
        $cap = Obj::of(['id' => 'c1', 'caveats' => [Obj::of(['type' => 'scope', 'value' => 's'])]]);
        $this->assertSame(['scope:s'], Abe::capabilityAttributes($cap));
        $this->assertSame([], Abe::capabilityAttributes(5));
        $this->assertSame([], Abe::capabilityAttributes($cap, Obj::of(['chain' => 'x'])));
        $this->assertSame([], Abe::capabilityAttributes($cap, Obj::of(['chain' => [$cap, 5]])));
        $this->assertSame([], Abe::capabilityAttributes($cap, Obj::of(['chain' => [5, $cap]])));
    }

    /** A post-quantum root names its attributes through a chain only with a string pin for its issuer (the pins are passed on). */
    public function testChainPqPins(): void
    {
        if (!Pca::suiteImplemented('ml-dsa-65')) {
            $this->markTestSkipped('needs ML-DSA-65 (OpenSSL >= 3.5)');
        }
        $grant = null;
        $pins = null;
        foreach (Vectors::load('authorize-pq-pin-fixtures.json')->get('cases') as $c) {
            if ($c->get('name') === 'pq-grant-pinned') {
                [$grant, $pins] = [$c->get('grant'), $c->get('pq_pins')];
            }
        }
        $want = Abe::capabilityAttributes($grant);
        $this->assertNotSame([], $want);
        $this->assertSame($want, Abe::capabilityAttributes($grant, Obj::of(['chain' => [$grant], 'pqPins' => $pins])));
        $this->assertSame([], Abe::capabilityAttributes($grant, Obj::of(['chain' => [$grant]])));
    }

    /** Scope caveats: non-objects are skipped (not the end), and only type scope + string value / type scopes + list values count. */
    public function testScopeCaveats(): void
    {
        $cap = Obj::of(['id' => 'c', 'caveats' => [5, Obj::of(['type' => 'scope', 'value' => 's']), Obj::of(['type' => 'other', 'value' => 'v']),
            Obj::of(['type' => 'x', 'values' => ['q']]), Obj::of(['type' => 'scope', 'value' => 5])]]);
        $this->assertSame(['scope:s'], Abe::capabilityAttributes($cap));
    }

    private static function envCap(string $predicates): Obj
    {
        return Js::parse('{"id":"c","caveats":[{"agent_binding":{},"caveats":[],"goal_commit":"g","predicates":' . $predicates . ',"risk_policy":{"bMax":1,"kappa":1,'
            . '"lambda":0.0005,"rho":0.5,"theta1":0.25,"theta2":0.6,"weights":{"alpha":0.25,"beta":0.2,"delta":0.2,"epsilon":0.1,"gamma":0.2,"zeta":0.05}},"type":"envelope"}]}');
    }

    /** Envelope predicates: non-string verbs are dropped; a non-object non-array entry is not a predicate, an array is one. */
    public function testEnvelopePredicates(): void
    {
        $this->assertSame(['act:["read","r"]', 'resource:r', 'verb:read'], Abe::capabilityAttributes(self::envCap('[{"resource":"r","verb":[5,"read"]},5]')));
        $this->assertSame(['act:["read","r"]'], Abe::capabilityAttributes(self::envCap('[{"resource":"r","verb":"read"},[]]')));
    }
}
