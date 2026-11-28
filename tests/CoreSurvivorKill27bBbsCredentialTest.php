<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bbs;
use Atlas\Pca\BbsCredential;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * The BBS capability credential: attribute encoding and its refusals, presentCredential's field, structure and disclosure refusals,
 * the presentation shape, and verifyPresentation's header pinning and message-count bound. The round trips need ext-ffi and
 * PCA_BLST_LIB (the pairing shard); the refusals before any curve call need neither.
 */
final class CoreSurvivorKill27bBbsCredentialTest extends TestCase
{
    private function needBlst(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            if (getenv('PCA_PAIRING_REQUIRED') === '1') {
                $this->fail('PCA_PAIRING_REQUIRED is set but ext-ffi or PCA_BLST_LIB is missing');
            }
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst)');
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

    private static function attr(mixed $index, mixed $name, mixed $value): Obj
    {
        return Obj::of(['index' => $index, 'name' => $name, 'value' => $value]);
    }

    /** A credential-shaped object with canonical base64url fields (not a valid signature: only paths before the curve are reached). */
    private static function shaped(array $over = []): Obj
    {
        return Obj::of([
            'issuerPublicKey' => 'AA',
            'header' => '',
            'signature' => 'AA',
            'attributes' => [self::attr(0, 'iss', 'I'), self::attr(1, 'sub', 'H')],
            ...$over,
        ]);
    }

    private static function priv(string $name, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(BbsCredential::class, $name))->invoke(null, ...$args);
    }

    /** encodeAttribute is public: name NUL value, and a non-string name or value and a NUL in the name are refused. */
    public function testEncodeAttribute(): void
    {
        $this->assertSame("a\0b", BbsCredential::encodeAttribute('a', 'b'));
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => BbsCredential::encodeAttribute(5, 'b'), $ia, 'attribute name and value must be strings');
        $this->throws(fn() => BbsCredential::encodeAttribute('a', 5), $ia, 'attribute name and value must be strings');
        $this->throws(fn() => BbsCredential::encodeAttribute("a\0b", 'c'), $ia, 'attribute name must not contain NUL');
    }

    /** A caveat that is not an object, or whose type is not a string, is refused. */
    public function testCapabilityAttributesRefusals(): void
    {
        $ia = \InvalidArgumentException::class;
        $cap = static fn(array $cs) => Obj::of(['issuer' => 'I', 'holder' => 'H', 'caveats' => $cs]);
        $this->throws(fn() => BbsCredential::capabilityAttributes($cap([5])), $ia, 'not an object');
        $this->throws(fn() => BbsCredential::capabilityAttributes($cap([Obj::of(['type' => 5])])), $ia, 'caveat type must be a string');
        $this->assertCount(2, BbsCredential::capabilityAttributes($cap([])));
    }

    /** Each of the three credential fields must be canonical base64url. */
    public function testPresentFieldRefusals(): void
    {
        $ia = \InvalidArgumentException::class;
        $msg = 'presentCredential: credential fields are not canonical base64url';
        foreach (['issuerPublicKey', 'header', 'signature'] as $f) {
            $this->throws(fn() => BbsCredential::presentCredential(self::shaped([$f => '!']), ['nope']), $ia, $msg);
        }
    }

    /** The attributes must be a list of objects. */
    public function testPresentStructureRefusals(): void
    {
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => BbsCredential::presentCredential(self::shaped(['attributes' => 5]), ['iss']), $ia, 'not an array');
        $this->throws(fn() => BbsCredential::presentCredential(self::shaped(['attributes' => ['x' => self::attr(0, 'iss', 'I')]]), ['iss']), $ia, 'not an array');
        $this->throws(fn() => BbsCredential::presentCredential(self::shaped(['attributes' => [5]]), ['iss']), $ia, 'not an object');
    }

    /** Unknown names are listed once each, without the known ones, before any proof is made. */
    public function testPresentUnknownAttributes(): void
    {
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => BbsCredential::presentCredential(self::shaped(), ['nope']), $ia, 'presentCredential: unknown attribute(s): nope');
        $this->throws(fn() => BbsCredential::presentCredential(self::shaped(), ['nope', 'nope']), $ia, 'presentCredential: unknown attribute(s): nope');
        $this->throws(fn() => BbsCredential::presentCredential(self::shaped(), ['iss', 'nope', 'x']), $ia, 'presentCredential: unknown attribute(s): nope, x');
    }

    /** A presentation that is not an object is a plain false. */
    public function testVerifyPresentationNeverThrows(): void
    {
        $this->assertFalse(BbsCredential::verifyPresentation(5));
        $this->assertFalse(BbsCredential::verifyPresentation(null));
    }

    /** An attribute index is an integer: a PHP int or an integral Num up to 2^31 - 1; a fraction or anything larger is refused. */
    public function testIndexOf(): void
    {
        $this->assertSame(3, self::priv('indexOf', self::attr(3, 'n', 'v')));
        $this->assertSame(2147483647, self::priv('indexOf', self::attr(2147483647, 'n', 'v')));
        $this->assertSame(4, self::priv('indexOf', self::attr(new Num('4'), 'n', 'v')));
        $ia = \InvalidArgumentException::class;
        $msg = 'attribute index is not an integer';
        $this->throws(fn() => self::priv('indexOf', self::attr(new Num('1.5'), 'n', 'v')), $ia, $msg);
        $this->throws(fn() => self::priv('indexOf', self::attr(2147483648, 'n', 'v')), $ia, $msg);
        $this->throws(fn() => self::priv('indexOf', self::attr('3', 'n', 'v')), $ia, $msg);
    }

    /** The disclosure key is index NUL name NUL value, and a non-string value is refused. */
    public function testDisclosureKey(): void
    {
        $this->assertSame("3\0n\0v", self::priv('key', self::attr(3, 'n', 'v')));
        $this->throws(fn() => self::priv('key', self::attr(0, 'n', 5)), \InvalidArgumentException::class, 'attribute name and value must be strings');
    }

    /** Disclosures compare as sets of keys whatever their order, and a different count never matches. */
    public function testSameDisclosure(): void
    {
        $x = self::attr(1, 'sub', 'H');
        $y = self::attr(0, 'iss', 'I');
        $this->assertTrue(self::priv('sameDisclosure', [$x, $y], [$y, $x]));
        $this->assertTrue(self::priv('sameDisclosure', [$y, $x], [$x, $y]));
        $this->assertFalse(self::priv('sameDisclosure', [$x], []));
        $this->assertFalse(self::priv('sameDisclosure', [$x], [$y]));
    }

    /** @return array{0:Obj,1:string} a credential over iss, sub and its issuer key */
    private static function credential(): array
    {
        $sk = Bbs::keyGen(str_repeat("\1", 32));
        $pk = Bbs::skToPk($sk);
        return [BbsCredential::issueCapabilityCredential(Obj::of(['issuer' => 'I', 'holder' => 'H', 'caveats' => []]), $sk, $pk), $pk];
    }

    /** A presentation carries exactly the six members, in order, with the presentation header it was made over; it verifies. */
    public function testPresentationShape(): void
    {
        $this->needBlst();
        [$cred, $pk] = self::credential();
        $pres = BbsCredential::presentCredential($cred, ['sub'], 'ctx');
        $this->assertSame(['issuerPublicKey', 'header', 'presentationHeader', 'messageCount', 'disclosed', 'proof'], $pres->keys());
        $this->assertSame(Pca::b64u($pk), $pres->get('issuerPublicKey'));
        $this->assertSame('', $pres->get('header'));
        $this->assertSame(Pca::b64u('ctx'), $pres->get('presentationHeader'));
        $this->assertSame(2, $pres->get('messageCount'));
        $this->assertSame([$cred->get('attributes')[1]], $pres->get('disclosed'));
        $this->assertTrue(BbsCredential::verifyPresentation($pres));
        $this->assertTrue(BbsCredential::verifyPresentation($pres, $pk, null, 'ctx'));
    }

    /** A pinned non-empty header must equal the one the presentation carries, even when the proof itself verifies under it. */
    public function testPinnedHeaderMustMatchCarried(): void
    {
        $this->needBlst();
        [$cred] = self::credential();
        $pres = BbsCredential::presentCredential($cred, ['sub'], 'ctx');
        $pres->set('presentationHeader', Pca::b64u('zzz'));
        $this->assertFalse(BbsCredential::verifyPresentation($pres, null, null, 'ctx'));
        $pres->set('presentationHeader', Pca::b64u('ctx'));
        $this->assertTrue(BbsCredential::verifyPresentation($pres, null, null, 'ctx'));
    }

    /** A pinned empty header is used as is (the reference checks the carried one only for a non-empty pin). */
    public function testPinnedEmptyHeader(): void
    {
        $this->needBlst();
        [$cred] = self::credential();
        $pres = BbsCredential::presentCredential($cred, ['sub']);
        $this->assertSame('', $pres->get('presentationHeader'));
        $pres->set('presentationHeader', Pca::b64u('ctx'));
        $this->assertTrue(BbsCredential::verifyPresentation($pres, null, null, ''));
        $this->assertFalse(BbsCredential::verifyPresentation($pres));
    }

    /** A native int messageCount bounds the disclosed indexes: an index equal to it is refused. */
    public function testMessageCountBound(): void
    {
        $this->needBlst();
        [$cred] = self::credential();
        $pres = BbsCredential::presentCredential($cred, ['sub']);
        $this->assertTrue(BbsCredential::verifyPresentation($pres));
        $pres->set('messageCount', 1);
        $this->assertFalse(BbsCredential::verifyPresentation($pres));
        $pres->set('messageCount', 2);
        $this->assertTrue(BbsCredential::verifyPresentation($pres));
    }
}
