<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestPuf.php';

use Atlas\Pca\AttestPuf;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PufEnrollmentRegistry;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the PUF fuzzy extractor, the simulated PUF, the derived-suite guard and the attestor / registry factories. */
final class AttestSurvivorKill7PufFuzzyTest extends TestCase
{
    private const BITS = "\1\0\1\1\1\0\0\1\0";

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e::class . ': ' . $e->getMessage();
        }
        return 'no error';
    }

    private static function params(mixed $rep, int $mb): Obj
    {
        return Obj::of(['rep' => $rep, 'messageBits' => $mb]);
    }

    /** @return array{0:array{key:string,helper:Obj},1:list<int>} */
    private static function enrolled(): array
    {
        $asked = [];
        $rb = static function (int $n) use (&$asked): string {
            $asked[] = $n;
            return count($asked) === 1 ? "\x03" : str_repeat('S', 32);
        };
        $r = AttestPuf::fuzzyEnroll(self::BITS, self::params(3, 3), $rb);
        return [$r, $asked];
    }

    /** A simulated PUF spanning several hash blocks returns every block (a stream overwritten per block would run out of bits). */
    public function testSimulatedPufUsesEveryStreamBlock(): void
    {
        $seed = 'seed-7';
        $stream = hash('sha256', $seed . 'c' . pack('N', 0), true) . hash('sha256', $seed . 'c' . pack('N', 1), true);
        $want = '';
        for ($i = 0; $i < 300; $i++) {
            $want .= ((ord($stream[$i >> 3]) >> ($i & 7)) & 1) === 1 ? "\1" : "\0";
        }
        $got = AttestPuf::createSimulatedPuf('p', $seed, 300)->response('c');
        $this->assertSame(300, strlen($got));
        $this->assertSame($want, $got);
    }

    /** Enrolling a 9-bit response packs two bytes, asks for the message then a 32-byte salt, and a short random source counts as zero bits. */
    public function testFuzzyEnrollPacksAndMasksExactly(): void
    {
        [$r, $asked] = self::enrolled();
        $h = $r['helper'];
        $this->assertSame([3, 32], $asked);
        $this->assertSame(Pca::b64u("\x9a\x00"), $h->get('sketch'));
        $this->assertSame(Pca::b64u(str_repeat('S', 32)), $h->get('salt'));
        $this->assertSame(3, $h->get('rep'));
        $this->assertSame(3, $h->get('messageBits'));
        $this->assertSame(9, $h->get('n'));
        $this->assertSame(hash_hkdf('sha256', "\x9d\x00", 32, AttestPuf::PUF_EXTRACT_INFO, str_repeat('S', 32)), $r['key']);
    }

    /** Enrollment refuses a non-integer repetition factor and reports a wrong response length with both numbers. */
    public function testFuzzyEnrollRefusals(): void
    {
        $rb = static fn(int $n): string => str_repeat("\1", $n);
        $this->assertSame(
            'RangeException: fuzzyEnroll: rep must be an odd positive integer',
            self::thrown(static fn() => AttestPuf::fuzzyEnroll(self::BITS, self::params(3.5, 3), $rb))
        );
        $this->assertSame(
            'RangeException: fuzzyEnroll: response length 5 != rep*messageBits 6',
            self::thrown(static fn() => AttestPuf::fuzzyEnroll("\0\0\0\0\0", self::params(3, 2), $rb))
        );
    }

    /** Reproduction over a 9-bit response returns the enrolled key, also under one flipped bit per block. */
    public function testFuzzyReproduceReturnsTheEnrolledKey(): void
    {
        [$r] = self::enrolled();
        $this->assertSame($r['key'], AttestPuf::fuzzyReproduce(self::BITS, $r['helper']));
        $noisy = self::BITS;
        $noisy[4] = "\0";
        $this->assertSame($r['key'], AttestPuf::fuzzyReproduce($noisy, $r['helper']));
    }

    /** Every malformed helper or response is refused with its own exact reason. */
    public function testFuzzyReproduceRefusals(): void
    {
        [$r] = self::enrolled();
        $h = $r['helper'];
        $re = static fn(mixed $helper, string $bits = self::BITS): string => self::thrown(static fn() => AttestPuf::fuzzyReproduce($bits, $helper));

        $badRep = Jsx::spread($h);
        $badRep->set('rep', 3.5);
        $this->assertSame('RangeException: fuzzyReproduce: malformed helper params', $re($badRep));
        $this->assertSame('RangeException: fuzzyReproduce: response length 5 != 9', $re($h, "\1\0\1\1\1"));
        $this->assertSame('RangeException: fuzzyReproduce: helper data missing sketch or salt', $re($h->without('salt')));
        $this->assertSame('RangeException: fuzzyReproduce: helper data missing sketch or salt', $re($h->without('sketch')));

        $badSketch = Jsx::spread($h);
        $badSketch->set('sketch', '!!');
        $this->assertSame('RangeException: fuzzyReproduce: helper sketch or salt is not canonical base64url', $re($badSketch));
        $badSalt = Jsx::spread($h);
        $badSalt->set('salt', '!!');
        $this->assertSame('RangeException: fuzzyReproduce: helper sketch or salt is not canonical base64url', $re($badSalt));

        $short = Jsx::spread($h);
        $short->set('sketch', Pca::b64u("\x9a"));
        $this->assertSame('RangeException: fuzzyReproduce: helper sketch has the wrong length', $re($short));
    }

    /** The repetition decoder takes a strict majority per block and yields exactly one bit per full block. */
    public function testRepDecodeMajorityAndLength(): void
    {
        $m = new \ReflectionMethod(AttestPuf::class, 'repDecode');
        $this->assertSame("\1", $m->invoke(null, "\1\1\0", 3));
        $this->assertSame("\0", $m->invoke(null, "\1\0", 2)); // a tie is not a majority
    }

    /** Only the three named derived suites are accepted, and the refusal names the offending suite. */
    public function testEnrollRefusesAnUnsupportedSuite(): void
    {
        $puf = AttestPuf::createSimulatedPuf('p', 'seed', 9);
        $this->assertSame(
            "RangeException: PUF root: unsupported derived suite 'rsa' (use ed25519, ml-dsa-65 or ml-dsa-87)",
            self::thrown(static fn() => AttestPuf::enrollPuf($puf, 'c', Obj::of(['rep' => 3, 'messageBits' => 3, 'alg' => 'rsa'])))
        );
    }

    /** An attestor over an enrollment whose challenge is not canonical base64url is refused at construction. */
    public function testAttestorRefusesANonCanonicalChallenge(): void
    {
        $puf = AttestPuf::createSimulatedPuf('p', 'seed', 9);
        $this->assertSame(
            'RangeException: Unknown letter: challenge is not canonical base64url',
            self::thrown(static fn() => AttestPuf::createPufAttestor($puf, Obj::of(['alg' => 'ed25519', 'challenge' => '!!'])))
        );
    }

    /** The registry factory is public and builds a working registry. */
    public function testRegistryFactoryIsPublic(): void
    {
        $reg = AttestPuf::createPufEnrollmentRegistry([Obj::of(['providerId' => 'a', 'x' => 1])]);
        $this->assertInstanceOf(PufEnrollmentRegistry::class, $reg);
        $this->assertSame(1, $reg->lookup('a')->get('x'));
        $this->assertFalse($reg->isRevoked('a'));
    }
}
