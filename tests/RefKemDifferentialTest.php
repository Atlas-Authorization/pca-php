<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/OpensslMlKem.php';
require_once __DIR__ . '/../src/Kem.php';

use Atlas\Pca\Kem;
use Atlas\Pca\MpcShake256;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslMlKem;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The KEM module (hybrid X25519 + ML-KEM-768 / -1024, X-Wing draft-09, the FIPS 203 key checks) against the TS reference:
 * test-data/ref-kem.json.gz. ML-KEM runs on OpenSSL >= 3.5 through ext-ffi (the whole suite is skipped without it, and FAILS when
 * PCA_REQUIRE_PQ=1), X25519 on ext-sodium. Keys travel as labels: a secret is sha256("atlas-pca-conformance/" . label), a hybrid or
 * ML-KEM key is rebuilt from its seeds. The reference draws randomness from the platform CSPRNG, so the corpus pins the stream and
 * the replay goes through the derandomised test seams. Cases whose argument is a JavaScript type confusion (a null where bytes are
 * required, and the key checks' null) are skipped.
 */
final class RefKemDifferentialTest extends TestCase
{
    private const FILE = 'ref-kem.json.gz';
    private const TOTAL = 464;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    protected function setUp(): void
    {
        if (OpensslMlKem::available() && MpcShake256::available() && function_exists('sodium_crypto_scalarmult')) {
            return;
        }
        $why = 'needs ext-ffi with OpenSSL >= 3.5 (ML-KEM-768 and -1024), ext-sodium';
        if (getenv('PCA_REQUIRE_PQ') === '1') {
            $this->fail($why);
        }
        $this->markTestSkipped($why);
    }

    /** Raw bytes of a corpus bytes argument: {$bytes: b64url} or {$bytes: {$seed: label}}; a bare string is itself; anything else is null. */
    private static function by(mixed $o): ?string
    {
        if ($o instanceof Obj && $o->has('$bytes')) {
            $v = $o->get('$bytes');
            if ($v instanceof Obj) {
                return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
            }
            return Pca::unb64u((string) $v);
        }
        return is_string($o) ? $o : null;
    }

    /** The pinned random stream: one bytes value or a list of parts, concatenated. */
    private static function rng(mixed $o): string
    {
        return is_array($o) ? implode('', array_map(static fn($p): string => (string) self::by($p), $o)) : (string) self::by($o);
    }

    private static function int(mixed $o): int
    {
        return (int) ($o instanceof Num ? $o->float() : $o);
    }

    /** @return list<array{0:int,1:int}> */
    private static function sets(Obj $o): array
    {
        return array_map(static fn($p): array => [self::int($p[0]), self::int($p[1])], $o->get('set') ?? []);
    }

    private static function hybridSk(Obj $o): string
    {
        $s = $o->get('$hybridSk');
        $level = self::int($s->get('level'));
        $sk = self::by($s->get('x')) . OpensslMlKem::keygen($level, self::by($s->get('d')) . self::by($s->get('z')))['secretKey'];
        if ($s->has('trim')) {
            $sk = substr($sk, 0, strlen($sk) - self::int($s->get('trim')));
        }
        if ($s->has('pad')) {
            $sk .= str_repeat("\0", self::int($s->get('pad')));
        }
        foreach (self::sets($s) as [$off, $v]) {
            $sk[$off] = chr($v);
        }
        return $sk;
    }

    private static function mlkemDk(Obj $o): string
    {
        $s = $o->get('$mlkemDk');
        $level = self::int($s->get('level'));
        $k = $level === 768 ? 3 : 4;
        $dk = OpensslMlKem::keygen($level, self::by($s->get('d')) . self::by($s->get('z')))['secretKey'];
        foreach (self::sets($s) as [$off, $v]) {
            $dk[$off] = chr($v);
        }
        if ($s->get('rehash') === true) {
            $dk = substr($dk, 0, 768 * $k + 32) . hash('sha3-256', substr($dk, 384 * $k, 384 * $k + 32), true) . substr($dk, 768 * $k + 64);
        }
        return $dk;
    }

    /** A secret key argument: a hybrid key built from seeds, an ML-KEM dk built from seeds, or plain bytes. */
    private static function key(mixed $o): ?string
    {
        if ($o instanceof Obj && $o->has('$hybridSk')) {
            return self::hybridSk($o);
        }
        if ($o instanceof Obj && $o->has('$mlkemDk')) {
            return self::mlkemDk($o);
        }
        return self::by($o);
    }

    /** The level of a key check: a JSON number, or the numeric text the reference's object lookup also accepts; anything else stays a refusal. */
    private static function level(mixed $o): mixed
    {
        return $o instanceof Num ? (int) $o->float() : (is_string($o) && ctype_digit($o) ? (int) $o : $o);
    }

    /** @param array{publicKey:string,secretKey:string} $k */
    private static function keyOut(array $k): array
    {
        return ['publicKey' => Base::outBytes($k['publicKey']), 'secretKeySha256' => hash('sha256', $k['secretKey']), 'secretKeyLen' => strlen($k['secretKey'])];
    }

    /** @param array{ciphertext:string,sharedSecret:string} $e */
    private static function encOut(array $e): array
    {
        return ['ciphertext' => Base::outBytes($e['ciphertext']), 'sharedSecret' => Base::outBytes($e['sharedSecret'])];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $out = static fn(string $x): Obj => Base::outBytes($x);
        $skipNull = static fn(callable $f) => static fn(array $a) => $a[1] === null ? [Base::SKIP, 'JS type confusion (null key)'] : $f($a);
        $map = [
            'constants' => static fn(array $a) => [
                'HYBRID_PUBLIC_KEY_LEN' => Kem::HYBRID_PUBLIC_KEY_LEN, 'HYBRID_CIPHERTEXT_LEN' => Kem::HYBRID_CIPHERTEXT_LEN,
                'HYBRID_SHARED_SECRET_LEN' => Kem::HYBRID_SHARED_SECRET_LEN, 'HYBRID_KEM_SUITE' => Kem::HYBRID_KEM_SUITE,
                'XWING_SUITE' => Kem::XWING_SUITE, 'XWING_SEED_LEN' => Kem::XWING_SEED_LEN, 'XWING_SECRET_KEY_LEN' => Kem::XWING_SECRET_KEY_LEN,
                'XWING_PUBLIC_KEY_LEN' => Kem::XWING_PUBLIC_KEY_LEN, 'XWING_CIPHERTEXT_LEN' => Kem::XWING_CIPHERTEXT_LEN,
                'XWING_SHARED_SECRET_LEN' => Kem::XWING_SHARED_SECRET_LEN, 'XWING_ESEED_LEN' => Kem::XWING_ESEED_LEN,
                'XWING_LABEL' => Base::outBytes(Kem::XWING_LABEL),
                'HYBRID1024_PUBLIC_KEY_LEN' => Kem::HYBRID1024_PUBLIC_KEY_LEN, 'HYBRID1024_CIPHERTEXT_LEN' => Kem::HYBRID1024_CIPHERTEXT_LEN,
                'HYBRID1024_SHARED_SECRET_LEN' => Kem::HYBRID1024_SHARED_SECRET_LEN, 'HYBRID1024_KEM_SUITE' => Kem::HYBRID1024_KEM_SUITE,
            ],
            'hybridKemKeygen' => static fn(array $a) => self::keyOut(Kem::hybridKemKeygenDerand(self::rng($a[0]))),
            'hybridKem1024Keygen' => static fn(array $a) => self::keyOut(Kem::hybridKem1024KeygenDerand(self::rng($a[0]))),
            'hybridEncapsulate' => static fn(array $a) => self::encOut(Kem::hybridEncapsulateDerand(self::by($a[0]), self::rng($a[1]))),
            'hybridEncapsulate1024' => static fn(array $a) => self::encOut(Kem::hybridEncapsulate1024Derand(self::by($a[0]), self::rng($a[1]))),
            'hybridDecapsulate' => static fn(array $a) => $out(Kem::hybridDecapsulate(self::by($a[0]), self::key($a[1]))),
            'hybridDecapsulate1024' => static fn(array $a) => $out(Kem::hybridDecapsulate1024(self::by($a[0]), self::key($a[1]))),
            'xwingKeygen' => static function (array $a) {
                $seed = self::by($a[0]);
                return self::keyOut(Kem::xwingKeygen($seed));
            },
            'xwingEncapsulateDerand' => static fn(array $a) => self::encOut(Kem::xwingEncapsulateDerand(self::by($a[0]), is_array($a[1]) ? self::rng($a[1]) : self::by($a[1]))),
            // the pinned stream of the randomised call is the 64 eseed bytes: the same code path as the derandomised entry
            'xwingEncapsulate' => static fn(array $a) => self::encOut(Kem::xwingEncapsulateDerand(self::by($a[0]), self::rng($a[1]))),
            'xwingDecapsulate' => static fn(array $a) => $out(Kem::xwingDecapsulate(self::by($a[0]), self::by($a[1]))),
            'mlKemEncapsulationKeyCheck' => $skipNull(static fn(array $a) => Kem::mlKemEncapsulationKeyCheck(self::level($a[0]), self::by($a[1]))),
            'mlKemDecapsulationKeyCheck' => $skipNull(static fn(array $a) => Kem::mlKemDecapsulationKeyCheck(self::level($a[0]), self::key($a[1]))),
        ];
        foreach (['HybridPublicKey', 'HybridCiphertext', 'XWingPublicKey', 'XWingCiphertext'] as $name) {
            $map["encode$name"] = static fn(array $a) => Kem::{"encode$name"}(self::by($a[0]));
            $map["decode$name"] = static fn(array $a) => $out(Kem::{"decode$name"}($a[0]));
        }
        Base::run($file, $fn, $k, $map);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
    }

    /** The randomised entry points: a round trip agrees on the shared secret, and two runs differ. */
    public function testRandomisedRoundTrips(): void
    {
        $suites = [
            ['hybridKemKeygen', 'hybridEncapsulate', 'hybridDecapsulate', Kem::HYBRID_PUBLIC_KEY_LEN, 2432],
            ['hybridKem1024Keygen', 'hybridEncapsulate1024', 'hybridDecapsulate1024', Kem::HYBRID1024_PUBLIC_KEY_LEN, 3200],
            ['xwingKeygen', 'xwingEncapsulate', 'xwingDecapsulate', Kem::XWING_PUBLIC_KEY_LEN, 32],
        ];
        foreach ($suites as [$gen, $enc, $dec, $pkLen, $skLen]) {
            $a = Kem::$gen();
            $b = Kem::$gen();
            $this->assertSame($pkLen, strlen($a['publicKey']), $gen);
            $this->assertSame($skLen, strlen($a['secretKey']), $gen);
            $this->assertNotSame($a['publicKey'], $b['publicKey'], $gen);
            $e = Kem::$enc($a['publicKey']);
            $this->assertSame(32, strlen($e['sharedSecret']), $enc);
            $this->assertSame($e['sharedSecret'], Kem::$dec($e['ciphertext'], $a['secretKey']), $dec);
            $this->assertNotSame($e['sharedSecret'], Kem::$enc($a['publicKey'])['sharedSecret'], $enc);
            $this->assertNotSame($e['sharedSecret'], Kem::$dec($e['ciphertext'], $b['secretKey']), "$dec with another key");
        }
    }
}
