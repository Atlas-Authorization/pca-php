<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FnDsaBackendMissing;
use Atlas\Pca\FndsaNative;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for FndsaNative: the loader's refusals (no ext-ffi, the library path it picks, size mismatches, load failures), the
 * length checks that answer before the library is touched, and (with libfndsa) the library's own sign refusal.
 */
final class SigSurvivorKill29FndsaNativeTest extends TestCase
{
    private const LOAD_PREFIX = 'libfndsa could not be loaded (set ATLAS_PCA_LIBFNDSA to the library built from the flagship\'s crate): ';

    private mixed $savedLib = null;
    private string|false $savedEnv = false;

    protected function setUp(): void
    {
        $this->savedLib = self::libProp()->getValue();
        $this->savedEnv = getenv('ATLAS_PCA_LIBFNDSA');
    }

    protected function tearDown(): void
    {
        FndsaNative::$extensionHook = null;
        FndsaNative::$packagedHook = null;
        FndsaNative::$cdefHook = null;
        self::libProp()->setValue(null, $this->savedLib);
        putenv($this->savedEnv === false ? 'ATLAS_PCA_LIBFNDSA' : 'ATLAS_PCA_LIBFNDSA=' . $this->savedEnv);
    }

    private static function libProp(): \ReflectionProperty
    {
        return new \ReflectionProperty(FndsaNative::class, 'lib');
    }

    /** Forget any loaded library so the next call goes through the loader. */
    private static function unload(): void
    {
        self::libProp()->setValue(null, null);
    }

    /** No library can load: the next touch of it throws (so a check that answers first is proven to need no library). */
    private static function noLibrary(): void
    {
        self::unload();
        FndsaNative::$extensionHook = static fn (string $n): bool => false;
    }

    /** A stand-in for the loaded library that reports the given sizes (the real ones by default). */
    private static function fakeLib(array $o): object
    {
        return new class($o) {
            public function __construct(private array $o)
            {
            }

            public function fndsa_len_vk(int $t): int
            {
                return $this->o["vk$t"] ?? ($t === 512 ? 897 : 1793);
            }

            public function fndsa_len_sk(int $t): int
            {
                return $this->o["sk$t"] ?? ($t === 512 ? 1345 : 2369);
            }

            public function fndsa_len_sig(int $t): int
            {
                return $this->o["sig$t"] ?? ($t === 512 ? 666 : 1280);
            }

            public function fndsa_len_seed(): int
            {
                return $this->o['seed'] ?? 32;
            }

            public function fndsa_cap_msg(): int
            {
                return $this->o['cap'] ?? 8192;
            }
        };
    }

    private function missing(string $message, ?int $code = null): FnDsaBackendMissing
    {
        try {
            FndsaNative::backend();
        } catch (FnDsaBackendMissing $e) {
            $this->assertSame($message, $e->getMessage());
            if ($code !== null) {
                $this->assertSame($code, $e->getCode());
            }
            return $e;
        }
        $this->fail("expected FnDsaBackendMissing: $message");
    }

    private function threw(string $class, string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class);
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected $class: $message");
    }

    /** Without ext-ffi the backend refuses with its own reason and available() is false. */
    public function testNoFfiIsRefused(): void
    {
        self::noLibrary();
        $this->assertFalse(FndsaNative::available());
        $this->missing('FN-DSA needs ext-ffi (ffi.enable=true)');
    }

    /** The library path: a non-empty ATLAS_PCA_LIBFNDSA wins, else the packaged library, else libfndsa.so. */
    public function testTheLibraryPathChoice(): void
    {
        $seen = [];
        FndsaNative::$extensionHook = static fn (string $n): bool => true;
        FndsaNative::$cdefHook = static function (mixed $path) use (&$seen): never {
            $seen[] = $path;
            throw new \RuntimeException('no lib here');
        };
        $load = function (): void {
            self::unload();
            $e = $this->missing(self::LOAD_PREFIX . 'no lib here', 0);
            $this->assertInstanceOf(\RuntimeException::class, $e->getPrevious());
            $this->assertSame('no lib here', $e->getPrevious()->getMessage());
        };
        putenv('ATLAS_PCA_LIBFNDSA=/opt/env/libfndsa.so');
        FndsaNative::$packagedHook = static fn (): string => '/pkg/libfndsa.so';
        $load();
        putenv('ATLAS_PCA_LIBFNDSA=');
        $load();
        putenv('ATLAS_PCA_LIBFNDSA');
        $load();
        FndsaNative::$packagedHook = static fn (): ?string => null;
        $load();
        $this->assertSame(['/opt/env/libfndsa.so', '/pkg/libfndsa.so', '/pkg/libfndsa.so', 'libfndsa.so'], $seen);
        $this->assertFalse(FndsaNative::available());
    }

    /** A library that reports sizes other than the ones this class hard-codes is refused, naming what differs. */
    public function testSizeMismatchesAreRefused(): void
    {
        FndsaNative::$extensionHook = static fn (string $n): bool => true;
        $cases = [
            ['libfndsa reports different sizes for fn-dsa-512', ['vk512' => 1]],
            ['libfndsa reports different sizes for fn-dsa-1024', ['sig1024' => 1]],
            ['libfndsa reports a different seed length or message cap', ['seed' => 31]],
            ['libfndsa reports a different seed length or message cap', ['cap' => 8191]],
        ];
        foreach ($cases as [$msg, $o]) {
            self::unload();
            $fake = self::fakeLib($o);
            FndsaNative::$cdefHook = static fn (mixed $path): object => $fake;
            $this->missing($msg, 0);
        }
    }

    /** verify answers false for a bad key, signature or message length without touching the library. */
    public function testVerifyLengthChecksNeedNoLibrary(): void
    {
        self::noLibrary();
        $pk = str_repeat("\0", 897);
        $sig = str_repeat("\0", 666);
        $this->assertFalse(FndsaNative::verify('fn-dsa-512', substr($pk, 1), 'm', $sig));
        $this->assertFalse(FndsaNative::verify('fn-dsa-512', $pk, 'm', substr($sig, 1)));
        $this->assertFalse(FndsaNative::verify('fn-dsa-512', $pk, str_repeat('m', FndsaNative::MESSAGE_CAP + 1), $sig));
        $this->assertFalse(FndsaNative::verify('fn-dsa-1024', $pk, 'm', $sig));
    }

    /** keygen and sign refuse bad seed, key and message lengths with exact reasons before the library is touched. */
    public function testKeygenAndSignRefusalsNeedNoLibrary(): void
    {
        self::noLibrary();
        $sk = str_repeat("\0", 1345);
        $this->threw(\InvalidArgumentException::class, 'fndsa native: seed must be 32 bytes', fn () => FndsaNative::keygen('fn-dsa-512', 'short'));
        $this->threw(\InvalidArgumentException::class, 'fndsa native: secret key must be 1345 bytes for fn-dsa-512', fn () => FndsaNative::sign('fn-dsa-512', 'short', 'm'));
        $this->threw(\InvalidArgumentException::class, 'fndsa native: secret key must be 2369 bytes for fn-dsa-1024', fn () => FndsaNative::sign('fn-dsa-1024', $sk, 'm'));
        $this->threw(\InvalidArgumentException::class, 'fndsa native: message over 8192 bytes', fn () => FndsaNative::sign('fn-dsa-512', $sk, str_repeat('m', 8193)));
        $this->threw(\InvalidArgumentException::class, 'fndsa native: seed must be 32 bytes', fn () => FndsaNative::sign('fn-dsa-512', $sk, 'm', 'short'));
        // the lengths all pass, so the library is reached (and here refuses to load)
        $this->threw(FnDsaBackendMissing::class, 'FN-DSA needs ext-ffi (ffi.enable=true)', fn () => FndsaNative::sign('fn-dsa-512', $sk, 'm', str_repeat("\1", 32)));
    }

    private function needLibrary(): void
    {
        if (!FndsaNative::available()) {
            if (getenv('ATLAS_PCA_LIBFNDSA_REQUIRED') === '1') {
                $this->fail('libfndsa must load (ATLAS_PCA_LIBFNDSA, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and libfndsa (ATLAS_PCA_LIBFNDSA)');
        }
    }

    /** With libfndsa: a secret key of the right length that does not decode is a sign failure carrying the library's code. */
    public function testTheLibraryRefusesAnUndecodableKey(): void
    {
        $this->needLibrary();
        $this->threw(\RuntimeException::class, 'fndsa native: sign failed (-2)',
            fn () => FndsaNative::sign('fn-dsa-512', str_repeat("\0", 1345), 'm', str_repeat("\1", 32)));
    }

    /** With libfndsa: the backend's seeded signer refuses a key length of no variant. */
    public function testTheSeededSignerRefusesAnUnknownKeyLength(): void
    {
        $this->needLibrary();
        $b = FndsaNative::backend();
        $this->threw(\InvalidArgumentException::class, 'fndsa native: unrecognised FN-DSA secret-key length',
            fn () => ($b->signSeeded)('short', 'm', str_repeat("\1", 32)));
        $this->threw(\InvalidArgumentException::class, 'fndsa native: unrecognised FN-DSA secret-key length',
            fn () => ($b->sign)('short', 'm'));
    }
}
