<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Aggsig;
use Atlas\Pca\NativeDir;
use PHPUnit\Framework\TestCase;

/**
 * The blst loader's candidate list and fallthrough, observed through the path seam, a non-Runtime failure inside it (a verifier then
 * answers false), and the key length every scalar buffer is sized by. Needs ext-ffi and PCA_BLST_LIB (the pairing shard).
 */
final class GrantSurvivorKill21bAggsigTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst)');
        }
    }

    private static function sk(): string
    {
        return str_repeat("\x11", 32); // a valid scalar: non-zero and below r
    }

    /** Runs `$f` on a fresh load with PCA_BLST_LIB set to `$env` and the path seam set to `$hook`; the loaded library and env are restored after. */
    private static function fresh(string $env, \Closure $hook, \Closure $f): mixed
    {
        $prop = new \ReflectionProperty(Aggsig::class, 'ffi');
        $saved = $prop->getValue();
        $old = (string)getenv('PCA_BLST_LIB');
        try {
            putenv('PCA_BLST_LIB=' . $env);
            $prop->setValue(null, null);
            Aggsig::$pathsHook = $hook;
            return $f();
        } finally {
            Aggsig::$pathsHook = null;
            putenv('PCA_BLST_LIB=' . $old);
            $prop->setValue(null, $saved);
        }
    }

    /** @return list<string> */
    private static function tail(): array
    {
        $packaged = NativeDir::lib('blst');
        return [...($packaged === null ? [] : [$packaged]), 'libblst.so', 'libblst.dylib', 'blst.dll'];
    }

    /** Candidates: the env override (when non-empty), the packaged library, then the system names; a path that fails to load is skipped for the next. */
    public function testLoaderCandidatesAndFallthrough(): void
    {
        $real = (string)getenv('PCA_BLST_LIB');
        $sk = self::sk();
        $pk = Aggsig::publicKeyOf($sk);
        $missing = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-g21b-no-libblst.so';
        $seen = [];
        $got = self::fresh($real, static function (array $paths) use (&$seen, $missing, $real): array {
            $seen[] = $paths;
            return [$missing, $real];
        }, static fn() => Aggsig::publicKeyOf($sk));
        $this->assertSame($pk, $got, 'the missing first path is skipped and the second one loads');
        $got = self::fresh('', static function (array $paths) use (&$seen, $real): array {
            $seen[] = $paths;
            return [$real];
        }, static fn() => Aggsig::publicKeyOf($sk));
        $this->assertSame($pk, $got);
        $this->assertSame([[$real, ...self::tail()], self::tail()], $seen);
    }

    /** A non-Runtime failure while loading is answered false by the verifiers (only a RuntimeException escapes). */
    public function testNonRuntimeLoadFailureIsFalse(): void
    {
        $sk = self::sk();
        $pk = Aggsig::publicKeyOf($sk);
        $pop = Aggsig::popProve($sk);
        $sig = Aggsig::sign($sk, 'm');
        $boom = static fn(array $p): array => throw new \Error('g21b loader');
        $this->assertFalse(self::fresh((string)getenv('PCA_BLST_LIB'), $boom, static fn() => Aggsig::popVerify($pk, $pop)));
        $this->assertFalse(self::fresh((string)getenv('PCA_BLST_LIB'), $boom, static fn() => Aggsig::verify($pk, 'm', $sig)));
        $this->assertTrue(Aggsig::popVerify($pk, $pop));
    }

    /** Secret keys are 32 bytes: exactly that length is accepted, and the refusal names it. */
    public function testSecretKeyLength(): void
    {
        $this->assertSame(32, Aggsig::SECRET_KEY_LENGTH);
        $this->assertSame(48, strlen(Aggsig::publicKeyOf(self::sk())));
    }
}
