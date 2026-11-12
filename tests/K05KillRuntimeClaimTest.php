<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RuntimeClaim;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for RuntimeClaim::verifiedClass, over claims this test signs itself. */
final class K05KillRuntimeClaimTest extends TestCase
{
    /** @return array{string, string} [attestor b64u, secret key] */
    private static function key(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x07", 32));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    /** A claim signed over domain || canonical(claim without sig). */
    private static function claim(array $over = []): Obj
    {
        [$att, $sk] = self::key();
        $o = Obj::of($over + [
            'v' => new Num('1'), 'class' => 'os_confined', 'passport_digest' => 'pd', 'evidence_digest' => 'ev',
            'iat' => new Num('100'), 'exp' => new Num('200'), 'attestor' => $att,
        ]);
        $o->set('sig', Pca::b64u(sodium_crypto_sign_detached(RuntimeClaim::DOMAIN . Json::canonicalizeStrict($o), $sk)));
        return $o;
    }

    private static function cls(mixed $c, string $pd = 'pd', mixed $now = 150): string
    {
        return RuntimeClaim::verifiedClass($c, [self::key()[0]], $pd, ['ev'], $now);
    }

    public function testValidClaimAndTheWindowStart(): void
    {
        $this->assertSame('os_confined', self::cls(self::claim()));
        $this->assertSame('os_confined', self::cls(self::claim(), 'pd', 100)); // iat <= now
        $this->assertSame('none', self::cls(self::claim(), 'pd', 99));
    }

    public function testOnlyAnObjIsAClaim(): void
    {
        $real = self::claim();
        // quacks like an Obj (keys/get/without), but is not one
        $fake = new class ($real) {
            public function __construct(private Obj $o)
            {
            }

            public function keys(): array
            {
                return $this->o->keys();
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function without(string ...$d): Obj
            {
                return $this->o->without(...$d);
            }
        };
        $this->assertSame('none', self::cls($fake));
    }

    public function testASignedExtraMemberIsRefused(): void
    {
        $this->assertSame('none', self::cls(self::claim(['extra' => 'x'])));
    }

    public function testDigestLengthBound(): void
    {
        $p128 = str_repeat('p', 128);
        $p129 = str_repeat('p', 129);
        $this->assertSame('os_confined', self::cls(self::claim(['passport_digest' => $p128]), $p128));
        $this->assertSame('none', self::cls(self::claim(['passport_digest' => $p129]), $p129));
    }

    public function testANegativeIatIsRefused(): void
    {
        $this->assertSame('none', self::cls(self::claim(['iat' => new Num('-1')])));
    }
}
