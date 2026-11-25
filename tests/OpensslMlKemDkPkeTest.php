<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\OpensslMlKem;
use PHPUnit\Framework\TestCase;

/** The decryption half of a decapsulation key is canonicalised mod q = 3329 before OpenSSL imports it (FIPS 203 ByteDecode_12). */
final class OpensslMlKemDkPkeTest extends TestCase
{
    private static function pack(int $c0, int $c1): string
    {
        return chr($c0 & 0xFF) . chr((($c0 >> 8) & 0x0F) | (($c1 & 0x0F) << 4)) . chr(($c1 >> 4) & 0xFF);
    }

    public function testACanonicalKeyIsReturnedByteIdentical(): void
    {
        $dk = '';
        for ($i = 0; $i < 384; $i += 3) {
            $dk .= self::pack(($i * 7) % 3329, ($i * 13 + 5) % 3329);
        }
        $dk .= str_repeat("\x99", 100);   // ek, H(ek), z are not touched
        $this->assertSame($dk, OpensslMlKem::canonicalDkPke($dk, 1));
    }

    public function testACoefficientAboveQIsReducedMod3329(): void
    {
        $dk = self::pack(4095, 3329) . str_repeat("\0", 381) . "tail";
        $out = OpensslMlKem::canonicalDkPke($dk, 1);
        $this->assertSame(self::pack(766, 0), substr($out, 0, 3));
        $this->assertSame(substr($dk, 3), substr($out, 3));
    }
}
