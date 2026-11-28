<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Amd;
use Atlas\Pca\Attest\Common;
use PHPUnit\Framework\TestCase;

/** Survivor kills for Attest/Amd.php: the report-signature scalar range check must refuse an oversized r before any encoding. */
final class HwSurvivorKill8SnpAmdTest extends TestCase
{
    public function testAnROneBitAboveTheGroupOrderIsRefusedWithoutAnyWarning(): void
    {
        $key = Common::ecKeyFromPoint('P-384', "\x04"
            . hex2bin('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7')
            . hex2bin('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'));
        $r = str_repeat("\0", 48) . "\x01" . str_repeat("\0", 23); // little-endian 2^384, 72 bytes
        $s = "\x01" . str_repeat("\0", 71);
        $this->assertSame(72, strlen($r));
        $warnings = [];
        set_error_handler(static function (int $no, string $str) use (&$warnings): bool {
            $warnings[] = $str;
            return true;
        });
        try {
            $ok = Amd::verifyReportSignature(['sig_r' => $r, 'sig_s' => $s, 'signed' => str_repeat("\0", 0x2A0)], $key);
        } finally {
            restore_error_handler();
        }
        $this->assertFalse($ok);
        $this->assertSame([], $warnings);
    }
}
