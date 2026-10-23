<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\LessFfi;
use Atlas\Pca\OpensslPq;
use PHPUnit\Framework\TestCase;

/**
 * The capability probes. Where CI promises a PQ-capable libcrypto (PCA_REQUIRE_MLDSA=1) or libatlas_less (ATLAS_PCA_LIBLESS),
 * the probe must say so: a probe that wrongly reports "unavailable" silently turns every PQ test into a skip.
 */
final class PqProbeKillTest extends TestCase
{
    public function testEveryOpensslPqTypeIsAvailableWhereCiPromisesIt(): void
    {
        if (getenv('PCA_REQUIRE_MLDSA') !== '1') {
            $this->markTestSkipped('PCA_REQUIRE_MLDSA is not set: no OpenSSL >= 3.5 promised here');
        }
        foreach (array_keys(OpensslPq::KEY_TYPES) as $type) {
            $this->assertTrue(OpensslPq::available($type), "$type must be available on an OpenSSL >= 3.5 libcrypto");
        }
        $this->assertFalse(OpensslPq::available('ML-DSA-44'), 'an unregistered type is never available');
    }

    public function testOpensslPqVerifyRefusesWrongLengthsAndForgeries(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->markTestSkipped('no ML-DSA-65 in this libcrypto');
        }
        [$pkLen, $sigLen] = OpensslPq::KEY_TYPES['ML-DSA-65'];
        $pk = str_repeat("\x01", $pkLen);
        $this->assertFalse(OpensslPq::verify('ML-DSA-65', $pk, 'm', str_repeat("\x00", $sigLen)), 'an all-zero signature is a forgery');
        $this->assertFalse(OpensslPq::verify('ML-DSA-65', $pk, 'm', str_repeat("\x00", $sigLen - 1)), 'one byte short');
        $this->assertFalse(OpensslPq::verify('ML-DSA-65', substr($pk, 1), 'm', str_repeat("\x00", $sigLen)), 'short key');
    }

    public function testLessIsAvailableWhereCiShipsTheLibrary(): void
    {
        if ((string) getenv('ATLAS_PCA_LIBLESS') === '') {
            $this->markTestSkipped('no libatlas_less configured');
        }
        $this->assertTrue(LessFfi::available());
    }

    /** With the library missing, verify fails closed (a fresh process: the FFI handle is cached per process). */
    public function testLessVerifyFailsClosedWithoutTheLibrary(): void
    {
        $autoload = dirname(__DIR__) . '/vendor/autoload.php';
        $code = 'require ' . var_export($autoload, true) . ';'
            . '$pk = str_repeat("\x01", \Atlas\Pca\LessFfi::PUBLIC_KEY_BYTES);'
            . '$sig = str_repeat("\x00", \Atlas\Pca\LessFfi::SIGNATURE_MAX_BYTES);'
            . 'echo json_encode([\Atlas\Pca\LessFfi::available(), \Atlas\Pca\LessFfi::verify($pk, "m", $sig)]);';
        $env = ['ATLAS_PCA_LIBLESS' => '/nonexistent/libatlas_less.so', 'PATH' => (string) getenv('PATH')];
        $p = proc_open([PHP_BINARY, '-d', 'ffi.enable=1', '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
        $this->assertIsResource($p);
        $out = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($p);
        // a system-wide libatlas_less could still be found; either way the zero signature never verifies
        $r = json_decode((string) $out, true);
        $this->assertIsArray($r, "child output: $out");
        $this->assertFalse($r[1]);
    }
}
