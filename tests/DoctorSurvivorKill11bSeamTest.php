<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Doctor.php';

use Atlas\Pca\Doctor;
use Atlas\Pca\FalconBackend;
use Atlas\Pca\Fndsa;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Doctor checks that read the runtime, the clock or randomness, with each one pinned so the expected values are exact. */
final class DoctorSurvivorKill11bSeamTest extends TestCase
{
    /** Run $f with ML-DSA-65 unavailable and FN-DSA available (an unavailable suite before an available one in registry order). */
    private static function withSuites(callable $f): mixed
    {
        $cur = new \ReflectionProperty(Fndsa::class, 'current');
        $probed = new \ReflectionProperty(OpensslPq::class, 'probed');
        $savedCur = $cur->getValue();
        $savedProbed = $probed->getValue();
        try {
            $cur->setValue(null, new FalconBackend(static fn(string $pk, string $msg, string $sig): bool => false));
            $probed->setValue(null, ['ML-DSA-65' => false] + $savedProbed);
            return $f();
        } finally {
            $cur->setValue(null, $savedCur);
            $probed->setValue(null, $savedProbed);
        }
    }

    /** The runtime check lists the verifiable and unverifiable suites as lists, and warns about exactly the listed unverifiable ones. */
    public function testRuntimeWithAnUnavailableSuite(): void
    {
        [$avail, $pass, $warn] = self::withSuites(static function (): array {
            $avail = array_values(array_filter(Pca::REGISTERED_SUITES, static fn(string $s): bool => Pca::suiteAvailable($s)));
            return [$avail, Doctor::checkRuntime(), Doctor::checkRuntime(['verifier' => ['allowedSuites' => ['ml-dsa-65', 'ed25519', 5]]])];
        });
        $missing = array_values(array_diff(Pca::REGISTERED_SUITES, $avail));
        self::assertContains('ed25519', $avail);
        self::assertContains('fn-dsa-512', $avail);
        self::assertContains('ml-dsa-65', $missing);
        $extras = [];
        foreach (['sodium', 'openssl', 'gmp', 'intl', 'mbstring', 'ffi'] as $ext) {
            $extras[$ext] = extension_loaded($ext);
        }
        $observed = ['available' => $avail, 'unavailable' => $missing, 'extras' => $extras];
        self::assertSame(['id' => 'suites.runtime', 'status' => 'pass', 'detail' => 'verifiable in this runtime (' . count($avail) . ' of '
            . count(Pca::REGISTERED_SUITES) . ' registered suites): ' . implode(', ', $avail), 'observed' => $observed], $pass);
        self::assertSame(['id' => 'suites.runtime', 'status' => 'warn',
            'detail' => 'allowedSuites names suite(s) this PHP runtime cannot verify (they are refused, fail closed): ml-dsa-65. Verifiable here: ' . implode(', ', $avail),
            'remediation' => 'Build PHP against OpenSSL >= 3.5 (post-quantum suites), enable ext-ffi for the LESS suites, or drop the suite from allowedSuites.',
            'observed' => $observed], $warn);
    }

    /** The probe's "now" is whole milliseconds: a not_before 0.5 ms past the truncated time is not yet reached. */
    public function testProbeTimeIsWholeMilliseconds(): void
    {
        Doctor::$clockHook = static fn(): float => 1000.0006;
        try {
            self::assertSame(['allowed' => false, 'reasons' => ['not_before']], Doctor::probeDecision(['type' => 'not_before', 'at' => 1000000.5], 50));
            self::assertSame(['allowed' => true, 'reasons' => []], Doctor::probeDecision(['type' => 'not_before', 'at' => 1000000], 50));
        } finally {
            Doctor::$clockHook = null;
        }
    }

    /** Randomness is a draw in 0..2^28-1 scaled into [0, 1): the midpoint picks TEST-NET-3 and octet 128. */
    public function testRandomDrawBounds(): void
    {
        $calls = [];
        Doctor::$randomHook = static function (int $min, int $max) use (&$calls): int {
            $calls[] = [$min, $max];
            return 134217728;
        };
        try {
            self::assertSame('203.0.113.128', Doctor::testNetIp());
        } finally {
            Doctor::$randomHook = null;
        }
        self::assertSame([[0, 268435455], [0, 268435455]], $calls);
    }
}
