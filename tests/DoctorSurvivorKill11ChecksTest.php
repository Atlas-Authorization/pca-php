<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Doctor.php';

use Atlas\Pca\Doctor;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** The doctor's individual checks with injected network and clock: exact status, detail and what each one sent. */
final class DoctorSurvivorKill11ChecksTest extends TestCase
{
    private const D = 784111777000.0; // Sun, 06 Nov 1994 08:49:37 GMT

    /** @param list<float> $times */
    private static function clockRun(array $clock, array $times, ?array &$timeouts = null): array
    {
        $timeouts = [];
        $fetch = static function (string $u, string $m, array $h, float $t) use (&$timeouts): array {
            $timeouts[] = [$u, $m, $t];
            return ['status' => 200, 'headers' => ['date' => 'Sun, 06 Nov 1994 08:49:37 GMT']];
        };
        $now = static function () use (&$times): float {
            return (float) array_shift($times);
        };
        return Doctor::checkClock(['url' => 'https://dep.example', 'clock' => ['referenceUrl' => 'local'] + $clock], $fetch, $now);
    }

    /** A skew whose upper bound is exactly the limit passes; the request is a HEAD with the default 10 s timeout. */
    public function testClockBoundaryAndRequest(): void
    {
        $r = self::clockRun(['maxSkewMs' => 500], [self::D + 500, self::D + 500], $calls);
        self::assertSame('pass', $r['status']);
        self::assertSame([['https://dep.example', 'HEAD', 10000.0]], $calls);
        self::assertSame(0.0, $r['observed']['skewMs']);
        self::assertSame(500.0, $r['observed']['uncertaintyMs']);
    }

    /** The printed uncertainty is in seconds with one decimal, rounded half up, and 1e21 s and above prints like String(x). */
    public function testClockUncertaintyText(): void
    {
        $r = self::clockRun([], [self::D + 500 - 750, self::D + 500 + 750]);
        self::assertStringContainsString('(+-1.3 s:', $r['detail']);
        $r = self::clockRun([], [self::D + 500 - 749, self::D + 500 + 749]);
        self::assertStringContainsString('(+-1.2 s:', $r['detail']);
        $r = self::clockRun([], [-1e24, 1e24]);
        self::assertStringContainsString('(+-1e+21 s:', $r['detail']);
    }

    /** Without an injected clock the machine's wall clock in milliseconds is used. */
    public function testClockDefaultsToTheWallClock(): void
    {
        $fetch = static fn(string $u, string $m, array $h, float $t): array => ['status' => 200, 'headers' => ['date' => gmdate('D, d M Y H:i:s', time()) . ' GMT']];
        $r = Doctor::checkClock(['url' => 'https://dep.example', 'clock' => ['referenceUrl' => 'local']], $fetch);
        self::assertLessThan(5000.0, abs($r['observed']['skewMs']));
    }

    /** @param list<mixed> $values */
    private static function probe(string $path, array $values, ?array &$calls = null): array
    {
        $calls = [];
        $fetch = static function (string $u, string $m, array $h, float $t) use (&$values, &$calls): array {
            $calls[] = [$u, $m, $t];
            $v = array_shift($values);
            return ['status' => 200, 'headers' => $v === null ? [] : ['ratelimit-remaining' => $v]];
        };
        return Doctor::checkProxyProbe(['url' => 'https://h.example/a/b?q=1', 'proxy' => ['probePath' => $path]], $fetch);
    }

    /** The probe path resolves against the deployment URL like `new URL(path, base)` (absolute, scheme-relative, rooted, empty, relative). */
    public function testProbeTargetResolution(): void
    {
        $cases = [
            'https://abs.example/z?y=2' => 'https://abs.example/z?y=2',
            '//other.example/p' => 'https://other.example/p',
            '/p?x=1' => 'https://h.example/p?x=1',
            '' => 'https://h.example/a/b?q=1',
            'c' => 'https://h.example/a/c',
        ];
        foreach ($cases as $path => $want) {
            $r = self::probe((string) $path, [5, 4, 3, 3], $calls);
            self::assertSame('pass', $r['status'], (string) $path);
            self::assertSame($want, $r['observed']['url'], (string) $path);
            self::assertSame([5.0, 4.0, 3.0, 3.0], $r['observed']['remaining']);
            self::assertSame([$want, 'GET', 10000.0], $calls[0]);
        }
        try {
            self::probe('https://[bad', [5, 4, 3, 3]);
            self::fail('an unparseable probe URL must throw');
        } catch (\Atlas\Pca\DoctorError $e) {
            self::assertSame('Invalid URL', $e->getMessage());
        }
    }

    /** A missing header on any probe is not observable; equal or rising plain counts are inconclusive, not a pass. */
    public function testProbeOutcomes(): void
    {
        self::assertSame('skip', self::probe('/p', [null, 4, 3, 3])['status']);
        self::assertSame('warn', self::probe('/p', [5, 4, 4, 4])['status']);
        self::assertSame('warn', self::probe('/p', [5, 5, 3, 4])['status']);
        self::assertSame('fail', self::probe('/p', [5, 4, 9, 3])['status']);
    }

    /** Documentation addresses: below 0.5 picks TEST-NET-2, else TEST-NET-3; the last octet is 1..254. */
    public function testForgedAddresses(): void
    {
        self::assertSame('203.0.113.128', Doctor::testNetIp(static fn(): float => 0.5));
        $seq = [0.4999, 0.0];
        self::assertSame('198.51.100.1', Doctor::testNetIp(static function () use (&$seq): float {
            return (float) array_shift($seq);
        }));
        $h = Doctor::forgedHeaders();
        $ips = explode(', ', $h['x-forwarded-for']);
        $ips[] = $h['x-real-ip'];
        self::assertCount(18, $ips);
        foreach ($ips as $ip) {
            self::assertSame(1, preg_match('/\A(?:198\.51\.100|203\.0\.113)\.([0-9]+)\z/', $ip, $m), $ip);
            self::assertTrue((int) $m[1] >= 1 && (int) $m[1] <= 254, $ip);
        }
    }

    /** A custom registry is the one checked against; a non-list allowedSuites is refused by the PQ check; pin keys print as given. */
    public function testSuitePolicies(): void
    {
        $r = Doctor::checkAllowedSuites(['verifier' => ['allowedSuites' => ['x-suite']]], ['x-suite']);
        self::assertSame(['id' => 'suites.allowed', 'status' => 'pass', 'detail' => 'allowedSuites = x-suite'], $r);
        try {
            Doctor::checkPqBinding(['verifier' => ['allowedSuites' => 'ed25519']]);
            self::fail('a non-list allowedSuites must throw');
        } catch (\TypeError $e) {
            self::assertSame('allowedSuites.filter is not a function', $e->getMessage());
        }
        $r = Doctor::checkPqBinding(['verifier' => ['pqPins' => ['5' => 'abc']]]);
        self::assertSame('fail', $r['status']);
        self::assertSame('pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): 5', $r['detail']);
    }

    /** The runtime check lists exactly the verifiable suites, the rest, and six extensions; only a listed unverifiable suite warns. */
    public function testRuntimeSuites(): void
    {
        $avail = array_values(array_filter(Pca::REGISTERED_SUITES, static fn(string $s): bool => Pca::suiteAvailable($s)));
        $missing = array_values(array_diff(Pca::REGISTERED_SUITES, $avail));
        $extras = [];
        foreach (['sodium', 'openssl', 'gmp', 'intl', 'mbstring', 'ffi'] as $ext) {
            $extras[$ext] = extension_loaded($ext);
        }
        $pass = ['id' => 'suites.runtime', 'status' => 'pass', 'detail' => 'verifiable in this runtime (' . count($avail) . ' of ' . count(Pca::REGISTERED_SUITES)
            . ' registered suites): ' . implode(', ', $avail), 'observed' => ['available' => $avail, 'unavailable' => $missing, 'extras' => $extras]];
        self::assertSame($pass, Doctor::checkRuntime());
        self::assertSame($pass, Doctor::checkRuntime(['verifier' => ['allowedSuites' => 'ed25519']]));
        self::assertSame($pass, Doctor::checkRuntime(['verifier' => ['allowedSuites' => ['ed25519']]]));
        self::assertSame($pass, Doctor::checkRuntime(['verifier' => ['allowedSuites' => [5]]]));
        if ($missing === []) {
            self::assertSame(Pca::REGISTERED_SUITES, $avail);
            return;
        }
        $r = Doctor::checkRuntime(['verifier' => ['allowedSuites' => [$missing[0], 'ed25519']]]);
        self::assertSame('warn', $r['status']);
        self::assertSame('allowedSuites names suite(s) this PHP runtime cannot verify (they are refused, fail closed): ' . $missing[0]
            . '. Verifiable here: ' . implode(', ', $avail), $r['detail']);
    }

    /** A configured adapter with no injected store check fails both store checks; an injected check's results come back as a list. */
    public function testStoreChecks(): void
    {
        $detail = "a store adapter is configured (./a.mjs) but this runtime has no store check injected (deps['store']): the store was NOT exercised";
        self::assertSame([
            ['id' => 'store.atomicity', 'status' => 'fail', 'detail' => $detail, 'remediation' => Doctor::ATOMICITY_REMEDIATION],
            ['id' => 'store.durability', 'status' => 'fail', 'detail' => $detail, 'remediation' => Doctor::DURABILITY_REMEDIATION],
        ], Doctor::checkStore(['store' => ['adapter' => './a.mjs']]));
        self::assertSame([['id' => 's']], Doctor::checkStore(['store' => ['adapter' => './a.mjs']], static fn(): array => ['x' => ['id' => 's']]));
    }

    /** A require string is a substring test that must keep every default, and is then refused as not a list; list items print as JS strings. */
    public function testEnforcementRequire(): void
    {
        $all = implode(' ', Doctor::DEFAULT_REQUIRED);
        try {
            Doctor::checkEnforcement(['verifier' => ['require' => $all]]);
            self::fail('a require string with every default must reach the join');
        } catch (\TypeError $e) {
            self::assertSame('require.join is not a function', $e->getMessage());
        }
        $r = Doctor::checkEnforcement(['verifier' => ['require' => 'replay']]);
        self::assertSame('warn', $r['status']);
        self::assertSame('the require list drops default check(s): counter_format, revocation, plan_root_authorized, audience, validity, grant_ref_bound', $r['detail']);
        $r = Doctor::checkEnforcement(['verifier' => ['require' => [...Doctor::DEFAULT_REQUIRED, true, null]]]);
        self::assertSame(['id' => 'verifier.enforcement', 'status' => 'pass', 'detail' => 'require = ' . implode(', ', Doctor::DEFAULT_REQUIRED) . ', true, '], $r);
    }

    /** A NaN duration is a configuration error; a group that throws is reported as its own failed check. */
    public function testConfigErrorsAndGuardedGroups(): void
    {
        self::assertSame(['clock.maxSkewMs must be a positive number'], Doctor::configProblems(['clock' => ['maxSkewMs' => NAN]]));
        $boom = static function (): array {
            throw new \RuntimeException('boom');
        };
        self::assertSame([['id' => 'store', 'status' => 'fail', 'detail' => 'store could not run: boom',
            'remediation' => 'Fix the configuration or the dependency named above and run the doctor again.']],
            Doctor::runDoctor(['store' => ['adapter' => 'x']], ['store'], ['store' => $boom]));
    }

    private static function nest(mixed $v, int $n, bool $list): mixed
    {
        for ($i = 0; $i < $n; $i++) {
            $v = $list ? [$v] : ['k' => $v];
        }
        return $v;
    }

    /** Strings are scrubbed down to nesting depth 8 of lists and objects alike; a container deeper than that is left as it is. */
    public function testScrubDepth(): void
    {
        $s = 'Bearer abcdefghijkl';
        $t = 'Bearer [redacted]';
        foreach ([true, false] as $list) {
            self::assertSame(self::nest($t, 6, $list), Doctor::scrubDeep(self::nest($s, 6, $list)));
            self::assertSame(self::nest($t, 9, $list), Doctor::scrubDeep(self::nest($s, 9, $list)));
            self::assertSame(self::nest($s, 10, $list), Doctor::scrubDeep(self::nest($s, 10, $list)));
        }
    }
}
