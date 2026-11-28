<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Doctor.php';

use Atlas\Pca\Doctor;
use Atlas\Pca\DoctorPca;
use PHPUnit\Framework\TestCase;

/** The library the doctor probes: its own in-process caveat evaluation, a Composer install found under a directory, and the probe amounts. */
final class DoctorSurvivorKill11LoadTest extends TestCase
{
    private const PCA = 'atlas-auth/atlas-pca';

    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $d) {
            foreach (['/vendor/composer/installed.json', '/vendor/autoload.php'] as $f) {
                if (is_file($d . $f)) {
                    unlink($d . $f);
                }
            }
            foreach (['/vendor/composer', '/vendor', ''] as $s) {
                if (is_dir($d . $s)) {
                    rmdir($d . $s);
                }
            }
        }
    }

    /** A fake application directory: vendor/autoload.php (when given) and vendor/composer/installed.json (when given). */
    private function app(?string $autoload, mixed $installed): string
    {
        $d = sys_get_temp_dir() . '/pca-k11-app-' . bin2hex(random_bytes(6));
        mkdir($d . '/vendor/composer', 0777, true);
        $this->dirs[] = $d;
        if ($autoload !== null) {
            file_put_contents("$d/vendor/autoload.php", $autoload);
        }
        if ($installed !== null) {
            file_put_contents("$d/vendor/composer/installed.json", (string) json_encode($installed));
        }
        return $d;
    }

    private static function realAutoload(): string
    {
        return "<?php\nif (getenv('PCA_K11_ENV_MARK') !== 'inherited') {\n    fwrite(STDERR, \"caller environment not inherited\\n\");\n    exit(3);\n}\n"
            . 'require ' . var_export(dirname(__DIR__) . '/vendor/autoload.php', true) . ";\n";
    }

    private static function refusal(callable $f): string
    {
        try {
            $f();
        } catch (\RuntimeException $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'accepted';
    }

    /** The in-process probe decides a payment through the caveat evaluation, numbers passed as JSON number lexemes. */
    public function testProbeDecision(): void
    {
        $cap = ['type' => 'max_spend', 'usd' => 100];
        self::assertSame(['allowed' => true, 'reasons' => []], Doctor::probeDecision($cap, 50));
        self::assertSame(['allowed' => false, 'reasons' => ['max_spend']], Doctor::probeDecision($cap, 150));
        self::assertSame(['allowed' => false, 'reasons' => ['pca-doctor-unknown-caveat']], Doctor::probeDecision(['type' => 'pca-doctor-unknown-caveat'], 50));
        // the context carries the current time
        self::assertSame(['allowed' => true, 'reasons' => []], Doctor::probeDecision(['type' => 'not_before', 'at' => 0], 50));
        // a non-finite number is written as its text ("INF"), which reads as 0 like any other unparseable lexeme
        self::assertSame(['allowed' => true, 'reasons' => []], Doctor::probeDecision(['type' => 'not_before', 'at' => INF], 50));
        self::assertSame(['allowed' => true, 'reasons' => []], Doctor::probeDecision($cap, INF));
    }

    /** With no directory the doctor probes its own library: Composer's version of this package, this checkout, the in-process probe. */
    public function testOwnLibrary(): void
    {
        $v = class_exists(\Composer\InstalledVersions::class) && \Composer\InstalledVersions::isInstalled(self::PCA)
            ? (string) \Composer\InstalledVersions::getPrettyVersion(self::PCA) : 'unknown';
        foreach ([null, ''] as $dir) {
            $pca = Doctor::loadPca($dir);
            self::assertSame($v, $pca->version);
            self::assertSame(dirname(__DIR__), $pca->path);
            self::assertSame(['allowed' => true, 'reasons' => []], ($pca->probe)(['type' => 'max_spend', 'usd' => 100], 50));
        }
    }

    /** A directory needs both vendor/autoload.php and vendor/composer/installed.json listing this package. */
    public function testInstallIsRequired(): void
    {
        $none = sys_get_temp_dir() . '/pca-k11-none-' . bin2hex(random_bytes(6));
        $onlyInstalled = $this->app(null, ['packages' => [['name' => self::PCA, 'version' => '1.0.0']]]);
        $onlyAutoload = $this->app("<?php\n", null);
        $other = $this->app("<?php\n", ['packages' => [['name' => 'other/pkg', 'version' => '1.0.0']]]);
        foreach ([$none, $onlyInstalled, $onlyAutoload] as $d) {
            self::assertSame("RuntimeException: atlas-auth/atlas-pca is not installed in $d (no vendor/autoload.php)", self::refusal(fn() => Doctor::loadPca($d)));
        }
        self::assertSame("RuntimeException: atlas-auth/atlas-pca is not installed in $other", self::refusal(fn() => Doctor::loadPca($other)));
    }

    /** The version is this package's entry (Composer 1 list or 2 {packages}), the last one listed winning, with a leading v dropped. */
    public function testInstalledVersion(): void
    {
        $cases = [
            '1.2.3' => ['packages' => [['name' => self::PCA, 'version' => 'v1.2.3'], ['name' => 'other/pkg', 'version' => 'v9.9.9']], 'dev' => true],
            '2.0.0' => [['name' => 'other/pkg', 'version' => '1.0.0'], ['name' => self::PCA, 'version' => '2.0.0']],
            '7' => ['packages' => [['name' => self::PCA, 'version' => 7]]],
            'unknown' => ['packages' => [['name' => self::PCA]]],
        ];
        foreach ($cases as $want => $installed) {
            $d = $this->app("<?php\n", $installed);
            $pca = Doctor::loadPca($d);
            self::assertSame((string) $want, $pca->version);
            self::assertSame(realpath($d) . '/vendor/atlas-auth/atlas-pca', $pca->path);
        }
    }

    /** The installed copy is probed in a child interpreter that inherits the environment; its failures surface with their last stderr line. */
    public function testChildProbe(): void
    {
        $inst = ['packages' => [['name' => self::PCA, 'version' => '0.6.0']]];
        $ok = Doctor::loadPca($this->app(self::realAutoload(), $inst));
        $fail = Doctor::loadPca($this->app("<?php\nfwrite(STDERR, \"first line\\nlast line\\n\");\nexit(3);\n", $inst));
        $garbage = Doctor::loadPca($this->app("<?php\necho 'not json';\nexit(0);\n", $inst));
        $cap = ['type' => 'max_spend', 'usd' => 100];
        putenv('PCA_K11_ENV_MARK=inherited');
        try {
            self::assertSame(['allowed' => true, 'reasons' => []], ($ok->probe)($cap, 50));
            self::assertSame(['allowed' => false, 'reasons' => ['max_spend']], ($ok->probe)($cap, 150));
            self::assertSame('RuntimeException: last line', self::refusal(fn() => ($fail->probe)($cap, 50)));
            self::assertSame('RuntimeException: probe failed', self::refusal(fn() => ($garbage->probe)($cap, 50)));
        } finally {
            putenv('PCA_K11_ENV_MARK');
        }
    }

    /** The root-caveat check probes max_spend 100 at 150 and 50 and an unknown caveat at 50, through the loader given the configured directory. */
    public function testRootCaveatProbeAmounts(): void
    {
        $calls = [];
        $dirs = [];
        $load = static function (?string $dir) use (&$calls, &$dirs): DoctorPca {
            $dirs[] = $dir;
            return new DoctorPca('0.6.0', '/k11/lib', static function (array $cv, int|float $amount) use (&$calls): array {
                $calls[] = [$cv, $amount];
                return ['allowed' => $cv['type'] === 'max_spend' && $amount <= $cv['usd'], 'reasons' => []];
            });
        };
        $r = Doctor::checkRootCaveats(['verifier' => ['pcaDir' => '/k11/app']], $load);
        self::assertSame(['/k11/app'], $dirs);
        self::assertSame([
            [['type' => 'max_spend', 'usd' => 100], 150],
            [['type' => 'max_spend', 'usd' => 100], 50],
            [['type' => 'pca-doctor-unknown-caveat'], 50],
        ], $calls);
        self::assertSame('pass', $r['status']);
        self::assertSame('@atlasauth/pca 0.6.0 at /k11/lib: root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)', $r['detail']);
    }
}
