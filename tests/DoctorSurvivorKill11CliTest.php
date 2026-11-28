<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Doctor.php';

use Atlas\Pca\Doctor;
use Atlas\Pca\DoctorError;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Swallows what is written to the stream it is attached to and keeps it for the test. */
final class DoctorK11Capture extends \php_user_filter
{
    public static string $buf = '';

    public function filter($in, $out, &$consumed, bool $closing): int
    {
        while ($b = stream_bucket_make_writeable($in)) {
            self::$buf .= $b->data;
            $consumed += $b->datalen;
        }
        return PSFS_PASS_ON;
    }
}

/** The doctor's configuration sources (env, files, flags), its merge, and the CLI's printed output and exit codes. */
final class DoctorSurvivorKill11CliTest extends TestCase
{
    /** @var list<string> */
    private array $files = [];

    protected function tearDown(): void
    {
        foreach ($this->files as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
    }

    private function file(string $ext, string $text): string
    {
        $p = sys_get_temp_dir() . '/pca-k11-cfg-' . bin2hex(random_bytes(6)) . $ext;
        file_put_contents($p, $text);
        $this->files[] = $p;
        return $p;
    }

    private static function refusal(callable $f): string
    {
        try {
            $f();
        } catch (DoctorError $e) {
            return $e->getMessage();
        }
        return 'accepted';
    }

    /** Env integers are ints below 9e15 and floats from there; the suite list is trimmed and compacted; pins must be a JSON object. */
    public function testConfigFromEnv(): void
    {
        $c = Doctor::configFromEnv(['TRUSTED_PROXY_COUNT' => '2', 'PCA_TRUSTED_PROXY_HOPS' => '9000000000000000', 'PCA_ALLOWED_SUITES' => ' a, ,b ']);
        self::assertSame(2, $c->get('proxy')->get('trustedProxyCount'));
        self::assertSame(9.0E15, $c->get('proxy')->get('hops'));
        self::assertSame(['a', 'b'], $c->get('verifier')->get('allowedSuites'));
        $o = Doctor::configFromEnv(Obj::of(['PCA_DOCTOR_URL' => 'https://e.example']));
        self::assertSame('https://e.example', $o->get('url'));
        self::assertSame('PCA_PQ_PINS must be a JSON object of issuer -> public key strings', self::refusal(fn() => Doctor::configFromEnv(['PCA_PQ_PINS' => '[]'])));
    }

    /** Every source is copied into the Obj / list model before the two-level merge, integer keys included. */
    public function testMergeConvertsTheModel(): void
    {
        $m = Doctor::mergeConfig(Obj::of(['clock' => ['maxSkewMs' => 5]]));
        self::assertInstanceOf(Obj::class, $m->get('clock'));
        self::assertSame(5, $m->get('clock')->get('maxSkewMs'));
        $m = Doctor::mergeConfig(['k' => [['x' => 1]]]);
        self::assertInstanceOf(Obj::class, $m->get('k')[0]);
        self::assertSame(1, $m->get('k')[0]->get('x'));
        $m = Doctor::mergeConfig([7 => 'y', 'url' => 'u']);
        self::assertSame('y', $m->get('7'));
        self::assertSame('u', $m->get('url'));
    }

    /** A .json file is parsed, a .php file must return an array or Obj, a missing file or another extension is refused by name. */
    public function testLoadConfigFile(): void
    {
        $j = $this->file('.json', '{"url":"u"}');
        self::assertSame('u', Doctor::loadConfigFile($j)->get('url'));
        $a = $this->file('.php', "<?php\nreturn ['url' => 'a'];\n");
        self::assertSame('a', Doctor::loadConfigFile($a)->get('url'));
        $o = $this->file('.php', "<?php\nreturn \\Atlas\\Pca\\Obj::of(['url' => 'o']);\n");
        self::assertSame('o', Doctor::loadConfigFile($o)->get('url'));
        $n = $this->file('.php', "<?php\nreturn 5;\n");
        self::assertSame("$n: defines no config", self::refusal(fn() => Doctor::loadConfigFile($n)));
        $missing = sys_get_temp_dir() . '/pca-k11-missing-' . bin2hex(random_bytes(6)) . '.json';
        self::assertSame("cannot read $missing", self::refusal(fn() => Doctor::loadConfigFile($missing)));
        self::assertSame('only a .json or .php config file can be loaded: x.yaml', self::refusal(fn() => Doctor::loadConfigFile('x.yaml')));
    }

    /** Numeric flags are ints when integral and below 2^53, else floats; groups drop empty names; a flag left without a value unsets it. */
    public function testParseArgs(): void
    {
        $a = Doctor::parseDoctorArgs(['--max-skew-ms', '1.5', '--trusted-proxy-count', '0', '--proxy-hops', '9007199254740992', '--only', ',clock,,store']);
        self::assertSame(1.5, $a->get('flags')->get('clock')->get('maxSkewMs'));
        self::assertSame(0, $a->get('flags')->get('proxy')->get('trustedProxyCount'));
        self::assertSame(9007199254740992.0, $a->get('flags')->get('proxy')->get('hops'));
        self::assertSame(['clock', 'store'], $a->get('only'));
        self::assertSame(5, Doctor::parseDoctorArgs(['--max-skew-ms', '5'])->get('flags')->get('clock')->get('maxSkewMs'));
        self::assertTrue(Doctor::parseDoctorArgs([3 => '--json'])->get('json'));
        self::assertSame('5', Doctor::parseDoctorArgs(['--url', 5])->get('flags')->get('url'));
        self::assertSame('unknown argument 1', self::refusal(fn() => Doctor::parseDoctorArgs([true])));
        self::assertSame([], Doctor::parseDoctorArgs(['--url', 'x', '--url'])->get('flags')->keys());
        $f = Doctor::parseDoctorArgs(['--store', 'a', '--store'])->get('flags');
        self::assertSame(['store'], $f->keys());
        self::assertSame([], $f->get('store')->keys());
    }

    /** --json prints JSON.stringify(v, null, 2) of target, verdict and results: undefined members are left out, undefined list items are null. */
    public function testJsonOutput(): void
    {
        $result = ['id' => 'store.atomicity', 'status' => 'pass', 'detail' => 'd',
            'observed' => ['u' => Jsx::$U, 'l' => [Jsx::$U], 'o' => Obj::of(['a' => 1])]];
        $printed = [];
        $code = Doctor::main(['--json', '--url', 'https://t.example', '--only', 'store', '--store', 'a.mjs'], [],
            static function (string $s) use (&$printed): void {
                $printed[] = $s;
            }, static function (string $s) use (&$printed): void {
                $printed[] = "err: $s";
            }, ['store' => static fn(): array => [$result]]);
        self::assertSame(0, $code);
        self::assertSame([<<<'JSON'
{
  "target": "https://t.example",
  "verdict": "pass",
  "results": [
    {
      "id": "store.atomicity",
      "status": "pass",
      "detail": "d",
      "observed": {
        "l": [
          null
        ],
        "o": {
          "a": 1
        }
      }
    }
  ]
}
JSON], $printed);
    }

    /** The text report pads the status to 4 and the id to 20, indents a fix line, and the verdict is not strict by default. */
    public function testTextReport(): void
    {
        $text = Doctor::formatResults([
            ['id' => 'x', 'status' => 'warn', 'detail' => 'd'],
            ['id' => 'y', 'status' => 'ok', 'detail' => 'e', 'remediation' => 'fix it'],
        ]);
        self::assertSame(implode("\n", [
            'pca-doctor',
            '  WARN  x' . str_repeat(' ', 19) . ' d',
            '  OK    y' . str_repeat(' ', 19) . ' e',
            str_repeat(' ', 28) . ' fix: fix it',
            'Summary: 0 pass, 1 warn, 0 fail, 0 skip -> WARN',
        ]), $text);
    }

    /** A usage error goes to stderr by default (message, blank line, usage) and exits 2. */
    public function testUsageErrorOnStderr(): void
    {
        if (!in_array('pca-k11-capture', stream_get_filters(), true)) {
            stream_filter_register('pca-k11-capture', DoctorK11Capture::class);
        }
        DoctorK11Capture::$buf = '';
        $filter = stream_filter_append(STDERR, 'pca-k11-capture', STREAM_FILTER_WRITE);
        self::assertIsResource($filter);
        $printed = [];
        try {
            $code = Doctor::main(['--bogus'], [], static function (string $s) use (&$printed): void {
                $printed[] = $s;
            });
        } finally {
            stream_filter_remove($filter);
        }
        self::assertSame(2, $code);
        self::assertSame([], $printed);
        self::assertSame("unknown argument --bogus\n\n" . Doctor::USAGE . "\n", DoctorK11Capture::$buf);
    }
}
