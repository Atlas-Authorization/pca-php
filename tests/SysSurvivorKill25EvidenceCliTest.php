<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Evidence;
use Atlas\Pca\EvidenceCli;
use Atlas\Pca\EvidenceVerify;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use PHPUnit\Framework\TestCase;

/**
 * Group 25 kills for src/EvidenceCli.php over the reference's consistent-but-unpinned bundle (test-data/ref-evidence-bundle-py.json.gz,
 * "no trust#1"): exit codes 0/1/2/3, the exact text and JSON reports, the usage paths, the trust-file gates and the default sinks.
 */
final class SysSurvivorKill25EvidenceCliTest extends TestCase
{
    private const CASE = 'verifyEvidenceBundle/no trust#1';
    private const USAGE = "usage: pca-evidence verify <bundle.json> [--trust trust.json] [--json] [--allow-unpinned]\n       pca-evidence digest <bundle.json>";
    private const PRINCIPAL = 'A2Dt8aB8KSXfA_eN9I5UX20S9k52oJV7040ICS4aBP4';

    private static ?string $bundleJson = null;
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/pca-k25-evcli-' . getmypid() . '-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        EvidenceCli::$stdoutStream = null;
        EvidenceCli::$stderrStream = null;
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    private static function bundleJson(): string
    {
        if (self::$bundleJson === null) {
            $h = gzopen(__DIR__ . '/../test-data/ref-evidence-bundle-py.json.gz', 'rb');
            self::assertNotFalse($h);
            $line = null;
            while (($l = gzgets($h)) !== false) {
                if (str_contains(substr($l, 0, 200), '"name":"' . self::CASE . '"')) {
                    $line = rtrim(rtrim($l, "\r\n"), ',');
                    break;
                }
            }
            gzclose($h);
            self::assertNotNull($line, 'corpus case missing');
            self::$bundleJson = Js::stringify((new Parser($line, PHP_INT_MAX))->run()->get('args')[0]);
        }
        return self::$bundleJson;
    }

    private function file(string $name, string $text): string
    {
        $p = $this->dir . '/' . $name;
        file_put_contents($p, $text);
        return $p;
    }

    /** @return array{0:int,1:string,2:string} exit code, stdout lines, stderr lines */
    private static function cli(string ...$argv): array
    {
        $out = [];
        $err = [];
        $code = EvidenceCli::main($argv, static function (string $s) use (&$out): void {
            $out[] = $s;
        }, static function (string $s) use (&$err): void {
            $err[] = $s;
        });
        return [$code, implode("\n", $out), implode("\n", $err)];
    }

    private static function report(): Obj
    {
        return EvidenceVerify::verifyEvidenceBundle(Json::parseStrict(self::bundleJson()), new Obj());
    }

    /** The text report of a consistent, unpinned bundle: verdict line, every finding, both summaries, the report digest. */
    private static function expectedText(Obj $r, string $verdict): string
    {
        $lines = ['bundle ' . $r->get('digest') . ": $verdict (incomplete: some artifacts not verified here)"];
        foreach ($r->get('findings') as $x) {
            $refs = $x->get('refs');
            $lines[] = '[' . $x->get('status') . '] ' . $x->get('code') . ($refs === [] ? '' : ' ' . implode(' ', $refs)) . ': ' . $x->get('text');
        }
        $lines[] = 'Proven:';
        foreach ($r->get('summary')->get('proven') as $s) {
            $lines[] = '  - ' . $s;
        }
        $lines[] = 'Not proven:';
        foreach ($r->get('summary')->get('not_proven') as $s) {
            $lines[] = '  - ' . $s;
        }
        $lines[] = 'report ' . $r->get('report_digest');
        return implode("\n", $lines);
    }

    /** A consistent bundle without pinned principals exits 3 with the exact report and the out-of-band warning. */
    public function testUnattributedBundleExitsThree(): void
    {
        $b = $this->file('b.json', self::bundleJson());
        $r = self::report();
        $this->assertTrue($r->get('consistent'));
        $this->assertFalse($r->get('attributed'));
        $this->assertFalse($r->get('complete'));
        $this->assertNotSame([], array_filter($r->get('findings'), static fn(Obj $x): bool => $x->get('refs') === []), 'control: a finding without refs');
        $this->assertSame([3, self::expectedText($r, 'CONSISTENT BUT NOT ATTRIBUTED'),
            'pca-evidence: the bundle is internally consistent but NOT attributed to any known principal (no pinned "principals" in the trust file). '
            . 'Keys to verify out of band: ' . self::PRINCIPAL . '. Pass --allow-unpinned to accept anyway.'], self::cli('verify', $b));
    }

    /** --allow-unpinned accepts it (exit 0) and still prints the keys to verify. */
    public function testAllowUnpinnedExitsZero(): void
    {
        $b = $this->file('b.json', self::bundleJson());
        $this->assertSame([0, self::expectedText(self::report(), 'CONSISTENT BUT NOT ATTRIBUTED'), 'pca-evidence: principal keys to verify out of band: ' . self::PRINCIPAL],
            self::cli('verify', '--allow-unpinned', $b));
    }

    /** Pinning the bundle's principal attributes it: exit 0 and an OK verdict. */
    public function testPinnedPrincipalExitsZero(): void
    {
        $b = $this->file('b.json', self::bundleJson());
        $t = $this->file('t.json', '{"principals":[{"key":"' . self::PRINCIPAL . '"}]}');
        [$code, $out, $err] = self::cli('verify', $b, '--trust', $t);
        $this->assertSame('', $err);
        $this->assertSame(0, $code);
        $this->assertStringStartsWith('bundle ' . self::report()->get('digest') . ': OK (incomplete: some artifacts not verified here)' . "\n", $out);
    }

    /** --json prints the report as two-space pretty JSON (nested indentation, one value per line). */
    public function testJsonReport(): void
    {
        $b = $this->file('b.json', self::bundleJson());
        [$code, $out, $err] = self::cli('verify', $b, '--json');
        $this->assertSame(3, $code);
        $this->assertStringContainsString('Keys to verify out of band', $err);
        $compact = Js::stringify(self::report());
        $this->assertEquals(json_decode($compact), json_decode($out), 'the same report');
        $reference = json_encode(json_decode($compact), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $this->assertSame(substr_count((string) $reference, "\n"), substr_count($out, "\n"), 'one value per line');
        $depth = 0;
        foreach (explode("\n", $out) as $i => $line) {
            $t = ltrim($line, ' ');
            if ($t !== '' && ($t[0] === '}' || $t[0] === ']')) {
                $depth--;
            }
            $this->assertSame(str_repeat('  ', $depth), substr($line, 0, strlen($line) - strlen($t)), "indentation of line $i");
            $last = substr(rtrim($t, ','), -1);
            if ($last === '{' || $last === '[') {
                $depth++;
            }
        }
        $this->assertSame(0, $depth);
        $this->assertStringStartsWith("{\n  \"ok\": false,\n  \"consistent\": true,", $out);
    }

    /** digest prints the evidence digest and exits 0. */
    public function testDigest(): void
    {
        $b = $this->file('b.json', self::bundleJson());
        $this->assertSame([0, Evidence::evidenceDigest(Json::parseStrict(self::bundleJson())), ''], self::cli('digest', $b));
    }

    /** Every usage error prints the usage text and exits 2, even when a readable bundle is named. */
    public function testUsagePaths(): void
    {
        $b = $this->file('b.json', self::bundleJson());
        $usage = [2, '', self::USAGE];
        $this->assertSame($usage, self::cli('nope', $b));
        $this->assertSame($usage, self::cli('verify', $b, '--trust'));
        $this->assertSame($usage, self::cli('verify', $b, $b));
        $this->assertSame($usage, self::cli('verify', '--bogus', $b));
        $this->assertSame($usage, self::cli('digest', '--allow-unpinned', $b));
        $this->assertSame($usage, self::cli('verify', '--json'));
    }

    /** Unreadable inputs and malformed trust files exit 2 with the exact reason. */
    public function testTrustAndReadRefusals(): void
    {
        $b = $this->file('b.json', self::bundleJson());
        $this->assertSame([2, '', 'pca-evidence: cannot read ' . $this->dir], self::cli('verify', $this->dir));
        foreach ([
            '[1]' => 'trust file must be a JSON object',
            '{"bogus":1}' => 'unknown trust member "bogus"',
            '{"acc":5}' => 'trust.acc must be an object',
            '{"principals":[]}' => 'trust.principals must be a non-empty array of {key, pq_pk?}',
        ] as $text => $why) {
            $t = $this->file('t.json', $text);
            $this->assertSame([2, '', 'pca-evidence: ' . $why], self::cli('verify', $b, '--trust', $t), $text);
        }
    }

    /** Without sinks, output goes to stdout and errors to stderr, one line each. */
    public function testDefaultSinks(): void
    {
        $b = $this->file('b.json', self::bundleJson());
        $o = fopen('php://memory', 'w+');
        $e = fopen('php://memory', 'w+');
        EvidenceCli::$stdoutStream = $o;
        EvidenceCli::$stderrStream = $e;
        $this->assertSame(0, EvidenceCli::main(['digest', $b]));
        $this->assertSame(2, EvidenceCli::main(['nope']));
        rewind($o);
        rewind($e);
        $this->assertSame(Evidence::evidenceDigest(Json::parseStrict(self::bundleJson())) . "\n", stream_get_contents($o));
        $this->assertSame(self::USAGE . "\n", stream_get_contents($e));
    }
}
