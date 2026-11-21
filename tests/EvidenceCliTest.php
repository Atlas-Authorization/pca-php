<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\EvidenceCli;
use PHPUnit\Framework\TestCase;

/** The pca-evidence command line: usage and parse errors exit 2, a malformed bundle fails the replay (exit 1) and the digest command refuses it. */
final class EvidenceCliTest extends TestCase
{
    /** @return array{0:int,1:string,2:string} */
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

    /** @param array<string,string> $files @param callable(array<string,string>):void $body */
    private static function withFiles(array $files, callable $body): void
    {
        $dir = sys_get_temp_dir() . '/pca-evidence-cli-' . bin2hex(random_bytes(6));
        mkdir($dir);
        $paths = [];
        try {
            foreach ($files as $name => $text) {
                $paths[$name] = "$dir/$name";
                file_put_contents($paths[$name], $text);
            }
            $body($paths);
        } finally {
            foreach ($paths as $p) {
                @unlink($p);
            }
            @rmdir($dir);
        }
    }

    public function testUsageErrorsExitTwo(): void
    {
        self::assertSame(2, self::cli()[0]);
        self::assertSame(2, self::cli('nope')[0]);
        self::assertSame(2, self::cli('verify')[0]);
        self::assertSame(2, self::cli('digest', '--trust', 'x', 'f')[0]);
        self::assertSame(2, self::cli('verify', 'a', 'b')[0]);
    }

    public function testUnreadableAndUnknownTrustExitTwo(): void
    {
        self::assertSame(2, self::cli('verify', '/nonexistent/bundle.json')[0]);
        self::withFiles(['b.json' => '{}', 't.json' => '{"bogus":1}'], function (array $p): void {
            [$code, , $err] = self::cli('verify', $p['b.json'], '--trust', $p['t.json']);
            self::assertSame(2, $code);
            self::assertStringContainsString('unknown trust member "bogus"', $err);
        });
    }

    public function testAMalformedBundleFailsTheReplayAndTheDigestRefusesIt(): void
    {
        self::withFiles(['b.json' => '{"v":1}'], function (array $p): void {
            [$code, $out] = self::cli('verify', $p['b.json']);
            self::assertSame(1, $code);
            self::assertStringContainsString('FAILED', $out);
            self::assertStringContainsString('report ', $out);
            self::assertSame(1, self::cli('verify', $p['b.json'], '--json')[0]);
            [$code, , $err] = self::cli('digest', $p['b.json']);
            self::assertSame(2, $code);
            self::assertStringContainsString('pca-evidence: ', $err);
        });
    }
}
