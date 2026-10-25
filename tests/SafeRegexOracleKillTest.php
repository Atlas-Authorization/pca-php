<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\SafeRegex;
use PHPUnit\Framework\TestCase;

/**
 * Differential kill test for SafeRegex.php against the TS reference (safe-regex.ts + predicates.ts isSafeRegexSource): every
 * pattern of test-data/k042-saferegex.txt.gz (tools/pca-audit/java-mutate/k042-saferegex-oracle.mjs) must compile to the EXACT
 * same NFA program (op, x, y, set ranges, negation, instruction for instruction) or be refused alike, get the same
 * isSafeRegexSource verdict, and full-match every recorded subject with the same true / false / null.
 * Lines: `P <hex units> <safe 0|1> <program|N>` then `M <hex units> <T|F|N>` per subject.
 */
final class SafeRegexOracleKillTest extends TestCase
{
    /** @return list<int> UTF-16 code units of a hex dump (4 hex digits each; "-" = empty) */
    private static function unitsOf(string $h): array
    {
        $u = [];
        for ($k = 0; $h !== '-' && $k < strlen($h); $k += 4) {
            $u[] = (int) hexdec(substr($h, $k, 4));
        }
        return $u;
    }

    /** Units to a (WTF-8) string: valid surrogate pairs as one 4-byte character, a lone surrogate as 3 bytes. */
    private static function wtf8(array $u): string
    {
        $s = '';
        $n = count($u);
        for ($i = 0; $i < $n; $i++) {
            $c = $u[$i];
            if ($c >= 0xD800 && $c <= 0xDBFF && $i + 1 < $n && $u[$i + 1] >= 0xDC00 && $u[$i + 1] <= 0xDFFF) {
                $c = 0x10000 + (($c - 0xD800) << 10) + ($u[++$i] - 0xDC00);
            }
            if ($c < 0x80) {
                $s .= chr($c);
            } elseif ($c < 0x800) {
                $s .= chr(0xC0 | ($c >> 6)) . chr(0x80 | ($c & 0x3F));
            } elseif ($c < 0x10000) {
                $s .= chr(0xE0 | ($c >> 12)) . chr(0x80 | (($c >> 6) & 0x3F)) . chr(0x80 | ($c & 0x3F));
            } else {
                $s .= chr(0xF0 | ($c >> 18)) . chr(0x80 | (($c >> 12) & 0x3F)) . chr(0x80 | (($c >> 6) & 0x3F)) . chr(0x80 | ($c & 0x3F));
            }
        }
        return $s;
    }

    /** The oracle's program dump (a dump over 1000 characters is its SHA-256). */
    private static function dump(?array $prog): string
    {
        if ($prog === null) {
            return 'N';
        }
        $parts = [];
        foreach ($prog as [$op, $x, $y, $set, $neg]) {
            $p = "$op,$x,$y,";
            if ($set === null) {
                $p .= '-,-';
            } else {
                $p .= ($neg ? 1 : 0) . ',';
                $p .= $set === [] ? 'E' : implode(':', array_map(fn($r) => $r[0] . '-' . $r[1], $set));
            }
            $parts[] = $p;
        }
        $s = implode(';', $parts);
        return strlen($s) > 1000 ? 'H' . hash('sha256', $s) : $s;
    }

    private static function show(string $s): string
    {
        return strlen($s) > 80 ? substr(json_encode($s, JSON_INVALID_UTF8_SUBSTITUTE) ?: '?', 0, 80) . '...' : (json_encode($s, JSON_INVALID_UTF8_SUBSTITUTE) ?: '?');
    }

    public function testCorpusMatchesTheTsReference(): void
    {
        $fails = [];
        $patterns = $compiled = $safe = $matches = 0;
        $fh = gzopen(__DIR__ . '/../test-data/k042-saferegex.txt.gz', 'rb');
        $this->assertNotFalse($fh);
        $pat = '';
        $cur = null;
        $first = false;
        while (($line = gzgets($fh)) !== false) {
            $f = explode(' ', rtrim($line, "\n"));
            if ($f[0] === 'P') {
                $patterns++;
                $pat = self::wtf8(self::unitsOf($f[1]));
                $cur = SafeRegex::compile($pat);
                $got = self::dump($cur);
                $compiled += $cur === null ? 0 : 1;
                if ($got !== $f[3]) {
                    $fails[] = 'compile /' . self::show($pat) . '/: want ' . substr($f[3], 0, 120) . ' got ' . substr($got, 0, 120);
                }
                $gotSafe = SafeRegex::isSafeRegexSource($pat);
                $safe += $gotSafe ? 1 : 0;
                if ($gotSafe !== ($f[2] === '1')) {
                    $fails[] = 'isSafeRegexSource /' . self::show($pat) . '/: want ' . $f[2];
                }
                if ($cur === null && SafeRegex::fullMatch($pat, 'a') !== null) {
                    $fails[] = 'fullMatch on refused /' . self::show($pat) . '/ not null';
                }
                $first = true;
            } else {
                $matches++;
                $want = $f[2] === 'N' ? null : $f[2] === 'T';
                if ($cur === null) {
                    $fails[] = 'subject for a refused pattern /' . self::show($pat) . '/';
                    continue;
                }
                $subj = self::unitsOf($f[1]);
                $got = SafeRegex::run($cur, $subj);
                if ($got !== $want) {
                    $fails[] = 'run /' . self::show($pat) . '/ on ' . self::show(self::wtf8($subj)) . ': want ' . var_export($want, true);
                }
                if ($first) {
                    $fm = SafeRegex::fullMatch($pat, self::wtf8($subj));
                    if ($fm !== $want) {
                        $fails[] = 'fullMatch /' . self::show($pat) . '/ on ' . self::show(self::wtf8($subj)) . ': want ' . var_export($want, true);
                    }
                    $first = false;
                }
            }
            if (count($fails) >= 5) {
                break;
            }
        }
        gzclose($fh);
        $this->assertSame([], $fails);
        // the generator's own counts: a truncated or regenerated-differently file must not pass silently
        $this->assertSame(8648, $patterns);
        $this->assertSame(5267, $compiled);
        $this->assertSame(3206, $safe);
        $this->assertSame(572525, $matches);
    }
}
