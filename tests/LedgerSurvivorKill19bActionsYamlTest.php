<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsYaml;
use PHPUnit\Framework\TestCase;

/**
 * mutation kills for src/ActionsYaml.php, second pass: a double-quoted scalar folded at an indent of 80 or more (the reference prints
 * its out-of-range fold character as undefined), and a block scalar whose folding pattern fails under a PCRE backtracking limit. Expected
 * texts are the reference YAML package's output for the same values.
 */
final class LedgerSurvivorKill19bActionsYamlTest extends TestCase
{
    /** Words cycled from $seed, cut to $n characters (a trailing space becomes 'x'). */
    private static function w(int $n, int $seed = 0): string
    {
        $words = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'fox', 'golf', 'hotel'];
        $s = '';
        $i = $seed;
        while (strlen($s) < $n) {
            $s .= ($s !== '' ? ' ' : '') . $words[$i++ % 8];
        }
        $s = substr($s, 0, $n);
        return str_ends_with($s, ' ') ? substr($s, 0, -1) . 'x' : $s;
    }

    private static function deep(int $d, mixed $v): mixed
    {
        for ($i = 0; $i < $d; $i++) {
            $v = [$v];
        }
        return $v;
    }

    /** At 40 nested sequences the first fold lands before the opening quote: the reference keeps all but the last two units and prints undefined. */
    public function testQuotedFoldAtIndentEighty(): void
    {
        $this->assertSame("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \"#" . str_repeat('a', 39) . "undefined\\\n" . str_repeat(' ', 80) . "a\\\n" . str_repeat(' ', 80) . str_repeat('a', 19) . "\\\n" . str_repeat(' ', 80) . "aaaaa\"\n", ActionsYaml::stringify(self::deep(40, '#' . str_repeat('a', 40))));
        $this->assertSame("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \"\\x01" . str_repeat('a', 13) . "\n\n" . str_repeat(' ', 80) . str_repeat('b', 17) . "undefined\\\n" . str_repeat(' ', 80) . "\"\n", ActionsYaml::stringify(self::deep(40, "\x01" . str_repeat('a', 13) . "\n" . str_repeat('b', 18))));
    }

    /** A folding pattern that hits the backtracking limit refuses the value instead of dropping the folded lines. */
    public function testFoldPatternFailureThrows(): void
    {
        $v = self::w(100);
        for ($k = 0; $k < 20; $k++) {
            $v .= "\n " . self::w(30, $k);
        }
        $v .= "\nx";
        $jit = ini_get('pcre.jit');
        $bt = ini_get('pcre.backtrack_limit');
        // 3 lets the unit split and newline patterns run (they need at most 2) and stops the folding pattern (it needs 7 with JIT, 74 without)
        ini_set('pcre.jit', '0');
        ini_set('pcre.backtrack_limit', '3');
        try {
            ActionsYaml::stringify($v);
            $msg = 'no exception';
        } catch (\RuntimeException $e) {
            $msg = get_class($e) . ': ' . $e->getMessage();
        } finally {
            ini_set('pcre.backtrack_limit', (string)$bt);
            ini_set('pcre.jit', (string)$jit);
        }
        $this->assertSame('RuntimeException: cannot fold the block scalar: Backtrack limit exhausted', $msg);
        $this->assertSame(">-\nalpha bravo charlie delta echo fox golf hotel alpha bravo charlie delta echo fox\ngolf hotel alpha br\n alpha bravo charlie delta echo\n bravo charlie delta echo fox g\n charlie delta echo fox golf ho\n delta echo fox golf hotel alph\n echo fox golf hotel alpha brav\n fox golf hotel alpha bravo cha\n golf hotel alpha bravo charlie\n hotel alpha bravo charlie delt\n alpha bravo charlie delta echo\n bravo charlie delta echo fox g\n charlie delta echo fox golf ho\n delta echo fox golf hotel alph\n echo fox golf hotel alpha brav\n fox golf hotel alpha bravo cha\n golf hotel alpha bravo charlie\n hotel alpha bravo charlie delt\n alpha bravo charlie delta echo\n bravo charlie delta echo fox g\n charlie delta echo fox golf ho\n delta echo fox golf hotel alph\nx\n", ActionsYaml::stringify($v));
    }
}
