<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsYaml;
use Atlas\Pca\Obj;
use Atlas\Pca\YamlSeq;
use PHPUnit\Framework\TestCase;

/**
 * mutation kills for src/ActionsYaml.php: folding at the width bounds (deep indents, long keys, anchors), escapes at the fold point, block
 * scalar headers and indents, line-length limits, UTF-16 surrogate handling and the scalar refusals. Expected texts are the reference YAML
 * package's output for the same values.
 */
final class LedgerSurvivorKill19ActionsYamlTest extends TestCase
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

    /** @param list<int> $spaces */
    private static function sp(int $n, array $spaces): string
    {
        $s = str_repeat('a', $n);
        foreach ($spaces as $p) {
            $s[$p] = ' ';
        }
        return $s;
    }

    /** @return array<string,mixed> */
    private static function cases(): array
    {
        $long = self::w(150);
        $c = [
            'k58' => Obj::of([str_repeat('k', 58) => $long]),
            'k59' => Obj::of([str_repeat('k', 59) => $long]),
            'deep31' => self::deep(31, $long),
            'deep31b' => self::deep(31, self::w(60) . "\n" . self::w(120, 3) . "\nend"),
            'moreInd' => ' ' . self::w(100) . "\nx",
            'moreInd2' => "\n " . self::w(100) . "\nb",
            'moreInd3' => Obj::of(['k' => ' ' . self::w(100) . "\nx"]),
            'dm78' => '--- ' . str_repeat('a', 74),
            'line80' => str_repeat('a', 40) . ' ' . str_repeat('b', 39) . "\nx",
            'line81' => "a\n" . str_repeat('a', 40) . ' ' . str_repeat('b', 40) . "\nx",
            'rest80' => "a\n" . str_repeat('a', 40) . ' ' . str_repeat('b', 39),
            'dqRootNl' => "\x01" . self::w(45) . "\nb",
            'dqRootFold' => '#' . self::w(120),
            'sqRootFold' => '"' . self::w(120),
            'dmNl' => "a\n---\nb",
            'plainNl' => "a\nb",
            'docMarker' => '---',
            'k1024' => Obj::of(['o' => Obj::of([str_repeat('k', 1024) => 'v'])]),
            'k1025' => Obj::of(['o' => Obj::of([str_repeat('k', 1025) => 'v'])]),
            'bang' => Obj::of(['k' => Obj::of(['a!' => [1]])]),
            'nums' => [INF, -INF, NAN, 5, 1.5],
            'x1f' => "#\x1f",
            'x01' => "#\x01",
        ];
        $sa = new YamlSeq([self::sp(90, [10, 76])]);
        $sb = new YamlSeq([self::sp(90, [10, 77])]);
        $inner = new YamlSeq([self::sp(90, [10, 74])]);
        $outer = new YamlSeq([$inner, 'x']);
        $c['anchA'] = Obj::of(['a' => $sa, 'b' => $sa]);
        $c['anchB'] = Obj::of(['a' => $sb, 'b' => $sb]);
        $c['anchNest'] = Obj::of(['a' => $outer, 'b' => $outer, 'c' => $inner]);
        for ($p = 72; $p <= 77; $p++) {
            $c["esc_x_$p"] = str_repeat('a', $p) . "\x01" . str_repeat('b', 30);
            $c["esc_u_$p"] = str_repeat('a', $p) . "\xED\xA0\x80" . str_repeat('b', 30);
            $c["esc_n_$p"] = '#' . str_repeat('a', $p) . '\\' . str_repeat('b', 30);
        }
        return $c;
    }

    /** @return array<string,string> */
    private static function expected(): array
    {
        return [
            'k58' => str_repeat('k', 58) . ": alpha bravo charlie\n  delta echo fox golf hotel alpha bravo charlie delta echo fox golf hotel alpha\n  bravo charlie delta echo fox golf hotel alpha bravox\n",
            'k59' => str_repeat('k', 59) . ":\n  alpha bravo charlie delta echo fox golf hotel alpha bravo charlie delta echo\n  fox golf hotel alpha bravo charlie delta echo fox golf hotel alpha bravox\n",
            'deep31' => "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - alpha bravo\n" . str_repeat(' ', 62) . "charlie delta echo\n" . str_repeat(' ', 62) . "fox golf hotel alpha\n" . str_repeat(' ', 62) . "bravo charlie delta\n" . str_repeat(' ', 62) . "echo fox golf hotel\n" . str_repeat(' ', 62) . "alpha bravo charlie\n" . str_repeat(' ', 62) . "delta echo fox golf\n" . str_repeat(' ', 62) . "hotel alpha bravox\n",
            'deep31b' => "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - >-\n" . str_repeat(' ', 62) . "\n" . str_repeat(' ', 62) . "alpha bravo\n" . str_repeat(' ', 62) . "charlie delta echo\n" . str_repeat(' ', 62) . "fox golf hotel alpha\n" . str_repeat(' ', 62) . "bravo ch\n\n" . str_repeat(' ', 62) . "delta echo fox golf\n" . str_repeat(' ', 62) . "hotel alpha bravo\n" . str_repeat(' ', 62) . "charlie delta echo\n" . str_repeat(' ', 62) . "fox golf hotel alpha\n" . str_repeat(' ', 62) . "bravo charlie delta\n" . str_repeat(' ', 62) . "echo fox golf hotel\n" . str_repeat(' ', 62) . "al\n\n" . str_repeat(' ', 62) . "end\n",
            'moreInd' => ">1-\n alpha bravo charlie delta echo fox golf hotel alpha bravo charlie delta echo fox golf hotel alpha br\nx\n",
            'moreInd2' => ">1-\n\n alpha bravo charlie delta echo fox golf hotel alpha bravo charlie delta echo fox golf hotel alpha br\nb\n",
            'moreInd3' => "k: >2-\n   alpha bravo charlie delta echo fox golf hotel alpha bravo charlie delta echo\n  fox golf hotel alpha br\n  x\n",
            'dm78' => "|-\n  --- " . str_repeat('a', 74) . "\n",
            'line80' => "|-\n" . str_repeat('a', 40) . " " . str_repeat('b', 39) . "\nx\n",
            'line81' => ">-\na\n\n" . str_repeat('a', 40) . "\n" . str_repeat('b', 40) . "\n\nx\n",
            'rest80' => "|-\na\n" . str_repeat('a', 40) . " " . str_repeat('b', 39) . "\n",
            'dqRootNl' => "\"\\x01alpha bravo charlie delta echo fox golf hotel\n\nb\"\n",
            'dqRootFold' => "\"#alpha bravo charlie delta echo fox golf hotel alpha bravo charlie delta echo\nfox golf hotel alpha bravo charlie delta ec\"\n",
            'sqRootFold' => "'\"alpha bravo charlie delta echo fox golf hotel alpha bravo charlie delta echo\nfox golf hotel alpha bravo charlie delta ec'\n",
            'dmNl' => "|-\n  a\n  ---\n  b\n",
            'plainNl' => "|-\na\nb\n",
            'docMarker' => "|-\n  ---\n",
            'k1024' => "o:\n  " . str_repeat('k', 1024) . ": v\n",
            'k1025' => "o:\n  ? " . str_repeat('k', 1025) . "\n  : v\n",
            'bang' => "k:\n  a!:\n    - 1\n",
            'nums' => "- .inf\n- -.inf\n- .nan\n- 5\n- 1.5\n",
            'anchA' => "a: &a1\n  - " . str_repeat('a', 10) . " " . str_repeat('a', 65) . "\n    " . str_repeat('a', 13) . "\nb: *a1\n",
            'anchB' => "a: &a1\n  - " . str_repeat('a', 10) . "\n    " . str_repeat('a', 66) . "\n    " . str_repeat('a', 12) . "\nb: *a1\n",
            'anchNest' => "a: &a1\n  - &a2\n    - " . str_repeat('a', 10) . "\n      " . str_repeat('a', 63) . "\n      " . str_repeat('a', 15) . "\n  - x\nb: *a1\nc: *a2\n",
            'x1f' => "\"#\\x1f\"\n",
            'x01' => "\"#\\x01\"\n",
            'esc_x_72' => "\"" . str_repeat('a', 72) . "\\x01bb\\\n" . str_repeat('b', 28) . "\"\n",
            'esc_x_73' => "\"" . str_repeat('a', 73) . "\\x01b\\\n" . str_repeat('b', 29) . "\"\n",
            'esc_x_74' => "\"" . str_repeat('a', 74) . "\\x01\\\n" . str_repeat('b', 30) . "\"\n",
            'esc_x_75' => "\"" . str_repeat('a', 75) . "\\\n\\x01" . str_repeat('b', 30) . "\"\n",
            'esc_x_76' => "\"" . str_repeat('a', 76) . "\\\n\\x01" . str_repeat('b', 30) . "\"\n",
            'esc_x_77' => "\"" . str_repeat('a', 77) . "\\\n\\x01" . str_repeat('b', 30) . "\"\n",
            'esc_u_72' => "\"" . str_repeat('a', 72) . "\\ud800\\\n" . str_repeat('b', 30) . "\"\n",
            'esc_u_73' => "\"" . str_repeat('a', 73) . "\\\n\\ud800" . str_repeat('b', 30) . "\"\n",
            'esc_u_74' => "\"" . str_repeat('a', 74) . "\\\n\\ud800" . str_repeat('b', 30) . "\"\n",
            'esc_u_75' => "\"" . str_repeat('a', 75) . "\\\n\\ud800" . str_repeat('b', 30) . "\"\n",
            'esc_u_76' => "\"" . str_repeat('a', 76) . "\\\n\\ud800" . str_repeat('b', 30) . "\"\n",
            'esc_u_77' => "\"" . str_repeat('a', 77) . "\\\n\\ud800" . str_repeat('b', 30) . "\"\n",
            'esc_n_72' => "\"#" . str_repeat('a', 72) . "\\\\bbb\\\n" . str_repeat('b', 27) . "\"\n",
            'esc_n_73' => "\"#" . str_repeat('a', 73) . "\\\\bb\\\n" . str_repeat('b', 28) . "\"\n",
            'esc_n_74' => "\"#" . str_repeat('a', 74) . "\\\\b\\\n" . str_repeat('b', 29) . "\"\n",
            'esc_n_75' => "\"#" . str_repeat('a', 75) . "\\\\\\\n" . str_repeat('b', 30) . "\"\n",
            'esc_n_76' => "\"#" . str_repeat('a', 76) . "\\\n\\\\" . str_repeat('b', 30) . "\"\n",
            'esc_n_77' => "\"#" . str_repeat('a', 77) . "\\\n\\\\" . str_repeat('b', 30) . "\"\n",
        ];
    }

    /** Each value's YAML text is byte-for-byte the reference package's. */
    public function testReferenceTexts(): void
    {
        $want = self::expected();
        foreach (self::cases() as $name => $v) {
            $this->assertSame($want[$name], ActionsYaml::stringify($v), $name);
        }
        $this->assertEqualsCanonicalizing(array_keys($want), array_keys(self::cases()));
    }

    /** Surrogates: a pair stays one character, a lone or mismatched surrogate is escaped, astral characters round-trip exactly. */
    public function testSurrogates(): void
    {
        $cases = [
            "\xED\xA0\x80" => "\"\\ud800\"\n",
            "#\xED\xA0\x80\u{E000}" => "\"#\\ud800\u{E000}\"\n",
            "#\x01\x1f" => "\"#\\x01\\x1f\"\n",
            "#\u{10000}" => "\"#\u{10000}\"\n",
            "#\u{10FFFF}" => "\"#\u{10FFFF}\"\n",
            "#\xED\xB0\x80\xED\xB0\x80" => "\"#\\udc00\\udc00\"\n",
            "#a\xED\xB0\x80" => "\"#a\\udc00\"\n",
            "\xED\xB0\x80" => "\"\\udc00\"\n",
            "#\xED\xBF\xBF" => "\"#\\udfff\"\n",
            "\u{10401}\u{10440}\u{20000}" => "\u{10401}\u{10440}\u{20000}\n",
        ];
        foreach ($cases as $in => $want) {
            $this->assertSame($want, ActionsYaml::stringify((string)$in), bin2hex((string)$in));
        }
    }

    /** Bytes that are not UTF-8 are read as code units by their bits: a value under 0x20 is escaped, anything else is kept. */
    public function testNonUtf8CodeUnits(): void
    {
        $cases = [
            "#\xC0\x80" => "\"#\\0\"\n",
            "#\xE0\x80" => "\"#\\0\"\n",
            "#\xC0\x81" => "\"#\\x01\"\n",
            "#\xC1\x80" => "\"#\xC1\x80\"\n",
            "#\xE0\x80\x81" => "\"#\\x01\"\n",
            "#\xE0\x81\x80" => "\"#\xE0\x81\x80\"\n",
        ];
        foreach ($cases as $in => $want) {
            $this->assertSame($want, ActionsYaml::stringify((string)$in), bin2hex((string)$in));
        }
    }

    /** A value that is not plain data is refused by its type. */
    public function testRefusesNonData(): void
    {
        try {
            ActionsYaml::stringify(Obj::of(['a' => new \stdClass()]));
            $this->fail('a stdClass must be refused');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('cannot write a stdClass as YAML', $e->getMessage());
        }
    }
}
