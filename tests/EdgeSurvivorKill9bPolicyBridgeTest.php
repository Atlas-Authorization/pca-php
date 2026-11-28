<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\PolicyBridge;
use PHPUnit\Framework\TestCase;

/** PolicyBridge follow-up: surrogate halves joined in the output, and the parser's recursion bound at exactly 2000. */
final class EdgeSurvivorKill9bPolicyBridgeTest extends TestCase
{
    private static function cedarWhen(string $cond): Obj
    {
        return PolicyBridge::cedarToPca('permit(principal, action, resource) when { ' . $cond . ' }');
    }

    private static function arr(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $r = [];
            foreach ($v->keys() as $k) {
                $r[$k] = self::arr($v->get($k));
            }
            return $r;
        }
        return is_array($v) ? array_map(static fn($x) => self::arr($x), $v) : $v;
    }

    private static function preds(Obj $r): array
    {
        return self::arr($r->get('predicates'));
    }

    /**
     * A Cedar like-escape drops the backslash, so `"\uD83D\\\uDE00"` becomes the two halves side by side: to the reference (JavaScript)
     * that is one astral character, and the translation must say so instead of returning two lone surrogates.
     */
    public function testAdjacentHalvesBecomeOneCharacter(): void
    {
        $halves = [["\xED\xA0\x80", "\xED\xB0\x80", "\u{10000}"], ["\xED\xAF\xBF", "\xED\xBF\xBF", "\u{10FFFF}"],
            ["\xED\xA0\xBD", "\xED\xB8\x80", "\u{1F600}"], ["\xED\xAA\xAA", "\xED\xB5\x95", "\u{BA955}"]];
        $text = '';
        $want = '';
        foreach ($halves as [$hi, $lo, $astral]) {
            $text .= $hi . '\\' . $lo;
            $want .= $astral;
        }
        $p = self::preds(self::cedarWhen('context.a like "' . $text . '"'));
        $this->assertSame(bin2hex($want), bin2hex($p[0]['where'][0]['value']));
        // a low half before a high half is not a pair: both stay lone surrogates
        $p = self::preds(self::cedarWhen("context.a like \"\xED\xB0\x80\\\xED\xA0\x80\""));
        $this->assertSame(bin2hex("\xED\xB0\x80\xED\xA0\x80"), bin2hex($p[0]['where'][0]['value']));
    }

    private static function nested(int $n): Obj
    {
        return self::cedarWhen(str_repeat('(', $n) . 'principal == U::"a"' . str_repeat(')', $n));
    }

    /** 1999 parentheses parse (2000 levels); 2000 exceed the bound and the policy is reported, not translated. */
    public function testRecursionBoundIsExactly2000Levels(): void
    {
        $r = self::nested(1999);
        $this->assertSame([], self::arr($r->get('report'))['errors']);
        $this->assertSame(self::preds(self::nested(0)), self::preds($r));
        $this->assertCount(1, self::preds($r));

        $r = self::nested(2000);
        $this->assertSame([], self::preds($r));
        $errors = self::arr($r->get('report'))['errors'];
        $this->assertCount(1, $errors);
        $this->assertStringEndsWith('": Maximum call stack size exceeded', $errors[0]);
    }
}
