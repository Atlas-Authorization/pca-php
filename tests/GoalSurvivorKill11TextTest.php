<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalKernel.php';

use Atlas\Pca\GoalIrError;
use Atlas\Pca\GoalKernel as K;
use PHPUnit\Framework\TestCase;

/** The goal-kernel tape text codec (WTF-8 code points both ways) and the caller-tape validation with its exact refusals. */
final class GoalSurvivorKill11TextTest extends TestCase
{
    private static function refusal(callable $f): string
    {
        try {
            $f();
        } catch (GoalIrError | \InvalidArgumentException $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'accepted';
    }

    /** Every lead byte range decodes to its code point; continuation bytes are masked to six bits and the cursor steps exactly. */
    public function testStringTokensPrintTheirCodePoints(): void
    {
        self::assertSame('s5a.9af5.59', K::tapeToText([['s', "Z\xE9\xAB\xB5Y"]]));
        self::assertSame('s5a.4b767.59.58', K::tapeToText([['s', "Z\xF1\x8B\x9D\xA7YX"]]));
        self::assertSame('se9.41', K::tapeToText([['s', "\xC3\xA9A"]]));
        // a bare continuation byte is a two-byte lead in this decoder, not ASCII
        self::assertSame('s1', K::tapeToText([['s', "\x80A"]]));
        self::assertSame('s800', K::tapeToText([['s', "\xE0\xA0\x80"]]));
        self::assertSame('s1f600', K::tapeToText([['s', "\xF0\x9F\x98\x80"]]));
        self::assertSame('s20ac', K::tapeToText([['s', "\xE2\x82\xAC"]]));
        self::assertSame('k5 i-3 s', K::tapeToText([['k', 5], ['i', -3], ['s', '']]));
    }

    /** Code points encode at the exact range boundaries, every bit of each byte in place. */
    public function testCodePointsEncodeAtEachBoundary(): void
    {
        self::assertSame([['s', "\x7F\xC2\x80\xDF\xBF\xE0\xA0\x80\xEF\xBF\xBF\xEA\xAA\x94\xF0\x90\x80\x80\xF4\x8F\xBF\xBF"]],
            K::tapeFromText('s7f.80.7ff.800.ffff.aa94.10000.10ffff'));
        self::assertSame("\xEA\xAA\x94", K::tapeFromText('saa94')[0][1]);
        self::assertSame('InvalidArgumentException: goal tape text: code point out of range', self::refusal(fn() => K::tapeFromText('s110000')));
        self::assertSame("\xF4\x8F\xBF\xBF", K::tapeFromText('s10ffff')[0][1]);
    }

    /** Integers parse exactly up to 18 digits (sign not counted); longer ones stay floats for the integer check to refuse. */
    public function testIntegerTextLengthRule(): void
    {
        self::assertSame([['i', 123456789012345678]], K::tapeFromText('i123456789012345678'));
        self::assertSame([['i', -123456789012345678]], K::tapeFromText('i-123456789012345678'));
        $long = K::tapeFromText('k1234567890123456789');
        self::assertSame('k', $long[0][0]);
        self::assertIsFloat($long[0][1]);
        // a NUL is trimmed from the ends of the text, but is not whitespace inside it
        self::assertSame([['k', 5]], K::tapeFromText("k5\0"));
        self::assertSame([['k', 5], ['i', 2]], K::tapeFromText("  k5 \n i2\t"));
    }

    /** Malformed tape text is refused with a message naming the bad token. */
    public function testBadTextIsRefusedByName(): void
    {
        self::assertSame("InvalidArgumentException: goal tape text: bad integer 'kx'", self::refusal(fn() => K::tapeFromText('kx')));
        self::assertSame("InvalidArgumentException: goal tape text: bad code point 'szz'", self::refusal(fn() => K::tapeFromText('szz')));
        self::assertSame("InvalidArgumentException: goal tape text: bad code point 's1..2'", self::refusal(fn() => K::tapeFromText('s1..2')));
        self::assertSame("Atlas\\Pca\\GoalIrError: goal tape text: bad token 'x1'", self::refusal(fn() => K::tapeFromText('x1')));
        // a code point too large for an integer is refused as out of range or decoded, never a type error
        $r = self::refusal(fn() => K::tapeFromText('s' . str_repeat('f', 20)));
        self::assertTrue($r === 'accepted' || str_starts_with($r, 'InvalidArgumentException: '), $r);
    }

    /** Caller tapes: integer tokens must be safe integers (a float only when integral), with the exact refusal text. */
    public function testIntegerTokensMustBeSafe(): void
    {
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: 1.5 is not a safe integer', self::refusal(fn() => K::kernelCall('render', [['k', 1.5]])));
        self::assertSame("Atlas\\Pca\\GoalIrError: goal tape: '5' is not a safe integer", self::refusal(fn() => K::kernelCall('render', [['i', '5']])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: true is not a safe integer', self::refusal(fn() => K::kernelCall('render', [['i', true]])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: value is not a safe integer', self::refusal(fn() => K::kernelCall('render', [['i', [1]]])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: 9007199254740992 is not a safe integer', self::refusal(fn() => K::kernelCall('render', [['i', 9007199254740992]])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: 9007199254740992.0 is not a safe integer', self::refusal(fn() => K::kernelCall('render', [['i', 9007199254740992.0]])));
        // the limits themselves and integral floats are accepted (the tape is not a goal, so it is malformed, not refused)
        self::assertSame(K::BAD, K::kernelCall('render', [['i', 9007199254740991]]));
        self::assertSame(K::BAD, K::kernelCall('render', [['i', -9007199254740991.0]]));
        self::assertSame(K::BAD, K::kernelCall('render', [['i', 1.0]]));
        self::assertSame(K::BAD, K::kernelCall('render', [['k', 480.0]]));
    }

    /** An integral float token is normalized to an int before decoding (k480.0 opens a goal like k480). */
    public function testIntegralFloatTokensDecodeAsIntegers(): void
    {
        $t = [['k', 480.0], ['i', 1.0], ['s', 'p'], ['s', ''], ['s', ''], ['i', 0], ['i', 0], ['i', 0], ['i', 0],
            ['k', 460], ['i', 0], ['i', 10], ['i', 0], ['k', 461], ['i', 0], ['i', 1], ['i', 0], ['i', 0], ['i', 0], ['i', 0]];
        $out = K::kernelCall('render', $t);
        self::assertSame(['i', 0], $out[0]);
        self::assertSame(['k', 480], $out[1]);
        self::assertSame(['i', 1], $out[2]);
    }

    /** The tape and each token must have the right shape, with distinct refusal texts. */
    public function testTapeShapeIsChecked(): void
    {
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: an Array of tokens expected', self::refusal(fn() => K::kernelCall('render', ['a' => ['k', 1]])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: token expected', self::refusal(fn() => K::kernelCall('render', ['x'])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: token expected', self::refusal(fn() => K::kernelCall('render', [['a' => 'k', 'b' => 1]])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: token expected', self::refusal(fn() => K::kernelCall('render', [['k']])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: token expected', self::refusal(fn() => K::kernelCall('render', [['k', 1, 2]])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: string token expected', self::refusal(fn() => K::kernelCall('render', [['s', 5]])));
        self::assertSame("Atlas\\Pca\\GoalIrError: goal tape: unknown token tag 'x'", self::refusal(fn() => K::kernelCall('render', [['x', 1]])));
        self::assertSame('Atlas\Pca\GoalIrError: goal tape: unknown token tag value', self::refusal(fn() => K::kernelCall('render', [[5, 1]])));
        self::assertSame("InvalidArgumentException: goal kernel: unknown op 'nope'", self::refusal(fn() => K::kernelCall('nope', [])));
    }
}
