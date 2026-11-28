<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentOmega;
use Atlas\Pca\IntentUx;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentUx.php: question-card cell refusals and every parseCardAnswer branch. */
final class IntentSurvivorKill30IntentUxTest extends TestCase
{
    private const RANGE = 'except values must be integers in [0, 10]';

    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function catDim(): Obj
    {
        return Obj::of(['kind' => 'cat', 'path' => 'action.params.s', 'values' => [
            Obj::of(['kind' => 'exact', 'value' => 'a']), Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER])]]);
    }

    private static function numDim(): Obj
    {
        return Obj::of(['kind' => 'num', 'path' => 'action.params.n', 'lo' => 0, 'hi' => 10, 'cuts' => []]);
    }

    private static function vs(array $dims): Obj
    {
        return Obj::of(['verb' => 'x.do', 'reversibility' => 'irreversible', 'weight' => 1, 'dims' => $dims]);
    }

    private static function omega(array $verbs): Obj
    {
        return Obj::of(['v' => 1, 'approximate' => [], 'verbs' => $verbs]);
    }

    private static function card(mixed $omega, mixed $cell): Obj
    {
        return IntentUx::questionCard($omega, Obj::of(['verb' => 'x.do', 'cell' => $cell]));
    }

    private static function outOfRange(\Closure $f): string
    {
        try {
            $f();
        } catch (\OutOfRangeException $e) {
            return $e->getMessage();
        }
        return 'no refusal';
    }

    private static function typeError(\Closure $f): string
    {
        try {
            $f();
        } catch (\TypeError $e) {
            return $e->getMessage();
        }
        return 'no type error';
    }

    private static function slots(): Obj
    {
        return Obj::of(['partial' => [Obj::of(['path' => 'action.params.n', 'kind' => 'num', 'lo' => 0, 'hi' => 10]),
            Obj::of(['path' => 'action.params.s', 'kind' => 'cat', 'options' => ['a']])]]);
    }

    private static function partly(array $extra): array
    {
        return IntentUx::parseCardAnswer(self::slots(), Obj::of(['answer' => 'partly', 'path' => 'action.params.n'] + $extra));
    }

    private function assertAnswer(string $json, array $r): void
    {
        $this->assertSame(['ok', 'answer'], array_keys($r));
        $this->assertTrue($r['ok']);
        $this->assertSame($json, Js::stringify($r['answer']));
    }

    /** A missing, infinite, fractional, negative or past-the-end cell index is out of range (never a warning, never cell 0). */
    public function testCellIndexRefusals(): void
    {
        $cat = self::omega([self::vs([self::catDim()])]);
        $num = self::omega([self::vs([self::numDim()])]);
        foreach ([[], [INF], [0.5], [2], [-1]] as $cell) {
            $this->assertSame('cell index out of range', self::outOfRange(static fn() => self::card($cat, $cell)), (string)json_encode($cell));
        }
        $this->assertSame('cell index out of range', self::outOfRange(static fn() => self::card($num, [1])));
        $this->assertSame([0], self::card($num, [0])->get('cell'), 'control');
    }

    /** The first verb space with the verb is the one carded; an unknown verb is named in the refusal. */
    public function testFirstVerbAndUnknownVerb(): void
    {
        $o = self::omega([self::vs([]), self::vs([self::catDim()])]);
        $this->assertSame([], self::card($o, [])->get('facts'));
        try {
            IntentUx::questionCard($o, Obj::of(['verb' => 'zz', 'cell' => []]));
            $this->fail('no refusal');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('questionCard: no verb zz', $e->getMessage());
        }
    }

    /** The card's cell is the list of the question's cell values (keys dropped). */
    public function testCardCellIsAList(): void
    {
        $this->assertSame([5, 0], self::card(self::omega([self::vs([self::catDim()])]), [1 => 5, 0 => 0])->get('cell'));
    }

    /** upTo and from: an in-range value splits the slot exactly. */
    public function testUpToAndFrom(): void
    {
        $this->assertAnswer('{"kind":"partial","path":"action.params.n","cuts":[3],"parts":[{"lo":0,"hi":3,"y":1},{"lo":4,"hi":10,"y":0}]}', self::partly(['upTo' => 3]));
        $this->assertAnswer('{"kind":"partial","path":"action.params.n","cuts":[3],"parts":[{"lo":0,"hi":2,"y":0},{"lo":3,"hi":10,"y":1}]}', self::partly(['from' => 3]));
    }

    /** except: values are de-duplicated (3 and 3.0 are one), sorted, and each kept; 0 is an integer, -0 is not. */
    public function testExcept(): void
    {
        $this->assertAnswer('{"kind":"partial","path":"action.params.n","cuts":[3,5],"parts":[{"lo":3,"hi":3,"y":0},{"lo":5,"hi":5,"y":0},{"lo":0,"hi":10,"y":1}]}', self::partly(['except' => [5, 3]]));
        $this->assertAnswer('{"kind":"partial","path":"action.params.n","cuts":[3],"parts":[{"lo":3,"hi":3,"y":0},{"lo":0,"hi":10,"y":1}]}', self::partly(['except' => [3, 3.0]]));
        $this->assertAnswer('{"kind":"partial","path":"action.params.n","cuts":[0],"parts":[{"lo":0,"hi":0,"y":0},{"lo":0,"hi":10,"y":1}]}', self::partly(['except' => [0]]));
        $this->assertSame(['ok' => false, 'error' => self::RANGE], self::partly(['except' => [-0.0]]));
    }

    /** A NaN, a string or an object next to a valid value is not merged into it: the answer is refused. */
    public function testExceptKeepsInvalidValues(): void
    {
        foreach ([[3, NAN], [3, 'a'], [3, new Obj()]] as $ex) {
            $this->assertSame(['ok' => false, 'error' => self::RANGE], self::partly(['except' => $ex]));
        }
    }

    /** Non-iterable except and non-array notFor throw the reference's TypeErrors. */
    public function testIterableRefusals(): void
    {
        $this->assertSame('object is not iterable', self::typeError(static fn() => self::partly(['except' => 5])));
        $this->assertSame('input.notFor.filter is not a function', self::typeError(static fn() => IntentUx::parseCardAnswer(self::slots(),
            Obj::of(['answer' => 'partly', 'path' => 'action.params.s', 'notFor' => 'abc']))));
        $this->assertSame('input.notFor.filter is not a function', self::typeError(static fn() => IntentUx::parseCardAnswer(self::slots(),
            Obj::of(['answer' => 'partly', 'newField' => 'action.params.z']))));
    }

    /** An array input has no fields: the answer names the undefined field instead of failing. */
    public function testArrayInputHasNoFields(): void
    {
        $this->assertSame(['ok' => false, 'error' => 'the card has no field undefined'],
            IntentUx::parseCardAnswer(self::slots(), ['answer' => 'partly', 'path' => 'action.params.n']));
    }

    /** The first card slot with the path is the one answered. */
    public function testFirstSlotWins(): void
    {
        $card = Obj::of(['partial' => [Obj::of(['path' => 'action.params.n', 'kind' => 'cat', 'options' => []]),
            Obj::of(['path' => 'action.params.n', 'kind' => 'num', 'lo' => 0, 'hi' => 10])]]);
        $r = IntentUx::parseCardAnswer($card, Obj::of(['answer' => 'partly', 'path' => 'action.params.n', 'notFor' => ['q']]));
        $this->assertAnswer('{"kind":"partial","path":"action.params.n","values":["q"],"parts":[{"values":["q"],"y":0},{"other":true,"y":1}]}', $r);
    }
}
