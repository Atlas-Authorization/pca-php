<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentSchema;
use Atlas\Pca\Js;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentSchema.php: the wallet floor refusal, the reversibility projection and the derived outcome space. */
final class IntentSurvivorKill30IntentSchemaTest extends TestCase
{
    private const N = 'action.params.n';
    private const S = 'action.params.s';

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

    private static function derive(array $params, array $extra = []): array
    {
        $schema = ['verbs' => [['verb' => 'pay.send', 'kind' => 'write', 'params' => Obj::of($params)]]];
        return IntentSchema::deriveOmegaFromSchema(['schema' => $schema] + $extra);
    }

    private static function dims(array $r): array
    {
        return Js::opt(Js::opt($r['omega'], 'verbs')[0], 'dims');
    }

    private static function dim(array $r, string $path): Obj
    {
        foreach (self::dims($r) as $d) {
            if ($d->get('path') === $path) {
                return $d;
            }
        }
        throw new \RuntimeException("no dim $path");
    }

    private static function lit(string $path, array $c): array
    {
        return ['slots' => ['constraints' => [['verb' => 'pay.send', 'path' => $path] + $c]]];
    }

    private static function values(Obj $d): array
    {
        return array_map(static fn(Obj $v) => [$v->get('kind'), $v->get('value')], $d->get('values'));
    }

    private static function int(): array
    {
        return [self::N => ['type' => 'integer', 'sensitivity' => 'material']];
    }

    private static function str(array $more = []): array
    {
        return [self::S => ['type' => 'string', 'sensitivity' => 'material'] + $more];
    }

    /** A non-string semantic on a free parameter is refused with the reference's TypeError text. */
    public function testNonStringSemanticRefusedWithReferenceText(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('semantic.startsWith is not a function');
        IntentSchema::effectiveSensitivity(['sensitivity' => 'free', 'semantic' => 5]);
    }

    /** A numeric floor prefix is compared as its text (startsWith coerces), not refused. */
    public function testNumericFloorPrefixIsCoercedToText(): void
    {
        $this->assertSame('material', IntentSchema::effectiveSensitivity(['sensitivity' => 'free', 'semantic' => 'abc'], ['prefixes' => ['ab'], 'exact' => []]), 'control');
        $this->assertSame('free', IntentSchema::effectiveSensitivity(['sensitivity' => 'free', 'semantic' => 'abc'], ['prefixes' => [5], 'exact' => []]));
        $this->assertSame('material', IntentSchema::effectiveSensitivity(['sensitivity' => 'free', 'semantic' => '5x'], ['prefixes' => [5], 'exact' => []]));
    }

    private static function rev(array $pd, mixed $map, array $rb = []): mixed
    {
        $by = ['param' => 'p'] + $rb;
        if ($map !== null) {
            $by['map'] = Obj::of($map);
        }
        return IntentSchema::verbReversibility(['reversibility_by' => $by, 'params' => Obj::of(['p' => $pd])]);
    }

    /** A boolean parameter is covered only when the map has both true and false; otherwise the default joins the max. */
    public function testBooleanDomainNeedsBothValues(): void
    {
        $this->assertSame('rate_limited', self::rev(['type' => 'boolean'], ['true' => 'reversible', 'false' => 'rate_limited']), 'control');
        $this->assertSame('irreversible', self::rev(['type' => 'boolean'], ['false' => 'reversible']));
    }

    /** Only a string parameter's values form a closed domain; a non-string type with values is never covered. */
    public function testValuesOnlyCloseAStringDomain(): void
    {
        $this->assertSame('reversible', self::rev(['type' => 'string', 'values' => ['a']], ['a' => 'reversible']), 'control');
        $this->assertSame('irreversible', self::rev(['type' => 'integer', 'values' => ['a']], ['a' => 'reversible']));
    }

    /** One unmapped value uncovers the domain, so the default (irreversible) is part of the max. */
    public function testUnmappedValueUncovers(): void
    {
        $this->assertSame('irreversible', self::rev(['type' => 'string', 'values' => ['a', 'b']], ['a' => 'reversible']));
    }

    /** No map at all: never covered, the default decides (no member call on a missing map). */
    public function testMissingMapFallsToDefault(): void
    {
        $this->assertSame('rate_limited', self::rev(['type' => 'string', 'values' => ['a']], null, ['default' => 'rate_limited']));
    }

    /** A non-string domain value is never a map key: the domain is uncovered, not an error. */
    public function testNonStringDomainValueUncovers(): void
    {
        $this->assertSame('irreversible', self::rev(['type' => 'string', 'values' => [1]], ['1' => 'reversible']));
    }

    /** Uncovered: every mapped outcome and the default all take part in the max. */
    public function testUncoveredKeepsEveryMappedOutcome(): void
    {
        $this->assertSame('rate_limited', self::rev(['type' => 'string', 'values' => ['a', 'b', 'c']], ['a' => 'reversible', 'b' => 'rate_limited'], ['default' => 'reversible']));
    }

    /** A reversibility_by without a param reads no parameter (not an error) and falls to the default. */
    public function testMissingParamFallsToDefault(): void
    {
        $r = IntentSchema::verbReversibility(['reversibility_by' => ['map' => Obj::of(['a' => 'reversible'])], 'params' => Obj::of([])]);
        $this->assertSame('irreversible', $r);
    }

    /** With no verbs option, a slot verb that the schema declares (even a read) is a cell. */
    public function testSlotVerbsJoinTheDefaultVerbList(): void
    {
        $schema = ['verbs' => [['verb' => 'doc.get', 'kind' => 'read', 'params' => Obj::of([])]]];
        $r = IntentSchema::deriveOmegaFromSchema(['schema' => $schema, 'slots' => ['verbs' => ['doc.get']]]);
        $verbs = Js::opt($r['omega'], 'verbs');
        $this->assertCount(1, $verbs);
        $this->assertSame('doc.get', $verbs[0]->get('verb'));
        $this->assertSame('reversible', $verbs[0]->get('reversibility'));
        $this->assertSame(1, $verbs[0]->get('weight'));
        $this->assertSame([], Js::opt(IntentSchema::deriveOmegaFromSchema(['schema' => $schema])['omega'], 'verbs'), 'control: read verbs are not cells by default');
    }

    /** A verb declared twice takes its first declaration. */
    public function testFirstDeclarationWins(): void
    {
        $schema = ['verbs' => [
            ['verb' => 'pay.send', 'kind' => 'write', 'reversibility' => 'reversible', 'params' => Obj::of([])],
            ['verb' => 'pay.send', 'kind' => 'write', 'reversibility' => 'irreversible', 'params' => Obj::of([])],
        ]];
        $r = IntentSchema::deriveOmegaFromSchema(['schema' => $schema]);
        $this->assertSame('reversible', Js::opt($r['omega'], 'verbs')[0]->get('reversibility'));
    }

    /** A literal dimension outside action.params (env.hour) is carried into the cell. */
    public function testNonParamLiteralDimensionsAreKept(): void
    {
        $r = self::derive([], self::lit('env.hour', ['max' => 5]));
        $this->assertSame(['env.hour'], array_map(static fn(Obj $d) => $d->get('path'), self::dims($r)));
    }

    /** Literal cuts and confirmed defaults merge by numeric value: two different numbers stay two cuts, in order. */
    public function testLiteralAndDefaultCutsStayDistinct(): void
    {
        $a = self::derive(self::int(), self::lit(self::N, ['max' => 4]) + ['confirmed' => [self::N => [5]]]);
        $this->assertSame([4, 5], self::dim($a, self::N)->get('cuts'));
        $b = self::derive(self::int(), self::lit(self::N, ['max' => 5]) + ['confirmed' => [self::N => [4]]]);
        $this->assertSame([4, 5], self::dim($b, self::N)->get('cuts'));
    }

    /** A default -0 and a literal 0 are the same cut (Set<number> semantics), and the first one (the literal 0) is kept. */
    public function testNegativeZeroDefaultMergesWithZero(): void
    {
        $r = self::derive(self::int(), self::lit(self::N, ['max' => 0]) + ['confirmed' => [self::N => [-0.0]]]);
        $this->assertSame([0], self::dim($r, self::N)->get('cuts'));
    }

    /** Two safe integers that agree in their first 14 digits are still two cuts (no ini-precision key collision). */
    public function testCloseLargeCutsStayDistinct(): void
    {
        $r = self::derive(self::int(), ['confirmed' => [self::N => [100000000000001, 100000000000000]]]);
        $this->assertSame([100000000000000, 100000000000001], self::dim($r, self::N)->get('cuts'));
    }

    /** 2^53-1 is a safe integer default (a cut); 2^53 is not. */
    public function testSafeIntegerBoundary(): void
    {
        $r = self::derive(self::int(), ['confirmed' => [self::N => [9007199254740991, 9007199254740992]]]);
        $this->assertSame([9007199254740991], self::dim($r, self::N)->get('cuts'));
    }

    /** The same large number from a literal and a default is one cut. */
    public function testLargeEqualCutsMerge(): void
    {
        $r = self::derive(self::int(), self::lit(self::N, ['max' => 1000000000000000]) + ['confirmed' => [self::N => [1000000000000000]]]);
        $this->assertSame([1000000000000000], self::dim($r, self::N)->get('cuts'));
    }

    /** Two huge literal cuts beyond the integer range stay distinct (keyed by their text, no float-to-int key). */
    public function testHugeLiteralCutsStayDistinct(): void
    {
        $r = self::derive(self::int(), self::lit(self::N, ['max' => 1e300, 'min' => 3e300]));
        $this->assertSame([1e300, 3e300], self::dim($r, self::N)->get('cuts'));
    }

    /** With no bounds the low end is one below the smallest cut (when negative), and a silent single default is recorded. */
    public function testLowEndIsOneBelowSmallestCut(): void
    {
        $r = self::derive(self::int(), ['confirmed' => [self::N => [-5]]]);
        $d = self::dim($r, self::N);
        $this->assertSame(-6.0, $d->get('lo'));
        $this->assertSame(10.0, $d->get('hi'));
        $this->assertSame('uniform', $d->get('dist'));
        $this->assertSame([-5], $d->get('cuts'));
        $this->assertSame(-5, $r['defaults'][0]->get('min'));
    }

    /** The domain bounds are inclusive and the kept cuts are a list. */
    public function testDomainBoundsInclusive(): void
    {
        $r = self::derive(self::int(), ['confirmed' => [self::N => [1, 3, 7, 9]], 'domains' => [self::N => ['lo' => 3, 'hi' => 7]]]);
        $d = self::dim($r, self::N);
        $this->assertSame([3, 7], $d->get('cuts'));
        $this->assertSame(3, $d->get('lo'));
        $this->assertSame([], $r['defaults']);
    }

    /** Cuts are emitted as plain numbers (a parsed Num becomes an int). */
    public function testCutsArePlainNumbers(): void
    {
        $r = self::derive(self::int(), ['confirmed' => [self::N => [new Num('5')]]]);
        $this->assertSame([5], self::dim($r, self::N)->get('cuts'));
        $this->assertSame(5, $r['defaults'][0]->get('max'));
    }

    /** Only numeric defaults count toward a silent integer default, whatever their position. */
    public function testOnlyNumericDefaultsCount(): void
    {
        $r = self::derive(self::int(), ['confirmed' => [self::N => ['x', 5]]]);
        $this->assertCount(1, $r['defaults']);
        $this->assertSame(5, $r['defaults'][0]->get('min'));
        $this->assertSame(5, $r['defaults'][0]->get('max'));
    }

    /** An integer parameter whose literal is categorical gets a numeric dimension with no cuts. */
    public function testIntegerWithCategoricalLiteral(): void
    {
        $r = self::derive(self::int(), self::lit(self::N, ['oneOf' => ['x']]));
        $d = self::dim($r, self::N);
        $this->assertSame('num', $d->get('kind'));
        $this->assertSame([], $d->get('cuts'));
        $this->assertSame(0.0, $d->get('lo'));
        $this->assertSame(10.0, $d->get('hi'));
    }

    /** A string parameter whose literal is numeric gets a categorical dimension of only OTHER. */
    public function testStringWithNumericLiteral(): void
    {
        $r = self::derive(self::str(), self::lit(self::S, ['max' => 5]));
        $d = self::dim($r, self::S);
        $this->assertSame('cat', $d->get('kind'));
        $this->assertCount(1, $d->get('values'));
        $this->assertSame('other', $d->get('values')[0]->get('kind'));
    }

    /** A non-integral literal exact value keeps its full text. */
    public function testLiteralExactKeepsFractionText(): void
    {
        $r = self::derive(self::str(), self::lit(self::S, ['oneOf' => [1.5]]));
        $this->assertSame([['exact', '1.5'], ['other', "\u{22A5}"]], self::values(self::dim($r, self::S)));
    }

    /** A non-integral literal prefix keeps its full text. */
    public function testLiteralPrefixKeepsFractionText(): void
    {
        $r = self::derive(self::str(), self::lit(self::S, ['prefixOneOf' => [1.5]]));
        $this->assertSame([['prefix', '1.5'], ['other', "\u{22A5}"]], self::values(self::dim($r, self::S)));
    }

    /** A non-integral declared string value keeps its full text. */
    public function testDeclaredValueKeepsFractionText(): void
    {
        $r = self::derive(self::str(['values' => ['a', 1.5]]));
        $this->assertSame([['exact', '1.5'], ['exact', 'a'], ['other', "\u{22A5}"]], self::values(self::dim($r, self::S)));
    }

    /** Numeric-looking exact values come out as strings. */
    public function testNumericLookingExactIsAString(): void
    {
        $r = self::derive(self::str(['values' => ['5']]));
        $this->assertSame([['exact', '5'], ['other', "\u{22A5}"]], self::values(self::dim($r, self::S)));
    }

    /** Numeric-looking prefixes come out as strings. */
    public function testNumericLookingPrefixIsAString(): void
    {
        $r = self::derive(self::str(), self::lit(self::S, ['prefixOneOf' => ['7']]));
        $this->assertSame([['prefix', '7'], ['other', "\u{22A5}"]], self::values(self::dim($r, self::S)));
    }

    /** A silent numeric-looking default comes out as a string in oneOf. */
    public function testNumericLookingDefaultIsAString(): void
    {
        $r = self::derive(self::str(), ['confirmed' => [self::S => ['5']]]);
        $this->assertSame(['5'], $r['defaults'][0]->get('oneOf'));
        $this->assertSame(self::S, $r['defaults'][0]->get('path'));
    }

    /** Prefixes are re-sorted by UTF-8 byte order (U+FF01 before U+1F600), not left in the literal's UTF-16 order. */
    public function testPrefixesSortedByUtf8(): void
    {
        $r = self::derive(self::str(), self::lit(self::S, ['prefixOneOf' => ["\u{1F600}", "\u{FF01}"]]));
        $this->assertSame([['prefix', "\u{FF01}"], ['prefix', "\u{1F600}"], ['other', "\u{22A5}"]], self::values(self::dim($r, self::S)));
    }
}
