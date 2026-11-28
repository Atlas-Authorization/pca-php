<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Explain;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Explain: UTF-16 slicing, text helpers, condition rendering, pinpoints, decision / chain explanations and their text renderers. */
final class ToolSurvivorKill18ExplainTest extends TestCase
{
    private static function call(string $m, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Explain::class, $m))->invoke(null, ...$args);
    }

    /** Runs $f with every reported (not @-suppressed) warning or notice turned into an exception. */
    private static function noWarnings(\Closure $f): mixed
    {
        set_error_handler(static function (int $no, string $msg): bool {
            if ((error_reporting() & $no) === 0) {
                return false;
            }
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    // ---- UTF-16 units ---------------------------------------------------------------------------------------------------

    public function testSlice16RoundTripsEveryEncodingWidth(): void
    {
        foreach ([
            "\xC2\x80", "\xC3\xBF", "\xE0\xA0\x80", "\xE0\xBF\xBFa", "\xEF\xBF\xBF", "\xF0\x90\x80\x80", "\xF1\x9F\xBF\xBF", "\xF4\x8F\xBF\xBF",
            "\u{1F600}", "a\u{1F600}b", "\xED\xA0\x80\xEE\x80\x80", "a\xED\xB0\x80", "\xED\xA0\x80", "\xED\xBF\xBF",
        ] as $s) {
            $this->assertSame($s, Explain::slice16($s, 0), bin2hex($s));
        }
    }

    public function testSlice16OfAStrayContinuationByte(): void
    {
        // a lone 0x80 takes the two-byte path with a missing continuation: one unit 0
        $this->assertSame("\x00", Explain::slice16("\x80", 0));
    }

    public function testSlice16Bounds(): void
    {
        $this->assertSame('', Explain::slice16('abcdef', 3, 2));
        $this->assertSame('', Explain::slice16('abc', 1, 1));
        $this->assertSame('bc', Explain::slice16('abcdef', 1, 3));
        $this->assertSame("\xED\xA0\xBD", Explain::slice16("\u{1F600}", 0, 1));
        $this->assertSame("\xED\xB8\x80b", Explain::slice16("\u{1F600}b", 1));
    }

    // ---- small helpers --------------------------------------------------------------------------------------------------

    public function testTrimRemovesLeadingAndTrailingWhitespace(): void
    {
        $this->assertSame('a b', self::call('trim', " \u{A0}a b\t"));
        $this->assertSame('a', self::call('trim', 'a'));
    }

    public function testPrimLeAndAdd(): void
    {
        $this->assertSame('[object Object]', self::call('prim', new Obj()));
        $this->assertSame('1,2', self::call('prim', [1, 2]));
        $this->assertTrue(self::call('le', '10', '9')); // string comparison: '9' < '10' is false
        $this->assertFalse(self::call('le', '9', '10'));
        $this->assertTrue(self::call('le', 1, 2));
        $this->assertSame('x5', self::call('add', 'x', 5));
        $this->assertSame(8.0, self::call('add', 3, 5));
    }

    public function testSliceFrom(): void
    {
        $this->assertSame('bc', self::call('sliceFrom', 'abc', 1));
        $this->assertSame([2], self::call('sliceFrom', [1, 2], 1));
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('slice is not a function');
        self::call('sliceFrom', 5, 0);
    }

    public function testShortKeepsElevenUnitsAndCutsTwelve(): void
    {
        $this->assertSame('abcdefghijk', self::call('short', 'abcdefghijk'));
        $this->assertSame('abcdefghij…', self::call('short', 'abcdefghijkl'));
        $this->assertSame('abcdefghij', self::call('short', 'abcdefghij'));
    }

    public function testRoundJs(): void
    {
        $this->assertSame(3.0, self::call('roundJs', 2.5));
        $this->assertSame(-2.0, self::call('roundJs', -2.5));
        $this->assertSame(2.0, self::call('roundJs', 2.4));
        // the largest double below 0.5: floor-based rounding gives 0 (PHP 8.3's round() pre-rounds it to 1)
        $this->assertSame(0.0, self::call('roundJs', 0.49999999999999994));
    }

    public function testValueSummaryShowsSixMembers(): void
    {
        $rest = Obj::of(['a' => 1, 'b' => 2, 'c' => 3, 'd' => 4, 'e' => 5, 'f' => 6, 'g' => 7]);
        $this->assertSame('a=1, b=2, c=3, d=4, e=5, f=6', self::call('valueSummary', $rest));
    }

    public function testRiskBandNeedsBothThresholds(): void
    {
        $this->assertSame('effective tier t=2', self::call('riskBand', 0.5, Jsx::$U, 0.7, 2));
        $this->assertSame('effective tier t=2', self::call('riskBand', 0.5, 0.7, Jsx::$U, 2));
        $this->assertSame('r 0.5 ≤ θ1 0.7 → claim band (t=1)', self::call('riskBand', 0.5, 0.7, 0.9, 2));
    }

    // ---- cleanText ------------------------------------------------------------------------------------------------------

    public function testCleanTextKeepsLoneSurrogatesAndStillRedacts(): void
    {
        $lone = "\xED\xA0\x80\xED\xAF\xBF\xED\xB0\x80\xED\xBF\xBF";
        $this->assertSame($lone, Explain::cleanText($lone));
        $this->assertSame("\xED\xA0\x80 token=[redacted]", Explain::cleanText("\xED\xA0\x80 token=abcdef"));
    }

    public function testCleanTextCutsAboveFourHundredUnits(): void
    {
        $s400 = str_repeat('a b ', 100);
        $this->assertSame($s400, Explain::cleanText($s400));
        $this->assertSame($s400 . '...', Explain::cleanText($s400 . 'c'));
    }

    // ---- condToText -----------------------------------------------------------------------------------------------------

    private static function leaf(string $f = 'f', string $op = 'eq', int $v = 1): Obj
    {
        return Obj::of(['field' => $f, 'op' => $op, 'value' => $v]);
    }

    private static function nots(int $k, mixed $c): mixed
    {
        for ($i = 0; $i < $k; $i++) {
            $c = Obj::of(['not' => $c]);
        }
        return $c;
    }

    private static function cond(mixed $c): string
    {
        return self::call('condToText', $c);
    }

    public function testConditionTextShapes(): void
    {
        $this->assertSame('f eq 1', self::cond(self::leaf()));
        $this->assertSame('(f eq 1 AND g lt 2)', self::cond(Obj::of(['all_of' => [self::leaf(), self::leaf('g', 'lt', 2)]])));
        $this->assertSame('(f eq 1 OR g lt 2)', self::cond(Obj::of(['any_of' => [self::leaf(), self::leaf('g', 'lt', 2)]])));
        $this->assertSame('NOT f eq 1', self::cond(self::nots(1, self::leaf())));
        $this->assertSame('f eq 1', self::cond(Obj::of(['all_of' => 5, 'field' => 'f', 'op' => 'eq', 'value' => 1])));
        $this->assertSame('f eq 1', self::cond(Obj::of(['any_of' => 5, 'field' => 'f', 'op' => 'eq', 'value' => 1])));
        $this->assertSame('f eq →r', self::cond(Obj::of(['field' => 'f', 'op' => 'eq', 'ref' => 'r'])));
        $this->assertSame('f eq', self::cond(Obj::of(['field' => 'f', 'op' => 'eq'])));
        $this->assertSame('undefined undefined', self::cond(['x']));
        $this->assertSame('<malformed>', self::cond(5));
    }

    public function testConditionDepthCap(): void
    {
        $this->assertSame(str_repeat('NOT ', 6) . 'f eq 1', self::cond(self::nots(6, self::leaf())));
        $this->assertSame(str_repeat('NOT ', 7) . '…', self::cond(self::nots(7, self::leaf())));
        foreach (['all_of', 'any_of'] as $k) {
            $this->assertSame(str_repeat('NOT ', 5) . '(f eq 1)', self::cond(self::nots(5, Obj::of([$k => [self::leaf()]]))), $k);
            $this->assertSame(str_repeat('NOT ', 6) . '(…)', self::cond(self::nots(6, Obj::of([$k => [self::leaf()]]))), $k);
        }
    }

    // ---- pinpoints ------------------------------------------------------------------------------------------------------

    public function testValidityPinpointBoundaries(): void
    {
        $vp = static fn(int $iat, int $exp, mixed $now): string => self::call('validityPinpoint', Obj::of(['iat' => $iat, 'exp' => $exp]), $now)['detail'];
        $this->assertSame('validity window invalid', $vp(0, Pca::MAX_LIFETIME_MS, Jsx::$U));
        $this->assertSame(sprintf('lifetime %dms exceeds the %dms maximum', Pca::MAX_LIFETIME_MS + 1, Pca::MAX_LIFETIME_MS), $vp(0, Pca::MAX_LIFETIME_MS + 1, Jsx::$U));
        $this->assertSame('validity window invalid', $vp(1000 + Pca::MAX_SKEW_MS, 1001 + Pca::MAX_SKEW_MS, 1000));
        $this->assertSame('validity window invalid', $vp(0, 1000, 1000));
        $this->assertSame('expired 1ms ago (exp 1000, now 1001)', $vp(0, 1000, 1001));
    }

    public function testLeafSignaturePinpointForASingleHop(): void
    {
        $out = self::call('leafSigPinpoint', Obj::of(['cap_chain' => [Obj::of(['holder' => 'h'])]]));
        $this->assertSame('leaf hop #0 signature (holder h, suite ed25519) does not verify', $out['detail']);
        $this->assertSame(0, $out['hop']);
    }

    // ---- explainVerification --------------------------------------------------------------------------------------------

    public function testCounterPassDetailsWithTwoArguments(): void
    {
        $e = self::noWarnings(static fn() => Explain::explainVerification(Obj::of(['counter' => 3]),
            Obj::of(['allow' => true, 'checks' => Obj::of(['counter' => 'pass', 'counter_format' => 'pass'])])));
        $detail = [];
        foreach ($e->get('checks') as $c) {
            $detail[$c->get('name')] = $c->get('detail');
        }
        $this->assertSame('counter 3 well-formed', $detail['counter']);
        $this->assertSame('counter 3 well-formed', $detail['counter_format']);
        $this->assertSame('allow', $e->get('verdict'));
    }

    public function testVerificationTextUppercasesTheVerdictBeyondAscii(): void
    {
        $this->assertSame("PCA verification — É\ns\n", Explain::verificationToText(Obj::of(['verdict' => 'é', 'summary' => 's', 'checks' => []])));
    }

    // ---- explainDecision ------------------------------------------------------------------------------------------------

    private static function decision(array $o = []): Obj
    {
        return Obj::of($o + ['admit' => false, 'releaseGuardianShare' => true, 'r' => 0.5,
            'requiredThreshold' => Obj::of(['t' => 2, 'proof' => 'p', 'optimisticAllowed' => false]), 'budget' => Obj::of(['B' => 0]), 'reasons' => ['r1']]);
    }

    private static function decide(Obj $d, ?Obj $opts = null): Obj
    {
        return self::noWarnings(static fn() => $opts === null ? Explain::explainDecision(null, $d) : Explain::explainDecision(null, $d, $opts));
    }

    /** @return list<array{0:string,1:bool}> */
    private static function caveatTypes(Obj $e): array
    {
        return array_map(static fn(Obj $c): array => [$c->get('type'), $c->get('delegated')], $e->get('caveats'));
    }

    public function testGrantReasonIsTheFirstPredicateReason(): void
    {
        $e = self::decide(self::decision(['releaseGuardianShare' => false, 'reasons' => ['no predicate permits x']]));
        $this->assertSame('no predicate permits x', $e->get('decisive')->get('reason'));
        $e = self::decide(self::decision(['releaseGuardianShare' => false, 'reasons' => ['predicate A', 'predicate B']]));
        $this->assertSame('predicate A', $e->get('grant')->get('reason'));
    }

    public function testEveryCaveatNamedInTheReasonIsUnsatisfied(): void
    {
        $env = Obj::of(['caveats' => [Obj::of(['type' => 'rate']), Obj::of(['type' => 'expires'])], 'risk_policy' => new Obj()]);
        $e = self::decide(self::decision(['reasons' => ['caveat(s) not satisfied: rate, expires']]), Obj::of(['envelope' => $env]));
        $this->assertFalse($e->get('caveats')[0]->get('satisfied'));
        $this->assertFalse($e->get('caveats')[1]->get('satisfied'));
    }

    public function testBudgetScanStopsAtTheFirstMatch(): void
    {
        $e = self::decide(self::decision(['reasons' => ['budget depleted', 5]]));
        $this->assertSame(['budget depleted', '5'], $e->get('reasons'));
        $this->assertSame('trust budget cannot cover the cost — step-up to t=3 (human recharge) required', $e->get('admission')->get('path'));
    }

    public function testDelegatedCaveatsStartAfterTheRootCount(): void
    {
        $leaf = Obj::of(['caveats' => [Obj::of(['type' => 'a']), Obj::of(['type' => 'b'])]]);
        $ctx = static fn(array $chain): Obj => Obj::of(['context' => Obj::of(['chain' => $chain])]);
        $this->assertSame([['a', true], ['b', true]], self::caveatTypes(self::decide(self::decision(), $ctx([null, $leaf]))));
        $this->assertSame([['a', true], ['b', true]], self::caveatTypes(self::decide(self::decision(), $ctx([Obj::of(['caveats' => 5]), $leaf]))));
        // a one-hop chain delegates nothing (its non-list caveats are never sliced)
        $e = self::decide(self::decision(), $ctx([Obj::of(['caveats' => 5])]));
        $this->assertSame([], $e->get('caveats'));
        $this->assertSame(['r1'], $e->get('reasons'));
    }

    public function testANonObjectActionIsAPredicateEvaluationError(): void
    {
        $e = self::decide(self::decision(), Obj::of(['envelope' => Obj::of(['risk_policy' => new Obj()]), 'context' => Obj::of(['action' => 'x'])]));
        $this->assertSame('predicate evaluation error (fail closed)', $e->get('decisive')->get('reason'));
        $this->assertSame(['r1'], $e->get('reasons'));
    }

    private static function grantedByDuplicate(): Obj
    {
        $p = Obj::of(['verb' => 'v', 'resource' => 'r']);
        return self::decide(self::decision(), Obj::of([
            'envelope' => Obj::of(['predicates' => [$p, $p], 'risk_policy' => new Obj()]),
            'context' => Obj::of(['action' => Obj::of(['action' => Obj::of(['verb' => 'v', 'resource' => 'r'])])]),
        ]));
    }

    public function testThePredicateIndexIsTheFirstOccurrence(): void
    {
        $g = self::grantedByDuplicate()->get('grant');
        $this->assertTrue($g->get('granted'));
        $this->assertSame(0, $g->get('predicateIndex'));
    }

    public function testCostWithANonPositiveKappaIsPositiveZero(): void
    {
        foreach ([-0.0, -2] as $kappa) {
            $env = Obj::of(['risk_policy' => Obj::of(['kappa' => $kappa])]);
            $cost = self::decide(self::decision(), Obj::of(['envelope' => $env]))->get('admission')->get('cost');
            $this->assertSame(0.0, $cost, (string)$kappa);
            $this->assertSame(INF, fdiv(1.0, $cost), (string)$kappa);
        }
    }

    public function testDecisionText(): void
    {
        $e = self::grantedByDuplicate();
        $e->set('verdict', 'é');
        $e->get('grant')->set('predicate', Obj::of(['verb' => [true, 'b']]));
        $e->set('caveats', [Obj::of(['satisfied' => true, 'remedy' => 'rx', 'detail' => 'd'])]);
        $t = Explain::decisionToText($e);
        $this->assertStringStartsWith('PCA decision — É (step-up)', $t);
        $this->assertStringContainsString('grants true|b on *', $t);
        $this->assertStringContainsString('  caveat ✓  : d', $t);
        $this->assertStringNotContainsString('rx', $t);
    }

    // ---- evalCaveat -----------------------------------------------------------------------------------------------------

    private static function toolCaveat(bool $requireX): Obj
    {
        $schema = Obj::of(['props' => Obj::of(['x' => Obj::of(['type' => 'string'])])] + ($requireX ? ['required' => ['x']] : []));
        return Obj::of(['type' => 'tool_schema', 'tool' => 'v', 'schema' => $schema, 'schema_digest' => Pca::hashCanonical($schema),
            'binding_digest' => Pca::hashCanonical(Obj::of(['tool' => 'v', 'signature_digest' => 'undefined', 'schema' => $schema]))]);
    }

    private static function evalCaveat(Obj $cv, Obj $action): bool
    {
        return self::call('evalCaveat', $cv, new Obj(), Obj::of(['action' => $action]));
    }

    public function testToolCallIsBuiltFromTheContextAction(): void
    {
        $this->assertTrue(self::evalCaveat(self::toolCaveat(true), Obj::of(['verb' => 'v', 'params' => Obj::of(['x' => 'hi'])])));
        $this->assertFalse(self::evalCaveat(self::toolCaveat(true), Obj::of(['verb' => 'w', 'params' => Obj::of(['x' => 'hi'])])));
        // no params: the call's args are an empty object
        $this->assertTrue(self::evalCaveat(self::toolCaveat(false), Obj::of(['verb' => 'v'])));
    }

    public function testPredicateCaveatSeesTheActionContext(): void
    {
        $cv = Obj::of(['type' => 'predicates', 'allow' => [Obj::of(['verb' => 'v', 'resource' => 'r'])]]);
        $this->assertTrue(self::evalCaveat($cv, Obj::of(['verb' => 'v', 'resource' => 'r'])));
        $this->assertFalse(self::evalCaveat($cv, Obj::of(['verb' => 'v', 'resource' => 's'])));
    }

    // ---- chains ---------------------------------------------------------------------------------------------------------

    private static function budget(int $limit): Obj
    {
        return Obj::of(['type' => 'budget_alloc', 'limit' => $limit]);
    }

    public function testBudgetNodeComesFromTheHopThatIntroducedIt(): void
    {
        $nodes = Explain::budgetAllocNodes([Obj::of(['id' => 'r']), Obj::of(['id' => 'l', 'caveats' => [self::budget(5)]])]);
        $this->assertCount(1, $nodes);
        $this->assertSame('l', $nodes[0]->get('capId'));
        $this->assertSame(1, $nodes[0]->get('depth'));
        $this->assertSame(0, $nodes[0]->get('caveatIndex'));
        $this->assertSame(5, $nodes[0]->get('limit'));
    }

    public function testBudgetNodeWithoutACapabilityId(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('canonicalize: undefined member');
        Explain::budgetAllocNodes([Obj::of(['caveats' => [self::budget(5)]])]);
    }

    public function testEnvelopeWithoutListsCountsZero(): void
    {
        $e = self::noWarnings(static fn() => Explain::explainChain([Obj::of(['issuer' => 'i', 'holder' => 'h', 'caveats' => [Obj::of(['type' => 'envelope'])]])]));
        $this->assertSame('grants envelope (0 predicate(s), 0 caveat(s))', $e->get('hops')[0]->get('narrowed'));
    }
}
