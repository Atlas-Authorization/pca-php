<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Decision;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Exact-outcome tests of the ternary decision, rule 20 (units) and rule 21 (tighten-only), and of their `units` / `tighten`
 * checks in the v2 pipeline (reported only when the signed envelope asks, so every other verification is unchanged).
 */
final class DecisionTest extends TestCase
{
    private static function j(string $t): mixed
    {
        return Json::parseLax($t);
    }

    public function testSharedVectorsRunAndNoneIsSkipped(): void
    {
        [$n, $fails] = Vectors::decision();
        $this->assertSame([], $fails);
        $this->assertGreaterThanOrEqual(74, $n);
    }

    public function testLatticeExactOutcomes(): void
    {
        $this->assertSame('deny', Decision::meet('allow', 'bogus'));
        $this->assertSame('deny', Decision::meet(null, 'allow'));
        $this->assertSame('allow', Decision::meetAll([]));
        $this->assertSame('escalate', Decision::meetAll(['allow', 'escalate', 'allow']));
        $this->assertSame('deny', Decision::meetAll(['allow', 'escalate', 'deny']));
        $this->assertSame('deny', Decision::tighten('allow', 'allow')); // only `ok` leaves the base alone
        $this->assertSame('allow', Decision::tighten('allow', 'ok'));
        $this->assertSame('deny', Decision::pepDecision('deny', true));
        $this->assertSame('bogus', Decision::pepDecision('bogus', true)); // not a decision: returned as is
        $this->assertSame('escalate', Decision::pepDecision('escalate', 1)); // only `true` counts as answered
    }

    public function testDecisionOfNeedsEveryFailingCheckEscalateClass(): void
    {
        $r = ['a: intent_required: q', 'b: escalate: asked'];
        $this->assertSame('allow', Decision::decisionOf(true, ['a' => 'fail'], []));
        $this->assertSame('escalate', Decision::decisionOf(false, ['a' => 'fail', 'b' => 'fail', 'c' => 'pass'], $r));
        $this->assertSame('deny', Decision::decisionOf(false, ['a' => 'fail', 'b' => 'fail', 'c' => 'fail'], $r));
        $this->assertSame('deny', Decision::decisionOf(false, ['a' => 'fail'], [])); // an unexplained failure never escalates
        $this->assertSame('deny', Decision::decisionOf(false, ['a' => 'fail'], ['a: intent_required: q', 'a: other']));
        $this->assertSame('deny', Decision::decisionOf(false, ['a' => 'pass'], [])); // no failing check: not an escalate
        $this->assertSame('deny', Decision::decisionOf(false, ['a' => 'fail'], ['a:intent_required: no space'])); // exact head
    }

    public function testTightenNullIsRejectedAndAbsentIsNot(): void
    {
        $r = Decision::decideTighten(self::j('{"tighten":null}'));
        $this->assertSame(['outcome' => 'deny', 'legacy' => false, 'offending' => [], 'reason' => 'malformed tighten list: tighten must be an array'], $r);
        $this->assertSame(['outcome' => 'ok', 'legacy' => false, 'offending' => []], Decision::decideTighten(self::j('{}')));
        $this->assertSame('deny', Decision::decideTighten(self::j('{"polarity":null}'))['outcome']);
        $this->assertSame('model_polarity must be \'legacy\' when present', Decision::decideTighten(self::j('{"polarity":"strict"}'))['reason']);
    }

    public function testTightenReasonsAreExact(): void
    {
        $ctx = '"context":{"env":{"class":{"tone":"hostile"}}}';
        $rule = '{"id":"r1","when":{"field":"env.class.tone","op":"eq","value":"hostile"},"signal":"escalate","reason":"tone"}';
        $r = Decision::decideTighten(self::j('{"tighten":[' . $rule . '],' . $ctx . '}'));
        $this->assertSame(['outcome' => 'escalate', 'legacy' => false, 'offending' => [], 'reason' => "escalate: asked by tighten rule 'r1' (tone)"], $r);
        $deny = str_replace('"escalate","reason":"tone"', '"deny"', $rule);
        $r = Decision::decideTighten(self::j('{"tighten":[' . $deny . '],' . $ctx . '}'));
        $this->assertSame("denied by tighten rule 'r1'", $r['reason']);
        $r = Decision::decideTighten(self::j('{"tighten":[' . $rule . ']}')); // the model value is missing: unknown -> escalate
        $this->assertSame("escalate: rule 'r1' could not be decided (a value it reads is missing or ill-typed)", $r['reason']);
        $dup = '{"tighten":[' . $rule . ',' . $rule . ']}';
        $this->assertSame("malformed tighten list: tighten[1].id 'r1' is a duplicate", Decision::decideTighten(self::j($dup))['reason']);
        $r = Decision::decideTighten(self::j('{"predicates":[[{"verb":"*","where":[{"field":"env.class.tone","op":"eq","value":"x"}]}]]}'));
        $this->assertSame("a grant's where reads model-derived path(s) env.class.tone: a model may only tighten (move them into tighten[]) (rule 21)", $r['reason']);
        $this->assertSame(['env.class.tone'], $r['offending']);
    }

    public function testUnitsReasonsAreExact(): void
    {
        $schema = '"schema_units":{"usd_minor":{"kind":"money","currency":"USD","exponent":2}},"verb_params":{"action.params.amount":{"unit":"usd_minor"}},"verb":"refund"';
        $tag = fn(string $t): string => '{"units":{"action.params.amount":' . $t . '},' . $schema . '}';
        $this->assertSame(['ok' => true], Decision::decideUnits(self::j($tag('{"kind":"money","currency":"USD","exponent":2}'))));
        $this->assertSame(['ok' => true], Decision::decideUnits(self::j($tag('{"kind":"money","currency":"USD","exponent":2.0}'))));
        $r = Decision::decideUnits(self::j($tag('{"kind":"money","currency":"USD","exponent":0}')));
        $this->assertSame(["ok" => false, 'reason' => "'action.params.amount' is declared as money/USD/e2 by the action schema but the policy term is tagged money/USD/e0 (unit confusion)"], $r);
        $r = Decision::decideUnits(self::j('{"units":{},' . $schema . ',"predicates":[[{"verb":"*","where":[{"field":"action.params.amount","op":"lt","value":5}]}]]}'));
        $this->assertSame(['ok' => false, 'reason' => "a policy term reads 'action.params.amount' (money/USD/e2) without a unit tag"], $r);
        $this->assertSame(['ok' => false, 'reason' => 'units must be an object'], Decision::decideUnits(self::j('{"units":null}')));
        $this->assertSame(['ok' => false, 'reason' => 'the verb is missing'], Decision::decideUnits(self::j('{"units":{}}')));
    }

    // ---- the v2 pipeline: units / tighten checks over the signed envelope -----------------------------------------------

    private static function grant(string $envelopeExtra): Obj
    {
        $risk = '"risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,"theta2":1,'
            . '"kappa":1,"lambda":0,"rho":0,"bMax":0}';
        return self::j('{"id":"g1","caveats":[{"type":"envelope","goal_commit":"x","predicates":[{"verb":"*","where":[]}],"caveats":[],'
            . '"agent_binding":{},' . $risk . $envelopeExtra . '}]}');
    }

    private static function pcactn(): Obj
    {
        return self::j('{"aud":"a","action":{"verb":"refund","resource":"r"}}');
    }

    /** @return array<string,array{ok:bool,reason?:string}> */
    private static function checks(array $d): array
    {
        $out = [];
        foreach ($d['checks'] as $c) {
            $out[$c['name']] = $c;
        }
        return $out;
    }

    public function testNoEnvelopeRuleMeansNoExtraCheck(): void
    {
        $d = IntentV2::decideIntentV2(self::pcactn(), self::grant(''), null, 1);
        $this->assertSame([], $d['checks']);
        $this->assertArrayNotHasKey('legacy_model_polarity', $d);
    }

    public function testAGrantThatReadsAModelPathIsRefusedByTheTightenCheck(): void
    {
        $g = self::grant(',"x":1');
        $env = $g->get('caveats')[0];
        $env->set('predicates', self::j('[{"verb":"*","where":[{"field":"env.judge.score","op":"gt","value":1}]}]'));
        $c = self::checks(IntentV2::decideIntentV2(self::pcactn(), $g, null, 1));
        $this->assertSame(['tighten'], array_keys($c));
        $this->assertFalse($c['tighten']['ok']);
        $this->assertStringContainsString('env.judge.score', $c['tighten']['reason']);
    }

    public function testLegacyPolarityLetsItThroughAndReportsDegraded(): void
    {
        $g = self::grant(',"model_polarity":"legacy"');
        $g->get('caveats')[0]->set('predicates', self::j('[{"verb":"*","where":[{"field":"env.judge.score","op":"gt","value":1}]}]'));
        $d = IntentV2::decideIntentV2(self::pcactn(), $g, null, 1);
        $this->assertTrue(self::checks($d)['tighten']['ok']);
        $this->assertTrue($d['legacy_model_polarity']);
        // the policy can force strict, which refuses the same grant
        $ctx = self::j('{"policy":{"model_polarity":"strict"}}');
        $d = IntentV2::decideIntentV2(self::pcactn(), $g, $ctx, 1);
        $this->assertFalse(self::checks($d)['tighten']['ok']);
        $this->assertArrayNotHasKey('legacy_model_polarity', $d);
    }

    public function testATightenRuleThatFiresEscalatesThroughTheCheck(): void
    {
        $g = self::grant(',"tighten":[{"id":"r1","when":{"field":"env.judge.score","op":"gt","value":5},"signal":"escalate"}]');
        $ctx = self::j('{"env":{"judge":{"score":9}}}');
        $c = self::checks(IntentV2::decideIntentV2(self::pcactn(), $g, $ctx, 1));
        $this->assertSame("escalate: asked by tighten rule 'r1'", $c['tighten']['reason']);
        $this->assertSame('escalate', Decision::decisionOf(false, ['tighten' => 'fail'], ['tighten: ' . $c['tighten']['reason']]));
        $ctx = self::j('{"env":{"judge":{"score":1}}}');
        $this->assertTrue(self::checks(IntentV2::decideIntentV2(self::pcactn(), $g, $ctx, 1))['tighten']['ok']);
    }
}
