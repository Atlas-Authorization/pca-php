<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RevocationStaleness;
use Atlas\Pca\Sign;
use Atlas\Pca\VerifyVerdict;
use PHPUnit\Framework\TestCase;

/**
 * The resource-server verdict, second battery: the grant's model rules read the verifier's own params and env, the caveat
 * language over root and delegated caveats, the bound tool signature, the plan node a proof names, the freshness and revocation
 * epoch gates, the assurance report of labelled hooks, the escalation budget and the first-failure rule between equal ranks.
 */
final class ProofSurvivorKill5bVerifyVerdictTest extends TestCase
{
    private const NOW = 1791288000000;
    private const UNITS = 'units: this verifier has no action schema configured';
    private const MODEL_WHERE = "tighten: a grant's where reads model-derived path(s) env.class.label: a model may only tighten (move them into tighten[]) (rule 21)";

    private static function kp(int $b): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    private static function plan(): array
    {
        return [['id' => 'n1', 'verb' => 'v', 'resource' => 'r', 'reversibility_class' => 'reversible'], ['id' => 'n2', 'verb' => 'w', 'resource' => 'r']];
    }

    private static function grant(array $env = []): Obj
    {
        return Sign::mintGrant(self::kp(1), self::kp(2)->public, $env + ['predicates' => [['verb' => 'v', 'resource' => 'r'], ['verb' => 'w', 'resource' => 'r']],
            'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()], 'g', 's')['grant'];
    }

    /** The grant with a root caveat outside its envelope. */
    private static function rootCaveatGrant(array $caveat): Obj
    {
        return Sign::mintRoot(self::kp(1), self::kp(2)->public, [self::grant()->get('caveats')[0], $caveat]);
    }

    private static function pcactn(Obj $g, array $extra = [], ?array $chain = null, ?array $plan = null, mixed $params = null, int $signer = 2): Obj
    {
        return Sign::buildPcactn($g, $chain ?? [$g], $plan ?? self::plan(), 'n1', 1, self::kp($signer), 'aud', $params, self::NOW, self::NOW + 60000, 60000, $extra);
    }

    private static function opts(Obj $g, array $ctx = [], array $o = []): array
    {
        return $o + ['grant' => $g, 'now' => self::NOW, 'audience' => 'aud', 'hooks' => ['revocation' => static fn(): array => ['enforced' => true, 'ok' => true]],
            'context' => Sign::n($ctx + ['plan' => self::plan(), 'planAuthorized' => true,
                'risk' => ['reversibility' => 1, 'blastRadius' => 0, 'confidence' => 1, 'semanticDistance' => 0, 'taint' => 0],
                'budget' => ['B' => 1, 'tau' => self::NOW, 'asOf' => self::NOW]])];
    }

    private static function rule(string $field, mixed $value, string $signal = 'deny'): array
    {
        return ['id' => 't1', 'when' => ['field' => $field, 'op' => 'eq', 'value' => $value], 'signal' => $signal];
    }

    private static function modelWhereGrant(array $env = []): Obj
    {
        return self::grant($env + ['predicates' => [['verb' => 'v', 'resource' => 'r', 'where' => [['field' => 'env.class.label', 'op' => 'eq', 'value' => 'ok']]]]]);
    }

    // ---- the grant's model rules: the verifier hands the core its own env and params

    public function testATightenRuleReadsTheVerifierEnv(): void
    {
        $g = self::grant(['tighten' => [self::rule('env.region', 'eu')]]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['env' => ['region' => 'us']]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
        $this->assertSame([], $v['reasons']);
        $this->assertSame('pass', $v['checks']['tighten']);
    }

    public function testATightenRuleReadsTheIntentV2Env(): void
    {
        $g = self::grant(['tighten' => [self::rule('env.region', 'eu')]]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, o: ['intentV2' => Sign::n(['env' => ['region' => 'us']])]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
    }

    public function testTheIntentV2EnvWinsOverTheContextEnv(): void
    {
        $g = self::grant(['tighten' => [self::rule('env.region', 'eu')]]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['env' => ['region' => 'eu']], ['intentV2' => Sign::n(['env' => ['region' => 'us']])]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
    }

    public function testATightenRuleReadsTheVerifierParams(): void
    {
        $g = self::grant(['tighten' => [self::rule('action.params.x', 2)]]);
        $v = VerifyVerdict::verify(self::pcactn($g, params: ['x' => 1]), self::opts($g, ['params' => ['x' => 1]]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
        $this->assertSame('pass', $v['checks']['params_digest']);
    }

    public function testTheIntentV2ParamsWinOverTheContextParams(): void
    {
        $g = self::grant(['tighten' => [self::rule('action.params.x', 1)]]);
        $v = VerifyVerdict::verify(self::pcactn($g, params: ['x' => 1]), self::opts($g, ['params' => ['x' => 1]], ['intentV2' => Sign::n(['params' => ['x' => 2]])]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
    }

    public function testAModelRuleFailureIsListedAfterAnEarlierFailure(): void
    {
        $g = self::modelWhereGrant();
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['env' => ['class' => ['label' => 'ok']]], ['audience' => 'other']));
        $this->assertFalse($v['allow']);
        $this->assertStringStartsWith('audience: ', $v['reasons'][0]);
        $this->assertContains(self::MODEL_WHERE, $v['reasons']);

        $g = self::grant(['units' => Sign::n(['action.params.x' => ['kind' => 'count']])]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, o: ['audience' => 'other']));
        $this->assertStringStartsWith('audience: ', $v['reasons'][0]);
        $this->assertContains(self::UNITS, $v['reasons']);
    }

    public function testOfTwoEqualRankFailuresTheFirstIsTheReason(): void
    {
        $g = self::modelWhereGrant(['units' => Sign::n(['action.params.x' => ['kind' => 'count']])]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['env' => ['class' => ['label' => 'ok']]]));
        $this->assertSame(self::UNITS, $v['reasons'][0]);
        $this->assertContains(self::MODEL_WHERE, $v['reasons']);
    }

    public function testALegacyPolarityPassIsReportedDegraded(): void
    {
        $g = self::modelWhereGrant(['model_polarity' => 'legacy']);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['env' => ['class' => ['label' => 'ok']]], ['assurance' => true]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
        $this->assertSame(['outcome' => 'pass', 'degraded' => true, 'reason' => "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)"],
            $v['assurance']['tighten']);

        $g = self::grant(['tighten' => [self::rule('env.region', 'eu')]]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['env' => ['region' => 'us']], ['assurance' => true]));
        $this->assertSame(['outcome' => 'pass'], $v['assurance']['tighten']);
    }

    // ---- an escalation keeps the post-decision budget, and only then

    public function testAnEscalationCarriesTheBudget(): void
    {
        $g = self::grant(['tighten' => [self::rule('env.region', 'eu', 'escalate')]]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['env' => ['region' => 'eu']]));
        $this->assertFalse($v['allow']);
        $this->assertSame("tighten: escalate: asked by tighten rule 't1'", $v['reasons'][0]);
        $this->assertArrayHasKey('budget', $v);

        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['env' => ['region' => 'eu'], 'budget' => null]));
        $this->assertFalse($v['allow']);
        $this->assertArrayNotHasKey('budget', $v);
    }

    // ---- the caveat language (K1) over a root caveat and over delegated caveats

    public function testARootSealedCaveatPassesWithTheLanguageConfigured(): void
    {
        $g = self::rootCaveatGrant(['type' => 'sealed']);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, o: ['k1' => new Obj()]));
        $this->assertSame('pass', $v['checks']['delegated_caveats']);
        $this->assertSame('pass', $v['checks']['policy']);
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
    }

    public function testARootSealedCaveatFailsWithoutTheLanguage(): void
    {
        $g = self::rootCaveatGrant(['type' => 'sealed']);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g));
        $this->assertFalse($v['allow']);
        $this->assertSame('fail', $v['checks']['delegated_caveats']);
        $this->assertContains('delegated_caveats: delegation caveat(s) not satisfied: sealed (the caveat language is not configured (no k1 input))', $v['reasons']);
    }

    public function testADelegatedSealedCaveatIsLeftToTheLanguage(): void
    {
        $g = self::grant();
        $child = Sign::delegate($g, self::kp(2), self::kp(3)->public, [['type' => 'sealed']]);
        $v = VerifyVerdict::verify(self::pcactn($g, chain: [$g, $child], signer: 3), self::opts($g, o: ['k1' => new Obj()]));
        $this->assertSame('pass', $v['checks']['delegated_caveats']);
    }

    public function testTheLanguageRunsOnlyForANarrowBlockOrALanguageCaveat(): void
    {
        $g = self::grant();
        // no K1 caveat and no narrow block: the language never runs, so its safe-integer clock rule cannot fail the hop caveats
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, o: ['k1' => new Obj(), 'now' => self::NOW + 0.5]));
        $this->assertSame('pass', $v['checks']['delegated_caveats']);
        // a narrow block alone makes it run (and this one does not verify)
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, o: ['k1' => Sign::n(['narrow' => 'x'])]));
        $this->assertSame('fail', $v['checks']['delegated_caveats']);
    }

    // ---- the signed tool binding reaches the tool_schema caveat

    public function testTheSignedToolBindingMustMatchTheAuthorizedSignature(): void
    {
        $schema = Sign::n(['props' => ['q' => ['type' => 'string']], 'required' => []]);
        $tool = static fn(string $sig): array => ['type' => 'tool_schema', 'tool' => 'v', 'schema' => $schema, 'schema_digest' => Pca::hashCanonical($schema),
            'signature_digest' => $sig, 'binding_digest' => Pca::hashCanonical(Sign::n(['tool' => 'v', 'signature_digest' => $sig, 'schema' => $schema]))];
        $tb = Pca::b64u(str_repeat("\x05", 32));
        $g = self::grant();
        foreach ([[$tb, 'pass'], [Pca::b64u(str_repeat("\x06", 32)), 'fail']] as [$sig, $want]) {
            $child = Sign::delegate($g, self::kp(2), self::kp(3)->public, [$tool($sig)]);
            $v = VerifyVerdict::verify(self::pcactn($g, ['tool_binding' => $tb], [$g, $child], signer: 3), self::opts($g));
            $this->assertSame($want, $v['checks']['delegated_caveats'], implode(' | ', $v['reasons']));
        }
    }

    // ---- the plan node the proof names feeds the semantic distance

    public function testTheSignedNodeIdFeedsTheSemanticDistance(): void
    {
        $plan = [['id' => 'n1', 'verb' => 'v', 'resource' => 'r', 'reversibility_class' => 'reversible']];
        $g = self::grant();
        $v = VerifyVerdict::verify(self::pcactn($g, plan: $plan), self::opts($g, ['plan' => $plan, 'risk' => ['reversibility' => 1, 'blastRadius' => 0, 'confidence' => 1, 'taint' => 0]]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
        $this->assertLessThan(0.1, $v['r']); // the goal is the node itself: distance 0 (an unknown node is distance 1)
    }

    // ---- hooks given as an object

    public function testHooksMayBeAnObject(): void
    {
        $g = self::grant();
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, o: ['hooks' => Obj::of(['revocation' => static fn(): array => ['enforced' => true, 'ok' => true]])]));
        $this->assertSame('pass', $v['checks']['revocation']);
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
    }

    public function testAHookFailureBeforeAThrowingStageIsKept(): void
    {
        $g = self::grant();
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, o: ['hooks' => [
            'attestation' => static fn(): array => ['enforced' => true, 'ok' => false, 'reason' => 'zk_compliance proof missing'],
            'threshold' => static fn() => throw new \RuntimeException('boom'),
            'revocation' => static fn(): array => ['enforced' => true, 'ok' => true]]]));
        $this->assertFalse($v['allow']);
        $this->assertSame('attestation: zk_compliance proof missing', $v['reasons'][0]);
    }

    // ---- the assurance report reads the labels of the hooks that ran

    public function testTheAssuranceReportCarriesHookLabels(): void
    {
        $g = self::grant();
        $rev = Assurance::setLabel(static fn(): array => ['enforced' => true, 'ok' => true], new AssuranceLabel('software', 'acme'));
        $zk = Assurance::setLabel(static fn(): array => ['enforced' => true, 'ok' => true], new AssuranceLabel('stark'));
        $v = VerifyVerdict::verify(self::pcactn($g, ['zk_compliance' => ['proof' => 'p']]), self::opts($g, o: ['assurance' => true, 'hooks' => ['revocation' => $rev, 'zk' => $zk]]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
        $this->assertSame(['outcome' => 'pass', 'level' => 'software', 'vendor' => 'acme'], $v['assurance']['revocation']);
        $this->assertSame('stark', $v['assurance']['zk_compliance']['level']);
    }

    // ---- the freshness gate and the revocation epoch

    public function testAFractionalEpochLengthIsNotTruncated(): void
    {
        $g = self::grant();
        // anchor = epoch 2 x 1.5 ms = 3 > now 2: in the future (a truncated 1 ms epoch would put it at 2, a pass)
        $p = self::pcactn($g, ['freshness' => ['beacon_ref' => 'b', 'epoch' => 2, 'accumulator_witness' => '']]);
        $v = VerifyVerdict::verify($p, self::opts($g, o: ['enforce' => ['freshness' => Sign::n(['epochMs' => 1.5, 'maxAgeMs' => 1000, 'now' => 2])]]));
        $this->assertSame('fail', $v['checks']['freshness']);
        $this->assertSame('freshness: freshness anchor is in the future', $v['reasons'][0]);
    }

    public function testAProofOlderThanTheRevocationEpochIsStale(): void
    {
        $g = self::grant();
        $ep = RevocationStaleness::signEpoch(str_repeat("\x0b", 32), ['instance_id' => 'i1', 'grant_ref' => $g->get('id'), 'epoch' => 5, 'set_size' => 0,
            'root' => 'r', 'issued_at' => self::NOW - 1000, 'not_after' => self::NOW + 60000]);
        $ctx = ['revocationEpoch' => ['epoch' => $ep, 'guardianPublic' => $ep->get('guardian')]];
        foreach ([[5, 'pass'], [1, 'fail']] as [$epoch, $want]) {
            $p = self::pcactn($g, ['freshness' => ['beacon_ref' => '', 'epoch' => $epoch, 'accumulator_witness' => '']]);
            $v = VerifyVerdict::verify($p, self::opts($g, $ctx));
            $this->assertSame($want, $v['checks']['freshness'], implode(' | ', $v['reasons']));
        }
        $this->assertContains('freshness: PCActn freshness.epoch 1 predates the revocation epoch 5', $v['reasons']);
    }
}
