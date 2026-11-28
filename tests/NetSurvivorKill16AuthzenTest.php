<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authzen;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** A search provider given as a class name: its static methods are not a provider object's methods. */
final class NetSurvivorKill16StaticProvider
{
    public static function searchSubject(mixed $r): array
    {
        return ['results' => []];
    }
}

/** A search provider object with one search method. */
final class NetSurvivorKill16ObjectProvider
{
    public function searchSubject(mixed $r): array
    {
        return ['results' => []];
    }
}

/**
 * The AuthZEN PDP past the proof checks: a verified PCActn reaches the policy (injected decide / deriveDecideInput), the decide
 * input it is given, the permit, policy-deny, authorizer and AARP approval outcomes with their exact contexts, the verify-stage
 * refusals (plan root, audience opt-out, freshness, enforce), the boxcar merge and break rules, the COAZ tool mapping, the search
 * request guards and provider lookup, and the clock.
 */
final class NetSurvivorKill16AuthzenTest extends TestCase
{
    private const NOW = 1_800_000_000_000;
    private const AUD = 'aud';
    private const PLAN = [['id' => 'a', 'verb' => 'doc.read', 'resource' => 'doc:1']];
    private const PERMIT = ['releaseGuardianShare' => true, 'admit' => true, 'r' => 0.1, 'requiredThreshold' => ['t' => 1]];

    protected function tearDown(): void
    {
        Authzen::$clockHook = null;
    }

    private static function key(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/net16-az-' . $label, true));
    }

    private static function plainGrant(): Obj
    {
        return Sign::mintRoot(self::key('principal'), self::key('holder')->public, []);
    }

    /** @return array{grant: Obj, goal_commit: string} a root intent grant whose envelope prices bMax at 5 */
    private static function envelopeGrant(): array
    {
        return Sign::mintGrant(self::key('principal'), self::key('holder')->public,
            ['predicates' => [], 'caveats' => [], 'risk_policy' => ['bMax' => 5] + Sign::defaultRiskPolicy()], 'read a document', 'net16-salt');
    }

    private static function pcactn(Obj $grant, mixed $params = ['k' => 'v'], int $iat = self::NOW): Obj
    {
        return Sign::buildPcactn($grant, [$grant], self::PLAN, 'a', 1, self::key('holder'), self::AUD, $params, $iat, null, 1000);
    }

    /** An Access Evaluation request for doc.read on doc:1 carrying `$p` (null: none). */
    private static function request(?Obj $p, array $context = []): array
    {
        $ctx = $context + ['env1' => 'e'];
        if ($p !== null) {
            $ctx['pca_action'] = Json::canonicalizeStrict($p);
        }
        return ['subject' => ['type' => 'user', 'id' => 'u1', 'properties' => ['role' => 'r']], 'action' => ['name' => 'doc.read', 'properties' => ['k' => 'v']],
            'resource' => ['type' => 'doc', 'id' => '1'], 'context' => $ctx];
    }

    /** @var list<array{0: mixed, 1: array}> every deriveDecideInput call */
    private array $derived = [];

    private function cfg(Obj $grant, mixed $decision = self::PERMIT, array $c = [], array $ctx = []): array
    {
        return $c + [
            'resolve' => static fn(mixed $req): array => $ctx + ['grant' => $grant, 'policy' => new Obj()],
            'now' => static fn(): int => self::NOW, 'audience' => self::AUD, 'insecureSkipPlanRootCheck' => true, 'requireAuthorizer' => false,
            'deriveDecideInput' => function (mixed $p, array $dctx): string {
                $this->derived[] = [$p, $dctx];
                return 'decide-input';
            },
            'decide' => static fn(mixed $i): mixed => $i === 'decide-input' ? $decision : null,
        ];
    }

    private static function denied(string $reason, ?int $status = null): array
    {
        $ctx = ['reason_admin' => ['denied' => true, 'reason' => $reason], 'reason_user' => ['message' => $reason]];
        if ($status !== null) {
            $ctx['error'] = ['status' => $status, 'message' => $reason];
        }
        return ['decision' => false, 'context' => $ctx];
    }

    private static function permitted(): array
    {
        return ['decision' => true, 'context' => ['reason_admin' => ['stage' => 'policy', 'risk' => 0.1, 'threshold' => ['t' => 1]]]];
    }

    /** Runs $f with every PHP warning / notice turned into a thrown error. */
    private static function noWarnings(\Closure $f): mixed
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    // ---- guards and mapping ------------------------------------------------------------------------------------------------

    /** A non-empty PHP associative array is a JSON object; approvalOf(null) reads a member of null and throws as JS does. */
    public function testRecordsAndApprovalOfNull(): void
    {
        $this->assertTrue(Authzen::isAuthzenSubject(['type' => 'user', 'id' => '1']));
        $this->assertTrue(Authzen::isAuthzenAction(['name' => 'read']));
        $this->assertNull(Authzen::approvalOf([]));
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("Cannot read properties of null (reading 'context')");
        Authzen::approvalOf(null);
    }

    /** defaultToAction reads PHP-array properties member by member; an integer-like property name fails where the member is stored. */
    public function testDefaultToActionReadsArrayProperties(): void
    {
        $m = Authzen::defaultToAction(['action' => ['name' => 'n', 'properties' => ['k' => 'v', 'j' => 'w']], 'resource' => ['type' => 't', 'id' => 'i']]);
        $this->assertSame(['k', 'j'], $m['params']->keys());
        $this->assertSame(['v', 'w'], [$m['params']->get('k'), $m['params']->get('j')]);
        $r = Authzen::evaluate(['resolve' => static fn(): array => ['grant' => new Obj(), 'policy' => new Obj()], 'now' => static fn(): int => self::NOW],
            ['subject' => ['type' => 'u', 'id' => '1'], 'action' => ['name' => 'n', 'properties' => ['5' => 'w']], 'resource' => ['type' => 't', 'id' => 'i']]);
        $this->assertFalse($r['decision']);
        $this->assertStringContainsString('Obj::set()', $r['context']['reason_admin']['reason']);
    }

    // ---- static admission (requireProof: false) -------------------------------------------------------------------------------

    /** Without a proof and requireProof false the host's admitsConcrete decides over the mapped action (the ctx toAction wins). */
    public function testStaticAdmission(): void
    {
        $seen = [];
        $admits = static function (mixed $policy, mixed $mapped) use (&$seen): bool {
            $seen[] = $mapped;
            return $mapped['verb'] === 'doc.read';
        };
        $c = ['resolve' => static fn(): array => ['grant' => new Obj(), 'policy' => new Obj()], 'now' => static fn(): int => self::NOW, 'requireProof' => false,
            'admitsConcrete' => $admits];
        $req = self::request(null);
        $this->assertSame(['decision' => true, 'context' => ['reason_admin' => ['reason' => 'statically admissible under the declared authority']]], Authzen::evaluate($c, $req));
        $this->assertSame(Authzen::defaultToAction($req)['verb'], $seen[0]['verb']);
        $c['resolve'] = static fn(): array => ['grant' => new Obj(), 'policy' => new Obj(), 'toAction' => static fn(): array => ['verb' => 'other']];
        $this->assertSame(self::denied('action is not admissible under the declared authority'), Authzen::evaluate($c, $req));
        $this->assertSame(['verb' => 'other'], $seen[1]);
        // a function NAME is not a configured callable
        $c['admitsConcrete'] = 'is_array';
        $this->assertSame(self::denied('evaluation error (fail closed): authzen: config.admitsConcrete is not provided (fail closed)', 500), Authzen::evaluate($c, $req));
        // the default requireProof refuses a request without a proof
        unset($c['requireProof']);
        $this->assertSame(self::denied('a signed PCActn is required (requireProof)'), Authzen::evaluate($c, $req));
    }

    /** A carried PCActn of exactly the artifact limit is parsed (here: no action, a fail-closed evaluation error); one byte more is malformed. */
    public function testACarriedProofAtTheArtifactLimitIsParsed(): void
    {
        $c = ['resolve' => static fn(): array => ['grant' => new Obj(), 'policy' => new Obj()], 'now' => static fn(): int => self::NOW,
            'authorizer' => static fn(): array => ['allow' => true]];
        $req = self::request(null);
        $req['context']['pca_action'] = '{"x":"' . str_repeat('a', Pca::MAX_ARTIFACT_BYTES - 8) . '"}';
        $this->assertSame(Pca::MAX_ARTIFACT_BYTES, strlen($req['context']['pca_action']));
        $this->assertSame(self::denied("evaluation error (fail closed): Cannot read properties of undefined (reading 'verb')", 500), Authzen::evaluate($c, $req));
        $req['context']['pca_action'] .= ' ';
        $this->assertSame(self::denied('context carries a malformed PCActn'), Authzen::evaluate($c, $req));
    }

    // ---- the verified path -------------------------------------------------------------------------------------------------------

    /** A verified proof reaches the policy with the decide input built from the ctx and the mapping; an admitted release permits. */
    public function testAPermitAndTheDecideInput(): void
    {
        $g = self::plainGrant();
        $p = self::pcactn($g);
        $r = self::noWarnings(fn(): array => Authzen::evaluate($this->cfg($g), self::request($p)));
        $this->assertSame(self::permitted(), $r);
        $this->assertCount(1, $this->derived);
        [$dp, $d] = $this->derived[0];
        $this->assertSame(Json::canonicalizeStrict($p), Json::canonicalizeStrict($dp));
        $this->assertSame(['grant', 'chain', 'params', 'risk', 'budget', 'now', 'subject', 'env'], array_keys($d));
        $this->assertSame($g, $d['grant']);
        $this->assertSame(Json::canonicalizeStrict($p->get('cap_chain')), Json::canonicalizeStrict($d['chain']));
        $this->assertSame([['k'], 'v'], [$d['params']->keys(), $d['params']->get('k')]);
        $this->assertInstanceOf(Obj::class, $d['risk']);
        $this->assertSame([], $d['risk']->keys());
        $this->assertSame(['B' => 0, 'tau' => self::NOW, 'asOf' => self::NOW], $d['budget'], 'a grant without an envelope starts at B = 0');
        $this->assertSame(self::NOW, $d['now']);
        $this->assertSame(['role' => 'r'], $d['subject']);
        $this->assertSame([['env1'], 'e'], [$d['env']->keys(), $d['env']->get('env1')]);
    }

    /** The ctx's chain, risk, budget and plan are handed on as given; an envelope's bMax seeds a fresh budget. */
    public function testTheCtxInputsAndTheEnvelopeBudget(): void
    {
        $g = self::plainGrant();
        $risk = Obj::of(['taint' => 'x']);
        $budget = ['B' => 9, 'tau' => 1, 'asOf' => 1];
        $r = Authzen::evaluate($this->cfg($g, self::PERMIT, [], ['chain' => 'C', 'risk' => $risk, 'budget' => $budget, 'plan' => 'P']), self::request(self::pcactn($g)));
        $this->assertSame(self::permitted(), $r);
        $d = $this->derived[0][1];
        $this->assertSame(['C', $risk, $budget, 'P'], [$d['chain'], $d['risk'], $d['budget'], $d['plan']]);
        $e = self::envelopeGrant();
        $this->assertSame(self::permitted(), Authzen::evaluate($this->cfg($e['grant']), self::request(self::pcactn($e['grant']))));
        $b = $this->derived[1][1]['budget'];
        $this->assertInstanceOf(Num::class, $b['B']);
        $this->assertSame([5.0, self::NOW, self::NOW], [$b['B']->float(), $b['tau'], $b['asOf']]);
    }

    /** A ctx toAction maps the request: a PHP-array params object is the params; a params that is no object is the empty object. */
    public function testTheMappedParams(): void
    {
        $g = self::plainGrant();
        $map = static fn(mixed $params): array => ['toAction' => static fn(): array => ['verb' => 'doc.read', 'resource' => 'doc:1', 'params' => $params]];
        $this->assertSame(self::permitted(), Authzen::evaluate($this->cfg($g, self::PERMIT, [], $map(['k' => 'v'])), self::request(self::pcactn($g))));
        $this->assertSame(self::permitted(), Authzen::evaluate($this->cfg($g, self::PERMIT, [], $map('x')), self::request(self::pcactn($g, new Obj()))));
        $this->assertSame(self::denied("the request attributes do not match the PCActn's signed params_digest"),
            Authzen::evaluate($this->cfg($g, self::PERMIT, [], $map('x')), self::request(self::pcactn($g))));
    }

    /** A policy that does not release the share is a policy denial with its reasons and risk. */
    public function testAPolicyDenial(): void
    {
        $g = self::plainGrant();
        $r = Authzen::evaluate($this->cfg($g, ['releaseGuardianShare' => false, 'reasons' => ['no'], 'r' => 0.5]), self::request(self::pcactn($g)));
        $this->assertSame(['decision' => false, 'context' => ['reason_admin' => ['denied' => true, 'stage' => 'policy', 'reasons' => ['no'], 'risk' => 0.5],
            'reason_user' => ['message' => 'the policy does not permit this action']]], $r);
    }

    /** The authorizer gets the operation, the PCActn and a forwarded provenance bundle; its answer is read from an array, an Obj or an object. */
    public function testTheAuthorizer(): void
    {
        $g = self::plainGrant();
        $p = self::pcactn($g);
        $inputs = [];
        $run = function (mixed $answer, array $context = []) use ($g, $p, &$inputs): array {
            $c = $this->cfg($g, self::PERMIT, ['authorizer' => static function (array $in) use ($answer, &$inputs): mixed {
                $inputs[] = $in;
                return $answer;
            }]);
            unset($c['requireAuthorizer']);
            return Authzen::evaluate($c, self::request($p, $context));
        };
        foreach ([['allow' => true], Obj::of(['allow' => true]), (object)['allow' => true]] as $yes) {
            $this->assertSame(self::permitted(), $run($yes));
        }
        $this->assertSame(['operation', 'pcactn'], array_keys($inputs[0]));
        $this->assertSame(['verb' => 'doc.read', 'resource' => 'doc:1'], array_slice($inputs[0]['operation'], 0, 2));
        $this->assertSame('v', $inputs[0]['operation']['params']->get('k'));
        $this->assertSame(Json::canonicalizeStrict($p), Json::canonicalizeStrict($inputs[0]['pcactn']));
        $run(['allow' => true], ['pca_provenance' => 'PV']);
        $this->assertSame('PV', $inputs[3]['provenance']);
        foreach ([[['allow' => false, 'reason' => 'a'], 'a'], [Obj::of(['allow' => false, 'reason' => 'b']), 'b'], [(object)['allow' => false, 'reason' => 'c'], 'c']] as [$no, $why]) {
            $this->assertSame(['decision' => false, 'context' => ['reason_admin' => ['denied' => true, 'stage' => 'authorize', 'reason' => $why],
                'reason_user' => ['message' => 'the proof-carrying action was not authorized']]], $run($no));
        }
    }

    /** An admitted release without the authorizer configured and requireAuthorizer false is a permit (the authorizer is not called). */
    public function testNoAuthorizerWhenNotRequired(): void
    {
        $g = self::plainGrant();
        $this->assertSame(self::permitted(), Authzen::evaluate($this->cfg($g), self::request(self::pcactn($g))));
        $c = $this->cfg($g);
        unset($c['requireAuthorizer']);
        $this->assertSame(self::denied('no replay/revocation authorizer is configured (requireAuthorizer)'), Authzen::evaluate($c, self::request(self::pcactn($g))));
    }

    private static function approvalId(Obj $p): string
    {
        $act = $p->get('action');
        $body = Obj::of(['d' => 'atlas-pca/authzen/aarp/v1', 'verb' => $act->get('verb'), 'resource' => $act->get('resource'),
            'params_digest' => $act->get('params_digest'), 'at' => self::NOW]);
        $body->set('counter', $p->get('counter'));
        return Pca::hashCanonical(Sign::n($body));
    }

    /** A release that is not admitted is an AARP approval request: its id, tier, threshold, reason and the envelope's goal commit. */
    public function testAnApprovalRequest(): void
    {
        $e = self::envelopeGrant();
        $p = self::pcactn($e['grant']);
        $rt = ['t' => 3, 'proof' => 'strong', 'optimisticAllowed' => false];
        $r = self::noWarnings(fn(): array => Authzen::evaluate($this->cfg($e['grant'], ['releaseGuardianShare' => true, 'admit' => false, 'r' => 0.7,
            'requiredThreshold' => $rt, 'reasons' => ['first', 'second']]), self::request($p)));
        $id = self::approvalId($p);
        $this->assertSame(['decision' => false, 'context' => [
            'id' => $id,
            'reason_admin' => ['stage' => 'step_up', 'risk' => 0.7, 'threshold' => $rt, 'reasons' => ['first', 'second']],
            'reason_user' => ['message' => 'approval required before this action can proceed'],
            'pca_approval' => ['approval_required' => true, 'auth_req_id' => $id, 'tier' => 3, 'required_threshold' => $rt, 'goal_commit' => $e['goal_commit'],
                'risk' => 0.7, 'reason' => 'first', 'requested_at' => self::NOW],
        ]], $r);
        // tier 2 below t = 3, the default reason without reasons, and no goal commit without an envelope
        $g = self::plainGrant();
        foreach ([[['t' => 2], null], [['t' => 1], []], [['t' => 2], 'not a list']] as [$rt2, $reasons]) {
            $r = self::noWarnings(fn(): array => Authzen::evaluate($this->cfg($g, ['releaseGuardianShare' => true, 'admit' => false, 'requiredThreshold' => $rt2,
                'reasons' => $reasons]), self::request(self::pcactn($g))));
            $a = $r['context']['pca_approval'];
            $this->assertSame([false, 2, 'requires tier-2 co-sign', '', $rt2], [$r['decision'], $a['tier'], $a['reason'], $a['goal_commit'], $a['required_threshold']]);
        }
    }

    /** The verify stage: no plan-root policy refuses, a listed root or the opt-out (any truthy value) admits. */
    public function testThePlanRootPolicy(): void
    {
        $g = self::plainGrant();
        $p = self::pcactn($g);
        $c = $this->cfg($g);
        unset($c['insecureSkipPlanRootCheck']);
        $r = Authzen::evaluate($c, self::request($p));
        $why = 'plan_root_authorized: no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)';
        $this->assertFalse($r['decision']);
        $this->assertSame(['denied' => true, 'stage' => 'verify'], array_slice($r['context']['reason_admin'], 0, 2));
        $this->assertFalse($r['context']['reason_admin']['checks']['plan_root_authorized']);
        $this->assertSame($why, $r['context']['reason_admin']['reason']);
        $this->assertSame(['message' => 'the proof-carrying action did not verify'], $r['context']['reason_user']);
        $this->assertSame(['reason_admin', 'reason_user'], array_keys($r['context']));
        $this->assertSame(self::permitted(), Authzen::evaluate($c + ['authorizedPlanRoots' => [$p->get('plan')->get('root')]], self::request($p)));
        $this->assertSame(self::permitted(), Authzen::evaluate(['insecureSkipPlanRootCheck' => 1] + $c, self::request($p)));
    }

    /** audience: a string is exact, an explicit null accepts the PCActn's own, an absent one refuses. */
    public function testTheAudience(): void
    {
        $g = self::plainGrant();
        $p = self::pcactn($g);
        $this->assertSame(self::permitted(), Authzen::evaluate(['audience' => null] + $this->cfg($g), self::request($p)));
        foreach (['other' => ['audience' => 'other'], 'absent' => []] as $label => $aud) {
            $c = $this->cfg($g);
            unset($c['audience']);
            $r = Authzen::evaluate($aud + $c, self::request($p));
            $this->assertFalse($r['decision'], $label);
            $this->assertSame('verify', $r['context']['reason_admin']['stage'], $label);
            $this->assertFalse($r['context']['reason_admin']['checks']['audience'], $label);
        }
    }

    /** enforce.freshness (an array or an Obj) turns on the anchor gate; anything else is no gate; enforce.attestation is refused. */
    public function testTheEnforceOptions(): void
    {
        $g = self::plainGrant();
        $p = self::pcactn($g);
        foreach (['array' => ['maxAgeMs' => 1000], 'obj' => Obj::of(['maxAgeMs' => 1000])] as $label => $fresh) {
            $r = Authzen::evaluate($this->cfg($g, self::PERMIT, [], ['enforce' => ['freshness' => $fresh]]), self::request($p));
            $this->assertSame([false, 'verify', false], [$r['decision'], $r['context']['reason_admin']['stage'], $r['context']['reason_admin']['checks']['freshness_anchor']], $label);
            $this->assertSame('freshness_anchor: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)', $r['context']['reason_admin']['reason'], $label);
        }
        $this->assertSame(self::permitted(), Authzen::evaluate($this->cfg($g, self::PERMIT, [], ['enforce' => ['freshness' => 'x']]), self::request($p)));
        $this->assertSame(self::denied('evaluation error (fail closed): authzen: enforce.attestation / enforce.taint are not supported by this verifier (fail closed)', 500),
            Authzen::evaluate($this->cfg($g, self::PERMIT, [], ['enforce' => ['attestation' => true]]), self::request($p)));
    }

    /** The native policy engine is the default decide: a config without decide never reports it missing. */
    public function testTheDefaultDecideIsNative(): void
    {
        $g = self::plainGrant();
        $c = $this->cfg($g);
        unset($c['decide']);
        $r = Authzen::evaluate($c, self::request(self::pcactn($g)));
        $this->assertStringNotContainsString('config.decide is not provided', (string)json_encode($r));
        $this->assertCount(1, $this->derived);
    }

    // ---- the clock ------------------------------------------------------------------------------------------------------------

    /** Without `now` the clock is the wall clock in whole epoch milliseconds (floored); a configured `now` wins over it. */
    public function testTheClock(): void
    {
        $g = self::plainGrant();
        $p = self::pcactn($g);
        $c = $this->cfg($g, ['releaseGuardianShare' => true, 'admit' => false, 'requiredThreshold' => ['t' => 2]]);
        unset($c['now']);
        Authzen::$clockHook = static fn(): float => 1_800_000_000.0006;
        $this->assertSame(self::NOW, Authzen::evaluate($c, self::request($p))['context']['pca_approval']['requested_at']);
        Authzen::$clockHook = static fn(): float => 5.0;
        $this->assertSame(self::NOW, Authzen::evaluate($c + ['now' => static fn(): int => self::NOW], self::request($p))['context']['pca_approval']['requested_at']);
        Authzen::$clockHook = null;
        // the real wall clock is far before this proof's iat
        $r = Authzen::evaluate($c, self::request(self::pcactn($g, ['k' => 'v'], 4_000_000_000_000)));
        $this->assertSame(['verify', 'validity: iat is in the future (clock skew)'], [$r['context']['reason_admin']['stage'], $r['context']['reason_admin']['reason']]);
    }

    // ---- the boxcar -------------------------------------------------------------------------------------------------------------

    /** Each item's own members win over the request defaults; an item with an invalid subject or action is incomplete; context is the item's, else the request's. */
    public function testTheBoxcarMerge(): void
    {
        $seen = [];
        $c = ['resolve' => static function (mixed $req) use (&$seen): mixed {
            $seen[] = $req;
            return null;
        }, 'now' => static fn(): int => self::NOW];
        $a = ['type' => 'user', 'id' => 'A'];
        $b = ['type' => 'user', 'id' => 'B'];
        $act = ['name' => 'read'];
        $res = ['type' => 'doc', 'id' => '1'];
        $out = Authzen::evaluations($c, ['subject' => $a, 'action' => $act, 'resource' => $res, 'context' => ['from' => 'defaults'], 'evaluations' => [
            ['subject' => $b, 'context' => ['from' => 'item']], [], ['subject' => ['type' => 'user']], ['action' => ['name' => 5]],
        ]]);
        $none = self::denied('no PCA authority resolved for this request');
        $bad = self::denied('incomplete evaluation (missing subject/action/resource)', 400);
        $this->assertSame([$none, $none, $bad, $bad], $out['evaluations']);
        $this->assertSame(['subject' => $b, 'action' => $act, 'resource' => $res, 'context' => ['from' => 'item']], $seen[0]);
        $this->assertSame(['subject' => $a, 'action' => $act, 'resource' => $res, 'context' => ['from' => 'defaults']], $seen[1]);
        $this->assertCount(2, $seen);
        $seen = [];
        Authzen::evaluations($c, ['subject' => $a, 'action' => $act, 'resource' => $res, 'evaluations' => [[]]]);
        $this->assertSame([['subject' => $a, 'action' => $act, 'resource' => $res]], $seen);
    }

    /** execute_all runs every item even after a permit; permit_on_first_permit stops at the first permit. */
    public function testTheBoxcarBreakRules(): void
    {
        $c = ['resolve' => static fn(): array => ['grant' => new Obj(), 'policy' => new Obj()], 'now' => static fn(): int => self::NOW, 'requireProof' => false,
            'admitsConcrete' => static fn(): bool => true];
        $req = ['subject' => ['type' => 'user', 'id' => 'A'], 'action' => ['name' => 'read'], 'resource' => ['type' => 'doc', 'id' => '1'], 'evaluations' => [[], []]];
        $this->assertCount(2, Authzen::evaluations($c, $req)['evaluations']);
        $this->assertCount(1, Authzen::evaluations($c, $req + ['options' => ['evaluations_semantic' => 'permit_on_first_permit']])['evaluations']);
        $this->assertCount(2, Authzen::evaluations($c, $req + ['options' => ['evaluations_semantic' => 'deny_on_first_deny']])['evaluations']);
    }

    // ---- COAZ ---------------------------------------------------------------------------------------------------------------------

    /** A tool call maps to {subject, action: {name: capability, properties: arguments}, resource: mcp_tool/name, context}. */
    public function testTheToolMapping(): void
    {
        $seen = [];
        $c = ['resolve' => static function (mixed $req) use (&$seen): mixed {
            $seen[] = $req;
            return null;
        }, 'now' => static fn(): int => self::NOW];
        $s = ['type' => 'agent', 'id' => 'x'];
        $r = Authzen::evaluateTool($c, ['subject' => $s, 'tool' => ['name' => 't1', 'arguments' => ['a' => 'b']], 'context' => ['c' => 'd']]);
        $this->assertSame([false, 't1', 't1'], [$r['decision'], $r['tool'], $r['required_capability']]);
        $this->assertSame(['subject' => $s, 'action' => ['name' => 't1', 'properties' => ['a' => 'b']], 'resource' => ['type' => 'mcp_tool', 'id' => 't1'],
            'context' => ['c' => 'd']], $seen[0]);
        Authzen::evaluateTool($c, ['subject' => $s, 'tool' => ['name' => 't2']]);
        $this->assertSame(['subject' => $s, 'action' => ['name' => 't2'], 'resource' => ['type' => 'mcp_tool', 'id' => 't2']], $seen[1]);
    }

    // ---- search -------------------------------------------------------------------------------------------------------------------

    /** Entity and action properties are optional, and must be an object when present. */
    public function testTheSearchRequestGuards(): void
    {
        $ok = ['subject' => ['type' => 'user', 'properties' => ['k' => 'v']], 'action' => ['name' => 'read', 'properties' => ['k' => 'v']],
            'resource' => ['type' => 'doc', 'id' => '1']];
        $this->assertTrue(Authzen::isSubjectSearch($ok));
        $this->assertTrue(Authzen::isSubjectSearch(['subject' => ['type' => 'user'], 'action' => ['name' => 'read'], 'resource' => ['type' => 'doc', 'id' => '1']]));
        $this->assertFalse(Authzen::isSubjectSearch(['subject' => ['type' => 'user', 'properties' => 'x']] + $ok));
        $this->assertFalse(Authzen::isSubjectSearch(['action' => ['name' => 'read', 'properties' => 'x']] + $ok));
    }

    /** A provider is a map of non-string callables or an object with the method; a class name, a function name or a number is not. */
    public function testTheProviderLookup(): void
    {
        $base = 'https://pdp.example';
        $this->assertSame(['search_subject_endpoint'], Authzen::searchMetadata($base, new NetSurvivorKill16ObjectProvider())->keys());
        $this->assertSame($base . Authzen::SEARCH_SUBJECT_PATH, Authzen::searchMetadata($base, new NetSurvivorKill16ObjectProvider())->get('search_subject_endpoint'));
        $this->assertSame([], Authzen::searchMetadata($base, NetSurvivorKill16StaticProvider::class)->keys());
        $this->assertSame([], Authzen::searchMetadata($base, ['searchSubject' => 'strlen', 'searchResource' => 5])->keys());
        $this->assertSame(['search_action_endpoint'], Authzen::searchMetadata($base, ['searchAction' => static fn(): array => ['results' => []]])->keys());
    }

    /** A provider whose results are a keyed map (not a list) fails closed. */
    public function testResultsMustBeAList(): void
    {
        $h = Authzen::searchHandler(['searchSubject' => static fn(): array => ['results' => ['a' => 1]]]);
        $r = $h(['path' => Authzen::SEARCH_SUBJECT_PATH, 'body' => ['subject' => ['type' => 'user'], 'action' => ['name' => 'read'], 'resource' => ['type' => 'doc', 'id' => '1']]]);
        $this->assertSame(['status' => 500, 'body' => ['error' => 'internal error']], $r);
    }
}
