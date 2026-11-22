<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AtomicKv;
use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\ClaimResult;
use Atlas\Pca\Escalation;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PlanRegistry;
use Atlas\Pca\RevocationStalenessPolicy;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * Authorize::authorize, the pipeline after the core verdict (src/Authorize.php from line 1321 on): the core verdict is replaced
 * through the Authorize::$coreHook test seam (every core check passes unless a test says otherwise), so the PCActn, the grant and
 * the chain can be shaped freely and each post-core branch is pinned by its exact check status and reason.
 */
final class K05KillAuthorize2Test extends TestCase
{
    private const CORE = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature',
        'counter_format'];
    private const ESC = 'intent: escalate: asked for a confirmation';

    private Obj $fix;
    private Obj $grant;
    private Obj $p;
    private Obj $op;
    private int $now;
    /** @var array<string,Obj> */
    private array $cases = [];

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            $this->cases[$c->get('name')] = $c;
        }
        $c = $this->cases['envelope-max-spend-within'];
        $this->grant = $c->get('grant');
        $this->p = $c->get('steps')[0]->get('pcactn');
        $this->op = $c->get('steps')[0]->get('operation');
        $this->now = $this->fix->get('now')->int();
        self::core();
    }

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    /** Replace the core verdict: every core check passes, except `$over` (false = fails, null = absent). */
    private static function core(array $over = [], array $reasons = [], array $more = []): void
    {
        Authorize::$coreHook = static function (array $c) use ($over, $reasons, $more): array {
            $checks = array_fill_keys(self::CORE, true);
            foreach ($over as $k => $v) {
                if ($v === null) {
                    unset($checks[$k]);
                } else {
                    $checks[$k] = $v;
                }
            }
            return ['allow' => !in_array(false, $checks, true), 'checks' => $checks, 'reason' => $reasons[0] ?? '', 'reasons' => $reasons] + $more;
        };
    }

    private static function j(string $json): mixed
    {
        return Json::parseLax($json);
    }

    private static function copy(Obj $o): Obj
    {
        return Json::parseLax(Json::canonicalizeStrict($o));
    }

    private function p(): Obj
    {
        return self::copy($this->p);
    }

    private function holder(): string
    {
        return $this->p->get('cap_chain')[0]->get('holder');
    }

    /** The fixture's envelope caveat with other predicates / caveats. */
    private function env(?array $predicates = null, ?array $caveats = null): Obj
    {
        $e = self::copy($this->grant->get('caveats')[0]);
        if ($predicates !== null) {
            $e->set('predicates', $predicates);
        }
        if ($caveats !== null) {
            $e->set('caveats', $caveats);
        }
        return $e;
    }

    private function grantWith(array $caveats, ?string $holder = null): Obj
    {
        $g = self::copy($this->grant);
        $g->set('caveats', $caveats);
        if ($holder !== null) {
            $g->set('holder', $holder);
        }
        return $g;
    }

    private function leaf(array $caveats, ?string $holder = null): Obj
    {
        $l = self::copy($this->p->get('cap_chain')[0]);
        $l->set('caveats', $caveats);
        if ($holder !== null) {
            $l->set('holder', $holder);
        }
        return $l;
    }

    /** A predicate on payments.send that also requires `$field == $value`. */
    private static function pred(string $field, string $value): Obj
    {
        return self::j('{"verb":"payments.send","resource":"payments/*","where":[{"field":"' . $field . '","op":"eq","value":"' . $value . '"}]}');
    }

    /** authorize() over the base fixture; `$o` overrides any named argument (plus `grant`). */
    private function az(array $o = []): AuthorizeResult
    {
        $op = $o['operation'] ?? $this->op;
        $g = $o['grant'] ?? $this->grant;
        unset($o['grant']);
        $base = ['pcactn' => $this->p(), 'operation' => $op, 'audience' => $this->fix->get('audience'), 'resolveGrant' => static fn($ref) => $g,
            'stateStore' => new MemoryStateStore(), 'isRevoked' => static fn() => false, 'now' => $this->now, 'plan' => 'single-step',
            'provenance' => ProvHarness::bundle($op), 'provenanceMediators' => [ProvHarness::pin()], 'hard' => CalmRisk::hard()];
        return Authorize::authorize(...array_merge($base, $o));
    }

    /** @return list<string> */
    private static function prefixed(AuthorizeResult $r, string $prefix): array
    {
        return array_values(array_filter($r->reasons, static fn(string $x): bool => str_starts_with($x, $prefix)));
    }

    /** A replay store: `last` answers with `$last` (a throwing closure throws), `claim` with `$claim`. */
    private static function store(mixed $last, mixed $claim = true): object
    {
        return new class ($last, $claim) {
            public function __construct(private mixed $l, private mixed $c)
            {
            }

            public function claim(string $key, int $counter): mixed
            {
                return $this->c === true ? new ClaimResult(true) : $this->c;
            }

            public function last(string $key): mixed
            {
                return $this->l instanceof \Closure ? ($this->l)() : $this->l;
            }
        };
    }

    private static function claimOnly(): object
    {
        return new class () {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }
        };
    }

    // ---- 1. the core verdict ---------------------------------------------------------------------------------------------

    public function testAWireFailureIsTheFixedMalformedRefusal(): void
    {
        Authorize::$coreHook = static fn(array $c): array => ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: boom'];
        $r = $this->az();
        $this->assertSame([false, 401, ['wire' => 'fail', 'malformed' => 'fail'], ['wire: boom'], 'wire: boom'],
            [$r->allow, $r->status, $r->checks, $r->reasons, $r->reason]);
    }

    public function testTheCoreReasonsSeedTheReasonList(): void
    {
        $checks = array_fill_keys(self::CORE, true);
        $checks['chain'] = false;
        // no `reasons` member: the single `reason`
        Authorize::$coreHook = static fn(array $c): array => ['allow' => false, 'checks' => $checks, 'reason' => 'chain: bad hop'];
        $r = $this->az();
        $this->assertSame([false, 401, 'chain: bad hop', 'chain: bad hop'], [$r->allow, $r->status, $r->reasons[0], $r->reason]);
        // an empty `reasons` list: the single `reason` too
        Authorize::$coreHook = static fn(array $c): array => ['allow' => false, 'checks' => $checks, 'reason' => 'chain: x', 'reasons' => []];
        $this->assertSame('chain: x', $this->az()->reasons[0]);
        // an empty reason adds nothing (and every check passing still allows)
        $all = array_fill_keys(self::CORE, true);
        Authorize::$coreHook = static fn(array $c): array => ['allow' => false, 'checks' => $all, 'reason' => '', 'reasons' => []];
        $r = $this->az();
        $this->assertSame([true, []], [$r->allow, $r->reasons]);
    }

    // ---- 2. revocation staleness, zk -------------------------------------------------------------------------------------

    public function testRevocationStateSource(): void
    {
        $pol = new RevocationStalenessPolicy(60000.0);
        $why = 'freshness: the revocation state source failed (fail closed)';
        $r = $this->az(['revocationStaleness' => $pol, 'revocationState' => static fn() => 'not a state']);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertContains($why, $r->reasons);
        $r = $this->az(['revocationStaleness' => $pol, 'revocationState' => static fn() => throw new \RuntimeException('down')]);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertContains($why, $r->reasons);
        // a non-string authoritative class is no class: the signed `irreversible` decides
        $r = $this->az(['revocationStaleness' => $pol, 'revocationState' => static fn() => null,
            'context' => static fn() => ['reversibility_class' => 5]]);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertContains('freshness: no verifiable (guardian-signed) revocation state for an irreversible action', $r->reasons);
    }

    public function testABondRefIsUnsupportedAndDenied(): void
    {
        $this->assertTrue($this->az()->allow);
        $p = $this->p();
        $p->set('bond_ref', 'b');
        $store = new MemoryStateStore();
        $r = $this->az(['pcactn' => $p, 'stateStore' => $store]);
        $this->assertSame([false, 403, 'unsupported', 'deny'], [$r->allow, $r->status, $r->checks['bond'], $r->decision]);
        $this->assertSame([Authorize::BOND_UNSUPPORTED], $r->reasons);
        $this->assertSame(Authorize::BOND_UNSUPPORTED, $r->reason);
        $this->assertSame('unsupported', $r->assurance['bond']['outcome']);
        // denied before the replay claim: nothing was written
        $this->assertTrue($this->az(['stateStore' => $store])->allow);
        // beside a failing check the failure stays decisive and the bond is still reported
        $bad = $this->op->without('verb');
        $bad->set('verb', 'other');
        $r = $this->az(['pcactn' => $p, 'operation' => $bad]);
        $this->assertSame('unsupported', $r->checks['bond']);
        $this->assertContains(Authorize::BOND_UNSUPPORTED, $r->reasons);
        $this->assertStringStartsWith('operation:', $r->reason);
        // a required bond stays `fail`: the unsupported status never replaces it
        $r = $this->az(['pcactn' => $p, 'require' => ['bond']]);
        $this->assertSame([false, 'fail', 'deny'], [$r->allow, $r->checks['bond'], $r->decision]);
        $this->assertContains(Authorize::BOND_UNSUPPORTED, $r->reasons);
    }

    // ---- 3./4. operation, grant_ref, params, plan ------------------------------------------------------------------------

    public function testAPcactnWithoutActionOrPlanIsRefusedByItsChecks(): void
    {
        $r = $this->az(['pcactn' => $this->p()->without('action')]);
        $this->assertSame('fail', $r->checks['operation']);
        $r = $this->az(['pcactn' => $this->p()->without('plan')]);
        $this->assertSame('fail', $r->checks['plan_root_authorized']);
        $this->assertContains('plan_root_authorized: known plan does not match plan.root', $r->reasons);
    }

    public function testGrantRefAndParamsDigestReasons(): void
    {
        $g = self::copy($this->grant);
        $g->set('id', 'some-other-grant');
        $r = $this->az(['grant' => $g]);
        $this->assertSame([false, 401, 'fail'], [$r->allow, $r->status, $r->checks['grant_ref']]);
        $this->assertContains('grant_ref: does not reference the supplied grant', $r->reasons);

        $op = Obj::of(['verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => Obj::of(['amount' => 400, 'currency' => 'usd'])]);
        $r = $this->az(['operation' => $op]);
        $this->assertSame('fail', $r->checks['params_digest']);
        $this->assertContains('params_digest: supplied params do not hash to action.params_digest', $r->reasons);
    }

    public function testAContextPlanMustBeAuthorized(): void
    {
        $node = Obj::of(['id' => 'n1', 'verb' => 'payments.send', 'resource' => 'payments/acme',
            'params_digest' => $this->p->get('action')->get('params_digest'), 'reversibility_class' => 'irreversible']);
        $r = $this->az(['plan' => null, 'context' => static fn() => ['plan' => [$node], 'plan_authorized' => false]]);
        $this->assertSame('fail', $r->checks['plan_root_authorized']);
        $this->assertContains('plan_root_authorized: the plan root has not been authorized by the principal', $r->reasons);
        $r = $this->az(['plan' => null, 'context' => static fn() => ['plan' => [$node], 'plan_authorized' => true]]);
        $this->assertSame('pass', $r->checks['plan_root_authorized']);
    }

    public function testThePlanRegistry(): void
    {
        // a stored record the registry itself cannot read (a non-string revokedReason): the registry fails, closed
        $kv = new class () implements AtomicKv {
            public function get(string $key): ?string
            {
                return '{"root":"r","nodes":[],"state":"revoked","revokedReason":{}}';
            }

            public function update(string $key, callable $fn): void
            {
            }
        };
        $r = $this->az(['plans' => new PlanRegistry($kv)]);
        $this->assertSame([false, 'fail'], [$r->allow, $r->checks['plan_state']]);
        $this->assertContains('plan_state: the plan registry failed (fail closed)', $r->reasons);
        // no record and a single-step plan: an unknown root in a registry no longer falls back to the one-node plan
        $r = $this->az(['plans' => new PlanRegistry()]);
        $this->assertSame([false, 'fail'], [$r->allow, $r->checks['plan_state']]);
        $this->assertSame('fail', $r->checks['plan_root_authorized']);
    }

    public function testAttestationRequiredReason(): void
    {
        $c = $this->cases['attestation-bound'];
        $s = $c->get('steps')[0];
        $r = $this->az(['grant' => $c->get('grant'), 'pcactn' => self::copy($s->get('pcactn')), 'operation' => $s->get('operation')]);
        $this->assertSame('fail', $r->checks['attestation']);
        $this->assertContains('attestation: the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED '
            . '(no attestation verifier in this SDK: fail closed)', $r->reasons);
    }

    // ---- reversibility and the policy contexts ---------------------------------------------------------------------------

    public function testReversibilityAgainstTheAuthoritativeClass(): void
    {
        $r = $this->az(['context' => static fn() => ['reversibility_class' => 'irreversible']]);
        $this->assertSame('pass', $r->checks['reversibility']);

        $p = $this->p();
        $p->get('action')->set('reversibility_class', 'reversible');
        $r = $this->az(['pcactn' => $p, 'context' => static fn() => ['reversibility_class' => 'irreversible']]);
        $this->assertSame('fail', $r->checks['reversibility']);
        $this->assertContains("reversibility: declared class 'reversible' is less restrictive than the authoritative 'irreversible'", $r->reasons);

        // equal rank: the authoritative class is the effective one the predicates see
        $p = $this->p();
        $p->get('action')->set('reversibility_class', 'costly');
        $g = $this->grantWith([$this->env([self::pred('action.reversibility_class', 'rate_limited')])]);
        $r = $this->az(['pcactn' => $p, 'grant' => $g, 'context' => static fn() => ['reversibility_class' => 'rate_limited']]);
        $this->assertSame(['pass', 'pass'], [$r->checks['reversibility'], $r->checks['policy']]);
    }

    public function testTheSubjectReachesThePredicates(): void
    {
        $g = $this->grantWith([$this->env([self::pred('subject.role', 'admin')])]);
        $r = $this->az(['grant' => $g, 'context' => static fn() => ['subject' => Obj::of(['role' => 'admin'])]]);
        $this->assertSame('pass', $r->checks['policy']);
    }

    public function testTheCaveatContext(): void
    {
        $cs = [
            self::j('{"type":"expires","at":' . ($this->now + 1000000) . '}'),
            self::j('{"type":"max_blast_radius","max":10}'),
            self::j('{"type":"reversibility_max","class":"irreversible"}'),
            self::j('{"type":"rate","max":1,"per_secs":60}'),
            self::j('{"type":"delegation_depth","max":0}'),
        ];
        $g = $this->grantWith([$this->env(null, $cs)]);
        $r = $this->az(['grant' => $g, 'context' => static fn() => ['blast_radius' => 5, 'recent_action_times' => []]]);
        $this->assertSame([], self::prefixed($r, 'policy: '));
        $this->assertSame('pass', $r->checks['policy']);
    }

    public function testDelegationDepth(): void
    {
        $g = $this->grantWith([$this->env(null, [self::j('{"type":"delegation_depth","max":0}')])]);
        $p = $this->p();
        $p->set('cap_chain', [self::copy($this->p->get('cap_chain')[0]), self::copy($this->p->get('cap_chain')[0])]);
        $r = $this->az(['grant' => $g, 'pcactn' => $p]);
        $this->assertSame(['policy: caveat(s) not satisfied: delegation_depth'], self::prefixed($r, 'policy: '));
        // no chain at all: depth 0, never negative
        $g = $this->grantWith([$this->env(null, [self::j('{"type":"delegation_depth","max":-1}')])]);
        $p = $this->p();
        $p->set('cap_chain', []);
        $r = $this->az(['grant' => $g, 'pcactn' => $p]);
        $this->assertSame(['policy: caveat(s) not satisfied: delegation_depth'], self::prefixed($r, 'policy: '));
    }

    public function testTheReversibilityClassOfThePlanNode(): void
    {
        $g = $this->grantWith([$this->env(null, [self::j('{"type":"reversibility_max","class":"reversible"}')])]);
        $p = $this->p();
        $p->set('action', $p->get('action')->without('reversibility_class'));
        $nodes = static fn(array $ns): \Closure => static fn() => ['plan' => $ns, 'plan_authorized' => true];
        $n = static fn(string $id, string $cls): Obj => Obj::of(['id' => $id, 'reversibility_class' => $cls]);
        // the node with the PCActn's node_id (n1), not the first one
        $r = $this->az(['grant' => $g, 'pcactn' => $p, 'plan' => null, 'context' => $nodes([$n('n0', 'irreversible'), $n('n1', 'reversible')])]);
        $this->assertSame('pass', $r->checks['policy']);
        // the first node with that id
        $r = $this->az(['grant' => $g, 'pcactn' => self::copy($p), 'plan' => null, 'context' => $nodes([$n('n1', 'reversible'), $n('n1', 'irreversible')])]);
        $this->assertSame('pass', $r->checks['policy']);
        // a declared class wins over the node's
        $r = $this->az(['grant' => $g, 'plan' => null, 'context' => $nodes([$n('n1', 'reversible')])]);
        $this->assertSame('fail', $r->checks['policy']);
        $this->assertSame(['policy: caveat(s) not satisfied: reversibility_max'], self::prefixed($r, 'policy: '));
    }

    public function testEveryPolicyReasonIsReported(): void
    {
        $spend = self::j('{"type":"max_spend","usd":10}');
        $g = $this->grantWith([$this->env(null, [$spend]), self::copy($spend)]);
        $r = $this->az(['grant' => $g]);
        $this->assertSame(['policy: caveat(s) not satisfied: max_spend', 'policy: root caveat(s) not satisfied: max_spend'],
            self::prefixed($r, 'policy: '));
    }

    // ---- K1: the caveat language -----------------------------------------------------------------------------------------

    public function testAK1CaveatWithoutK1InputIsRefusedByTheLanguage(): void
    {
        $g = $this->grantWith([$this->env(), self::j('{"type":"expires","at":' . ($this->now + 1000000) . '}'), self::j('{"type":"sealed"}')]);
        $p = $this->p();
        $p->set('cap_chain', []);
        $r = $this->az(['grant' => $g, 'pcactn' => $p]);
        $this->assertSame(['policy: caveat language: sealed: the caveat language is not configured (no k1 input)'], self::prefixed($r, 'policy: '));
    }

    public function testK1InputSatisfiesASealedRootCaveat(): void
    {
        $g = $this->grantWith([$this->env(), self::j('{"type":"sealed"}'), self::j('{"type":"expires","at":' . ($this->now + 1000000) . '}')]);
        $p = $this->p();
        $p->set('cap_chain', []);
        $r = $this->az(['grant' => $g, 'pcactn' => $p, 'k1' => new Obj()]);
        $this->assertSame('pass', $r->checks['policy']);
        $this->assertSame([], self::prefixed($r, 'policy: '));
    }

    public function testAnUnsafeClockWithoutK1CaveatsNeverReachesTheLanguage(): void
    {
        $r = $this->az(['now' => 1 << 60]);
        $this->assertSame(['pass', 'pass'], [$r->checks['policy'], $r->checks['delegated_caveats']]);
    }

    public function testARootK1CaveatIsAStockCaveatWhenTheLeafCarriesNone(): void
    {
        $g = $this->grantWith([$this->env(), self::j('{"type":"sealed"}')]);
        $p = $this->p();
        $p->set('cap_chain', [$this->leaf([$this->env()])]);
        $r = $this->az(['grant' => $g, 'pcactn' => $p]);
        $this->assertContains('policy: root caveat(s) not satisfied: sealed', $r->reasons);
    }

    public function testADelegatedK1Caveat(): void
    {
        $p = $this->p();
        $p->set('cap_chain', [$this->leaf([$this->env(), self::j('{"type":"sealed"}')])]);
        $r = $this->az(['pcactn' => $p, 'k1' => new Obj()]);
        $this->assertSame([true, 200, 'pass'], [$r->allow, $r->status, $r->checks['delegated_caveats']]);

        $r = $this->az(['pcactn' => self::copy($p)]);
        $this->assertSame('fail', $r->checks['delegated_caveats']);
        $this->assertContains('delegated_caveats: delegation caveat(s) not satisfied: sealed (the caveat language is not configured (no k1 input))', $r->reasons);
    }

    public function testAnUnreadableLeafHop(): void
    {
        $p = $this->p();
        $p->set('cap_chain', ['not a hop']);
        $r = $this->az(['pcactn' => $p]);
        $this->assertSame(['fail', 'pass'], [$r->checks['delegated_caveats'], $r->checks['replay']]);
        $this->assertContains('delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>', $r->reasons);
    }

    public function testNarrowBlockCaveats(): void
    {
        $kp = new KeyPair(str_repeat("\x07", 32));
        $spend = [self::j('{"type":"max_spend","usd":10}')];
        // no chain: the narrow block attenuates the grant itself
        $g = $this->grantWith([$this->env()], $kp->public);
        $n = Sign::signNarrow($kp, Pca::capHash($g), $spend, $this->now - 1000, $this->now + 60000);
        $p = $this->p();
        $p->set('cap_chain', []);
        $r = $this->az(['grant' => $g, 'pcactn' => $p, 'k1' => Obj::of(['narrow' => $n])]);
        $this->assertSame(['policy: narrow caveat(s) not satisfied: max_spend'], self::prefixed($r, 'policy: '));
        // a chain: the leaf's own caveats and the narrow block's
        $leaf = $this->leaf([$this->env(), self::j('{"type":"max_spend","usd":20}')], $kp->public);
        $n = Sign::signNarrow($kp, Pca::capHash($leaf), $spend, $this->now - 1000, $this->now + 60000);
        $p = $this->p();
        $p->set('cap_chain', [$leaf]);
        $r = $this->az(['pcactn' => $p, 'k1' => Obj::of(['narrow' => $n])]);
        $this->assertContains('delegated_caveats: delegation caveat(s) not satisfied: max_spend, max_spend', $r->reasons);
    }

    public function testMaxUsesIsSpentFromTheUsesStore(): void
    {
        $p = $this->p();
        $p->set('cap_chain', [$this->leaf([$this->env(), self::j('{"type":"max_uses","id":"m1","n":1,"until":' . ($this->now + 600000) . '}')])]);
        $none = "max_uses: max_uses: the chain carries a max_uses caveat and there is no usesStore (fail closed)";
        foreach ([null, new \stdClass()] as $u) {
            $r = $this->az(['pcactn' => self::copy($p), 'k1' => new Obj(), 'usesStore' => $u]);
            $this->assertSame([false, 'fail'], [$r->allow, $r->checks['max_uses']]);
            $this->assertContains($none, $r->reasons);
        }
        $u = new MemoryStateStore();
        $this->assertTrue($this->az(['pcactn' => self::copy($p), 'k1' => new Obj(), 'usesStore' => $u])->allow);
        $r = $this->az(['pcactn' => self::copy($p), 'k1' => new Obj(), 'usesStore' => $u]);
        $this->assertSame([false, 'fail'], [$r->allow, $r->checks['max_uses']]);
        $this->assertContains("max_uses: max_uses: max_uses 'm1' is exhausted", $r->reasons);
        // a claim-only store, and a consume-once-only store
        $this->assertTrue($this->az(['pcactn' => self::copy($p), 'k1' => new Obj(), 'usesStore' => self::claimOnly()])->allow);
        $once = new class () {
            public function consumeOnce(string $key, int $retainUntilMs, int $nowMs): bool
            {
                return true;
            }
        };
        $this->assertTrue($this->az(['pcactn' => self::copy($p), 'k1' => new Obj(), 'usesStore' => $once])->allow);
    }

    // ---- required checks, assurance --------------------------------------------------------------------------------------

    public function testRequiredChecks(): void
    {
        $r = $this->az(['require' => ['nonexistent']]);
        $this->assertSame([false, 'fail'], [$r->allow, $r->checks['nonexistent']]);
        $this->assertContains('nonexistent: required check is absent (default-deny: not enforced by this resource server)', $r->reasons);
        self::core(['counter_format' => null]);
        $r = $this->az();
        $this->assertSame([false, 'fail'], [$r->allow, $r->checks['counter_format']]);
        $this->assertContains('counter_format: required check is absent (default-deny: not enforced by this resource server)', $r->reasons);
    }

    public function testLegacyModelPolarityDegradesTheTightenCheck(): void
    {
        self::core(['tighten' => true], [], ['legacy_model_polarity' => true]);
        $r = $this->az();
        $this->assertSame(['pass', true], [$r->assurance['tighten']['outcome'], $r->assurance['tighten']['degraded'] ?? null]);
        self::core(['tighten' => true]);
        $r = $this->az();
        $this->assertSame('pass', $r->assurance['tighten']['outcome']);
        $this->assertArrayNotHasKey('degraded', $r->assurance['tighten']);
    }

    public function testAnUnregisteredLeafSuiteIsNotUnboundPq(): void
    {
        $p = $this->p();
        $p->set('alg', 'not-a-suite');
        $r = $this->az(['pcactn' => $p]);
        $this->assertSame('unknown', $r->assurance['leaf_signature']['level']);
    }

    // ---- provenance ------------------------------------------------------------------------------------------------------

    public function testTheProvenanceBundleAndPins(): void
    {
        // an explicit bundle wins over the reader
        $r = $this->az(['provenanceBundle' => static fn(mixed ...$a): string => 'not json']);
        $this->assertSame('pass', $r->checks['provenance_flow']);
        // pins given as PHP arrays
        $pin = ProvHarness::pin();
        $r = $this->az(['provenanceMediators' => [['mediator' => $pin->get('mediator'), 'kid' => $pin->get('kid'), 'pk' => $pin->get('pk')]]]);
        $this->assertSame('pass', $r->checks['provenance_flow']);
        // a bundle given as a PHP array
        $b = ProvHarness::bundle($this->op);
        $arr = [];
        foreach ($b->keys() as $k) {
            $arr[$k] = $b->get($k);
        }
        $r = $this->az(['provenance' => $arr]);
        $this->assertSame('pass', $r->checks['provenance_flow']);
    }

    // ---- the replay counter ----------------------------------------------------------------------------------------------

    public function testAnAlreadySeenCounterOnARefusal(): void
    {
        self::core(['chain' => false], ['chain: bad hop']);
        $s = new MemoryStateStore();
        $s->claim(Authorize::stateKey($this->grant->get('id'), $this->holder()), 5);
        $r = $this->az(['stateStore' => $s]);
        $this->assertContains('replay: 1 is not greater than last seen 5 (replay)', $r->reasons);
        // no counter: the pre-check is skipped
        $r = $this->az(['pcactn' => $this->p()->without('counter'), 'stateStore' => self::store(5)]);
        $this->assertSame(['fail', 'pass'], [$r->checks['chain'], $r->checks['replay']]);
    }

    public function testThePreCheckRunsOnlyOnARefusal(): void
    {
        // a store whose `last` is ahead but whose claim accepts: only the claim decides an otherwise passing proof
        $r = $this->az(['stateStore' => self::store(5)]);
        $this->assertSame([true, 'pass'], [$r->allow, $r->checks['replay']]);
    }

    public function testReplayRefusals(): void
    {
        $r = $this->az(['stateStore' => self::store(null, false)]);
        $this->assertSame('fail', $r->checks['replay']);
        $this->assertContains('replay: 1 was already claimed (replay)', $r->reasons);
        $why = 'replay: no counter stream for this proof (fail closed)';
        $r = $this->az(['pcactn' => $this->p()->without('counter')]);
        $this->assertSame([false, 'fail'], [$r->allow, $r->checks['replay']]);
        $this->assertContains($why, $r->reasons);
        $p = $this->p();
        $p->set('cap_chain', []);
        $r = $this->az(['pcactn' => $p]);
        $this->assertSame([false, 'fail'], [$r->allow, $r->checks['replay']]);
        $this->assertContains($why, $r->reasons);
    }

    // ---- escalation ------------------------------------------------------------------------------------------------------

    public function testTheEscalationRequest(): void
    {
        self::core(['intent' => false], [self::ESC]);
        $r = $this->az(['stateStore' => self::store(0)]);
        $this->assertSame([false, 'escalate'], [$r->allow, $r->decision]);
        $this->assertSame($this->now + 3_600_000, $r->escalation->get('expires_at')->int());
        $this->assertSame(Escalation::historyHead(0), $r->escalation->get('history_head'));
    }

    public function testNoHolderIsADenialNotAnEscalation(): void
    {
        self::core(['intent' => false], [self::ESC]);
        $p = $this->p();
        $p->set('cap_chain', []);
        $r = $this->az(['pcactn' => $p]);
        $this->assertSame([false, 'deny', 'fail'], [$r->allow, $r->decision, $r->checks['intent']]);
    }

    public function testAnAnswerIsVerifiedOnlyAgainstAKnownHistoryHead(): void
    {
        self::core(['intent' => false], [self::ESC]);
        $esc = static fn(AuthorizeResult $r): array => self::prefixed($r, 'escalation: ');
        $o = ['escalationPrincipals' => [], 'escalationAnswer' => Obj::of(['x' => 1]), 'insecureUnboundApproval' => true];
        foreach ([self::claimOnly(), self::store('x'), self::store(static fn() => throw new \RuntimeException('down'))] as $s) {
            $r = $this->az($o + ['stateStore' => $s]);
            $this->assertSame('escalate', $r->decision);
            $this->assertSame([], $esc($r));
        }
        $r = $this->az($o + ['stateStore' => self::store(0)]);
        $this->assertSame('escalate', $r->decision);
        $this->assertCount(1, $esc($r));
        // an answer as JSON text of exactly the artifact limit is read
        $text = '{"a":"' . str_repeat('x', Pca::MAX_ARTIFACT_BYTES - 8) . '"}';
        $this->assertSame(Pca::MAX_ARTIFACT_BYTES, strlen($text));
        $r = $this->az(['escalationAnswer' => $text] + $o + ['stateStore' => self::store(0)]);
        $this->assertCount(1, $esc($r));
        // JSON text that is not an object is no answer
        $r = $this->az(['escalationAnswer' => '5'] + $o + ['stateStore' => self::store(0)]);
        $this->assertSame('escalate', $r->decision);
        $this->assertSame([], $esc($r));
    }

    // ---- the Intent v2 predicate env -------------------------------------------------------------------------------------

    public function testTheHostEnvReachesThePredicatesOfAnIntentSession(): void
    {
        $p = $this->p();
        $p->set('intent_session', new Obj());
        $v2 = Obj::of(['policy' => 5]); // a malformed v2 context: the v2 decision computes no env members
        $g = $this->grantWith([$this->env([self::pred('env.tier', 'gold')])]);
        $r = $this->az(['pcactn' => $p, 'grant' => $g, 'intentV2' => $v2, 'context' => static fn() => ['env' => Obj::of(['tier' => 'gold'])]]);
        $this->assertSame('pass', $r->checks['policy']);
        $r = $this->az(['pcactn' => self::copy($p), 'intentV2' => Obj::of(['policy' => 5])]);
        $this->assertSame('pass', $r->checks['policy']);
    }

    // ---- isAuthorizedFor -------------------------------------------------------------------------------------------------

    public function testIsAuthorizedForNeedsARealAllow(): void
    {
        $ok = $this->az();
        $this->assertTrue($ok->allow);
        $this->assertTrue(Authorize::isAuthorizedFor($ok, $this->op));
        $forged = new \stdClass();
        $forged->allow = true;
        $forged->operation = $ok->operation;
        $this->assertFalse(Authorize::isAuthorizedFor($forged, $this->op));
        $this->assertFalse(Authorize::isAuthorizedFor(new AuthorizeResult(false, 403, operation: $ok->operation), $this->op));
        $this->assertFalse(Authorize::isAuthorizedFor($ok, ['verb' => 'payments.send', 'resource' => 'payments/acme',
            'params' => Obj::of(['amount' => INF])]));
    }

    // ---- k05 review --------------------------------------------------------------------------------------------------------

    public function testANonObjectPlanNodeIsSkippedByTheReversibilityLookup(): void
    {
        // no signed class and no authoritative one: the class is looked up in the plan nodes, where a scalar is no node
        $p = $this->p();
        $p->set('action', $p->get('action')->without('reversibility_class'));
        $r = $this->az(['pcactn' => $p, 'context' => static fn() => ['plan' => [5]]]);
        $this->assertArrayNotHasKey('authorize', $r->checks);
        $this->assertSame('fail', $r->checks['plan_root_authorized'] ?? null);
        $this->assertContains('plan_root_authorized: known plan does not match plan.root', $r->reasons);
    }

    public function testAnOwnV2EnvIsMergedWithTheHostEnv(): void
    {
        Authorize::$coreHook = null; // the real core: its Intent v2 tighten rule reads the env Authorize hands it
        $env = $this->env();
        $env->set('tighten', self::j('[{"id":"r1","when":{"field":"env.judge.score","op":"gt","value":5},"signal":"escalate"}]'));
        $g = $this->grantWith([$env]);
        // the host's judge.score (1) reaches the rule under the v2 context's own env: decided, not fired
        $r = $this->az(['grant' => $g, 'intentV2' => Obj::of(['env' => self::j('{"other":1}')]),
            'context' => static fn() => ['env' => self::j('{"judge":{"score":1}}')]]);
        $this->assertSame('pass', $r->checks['tighten'] ?? null);
        // without the host env the value is missing: undecidable, so the rule escalates
        $r = $this->az(['grant' => $g, 'intentV2' => Obj::of(['env' => self::j('{"other":1}')])]);
        $this->assertSame('fail', $r->checks['tighten'] ?? null);
    }

    public function testAPolicyEvaluationErrorFailsClosed(): void
    {
        Authorize::$evalHook = static function (string $at): void {
            if ($at === 'policy') {
                throw new \RuntimeException('boom');
            }
        };
        try {
            $r = $this->az();
        } finally {
            Authorize::$evalHook = null;
        }
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['policy']);
        $this->assertSame(['policy: policy evaluation error (fail closed)'], self::prefixed($r, 'policy:'));
    }
}
