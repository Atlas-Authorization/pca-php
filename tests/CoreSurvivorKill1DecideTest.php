<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\Decide;
use Atlas\Pca\DecideInputGrantRequired;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/Decide.php: the Policy VM decision over a calm, releasing baseline with one thing changed per test. */
final class CoreSurvivorKill1DecideTest extends TestCase
{
    private const NOW = 1800000000000;
    private const K1_OFF = 'caveat language: max_uses: the caveat language is not configured (no k1 input)';

    private static function grant(array $envCaveats = [], ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $env = ['predicates' => [['verb' => 'read', 'resource' => '*']], 'caveats' => $envCaveats, 'risk_policy' => Sign::defaultRiskPolicy()];
        return Sign::mintGrant(new KeyPair(str_repeat("\x11", 32)), (new KeyPair(str_repeat("\x12", 32)))->public, $env, 'read docs', 'c2FsdA', null, $alg, $pq)['grant'];
    }

    /** The grant with extra root caveats after the envelope (unsigned: use with chainVerified). */
    private static function withRoot(Obj $g, Obj ...$extra): Obj
    {
        $x = $g->without();
        $x->set('caveats', [...$g->get('caveats'), ...$extra]);
        return $x;
    }

    private static function input(Obj $g, array $over = [], ?Obj $params = null): Obj
    {
        $n = static fn(string $s): Num => new Num($s);
        $act = Obj::of(['verb' => 'read', 'resource' => 'doc']);
        if ($params !== null) {
            $act->set('params', $params);
        }
        $in = Obj::of(['grant' => $g, 'chainVerified' => true, 'action' => Obj::of(['action' => $act]),
            'risk' => Obj::of(['semanticDistance' => $n('0'), 'reversibility' => $n('1'), 'blastRadius' => $n('0'), 'taint' => $n('0'),
                'confidence' => $n('1'), 'age' => $n('0')]),
            'budget' => Obj::of(['B' => $n('1'), 'tau' => $n((string) self::NOW)]), 'now' => $n((string) self::NOW)]);
        foreach ($over as $k => $v) {
            $in->set($k, $v);
        }
        return $in;
    }

    private static function noEvalError(array $res): void
    {
        foreach ($res['reasons'] as $r) {
            self::assertStringStartsNotWith('policy evaluation error', $r);
        }
    }

    /** Control: the calm baseline releases with no reasons. */
    public function testBaselineReleases(): void
    {
        $res = Decide::decide(self::input(self::grant()));
        self::assertSame([], $res['reasons']);
        self::assertTrue($res['releaseGuardianShare']);
    }

    /** A K1 caveat on the root runs the caveat language: unconfigured, it denies with its exact reason and reports the bound caveat. */
    public function testRootK1CaveatRunsTheCaveatLanguage(): void
    {
        $mu = Obj::of(['type' => 'max_uses', 'id' => 'u1', 'n' => new Num('1')]);
        $ok = Obj::of(['type' => 'expires', 'at' => new Num((string) (self::NOW + 1000))]);
        $g = self::withRoot(self::grant(), $mu, $ok);
        $res = Decide::decide(self::input($g));
        // the K1 caveat is not a root agent caveat (filtered, list kept): only the caveat language speaks
        self::assertSame([self::K1_OFF], $res['reasons']);
        self::assertFalse($res['releaseGuardianShare']);
        self::assertSame([['caveat' => $mu, 'hop' => 0, 'capHash' => Pca::capHash($g)]], $res['k1Bound']);
    }

    /** A configured caveat language (an Obj k1) is passed through; a `narrow` block alone switches it on, an empty k1 does not. */
    public function testK1InputSelection(): void
    {
        $mu = Obj::of(['type' => 'max_uses', 'id' => 'u1', 'n' => new Num('1')]);
        $res = Decide::decide(self::input(self::withRoot(self::grant(), $mu), ['k1' => new Obj()]));
        self::assertNotContains(self::K1_OFF, $res['reasons']);
        self::assertArrayHasKey('k1Bound', Decide::decide(self::input(self::grant(), ['k1' => Obj::of(['narrow' => 'x'])])));
        self::assertArrayNotHasKey('k1Bound', Decide::decide(self::input(self::grant(), ['k1' => new Obj()])));
        self::assertArrayNotHasKey('k1Bound', Decide::decide(self::input(self::grant())));
    }

    /** The leaf hop's own caveats drive the caveat language, and the leaf's extra non-K1 caveats are still delegated caveats. */
    public function testLeafCaveatsAreDelegatedAndDriveK1(): void
    {
        $g = self::grant();
        $leaf = Obj::of(['caveats' => [...$g->get('caveats'), Obj::of(['type' => 'max_uses', 'id' => 'u1', 'n' => new Num('1')]),
            Obj::of(['type' => 'expires', 'at' => new Num('1')])]]);
        $res = Decide::decide(self::input($g, ['chain' => [$g, $leaf]]));
        self::assertSame(['delegated caveat(s) not satisfied: expires', self::K1_OFF], $res['reasons']);
    }

    /** The caveat clock is the decision time itself: a fractional or a huge time is never truncated to an int. */
    public function testCaveatClockIsNotTruncated(): void
    {
        $g = self::withRoot(self::grant(), Obj::of(['type' => 'expires', 'at' => new Num('1.2')]));
        $in = self::input($g, ['now' => new Num('1.5'), 'budget' => Obj::of(['B' => new Num('1'), 'tau' => new Num('1')])]);
        self::assertContains('root caveat(s) not satisfied: expires', Decide::decide($in)['reasons']);
        $g = self::withRoot(self::grant(), Obj::of(['type' => 'expires', 'at' => new Num('1e299')]));
        $in = self::input($g, ['now' => new Num('1e300'), 'budget' => Obj::of(['B' => new Num('1'), 'tau' => new Num('1')])]);
        self::assertContains('root caveat(s) not satisfied: expires', Decide::decide($in)['reasons']);
    }

    /** The reversibility class comes from the FIRST plan node with the action's node id; non-object nodes are skipped. */
    public function testPlanNodeClassIsTheFirstMatch(): void
    {
        $g = self::withRoot(self::grant(), Obj::of(['type' => 'reversibility_max', 'class' => 'reversible']));
        $plan = ['x', Obj::of(['id' => 'n1', 'reversibility_class' => 'reversible']), Obj::of(['id' => 'n1', 'reversibility_class' => 'irreversible'])];
        $res = Decide::decide(self::input($g, ['plan' => $plan, 'nodeId' => 'n1']));
        self::assertSame([], $res['reasons']);
        self::assertSame('reversible', Decide::resolveReversibilityClass(null, $plan, 'n1'));
    }

    private static function toolCaveat(bool $required): Obj
    {
        $schema = Obj::of(['props' => Obj::of(['amount' => Obj::of(['type' => 'number'])])]);
        if ($required) {
            $schema->set('required', ['amount']);
        }
        return Obj::of(['type' => 'tool_schema', 'tool' => 'read', 'schema' => $schema, 'schema_digest' => Pca::hashCanonical($schema),
            'signature_digest' => 'sd', 'binding_digest' => Pca::hashCanonical(Obj::of(['tool' => 'read', 'signature_digest' => 'sd', 'schema' => $schema]))]);
    }

    /** The tool call is the action's verb and params (params default to {}), with no signature digest unless the context binds one. */
    public function testToolCallFromTheAction(): void
    {
        $res = Decide::decide(self::input(self::withRoot(self::grant(), self::toolCaveat(true)), [], Obj::of(['amount' => new Num('5')])));
        self::assertSame([], $res['reasons']);
        $res = Decide::decide(self::input(self::withRoot(self::grant(), self::toolCaveat(false))));
        self::assertSame([], $res['reasons']);
    }

    /** A one-hop chain has delegation depth 0. */
    public function testOneHopChainHasDepthZero(): void
    {
        $g = self::grant([['type' => 'delegation_depth', 'max' => 0]]);
        self::assertSame([], Decide::decide(self::input($g, ['chain' => [$g]]))['reasons']);
    }

    /** A leaf hop that is not an object has no caveats: it is not an evaluation error. */
    public function testNonObjectLeafHasNoCaveats(): void
    {
        $res = Decide::decide(self::input(self::grant(), ['chain' => ['x']]));
        self::assertSame([], $res['reasons']);
        self::assertTrue($res['releaseGuardianShare']);
    }

    /** A budget without B has nothing to spend (0), never a full budget. */
    public function testBudgetWithoutBIsEmpty(): void
    {
        $res = Decide::decide(self::input(self::grant(), ['budget' => Obj::of(['tau' => new Num((string) self::NOW)])]));
        self::assertSame(0.0, $res['budget']['B']);
    }

    /** A goal node id that is not a string gives the worst semantic distance, never an evaluation error. */
    public function testNonStringGoalIsWorstDistance(): void
    {
        $risk = Obj::of(['reversibility' => new Num('1'), 'blastRadius' => new Num('0'), 'taint' => new Num('0'), 'confidence' => new Num('1'), 'age' => new Num('0')]);
        $res = Decide::decide(self::input(self::grant(), ['plan' => [Obj::of(['id' => 'n1'])], 'nodeId' => 'n1', 'goalNodeId' => new Num('5'), 'risk' => $risk]));
        self::noEvalError($res);
        self::assertSame(0.25, $res['r']);
    }

    /** decide re-verifies an unvouched chain; a trustedRoot that is not an object is ignored (no error). */
    public function testReverifyIgnoresANonObjectTrustedRoot(): void
    {
        $in = self::input(self::grant(), ['trustedRoot' => 'x']);
        $in = $in->without('chainVerified');
        self::assertSame([], Decide::decide($in)['reasons']);
    }

    /** A post-quantum root verifies under an Obj pin or the trusted root, never under a PHP-array pin set. */
    public function testPqRootAuthorities(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $pq = new PqKeyPair('ML-DSA-65', str_repeat("\x13", 32));
        $g = self::grant([], 'ml-dsa-65', $pq);
        $iss = $g->get('issuer');
        $run = static function (array $over) use ($g): array {
            return Decide::decide(self::input($g, $over)->without('chainVerified'))['reasons'];
        };
        $refused = static fn(array $r): bool => $r !== [] && str_starts_with($r[0], 'capability chain unverified: hop 0: root suite');
        self::assertTrue($refused($run([])), 'control: no authority');
        self::assertFalse($refused($run(['pqPins' => Obj::of([$iss => $pq->public])])));
        self::assertFalse($refused($run(['trustedRoot' => $g])));
        self::assertTrue($refused($run(['pqPins' => [$iss => $pq->public]])));
    }

    /** deriveDecideInput refuses a missing context with its own TypeError. */
    public function testDeriveWithoutContext(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('deriveDecideInput: no context');
        Decide::deriveDecideInput(Obj::of([]), null);
    }

    /** The grant-required refusal carries its message and code. */
    public function testDeriveWithoutGrantMessage(): void
    {
        try {
            Decide::deriveDecideInput(Obj::of([]), Obj::of([]));
            self::fail('expected DecideInputGrantRequired');
        } catch (DecideInputGrantRequired $e) {
            self::assertSame('grant_required', $e->errorCode);
            self::assertSame('deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant', $e->getMessage());
        }
    }
}
