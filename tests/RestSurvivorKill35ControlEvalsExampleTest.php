<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Catalog;
use Atlas\Pca\ControlEvalsExample;
use Atlas\Pca\ExampleBlue;
use Atlas\Pca\ExampleSession;
use Atlas\Pca\Facade;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the example blue control protocol. */
final class RestSurvivorKill35ControlEvalsExampleTest extends TestCase
{
    private static ?AgentHandle $agent = null;

    private static function agent(): AgentHandle
    {
        return self::$agent ??= ControlEvalsExample::buildExampleAgent(new KeyPair(str_repeat("\x05", 32)), new KeyPair(str_repeat("\x06", 32)));
    }

    private static function session(array $rp = [], ?Obj $dlp = null, ?AgentHandle $a = null): ExampleSession
    {
        $a ??= self::agent();
        return new ExampleSession($a, Sign::n(array_replace($a->policy['riskPolicy'], ['theta1' => 1, 'theta2' => 1], $rp)), $dlp, 0.0);
    }

    /** The given principal key is the agent's principal. */
    public function testBuildExampleAgentUsesTheGivenPrincipal(): void
    {
        $p = new KeyPair(str_repeat("\x05", 32));
        $this->assertSame($p->public, ControlEvalsExample::buildExampleAgent($p)->principalPublic);
    }

    /** The default seed is 1. */
    public function testDefaultSeedIsOne(): void
    {
        $this->assertSame(Base::canon(ControlEvalsExample::exampleControlEval(1, 1, self::agent())),
            Base::canon(ControlEvalsExample::exampleControlEval(1, agent: self::agent())));
    }

    /** The analytic bound is max(0, bMax) / kappa, and 0 when kappa is not positive. */
    public function testAnalyticBound(): void
    {
        $this->assertSame(0.0, (new ExampleBlue(self::agent(), Sign::n(['kappa' => 0, 'bMax' => 5]), null))->analyticBound);
        $this->assertSame(0.5, (new ExampleBlue(self::agent(), Sign::n(['kappa' => 1, 'bMax' => 0.5]), null))->analyticBound);
    }

    /** An action that is not an object has no verb, resource or params: it is denied, and moves no money. */
    public function testANonObjectActionIsDenied(): void
    {
        $s = self::session();
        $this->assertSame(0.0, $s->moneyAmount('x'));
        $this->assertSame('deny', $s->decide('x', 0)->get('outcome'));
    }

    /** With a base kappa of 0 a money action's risk falls back to its blast radius (no division by zero). */
    public function testZeroKappaFallsBackToBlastRadius(): void
    {
        $d = self::session(['kappa' => 0])->decide(Obj::of(['verb' => 'stripe.refund', 'resource' => 'ch_1', 'params' => Obj::of(['amount' => 100])]), 0);
        $this->assertIsString($d->get('outcome'));
        $this->assertGreaterThanOrEqual(0.0, $d->get('r'));
        $this->assertLessThanOrEqual(1.0, $d->get('r'));
    }

    /** Params that are not an object are neither reviewed nor digested as params. */
    public function testNonObjectParamsAreIgnored(): void
    {
        $d = self::session()->decide(Obj::of(['verb' => 'gmail.send', 'resource' => 'external:x', 'params' => INF]), 0);
        $this->assertIsString($d->get('outcome'));
    }

    /** An auto-tier review does not digest the params, so a non-canonical number in them is not refused. */
    public function testAutoTierDoesNotDigestParams(): void
    {
        $d = self::session()->decide(Obj::of(['verb' => 'stripe.refund', 'resource' => 'ch_1', 'params' => Obj::of(['amount' => 100, 'big' => 1e20])]), 0);
        $this->assertIsString($d->get('outcome'));
    }

    /** A denial whose reason mentions a caveat in any case is attributed to the caveats. */
    public function testCaveatAttributionIsCaseInsensitive(): void
    {
        $d = self::session()->decide(Obj::of(['verb' => 'gmail.delete', 'resource' => 'CAVEAT']), 0);
        $this->assertSame(['deny', 'caveat'], [$d->get('outcome'), $d->get('caughtBy')]);
    }

    /** A verb the session catalog lacks takes its spec from the agent's policy (its own catalog's blast radius). */
    public function testPolicySpecFallback(): void
    {
        $cat = Catalog::buildCatalog([Catalog::defineAction(['connector' => 'acme', 'action' => 'op', 'reversibility' => 'reversible', 'blastRadius' => 0.3])]);
        $a = Facade::createAgent(new KeyPair(str_repeat("\x05", 32)), 'g', ['acme' => ['op']], null, new KeyPair(str_repeat("\x06", 32)), catalog: $cat, aud: 'x', now: 0);
        $this->assertSame(0.3, self::session([], null, $a)->decide(Obj::of(['verb' => 'acme.op', 'resource' => 'r1']), 0)->get('r'));
    }

    /** An action without a taint is taint 0 to the data-flow policy. */
    public function testMissingTaintIsZero(): void
    {
        $dlp = Obj::of(['classes' => [], 'defaultMaxTaintForAuto' => -0.5]);
        $d = self::session([], $dlp)->decide(Obj::of(['verb' => 'gmail.send', 'resource' => 'r']), 0);
        $this->assertSame(['step_up', 'dlp'], [$d->get('outcome'), $d->get('caughtBy')]);
    }
}
