<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** F3 requireVerifiedPrincipal / resolvePrincipal: identity enforcement at the resource server. */
final class K05HardPrincipalTest extends TestCase
{
    private Obj $fix;
    private Obj $grant;
    private Obj $p;
    private Obj $op;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                $this->grant = $c->get('grant');
                $this->p = $c->get('steps')[0]->get('pcactn');
                $this->op = $c->get('steps')[0]->get('operation');
            }
        }
        $all = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'];
        Authorize::$coreHook = static fn(array $c): array => ['allow' => true, 'checks' => array_fill_keys($all, true), 'reason' => '', 'reasons' => []];
    }

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    private function az(array $o = []): AuthorizeResult
    {
        $g = $this->grant;
        $p = Json::parseLax(Json::canonicalizeStrict($this->p));
        return Authorize::authorize(...array_merge(['pcactn' => $p, 'operation' => $this->op, 'audience' => $this->fix->get('audience'),
            'resolveGrant' => static fn($ref) => $g, 'stateStore' => new MemoryStateStore(), 'isRevoked' => static fn() => false,
            'now' => $this->fix->get('now')->int(), 'plan' => 'single-step', 'provenance' => ProvHarness::bundle($this->op),
            'provenanceMediators' => [ProvHarness::pin()]], $o));
    }

    public function testNoResolverNoRequirementReportsNothing(): void
    {
        $r = $this->az();
        $this->assertArrayNotHasKey('principal', $r->checks);
    }

    public function testRequiringWithoutAResolverDenies(): void
    {
        $r = $this->az(['requireVerifiedPrincipal' => true]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['principal']);
        $this->assertContains('principal: requireVerifiedPrincipal needs a resolvePrincipal resolver', $r->reasons);
    }

    public function testAVerifiedPrincipalPasses(): void
    {
        $seen = [];
        $resolver = function (string $pub, Obj $grant) use (&$seen): array {
            $seen = [$pub, $grant->get('id')];
            return ['verified' => true, 'subject_id' => 'u1'];
        };
        foreach ([false, true] as $require) {
            $r = $this->az(['resolvePrincipal' => $resolver, 'requireVerifiedPrincipal' => $require]);
            $this->assertSame('pass', $r->checks['principal'], 'require ' . json_encode($require));
        }
        $this->assertSame([$this->grant->get('issuer'), $this->grant->get('id')], $seen);
    }

    public function testAnUnverifiedPrincipalDeniesOnlyWhenRequired(): void
    {
        foreach ([null, ['verified' => false], ['verified' => 'yes'], ['subject_id' => 'x'], Obj::of(['verified' => false])] as $resolved) {
            $r = $this->az(['resolvePrincipal' => static fn() => $resolved]);
            $this->assertSame('not-enforced', $r->checks['principal'], json_encode($resolved instanceof Obj ? 'obj' : $resolved));
            $d = $this->az(['resolvePrincipal' => static fn() => $resolved, 'requireVerifiedPrincipal' => true]);
            $this->assertFalse($d->allow);
            $this->assertSame('fail', $d->checks['principal']);
            $this->assertContains('principal: the grant issuer is not an enrolled, verified principal', $d->reasons);
        }
    }

    public function testAThrowingResolverIsAnUnverifiedPrincipal(): void
    {
        $d = $this->az(['resolvePrincipal' => static fn() => throw new \RuntimeException('down'), 'requireVerifiedPrincipal' => true]);
        $this->assertFalse($d->allow);
        $this->assertSame('fail', $d->checks['principal']);
        $this->assertSame('not-enforced', $this->az(['resolvePrincipal' => static fn() => throw new \RuntimeException('down')])->checks['principal']);
    }

    public function testObjVerifiedTrueIsAccepted(): void
    {
        $r = $this->az(['resolvePrincipal' => static fn() => Obj::of(['verified' => true]), 'requireVerifiedPrincipal' => true]);
        $this->assertSame('pass', $r->checks['principal']);
    }
}
