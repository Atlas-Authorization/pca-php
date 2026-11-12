<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** F1: the core `plan_root_authorized` check (authorizedPlanRoots / insecureSkipPlanRootCheck), replayed from plan-root-vectors.json. */
final class K05HardPlanRootTest extends TestCase
{
    private static function vector(string $name): Obj
    {
        foreach (Vectors::load('vectors.json')->get('vectors') as $v) {
            if ($v->get('name') === $name) {
                return $v;
            }
        }
        throw new \RuntimeException("no vector $name");
    }

    public function testPlanRootVectors(): void
    {
        $cases = Vectors::load('plan-root-vectors.json')->get('plan_root_authorized');
        $this->assertGreaterThanOrEqual(9, count($cases));
        foreach ($cases as $c) {
            $v = self::vector($c->get('vector'));
            $root = $v->get('pcactn')->get('plan')->get('root');
            $o = $c->get('options');
            $roots = $o->has('authorizedPlanRoots') ? array_map(static fn($r) => $r === '$plan_root' ? $root : $r, $o->get('authorizedPlanRoots')) : null;
            $skip = $o->has('insecureSkipPlanRootCheck') && $o->get('insecureSkipPlanRootCheck') === true;
            $ctx = $v->get('context');
            $r = Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'), null, null, null, null, $roots, $skip);
            $x = $c->get('expect');
            $name = $c->get('name');
            $this->assertSame($x->get('allow'), $r['allow'], "$name allow");
            $status = in_array('plan_root_authorized', $r['not_enforced'] ?? [], true) ? 'not-enforced'
                : (($r['checks']['plan_root_authorized'] ?? null) === true ? 'pass' : 'fail');
            $this->assertSame($x->get('check'), $status, "$name check");
            if ($x->has('reason')) {
                $this->assertSame($x->get('reason'), $r['reason'], "$name reason");
            }
        }
    }

    public function testTheListWinsOverTheOptOut(): void
    {
        $v = self::vector('valid-in-plan-action');
        $ctx = $v->get('context');
        $root = $v->get('pcactn')->get('plan')->get('root');
        $call = static fn(?array $roots, bool $skip): array => Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'), null, null, null, null, $roots, $skip);
        $this->assertTrue($call([$root], false)['allow']);
        $this->assertFalse($call([], false)['allow'], 'an empty list is enforced');
        $this->assertFalse($call([], true)['allow'], 'the list wins over the opt-out');
        $this->assertFalse($call(null, false)['allow']);
        $this->assertTrue($call(null, true)['allow']);
        $this->assertSame(['plan_root_authorized'], $call(null, true)['not_enforced']);
        $this->assertArrayNotHasKey('plan_root_authorized', $call(null, true)['checks']);
    }
}
