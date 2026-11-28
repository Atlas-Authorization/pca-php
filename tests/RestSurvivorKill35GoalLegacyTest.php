<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Catalog;
use Atlas\Pca\GoalLegacy;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for lifting a legacy permissions/limits policy into a goal. */
final class RestSurvivorKill35GoalLegacyTest extends TestCase
{
    private static function spec(string $action, array $o = []): array
    {
        return $o + ['connector' => 'shop', 'action' => $action, 'verb' => "shop.$action", 'reversibility' => 'reversible', 'blastRadius' => 0.1];
    }

    private static function refusal(\Closure $f): string
    {
        try {
            $f();
        } catch (\InvalidArgumentException $e) {
            return $e->getMessage();
        }
        return 'no refusal';
    }

    /** An assoc-array input (and an assoc-array limits map, like the reference's object) is read like an Obj: the '$' limit becomes the cap. */
    public function testAssocArrayInputAndLimits(): void
    {
        $r = GoalLegacy::liftLegacy(['permissions' => ['shop' => ['tip']], 'catalog' => [self::spec('tip', ['amountField' => 'cents'])],
            'limits' => ['tip' => '$5'], 'principal' => 'p', 'nlDigest' => 'n']);
        $goal = $r->get('goal');
        $this->assertSame(['p', 'n'], [$goal->get('principal'), $goal->get('nlDigest')]);
        $cond = $goal->get('grants')[0]->get('cond');
        $this->assertSame('and', $cond->get('k'));
        $this->assertSame(500, $cond->get('b')->get('r')->get('v')->get('q')->get('n'));
        $this->assertSame('cents', $cond->get('b')->get('l')->get('path'));
    }

    /** A null input reaches the facade, which refuses the missing permission map. */
    public function testNullInputIsRefusedByTheFacade(): void
    {
        try {
            GoalLegacy::liftLegacy(null);
            $this->fail('lifted null');
        } catch (\TypeError $e) {
            $this->assertStringContainsString('compilePolicy(): Argument #1', $e->getMessage());
        }
    }

    /** A Catalog instance or a list of specs is the catalog: its amount field makes the '$' limit enforceable. */
    public function testCatalogInstanceOrList(): void
    {
        $spec = self::spec('tip', ['amountField' => 'cents']);
        foreach ([new Catalog([$spec]), [$spec]] as $cat) {
            $r = GoalLegacy::liftLegacy(Obj::of(['permissions' => Obj::of(['shop' => ['tip']]), 'catalog' => $cat, 'limits' => Obj::of(['tip' => '$5'])]));
            $this->assertSame('and', $r->get('goal')->get('grants')[0]->get('cond')->get('k'));
        }
        $this->assertStringContainsString('no amount field', self::refusal(static fn() => GoalLegacy::liftLegacy(Obj::of(['permissions' => Obj::of(['shop' => ['tip']]),
            'limits' => Obj::of(['tip' => '$5'])]))));
    }

    /** An exact catalog resource is an exact grant; only the wildcard grants are acknowledged, as a list. */
    public function testExactResourceAndWildcardAck(): void
    {
        $r = GoalLegacy::liftLegacy(Obj::of(['permissions' => Obj::of(['shop' => ['a', 'b']]),
            'catalog' => [self::spec('a', ['resource' => 'acct_1']), self::spec('b')]]));
        $goal = $r->get('goal');
        $grants = $goal->get('grants');
        $this->assertSame(['g:shop.a', 'g:shop.b'], [$grants[0]->get('gid'), $grants[1]->get('gid')]);
        $this->assertSame(['exact', 'acct_1'], [$grants[0]->get('res')->get('k'), $grants[0]->get('res')->get('id')]);
        $this->assertSame('any', $grants[1]->get('res')->get('k'));
        $this->assertSame(['g:shop.b'], $goal->get('wildcardAck'));
    }

    /** A resource pattern other than '*' is refused with its reason. */
    public function testResourcePatternIsRefused(): void
    {
        $this->assertSame("liftLegacy: resource pattern 'acct_*' of shop.a is not expressible; name exact resources or acknowledge a wildcard",
            self::refusal(static fn() => GoalLegacy::liftLegacy(Obj::of(['permissions' => Obj::of(['shop' => ['a']]), 'catalog' => [self::spec('a', ['resource' => 'acct_*'])]]))));
    }

    /** A verb granted twice is refused as a duplicate grant. */
    public function testDuplicateGrantIsRefused(): void
    {
        $this->assertSame('liftLegacy: duplicate grant g:shop.a',
            self::refusal(static fn() => GoalLegacy::liftLegacy(Obj::of(['permissions' => Obj::of(['shop' => ['a', 'a']]), 'catalog' => [self::spec('a')]]))));
    }

    /** A count limit of exactly the largest safe integer is accepted as the cap. */
    public function testLargestSafeCountLimit(): void
    {
        $r = GoalLegacy::liftLegacy(Obj::of(['permissions' => Obj::of(['shop' => ['a']]), 'catalog' => [self::spec('a')],
            'limits' => Obj::of(['a' => '9007199254740991'])]));
        $this->assertSame(GoalLegacy::MAX_SAFE, $r->get('goal')->get('bounds')[0]->get('cap')->get('n'));
    }
}
