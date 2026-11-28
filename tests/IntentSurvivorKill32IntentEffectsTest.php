<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentEffects;
use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/IntentEffects.php';
require_once __DIR__ . '/../src/IntentMapKit.php';

/** Group 32 mutation kills for src/IntentEffects.php: postcondition leaves, path reads, the per-postcondition outcome and verifyOutcome. */
final class IntentSurvivorKill32IntentEffectsTest extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function vs(string $verb = 'v', string $rev = 'reversible'): Obj
    {
        return Obj::of(['verb' => $verb, 'reversibility' => $rev, 'weight' => 1, 'dims' => []]);
    }

    private static function omega(Obj ...$verbs): Obj
    {
        return Obj::of(['v' => 1, 'approximate' => [], 'verbs' => $verbs]);
    }

    private static function leaf(string $field, string $op, mixed $v, bool $ref = false): Obj
    {
        $o = Obj::of(['field' => $field, 'op' => $op]);
        $o->set($ref ? 'ref' : 'value', $v);
        return $o;
    }

    private static function pc(string $id, array $where, string $verb = 'v'): Obj
    {
        return Obj::of(['id' => $id, 'verb' => $verb, 'description' => $id, 'where' => $where]);
    }

    /** checkPostconditions of the dimensionless verb 'v' with `$pcs` against the effect. */
    private static function check(array $pcs, Obj $effect): array
    {
        $vs = self::vs();
        return IntentEffects::checkPostconditions($vs, IntentOmega::cellRep($vs, []), $effect, $pcs);
    }

    private static function stub(Obj $omega): object
    {
        return new class ($omega) {
            public function __construct(public Obj $omega)
            {
            }
        };
    }

    /** A group whose all_of / any_of is not an array contributes no leaf (it is never iterated). */
    public function testANonArrayGroupHasNoLeaves(): void
    {
        foreach (['all_of', 'any_of'] as $k) {
            $r = self::check([self::pc('p', [Obj::of([$k => 'x'])])], new Obj());
            self::assertSame(['p'], $r['checked'], $k);
            self::assertSame([], $r['missing'], $k);
        }
    }

    /** Path reads: a list element by a canonical index below its length; past the end, or into a string, is undefined. */
    public function testPathReads(): void
    {
        $effect = Obj::of(['xs' => [7], 'n' => 7, 's' => 'abc']);
        $ok = self::check([self::pc('p', [self::leaf('env.effect.n', 'eq', 'env.effect.xs.0', true)])], $effect);
        self::assertSame('ok', $ok['status']);
        self::assertSame(['p'], $ok['checked']);
        $past = self::check([self::pc('p', [self::leaf('env.effect.n', 'eq', 'env.effect.xs.1', true)])], $effect);
        self::assertSame(['pending', ['env.effect.xs.1']], [$past['status'], $past['missing']]);
        $str = self::check([self::pc('p', [self::leaf('env.effect.n', 'eq', 'env.effect.s.0', true)])], $effect);
        self::assertSame(['pending', ['env.effect.s.0']], [$str['status'], $str['missing']]);
    }

    /** A postcondition whose non-effect reference is absent is not applicable, and the next one is still checked. */
    public function testNotApplicableThenChecked(): void
    {
        $r = self::check([
            self::pc('na', [self::leaf('env.effect.n', 'eq', 'action.params.nope', true)]),
            self::pc('p', [self::leaf('env.effect.n', 'eq', 7)]),
        ], Obj::of(['n' => 7]));
        self::assertSame(['na'], $r['notApplicable']);
        self::assertSame(['p'], $r['checked']);
        self::assertSame('ok', $r['status']);
    }

    /** Only env.effect.* members can be missing: an absent action field is checked (and evaluated), not pending. */
    public function testOnlyEffectFieldsCanBeMissing(): void
    {
        $r = self::check([self::pc('p', [self::leaf('action.params.nope', 'eq', 1)])], new Obj());
        self::assertSame(['p'], $r['checked']);
        self::assertSame([], $r['missing']);
    }

    /** A member missing for two postconditions is listed once. */
    public function testMissingIsDistinct(): void
    {
        $r = self::check([self::pc('a', [self::leaf('env.effect.amount', 'gte', 0)]), self::pc('b', [self::leaf('env.effect.amount', 'lte', 9)])], new Obj());
        self::assertSame(['pending', ['env.effect.amount']], [$r['status'], $r['missing']]);
    }

    /** The context carries the verb space's reversibility as action.reversibility_class. */
    public function testTheContextCarriesTheReversibility(): void
    {
        $vs = self::vs('v', 'irreversible');
        $ctx = IntentEffects::effectContext($vs, IntentOmega::cellRep($vs, []), new Obj());
        self::assertSame('irreversible', $ctx->get('action')->get('reversibility_class'));
    }

    /** verifyOutcome is public; it uses the FIRST verb space of the outcome's verb and returns only the report when nothing is violated. */
    public function testVerifyOutcomeWithoutAViolation(): void
    {
        $pcs = [self::pc('p', [self::leaf('action.reversibility_class', 'eq', 'reversible')])];
        $o = IntentOmega::cellRep(self::vs(), []);
        $r = IntentEffects::verifyOutcome(self::stub(self::omega(self::vs('w', 'irreversible'), self::vs('v', 'reversible'), self::vs('v', 'irreversible'))), $o, new Obj(), $pcs);
        self::assertSame(['report'], array_keys($r));
        self::assertSame('ok', $r['report']['status']);
        self::assertSame(['p'], $r['report']['checked']);
    }

    /** An outcome of a verb the learner's omega lacks is refused, naming it. */
    public function testVerifyOutcomeRefusesAMissingVerb(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("verifyOutcome: no verb zz in \u{03A9}");
        IntentEffects::verifyOutcome(self::stub(self::omega(self::vs())), IntentOmega::cellRep(self::vs('zz'), []), new Obj(), []);
    }

    /** A violation is a negative runtime observation (y = 0): the confirmed cell leaves the grant. */
    public function testAViolationVetoesTheCell(): void
    {
        $vs = self::vs();
        $l = IntentMapKit::createLearner(self::omega($vs));
        $o = IntentOmega::cellRep($vs, []);
        $l->observe($o, 1);
        $r = IntentEffects::verifyOutcome($l, $o, Obj::of(['x' => 2]), [self::pc('p', [self::leaf('env.effect.x', 'eq', 1)])]);
        self::assertSame(['report', 'divergence'], array_keys($r));
        self::assertSame(['p'], $r['report']['violated']);
        self::assertSame([1, 0], [$r['divergence']['before'], $r['divergence']['after']]);
    }
}
