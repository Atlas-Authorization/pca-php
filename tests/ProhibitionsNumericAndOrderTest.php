<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Prohibitions;
use PHPUnit\Framework\TestCase;

/** Number forms, first-problem ordering, defensive copies and key handling of the prohibition plane (reference: packages/pca/src/prohibitions.ts). */
final class ProhibitionsNumericAndOrderTest extends TestCase
{
    private static function when(): Obj
    {
        return Obj::of(['verb' => 'pay']);
    }

    private static function state(array $ledger = [], array $latched = []): Obj
    {
        return Obj::of(['now' => new Num('2000000'), 'seq' => new Num('0'), 'parent' => null, 'ledger' => Obj::of($ledger), 'latched' => Obj::of($latched)]);
    }

    private static function rateWithMax(mixed $max): array
    {
        return Prohibitions::validateInvariant(Obj::of(['id' => 'r', 'kind' => 'rate', 'when' => self::when(), 'max' => $max, 'window_secs' => new Num('1')]));
    }

    public function testNegativeZeroIsRefusedForARateMaxInEveryNumberForm(): void
    {
        foreach ([new Num('-0'), new Num('-0.0'), -0.0] as $negative) {
            $this->assertSame(['r: max must be an integer in [0,10000]'], self::rateWithMax($negative));
        }
        foreach ([new Num('0'), new Num('0.0'), 0.0, 0, new Num('5'), 5.0, 5] as $fine) {
            $this->assertSame([], self::rateWithMax($fine));
        }
    }

    public function testANegativeNonZeroLexemeKeepsItsValueInTheCanonicalState(): void
    {
        $entry = Obj::of(['t' => new Num('-5'), 'amount' => new Num('1')]);
        $canon = Prohibitions::canonicalState(self::state(['k' => [$entry]], ['l' => new Num('-5')]));
        $this->assertSame('-5', $canon->get('ledger')->get('k')[0]->get('t')->lexeme);
        $this->assertSame('1', $canon->get('ledger')->get('k')[0]->get('amount')->lexeme);
        $this->assertSame('-5', $canon->get('latched')->get('l')->lexeme);
    }

    public function testTheFirstProblemOfAnInvariantFollowsTheReferenceOrder(): void
    {
        $bad = Obj::of([]);
        $this->assertSame(['u: when: not an object'], Prohibitions::validateInvariant(Obj::of(['id' => 'u', 'kind' => 'never_unless', 'when' => 5, 'unless' => []])));
        $this->assertSame(['u: unless must be a non-empty array'], Prohibitions::validateInvariant(Obj::of(['id' => 'u', 'kind' => 'never_unless', 'when' => self::when(), 'unless' => []])));
        $this->assertSame(['a: after: not an object'], Prohibitions::validateInvariant(Obj::of(['id' => 'a', 'kind' => 'never_after', 'after' => 5, 'forbid' => $bad])));
        $this->assertSame(['a: forbid: bad verb'], Prohibitions::validateInvariant(Obj::of(['id' => 'a', 'kind' => 'never_after', 'after' => self::when(), 'forbid' => $bad])));
        $this->assertSame(['p: when: not an object'], Prohibitions::validateInvariant(Obj::of(['id' => 'p', 'kind' => 'require_prior', 'when' => 5, 'prior' => $bad])));
        $this->assertSame(['p: prior: bad verb'], Prohibitions::validateInvariant(Obj::of(['id' => 'p', 'kind' => 'require_prior', 'when' => self::when(), 'prior' => $bad])));
    }

    public function testTheVersionMustBeAParsedNumberOne(): void
    {
        $with = static fn(mixed $v): array => Prohibitions::validateConstitution(Obj::of(['version' => $v, 'principal' => 'p', 'invariants' => []]));
        $this->assertSame([], $with(new Num('1')));
        $this->assertSame(['unsupported version 1'], $with(1));
        $this->assertSame(['unsupported version 1'], $with(1.0));
        $this->assertSame(['unsupported version true'], $with(true));
        $this->assertSame(['unsupported version 1'], $with('1'));
    }

    public function testOnlyARealObjectIsAMonitorState(): void
    {
        $this->assertNull(Prohibitions::stateProblem(self::state()));
        $fake = new class (self::state()) {
            public function __construct(private Obj $o)
            {
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function has(string $k): bool
            {
                return $this->o->has($k);
            }
        };
        $this->assertSame('malformed monitor state', Prohibitions::stateProblem($fake));
        // a ledger or latch map that is not an object is reported before any later problem, whatever the sequence number is
        foreach (['ledger', 'latched'] as $k) {
            $st = Obj::of(['now' => new Num('2000000'), 'seq' => new Num('-1'), 'parent' => null, 'ledger' => Obj::of([]), 'latched' => Obj::of([])]);
            $st->set($k, 5);
            $this->assertSame('malformed monitor state', Prohibitions::stateProblem($st));
        }
    }

    public function testEvidenceRowsAreCopiedNotShared(): void
    {
        $c = Obj::of(['version' => new Num('1'), 'principal' => 'p', 'invariants' => [Obj::of(['id' => 'n', 'kind' => 'never', 'when' => Obj::of(['verb' => 'wire'])])]]);
        $act = Obj::of(['action' => Obj::of(['verb' => 'pay', 'resource' => '/r'])]);
        $st = self::state();
        $r = Prohibitions::check($act, $c, $st);
        $ev = Prohibitions::evidenceFrom($r, $act, $c, $st);
        $row = $ev->get('evaluated')[0];
        $this->assertNotSame($r['evaluated'][0], $row);
        $r['evaluated'][0]->set('id', 'changed');
        $this->assertSame('n', $row->get('id'));
    }

    public function testANumericLookingInvariantIdSurvivesAdvance(): void
    {
        $cap = Obj::of(['id' => '7', 'kind' => 'cap', 'when' => self::when(), 'amount' => 'action.params.amount', 'max' => new Num('100')]);
        $c = Obj::of(['version' => new Num('1'), 'principal' => 'p', 'invariants' => [$cap]]);
        $act = Obj::of(['action' => Obj::of(['verb' => 'pay', 'resource' => '/r', 'params' => Obj::of(['amount' => new Num('5')])])]);
        $r = Prohibitions::advanceStrict($act, $c, self::state());
        $this->assertTrue($r['ok']);
        $this->assertSame(['7'], $r['state']->get('ledger')->keys());
        $this->assertCount(1, $r['state']->get('ledger')->get('7'));
    }
}
