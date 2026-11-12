<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Decision.php';

use Atlas\Pca\Decision;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for Decision: the lattice on non-string inputs, decisionOfVerdict on host objects that only look like
 * an Obj, model-path collection (depth limit, skipped lists, non-object conditions), decideTighten / decideUnits catch
 * messages, and the units rule's tag / read loops (continue vs break, sort order, numeric paths, nesting depth).
 */
final class K05KillDecisionTest extends TestCase
{
    private static function o(array|string $v): mixed
    {
        return Json::parseLax(is_string($v) ? $v : json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /** A host object that answers keys / has / get like an Obj but is not one. */
    private static function lookalike(array $d): object
    {
        return new class ($d) {
            public function __construct(private readonly array $d)
            {
            }

            public function keys(): array
            {
                return array_map('strval', array_keys($this->d));
            }

            public function has(string $k): bool
            {
                return array_key_exists($k, $this->d);
            }

            public function get(string $k): mixed
            {
                return $this->d[$k] ?? null;
            }
        };
    }

    /** `$leaf` wrapped in `$n` levels of `{all_of: [..]}`, so collectPaths sees it at depth `$n`. */
    private static function nest(Obj $leaf, int $n): Obj
    {
        for ($i = 0; $i < $n; $i++) {
            $leaf = Obj::of(['all_of' => [$leaf]]);
        }
        return $leaf;
    }

    public function testMeetOfAnObjectIsADenyWithoutTouchingTheRankTable(): void
    {
        // a non-string must short-circuit before isset(RANK[$obj]) (which throws for an object offset)
        $this->assertSame('deny', Decision::meet(new Obj(), 'allow'));
        $this->assertSame('deny', Decision::meet('allow', new Obj()));
    }

    public function testSignalCeilingIsPublic(): void
    {
        $this->assertSame(['allow', 'escalate', 'deny'], [Decision::signalCeiling('ok'), Decision::signalCeiling('escalate'), Decision::signalCeiling('x')]);
    }

    public function testDecisionOfVerdictNeedsRealObjs(): void
    {
        $this->assertSame('allow', Decision::decisionOfVerdict(Obj::of(['allow' => true, 'checks' => new Obj()])), 'control');
        // checks that only look like an Obj
        $this->assertSame('deny', Decision::decisionOfVerdict(Obj::of(['allow' => true, 'checks' => self::lookalike(['a' => 'pass'])])));
        // a verdict that only looks like an Obj, with real checks
        $this->assertSame('deny', Decision::decisionOfVerdict(self::lookalike(['allow' => true, 'checks' => new Obj()])));
        // reasons that are not a list are dropped, not fed to array_is_list
        $this->assertSame('allow', Decision::decisionOfVerdict(Obj::of(['allow' => true, 'checks' => new Obj(), 'reasons' => 'x'])));
    }

    public function testIsModelDerivedPathNeedsAStringUnderEnv(): void
    {
        $this->assertFalse(Decision::isModelDerivedPath(5));
        $this->assertFalse(Decision::isModelDerivedPath('x.class'));
        $this->assertTrue(Decision::isModelDerivedPath('env.class'), 'control');
    }

    public function testModelPathsDepthLimitIsExactly64(): void
    {
        $where = [self::nest(Obj::of(['field' => 'env.class.a']), 64), self::nest(Obj::of(['field' => 'env.class.b']), 65)];
        $this->assertSame(['env.class.a'], Decision::modelPathsRead([[Obj::of(['verb' => '*', 'where' => $where])]]));
    }

    public function testModelPathsSkipNonListsAndNonObjects(): void
    {
        $p = Obj::of(['where' => [Obj::of(['field' => 'env.class.t'])]]);
        $this->assertSame(['env.class.t'], Decision::modelPathsRead(['x', [$p]]), 'a non-list predicate list is skipped, not the end');
        $this->assertSame([], Decision::modelPathsRead([[Obj::of(['where' => [5]])]]), 'a non-object condition is ignored');
        $this->assertSame(['env.class.t'], Decision::modelPathsRead([[Obj::of(['where' => [Obj::of(['field' => '5']), Obj::of(['field' => 'env.class.t'])]])]]));
    }

    public function testDecideTightenCatchMessageIsExact(): void
    {
        $this->assertSame(['outcome' => 'deny', 'legacy' => false, 'offending' => [], 'reason' => 'evaluation error (fail closed): input is not an object'],
            Decision::decideTighten(5));
    }

    public function testUnitTagExponentMustBeAJsonNumber(): void
    {
        $u = Obj::of(['action.params.a' => Obj::of(['kind' => 'm', 'exponent' => 2])]);
        $this->assertSame("units['action.params.a'].exponent must be an integer in [0, 18]", Decision::unitTagsError($u));
    }

    public function testDecideUnitsCatchMessageIsExact(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'evaluation error (fail closed): input is not an object'], Decision::decideUnits(5));
    }

    /** `$preds` (built Objs, which json_encode cannot carry) replaces `predicates` after parsing. */
    private static function units(array $over, mixed $preds = null): array
    {
        $in = self::o($over + [
            'units' => (object)[], 'verb' => 'refund', 'schema_units' => ['u' => ['kind' => 'money', 'currency' => 'USD']],
            'verb_params' => ['action.params.a' => ['unit' => 'u'], 'action.params.b' => ['unit' => 'u']],
        ]);
        if ($preds !== null) {
            $in->set('predicates', $preds);
        }
        return Decision::decideUnits($in);
    }

    private static function readMsg(string $p): array
    {
        return ['ok' => false, 'reason' => "a policy term reads '$p' (money/USD) without a unit tag"];
    }

    public function testDecideUnitsSkipsANonObjectPredicate(): void
    {
        $this->assertSame(['ok' => true], self::units(['predicates' => [[5]]]));
    }

    public function testATagForAnUndeclaredParamIsSkippedNotTheEnd(): void
    {
        $r = self::units(['units' => ['action.params.a' => ['kind' => 'money'], 'action.params.c' => ['kind' => 'money']],
            'verb_params' => ['action.params.c' => ['unit' => 'u']]]);
        $this->assertSame(['ok' => false, 'reason' => "'action.params.c' is declared as money/USD by the action schema but the policy term is tagged money (unit confusion)"], $r);
    }

    public function testAnOutOfScopePredicateIsSkippedNotTheEnd(): void
    {
        $w = [['field' => 'action.params.a']];
        $this->assertSame(self::readMsg('action.params.a'), self::units(['predicates' => [[['verb' => 'other', 'where' => $w], ['verb' => 'refund', 'where' => $w]]]]));
    }

    public function testReadPathsAreSortedAndNonParamPathsSkipped(): void
    {
        $where = [['field' => 'action.params.b'], ['field' => 'action.params.a']];
        $this->assertSame(self::readMsg('action.params.a'), self::units(['predicates' => [[['verb' => '*', 'where' => $where]]]]));
        $where = [['field' => 'a.x'], ['field' => 'action.params.a']];
        $this->assertSame(self::readMsg('action.params.a'), self::units(['predicates' => [[['verb' => '*', 'where' => $where]]]]));
        // a numeric path is a string key that PHP stores as an int: it must reach preg_match as a string
        $this->assertSame(['ok' => true], self::units(['predicates' => [[['verb' => '*', 'where' => [['field' => '5']]]]]]));
    }

    public function testUnitsReadDepthStartsAtZero(): void
    {
        $leaf = Obj::of(['field' => 'action.params.a']);
        $in = static fn(int $n): array => self::units([], [[Obj::of(['verb' => '*', 'where' => [self::nest($leaf, $n)]])]]);
        $this->assertSame(self::readMsg('action.params.a'), $in(64));
        $this->assertSame(['ok' => true], $in(65));
    }
}
