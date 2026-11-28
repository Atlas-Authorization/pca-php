<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Jsx.php';
require_once __DIR__ . '/../src/GoalNormalize.php';

use Atlas\Pca\GoalNormalize;
use Atlas\Pca\Obj;
use Atlas\Pca\Undef;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/GoalNormalize.php: undefined members in the stable key, id ordering of members without a string id, the goal type check. */
final class RestSurvivorKill36dGoalNormalizeTest extends TestCase
{
    private static function goal(array $grants): Obj
    {
        return Obj::of(['grants' => $grants, 'prohibits' => [], 'bounds' => [], 'holes' => [], 'wildcardAck' => [],
            'deleg' => Obj::of(['mayTouch' => []])]);
    }

    /** An undefined member is dropped from the stable key, like JSON.stringify drops it. */
    public function testStableDropsUndefinedMembers(): void
    {
        $this->assertSame('{"b":"x","c":"y"}', GoalNormalize::stable(Obj::of(['c' => 'y', 'a' => new Undef(), 'b' => 'x'])));
        $this->assertSame('{"b":"x","c":"y"}', GoalNormalize::stable(Obj::of(['c' => 'y', 'b' => 'x'])));
    }

    /** Grants whose ids are not strings compare equal: a stable sort keeps their order, even past the insertion-sort size (17 members). */
    public function testNonStringIdsKeepTheirOrder(): void
    {
        $grants = [];
        for ($i = 0; $i < 17; $i++) {
            $grants[] = Obj::of(['gid' => $i]);
        }
        $out = GoalNormalize::canonicalizeGoal(self::goal($grants))->get('grants');
        $this->assertSame(range(0, 16), array_map(static fn(Obj $g) => $g->get('gid'), $out));
        $two = GoalNormalize::canonicalizeGoal(self::goal([Obj::of(['gid' => 2]), Obj::of(['gid' => 1])]))->get('grants');
        $this->assertSame([2, 1], array_map(static fn(Obj $g) => $g->get('gid'), $two));
    }

    /** A string id next to a non-string id is not compared as strings: the pair stays as given, no error. */
    public function testMixedIdKindsCompareEqual(): void
    {
        $out = GoalNormalize::canonicalizeGoal(self::goal([Obj::of(['gid' => 'a']), Obj::of(['gid' => 1])]))->get('grants');
        $this->assertSame(['a', 1], array_map(static fn(Obj $g) => $g->get('gid'), $out));
        $sorted = GoalNormalize::canonicalizeGoal(self::goal([Obj::of(['gid' => 'b']), Obj::of(['gid' => 'a'])]))->get('grants');
        $this->assertSame(['a', 'b'], array_map(static fn(Obj $g) => $g->get('gid'), $sorted));
    }

    /** A goal that is not an object is refused with the goal's own message. */
    public function testNonObjectGoalIsRefused(): void
    {
        try {
            GoalNormalize::canonicalizeGoal(['grants' => []]);
            $this->fail('no TypeError');
        } catch (\TypeError $e) {
            $this->assertSame('goal must be an object', $e->getMessage());
        }
    }
}
