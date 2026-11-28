<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalNversion.php';

use Atlas\Pca\GoalNversion;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of the N-version meet (nversion.ts): prohibition / bound / escalation merging, validity, touch, wildcard acks, holes, panel. */
final class MathSurvivorKill31GoalNversionTest extends TestCase
{
    private static function j(mixed $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION));
    }

    private static function goal(array $over = []): array
    {
        return $over + ['v' => 1, 'principal' => 'p', 'ontDigest' => 'o', 'nlDigest' => 'n', 'sources' => [], 'grants' => [], 'prohibits' => [], 'bounds' => [],
            'validity' => ['notBefore' => 0, 'notAfter' => 100, 'maxIdle' => 0], 'deleg' => ['maxDepth' => 1, 'narrowOnly' => true, 'mayTouch' => []],
            'escalateOn' => [], 'wildcardAck' => [], 'holes' => []];
    }

    private static function gr(string $gid, string $verb, ?string $exact = null): array
    {
        return ['gid' => $gid, 'verb' => $verb, 'res' => $exact === null ? ['k' => 'any', 'reason' => 'r'] : ['k' => 'exact', 'id' => $exact], 'cond' => ['k' => 'true']];
    }

    private static function meet(array $g0, array $g1): Obj
    {
        return GoalNversion::meet([self::j($g0), self::j($g1)]);
    }

    /** @return list<mixed> */
    private static function ids(Obj $m, string $list, string $id): array
    {
        return array_map(fn(Obj $x) => $x->get($id), $m->get($list));
    }

    private static function pro(string $pid, string $verb): array
    {
        return ['pid' => $pid, 'target' => ['k' => 'verb', 'verb' => $verb], 'res' => ['k' => 'any', 'reason' => 'r'], 'cond' => ['k' => 'true']];
    }

    private static function bnd(string $bid, array $gids, int $cap = 5): array
    {
        $q = ['u' => ['k' => 'count'], 'n' => 1];
        return ['bid' => $bid, 'sel' => ['k' => 'gids', 'gids' => $gids], 'agg' => 'count', 'value' => ['k' => 'lit', 'v' => ['k' => 'q', 'q' => $q]], 'key' => '',
            'window' => ['k' => 'task'], 'scope' => ['k' => 'session'], 'cap' => ['u' => ['k' => 'count'], 'n' => $cap], 'onExceed' => 'escalate'];
    }

    /** A prohibition repeated under another pid is kept once; a different one reusing a taken pid is renamed pid#reading. */
    public function testProhibitionMerging(): void
    {
        $m = self::meet(self::goal(['prohibits' => [self::pro('p1', 'x')]]), self::goal(['prohibits' => [self::pro('p9', 'x'), self::pro('p1', 'y')]]));
        self::assertSame(['p1', 'p1#1'], self::ids($m, 'prohibits', 'pid'));
    }

    /** A bound deriving no merged grant is skipped (the next one still counts); a duplicate merges into the first (the next one still counts). */
    public function testBoundMerging(): void
    {
        $gr0 = [self::gr('a', 'v'), self::gr('b', 'w')];
        $gr1 = [self::gr('c', 'v'), self::gr('d', 'w')];
        $m = self::meet(self::goal(['grants' => $gr0, 'bounds' => [self::bnd('b0', ['zz']), self::bnd('b1', ['a'])]]),
            self::goal(['grants' => $gr1, 'bounds' => [self::bnd('b1x', ['c'], 3), self::bnd('b2', ['d'])]]));
        self::assertSame(['b1', 'b2'], self::ids($m, 'bounds', 'bid'));
        self::assertSame('3', $m->get('bounds')[0]->get('cap')->get('n')->lexeme, 'the smaller cap wins');
    }

    /** Distinct escalation conditions of the readings are all kept. */
    public function testEscalationsAreUnioned(): void
    {
        $m = self::meet(self::goal(['escalateOn' => [['k' => 'true']]]), self::goal(['escalateOn' => [['k' => 'not', 'c' => ['k' => 'true']]]]));
        self::assertCount(2, $m->get('escalateOn'));
    }

    /** maxIdle is the smallest positive one (1 counts); on a tie the first reading's own value is kept. */
    public function testValidityMeet(): void
    {
        $m = self::meet(self::goal(['validity' => ['notBefore' => 5, 'notAfter' => 100, 'maxIdle' => 1]]),
            self::goal(['validity' => ['notBefore' => 5.0, 'notAfter' => 100.0, 'maxIdle' => 0]]));
        $v = $m->get('validity');
        self::assertSame(1.0, Js::num($v->get('maxIdle')));
        self::assertSame(['5', '100'], [$v->get('notBefore')->lexeme, $v->get('notAfter')->lexeme]);
    }

    /** A merged grant may be touched only when every reading lets its own source grant be touched. */
    public function testMayTouch(): void
    {
        $g0 = self::goal(['grants' => [self::gr('a', 'v')], 'deleg' => ['maxDepth' => 1, 'narrowOnly' => true, 'mayTouch' => ['a']]]);
        $g1 = self::goal(['grants' => [self::gr('c', 'v')], 'deleg' => ['maxDepth' => 1, 'narrowOnly' => true, 'mayTouch' => ['c']]]);
        self::assertSame(['a&c'], self::meet($g0, $g1)->get('deleg')->get('mayTouch'));
        $g1['deleg']['mayTouch'] = [];
        self::assertSame([], self::meet($g0, $g1)->get('deleg')->get('mayTouch'));
    }

    /** A merged wildcard grant is acknowledged only when every reading acknowledged its own (first-found) source grant or that grant is not a wildcard. */
    public function testWildcardAck(): void
    {
        $g0 = self::goal(['grants' => [self::gr('a', 'v', 'r1'), self::gr('b', 'w')], 'wildcardAck' => ['b']]);
        $g1 = self::goal(['grants' => [self::gr('c', 'v', 'r1'), self::gr('d', 'w')], 'wildcardAck' => ['d']]);
        self::assertSame(['b&d'], self::meet($g0, $g1)->get('wildcardAck'));
        $g1['wildcardAck'] = [];
        self::assertSame([], self::meet($g0, $g1)->get('wildcardAck'));
        $dup = self::goal(['grants' => [self::gr('b', 'z', 'r1'), self::gr('b', 'w')]]);
        self::assertSame(['b&d'], self::meet($dup, self::goal(['grants' => [self::gr('d', 'w')], 'wildcardAck' => ['d']]))->get('wildcardAck'));
    }

    /** Holes with the same hid merge their affected grants across readings; a hole without a hid is kept. */
    public function testHoles(): void
    {
        $h = fn(?string $hid, array $affects) => ($hid === null ? [] : ['hid' => $hid]) + ['q' => 'q', 'domain' => [], 'affects' => $affects, 'global' => false];
        $g0 = self::goal(['grants' => [self::gr('a', 'v'), self::gr('b', 'w')], 'holes' => [$h('h1', ['a']), $h(null, [])]]);
        $g1 = self::goal(['grants' => [self::gr('c', 'v'), self::gr('d', 'w')], 'holes' => [$h('h1', ['d'])]]);
        $holes = self::meet($g0, $g1)->get('holes');
        self::assertCount(2, $holes);
        $h1 = array_values(array_filter($holes, fn(Obj $x) => $x->get('hid') === 'h1'));
        self::assertSame(['a&c', 'b&d'], $h1[0]->get('affects'));
    }

    /** Model families are counted by family, not by reading. */
    public function testPanelCountsFamilies(): void
    {
        $issues = GoalNversion::checkPanel([self::j(['deterministic' => true, 'family' => 't']), self::j(['family' => 'x']), self::j(['family' => 'x'])]);
        self::assertSame(['no_family_diversity'], array_map(fn(Obj $o) => $o->get('code'), $issues));
    }
}
