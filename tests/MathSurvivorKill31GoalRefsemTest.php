<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalRefsem;
use Atlas\Pca\Json;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of the independent goal semantics (refsem.ts): condition truth, resources, scopes, windows, bounds. */
final class MathSurvivorKill31GoalRefsemTest extends TestCase
{
    private static function j(mixed $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    /** @return array{0:array,1:array,2:array,3:array} goal, ontology, action, history */
    private static function base(): array
    {
        $g = ['validity' => ['notBefore' => 0, 'notAfter' => 1000000], 'deleg' => ['maxDepth' => 1, 'mayTouch' => ['g1']], 'prohibits' => [], 'escalateOn' => [],
            'grants' => [['gid' => 'g1', 'verb' => 'v', 'res' => ['k' => 'any'], 'cond' => ['k' => 'true']]], 'bounds' => []];
        $ont = ['verbs' => [['verb' => 'v', 'cls' => 'pay']], 'rels' => []];
        $a = ['verb' => 'v', 'res' => 'r1', 't' => 100, 'depth' => 0, 'params' => (object)[], 'sess' => 's1', 'prin' => 'p1', 'org' => 'o1', 'agent' => 'ag1'];
        $h = ['aggs' => (object)[], 'last' => 50, 'adms' => []];
        return [$g, $ont, $a, $h];
    }

    /** @return array{0:int,1:mixed,2:int} [d, witness, prohibit] */
    private static function runRefsem(array $g, array $ont, array $a, array $h): array
    {
        $r = GoalRefsem::refExplain(self::j($g), self::j($ont), self::j($a), self::j($h));
        return [$r->get('d'), $r->get('witness'), $r->get('prohibit')];
    }

    private static function q(mixed $n, mixed $u = 'usd'): array
    {
        return ['k' => 'q', 'q' => ['n' => $n, 'u' => $u]];
    }

    private static function lit(mixed $v): array
    {
        return ['k' => 'lit', 'v' => $v];
    }

    private static function cmp(string $op, array $l, array $r): array
    {
        return ['k' => 'cmp', 'op' => $op, 'l' => $l, 'r' => $r];
    }

    /** The decision when the only grant carries condition $c (so d is the condition's truth), with params $p. */
    private static function grantCond(array $c, array $p = [], array $aggs = []): int
    {
        [$g, $ont, $a, $h] = self::base();
        $g['grants'][0]['cond'] = $c;
        $a['params'] = (object)$p;
        $h['aggs'] = (object)$aggs;
        return self::runRefsem($g, $ont, $a, $h)[0];
    }

    /** The decision when $c is the only escalateOn condition beside an allowing grant: 2 when $c is false, 1 otherwise. */
    private static function escalateCond(array $c, array $p = []): int
    {
        [$g, $ont, $a, $h] = self::base();
        $g['escalateOn'] = [$c];
        $a['params'] = (object)$p;
        return self::runRefsem($g, $ont, $a, $h)[0];
    }

    /** A count bound (cap 1, deny) over g1 with the given scope and window and one admitted act $x: 0 when $x is counted, 2 when not. */
    private static function counted(array $scope, array $window, array $x, int $at = 100, array $aOver = []): int
    {
        [$g, $ont, $a, $h] = self::base();
        $g['bounds'] = [['sel' => ['k' => 'gids', 'gids' => ['g1']], 'scope' => $scope, 'window' => $window, 'agg' => 'count', 'cap' => ['n' => 1], 'onExceed' => 'deny']];
        $a['t'] = $at;
        $h['adms'] = [['gid' => 'g1', 'act' => $x + ['verb' => 'v', 'sess' => 's1', 'agent' => 'ag2', 't' => 50]]];
        return self::runRefsem($g, $ont, $aOver + $a, $h)[0];
    }

    /** A sum / max / distinct bound over g1 whose admitted acts carry the amounts $adm and the candidate $own. */
    private static function aggBound(string $agg, mixed $cap, array $adm, array $own, ?string $key = null): int
    {
        [$g, $ont, $a, $h] = self::base();
        $b = ['sel' => ['k' => 'gids', 'gids' => ['g1']], 'scope' => ['k' => 'session'], 'window' => ['k' => 'lifetime'], 'agg' => $agg, 'cap' => ['n' => $cap, 'u' => 'usd'],
            'onExceed' => 'deny', 'value' => ['k' => 'param', 'path' => 'amt']];
        if ($key !== null) {
            $b['key'] = $key;
        }
        $g['bounds'] = [$b];
        $a['params'] = (object)$own;
        $h['adms'] = array_map(fn($p) => ['gid' => 'g1', 'act' => ['verb' => 'v', 'sess' => 's1', 't' => 50, 'params' => (object)$p]], $adm);
        return self::runRefsem($g, $ont, $a, $h)[0];
    }

    /** With no restriction the grant allows (witness g1) and the prohibition meet is 2; with no grant at all the decision is deny. */
    public function testBaselineAndNoGrant(): void
    {
        [$g, $ont, $a, $h] = self::base();
        self::assertSame([2, 'g1', 2], self::runRefsem($g, $ont, $a, $h));
        $g['grants'] = [];
        self::assertSame([0, null, 2], self::runRefsem($g, $ont, $a, $h));
    }

    /** An absent unit is not the same unit as a null one: the comparison is unknown. */
    public function testAbsentUnitIsNotNullUnit(): void
    {
        self::assertSame(1, self::grantCond(self::cmp('eq', ['k' => 'param', 'path' => 'amt'], self::lit(self::q(5, null))), ['amt' => ['k' => 'q', 'q' => ['n' => 5]]]));
    }

    /** An aggregate reads as a quantity {k: q}; different units compare unknown. */
    public function testAggregateAndUnits(): void
    {
        self::assertSame(2, self::grantCond(self::cmp('eq', ['k' => 'agg', 'bid' => 'b1'], self::lit(self::q(5))), [], ['b1' => ['n' => 5, 'u' => 'usd']]));
        self::assertSame(1, self::grantCond(self::cmp('eq', ['k' => 'param', 'path' => 'amt'], self::lit(self::q(5, 'eur'))), ['amt' => self::q(5)]));
    }

    /** Each comparison operator gives its exact truth value. */
    public function testEveryOperator(): void
    {
        $p = ['k' => 'param', 'path' => 'x'];
        $cases = [['eq', 3, 5, 0], ['eq', 5, 5, 2], ['ne', 3, 5, 2], ['ne', 5, 5, 0], ['lt', 3, 5, 2], ['lt', 5, 3, 0], ['gte', 3, 5, 0], ['gte', 5, 3, 2],
            ['gt', 5, 3, 2], ['gt', 3, 5, 0], ['lte', 3, 5, 2], ['lte', 5, 3, 0]];
        foreach ($cases as [$op, $x, $y, $want]) {
            self::assertSame($want, self::grantCond(self::cmp($op, $p, self::lit(self::q($y))), ['x' => self::q($x)]), "$op $x $y");
        }
        $sa = ['k' => 's', 's' => 'a'];
        $set = fn(string $s) => self::lit(['k' => 'set', 'items' => [['k' => 's', 's' => $s]]]);
        self::assertSame(2, self::grantCond(self::cmp('in', $p, $set('a')), ['x' => $sa]));
        self::assertSame(0, self::grantCond(self::cmp('in', $p, $set('b')), ['x' => $sa]));
        self::assertSame(0, self::grantCond(self::cmp('notin', $p, $set('a')), ['x' => $sa]));
        self::assertSame(2, self::grantCond(self::cmp('notin', $p, $set('b')), ['x' => $sa]));
        self::assertSame(1, self::grantCond(self::cmp('in', $p, self::lit(self::q(5))), ['x' => self::q(5)]), 'in a non-set is unknown');
    }

    /** False conditions never escalate: an empty-set membership, a negated true, a notin of a member. */
    public function testFalseConditionsDoNotEscalate(): void
    {
        $p = ['k' => 'param', 'path' => 'x'];
        $sa = ['k' => 's', 's' => 'a'];
        self::assertSame(2, self::escalateCond(self::cmp('in', $p, self::lit(['k' => 'set', 'items' => []])), ['x' => $sa]));
        self::assertSame(2, self::escalateCond(['k' => 'not', 'c' => ['k' => 'true']]));
        self::assertSame(2, self::escalateCond(self::cmp('notin', $p, self::lit(['k' => 'set', 'items' => [$sa]])), ['x' => $sa]));
        self::assertSame(1, self::escalateCond(['k' => 'true']), 'control');
    }

    /** An unknown condition kind is refused. */
    public function testUnknownConditionThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('unknown condition');
        self::grantCond(['k' => 'weird']);
    }

    /** related takes the members of the FIRST entry matching both rel and anchor; an entry without members has none; an unknown kind never matches. */
    public function testResources(): void
    {
        [$g, $ont, $a, $h] = self::base();
        $g['grants'][0]['res'] = ['k' => 'related', 'rel' => 'owns', 'anchor' => 'A'];
        $ont['rels'] = [['rel' => 'owns', 'anchor' => 'X', 'members' => ['r9']], ['rel' => 'owns', 'anchor' => 'A', 'members' => ['r1']], ['rel' => 'owns', 'anchor' => 'A', 'members' => ['r9']]];
        self::assertSame([2, 'g1', 2], self::runRefsem($g, $ont, $a, $h));
        $ont['rels'] = [['rel' => 'owns', 'anchor' => 'A']];
        self::assertSame([0, null, 2], self::runRefsem($g, $ont, $a, $h));
        $g['grants'][0]['res'] = ['k' => 'weird'];
        self::assertSame([0, null, 2], self::runRefsem($g, $ont, $a, $h));
    }

    /** A class prohibition covers every verb of the class, not only the first. */
    public function testClassProhibitionCoversEveryVerb(): void
    {
        [$g, $ont, $a, $h] = self::base();
        $ont['verbs'] = [['verb' => 'v0', 'cls' => 'pay'], ['verb' => 'v', 'cls' => 'pay']];
        $g['prohibits'] = [['target' => ['k' => 'cls', 'cls' => 'pay'], 'res' => ['k' => 'any'], 'cond' => ['k' => 'true']]];
        self::assertSame([0, null, 0], self::runRefsem($g, $ont, $a, $h));
    }

    /** A fleet scope counts an act only when both agents are in the fleet; an unknown scope counts nothing. */
    public function testScopes(): void
    {
        $fleet = ['k' => 'fleet', 'agents' => ['ag1', 'ag2']];
        $life = ['k' => 'lifetime'];
        self::assertSame(0, self::counted($fleet, $life, ['agent' => 'ag2']));
        self::assertSame(2, self::counted($fleet, $life, ['agent' => 'ag3']));
        self::assertSame(2, self::counted(['k' => 'weird'], $life, []));
        self::assertSame(0, self::counted(['k' => 'session'], $life, []), 'control');
    }

    /** Windows: task and lifetime count everything; sliding is (t - ms, t]; period buckets by floor((t - t0) / ms) and needs ms > 0; unknown counts nothing. */
    public function testWindows(): void
    {
        $s = ['k' => 'session'];
        self::assertSame(0, self::counted($s, ['k' => 'task'], []));
        self::assertSame(0, self::counted($s, ['k' => 'lifetime'], []));
        self::assertSame(2, self::counted($s, ['k' => 'weird'], []));
        $sl = ['k' => 'sliding', 'ms' => 100];
        self::assertSame(0, self::counted($s, $sl, ['t' => 200], 200));
        self::assertSame(0, self::counted($s, $sl, ['t' => 150], 200));
        self::assertSame(2, self::counted($s, $sl, ['t' => 100], 200));
        self::assertSame(0, self::counted($s, ['k' => 'period', 'ms' => 100, 't0' => 0], ['t' => 0], 60));
        self::assertSame(2, self::counted($s, ['k' => 'period', 'ms' => 0, 't0' => 0], ['t' => 10], 60));
        self::assertSame(0, self::counted($s, ['k' => 'period', 'ms' => 1, 't0' => 0], ['t' => 60], 60));
        self::assertSame(0, self::counted($s, ['k' => 'period', 'ms' => 100, 't0' => 50], ['t' => 60], 120));
        self::assertSame(2, self::counted($s, ['k' => 'period', 'ms' => 100, 't0' => 0], ['t' => 0], 160), 'control');
    }

    /** A sum is the JavaScript + fold from 0: a string concatenates in order ("57", "07"), it never adds. */
    public function testSumIsTheJsFold(): void
    {
        self::assertSame(0, self::aggBound('sum', 56, [['amt' => self::q(5)]], ['amt' => self::q('7')]));
        self::assertSame(2, self::aggBound('sum', 60, [['amt' => self::q(5)]], ['amt' => self::q('7')]));
        self::assertSame(0, self::aggBound('sum', 100, [['amt' => self::q(5)], ['amt' => self::q('7')]], ['amt' => self::q(1)]));
        self::assertSame(0, self::aggBound('sum', 5, [], ['amt' => self::q('7')]));
    }

    /** A max over values with a NaN is NaN, which never exceeds the cap. */
    public function testMaxWithNaNNeverExceeds(): void
    {
        self::assertSame(2, self::aggBound('max', 100, [['amt' => self::q(500)], ['amt' => self::q('abc')]], ['amt' => self::q(500)]));
        self::assertSame(0, self::aggBound('max', 100, [['amt' => self::q(500)]], ['amt' => self::q(500)]), 'control');
    }

    /** A distinct bound whose key the candidate lacks is unknown: the grant escalates. */
    public function testDistinctMissingKeyEscalates(): void
    {
        self::assertSame(1, self::aggBound('distinct', 5, [], ['amt' => self::q(1)], 'cust'));
    }

    /** maxIdle applies from 1 and from last = 0: an idle session is denied (exactly 0). */
    public function testMaxIdle(): void
    {
        [$g, $ont, $a, $h] = self::base();
        $g['validity']['maxIdle'] = 1;
        self::assertSame([0, null, 2], self::runRefsem($g, $ont, $a, $h));
        $g['validity']['maxIdle'] = 10;
        $h['last'] = 0;
        self::assertSame([0, null, 2], self::runRefsem($g, $ont, $a, $h));
        $g['validity']['maxIdle'] = 100;
        $h['last'] = 50;
        self::assertSame([2, 'g1', 2], self::runRefsem($g, $ont, $a, $h), 'control');
    }
}
