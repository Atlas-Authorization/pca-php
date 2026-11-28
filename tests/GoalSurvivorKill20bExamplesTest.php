<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalExamples.php';

use Atlas\Pca\GoalDigests;
use Atlas\Pca\GoalExamples as E;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Boundary examples: the decision space, cell enumeration (complete and capped grids), Allow witnesses, cap sequences, and the signed test/pin checks. */
final class GoalSurvivorKill20bExamplesTest extends TestCase
{
    private const OTHER_RES = "\0other-resource";

    private static function refusal(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'accepted';
    }

    private static function j(mixed $x): string
    {
        return Js::stringify($x);
    }

    private static function q(string $unit, mixed $n): Obj
    {
        return Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => $unit]), 'n' => $n])]);
    }

    private static function lit(Obj $v): Obj
    {
        return Obj::of(['k' => 'lit', 'v' => $v]);
    }

    private static function par(string $p): Obj
    {
        return Obj::of(['k' => 'param', 'path' => $p]);
    }

    private static function cmp(string $op, Obj $l, Obj $r): Obj
    {
        return Obj::of(['k' => 'cmp', 'op' => $op, 'l' => $l, 'r' => $r]);
    }

    private static function s(string $x): Obj
    {
        return Obj::of(['k' => 's', 's' => $x]);
    }

    /** @param list<string> $xs */
    private static function inSet(string $p, array $xs): Obj
    {
        return self::cmp('in', self::par($p), self::lit(Obj::of(['k' => 'set', 'items' => array_map(self::s(...), $xs)])));
    }

    private static function all(Obj ...$cs): Obj
    {
        $c = array_pop($cs);
        while ($cs !== []) {
            $c = Obj::of(['k' => 'and', 'a' => array_pop($cs), 'b' => $c]);
        }
        return $c;
    }

    private static function yes(): Obj
    {
        return Obj::of(['k' => 'true']);
    }

    private static function anyRes(): Obj
    {
        return Obj::of(['k' => 'any']);
    }

    private static function grant(mixed $gid, string $verb, Obj $cond, ?Obj $res = null): Obj
    {
        return Obj::of(['gid' => $gid, 'verb' => $verb, 'res' => $res ?? self::anyRes(), 'cond' => $cond]);
    }

    private static function bound(string $bid, array $gids, string $agg, Obj $cap, ?Obj $value = null): Obj
    {
        $b = Obj::of(['bid' => $bid, 'sel' => Obj::of(['k' => 'gids', 'gids' => $gids]), 'agg' => $agg]);
        if ($value !== null) {
            $b->set('value', $value);
        }
        foreach (['key' => 'k1', 'window' => Obj::of(['k' => 'lifetime']), 'scope' => Obj::of(['k' => 'session']), 'cap' => $cap, 'onExceed' => 'deny'] as $k => $v) {
            $b->set($k, $v);
        }
        return $b;
    }

    private static function cap(string $unit, mixed $n): Obj
    {
        return Obj::of(['u' => Obj::of(['k' => $unit]), 'n' => $n]);
    }

    private static function goal(array $grants, array $prohibits = [], array $bounds = []): Obj
    {
        return Obj::of(['v' => 1, 'grants' => $grants, 'prohibits' => $prohibits, 'bounds' => $bounds, 'escalateOn' => [],
            'validity' => Obj::of(['notBefore' => 0, 'notAfter' => 4102444800000, 'maxIdle' => 0]),
            'deleg' => Obj::of(['maxDepth' => 0, 'narrowOnly' => true, 'mayTouch' => []]), 'holes' => [], 'wildcardAck' => []]);
    }

    private static function ont(): Obj
    {
        return Obj::of(['rels' => [], 'verbs' => []]);
    }

    private static function space(array $grants, array $prohibits = []): Obj
    {
        return E::buildSpace([self::goal($grants, $prohibits)]);
    }

    /** @return list<string> the number texts of a space's quantity literals for one parameter and unit */
    private static function nums(Obj $sp, string $p, string $unit = 'count'): array
    {
        return array_map(static fn(Num $n) => $n->lexeme, $sp->get('q')->get($p)->get($unit));
    }

    public function testSmallHelpers(): void
    {
        self::assertSame('{"adms":[],"last":-1,"aggs":{}}', self::j(E::emptyHist()));
        self::assertSame(['allow', 'escalate', 'deny', 'allow'], [E::decisionOf(2), E::decisionOf(1), E::decisionOf(0), E::decisionOf(new Num('2'))]);
        self::assertSame([0, 1, 2, 2], [E::rankOf('allow'), E::rankOf('escalate'), E::rankOf('deny'), E::rankOf('x')]);
    }

    /** An override object or an associative array replaces envelope members (numeric keys become strings); a list is ignored. */
    public function testActionOverrides(): void
    {
        $env = ['verb', 'res', 'params', 't', 'sess', 'prin', 'org', 'agent', 'depth'];
        $a = E::mkAct('v', 'r', null, Obj::of(['t' => new Num('5'), 'zz' => 'q']));
        self::assertSame([...$env, 'zz'], $a->keys());
        self::assertSame(['5', 'q'], [self::j($a->get('t')), $a->get('zz')]);
        $b = E::mkAct('v', 'r', null, ['sess' => 's2', '7' => 'x']);
        self::assertSame([...$env, '7'], $b->keys());
        self::assertSame(['s2', 'x'], [$b->get('sess'), $b->get('7')]);
        self::assertSame($env, E::mkAct('v', 'r', null, ['a', 'b'])->keys());
        self::assertSame('{"verb":"v","res":"r","params":{},"t":0,"sess":"s","prin":"p","org":"o","agent":"a","depth":0}', self::j(E::mkAct('v', 'r')));
    }

    /** A refused action is skipped (later ones still count); an Allow without a grant id is not recorded either. */
    public function testReplay(): void
    {
        $g = self::goal([self::grant('g1', 'r', self::yes())]);
        $h = E::replay($g, self::ont(), [E::mkAct('w', 'x'), E::mkAct('r', 'x', null, Obj::of(['t' => new Num('7')]))], []);
        self::assertSame(['g1'], array_map(static fn(Obj $x) => $x->get('gid'), $h->get('adms')));
        self::assertSame('7', self::j($h->get('last')));
        $g0 = self::goal([self::grant(null, 'r', self::yes())]);
        self::assertSame('allow', E::decideCase($g0, self::ont(), Obj::of(['act' => E::mkAct('r', 'x')]))->get('decision'));
        self::assertSame('{"adms":[],"last":-1,"aggs":{}}', self::j(E::replay($g0, self::ont(), [E::mkAct('r', 'x')], [])));
    }

    /** Literals on either side of a comparison, in prohibitions too; comparisons without a parameter-literal pair add nothing. */
    public function testSpaceLiterals(): void
    {
        $sp = self::space([self::grant('g', 'v', self::cmp('lte', self::lit(self::q('count', 3)), self::par('x')))],
            [Obj::of(['pid' => 'p', 'target' => Obj::of(['k' => 'verb', 'verb' => 'z']), 'res' => self::anyRes(), 'cond' => self::cmp('lte', self::par('pz'), self::lit(self::q('count', 7)))])]);
        self::assertSame(['3'], self::nums($sp, 'x'));
        self::assertSame(['7'], self::nums($sp, 'pz'));
        self::assertInstanceOf(Num::class, $sp->get('q')->get('x')->get('count')[0]);
        $none = self::space([self::grant('g', 'v', self::all(self::cmp('eq', self::lit(self::s('a')), self::lit(self::s('b'))), self::cmp('eq', self::par('x'), self::par('y'))))]);
        self::assertSame(['{}', '{}'], [self::j($none->get('q')), self::j($none->get('d'))]);
        self::assertSame("TypeError: a quantity literal must be a number",
            self::refusal(fn() => self::space([self::grant('g', 'v', self::cmp('lte', self::par('x'), self::lit(self::q('count', 'oops'))))])));
        $z = self::space([self::grant('g', 'v', self::all(self::cmp('lte', self::par('x'), self::lit(self::q('count', 0.0))), self::cmp('gte', self::par('x'), self::lit(self::q('count', -0.0)))))]);
        self::assertSame(['0'], self::nums($z, 'x'), '0 and -0 are one literal');
    }

    /** @return list<string> rel/anchor of a space's relations, in order */
    private static function rels(array $pairs): array
    {
        $parts = array_map(static fn(array $p) => Obj::of(['k' => 'related', 'rel' => $p[0], 'anchor' => $p[1]]), $pairs);
        $sp = self::space([self::grant('g', 'v', self::yes(), Obj::of(['k' => 'all_of', 'parts' => $parts]))]);
        return array_map(static fn(Obj $x) => $x->get('rel') . '/' . $x->get('anchor'), $sp->get('rels'));
    }

    /** Relations are de-duplicated by the (rel, anchor) pair and ordered by rel then anchor text. */
    public function testSpaceRelations(): void
    {
        self::assertSame(['ab/c', 'a/bc'], self::rels([['ab', 'c'], ['a', 'bc']]));
        self::assertSame(['r1/x', 'r2/x'], self::rels([['r1', 'x'], ['r2', 'x']]));
        self::assertSame(['r1/x', 'r1/y'], self::rels([['r1', 'x'], ['r1', 'y']]));
        self::assertSame(['a/z', 'b/a'], self::rels([['b', 'a'], ['a', 'z']]));
        self::assertSame(['a/b', 'a/c'], self::rels([['a', 'b'], ['a', 'c']]));
        self::assertSame(['a/b', 'a/z'], self::rels([['a', 'z'], ['a', 'b']]));
    }

    /** @return array<string,string> the per-parameter classes of a case's cell */
    private static function cellOf(Obj $sp, Obj $act, array $rels = []): array
    {
        return json_decode(E::cellKey($sp, Obj::of(['act' => $act, 'rels' => $rels])), true);
    }

    /** A literal in an unknown unit is "unit" when the parameter has other literals; a string literal against numbers only is "unit". */
    public function testCellClasses(): void
    {
        $sp = self::space([self::grant('g', 'v', self::all(self::cmp('lte', self::par('x'), self::lit(self::q('count', 5))),
            self::cmp('eq', self::par('y'), self::lit(self::s('a'))), self::cmp('lte', self::par('z'), self::lit(self::q('count', 5))), self::cmp('eq', self::par('z'), self::lit(self::s('a')))))]);
        $money = Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => 'money', 'ccy' => 'USD']), 'n' => 1])]);
        $act = E::mkAct('v', 'r', Obj::of(['x' => self::s('a'), 'y' => self::q('count', 1), 'z' => $money]));
        self::assertSame(['x' => 'unit', 'y' => 'unit', 'z' => 'unit'], self::cellOf($sp, $act)['p']);
        self::assertSame('TypeError: a quantity literal must be a number',
            self::refusal(fn() => self::cellOf($sp, E::mkAct('v', 'r', Obj::of(['x' => self::q('count', 'oops')])))));
        $bare = Obj::of(['act' => Obj::of(['verb' => 'v', 'res' => 'r', 'params' => null]), 'rels' => []]);
        self::assertSame(['x' => 'missing', 'y' => 'missing', 'z' => 'missing'], json_decode(E::cellKey($sp, $bare), true)['p']);
    }

    /** A relation bit reads the fact for that exact (rel, anchor) pair, not one sharing only the anchor. */
    public function testRelationBit(): void
    {
        $parts = [Obj::of(['k' => 'related', 'rel' => 'r1', 'anchor' => 'a']), Obj::of(['k' => 'related', 'rel' => 'r2', 'anchor' => 'a'])];
        $sp = self::space([self::grant('g', 'v', self::yes(), Obj::of(['k' => 'all_of', 'parts' => $parts]))]);
        $facts = [Obj::of(['rel' => 'r2', 'anchor' => 'a', 'members' => ['R']]), Obj::of(['rel' => 'r1', 'anchor' => 'a', 'members' => []])];
        self::assertSame([0, 1], self::cellOf($sp, E::mkAct('v', 'R'), $facts)['l']);
    }

    private static function sig(Obj $c): string
    {
        $act = $c->get('act');
        $bits = implode('', array_map(static fn(Obj $r) => $r->get('members') === [] ? '0' : '1', $c->get('rels')));
        $ps = [];
        foreach ($act->get('params')->keys() as $k) {
            $v = $act->get('params')->get($k);
            $ps[] = $k . '=' . ($v->get('k') === 's' ? ($v->get('s') === E::OTHER ? 'OTHER' : $v->get('s')) : self::j($v->get('q')->get('n')));
        }
        return ($act->get('res') === self::OTHER_RES ? 'other' : $act->get('res')) . '|' . $bits . '|' . implode(',', $ps);
    }

    /**
     * Over MAX_CELLS the grid is a subset: the base choice (each parameter's third option, or its last), every resource and relation
     * pattern at the base, then one parameter varied at a time. Count literals never go negative; instants do.
     */
    public function testCappedGrid(): void
    {
        $d = array_map(static fn($i) => "d$i", range(0, 9));
        $e = array_map(static fn($i) => "e$i", range(0, 9));
        $res = Obj::of(['k' => 'all_of', 'parts' => [Obj::of(['k' => 'exact', 'id' => 'r1']), Obj::of(['k' => 'related', 'rel' => 'ra', 'anchor' => 'x']),
            Obj::of(['k' => 'related', 'rel' => 'rb', 'anchor' => 'x'])]]);
        $sp = self::space([self::grant('g', 'v', self::all(self::inSet('a', ['x1', 'x2', 'x3']), self::cmp('lte', self::par('b'), self::lit(self::q('count', -1))),
            self::cmp('lte', self::par('c'), self::lit(self::q('count', -5))), self::inSet('d', $d), self::inSet('e', $e),
            self::cmp('gte', self::par('f'), self::lit(self::q('instant', 0)))), $res)]);
        $cells = E::cells($sp, Obj::of(['verbs' => ['v']]));
        self::assertFalse($cells->get('complete'));
        $base = ['a' => 'x2', 'b' => '0', 'c' => null, 'd' => 'd1', 'e' => 'e1', 'f' => '0'];
        $p = static function (array $over) use ($base): string {
            $out = [];
            foreach (array_merge($base, $over) as $k => $v) {
                if ($v !== null) {
                    $out[] = "$k=$v";
                }
            }
            return implode(',', $out);
        };
        $want = ['r1|00|' . $p([])];
        foreach (['r1', 'other'] as $r) {
            foreach (['00', '10', '01', '11'] as $bits) {
                if ("$r|$bits" !== 'r1|00') {
                    $want[] = "$r|$bits|" . $p([]);
                }
            }
        }
        $vary = ['a' => [null, 'x1', 'x3', 'OTHER'], 'b' => [null], 'd' => [null, 'd0', ...array_slice($d, 2), 'OTHER'], 'e' => [null, 'e0', ...array_slice($e, 2), 'OTHER'], 'f' => [null, '-1', '1']];
        foreach ($vary as $k => $vs) {
            foreach ($vs as $v) {
                $want[] = 'r1|00|' . $p([$k => $v]);
            }
        }
        self::assertSame($want, array_map(self::sig(...), $cells->get('cases')));
    }

    /** 2^10 relation patterns fit the grid (complete); a parameter in both a quantity and a string comparison counts its options once. */
    public function testCompleteGridSizes(): void
    {
        $parts = array_map(static fn($i) => Obj::of(['k' => 'related', 'rel' => "r$i", 'anchor' => 'x']), range(0, 9));
        $c = E::cells(self::space([self::grant('g', 'v', self::yes(), Obj::of(['k' => 'all_of', 'parts' => $parts]))]), Obj::of(['verbs' => ['v']]));
        self::assertTrue($c->get('complete'));
        self::assertCount(1024, $c->get('cases'));
        $strs = array_map(static fn($i) => sprintf('s%03d', $i), range(0, 149));
        $c2 = E::cells(self::space([self::grant('g', 'v', self::all(self::cmp('lte', self::par('p'), self::lit(self::q('count', 5))), self::inSet('p', $strs)))]));
        self::assertTrue($c2->get('complete'));
        self::assertCount(310, $c2->get('cases'));
    }

    /** Exactly MAX_CELLS (1600 verbs x 5 x 5 options, overlapping literals de-duplicated) is still a complete grid. */
    public function testGridAtTheCellLimit(): void
    {
        $sp = self::space([self::grant('g', 'v', self::all(self::cmp('lte', self::par('p1'), self::lit(self::q('count', 1))), self::cmp('lte', self::par('p1'), self::lit(self::q('count', 2))),
            self::cmp('lte', self::par('p2'), self::lit(self::q('count', 1))), self::cmp('lte', self::par('p2'), self::lit(self::q('count', 2)))))]);
        $c = E::cells($sp, Obj::of(['verbs' => array_map(static fn($i) => sprintf('w%04d', $i), range(0, 1599))]));
        self::assertTrue($c->get('complete'));
        self::assertCount(25, $c->get('cases'));
    }

    /** The minimal witness minimises the summed |amount| over all quantity parameters, across the whole grid of the grant's own verb. */
    public function testAllowWitnessIsMinimal(): void
    {
        $prohibits = array_map(static fn($i) => Obj::of(['pid' => "p$i", 'target' => Obj::of(['k' => 'verb', 'verb' => sprintf('p%03d', $i)]), 'res' => self::anyRes(), 'cond' => self::yes()]), range(0, 136));
        $g1 = self::grant('g1', 'v', self::all(self::cmp('gte', self::par('a'), self::lit(self::q('instant', -1))), self::cmp('lte', self::par('b'), self::lit(self::q('count', 10)))));
        $g = self::goal([$g1, self::grant('g2', 'w', self::inSet('e', array_map(static fn($i) => sprintf('e%02d', $i), range(0, 16))))], $prohibits);
        $w = E::allowWitness($g, $g1, self::ont());
        self::assertSame(['v', self::OTHER_RES], [$w->get('act')->get('verb'), $w->get('act')->get('res')]);
        self::assertSame('{"a":{"k":"q","q":{"u":{"k":"instant"},"n":0}},"b":{"k":"q","q":{"u":{"k":"count"},"n":9}}}', self::j($w->get('act')->get('params')));
    }

    /** On a capped grid the base case wins a tie: string parameters add nothing to the magnitude. */
    public function testAllowWitnessIgnoresStringParameters(): void
    {
        $c = array_map(static fn($i) => sprintf('c%03d', $i), range(0, 119));
        $d = array_map(static fn($i) => sprintf('d%03d', $i), range(0, 119));
        $g1 = self::grant('g1', 'v', self::cmp('gte', self::par('b'), self::lit(self::q('instant', 0))));
        $g = self::goal([$g1, self::grant('g2', 'w', self::all(self::cmp('eq', self::par('a'), self::lit(self::s('x'))), self::inSet('c', $c), self::inSet('d', $d)))]);
        $p = E::allowWitness($g, $g1, self::ont())->get('act')->get('params');
        self::assertSame(['a', 'b', 'c', 'd'], $p->keys());
        self::assertSame([E::OTHER, '0', 'c001', 'd001'], [$p->get('a')->get('s'), self::j($p->get('b')->get('q')->get('n')), $p->get('c')->get('s'), $p->get('d')->get('s')]);
    }

    /** @return array{0:list<array{0:string,1:int,2:string,3:string}>,1:int} the cap sequences [why, history length, decision, verb] and the number of Allow witnesses */
    private static function capSeq(Obj $g): array
    {
        $out = [];
        $witnesses = 0;
        foreach (E::boundaryExamples($g, Obj::of(['ont' => self::ont()]))->get('examples') as $e) {
            if ($e->get('kind') === 'cap_sequence') {
                $out[] = [$e->get('why'), count($e->get('hist')->get('adms')), $e->get('decision'), $e->get('act')->get('verb')];
            }
            $witnesses += $e->get('kind') === 'allow_witness' ? 1 : 0;
        }
        return [$out, $witnesses];
    }

    /** Bounds without a witness grant, sum bounds without a positive amount and over-long sequences are skipped; later bounds still count. */
    public function testCapSequencesSkip(): void
    {
        $g = self::goal([self::grant('g1', 'v', self::yes()), self::grant('g2', 'w', self::yes())], [], [
            self::bound('b0', ['nope'], 'count', self::cap('count', 1)),
            self::bound('b1', ['g1'], 'sum', self::cap('count', 5), self::lit(self::q('count', 1))),
            self::bound('b2', ['g1'], 'count', self::cap('count', 100)),
            self::bound('b3', ['g1', 'g2'], 'count', self::cap('count', 2)),
        ]);
        self::assertSame([[['reach the b3 cap with 2 action(s), then one more', 2, 'deny', 'v']], 2], self::capSeq($g));
        $g60 = self::goal([self::grant('g1', 'v', self::yes())], [], [self::bound('c60', ['g1'], 'count', self::cap('count', 60))]);
        self::assertSame([[['reach the c60 cap with 60 action(s), then one more', 60, 'deny', 'v']], 1], self::capSeq($g60));
    }

    /** The sequence length is floor(cap / per-action amount) with JavaScript division; a missing cap counts as 0. */
    public function testCapSequenceLengths(): void
    {
        $t = self::yes();
        $one = static fn(Obj $b, ?Obj $cond = null) => self::capSeq(self::goal([self::grant('g1', 'v', $cond ?? $t)], [], [$b]));
        $zero = self::lit(self::q('count', 0));
        self::assertSame([[['reach the m cap with NaN action(s), then one more', 0, 'allow', 'v']], 1], $one(self::bound('m', ['g1'], 'max', self::cap('count', 0), $zero)), '0 / 0');
        self::assertSame([[], 1], $one(self::bound('m', ['g1'], 'max', self::cap('count', 5), $zero)), '5 / 0 is too long');
        $neg = self::cmp('lt', self::par('b'), self::lit(self::q('instant', 0)));
        self::assertSame([[['reach the m cap with -5 action(s), then one more', 0, 'allow', 'v']], 1],
            $one(self::bound('m', ['g1'], 'max', self::cap('instant', 5), self::par('b')), $neg), 'a negative length replays nothing');
        self::assertSame([[], 1], $one(self::bound('s', ['g1'], 'sum', self::cap('instant', 5), self::par('b')), $neg), 'sum with a negative amount');
        self::assertSame([[], 1], $one(self::bound('s', ['g1'], 'sum', self::cap('count', 0), self::par('b'))), 'sum with a zero amount');
        self::assertSame([[], 1], $one(self::bound5(), self::cmp('eq', self::par('k1'), self::lit(self::s('a')))), 'distinct over a non-string path');
        self::assertSame([[['reach the c cap with 0 action(s), then one more', 0, 'allow', 'v']], 1],
            $one(self::bound('c', ['g1'], 'count', Obj::of(['u' => Obj::of(['k' => 'count'])]))), 'a cap without n');
        self::assertSame([[['reach the s cap with 2 action(s), then one more', 2, 'deny', 'v']], 1],
            $one(self::bound('s', ['g1'], 'sum', self::cap('count', 5), self::par('amt')), self::cmp('gte', self::par('amt'), self::lit(self::q('count', 2)))), '5 / 2 floors');
    }

    /** A distinct bound whose value path is the number 5 (never a parameter name). */
    private static function bound5(): Obj
    {
        $b = self::bound('k', ['g1'], 'distinct', self::cap('count', 3));
        $b->set('value', Obj::of(['k' => 'param', 'path' => 5]));
        return $b;
    }

    /** Probes come from every grant with a witness, even after one without. */
    public function testProbesSkipGrantsWithoutWitness(): void
    {
        $g = self::goal([self::grant('g0', 'v', self::cmp('lt', self::par('p'), self::lit(self::q('count', 0)))), self::grant('g1', 'w', self::yes(), Obj::of(['k' => 'exact', 'id' => 'r1']))]);
        $whys = [];
        foreach (E::boundaryExamples($g, Obj::of(['ont' => self::ont()]))->get('examples') as $e) {
            if ($e->get('kind') === 'probe') {
                $whys[] = $e->get('why') . ' ' . $e->get('act')->get('verb') . ' ' . ($e->get('act')->get('res') === self::OTHER_RES ? 'other' : $e->get('act')->get('res'));
            }
        }
        self::assertSame(['other resource w other', 'other customer/anchor w r1'], $whys);
    }

    public function testReviewCapMustBeANonNegativeNumber(): void
    {
        $bad = 'InvalidArgumentException: a review cap is a non-negative number';
        self::assertSame([$bad, $bad], [self::refusal(fn() => E::reviewSet([], -1)), self::refusal(fn() => E::reviewSet([], 'x'))]);
        self::assertSame([], E::reviewSet([], 0));
    }

    public function testSignedChecksReportTheirReason(): void
    {
        $kp = new KeyPair(hash('sha256', 'group20b-examples', true));
        $s = E::signGoalTests(Obj::of(['goal_digest' => 'g', 'ontology_digest' => 'o', 'tests' => [], 'tests_digest' => 'bad']), $kp);
        self::assertSame('{"ok":false,"reason":"tests_digest","failures":[]}', self::j(E::checkGoalTests($s, [$kp->public], static fn($t) => 'allow')));
        $ok = E::signGoalTests(Obj::of(['goal_digest' => 'g', 'ontology_digest' => 'o', 'tests' => [], 'tests_digest' => E::testsDigest([])]), $kp);
        self::assertSame('{"ok":true,"failures":[]}', self::j(E::checkGoalTests($ok, [$kp->public], static fn($t) => 'allow')), 'control');
        $goal = Obj::of(['ontDigest' => 'o2']);
        $td = E::testsDigest([]);
        $pin = E::signPin(Obj::of(['goal_digest' => GoalDigests::goalDigest($goal), 'policy_digest' => 'pd', 'tests_digest' => $td, 'ontology_digest' => 'o1']), $kp);
        $cur = Obj::of(['goal' => $goal, 'policy_digest' => 'pd', 'tests' => Obj::of(['tests' => [], 'tests_digest' => $td])]);
        self::assertSame('{"ok":false,"reason":"ontology changed under the pin"}', self::j(E::checkPin($pin, [$kp->public], $cur)));
        $goal->set('ontDigest', 'o1');
        $pin = E::signPin(Obj::of(['goal_digest' => GoalDigests::goalDigest($goal), 'policy_digest' => 'pd', 'tests_digest' => $td, 'ontology_digest' => 'o1']), $kp);
        self::assertSame('{"ok":true}', self::j(E::checkPin($pin, [$kp->public], $cur)), 'control');
    }
}
