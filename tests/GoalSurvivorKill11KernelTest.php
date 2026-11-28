<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalKernel.php';

use Atlas\Pca\GoalKernel as K;
use Atlas\Pca\GoalKernelReader as R;
use PHPUnit\Framework\TestCase;

/**
 * The goal kernel over token tapes: every decoder/encoder arm round-trips, malformed tapes stay malformed, the Kleene
 * comparisons, windows, validity and bounds decide exactly, the typing reasons name each ill-typed part, and the compiled
 * policy, its decision and its witness check hold.
 */
final class GoalSurvivorKill11KernelTest extends TestCase
{
    // ---- token builders
    private static function k(int $n): array
    {
        return ['k', $n];
    }

    private static function i(int $n): array
    {
        return ['i', $n];
    }

    private static function s(string $x): array
    {
        return ['s', $x];
    }

    private static function strs(array $xs): array
    {
        $o = [self::i(count($xs))];
        foreach ($xs as $x) {
            $o[] = self::s($x);
        }
        return $o;
    }

    private static function lst(array $items): array
    {
        $o = [self::i(count($items))];
        foreach ($items as $t) {
            array_push($o, ...$t);
        }
        return $o;
    }

    private static function money(string $c): array
    {
        return [self::k(300), self::s($c)];
    }

    private static function cnt(): array
    {
        return [self::k(301)];
    }

    private static function q(array $u, int $n): array
    {
        return [...$u, self::i($n)];
    }

    private static function tyq(array $u): array
    {
        return [self::k(310), ...$u];
    }

    private static function tys(): array
    {
        return [self::k(311)];
    }

    private static function aq(array $q): array
    {
        return [self::k(320), ...$q];
    }

    private static function atomS(string $x): array
    {
        return [self::k(321), self::s($x)];
    }

    private static function vq(array $q): array
    {
        return [self::k(330), ...$q];
    }

    private static function vs(string $x): array
    {
        return [self::k(331), self::s($x)];
    }

    private static function vset(array $atoms): array
    {
        return [self::k(332), ...self::lst($atoms)];
    }

    private static function param(string $p, array $ty): array
    {
        return [self::k(340), self::s($p), ...$ty];
    }

    private static function lit(array $v): array
    {
        return [self::k(341), ...$v];
    }

    private static function hagg(string $n, array $u): array
    {
        return [self::k(342), self::s($n), ...$u];
    }

    private static function qc(int $n): array
    {
        return self::lit(self::vq(self::q(self::cnt(), $n)));
    }

    private static function sa(string $x): array
    {
        return self::lit(self::vs($x));
    }

    private static function op(string $o): array
    {
        return [self::k(350 + array_search($o, K::OPS_BY_KW, true))];
    }

    private static function ctrue(): array
    {
        return [self::k(360)];
    }

    private static function cmp(string $o, array $l, array $r): array
    {
        return [self::k(361), ...self::op($o), ...$l, ...$r];
    }

    private static function cand(array $a, array $b): array
    {
        return [self::k(362), ...$a, ...$b];
    }

    private static function cor(array $a, array $b): array
    {
        return [self::k(363), ...$a, ...$b];
    }

    private static function cnot(array $a): array
    {
        return [self::k(364), ...$a];
    }

    private static function exact(string $x): array
    {
        return [self::k(370), self::s($x)];
    }

    private static function oneof(array $xs): array
    {
        return [self::k(371), ...self::strs($xs)];
    }

    private static function related(string $r, string $a): array
    {
        return [self::k(372), self::s($r), self::s($a)];
    }

    private static function anyres(string $x): array
    {
        return [self::k(373), self::s($x)];
    }

    private static function allof(array $parts): array
    {
        return [self::k(374), ...self::lst($parts)];
    }

    private static function pexact(string $x): array
    {
        return [self::k(375), self::s($x)];
    }

    private static function poneof(array $xs): array
    {
        return [self::k(376), ...self::strs($xs)];
    }

    private static function prelated(string $r, string $a): array
    {
        return [self::k(377), self::s($r), self::s($a)];
    }

    private static function grant(string $gid, string $verb, array $res, array $cond): array
    {
        return [self::k(380), self::s($gid), self::s($verb), ...$res, ...$cond];
    }

    private static function pverb(string $v): array
    {
        return [self::k(390), self::s($v)];
    }

    private static function peffect(string $c): array
    {
        return [self::k(391), self::s($c)];
    }

    private static function prohibit(string $pid, array $target, array $res, array $cond): array
    {
        return [self::k(392), self::s($pid), ...$target, ...$res, ...$cond];
    }

    private static function selGids(array $xs): array
    {
        return [self::k(410), ...self::strs($xs)];
    }

    private static function selEffect(string $c): array
    {
        return [self::k(411), self::s($c)];
    }

    /** @param int $agg 400 count, 401 sum, 402 max, 403 distinct */
    private static function core(int $agg, array $value, string $key, array $window, array $scope, array $cap, bool $deny): array
    {
        return [self::k(450), self::k($agg), ...$value, self::s($key), ...$window, ...$scope, ...$cap, self::k($deny ? 440 : 441)];
    }

    private static function bound(string $bid, array $sel, array $core): array
    {
        return [self::k(451), self::s($bid), ...$sel, ...$core];
    }

    private static function hole(string $hid, string $q, array $domain, array $affects, int $global): array
    {
        return [self::k(470), self::s($hid), self::s($q), ...self::strs($domain), ...self::strs($affects), self::i($global)];
    }

    private static function goal(array $grants = [], array $prohibits = [], array $bounds = [], array $escs = [], array $wild = [],
        array $holes = [], array $validity = [-100, 100, 0], int $maxDepth = 2, int $narrow = 1, array $mayTouch = [],
        array $sources = []): array
    {
        return [self::k(480), self::i(1), self::s('p'), self::s('od'), self::s('nd'), ...self::strs($sources),
            ...self::lst($grants), ...self::lst($prohibits), ...self::lst($bounds),
            self::k(460), self::i($validity[0]), self::i($validity[1]), self::i($validity[2]),
            self::k(461), self::i($maxDepth), self::i($narrow), ...self::strs($mayTouch),
            ...self::lst($escs), ...self::strs($wild), ...self::lst($holes)];
    }

    private static function pdecl(string $p, array $ty): array
    {
        return [self::k(500), self::s($p), ...$ty];
    }

    private static function verb(string $v, string $cls, array $params): array
    {
        return [self::k(501), self::s($v), self::s($cls), ...self::lst($params)];
    }

    private static function ont(?array $verbs = null): array
    {
        $verbs ??= [self::verb('v', 'c', [self::pdecl('n', self::tyq(self::cnt())), self::pdecl('s', self::tys())]), self::verb('v2', 'c', [])];
        return [self::k(510), ...self::lst($verbs), ...self::lst([[self::k(502), self::s('owns'), self::s('alice'), ...self::strs(['r1', 'r2'])]])];
    }

    /** @param array<string, list<array>> $params */
    private static function act(int $t = 0, array $params = [], string $verb = 'v', string $res = 'r1', string $sess = 'S'): array
    {
        $ps = [];
        foreach ($params as $key => $val) {
            $ps[] = [self::k(520), self::s($key), ...$val];
        }
        return [self::k(530), self::s($verb), self::s($res), ...self::lst($ps), self::i($t), self::s($sess), self::s('P'), self::s('O'),
            self::s('A'), self::i(0)];
    }

    /** @param list<array{0:string,1:list<array>}> $adms @param array<string, list<array>> $aggs */
    private static function hist(array $adms = [], int $last = -1, array $aggs = []): array
    {
        $as = [];
        foreach ($adms as [$gid, $act]) {
            $as[] = [self::k(531), self::s($gid), ...$act];
        }
        $gs = [];
        foreach ($aggs as $key => $q) {
            $gs[] = [self::k(540), self::s($key), ...$q];
        }
        return [self::k(541), ...self::lst($as), self::i($last), ...self::lst($gs)];
    }

    private static function g1(): array
    {
        return self::grant('g1', 'v', self::exact('r1'), self::ctrue());
    }

    private static function dg(array $goal, ?array $act = null, ?array $hist = null): int
    {
        $out = K::kernelCall('decideg', $goal, self::ont(), $act ?? self::act(), $hist ?? self::hist());
        self::assertSame(['i', 0], $out[0]);
        self::assertCount(2, $out);
        return $out[1][1];
    }

    /** The decision of one grant conditioned on c: the Kleene truth of c, clamped to Deny..Allow. */
    private static function truth(array $c, array $params = [], array $aggs = []): int
    {
        return self::dg(self::goal(grants: [self::grant('g1', 'v', self::exact('r1'), $c)]), self::act(0, $params), self::hist([], -1, $aggs));
    }

    /** The decision of an escalation on c: Allow exactly when c is false (0), else Escalate. */
    private static function escTruth(array $c): int
    {
        return self::dg(self::goal(grants: [self::g1()], escs: [$c]));
    }

    private static function tc(array $goal, ?array $ont = null): array
    {
        return K::kernelCall('typecheck', $goal, $ont ?? self::ont());
    }

    private static function ok(): array
    {
        return [['i', 0]];
    }

    private static function bad(string ...$rs): array
    {
        return [['i', 1], ...self::strs($rs)];
    }

    private static function escGoal(array $c): array
    {
        return self::goal(grants: [self::g1()], escs: [$c]);
    }

    private static function boundGoal(array $sel, array $core): array
    {
        return self::goal(grants: [self::g1()], bounds: [self::bound('b1', $sel, $core)]);
    }

    private static function countCore(array $window, array $scope = [['k', 430]], int $cap = 1, array $value = [['k', 341], ['k', 331], ['s', 'x']]): array
    {
        return self::core(400, $value, '', $window, $scope, self::q(self::cnt(), $cap), true);
    }

    /** Deny when the one admitted action at time $x is counted in the window of the candidate at time $a (cap 1), else Allow. */
    private static function windowDecision(array $window, int $a, int $x): int
    {
        $g = self::boundGoal(self::selGids(['g1']), self::countCore($window));
        return self::dg($g, self::act($a), self::hist([['g1', self::act($x)]]));
    }

    // ---- decoding and rendering

    /** A goal using every constructor renders back to exactly its own tape. */
    public function testEveryConstructorRoundTrips(): void
    {
        $pn = self::param('n', self::tyq(self::cnt()));
        $grants = [
            self::grant('g1', 'v', self::exact('r1'), self::cor(self::cmp('eq', $pn, self::qc(3)),
                self::cmp('lt', self::hagg('spent', self::money('usd')), self::lit(self::vq(self::q(self::money('eur'), 5)))))),
            self::grant('g2', 'v', self::oneof(['a', 'b']), self::cnot(self::cmp('in', self::param('s', self::tys()),
                self::lit(self::vset([self::aq(self::q([self::k(302)], 1)), self::atomS('x')]))))),
            self::grant('g3', 'v', self::related('owns', 'alice'), self::cand(self::ctrue(), self::cmp('nin', self::sa('a'),
                self::lit(self::vset([self::aq(self::q([self::k(303)], 2))]))))),
            self::grant('g4', 'v', self::anyres('w'), self::cmp('ne', self::param('b', self::tyq([self::k(304)])), self::lit(self::vq(self::q([self::k(305)], 7))))),
            self::grant('g5', 'v', self::allof([self::pexact('a'), self::poneof(['a', 'b']), self::prelated('owns', 'alice')]),
                self::cand(self::cmp('lte', $pn, self::qc(1)), self::cor(self::cmp('gt', $pn, self::qc(2)), self::cmp('gte', $pn, self::qc(4))))),
        ];
        $prohibits = [
            self::prohibit('p1', self::pverb('v'), self::exact('r1'), self::ctrue()),
            self::prohibit('p2', self::peffect('c'), self::oneof(['a']), self::cnot(self::cmp('eq', self::sa('x'), self::sa('y')))),
        ];
        $bounds = [
            self::bound('b1', self::selGids(['g1']), self::core(400, self::sa('x'), '', [self::k(420)], [self::k(430)], self::q(self::cnt(), 1), true)),
            self::bound('b2', self::selEffect('c'), self::core(401, $pn, 'k', [self::k(421), self::i(10)], [self::k(431)], self::q(self::cnt(), 5), false)),
            self::bound('b3', self::selGids(['g1', 'g2']), self::core(402, self::hagg('h', self::money('usd')), '', [self::k(422), self::i(4), self::i(1)],
                [self::k(432)], self::q(self::money('usd'), 9), true)),
            self::bound('b4', self::selEffect('c'), self::core(403, self::sa('y'), 'key', [self::k(423)], [self::k(433), ...self::strs(['A', 'B'])],
                self::q([self::k(305)], 2), false)),
        ];
        $escs = [self::cor(self::cmp('eq', $pn, self::qc(8)), self::cnot(self::cmp('eq', $pn, self::qc(9)))), self::ctrue()];
        $holes = [self::hole('h1', 'q?', ['x', 'y'], ['g2'], 1), self::hole('h2', 'q2', [], [], 0)];
        $t = self::goal($grants, $prohibits, $bounds, $escs, ['g4'], $holes, [3, 9, 2], 4, 0, ['g1'], ['src-a', 'src-b']);
        self::assertSame([['i', 0], ...$t], K::kernelCall('render', $t));
    }

    /** Three nested negations decode within the fuel of the remaining tape (fuel drops by one per level). */
    public function testNestedNegationFitsTheFuel(): void
    {
        $t = self::goal(escs: [self::cnot(self::cnot(self::cnot(self::ctrue())))]);
        self::assertSame([['i', 0], ...$t], K::kernelCall('render', $t));
    }

    /** An unknown keyword anywhere, a wrong opening keyword, a non-boolean flag or a negative length makes the tape malformed. */
    public function testMalformedTapesAreRefused(): void
    {
        $core = fn(array $agg, array $window, array $scope, array $on) => [self::k(450), ...$agg, ...self::sa('x'), self::s(''), ...$window,
            ...$scope, ...self::q(self::cnt(), 1), ...$on];
        $okCore = $core([self::k(400)], [self::k(420)], [self::k(430)], [self::k(440)]);
        self::assertSame([['i', 0], ...self::boundGoal(self::selGids(['g1']), $okCore)],
            K::kernelCall('render', self::boundGoal(self::selGids(['g1']), $okCore)));
        $bad = [
            'unit' => self::escGoal(self::cmp('eq', self::lit([self::k(330), self::k(306), self::i(1)]), self::sa('a'))),
            'ty' => self::escGoal(self::cmp('eq', [self::k(340), self::s('n'), self::k(312)], self::sa('a'))),
            'atom' => self::escGoal(self::cmp('in', self::sa('a'), [self::k(341), self::k(332), self::i(1), self::k(322), self::s('x')])),
            'val' => self::escGoal(self::cmp('eq', [self::k(341), self::k(333), self::s('a')], self::sa('a'))),
            'term' => self::escGoal(self::cmp('eq', [self::k(343), self::s('a')], self::sa('a'))),
            'op high' => self::escGoal([self::k(361), self::k(358), ...self::sa('a'), ...self::sa('a')]),
            'op low' => self::escGoal([self::k(361), self::k(349), ...self::sa('a'), ...self::sa('a')]),
            'cond' => self::escGoal([self::k(365)]),
            'part' => self::goal(grants: [self::grant('g1', 'v', [self::k(374), self::i(1), self::k(378), self::s('a')], self::ctrue())]),
            'res' => self::goal(grants: [self::grant('g1', 'v', [self::k(369), self::s('a')], self::ctrue())]),
            'res part kw' => self::goal(grants: [self::grant('g1', 'v', [self::k(375), self::s('a')], self::ctrue())]),
            'target' => self::goal(prohibits: [self::prohibit('p1', [self::k(393), self::s('v')], self::exact('r1'), self::ctrue())]),
            'sel' => self::boundGoal([self::k(412), self::s('c')], $okCore),
            'window' => self::boundGoal(self::selGids(['g1']), $core([self::k(400)], [self::k(424)], [self::k(430)], [self::k(440)])),
            'scope' => self::boundGoal(self::selGids(['g1']), $core([self::k(400)], [self::k(420)], [self::k(434)], [self::k(440)])),
            'onExceed' => self::boundGoal(self::selGids(['g1']), $core([self::k(400)], [self::k(420)], [self::k(430)], [self::k(442)])),
            'agg high' => self::boundGoal(self::selGids(['g1']), $core([self::k(404)], [self::k(420)], [self::k(430)], [self::k(440)])),
            'agg low' => self::boundGoal(self::selGids(['g1']), $core([self::k(399)], [self::k(420)], [self::k(430)], [self::k(440)])),
            'opening' => [self::k(481), ...array_slice(self::goal(), 1)],
            'narrowOnly 2' => self::goal(narrow: 2),
            'narrowOnly -1' => self::goal(narrow: -1),
            'negative length' => [...array_slice(self::goal(), 0, 5), self::i(-1), ...array_slice(self::goal(), 6)],
        ];
        foreach ($bad as $name => $t) {
            self::assertSame(K::BAD, K::kernelCall('render', $t), $name);
        }
    }

    /** Each reader method is part of the public decoding API and decodes its own construct. */
    public function testReaderMethodsDecodeDirectly(): void
    {
        $r = new R([self::k(1), self::i(2)]);
        self::assertSame(2, $r->rest());
        self::assertSame(1, $r->kw());
        self::assertSame(1, $r->rest());
        self::assertSame(2, $r->int());
        self::assertSame(0, $r->rest());
        self::assertSame('x', (new R([self::s('x')]))->str());
        self::assertTrue((new R([self::i(1)]))->bool());
        self::assertFalse((new R([self::i(0)]))->bool());
        $r = new R([self::i(2), self::i(5), self::i(6)]);
        self::assertSame([5, 6], $r->lst(fn() => $r->int()));
        self::assertSame(['a'], (new R(self::strs(['a'])))->strs());
        self::assertSame(['count'], (new R(self::cnt()))->unit());
        self::assertSame(['u' => ['count'], 'n' => 3], (new R(self::q(self::cnt(), 3)))->q());
        self::assertSame(['tys'], (new R(self::tys()))->ty());
        self::assertSame(['as', 'x'], (new R(self::atomS('x')))->atom());
        self::assertSame(['vs', 'x'], (new R(self::vs('x')))->val());
        self::assertSame(['lit', ['vs', 'x']], (new R(self::sa('x')))->term());
        self::assertSame('nin', (new R([self::k(357)]))->op());
        self::assertSame('eq', (new R([self::k(350)]))->op());
        self::assertSame(['ctrue'], (new R(self::ctrue()))->cond(1));
        self::assertSame(['not', ['ctrue']], (new R(self::cnot(self::ctrue())))->condTop());
        self::assertSame(['pexact', 'a'], (new R(self::pexact('a')))->part());
        self::assertSame(['anyres', 'w'], (new R(self::anyres('w')))->resSel());
        self::assertSame(['gid' => 'g', 'verb' => 'v', 'res' => ['anyres', 'w'], 'cond' => ['ctrue']],
            (new R(self::grant('g', 'v', self::anyres('w'), self::ctrue())))->grant());
        self::assertSame(['peffect', 'e'], (new R(self::peffect('e')))->prohTarget());
        self::assertSame(['pid' => 'p', 'target' => ['pverb', 'v'], 'res' => ['exact', 'r'], 'cond' => ['ctrue']],
            (new R(self::prohibit('p', self::pverb('v'), self::exact('r'), self::ctrue())))->prohibit());
        self::assertSame(['sel_effect', 'e'], (new R(self::selEffect('e')))->sel());
        self::assertSame(['wlifetime'], (new R([self::k(423)]))->window());
        self::assertSame(['sorg'], (new R([self::k(432)]))->scope());
        self::assertSame('on_escalate', (new R([self::k(441)]))->onExceed());
        self::assertSame('distinct', (new R([self::k(403)]))->agg());
        self::assertSame('count', (new R([self::k(400)]))->agg());
        $core = self::core(400, self::sa('x'), 'key', [self::k(420)], [self::k(430)], self::q(self::cnt(), 1), true);
        $coreV = ['agg' => 'count', 'value' => ['lit', ['vs', 'x']], 'key' => 'key', 'window' => ['wtask'], 'scope' => ['ssession'],
            'cap' => ['u' => ['count'], 'n' => 1], 'onExceed' => 'on_deny'];
        self::assertSame($coreV, (new R($core))->bcore());
        self::assertSame(['bid' => 'b', 'sel' => ['sel_effect', 'e'], 'core' => $coreV], (new R(self::bound('b', self::selEffect('e'), $core)))->bound());
        self::assertSame(['notBefore' => 1, 'notAfter' => 2, 'maxIdle' => 3], (new R([self::k(460), self::i(1), self::i(2), self::i(3)]))->validity());
        self::assertSame(['maxDepth' => 2, 'narrowOnly' => true, 'mayTouch' => ['g']], (new R([self::k(461), self::i(2), self::i(1), ...self::strs(['g'])]))->deleg());
        self::assertSame(['hid' => 'h', 'q' => 'q', 'domain' => [], 'affects' => ['g'], 'global' => true], (new R(self::hole('h', 'q', [], ['g'], 1)))->hole());
        self::assertSame(['path' => 'n', 'ty' => ['tys']], (new R(self::pdecl('n', self::tys())))->paramDecl());
        self::assertSame(['verb' => 'v', 'cls' => 'c', 'params' => []], (new R(self::verb('v', 'c', [])))->verbDecl());
        self::assertSame(['rel' => 'r', 'anchor' => 'a', 'members' => ['m']], (new R([self::k(502), self::s('r'), self::s('a'), ...self::strs(['m'])]))->relDecl());
        $r = new R([self::i(2), self::k(520), self::s('a'), self::i(1), self::k(520), self::s('a'), self::i(2)]);
        self::assertSame(['a' => 1], $r->keyed(520, fn() => $r->int()));
        self::assertSame(['gid' => 'g', 'act' => ['verb' => 'v', 'res' => 'r1', 'params' => [], 't' => 5, 'sess' => 'S', 'prin' => 'P', 'org' => 'O',
            'agent' => 'A', 'depth' => 0]], (new R([self::k(531), self::s('g'), ...self::act(5)]))->adm());
    }

    // ---- Kleene truth

    /** The public Kleene operators: and is the minimum, or the maximum, not the mirror. */
    public function testKleeneOperators(): void
    {
        self::assertSame(2, K::b2t(true));
        self::assertSame(0, K::b2t(false));
        self::assertSame(0, K::andK(0, 2));
        self::assertSame(1, K::andK(2, 1));
        self::assertSame(2, K::orK(0, 2));
        self::assertSame(2, K::orK(2, 1));
        self::assertSame(1, K::orK(1, 0));
        self::assertSame(2, K::notK(0));
        self::assertSame(1, K::notK(1));
        $q = ['u' => ['count'], 'n' => 3];
        self::assertSame(['vq', $q], K::atomV(['aq', $q]));
        self::assertSame(['vs', 'x'], K::atomV(['as', 'x']));
        self::assertSame(['tyq', ['count']], K::typeOfV(['vq', $q]));
        self::assertSame(['tys'], K::typeOfV(['vs', 'x']));
        self::assertNull(K::typeOfV(['vset', []]));
    }

    /** Equality is true/false only between values of one type (same unit for quantities), otherwise unknown. */
    public function testEqualityIsTyped(): void
    {
        self::assertSame(2, self::truth(self::cmp('eq', self::qc(3), self::qc(3))));
        self::assertSame(0, self::truth(self::cmp('eq', self::qc(3), self::qc(4))));
        self::assertSame(1, self::truth(self::cmp('eq', self::qc(3), self::lit(self::vq(self::q([self::k(302)], 3))))));
        self::assertSame(1, self::truth(self::cmp('eq', self::qc(3), self::sa('a'))));
        self::assertSame(2, self::truth(self::cmp('eq', self::sa('a'), self::sa('a'))));
        self::assertSame(0, self::truth(self::cmp('eq', self::sa('a'), self::sa('b'))));
        self::assertSame(1, self::truth(self::cmp('eq', self::sa('a'), self::qc(3))));
        self::assertSame(1, self::truth(self::cmp('eq', self::lit(self::vset([self::atomS('a')])), self::qc(3))));
        self::assertSame(1, self::truth(self::cmp('ne', self::lit(self::vset([self::atomS('a')])), self::qc(3))));
    }

    /** Ordering is defined only between quantities of one unit; membership needs a set, else unknown. */
    public function testOrderingAndMembership(): void
    {
        self::assertSame(2, self::truth(self::cmp('lt', self::qc(3), self::qc(4))));
        self::assertSame(0, self::truth(self::cmp('lt', self::qc(4), self::qc(3))));
        self::assertSame(1, self::truth(self::cmp('lt', self::qc(3), self::sa('a'))));
        self::assertSame(1, self::truth(self::cmp('lt', self::sa('a'), self::qc(3))));
        self::assertSame(1, self::truth(self::cmp('lt', self::qc(3), self::lit(self::vq(self::q([self::k(302)], 4))))));
        self::assertSame(1, self::truth(self::cmp('in', self::qc(3), self::qc(3))));
        self::assertSame(1, self::truth(self::cmp('nin', self::qc(3), self::qc(3))));
        self::assertSame(2, self::truth(self::cmp('in', self::qc(3), self::lit(self::vset([self::aq(self::q(self::cnt(), 3))])))));
        self::assertSame(0, self::truth(self::cmp('in', self::sa('a'), self::lit(self::vset([self::atomS('b')])))));
        self::assertSame(2, self::truth(self::cmp('nin', self::sa('a'), self::lit(self::vset([self::atomS('b')])))));
        // membership in the empty set is exactly false: an escalation on it does not fire
        self::assertSame(K::ALLOW, self::escTruth(self::cmp('in', self::qc(3), self::lit(self::vset([])))));
        self::assertSame(K::ESCALATE, self::escTruth(self::cmp('nin', self::qc(3), self::lit(self::vset([])))));
    }

    /** Parameters and history aggregates read from the action and the history; a missing one is unknown. */
    public function testTermsReadTheirSource(): void
    {
        $n3 = ['n' => self::vq(self::q(self::cnt(), 3))];
        self::assertSame(2, self::truth(self::cmp('eq', self::param('n', self::tyq(self::cnt())), self::qc(3)), $n3));
        self::assertSame(1, self::truth(self::cmp('eq', self::param('m', self::tyq(self::cnt())), self::qc(3)), $n3));
        $aggs = ['spent' => self::q(self::cnt(), 5)];
        self::assertSame(2, self::truth(self::cmp('eq', self::hagg('spent', self::cnt()), self::qc(5)), [], $aggs));
        self::assertSame(0, self::truth(self::cmp('eq', self::hagg('spent', self::cnt()), self::qc(6)), [], $aggs));
        self::assertSame(1, self::truth(self::cmp('eq', self::hagg('none', self::cnt()), self::qc(5)), [], $aggs));
    }

    /** The connectives combine both operands; a negated truth is exactly false (an escalation on it does not fire). */
    public function testConnectives(): void
    {
        $f = self::cmp('eq', self::sa('a'), self::sa('b'));
        $t = self::cmp('eq', self::sa('a'), self::sa('a'));
        self::assertSame(2, self::truth(self::cor($f, $t)));
        self::assertSame(2, self::truth(self::cor($t, $f)));
        self::assertSame(0, self::truth(self::cor($f, $f)));
        self::assertSame(0, self::truth(self::cand($t, $f)));
        self::assertSame(0, self::truth(self::cand($f, $t)));
        self::assertSame(2, self::truth(self::cnot($f)));
        self::assertSame(0, self::truth(self::cnot($t)));
        self::assertSame(2, self::truth(self::ctrue()));
        self::assertSame(K::ALLOW, self::escTruth(self::cnot(self::ctrue())));
        self::assertSame(K::ESCALATE, self::escTruth(self::ctrue()));
    }

    /** Negation normal form: negation pushed to the atoms (operators flipped), and/or swapped under negation. */
    public function testNegationNormalForm(): void
    {
        $la = ['lit', ['vs', 'a']];
        $lb = ['lit', ['vs', 'b']];
        $a = ['cmp', 'eq', $la, $lb];
        $b = ['cmp', 'lt', $la, $lb];
        self::assertSame(['ntrue'], K::nnf(['ctrue'], true));
        self::assertSame(['nfalse'], K::nnf(['ctrue'], false));
        self::assertSame(['natom', 'eq', $la, $lb], K::nnf($a, true));
        self::assertSame(['nand', ['natom', 'eq', $la, $lb], ['natom', 'lt', $la, $lb]], K::nnf(['and', $a, $b], true));
        self::assertSame(['nor', ['natom', 'ne', $la, $lb], ['natom', 'gte', $la, $lb]], K::nnf(['and', $a, $b], false));
        self::assertSame(['nor', ['natom', 'eq', $la, $lb], ['natom', 'lt', $la, $lb]], K::nnf(['or', $a, $b], true));
        self::assertSame(['nand', ['natom', 'ne', $la, $lb], ['natom', 'gte', $la, $lb]], K::nnf(['or', $a, $b], false));
        self::assertSame(['natom', 'ne', $la, $lb], K::nnf(['not', $a], true));
        self::assertSame(['natom', 'eq', $la, $lb], K::nnf(['not', $a], false));
        $neg = ['eq' => 'ne', 'ne' => 'eq', 'lt' => 'gte', 'gte' => 'lt', 'gt' => 'lte', 'lte' => 'gt', 'in' => 'nin', 'nin' => 'in'];
        foreach ($neg as $op => $flip) {
            self::assertSame(['natom', $flip, $la, $lb], K::nnf(['cmp', $op, $la, $lb], false), $op);
        }
    }

    /** Resource selectors resolve to sets; an all-of intersects its parts in the order of the first part. */
    public function testResourceSelectorsResolve(): void
    {
        $o = (new R(self::ont()))->ontology();
        self::assertSame(['pset', ['b', 'a']], K::resolveSel($o, ['allof', [['poneof', ['b', 'a']], ['poneof', ['a', 'b']]]]));
        self::assertSame(['pset', ['r1']], K::resolveSel($o, ['allof', [['pexact', 'r1'], ['prelated', 'owns', 'alice']]]));
        self::assertSame(['pset', ['r2']], K::resolveSel($o, ['allof', [['prelated', 'owns', 'alice'], ['pexact', 'r2']]]));
        self::assertSame(['pset', []], K::resolveSel($o, ['allof', [['pexact', 'zz'], ['poneof', ['r1', 'r2']]]]));
        self::assertSame(['pset', ['r1', 'r2']], K::resolveSel($o, ['related', 'owns', 'alice']));
        self::assertSame(['pset', []], K::resolveSel($o, ['related', 'owns', 'bob']));
        self::assertSame(['pstar'], K::resolveSel($o, ['anyres', 'w']));
        self::assertSame(['pset', ['x']], K::resolveSel($o, ['exact', 'x']));
    }

    // ---- windows, validity, bounds

    /** A period window buckets times by floor division (negative times round down), offset by its phase. */
    public function testPeriodWindowBucketsByFloor(): void
    {
        $w = [self::k(422), self::i(4), self::i(0)];
        self::assertSame(K::ALLOW, self::windowDecision($w, 0, -1));
        self::assertSame(K::DENY, self::windowDecision($w, -1, -4));
        self::assertSame(K::DENY, self::windowDecision($w, 4, 5));
        self::assertSame(K::ALLOW, self::windowDecision($w, 4, 3));
        self::assertSame(K::ALLOW, self::windowDecision($w, 8, 5));
        // phase 1: buckets [1,5) and [5,9)
        $w1 = [self::k(422), self::i(4), self::i(1)];
        self::assertSame(K::DENY, self::windowDecision($w1, 4, 1));
        self::assertSame(K::ALLOW, self::windowDecision($w1, 5, 4));
        // a non-positive period counts nothing (and never divides)
        self::assertSame(K::ALLOW, self::windowDecision([self::k(422), self::i(0), self::i(0)], 0, 0));
    }

    /** A sliding window of w counts (t-w, t]: the far edge is out, the candidate's own instant is in. */
    public function testSlidingWindowEdges(): void
    {
        $w = [self::k(421), self::i(10)];
        self::assertSame(K::ALLOW, self::windowDecision($w, 20, 10));
        self::assertSame(K::DENY, self::windowDecision($w, 20, 11));
        self::assertSame(K::DENY, self::windowDecision($w, 20, 20));
        self::assertSame(K::ALLOW, self::windowDecision($w, 20, 21));
        self::assertSame(K::DENY, self::windowDecision([self::k(420)], 20, 99));
    }

    /** A max bound over a value the action does not carry is unreadable: Escalate, not Allow. */
    public function testUnreadableMaxEscalates(): void
    {
        $core = self::core(402, self::param('amt', self::tyq(self::cnt())), '', [self::k(420)], [self::k(430)], self::q(self::cnt(), 10), true);
        self::assertSame(K::ESCALATE, self::dg(self::boundGoal(self::selGids(['g1']), $core)));
        $amt = ['amt' => self::vq(self::q(self::cnt(), 4))];
        self::assertSame(K::ALLOW, self::dg(self::boundGoal(self::selGids(['g1']), $core), self::act(0, $amt)));
    }

    /** Validity is inclusive at both ends; idleness counts from a last use at time 0. */
    public function testValidityEdges(): void
    {
        $g = self::goal(grants: [self::g1()], validity: [0, 10, 0]);
        self::assertSame(K::ALLOW, self::dg($g, self::act(0)));
        self::assertSame(K::ALLOW, self::dg($g, self::act(10)));
        self::assertSame(K::DENY, self::dg($g, self::act(11)));
        self::assertSame(K::DENY, self::dg($g, self::act(-1)));
        $idle = self::goal(grants: [self::g1()], validity: [0, 100, 5]);
        self::assertSame(K::DENY, self::dg($idle, self::act(10), self::hist([], 0)));
        self::assertSame(K::ALLOW, self::dg($idle, self::act(5), self::hist([], 0)));
        self::assertSame(K::ALLOW, self::dg($idle, self::act(10), self::hist([], -1)));
    }

    // ---- typing

    /** Grants must be in strictly increasing gid order; a duplicate is not canonical, two sorted grants are fine. */
    public function testCanonicalOrder(): void
    {
        self::assertSame(self::bad('not_canonical_order'), self::tc(self::goal(grants: [self::g1(), self::g1()])));
        self::assertSame(self::ok(), self::tc(self::goal(grants: [self::g1(), self::grant('g2', 'v', self::exact('r1'), self::ctrue())])));
        self::assertSame(self::bad('not_canonical_order', 'bad_validity_or_delegation'),
            self::tc(self::goal(grants: [self::g1(), self::g1()], validity: [10, 5, 0])));
    }

    /** Terms are well typed only with non-empty names, valid units and every set atom's unit valid. */
    public function testTermTyping(): void
    {
        $setCore = fn(array $atoms) => self::countCore([self::k(420)], [self::k(430)], 1, self::lit(self::vset($atoms)));
        self::assertSame(self::ok(), self::tc(self::boundGoal(self::selGids(['g1']), $setCore([self::aq(self::q(self::cnt(), 1)), self::atomS('x')]))));
        self::assertSame(self::bad('ill_typed_bound'), self::tc(self::boundGoal(self::selGids(['g1']), $setCore([self::aq(self::q(self::money(''), 1))]))));
        self::assertSame(self::bad('ill_typed_bound'), self::tc(self::boundGoal(self::selGids(['g1']), $setCore([self::atomS('x'), self::aq(self::q(self::money(''), 1))]))));
        self::assertSame(self::ok(), self::tc(self::escGoal(self::cmp('eq', self::hagg('spent', self::cnt()), self::qc(1)))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cmp('eq', self::hagg('', self::cnt()), self::qc(1)))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cmp('eq', self::hagg('m', self::money('')), self::lit(self::vq(self::q(self::money(''), 1)))))));
        self::assertSame(self::ok(), self::tc(self::escGoal(self::cmp('eq', self::param('n', self::tyq(self::cnt())), self::qc(1)))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cmp('eq', self::param('', self::tys()), self::sa('x')))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cmp('eq', self::sa('x'), self::param('', self::tys())))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cmp('eq', self::lit(self::vset([])), self::lit(self::vset([]))))));
    }

    /** Comparisons: equal types for eq, a quantity for ordering, a set literal of the left type for membership. */
    public function testComparisonTyping(): void
    {
        $pn = self::param('n', self::tyq(self::cnt()));
        self::assertSame(self::ok(), self::tc(self::escGoal(self::cmp('eq', self::sa('a'), self::sa('b')))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cmp('in', self::qc(1), self::qc(1)))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cmp('in', $pn, self::lit(self::vset([self::atomS('x')]))))));
        self::assertSame(self::ok(), self::tc(self::escGoal(self::cmp('in', $pn, self::lit(self::vset([self::aq(self::q(self::cnt(), 1))]))))));
        self::assertSame(self::ok(), self::tc(self::escGoal(self::cand(self::ctrue(), self::cor(self::cmp('eq', self::sa('a'), self::sa('b')), self::cnot(self::ctrue()))))));
        $badCmp = self::cmp('eq', self::sa('a'), self::qc(1));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cand(self::ctrue(), $badCmp))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cand($badCmp, self::ctrue()))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cor(self::ctrue(), $badCmp))));
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cnot($badCmp))));
        // an escalation parameter must not conflict with any verb's declaration of that path
        self::assertSame(self::bad('ill_typed_escalation'), self::tc(self::escGoal(self::cmp('eq', self::param('n', self::tys()), self::sa('x')))));
        // a grant parameter must be declared for its verb, on either side of the comparison
        self::assertSame(self::bad('ill_typed_grant'), self::tc(self::goal(grants: [self::grant('g1', 'v', self::exact('r1'), self::cmp('eq', self::sa('x'), self::param('zz', self::tys())))])));
        self::assertSame(self::ok(), self::tc(self::goal(grants: [self::grant('g1', 'v', self::exact('r1'), self::cmp('eq', self::sa('x'), self::param('s', self::tys())))])));
    }

    /** Resource selectors type-check: declared relations (rel and anchor), non-empty names and lists, all-of parts checked. */
    public function testResourceTyping(): void
    {
        $gr = fn(array $res) => self::tc(self::goal(grants: [self::grant('g1', 'v', $res, self::ctrue())]));
        self::assertSame(self::ok(), $gr(self::related('owns', 'alice')));
        self::assertSame(self::bad('ill_typed_grant'), $gr(self::related('owns', 'bob')));
        self::assertSame(self::bad('ill_typed_grant'), $gr(self::related('x', 'alice')));
        self::assertSame(self::bad('ill_typed_grant'), $gr(self::related('x', 'y')));
        self::assertSame(self::ok(), $gr(self::allof([self::pexact('r1'), self::poneof(['r1'])])));
        self::assertSame(self::ok(), $gr(self::allof([self::prelated('owns', 'alice'), self::pexact('r1')])));
        self::assertSame(self::bad('ill_typed_grant'), $gr(self::allof([self::pexact(''), self::pexact('r1')])));
        self::assertSame(self::bad('ill_typed_grant'), $gr(self::allof([self::poneof([]), self::pexact('r1')])));
        self::assertSame(self::bad('ill_typed_grant'), $gr(self::allof([self::prelated('owns', 'bob'), self::pexact('r1')])));
        self::assertSame(self::bad('ill_typed_grant'), $gr(self::exact('')));
        self::assertSame(self::bad('ill_typed_grant'), $gr(self::oneof([])));
        self::assertSame(self::ok(), $gr(self::oneof(['r1'])));
        self::assertSame(self::bad('ill_typed_grant'), self::tc(self::goal(grants: [self::grant('', 'v', self::exact('r1'), self::ctrue())])));
    }

    /** Prohibitions need a pid, a declared verb or a non-empty effect class with verbs, and a typed condition. */
    public function testProhibitTyping(): void
    {
        $pr = fn(array $p, ?array $ont = null) => self::tc(self::goal(grants: [self::g1()], prohibits: [$p]), $ont);
        self::assertSame(self::ok(), $pr(self::prohibit('p1', self::pverb('v'), self::exact('r1'), self::ctrue())));
        self::assertSame(self::ok(), $pr(self::prohibit('p1', self::peffect('c'), self::exact('r1'), self::ctrue())));
        self::assertSame(self::bad('ill_typed_prohibit'), $pr(self::prohibit('', self::pverb('v'), self::exact('r1'), self::ctrue())));
        self::assertSame(self::bad('ill_typed_prohibit'), $pr(self::prohibit('p1', self::pverb('undeclared'), self::exact('r1'), self::ctrue())));
        self::assertSame(self::bad('ill_typed_prohibit'), $pr(self::prohibit('p1', self::peffect('nope'), self::exact('r1'), self::ctrue())));
        // an empty effect class is refused even when the ontology has verbs of class ''
        $ont = self::ont([self::verb('v', 'c', []), self::verb('vx', '', [])]);
        self::assertSame(self::bad('ill_typed_prohibit'), $pr(self::prohibit('p1', self::peffect(''), self::exact('r1'), self::ctrue()), $ont));
    }

    /** Bounds need a bid, a valid cap (zero allowed), a non-empty fleet, a non-empty known selector and a distinct key. */
    public function testBoundTyping(): void
    {
        $b = fn(string $bid, array $sel, array $core) => self::tc(self::goal(grants: [self::g1()], bounds: [self::bound($bid, $sel, $core)]));
        $c = self::countCore([self::k(420)]);
        self::assertSame(self::ok(), $b('b1', self::selGids(['g1']), $c));
        self::assertSame(self::ok(), $b('b1', self::selGids(['g1']), self::countCore([self::k(420)], [self::k(430)], 0)));
        self::assertSame(self::bad('ill_typed_bound'), $b('', self::selGids(['g1']), $c));
        self::assertSame(self::bad('ill_typed_bound'), $b('b1', self::selGids(['g1']), self::countCore([self::k(420)], [self::k(433), self::i(0)])));
        self::assertSame(self::ok(), $b('b1', self::selGids(['g1']), self::countCore([self::k(420)], [self::k(433), ...self::strs(['A'])])));
        self::assertSame(self::bad('ill_typed_bound'), $b('b1', self::selGids([]), $c));
        self::assertSame(self::bad('ill_typed_bound'), $b('b1', self::selGids(['nope']), $c));
        self::assertSame(self::bad('ill_typed_bound'), $b('b1', self::selEffect(''), $c));
        self::assertSame(self::ok(), $b('b1', self::selEffect('c'), $c));
        $distinct = fn(string $key) => self::core(403, self::sa('x'), $key, [self::k(420)], [self::k(430)], self::q(self::cnt(), 1), true);
        self::assertSame(self::ok(), $b('b1', self::selGids(['g1']), $distinct('k')));
        self::assertSame(self::bad('ill_typed_bound'), $b('b1', self::selGids(['g1']), $distinct('')));
    }

    /** Validity may be a single instant; delegation depth 16 is the maximum; an inverted window is refused. */
    public function testValidityTyping(): void
    {
        self::assertSame(self::ok(), self::tc(self::goal(grants: [self::g1()], validity: [5, 5, 0])));
        self::assertSame(self::ok(), self::tc(self::goal(grants: [self::g1()], maxDepth: 16)));
        self::assertSame(self::bad('bad_validity_or_delegation'), self::tc(self::goal(grants: [self::g1()], maxDepth: 17)));
        self::assertSame(self::bad('bad_validity_or_delegation'), self::tc(self::goal(grants: [self::g1()], validity: [10, 5, 0])));
    }

    // ---- compile, decide, witness

    /** The compiled policy tape: grants lowered to negation normal form (every normal-form node encoded), prohibitions to verbs. */
    public function testCompiledPolicyTape(): void
    {
        $pn = self::param('n', self::tyq(self::cnt()));
        $g = self::goal(
            grants: [self::grant('g1', 'v', self::exact('r1'), self::cand(self::cnot(self::ctrue()), self::cor(self::cmp('eq', $pn, self::qc(3)), self::cmp('lt', $pn, self::qc(5)))))],
            prohibits: [self::prohibit('p1', self::pverb('v2'), self::exact('r2'), self::ctrue())],
        );
        $pnT = [self::k(340), self::s('n'), self::k(310), self::k(301)];
        $want = [self::i(0), self::k(650),
            self::i(1), self::k(620), self::s('g1'), self::s('v'), self::k(631), self::i(1), self::s('r1'),
            self::k(603), self::k(601), self::k(604),
            self::k(602), self::k(350), ...$pnT, self::k(341), self::k(330), self::k(301), self::i(3),
            self::k(602), self::k(352), ...$pnT, self::k(341), self::k(330), self::k(301), self::i(5),
            self::i(1), self::k(640), self::s('p1'), self::i(1), self::s('v2'), self::k(631), self::i(1), self::s('r2'), self::k(600),
            self::i(0),
            self::i(0),
            self::k(460), self::i(-100), self::i(100), self::i(0), self::k(461), self::i(2), self::i(1), self::i(0)];
        self::assertSame($want, K::kernelCall('compile', $g, self::ont()));
    }

    /** Compiling strips the grants a hole touches and leaves the remaining grants as a list. */
    public function testCompileStripsHoleGrantsIntoAList(): void
    {
        $t = self::goal(grants: [self::g1(), self::grant('g2', 'v', self::exact('r1'), self::ctrue())], holes: [self::hole('h1', 'q', [], ['g1'], 0)]);
        $g = (new R($t))->goal();
        $o = (new R(self::ont()))->ontology();
        self::assertSame([], K::typeReasons($o, $g));
        [$kind, $p] = K::compile($o, $g);
        self::assertSame('compiled', $kind);
        self::assertTrue(array_is_list($p['preds']));
        self::assertSame(['g2'], array_column($p['preds'], 'gid'));
        self::assertSame(['escalate', ['bad_validity_or_delegation']], K::compile($o, (new R(self::goal(grants: [self::g1()], validity: [9, 1, 0])))->goal()));
    }

    /** decidep: an ill-typed goal escalates with its reasons; a well-typed one decides with a checked witness. */
    public function testDecidePolicy(): void
    {
        $bad = self::goal(grants: [self::grant('', 'v', self::exact('r1'), self::ctrue())]);
        self::assertSame([['i', 1], ['i', 1], ['s', 'ill_typed_grant']], K::kernelCall('decidep', $bad, self::ont(), self::act(), self::hist()));
        $ok = self::goal(grants: [self::g1()]);
        self::assertSame([['i', 0], ['i', 2], ['s', 'g1'], ['i', 0], ['i', 1]], K::kernelCall('decidep', $ok, self::ont(), self::act(), self::hist()));
        self::assertSame([['i', 0], ['i', 0], ['s', ''], ['i', 0], ['i', 0]], K::kernelCall('decidep', $ok, self::ont(), self::act(0, [], 'v2'), self::hist()));
    }

    /** Any malformed input of a call (goal, ontology, action or history) yields the malformed answer. */
    public function testEachMalformedInputIsRefused(): void
    {
        $g = self::goal(grants: [self::g1()]);
        self::assertSame(K::BAD, K::kernelCall('typecheck', $g, []));
        self::assertSame(K::BAD, K::kernelCall('typecheck', [self::k(1)], self::ont()));
        self::assertSame(K::BAD, K::kernelCall('decideg', $g, self::ont(), [], self::hist()));
        self::assertSame(K::BAD, K::kernelCall('decideg', $g, self::ont(), self::act(), []));
        self::assertSame(K::BAD, K::kernelCall('decidep', $g, self::ont(), self::act(), [self::k(541)]));
        self::assertSame(K::BAD, K::kernelCall('decideg', $g, self::ont(), self::act(), [self::k(539), ...array_slice(self::hist(), 1)]));
        self::assertSame([['i', 0], ['i', 2]], K::kernelCall('decideg', $g, self::ont(), self::act(), self::hist()));
    }

    private static function policy(array $cond, array $escs = [], int $notAfter = 100): array
    {
        return ['preds' => [['gid' => 'g1', 'verb' => 'v', 'res' => ['pstar'], 'cond' => $cond]], 'prohs' => [], 'ceils' => [], 'escs' => $escs,
            'validity' => ['notBefore' => -100, 'notAfter' => $notAfter, 'maxIdle' => 0], 'deleg' => ['maxDepth' => 2, 'narrowOnly' => true, 'mayTouch' => []]];
    }

    private static function a(): array
    {
        return ['verb' => 'v', 'res' => 'r1', 'params' => [], 't' => 0, 'sess' => 'S', 'prin' => 'P', 'org' => 'O', 'agent' => 'A', 'depth' => 0];
    }

    private static function h(): array
    {
        return ['adms' => [], 'last' => -1, 'aggs' => []];
    }

    /** The compiled decision evaluates every normal-form node; a false escalation does not fire. */
    public function testPolicyDecisionOverNormalForms(): void
    {
        $l3 = ['lit', ['vq', ['u' => ['count'], 'n' => 3]]];
        self::assertSame(K::ALLOW, K::dp(self::policy(['ntrue']), self::a(), self::h()));
        self::assertSame(K::DENY, K::dp(self::policy(['nfalse']), self::a(), self::h()));
        self::assertSame(K::ALLOW, K::dp(self::policy(['ntrue'], [['nfalse']]), self::a(), self::h()));
        self::assertSame(K::ESCALATE, K::dp(self::policy(['ntrue'], [['ntrue']]), self::a(), self::h()));
        self::assertSame(K::ALLOW, K::dp(self::policy(['nor', ['nfalse'], ['ntrue']]), self::a(), self::h()));
        self::assertSame(K::ALLOW, K::dp(self::policy(['nor', ['ntrue'], ['nfalse']]), self::a(), self::h()));
        self::assertSame(K::DENY, K::dp(self::policy(['nor', ['nfalse'], ['nfalse']]), self::a(), self::h()));
        self::assertSame(K::DENY, K::dp(self::policy(['nand', ['ntrue'], ['nfalse']]), self::a(), self::h()));
        self::assertSame(K::ALLOW, K::dp(self::policy(['natom', 'eq', $l3, $l3]), self::a(), self::h()));
        self::assertSame(K::ESCALATE, K::dp(self::policy(['natom', 'eq', $l3, ['lit', ['vs', 'x']]]), self::a(), self::h()));
    }

    /** The witness names the first allowing grant; checking it needs validity, that grant allowing, and the exact bounds. */
    public function testWitnessCheck(): void
    {
        $p = self::policy(['ntrue']);
        self::assertSame([K::ALLOW, 'g1', []], K::decideW($p, self::a(), self::h()));
        self::assertSame([K::DENY, '', []], K::decideW(self::policy(['nfalse']), self::a(), self::h()));
        self::assertTrue(K::verifyWitness($p, self::a(), self::h(), 'g1', []));
        self::assertFalse(K::verifyWitness($p, self::a(), self::h(), 'zz', []));
        self::assertFalse(K::verifyWitness($p, self::a(), self::h(), 'g1', ['b9']));
        self::assertFalse(K::verifyWitness(self::policy(['nfalse']), self::a(), self::h(), 'g1', []));
        // outside its validity the policy's witness never verifies, even for an allowing grant
        self::assertFalse(K::verifyWitness(self::policy(['ntrue'], [], -1), self::a(), self::h(), 'g1', []));
        self::assertFalse(K::verifyWitness(self::policy(['ntrue'], [['ntrue']]), self::a(), self::h(), 'g1', []));
    }

    /** The reference decision and the render are public entry points over decoded goals. */
    public function testDecodedGoalEntryPoints(): void
    {
        $t = self::goal(grants: [self::g1()]);
        $g = (new R($t))->goal();
        $o = (new R(self::ont()))->ontology();
        $a = (new R(self::act()))->act();
        $h = (new R(self::hist()))->hist();
        self::assertSame(K::ALLOW, K::dg($o, $g, $a, $h));
        self::assertSame($t, K::render($g));
    }
}
