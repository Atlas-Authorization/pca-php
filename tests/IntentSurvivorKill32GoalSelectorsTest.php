<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsBuiltin;
use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalCompiler;
use Atlas\Pca\GoalSelectors;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/GoalSelectors.php';
require_once __DIR__ . '/../src/GoalCompiler.php';
require_once __DIR__ . '/../src/ActionsBuiltin.php';

/** Group 32 mutation kills for src/GoalSelectors.php: catalogs, role resolution, bound values, the selector reasons, compilation, the card and the carrier. */
final class IntentSurvivorKill32GoalSelectorsTest extends TestCase
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

    private static function thrown(\Closure $f): string
    {
        try {
            return 'returned ' . Json::stringify($f());
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
    }

    private static function grant(string $gid, string $verb): Obj
    {
        return Obj::of(['gid' => $gid, 'sel' => Obj::of(['k' => 'verb', 'verb' => $verb]), 'res' => Obj::of(['k' => 'any']), 'cond' => Obj::of(['k' => 'true'])]);
    }

    /** A selector goal with the members the expansion reads. */
    private static function sg(array $grants, array $bounds, ?Obj $cat = null): Obj
    {
        $sg = Obj::of(['grants' => $grants, 'prohibits' => [], 'bounds' => $bounds, 'deleg' => Obj::of(['mayTouch' => []]), 'holes' => [], 'wildcardAck' => []]);
        if ($cat !== null) {
            $sg->set('catDigest', GoalSelectors::selCatalogDigest($cat));
        }
        return $sg;
    }

    private static function emptyCat(): Obj
    {
        return Obj::of(['known' => [], 'verbs' => []]);
    }

    /** A parameter list's `length` of null or undefined throws (a role mapped to either). */
    public function testLengthOfNullOrUndefinedThrows(): void
    {
        $act = Obj::of(['verb' => 'v', 'params' => new Obj()]);
        $msg = 'TypeError: cannot read properties of null or undefined (reading length)';
        foreach ([null, AnalyzerJs::undef()] as $x) {
            $cat = Obj::of(['verbs' => [Obj::of(['verb' => 'v', 'roles' => Obj::of(['r' => $x])])]]);
            self::assertSame($msg, self::thrown(static fn() => GoalSelectors::withRoleParams($act, $cat)));
        }
    }

    /** The catalog of defs: the given registry's keys as text, parameters of one role listed in name order. */
    public function testTheCatalogOfDefs(): void
    {
        self::assertSame(['5', '7'], GoalSelectors::selCatalogOfDefs([], ['7' => [], '5' => []])->get('known'));
        $d0 = ActionsBuiltin::builtinDefs()[0];
        $params = new Obj();
        foreach ($d0->get('params')->keys() as $k) {
            $params->set($k, $d0->get('params')->get($k));
        }
        $params->set('acct', Obj::of(['type' => 'string', 'max_len' => 128, 'role' => 'id.stripe.customer']));
        $d = $d0->without('params');
        $d->set('params', $params);
        $roles = GoalSelectors::selCatalogOfDefs([$d])->get('verbs')[0]->get('roles');
        self::assertSame(['acct', 'customer'], $roles->get('id.stripe.customer'));
        self::assertSame(['amount'], $roles->get('money.amount'));
    }

    /** A domain catalog with a registry is refused; an unknown domain is a type error naming it. */
    public function testDomainCatalogs(): void
    {
        self::assertSame('LogicException: only the shipped trait registry is derived natively', self::thrown(static fn() => GoalSelectors::selCatalogOfDomain('payments', [])));
        self::assertSame('TypeError: unknown domain "zz_none"', self::thrown(static fn() => GoalSelectors::selCatalogOfDomain('zz_none')));
    }

    /** declOf / infoOf are public lookups; resolveRole is null without a declaration, with a non-object roles map, or with a non-string role. */
    public function testRoleResolution(): void
    {
        $ont = Obj::of(['verbs' => [Obj::of(['verb' => 'v', 'params' => [Obj::of(['path' => 'p', 'ty' => Obj::of(['k' => 's'])])]])]]);
        $cat = Obj::of(['verbs' => [Obj::of(['verb' => 'v', 'roles' => Obj::of(['5' => ['p'], 'r' => ['p']])])]]);
        self::assertSame($ont->get('verbs')[0], GoalSelectors::declOf($ont, 'v'));
        self::assertSame($cat->get('verbs')[0], GoalSelectors::infoOf($cat, 'v'));
        self::assertSame('{"path":"p","ty":{"k":"s"}}', Json::stringify(GoalSelectors::resolveRole($ont, $cat, 'v', 'r')));
        self::assertNull(GoalSelectors::resolveRole(Obj::of(['verbs' => []]), $cat, 'v', 'r'), 'no declaration');
        self::assertNull(GoalSelectors::resolveRole($ont, Obj::of(['verbs' => [Obj::of(['verb' => 'v', 'roles' => []])]]), 'v', 'r'), 'roles is not an object');
        self::assertNull(GoalSelectors::resolveRole($ont, $cat, 'v', 5), 'a non-string role');
    }

    /** Two verbs whose role parameter shares a path but whose type is null for one and absent for the other have no common value term. */
    public function testNullAndAbsentTypesDiffer(): void
    {
        $ont = Obj::of(['verbs' => [Obj::of(['verb' => 'v1', 'params' => [Obj::of(['path' => 'p', 'ty' => null])]]), Obj::of(['verb' => 'v2', 'params' => [Obj::of(['path' => 'p'])]])]]);
        $cat = Obj::of(['known' => [], 'verbs' => [Obj::of(['verb' => 'v1', 'traits' => [], 'roles' => Obj::of(['amt' => ['p']])]), Obj::of(['verb' => 'v2', 'traits' => [], 'roles' => Obj::of(['amt' => ['p']])])]]);
        $b = Obj::of(['bid' => 'b', 'sel' => Obj::of(['k' => 'gids', 'gids' => ['g1', 'g2']]), 'agg' => 'sum', 'value' => Obj::of(['k' => 'role', 'role' => 'amt'])]);
        $x = GoalSelectors::expandSelGoal(self::sg([self::grant('g1', 'v1'), self::grant('g2', 'v2')], [$b]), $ont, $cat);
        self::assertSame([], $x->get('goal')->get('bounds'));
        self::assertSame([], $x->get('report')->get('bounds'));
    }

    /** Paths that differ with one type: the role key, typed with the FIRST verb's type object. */
    public function testTheRoleKeyUsesTheFirstType(): void
    {
        $t0 = Obj::of(['k' => 's']);
        $t1 = Obj::of(['k' => 's']);
        $ont = Obj::of(['verbs' => [Obj::of(['verb' => 'v1', 'params' => [Obj::of(['path' => 'p1', 'ty' => $t0])]]), Obj::of(['verb' => 'v2', 'params' => [Obj::of(['path' => 'p2', 'ty' => $t1])]])]]);
        $cat = Obj::of(['known' => [], 'verbs' => [Obj::of(['verb' => 'v1', 'traits' => [], 'roles' => Obj::of(['amt' => ['p1']])]), Obj::of(['verb' => 'v2', 'traits' => [], 'roles' => Obj::of(['amt' => ['p2']])])]]);
        $b = Obj::of(['bid' => 'b', 'sel' => Obj::of(['k' => 'gids', 'gids' => ['g1', 'g2']]), 'agg' => 'sum', 'value' => Obj::of(['k' => 'role', 'role' => 'amt'])]);
        $x = GoalSelectors::expandSelGoal(self::sg([self::grant('g1', 'v1'), self::grant('g2', 'v2')], [$b]), $ont, $cat);
        $v = $x->get('goal')->get('bounds')[0]->get('value');
        self::assertSame('@amt', $v->get('path'));
        self::assertSame($t0, $v->get('ty'));
        self::assertSame('role_key', $x->get('report')->get('bounds')[0]->get('value'));
    }

    /** A bound selector of an unknown kind has no grant ids: the expansion throws. */
    public function testAnUnknownBoundSelectorThrows(): void
    {
        $ont = Obj::of(['verbs' => [Obj::of(['verb' => 'v1', 'params' => []])]]);
        $b = Obj::of(['bid' => 'b', 'sel' => Obj::of(['k' => 'zz']), 'agg' => 'count', 'value' => Obj::of(['k' => 'lit', 'v' => 1])]);
        self::assertSame('TypeError: cannot read properties of undefined (reading length)',
            self::thrown(static fn() => GoalSelectors::expandSelGoal(self::sg([self::grant('g1', 'v1')], [$b]), $ont, self::emptyCat())));
    }

    /** catalog_mismatch: exactly when a catalog verb has no declaration; the first one stops the scan (a later null is never read). */
    public function testCatalogMismatch(): void
    {
        $ont = Obj::of(['verbs' => [Obj::of(['verb' => 'v', 'params' => []])]]);
        $ok = Obj::of(['known' => [], 'verbs' => [Obj::of(['verb' => 'v', 'traits' => [], 'roles' => new Obj()])]]);
        self::assertSame([], GoalSelectors::selReasons(self::sg([], [], $ok), $ont, $ok));
        $bad = Obj::of(['known' => [], 'verbs' => [Obj::of(['verb' => 'zz', 'traits' => [], 'roles' => new Obj()])]]);
        self::assertSame(['catalog_mismatch'], GoalSelectors::selReasons(self::sg([], [], $bad), $ont, $bad));
        $badNull = Obj::of(['known' => [], 'verbs' => [Obj::of(['verb' => 'zz', 'traits' => [], 'roles' => new Obj()]), null]]);
        self::assertSame(['catalog_mismatch'], GoalSelectors::selReasons(self::sg([], [], $badNull), $ont, $badNull));
    }

    /** compileSelGoal: the given compiler's verdict is wrapped (ok: policy, goal, report; else ok false and the reasons). */
    public function testCompileWithAGivenCompiler(): void
    {
        $cat = self::emptyCat();
        $ont = Obj::of(['verbs' => []]);
        $ok = GoalSelectors::compileSelGoal(self::sg([], [], $cat), $ont, $cat, static fn($g, $o) => Obj::of(['ok' => true, 'policy' => 'P']));
        self::assertSame(['ok', 'policy', 'goal', 'report'], $ok->keys());
        self::assertTrue($ok->get('ok'));
        self::assertSame('P', $ok->get('policy'));
        self::assertInstanceOf(Obj::class, $ok->get('goal'));
        self::assertSame(['grants', 'prohibits', 'bounds'], $ok->get('report')->keys());
        $no = GoalSelectors::compileSelGoal(self::sg([], [], $cat), $ont, $cat, static fn($g, $o) => Obj::of(['ok' => false, 'reasons' => ['s']]));
        self::assertSame('{"ok":false,"reasons":["s"]}', Json::stringify($no));
    }

    /** With no compiler given, the package's own compiler is loaded and used. */
    public function testCompileWithThePackageCompiler(): void
    {
        $cat = self::emptyCat();
        $ont = Obj::of(['verbs' => []]);
        $own = self::thrown(static fn() => GoalSelectors::compileSelGoal(self::sg([], [], $cat), $ont, $cat));
        $given = self::thrown(static fn() => GoalSelectors::compileSelGoal(self::sg([], [], $cat), $ont, $cat, GoalCompiler::compileGoal(...)));
        self::assertSame($given, $own);
    }

    /** The card names traits by the given registry's phrases; a non-string trait id is its own text even when the registry has that key. */
    public function testTheCardUsesTheGivenRegistry(): void
    {
        $grant = Obj::of(['gid' => 'rd', 'sel' => Obj::of(['k' => 'class', 'all_of' => ['t1', 5], 'none_of' => []]), 'res' => Obj::of(['k' => 'any', 'reason' => 'x']), 'cond' => Obj::of(['k' => 'true'])]);
        $sg = self::sg([$grant], []);
        foreach (['v' => 2, 'principal' => 'pr1', 'ontDigest' => 'ont', 'nlDigest' => 'nl', 'sources' => [], 'escalateOn' => []] as $k => $v) {
            $sg->set($k, $v);
        }
        $sg->set('validity', Obj::of(['notBefore' => 0, 'notAfter' => 3500000000000, 'maxIdle' => 0]));
        $sg->set('deleg', Obj::of(['maxDepth' => 1, 'narrowOnly' => true, 'mayTouch' => []]));
        $cat = Obj::of(['known' => ['t1'], 'verbs' => [Obj::of(['verb' => 'v', 'traits' => ['t9'], 'roles' => new Obj()])]]);
        $reg = ['t1' => ['card_phrase' => 'TEE'], '5' => ['card_phrase' => 'five']];
        $card = GoalSelectors::renderSelCard($sg, Obj::of(['verbs' => [Obj::of(['verb' => 'v', 'cls' => 'reversible', 'params' => []])]]), $cat, $reg);
        self::assertSame('ALLOW "rd": every action that TEE and 5 [0 verb(s) in the pinned catalog: ]', $card->get('lines')[0]);
    }

    /** traitClosure uses the given registry. */
    public function testTraitClosureUsesTheGivenRegistry(): void
    {
        self::assertSame(['t1', 't2'], GoalSelectors::traitClosure(['t1'], ['t1' => ['implies' => ['t2']], 't2' => ['implies' => []]]));
    }

    /** The carrier joins a selector's trait list like Array.prototype.join: null and undefined are empty. */
    public function testTheCarrierJoin(): void
    {
        $sel = Obj::of(['k' => 'class', 'all_of' => [null, AnalyzerJs::undef(), 'a'], 'none_of' => ['b']]);
        $sg = Obj::of(['grants' => [Obj::of(['gid' => 'g', 'sel' => $sel, 'cond' => Obj::of(['k' => 'true'])])], 'prohibits' => [], 'bounds' => []]);
        self::assertSame("C\x01\x02\x02a\x01b", GoalSelectors::selCarrier($sg)->get('grants')[0]->get('verb'));
    }
}
