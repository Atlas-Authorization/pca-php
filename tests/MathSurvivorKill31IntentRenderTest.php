<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentRender.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\Catalog;
use Atlas\Pca\IntentRender;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of render.ts: catalog lookup, list guards, lowerFirst, toISOString, the claim IR and the claim diff kinds. */
final class MathSurvivorKill31IntentRenderTest extends TestCase
{
    private static function call(string $fn, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentRender::class, $fn))->invoke(null, ...$a);
    }

    private static function j(mixed $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    private static function typeErr(?string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\TypeError $e) {
            if ($msg !== null) {
                self::assertSame($msg, $e->getMessage());
            }
            self::assertInstanceOf(\TypeError::class, $e);
            return;
        }
        self::fail('no TypeError');
    }

    /** Runs $f and asserts it raised no PHP warning or notice. */
    private static function quiet(callable $f): mixed
    {
        $w = [];
        set_error_handler(static function (int $no, string $msg) use (&$w): bool {
            $w[] = $msg;
            return true;
        });
        try {
            $r = $f();
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $w);
        return $r;
    }

    /** A Catalog, an Obj map, a list (later specs win; non-spec members skipped), the built-in list for null / undefined; a scalar refuses. */
    public function testCatalogGet(): void
    {
        self::assertSame('stripe.refund', IntentRender::catalogGet(new Catalog(), 'stripe.refund')->get('verb'));
        self::assertNull(IntentRender::catalogGet(new Catalog(), 'zz'));
        $spec = Obj::of(['verb' => 'x']);
        self::assertSame($spec, IntentRender::catalogGet(Obj::of(['x' => $spec]), 'x'));
        $list = [['verb' => 'x', 'description' => 'D'], Obj::of(['verb' => 'y']), 'junk', ['a', 'b'], ['verb' => 'x', 'description' => 'E']];
        self::assertSame('E', self::quiet(fn() => IntentRender::catalogGet($list, 'x'))->get('description'));
        self::assertSame('y', IntentRender::catalogGet($list, 'y')->get('verb'));
        self::assertNull(IntentRender::catalogGet($list, 'stripe.refund'), 'a given list replaces the built-in one');
        foreach ([null, AnalyzerJs::undef()] as $c) {
            self::assertSame('stripe.refund', IntentRender::catalogGet($c, 'stripe.refund')->get('verb'));
        }
        self::typeErr('catalog is not iterable', fn() => IntentRender::catalogGet('str', 'x'));
    }

    /** A where list must be a list: a string or a map refuses, null is empty; a non-object condition is unreadable. */
    public function testListGuardAndUnreadableCondition(): void
    {
        self::typeErr('map is not a function', fn() => self::call('arr', 'x'));
        self::typeErr('map is not a function', fn() => self::call('arr', ['a' => 1]));
        self::assertSame([], self::call('arr', null));
        foreach (['x', 5] as $c) {
            self::assertSame('an unreadable condition (not understood)', IntentRender::renderCondition($c));
        }
    }

    /** lowerFirst lowers the first character (multibyte too), keeps a leading newline, the empty string and a non-BMP first character. */
    public function testLowerFirst(): void
    {
        self::assertSame("a\n", self::call('lowerFirst', "A\n"));
        self::assertSame("\nAb", self::call('lowerFirst', "\nAb"));
        self::assertSame('éa', self::call('lowerFirst', 'Éa'));
        self::assertSame('', self::quiet(fn() => self::call('lowerFirst', '')));
        self::assertSame("\u{10400}X", self::call('lowerFirst', "\u{10400}X"), 'the reference lowers one UTF-16 unit, half of this pair');
    }

    /** A catalogued verb needs its reversibility (the reference's .replace throws); a present one is dashed. */
    public function testRenderVerbReversibility(): void
    {
        self::assertSame('do it [x, rate-limited]', self::call('renderVerb', 'x', [['verb' => 'x', 'description' => 'Do it.', 'reversibility' => 'rate_limited']]));
        self::typeErr(null, fn() => self::call('renderVerb', 'x', [['verb' => 'x', 'description' => 'Do it.']]));
    }

    /** new Date(t).toISOString() as node prints it: leap days, century rules, year 0, negative and expanded years, minutes. */
    public function testIso(): void
    {
        $want = [
            [951782400000, '2000-02-29T00:00:00.000Z'], [951868800000, '2000-03-01T00:00:00.000Z'], [4107542400000, '2100-03-01T00:00:00.000Z'],
            [1709164800000, '2024-02-29T00:00:00.000Z'], [-62167219200000, '0000-01-01T00:00:00.000Z'], [60000, '1970-01-01T00:01:00.000Z'],
            [-62162121600000, '0000-02-29T00:00:00.000Z'], [-74784816000000, '-000400-03-01T00:00:00.000Z'], [954460800000, '2000-03-31T00:00:00.000Z'],
            [962409600000, '2000-07-01T00:00:00.000Z'], [-4117156787527519, '-128498-07-01T08:47:52.481Z'], [-2197258072846079, '-067659-08-31T07:19:13.921Z'],
            [253402300800000, '+010000-01-01T00:00:00.000Z'], [-1, '1969-12-31T23:59:59.999Z'],
        ];
        foreach ($want as [$t, $s]) {
            self::assertSame($s, self::call('iso', $t), "iso($t)");
        }
    }

    /** The values of a dimension are listed in cell order even when the admitted cells meet them out of order. */
    public function testClaimValuesSorted(): void
    {
        $f = static fn(string $field, string $op, mixed $v) => ['field' => $field, 'op' => $op, 'value' => $v];
        $amt = 'action.params.amount';
        $cur = 'action.params.currency';
        $policy = ['predicates' => [
            ['verb' => 'stripe.refund', 'resource' => '/acct/*', 'where' => [$f($amt, 'lte', 250), $f($cur, 'eq', 'usd')]],
            ['verb' => 'stripe.refund', 'resource' => '/acct/*', 'where' => [$f($amt, 'gt', 500), $f($cur, 'eq', 'eur')]],
        ]];
        $omega = ['v' => 1, 'verbs' => [['verb' => 'stripe.refund', 'reversibility' => 'irreversible', 'weight' => 1, 'dims' => [
            ['kind' => 'num', 'path' => $amt, 'lo' => 0, 'hi' => 100000, 'cuts' => [250, 500], 'dist' => 'loguniform'],
            ['kind' => 'cat', 'path' => $cur, 'values' => [['kind' => 'exact', 'value' => 'eur'], ['kind' => 'exact', 'value' => 'usd'], ['kind' => 'other', 'value' => "\u{22a5}"]]],
            ['kind' => 'cat', 'path' => 'action.resource', 'values' => [['kind' => 'prefix', 'value' => '/acct/'], ['kind' => 'other', 'value' => "\u{22a5}"]]],
        ]]], 'approximate' => []];
        $c = IntentRender::claimsOf(self::j($policy), self::j($omega));
        self::assertSame(['eur', 'usd'], $c[0]['dims'][1]['values']);
    }

    /** @return list<string> the diff kinds of one allowed verb with the given dimension claims */
    private static function kinds(array $gd, array $sd, bool $gBox = true, bool $sBox = true): array
    {
        $w = ['extra' => fn($v) => 'e', 'missing' => fn($v) => 'm', 'shape' => fn($v) => 's', 'dim' => fn($v, $p, $a, $b) => 'd'];
        $g = [['verb' => 'v', 'allowed' => true, 'boxShaped' => $gBox, 'dims' => $gd]];
        $s = [['verb' => 'v', 'allowed' => true, 'boxShaped' => $sBox, 'dims' => $sd]];
        return array_map(fn(array $x) => $x['kind'], self::call('diffClaims', $g, $s, $w));
    }

    /** Shape only when exactly one side is box-shaped; range and any-only kinds from the first side's point of view. */
    public function testDiffKinds(): void
    {
        self::assertSame([], self::kinds([], [], false, false));
        self::assertSame(['shape'], self::kinds([], [], true, false));
        $r = fn(int $lo, int $hi) => [['path' => 'p', 'any' => false, 'range' => [$lo, $hi]]];
        self::assertSame(['looser'], self::kinds($r(0, 10), $r(5, 10)));
        self::assertSame(['different'], self::kinds($r(0, 5), $r(3, 10)));
        self::assertSame(['tighter'], self::kinds($r(5, 10), $r(0, 10)));
        $mixed = fn(bool $ga, bool $sa) => self::kinds([['path' => 'p', 'any' => $ga, 'range' => [1, 2]]], [['path' => 'p', 'any' => $sa, 'values' => ['x']]]);
        self::assertSame([['looser'], ['different'], ['different'], ['different']], [$mixed(true, false), $mixed(false, false), $mixed(false, true), $mixed(true, true)]);
    }

    /** renderAction: no values object lists nothing; a catalogued verb needs vs.reversibility and dashes it. */
    public function testRenderAction(): void
    {
        self::assertSame('The agent wants to: perform "zz" [uncatalogued: treated as irreversible].', IntentRender::renderAction(Obj::of(['verb' => 'zz']), null));
        self::assertSame('The agent wants to: Returns money for a charge to the customer [stripe.refund, irreversible].',
            IntentRender::renderAction(Obj::of(['verb' => 'stripe.refund', 'reversibility' => 'irreversible']), null));
        self::typeErr(null, fn() => IntentRender::renderAction(Obj::of(['verb' => 'stripe.refund']), null));
    }
}
