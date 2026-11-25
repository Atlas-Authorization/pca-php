<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/BudgetForecast.php';
require_once __DIR__ . '/../src/PolicySim.php';
require_once __DIR__ . '/../src/Facade.php';

use Atlas\Pca\BudgetForecast;
use Atlas\Pca\Catalog;
use Atlas\Pca\Facade;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\PolicySim;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Budget forecasting and policy simulation against the TS reference: every case of test-data/ref-budget-forecast.json.gz (forecast,
 * recommendPolicy, autonomyBoundOf), the policy simulator's cases of test-data/ref-core-research-java.json.gz (simulate, lintPolicy) and
 * the forecast cases of test-data/ref-core-sweep-java.json.gz (recommendPolicy, autonomyBoundOf); those two corpora are shared by
 * several modules, each replays its own functions and asserts their counts. A spec `{permissions, limits?, budgetModel?,
 * riskPolicy?, now}` is compiled with the facade; {"$num": ...} is that non-finite double, in arguments and in results.
 */
final class RefBudgetForecastDifferentialTest extends TestCase
{
    private const FORECAST = 'ref-budget-forecast.json.gz';
    private const SHARED = ['ref-core-research-java.json.gz' => ['simulate' => 189, 'lintPolicy' => 9],
        'ref-core-sweep-java.json.gz' => ['recommendPolicy' => 110, 'autonomyBoundOf' => 10]];

    public static function provide(): array
    {
        $out = Base::datasets(self::FORECAST);
        foreach (self::SHARED as $file => $fns) {
            foreach (Base::datasets($file) as $k => $v) {
                if (isset($fns[$v[1]])) {
                    $out["$file $k"] = $v;
                }
            }
        }
        return $out;
    }

    private static function plain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
            }
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::plain($v->get($k));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::plain(...), $v) : ($v instanceof Num ? $v->float() : $v);
    }

    /** {"$num"} to the double; everything else as parsed. */
    private static function un(mixed $v): mixed
    {
        if ($v instanceof Obj && $v->keys() === ['$num']) {
            return self::plain($v);
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::un($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::un(...), $v) : $v;
    }

    private static function out(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::out(...), $v);
        }
        return is_float($v) && !is_finite($v) ? Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]) : $v;
    }

    /** @return array<string,mixed> the compiled policy of a spec */
    private static function compile(Obj $sp): array
    {
        $rp = $sp->get('riskPolicy');
        return Facade::compilePolicy($sp->get('permissions'), $sp->get('limits'), null, $sp->get('budgetModel'), $rp instanceof Obj ? self::plain($rp) : null, (int)$sp->get('now')->float());
    }

    private static function start(mixed $s): int|float
    {
        return $s === null ? 0 : $s->float();
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'forecast' => static fn(array $a) => BudgetForecast::forecast(self::compile($a[0]), $a[1], self::start($a[2]),
                $a[3] === null ? null : Catalog::buildCatalog(array_map(Catalog::defineAction(...), self::plain($a[3])))),
            'recommendPolicy' => static fn(array $a) => BudgetForecast::recommendPolicy(self::un($a[0]), self::un($a[1]), self::un($a[2])),
            'autonomyBoundOf' => static fn(array $a) => self::out(BudgetForecast::autonomyBoundOf(self::un($a[0]))),
            'simulate' => static fn(array $a) => PolicySim::simulate(self::compile($a[0]), $a[1], null, self::start($a[2])),
            'lintPolicy' => static fn(array $a) => PolicySim::lintPolicy(self::compile($a[0])),
        ]);
    }

    public function testCorporaHaveTheExpectedCaseTotals(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FORECAST)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(326, $n);
        foreach (self::SHARED as $file => $fns) {
            $have = array_fill_keys(array_keys($fns), 0);
            foreach (gzfile(Base::path($file)) as $line) {
                foreach ($have as $fn => $_) {
                    $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
                }
            }
            $this->assertSame($fns, $have, $file);
        }
    }
}
