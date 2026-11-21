<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrontierSignals.php';

use Atlas\Pca\FrontierSignals;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The tighten-or-escalate signals of the intent-frontier results against the TS reference: every case of
 * test-data/ref-frontier-signals.json.gz and the signal cases of test-data/ref-core-sweep-java.json.gz (shared by several modules, each
 * replays its own functions and asserts their counts). {"$num": ...} is a non-finite double, in arguments and in results.
 */
final class RefFrontierSignalsDifferentialTest extends TestCase
{
    private const FILE = 'ref-frontier-signals.json.gz';
    private const SHARED = ['ref-core-sweep-java.json.gz' => ['semanticSignal' => 26, 'progressSignal' => 26, 'objectiveSignal' => 26, 'tightenRiskInputs' => 121]];

    public static function provide(): array
    {
        $out = Base::datasets(self::FILE);
        foreach (self::SHARED as $file => $fns) {
            foreach (Base::datasets($file) as $k => $v) {
                if (isset($fns[$v[1]])) {
                    $out["$file $k"] = $v;
                }
            }
        }
        return $out;
    }

    private static function un(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::un($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::un(...), $v) : $v;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'semanticSignal' => static fn(array $a) => FrontierSignals::semanticSignal(self::un($a[0])),
            'progressSignal' => static fn(array $a) => FrontierSignals::progressSignal(self::un($a[0])),
            'objectiveSignal' => static fn(array $a) => FrontierSignals::objectiveSignal(self::un($a[0])),
            'tightenRiskInputs' => static fn(array $a) => FrontierSignals::tightenRiskInputs(self::un($a[0]), self::un($a[1])),
        ]);
    }

    public function testCorporaHaveTheExpectedCaseTotals(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(690, $n);
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
