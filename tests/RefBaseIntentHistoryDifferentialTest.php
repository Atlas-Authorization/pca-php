<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentHistory;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The session-history base corpus against the TS reference (test-data/base-intenthistory.json.gz): window membership, accumulator keys, pre-states and post
 * values over hostile histories (junk entries, unreadable times, safe-integer edges, a candidate missing its key parameter) and the monitor folds. Where the
 * reference throws, the native throws; where it returns a value (a junk entry that is not an object is simply not counted) the native returns the same.
 */
final class RefBaseIntentHistoryDifferentialTest extends TestCase
{
    private const FILE = 'base-intenthistory.json.gz';
    private const FNS = ['accPost' => 14784, 'accPreState' => 11340, 'inWindow' => 1848, 'monitorStep' => 1003, 'accKeyOf' => 104, 'monitorState' => 100];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** {"$num": ...} to the double, at any depth. */
    private static function un(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::un(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if ($v->keys() === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::un($v->get($k)));
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'inWindow' => static fn(array $a) => IntentHistory::inWindow(self::un($a[0]), self::un($a[1]), self::un($a[2])),
            'accKeyOf' => static fn(array $a) => IntentHistory::accKeyOf($a[0], $a[1]),
            'accPreState' => static fn(array $a) => IntentHistory::accPreState($a[0], $a[1], $a[2]->get('params'), self::un($a[2]->get('t')), $a[3] ?? null),
            'accPost' => static fn(array $a) => IntentHistory::accPost($a[0], $a[1], $a[2]->get('verb'), $a[2]->get('params'), self::un($a[2]->get('t')), $a[3] ?? null),
            'monitorStep' => static fn(array $a) => IntentHistory::monitorStep($a[0], $a[1], $a[2]),
            'monitorState' => static fn(array $a) => IntentHistory::monitorState($a[0], $a[1]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
