<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalRoundtrip.php';

use Atlas\Pca\GoalRoundtrip;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The card tape round trip, widening mutations and the explainer + comparator detector against the TS reference:
 * test-data/ref-goal-roundtrip.json.gz. Injected explainers and comparators are chosen by mode name.
 */
final class RefGoalRoundtripDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-roundtrip.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function explainer(string $mode): \Closure
    {
        return static function (array $lines) use ($mode): string {
            if ($mode === 'throw') {
                throw new \RuntimeException('boom');
            }
            return implode("\n", $lines);
        };
    }

    private static function comparator(string $mode): \Closure
    {
        return static function (mixed $text, mixed $explanation) use ($mode): Obj {
            if ($mode === 'throw') {
                throw new \RuntimeException('boom');
            }
            if ($mode === 'ok') {
                return Obj::of(['equivalent' => true]);
            }
            if ($mode === 'no') {
                return Obj::of(['equivalent' => false, 'reason' => 'x']);
            }
            return Obj::of(['equivalent' => str_contains((string)$explanation, substr($mode, 9))]);
        };
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'cardRoundTrips' => fn(array $a) => GoalRoundtrip::cardRoundTrips($a[0]),
            'mutateGoal' => fn(array $a) => GoalRoundtrip::mutateGoal($a[0], $a[1], $a[2]),
            'roundTrip' => fn(array $a) => GoalRoundtrip::roundTrip($a[0], $a[1], self::explainer((string)$a[2]), self::comparator((string)$a[3])),
            'measureDetection' => fn(array $a) => GoalRoundtrip::measureDetection($a[0], $a[1], self::explainer((string)$a[2]), self::comparator((string)$a[3])),
        ]);
    }
}
