<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalDrift.php';
require_once __DIR__ . '/../src/GoalDriftMonitor.php';
require_once __DIR__ . '/../src/GoalCrc.php';

use Atlas\Pca\GoalCrc;
use Atlas\Pca\GoalDrift;
use Atlas\Pca\GoalDriftMonitor;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The tighten-only drift monitor (driven through a step script, as the monitor is stateful), conformal risk control numerics and the
 * fidelity report against the TS reference: test-data/ref-goal-drift.json.gz.
 */
final class RefGoalDriftDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-drift.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function deep(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::deep($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::deep(...), $v) : $v;
    }

    private static function b64d(string $s): string
    {
        return (string)base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
    }

    private static function flow(array $a): array
    {
        [$goal, $opts, $steps] = $a;
        $mon = new GoalDriftMonitor($goal, $opts);
        $last = null;
        $out = [];
        foreach ($steps as $s) {
            switch ($s->get('op')) {
                case 'observe':
                    $out[] = $mon->observe($s->get('act'), $s->get('t'));
                    break;
                case 'state':
                    $out[] = self::deep($mon->state());
                    break;
                case 'seal':
                    $last = self::deep($mon->seal(self::b64d($s->get('key'))));
                    $out[] = $last;
                    break;
                case 'restoreLast':
                    $sealed = self::deep($last);
                    $mode = $s->get('mode');
                    if ($mode === 'state') {
                        $sealed->get('state')->set('strikes', 0);
                    }
                    if ($mode === 'mac') {
                        $m = $sealed->get('mac');
                        $sealed->set('mac', ($m[0] === '0' ? '1' : '0') . substr($m, 1));
                    }
                    if ($mode === 'badmac') {
                        $sealed->set('mac', 'zz');
                    }
                    $mon = GoalDriftMonitor::restore($goal, $sealed, self::b64d($s->get('key')), $opts);
                    $out[] = self::deep($mon->state());
                    break;
                case 'guarded':
                    $r = GoalDrift::guardedDecide($goal, $s->get('ont'), $mon, $s->get('case'), $s->get('t'));
                    $out[] = Obj::of(['decision' => $r->get('decision'), 'signal' => $r->get('signal')]);
                    break;
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'flow' => fn(array $a) => self::flow($a),
            'applyDrift' => fn(array $a) => GoalDrift::applyDrift($a[0], $a[1]),
            'alphaOf' => fn(array $a) => GoalCrc::alphaOf($a[0]),
            'calibrate' => function (array $a) {
                $gate = $a[2];
                $g = $gate === 'none' ? null : static fn($k, $n): bool => GoalCrc::cpUpper95($k, $n) <= (float)substr((string)$gate, 2) / 1e5;
                return GoalCrc::calibrate($a[0], $a[1], $g);
            },
            'assertMonotone' => function (array $a) {
                GoalCrc::assertMonotone($a[0]);
                return null;
            },
            'cpUpper95' => fn(array $a) => GoalCrc::cpUpper95($a[0], $a[1]),
            'renderReportMarkdown' => fn(array $a) => GoalCrc::renderReportMarkdown($a[0], $a[1]),
        ]);
    }
}
