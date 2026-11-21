<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalReview;
use Atlas\Pca\Js;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/GoalReview.php';

/**
 * Goal review against the TS reference: test-data/ref-goal-review.json.gz (the policy card, the semantic diff, the signed goal
 * approval and its loader) over the reference generator's stub kernel. The kernel mode travels in the options as `kmode`; the approval
 * key is derived from the base64url seed the case carries.
 */
final class RefGoalReviewDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-review.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /**
     * compile: no grants is {ok: false}; the policy digest is a hash of the stub policy; analyze: five grants are too many; decide: some
     * grant has the verb; newly allowed: the grants of next the previous goal lacks.
     */
    private static function stub(string $mode): Obj
    {
        $compile = static function ($g, $ont) use ($mode) {
            if ($mode === 'throwcompile') {
                throw new \RuntimeException('boom');
            }
            $grants = AnalyzerJs::jget($g, 'grants');
            return $grants === []
                ? Obj::of(['ok' => false, 'reasons' => ['empty']])
                : Obj::of(['ok' => true, 'policy' => Obj::of(['gids' => array_map(static fn($x) => AnalyzerJs::jget($x, 'gid'), $grants), 'n' => new Num((string)count($grants))])]);
        };
        $digest = static function ($p) use ($mode) {
            if ($mode === 'throwdigest') {
                throw new \RuntimeException('boom');
            }
            return Pca::hashCanonical(Obj::of(['d' => 'stub-policy', 'p' => $p]));
        };
        $decide = static function ($g, $ont, $act, $hist) {
            foreach (AnalyzerJs::jget($g, 'grants') as $x) {
                if (AnalyzerJs::strictEq(AnalyzerJs::jget($x, 'verb'), AnalyzerJs::jget($act, 'verb'))) {
                    return 'allow';
                }
            }
            return 'deny';
        };
        $newly = static function ($prev, $next, $ont = null, $limit = null) {
            $ws = [];
            foreach (AnalyzerJs::jget($next, 'grants') as $x) {
                $seen = false;
                foreach (AnalyzerJs::jget($prev, 'grants') as $y) {
                    $seen = $seen || AnalyzerJs::strictEq(AnalyzerJs::jget($y, 'gid'), AnalyzerJs::jget($x, 'gid'));
                }
                if (!$seen) {
                    $ws[] = Obj::of(['verb' => AnalyzerJs::jget($x, 'verb'), 'res' => 'r', 'params' => new Obj(), 't' => 0, 'sess' => 's', 'prin' => 'p', 'org' => 'o', 'agent' => 'a', 'depth' => 0]);
                }
            }
            return Obj::of(['witnesses' => $ws, 'complete' => true]);
        };
        $analyze = static fn($p) => Js::num(AnalyzerJs::jget($p, 'n')) >= 5 ? ['too many'] : [];
        $k = new Obj();
        $k->set('compile', $compile);
        $k->set('policyDigest', $digest);
        $k->set('analyze', $analyze);
        if ($mode !== 'nodecide') {
            $k->set('decide', $decide);
        }
        if ($mode !== 'nonewly') {
            $k->set('newlyAllowed', $newly);
        }
        return $k;
    }

    /** @return array{0:Obj,1:string} the options without `kmode`, and the kernel mode */
    private static function split(mixed $opts): array
    {
        $o = $opts instanceof Obj ? $opts : new Obj();
        $km = $o->get('kmode');
        return [$o->without('kmode'), is_string($km) ? $km : 'full'];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'effectiveLimits' => fn(array $a) => GoalReview::effectiveLimits($a[0] ?? null),
            'renderPolicyCard' => fn(array $a) => GoalReview::renderPolicyCard($a[0], $a[1] ?? null, $a[2] ?? null),
            'cardDigest' => fn(array $a) => GoalReview::cardDigest($a[0]),
            'cardToText' => fn(array $a) => GoalReview::cardToText($a[0]),
            'diffGoals' => function (array $a) {
                [$o, $km] = self::split($a[2] ?? null);
                return GoalReview::diffGoals($a[0], $a[1], self::stub($km), $o);
            },
            'diffToText' => fn(array $a) => GoalReview::diffToText($a[0]),
            'approveGoalSeed' => function (array $a) {
                [$o, $km] = self::split($a[2] ?? null);
                $o->set('kernel', self::stub($km));
                return GoalReview::approveGoal($a[0], $a[1] instanceof Obj ? Base::seedBytes($a[1]) : Pca::unb64u($a[1]), $o);
            },
            'loadApprovedGoal' => function (array $a) {
                [$o, $km] = self::split($a[2] ?? null);
                $o->set('kernel', self::stub($km));
                return GoalReview::loadApprovedGoal($a[0], $a[1], $o);
            },
        ]);
    }
}
