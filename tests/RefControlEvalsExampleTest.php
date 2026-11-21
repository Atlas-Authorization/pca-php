<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AgentHandle;
use Atlas\Pca\ControlEnv;
use Atlas\Pca\ControlEvals;
use Atlas\Pca\ControlEvalsExample;
use Atlas\Pca\Obj;
use Atlas\Pca\RedPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The example blue control protocol (replay, the grant's review, DLP, the budget under the immune-adapted policy) against the reference's own
 * recorded runs: every runEpisode / controlEval case of the control-evaluation corpus is run through the NATIVE protocol and must equal the
 * reference's transcript and report (outcome, control, risk, threat level, reason, budget).
 */
final class RefControlEvalsExampleTest extends TestCase
{
    private const FILE = 'ref-control-evals.json.gz';
    private static ?AgentHandle $agent = null;

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(string $name): bool => str_starts_with($name, 'runEpisode ') || str_starts_with($name, 'controlEval '), ARRAY_FILTER_USE_KEY);
    }

    private static function agent(): AgentHandle
    {
        return self::$agent ??= ControlEvalsExample::buildExampleAgent();
    }

    private static function red(string $name): RedPolicy
    {
        return match ($name) {
            'over-cap' => ControlEvals::overCapRed(), 'off-verb' => ControlEvals::offVerbRed(), 'slow-burn' => ControlEvals::slowBurnRed(),
            'taint-exfil' => ControlEvals::taintExfilRed(), 'replay' => ControlEvals::replayRed(), 'immune-probe' => ControlEvals::immuneProbeBurstRed(),
            'benign' => ControlEvals::benignBaselineRed(), 'gap-exploit' => ControlEvals::gapExploitRed(),
        };
    }

    private static function env(string $name): ControlEnv
    {
        if ($name === 'example') {
            return ControlEvals::exampleEnv();
        }
        return $name === 'gap-aware' ? ControlEvals::gapAwareEnv() : ControlEvals::gapAwareEnv(substr($name, strlen('gap-aware:')));
    }

    #[DataProvider('provide')]
    public function testDecidesLikeTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'runEpisode' => fn(array $a) => ControlEvals::runEpisode(
                self::red($a[0]->get('red')),
                ControlEvalsExample::exampleBlue(self::agent()),
                self::env($a[0]->get('env')),
                $a[0]->get('seed'),
            ),
            'controlEval' => function (array $a) {
                $spec = $a[0];
                $r = $spec->get('reds');
                $reds = is_array($r) ? array_map(fn($n) => self::red($n), $r) : $r;
                return ControlEvals::controlEval($reds, ControlEvalsExample::exampleBlue(self::agent()), self::env($spec->get('env')), $spec->get('episodes'), $spec->get('seed'));
            },
        ]);
    }

    public function testExampleControlEvalIsDeterministicAndScoresEveryStrategy(): void
    {
        $r = ControlEvalsExample::exampleControlEval();
        $reds = ControlEvals::exampleRedPolicies();
        $this->assertSame(8 * count($reds), $r->get('episodes'));
        $this->assertSame(count(array_unique(array_map(static fn(RedPolicy $p) => $p->strategy, $reds))), count($r->get('byStrategy')->keys()));
        $this->assertSame(Base::canon($r), Base::canon(ControlEvalsExample::exampleControlEval()));
        $this->expectException(\InvalidArgumentException::class);
        ControlEvalsExample::exampleControlEval(0, 1);
    }
}
