<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Approvals;
use Atlas\Pca\ControlEnv;
use Atlas\Pca\ControlEvals;
use Atlas\Pca\ControlEvalsExample;
use Atlas\Pca\ExampleBlue;
use Atlas\Pca\Facade;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\RedPolicy;
use PHPUnit\Framework\TestCase;

/**
 * The blue control protocol against the reference: the example agent (with its review battery), the example blue protocol, the decision
 * procedure behind every episode (replay, predicates and caveats, data-flow governance, the immune-adapted metered budget) and the example
 * evaluation: every case of test-data/ref-control-blue.json.gz, totals asserted. Numbers compare to a relative 1e-12 (the leak decays
 * exponentially). Counted deviation (asserted, never skipped): a params value that is not canonical JSON (a number past 2^53) makes the
 * reference throw out of the episode (5 cases); here the episode must throw or end in a non-allow at that action (fail closed).
 */
final class RefControlBlueDifferentialTest extends TestCase
{
    private const FILE = 'ref-control-blue.json.gz';
    private const FNS = ['buildExampleAgent' => 1, 'exampleBlue' => 3, 'blueEpisode' => 352, 'exampleEval' => 6];
    private const REFERENCE_REFUSALS = 5;

    private static function agent(string $name): AgentHandle
    {
        if ($name === 'example') {
            return ControlEvalsExample::buildExampleAgent();
        }
        return Facade::createAgent(KeyPair::generate(), 'handle refunds and customer email for October',
            ['stripe' => ['refund'], 'gmail' => ['send', 'draft'], 'files' => ['read', 'write'], 'github' => ['read']],
            $name === 'cap50' ? ['refund' => '$50/day'] : null, aud: 'ins_example', now: 0);
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
        return $name === 'example' ? ControlEvals::exampleEnv() : ControlEvals::gapAwareEnv();
    }

    /** @return array<string,float>|null */
    private static function floats(mixed $o): ?array
    {
        if (!($o instanceof Obj)) {
            return null;
        }
        $m = [];
        foreach ($o->keys() as $k) {
            $m[$k] = $o->get($k)->float();
        }
        return $m;
    }

    private static function blue(Obj $b): ExampleBlue
    {
        $a = self::agent($b->get('agent'));
        $base = $b->get('theta') === 'agent' ? \Atlas\Pca\Sign::n($a->policy['riskPolicy']) : ControlEvalsExample::exampleBlue($a)->base;
        $blue = new ExampleBlue($a, $base, $b->get('dlp') === false ? null : ControlEvals::exampleDlpPolicy(), self::floats($b->has('immune') ? $b->get('immune') : null),
            self::floats($b->has('adapt') ? $b->get('adapt') : null));
        // the analytic bound follows the base policy, exactly as ExampleBlue computes it for the example base
        if ($b->has('stepMs')) {
            $blue->stepMs = $b->get('stepMs')->float();
        }
        if ($b->has('startMs')) {
            $blue->startMs = $b->get('startMs')->float();
        }
        return $blue;
    }

    private static function episode(array $a): Obj
    {
        $spec = $a[0];
        $blue = self::blue($spec->get('blue'));
        if (isset($a[1])) {
            $list = $a[1];
            $red = new RedPolicy('custom', 'custom', static fn($ctx): array => $list);
        } else {
            $red = self::red($spec->get('red'));
        }
        return ControlEvals::runEpisode($red, $blue, self::env($spec->get('env')), $spec->get('seed'));
    }

    private static function battery(Obj $o): Obj
    {
        $a = ControlEvalsExample::buildExampleAgent();
        $p = $a->policy;
        $acts = [];
        foreach ($p['actions'] as $s) {
            $m = ['connector' => $s['connector'], 'action' => $s['action'], 'verb' => $s['verb'], 'reversibility' => $s['reversibility'], 'blastRadius' => $s['blastRadius']];
            foreach (['amountField', 'resource'] as $k) {
                if (isset($s[$k])) {
                    $m[$k] = $s[$k];
                }
            }
            $acts[] = $m;
        }
        $reviews = [];
        foreach ($o->get('reviews') as $e) {
            $params = $e->has('params') ? $e->get('params') : null;
            $r = Approvals::reviewAction($a, $e->get('verb'), $e->get('resource'), $params, (int)$e->get('now')->float(), insecureUnboundApproval: true);
            $rev = Obj::of(['kind' => $r['kind']]);
            if (isset($r['reason'])) {
                $rev->set('reason', $r['reason']);
            }
            $out = new Obj();
            foreach ($e->keys() as $k) {
                $out->set($k, $e->get($k));
            }
            $out->set('review', $rev);
            $reviews[] = $out;
        }
        return Obj::of(['policy' => [
            'predicates' => $p['predicates'], 'caveats' => $p['caveats'], 'riskPolicy' => $p['riskPolicy'], 'budgetModel' => $p['budgetModel'],
            'approximations' => $p['approximations'], 'inputLimits' => $p['inputLimits'], 'actions' => $acts], 'reviews' => $reviews]);
    }

    /** Structural equality, numbers to a relative 1e-12. */
    private static function same(mixed $w, mixed $g): bool
    {
        if (is_int($w) || is_float($w)) {
            return (is_int($g) || is_float($g)) && ($w == $g || abs($w - $g) <= 1e-12 * max(1.0, abs((float)$w)));
        }
        if ($w instanceof \stdClass) {
            if (!($g instanceof \stdClass)) {
                return false;
            }
            $a = (array)$w;
            $b = (array)$g;
            if (count($a) !== count($b)) {
                return false;
            }
            foreach ($a as $k => $v) {
                if (!array_key_exists($k, $b) || !self::same($v, $b[$k])) {
                    return false;
                }
            }
            return true;
        }
        if (is_array($w)) {
            if (!is_array($g) || count($w) !== count($g)) {
                return false;
            }
            foreach ($w as $i => $v) {
                if (!self::same($v, $g[$i])) {
                    return false;
                }
            }
            return true;
        }
        return $w === $g;
    }

    private static function plain(mixed $x): mixed
    {
        return json_decode(Base::canon($x));
    }

    public function testEveryCaseAgreesWithTheReference(): void
    {
        $seen = [];
        $bad = [];
        $deviations = 0;
        foreach (array_keys(self::FNS) as $fn) {
            for ($k = 0; ($cases = Base::cases(self::FILE, $fn, $k)) !== []; $k++) {
                foreach ($cases as $c) {
                    $seen[$fn] = ($seen[$fn] ?? 0) + 1;
                    $a = $c->get('args');
                    $want = $c->get('out');
                    $threw = null;
                    $have = null;
                    try {
                        $have = match ($fn) {
                            'buildExampleAgent' => self::battery($want),
                            'exampleBlue' => (static function (string $n): Obj {
                                $b = ControlEvalsExample::exampleBlue(self::agent($n));
                                return Obj::of(['name' => $b->name, 'basePolicy' => $b->base, 'dlp' => $b->dlp, 'startMs' => $b->startMs, 'stepMs' => $b->stepMs]);
                            })($a[0]),
                            'blueEpisode' => self::episode($a),
                            'exampleEval' => ControlEvalsExample::exampleControlEval($a[0]->get('episodes'), $a[0]->get('seed')),
                        };
                    } catch (\Throwable $e) {
                        $threw = $e;
                    }
                    $name = (string)$c->get('name');
                    if ($want instanceof Obj && $want->has('$throws')) {
                        $denied = false;
                        foreach ($have === null ? [] : $have->get('steps') as $s) {
                            $denied = $denied || $s->get('outcome') !== 'allow';
                        }
                        if ($threw === null && !$denied) {
                            $bad[] = "$name: the reference refuses non-canonical params, the native episode allowed everything";
                        } else {
                            $deviations++;
                        }
                        continue;
                    }
                    if ($threw !== null) {
                        $bad[] = "$name: threw " . get_class($threw) . ': ' . $threw->getMessage();
                    } elseif (!self::same(self::plain($want), self::plain($have))) {
                        $bad[] = "$name\n   want " . substr(Base::canon($want), 0, 600) . "\n   have " . substr(Base::canon($have), 0, 600);
                    }
                }
            }
        }
        $this->assertSame([], array_slice($bad, 0, 20), count($bad) . ' mismatches');
        $this->assertSame(self::FNS, $seen, 'every case of every fn replayed');
        $this->assertSame(self::REFERENCE_REFUSALS, $deviations, 'counted deviations: reference refusals of non-canonical params');
    }
}
