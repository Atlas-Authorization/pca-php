<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalDrift.php';

/** The stateful drift monitor of {@see GoalDrift}: strikes, the recent action times, novel resources and the per-parameter history. */
final class GoalDriftMonitor
{
    /** The monitor state `{strikes, times, novel, seen}`. */
    public Obj $st;
    public readonly Obj $o;

    /** @param mixed $opts an Obj or an assoc array of the options (windowMs, maxPerWindow, maxNovel, magnitudeFactor, warmup, lockdown) */
    public function __construct(private readonly mixed $goal, mixed $opts = null)
    {
        $o = GoalDrift::defaultDrift();
        if ($opts instanceof Obj) {
            foreach ($opts->keys() as $k) {
                $o->set($k, $opts->get($k));
            }
        } elseif (is_array($opts) && !array_is_list($opts)) {
            foreach ($opts as $k => $v) {
                $o->set((string)$k, $v);
            }
        }
        $this->o = $o;
        $this->st = self::fresh(0);
    }

    private static function fresh(mixed $strikes): Obj
    {
        return Obj::of(['strikes' => $strikes, 'times' => [], 'novel' => [], 'seen' => new Obj()]);
    }

    private static function out(float $f): int|float
    {
        return is_finite($f) && $f == floor($f) && abs($f) < 9007199254740992.0 ? (int)$f : $f;
    }

    private static function n(mixed $v): float
    {
        return AnalyzerJs::toNumber($v);
    }

    /** Observe one action `{verb, res, params, ...}` at time `$t`: the signal `{anomalous, strikes, lockdown, reasons}`. */
    public function observe(mixed $a, mixed $t): Obj
    {
        $reasons = [];
        $verb = AnalyzerJs::jget($a, 'verb');
        if (!AnalyzerJs::includes(GoalDrift::expectedVerbs($this->goal), $verb)) {
            $reasons[] = 'verb ' . AnalyzerJs::jsStr($verb) . ' outside the goal profile';
        }
        $known = GoalDrift::knownResources($this->goal);
        $res = AnalyzerJs::jget($a, 'res');
        $novel = AnalyzerJs::reqList($this->st->get('novel'));
        if ($known !== [] && !AnalyzerJs::includes($known, $res) && !AnalyzerJs::includes($novel, $res)) {
            $novel[] = $res;
            $this->st->set('novel', $novel);
        }
        if (AnalyzerJs::jsGt(count($novel), $this->o->get('maxNovel'))) {
            $reasons[] = 'novel resources beyond the allowance';
        }
        $cut = self::n($t) - self::n($this->o->get('windowMs'));
        $times = [];
        foreach (AnalyzerJs::reqList($this->st->get('times')) as $x) {
            if (AnalyzerJs::jsGt($x, $cut)) {
                $times[] = $x;
            }
        }
        $times[] = $t;
        $this->st->set('times', $times);
        if (AnalyzerJs::jsGt(count($times), $this->o->get('maxPerWindow'))) {
            $reasons[] = 'rate above the profile';
        }
        $params = AnalyzerJs::jget($a, 'params');
        $seen = $this->st->get('seen');
        foreach (GoalJs::okeys($params) as $p) {
            $l = GoalJs::kget($params, $p);
            if (AnalyzerJs::jget($l, 'k') !== 'q') {
                continue;
            }
            $hist = $seen->get($p) ?? [];
            $v = AnalyzerJs::jget(AnalyzerJs::jget($l, 'q'), 'n');
            $hist = AnalyzerJs::reqList($hist);
            if (self::n(count($hist)) >= self::n($this->o->get('warmup'))) {
                $sum = 0.0;
                foreach ($hist as $x) {
                    $sum += self::n($x);
                }
                $mean = fdiv($sum, (float)count($hist));
                if ($mean > 0 && AnalyzerJs::jsGt($v, $mean * self::n($this->o->get('magnitudeFactor')))) {
                    $reasons[] = $p . ' magnitude ' . AnalyzerJs::jsStr($this->o->get('magnitudeFactor')) . 'x above the running mean';
                }
            }
            $hist[] = $v;
            $seen->set($p, array_slice($hist, -50));
        }
        if ($reasons !== []) { // ratchet: only ever increases
            $this->st->set('strikes', self::out(self::n($this->st->get('strikes')) + 1));
        }
        $strikes = $this->st->get('strikes');
        return Obj::of(['anomalous' => $reasons !== [], 'strikes' => $strikes, 'lockdown' => self::n($strikes) >= self::n($this->o->get('lockdown')),
            'reasons' => $reasons]);
    }

    public function state(): Obj
    {
        return $this->st;
    }

    private static function mac(mixed $state, string $key): string
    {
        return hash_hmac('sha256', Js::utf8(Js::stringify($state)), $key, true);
    }

    /** Sealed state `{state, mac}`: durable and not agent-writable (the monitor key is held outside the agent). */
    public function seal(string $key): Obj
    {
        return Obj::of(['state' => $this->st, 'mac' => bin2hex(self::mac($this->st, $key))]);
    }

    /** Restore; a state that fails its MAC locks down (fail closed). */
    public static function restore(mixed $goal, mixed $sealed, string $key, mixed $opts = null): self
    {
        $m = new self($goal, $opts);
        $want = self::mac(AnalyzerJs::jget($sealed, 'state'), $key);
        $got = GoalDrift::nodeHex(AnalyzerJs::jget($sealed, 'mac'));
        $m->st = hash_equals($want, $got) ? AnalyzerJs::jget($sealed, 'state') : self::fresh($m->o->get('lockdown'));
        return $m;
    }
}
