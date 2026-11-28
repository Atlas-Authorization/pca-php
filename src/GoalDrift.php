<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalExamples.php';
require_once __DIR__ . '/GoalDriftMonitor.php';

/**
 * Runtime drift monitoring, tighten-only. A monitor ({@see GoalDriftMonitor}) compares the action stream to the goal's expected
 * profile (verbs, resources, magnitude, rate, novelty). Anomalies convert Allow to Escalate; the strike counter is a ratchet (never
 * decreases); at `lockdown` strikes every Allow becomes Escalate. `applyDrift` never relaxes a decision.
 */
final class GoalDrift
{
    /** Default monitor options. */
    public static function defaultDrift(): Obj
    {
        return Obj::of(['windowMs' => 60000, 'maxPerWindow' => 20, 'maxNovel' => 3, 'magnitudeFactor' => 3, 'warmup' => 5, 'lockdown' => 5]);
    }

    /** @return list<mixed> the distinct verbs the goal grants */
    public static function expectedVerbs(mixed $g): array
    {
        return self::uniq(array_map(static fn(mixed $x): mixed => AnalyzerJs::jget($x, 'verb'), AnalyzerJs::reqList(AnalyzerJs::jget($g, 'grants'))));
    }

    /** @return list<mixed> */
    private static function uniq(array $xs): array
    {
        $out = [];
        foreach ($xs as $x) {
            if (!AnalyzerJs::includes($out, $x)) {
                $out[] = $x;
            }
        }
        return $out;
    }

    /** @return list<mixed> */
    private static function resIds(mixed $s): array
    {
        switch (AnalyzerJs::jget($s, 'k')) {
            case 'exact':
                return [AnalyzerJs::jget($s, 'id')];
            case 'oneof':
                return AnalyzerJs::reqList(AnalyzerJs::jget($s, 'ids'));
            case 'all_of':
                $out = [];
                foreach (AnalyzerJs::reqList(AnalyzerJs::jget($s, 'parts')) as $p) {
                    array_push($out, ...self::resIds($p));
                }
                return $out;
            default:
                return [];
        }
    }

    /** @return list<mixed> */
    public static function knownResources(mixed $g): array
    {
        $out = [];
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($g, 'grants')) as $x) {
            array_push($out, ...self::resIds(AnalyzerJs::jget($x, 'res')));
        }
        return self::uniq($out);
    }

    /** Node's lenient Buffer.from(s, 'hex'): decoding stops at the first invalid pair (an odd trailing digit is dropped). */
    public static function nodeHex(mixed $s): string
    {
        if (!is_string($s)) {
            throw new \TypeError('the first argument must be a string');
        }
        $out = '';
        $n = strlen($s);
        for ($i = 0; $i + 1 < $n; $i += 2) {
            $pair = substr($s, $i, 2);
            if (!ctype_xdigit($pair)) {
                break;
            }
            $out .= chr((int)hexdec($pair));
        }
        return $out;
    }

    /** Tighten-only: Allow becomes Escalate on an anomaly or lockdown; nothing else changes. */
    public static function applyDrift(mixed $d, mixed $s): mixed
    {
        return $d === 'allow' && (AnalyzerJs::truthy(AnalyzerJs::jget($s, 'anomalous')) || AnalyzerJs::truthy(AnalyzerJs::jget($s, 'lockdown'))) ? 'escalate' : $d;
    }

    /** Decide, observe, tighten: `{decision, signal}`. */
    public static function guardedDecide(mixed $goal, mixed $ont, GoalDriftMonitor $mon, mixed $c, mixed $t): Obj
    {
        $base = AnalyzerJs::jget(GoalExamples::decideCase($goal, $ont, $c), 'decision');
        $signal = $mon->observe(AnalyzerJs::jget($c, 'act'), $t);
        return Obj::of(['decision' => self::applyDrift($base, $signal), 'signal' => $signal]);
    }
}
