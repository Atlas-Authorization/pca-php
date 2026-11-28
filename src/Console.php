<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Immune.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';

/**
 * The principal's live agent console, the data layer: a stream of activity events projected into a per-agent view with a threat read
 * (the immune system's), and the local kill-switch set. Pure and offline; the freeze set is the fast layer in front of the ledger's
 * revocation epoch. An event is `{at, agent, verb, resource, outcome, r?, taint?, digest?, goalCommit?}`, a freeze set `{frozen: [agent...]}`.
 */
final class Console
{
    /** The kill switch with nothing frozen. */
    public static function emptyFreeze(): Obj
    {
        return Obj::of(['frozen' => []]);
    }

    /** `x ?? d`: null and an absent member both give the default. */
    private static function or(mixed $x, mixed $d): mixed
    {
        return $x === null || $x instanceof Undef ? $d : $x;
    }

    /** An activity event from a PCActn and the verifier's outcome (`$at` null = the action's own `iat`); a malformed PCActn throws. */
    public static function eventFromPCActn(mixed $p, string $outcome, mixed $at = null): Obj
    {
        $chain = Jsx::rd($p, 'cap_chain');
        $n = Jsx::get($chain, 'length');
        if (!is_int($n)) {
            throw new \TypeError('cap_chain has no length');
        }
        $leaf = $n > 0 ? Jsx::get($chain, (string)($n - 1)) : Jsx::$U;
        $agent = $leaf === null || $leaf instanceof Undef ? Jsx::$U : Jsx::get($leaf, 'holder');
        $action = Jsx::rd($p, 'action');
        $e = Obj::of(['at' => self::or($at, Jsx::get($p, 'iat')), 'agent' => self::or($agent, 'unknown'),
            'verb' => Jsx::rd($action, 'verb'), 'resource' => Jsx::rd($action, 'resource'), 'outcome' => $outcome]); // action.verb throws on an absent action
        $rc = Jsx::get($p, 'risk_claim');
        $pv = Jsx::get($p, 'provenance');
        $out = new Obj();
        foreach ([...$e->keys(), 'r', 'taint', 'digest'] as $k) {
            $v = match ($k) {
                'r' => $rc === null || $rc instanceof Undef ? Jsx::$U : Jsx::get($rc, 'r'),
                'taint' => $pv === null || $pv instanceof Undef ? Jsx::$U : Jsx::get($pv, 'taint_level'),
                'digest' => Pca::hashCanonical($p),
                default => $e->get($k),
            };
            if (!($v instanceof Undef)) { // undefined members are not part of the event
                $out->set($k, $v);
            }
        }
        return $out;
    }

    /** An event with a finite time and a non-empty agent id; anything else cannot be placed on a timeline or attributed. */
    private static function usable(mixed $e): bool
    {
        if (!($e instanceof Obj)) {
            return false;
        }
        $at = Jsx::get($e, 'at');
        $ag = Jsx::get($e, 'agent');
        return Js::isNum($at) && is_finite((float)Js::num($at)) && is_string($ag) && $ag !== '';
    }

    private static function time(Obj $e): float
    {
        return (float)Js::num($e->get('at'));
    }

    /** Project a stream of activity events (a list; anything else throws) into a per-agent console view with a threat read. */
    public static function buildConsole(mixed $events): Obj
    {
        if (!is_array($events) || !array_is_list($events)) {
            throw new \TypeError('events must be a list');
        }
        $kept = array_values(array_filter($events, self::usable(...)));
        $dropped = count($events) - count($kept);
        /** @var array<string,list<Obj>> $by */
        $by = [];
        foreach ($kept as $e) {
            $by['k' . $e->get('agent')][] = $e;
        }
        $agents = [];
        foreach ($by as $evs) {
            usort($evs, static fn(Obj $a, Obj $b): int => self::time($a) <=> self::time($b));
            $immune = Immune::initialState();
            $autos = $stepUps = $denies = $executed = 0;
            $totalRisk = 0.0;
            foreach ($evs as $e) {
                $rv = self::or(Jsx::get($e, 'r'), 0);
                $r = Jsx::toNum($rv);
                $totalRisk += $r;
                $o = Jsx::get($e, 'outcome');
                $autos += $o === 'auto' ? 1 : 0;
                $stepUps += $o === 'step_up' ? 1 : 0;
                $denies += $o === 'deny' ? 1 : 0;
                $executed += $o === 'executed' ? 1 : 0;
                $immune = Immune::observe($immune, Obj::of(['r' => $rv, 'at' => $e->get('at'), 'stepUp' => $o === 'step_up', 'denied' => $o === 'deny']));
            }
            $agents[] = Obj::of(['agent' => $evs[0]->get('agent'), 'actions' => count($evs), 'autos' => $autos, 'stepUps' => $stepUps,
                'denies' => $denies, 'executed' => $executed, 'totalRisk' => $totalRisk, 'firstSeen' => $evs[0]->get('at'),
                'lastSeen' => $evs[count($evs) - 1]->get('at'), 'threat' => Immune::assess($immune)]);
        }
        usort($agents, static function (Obj $a, Obj $b): int {
            $s = (float)Js::num($b->get('threat')->get('score')) <=> (float)Js::num($a->get('threat')->get('score'));
            return $s !== 0 ? $s : (float)Js::num($b->get('lastSeen')) <=> (float)Js::num($a->get('lastSeen'));
        });
        $t = ['actions' => 0, 'autos' => 0, 'stepUps' => 0, 'denies' => 0, 'executed' => 0];
        foreach ($agents as $a) {
            foreach ($t as $k => $_) {
                $t[$k] += $a->get($k);
            }
        }
        $ats = array_map(self::time(...), $kept);
        return Obj::of(['agents' => $agents, 'totals' => Obj::of($t),
            'window' => Obj::of(['from' => $ats === [] ? 0 : min($ats), 'to' => $ats === [] ? 0 : max($ats)]), 'dropped' => $dropped]);
    }

    /** The agents of a console view whose threat read is not calm. */
    public static function anomalies(mixed $view): array
    {
        return array_values(array_filter(Jsx::iter(Jsx::rd($view, 'agents')), static fn($a) => Jsx::get(Jsx::rd($a, 'threat'), 'level') !== 'calm'));
    }

    /** The freeze set with the agent added (sorted by UTF-16 code units, as the reference's default sort); a non-string or empty agent throws. */
    public static function freezeAgent(mixed $set, mixed $agent): Obj
    {
        if (!is_string($agent) || $agent === '') {
            throw new \TypeError('freezeAgent: agent must be a non-empty string');
        }
        $frozen = Jsx::rd($set, 'frozen');
        if (is_string($frozen)) { // `includes` is a substring test on a string, and the spread splits it into code points
            if (str_contains($frozen, $agent)) {
                return $set;
            }
            $frozen = preg_split('//u', $frozen, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        } elseif (!is_array($frozen)) {
            throw new \TypeError('freezeAgent: the set has no frozen list');
        }
        if (in_array($agent, $frozen, true)) {
            return $set;
        }
        $all = [...$frozen, $agent];
        $key = static fn($x): string => (string)mb_convert_encoding(Js::str($x), 'UTF-16BE', 'UTF-8');
        usort($all, static fn($a, $b): int => strcmp($key($a), $key($b)));
        return Obj::of(['frozen' => $all]);
    }

    /** The freeze set without the agent. */
    public static function unfreezeAgent(mixed $set, mixed $agent): Obj
    {
        $frozen = Jsx::rd($set, 'frozen');
        if (!is_array($frozen)) {
            throw new \TypeError('unfreezeAgent: the set has no frozen list');
        }
        return Obj::of(['frozen' => array_values(array_filter($frozen, static fn($a) => $a !== $agent))]);
    }

    /** True when the agent is frozen; fails closed: no identifiable agent, or a malformed set, counts as frozen. */
    public static function isFrozen(mixed $set, mixed $agent): bool
    {
        if (!is_string($agent) || $agent === '' || !($set instanceof Obj) || !is_array($set->get('frozen'))) {
            return true;
        }
        return in_array($agent, $set->get('frozen'), true);
    }
}
