<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Predicates.php';

/** The session history is corrupt (or the candidate unusable): the caller fails closed. */
final class HistoryError extends \RuntimeException
{
}

/**
 * Session histories (Intent Layer v2 section 2.1; intent-history.ts): the host side of accumulators and monitors. The verifier
 * receives the PRE-STATE of the action's group from its own store; these functions compute it from the session's event history
 * (window, key, selection and counted statuses applied) and fold a monitor over it. They are pure: the store, its lock and the
 * reservation are the host's. A function the reference reports as throwing (a corrupt history) throws {@see HistoryError}.
 *
 * An event is an Obj `{id, verb, resource, params: Obj, t, status}` (status reserved | committed | released | reverted); a
 * history is the session's events in admission order. COUNTED statuses are reserved and committed.
 */
final class IntentHistory
{
    private const MAX_SAFE = 9007199254740991;

    private static function f(mixed $x): float
    {
        return $x instanceof Num ? $x->float() : (float)$x;
    }

    private static function isTime(mixed $x): bool
    {
        return IntentWb::isSafeInt($x);
    }

    private static function counted(mixed $status): bool
    {
        return $status === 'reserved' || $status === 'committed';
    }

    /**
     * Does the counted event stamped `$ti` still count at `$t`? task: always; sliding(ms): (t - ms, t]; period(ms, t0): the
     * period containing t; and every event stamped AFTER t (it has not left any window). A time that is not a safe integer is
     * in no window (fail closed).
     */
    public static function inWindow(mixed $win, mixed $ti, mixed $t): bool
    {
        if (!self::isTime($ti) || !self::isTime($t)) {
            return false;
        }
        $a = self::f($ti);
        $b = self::f($t);
        if ($a > $b) {
            return true;
        }
        $kind = $win instanceof Obj ? $win->get('kind') : null;
        return match ($kind) {
            'task' => true,
            'sliding' => $a > $b - self::f($win->get('ms')),
            'period' => floor(($a - self::f($win->get('t0'))) / self::f($win->get('ms')))
                === floor(($b - self::f($win->get('t0'))) / self::f($win->get('ms'))),
            default => false,
        };
    }

    /** The canonical key of the grouping parameter, '•' when ungrouped, null when the parameter is missing. */
    public static function accKeyOf(Obj $a, Obj $params): ?string
    {
        $key = $a->get('key');
        if ($key === null) {
            return '•';
        }
        $name = substr((string)$key, strlen('action.params.'));
        return $params->has($name) ? IntentV2::distinctKey($params->get($name)) : null;
    }

    private static function emptyPre(string $agg): Obj
    {
        return match ($agg) {
            'sum' => Obj::of(['sum' => new Num('0')]),
            'count' => Obj::of(['count' => new Num('0')]),
            'max' => Obj::of(['max' => new Num('0')]),
            default => Obj::of(['values' => []]),
        };
    }

    /**
     * The pre-state of the accumulator for a candidate action `{params, t}`; throws HistoryError on a corrupt history.
     * @param list<Obj> $history
     */
    public static function accPreState(Obj $a, array $history, Obj $params, mixed $t, mixed $schema = null): Obj
    {
        $key = self::accKeyOf($a, $params);
        if ($key === null) {
            throw new HistoryError('the key parameter ' . IntentWb::jsStr($a->get('key')) . ' is missing');
        }
        if (!self::isTime($t)) {
            throw new HistoryError('the candidate time is not a safe integer');
        }
        $sum = 0;
        $count = 0;
        $max = 0;
        $vals = [];
        foreach ($history as $e) {
            $counted = self::counted($e->get('status'));
            if ($counted && !self::isTime($e->get('t'))) {
                throw new HistoryError('event ' . IntentWb::jsStr($e->get('id')) . ': the time is not a safe integer');
            }
            if (!$counted || !self::inWindow($a->get('win'), $e->get('t'), $t) || !IntentV2::accSelects($a, $e->get('verb'), $schema)
                || self::accKeyOf($a, $e->get('params')) !== $key) {
                continue;
            }
            $v = IntentV2::accValueOf($a, $e->get('verb'), $e->get('params'), $schema);
            if (!$v['ok']) {
                throw new HistoryError('event ' . IntentWb::jsStr($e->get('id')) . ': ' . $v['reason']);
            }
            $sum += $v['val'];
            $count++;
            $max = max($max, $v['val']);
            if (isset($v['key'])) {
                $vals[] = $v['key'];
            }
        }
        switch ($a->get('agg')) {
            case 'sum':
                if ($sum > self::MAX_SAFE) {
                    throw new HistoryError('sum exceeds 2^53-1');
                }
                return Obj::of(['sum' => new Num((string)$sum)]);
            case 'count':
                return Obj::of(['count' => new Num((string)$count)]);
            case 'max':
                return Obj::of(['max' => new Num((string)$max)]);
            default:
                $vals = array_values(array_unique($vals));
                usort($vals, 'strcmp');
                return Obj::of(['values' => $vals]);
        }
    }

    /**
     * post(history, omega, t): the pre-state combined with omega when omega is selected, else the pre-state's value.
     * @param list<Obj> $history
     */
    public static function accPost(Obj $a, array $history, string $verb, Obj $params, mixed $t, mixed $schema = null): int
    {
        $pre = $a->get('key') !== null && self::accKeyOf($a, $params) === null
            ? self::emptyPre((string)$a->get('agg'))
            : self::accPreState($a, $history, $params, $t, $schema);
        if (!IntentV2::accSelects($a, $verb, $schema)) {
            return IntentV2::preValue($a, $pre);
        }
        $v = IntentV2::accValueOf($a, $verb, $params, $schema);
        if (!$v['ok']) {
            throw new HistoryError($v['reason']);
        }
        $post = IntentV2::combineAcc($a, $pre, $v);
        if ($post === null) {
            throw new HistoryError('overflow');
        }
        return $post;
    }

    private static function initial(Obj $m): string
    {
        return match ($m->get('kind')) {
            'requires_prior', 'precedes' => 'unmet',
            'never' => 'clean',
            'always' => 'ok',
            default => 'idle',
        };
    }

    /** One monitor step on one event; statuses that do not count leave the state unchanged. */
    public static function monitorStep(Obj $m, string $q, Obj $e): string
    {
        $status = $e->get('status');
        $mode = $m->get('status') ?? 'admitted';
        $counts = $mode === 'committed' ? $status === 'committed' : self::counted($status);
        if (!$counts) {
            return $q;
        }
        $ctx = Obj::of(['action' => Obj::of(['verb' => $e->get('verb'), 'resource' => $e->get('resource'), 'params' => $e->get('params')])]);
        $matches = static fn(mixed $p): bool => Predicates::predicateMatches($p, $ctx);
        switch ($m->get('kind')) {
            case 'requires_prior':
            case 'precedes':
                return $q === 'met' || $matches($m->get('p')) ? 'met' : 'unmet';
            case 'never':
                return $q === 'seen' || $matches($m->get('p')) ? 'seen' : 'clean';
            case 'always':
                return $q === 'broken' || !$matches($m->get('p')) ? 'broken' : 'ok';
            case 'responds_within':
                if ($q === 'missed') {
                    return 'missed';
                }
                $w = self::f($m->get('within'));
                $pending = null;
                if (str_starts_with($q, 'pending:')) {
                    $n = substr($q, strlen('pending:'));
                    // shortcut: only canonical decimal digits parse; any other text is NaN (JS Number() also reads hex / exponents), a state this module never emits
                    $pending = preg_match('/\A[0-9]+\z/D', $n) === 1 ? (float)$n : NAN;
                }
                if ($pending !== null) {
                    if ($matches($m->get('q'))) {
                        $pending = null;
                    } elseif ($pending - 1 <= 0) {
                        return 'missed';
                    } else {
                        $pending -= 1;
                    }
                }
                if ($matches($m->get('p'))) {
                    $pending = $pending === null ? $w : (is_nan($pending) || is_nan($w) ? NAN : min($pending, $w));
                }
                return $pending === null ? 'idle' : 'pending:' . IntentWb::jsStr($pending);
            default:
                return $q;
        }
    }

    /**
     * The fold of the monitor over the history (admission order, current statuses).
     * @param list<Obj> $history
     */
    public static function monitorState(Obj $m, array $history): string
    {
        $q = self::initial($m);
        foreach ($history as $e) {
            $q = self::monitorStep($m, $q, $e);
        }
        return $q;
    }
}
