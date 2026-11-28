<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/IntentSessionStore.php';

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
    /** @var list<string> */
    public const EVENT_STATUSES = ['reserved', 'committed', 'released', 'reverted'];
    /** @var list<string> a reservation counts as soon as it is made, so two concurrent actions cannot both fit under a cap */
    public const COUNTED_STATUSES = ['reserved', 'committed'];

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
    public static function inWindow(mixed $win, mixed $ti, mixed $t): ?bool
    {
        if (!self::isTime($ti) || !self::isTime($t)) {
            return false;
        }
        $a = self::f($ti);
        $b = self::f($t);
        if ($a > $b) {
            return true;
        }
        if ($win === null) {
            throw new \TypeError("Cannot read properties of null (reading 'kind')");
        }
        // a window without a kind, or of an unknown kind, answers undefined (null), as the reference's switch falls through
        $kind = $win instanceof Obj ? $win->get('kind') : null;
        return match ($kind) {
            'task' => true,
            'sliding' => $a > $b - self::winNum($win, 'ms'),
            'period' => floor(fdiv($a - self::winNum($win, 't0'), self::winNum($win, 'ms'))) === floor(fdiv($b - self::winNum($win, 't0'), self::winNum($win, 'ms'))),
            default => null,
        };
    }

    /**
     * A window member in arithmetic, as `t - win.ms` coerces it (ToNumber): an absent member is undefined (NaN), null 0, a boolean 0 / 1,
     * a string Number(s), a list its joined text; anything else NaN. Only reached with a window object (a kind was read from it).
     */
    private static function winNum(Obj $win, string $k): float
    {
        if (!$win->has($k)) {
            return NAN;
        }
        $v = $win->get($k);
        return match (true) {
            $v instanceof Num => $v->float(),
            is_int($v), is_float($v) => (float)$v,
            is_bool($v) => $v ? 1.0 : 0.0,
            $v === null => 0.0,
            is_string($v) => IntentWb::jsNumber($v),
            is_array($v) && array_is_list($v) => IntentWb::jsNumber(Js::str($v)),
            default => NAN,
        };
    }

    /** The canonical key of the grouping parameter, '•' when ungrouped, null when the parameter is missing. */
    public static function accKeyOf(Obj $a, mixed $params): ?string
    {
        $key = $a->get('key');
        if ($key === null) {
            return '•';
        }
        $name = substr((string)$key, strlen('action.params.'));
        // an own member of an object; anything else (null, a string, a number) has none
        return $params instanceof Obj && $params->has($name) ? IntentV2::distinctKey($params->get($name)) : null;
    }

    private static function emptyPre(mixed $agg): Obj
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
    public static function accPreState(Obj $a, array $history, mixed $params, mixed $t, mixed $schema = null): Obj
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
            if ($e === null) {
                throw new HistoryError("Cannot read properties of null (reading 'status')");
            }
            $e = $e instanceof Obj ? $e : new Obj(); // a junk entry (a string, a number, a list) has no members: it is not counted
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
    public static function accPost(Obj $a, array $history, mixed $verb, mixed $params, mixed $t, mixed $schema = null): int
    {
        // a host-built declaration is not validated here otherwise: an unknown agg would read as distinct in the pre-state
        if (!in_array($a->get('agg'), IntentV2::ACC_AGGS, true)) {
            throw new HistoryError('accPost: unknown agg');
        }
        $pre = $a->get('key') !== null && self::accKeyOf($a, $params) === null
            ? self::emptyPre($a->get('agg')) // strict match, as intent-history.ts (a.agg === 'sum')
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
    public static function monitorStep(Obj $m, ?string $q, mixed $e): ?string
    {
        if ($e === null) {
            throw new HistoryError("Cannot read properties of null (reading 'status')");
        }
        $e = $e instanceof Obj ? $e : new Obj();
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
                    $pending = IntentWb::jsNumber(substr($q, strlen('pending:')));
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
                return null; // an unknown kind: the reference's switch falls through (undefined)
        }
    }

    /**
     * The fold of the monitor over the history (admission order, current statuses).
     * @param list<Obj> $history
     */
    public static function monitorState(Obj $m, array $history): ?string
    {
        $q = self::initial($m);
        foreach ($history as $e) {
            $q = self::monitorStep($m, $q, $e);
        }
        return $q;
    }

    /**
     * The verifier context (`intentV2.acc`) for a candidate action: pre-states of the site-local accumulators and monitor states.
     * @param Obj $root `{accumulators: list<Obj>, monitors: list<Obj>}`
     * @param list<Obj> $history
     * @param Obj $cand `{params: Obj, t}`
     * @return array{state:Obj,monitors:Obj}
     */
    public static function accContextFor(Obj $root, array $history, Obj $cand, mixed $schema = null): array
    {
        $state = new Obj();
        foreach ($root->get('accumulators') ?? [] as $a) {
            $holder = $a->get('holder');
            if (!($holder instanceof Obj) || $holder->get('kind') !== 'site_local') {
                continue;
            }
            if ($a->get('key') !== null && self::accKeyOf($a, $cand->get('params')) === null) {
                continue; // the verifier fails the claim (missing key)
            }
            $state->set((string)$a->get('id'), self::accPreState($a, $history, $cand->get('params'), $cand->get('t'), $schema));
        }
        $monitors = new Obj();
        foreach ($root->get('monitors') ?? [] as $m) {
            $monitors->set((string)$m->get('id'), self::monitorState($m, $history));
        }
        return ['state' => $state, 'monitors' => $monitors];
    }

    /**
     * Admit one action atomically against the session's accumulators (site-local holder): under the session lock, compute the pre-states
     * and monitor states from the history, run `verify` with them, and on `allow` append the event as `reserved`. After the effect the host
     * calls {@see settleIntentEvent}. A store that is not durable is refused (a restart would reset every cap) unless `requireDurable` is false.
     * @param array{session:string,root:Obj,event:Obj,verify:callable,schema?:mixed,requireDurable?:bool} $args
     * @return array<string,mixed> the verifier's verdict (an array with `allow`)
     */
    public static function admitIntentAction(IntentSessionStore $store, array $args): mixed
    {
        if (($args['requireDurable'] ?? true) !== false && !$store->durable()) {
            throw new \RuntimeException('admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore');
        }
        return $store->withSession($args['session'], static function (SessionTx $tx) use ($args): mixed {
            $history = $tx->events();
            $acc = self::accContextFor($args['root'], $history, $args['event'], $args['schema'] ?? null);
            $v = ($args['verify'])($acc);
            if (is_array($v) ? ($v['allow'] ?? false) : ($v instanceof Obj && $v->get('allow') === true)) {
                $e = $args['event']->without('status');
                $e->set('status', 'reserved');
                $tx->append($e);
            }
            return $v;
        });
    }

    /** Settle an admitted event (`committed`, `released` or `reverted`); false when the session has no such event. */
    public static function settleIntentEvent(IntentSessionStore $store, string $session, string $id, string $status): bool
    {
        return $store->withSession($session, static fn(SessionTx $tx): bool => $tx->setStatus($id, $status));
    }
}
