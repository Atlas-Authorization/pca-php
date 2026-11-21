<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/IntentMapKit.php';
require_once __DIR__ . '/IntentLearner.php';

/**
 * Frame and side-effect constraints (frames.ts): monitored state snapshots, write sets, the frame condition over everything a
 * verb does not write and the verb's postconditions (exact numeric deltas, predicate conditions over env.pre / env.post /
 * env.effect). Values are the parsed-JSON model; reports are Obj. {@see IntentFrames::applyFrameReport} calls
 * IntentMapKit::applyDivergence.
 */
final class IntentFrames
{
    public const FRAME_STATE_DOMAIN = 'atlas-pca/intent-frame-state/v1';

    /** Digest of a state value (site-local, never cross-language: the lenient canonical form). */
    public static function stateDigest(mixed $value): string
    {
        return Pca::b64u(hash('sha256', Json::canonicalizeLenient(Obj::of(['d' => self::FRAME_STATE_DOMAIN, 'v' => $value])), true));
    }

    /** Snapshot already-read values (an Obj or assoc array of name => value). */
    public static function snapshotState(mixed $values, bool $keepValues = true): Obj
    {
        $out = new Obj();
        foreach (Jsx::keys($values) as $k) {
            $v = Js::opt($values, $k);
            $e = new Obj();
            $e->set('digest', self::stateDigest($v));
            if ($keepValues) {
                $e->set('value', $v);
            }
            $out->set($k, $e);
        }
        return $out;
    }

    /** Read every monitored variable through its (synchronous) reader Closure and snapshot it. */
    public static function captureState(array $readers, bool $keepValues = true): Obj
    {
        $keys = array_map('strval', array_keys($readers));
        usort($keys, IntentV2::compareUtf8(...));
        $values = new Obj();
        foreach ($keys as $k) {
            $values->set($k, ($readers[$k])());
        }
        return self::snapshotState($values, $keepValues);
    }

    /** Own-property path read on objects and arrays; undefined ({@see Jsx::$U}) otherwise. */
    private static function get(mixed $root, string $path): mixed
    {
        Jsx::init();
        $cur = $root;
        foreach (explode('.', $path) as $s) {
            if (!($cur instanceof Obj || is_array($cur))) {
                return Jsx::$U;
            }
            $cur = Jsx::get($cur, $s);
            if ($cur instanceof Undef) {
                return $cur;
            }
        }
        return $cur;
    }

    private static function isObject(mixed $x): bool
    {
        return $x instanceof Obj || is_array($x);
    }

    /** W(action): the declared list, or the parameter-selected list (unknown parameter value: default, else empty). @return list<mixed> */
    public static function writeSetOf(mixed $spec, mixed $action): array
    {
        $verb = Jsx::get($action, 'verb');
        $w = Jsx::get($spec, 'writes');
        if ($w instanceof Undef || $w === null) {
            throw new \TypeError('Cannot convert undefined or null to object');
        }
        $d = is_string($verb) && $w instanceof Obj && $w->has($verb) ? $w->get($verb) : Jsx::$U;
        if ($d instanceof Undef) {
            return [];
        }
        if (is_array($d) && array_is_list($d)) {
            return $d;
        }
        $p = Jsx::rd($d, 'param');
        if (!is_string($p)) {
            throw new \TypeError('d.param.startsWith is not a function');
        }
        $params = Jsx::get($action, 'params');
        $v = self::get(($params instanceof Undef || $params === null) ? new Obj() : $params,
            str_starts_with($p, 'action.params.') ? substr($p, strlen('action.params.')) : $p);
        $key = is_string($v) || is_bool($v) || Js::isNum($v) ? Js::str($v) : null;
        $map = Jsx::rd($d, 'map');
        if ($key !== null && $map instanceof Obj && $map->has($key)) {
            return Js::spread($map->get($key));
        }
        $def = Jsx::get($d, 'default');
        return $def instanceof Undef || $def === null ? [] : Js::spread($def);
    }

    /** @param list<string> $out */
    private static function envReads(mixed $c, array &$out): void
    {
        if (!($c instanceof Obj || is_array($c))) {
            return;
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of') && is_array($c->get('all_of')) && array_is_list($c->get('all_of'))) {
                foreach ($c->get('all_of') as $x) {
                    self::envReads($x, $out);
                }
            } elseif ($c->has('any_of') && is_array($c->get('any_of')) && array_is_list($c->get('any_of'))) {
                foreach ($c->get('any_of') as $x) {
                    self::envReads($x, $out);
                }
            } elseif ($c->has('not')) {
                self::envReads($c->get('not'), $out);
            }
            return;
        }
        if (Predicates::isLeafCondition($c)) {
            if (str_starts_with((string)$c->get('field'), 'env.')) {
                $out[] = (string)$c->get('field');
            }
            $ref = $c->get('ref');
            if (is_string($ref) && str_starts_with($ref, 'env.')) {
                $out[] = $ref;
            }
        }
    }

    private static function nest(mixed $s): Obj
    {
        $root = new Obj();
        foreach (Jsx::keys($s) as $k) {
            $v = Jsx::get($s, $k);
            if (!self::isObject($v)) {
                throw new \TypeError("Cannot use 'in' operator to search for 'value' in " . Js::str($v));
            }
            if (!($v instanceof Obj && $v->has('value'))) {
                continue;
            }
            $segs = explode('.', $k);
            $cur = $root;
            for ($i = 0; $i < count($segs) - 1; $i++) {
                $n = $cur->has($segs[$i]) ? $cur->get($segs[$i]) : null;
                if (!($n instanceof Obj)) {
                    $n = new Obj();
                    $cur->set($segs[$i], $n);
                }
                $cur = $n;
            }
            $cur->set($segs[count($segs) - 1], $v->get('value'));
        }
        return $root;
    }

    private static function strictEq(mixed $a, mixed $b): bool
    {
        if ($a instanceof Undef || $b instanceof Undef) {
            return $a instanceof Undef && $b instanceof Undef;
        }
        if (Js::isNum($a) && Js::isNum($b)) {
            return Js::num($a) === Js::num($b);
        }
        return $a === $b;
    }

    /** @return list<string> unique, sorted */
    private static function uniqSorted(array $xs): array
    {
        $u = array_values(array_unique(array_map(fn($x) => $x instanceof Undef ? 'undefined' : Js::str($x), $xs)));
        usort($u, IntentV2::compareUtf8(...));
        return $u;
    }

    /**
     * Check one executed action: the frame condition over the monitored state outside its write set and the verb's postconditions.
     * Total: never throws (a failure is a `missing` entry `error: <message>`). `$opts` is an Obj or assoc array (`effect`,
     * `attributions` = [{var, actor}] excusing a change by an actor other than `self`, `self`).
     */
    public static function checkFrame(mixed $spec, mixed $action, mixed $pre, mixed $post, mixed $opts = null): Obj
    {
        Jsx::init();
        $outOfFrame = [];
        $attributed = [];
        $postViolated = [];
        $missing = [];
        $unmonitored = false;
        try {
            $state = self::isObject($spec) ? Jsx::get($spec, 'state') : null;
            if (!self::isObject($spec) || !is_array($state) || !array_is_list($state) || !self::isObject($action) || !self::isObject($pre) || !self::isObject($post)) {
                throw new \TypeError('spec, action, pre and post must be objects (spec.state an array)');
            }
            $unmonitored = count($state) === 0;
            $W = [];
            foreach (self::writeSetOf($spec, $action) as $w) {
                if (is_string($w)) {
                    $W[$w] = true;
                }
            }
            $sorted = array_map(fn($x) => is_string($x) ? $x : throw new \TypeError('state entry is not a string'), $state);
            usort($sorted, IntentV2::compareUtf8(...));
            $attrs = Js::opt($opts, 'attributions');
            $self = Js::opt($opts, 'self') ?? Jsx::$U;
            foreach ($sorted as $v) {
                if (isset($W[$v])) {
                    continue;
                }
                $a = Jsx::get($pre, $v);
                $b = Jsx::get($post, $v);
                if (!Jsx::truthy($a) || !Jsx::truthy($b)) {
                    $missing[] = $v;
                    continue;
                }
                if (self::strictEq(Jsx::get($a, 'digest'), Jsx::get($b, 'digest'))) {
                    continue;
                }
                $other = false;
                foreach (($attrs instanceof Undef || $attrs === null) ? [] : Js::spread($attrs) as $x) {
                    if (self::strictEq(Jsx::rd($x, 'var'), $v) && !self::strictEq(Jsx::rd($x, 'actor'), $self)) {
                        $other = true;
                        break;
                    }
                }
                if ($other) {
                    $attributed[] = $v;
                } else {
                    $outOfFrame[] = $v;
                }
            }
            $effect = Js::opt($opts, 'effect');
            $env = Obj::of(['pre' => self::nest($pre), 'post' => self::nest($post), 'effect' => ($effect instanceof Undef || $effect === null) ? new Obj() : $effect]);
            $params = Jsx::get($action, 'params');
            $ctx = Obj::of(['action' => Obj::of(['verb' => Js::opt($action, 'verb'), 'resource' => Js::opt($action, 'resource'),
                'params' => ($params instanceof Undef || $params === null) ? new Obj() : $params]), 'env' => $env]);
            $pcs = Jsx::get($spec, 'post');
            foreach (($pcs instanceof Undef || $pcs === null) ? [] : Js::spread($pcs) as $pc) {
                if (!self::strictEq(Jsx::rd($pc, 'verb'), Jsx::get($action, 'verb'))) {
                    continue;
                }
                $id = Jsx::get($pc, 'id');
                $pending = false;
                $deltas = Jsx::get($pc, 'deltas');
                foreach (($deltas instanceof Undef || $deltas === null) ? [] : Js::spread($deltas) as $d) {
                    $path = Jsx::rd($d, 'path');
                    if (!is_string($path)) {
                        throw new \TypeError('path.split is not a function');
                    }
                    $x = self::get($env->get('pre'), $path);
                    $y = self::get($env->get('post'), $path);
                    if (!Js::isNum($x) || !Js::isNum($y)) {
                        $missing[] = Jsx::str($id) . ':' . $path;
                        $pending = true;
                    } else {
                        $by = Jsx::get($d, 'by');
                        $sum = Js::isNum($by) ? Js::num($x) + Js::num($by) : NAN;
                        if (!Js::isNum($by) || Js::num($y) !== $sum) {
                            $postViolated[] = $id;
                            $pending = true;
                            break;
                        }
                    }
                }
                if ($pending) {
                    continue;
                }
                $where = Jsx::get($pc, 'where');
                $wl = ($where instanceof Undef || $where === null) ? [] : $where;
                if (!is_array($wl)) {
                    if (Jsx::truthy($wl)) {
                        throw new \TypeError('(pc.where ?? []).forEach is not a function');
                    }
                    $wl = [];
                }
                $reads = [];
                foreach ($wl as $c) {
                    self::envReads($c, $reads);
                }
                $absent = [];
                $envOnly = Obj::of(['env' => $env]);
                foreach ($reads as $r) {
                    if (self::get($envOnly, $r) instanceof Undef) {
                        $absent[] = $r;
                    }
                }
                if (count($absent) > 0) {
                    foreach ($absent as $r) {
                        $missing[] = Jsx::str($id) . ':' . $r;
                    }
                    continue;
                }
                if (Jsx::truthy($where) && is_array($where) && count($where) > 0
                    && !Predicates::evaluatePredicates([Obj::of(['verb' => Js::opt($action, 'verb'), 'where' => $where])], $ctx)['allowed']) {
                    $postViolated[] = $id;
                }
            }
        } catch (\Throwable $e) {
            $missing[] = 'error: ' . $e->getMessage();
        }
        $missing = self::uniqSorted($missing);
        $postViolated = self::uniqSorted($postViolated);
        $status = count($outOfFrame) > 0 || count($postViolated) > 0 ? 'violated' : (count($missing) > 0 ? 'pending' : 'ok');
        return Obj::of(['status' => $status, 'outOfFrame' => $outOfFrame, 'attributed' => $attributed, 'postViolated' => $postViolated,
            'missing' => $missing, 'unmonitored' => $unmonitored]);
    }

    /**
     * Feed a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell for good; `ok` and
     * `pending` change nothing (a met frame is not the principal's endorsement). Needs IntentMapKit::applyDivergence.
     */
    public static function applyFrameReport(IntentLearner $l, mixed $o, mixed $report): Obj
    {
        if (!($report instanceof Obj) || $report->get('status') !== 'violated') {
            return new Obj();
        }
        return Obj::of(['signal' => 'postcondition-violation', 'divergence' => IntentMapKit::applyDivergence($l, $o, 0)]);
    }
}
