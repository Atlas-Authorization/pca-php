<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/Prohibitions.php';
require_once __DIR__ . '/SafeRegex.php';

/** The marker for "this field is absent" in a probe grid (compare with ===; see {@see AnalyzerCore::absent()}). */
final class AnalyzerAbsent
{
    public function __toString(): string
    {
        return 'ABSENT';
    }
}

/**
 * Static analyzability of authority: the bounded decision engine and its relational queries (reachability, vacuity, totality,
 * subsumption, disjointness, equivalence, intent conformance). Port of the policy analyzer's caveat, constitution, field,
 * enumeration and query modules.
 *
 * Policies are parsed-JSON trees; a model, a probe set, a representative and every result are {@see Obj}s. The engine enumerates
 * a finite distinguishing grid of representative actions and evaluates the real predicate evaluator at each, so a verdict is
 * exact over the decided fragment and fails safe (`approximate`) outside it.
 */
final class AnalyzerCore
{
    public const DEFAULT_MAX_COMBINATIONS = 200000;
    public const FRESH_STRING = "\x00atlas-analyzer::fresh-unmatched\x00";
    public const FRESH_VERB = "\x00atlas-analyzer::fresh-verb\x00";
    public const FRESH_RESOURCE = "\x00atlas-analyzer::fresh-resource\x00";

    public const REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'];

    private static ?AnalyzerAbsent $absent = null;

    /** The singleton ABSENT marker. */
    public static function absent(): AnalyzerAbsent
    {
        return self::$absent ??= new AnalyzerAbsent();
    }

    /** The unbounded numeric interval {lo, loInclusive, hi, hiInclusive} (a fresh Obj per call). */
    public static function fullInterval(): Obj
    {
        return Obj::of(['lo' => -INF, 'loInclusive' => false, 'hi' => INF, 'hiInclusive' => false]);
    }

    private static function isObjOrArr(mixed $x): bool
    {
        return $x instanceof Obj || is_array($x);
    }

    /** Append a string to a list unless already present (an ordered set). @param list<string> $set */
    private static function addUnique(array &$set, string $s): void
    {
        if (!in_array($s, $set, true)) {
            $set[] = $s;
        }
    }

    // ---- caveats ------------------------------------------------------------------------------------------------------------

    /** Static satisfiability of an envelope caveat set: {sat, reason?, revCap?} (revCap indexes the reversibility order). */
    public static function analyzeCaveats(mixed $caveats): Obj
    {
        if (!AnalyzerJs::isArr($caveats)) {
            return Obj::of(['sat' => false, 'reason' => 'caveats are not an array']);
        }
        $notBeforeMax = -INF;
        $expiresMin = INF;
        $revCap = null;
        foreach ($caveats as $cv) {
            if (!($cv instanceof Obj) || !is_string($cv->get('type'))) {
                return Obj::of(['sat' => false, 'reason' => 'malformed caveat (not an object with a string type)']);
            }
            $t = $cv->get('type');
            if ($t === 'expires') {
                $at = AnalyzerJs::fin(AnalyzerJs::own($cv, 'at'));
                if ($at === null) {
                    return Obj::of(['sat' => false, 'reason' => 'expires.at is not a finite number']);
                }
                $expiresMin = min($expiresMin, $at);
            } elseif ($t === 'not_before') {
                $at = AnalyzerJs::fin(AnalyzerJs::own($cv, 'at'));
                if ($at === null) {
                    return Obj::of(['sat' => false, 'reason' => 'not_before.at is not a finite number']);
                }
                $notBeforeMax = max($notBeforeMax, $at);
            } elseif ($t === 'rate') {
                $mx = AnalyzerJs::fin(AnalyzerJs::own($cv, 'max'));
                $per = AnalyzerJs::fin(AnalyzerJs::own($cv, 'per_secs'));
                if ($mx === null || $per === null || $per <= 0) {
                    return Obj::of(['sat' => false, 'reason' => 'rate caveat requires finite max and per_secs > 0']);
                }
                if ($mx < 1) {
                    return Obj::of(['sat' => false, 'reason' => 'rate.max ' . AnalyzerJs::numStr($mx) . ' < 1 forbids every action']);
                }
            } elseif ($t === 'max_blast_radius') {
                $mx = AnalyzerJs::fin(AnalyzerJs::own($cv, 'max'));
                if ($mx === null) {
                    return Obj::of(['sat' => false, 'reason' => 'max_blast_radius.max is not a finite number']);
                }
                if ($mx < 0) {
                    return Obj::of(['sat' => false, 'reason' => 'max_blast_radius.max < 0 forbids every action']);
                }
            } elseif ($t === 'reversibility_max') {
                $cls = AnalyzerJs::jsStr(AnalyzerJs::own($cv, 'class'));
                $idx = array_search($cls, self::REVERSIBILITY_ORDER, true);
                if ($idx === false) {
                    return Obj::of(['sat' => false, 'reason' => "reversibility_max.class '" . $cls . "' is unknown"]);
                }
                $revCap = $revCap === null ? $idx : min($revCap, $idx);
            } elseif ($t === 'delegation_depth') {
                $mx = AnalyzerJs::fin(AnalyzerJs::own($cv, 'max'));
                if ($mx === null) {
                    return Obj::of(['sat' => false, 'reason' => 'delegation_depth.max is not a finite number']);
                }
                if ($mx < 0) {
                    return Obj::of(['sat' => false, 'reason' => 'delegation_depth.max < 0 forbids every action']);
                }
            } elseif ($t === 'budget_alloc') {
                $lim = AnalyzerJs::fin(AnalyzerJs::own($cv, 'limit'));
                if ($lim === null || $lim < 0) {
                    return Obj::of(['sat' => false, 'reason' => 'budget_alloc.limit must be a finite number >= 0']);
                }
            } else {
                return Obj::of(['sat' => false, 'reason' => "unknown caveat type '" . $t . "' (fail closed)"]);
            }
        }
        if ($notBeforeMax !== -INF && $expiresMin !== INF && $notBeforeMax >= $expiresMin) {
            return Obj::of(['sat' => false, 'reason' => 'not_before (' . AnalyzerJs::numStr($notBeforeMax) . ') >= expires ('
                . AnalyzerJs::numStr($expiresMin) . '): the validity window is empty']);
        }
        $out = Obj::of(['sat' => true]);
        if ($revCap !== null) {
            $out->set('revCap', $revCap);
        }
        return $out;
    }

    // ---- constitution -------------------------------------------------------------------------------------------------------

    /** A constitution's stateless invariants as analyzer vetoes; the rest are reported in `unmodeled`. */
    public static function vetoesFromConstitution(mixed $c): Obj
    {
        $vetoes = [];
        $unmodeled = [];
        $invs = $c instanceof Obj ? AnalyzerJs::own($c, 'invariants') : AnalyzerJs::undef();
        foreach (AnalyzerJs::isArr($invs) ? $invs : [] as $inv) {
            $kind = AnalyzerJs::jget($inv, 'kind');
            $iid = AnalyzerJs::jget($inv, 'id');
            if ($kind === 'never') {
                $vetoes[] = AnalyzerJs::uobj(['id' => $iid, 'kind' => 'deny', 'when' => AnalyzerJs::jget($inv, 'when')]);
            } elseif ($kind === 'never_unless') {
                $vetoes[] = AnalyzerJs::uobj(['id' => $iid, 'kind' => 'deny', 'when' => AnalyzerJs::jget($inv, 'when'),
                    'unless' => AnalyzerJs::jget($inv, 'unless')]);
            } elseif ($kind === 'require_approval_over') {
                $vetoes[] = AnalyzerJs::uobj([
                    'id' => $iid, 'kind' => 'approval', 'when' => AnalyzerJs::jget($inv, 'when'),
                    'over' => AnalyzerJs::uobj(['path' => AnalyzerJs::jget($inv, 'amount'), 'threshold' => AnalyzerJs::jget($inv, 'threshold')]),
                    'unless' => AnalyzerJs::jget($inv, 'approved'),
                ]);
            } elseif ($kind === 'cap' || $kind === 'rate') {
                $unmodeled[] = AnalyzerJs::uobj(['id' => $iid, 'kind' => $kind,
                    'reason' => 'windowed total: bounded by maxExposure, not by a per-action veto']);
            } else {
                $unmodeled[] = AnalyzerJs::uobj(['id' => $iid, 'kind' => $kind, 'reason' => 'needs action history']);
            }
        }
        return Obj::of(['vetoes' => $vetoes, 'unmodeled' => $unmodeled]);
    }

    // ---- single-field interval / finite-set engine --------------------------------------------------------------------------

    /**
     * @param list<float> $thresholds
     * @return list<float>
     */
    private static function numericCellReps(array $thresholds): array
    {
        $s = [];
        foreach ($thresholds as $t) {
            if (is_finite($t) && !in_array($t, $s, true)) {   // a Set: 0 and -0 are one value
                $s[] = $t;
            }
        }
        if ($s === []) {
            return [];
        }
        sort($s, SORT_NUMERIC);
        $n = count($s);
        $out = [$s[0] - 1];
        for ($i = 0; $i < $n; $i++) {
            $out[] = $s[$i];
            if ($i + 1 < $n) {
                $out[] = ($s[$i] + $s[$i + 1]) / 2;
            }
        }
        $out[] = $s[$n - 1] + 1;
        return $out;
    }

    private static function valueKey(mixed $x): string
    {
        if ($x === self::FRESH_STRING) {
            return 's:__fresh__';
        }
        $t = AnalyzerJs::isNum($x) ? 'number' : (is_string($x) ? 'string' : (is_bool($x) ? 'boolean' : ($x instanceof Undef ? 'undefined' : 'object')));
        return $t . ':' . ($x instanceof Undef ? 'undefined' : AnalyzerJs::jsJson($x));
    }

    /** Representative probe values for one field from the conjunction of `where` conditions on it. @return list<mixed> */
    public static function fieldProbes(mixed $conditions): array
    {
        $literals = [];
        $thresholds = [];
        $prefixes = [];
        foreach (AnalyzerJs::reqList($conditions) as $c) {
            if (!Predicates::isLeafCondition($c) || $c->has('ref')) {
                continue;
            }
            $v = AnalyzerJs::own($c, 'value');
            $op = AnalyzerJs::own($c, 'op');
            if ($op === 'eq' || $op === 'ne') {
                $literals[] = $v;
                if (AnalyzerJs::isFin($v)) {
                    $thresholds[] = AnalyzerJs::jsnum($v);
                }
            } elseif ($op === 'in' || $op === 'nin') {
                if (AnalyzerJs::isArr($v)) {
                    foreach ($v as $x) {
                        $literals[] = $x;
                        if (AnalyzerJs::isFin($x)) {
                            $thresholds[] = AnalyzerJs::jsnum($x);
                        }
                    }
                }
            } elseif ($op === 'lt' || $op === 'lte' || $op === 'gt' || $op === 'gte') {
                if (AnalyzerJs::isFin($v)) {
                    $thresholds[] = AnalyzerJs::jsnum($v);
                }
            } elseif ($op === 'prefix' || $op === 'like' || $op === 'matches' || $op === 'is_a') {
                if (is_string($v)) {
                    $literals[] = $v;
                    if ($op === 'prefix') {
                        $prefixes[] = $v;
                    }
                }
            } elseif ($op === 'member_of') {
                if (is_string($v)) {
                    $literals[] = $v;
                } elseif (AnalyzerJs::isArr($v)) {
                    foreach ($v as $x) {
                        if (is_string($x)) {
                            $literals[] = $x;
                        }
                    }
                }
            }
        }
        $out = [];
        $seen = [];
        $add = static function (mixed $x) use (&$out, &$seen): void {
            $k = 'k' . self::valueKey($x);
            if (!isset($seen[$k])) {
                $seen[$k] = true;
                $out[] = $x;
            }
        };
        foreach ($literals as $lit) {
            $add($lit);
        }
        foreach (self::numericCellReps($thresholds) as $n) {
            $add($n);
        }
        foreach ($prefixes as $p) {
            $add($p);
            $add($p . 'x');
        }
        $add(self::FRESH_STRING);
        return $out;
    }

    /** Tighten an interval {lo, loInclusive, hi, hiInclusive} by one numeric condition (a non-numeric operand returns it as is). */
    public static function tightenInterval(Obj $iv, mixed $op, mixed $value): Obj
    {
        $f = AnalyzerJs::fin($value);
        if ($f === null) {
            return $iv;
        }
        $n = AnalyzerJs::copy($iv);
        $lo = AnalyzerJs::jsnum($n->get('lo'));
        $hi = AnalyzerJs::jsnum($n->get('hi'));
        if ($op === 'eq') {
            if ($f > $lo || ($f === $lo && !$n->get('loInclusive'))) {
                $n->set('lo', $value);
                $n->set('loInclusive', true);
            }
            if ($f < $hi || ($f === $hi && !$n->get('hiInclusive'))) {
                $n->set('hi', $value);
                $n->set('hiInclusive', true);
            }
        } elseif ($op === 'gte') {
            if ($f > $lo) {
                $n->set('lo', $value);
                $n->set('loInclusive', true);
            }
        } elseif ($op === 'gt') {
            if ($f > $lo || ($f === $lo && $n->get('loInclusive'))) {
                $n->set('lo', $value);
                $n->set('loInclusive', false);
            }
        } elseif ($op === 'lte') {
            if ($f < $hi) {
                $n->set('hi', $value);
                $n->set('hiInclusive', true);
            }
        } elseif ($op === 'lt') {
            if ($f < $hi || ($f === $hi && $n->get('hiInclusive'))) {
                $n->set('hi', $value);
                $n->set('hiInclusive', false);
            }
        }
        return $n;
    }

    public static function intervalEmpty(Obj $iv): bool
    {
        $lo = AnalyzerJs::jsnum($iv->get('lo'));
        $hi = AnalyzerJs::jsnum($iv->get('hi'));
        if ($lo > $hi) {
            return true;
        }
        if ($lo === $hi) {
            return !($iv->get('loInclusive') && $iv->get('hiInclusive'));
        }
        return false;
    }

    /** Is the numeric part of a field's `where` conjunction satisfiable (an empty interval is not)? */
    public static function numericConjunctionSatisfiable(mixed $conditions): bool
    {
        $byField = [];
        foreach (AnalyzerJs::reqList($conditions) as $c) {
            if (!Predicates::isLeafCondition($c) || $c->has('ref')) {
                continue;
            }
            $k = 'k' . $c->get('field');
            $byField[$k] = self::tightenInterval($byField[$k] ?? self::fullInterval(), AnalyzerJs::own($c, 'op'), AnalyzerJs::own($c, 'value'));
        }
        foreach ($byField as $iv) {
            if (self::intervalEmpty($iv)) {
                return false;
            }
        }
        return true;
    }

    public static function predicateNumericSatisfiable(mixed $where): bool
    {
        if (!AnalyzerJs::isArr($where)) {
            return true;
        }
        return self::numericConjunctionSatisfiable($where);
    }

    // ---- model --------------------------------------------------------------------------------------------------------------

    /** A value that is not a policy is an empty policy (the verifier admits nothing under it). */
    public static function normalizePolicy(mixed $p): Obj
    {
        if (!($p instanceof Obj)) {
            return Obj::of(['predicates' => [], 'caveats' => [], 'vetoes' => [], 'tighten' => []]);
        }
        $arr = static function (string $k) use ($p): array {
            $v = AnalyzerJs::own($p, $k);
            return AnalyzerJs::isArr($v) ? $v : [];
        };
        return Obj::of(['predicates' => $arr('predicates'), 'caveats' => $arr('caveats'), 'vetoes' => $arr('vetoes'), 'tighten' => $arr('tighten')]);
    }

    /** The predicates whose literals shape the grid: the permits plus every veto and tighten trigger. @return list<mixed> */
    public static function probeSet(Obj $m): array
    {
        $out = $m->get('predicates');
        foreach ($m->get('vetoes') as $v) {
            $out[] = AnalyzerJs::jget($v, 'when');
            $unless = AnalyzerJs::jget($v, 'unless');
            if (AnalyzerJs::isArr($unless) && count($unless) > 0) {
                $out[] = Obj::of(['verb' => '*', 'where' => $unless]);
            }
            $over = AnalyzerJs::jget($v, 'over');
            if (AnalyzerJs::truthy($over)) {
                $out[] = Obj::of(['verb' => '*', 'where' => [Obj::of(['field' => AnalyzerJs::jget($over, 'path'), 'op' => 'gt',
                    'value' => AnalyzerJs::jget($over, 'threshold')])]]);
            }
        }
        foreach ($m->get('tighten') as $t) {
            $out[] = Obj::of(['verb' => '*', 'where' => [AnalyzerJs::jget($t, 'when')]]);
        }
        foreach ($m->get('meets') as $x) {
            foreach (self::probeSet($x) as $y) {
                $out[] = $y;
            }
        }
        return $out;
    }

    /** @param list<string> $reasons */
    private static function conditionUndecidable(mixed $c, array &$reasons): void
    {
        if (!self::isObjOrArr($c)) {
            return;
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of') && AnalyzerJs::isArr($c->get('all_of'))) {
                foreach ($c->get('all_of') as $x) {
                    self::conditionUndecidable($x, $reasons);
                }
            } elseif ($c->has('any_of') && AnalyzerJs::isArr($c->get('any_of'))) {
                foreach ($c->get('any_of') as $x) {
                    self::conditionUndecidable($x, $reasons);
                }
            } elseif ($c->has('not')) {
                self::conditionUndecidable($c->get('not'), $reasons);
            }
            return;
        }
        if (!Predicates::isLeafCondition($c)) {
            return;
        }
        if ($c->has('ref')) {
            self::addUnique($reasons, 'cross-field `ref` condition — the relation between two fields is not resolved');
        }
        if ($c->get('field') === 'action.params') {
            self::addUnique($reasons, 'condition on the whole `action.params` object is not enumerated precisely');
        }
        $op = AnalyzerJs::own($c, 'op');
        if (in_array($op, ['lt', 'lte', 'gt', 'gte'], true) && !AnalyzerJs::isFin(AnalyzerJs::own($c, 'value'))) {
            self::addUnique($reasons, '`' . $op . '` against a non-numeric operand — string ordering is not enumerated exactly');
        }
        if (in_array($op, ['like', 'matches', 'is_a', 'member_of'], true)) {
            self::addUnique($reasons, '`' . $op . '` condition — matched by over-approximation, not enumerated exactly');
        }
    }

    /** @return list<string> */
    private static function detectUndecidable(iterable $predicates): array
    {
        $reasons = [];
        foreach ($predicates as $p) {
            if (!self::isObjOrArr($p)) {
                continue;
            }
            $r = AnalyzerJs::own($p, 'resource');
            if (is_string($r) && str_starts_with($r, 're:')) {
                self::addUnique($reasons, 're: regex resource matcher — resource dimension cannot be soundly enumerated');
            }
            $w = AnalyzerJs::own($p, 'where');
            if (AnalyzerJs::isArr($w)) {
                foreach ($w as $c) {
                    self::conditionUndecidable($c, $reasons);
                }
            }
        }
        return $reasons;
    }

    /** The analyzable model of a policy: {predicates, caveats, vetoes, tighten, meets, caveatSat, caveatReason?, revCap?, undecidable}. */
    public static function toModel(mixed $p): Obj
    {
        $n = self::normalizePolicy($p);
        $ca = self::analyzeCaveats($n->get('caveats'));
        $meet = $p instanceof Obj ? AnalyzerJs::own($p, 'meet') : AnalyzerJs::undef();
        $meets = [];
        if (AnalyzerJs::isArr($meet)) {
            foreach ($meet as $x) {
                $meets[] = self::toModel($x);
            }
        }
        $meetsSat = true;
        foreach ($meets as $x) {
            if (!$x->get('caveatSat')) {
                $meetsSat = false;
            }
        }
        $reason = null;
        if ($ca->get('sat') === true) {
            foreach ($meets as $x) {
                if (!$x->get('caveatSat')) {
                    $reason = $x->get('caveatReason');
                    break;
                }
            }
        } else {
            $reason = $ca->get('reason');
        }
        $caps = [];
        if ($ca->get('revCap') !== null) {
            $caps[] = $ca->get('revCap');
        }
        foreach ($meets as $x) {
            if ($x->get('revCap') !== null) {
                $caps[] = $x->get('revCap');
            }
        }
        $m = Obj::of([
            'predicates' => $n->get('predicates'), 'caveats' => $n->get('caveats'), 'vetoes' => $n->get('vetoes'),
            'tighten' => $n->get('tighten'), 'meets' => $meets, 'caveatSat' => $ca->get('sat') === true && $meetsSat,
        ]);
        if ($reason !== null) {
            $m->set('caveatReason', $reason);
        }
        if ($caps !== []) {
            $m->set('revCap', min($caps));
        }
        $seen = [];
        foreach (self::detectUndecidable(self::probeSet($m)) as $r) {
            self::addUnique($seen, $r);
        }
        foreach ($meets as $x) {
            foreach ($x->get('undecidable') as $r) {
                self::addUnique($seen, $r);
            }
        }
        $m->set('undecidable', $seen);
        return $m;
    }

    // ---- probe collection ---------------------------------------------------------------------------------------------------

    /** @param array<string,mixed> $st */
    private static function addVerb(array &$st, mixed $v): void
    {
        $k = is_string($v) ? 's:' . $v : ($v instanceof Obj ? 'o:' . spl_object_id($v) : 'x:' . self::valueKey($v));
        if (!isset($st['vseen'][$k])) {
            $st['vseen'][$k] = true;
            $st['verbs'][] = $v;
        }
    }

    /** @param array<string,mixed> $st */
    private static function addResource(array &$st, string $r): void
    {
        $k = 'k' . $r;
        if (!isset($st['rseen'][$k])) {
            $st['rseen'][$k] = true;
            $st['res'][] = $r;
        }
    }

    /** @param array<string,mixed> $st */
    private static function addVerbLiterals(Obj $c, array &$st): void
    {
        $v = AnalyzerJs::own($c, 'value');
        $op = AnalyzerJs::own($c, 'op');
        if (in_array($op, ['eq', 'ne', 'prefix', 'like', 'is_a'], true)) {
            if (is_string($v)) {
                self::addVerb($st, $v);
            }
        } elseif (($op === 'in' || $op === 'nin') && AnalyzerJs::isArr($v)) {
            foreach ($v as $x) {
                if (is_string($x)) {
                    self::addVerb($st, $x);
                }
            }
        }
    }

    /** @param array<string,mixed> $st */
    private static function classifyResource(array &$st, mixed $r): void
    {
        if ($r instanceof Undef || $r === '*') {
            return;
        }
        if (!is_string($r)) {
            throw new \TypeError('resource matcher is not a string');
        }
        if (str_starts_with($r, 're:')) {
            return;
        }
        if (str_ends_with($r, '*')) {
            $body = substr($r, 0, -1);
            self::addResource($st, $body);
            self::addResource($st, $body . 'x');
            return;
        }
        self::addResource($st, $r);
    }

    /** @param array<string,mixed> $st */
    private static function handleCond(array &$st, mixed $c): void
    {
        if (!self::isObjOrArr($c)) {
            return;
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of') && AnalyzerJs::isArr($c->get('all_of'))) {
                foreach ($c->get('all_of') as $x) {
                    self::handleCond($st, $x);
                }
            } elseif ($c->has('any_of') && AnalyzerJs::isArr($c->get('any_of'))) {
                foreach ($c->get('any_of') as $x) {
                    self::handleCond($st, $x);
                }
            } elseif ($c->has('not')) {
                self::handleCond($st, $c->get('not'));
            }
            return;
        }
        if (!Predicates::isLeafCondition($c)) {
            return;
        }
        $field = $c->get('field');
        if ($field === 'action.verb') {
            self::addVerbLiterals($c, $st);
            return;
        }
        if ($field === 'action.resource') {
            $v = AnalyzerJs::own($c, 'value');
            if (AnalyzerJs::own($c, 'op') === 'prefix' && is_string($v)) {
                self::classifyResource($st, $v . '*');
            } elseif (is_string($v)) {
                self::classifyResource($st, $v);
            } elseif (AnalyzerJs::isArr($v)) {
                foreach ($v as $x) {
                    if (is_string($x)) {
                        self::classifyResource($st, $x);
                    }
                }
            }
            return;
        }
        $fk = 'k' . $field;
        if (!isset($st['fc'][$fk])) {
            $st['fc'][$fk] = [];
            $st['fo'][] = $field;
        }
        $st['fc'][$fk][] = $c;
    }

    /**
     * The grid dimensions {verbs, resources, revClasses, fields:[{path, values}]} of a set of predicate sets
     * ({predicateSets, extraVerbs?, extraResources?, extraFieldConditions?, varyReversibility}); an absent value is ABSENT.
     */
    public static function collectProbes(Obj $inputs): Obj
    {
        $st = ['verbs' => [], 'vseen' => [], 'res' => [], 'rseen' => [], 'fc' => [], 'fo' => []];
        foreach (Jsx::iter(AnalyzerJs::nn(AnalyzerJs::own($inputs, 'extraVerbs'), [])) as $v) {
            self::addVerb($st, $v);
        }
        foreach (AnalyzerJs::reqList($inputs->get('predicateSets')) as $lst) {
            foreach (AnalyzerJs::reqList($lst) as $p) {
                if (!self::isObjOrArr($p)) {
                    continue;
                }
                $verb = AnalyzerJs::own($p, 'verb');
                if (is_string($verb)) {
                    if ($verb !== '*') {
                        self::addVerb($st, $verb);
                    }
                } elseif (AnalyzerJs::isArr($verb)) {
                    foreach ($verb as $v) {
                        if (is_string($v) && $v !== '*') {
                            self::addVerb($st, $v);
                        }
                    }
                }
                self::classifyResource($st, AnalyzerJs::own($p, 'resource'));
                $w = AnalyzerJs::own($p, 'where');
                if (AnalyzerJs::isArr($w)) {
                    foreach ($w as $c) {
                        self::handleCond($st, $c);
                    }
                }
            }
        }
        foreach (Jsx::iter(AnalyzerJs::nn(AnalyzerJs::own($inputs, 'extraResources'), [])) as $r) {
            self::classifyResource($st, $r);
        }
        foreach (Jsx::iter(AnalyzerJs::nn(AnalyzerJs::own($inputs, 'extraFieldConditions'), [])) as $ec) {
            $cond = AnalyzerJs::spread($ec->get('cond'));
            $cond->set('field', $ec->get('path'));
            self::handleCond($st, $cond);
        }
        $fields = [];
        foreach ($st['fo'] as $path) {
            $values = self::fieldProbes($st['fc']['k' . $path]);
            $values[] = self::absent();
            $fields[] = Obj::of(['path' => $path, 'values' => $values]);
        }
        $verbs = $st['verbs'];
        $verbs[] = self::FRESH_VERB;
        $res = $st['res'];
        $res[] = self::FRESH_RESOURCE;
        return Obj::of([
            'verbs' => $verbs,
            'resources' => $res,
            'revClasses' => AnalyzerJs::truthy(AnalyzerJs::own($inputs, 'varyReversibility')) ? self::REVERSIBILITY_ORDER : [null],
            'fields' => $fields,
        ]);
    }

    /** The grid size (int, or float past the int range). */
    public static function productSize(Obj $pr): int|float
    {
        $n = count($pr->get('verbs')) * count($pr->get('resources')) * count($pr->get('revClasses'));
        foreach ($pr->get('fields') as $f) {
            $n *= count($f->get('values'));
        }
        return $n;
    }

    // ---- representatives ----------------------------------------------------------------------------------------------------

    /**
     * @param list<Obj> $fields
     * @param array<string,array{0:string,1:mixed}> $acc path-keyed assignments, mutated in place as the grid is walked
     */
    private static function enumerateFields(array $fields, int $i, array &$acc): \Generator
    {
        if ($i >= count($fields)) {
            $o = new Obj();
            foreach ($acc as [$path, $val]) {
                $o->set($path, $val);
            }
            yield $o;
            return;
        }
        $f = $fields[$i];
        $path = $f->get('path');
        foreach ($f->get('values') as $v) {
            if ($v === self::absent()) {
                unset($acc['k' . $path]);
            } else {
                $acc['k' . $path] = [$path, $v];
            }
            yield from self::enumerateFields($fields, $i + 1, $acc);
        }
    }

    /** Every grid point as {verb, resource, revClass (null = no class), assignments: {path: value}}. */
    public static function representatives(Obj $pr): \Generator
    {
        foreach ($pr->get('verbs') as $verb) {
            foreach ($pr->get('resources') as $resource) {
                foreach ($pr->get('revClasses') as $rev) {
                    $acc = [];
                    foreach (self::enumerateFields($pr->get('fields'), 0, $acc) as $assignments) {
                        yield Obj::of(['verb' => $verb, 'resource' => $resource, 'revClass' => $rev, 'assignments' => $assignments]);
                    }
                }
            }
        }
    }

    /** @param list<string> $segs */
    private static function insert(Obj $root, array $segs, mixed $value): void
    {
        $node = $root;
        $last = count($segs) - 1;
        for ($i = 0; $i < $last; $i++) {
            $key = $segs[$i];
            $nxt = $node->has($key) ? $node->get($key) : null;
            if ($nxt === null || $nxt instanceof \stdClass) {
                $created = new Obj();
                $node->set($key, $created);
                $node = $created;
            } else {
                $node = $nxt;
            }
        }
        $leaf = new \stdClass();
        $leaf->value = $value;
        $node->set($segs[$last], $leaf);
    }

    private static function materialize(Obj $node): Obj
    {
        $o = new Obj();
        foreach ($node->keys() as $k) {
            $c = $node->get($k);
            $o->set($k, $c instanceof \stdClass ? $c->value : self::materialize($c));
        }
        return $o;
    }

    private static function buildRoots(Obj $rep): Obj
    {
        $roots = ['action' => new Obj(), 'subject' => new Obj(), 'env' => new Obj()];
        $assignments = $rep->get('assignments');
        foreach ($assignments->keys() as $path) {
            $segs = explode('.', $path);
            if (count($segs) < 2 || !array_key_exists($segs[0], $roots)) {
                continue;
            }
            self::insert($roots[$segs[0]], array_slice($segs, 1), $assignments->get($path));
        }
        $action = Obj::of(['verb' => $rep->get('verb'), 'resource' => $rep->get('resource'), 'params' => new Obj()]);
        foreach ($roots['action']->keys() as $key) {
            $child = $roots['action']->get($key);
            if ($key === 'verb' || $key === 'resource') {
                continue;
            }
            if ($key === 'params') {
                if (!($child instanceof \stdClass)) {
                    $action->set('params', self::materialize($child));
                }
            } else {
                $action->set($key, $child instanceof \stdClass ? $child->value : self::materialize($child));
            }
        }
        if ($rep->get('revClass') !== null) {
            $action->set('reversibility_class', $rep->get('revClass'));
        }
        return Obj::of(['action' => $action, 'subject' => self::materialize($roots['subject']), 'env' => self::materialize($roots['env'])]);
    }

    private static function reversibilityOk(Obj $model, mixed $rev): bool
    {
        if (!$model->has('revCap')) {
            return true;
        }
        if ($rev === null || $rev instanceof Undef) {
            return false;   // a reversibility_max caveat denies an action with no class
        }
        if (!is_string($rev)) {
            return false;
        }
        $i = array_search($rev, self::REVERSIBILITY_ORDER, true);
        return $i !== false && $i <= $model->get('revCap');
    }

    /** Does a veto apply at this context? Veto polarity: whatever cannot be decided counts as applying. */
    public static function vetoApplies(mixed $v, Obj $ctx): bool
    {
        $w = AnalyzerJs::jget($v, 'when');
        if (!Prohibitions::whenMatches($w instanceof Undef ? null : $w, $ctx)) {
            return false;
        }
        $over = AnalyzerJs::jget($v, 'over');
        if (AnalyzerJs::truthy($over)) {
            $r = Predicates::resolvePath($ctx, AnalyzerJs::jget($over, 'path'));
            $val = $r['value'] ?? null;
            $isOver = !$r['found'] || !AnalyzerJs::isFin($val) || AnalyzerJs::jsnum($val) < 0
                || AnalyzerJs::jsGt($val, AnalyzerJs::jget($over, 'threshold'));
            if (!$isOver) {
                return false;
            }
        }
        $unless = AnalyzerJs::jget($v, 'unless');
        if (AnalyzerJs::jget($v, 'kind') !== 'approval' && AnalyzerJs::truthy($unless)) {
            if (!AnalyzerJs::isArr($unless)) {
                throw new \TypeError('unless.every is not a function');
            }
            $all = true;
            foreach ($unless as $c) {
                if (!Predicates::evaluateCondition($c, $ctx)) {
                    $all = false;
                    break;
                }
            }
            if ($all) {
                return false;
            }
        }
        return true;
    }

    /** The ternary decision 'allow' | 'escalate' | 'deny' of the permission layer at a concrete context. */
    public static function decisionAtContext(Obj $model, Obj $ctx): string
    {
        if (!Predicates::evaluatePredicates($model->get('predicates'), $ctx)['allowed']) {
            return 'deny';
        }
        $escalate = false;
        foreach ($model->get('vetoes') as $v) {
            if (!self::vetoApplies($v, $ctx)) {
                continue;
            }
            if (AnalyzerJs::jget($v, 'kind') === 'deny') {
                return 'deny';
            }
            $escalate = true;
        }
        foreach ($model->get('tighten') as $t) {
            $w = AnalyzerJs::jget($t, 'when');
            if (Predicates::evaluateConditionTri($w instanceof Undef ? null : $w, $ctx) === 'false') {
                continue;
            }
            if (AnalyzerJs::jget($t, 'signal') === 'deny') {
                return 'deny';
            }
            $escalate = true;
        }
        $own = $escalate ? 'escalate' : 'allow';
        foreach ($model->get('meets') as $x) {
            $d = self::decisionAtContext($x, $ctx);
            if ($d === 'deny') {
                return 'deny';
            }
            if ($d === 'escalate') {
                $own = 'escalate';
            }
        }
        return $own;
    }

    /** Ternary decision of a representative (the static caveat gate first). */
    public static function decide(Obj $model, Obj $rep): string
    {
        if (!$model->get('caveatSat')) {
            return 'deny';
        }
        if (!self::reversibilityOk($model, $rep->get('revClass'))) {
            return 'deny';
        }
        return self::decisionAtContext($model, self::buildRoots($rep));
    }

    public static function admits(Obj $model, Obj $rep): bool
    {
        return self::decide($model, $rep) !== 'deny';
    }

    public static function contextOfAction(mixed $action): Obj
    {
        $act = new Obj();
        $verb = AnalyzerJs::jget($action, 'verb');
        $resource = AnalyzerJs::jget($action, 'resource');
        if (!($verb instanceof Undef)) {
            $act->set('verb', $verb);
        }
        if (!($resource instanceof Undef)) {
            $act->set('resource', $resource);
        }
        $params = AnalyzerJs::jget($action, 'params');
        $act->set('params', AnalyzerJs::spread($params instanceof Undef ? null : $params));
        $rc = AnalyzerJs::jget($action, 'reversibilityClass');
        if (!($rc instanceof Undef)) {
            $act->set('reversibility_class', $rc);
        }
        $subj = AnalyzerJs::jget($action, 'subject');
        $env = AnalyzerJs::jget($action, 'env');
        return Obj::of(['action' => $act, 'subject' => AnalyzerJs::spread($subj instanceof Undef ? null : $subj),
            'env' => AnalyzerJs::spread($env instanceof Undef ? null : $env)]);
    }

    /** Ternary decision of a fully-specified action. */
    public static function decideAction(Obj $model, mixed $action): string
    {
        if (!$model->get('caveatSat')) {
            return 'deny';
        }
        if (!self::reversibilityOk($model, AnalyzerJs::jget($action, 'reversibilityClass'))) {
            return 'deny';
        }
        return self::decisionAtContext($model, self::contextOfAction($action));
    }

    public static function admitsAction(Obj $model, mixed $action): bool
    {
        return self::decideAction($model, $action) !== 'deny';
    }

    public static function repToAction(Obj $rep): Obj
    {
        $roots = self::buildRoots($rep);
        $action = Obj::of(['verb' => $rep->get('verb'), 'resource' => $rep->get('resource'),
            'params' => AnalyzerJs::copy($roots->get('action')->get('params'))]);
        if ($rep->get('revClass') !== null) {
            $action->set('reversibilityClass', $rep->get('revClass'));
        }
        if (count($roots->get('subject')->keys()) > 0) {
            $action->set('subject', $roots->get('subject'));
        }
        if (count($roots->get('env')->keys()) > 0) {
            $action->set('env', $roots->get('env'));
        }
        return $action;
    }

    /** Walk the grid to the first representative the predicate accepts: {hit?, overflow}. */
    public static function search(Obj $pr, callable $predicate, mixed $mx): Obj
    {
        if (self::productSize($pr) > AnalyzerJs::jsnum($mx)) {
            return Obj::of(['overflow' => true]);
        }
        foreach (self::representatives($pr) as $rep) {
            if ($predicate($rep)) {
                return Obj::of(['hit' => $rep, 'overflow' => false]);
            }
        }
        return Obj::of(['overflow' => false]);
    }

    /** Like `search`, collecting up to `limit` accepted representatives: {hits, overflow}. */
    public static function collect(Obj $pr, callable $predicate, mixed $mx, mixed $limit): Obj
    {
        if (self::productSize($pr) > AnalyzerJs::jsnum($mx)) {
            return Obj::of(['hits' => [], 'overflow' => true]);
        }
        $hits = [];
        $lim = AnalyzerJs::jsnum($limit);
        foreach (self::representatives($pr) as $rep) {
            if ($predicate($rep)) {
                $hits[] = $rep;
                if (count($hits) >= $lim) {
                    break;
                }
            }
        }
        return Obj::of(['hits' => $hits, 'overflow' => false]);
    }

    // ---- queries ------------------------------------------------------------------------------------------------------------

    /** The grid bound; anything but a non-negative finite number falls back to the default. */
    public static function boundOf(mixed $opts): int|float
    {
        if (is_array($opts) && !array_is_list($opts)) {
            $opts = Obj::of($opts);
        }
        $m = $opts instanceof Obj ? AnalyzerJs::own($opts, 'maxCombinations') : AnalyzerJs::undef();
        $f = AnalyzerJs::fin($m);
        return $f !== null && $f >= 0 ? $f : self::DEFAULT_MAX_COMBINATIONS;
    }

    private static function mergeWitness(Obj $witness, mixed $provided): Obj
    {
        $wp = $witness->get('params');
        $params = $wp instanceof Obj ? AnalyzerJs::copy($wp) : new Obj();
        $pp = AnalyzerJs::jget($provided, 'params');
        $sp = AnalyzerJs::spread($pp instanceof Undef ? null : $pp);
        foreach ($sp->keys() as $k) {
            $params->set($k, $sp->get($k));
        }
        $out = AnalyzerJs::uobj(['verb' => AnalyzerJs::jget($provided, 'verb'), 'resource' => AnalyzerJs::jget($provided, 'resource'),
            'params' => $params]);
        $rc = AnalyzerJs::jget($provided, 'reversibilityClass');
        if ($rc instanceof Undef || $rc === null) {
            $rc = AnalyzerJs::own($witness, 'reversibilityClass');
        }
        if (!($rc instanceof Undef)) {
            $out->set('reversibilityClass', $rc);
        }
        if ($witness->has('subject')) {
            $out->set('subject', $witness->get('subject'));
        }
        if ($witness->has('env')) {
            $out->set('env', $witness->get('env'));
        }
        return $out;
    }

    private static function caveatReasonOf(Obj $model): string
    {
        return $model->has('caveatReason') ? AnalyzerJs::jsStr($model->get('caveatReason')) : 'unknown';
    }

    /** Can any input complete `action` into one the policy admits? {reachable, witness?, approximate?, reason?}. */
    public static function reachable(mixed $policy, mixed $action, mixed $opts = null): Obj
    {
        $model = self::toModel($policy);
        $mx = self::boundOf($opts);
        if (!$model->get('caveatSat')) {
            return Obj::of(['reachable' => false, 'reason' => 'caveats unsatisfiable: ' . self::caveatReasonOf($model)]);
        }
        $rc = AnalyzerJs::jget($action, 'reversibilityClass');
        if (!($rc instanceof Undef) && $model->has('revCap')) {
            $idx = is_string($rc) && in_array($rc, self::REVERSIBILITY_ORDER, true) ? array_search($rc, self::REVERSIBILITY_ORDER, true) : -1;
            if ($idx < 0 || $idx > $model->get('revCap')) {
                return Obj::of(['reachable' => false, 'reason' => "reversibility class '" . AnalyzerJs::jsStr($rc) . "' exceeds the caveat cap"]);
            }
        }
        if (self::admitsAction($model, $action)) {
            return Obj::of(['reachable' => true, 'witness' => $action]);
        }
        $base = self::collectProbes(Obj::of(['predicateSets' => [self::probeSet($model)], 'varyReversibility' => $model->has('revCap')]));
        $provided = AnalyzerJs::nn(AnalyzerJs::jget($action, 'params'), new Obj());
        $fields = [];
        foreach ($base->get('fields') as $f) {
            $path = $f->get('path');
            if (str_starts_with($path, 'action.params.')) {
                $key = substr($path, strlen('action.params.'));
                if ($provided instanceof Obj && $provided->has($key)) {
                    $fields[] = Obj::of(['path' => $path, 'values' => [$provided->get($key)]]);
                    continue;
                }
            }
            $fields[] = $f;
        }
        if (!($rc instanceof Undef)) {
            $revClasses = [$rc];
        } elseif ($model->has('revCap')) {
            $revClasses = self::REVERSIBILITY_ORDER;
        } else {
            $revClasses = [null];
        }
        $pr = Obj::of(['verbs' => [AnalyzerJs::jget($action, 'verb')], 'resources' => [AnalyzerJs::jget($action, 'resource')],
            'revClasses' => $revClasses, 'fields' => $fields]);
        $outcome = self::search($pr, static fn(Obj $rep): bool => self::admits($model, $rep), $mx);
        if ($outcome->has('hit')) {
            return Obj::of(['reachable' => true, 'witness' => self::mergeWitness(self::repToAction($outcome->get('hit')), $action)]);
        }
        if ($outcome->get('overflow')) {
            return Obj::of(['reachable' => true, 'approximate' => true,
                'reason' => 'representative grid exceeded the bound; could not prove unreachable']);
        }
        if (count($model->get('undecidable')) > 0) {
            return Obj::of(['reachable' => true, 'approximate' => true,
                'reason' => 'over-approximated (' . implode('; ', $model->get('undecidable'))
                    . '); could not construct a witness but cannot prove unreachable']);
        }
        return Obj::of(['reachable' => false, 'reason' => 'no predicate admits this action for any input (proven over the decided fragment)']);
    }

    /** @param list<Obj> $models */
    private static function probesFor(array $models, mixed $verb = null): Obj
    {
        $sets = [];
        $vary = false;
        foreach ($models as $m) {
            $sets[] = self::probeSet($m);
            if ($m->has('revCap')) {
                $vary = true;
            }
        }
        $pr = self::collectProbes(Obj::of(['predicateSets' => $sets, 'varyReversibility' => $vary]));
        if ($verb !== null && !($verb instanceof Undef)) {
            $pr->set('verbs', [$verb]);
        }
        return $pr;
    }

    /** Does the policy deny everything (optionally restricted to `verb`)? Proven only over the decided fragment. */
    public static function alwaysDenies(mixed $policy, mixed $verb = null, mixed $opts = null): Obj
    {
        $model = self::toModel($policy);
        $mx = self::boundOf($opts);
        if (!$model->get('caveatSat')) {
            return Obj::of(['alwaysDenies' => true, 'reason' => 'caveats unsatisfiable: ' . self::caveatReasonOf($model)]);
        }
        $outcome = self::search(self::probesFor([$model], $verb), static fn(Obj $rep): bool => self::admits($model, $rep), $mx);
        if ($outcome->has('hit')) {
            return Obj::of(['alwaysDenies' => false, 'witness' => self::repToAction($outcome->get('hit'))]);
        }
        if ($outcome->get('overflow')) {
            return Obj::of(['alwaysDenies' => false, 'approximate' => true, 'reason' => 'grid exceeded the bound; cannot prove vacuity']);
        }
        if (count($model->get('undecidable')) > 0) {
            return Obj::of(['alwaysDenies' => false, 'approximate' => true,
                'reason' => 'over-approximated (' . implode('; ', $model->get('undecidable')) . '); cannot prove vacuity']);
        }
        return Obj::of(['alwaysDenies' => true]);
    }

    /** Does the policy admit EVERY action of `verb`? Proven only over the decided fragment. */
    public static function alwaysAllows(mixed $policy, mixed $verb, mixed $opts = null): Obj
    {
        $model = self::toModel($policy);
        $mx = self::boundOf($opts);
        if (!$model->get('caveatSat')) {
            return Obj::of(['alwaysAllows' => false, 'reason' => 'caveats unsatisfiable: ' . self::caveatReasonOf($model)]);
        }
        $outcome = self::search(self::probesFor([$model], $verb), static fn(Obj $rep): bool => !self::admits($model, $rep), $mx);
        if ($outcome->has('hit')) {
            return Obj::of(['alwaysAllows' => false, 'counterexample' => self::repToAction($outcome->get('hit'))]);
        }
        if ($outcome->get('overflow')) {
            return Obj::of(['alwaysAllows' => false, 'approximate' => true, 'reason' => 'grid exceeded the bound; cannot prove totality']);
        }
        if (count($model->get('undecidable')) > 0) {
            return Obj::of(['alwaysAllows' => false, 'approximate' => true,
                'reason' => 'over-approximated (' . implode('; ', $model->get('undecidable')) . '); cannot prove totality']);
        }
        return Obj::of(['alwaysAllows' => true]);
    }

    /** @param list<Obj> $models */
    private static function approxNote(array $models, bool $overflow): ?string
    {
        if ($overflow) {
            return 'representative grid exceeded the bound; cannot prove the relation';
        }
        $reasons = [];
        foreach ($models as $m) {
            foreach ($m->get('undecidable') as $r) {
                self::addUnique($reasons, $r);
            }
        }
        if ($reasons !== []) {
            return 'over-approximated (' . implode('; ', $reasons) . '); cannot prove the relation';
        }
        return null;
    }

    private static function relation(mixed $a, mixed $b, mixed $opts, callable $pred, string $key, string $witnessKey): Obj
    {
        $ma = self::toModel($a);
        $mb = self::toModel($b);
        $mx = self::boundOf($opts);
        $outcome = self::search(self::probesFor([$ma, $mb]), static fn(Obj $rep): bool => $pred($ma, $mb, $rep), $mx);
        if ($outcome->has('hit')) {
            return Obj::of([$key => false, $witnessKey => self::repToAction($outcome->get('hit'))]);
        }
        $note = self::approxNote([$ma, $mb], (bool)$outcome->get('overflow'));
        if ($note !== null) {
            return Obj::of([$key => false, 'approximate' => true, 'reason' => $note]);
        }
        return Obj::of([$key => true]);
    }

    /** Does `a` permit everything `b` permits? A counterexample is an action `b` admits that `a` denies. */
    public static function subsumes(mixed $a, mixed $b, mixed $opts = null): Obj
    {
        return self::relation($a, $b, $opts, static fn(Obj $ma, Obj $mb, Obj $r): bool => self::admits($mb, $r) && !self::admits($ma, $r),
            'subsumes', 'counterexample');
    }

    /** Is there no action both policies admit? A witness is one both admit. */
    public static function disjoint(mixed $a, mixed $b, mixed $opts = null): Obj
    {
        return self::relation($a, $b, $opts, static fn(Obj $ma, Obj $mb, Obj $r): bool => self::admits($ma, $r) && self::admits($mb, $r),
            'disjoint', 'witness');
    }

    /** Do the policies admit exactly the same actions? A counterexample is admitted by exactly one. */
    public static function equivalent(mixed $a, mixed $b, mixed $opts = null): Obj
    {
        return self::relation($a, $b, $opts, static fn(Obj $ma, Obj $mb, Obj $r): bool => self::admits($ma, $r) !== self::admits($mb, $r),
            'equivalent', 'counterexample');
    }

    private static function scopeMatches(mixed $scope, string $resource): bool
    {
        if (!is_string($scope)) {
            throw new \TypeError('scope.startsWith is not a function');
        }
        if ($scope === '*') {
            return true;
        }
        if (str_starts_with($scope, 're:')) {
            $src = substr($scope, 3);
            if (SafeRegex::utf16Len($src) > 200 || SafeRegex::utf16Len($resource) > Predicates::MAX_RE_RESOURCE_LEN
                || !SafeRegex::isSafeRegexSource($src)) {
                return false;
            }
            return SafeRegex::fullMatch($src, $resource) === true;
        }
        if (str_ends_with($scope, '*')) {
            return SafeRegex::startsWithUnits($resource, substr($scope, 0, -1));
        }
        return $scope === $resource;
    }

    /** @return list<string> */
    private static function intentViolationKinds(Obj $action, mixed $intent, mixed $amountField, mixed $minAmount): array
    {
        $kinds = [];
        $verbs = AnalyzerJs::jget($intent, 'verbs');
        if (!(AnalyzerJs::includes($verbs, '*') || AnalyzerJs::includes($verbs, $action->get('verb')))) {
            $kinds[] = 'off-verb';
        }
        $scopes = AnalyzerJs::reqList(AnalyzerJs::nn(AnalyzerJs::jget($intent, 'resourceScopes'), []));
        if (count($scopes) > 0) {
            $any = false;
            foreach ($scopes as $s) {
                if (self::scopeMatches($s, $action->get('resource'))) {
                    $any = true;
                    break;
                }
            }
            if (!$any) {
                $kinds[] = 'off-scope';
            }
        }
        $maxAmount = AnalyzerJs::jget($intent, 'maxAmount');
        if (!($maxAmount instanceof Undef)) {
            $amt = AnalyzerJs::own(AnalyzerJs::nn(AnalyzerJs::own($action, 'params'), new Obj()), AnalyzerJs::jsStr($amountField));
            if (AnalyzerJs::isFin($amt)) {
                if (AnalyzerJs::jsGt($amt, $maxAmount)) {
                    $kinds[] = 'over-amount';
                } elseif (AnalyzerJs::jsLt($amt, $minAmount)) {
                    $kinds[] = 'under-amount';
                }
            }
        }
        return $kinds;
    }

    private static function scopeStartsRe(mixed $s): bool
    {
        if (!is_string($s)) {
            throw new \TypeError('s.startsWith is not a function');
        }
        return str_starts_with($s, 're:');
    }

    /** Does the policy admit ONLY actions inside the declared intent envelope? {conforms, violations, approximate?, reason?}. */
    public static function intentConformance(mixed $policy, mixed $intent, mixed $opts = null): Obj
    {
        $model = self::toModel($policy);
        $mx = self::boundOf($opts);
        $amountField = AnalyzerJs::nn(AnalyzerJs::jget($intent, 'amountField'), 'amount');
        $minAmount = AnalyzerJs::nn(AnalyzerJs::jget($intent, 'minAmount'), 0);
        if (!$model->get('caveatSat')) {
            return Obj::of(['conforms' => true, 'violations' => []]);
        }
        $extraConds = [];
        $maxAmount = AnalyzerJs::jget($intent, 'maxAmount');
        if (!($maxAmount instanceof Undef)) {
            $path = 'action.params.' . AnalyzerJs::jsStr($amountField);
            $extraConds[] = Obj::of(['path' => $path, 'cond' => Obj::of(['field' => $path, 'op' => 'lte', 'value' => $maxAmount])]);
            $extraConds[] = Obj::of(['path' => $path, 'cond' => Obj::of(['field' => $path, 'op' => 'gte', 'value' => $minAmount])]);
        }
        $verbs = AnalyzerJs::reqList(AnalyzerJs::jget($intent, 'verbs'));
        $extraVerbs = [];
        foreach ($verbs as $v) {
            if ($v !== '*') {
                $extraVerbs[] = $v;
            }
        }
        $pr = self::collectProbes(Obj::of([
            'predicateSets' => [self::probeSet($model)],
            'extraVerbs' => $extraVerbs,
            'extraResources' => AnalyzerJs::nn(AnalyzerJs::jget($intent, 'resourceScopes'), []),
            'extraFieldConditions' => $extraConds,
            'varyReversibility' => $model->has('revCap'),
        ]));
        $fp = 1;
        foreach ($pr->get('fields') as $f) {
            $fp *= count($f->get('values'));
        }
        if (count($pr->get('verbs')) * count($pr->get('resources')) * count($pr->get('revClasses')) * $fp > AnalyzerJs::jsnum($mx)) {
            return Obj::of(['conforms' => false, 'approximate' => true, 'violations' => [],
                'reason' => 'grid exceeded the bound; cannot prove conformance']);
        }
        $violations = [];
        foreach (self::representatives($pr) as $rep) {
            if (!self::admits($model, $rep)) {
                continue;
            }
            $action = self::repToAction($rep);
            $kinds = self::intentViolationKinds($action, $intent, $amountField, $minAmount);
            if ($kinds !== []) {
                $violations[] = Obj::of(['action' => $action, 'kinds' => $kinds]);
                if (count($violations) >= 16) {
                    break;
                }
            }
        }
        if ($violations !== []) {
            return Obj::of(['conforms' => false, 'violations' => $violations]);
        }
        $scopes = AnalyzerJs::reqList(AnalyzerJs::nn(AnalyzerJs::jget($intent, 'resourceScopes'), []));
        $intentRegex = false;
        foreach ($scopes as $s) {
            if (self::scopeStartsRe($s)) {
                $intentRegex = true;
                break;
            }
        }
        if (count($model->get('undecidable')) > 0 || $intentRegex) {
            $reasons = $model->get('undecidable');
            if ($intentRegex) {
                $reasons[] = 're: intent resource scope not enumerated soundly';
            }
            return Obj::of(['conforms' => false, 'approximate' => true, 'violations' => [],
                'reason' => 'over-approximated (' . implode('; ', $reasons) . '); cannot prove conformance']);
        }
        return Obj::of(['conforms' => true, 'violations' => []]);
    }

    /** Exact admission of a fully-specified action (no existential search). */
    public static function admitsConcrete(mixed $policy, mixed $action): bool
    {
        return self::admitsAction(self::toModel($policy), $action);
    }
}
