<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/AnalyzerCore.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/Predicates.php';

/**
 * Quantitative and ternary static queries over a policy (the most that can ever be spent, the actions that need a human, the reach
 * of a delegation chain, a first-class diff) and the exposure of a workflow DAG. Everything sits outside the trusted core, on the
 * same bounded enumeration as the rest of the analyzer; every witness is re-checked by the real evaluator.
 */
final class AnalyzerExposure
{
    public const HUGE = 9007199254740991;
    public const PATH_CAP = 1000000;
    public const WIDEN = ['deny->allow', 'deny->escalate', 'escalate->allow'];

    /** `Number(v)`. */
    private static function n(mixed $v): float
    {
        return AnalyzerJs::toNumber($v);
    }

    /** `Math.max`: NaN when any argument is NaN. */
    private static function jsMax(float ...$xs): float
    {
        $m = -INF;
        foreach ($xs as $x) {
            if (is_nan($x)) {
                return NAN;
            }
            if ($x > $m) {
                $m = $x;
            }
        }
        return $m;
    }

    /** `Math.min`: NaN when any argument is NaN. */
    private static function jsMin(float ...$xs): float
    {
        $m = INF;
        foreach ($xs as $x) {
            if (is_nan($x)) {
                return NAN;
            }
            if ($x < $m) {
                $m = $x;
            }
        }
        return $m;
    }

    /** @return Obj {spec, catalogued}: a catalogued verb's spec, else the fail-closed spec (irreversible, maximum blast radius). */
    public static function resolveAction(mixed $catalog, string $verb): Obj
    {
        $spec = self::catalogGet($catalog, $verb);
        if ($spec !== null) {
            return Obj::of(['spec' => $spec, 'catalogued' => true]);
        }
        $parts = explode('.', $verb);
        $rest = implode('.', array_slice($parts, 1));
        return Obj::of([
            'spec' => Obj::of([
                'connector' => $parts[0], 'action' => $rest !== '' ? $rest : $verb, 'verb' => $verb,
                'reversibility' => 'irreversible', 'blastRadius' => 1, 'description' => '(uncatalogued) ' . $verb,
            ]),
            'catalogued' => false,
        ]);
    }

    private static function catalogGet(mixed $catalog, string $verb): mixed
    {
        if ($catalog === null || $catalog instanceof Undef) {
            $catalog = Catalog::BUILTIN_ACTIONS;
        }
        if ($catalog instanceof Catalog) {
            $s = $catalog->get($verb);
            return $s === null ? null : Obj::of($s);
        }
        if ($catalog instanceof Obj) {
            return $catalog->get($verb);
        }
        if (!is_array($catalog)) {
            throw new \TypeError('catalog is not iterable');
        }
        $found = null;
        foreach ($catalog as $a) { // a list of specs: a later spec with the same verb replaces an earlier one
            if (is_array($a) && !array_is_list($a)) {
                $a = Obj::of($a);
            }
            if ($a instanceof Obj && $a->get('verb') === $verb) {
                $found = $a;
            }
        }
        return $found;
    }

    /** @param list<mixed> $into */
    private static function condThresholds(mixed $c, string $path, array &$into): void
    {
        if (!($c instanceof Obj) && !AnalyzerJs::isArr($c)) {
            return;
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of') && AnalyzerJs::isArr($c->get('all_of'))) {
                foreach ($c->get('all_of') as $x) {
                    self::condThresholds($x, $path, $into);
                }
            } elseif ($c->has('any_of') && AnalyzerJs::isArr($c->get('any_of'))) {
                foreach ($c->get('any_of') as $x) {
                    self::condThresholds($x, $path, $into);
                }
            } elseif ($c->has('not')) {
                self::condThresholds($c->get('not'), $path, $into);
            }
            return;
        }
        if (!Predicates::isLeafCondition($c) || $c->get('field') !== $path) {
            return;
        }
        $v = AnalyzerJs::own($c, 'value');
        if (AnalyzerJs::isFin($v)) {
            $into[] = $v;
        } elseif (AnalyzerJs::isArr($v)) {
            foreach ($v as $x) {
                if (AnalyzerJs::isFin($x)) {
                    $into[] = $x;
                }
            }
        }
    }

    /**
     * Every numeric literal the policy compares `path` against, ascending and de-duplicated.
     *
     * @return list<mixed>
     */
    public static function thresholdsOf(Obj $model, string $path): array
    {
        $out = [];
        foreach (AnalyzerCore::probeSet($model) as $p) {
            $w = AnalyzerJs::nn(AnalyzerJs::jget($p, 'where'), []);
            foreach (AnalyzerJs::reqList($w) as $c) {
                self::condThresholds($c, $path, $out);
            }
        }
        foreach (AnalyzerJs::reqList($model->get('vetoes')) as $v) {
            $over = AnalyzerJs::jget($v, 'over');
            if (AnalyzerJs::truthy($over) && AnalyzerJs::jget($over, 'path') === $path && AnalyzerJs::isNum(AnalyzerJs::jget($over, 'threshold'))) {
                $out[] = AnalyzerJs::jget($over, 'threshold');
            }
        }
        $seen = [];
        foreach ($out as $x) {
            $f = AnalyzerJs::jsnum($x);
            $key = $f == 0.0 ? '0' : sprintf('%.17g', $f);
            if (!array_key_exists($key, $seen)) {
                $seen[$key] = [$f, $x];
            }
        }
        $pairs = array_values($seen);
        usort($pairs, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
        return array_map(static fn(array $p): mixed => $p[1], $pairs);
    }

    private static function pinned(Obj $pr, string $path, mixed $value, mixed $resource): Obj
    {
        $fields = [];
        foreach ($pr->get('fields') as $f) {
            if ($f->get('path') !== $path) {
                $fields[] = $f;
            }
        }
        $fields[] = Obj::of(['path' => $path, 'values' => [$value]]);
        $o = AnalyzerJs::copy($pr);
        $o->set('resources', $resource instanceof Undef ? $pr->get('resources') : [$resource]);
        $o->set('fields', $fields);
        return $o;
    }

    private static function peakAt(Obj $model, Obj $o, string $level): Obj
    {
        $field = AnalyzerJs::nn(AnalyzerJs::jget($o, 'amountField'), 'amount');
        $fname = AnalyzerJs::jsStr($field);
        $path = 'action.params.' . $fname;
        $mx = AnalyzerCore::boundOf($o);
        $base = AnalyzerCore::collectProbes(Obj::of(['predicateSets' => [AnalyzerCore::probeSet($model)], 'varyReversibility' => $model->has('revCap')]));
        $base->set('verbs', [AnalyzerJs::jget($o, 'verb')]);
        $T = self::thresholdsOf($model, $path);
        $Tn = array_map(self::n(...), $T);
        $lo = self::jsMax(0.0, self::n(AnalyzerJs::nn(AnalyzerJs::jget($o, 'min'), 0)));
        $hi = self::n(AnalyzerJs::nn(AnalyzerJs::jget($o, 'max'), INF));
        $raw = [];
        $cnt = count($Tn);
        foreach ($Tn as $i => $t) {
            $raw[] = $t - 1;
            $raw[] = $t;
            if ($i + 1 < $cnt) {
                $raw[] = ($t + $Tn[$i + 1]) / 2;
            }
        }
        $raw[] = $cnt > 0 ? $Tn[$cnt - 1] + 1 : 0.0;
        $raw[] = (float)self::HUGE;
        $raw[] = $lo;
        if (is_finite($hi)) {
            $raw[] = $hi;
        }
        $uniq = [];
        foreach ($raw as $c) {
            $uniq[$c == 0.0 ? '0' : sprintf('%.17g', $c)] ??= $c;
        }
        $cands = [];
        foreach ($uniq as $c) {
            if ($lo <= $c && $c <= $hi && is_finite($c)) {
                $cands[] = $c;
            }
        }
        rsort($cands);
        $resource = AnalyzerJs::jget($o, 'resource');
        $ok = static function (Obj $rep) use ($model, $level): bool {
            $d = AnalyzerCore::decide($model, $rep);
            return $level === 'allow' ? $d === 'allow' : $d !== 'deny';
        };
        $overflow = false;
        foreach ($cands as $c) {
            $out = AnalyzerCore::search(self::pinned($base, $path, $c, $resource), $ok, $mx);
            if (AnalyzerJs::truthy($out->get('overflow'))) {
                $overflow = true;
                break;
            }
            $hit = $out->get('hit');
            if (!$out->has('hit') || $hit === null) {
                continue;
            }
            $act = static function (mixed $v) use ($hit, $fname): Obj {
                $a = AnalyzerJs::copy(AnalyzerCore::repToAction($hit));
                $p = $a->get('params');
                $np = AnalyzerJs::truthy($p) && $p instanceof Obj ? AnalyzerJs::copy($p) : new Obj();
                $np->set($fname, $v);
                $a->set('params', $np);
                return $a;
            };
            $holds = static function (Obj $a) use ($model, $level): bool {
                $d = AnalyzerCore::decideAction($model, $a);
                return $level === 'allow' ? $d === 'allow' : $d !== 'deny';
            };
            $top = $cnt > 0 ? $Tn[$cnt - 1] : -INF;
            if ($c > $top) { // the cell above every threshold: unbounded unless the schema caps the parameter
                if (is_finite($hi)) {
                    return Obj::of(['peak' => Obj::of(['admitted' => true, 'max' => $hi, 'attained' => $holds($act($hi)), 'witness' => $act($hi)]), 'overflow' => false]);
                }
                return Obj::of(['peak' => Obj::of(['admitted' => true, 'max' => INF, 'attained' => false, 'witness' => $act(self::HUGE)]), 'overflow' => false]);
            }
            if (in_array($c, $Tn, false)) {
                return Obj::of(['peak' => Obj::of(['admitted' => true, 'max' => $c, 'attained' => true, 'witness' => $act($c)]), 'overflow' => false]);
            }
            $nxt = null;
            foreach ($Tn as $t) {
                if ($t > $c) {
                    $nxt = $t;
                    break;
                }
            }
            if ($nxt === null) {
                throw new \RuntimeException('no threshold above the cell');
            }
            if (AnalyzerJs::jget($o, 'integer') === true) {
                $m = ceil($nxt) - 1;
                if ($m >= $c && $holds($act($m))) {
                    return Obj::of(['peak' => Obj::of(['admitted' => true, 'max' => $m, 'attained' => true, 'witness' => $act($m)]), 'overflow' => false]);
                }
            }
            return Obj::of(['peak' => Obj::of(['admitted' => true, 'max' => $nxt, 'attained' => false, 'witness' => $act($c)]), 'overflow' => false]);
        }
        return Obj::of(['peak' => Obj::of(['admitted' => false, 'max' => 0, 'attained' => false]), 'overflow' => $overflow]);
    }

    private static function universal(mixed $p, mixed $verb): bool
    {
        $pv = AnalyzerJs::jget($p, 'verb');
        $verbOk = AnalyzerJs::strictEq($pv, '*') || AnalyzerJs::strictEq($pv, $verb)
            || (AnalyzerJs::isArr($pv) && (AnalyzerJs::includes($pv, '*') || AnalyzerJs::includes($pv, $verb)));
        $res = AnalyzerJs::jget($p, 'resource');
        $where = AnalyzerJs::jget($p, 'where');
        if (!$verbOk || !($res instanceof Undef || AnalyzerJs::strictEq($res, '*'))) {
            return false;
        }
        if ($where === null) {
            throw new \TypeError("cannot read properties of null (reading 'length')");
        }
        return $where instanceof Undef || AnalyzerJs::strictEq(AnalyzerJs::jget($where, 'length'), 0);
    }

    private static function ceilDiv(mixed $a, mixed $b): float
    {
        $q = fdiv(self::n($a), self::n($b));
        return is_finite($q) ? ceil($q) : $q;
    }

    private static function windowBound(Obj $model, mixed $c, Obj $o, Obj $peak): Obj
    {
        $W = AnalyzerJs::jget($o, 'windowSecs');
        $path = 'action.params.' . AnalyzerJs::jsStr(AnalyzerJs::nn(AnalyzerJs::jget($o, 'amountField'), 'amount'));
        $per = $peak->get('admitted') === true ? self::n($peak->get('max')) : 0.0;
        $basis = [];
        $notApplied = [];
        $maxActions = INF;
        $limitActions = static function (mixed $n, mixed $perSecs, string $why) use (&$maxActions, &$basis, $W): void {
            // a sliding limit of n per perSecs: at most n per started period
            $k = $W instanceof Undef ? INF : self::n($n) * self::ceilDiv($W, $perSecs);
            if ($k < $maxActions) {
                $maxActions = $k;
                $basis[] = $why;
            }
        };
        $caveats = array_values(AnalyzerJs::reqList($model->get('caveats')));
        foreach (AnalyzerJs::reqList($model->get('meets')) as $m) {
            foreach (AnalyzerJs::reqList(AnalyzerJs::jget($m, 'caveats')) as $x) {
                $caveats[] = $x;
            }
        }
        $invs = $c instanceof Obj ? AnalyzerJs::own($c, 'invariants') : AnalyzerJs::undef();
        $invs = AnalyzerJs::isArr($invs) ? $invs : [];
        foreach ($caveats as $cv) {
            $mx = AnalyzerJs::jget($cv, 'max');
            $ps = AnalyzerJs::jget($cv, 'per_secs');
            if (AnalyzerJs::jget($cv, 'type') === 'rate' && AnalyzerJs::isNum($mx) && AnalyzerJs::isNum($ps) && AnalyzerJs::jsnum($ps) > 0) {
                $limitActions($mx, $ps, 'rate caveat ' . AnalyzerJs::numStr(AnalyzerJs::jsnum($mx)) . '/' . AnalyzerJs::numStr(AnalyzerJs::jsnum($ps)) . 's');
            }
        }
        foreach ($invs as $inv) {
            if (AnalyzerJs::jget($inv, 'kind') !== 'rate') {
                continue;
            }
            if (self::universal(AnalyzerJs::jget($inv, 'when'), AnalyzerJs::jget($o, 'verb'))) {
                $limitActions(AnalyzerJs::jget($inv, 'max'), AnalyzerJs::jget($inv, 'window_secs'), 'rate invariant ' . AnalyzerJs::jsStr(AnalyzerJs::jget($inv, 'id')));
            } else {
                $notApplied[] = AnalyzerJs::jget($inv, 'id');
            }
        }
        $bound = $per == 0.0 ? 0.0 : ($maxActions == INF ? INF : $per * $maxActions);
        if (is_finite($per) && $per > 0) {
            array_unshift($basis, 'per-action ceiling');
        }
        foreach ($caveats as $cv) {
            $lim = AnalyzerJs::jget($cv, 'limit');
            if (AnalyzerJs::jget($cv, 'type') !== 'budget_alloc' || !AnalyzerJs::isNum($lim)) {
                continue;
            }
            $bm = AnalyzerJs::jget($o, 'budgetModel');
            $kappa = AnalyzerJs::jget($o, 'kappa');
            $limF = AnalyzerJs::jsnum($lim);
            if ($bm === 'dollars') {
                if ($limF < $bound) {
                    $bound = $limF; // in the dollar model the allocation is a lifetime cap on the total
                    $basis[] = 'budget_alloc limit ' . AnalyzerJs::numStr($limF);
                }
            } elseif ($bm === 'risk' && AnalyzerJs::isNum($kappa) && AnalyzerJs::jsnum($kappa) > 0) {
                $r = AnalyzerJs::jget($o, 'blastRadius');
                if ($r instanceof Undef || $r === null) {
                    $r = self::resolveAction(null, AnalyzerJs::jget($o, 'verb'))->get('spec')->get('blastRadius');
                }
                $cost = AnalyzerJs::jsnum($kappa) * self::jsMin(1.0, self::jsMax(0.0, self::n($r)));
                $nn = $cost > 0 ? floor(fdiv($limF, $cost)) : INF;
                if ($nn < $maxActions) {
                    $maxActions = $nn;
                    $bound = $nn == 0.0 ? 0.0 : (is_finite($per) && $per > 0 ? $per * $nn : $bound);
                    $basis[] = 'budget_alloc ' . AnalyzerJs::numStr($limF) . ' / cost ' . AnalyzerJs::numStr($cost) . ' = ' . AnalyzerJs::numStr($nn) . ' actions';
                }
            } else {
                $notApplied[] = 'budget_alloc ' . AnalyzerJs::numStr($limF) . ' (trust-budget units; pass budgetModel and kappa)';
            }
        }
        foreach ($invs as $inv) {
            if (AnalyzerJs::jget($inv, 'kind') !== 'cap') {
                continue;
            }
            if (!self::universal(AnalyzerJs::jget($inv, 'when'), AnalyzerJs::jget($o, 'verb')) || AnalyzerJs::jget($inv, 'amount') !== $path) {
                $notApplied[] = AnalyzerJs::jget($inv, 'id');
                continue;
            }
            $ws = AnalyzerJs::jget($inv, 'window_secs');
            if (!($ws instanceof Undef) && $W instanceof Undef) {
                continue; // a windowed cap says nothing about a lifetime total
            }
            $cap = ($ws instanceof Undef || $W instanceof Undef) ? self::n(AnalyzerJs::jget($inv, 'max'))
                : self::n(AnalyzerJs::jget($inv, 'max')) * self::ceilDiv($W, $ws);
            if ($cap < $bound) {
                $bound = $cap;
                $basis[] = 'cap invariant ' . AnalyzerJs::jsStr(AnalyzerJs::jget($inv, 'id'));
            }
        }
        $na = [];
        foreach ($notApplied as $x) {
            if (!($x instanceof Undef)) {
                $na[] = $x;
            }
        }
        $out = Obj::of(['maxActions' => $maxActions, 'bound' => $bound, 'basis' => $basis, 'notApplied' => $na]);
        if (!($W instanceof Undef)) {
            $out->set('secs', $W);
        }
        $w = $peak->get('witness');
        $pmax = self::n($peak->get('max'));
        if ($peak->get('admitted') === true && $w !== null && is_finite($maxActions) && is_finite($pmax) && $pmax > 0) {
            $out->set('sequence', Obj::of(['action' => $w, 'repeat' => $maxActions]));
        }
        return $out;
    }

    private static function unbounded(): Obj
    {
        return Obj::of(['admitted' => true, 'max' => INF, 'attained' => false]);
    }

    /**
     * The most that can ever leave under a policy: the largest single action, the largest autonomous action and the windowed
     * total ({verb, amountField, perAction, autonomousPerAction, window, autonomousWindow, unmodeled, approximate?, reason?}).
     */
    public static function maxExposure(mixed $policy, mixed $given): Obj
    {
        $o = $given instanceof Obj ? AnalyzerJs::copy($given) : new Obj();
        if (AnalyzerJs::jget($given, 'budgetModel') instanceof Undef) {
            $bmodel = AnalyzerJs::jget($policy, 'budgetModel');
            if ($bmodel === 'dollars' || $bmodel === 'risk') {
                $o->set('budgetModel', $bmodel);
            }
        }
        if (AnalyzerJs::jget($given, 'kappa') instanceof Undef) {
            $rp = AnalyzerJs::jget($policy, 'riskPolicy');
            $pk = (!($rp instanceof Undef) && $rp !== null) ? AnalyzerJs::jget($rp, 'kappa') : AnalyzerJs::undef();
            if (AnalyzerJs::isNum($pk)) {
                $o->set('kappa', $pk);
            }
        }
        $c = AnalyzerJs::jget($o, 'constitution');
        $cv = $c instanceof Undef ? null : AnalyzerCore::vetoesFromConstitution($c);
        $base = AnalyzerCore::toModel($policy);
        $model = $base;
        if ($cv !== null) {
            $model = AnalyzerJs::copy($base);
            $model->set('vetoes', array_merge(array_values(AnalyzerJs::reqList($base->get('vetoes'))), array_values(AnalyzerJs::reqList($cv->get('vetoes')))));
        }
        $admit = self::peakAt($model, $o, 'admit');
        $auto = self::peakAt($model, $o, 'allow');
        $undecidable = AnalyzerJs::reqList($model->get('undecidable'));
        $approximate = $admit->get('overflow') === true || $auto->get('overflow') === true || count($undecidable) > 0;
        $ap = $admit->get('overflow') === true ? self::unbounded() : $admit->get('peak');
        $up = $auto->get('overflow') === true ? self::unbounded() : $auto->get('peak');
        $unmodeled = [];
        if ($cv !== null) {
            foreach (AnalyzerJs::reqList($cv->get('unmodeled')) as $u) {
                $kind = AnalyzerJs::own($u, 'kind');
                if ($kind !== 'cap' && $kind !== 'rate') {
                    $unmodeled[] = AnalyzerJs::jsStr(AnalyzerJs::own($u, 'id')) . ': ' . AnalyzerJs::jsStr(AnalyzerJs::jget($u, 'reason'));
                }
            }
        }
        $e = AnalyzerJs::uobj([
            'verb' => AnalyzerJs::jget($o, 'verb'), 'amountField' => AnalyzerJs::nn(AnalyzerJs::jget($o, 'amountField'), 'amount'),
            'perAction' => $ap, 'autonomousPerAction' => $up,
            'window' => self::windowBound($model, $c, $o, $ap), 'autonomousWindow' => self::windowBound($model, $c, $o, $up),
            'unmodeled' => $unmodeled,
        ]);
        if ($approximate) {
            $e->set('approximate', true);
            $e->set('reason', ($admit->get('overflow') === true || $auto->get('overflow') === true)
                ? 'representative grid exceeded the bound; exposure reported as unbounded'
                : 'over-approximated (' . implode('; ', $undecidable) . ')');
        }
        return $e;
    }

    /** The actions that are admitted only with a human: {escalates, witnesses, approximate?, reason?}. */
    public static function escalationSurface(mixed $policy, mixed $opts = null): Obj
    {
        $opts ??= new Obj();
        $model = AnalyzerCore::toModel($policy);
        $base = AnalyzerCore::collectProbes(Obj::of(['predicateSets' => [AnalyzerCore::probeSet($model)], 'varyReversibility' => $model->has('revCap')]));
        $verb = AnalyzerJs::jget($opts, 'verb');
        if (!($verb instanceof Undef)) {
            $base->set('verbs', [$verb]);
        }
        $r = AnalyzerCore::collect(
            $base,
            static fn(Obj $rep): bool => AnalyzerCore::decide($model, $rep) === 'escalate',
            AnalyzerCore::boundOf($opts),
            AnalyzerJs::nn(AnalyzerJs::jget($opts, 'limit'), 8),
        );
        $witnesses = [];
        foreach (AnalyzerJs::reqList($r->get('hits')) as $h) {
            $a = AnalyzerCore::repToAction($h);
            if (AnalyzerCore::decideAction($model, $a) === 'escalate') {
                $witnesses[] = $a;
            }
        }
        $out = Obj::of(['escalates' => count($witnesses) > 0, 'witnesses' => $witnesses]);
        $undecidable = AnalyzerJs::reqList($model->get('undecidable'));
        if ($r->get('overflow') === true || count($undecidable) > 0) {
            $out->set('approximate', true);
            $out->set('reason', $r->get('overflow') === true ? 'representative grid exceeded the bound' : 'over-approximated (' . implode('; ', $undecidable) . ')');
        }
        return $out;
    }

    /** The join of everything any holder of the leaf could do, with the remaining delegation depth. */
    public static function delegationEnvelope(mixed $chain, mixed $opts = null): Obj
    {
        $chain = AnalyzerJs::reqList($chain);
        $leaf = $chain !== [] ? $chain[count($chain) - 1] : AnalyzerJs::undef();
        if ($leaf instanceof Obj || AnalyzerJs::isArr($leaf)) {
            $extra = $leaf instanceof Obj ? AnalyzerJs::own($leaf, 'meet') : AnalyzerJs::undef();
            if (AnalyzerJs::truthy($extra) && !AnalyzerJs::isArr($extra)) {
                throw new \TypeError('meet is not iterable');
            }
            $meet = array_merge(array_slice($chain, 0, -1), AnalyzerJs::truthy($extra) ? $extra : []);
            if ($leaf instanceof Obj) {
                $policy = AnalyzerJs::copy($leaf);
                $policy->set('meet', $meet);
            } else {
                $policy = Obj::of(['meet' => array_slice($chain, 0, -1)]);
            }
        } else {
            $policy = Obj::of(['predicates' => []]);
        }
        $model = AnalyzerCore::toModel($policy);
        $base = AnalyzerCore::collectProbes(Obj::of(['predicateSets' => [AnalyzerCore::probeSet($model)], 'varyReversibility' => $model->has('revCap')]));
        $verbs = [];
        $anyVerb = false;
        $overflow = false;
        $mx = AnalyzerCore::boundOf($opts);
        foreach (AnalyzerJs::reqList($base->get('verbs')) as $verb) {
            $pv = AnalyzerJs::copy($base);
            $pv->set('verbs', [$verb]);
            $r = AnalyzerCore::collect($pv, static fn(Obj $rep): bool => AnalyzerCore::decide($model, $rep) !== 'deny', $mx, 1);
            if ($r->get('overflow') === true) {
                $overflow = true;
                break;
            }
            $hits = AnalyzerJs::reqList($r->get('hits'));
            if (count($hits) === 0) {
                continue;
            }
            $hit = $hits[0];
            $w = AnalyzerCore::repToAction($hit);
            if (str_starts_with($verb, "\u{0000}")) {
                $anyVerb = true;
            } else {
                $verbs[] = Obj::of(['verb' => $verb, 'witness' => $w, 'autonomous' => AnalyzerCore::decide($model, $hit) === 'allow']);
            }
        }
        $violations = [];
        for ($i = 0; $i < count($chain) - 1; $i++) {
            $a = AnalyzerCore::toModel($chain[$i]);
            $b = AnalyzerCore::toModel($chain[$i + 1]);
            $pr = AnalyzerCore::collectProbes(Obj::of([
                'predicateSets' => [AnalyzerCore::probeSet($a), AnalyzerCore::probeSet($b)],
                'varyReversibility' => $a->has('revCap') || $b->has('revCap'),
            ]));
            $out = AnalyzerCore::search(
                $pr,
                static fn(Obj $rep): bool => AnalyzerCore::decide($b, $rep) !== 'deny' && AnalyzerCore::decide($a, $rep) === 'deny',
                $mx,
            );
            if ($out->has('hit') || $out->get('overflow') === true) {
                $violations[] = $i + 1;
            }
        }
        $depths = [];
        foreach ($chain as $p) {
            $cvs = $p instanceof Obj ? AnalyzerJs::own($p, 'caveats') : AnalyzerJs::undef();
            foreach (AnalyzerJs::isArr($cvs) ? $cvs : [] as $c) {
                if (AnalyzerJs::jget($c, 'type') === 'delegation_depth' && AnalyzerJs::isNum(AnalyzerJs::jget($c, 'max'))) {
                    $depths[] = AnalyzerJs::jget($c, 'max');
                }
            }
        }
        $used = max(0, count($chain) - 1);
        $depth = Obj::of(['used' => $used]);
        if ($depths !== []) {
            $allowed = $depths[0];
            foreach ($depths as $d) {
                if (AnalyzerJs::jsnum($d) < AnalyzerJs::jsnum($allowed)) {
                    $allowed = $d;
                }
            }
            $depth->set('allowed', $allowed);
            $depth->set('remaining', self::jsMax(0.0, AnalyzerJs::jsnum($allowed) - $used));
        }
        $out2 = Obj::of(['violations' => $violations, 'verbs' => $verbs, 'anyVerb' => $anyVerb, 'depth' => $depth]);
        $undecidable = AnalyzerJs::reqList($model->get('undecidable'));
        if ($overflow || count($undecidable) > 0) {
            $out2->set('approximate', true);
            $out2->set('reason', $overflow ? 'representative grid exceeded the bound' : 'over-approximated (' . implode('; ', $undecidable) . ')');
        }
        return $out2;
    }

    /** `x - y`, with Infinity - Infinity as no change. */
    private static function sub(float $x, float $y): float
    {
        return $x == $y ? 0.0 : $x - $y;
    }

    /** `diff(A, B)`: which actions move between allow / escalate / deny, with witnesses; optionally how the max exposure moved. */
    public static function diffPolicies(mixed $a, mixed $b, mixed $o = null): Obj
    {
        $o ??= new Obj();
        $ma = AnalyzerCore::toModel($a);
        $mb = AnalyzerCore::toModel($b);
        $pr = AnalyzerCore::collectProbes(Obj::of([
            'predicateSets' => [AnalyzerCore::probeSet($ma), AnalyzerCore::probeSet($mb)],
            'varyReversibility' => $ma->has('revCap') || $mb->has('revCap'),
        ]));
        $limit = AnalyzerJs::nn(AnalyzerJs::jget($o, 'limit'), 4);
        $shifts = new Obj();
        $counts = [];
        $visit = static function (Obj $rep) use ($ma, $mb, $shifts, &$counts, $limit): bool {
            $x = AnalyzerCore::decide($ma, $rep);
            $y = AnalyzerCore::decide($mb, $rep);
            if ($x === $y) {
                return false;
            }
            $k = $x . '->' . $y;
            $n = $counts[$k] ?? 0;
            $counts[$k] = $n + 1;
            if (AnalyzerJs::jsLt($n, $limit)) {
                $cur = $shifts->has($k) ? $shifts->get($k) : [];
                $cur[] = AnalyzerCore::repToAction($rep);
                $shifts->set($k, $cur);
            }
            return false; // walk the whole grid
        };
        $walk = AnalyzerCore::collect($pr, $visit, AnalyzerCore::boundOf($o), 1);
        $overflow = $walk->get('overflow') === true;
        $kinds = $shifts->keys();
        $widens = false;
        $narrows = false;
        foreach ($kinds as $k) {
            if (in_array($k, self::WIDEN, true)) {
                $widens = true;
            } else {
                $narrows = true;
            }
        }
        $summary = [];
        foreach ($kinds as $k) {
            $list = $shifts->get($k);
            $first = $list[0];
            $params = $first->get('params');
            $summary[] = $k . ': ' . count($list) . '+ action(s), e.g. ' . AnalyzerJs::jsStr($first->get('verb')) . ' ' . AnalyzerJs::jsStr($first->get('resource')) . ' '
                . AnalyzerJs::jsJson(AnalyzerJs::truthy($params) ? $params : new Obj());
        }
        $undA = AnalyzerJs::reqList($ma->get('undecidable'));
        $undB = AnalyzerJs::reqList($mb->get('undecidable'));
        $d = Obj::of([
            'equivalent' => $kinds === [] && !$overflow && count($undA) === 0 && count($undB) === 0,
            'shifts' => $shifts, 'widens' => $widens, 'narrows' => $narrows, 'summary' => $summary,
        ]);
        $ex = AnalyzerJs::jget($o, 'exposure');
        if (!($ex instanceof Undef)) {
            $before = self::maxExposure($a, $ex);
            $after = self::maxExposure($b, $ex);
            $e = Obj::of([
                'before' => $before, 'after' => $after,
                'perActionDelta' => self::sub(self::n($after->get('perAction')->get('max')), self::n($before->get('perAction')->get('max'))),
                'autonomousDelta' => self::sub(self::n($after->get('autonomousWindow')->get('bound')), self::n($before->get('autonomousWindow')->get('bound'))),
                'delta' => self::sub(self::n($after->get('window')->get('bound')), self::n($before->get('window')->get('bound'))),
            ]);
            $d->set('exposure', $e);
            $worst = self::jsMax($e->get('delta'), $e->get('perActionDelta'), $e->get('autonomousDelta'));
            $best = self::jsMin($e->get('delta'), $e->get('perActionDelta'));
            $verb = AnalyzerJs::jsStr(AnalyzerJs::jget($ex, 'verb'));
            if ($worst > 0) {
                $summary[] = 'max exposure of ' . $verb . ' rises by ' . AnalyzerJs::numStr($worst);
            } elseif ($best < 0) {
                $summary[] = 'max exposure of ' . $verb . ' falls by ' . AnalyzerJs::numStr(-$best);
            }
        }
        $d->set('summary', $summary);
        if ($overflow || count($undA) > 0 || count($undB) > 0) {
            $d->set('approximate', true);
            $seen = [];
            foreach (array_merge($undA, $undB) as $r) {
                $seen[(string)$r] = $r;
            }
            $d->set('reason', $overflow ? 'representative grid exceeded the bound' : 'over-approximated (' . implode('; ', array_values($seen)) . ')');
        }
        return $d;
    }

    /** A CI gate over a diff: fails when the change widens authority beyond what the reviewer allowed. */
    public static function diffGate(mixed $d, mixed $allow = null): Obj
    {
        $allow ??= new Obj();
        $reasons = [];
        if (AnalyzerJs::jget($d, 'widens') === true && AnalyzerJs::jget($allow, 'widen') !== true) {
            $hit = [];
            foreach (AnalyzerJs::reqList(AnalyzerJs::jget($d, 'summary')) as $s) {
                foreach (self::WIDEN as $k) {
                    if (str_starts_with($s, $k)) {
                        $hit[] = $s;
                        break;
                    }
                }
            }
            $reasons[] = 'widens authority: ' . implode('; ', $hit);
        }
        $ex = AnalyzerJs::jget($d, 'exposure');
        $rise = AnalyzerJs::truthy($ex)
            ? self::jsMax(self::n(AnalyzerJs::jget($ex, 'delta')), self::n(AnalyzerJs::jget($ex, 'perActionDelta')), self::n(AnalyzerJs::jget($ex, 'autonomousDelta')))
            : 0.0;
        $lim = AnalyzerJs::nn(AnalyzerJs::jget($allow, 'maxExposureIncrease'), 0);
        if (AnalyzerJs::jsGt($rise, $lim)) {
            $reasons[] = 'max exposure rises by ' . AnalyzerJs::numStr($rise);
        }
        if (AnalyzerJs::truthy(AnalyzerJs::jget($d, 'approximate'))) {
            $reasons[] = 'inconclusive: ' . AnalyzerJs::jsStr(AnalyzerJs::nn(AnalyzerJs::jget($d, 'reason'), 'approximate'));
        }
        return Obj::of(['ok' => count($reasons) === 0, 'reasons' => $reasons]);
    }

    /**
     * Check what an optional external solver returned: a witness is re-checked by the real evaluator (never trusted); an unsat
     * claim is returned labelled as solver-claimed. `$backend` has a `name` and a `find(query)` callable returning {witness?, unsat?}
     * (an Obj, an assoc array, or an object with a `find` method and a `name` property or method).
     */
    public static function findWithBackend(mixed $backend, mixed $q): Obj
    {
        if ($backend instanceof Obj) {
            $find = $backend->get('find');
            $name = $backend->get('name');
        } elseif (is_array($backend)) {
            $find = $backend['find'] ?? null;
            $name = $backend['name'] ?? null;
        } elseif (is_object($backend)) {
            $find = [$backend, 'find'];
            $name = method_exists($backend, 'name') ? $backend->name() : ($backend->name ?? null);
        } else {
            throw new \TypeError('backend must have find and name');
        }
        if (!is_callable($find)) {
            throw new \TypeError('backend.find is not a function');
        }
        $r = $find($q);
        $w = AnalyzerJs::jget($r, 'witness');
        if (!($w instanceof Undef)) {
            $ma = AnalyzerCore::toModel(AnalyzerJs::jget($q, 'a'));
            $qb = AnalyzerJs::jget($q, 'b');
            $qv = AnalyzerJs::jget($q, 'verb');
            if (AnalyzerJs::jget($q, 'kind') === 'reachable') {
                $ok = AnalyzerCore::decideAction($ma, $w) !== 'deny' && ($qv instanceof Undef || AnalyzerJs::strictEq(AnalyzerJs::jget($w, 'verb'), $qv));
            } else {
                $ok = !($qb instanceof Undef)
                    && ((AnalyzerCore::decideAction($ma, $w) !== 'deny') !== (AnalyzerCore::decideAction(AnalyzerCore::toModel($qb), $w) !== 'deny'));
            }
            return $ok ? Obj::of(['witness' => $w]) : Obj::of(['rejected' => true]);
        }
        if (AnalyzerJs::jget($r, 'unsat') === true) {
            return Obj::of(['claimedUnsat' => Obj::of(['by' => $name, 'proof' => 'solver-claimed, not machine-checked'])]);
        }
        return new Obj();
    }

    // ---- workflow DAG exposure ------------------------------------------------------------------------------------------------

    /** A hashable key for a step id (a JavaScript Map key); an object or array id is unhashable and throws. */
    private static function idKey(mixed $id): string
    {
        if (is_string($id)) {
            return 's' . $id;
        }
        if (AnalyzerJs::isNum($id)) {
            $f = AnalyzerJs::jsnum($id);
            return 'n' . ($f == 0.0 ? '0' : sprintf('%.17g', $f));
        }
        if ($id === null) {
            return 'z';
        }
        if (is_bool($id)) {
            return $id ? 'bt' : 'bf';
        }
        if ($id instanceof Undef) {
            return 'u';
        }
        throw new \TypeError('unhashable step id');
    }

    /**
     * @param array<string,mixed> $byId
     * @param array<string,int> $level
     * @param array<string,array<string,mixed>> $anc
     * @param array<string,bool> $visiting
     */
    private static function dagVisit(mixed $id, array $byId, array &$level, array &$anc, array &$visiting): void
    {
        $k = self::idKey($id);
        if (array_key_exists($k, $level)) {
            return;
        }
        if (isset($visiting[$k])) {
            throw new \InvalidArgumentException('dagExposure: cycle');
        }
        $visiting[$k] = true;
        if (!array_key_exists($k, $byId)) {
            throw new \InvalidArgumentException('dagExposure: unknown step ' . AnalyzerJs::jsStr($id));
        }
        $s = $byId[$k];
        $a = [];
        $lv = 0;
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($s, 'deps')) as $d) {
            self::dagVisit($d, $byId, $level, $anc, $visiting);
            $dk = self::idKey($d);
            $a[$dk] = $d;
            foreach ($anc[$dk] as $xk => $x) {
                $a[$xk] = $x;
            }
            $lv = max($lv, $level[$dk] + 1);
        }
        unset($visiting[$k]);
        $anc[$k] = $a;
        $level[$k] = $lv;
    }

    /**
     * @param array<string,list<mixed>> $children
     * @param array<string,int> $memo
     */
    private static function dagLeaves(mixed $id, array $children, array &$memo, bool &$capped): int
    {
        $k = self::idKey($id);
        if (array_key_exists($k, $memo)) {
            return $memo[$k];
        }
        $kids = $children[$k];
        $n = count($kids) === 0 ? 1 : 0;
        foreach ($kids as $kid) {
            $n += self::dagLeaves($kid, $children, $memo, $capped);
        }
        if ($n > self::PATH_CAP) {
            $n = self::PATH_CAP;
            $capped = true;
        }
        $memo[$k] = $n;
        return $n;
    }

    /**
     * @param array<string,array<string,mixed>> $feeds
     * @param array<string,mixed> $seen
     */
    private static function dagLineage(mixed $id, array $feeds, array &$seen): void
    {
        $k = self::idKey($id);
        if (!array_key_exists($k, $feeds)) {
            throw new \TypeError('edge refers to an unknown step');
        }
        foreach ($feeds[$k] as $fk => $f) {
            if (!array_key_exists($fk, $seen)) {
                $seen[$fk] = $f;
                self::dagLineage($f, $feeds, $seen);
            }
        }
    }

    /** `x.length > 0` of a list-like member (a missing one is not greater). */
    private static function nonEmpty(mixed $x): bool
    {
        return AnalyzerJs::jsGt(AnalyzerJs::jget($x, 'length'), 0);
    }

    /**
     * Static exposure of a workflow body (steps, dependency DAG, edges, budget); throws \InvalidArgumentException (the reference's
     * RangeError) on a body that is not a DAG.
     */
    public static function dagExposure(mixed $b): Obj
    {
        $steps = AnalyzerJs::reqList(AnalyzerJs::jget($b, 'steps'));
        $byId = [];
        foreach ($steps as $s) {
            $byId[self::idKey(AnalyzerJs::jget($s, 'id'))] = $s;
        }
        if (count($byId) !== count($steps)) {
            throw new \InvalidArgumentException('dagExposure: duplicate step id');
        }
        $level = [];
        $anc = [];
        $visiting = [];
        foreach ($steps as $s) {
            self::dagVisit(AnalyzerJs::jget($s, 'id'), $byId, $level, $anc, $visiting);
        }
        $depth = max(array_merge([0], array_values($level))) + 1;
        $widths = [];
        foreach ($level as $lv) {
            $widths[$lv] = ($widths[$lv] ?? 0) + 1;
        }
        $levelWidth = $widths !== [] ? max($widths) : -INF;

        $children = [];
        foreach ($steps as $s) {
            $children[self::idKey(AnalyzerJs::jget($s, 'id'))] = [];
        }
        foreach ($steps as $s) {
            foreach (AnalyzerJs::reqList(AnalyzerJs::jget($s, 'deps')) as $d) {
                $children[self::idKey($d)][] = AnalyzerJs::jget($s, 'id');
            }
        }
        $memo = [];
        $capped = false;
        $paths = 0;
        foreach ($steps as $s) {
            if (count(AnalyzerJs::reqList(AnalyzerJs::jget($s, 'deps'))) === 0) {
                $paths = min(self::PATH_CAP, $paths + self::dagLeaves(AnalyzerJs::jget($s, 'id'), $children, $memo, $capped));
            }
        }

        $budget = AnalyzerJs::jget($b, 'budget');
        $caps = AnalyzerJs::jget($budget, 'caps');
        if (!($caps instanceof Obj)) {
            throw new \TypeError('Object.entries requires an object');
        }
        $cost = new Obj();
        foreach (AnalyzerJs::keyOrder($caps) as $name) {
            $cap = $caps->get($name);
            $total = 0.0;
            foreach ($steps as $s) {
                $sc = AnalyzerJs::jget($s, 'cost');
                $total += ($sc instanceof Obj && $sc->has($name) && $sc->get($name) !== null) ? self::n($sc->get($name)) : 0.0;
            }
            $cost->set($name, Obj::of(['cap' => $cap, 'total' => $total, 'maxSpend' => self::jsMin(self::n($cap), $total)]));
        }
        $maxSteps = AnalyzerJs::jget($budget, 'max_steps');
        $never = [];
        foreach ($steps as $s) {
            $sc = AnalyzerJs::jget($s, 'cost');
            $over = false;
            if ($sc instanceof Obj) {
                foreach ($sc->keys() as $nm) {
                    if (AnalyzerJs::jsGt($sc->get($nm), AnalyzerJs::nn($caps->get($nm), 0))) {
                        $over = true;
                        break;
                    }
                }
            }
            if ($over) {
                $never[] = Obj::of(['step' => AnalyzerJs::jget($s, 'id'), 'reason' => 'cost_over_cap']);
            } elseif (AnalyzerJs::isNum($maxSteps) && count($anc[self::idKey(AnalyzerJs::jget($s, 'id'))]) + 1 > AnalyzerJs::jsnum($maxSteps)) {
                $never[] = Obj::of(['step' => AnalyzerJs::jget($s, 'id'), 'reason' => 'needs_more_steps_than_budget']);
            }
        }

        $edges = AnalyzerJs::reqList(AnalyzerJs::jget($b, 'edges'));
        $feeds = [];
        foreach ($steps as $s) {
            $feeds[self::idKey(AnalyzerJs::jget($s, 'id'))] = [];
        }
        foreach ($edges as $e) {
            $tk = self::idKey(AnalyzerJs::jget(AnalyzerJs::jget($e, 'to'), 'step'));
            if (!array_key_exists($tk, $feeds)) {
                throw new \TypeError('edge refers to an unknown step');
            }
            $from = AnalyzerJs::jget(AnalyzerJs::jget($e, 'from'), 'step');
            $feeds[$tk][self::idKey($from)] = $from;
        }

        $sinks = [];
        foreach ($steps as $s) {
            $sk = AnalyzerJs::jget($s, 'sink');
            if ($sk === null) {
                continue;
            }
            $sid = AnalyzerJs::jget($s, 'id');
            $incoming = [];
            foreach ($edges as $e) {
                if (AnalyzerJs::strictEq(AnalyzerJs::jget(AnalyzerJs::jget($e, 'to'), 'step'), $sid)) {
                    $incoming[] = $e;
                }
            }
            $seen = [];
            self::dagLineage($sid, $feeds, $seen);
            $lineage = array_values($seen);
            foreach ($lineage as $x) {
                if (!is_string($x)) {
                    throw new \TypeError('lineage entry is not a string');
                }
            }
            usort($lineage, static fn(string $x, string $y): int => AnalyzerJs::u16cmp($x, $y));
            $prot = self::nonEmpty(AnalyzerJs::jget($s, 'deny_labels')) || self::nonEmpty(AnalyzerJs::jget($s, 'escalate_labels'));
            if (!$prot) {
                foreach ($incoming as $e) {
                    if (self::nonEmpty(AnalyzerJs::jget($e, 'deny_labels'))) {
                        $prot = true;
                        break;
                    }
                }
            }
            $sinks[] = AnalyzerJs::uobj(['step' => $sid, 'sink' => $sk, 'lineage' => $lineage, 'protected' => $prot]);
        }
        $unprotected = [];
        foreach ($sinks as $k) {
            if ($k->get('protected') !== true && count($k->get('lineage')) > 0) {
                $unprotected[] = $k->get('step');
            }
        }
        $orderingOnly = [];
        foreach ($steps as $s) {
            if (count(AnalyzerJs::reqList(AnalyzerJs::jget($s, 'deps'))) > 0) {
                $targeted = false;
                foreach ($edges as $e) {
                    if (AnalyzerJs::strictEq(AnalyzerJs::jget(AnalyzerJs::jget($e, 'to'), 'step'), AnalyzerJs::jget($s, 'id'))) {
                        $targeted = true;
                        break;
                    }
                }
                if (!$targeted) {
                    $orderingOnly[] = AnalyzerJs::jget($s, 'id');
                }
            }
        }
        $pipelinable = [];
        foreach ($edges as $i => $e) {
            if (AnalyzerJs::jget($e, 'promise') !== null) {
                $pipelinable[] = $i;
            }
        }
        $ms = AnalyzerJs::isNum($maxSteps) ? AnalyzerJs::jsnum($maxSteps) : NAN;
        return Obj::of([
            'steps' => count($steps), 'maxSteps' => is_nan($ms) ? null : self::jsMin((float)count($steps), $ms), 'depth' => $depth, 'levelWidth' => $levelWidth,
            'paths' => $paths, 'pathsCapped' => $capped, 'cost' => $cost, 'neverRunnable' => $never, 'sinks' => $sinks, 'unprotectedSinks' => $unprotected,
            'orderingOnly' => $orderingOnly, 'pipelinable' => $pipelinable,
        ]);
    }
}
