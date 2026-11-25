<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/AnalyzerCore.php';
require_once __DIR__ . '/AnalyzerExposure.php';
require_once __DIR__ . '/AnalyzerResidual.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Predicates.php';

/**
 * Policy coverage (which clauses decided, which never matched, how close traffic came to each threshold, which single-edit mutants
 * the traffic cannot tell from the policy) and the minimal-change counterfactual search on a deny or escalate. Outside the trusted
 * core: every repair offered is confirmed by the real decision.
 */
final class AnalyzerCoverage
{
    private const FLIP = ['lt' => 'lte', 'lte' => 'lt', 'gt' => 'gte', 'gte' => 'gt', 'eq' => 'ne', 'ne' => 'eq', 'in' => 'nin', 'nin' => 'in'];
    private const RANK = ['deny' => 0, 'escalate' => 1, 'allow' => 2];

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

    /** `xs.slice(0, count)` for a JavaScript number `count` (NaN is 0, negative counts from the end). @param list<mixed> $xs @return list<mixed> */
    private static function sliceN(array $xs, mixed $count): array
    {
        $f = self::n($count);
        if (is_nan($f)) {
            return [];
        }
        if (is_infinite($f)) {
            return $f > 0 ? $xs : [];
        }
        $f = $f < 0 ? ceil($f) : floor($f);
        $f = max(-1.0e15, min(1.0e15, $f));
        return array_slice($xs, 0, (int)$f);
    }

    public static function permitId(int $i): string
    {
        return 'permit[' . $i . ']';
    }

    private static function id(mixed $x): mixed
    {
        return $x instanceof Undef ? null : $x;
    }

    /** A map key for an id (a string, or anything else by its JSON text). */
    private static function ck(mixed $k): string
    {
        return is_string($k) ? 's' . $k : 'j' . AnalyzerJs::jsJson($k);
    }

    /** The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit. */
    public static function witnessOf(Obj $model, mixed $action): Obj
    {
        $decision = AnalyzerCore::decideAction($model, $action);
        $ctx = AnalyzerCore::contextOfAction($action);
        $permits = [];
        foreach (AnalyzerJs::reqList($model->get('predicates')) as $i => $p) {
            if (Predicates::predicateMatches($p, $ctx)) {
                $permits[] = self::permitId($i);
            }
        }
        $vetoes = [];
        foreach (AnalyzerJs::reqList($model->get('vetoes')) as $v) {
            if (AnalyzerCore::vetoApplies($v, $ctx)) {
                $vetoes[] = $v;
            }
        }
        $tighten = [];
        foreach (AnalyzerJs::reqList($model->get('tighten')) as $t) {
            $w = AnalyzerJs::jget($t, 'when');
            if (Predicates::evaluateConditionTri($w instanceof Undef ? null : $w, $ctx) !== 'false') {
                $tighten[] = $t;
            }
        }
        $others = static function (mixed $win) use ($permits, $vetoes, $tighten): array {
            $all = $permits;
            foreach ($vetoes as $v) {
                $all[] = self::id(AnalyzerJs::jget($v, 'id'));
            }
            foreach ($tighten as $t) {
                $all[] = self::id(AnalyzerJs::jget($t, 'id'));
            }
            $out = [];
            foreach ($all as $i) {
                if (!AnalyzerJs::strictEq($i, $win)) {
                    $out[] = $i;
                }
            }
            return $out;
        };
        $done = static function (string $kind, mixed $id) use ($decision, $others): Obj {
            $id = self::id($id);
            return Obj::of(['decision' => $decision, 'winner' => Obj::of(['kind' => $kind, 'id' => $id]), 'also' => $others($id)]);
        };
        $caveatSat = AnalyzerJs::truthy($model->get('caveatSat'));
        if (!$caveatSat || $decision === 'deny') {
            if (!$caveatSat) {
                return $done('caveat', 'caveats');
            }
            if (count($permits) === 0) {
                return Obj::of(['decision' => $decision, 'winner' => Obj::of(['kind' => 'none', 'id' => null]), 'also' => $others(null)]);
            }
            foreach ($vetoes as $v) {
                if (AnalyzerJs::jget($v, 'kind') === 'deny') {
                    return $done('veto', AnalyzerJs::jget($v, 'id'));
                }
            }
            foreach ($tighten as $t) {
                if (AnalyzerJs::jget($t, 'signal') === 'deny') {
                    return $done('tighten', AnalyzerJs::jget($t, 'id'));
                }
            }
            return $done('caveat', 'caveats'); // reversibility cap or an ancestor of the chain
        }
        if ($decision === 'escalate') {
            foreach ($vetoes as $v) {
                if (AnalyzerJs::jget($v, 'kind') === 'approval') {
                    return $done('veto', AnalyzerJs::jget($v, 'id'));
                }
            }
            return $done('tighten', count($tighten) > 0 ? AnalyzerJs::jget($tighten[0], 'id') : null);
        }
        return $done('permit', count($permits) > 0 ? $permits[0] : null);
    }

    // ---- mutation operators -----------------------------------------------------------------------------------------------------

    /** @return list<Obj> {cond, what} */
    private static function variantsOfCond(mixed $c, mixed $eps): array
    {
        if (!($c instanceof Obj) && !AnalyzerJs::isArr($c)) {
            return [];
        }
        if (Predicates::isGroupCondition($c)) {
            $out = [];
            if ($c->has('not')) {
                foreach (self::variantsOfCond($c->get('not'), $eps) as $v) {
                    $out[] = Obj::of(['cond' => Obj::of(['not' => $v->get('cond')]), 'what' => 'not(' . $v->get('what') . ')']);
                }
                return $out;
            }
            $isAll = $c->has('all_of');
            $kids = AnalyzerJs::reqList($isAll ? $c->get('all_of') : AnalyzerJs::own($c, 'any_of'));
            foreach ($kids as $i => $k) {
                foreach (self::variantsOfCond($k, $eps) as $v) {
                    $nxt = $kids;
                    $nxt[$i] = $v->get('cond');
                    $out[] = Obj::of([
                        'cond' => Obj::of([$isAll ? 'all_of' : 'any_of' => $nxt]),
                        'what' => ($isAll ? 'all_of' : 'any_of') . '[' . $i . '] ' . $v->get('what'),
                    ]);
                }
            }
            return $out;
        }
        if (!Predicates::isLeafCondition($c) || $c->has('ref')) {
            return [];
        }
        $out = [];
        $name = (string)preg_replace('/^action\.params\./', '', $c->get('field'));
        $val = AnalyzerJs::own($c, 'value');
        $op = AnalyzerJs::own($c, 'op');
        if (AnalyzerJs::isFin($val) && is_string($op) && in_array($op, ['lt', 'lte', 'gt', 'gte', 'eq'], true)) {
            $vf = AnalyzerJs::jsnum($val);
            $up = $vf + self::n($eps);
            $dn = $vf - self::n($eps);
            $cu = AnalyzerJs::copy($c);
            $cu->set('value', $up);
            $out[] = Obj::of(['cond' => $cu, 'what' => $name . ' ' . $op . ' ' . AnalyzerJs::numStr($vf) . ' -> ' . AnalyzerJs::numStr($up)]);
            $cd = AnalyzerJs::copy($c);
            $cd->set('value', $dn);
            $out[] = Obj::of(['cond' => $cd, 'what' => $name . ' ' . $op . ' ' . AnalyzerJs::numStr($vf) . ' -> ' . AnalyzerJs::numStr($dn)]);
        }
        if (is_string($op) && array_key_exists($op, self::FLIP)) {
            $cf = AnalyzerJs::copy($c);
            $cf->set('op', self::FLIP[$op]);
            $out[] = Obj::of(['cond' => $cf, 'what' => $name . ' ' . $op . ' -> ' . self::FLIP[$op]]);
        }
        return $out;
    }

    /** @param list<mixed> $xs @return list<mixed> */
    private static function without(array $xs, int $i): array
    {
        $out = [];
        foreach ($xs as $j => $x) {
            if ($j !== $i) {
                $out[] = $x;
            }
        }
        return $out;
    }

    /** @param list<mixed> $xs @return list<mixed> */
    private static function replaceAt(array $xs, int $i, mixed $v): array
    {
        $xs[$i] = $v;
        return $xs;
    }

    /** @return list<Obj> {id, description, policy} */
    private static function mutantsOf(Obj $policy, mixed $eps): array
    {
        $out = [];
        $mk = static function (array $over) use ($policy): Obj {
            $o = Obj::of([
                'predicates' => $policy->get('predicates'), 'caveats' => $policy->get('caveats'),
                'vetoes' => $policy->get('vetoes'), 'tighten' => $policy->get('tighten'),
            ]);
            foreach ($over as $k => $v) {
                $o->set((string)$k, $v);
            }
            return $o;
        };
        $preds = AnalyzerJs::reqList($policy->get('predicates'));
        foreach ($preds as $i => $p) {
            $pid = self::permitId($i);
            $out[] = Obj::of(['id' => 'drop-' . $pid, 'description' => 'drop ' . $pid, 'policy' => $mk(['predicates' => self::without($preds, $i)])]);
            $where = AnalyzerJs::reqList(AnalyzerJs::nn(AnalyzerJs::jget($p, 'where'), []));
            foreach ($where as $j => $c) {
                foreach (self::variantsOfCond($c, $eps) as $v) {
                    $np = AnalyzerJs::spread($p);
                    $np->set('where', self::replaceAt($where, $j, $v->get('cond')));
                    $out[] = Obj::of([
                        'id' => $pid . '.where[' . $j . ']:' . $v->get('what'), 'description' => $pid . ': ' . $v->get('what'),
                        'policy' => $mk(['predicates' => self::replaceAt($preds, $i, $np)]),
                    ]);
                }
                $np = AnalyzerJs::spread($p);
                $np->set('where', self::without($where, $j));
                $out[] = Obj::of([
                    'id' => $pid . '.where[' . $j . ']:drop', 'description' => $pid . ': drop condition ' . $j,
                    'policy' => $mk(['predicates' => self::replaceAt($preds, $i, $np)]),
                ]);
            }
        }
        $vetoes = AnalyzerJs::reqList($policy->get('vetoes'));
        foreach ($vetoes as $i => $v) {
            $vid = AnalyzerJs::jsStr(AnalyzerJs::jget($v, 'id'));
            $out[] = Obj::of(['id' => 'drop-veto:' . $vid, 'description' => 'drop prohibition ' . $vid, 'policy' => $mk(['vetoes' => self::without($vetoes, $i)])]);
            $over = AnalyzerJs::jget($v, 'over');
            if (AnalyzerJs::truthy($over)) {
                $no = AnalyzerJs::spread($over);
                $no->set('threshold', self::n(AnalyzerJs::jget($over, 'threshold')) + self::n($eps));
                $nvv = AnalyzerJs::spread($v);
                $nvv->set('over', $no);
                $out[] = Obj::of([
                    'id' => 'veto:' . $vid . ':threshold+', 'description' => 'raise the ' . $vid . ' threshold by ' . AnalyzerJs::numStr(self::n($eps)),
                    'policy' => $mk(['vetoes' => self::replaceAt($vetoes, $i, $nvv)]),
                ]);
            }
        }
        $tighten = AnalyzerJs::reqList($policy->get('tighten'));
        foreach ($tighten as $i => $t) {
            $tid = AnalyzerJs::jsStr(AnalyzerJs::jget($t, 'id'));
            $out[] = Obj::of(['id' => 'drop-tighten:' . $tid, 'description' => 'drop tighten rule ' . $tid, 'policy' => $mk(['tighten' => self::without($tighten, $i)])]);
        }
        return $out;
    }

    private static function reach(Obj $model, string $kind, int $idx): mixed
    {
        if ($kind === 'permit') {
            $r = AnalyzerCore::alwaysDenies(Obj::of(['predicates' => [$model->get('predicates')[$idx]], 'caveats' => $model->get('caveats')]));
            return AnalyzerJs::truthy($r->get('approximate')) ? 'unknown' : $r->get('alwaysDenies') !== true;
        }
        if ($kind === 'veto') {
            $r = AnalyzerCore::alwaysDenies(Obj::of(['predicates' => [AnalyzerJs::jget($model->get('vetoes')[$idx], 'when')]]));
            return AnalyzerJs::truthy($r->get('approximate')) ? 'unknown' : $r->get('alwaysDenies') !== true;
        }
        return 'unknown';
    }

    /** @param array<string,string> $paths */
    private static function walkPaths(mixed $c, array &$paths): void
    {
        if (!($c instanceof Obj) && !AnalyzerJs::isArr($c)) {
            return;
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of')) {
                foreach (AnalyzerJs::reqList($c->get('all_of')) as $x) {
                    self::walkPaths($x, $paths);
                }
            } elseif ($c->has('any_of')) {
                foreach (AnalyzerJs::reqList($c->get('any_of')) as $x) {
                    self::walkPaths($x, $paths);
                }
            } else {
                self::walkPaths($c->get('not'), $paths);
            }
        } elseif (Predicates::isLeafCondition($c) && str_starts_with($c->get('field'), 'action.params.')
            && in_array(AnalyzerJs::own($c, 'op'), ['lt', 'lte', 'gt', 'gte', 'eq', 'in', 'nin'], true)) {
            $paths['k' . $c->get('field')] = $c->get('field');
        }
    }

    private static function ratio(int $n, int $d): float
    {
        return $d === 0 ? 1.0 : $n / $d;
    }

    /** Coverage of `policy` by `traffic` (actions): clauses, boundaries, mutants and the 0..1 scores. */
    public static function coverage(mixed $policy, mixed $traffic, mixed $o = null): Obj
    {
        $o ??= new Obj();
        $traffic = AnalyzerJs::reqList($traffic);
        $model = AnalyzerCore::toModel($policy);
        $eps = AnalyzerJs::nn(AnalyzerJs::jget($o, 'epsilon'), 1);
        $ids = [];
        foreach (array_keys(AnalyzerJs::reqList($model->get('predicates'))) as $i) {
            $ids[] = ['id' => self::permitId($i), 'kind' => 'permit'];
        }
        foreach (AnalyzerJs::reqList($model->get('vetoes')) as $v) {
            $ids[] = ['id' => self::id(AnalyzerJs::jget($v, 'id')), 'kind' => 'veto'];
        }
        foreach (AnalyzerJs::reqList($model->get('tighten')) as $t) {
            $ids[] = ['id' => self::id(AnalyzerJs::jget($t, 'id')), 'kind' => 'tighten'];
        }
        $matched = [];
        $decisive = [];
        $bump = static function (array &$m, mixed $k): void {
            if ($k !== null) {
                $key = self::ck($k);
                $m[$key] = ($m[$key] ?? 0) + 1;
            }
        };
        foreach ($traffic as $a) {
            $w = self::witnessOf($model, $a);
            $winner = $w->get('winner');
            $bump($decisive, $winner->get('id'));
            $bump($matched, $winner->get('id'));
            foreach ($w->get('also') as $i) {
                $bump($matched, $i);
            }
        }
        $np = count($model->get('predicates'));
        $nv = count($model->get('vetoes'));
        $clauses = [];
        foreach ($ids as $n => $c) {
            $idx = $c['kind'] === 'permit' ? $n : ($c['kind'] === 'veto' ? $n - $np : $n - $np - $nv);
            $key = $c['id'] === null ? null : self::ck($c['id']);
            $clauses[] = Obj::of([
                'id' => $c['id'], 'kind' => $c['kind'],
                'matched' => $key === null ? 0 : ($matched[$key] ?? 0), 'decisive' => $key === null ? 0 : ($decisive[$key] ?? 0),
                'reachable' => self::reach($model, $c['kind'], $idx),
            ]);
        }
        $paths = [];
        foreach (AnalyzerCore::probeSet($model) as $p) {
            foreach (AnalyzerJs::reqList(AnalyzerJs::nn(AnalyzerJs::jget($p, 'where'), [])) as $c) {
                self::walkPaths($c, $paths);
            }
        }
        foreach (AnalyzerJs::reqList($model->get('vetoes')) as $v) {
            $over = AnalyzerJs::jget($v, 'over');
            if (AnalyzerJs::truthy($over)) {
                $pp = AnalyzerJs::jget($over, 'path');
                if (!is_string($pp)) {
                    throw new \TypeError('veto path is not a string');
                }
                $paths['k' . $pp] = $pp;
            }
        }
        $pathList = array_values($paths);
        usort($pathList, static fn(string $x, string $y): int => AnalyzerJs::u16cmp($x, $y));
        $boundaries = [];
        $epsF = self::n($eps);
        foreach ($pathList as $path) {
            $name = substr($path, strlen('action.params.'));
            $vals = [];
            foreach ($traffic as $a) {
                $x = AnalyzerJs::own(AnalyzerJs::nn(AnalyzerJs::jget($a, 'params'), new Obj()), $name);
                if (AnalyzerJs::isNum($x)) {
                    $vals[] = $x;
                }
            }
            foreach (AnalyzerExposure::thresholdsOf($model, $path) as $t) {
                $tf = AnalyzerJs::jsnum($t);
                $at = false;
                $below = false;
                $above = false;
                foreach ($vals as $v) {
                    $vf = AnalyzerJs::jsnum($v);
                    $at = $at || AnalyzerJs::strictEq($v, $t);
                    $below = $below || ($vf < $tf && $vf >= $tf - $epsF);
                    $above = $above || ($vf > $tf && $vf <= $tf + $epsF);
                }
                $boundaries[] = Obj::of(['path' => $path, 'threshold' => $t, 'at' => $at, 'below' => $below, 'above' => $above]);
            }
        }
        $survivors = [];
        $killed = 0;
        $equiv = 0;
        $allm = self::sliceN(self::mutantsOf($model, $eps), AnalyzerJs::nn(AnalyzerJs::jget($o, 'maxMutants'), 200));
        $base = [];
        foreach ($traffic as $a) {
            $base[] = AnalyzerCore::decideAction($model, $a);
        }
        foreach ($allm as $m) {
            $mmod = AnalyzerCore::toModel($m->get('policy'));
            $dead = false;
            foreach ($traffic as $i => $a) {
                if (AnalyzerCore::decideAction($mmod, $a) !== $base[$i]) {
                    $dead = true;
                    break;
                }
            }
            if ($dead) {
                $killed++;
                continue;
            }
            $eq = AnalyzerCore::equivalent($policy, $m->get('policy'));
            if ($eq->get('equivalent') === true) {
                $equiv++;
                continue;
            }
            $s = Obj::of(['id' => $m->get('id'), 'description' => $m->get('description')]);
            $ce = AnalyzerJs::own($eq, 'counterexample');
            if (AnalyzerJs::truthy($ce)) {
                $s->set('killer', $ce);
            }
            $survivors[] = $s;
        }
        $live = [];
        foreach ($clauses as $c) {
            if ($c->get('reachable') !== false) {
                $live[] = $c;
            }
        }
        $liveDecisive = 0;
        foreach ($live as $c) {
            if ($c->get('decisive') > 0) {
                $liveDecisive++;
            }
        }
        $full = 0;
        foreach ($boundaries as $b) {
            if ($b->get('at') && $b->get('below') && $b->get('above')) {
                $full++;
            }
        }
        $neverMatched = [];
        $neverDecisive = [];
        $untested = [];
        $unreachable = [];
        foreach ($clauses as $c) {
            if ($c->get('matched') === 0) {
                $neverMatched[] = $c->get('id');
            }
            if ($c->get('decisive') === 0) {
                $neverDecisive[] = $c->get('id');
            }
            if ($c->get('reachable') !== false && $c->get('matched') === 0) {
                $untested[] = $c->get('id');
            }
            if ($c->get('reachable') === false) {
                $unreachable[] = $c->get('id');
            }
        }
        return Obj::of([
            'traffic' => count($traffic),
            'policyDigest' => AnalyzerResidual::policyDigestOf($model),
            'clauses' => $clauses,
            'neverMatched' => $neverMatched,
            'neverDecisive' => $neverDecisive,
            'untested' => $untested,
            'unreachable' => $unreachable,
            'boundaries' => $boundaries,
            'mutants' => Obj::of(['total' => count($allm), 'killed' => $killed, 'equivalent' => $equiv, 'survivors' => $survivors]),
            'score' => Obj::of([
                'clauses' => self::ratio($liveDecisive, count($live)),
                'boundaries' => self::ratio($full, count($boundaries)),
                'mutation' => self::ratio($killed, count($allm) - $equiv),
            ]),
        ]);
    }

    /** A CI gate over a coverage report: {ok, reasons}. */
    public static function coverageGate(mixed $r, mixed $minimum = null): Obj
    {
        $mn = $minimum ?? new Obj();
        $reasons = [];
        $score = AnalyzerJs::jget($r, 'score');
        foreach ([['clauses', 'clause coverage'], ['boundaries', 'boundary coverage'], ['mutation', 'mutation score']] as [$key, $label]) {
            $lim = AnalyzerJs::jget($mn, $key);
            $sv = self::n(AnalyzerJs::jget($score, $key));
            if ($sv < self::n(AnalyzerJs::nn($lim, 0))) {
                $reasons[] = $label . ' ' . AnalyzerJs::toFixed($sv, 2) . ' < ' . (AnalyzerJs::isNum($lim) ? AnalyzerJs::numStr(AnalyzerJs::jsnum($lim)) : AnalyzerJs::jsStr($lim));
            }
        }
        $ms = AnalyzerJs::jget($mn, 'maxSurvivors');
        $survivors = AnalyzerJs::reqList(AnalyzerJs::jget(AnalyzerJs::jget($r, 'mutants'), 'survivors'));
        if (!($ms instanceof Undef) && count($survivors) > self::n($ms)) {
            $reasons[] = count($survivors) . ' surviving mutants > ' . (AnalyzerJs::isNum($ms) ? AnalyzerJs::numStr(AnalyzerJs::jsnum($ms)) : AnalyzerJs::jsStr($ms));
        }
        $unreachable = AnalyzerJs::reqList(AnalyzerJs::jget($r, 'unreachable'));
        if (count($unreachable) > 0) {
            $reasons[] = 'unreachable clauses: ' . implode(', ', array_map(AnalyzerJs::jsStr(...), $unreachable));
        }
        return Obj::of(['ok' => count($reasons) === 0, 'reasons' => $reasons]);
    }

    // ---- minimal flip -----------------------------------------------------------------------------------------------------------

    /** The reference's camelCase caveat context as the snake_case context the caveat evaluator reads. */
    private static function cavCtx(mixed $c): mixed
    {
        if (!($c instanceof Obj)) {
            return $c;
        }
        $out = AnalyzerJs::copy($c);
        foreach ([['blastRadius', 'blast_radius'], ['reversibilityClass', 'reversibility_class'], ['delegationDepth', 'delegation_depth'], ['recentActionTimes', 'recent_action_times']] as [$camel, $snake]) {
            if ($out->has($camel)) {
                $v = $out->get($camel);
                $out = $out->without($camel);
                $out->set($snake, $v);
            }
        }
        return $out;
    }

    private static function waitTime(mixed $caveats, mixed $ctx): mixed
    {
        $at = AnalyzerJs::undef();
        $now = AnalyzerJs::jget($ctx, 'now');
        foreach (AnalyzerJs::reqList($caveats) as $c) {
            $t = AnalyzerJs::jget($c, 'type');
            $cat = AnalyzerJs::jget($c, 'at');
            if ($t === 'not_before' && AnalyzerJs::isNum($cat) && AnalyzerJs::jsGt($cat, $now)) {
                $at = self::jsMax($at instanceof Undef ? 0.0 : $at, AnalyzerJs::jsnum($cat));
            }
            $mx = AnalyzerJs::jget($c, 'max');
            $ps = AnalyzerJs::jget($c, 'per_secs');
            if ($t === 'rate' && AnalyzerJs::isNum($mx) && AnalyzerJs::isNum($ps)) {
                $span = AnalyzerJs::jsnum($ps) * 1000;
                $times = AnalyzerJs::nn(AnalyzerJs::jget($ctx, 'recentActionTimes'), []);
                $recent = [];
                foreach (AnalyzerJs::reqList($times) as $x) {
                    if (AnalyzerJs::jsGt($x, self::n($now) - $span)) {
                        $recent[] = $x;
                    }
                }
                usort($recent, static fn(mixed $x, mixed $y): int => self::n($x) <=> self::n($y));
                if (count($recent) >= AnalyzerJs::jsnum($mx)) {
                    $i = count($recent) - AnalyzerJs::jsnum($mx);
                    $v = ($i == floor($i) && $i >= 0 && $i < count($recent)) ? self::n($recent[(int)$i]) + $span : NAN;
                    $at = self::jsMax($at instanceof Undef ? 0.0 : $at, $v);
                }
            }
        }
        return $at;
    }

    private static function meters(Obj $m): bool
    {
        $cs = array_values(AnalyzerJs::reqList($m->get('caveats')));
        foreach (AnalyzerJs::reqList($m->get('meets')) as $x) {
            foreach (AnalyzerJs::reqList(AnalyzerJs::jget($x, 'caveats')) as $c) {
                $cs[] = $c;
            }
        }
        foreach ($cs as $c) {
            if (in_array(AnalyzerJs::jget($c, 'type'), ['rate', 'budget_alloc', 'max_blast_radius'], true)) {
                return true;
            }
        }
        return false;
    }

    /** @param list<string> $path */
    private static function setPath(Obj $o, array $path, mixed $v): Obj
    {
        if (count($path) === 0) {
            return $o;
        }
        $k = $path[0];
        $rest = array_slice($path, 1);
        $o->set($k, count($rest) === 0 ? $v : self::setPath(AnalyzerJs::spread(AnalyzerJs::nn($o->get($k), new Obj())), $rest, $v));
        return $o;
    }

    private static function decl(mixed $shape, string $name): mixed
    {
        if ($shape instanceof Undef) {
            return $shape;
        }
        return AnalyzerJs::jget(AnalyzerJs::jget($shape, 'params'), $name);
    }

    private static function withParam(mixed $action, Obj $params, string $name, mixed $v): Obj
    {
        $a = AnalyzerJs::spread($action);
        $p = AnalyzerJs::copy($params);
        $p->set($name, $v);
        $a->set('params', $p);
        return $a;
    }

    /** First-seen de-duplication of numbers (by value), strings (by value) and anything else (by identity). @param list<mixed> $xs @return list<mixed> */
    private static function uniq(array $xs): array
    {
        $seen = [];
        foreach ($xs as $x) {
            if (AnalyzerJs::isNum($x)) {
                $f = AnalyzerJs::jsnum($x);
                $k = 'n' . ($f == 0.0 ? '0' : sprintf('%.17g', $f));
            } elseif (is_string($x)) {
                $k = 's' . $x;
            } elseif ($x instanceof Obj) {
                $k = 'o' . spl_object_id($x);
            } else {
                $k = 'j' . AnalyzerJs::jsJson($x);
            }
            $seen[$k] ??= $x;
        }
        return array_values($seen);
    }

    private static function fieldOf(Obj $pr, string $path): ?Obj
    {
        foreach (AnalyzerJs::reqList($pr->get('fields')) as $f) {
            if ($f->get('path') === $path) {
                return $f;
            }
        }
        return null;
    }

    /**
     * The smallest verified change that gets `action` to the wanted decision (default allow), ordered by cost: wait, change one
     * parameter, change two together, another resource, obtain a fact, split (opt-in), ask a human. Only a repair the real
     * decision confirms is returned; shown only to the authenticated holder; critical values are redacted by default.
     */
    public static function minimalFlip(mixed $policy, mixed $action, mixed $o): Obj
    {
        $model = AnalyzerCore::toModel($policy);
        $cctx = AnalyzerJs::jget($o, 'caveatContext');
        $caveatsOk = $cctx instanceof Undef || Pca::evaluateCaveats($model->get('caveats'), self::cavCtx($cctx))['ok'];
        $current = $caveatsOk ? AnalyzerCore::decideAction($model, $action) : 'deny';
        $want = AnalyzerJs::nn(AnalyzerJs::jget($o, 'desired'), 'allow');
        $rankWant = is_string($want) && array_key_exists($want, self::RANK) ? (float)self::RANK[$want] : NAN;
        $res = Obj::of(['current' => $current, 'repairs' => [], 'repairExists' => false]);
        if (!AnalyzerJs::truthy(AnalyzerJs::jget($o, 'holderAuthenticated'))) {
            $r = AnalyzerJs::copy($res);
            $r->set('refused', 'counterfactuals are shown only to the authenticated holder');
            return $r;
        }
        $probe = AnalyzerJs::jget($o, 'probe');
        if (AnalyzerJs::truthy($probe)) {
            $now = AnalyzerJs::jget($probe, 'now');
            $history = AnalyzerJs::reqList(AnalyzerJs::jget($probe, 'history'));
            // a clock, window or history stamp that is not finite cannot say what is still inside the window: refuse (a +Infinity limit stays an unbounded cap)
            $fin = static fn(mixed $x): bool => (is_int($x) || is_float($x) || $x instanceof Num) && is_finite(AnalyzerJs::toNumber($x));
            $stampsOk = $fin($now) && $fin(AnalyzerJs::jget($probe, 'windowSecs'));
            foreach ($history as $t) {
                $stampsOk = $stampsOk && $fin($t);
            }
            if (!$stampsOk) {
                $r = AnalyzerJs::copy($res);
                $r->set('refused', 'probe budget exhausted');
                $r->set('probe', Obj::of(['history' => $history]));
                return $r;
            }
            $recent = [];
            foreach ($history as $t) {
                if (AnalyzerJs::jsGt($t, self::n($now) - self::n(AnalyzerJs::jget($probe, 'windowSecs')) * 1000)) {
                    $recent[] = $t;
                }
            }
            if (!(count($recent) < self::n(AnalyzerJs::jget($probe, 'limit')))) {
                $r = AnalyzerJs::copy($res);
                $r->set('refused', 'probe budget exhausted');
                $r->set('probe', Obj::of(['history' => $recent]));
                return $r;
            }
            $res->set('probe', Obj::of(['history' => array_merge($recent, [$now])]));
        }
        $digest = AnalyzerResidual::policyDigestOf($model);
        if (self::RANK[$current] >= $rankWant) {
            return $res;
        }

        $schema = AnalyzerJs::jget($o, 'schema');
        $shape = AnalyzerJs::undef();
        if (!($schema instanceof Undef) && $schema !== null) {
            foreach (AnalyzerJs::reqList($schema) as $s) {
                if (AnalyzerJs::strictEq(AnalyzerJs::jget($s, 'verb'), AnalyzerJs::jget($action, 'verb'))) {
                    $shape = $s;
                    break;
                }
            }
        }

        $reaches = static function (mixed $a) use ($model, $rankWant): ?string {
            $d = AnalyzerCore::decideAction($model, $a);
            return self::RANK[$d] >= $rankWant ? $d : null;
        };
        /** @var list<Obj> $cands */
        $cands = [];
        $push = static function (Obj $repair, mixed $cost, mixed $a) use (&$cands, $reaches): void {
            $d = $reaches($a);
            if ($d !== null) {
                $cands[] = Obj::of(['repair' => $repair, 'cost' => $cost, 'decision' => $d, 'action' => $a]);
            }
        };

        $pr = AnalyzerCore::collectProbes(Obj::of(['predicateSets' => [AnalyzerCore::probeSet($model)], 'varyReversibility' => $model->has('revCap')]));
        $params = AnalyzerJs::spread(AnalyzerJs::nn(AnalyzerJs::jget($action, 'params'), new Obj()));
        $ch = AnalyzerJs::jget($o, 'changeable');
        if (!($ch instanceof Undef) && $ch !== null) {
            $names = array_map(static fn(mixed $x): string => is_string($x) ? $x : AnalyzerJs::jsStr($x), AnalyzerJs::reqList($ch));
        } elseif (!($shape instanceof Undef)) {
            $sp = AnalyzerJs::jget($shape, 'params');
            if (!($sp instanceof Obj)) {
                throw new \TypeError('schema params is not an object');
            }
            $names = AnalyzerJs::keyOrder($sp);
        } else {
            $names = AnalyzerJs::keyOrder($params);
        }

        // 1. wait: a time caveat that is not open yet, or a rate window that will reset
        if (!$caveatsOk && AnalyzerJs::truthy($cctx)) {
            $at = self::waitTime($model->get('caveats'), $cctx);
            $d = AnalyzerCore::decideAction($model, $action);
            if (!($at instanceof Undef)) {
                $later = AnalyzerJs::spread($cctx);
                $later->set('now', $at);
                if (Pca::evaluateCaveats($model->get('caveats'), self::cavCtx($later))['ok'] && self::RANK[$d] >= $rankWant) {
                    $cands[] = Obj::of([
                        'repair' => Obj::of(['kind' => 'wait_until', 'at' => $at, 'reason' => 'a time or rate caveat opens then']),
                        'cost' => 1, 'decision' => $d, 'action' => $action,
                    ]);
                }
            }
        }
        $finish = !$caveatsOk; // nothing else helps while a caveat is closed

        // 2. one parameter changed: the nearest verified value, per parameter
        foreach ($finish ? [] : $names as $name) {
            $path = 'action.params.' . $name;
            $decl = self::decl($shape, $name);
            $cur = AnalyzerJs::own($params, $name);
            $field = self::fieldOf($pr, $path);
            $dvals = AnalyzerJs::oget($decl, 'values');
            $dmin = AnalyzerJs::oget($decl, 'min');
            $dmax = AnalyzerJs::oget($decl, 'max');
            $poolRaw = $field !== null ? array_values(Jsx::iter($field->get('values'))) : [];
            if (!($dvals instanceof Undef)) {
                $poolRaw = array_merge($poolRaw, Jsx::iter($dvals));
            }
            if (!($dmin instanceof Undef)) {
                $poolRaw[] = $dmin;
            }
            if (!($dmax instanceof Undef)) {
                $poolRaw[] = $dmax;
            }
            $absent = AnalyzerCore::absent();
            $pool = array_values(array_filter($poolRaw, static fn(mixed $v): bool => $v !== $absent));
            $nums = array_values(array_filter($pool, static fn(mixed $v): bool => AnalyzerJs::isFin($v)));
            $T = AnalyzerExposure::thresholdsOf($model, $path);
            $integer = AnalyzerJs::oget($decl, 'type') === 'integer'
                || (AnalyzerJs::isNum($cur) && is_finite(AnalyzerJs::jsnum($cur)) && AnalyzerJs::jsnum($cur) == floor(AnalyzerJs::jsnum($cur)));
            $ints = [];
            if ($integer) {
                foreach ($T as $t) {
                    $ints[] = self::n($t) - 1;
                    $ints[] = self::n($t) + 1;
                }
            }
            $curn = AnalyzerJs::isNum($cur) ? AnalyzerJs::jsnum($cur) : 0.0;
            $numeric = [];
            foreach (self::uniq(array_merge($nums, $ints)) as $v) {
                if (($dmin instanceof Undef || self::n($v) >= self::n($dmin)) && ($dmax instanceof Undef || self::n($v) <= self::n($dmax))) {
                    $numeric[] = $v;
                }
            }
            usort($numeric, static function (mixed $x, mixed $y) use ($curn): int {
                return [abs(self::n($x) - $curn), self::n($x)] <=> [abs(self::n($y) - $curn), self::n($y)];
            });
            $strs = self::uniq(array_values(array_filter($pool, static fn(mixed $v): bool => is_string($v) && !str_starts_with($v, "\u{0000}"))));
            $best = null;
            foreach (array_merge($numeric, $strs) as $v) {
                if (AnalyzerJs::strictEq($v, $cur)) {
                    continue;
                }
                $a = self::withParam($action, $params, $name, $v);
                $d = $reaches($a);
                if ($d !== null) {
                    $extra = (AnalyzerJs::isNum($v) && AnalyzerJs::isNum($cur))
                        ? self::jsMin(1.0, abs(AnalyzerJs::jsnum($v) - AnalyzerJs::jsnum($cur)) / (abs(AnalyzerJs::jsnum($cur)) + 1)) : 0.5;
                    $best = Obj::of([
                        'repair' => AnalyzerJs::uobj(['kind' => 'set_param', 'param' => $name, 'from' => $cur, 'to' => $v]),
                        'cost' => 2 + $extra, 'decision' => $d, 'action' => $a,
                    ]);
                    break; // the pool is ordered nearest first
                }
            }
            if ($best !== null) {
                $cands[] = $best;
            }
        }

        $ares = AnalyzerJs::jget($action, 'resource');
        // 2b. when no single edit works, the cheapest PAIR of edits
        if (!$finish && count($cands) === 0) {
            $dims = [];
            $paramDim = static function (string $name) use ($pr, $shape, $params): array {
                $field = self::fieldOf($pr, 'action.params.' . $name);
                $decl = self::decl($shape, $name);
                $dv = AnalyzerJs::oget($decl, 'values');
                $vals = $field !== null ? array_values(Jsx::iter($field->get('values'))) : [];
                if (!($dv instanceof Undef)) {
                    $vals = array_merge($vals, Jsx::iter($dv));
                }
                $vals = array_values(array_filter($vals, static fn(mixed $v): bool => (is_string($v) && !str_starts_with($v, "\u{0000}")) || AnalyzerJs::isNum($v)));
                $own = AnalyzerJs::own($params, $name);
                $vals = array_values(array_filter($vals, static fn(mixed $v): bool => !AnalyzerJs::strictEq($v, $own)));
                return [
                    'cost' => 2,
                    'make' => static function (mixed $a, mixed $v) use ($name): Obj {
                        $p = AnalyzerJs::jget($a, 'params');
                        return self::withParam($a, $p instanceof Obj ? $p : new Obj(), $name, $v);
                    },
                    'step' => static fn(mixed $v): Obj => AnalyzerJs::uobj(['kind' => 'set_param', 'param' => $name, 'from' => AnalyzerJs::own($params, $name), 'to' => $v]),
                    'values' => array_slice(self::uniq($vals), 0, 6),
                ];
            };
            foreach ($names as $name) {
                $dims[] = $paramDim($name);
            }
            $resVals = [];
            foreach (AnalyzerJs::reqList($pr->get('resources')) as $x) {
                if (!str_starts_with($x, "\u{0000}") && !AnalyzerJs::strictEq($x, $ares)) {
                    $resVals[] = $x;
                }
            }
            $dims[] = [
                'cost' => 3,
                'make' => static function (mixed $a, mixed $v): Obj {
                    $r = AnalyzerJs::spread($a);
                    $r->set('resource', $v);
                    return $r;
                },
                'step' => static fn(mixed $v): Obj => AnalyzerJs::uobj(['kind' => 'set_resource', 'from' => $ares, 'to' => $v]),
                'values' => array_slice($resVals, 0, 6),
            ];
            for ($i = 0; $i < count($dims); $i++) {
                for ($j = $i + 1; $j < count($dims); $j++) {
                    foreach ($dims[$i]['values'] as $x) {
                        foreach ($dims[$j]['values'] as $y) {
                            $a = $dims[$j]['make']($dims[$i]['make']($action, $x), $y);
                            $d = $reaches($a);
                            if ($d !== null) {
                                $cands[] = Obj::of([
                                    'repair' => Obj::of(['kind' => 'combine', 'steps' => [$dims[$i]['step']($x), $dims[$j]['step']($y)]]),
                                    'cost' => $dims[$i]['cost'] + $dims[$j]['cost'], 'decision' => $d, 'action' => $a,
                                ]);
                            }
                        }
                    }
                }
            }
        }

        // 3. another allowed resource
        if (!$finish) {
            foreach (AnalyzerJs::reqList($pr->get('resources')) as $r) {
                if (!str_starts_with($r, "\u{0000}") && !AnalyzerJs::strictEq($r, $ares)) {
                    $na = AnalyzerJs::spread($action);
                    $na->set('resource', $r);
                    $push(AnalyzerJs::uobj(['kind' => 'set_resource', 'from' => $ares, 'to' => $r]), 3, $na);
                }
            }
        }

        // 4. a named fact that is missing: a subject or env field the policy reads
        if (!$finish) {
            $absent = AnalyzerCore::absent();
            foreach (AnalyzerJs::reqList($pr->get('fields')) as $f) {
                $fp = $f->get('path');
                if (!(str_starts_with($fp, 'subject.') || str_starts_with($fp, 'env.'))) {
                    continue;
                }
                $segs = explode('.', $fp);
                $root = $segs[0];
                $rest = array_slice($segs, 1);
                foreach (AnalyzerJs::reqList($f->get('values')) as $v) {
                    if ($v === $absent) {
                        continue;
                    }
                    $curRoot = AnalyzerJs::jget($action, $root);
                    $a = AnalyzerJs::spread($action);
                    $a->set($root, self::setPath(AnalyzerJs::spread(AnalyzerJs::nn($curRoot, new Obj())), $rest, $v));
                    $before = $reaches($action);
                    $d = $reaches($a);
                    if ($d !== null && $before === null) {
                        $cands[] = Obj::of([
                            'repair' => Obj::of(['kind' => 'obtain_fact', 'path' => $fp, 'value' => $v]),
                            'cost' => 4, 'decision' => $d, 'action' => $a,
                        ]);
                        break;
                    }
                }
            }
        }

        // 5. split (opt-in, and only when nothing meters the total)
        if (AnalyzerJs::jget($o, 'allowSplit') === true && !self::meters($model)) {
            foreach ($names as $name) {
                $cur = AnalyzerJs::own($params, $name);
                if (!AnalyzerJs::isNum($cur)) {
                    continue;
                }
                $flipped = null;
                foreach ($cands as $c) {
                    $rp = $c->get('repair');
                    if ($rp->get('kind') === 'set_param' && $rp->get('param') === $name && AnalyzerJs::isNum(AnalyzerJs::own($rp, 'to'))) {
                        $flipped = $c;
                        break;
                    }
                }
                $part = ($flipped !== null && $flipped->get('repair')->get('kind') === 'set_param') ? $flipped->get('repair')->get('to') : AnalyzerJs::undef();
                if ($part instanceof Undef || self::n($part) <= 0 || self::n($part) >= self::n($cur)) {
                    continue;
                }
                $nf = ceil(fdiv(AnalyzerJs::jsnum($cur), AnalyzerJs::jsnum($part)));
                if ($nf > 8) {
                    continue;
                }
                $cnt = (int)$nf;
                $parts = [];
                for ($i = 0; $i < $cnt; $i++) {
                    $parts[] = Obj::of([$name => $i < $cnt - 1 ? $part : AnalyzerJs::jsnum($cur) - AnalyzerJs::jsnum($part) * ($cnt - 1)]);
                }
                $all = true;
                foreach ($parts as $p) {
                    $na = AnalyzerJs::spread($action);
                    $np = AnalyzerJs::copy($params);
                    foreach ($p->keys() as $pk) {
                        $np->set($pk, $p->get($pk));
                    }
                    $na->set('params', $np);
                    if ($reaches($na) === null) {
                        $all = false;
                        break;
                    }
                }
                if ($all) {
                    $cands[] = Obj::of([
                        'repair' => Obj::of(['kind' => 'split', 'param' => $name, 'parts' => $parts]),
                        'cost' => 3 + $cnt, 'decision' => $want, 'action' => $action,
                    ]);
                }
            }
        }

        usort($cands, static fn(Obj $x, Obj $y): int => self::n($x->get('cost')) <=> self::n($y->get('cost')));
        $top = self::sliceN($cands, AnalyzerJs::nn(AnalyzerJs::jget($o, 'maxCandidates'), 8));
        $res->set('repairExists', count($top) > 0);
        $redact = AnalyzerJs::nn(AnalyzerJs::jget($o, 'redact'), 'critical');
        $hide = static function (Obj $c) use ($redact, $shape, $res, $action): Obj {
            $rp = $c->get('repair');
            if ($redact === 'none' || $rp->get('kind') !== 'set_param') {
                return $c;
            }
            $sens = AnalyzerJs::oget(self::decl($shape, $rp->get('param')), 'sensitivity');
            if ($redact === 'critical' && $sens !== 'critical') {
                return $c;
            }
            $res->set('redacted', true);
            $h = AnalyzerJs::copy($c);
            $h->set('repair', Obj::of(['kind' => 'set_param', 'param' => $rp->get('param'), 'redacted' => true]));
            $h->set('action', AnalyzerJs::spread($action));
            return $h;
        };
        if ($redact === 'all') {
            $res->set('redacted', true);
        } else {
            $hidden = [];
            foreach ($top as $c) {
                $hidden[] = $hide($c);
            }
            $res->set('repairs', $hidden);
        }
        $free = null;
        foreach ($top as $c) {
            if ($c->get('decision') === 'allow' && $c->get('repair')->get('kind') !== 'split') {
                $free = $c;
                break;
            }
        }
        if ($free !== null && $current === 'escalate') {
            $res->set('humanFree', $hide($free));
        }
        if ($current === 'escalate' || count($top) === 0) {
            $res->set('humanAsk', AnalyzerJs::uobj([
                'verb' => AnalyzerJs::jget($action, 'verb'), 'resource' => AnalyzerJs::jget($action, 'resource'), 'params' => AnalyzerJs::copy($params),
                'kind' => $current === 'escalate' ? 'approval' : 'access-request', 'policyDigest' => $digest,
            ]));
        }
        return $res;
    }
}
