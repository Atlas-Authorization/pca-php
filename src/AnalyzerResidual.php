<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/AnalyzerCore.php';
require_once __DIR__ . '/AnalyzerExposure.php';
require_once __DIR__ . '/AnalyzerFilter.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/Pca.php';

/**
 * Partial evaluation, residual policies and "what may I do?" discovery. A residual specialises a policy to the facts known about a
 * request (verb, resource, principal state, remaining budget) and leaves the unknown fields symbolic; it is itself a policy the
 * ordinary evaluator understands. Everything here is advisory: the verifier stays authoritative. The data-filter compilers (SQL
 * and UCAST) live in {@see AnalyzerFilter}; thin forwards are kept here.
 */
final class AnalyzerResidual
{
    private const UNKNOWN_VERB = "\u{0}unknown-verb\u{0}";
    private const UNKNOWN_RESOURCE = "\u{0}unknown-resource\u{0}";
    private const REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'];

    /** A path is symbolic when it is an unknown path, below one, or an ancestor of one. @param list<mixed> $unknown */
    private static function isUnknownPath(mixed $path, array $unknown): bool
    {
        if (!is_string($path)) {
            return false;
        }
        foreach ($unknown as $u) {
            $us = AnalyzerJs::jsStr($u);
            if ($path === $u || str_starts_with($path, $us . '.') || str_starts_with($us, $path . '.')) {
                return true;
            }
        }
        return false;
    }

    /** @return array{t: string, v: string, src: mixed} */
    private static function konst(string $v, mixed $src): array
    {
        return ['t' => 'const', 'v' => $v, 'src' => $src];
    }

    /** @param list<mixed> $unk @return array<string, mixed> */
    private static function pe(mixed $c, Obj $ctx, array $unk): array
    {
        if (!($c instanceof Obj) && !AnalyzerJs::isArr($c)) {
            return self::konst('unknown', $c);
        }
        if (Predicates::isGroupCondition($c)) {
            /** @var Obj $c */
            foreach (['all_of', 'any_of'] as $key) {
                if (!$c->has($key)) {
                    continue;
                }
                $a = $c->get($key);
                if (!AnalyzerJs::isArr($a) || count($a) === 0) {
                    return self::konst('unknown', $c);
                }
                $rs = array_map(static fn($x) => self::pe($x, $ctx, $unk), $a);
                $all = $key === 'all_of';
                $decisive = $all ? 'false' : 'true';
                $neutral = $all ? 'true' : 'false';
                foreach ($rs as $r) {
                    if ($r['t'] === 'const' && $r['v'] === $decisive) {
                        return self::konst($decisive, $c);
                    }
                }
                $kept = array_values(array_filter($rs, static fn($r) => !($r['t'] === 'const' && $r['v'] === $neutral)));
                if (count($kept) === 0) {
                    return self::konst($neutral, $c);
                }
                if (count(array_filter($kept, static fn($r) => $r['t'] !== 'const')) === 0) {
                    return self::konst('unknown', $c);
                }
                $cs = array_map(static fn($r) => $r['t'] === 'const' ? $r['src'] : $r['c'], $kept);
                return ['t' => 'cond', 'c' => count($cs) === 1 ? $cs[0] : Obj::of([$key => $cs])];
            }
            $r = self::pe($c->get('not'), $ctx, $unk);
            if ($r['t'] === 'cond') {
                return ['t' => 'cond', 'c' => Obj::of(['not' => $r['c']])];
            }
            return self::konst($r['v'] === 'true' ? 'false' : ($r['v'] === 'false' ? 'true' : 'unknown'), $c);
        }
        if (Predicates::isLeafCondition($c)
            && (self::isUnknownPath($c->get('field'), $unk) || self::isUnknownPath($c->get('ref'), $unk) || self::isUnknownPath($c->get('collection'), $unk))) {
            return ['t' => 'cond', 'c' => $c];
        }
        return self::konst(Predicates::evaluateConditionTri($c, $ctx), $c);
    }

    /**
     * AND of a `where` list: ['v', 'true'|'false'|'unknown'] or ['cs', symbolic conditions].
     *
     * @param list<mixed> $unk @return array{0: string, 1: mixed}
     */
    private static function peAll(mixed $where, Obj $ctx, array $unk): array
    {
        if ($where instanceof Undef) {
            return ['v', 'true'];
        }
        if (!AnalyzerJs::isArr($where)) {
            return ['v', 'unknown'];
        }
        $rs = array_map(static fn($w) => self::pe($w, $ctx, $unk), $where);
        foreach ($rs as $r) {
            if ($r['t'] === 'const' && $r['v'] === 'false') {
                return ['v', 'false'];
            }
        }
        $kept = array_values(array_filter($rs, static fn($r) => !($r['t'] === 'const' && $r['v'] === 'true')));
        if (count($kept) === 0) {
            return ['v', 'true'];
        }
        if (count(array_filter($kept, static fn($r) => $r['t'] !== 'const')) === 0) {
            return ['v', 'unknown'];
        }
        return ['cs', array_map(static fn($r) => $r['t'] === 'const' ? $r['src'] : $r['c'], $kept)];
    }

    private static function contextOf(mixed $k): Obj
    {
        $verb = AnalyzerJs::jget($k, 'verb');
        $resource = AnalyzerJs::jget($k, 'resource');
        $params = AnalyzerJs::jget($k, 'params');
        $subj = AnalyzerJs::jget($k, 'subject');
        $env = AnalyzerJs::jget($k, 'env');
        $rc = AnalyzerJs::jget($k, 'reversibilityClass');
        $action = Obj::of([
            'verb' => ($verb instanceof Undef || $verb === null) ? self::UNKNOWN_VERB : $verb,
            'resource' => ($resource instanceof Undef || $resource === null) ? self::UNKNOWN_RESOURCE : $resource,
            'params' => AnalyzerJs::spread($params),
        ]);
        if (!($rc instanceof Undef)) {
            $action->set('reversibility_class', $rc);
        }
        return Obj::of(['action' => $action, 'subject' => AnalyzerJs::spread($subj), 'env' => AnalyzerJs::spread($env)]);
    }

    /** hashCanonical of the policy a residual was planned against. */
    public static function policyDigestOf(mixed $model): string
    {
        return Pca::hashCanonical(Obj::of([
            'predicates' => $model->get('predicates'),
            'caveats' => $model->get('caveats'),
            'vetoes' => $model->get('vetoes'),
            'tighten' => $model->get('tighten'),
            'meet' => array_map(self::policyDigestOf(...), $model->get('meets')),
        ]));
    }

    /** @return list<mixed> */
    private static function flatten(mixed $m): array
    {
        $out = [$m];
        foreach ($m->get('meets') as $x) {
            foreach (self::flatten($x) as $y) {
                $out[] = $y;
            }
        }
        return $out;
    }

    private static function pm(Obj $pat, Obj $ctx): bool
    {
        return Predicates::predicateMatches($pat, $ctx);
    }

    /** `{...o}` without the members whose value is undefined. */
    private static function dropUndef(Obj $o): Obj
    {
        $r = new Obj();
        foreach ($o->keys() as $k) {
            if (!($o->get($k) instanceof Undef)) {
                $r->set($k, $o->get($k));
            }
        }
        return $r;
    }

    /** @param list<mixed> $unk */
    private static function residualPart(mixed $part, Obj $ctx, array $unk, bool $verbKnown, bool $resKnown): Obj
    {
        $predicates = [];
        foreach ($part->get('predicates') as $p) {
            if (!($p instanceof Obj) && !AnalyzerJs::isArr($p)) {
                continue;
            }
            $pv = AnalyzerJs::jget($p, 'verb');
            $pr = AnalyzerJs::jget($p, 'resource');
            if ($verbKnown && !self::pm(AnalyzerJs::uobj(['verb' => $pv, 'resource' => '*']), $ctx)) {
                continue;
            }
            if ($resKnown && !self::pm(AnalyzerJs::uobj(['verb' => '*', 'resource' => $pr]), $ctx)) {
                continue;
            }
            $w = self::peAll(AnalyzerJs::jget($p, 'where'), $ctx, $unk);
            if ($w[0] === 'v' && $w[1] !== 'true') {
                continue; // false and unknown both fail closed for a permit
            }
            $item = AnalyzerJs::uobj(['verb' => $verbKnown ? '*' : $pv]);
            if (!$resKnown && !($pr instanceof Undef)) {
                $item->set('resource', $pr);
            }
            if ($w[0] === 'cs') {
                $item->set('where', $w[1]);
            }
            $predicates[] = $item;
        }
        $vetoes = [];
        foreach ($part->get('vetoes') as $v) {
            $pv = self::peVeto($v, $ctx, $unk, $verbKnown, $resKnown);
            if ($pv !== null) {
                $vetoes[] = $pv;
            }
        }
        $tighten = [];
        foreach ($part->get('tighten') as $t) {
            $tw = AnalyzerJs::jget($t, 'when');
            $r = self::pe($tw instanceof Undef ? null : $tw, $ctx, $unk);
            if ($r['t'] === 'const' && $r['v'] === 'false') {
                continue; // a veto-polarity rule that cleanly cannot hold
            }
            $nt = AnalyzerJs::spread($t);
            $nt->set('when', $r['t'] === 'cond' ? $r['c'] : $tw);
            $tighten[] = self::dropUndef($nt);
        }
        return Obj::of(['predicates' => $predicates, 'caveats' => $part->get('caveats'), 'vetoes' => $vetoes, 'tighten' => $tighten]);
    }

    /** @param list<mixed> $unk */
    private static function peVeto(mixed $v, Obj $ctx, array $unk, bool $verbKnown, bool $resKnown): ?Obj
    {
        $when = AnalyzerJs::jget($v, 'when');
        $wv = AnalyzerJs::jget($when, 'verb');
        if ($verbKnown && !self::pm(AnalyzerJs::uobj(['verb' => $wv, 'resource' => '*']), $ctx)) {
            return null;
        }
        $wr = AnalyzerJs::jget($when, 'resource');
        if ($resKnown && !($wr instanceof Undef) && !self::pm(AnalyzerJs::uobj(['verb' => '*', 'resource' => $wr]), $ctx)) {
            return null;
        }
        $w = self::peAll(AnalyzerJs::jget($when, 'where'), $ctx, $unk);
        if ($w[0] === 'v' && $w[1] === 'false') {
            return null; // veto polarity: a clean false removes the veto; true and unknown mean it applies
        }
        $keep = $w[0] === 'cs' ? $w[1] : null;
        $nw = AnalyzerJs::uobj(['verb' => $verbKnown ? '*' : $wv]);
        if (!$resKnown && !($wr instanceof Undef)) {
            $nw->set('resource', $wr);
        }
        if ($keep !== null) {
            $nw->set('where', $keep);
        }
        $out = AnalyzerJs::uobj(['id' => AnalyzerJs::jget($v, 'id'), 'kind' => AnalyzerJs::jget($v, 'kind'), 'when' => $nw]);
        $over = AnalyzerJs::jget($v, 'over');
        if (AnalyzerJs::truthy($over)) {
            if (self::isUnknownPath(AnalyzerJs::jget($over, 'path'), $unk)) {
                $out->set('over', $over);
            } else {
                $r = Predicates::resolvePath($ctx, AnalyzerJs::jget($over, 'path'));
                $val = $r['value'] ?? null;
                $f = AnalyzerJs::fin($val);
                $isOver = !$r['found'] || $f === null || $f < 0 || AnalyzerJs::jsGt($val, AnalyzerJs::jget($over, 'threshold'));
                if (!$isOver) {
                    return null;
                }
            }
        }
        $unless = AnalyzerJs::jget($v, 'unless');
        if (AnalyzerJs::truthy($unless) && AnalyzerJs::jget($v, 'kind') === 'approval') {
            $out->set('unless', $unless); // the evidence of approval: carried, never used to drop the veto
        } elseif (AnalyzerJs::truthy($unless)) {
            $u = self::peAll($unless, $ctx, $unk);
            if ($u[0] === 'cs') {
                $out->set('unless', $u[1]);
            } elseif ($u[1] === 'true') {
                return null; // the exception certainly holds: the veto never applies
            }
        }
        return $out;
    }

    /**
     * Specialise `$policy` to `$known` ({verb?, resource?, params?, subject?, env?, reversibilityClass?}); everything under
     * `$opts.unknown` stays symbolic. Returns {decision: 'never'|'always'|'conditional', reason?, policy, policyDigest}.
     */
    public static function residual(mixed $policy, mixed $known, mixed $opts = null): Obj
    {
        $opts = $opts ?? new Obj();
        $model = AnalyzerCore::toModel($policy);
        $digest = self::policyDigestOf($model);
        $verbKnown = !(AnalyzerJs::jget($known, 'verb') instanceof Undef);
        $resKnown = !(AnalyzerJs::jget($known, 'resource') instanceof Undef) && AnalyzerJs::jget($opts, 'resourceUnknown') !== true;
        $unknown = AnalyzerJs::nn(AnalyzerJs::jget($opts, 'unknown'), ['action.params']);
        $unk = array_merge(AnalyzerJs::reqList($unknown), $verbKnown ? [] : ['action.verb'], $resKnown ? [] : ['action.resource']);
        $ctx = self::contextOf($known);
        $never = static fn(string $reason): Obj => Obj::of([
            'decision' => 'never',
            'reason' => $reason,
            'policy' => Obj::of(['predicates' => [], 'caveats' => [], 'vetoes' => [], 'tighten' => []]),
            'policyDigest' => $digest,
        ]);

        if (!$model->get('caveatSat')) {
            return $never('caveats unsatisfiable: ' . AnalyzerJs::jsStr(AnalyzerJs::own($model, 'caveatReason', 'unknown', true)));
        }
        $rc = AnalyzerJs::jget($known, 'reversibilityClass');
        if (!($rc instanceof Undef) && $model->has('revCap')) {
            $idx = is_string($rc) && in_array($rc, self::REVERSIBILITY_ORDER, true) ? array_search($rc, self::REVERSIBILITY_ORDER, true) : -1;
            if ($idx < 0 || AnalyzerJs::jsGt($idx, $model->get('revCap'))) {
                return $never('reversibility class exceeds the caveat cap');
            }
        }
        $parts = array_map(static fn($m) => self::residualPart($m, $ctx, $unk, $verbKnown, $resKnown), self::flatten($model));
        $own = $parts[0];
        $rest = array_slice($parts, 1);
        $pol = AnalyzerJs::copy($own);
        if (count($rest) > 0) {
            $pol->set('meet', $rest);
        }
        $res = Obj::of(['decision' => 'conditional', 'policy' => $pol, 'policyDigest' => $digest]);
        foreach ($parts as $p) {
            if (count($p->get('predicates')) === 0) {
                return $never('no permit survives the known facts');
            }
        }
        foreach ($parts as $p) {
            foreach ($p->get('vetoes') as $v) {
                $w = $v->get('when');
                if (AnalyzerJs::own($v, 'kind') === 'deny'
                    && (!$w->has('resource') || AnalyzerJs::strictEq($w->get('resource'), '*'))
                    && (!$w->has('where') || count($w->get('where')) === 0)
                    && !$v->has('unless') && !$v->has('over')) {
                    return $never('veto ' . AnalyzerJs::jsStr(AnalyzerJs::own($v, 'id')) . ' applies to every completion');
                }
            }
        }
        $always = true;
        foreach ($parts as $p) {
            $anyOpen = false;
            foreach ($p->get('predicates') as $x) {
                if (!$x->has('where')) {
                    $anyOpen = true;
                    break;
                }
            }
            if (!($anyOpen && count($p->get('vetoes')) === 0 && count($p->get('tighten')) === 0)) {
                $always = false;
                break;
            }
        }
        if ($always) {
            $res->set('decision', 'always');
        }
        return $res;
    }

    /** The residual as a policy the analyzer and the real evaluator both understand. */
    public static function residualPolicy(mixed $r): Obj
    {
        $pol = AnalyzerJs::jget($r, 'policy');
        if (!($pol instanceof Obj)) {
            throw new \TypeError('policy is not an object');
        }
        $own = $pol->without('meet');
        $meet = $pol->get('meet');
        if (AnalyzerJs::truthy($meet)) {
            $own->set('meet', array_map(static fn($m) => AnalyzerJs::copy($m), AnalyzerJs::reqList($meet)));
        }
        return $own;
    }

    /** Ternary decision of a residual once the unknown fields are bound. */
    public static function evaluateResidual(mixed $r, mixed $ctx): string
    {
        if (AnalyzerJs::jget($r, 'decision') === 'never') {
            return 'deny';
        }
        $a = AnalyzerJs::jget($ctx, 'action');
        $action = AnalyzerJs::uobj(['verb' => AnalyzerJs::jget($a, 'verb'), 'resource' => AnalyzerJs::jget($a, 'resource')]);
        if (AnalyzerJs::truthy(AnalyzerJs::jget($a, 'params'))) {
            $action->set('params', AnalyzerJs::jget($a, 'params'));
        }
        if (AnalyzerJs::truthy(AnalyzerJs::jget($ctx, 'subject'))) {
            $action->set('subject', AnalyzerJs::jget($ctx, 'subject'));
        }
        if (AnalyzerJs::truthy(AnalyzerJs::jget($ctx, 'env'))) {
            $action->set('env', AnalyzerJs::jget($ctx, 'env'));
        }
        if (AnalyzerJs::truthy(AnalyzerJs::jget($a, 'reversibility_class'))) {
            $action->set('reversibilityClass', AnalyzerJs::jget($a, 'reversibility_class'));
        }
        return AnalyzerCore::decideAction(AnalyzerCore::toModel(self::residualPolicy($r)), $action);
    }

    // ---- "what may I do?" ------------------------------------------------------------------------------------------------------

    /**
     * Merge overlapping ranges. Ranges are PHP assoc arrays with the optional keys lo / hi / loInclusive / hiInclusive (key order
     * follows the reference: a re-set key moves to the end).
     *
     * @param list<array<string, mixed>> $rs @return list<array<string, mixed>>
     */
    private static function mergeRanges(array $rs): array
    {
        $lo = static fn(array $r): float => array_key_exists('lo', $r) ? AnalyzerJs::jsnum($r['lo']) : -INF;
        usort($rs, static function (array $a, array $b) use ($lo): int {
            $la = $lo($a);
            $lb = $lo($b);
            $d = !($la == $lb && is_infinite($la)) ? $la - $lb : NAN;
            if (is_nan($d) || $d == 0) { // NaN and 0 are falsy: fall through to the inclusive tie-break
                return ((int)!empty($b['loInclusive'])) - ((int)!empty($a['loInclusive']));
            }
            return $d < 0 ? -1 : 1;
        });
        $out = [];
        foreach ($rs as $r) {
            $n = count($out);
            $rlo = array_key_exists('lo', $r) ? AnalyzerJs::jsnum($r['lo']) : -INF;
            $rhi = array_key_exists('hi', $r) ? AnalyzerJs::jsnum($r['hi']) : INF;
            $lhi = 0.0;
            if ($n > 0) {
                $lhi = array_key_exists('hi', $out[$n - 1]) ? AnalyzerJs::jsnum($out[$n - 1]['hi']) : INF;
            }
            if ($n > 0 && $lhi >= $rlo && !($lhi == $rlo && empty($out[$n - 1]['hiInclusive']) && empty($r['loInclusive']))) {
                if ($rhi > $lhi || ($rhi == $lhi && !empty($r['hiInclusive']))) {
                    if (!array_key_exists('hi', $r)) {
                        unset($out[$n - 1]['hi']);
                    } else {
                        $out[$n - 1]['hi'] = $r['hi'];
                    }
                    if (!empty($r['hiInclusive'])) {
                        $out[$n - 1]['hiInclusive'] = true;
                    } else {
                        unset($out[$n - 1]['hiInclusive']);
                    }
                }
            } else {
                $out[] = $r;
            }
        }
        return $out;
    }

    /** @param list<mixed> $T @return array<string, mixed> */
    private static function cellRange(mixed $value, array $T): array
    {
        foreach ($T as $t) {
            if (AnalyzerJs::strictEq($t, $value)) {
                return ['lo' => $value, 'hi' => $value, 'loInclusive' => true, 'hiInclusive' => true];
            }
        }
        $out = [];
        for ($i = count($T) - 1; $i >= 0; $i--) {
            if (AnalyzerJs::jsLt($T[$i], $value)) {
                $out['lo'] = $T[$i];
                break;
            }
        }
        foreach ($T as $t) {
            if (AnalyzerJs::jsGt($t, $value)) {
                $out['hi'] = $t;
                break;
            }
        }
        return $out;
    }

    /** JS `a >= b` for a number `a`. */
    private static function jsGe(mixed $a, mixed $b): bool
    {
        return Jsx::toNum($a) >= Jsx::toNum($b);
    }

    /** JS `a <= b` for a number `a`. */
    private static function jsLe(mixed $a, mixed $b): bool
    {
        return Jsx::toNum($a) <= Jsx::toNum($b);
    }

    /** @param list<array<string, mixed>> $rs @return list<Obj> */
    private static function rangeObjs(array $rs): array
    {
        return array_map(static fn(array $r) => Obj::of($r), $rs);
    }

    /** @param list<string> $xs @return list<string> */
    private static function u16sorted(array $xs): array
    {
        usort($xs, static fn(string $a, string $b): int => AnalyzerJs::u16cmp($a, $b));
        return $xs;
    }

    /**
     * Per verb shape ({verb, params}): autonomous / approval-only / denied for the known principal, and which parameter values and
     * resources are still allowed. Advisory; sound on the decided fragment, otherwise `approximate`.
     *
     * @return list<Obj>
     */
    public static function whatMayIDo(mixed $policy, mixed $verbs, mixed $known = null, mixed $o = null): array
    {
        $known = $known ?? new Obj();
        $o = $o ?? new Obj();
        $out = [];
        $mc = AnalyzerJs::jget($o, 'maxCombinations');
        $mx = AnalyzerJs::isNum($mc) ? AnalyzerJs::jsnum($mc) : AnalyzerCore::DEFAULT_MAX_COMBINATIONS;
        foreach (AnalyzerJs::reqList($verbs) as $shape) {
            $sverb = AnalyzerJs::jget($shape, 'verb');
            $kn = AnalyzerJs::spread($known);
            $kn->set('verb', $sverb);
            $res = self::residual($policy, self::dropUndef($kn));
            $env = AnalyzerJs::uobj([
                'verb' => $sverb,
                'status' => 'denied',
                'params' => new Obj(),
                'resources' => Obj::of(['autonomous' => [], 'withApproval' => [], 'other' => false]),
                'policyDigest' => $res->get('policyDigest'),
                'advisory' => true,
            ]);
            $rem = AnalyzerJs::jget($o, 'remaining');
            if (AnalyzerJs::truthy($rem)) {
                $env->set('remaining', AnalyzerJs::spread($rem));
            }
            $md = AnalyzerJs::jget($o, 'missingDischarges');
            if (AnalyzerJs::truthy($md)) {
                $env->set('missingDischarges', Jsx::iter($md));
            }
            if ($res->get('decision') === 'never') {
                if ($res->has('reason')) {
                    $env->set('reason', $res->get('reason'));
                }
                $out[] = $env;
                continue;
            }
            $rp = AnalyzerCore::toModel(self::residualPolicy($res));
            $sparams = AnalyzerJs::jget($shape, 'params');
            if (!($sparams instanceof Obj)) {
                throw new \TypeError('Object.entries requires an object');
            }
            $names = AnalyzerJs::keyOrder($sparams);
            $extra = [];
            foreach ($names as $name) {
                $d = $sparams->get($name);
                if (!(AnalyzerJs::jget($d, 'values') instanceof Undef)) {
                    $extra[] = Obj::of(['path' => "action.params.$name", 'cond' => Obj::of(['field' => "action.params.$name", 'op' => 'in', 'value' => $d->get('values')])]);
                }
            }
            $extraNum = [];
            foreach ($names as $name) {
                $d = $sparams->get($name);
                if (!(AnalyzerJs::jget($d, 'min') instanceof Undef)) {
                    $extraNum[] = Obj::of(['path' => "action.params.$name", 'cond' => Obj::of(['field' => "action.params.$name", 'op' => 'gte', 'value' => $d->get('min')])]);
                }
                if (!(AnalyzerJs::jget($d, 'max') instanceof Undef)) {
                    $extraNum[] = Obj::of(['path' => "action.params.$name", 'cond' => Obj::of(['field' => "action.params.$name", 'op' => 'lte', 'value' => $d->get('max')])]);
                }
            }
            $pr = AnalyzerCore::collectProbes(Obj::of([
                'predicateSets' => [AnalyzerCore::probeSet($rp)],
                'extraFieldConditions' => array_merge($extra, $extraNum),
                'varyReversibility' => $rp->has('revCap'),
            ]));
            $pr->set('verbs', [$sverb]);
            $declared = $names;
            if (AnalyzerCore::productSize($pr) > $mx) {
                $env->set('status', 'needs-approval');
                $env->set('approximate', true);
                $env->set('reason', 'representative grid exceeded the bound; no domain is claimed');
                $out[] = $env;
                continue;
            }
            $kres = AnalyzerJs::jget($known, 'resource');
            if (!($kres instanceof Undef)) {
                $pr->set('resources', [$kres]);
            }
            /** @var array<string, array<string, \stdClass>> $seen */
            $seen = [];
            /** @var array<string, array{0: string, 1: \stdClass}> $resSeen */
            $resSeen = [];
            $anyAllow = false;
            $anyEscalate = false;
            $freshRes = false;
            foreach (AnalyzerCore::representatives($pr) as $rep) {
                $d = AnalyzerCore::decide($rp, $rep);
                if ($d === 'deny') {
                    continue;
                }
                if ($d === 'allow') {
                    $anyAllow = true;
                } else {
                    $anyEscalate = true;
                }
                $act = AnalyzerCore::repToAction($rep);
                $params = $act->get('params');
                if (!AnalyzerJs::truthy($params)) {
                    $params = new Obj();
                }
                foreach ($declared as $name) {
                    $v = AnalyzerJs::own($params, $name);
                    $k = $v instanceof Undef ? "\u{0}absent" : AnalyzerJs::jsJson($v);
                    if (!isset($seen['k' . $name]['k' . $k])) {
                        $c = new \stdClass();
                        $c->value = $v;
                        $c->allow = false;
                        $c->escalate = false;
                        $seen['k' . $name]['k' . $k] = $c;
                    }
                    $cur = $seen['k' . $name]['k' . $k];
                    if ($d === 'allow') {
                        $cur->allow = true;
                    } else {
                        $cur->escalate = true;
                    }
                }
                $resource = $act->get('resource');
                if (!is_string($resource)) {
                    throw new \TypeError('resource.startsWith is not a function');
                }
                if (!isset($resSeen['k' . $resource])) {
                    $rc = new \stdClass();
                    $rc->allow = false;
                    $rc->escalate = false;
                    $resSeen['k' . $resource] = [$resource, $rc];
                }
                $rr = $resSeen['k' . $resource][1];
                if ($d === 'allow') {
                    $rr->allow = true;
                } else {
                    $rr->escalate = true;
                }
                if (str_starts_with($resource, "\u{0}")) {
                    $freshRes = true;
                }
            }
            $env->set('status', $anyAllow ? 'autonomous' : ($anyEscalate ? 'needs-approval' : 'denied'));
            foreach ($declared as $name) {
                $decl = $sparams->get($name);
                $path = "action.params.$name";
                $T = AnalyzerExposure::thresholdsOf($rp, $path);
                $vals = array_values($seen['k' . $name] ?? []);
                $dmin = AnalyzerJs::jget($decl, 'min');
                $dmax = AnalyzerJs::jget($decl, 'max');
                $nums = array_values(array_filter($vals, static fn($x) => AnalyzerJs::isNum($x->value)
                    && ($dmin instanceof Undef || self::jsGe($x->value, $dmin))
                    && ($dmax instanceof Undef || self::jsLe($x->value, $dmax))));
                $strs = array_values(array_filter($vals, static fn($x) => is_string($x->value)));
                $dvalues = AnalyzerJs::jget($decl, 'values');
                $pdom = $env->get('params');
                if (AnalyzerJs::jget($decl, 'type') === 'integer' || count($nums) > 0) {
                    $clip = static function (array $r) use ($dmin, $dmax): array {
                        $n = $r;
                        if (!($dmin instanceof Undef) && (!array_key_exists('lo', $r) || AnalyzerJs::jsLt($r['lo'], $dmin))) {
                            $n['lo'] = $dmin;
                            $n['loInclusive'] = true;
                        }
                        if (!($dmax instanceof Undef) && (!array_key_exists('hi', $r) || AnalyzerJs::jsGt($r['hi'], $dmax))) {
                            $n['hi'] = $dmax;
                            $n['hiInclusive'] = true;
                        }
                        return $n;
                    };
                    $ranges = static function (callable $pick) use ($nums, $T, $clip): array {
                        $rs = [];
                        foreach ($nums as $x) {
                            if ($pick($x)) {
                                $rs[] = $clip(self::cellRange($x->value, $T));
                            }
                        }
                        return self::rangeObjs(self::mergeRanges($rs));
                    };
                    $pdom->set($name, Obj::of([
                        'kind' => 'numeric',
                        'autonomous' => $ranges(static fn($x) => $x->allow),
                        'withApproval' => $ranges(static fn($x) => $x->escalate && !$x->allow),
                    ]));
                } elseif (!($dvalues instanceof Undef) || count($strs) > 0) {
                    $pickList = static function (callable $f) use ($strs): array {
                        $xs = [];
                        foreach ($strs as $x) {
                            if ($f($x) && !str_starts_with($x->value, "\u{0}")) {
                                $xs[] = $x->value;
                            }
                        }
                        return self::u16sorted($xs);
                    };
                    $fresh = null;
                    foreach ($strs as $x) {
                        if (str_starts_with($x->value, "\u{0}")) {
                            $fresh = $x;
                            break;
                        }
                    }
                    $pdom->set($name, Obj::of([
                        'kind' => 'enum',
                        'autonomous' => $pickList(static fn($x) => $x->allow),
                        'withApproval' => $pickList(static fn($x) => $x->escalate && !$x->allow),
                        'otherAutonomous' => $dvalues instanceof Undef && $fresh !== null && $fresh->allow === true,
                        'otherWithApproval' => $dvalues instanceof Undef && $fresh !== null && $fresh->escalate && !$fresh->allow,
                    ]));
                } else {
                    $pdom->set($name, Obj::of(['kind' => 'unconstrained']));
                }
            }
            $auto = [];
            $appr = [];
            foreach ($resSeen as [$rname, $v]) {
                if (str_starts_with($rname, "\u{0}")) {
                    continue;
                }
                if ($v->allow) {
                    $auto[] = $rname;
                }
                if ($v->escalate && !$v->allow) {
                    $appr[] = $rname;
                }
            }
            $env->set('resources', Obj::of(['autonomous' => self::u16sorted($auto), 'withApproval' => self::u16sorted($appr), 'other' => $freshRes]));
            $undecidable = $rp->get('undecidable');
            if (count($undecidable) > 0) {
                $env->set('approximate', true);
                $env->set('reason', 'over-approximated (' . implode('; ', array_map(AnalyzerJs::jsStr(...), $undecidable)) . ')');
            }
            $out[] = $env;
        }
        return $out;
    }

    // ---- data filters: see AnalyzerFilter ------------------------------------------------------------------------------------------

    public static function toFilter(mixed $res, mixed $o): Obj
    {
        return AnalyzerFilter::toFilter($res, $o);
    }

    public static function evalFilter(mixed $e, mixed $row): ?bool
    {
        return AnalyzerFilter::evalFilter($e, $row);
    }

    public static function toUcast(mixed $e): Obj
    {
        return AnalyzerFilter::toUcast($e);
    }

    public static function evalUcast(mixed $u, mixed $row): bool
    {
        return AnalyzerFilter::evalUcast($u, $row);
    }
}
