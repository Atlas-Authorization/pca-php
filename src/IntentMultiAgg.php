<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentLearner.php';
require_once __DIR__ . '/IntentMapKit.php';
require_once __DIR__ . '/IntentMulti.php';
require_once __DIR__ . '/IntentRegion.php';

/**
 * Multi-principal aggregation over Intent Maps: the joint grant under a unanimity / quorum / weighted rule (every number recomputable from
 * the inputs), lifting a map onto a common refinement, and cross-organisation aggregation. Maps are Obj trees (see IntentMapKit); `$opts`
 * is an Obj or assoc array {orgs?: {principal ref: org name}}.
 */
final class IntentMultiAgg
{
    private const ORDER = ['reversible', 'rate_limited', 'irreversible'];

    private static function g(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    private static function f(mixed $x): float
    {
        return Js::num($x) ?? NAN;
    }

    private static function req(mixed $o, string $k): mixed
    {
        if (!Js::has($o, $k)) {
            throw new \OutOfBoundsException("'$k'");
        }
        return Js::opt($o, $k);
    }

    /** Aggregate single-principal maps over a SHARED omega under a rule; the result has `aggregation` set. */
    public static function aggregateIntentMaps(array $maps, mixed $rule, mixed $opts = null): Obj
    {
        $orgs = self::g($opts, 'orgs');
        if (count($maps) === 0) {
            throw new \InvalidArgumentException('aggregateIntentMaps: no maps');
        }
        $om = Js::stringify(self::g($maps[0], 'omega'));
        foreach ($maps as $m) {
            if (Js::stringify(self::g($m, 'omega')) !== $om) {
                throw new \InvalidArgumentException('aggregateIntentMaps: maps must share ' . "\u{03A9}" . ' (lift them with crossOrgAggregate)');
            }
        }
        foreach ($maps as $m) {
            if (self::g($m, 'aggregation') !== null || count(self::g($m, 'principals')) !== 1 || !is_string(self::g($m, 'intent_ref'))) {
                throw new \InvalidArgumentException('aggregateIntentMaps: every input must be a single-principal map with an intent_ref');
            }
        }
        $refs = array_map(static fn($m) => self::g($m, 'intent_ref'), $maps);
        if (count(array_unique($refs)) !== count($refs)) {
            throw new \InvalidArgumentException('aggregateIntentMaps: duplicate principal');
        }
        $n = IntentMulti::normalizeRule($rule, $refs);
        $omega = IntentMapKit::omegaFromJSON(self::g($maps[0], 'omega'));
        $stats = [];
        foreach (self::g($omega, 'verbs') as $vs) {
            $nc = WalletOmega::verbCellCount($vs);
            for ($c = 0; $c < $nc; $c++) {
                $stats[] = WalletOmega::cellStats($vs, WalletOmega::decodeCell($vs, $c));
            }
        }
        $cells = [];
        foreach (self::g($maps[0], 'cells') as $i => $c) {
            $ps = [];
            $ins = [];
            foreach ($maps as $m) {
                $mc = self::g($m, 'cells')[$i];
                $ps[] = self::f(self::g($mc, 'p_ppm')) / 1e6;
                $ins[] = self::g($mc, 'in_grant');
            }
            $cells[] = ['verb' => self::g($c, 'verb'), 'cell' => self::g($c, 'cell'), 'p_ppm' => IntentMulti::ppm(IntentMulti::jointAcceptance($n, $ps)),
                'in_grant' => IntentMulti::ruleAdmits($n, $ins)];
        }
        $predicates = [];
        $worst = -1;
        $off = 0;
        foreach (self::g($omega, 'verbs') as $vs) {
            $nc = WalletOmega::verbCellCount($vs);
            $allowed = [];
            $any = false;
            for ($c = 0; $c < $nc; $c++) {
                $a = $cells[$off + $c]['in_grant'];
                $allowed[] = $a ? 1 : 0;
                $any = $any || $a;
            }
            $off += $nc;
            if (!$any) {
                continue;
            }
            $ix = array_search(self::g($vs, 'reversibility'), self::ORDER, true);
            $worst = max($worst, $ix === false ? -1 : $ix);
            foreach (IntentLearner::boxesToPredicates($vs, $allowed) as $p) {
                $predicates[] = $p;
            }
        }
        $grant = ['predicates' => $predicates, 'caveats' => $worst >= 0 ? [['type' => 'reversibility_max', 'class' => self::ORDER[$worst]]] : []];
        // each principal's own posterior estimate of the JOINT grant
        $per = [];
        foreach ($maps as $i => $m) {
            $R = $B = $Rmax = 0.0;
            foreach (self::g($m, 'cells') as $j => $c) {
                $p = self::f(self::g($c, 'p_ppm')) / 1e6;
                $mass = $stats[$j]['mass'];
                $harm = $stats[$j]['harm'];
                $Rmax += $mass * (1 - $p) * $harm;
                if ($cells[$j]['in_grant']) {
                    $R += $mass * (1 - $p) * $harm;
                } else {
                    $B += $mass * $p;
                }
            }
            $e = ['intent_ref' => $refs[$i]];
            $org = Js::isObj($orgs) ? self::g($orgs, $refs[$i]) : null;
            if (Js::truthy($org)) {
                $e['org'] = $org;
            }
            $e['R'] = $R;
            $e['B'] = $B;
            $e['F'] = $Rmax > 0 ? 1 - $R / $Rmax : 1.0;
            $per[] = $e;
        }
        $worstMetric = static function (string $k, \Closure $f) use ($maps): mixed {
            return $f(array_map(static function ($m) use ($k) {
                $v = self::g(self::g($m, 'metrics'), $k);
                return $v !== null ? Js::num($v) : 0;
            }, $maps));
        };
        $kind = self::g($rule, 'kind');
        $aggregation = ['rule' => $kind];
        if ($kind === 'quorum') {
            $aggregation['k'] = self::g($rule, 'k');
        }
        if ($kind === 'weighted') {
            $w = new Obj();
            foreach ($refs as $i => $r) {
                $w->set($r, $n['weights'][$i]);
            }
            $aggregation['weights'] = $w;
            $aggregation['threshold'] = self::g($rule, 'threshold');
        }
        $aggregation['vetoers'] = array_values(array_filter($refs, static fn($r, $i) => $n['veto'][$i], ARRAY_FILTER_USE_BOTH));
        $pp = [];
        foreach ($per as $x) {
            $e = ['intent_ref' => $x['intent_ref']];
            if (!empty($x['org'])) {
                $e['org'] = $x['org'];
            }
            $e['residual_risk_ppm'] = IntentMulti::ppm($x['R']);
            $e['burden_ppm'] = IntentMulti::ppm($x['B']);
            $pp[] = $e;
        }
        $aggregation['per_principal'] = $pp;
        $anyNullLog = false;
        foreach ($maps as $m) {
            if (self::g(self::g($m, 'metrics'), 'log2_vs_mbits') === null) {
                $anyNullLog = true;
            }
        }
        $sum = static fn(array $xs) => array_sum($xs);
        return IntentMapKit::obj([
            'v' => 1,
            'kind' => 'pca-intent-map',
            'intent_ref' => null,
            'principals' => $refs,
            'omega' => self::g($maps[0], 'omega'),
            'learner' => self::g($maps[0], 'learner'),
            'observations' => array_merge(...array_map(static fn($m) => array_values(self::g($m, 'observations')), $maps)),
            'cells' => $cells,
            'grant' => $grant,
            'grant_digest' => IntentMapKit::grantDigest(IntentMapKit::obj($grant)),
            'metrics' => [
                // every principal's own posterior estimate of the joint grant; the map reports the worst of them
                'residual_risk_ppm' => max(array_map(static fn($x) => $x['residual_risk_ppm'], $pp)),
                'burden_ppm' => max(array_map(static fn($x) => $x['burden_ppm'], $pp)),
                'uncertainty_ppm' => $worstMetric('uncertainty_ppm', max(...)),
                'disagreement_ppm' => $worstMetric('disagreement_ppm', max(...)),
                'mean_harm_ppm' => self::g(self::g($maps[0], 'metrics'), 'mean_harm_ppm'),
                'fidelity_est_ppm' => IntentMulti::ppm(min(array_map(static fn($x) => $x['F'], $per))),
                'entropy_mbits' => $worstMetric('entropy_mbits', $sum),
                'log2_vs_mbits' => $anyNullLog ? null : $worstMetric('log2_vs_mbits', $sum),
                'questions' => $worstMetric('questions', $sum),
                'conflicts' => $worstMetric('conflicts', $sum),
            ],
            'aggregation' => $aggregation,
        ]);
    }

    /** The unanimity rule: the joint grant is the intersection of the principals' conservative grants. */
    public static function combineIntentMaps(array $maps, mixed $opts = null): Obj
    {
        return self::aggregateIntentMaps($maps, ['kind' => 'unanimity'], $opts);
    }

    /** The rule an aggregated map records. */
    public static function ruleOf(mixed $agg): Obj
    {
        $a = self::g($agg, 'aggregation');
        if (!Js::truthy($a)) {
            throw new \InvalidArgumentException('ruleOf: not an aggregated map');
        }
        if (self::g($a, 'rule') === 'unanimity') {
            return IntentMapKit::obj(['kind' => 'unanimity', 'vetoers' => self::req($a, 'vetoers')]);
        }
        if (self::g($a, 'rule') === 'quorum') {
            return IntentMapKit::obj(['kind' => 'quorum', 'k' => self::g($a, 'k'), 'vetoers' => self::req($a, 'vetoers')]);
        }
        return IntentMapKit::obj(['kind' => 'weighted', 'weights' => self::g($a, 'weights'), 'threshold' => self::g($a, 'threshold'), 'vetoers' => self::req($a, 'vetoers')]);
    }

    /**
     * Replay-verify every input map, then recompute the aggregate and compare digests (inputs share the omega).
     * @return array{ok:bool,problems:list<string>}
     */
    public static function verifyAggregate(mixed $agg, array $inputs, mixed $opts = null): array
    {
        $problems = [];
        try {
            foreach ($inputs as $i => $m) {
                $r = IntentMapKit::verifyIntentMap($m);
                if (!$r['ok']) {
                    $problems[] = "input $i: " . implode('; ', $r['problems']);
                }
            }
            if ($problems !== []) {
                return ['ok' => false, 'problems' => $problems];
            }
            $again = self::aggregateIntentMaps($inputs, self::ruleOf($agg), $opts);
            if (IntentMapKit::intentMapDigest($again) !== IntentMapKit::intentMapDigest($agg)) {
                $problems[] = 'aggregate does not match its recomputation';
            }
        } catch (\Throwable $e) {
            $problems[] = 'recompute failed: ' . $e->getMessage();
        }
        return ['ok' => $problems === [], 'problems' => $problems];
    }

    /**
     * Re-express a single-principal map on a refinement of its omega: observations re-applied as value-space regions and prior mass 1 on
     * the empty hypothesis for every verb the map did not cover.
     */
    public static function liftIntentMap(mixed $m, mixed $target): Obj
    {
        if (self::g($m, 'aggregation') !== null || count(self::g($m, 'principals')) > 1) {
            throw new \InvalidArgumentException('liftIntentMap: lift single-principal maps, then aggregate');
        }
        $src = IntentMapKit::omegaFromJSON(self::g($m, 'omega'));
        $o = IntentMapKit::mapLearnerOptions($m);
        $known = array_map(static fn($v) => self::g($v, 'verb'), self::g($src, 'verbs'));
        $srcMass = $o['nullMass'];
        $nullMass = new Obj();
        foreach (self::g($target, 'verbs') as $vs) {
            $verb = self::g($vs, 'verb');
            if (in_array($verb, $known, true)) {
                $own = Js::isObj($srcMass) ? self::g($srcMass, $verb) : null;
                $nullMass->set($verb, $own === null ? 0.2 : $own);
            } else {
                $nullMass->set($verb, 1);
            }
        }
        $l = IntentMapKit::createLearner($target, array_merge($o, ['nullMass' => $nullMass]));
        foreach (self::g($m, 'observations') as $ob) {
            $svs = $tvs = null;
            foreach (self::g($src, 'verbs') as $v) {
                if (self::g($v, 'verb') === self::g($ob, 'verb')) {
                    $svs = $v;
                    break;
                }
            }
            foreach (self::g($target, 'verbs') as $v) {
                if (self::g($v, 'verb') === self::g($ob, 'verb')) {
                    $tvs = $v;
                    break;
                }
            }
            if ($svs === null || $tvs === null) {
                throw new \InvalidArgumentException('liftIntentMap: verb ' . Js::str(self::g($ob, 'verb')) . " missing from \u{03A9}");
            }
            $values = new Obj();
            $ov = self::g($ob, 'values');
            foreach ($ov->keys() as $k) {
                $values->set($k, $ov->get($k));
            }
            foreach (self::g($tvs, 'dims') as $d) {
                if (!$values->has((string)self::g($d, 'path'))) {
                    $values->set((string)self::g($d, 'path'), WalletOmega::repValue($d, 0));
                }
            }
            $ownCell = WalletOmega::cellOf($svs, Obj::of(['verb' => self::g($ob, 'verb'), 'values' => $ov]));
            if ($ownCell === null) {
                throw new \InvalidArgumentException('liftIntentMap: an observation of ' . Js::str(self::g($ob, 'verb')) . " lies outside the map's own \u{03A9}");
            }
            $region = self::g($ob, 'region');
            if ($region === null) {
                $region = IntentRegion::regionOfCell($svs, $ownCell);
            }
            $l->observe(Obj::of(['verb' => self::g($ob, 'verb'), 'values' => $values]), (int)self::f(self::g($ob, 'y')), (string)self::g($ob, 'source'), $region);
        }
        return IntentMapKit::emitIntentMap($l, self::g($m, 'intent_ref'));
    }

    /**
     * Replay-verify every map, lift all of them onto the common refinement of their omegas, then aggregate.
     * @return array{aggregate:Obj,lifted:list<Obj>,omega:Obj}
     */
    public static function crossOrgAggregate(array $maps, mixed $rule, mixed $opts = null): array
    {
        foreach ($maps as $i => $m) {
            $r = IntentMapKit::verifyIntentMap($m);
            if (!$r['ok']) {
                throw new \InvalidArgumentException("crossOrgAggregate: map $i does not verify: " . implode('; ', $r['problems']));
            }
        }
        $omega = IntentMulti::commonRefinement(array_map(static fn($m) => IntentMapKit::omegaFromJSON(self::g($m, 'omega')), $maps));
        $lifted = array_map(static fn($m) => self::liftIntentMap($m, $omega), $maps);
        return ['aggregate' => self::aggregateIntentMaps($lifted, $rule, $opts), 'lifted' => $lifted, 'omega' => $omega];
    }

    /** Verify a cross-org aggregate by recomputing it from the ORIGINAL maps. @return array{ok:bool,problems:list<string>} */
    public static function verifyCrossOrgAggregate(mixed $agg, array $maps, mixed $opts = null): array
    {
        try {
            $again = self::crossOrgAggregate($maps, self::ruleOf($agg), $opts)['aggregate'];
            if (IntentMapKit::intentMapDigest($again) === IntentMapKit::intentMapDigest($agg)) {
                return ['ok' => true, 'problems' => []];
            }
            return ['ok' => false, 'problems' => ['aggregate does not match its recomputation']];
        } catch (\Throwable $e) {
            return ['ok' => false, 'problems' => [$e->getMessage()]];
        }
    }

    /** The omega of an aggregated or single map as JSON (a comparison key). */
    public static function omegaKey(mixed $o): string
    {
        return Js::stringify(IntentMapKit::omegaToJSON($o));
    }
}
