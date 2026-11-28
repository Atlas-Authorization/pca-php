<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/DetMath.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/IntentLearner.php';
require_once __DIR__ . '/Pca.php';

/**
 * The Intent Map: a content-addressed, replayable artifact holding the outcome space, the learner parameters, every answer, the learned
 * cells, the conservative grant and the quantified fidelity (all probabilities and metrics are integer ppm so the digest is
 * language-portable). Maps are Obj trees (numbers as PHP ints / floats until hashed); omegas and learner options are Obj or assoc arrays
 * with the reference's field names. IntentV2Map holds the committed-map verifier.
 */
final class IntentMapKit
{
    public const INTENT_MAP_DOMAIN = 'atlas-pca/intent-map/v1';
    public const PPM = 1000000;

    private static function g(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    private static function dflt(mixed $o, string $k, mixed $d): mixed
    {
        $v = Js::opt($o, $k);
        return $v === null ? $d : $v;
    }

    private static function f(mixed $x): float
    {
        return Js::num($x) ?? NAN;
    }

    /** JS Math.round: the nearest integer, ties toward +infinity. */
    public static function jsRound(float $x): int
    {
        $f = floor($x);
        return (int)($x - $f >= 0.5 ? $f + 1 : $f);
    }

    public static function ppm(float $x): int
    {
        return self::jsRound($x * self::PPM);
    }

    private static function qz(mixed $x): float
    {
        return self::jsRound(self::f($x) * self::PPM) / 1000000.0;
    }

    /** Assoc arrays become Obj (recursively), lists stay lists. */
    public static function obj(mixed $v): mixed
    {
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::obj(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string)$k, self::obj($x));
            }
            return $o;
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::obj($v->get($k)));
            }
            return $o;
        }
        return $v;
    }

    /** The canonical-hash model of a value: objects as Obj, every number a Num (JS number form). */
    private static function model(mixed $v): mixed
    {
        $v = self::obj($v);
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::model($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::model(...), $v);
        }
        if (is_int($v)) {
            return new Num((string)$v);
        }
        if (is_float($v)) {
            if (!is_finite($v)) {
                throw new \InvalidArgumentException('non-finite number');
            }
            return new Num($v == 0.0 ? '0' : IntentWb::jsStr($v));
        }
        return $v;
    }

    private static function list(mixed $x): array
    {
        if (!is_array($x) || !array_is_list($x)) {
            throw new \TypeError('expected an array');
        }
        return $x;
    }

    // ---- omega <-> JSON ------------------------------------------------------------------------------------------------------

    public static function omegaToJSON(mixed $o): Obj
    {
        $verbs0 = self::list(self::g($o, 'verbs'));
        $ws = array_map(static fn($v) => self::f(self::g($v, 'weight')), $verbs0);
        $equal = true;
        foreach ($ws as $w) {
            if (!(abs($w - $ws[0]) < 1e-15)) {
                $equal = false;
                break;
            }
        }
        $verbs = [];
        foreach ($verbs0 as $v) {
            $dims = [];
            foreach (self::g($v, 'dims') as $d) {
                if (self::g($d, 'kind') === 'num') {
                    $nd = ['kind' => 'num', 'path' => self::g($d, 'path'), 'lo' => self::g($d, 'lo'), 'hi' => self::g($d, 'hi'), 'cuts' => array_values(self::g($d, 'cuts'))];
                    if (Js::has($d, 'dist')) {
                        $nd['dist'] = self::g($d, 'dist');
                    }
                    $dims[] = $nd;
                } else {
                    $dims[] = ['kind' => 'cat', 'path' => self::g($d, 'path'), 'values' => array_values(self::g($d, 'values'))];
                }
            }
            $verbs[] = ['verb' => self::g($v, 'verb'), 'reversibility' => self::g($v, 'reversibility'),
                'w' => $equal ? 1 : max(1, self::jsRound(self::f(self::g($v, 'weight')) * self::PPM)), 'dims' => $dims];
        }
        return self::obj(['verbs' => $verbs, 'approximate' => array_values(self::g($o, 'approximate'))]);
    }

    public static function omegaFromJSON(mixed $j): Obj
    {
        $tot = 0.0;
        foreach (self::list(self::g($j, 'verbs')) as $v) {
            $tot += self::f(self::g($v, 'w'));
        }
        $verbs = [];
        foreach (self::g($j, 'verbs') as $v) {
            $dims = [];
            foreach (self::g($v, 'dims') as $d) {
                if (self::g($d, 'kind') === 'num') {
                    $dims[] = ['kind' => 'num', 'path' => self::g($d, 'path'), 'lo' => self::g($d, 'lo'), 'hi' => self::g($d, 'hi'),
                        'cuts' => array_values(self::dflt($d, 'cuts', [])), 'dist' => self::dflt($d, 'dist', 'uniform')];
                } else {
                    $vals = self::g($d, 'values');
                    if (!is_array($vals) || !array_is_list($vals) || $vals === []) { // a categorical dimension holds one of its values: with none it can hold nothing
                        throw new \InvalidArgumentException("omegaFromJSON: categorical dimension '" . Js::str(self::g($d, 'path')) . "' has no values");
                    }
                    $dims[] = ['kind' => 'cat', 'path' => self::g($d, 'path'), 'values' => $vals];
                }
            }
            $verbs[] = ['verb' => self::g($v, 'verb'), 'reversibility' => self::g($v, 'reversibility'), 'weight' => self::f(self::g($v, 'w')) / $tot, 'dims' => $dims];
        }
        return self::obj(['v' => 1, 'approximate' => array_values(self::g($j, 'approximate')), 'verbs' => $verbs]);
    }

    public static function grantDigest(mixed $g): string
    {
        $inner = new Obj();
        if (self::g($g, 'predicates') !== null) {
            $inner->set('predicates', self::g($g, 'predicates'));
        }
        $inner->set('caveats', Js::has($g, 'caveats') ? self::g($g, 'caveats') : []);
        return Pca::hashCanonical(self::model(['d' => 'atlas-pca/intent-grant/v1', 'g' => $inner]));
    }

    /** Content address of an Intent Map (the core definition, so the server and relying parties agree). */
    public static function intentMapDigest(mixed $m): string
    {
        return Pca::hashCanonical(self::model(['d' => self::INTENT_MAP_DOMAIN, 'm' => $m]));
    }

    private static function metricsOf(IntentLearner $l): array
    {
        $m = $l->metrics();
        $rmax = 0.0;
        foreach ($l->cells() as $c) {
            $rmax += $c['mass'] * (1 - $c['p']) * $c['harm'];
        }
        return [
            'residual_risk_ppm' => self::ppm($m['residualRisk']),
            'burden_ppm' => self::ppm($m['burden']),
            'uncertainty_ppm' => self::ppm($m['uncertainty']),
            'disagreement_ppm' => self::ppm($m['disagreementMass']),
            'mean_harm_ppm' => self::ppm($m['meanHarm']),
            'fidelity_est_ppm' => self::ppm($rmax > 0 ? 1 - $m['residualRisk'] / $rmax : 1.0),
            'entropy_mbits' => self::jsRound($m['entropyBits'] * 1000),
            'log2_vs_mbits' => $m['log2VersionSpace'] === null ? null : self::jsRound($m['log2VersionSpace'] * 1000),
            'questions' => $m['questions'],
            'conflicts' => $m['conflicts'],
        ];
    }

    private static function isSafeInteger(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991;
    }

    /** The learner's priorMix for a data-form population prior (ppm-quantised like every map number). */
    private static function priorMixOf(mixed $pm): array
    {
        $byVerb = [];
        foreach (self::g($pm, 'cells') as $c) {
            $q = self::qz(self::g($c, 'q'));
            $cell = self::g($c, 'cell');
            if (!($q >= 0 && $q <= 1) || !self::isSafeInteger($cell) || self::f($cell) < 0) {
                throw new \InvalidArgumentException('pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0');
            }
            $byVerb[(string)self::g($c, 'verb')][] = ['cell' => self::f($cell), 'lq' => DetMath::detLn($q), 'lnq' => DetMath::detLn(1 - $q)];
        }
        $weight = static function (mixed $vs, \Closure $contains) use ($byVerb): float {
            $lw = 0.0;
            foreach ($byVerb[(string)Js::opt($vs, 'verb')] ?? [] as $t) {
                $lw += $contains($t['cell']) ? $t['lq'] : $t['lnq'];
            }
            return DetMath::detExp($lw);
        };
        return ['beta' => self::qz(self::g($pm, 'beta')), 'weight' => $weight];
    }

    private static function anchorOpt(mixed $a): array
    {
        return ['policy' => ['predicates' => self::g(self::g($a, 'policy'), 'predicates'), 'caveats' => self::dflt(self::g($a, 'policy'), 'caveats', [])],
            'lambda' => self::jsRound(self::f(self::g($a, 'lambda')) * 1000) / 1000.0];
    }

    private static function anchorJson(mixed $a): array
    {
        return ['policy' => ['predicates' => self::g(self::g($a, 'policy'), 'predicates'), 'caveats' => self::dflt(self::g($a, 'policy'), 'caveats', [])],
            'lambda_milli' => self::jsRound(self::f(self::g($a, 'lambda')) * 1000)];
    }

    private static function quantizeClass(mixed $h): array
    {
        if (!Js::truthy($h) || self::g($h, 'kind') === 'box') {
            return ['kind' => 'box'];
        }
        $decay = self::qz(self::dflt($h, 'decay', 0.25));
        if (self::g($h, 'kind') === 'union') {
            return ['kind' => 'union', 'k' => self::g($h, 'k'), 'decay' => $decay];
        }
        return ['kind' => 'decision-list', 'maxRules' => self::g($h, 'maxRules'), 'decay' => $decay, 'conditions' => self::dflt($h, 'conditions', 'box')];
    }

    private static function nullMassOf(mixed $o, mixed $verb): float
    {
        $nm = self::g($o, 'nullMass');
        if (Js::isNum($nm)) {
            return self::f($nm);
        }
        $own = Js::isObj($nm) ? self::g($nm, (string)$verb) : null; // own entries only: a verb named like an Object member is an ordinary key
        if ($own !== null) {
            return self::f($own);
        }
        return self::f(self::dflt($o, 'defaultNullMass', 0.2));
    }

    /** Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised). */
    public static function createLearner(mixed $omega, mixed $o = null): IntentLearner
    {
        $eta0 = self::f(self::dflt($o, 'eta', 0));
        $opts = [
            'eta' => self::qz($eta0),
            'tau' => self::qz(self::dflt($o, 'tau', $eta0 == 0 ? 1 : 0.95)),
            'strategy' => self::dflt($o, 'strategy', 'disagreement'),
            'nullMass' => static fn($vs) => self::qz(self::nullMassOf($o, Js::opt($vs, 'verb'))),
            'hypothesisClass' => self::quantizeClass(self::g($o, 'hypothesisClass')),
        ];
        if (Js::has($o, 'agnosticSlack')) {
            $opts['agnosticSlack'] = self::g($o, 'agnosticSlack');
        }
        if (Js::truthy(self::g($o, 'anchor'))) {
            $opts['anchor'] = self::anchorOpt(self::g($o, 'anchor'));
        }
        $as = self::g($o, 'anchors');
        if (is_array($as) && count($as) > 0) {
            $opts['anchors'] = array_map(self::anchorOpt(...), $as);
        }
        $mono = self::g($o, 'monotone');
        if (Js::truthy($mono)) {
            $opts['monotone'] = ['paths' => array_values(self::g($mono, 'paths')), 'offMass' => self::qz(self::dflt($mono, 'offMass', 0))];
        }
        if (Js::has($o, 'etaPos')) {
            $opts['etaPos'] = self::qz(self::g($o, 'etaPos'));
        }
        if (Js::has($o, 'etaNeg')) {
            $opts['etaNeg'] = self::qz(self::g($o, 'etaNeg'));
        }
        if (Js::truthy(self::g($o, 'priorMix'))) {
            $opts['priorMix'] = self::priorMixOf(self::g($o, 'priorMix'));
        }
        $l = new IntentLearner($omega, $opts);
        $l->mapParams = $o ?? new Obj();
        return $l;
    }

    /** The serialisable parameters a learner was built with (createLearner only). */
    public static function learnerOptionsOf(IntentLearner $l): mixed
    {
        if ($l->mapParams === null) {
            throw new \InvalidArgumentException('pca-intent: build the learner with createLearner() so its parameters are serialisable');
        }
        return $l->mapParams;
    }

    public static function emitIntentMap(IntentLearner $l, ?string $intentRef = null): Obj
    {
        $o = self::learnerOptionsOf($l);
        $nullMass = new Obj();
        foreach (self::g($l->omega, 'verbs') as $vs) {
            $nullMass->set((string)self::g($vs, 'verb'), self::ppm(self::nullMassOf($o, self::g($vs, 'verb'))));
        }
        $grant = $l->synthesize();
        $hc = $l->hypothesisClass;
        $kind = self::g($hc, 'kind');
        $learner = ['hypothesis_class' => IntentLearner::hypothesisClassName($hc)];
        if ($kind === 'union') {
            $learner['class_params'] = ['k' => self::g($hc, 'k'), 'decay_ppm' => self::ppm(self::f(self::dflt($hc, 'decay', 0.25)))];
        }
        if ($kind === 'decision-list') {
            $learner['class_params'] = ['max_rules' => self::g($hc, 'maxRules'), 'decay_ppm' => self::ppm(self::f(self::dflt($hc, 'decay', 0.25)))];
        }
        if ($l->agnosticSlack !== null) {
            $learner['agnostic_slack'] = $l->agnosticSlack;
        }
        $learner['eta_ppm'] = self::ppm($l->eta);
        $learner['tau_ppm'] = self::ppm($l->tau);
        $learner['strategy'] = $l->strategy;
        $learner['null_mass_ppm'] = $nullMass;
        if (Js::truthy(self::g($o, 'anchor'))) {
            $learner['anchor'] = self::anchorJson(self::g($o, 'anchor'));
        }
        $as = self::g($o, 'anchors');
        if (is_array($as) && count($as) > 0) {
            $learner['anchors'] = array_map(self::anchorJson(...), $as);
        }
        $mono = self::g($o, 'monotone');
        if (Js::truthy($mono)) {
            $learner['monotone'] = ['paths' => array_values(self::g($mono, 'paths')), 'off_ppm' => self::ppm(self::f(self::dflt($mono, 'offMass', 0)))];
        }
        if (Js::has($o, 'etaPos') || Js::has($o, 'etaNeg')) {
            $learner['noise'] = ['eta_pos_ppm' => self::ppm($l->etaPos), 'eta_neg_ppm' => self::ppm($l->etaNeg)];
        }
        $pm = self::g($o, 'priorMix');
        if (Js::truthy($pm)) {
            $learner['prior_mix'] = ['beta_ppm' => self::ppm(self::f(self::g($pm, 'beta'))),
                'cells' => array_map(static fn($c) => ['verb' => self::g($c, 'verb'), 'cell' => self::g($c, 'cell'), 'q_ppm' => self::ppm(self::f(self::g($c, 'q')))], self::g($pm, 'cells'))];
        }
        $observations = [];
        foreach ($l->observations as $x) {
            $ob = ['verb' => $x['verb'], 'values' => $x['values'], 'y' => $x['y'], 'source' => $x['source']];
            if (($x['region'] ?? null) !== null) {
                $ob['region'] = $x['region'];
            }
            $observations[] = $ob;
        }
        return self::obj([
            'v' => 1,
            'kind' => 'pca-intent-map',
            'intent_ref' => $intentRef,
            'principals' => $intentRef !== null && $intentRef !== '' ? [$intentRef] : [],
            'omega' => self::omegaToJSON($l->omega),
            'learner' => $learner,
            'observations' => $observations,
            'cells' => array_map(static fn($c) => ['verb' => $c['verb'], 'cell' => $c['cell'], 'p_ppm' => self::ppm($c['p']), 'in_grant' => $c['inGrant']], $l->cells()),
            'grant' => $grant,
            'grant_digest' => self::grantDigest(self::obj($grant)),
            'metrics' => self::metricsOf($l),
        ]);
    }

    /** The learner parameters a map records (inverse of what emitIntentMap writes). */
    public static function mapLearnerOptions(mixed $m): array
    {
        $lr = self::g($m, 'learner');
        $nullMass = new Obj();
        $nmp = self::g($lr, 'null_mass_ppm');
        foreach ($nmp->keys() as $k) {
            $nullMass->set($k, self::f($nmp->get($k)) / 1e6);
        }
        $cp = self::g($lr, 'class_params');
        $hcn = self::g($lr, 'hypothesis_class');
        if ($hcn === 'per-verb-union/v1') {
            $hc = ['kind' => 'union', 'k' => self::dflt($cp, 'k', 2), 'decay' => self::f(self::dflt($cp, 'decay_ppm', 250000)) / 1e6];
        } elseif ($hcn === 'per-verb-decision-list/v1' || $hcn === 'per-verb-decision-list/v2') {
            $hc = ['kind' => 'decision-list', 'maxRules' => self::dflt($cp, 'max_rules', 2), 'decay' => self::f(self::dflt($cp, 'decay_ppm', 250000)) / 1e6,
                'conditions' => $hcn === 'per-verb-decision-list/v1' ? 'atomic' : 'box'];
        } else {
            $hc = ['kind' => 'box'];
        }
        $out = ['eta' => self::f(self::g($lr, 'eta_ppm')) / 1e6, 'tau' => self::f(self::g($lr, 'tau_ppm')) / 1e6, 'strategy' => self::g($lr, 'strategy'),
            'nullMass' => $nullMass, 'hypothesisClass' => $hc];
        if (self::g($lr, 'agnostic_slack') !== null) {
            $out['agnosticSlack'] = self::g($lr, 'agnostic_slack');
        }
        if (Js::truthy(self::g($lr, 'anchor'))) {
            $out['anchor'] = ['policy' => self::g(self::g($lr, 'anchor'), 'policy'), 'lambda' => self::f(self::g(self::g($lr, 'anchor'), 'lambda_milli')) / 1000];
        }
        $as = self::g($lr, 'anchors');
        if (is_array($as) && count($as) > 0) {
            $out['anchors'] = array_map(static fn($a) => ['policy' => self::g($a, 'policy'), 'lambda' => self::f(self::g($a, 'lambda_milli')) / 1000], $as);
        }
        $mono = self::g($lr, 'monotone');
        if (Js::truthy($mono)) {
            $out['monotone'] = ['paths' => array_values(self::g($mono, 'paths')), 'offMass' => self::f(self::g($mono, 'off_ppm')) / 1e6];
        }
        $noise = self::g($lr, 'noise');
        if (Js::truthy($noise)) {
            $out['etaPos'] = self::f(self::g($noise, 'eta_pos_ppm')) / 1e6;
            $out['etaNeg'] = self::f(self::g($noise, 'eta_neg_ppm')) / 1e6;
        }
        $pm = self::g($lr, 'prior_mix');
        if (Js::truthy($pm)) {
            $out['priorMix'] = ['beta' => self::f(self::g($pm, 'beta_ppm')) / 1e6,
                'cells' => array_map(static fn($c) => ['verb' => self::g($c, 'verb'), 'cell' => self::g($c, 'cell'), 'q' => self::f(self::g($c, 'q_ppm')) / 1e6], self::g($pm, 'cells'))];
        }
        return $out;
    }

    /** Rebuild the learner a map describes (omega + prior + observations). */
    public static function learnerFromMap(mixed $m): IntentLearner
    {
        // a parsed map carries Num leaves: the learner computes with plain PHP numbers
        $l = self::createLearner(WalletOmega::plain(self::omegaFromJSON(self::g($m, 'omega'))), self::mapLearnerOptions($m));
        foreach (self::g($m, 'observations') as $o) {
            $l->observe(['verb' => self::g($o, 'verb'), 'values' => WalletOmega::plain(self::g($o, 'values'))], (int)self::f(self::g($o, 'y')), (string)self::g($o, 'source'), self::g($o, 'region'));
        }
        return $l;
    }

    private static function isOne(mixed $v): bool
    {
        return Js::isNum($v) && self::f($v) === 1.0;
    }

    /** `Math.abs(a - b) <= 2` for two numbers; anything else (a missing, non-numeric or NaN claim) is not close: a mismatch must fail closed. */
    private static function within2(mixed $a, mixed $b): bool
    {
        return Js::isNum($a) && Js::isNum($b) && abs(self::f($a) - self::f($b)) <= 2;
    }

    /**
     * Replay a single-principal map and check every number, every cell and the grant.
     * @return array{ok:bool,problems:list<string>}
     */
    public static function verifyIntentMap(mixed $m): array
    {
        $problems = [];
        try {
            if (!(Js::isObj($m) && self::isOne(self::g($m, 'v')) && self::g($m, 'kind') === 'pca-intent-map')) {
                return ['ok' => false, 'problems' => ['not an intent map v1']];
            }
            if (count(self::list(self::g($m, 'principals'))) > 1 || self::g($m, 'aggregation') !== null) {
                return ['ok' => false, 'problems' => ['combined map: verify each principal map and recombine with verifyAggregate']];
            }
            if (!Js::has($m, 'intent_ref')) {
                throw new \OutOfBoundsException("'intent_ref'");
            }
            $r = self::emitIntentMap(self::learnerFromMap($m), self::g($m, 'intent_ref'));
            if ($r->get('grant_digest') !== self::g($m, 'grant_digest') || self::grantDigest(self::g($m, 'grant')) !== self::g($m, 'grant_digest')) {
                $problems[] = 'grant does not match the replayed posterior';
            }
            $rc = $r->get('cells');
            $mc = self::list(self::g($m, 'cells'));
            if (count($rc) !== count($mc)) {
                $problems[] = 'cell count differs';
            } else {
                foreach ($rc as $i => $c) {
                    $x = $mc[$i];
                    if (self::g($c, 'verb') !== self::g($x, 'verb') || self::g($c, 'in_grant') !== self::g($x, 'in_grant') || !self::within2(self::g($c, 'p_ppm'), self::g($x, 'p_ppm'))) {
                        $problems[] = "cell $i differs";
                    }
                }
            }
            $mm = self::g($m, 'metrics');
            $rm = $r->get('metrics');
            foreach ($rm->keys() as $k) {
                $a = $rm->get($k);
                $has = Js::isObj($mm) && Js::has($mm, $k);
                $b = $has ? self::g($mm, $k) : null;
                if ($a === null || ($has && $b === null)) {
                    $bad = !($a === null && $has && $b === null); // reference: a is not b (an absent claim is not null)
                } else {
                    $bad = !self::within2($a, $b);
                }
                if ($bad) {
                    $problems[] = "metric $k differs (" . ($has ? Js::str($b) : 'undefined') . ' claimed, ' . Js::str($a) . ' replayed)';
                }
            }
        } catch (\Throwable $e) {
            $problems[] = 'replay failed: ' . $e->getMessage();
        }
        return ['ok' => count($problems) === 0, 'problems' => $problems];
    }

    /**
     * A runtime divergence is one more labelled observation; a NEGATIVE one also vetoes the outcome's cell for good.
     * @return array{before:int,after:int,grant:array}
     */
    public static function applyDivergence(IntentLearner $l, mixed $outcome, int $y): array
    {
        $count = static function () use ($l): int {
            $n = 0;
            foreach ($l->cells() as $c) {
                if ($c['inGrant']) {
                    $n++;
                }
            }
            return $n;
        };
        $before = $count();
        $l->observe($outcome, $y, 'runtime');
        return ['before' => $before, 'after' => $count(), 'grant' => $l->synthesize()];
    }
}
