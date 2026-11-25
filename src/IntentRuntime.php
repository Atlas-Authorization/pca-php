<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentPolicy.php';
require_once __DIR__ . '/IntentV2.php';

/**
 * Runtime intent conformance: routing an admitted action by the map's posterior and the verb's reversibility, the judge panel input,
 * the intent-conformance attestation (IC-Att) and just-in-time consent. A "learner" is an IntentLearner (public `omega`, acceptance(),
 * admitsOutcome(), isVetoed(); an optional public `harm` HarmModel); the signed-verdict threshold check is injected (the core has no
 * semantic-threshold verifier). Rendering goes through IntentRender::renderAction; recordJitDecision through IntentMapKit.
 */
final class IntentRuntime
{
    public const IC_ATT_DOMAIN = 'atlas-pca/intent-ic-att/v1';
    private const MICROS = 1000000;
    private const MAX_SAFE_MICROS = 1e15;

    public static function defaultBondPolicy(): Obj
    {
        return Obj::of(['floor' => 1, 'k' => 1, 'maxOpenClaims' => 100, 'maxOpenAmount' => INF]);
    }

    private static function f(mixed $x): float
    {
        return Js::num($x) ?? NAN;
    }

    private static function quantizeUp(float $x): float
    {
        if (!is_finite($x) || $x <= 0) {
            return $x;
        }
        $scaled = $x * self::MICROS;
        if ($scaled > self::MAX_SAFE_MICROS) {
            return $x;
        }
        $r = floor($scaled + 0.5);
        $m = ($r / self::MICROS == $x || abs($scaled - $r) <= 1e-3) ? $r : ceil($scaled);
        return $m / self::MICROS;
    }

    private static function curveComponent(mixed $curve, float $k, float $e): float
    {
        $kind = $curve instanceof Obj || is_array($curve) ? Js::opt($curve, 'kind') : null;
        if (!Js::truthy($curve) || $kind === 'linear') {
            return $k * $e;
        }
        if ($kind === 'power') {
            $g = Js::num(Js::opt($curve, 'gamma'));
            if ($g === null || !is_finite($g) || !($g >= 1)) {
                throw new \InvalidArgumentException('bondAmount: power curve requires finite gamma >= 1');
            }
            return $k * BondSettlement::powEighths($e, $g);
        }
        $tiers = Js::opt($curve, 'tiers');
        if (!is_array($tiers) || !array_is_list($tiers) || count($tiers) === 0) {
            throw new \InvalidArgumentException('bondAmount: piecewise curve requires at least one tier');
        }
        $acc = 0.0;
        $prevUp = 0.0;
        $prevMarginal = 0.0;
        foreach ($tiers as $t) {
            $up = self::f(Js::opt($t, 'upTo'));
            $mk = self::f(Js::opt($t, 'marginalK'));
            if (!(is_finite($up) && $up > $prevUp) && $up !== INF) {
                throw new \InvalidArgumentException('bondAmount: piecewise tier `upTo` must be strictly increasing');
            }
            if (!(is_finite($mk) && $mk >= 0)) {
                throw new \InvalidArgumentException('bondAmount: piecewise `marginalK` must be a finite number >= 0');
            }
            if ($mk < $prevMarginal) {
                throw new \InvalidArgumentException('bondAmount: piecewise marginal rates must be non-decreasing (convex)');
            }
            $width = min($e, $up) - $prevUp;
            if ($width > 0) {
                $acc += $width * $mk;
            }
            $prevUp = $up;
            $prevMarginal = $mk;
            if ($e <= $up) {
                break;
            }
        }
        if ($e > $prevUp) {
            $acc += ($e - $prevUp) * $prevMarginal;
        }
        return $k * $acc;
    }

    /** max(floor, curve(k, exposure)) snapped up onto the micro grid; a non-finite or non-positive exposure gives the floor. */
    public static function bondAmount(mixed $policy, mixed $exposure): float
    {
        $x = self::f($exposure);
        $e = is_finite($x) && $x > 0 ? $x : 0.0;
        return self::quantizeUp((float)IntentOmega::jsMax(self::f(Js::opt($policy, 'floor')),
            self::curveComponent(Js::opt($policy, 'curve'), self::f(Js::opt($policy, 'k')), $e)));
    }

    private static function vsOf(object $l, mixed $verb): mixed
    {
        foreach (Js::opt($l->omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === $verb) {
                return $v;
            }
        }
        return null;
    }

    /**
     * deny / allow / optimistic / jit-consent for an action the grant already admits.
     * @return array<string,mixed>
     */
    public static function routeAction(object $l, mixed $o, mixed $opts = null): array
    {
        $vs = self::vsOf($l, Js::opt($o, 'verb'));
        if ($vs === null || IntentOmega::cellOf($vs, $o) === null) {
            return ['route' => 'deny', 'p' => 0, 'inGrant' => false, 'vetoed' => false, 'reversibility' => $vs !== null ? Js::opt($vs, 'reversibility') : 'unknown',
                'harm' => 0, 'risk' => 1, 'judges' => false, 'reason' => "outside the Intent Map's outcome space"];
        }
        $harmModel = property_exists($l, 'harm') && $l->harm instanceof HarmModel ? $l->harm : null;
        $p = $l->acceptance($o);
        $inGrant = $l->admitsOutcome($o);
        $vetoed = $l->isVetoed($o);
        $harm = IntentOmega::harmOf($vs, $o, $harmModel);
        $hMax = Js::opt($opts, 'hMax');
        $hMax = $hMax === null ? IntentOmega::harmMax($l->omega, $harmModel) : self::f($hMax);
        $risk = min(1, max(0, ((1 - $p) * $harm) / ($hMax > 0 ? $hMax : 1)));
        $theta2 = Js::opt($opts, 'theta2');
        $theta2 = $theta2 === null ? 0.5 : self::f($theta2);
        $rev = Js::opt($vs, 'reversibility');
        $base = ['p' => $p, 'inGrant' => $inGrant, 'vetoed' => $vetoed, 'reversibility' => $rev, 'harm' => $harm, 'risk' => $risk];
        if (!$inGrant) {
            return $base + ['route' => 'deny', 'judges' => false,
                'reason' => $vetoed ? 'the cell was vetoed by a runtime divergence' : "outside the conservative grant (p_n < \u{03C4})"];
        }
        $judges = $rev === 'irreversible' || $p < 1 - 1e-12 || !($risk < $theta2); // a missing or NaN threshold never waves a risky action through unjudged
        if ($rev === 'irreversible') {
            return $base + ['route' => 'jit-consent', 'judges' => $judges, 'reason' => 'irreversible: just-in-time consent on the rendered action'];
        }
        if ($judges) {
            return $base + ['route' => 'optimistic', 'judges' => $judges, 'bond' => self::bondAmount(Js::opt($opts, 'bondPolicy') ?? self::defaultBondPolicy(), $harm),
                'reason' => $p < 1 - 1e-12 ? 'unconfirmed region (p_n < 1): bonded claim + judges' : "risk \u{2265} \u{03B8}\u{2082}: bonded claim + judges"];
        }
        return $base + ['route' => 'allow', 'judges' => false, 'reason' => 'confirmed region, reversible, low risk'];
    }

    // ---- L3: the judge panel input and the IC-Att -------------------------------------------------------------------

    public static function pcactnActionOf(mixed $vs, mixed $o): Obj
    {
        $a = IntentPolicy::outcomeToAction($vs, $o);
        $params = $a->get('params');
        return Obj::of(['verb' => $a->get('verb'), 'resource' => $a->get('resource'),
            'params_digest' => IntentV2::hashCanonical(Js::truthy($params) || $params instanceof Obj ? $params : new Obj()), 'reversibility_class' => Js::opt($vs, 'reversibility')]);
    }

    public static function actionDigest(mixed $action): string
    {
        return IntentV2::hashCanonical($action);
    }

    private static function copy(mixed $o): Obj
    {
        $c = new Obj();
        if ($o instanceof Obj) {
            foreach ($o->keys() as $k) {
                $c->set($k, $o->get($k));
            }
        }
        return $c;
    }

    /** The judge panel input for one outcome: the caller's context plus the rendered action, p, reversibility and the action digest. */
    public static function judgeInputOf(mixed $vs, mixed $o, mixed $p, mixed $ctx): Obj
    {
        require_once __DIR__ . '/IntentRender.php';
        $r = self::copy($ctx);
        $r->set('renderedAction', IntentRender::renderAction($vs, Js::opt($o, 'values')));
        $r->set('p', $p);
        $r->set('reversibility', Js::opt($vs, 'reversibility'));
        $r->set('actionDigest', self::actionDigest(self::pcactnActionOf($vs, $o)));
        return $r;
    }

    public static function calibrationDigest(mixed $c): string
    {
        $samples = [];
        foreach (Js::opt($c, 'samples') as $s) {
            $samples[] = Obj::of(['score' => Js::opt($s, 'score'), 'faithful' => Js::opt($s, 'faithful')]);
        }
        return IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/intent-calibration/v1', 'alpha' => Js::opt($c, 'alpha'), 'samples' => $samples]));
    }

    private static function toPpm(mixed $x): ?int
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) ? (int)floor($f * 1000000 + 0.5) : null;
    }

    /**
     * Ask the panel and attest (the hook form): `$panel` is a callable `fn($input): array` or an object with `verdicts($input)`; the verifier is the one
     * of {@see intentConformanceAttestation}. Returns {att, verdicts}.
     *
     * @param \Closure(mixed,Obj):mixed $verify
     * @param (\Closure(mixed):string)|null $verdictDigest
     */
    public static function checkIntentConformance(mixed $panel, mixed $input, mixed $opts, \Closure $verify, ?\Closure $verdictDigest = null): Obj
    {
        $verdicts = is_callable($panel) ? $panel($input) : $panel->verdicts($input);
        return Obj::of(['att' => self::intentConformanceAttestation($input, $verdicts, $opts, $verify, $verdictDigest), 'verdicts' => $verdicts]);
    }

    /**
     * Verify a panel's verdicts for one action with the injected threshold verifier and produce the IC-Att. The verifier takes
     * (verdicts, {judgeKeys, k, goalCommitment, actionDigest, calibration?, attestation?}) and returns {ok, agreeCount, aggregateScore,
     * cutoff?, reason?}.
     * @param \Closure(mixed,Obj):mixed $verify
     * @param (\Closure(mixed):string)|null $verdictDigest
     */
    public static function intentConformanceAttestation(mixed $input, array $verdicts, mixed $opts, \Closure $verify, ?\Closure $verdictDigest = null): Obj
    {
        $verdictDigest ??= static fn($v): string => IntentV2::hashCanonical($v);
        $vo = Obj::of(['judgeKeys' => Js::opt($opts, 'judgeKeys'), 'k' => Js::opt($opts, 'k'), 'goalCommitment' => Js::opt($input, 'goalCommitment'),
            'actionDigest' => Js::opt($input, 'actionDigest')]);
        if (Js::truthy(Js::opt($opts, 'calibration'))) {
            $vo->set('calibration', Js::opt($opts, 'calibration'));
        }
        if (Js::truthy(Js::opt($opts, 'attestation'))) {
            $vo->set('attestation', Js::opt($opts, 'attestation'));
        }
        $r = $verify($verdicts, $vo);
        $digests = array_map($verdictDigest, $verdicts);
        sort($digests, SORT_STRING);
        $cutoff = Js::opt($r, 'cutoff');
        $att = Obj::of(['v' => 1, 'kind' => 'pca-ic-att', 'intent_ref' => Js::opt($input, 'intentRef'), 'map_digest' => Js::opt($input, 'mapDigest'),
            'action_digest' => Js::opt($input, 'actionDigest'), 'goal_commitment' => Js::opt($input, 'goalCommitment'), 'verdict_digests' => $digests,
            'calibration_digest' => Js::truthy(Js::opt($opts, 'calibration')) ? self::calibrationDigest(Js::opt($opts, 'calibration')) : null,
            'k' => Js::opt($opts, 'k'), 'ok' => Js::opt($r, 'ok'), 'agree_count' => Js::opt($r, 'agreeCount'),
            'aggregate_score_ppm' => self::toPpm(Js::opt($r, 'aggregateScore')) ?? 0,
            'cutoff_ppm' => $cutoff === null ? null : self::toPpm($cutoff)]);
        if (Js::truthy(Js::opt($r, 'reason'))) {
            $att->set('reason', Js::opt($r, 'reason'));
        }
        return $att;
    }

    public static function icAttDigest(mixed $a): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::IC_ATT_DOMAIN, 'a' => $a]));
    }

    /** Re-verify an IC-Att from the verdicts it names (a relying party never trusts the ok bit). @return array{ok:bool,problems:list<string>} */
    public static function verifyIcAtt(mixed $att, mixed $input, array $verdicts, mixed $opts, \Closure $verify): array
    {
        $again = self::intentConformanceAttestation($input, $verdicts, $opts, $verify);
        $problems = [];
        if (self::icAttDigest($again) !== self::icAttDigest($att)) {
            $problems[] = 'IC-Att does not match the recomputation from its verdicts';
        }
        if ($again->get('ok') !== true && !Js::truthy($again->get('ok'))) {
            $problems[] = 'panel does not pass: ' . ($again->get('reason') ?: 'unknown');
        }
        return ['ok' => count($problems) === 0, 'problems' => $problems];
    }

    public static function semanticRiskContribution(mixed $score): int|float
    {
        $f = Js::num($score);
        if ($f === null || !is_finite($f)) {
            return 1;
        }
        $r = 1 - $f;
        return $r < 0 ? 0 : ($r > 1 ? 1 : $r);
    }

    /** The monotone risk fold: r := max(r, 1 - aggregateScore). Never lowers r. */
    public static function foldSemanticRisk(mixed $r, mixed $att): int|float
    {
        $ppm = Js::opt($att, 'aggregate_score_ppm');
        $score = Js::isNum($ppm) ? Js::num($ppm) / 1000000 : NAN;
        return IntentOmega::jsMax(self::f($r), self::semanticRiskContribution($score));
    }

    // ---- L4: just-in-time consent ------------------------------------------------------------------------------------

    public static function jitConsentRequest(mixed $vs, mixed $o, mixed $p, mixed $intentRef, mixed $mapDigest): Obj
    {
        require_once __DIR__ . '/IntentRender.php';
        return Obj::of(['v' => 1, 'kind' => 'pca-intent-jit', 'intent_ref' => $intentRef, 'map_digest' => $mapDigest, 'verb' => Js::opt($o, 'verb'),
            'values' => self::copy(Js::opt($o, 'values')), 'reversibility' => Js::opt($vs, 'reversibility'),
            'p_ppm' => (int)floor(self::f($p) * 1000000 + 0.5),
            'text' => IntentRender::renderAction($vs, Js::opt($o, 'values')) . ' This cannot be undone. Approve?']);
    }

    public static function jitConsentDigest(mixed $r): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/intent-jit/v1', 'r' => $r]));
    }

    /**
     * Record the principal's JIT decision as a runtime observation: approve -> y = 1 (widens the grant only through the posterior),
     * deny -> y = 0 and the cell is vetoed. Calls IntentMapKit::applyDivergence.
     */
    public static function recordJitDecision(object $l, mixed $req, string $decision): mixed
    {
        require_once __DIR__ . '/IntentMapKit.php';
        return IntentMapKit::applyDivergence($l, Obj::of(['verb' => Js::opt($req, 'verb'), 'values' => Js::opt($req, 'values')]), $decision === 'approve' ? 1 : 0);
    }
}
