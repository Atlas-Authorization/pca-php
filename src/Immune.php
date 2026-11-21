<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';

/**
 * The behavioral immune system: the per-principal risk baseline, the observation fold ({@see observe}), the state validation and the
 * threat read ({@see assess}), the adaptation of a base risk policy that never widens it ({@see adapt}), guardian-signed tightening
 * proposals and a durable store over an {@see AtomicKv}. A heuristic (EWMA and z-score over one principal's history): it can be gamed by
 * a slow attacker who drifts the baseline and is no proof that an agent is compromised or benign.
 *
 * An immune state is `{baseline: {n, mean, m2}, ewma, stepUps, denies, lastAt, seeded}`; an observation is `{r, at, stepUp?, denied?}`.
 * Values are the parsed-JSON model (Obj, list arrays, string, Num / int / float, bool, null); the reference's number coercions are
 * reproduced (null is 0, an absent member is NaN).
 */
final class Immune
{
    public const TIGHTENING_DOMAIN = "atlas-pca/immune-tightening/v1\0";
    private const MAX_COUNT = 1e9;
    private const ALPHA = 0.3;
    private const HALF_LIFE_MS = 3600000.0;
    private const DRIFT_Z_SAT = 3.0;
    private const STEP_UP_SAT = 5.0;
    private const DENY_SAT = 3.0;

    // ---- number helpers ----------------------------------------------------------------------------------------------------

    /** `Number.isFinite(x)`: a number (no coercion) that is finite. */
    private static function fin(mixed $x): bool
    {
        return Js::isNum($x) && is_finite((float)Js::num($x));
    }

    /** `Math.max(0, Math.min(1, x))`: NaN stays NaN. */
    private static function clamp01(float $x): float
    {
        return is_nan($x) ? $x : max(0.0, min(1.0, $x));
    }

    /** The value of a number already known to be one. */
    private static function f(mixed $x): float
    {
        return (float)Js::num($x);
    }

    /** `Number.isSafeInteger(x)` (a number, integral, magnitude below 2^53). */
    private static function safeInt(mixed $x): bool
    {
        if (!self::fin($x)) {
            return false;
        }
        $v = self::f($x);
        return $v == floor($v) && abs($v) <= 9007199254740991.0;
    }

    private static function negZero(mixed $x): bool
    {
        $v = self::f($x);
        return $v == 0.0 && fdiv(1.0, $v) < 0;
    }

    /** `a <= b` over JSON values: two strings compare as strings, anything else as numbers (NaN is false). */
    private static function le(mixed $a, mixed $b): bool
    {
        if (is_string($a) && is_string($b)) {
            return !Jsx::lt($b, $a);
        }
        return Jsx::toNum($a) <= Jsx::toNum($b);
    }

    /** `a !== b` negated (`a === b`): numbers by value (NaN equals nothing), objects by instance, an absent member only an absent one. */
    private static function same(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) || Js::isNum($b)) {
            return Js::isNum($a) && Js::isNum($b) && self::f($a) == self::f($b);
        }
        if (is_array($a) || is_array($b)) {
            return false; // shortcut: PHP arrays have no identity, a list is never the same value (fail closed), only reachable with a list member
        }
        return $a === $b;
    }

    // ---- baseline (Welford running mean / variance) ------------------------------------------------------------------------

    /** The empty baseline {n: 0, mean: 0, m2: 0}. */
    public static function emptyBaseline(): Obj
    {
        return Obj::of(['n' => 0, 'mean' => 0, 'm2' => 0]);
    }

    /** The state of a principal with no history. */
    public static function initialState(): Obj
    {
        return Obj::of(['baseline' => self::emptyBaseline(), 'ewma' => 0, 'stepUps' => 0, 'denies' => 0, 'lastAt' => 0, 'seeded' => false]);
    }

    /** Welford update of a baseline with one risk sample (a non-finite sample counts as 0). */
    public static function updateBaseline(mixed $b, mixed $r): Obj
    {
        $x = self::fin($r) ? self::f($r) : 0.0;
        $n = Jsx::toNum(Jsx::rd($b, 'n')) + 1;
        $mean0 = Jsx::toNum(Jsx::rd($b, 'mean'));
        $delta = $x - $mean0;
        $mean = $mean0 + $delta / $n;
        $m2 = Jsx::toNum(Jsx::rd($b, 'm2')) + $delta * ($x - $mean);
        return Obj::of(['n' => $n, 'mean' => $mean, 'm2' => $m2]);
    }

    /** Population standard deviation of the baseline (0 until at least 2 samples). */
    public static function baselineStd(mixed $b): float
    {
        $n = Jsx::toNum(Jsx::rd($b, 'n'));
        return $n >= 2 ? sqrt(Jsx::toNum(Jsx::rd($b, 'm2')) / $n) : 0.0;
    }

    private static function decay(float $count, float $dtMs, float $halfLifeMs = self::HALF_LIFE_MS): float
    {
        if ($dtMs <= 0 || $count === 0.0) {
            return $count;
        }
        return $count * (0.5 ** ($dtMs / $halfLifeMs));
    }

    /** One member of an optional immune config ({alpha, halfLifeMs, driftZSat, stepUpSat, denySat}; absent = the default). */
    private static function cfg(?array $cfg, string $k, float $default): float
    {
        return isset($cfg[$k]) ? (float)Js::num($cfg[$k]) : $default;
    }

    /** Fold one observation into the immune state (baseline, recent EWMA, decayed step-up and deny counters), under an optional config. */
    public static function observe(mixed $state, mixed $obs, ?array $cfg = null): Obj
    {
        $alpha = self::cfg($cfg, 'alpha', self::ALPHA);
        $half = self::cfg($cfg, 'halfLifeMs', self::HALF_LIFE_MS);
        $or = Jsx::rd($obs, 'r');
        $r = self::clamp01(self::fin($or) ? self::f($or) : 0.0);
        $lastAt = Jsx::rd($state, 'lastAt');
        $oa = Jsx::rd($obs, 'at');
        $at = self::fin($oa) ? $oa : $lastAt; // a bad timestamp is pinned to the last good one: this observation advances no clock
        $seeded = Jsx::truthy(Jsx::rd($state, 'seeded'));
        $dt = $seeded ? self::jsMax0(Jsx::toNum($at) - Jsx::toNum($lastAt)) : 0.0;
        $baseline = self::updateBaseline(Jsx::rd($state, 'baseline'), $r);
        $ewma = $seeded ? $alpha * $r + (1 - $alpha) * Jsx::toNum(Jsx::rd($state, 'ewma')) : $r;
        $stepUps = self::decay(Jsx::toNum(Jsx::rd($state, 'stepUps')), $dt, $half) + (Jsx::truthy(Jsx::rd($obs, 'stepUp')) ? 1 : 0);
        $denies = self::decay(Jsx::toNum(Jsx::rd($state, 'denies')), $dt, $half) + (Jsx::truthy(Jsx::rd($obs, 'denied')) ? 1 : 0);
        return Obj::of(['baseline' => $baseline, 'ewma' => $ewma, 'stepUps' => $stepUps, 'denies' => $denies, 'lastAt' => $at, 'seeded' => true]);
    }

    /** `Math.max(0, x)`: NaN stays NaN. */
    private static function jsMax0(float $x): float
    {
        return is_nan($x) ? $x : max(0.0, $x);
    }

    private static function inRange(mixed $x, float $lo, float $hi): bool
    {
        return self::fin($x) && self::f($x) >= $lo && self::f($x) <= $hi;
    }

    private static function isObject(mixed $x): bool
    {
        return $x instanceof Obj || is_array($x);
    }

    /** The reason a state is malformed (non-finite, negative, out of bound), or null. */
    public static function validateImmuneState(mixed $s): ?string
    {
        if (!self::isObject($s)) {
            return 'state must be an object';
        }
        $b = Jsx::get($s, 'baseline');
        if (!self::isObject($b)) {
            return 'baseline missing';
        }
        $n = Jsx::get($b, 'n');
        if (!self::inRange($n, 0, self::MAX_COUNT) || self::f($n) != floor(self::f($n)) || self::negZero($n)) {
            return 'baseline.n must be an integer in [0, 1e9]';
        }
        if (!self::inRange(Jsx::get($b, 'mean'), 0, 1)) {
            return 'baseline.mean must be in [0, 1]';
        }
        if (!self::inRange(Jsx::get($b, 'm2'), 0, self::MAX_COUNT)) {
            return 'baseline.m2 must be finite and >= 0';
        }
        if (!self::inRange(Jsx::get($s, 'ewma'), 0, 1)) {
            return 'ewma must be in [0, 1]';
        }
        if (!self::inRange(Jsx::get($s, 'stepUps'), 0, self::MAX_COUNT)) {
            return 'stepUps must be finite and >= 0';
        }
        if (!self::inRange(Jsx::get($s, 'denies'), 0, self::MAX_COUNT)) {
            return 'denies must be finite and >= 0';
        }
        if (!self::inRange(Jsx::get($s, 'lastAt'), 0, 9007199254740991.0)) {
            return 'lastAt must be a finite non-negative time';
        }
        if (!is_bool(Jsx::get($s, 'seeded'))) {
            return 'seeded must be a boolean';
        }
        return null;
    }

    // ---- threat assessment -------------------------------------------------------------------------------------------------

    /**
     * The current threat from the immune state: {level: calm | elevated | high, score, signals, components: {drift, volatility, violation}}.
     * The score is the maximum of the drift, step-up volatility and violation signals; levels switch at 0.33 and 0.66. A malformed state
     * is the maximal threat.
     */
    public static function assess(mixed $state, ?array $cfg = null): Obj
    {
        $bad = self::validateImmuneState($state);
        if ($bad !== null) {
            return self::threat('high', 1, ["invalid immune state: $bad"], 1, 1, 1);
        }
        $base = Jsx::get($state, 'baseline');
        $std = self::baselineStd($base);
        $signals = [];
        $drift = 0.0;
        if (self::f(Jsx::get($base, 'n')) >= 5 && $std > 1e-9) {
            $z = (self::f(Jsx::get($state, 'ewma')) - self::f(Jsx::get($base, 'mean'))) / $std;
            $drift = self::clamp01($z / self::cfg($cfg, 'driftZSat', self::DRIFT_Z_SAT));
            if ($drift > 0.33) {
                $signals[] = 'risk drifted ' . AnalyzerJs::toFixed($z, 1) . 'σ above baseline';
            }
        }
        $stepUps = self::f(Jsx::get($state, 'stepUps'));
        $volatility = self::clamp01($stepUps / self::cfg($cfg, 'stepUpSat', self::STEP_UP_SAT));
        if ($volatility > 0.33) {
            $signals[] = 'elevated step-up rate (' . AnalyzerJs::toFixed($stepUps, 1) . ')';
        }
        $denies = self::f(Jsx::get($state, 'denies'));
        $violation = self::clamp01($denies / self::cfg($cfg, 'denySat', self::DENY_SAT));
        if ($violation > 0.33) {
            $signals[] = 'repeated policy violations (' . AnalyzerJs::toFixed($denies, 1) . ')';
        }
        $score = max($drift, $volatility, $violation);
        return self::threat($score >= 0.66 ? 'high' : ($score >= 0.33 ? 'elevated' : 'calm'), $score, $signals, $drift, $volatility, $violation);
    }

    /** @param list<string> $signals */
    private static function threat(string $level, float|int $score, array $signals, float|int $drift, float|int $volatility, float|int $violation): Obj
    {
        return Obj::of(['level' => $level, 'score' => $score, 'signals' => $signals,
            'components' => Obj::of(['drift' => $drift, 'volatility' => $volatility, 'violation' => $violation])]);
    }

    // ---- adaptation --------------------------------------------------------------------------------------------------------

    /** risk.ts validateRiskPolicy over the JSON model: the reason a risk policy is malformed, or null. */
    private static function validateRiskPolicy(mixed $p): ?string
    {
        if (!self::isObject($p)) {
            return 'risk_policy must be an object';
        }
        $w = Jsx::get($p, 'weights');
        if (!self::isObject($w)) {
            return 'risk_policy.weights missing';
        }
        foreach (['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'] as $k) {
            $v = Jsx::get($w, $k);
            if (!self::fin($v) || self::f($v) < 0) {
                return "risk_policy.weights.$k must be finite and >= 0";
            }
        }
        foreach (['theta1', 'theta2', 'kappa', 'lambda', 'rho', 'bMax'] as $k) {
            if (!self::fin(Jsx::get($p, $k))) {
                return "risk_policy.$k must be finite";
            }
        }
        $t1 = self::f(Jsx::get($p, 'theta1'));
        if ($t1 < 0 || self::f(Jsx::get($p, 'theta2')) < $t1) {
            return 'risk_policy requires 0 <= theta1 <= theta2';
        }
        if (self::f(Jsx::get($p, 'kappa')) <= 0) {
            return 'risk_policy.kappa must be > 0';
        }
        if (self::f(Jsx::get($p, 'lambda')) < 0 || self::f(Jsx::get($p, 'rho')) < 0 || self::f(Jsx::get($p, 'bMax')) < 0) {
            return 'risk_policy lambda/rho/bMax must be >= 0';
        }
        return null;
    }

    /**
     * The adapted policy for a threat assessment, derived from the BASE policy (never compounded): {policy, changed, rationale}. Default
     * caps: kappa x3, theta x0.4. A non-finite score is the worst case, never calm.
     */
    public static function adapt(mixed $base, mixed $assessment, float|int $maxKappaMult = 3, float|int $minThetaMult = 0.4): Obj
    {
        $sc = Jsx::rd($assessment, 'score');
        $s = self::fin($sc) ? self::clamp01(self::f($sc)) : 1.0;
        if ($s === 0.0) {
            return self::adaptation($base, false, 'calm — baseline policy');
        }
        $kappaMult = 1 + ($maxKappaMult - 1) * $s;
        $thetaMult = 1 - (1 - $minThetaMult) * $s;
        $w = Jsx::rd($base, 'weights');
        $policy = Jsx::spread($base);
        $policy->set('weights', Jsx::spread($w));
        $policy->set('kappa', Jsx::toNum(Jsx::get($base, 'kappa')) * $kappaMult);
        $policy->set('theta1', self::clamp01(Jsx::toNum(Jsx::get($base, 'theta1')) * $thetaMult));
        $policy->set('theta2', self::clamp01(Jsx::toNum(Jsx::get($base, 'theta2')) * $thetaMult));
        $bad = self::validateRiskPolicy($policy) ?? self::noWidenViolation($base, $policy);
        if ($bad !== null) {
            return self::adaptation($base, false, "adaptation rejected ($bad) — kept baseline");
        }
        $sig = Jsx::rd($assessment, 'signals');
        if ($sig === null || Jsx::isUndef($sig)) {
            throw new \TypeError("Cannot read properties of null or undefined (reading 'length')");
        }
        $has = is_array($sig) ? $sig !== [] : (is_string($sig) && $sig !== '');
        if (is_string($sig) && $has) {
            throw new \TypeError('assessment.signals.join is not a function');
        }
        $why = $has ? implode('; ', array_map(static fn(mixed $e): string => $e === null ? '' : Js::str($e), $sig)) : 'threat score ' . AnalyzerJs::toFixed($s, 2);
        $level = Jsx::str(Jsx::get($assessment, 'level'));
        return self::adaptation($policy, true, $level . ': ' . $why . ' → κ ×' . AnalyzerJs::toFixed($kappaMult, 2) . ', θ ×' . AnalyzerJs::toFixed($thetaMult, 2));
    }

    private static function adaptation(mixed $policy, bool $changed, string $rationale): Obj
    {
        return Obj::of(['policy' => $policy, 'changed' => $changed, 'rationale' => $rationale]);
    }

    /** Why `$adapted` is looser than `$base`, or null when it only tightens (kappa up, thetas down, the rest identical). A non-number reads as looser. */
    public static function noWidenViolation(mixed $base, mixed $adapted): ?string
    {
        if (!self::le(Jsx::rd($base, 'kappa'), Jsx::rd($adapted, 'kappa'))) {
            return 'kappa decreased';
        }
        if (!self::le(Jsx::rd($adapted, 'theta1'), Jsx::rd($base, 'theta1'))) {
            return 'theta1 increased';
        }
        if (!self::le(Jsx::rd($adapted, 'theta2'), Jsx::rd($base, 'theta2'))) {
            return 'theta2 increased';
        }
        foreach (['lambda', 'rho', 'bMax'] as $k) {
            if (!self::same(Jsx::rd($adapted, $k), Jsx::rd($base, $k))) {
                return "$k changed";
            }
        }
        $bw = Jsx::rd($base, 'weights');
        if ($bw === null || Jsx::isUndef($bw)) {
            throw new \TypeError('Cannot convert undefined or null to object');
        }
        foreach (Jsx::keys($bw) as $k) {
            if (!self::same(Jsx::rd(Jsx::get($adapted, 'weights'), $k), Jsx::get($bw, $k))) {
                return "weights.$k changed";
            }
        }
        return null;
    }

    /** Throws unless `$adapted` only tightens `$base`. */
    public static function assertNoWiden(mixed $base, mixed $adapted): void
    {
        $v = self::noWidenViolation($base, $adapted);
        if ($v !== null) {
            throw new \RuntimeException("immune: adaptation widens the policy ($v)");
        }
    }

    // ---- signed tightening proposals ---------------------------------------------------------------------------------------

    private static function hashLenient(mixed $v): string
    {
        return Pca::b64u(hash('sha256', Json::canonicalizeLenient($v), true));
    }

    public static function policyDigest(mixed $p): string
    {
        return self::hashLenient($p);
    }

    public static function immuneStateDigest(mixed $s): string
    {
        return self::hashLenient($s);
    }

    private static function tighteningMessage(Obj $claim): string
    {
        return self::TIGHTENING_DOMAIN . Json::canonicalizeLenient($claim);
    }

    /**
     * Derive and sign the tightening for `$state`; throws on a malformed base, an epoch that is not an integer >= 1, a non-finite `$now` or
     * a malformed state (never an unsigned loosening). `$guardianSecret` is the 32-byte Ed25519 seed (raw bytes).
     */
    public static function issueTighteningProposal(mixed $base, mixed $state, mixed $epoch, mixed $now, string $guardianSecret): Obj
    {
        $bad = self::validateRiskPolicy($base);
        if ($bad !== null) {
            throw new \InvalidArgumentException("issueTighteningProposal: $bad");
        }
        if (!self::safeInt($epoch) || self::f($epoch) < 1) {
            throw new \InvalidArgumentException('issueTighteningProposal: epoch must be an integer >= 1');
        }
        if (!self::fin($now)) {
            throw new \InvalidArgumentException('issueTighteningProposal: now must be finite');
        }
        $key = new KeyPair($guardianSecret);
        $ad = self::adapt($base, self::assess($state));
        $claim = Obj::of(['v' => 1, 'base_digest' => self::policyDigest($base), 'state_digest' => self::hashLenient($state), 'epoch' => $epoch,
            'issued_at' => $now, 'policy' => $ad->get('policy'), 'rationale' => $ad->get('rationale'), 'guardian' => $key->public]);
        $p = Jsx::spread($claim);
        $p->set('sig', Pca::b64u($key->sign(self::tighteningMessage($claim))));
        return $p;
    }

    private static function refused(string $reason): Obj
    {
        return Obj::of(['ok' => false, 'reason' => $reason]);
    }

    /**
     * Verify a proposal and return {ok: true, policy, epoch} or {ok: false, reason}; never throws. `$o` holds the pinned `guardian` (b64u,
     * required), `lastEpoch`, `now`, `maxAgeMs` and optionally `state` (a recompute check).
     */
    public static function applyTightening(mixed $base, mixed $p, mixed $o): Obj
    {
        try {
            if (!($p instanceof Obj) || !self::isOne(Jsx::get($p, 'v')) || !is_string($p->get('sig')) || !is_string($p->get('guardian'))) {
                return self::refused('malformed');
            }
            $pin = Jsx::rd($o, 'guardian');
            if (!is_string($pin) || $pin !== $p->get('guardian')) {
                return self::refused('guardian');
            }
            $claim = $p->without('sig');
            if (!Pca::verifyEd25519B64u($p->get('guardian'), self::tighteningMessage($claim), $p->get('sig'))) {
                return self::refused('signature');
            }
            $pol = Jsx::get($p, 'policy');
            if (self::validateRiskPolicy($base) !== null || self::validateRiskPolicy($pol) !== null) {
                return self::refused('invalid-policy');
            }
            if (Jsx::get($p, 'base_digest') !== self::policyDigest($base)) {
                return self::refused('base');
            }
            $now = Jsx::get($o, 'now');
            $at = Jsx::get($p, 'issued_at');
            if (!self::fin($now) || !self::fin($at) || !(self::f($at) <= self::f($now))
                || !(self::f($now) - self::f($at) <= Jsx::toNum(Jsx::get($o, 'maxAgeMs')))) {
                return self::refused('stale');
            }
            $epoch = Jsx::get($p, 'epoch');
            if (!self::safeInt($epoch) || self::negZero($epoch) || !(self::f($epoch) > Jsx::toNum(Jsx::get($o, 'lastEpoch')))) {
                return self::refused('replayed-epoch');
            }
            if (self::noWidenViolation($base, $pol) !== null) {
                return self::refused('widens');
            }
            $st = Jsx::get($o, 'state');
            if (Jsx::truthy($st) && (Jsx::get($p, 'state_digest') !== self::hashLenient($st)
                    || self::policyDigest(self::adapt($base, self::assess($st))->get('policy')) !== self::policyDigest($pol))) {
                return self::refused('state-mismatch');
            }
            return Obj::of(['ok' => true, 'policy' => $pol, 'epoch' => $epoch]);
        } catch (\Throwable) {
            return self::refused('malformed');
        }
    }

    /** `v === 1`. */
    private static function isOne(mixed $v): bool
    {
        return Js::isNum($v) && self::f($v) == 1.0;
    }

    // ---- durable state -----------------------------------------------------------------------------------------------------

    /** Immune state and applied epoch for one subject over an atomic kv, so a restart keeps the history and the replay floor. */
    public static function createImmuneStore(AtomicKv $kv, string $subject): ImmuneStore
    {
        return new ImmuneStore($kv, $subject);
    }
}

/** Immune state and applied epoch for one subject over an {@see AtomicKv} (JSON documents; a stored JSON null is a stored value, not an absent one). */
final class ImmuneStore
{
    private readonly string $stateKey;
    private readonly string $epochKey;

    public function __construct(private readonly AtomicKv $kv, string $subject)
    {
        $this->stateKey = "immune/state/$subject";
        $this->epochKey = "immune/epoch/$subject";
    }

    /** The stored state, or the initial one. */
    public function get(): mixed
    {
        $raw = $this->kv->get($this->stateKey);
        return $raw === null ? Immune::initialState() : Json::parseLax($raw);
    }

    /** Folds one observation atomically; throws when the stored state is malformed (it is never silently reset to calm). */
    public function observe(mixed $obs): Obj
    {
        $out = null;
        $this->kv->update($this->stateKey, static function (?string $prev) use ($obs, &$out): string {
            $cur = $prev === null ? Immune::initialState() : Json::parseLax($prev);
            $bad = Immune::validateImmuneState($cur);
            if ($bad !== null) {
                throw new \RuntimeException("immune store: stored state invalid ($bad)");
            }
            $out = Immune::observe($cur, $obs);
            return Json::canonicalizeLenient($out);
        });
        if (!($out instanceof Obj)) {
            throw new \RuntimeException('immune store: the update did not run');
        }
        return $out;
    }

    /** The highest epoch applied for this subject (0 when none). */
    public function lastEpoch(): int|float
    {
        $raw = $this->kv->get($this->epochKey);
        $v = $raw === null ? null : Json::parseLax($raw);
        return Js::isNum($v) ? (float)Js::num($v) : 0;
    }

    /**
     * Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. `$o` is as for
     * {@see Immune::applyTightening} without `lastEpoch`.
     */
    public function apply(mixed $base, mixed $p, mixed $o): Obj
    {
        $out = Obj::of(['ok' => false, 'reason' => 'malformed']);
        $this->kv->update($this->epochKey, static function (?string $prev) use ($base, $p, $o, &$out): ?string {
            $v = $prev === null ? null : Json::parseLax($prev);
            $oo = Jsx::spread($o);
            $oo->set('lastEpoch', Js::isNum($v) ? $v : 0);
            $out = Immune::applyTightening($base, $p, $oo);
            return $out->get('ok') === true ? Json::canonicalizeLenient($out->get('epoch')) : null;
        });
        return $out;
    }
}
