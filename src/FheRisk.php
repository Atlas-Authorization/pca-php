<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * The pure, scheme-independent parts of the homomorphic risk gate: risk-input transformation and fixed-point quantization, the public gate
 * policy, the risk claim binding read from a signed action, and the plaintext reference verdict. Values are parsed JSON (Obj, lists, Num,
 * string, bool, null); a JavaScript number that is not finite is the fail-closed worst case, as in the reference. The BFV evaluation is the
 * separate FheSeal (Microsoft SEAL); the signed-claim layer is FheOrigin.
 */
final class FheRisk
{
    public const POLY_MODULUS_DEGREE = 8192;
    public const PLAIN_MODULUS_BITS = 30;
    public const PLAIN_MODULUS = 1073692673;
    public const SIGNED_BOUND = 536846336; // floor(PLAIN_MODULUS / 2)
    public const DEFAULT_SCALE = 1000;
    public const RISK_DIM = 6;

    private const INPUT_FIELDS = ['semanticDistance', 'reversibility', 'blastRadius', 'taint', 'confidence', 'age'];

    /** The JavaScript number value of a parsed JSON number; NaN for anything that is not a number. */
    public static function num(mixed $o): float
    {
        if ($o instanceof Num) {
            return $o->float();
        }
        return is_int($o) || is_float($o) ? (float) $o : NAN;
    }

    private static function finite(float $x): bool
    {
        return is_finite($x);
    }

    private static function clamp01(float $x): float
    {
        return $x < 0 ? 0.0 : ($x > 1 ? 1.0 : $x);
    }

    private static function unit(float $x, float $worst): float
    {
        return self::finite($x) ? self::clamp01($x) : $worst;
    }

    private static function wt(float $x): float
    {
        return self::finite($x) && $x > 0 ? $x : 0.0;
    }

    private static function obj(mixed $o): Obj
    {
        if (!($o instanceof Obj)) {
            throw new \TypeError('Cannot read properties of ' . ($o === null ? 'undefined' : 'a non-object'));
        }
        return $o;
    }

    private static function field(mixed $m, string $k): float
    {
        if ($m === null) {
            throw new \TypeError("Cannot read properties of null (reading '$k')");
        }
        return $m instanceof Obj ? self::num($m->get($k)) : NAN;
    }

    /** @return list<float> [d, 1 - rev, bl, taint, 1 - conf, age], each through unit() with the worst case of the risk score */
    public static function transformedInputs(mixed $i): array
    {
        return [
            self::unit(self::field($i, 'semanticDistance'), 1.0),
            1 - self::unit(self::field($i, 'reversibility'), 0.0),
            self::unit(self::field($i, 'blastRadius'), 1.0),
            self::unit(self::field($i, 'taint'), 1.0),
            1 - self::unit(self::field($i, 'confidence'), 0.0),
            self::unit(self::field($i, 'age'), 1.0),
        ];
    }

    /** @return list<float> the weight vector of the risk score in canonical order with its clamp applied */
    public static function weightVector(mixed $w): array
    {
        return array_map(
            static fn(string $k): float => self::wt(self::field($w, $k)),
            ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'],
        );
    }

    /** JavaScript Math.round (ties toward +infinity), exact. */
    public static function jsRound(float $x): float
    {
        if (!self::finite($x)) {
            return $x;
        }
        $f = floor($x);
        return $x - $f >= 0.5 ? $f + 1 : $f;
    }

    private static function requireScale(float $scale): void
    {
        if (!self::finite($scale) || $scale != floor($scale) || $scale <= 0) {
            throw new \InvalidArgumentException('scale must be a positive integer');
        }
    }

    /** @return list<float> round(x_i * scale) for each transformed input: the integer vector the agent encrypts */
    public static function quantizeRiskInputs(mixed $i, mixed $scale = self::DEFAULT_SCALE): array
    {
        $s = self::num($scale);
        self::requireScale($s);
        return array_map(static fn(float $t): float => self::jsRound($t * $s), self::transformedInputs($i));
    }

    /** A JSON number for a JavaScript number: a safe integer by its digits, else a plain (never exponent) decimal. */
    public static function numVal(float $d): Num
    {
        if ($d == floor($d) && abs($d) <= 9007199254740991.0) {
            return new Num((string) (int) $d);
        }
        $s = IntentWb::jsStr($d);
        if (preg_match('/\A(-?)(\d)(?:\.(\d+))?e([+-]\d+)\z/', $s, $m) !== 1) {
            return new Num($s);
        }
        $digits = $m[2] . ($m[3] ?? '');
        $point = 1 + (int) $m[4]; // digits before the decimal point after shifting
        if ($point <= 0) {
            $plain = '0.' . str_repeat('0', -$point) . $digits;
        } elseif ($point >= strlen($digits)) {
            $plain = $digits . str_repeat('0', $point - strlen($digits));
        } else {
            $plain = substr($digits, 0, $point) . '.' . substr($digits, $point);
        }
        return new Num($m[1] . $plain);
    }

    /**
     * The public gate policy from a risk policy {weights, kappa} and the trust budget B, at fixed-point scale S: weights round(w_i S),
     * kappa-weighted weights round(kappa w_i S), budget round(B S^2). Refuses a policy whose scaled values could overflow the signed
     * plain-modulus range (a wrap would silently corrupt the verdict).
     */
    public static function fheRiskPolicy(mixed $core, mixed $budget, mixed $scaleArg = self::DEFAULT_SCALE): Obj
    {
        $scale = self::num($scaleArg);
        self::requireScale($scale);
        $b = self::num($budget);
        if (!(self::finite($b) && $b >= 0)) {
            throw new \InvalidArgumentException('budget must be finite and >= 0');
        }
        $kappa = self::field($core, 'kappa');
        if (!(self::finite($kappa) && $kappa > 0)) {
            throw new \InvalidArgumentException('policy.kappa must be finite and > 0');
        }
        $w = self::weightVector(self::obj($core->get('weights')));
        $ws = array_map(static fn(float $x): float => self::jsRound($x * $scale), $w);
        $kws = array_map(static fn(float $x): float => self::jsRound($kappa * $x * $scale), $w);
        $budgetScaled = self::jsRound($b * $scale * $scale);
        $maxAbs = max(array_sum($ws) * $scale, array_sum($kws) * $scale, $budgetScaled);
        if ($maxAbs >= self::SIGNED_BOUND) {
            throw new \InvalidArgumentException('policy/scale overflow the plain modulus: max |value| ' . IntentWb::jsStr($maxAbs) . ' must be < SIGNED_BOUND ' . self::SIGNED_BOUND . '. Lower the scale or the weights/budget.');
        }
        $o = new Obj();
        $o->set('scale', self::numVal($scale));
        $o->set('dim', new Num((string) self::RISK_DIM));
        $o->set('weightsScaled', array_map(self::numVal(...), $ws));
        $o->set('kappaWeightsScaled', array_map(self::numVal(...), $kws));
        $o->set('budgetScaled', self::numVal($budgetScaled));
        $o->set('kappa', self::numVal($kappa));
        return $o;
    }

    /** The six normalized risk inputs of a signed action's risk claim; a missing or non-numeric field is NaN (fail-closed). */
    public static function riskInputsFromPCActn(mixed $p): Obj
    {
        $src = self::obj(self::obj(self::obj($p)->get('risk_claim'))->get('inputs'));
        $out = new Obj();
        foreach (self::INPUT_FIELDS as $k) {
            $v = $src->get($k);
            $out->set($k, $v instanceof Num || is_int($v) || is_float($v) ? $v : NAN);
        }
        return $out;
    }

    /** The replay binding of a signed action: audience, action digest, counter and the optional nonce. */
    public static function bindingFromPCActn(mixed $p): Obj
    {
        $p = self::obj($p);
        $m = new Obj();
        $m->set('aud', $p->get('aud'));
        $m->set('actionRef', self::obj($p->get('action'))->get('params_digest'));
        $m->set('counter', $p->get('counter'));
        if ($p->has('nonce')) {
            $m->set('nonce', $p->get('nonce'));
        }
        return $m;
    }

    /** The plaintext reference verdict: r = risk score, admit iff kappa-cost(r) <= budget. @return Obj {r, admit} */
    public static function plaintextVerdict(mixed $inputs, mixed $core, mixed $budget): Obj
    {
        $w = self::obj(self::obj($core)->get('weights'));
        $r = self::clamp01(
            self::wt(self::field($w, 'alpha')) * self::unit(self::field($inputs, 'semanticDistance'), 1.0)
            + self::wt(self::field($w, 'beta')) * (1 - self::unit(self::field($inputs, 'reversibility'), 0.0))
            + self::wt(self::field($w, 'gamma')) * self::unit(self::field($inputs, 'blastRadius'), 1.0)
            + self::wt(self::field($w, 'delta')) * self::unit(self::field($inputs, 'taint'), 1.0)
            + self::wt(self::field($w, 'epsilon')) * (1 - self::unit(self::field($inputs, 'confidence'), 0.0))
            + self::wt(self::field($w, 'zeta')) * self::unit(self::field($inputs, 'age'), 1.0)
        );
        $kappa = self::field($core, 'kappa');
        $cost = (self::finite($kappa) && $kappa > 0 ? $kappa : 0.0) * self::clamp01(self::finite($r) ? $r : 1.0);
        $o = new Obj();
        $o->set('r', self::numVal($r));
        $o->set('admit', $cost <= self::num($budget));
        return $o;
    }
}
