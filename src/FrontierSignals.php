<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';

/**
 * Tighten-or-escalate typing of the intent-frontier results (semantic threshold, proof of progress, objective risk): each becomes a
 * signal `ok | escalate | deny` that can only LOWER a decision; `ok` is the neutral element, never a grant. Every signal function is
 * total: a missing, malformed or unrecognised result is `deny`. Values are the parsed-JSON model.
 */
final class FrontierSignals
{
    /** A non-array object. */
    private static function isObj(mixed $v): bool
    {
        return $v instanceof Obj;
    }

    /** `ok` when the result is an object with a boolean `ok` that is true; a clean "not faithful" escalates; anything else denies. */
    public static function semanticSignal(mixed $result): string
    {
        if (!self::isObj($result) || !is_bool($result->get('ok'))) {
            return 'deny';
        }
        return $result->get('ok') ? 'ok' : 'escalate';
    }

    /** `ok` when the step verified; running out of exploration or budget escalates (exact reason match); every other denial denies. */
    public static function progressSignal(mixed $result): string
    {
        if (!self::isObj($result) || !is_bool($result->get('ok'))) {
            return 'deny';
        }
        if ($result->get('ok')) {
            return 'ok';
        }
        $r = $result->get('reason');
        return is_string($r) && in_array($r, ['exploration-exhausted', 'budget-exceeded'], true) ? 'escalate' : 'deny';
    }

    /** Nothing committed or a reproduced result is `ok`; a mismatch is `ok` only with `onMismatch: "heuristic"`; anything else denies. */
    public static function objectiveSignal(mixed $res): string
    {
        if (!self::isObj($res)) {
            return 'deny';
        }
        $m = $res->get('mode');
        if ($m === 'none' || $m === 'objective') {
            return 'ok';
        }
        if ($m === 'mismatch') {
            return $res->get('onMismatch') === 'heuristic' ? 'ok' : 'deny';
        }
        return 'deny';
    }

    private static function fin(mixed $x): ?float
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) ? $f : null;
    }

    /** IEEE minimum / maximum: -0 orders below 0. */
    private static function ieee(float $a, float $b, bool $max): float
    {
        if ($a == 0.0 && $b == 0.0) {
            $neg = (fdiv(1, $a) < 0) || (fdiv(1, $b) < 0);
            return $max ? ($neg && (fdiv(1, $a) < 0) && (fdiv(1, $b) < 0) ? -0.0 : 0.0) : ($neg ? -0.0 : 0.0);
        }
        return $max ? ($a > $b ? $a : $b) : ($a < $b ? $a : $b);
    }

    /**
     * Combine the baseline risk inputs with the objective ones so the objective path can only RAISE risk: reversibility is the lower
     * of the two, blast radius the higher, and a non-finite value on either side makes BOTH the worst case (0 and 1). The distance is
     * the objective's when a finite number, else 1. A null baseline or objective throws (a property read on null); no clamping.
     */
    public static function tightenRiskInputs(mixed $baseline, mixed $objective): Obj
    {
        $br = self::fin(Jsx::rd($baseline, 'reversibility'));
        $or = self::fin(Jsx::rd($objective, 'reversibility'));
        $bb = self::fin(Jsx::get($baseline, 'blastRadius'));
        $ob = self::fin(Jsx::get($objective, 'blastRadius'));
        $ok = $br !== null && $or !== null && $bb !== null && $ob !== null;
        $sd = Jsx::get($objective, 'semanticDistance');
        return Obj::of(['reversibility' => $ok ? self::ieee($br, $or, false) : 0, 'blastRadius' => $ok ? self::ieee($bb, $ob, true) : 1,
            'semanticDistance' => self::fin($sd) !== null ? $sd : 1]);
    }
}
