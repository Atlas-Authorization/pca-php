<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';

/**
 * The multi-agent trust-budget algebra over budgets of any JSON shape (budgets that arrive from a carried or hostile document): a
 * sub-agent allocation, a consolidated debit that also debits every ancestor, and the full recharge. A budget is `{B, tau, asOf?}`; a
 * debit keeps every other member of the budget it was given. The typed float form is {@see Risk}.
 */
final class BudgetTree
{
    /** Number.isFinite(x) && x > 0 ? x : 0 (a number only, no coercion). */
    private static function nz(mixed $x): float
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f > 0 ? $f : 0.0;
    }

    /** The budget without its undefined members, as an object. */
    private static function obj(array $members): Obj
    {
        $o = new Obj();
        foreach ($members as $k => $v) {
            if (!($v instanceof Undef)) {
                $o->set((string)$k, $v);
            }
        }
        return $o;
    }

    /** `{...b, B: Math.max(0, b.B - nz(c))}` (a budget that is not an object has no members to keep). */
    public static function debit(mixed $b, mixed $c): Obj
    {
        $o = Jsx::spread($b);
        $d = Jsx::toNum(Jsx::rd($b, 'B')) - self::nz($c);
        $o->set('B', is_nan($d) ? $d : max(0.0, $d));
        return $o;
    }

    /**
     * An allocation `$alloc` of the parent's remaining budget: refused unless finite and within `0 <= alloc <= parent.B`.
     * @return array{ok:false,reason:string}|array{ok:true,sub:Obj}
     */
    public static function subBudget(mixed $parent, mixed $alloc): array
    {
        $a = Js::num($alloc);
        if ($a === null || !is_finite($a) || $a < 0) {
            return ['ok' => false, 'reason' => 'allocation must be finite and >= 0'];
        }
        if (!(is_finite(Jsx::toNum(Jsx::rd($parent, 'B'))) && Jsx::toNum($alloc) <= Jsx::toNum(Jsx::rd($parent, 'B')))) {
            return ['ok' => false, 'reason' => 'allocation exceeds parent remaining budget'];
        }
        $tau = Jsx::get($parent, 'tau');
        $asOf = Jsx::get($parent, 'asOf');
        return ['ok' => true, 'sub' => self::obj(['B' => $alloc, 'tau' => $tau, 'asOf' => $asOf === null || $asOf instanceof Undef ? $tau : $asOf])];
    }

    /**
     * A sub-agent's debit also debits the parent; refused, with no state change, when either cannot cover `$c`.
     * @return array{ok:false,reason:string}|array{ok:true,parent:Obj,sub:Obj}
     */
    public static function debitConsolidated(mixed $parent, mixed $sub, mixed $c): array
    {
        $x = self::nz($c);
        if (!(is_finite(Jsx::toNum(Jsx::rd($sub, 'B'))) && Jsx::toNum(Jsx::rd($sub, 'B')) >= $x)) {
            return ['ok' => false, 'reason' => 'sub-agent budget insufficient'];
        }
        if (!(is_finite(Jsx::toNum(Jsx::rd($parent, 'B'))) && Jsx::toNum(Jsx::rd($parent, 'B')) >= $x)) {
            return ['ok' => false, 'reason' => 'parent budget insufficient'];
        }
        return ['ok' => true, 'parent' => self::debit($parent, $x), 'sub' => self::debit($sub, $x)];
    }

    /**
     * The consolidated debit along a root-to-leaf path of budgets: every node must cover `$c`, else nothing is debited and the first
     * offender is named.
     * @return array{ok:false,reason:string}|array{ok:true,nodes:list<Obj>}
     */
    public static function debitConsolidatedPath(mixed $path, mixed $c): array
    {
        if (!is_array($path) || !array_is_list($path)) {
            throw new \TypeError('path must be a list of budgets');
        }
        $x = self::nz($c);
        foreach ($path as $i => $node) {
            $b = Jsx::rd($node, 'B');
            $n = Jsx::toNum($b);
            if (!(is_finite($n) && $n >= $x)) {
                return ['ok' => false, 'reason' => "budget node at depth $i insufficient (need " . IntentWb::jsNumStr($x) . ', have ' . Jsx::str($b) . ')'];
            }
        }
        return ['ok' => true, 'nodes' => array_map(fn($b): Obj => self::debit($b, $x), $path)];
    }

    /** Full goal re-confirmation: `{B: bMax (non-finite or negative as 0), tau: now, asOf: now}`. */
    public static function rechargeFull(mixed $bMax, mixed $now): Obj
    {
        return Obj::of(['B' => self::nz($bMax), 'tau' => $now, 'asOf' => $now]);
    }
}
