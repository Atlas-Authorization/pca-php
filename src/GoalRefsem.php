<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/GoalJs.php';

/**
 * An independent reading of the goal semantics D_G: a second, hand-written implementation used to cross-check a compiled
 * policy. Not the trusted decision function. Decisions are 0 deny, 1 escalate, 2 allow; condition truth is 0 false, 1 unknown,
 * 2 true.
 */
final class GoalRefsem
{
    private static function b2t(mixed $b): int
    {
        return AnalyzerJs::truthy($b) ? 2 : 0;
    }

    private static function sameUnit(mixed $a, mixed $b): bool
    {
        if (AnalyzerJs::isUndef($a) || AnalyzerJs::isUndef($b)) {
            return $a === $b;
        }
        return AnalyzerJs::jsJson($a) === AnalyzerJs::jsJson($b);
    }

    /** Object.hasOwn-style membership; a null or undefined object throws. */
    private static function has(mixed $o, mixed $k): bool
    {
        if ($o === null || AnalyzerJs::isUndef($o)) {
            throw new \TypeError('cannot convert undefined or null to object');
        }
        return $o instanceof Obj && is_string($k) && $o->has($k);
    }

    private static function val(mixed $t, mixed $a, mixed $h): mixed
    {
        $k = AnalyzerJs::jget($t, 'k');
        if ($k === 'param') {
            $params = AnalyzerJs::jget($a, 'params');
            $path = AnalyzerJs::jget($t, 'path');
            return self::has($params, $path) ? $params->get($path) : AnalyzerJs::undef();
        }
        if ($k === 'lit') {
            return AnalyzerJs::jget($t, 'v');
        }
        $aggs = AnalyzerJs::jget($h, 'aggs');
        $bid = AnalyzerJs::jget($t, 'bid');
        return self::has($aggs, $bid) ? AnalyzerJs::uobj(['k' => 'q', 'q' => $aggs->get($bid)]) : AnalyzerJs::undef();
    }

    private static function eq(mixed $x, mixed $y): int
    {
        if (AnalyzerJs::jget($x, 'k') === 'q' && AnalyzerJs::jget($y, 'k') === 'q') {
            $xq = AnalyzerJs::jget($x, 'q');
            $yq = AnalyzerJs::jget($y, 'q');
            return self::sameUnit(AnalyzerJs::jget($xq, 'u'), AnalyzerJs::jget($yq, 'u'))
                ? self::b2t(AnalyzerJs::strictEq(AnalyzerJs::jget($xq, 'n'), AnalyzerJs::jget($yq, 'n'))) : 1;
        }
        if (AnalyzerJs::jget($x, 'k') === 's' && AnalyzerJs::jget($y, 'k') === 's') {
            return self::b2t(AnalyzerJs::strictEq(AnalyzerJs::jget($x, 's'), AnalyzerJs::jget($y, 's')));
        }
        return 1;
    }

    private static function lt(mixed $x, mixed $y): int
    {
        if (AnalyzerJs::jget($x, 'k') === 'q' && AnalyzerJs::jget($y, 'k') === 'q'
            && self::sameUnit(AnalyzerJs::jget(AnalyzerJs::jget($x, 'q'), 'u'), AnalyzerJs::jget(AnalyzerJs::jget($y, 'q'), 'u'))) {
            return self::b2t(AnalyzerJs::jsLt(AnalyzerJs::jget(AnalyzerJs::jget($x, 'q'), 'n'), AnalyzerJs::jget(AnalyzerJs::jget($y, 'q'), 'n')));
        }
        return 1;
    }

    private static function inSet(mixed $x, mixed $y): int
    {
        if (AnalyzerJs::jget($y, 'k') !== 'set') {
            return 1;
        }
        $acc = 0;
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($y, 'items')) as $it) {
            $acc = max($acc, self::eq($x, $it));
        }
        return $acc;
    }

    private static function cmp(mixed $op, mixed $x, mixed $y): int
    {
        if (!AnalyzerJs::truthy($x) || !AnalyzerJs::truthy($y)) {
            return 1;
        }
        return match ($op) {
            'eq' => self::eq($x, $y),
            'ne' => 2 - self::eq($x, $y),
            'lt' => self::lt($x, $y),
            'gte' => 2 - self::lt($x, $y),
            'gt' => self::lt($y, $x),
            'lte' => 2 - self::lt($y, $x),
            'in' => self::inSet($x, $y),
            default => 2 - self::inSet($x, $y),
        };
    }

    private static function evalC(mixed $c, mixed $a, mixed $h): int
    {
        switch (AnalyzerJs::jget($c, 'k')) {
            case 'true':
                return 2;
            case 'cmp':
                return self::cmp(AnalyzerJs::jget($c, 'op'), self::val(AnalyzerJs::jget($c, 'l'), $a, $h), self::val(AnalyzerJs::jget($c, 'r'), $a, $h));
            case 'and':
                return min(self::evalC(AnalyzerJs::jget($c, 'a'), $a, $h), self::evalC(AnalyzerJs::jget($c, 'b'), $a, $h));
            case 'or':
                return max(self::evalC(AnalyzerJs::jget($c, 'a'), $a, $h), self::evalC(AnalyzerJs::jget($c, 'b'), $a, $h));
            case 'not':
                return 2 - self::evalC(AnalyzerJs::jget($c, 'c'), $a, $h);
            default:
                throw new \InvalidArgumentException('unknown condition'); // the reference yields NaN here; refuse instead
        }
    }

    private static function resOk(mixed $s, mixed $ont, mixed $r): bool
    {
        switch (AnalyzerJs::jget($s, 'k')) {
            case 'any':
                return true;
            case 'exact':
                return AnalyzerJs::strictEq($r, AnalyzerJs::jget($s, 'id'));
            case 'oneof':
                return AnalyzerJs::includes(AnalyzerJs::jget($s, 'ids'), $r);
            case 'related':
                $members = [];
                foreach (AnalyzerJs::reqList(AnalyzerJs::jget($ont, 'rels')) as $x) {
                    if (!(AnalyzerJs::strictEq(AnalyzerJs::jget($x, 'rel'), AnalyzerJs::jget($s, 'rel'))
                        && AnalyzerJs::strictEq(AnalyzerJs::jget($x, 'anchor'), AnalyzerJs::jget($s, 'anchor')))) {
                        continue;
                    }
                    $m = AnalyzerJs::jget($x, 'members');
                    $members = ($m === null || AnalyzerJs::isUndef($m)) ? [] : $m;
                    break;
                }
                return AnalyzerJs::includes($members, $r);
            case 'all_of':
                foreach (AnalyzerJs::reqList(AnalyzerJs::jget($s, 'parts')) as $p) {
                    if (!self::resOk($p, $ont, $r)) {
                        return false;
                    }
                }
                return true;
            default:
                return false;
        }
    }

    /** @return list<mixed> */
    private static function verbsOf(mixed $ont, mixed $cls): array
    {
        $out = [];
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($ont, 'verbs')) as $v) {
            if (AnalyzerJs::strictEq(AnalyzerJs::jget($v, 'cls'), $cls)) {
                $out[] = AnalyzerJs::jget($v, 'verb');
            }
        }
        return $out;
    }

    private static function inScope(mixed $sc, mixed $a, mixed $x): bool
    {
        switch (AnalyzerJs::jget($sc, 'k')) {
            case 'session':
                return AnalyzerJs::strictEq(AnalyzerJs::jget($a, 'sess'), AnalyzerJs::jget($x, 'sess'));
            case 'principal':
                return AnalyzerJs::strictEq(AnalyzerJs::jget($a, 'prin'), AnalyzerJs::jget($x, 'prin'));
            case 'org':
                return AnalyzerJs::strictEq(AnalyzerJs::jget($a, 'org'), AnalyzerJs::jget($x, 'org'));
            case 'fleet':
                return AnalyzerJs::includes(AnalyzerJs::jget($sc, 'agents'), AnalyzerJs::jget($a, 'agent'))
                    && AnalyzerJs::includes(AnalyzerJs::jget($sc, 'agents'), AnalyzerJs::jget($x, 'agent'));
            default:
                return false;
        }
    }

    private static function floorOf(float $v): float
    {
        return is_finite($v) ? floor($v) : $v;
    }

    private static function inWin(mixed $w, mixed $a, mixed $x): bool
    {
        switch (AnalyzerJs::jget($w, 'k')) {
            case 'task':
            case 'lifetime':
                return true;
            case 'sliding':
                $at = AnalyzerJs::toNumber(AnalyzerJs::jget($a, 't'));
                $xt = AnalyzerJs::toNumber(AnalyzerJs::jget($x, 't'));
                $ms = AnalyzerJs::toNumber(AnalyzerJs::jget($w, 'ms'));
                return AnalyzerJs::jsGt(AnalyzerJs::jget($x, 't'), $at - $ms) && $xt <= $at;
            case 'period':
                $ms = AnalyzerJs::jget($w, 'ms');
                if (!AnalyzerJs::jsGt($ms, 0)) {
                    return false;
                }
                $m = AnalyzerJs::toNumber($ms);
                $t0 = AnalyzerJs::toNumber(AnalyzerJs::jget($w, 't0'));
                return self::floorOf(fdiv(AnalyzerJs::toNumber(AnalyzerJs::jget($a, 't')) - $t0, $m))
                    == self::floorOf(fdiv(AnalyzerJs::toNumber(AnalyzerJs::jget($x, 't')) - $t0, $m));
            default:
                return false;
        }
    }

    /** JS `+` accumulation from 0: numbers add, anything else concatenates the strings. @param list<mixed> $xs */
    private static function fsum(array $xs): mixed
    {
        $s = 0.0;
        foreach ($xs as $x) {
            $s = (is_float($s) && Js::isNum($x)) ? $s + AnalyzerJs::jsnum($x) : AnalyzerJs::jsStr($s) . AnalyzerJs::jsStr($x);
        }
        return $s;
    }

    public static function refDecide(mixed $g, mixed $ont, mixed $a, mixed $h): mixed
    {
        return self::refExplain($g, $ont, $a, $h)->get('d');
    }

    /**
     * `{d, witness, prohibit}`: the decision, the first grant (goal order) whose own decision is Allow (null unless d = 2), and
     * the meet over the prohibitions alone (0 one fires, 1 one is unknown, 2 none applies).
     */
    public static function refExplain(mixed $g, mixed $ont, mixed $a, mixed $h): Obj
    {
        $d = 2;
        $prohibit = 2;
        $witness = null;
        $v = AnalyzerJs::jget($g, 'validity');
        $t = AnalyzerJs::jget($a, 't');
        $deleg = AnalyzerJs::jget($g, 'deleg');
        $last = AnalyzerJs::jget($h, 'last');
        $depth = AnalyzerJs::jget($a, 'depth');
        if (AnalyzerJs::jsLt($t, AnalyzerJs::jget($v, 'notBefore')) || AnalyzerJs::jsGt($t, AnalyzerJs::jget($v, 'notAfter'))) {
            $d = min($d, 0);
        } elseif (AnalyzerJs::jsGt(AnalyzerJs::jget($v, 'maxIdle'), 0) && !AnalyzerJs::jsLt($last, 0)
            && ($nl = AnalyzerJs::toNumber($last)) == $nl
            && AnalyzerJs::jsGt(AnalyzerJs::toNumber($t) - AnalyzerJs::toNumber($last), AnalyzerJs::jget($v, 'maxIdle'))) {
            $d = min($d, 0);
        } elseif (AnalyzerJs::jsLt($depth, 0) || AnalyzerJs::jsGt($depth, AnalyzerJs::jget($deleg, 'maxDepth'))) {
            $d = min($d, 0);
        }
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($g, 'prohibits')) as $p) {
            $tg = AnalyzerJs::jget($p, 'target');
            $verbs = AnalyzerJs::jget($tg, 'k') === 'verb' ? [AnalyzerJs::jget($tg, 'verb')] : self::verbsOf($ont, AnalyzerJs::jget($tg, 'cls'));
            $m = min(
                self::b2t(AnalyzerJs::includes($verbs, AnalyzerJs::jget($a, 'verb'))),
                min(self::b2t(self::resOk(AnalyzerJs::jget($p, 'res'), $ont, AnalyzerJs::jget($a, 'res'))), self::evalC(AnalyzerJs::jget($p, 'cond'), $a, $h))
            );
            $pd = $m === 2 ? 0 : ($m === 1 ? 1 : 2);
            $d = min($d, $pd);
            $prohibit = min($prohibit, $pd);
        }
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($g, 'escalateOn')) as $c) {
            $d = min($d, self::evalC($c, $a, $h) === 0 ? 2 : 1);
        }
        $best = 0;
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($g, 'grants')) as $gr) {
            $verbOk = AnalyzerJs::strictEq(AnalyzerJs::jget($a, 'verb'), AnalyzerJs::jget($gr, 'verb'))
                && (AnalyzerJs::strictEq($depth, 0) || AnalyzerJs::includes(AnalyzerJs::jget($deleg, 'mayTouch'), AnalyzerJs::jget($gr, 'gid')));
            $gd = min(
                self::b2t($verbOk),
                min(self::b2t(self::resOk(AnalyzerJs::jget($gr, 'res'), $ont, AnalyzerJs::jget($a, 'res'))), self::evalC(AnalyzerJs::jget($gr, 'cond'), $a, $h))
            );
            foreach (AnalyzerJs::reqList(AnalyzerJs::jget($g, 'bounds')) as $b) {
                $gd = min($gd, self::boundDec($b, $gr, $ont, $a, $h));
            }
            if ($gd === 2 && $witness === null) {
                $witness = AnalyzerJs::jget($gr, 'gid');
            }
            $best = max($best, $gd);
        }
        $d = min($d, $best);
        return AnalyzerJs::uobj(['d' => $d, 'witness' => $d === 2 ? $witness : null, 'prohibit' => $prohibit]);
    }

    /** The decision one bound imposes on the candidate under one grant (2 when it does not apply). */
    private static function boundDec(mixed $b, mixed $gr, mixed $ont, mixed $a, mixed $h): int
    {
        $sel = AnalyzerJs::jget($b, 'sel');
        $gids = AnalyzerJs::jget($sel, 'k') === 'gids' ? AnalyzerJs::jget($sel, 'gids') : [];
        $verbs = AnalyzerJs::jget($sel, 'k') === 'effect' ? self::verbsOf($ont, AnalyzerJs::jget($sel, 'cls')) : [];
        if (!(AnalyzerJs::includes($gids, AnalyzerJs::jget($gr, 'gid')) || AnalyzerJs::includes($verbs, AnalyzerJs::jget($a, 'verb')))) {
            return 2;
        }
        $items = [];
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($h, 'adms')) as $x) {
            $xa = AnalyzerJs::jget($x, 'act');
            if ((AnalyzerJs::includes($gids, AnalyzerJs::jget($x, 'gid')) || AnalyzerJs::includes($verbs, AnalyzerJs::jget($xa, 'verb')))
                && self::inScope(AnalyzerJs::jget($b, 'scope'), $a, $xa) && self::inWin(AnalyzerJs::jget($b, 'window'), $a, $xa)) {
                $items[] = $xa;
            }
        }
        $items[] = $a;
        $cap = AnalyzerJs::jget($b, 'cap');
        $agg = AnalyzerJs::jget($b, 'agg');
        if ($agg === 'count') {
            $ex = self::b2t(AnalyzerJs::jsGt(count($items), AnalyzerJs::jget($cap, 'n')));
        } elseif ($agg === 'sum' || $agg === 'max') {
            $ex = self::sumMaxEx($b, $agg, $items, $cap, $h);
        } else {
            $ex = self::distinctEx($b, $items, $cap);
        }
        return $ex === 2 ? (AnalyzerJs::jget($b, 'onExceed') === 'deny' ? 0 : 1) : ($ex === 1 ? 1 : 2);
    }

    /** @param list<mixed> $items */
    private static function sumMaxEx(mixed $b, string $agg, array $items, mixed $cap, mixed $h): int
    {
        $xs = [];
        foreach ($items as $it) {
            $v = self::val(AnalyzerJs::jget($b, 'value'), $it, $h);
            if (!AnalyzerJs::truthy($v) || AnalyzerJs::jget($v, 'k') !== 'q'
                || !self::sameUnit(AnalyzerJs::jget(AnalyzerJs::jget($v, 'q'), 'u'), AnalyzerJs::jget($cap, 'u'))) {
                return 1;
            }
            $xs[] = AnalyzerJs::jget(AnalyzerJs::jget($v, 'q'), 'n');
        }
        if ($agg === 'sum') {
            return self::b2t(AnalyzerJs::jsGt(self::fsum($xs), AnalyzerJs::jget($cap, 'n')));
        }
        if ($xs === []) {
            return 1;
        }
        $ns = array_map(AnalyzerJs::toNumber(...), $xs);
        $mx = NAN;
        if (!in_array(true, array_map('is_nan', $ns), true)) {
            $mx = max($ns);
        }
        return self::b2t(AnalyzerJs::jsGt($mx, AnalyzerJs::jget($cap, 'n')));
    }

    /** @param list<mixed> $items */
    private static function distinctEx(mixed $b, array $items, mixed $cap): int
    {
        $ks = [];
        $key = AnalyzerJs::jget($b, 'key');
        foreach ($items as $it) {
            $ip = AnalyzerJs::jget($it, 'params');
            if (!self::has($ip, $key)) {
                return 1;
            }
            $ks[] = AnalyzerJs::jsJson($ip->get($key));
        }
        return self::b2t(AnalyzerJs::jsGt(count(array_unique($ks, SORT_STRING)), AnalyzerJs::jget($cap, 'n')));
    }
}
