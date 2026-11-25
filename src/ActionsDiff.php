<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDerive.php';
require_once __DIR__ . '/ActionsEffective.php';
require_once __DIR__ . '/ActionsSelector.php';
require_once __DIR__ . '/Js.php';

/**
 * Semantic diff of two versions of one ActionDef (native port of diff.ts and defdiff.ts of the reference actions package). diffDefs is the
 * grant-pin form (equal|narrow|widen|incomparable, never optimistic); diffDefsAuthoring and diffPacks are the authoring-CLI form. Pure.
 */
final class ActionsDiff
{
    private const DEFAULT_MAX_LEN = 1024;
    private const DEFAULT_MAX_ITEMS = 64;
    private const SCOPE_RANK = ['one' => 0, 'set' => 1, 'tenant' => 2, 'global' => 3];
    private const IDEM_RANK = ['none' => 0, 'natural' => 1, 'key_param' => 2];

    /** `o[k] ?? default` as a number. */
    private static function g(Obj $o, string $k, float $d): float
    {
        $v = $o->get($k);
        return $v === null ? $d : (float)Js::num($v);
    }

    /** JSON.stringify(o[k]); an absent member is 'undefined'. */
    private static function sj(Obj $o, string $k): string
    {
        return $o->has($k) ? self::sjv($o->get($k)) : 'undefined';
    }

    /** Key order is not meaning: object keys sorted recursively (lists keep their order), then JSON.stringify. */
    private static function sjv(mixed $v): string
    {
        return Js::stringify(self::sortKeys($v));
    }

    private static function sortKeys(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach (K3Sig::sortedUtf16($v->keys()) as $k) {
                $o->set($k, self::sortKeys($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::sortKeys(...), $v);
            }
            $keys = array_map('strval', array_keys($v));
            $o = new Obj();
            foreach (K3Sig::sortedUtf16($keys) as $k) {
                $o->set($k, self::sortKeys($v[$k] ?? $v[(int)$k] ?? null));
            }
            return $o;
        }
        return $v;
    }

    private static function same(Obj $a, Obj $b, string $k): bool
    {
        return self::sj($a, $k) === self::sj($b, $k);
    }

    /** @param list<mixed> $old @param list<mixed> $new */
    private static function setRel(array $old, array $new): string
    {
        $added = array_filter($new, static fn($x) => !in_array($x, $old, true)) !== [];
        $removed = array_filter($old, static fn($x) => !in_array($x, $new, true)) !== [];
        return $added && $removed ? 'inc' : ($added ? 'narrow' : ($removed ? 'widen' : 'eq'));
    }

    /** More restrictive = larger. */
    private static function rankRel(float $o, float $n): string
    {
        return $n == $o ? 'eq' : ($n > $o ? 'narrow' : 'widen');
    }

    private static function contains(array $outer, mixed $v): bool
    {
        return in_array($v, $outer, true);
    }

    private static function domainContains(Obj $outer, Obj $inner): bool
    {
        $t = $outer->get('type');
        if ($t !== $inner->get('type')) {
            return false;
        }
        if ($t === 'string' || $t === 'object_ref') {
            if (self::g($inner, 'max_len', self::DEFAULT_MAX_LEN) > self::g($outer, 'max_len', self::DEFAULT_MAX_LEN)) {
                return false;
            }
            if ($outer->get('values') !== null) {
                if ($inner->get('values') === null) {
                    return false;
                }
                foreach ($inner->get('values') as $v) {
                    if (!self::contains($outer->get('values'), $v)) {
                        return false;
                    }
                }
            }
            return $outer->get('format') === null || $inner->get('format') === $outer->get('format');
        }
        if ($t === 'integer') {
            return self::g($inner, 'min', -INF) >= self::g($outer, 'min', -INF) && self::g($inner, 'max', INF) <= self::g($outer, 'max', INF);
        }
        if ($t === 'duration') {
            return max(self::g($inner, 'min', 0), 0) >= max(self::g($outer, 'min', 0), 0) && self::g($inner, 'max', INF) <= self::g($outer, 'max', INF);
        }
        if ($t === 'set') {
            $ov = $outer->get('values') ?? [];
            $iv = $inner->get('values') ?? [];
            foreach ($iv as $v) {
                if (!self::contains($ov, $v)) {
                    return false;
                }
            }
            $oMax = min(self::g($outer, 'max_items', count($ov)), count($ov));
            $iMax = min(self::g($inner, 'max_items', count($iv)), count($iv));
            return self::g($inner, 'min_items', 0) >= self::g($outer, 'min_items', 0) && $iMax <= $oMax;
        }
        if ($t === 'array') {
            if (($outer->get('items') ?? 'string') !== ($inner->get('items') ?? 'string')) {
                return false;
            }
            if (self::g($inner, 'min_items', 0) < self::g($outer, 'min_items', 0) || self::g($inner, 'max_items', self::DEFAULT_MAX_ITEMS) > self::g($outer, 'max_items', self::DEFAULT_MAX_ITEMS)) {
                return false;
            }
            if ($outer->get('items') === 'integer') {
                return self::g($inner, 'min', -INF) >= self::g($outer, 'min', -INF) && self::g($inner, 'max', INF) <= self::g($outer, 'max', INF);
            }
            return self::g($inner, 'max_len', self::DEFAULT_MAX_LEN) <= self::g($outer, 'max_len', self::DEFAULT_MAX_LEN);
        }
        return true; // boolean, date, datetime: no domain members
    }

    /** Is every call conforming to $inner also conforming to $outer? Closed world, required members, domains. */
    private static function callsContained(Obj $outer, Obj $inner): bool
    {
        foreach ($inner->keys() as $name) {
            if (!$outer->has($name) || !self::domainContains($outer->get($name), $inner->get($name))) {
                return false;
            }
        }
        foreach ($outer->keys() as $name) {
            if (Js::truthy($outer->get($name)->get('required'))) {
                $ip = $inner->get($name);
                if ($ip === null || !Js::truthy($ip->get('required'))) {
                    return false;
                }
            }
        }
        return true;
    }

    private static function callSetRel(Obj $oldP, Obj $newP): string
    {
        $sub = self::callsContained($oldP, $newP);
        $sup = self::callsContained($newP, $oldP);
        return $sub && $sup ? 'eq' : ($sub ? 'narrow' : ($sup ? 'widen' : 'inc'));
    }

    private static function provRank(mixed $p): int
    {
        return $p === null ? count(Actions::PROVENANCE) - 1 : (int)array_search($p, Actions::PROVENANCE, true);
    }

    /** @return list<array{0:string,1:string}> */
    private static function paramAttrRels(Obj $o, Obj $n): array
    {
        $out = [];
        if ($o->get('role') !== $n->get('role')) {
            $out[] = ['role', 'inc'];
        }
        $out[] = ['sensitivity', self::rankRel(Actions::SENSITIVITY_RANK[$o->get('sensitivity')], Actions::SENSITIVITY_RANK[$n->get('sensitivity')])];
        $out[] = ['tags', self::setRel($o->get('tags') ?? [], $n->get('tags') ?? [])];
        $out[] = ['provenance_min', self::rankRel(-self::provRank($o->get('provenance_min')), -self::provRank($n->get('provenance_min')))];
        if (!self::same($o, $n, 'unit')) {
            $out[] = ['unit', 'inc'];
        }
        $out[] = ['accumulates', self::setRel($o->get('accumulates') ?? [], $n->get('accumulates') ?? [])];
        if (!self::same($o, $n, 'default') || !self::same($o, $n, 'principal_neutral_default')) {
            $out[] = ['default', 'inc'];
        }
        return $out;
    }

    private static function textDiffers(Obj $o, Obj $n): bool
    {
        foreach (['title', 'description', 'compensates'] as $k) {
            if (!self::same($o, $n, $k)) {
                return true;
            }
        }
        return false;
    }

    private static function profRel(array $a, array $b): string
    {
        return Actions::leq($a, $b) ? (Actions::leq($b, $a) ? 'eq' : 'narrow') : (Actions::leq($b, $a) ? 'widen' : 'inc');
    }

    /**
     * The semantic diff of $next against $prev (two versions of one verb): {class, reasons}. Throws diff_verb for two different verbs.
     *
     * @return array{class:string,reasons:list<string>}
     */
    public static function diffDefs(Obj $prev, Obj $next, ?array $reg = null, ?\Closure $verifier = null): array
    {
        $reg ??= Actions::coreRegistry();
        if ($prev->get('verb') !== $next->get('verb')) {
            throw new ActionKitError('diff_verb', "diff compares two versions of one verb, not '" . Js::str($prev->get('verb')) . "' and '" . Js::str($next->get('verb')) . "'");
        }
        $o = Actions::normalize($prev);
        $n = Actions::normalize($next);
        $rels = [];
        $text = self::textDiffers($o, $n);
        $rels[] = ['effects', self::setRel($o->get('effects'), $n->get('effects'))];
        $rels[] = ['params.accepted_calls', self::callSetRel($o->get('params'), $n->get('params'))];
        $names = $o->get('params')->keys();
        sort($names, SORT_STRING);
        foreach ($names as $name) {
            if ($n->get('params')->has($name)) {
                foreach (self::paramAttrRels($o->get('params')->get($name), $n->get('params')->get($name)) as [$k, $r]) {
                    $rels[] = ["params.$name.$k", $r];
                }
            }
        }
        $eo = ActionsDerive::effectiveWith($prev, $reg, $verifier);
        $en = ActionsDerive::effectiveWith($next, $reg, $verifier);
        $rels[] = ['traits', self::setRel(Actions::closure($reg, $eo['hint']['traits']), Actions::closure($reg, $en['hint']['traits']))];
        $rels[] = ['profile', self::profRel($eo['hint']['eff'], $en['hint']['eff'])];
        $rels[] = ['confirmation', self::rankRel($eo['confirmed'] ? 0 : 1, $en['confirmed'] ? 0 : 1)];
        $rels[] = ['effective.traits', self::setRel(Actions::closure($reg, $eo['traits']), Actions::closure($reg, $en['traits']))];
        $rels[] = ['effective.profile', self::profRel($eo['eff'], $en['eff'])];
        $rels[] = ['reversibility', self::rankRel(Actions::REV_RANK[Actions::worstReversibility($o->get('reversibility'), $o->get('params'))], Actions::REV_RANK[Actions::worstReversibility($n->get('reversibility'), $n->get('params'))])];
        $rels[] = ['blast', self::rankRel((float)Js::num($o->get('blast')->get('ppm')), (float)Js::num($n->get('blast')->get('ppm')))];
        $oi = $o->get('idempotency');
        $ni = $n->get('idempotency');
        $idem = $oi->get('mode') === 'key_param' && $ni->get('mode') === 'key_param' && $oi->get('param') !== $ni->get('param')
            ? 'inc' : self::rankRel(self::IDEM_RANK[$oi->get('mode')], self::IDEM_RANK[$ni->get('mode')]);
        $rels[] = ['idempotency', $idem];
        $rels[] = ['context', self::setRel($o->get('context'), $n->get('context'))];
        $se = static fn(Obj $x): array => array_map(static fn(Obj $s): string => $s->get('target') . '|' . $s->get('kind'), $x->get('side_effects'));
        $rels[] = ['side_effects', self::setRel($se($o), $se($n))];
        $orr = $o->get('resource');
        $nrr = $n->get('resource');
        if (self::sjv($orr->get('id')) === self::sjv($nrr->get('id'))) {
            $resId = 'eq';
        } elseif (ActionsIdPattern::idPatternContains($orr->get('id'), $nrr->get('id'))) {
            $resId = 'narrow';
        } elseif (ActionsIdPattern::idPatternContains($nrr->get('id'), $orr->get('id'))) {
            $resId = 'widen';
        } else {
            $resId = 'inc';
        }
        $rels[] = ['resource.id', $orr->get('type') !== $nrr->get('type') ? 'inc' : $resId];
        $rels[] = ['resource.scope', self::rankRel(-self::SCOPE_RANK[$orr->get('scope')], -self::SCOPE_RANK[$nrr->get('scope')])];
        $ar = self::setRel($o->get('aliases'), $n->get('aliases')); // new aliases widen what natural language can reach
        $rels[] = ['aliases', $ar === 'narrow' ? 'widen' : ($ar === 'widen' ? 'narrow' : $ar)];
        $rels[] = ['bindings', self::sjv($o->get('bindings')) === self::sjv($n->get('bindings')) ? 'eq' : 'inc'];

        $diffs = array_values(array_filter($rels, static fn(array $x) => $x[1] !== 'eq'));
        $reasons = array_map(static fn(array $x): string => $x[0] . ': ' . ($x[1] === 'inc' ? 'incomparable' : $x[1]), $diffs);
        if ($text) {
            $reasons[] = 'text: title, description or compensates changed';
        }
        sort($reasons, SORT_STRING);
        $has = static fn(string $r): bool => array_filter($diffs, static fn(array $x) => $x[1] === $r) !== [];
        $cls = $has('inc') || ($has('narrow') && $has('widen')) ? 'incomparable' : ($has('widen') ? 'widen' : ($has('narrow') ? 'narrow' : 'equal'));
        return ['class' => $cls, 'reasons' => $reasons];
    }

    /** Does a pin follow this change on its own (no principal)? */
    public static function diffIsFree(string $c): bool
    {
        return $c === 'equal' || $c === 'narrow';
    }

    // ---- the authoring diff (defdiff.ts) -----------------------------------------------------------------------------------

    private static function numStr(mixed $v): string
    {
        return IntentWb::jsStr($v === null ? JsUndefined::U : $v);
    }

    private static function pl(mixed $v): int
    {
        if ($v === null) {
            return count(Actions::PROVENANCE);
        }
        $i = array_search($v, Actions::PROVENANCE, true);
        return $i === false ? -1 : $i;
    }

    private static function sensFloor(mixed $r): int
    {
        return is_string($r) && isset(Actions::ROLE_SENSITIVITY_FLOOR[$r]) ? Actions::SENSITIVITY_RANK[Actions::ROLE_SENSITIVITY_FLOOR[$r]] : 0;
    }

    /** @param list<string> $wide @param list<string> $narrow @param list<string> $incomp */
    private static function paramDiff(string $k, Obj $x, Obj $y, array &$wide, array &$narrow, array &$incomp): void
    {
        $num = static function (string $f, bool $lowerIsWider) use ($k, $x, $y, &$wide, &$narrow): void {
            $o = $x->get($f);
            $n = $y->get($f);
            $fo = $o === null ? null : (float)Js::num($o);
            $fn = $n === null ? null : (float)Js::num($n);
            if ($fo === $fn || ($fo !== null && $fn !== null && $fo == $fn)) {
                return;
            }
            $rank = static fn(?float $v): float => $v ?? ($lowerIsWider ? -INF : INF);
            $widerNew = $lowerIsWider ? $rank($fn) < $rank($fo) : $rank($fn) > $rank($fo);
            $msg = "param $k: $f " . self::numStr($o) . ' to ' . self::numStr($n);
            if ($widerNew) {
                $wide[] = $msg;
            } else {
                $narrow[] = $msg;
            }
        };
        if ($x->get('type') !== $y->get('type')) {
            $incomp[] = "param $k: type changed";
        }
        $num('min', true);
        $num('max', false);
        $num('max_len', false);
        $num('max_items', false);
        $num('min_items', true);
        if (Js::stringify($x->get('unit')) !== Js::stringify($y->get('unit'))) {
            $incomp[] = "param $k: unit changed";
        }
        $vo = $x->get('values');
        $vn = $y->get('values');
        if ($vo !== null || $vn !== null) {
            if ($vo === null) {
                $narrow[] = "param $k: values restricted";
            } elseif ($vn === null) {
                $wide[] = "param $k: values unrestricted";
            } else {
                $added = array_values(array_filter($vn, static fn($v) => !in_array($v, $vo, true)));
                $removed = array_values(array_filter($vo, static fn($v) => !in_array($v, $vn, true)));
                if ($added) {
                    $wide[] = "param $k: values added (" . implode(', ', array_map(static fn($v) => Js::str($v), $added)) . ')';
                }
                if ($removed) {
                    $narrow[] = "param $k: values removed (" . implode(', ', array_map(static fn($v) => Js::str($v), $removed)) . ')';
                }
            }
        }
        if ($x->get('required') === true && $y->get('required') === false) {
            $wide[] = "param $k: required to optional";
        }
        if ($x->get('required') === false && $y->get('required') === true) {
            $narrow[] = "param $k: optional to required";
        }
        if (self::pl($y->get('provenance_min')) > self::pl($x->get('provenance_min'))) {
            $wide[] = "param $k: provenance_min loosened";
        } elseif (self::pl($y->get('provenance_min')) < self::pl($x->get('provenance_min'))) {
            $narrow[] = "param $k: provenance_min tightened";
        }
        $sx = Actions::SENSITIVITY_RANK[Actions::effectiveParamSensitivity($x)];
        $sy = Actions::SENSITIVITY_RANK[Actions::effectiveParamSensitivity($y)];
        if ($sy < $sx) {
            $wide[] = "param $k: sensitivity lowered";
        } elseif ($sy > $sx) {
            $narrow[] = "param $k: sensitivity raised";
        }
        if ($x->get('role') !== $y->get('role')) {
            $fy = self::sensFloor($y->get('role'));
            $fx = self::sensFloor($x->get('role'));
            if ($fy < $fx) {
                $wide[] = "param $k: role changed to a lower-floor role";
            } elseif ($fy > $fx) {
                $narrow[] = "param $k: role changed to a higher-floor role";
            } else {
                $incomp[] = "param $k: role changed";
            }
        }
    }

    /**
     * {class, breaking, reasons}: anything not shown to be no wider is widening. A renamed verb is a breaking widen.
     *
     * @return array{class:string,breaking:bool,reasons:list<string>}
     */
    public static function diffDefsAuthoring(Obj $a, Obj $b, array $reg): array
    {
        if ($a->get('verb') !== $b->get('verb')) {
            return ['class' => 'widen', 'breaking' => true, 'reasons' => ['verb renamed: removed + added (grants on the old verb do not follow)']];
        }
        $wide = [];
        $narrow = [];
        $incomp = [];
        $breaking = false;
        $na = Actions::normalize($a);
        $nb = Actions::normalize($b);
        $ea = ActionsDerive::effectiveWith($a, $reg)['hint'];
        $eb = ActionsDerive::effectiveWith($b, $reg)['hint'];
        if (!Actions::leq($ea['eff'], $eb['eff'])) {
            $wide[] = 'the effective profile is not at least the old one';
        } elseif (!ActionsEffective::profileEq($ea['eff'], $eb['eff'])) {
            $narrow[] = 'the effective profile rose';
        }
        foreach ($na->get('effects') as $e) {
            if (!in_array($e, $nb->get('effects'), true)) {
                $wide[] = "effect $e removed";
            }
        }
        foreach ($nb->get('effects') as $e) {
            if (!in_array($e, $na->get('effects'), true)) {
                $narrow[] = "effect $e added";
            }
        }
        foreach ($na->get('traits') as $t) {
            if (!in_array($t, $nb->get('traits'), true)) {
                $wide[] = "declared trait $t removed";
            }
        }
        foreach ($nb->get('traits') as $t) {
            if (!in_array($t, $na->get('traits'), true)) {
                $narrow[] = "declared trait $t added";
            }
        }
        $ra = Actions::worstReversibility($na->get('reversibility'), $na->get('params'));
        $rb = Actions::worstReversibility($nb->get('reversibility'), $nb->get('params'));
        if (Actions::REV_RANK[$rb] < Actions::REV_RANK[$ra]) {
            $wide[] = "reversibility lowered ($ra to $rb)";
        } elseif (Actions::REV_RANK[$rb] > Actions::REV_RANK[$ra]) {
            $narrow[] = "reversibility raised ($ra to $rb)";
        }
        $ba = (float)Js::num($na->get('blast')->get('ppm'));
        $bb = (float)Js::num($nb->get('blast')->get('ppm'));
        if ($bb < $ba) {
            $wide[] = 'blast lowered';
        } elseif ($bb > $ba) {
            $narrow[] = 'blast raised';
        }
        $idem = static fn(string $m): int => $m === 'none' ? 0 : 1;
        $ia = $idem($na->get('idempotency')->get('mode'));
        $ib = $idem($nb->get('idempotency')->get('mode'));
        if ($ib < $ia) {
            $wide[] = 'idempotency loosened';
        } elseif ($ib > $ia) {
            $narrow[] = 'idempotency added';
        }
        $ra2 = $na->get('resource');
        $rb2 = $nb->get('resource');
        if ($ra2->get('type') !== $rb2->get('type')) {
            $incomp[] = 'resource type changed';
        }
        if (self::SCOPE_RANK[$rb2->get('scope')] > self::SCOPE_RANK[$ra2->get('scope')]) {
            $wide[] = 'resource scope widened';
        } elseif (self::SCOPE_RANK[$rb2->get('scope')] < self::SCOPE_RANK[$ra2->get('scope')]) {
            $narrow[] = 'resource scope narrowed';
        }
        $inOld = ActionsIdPattern::idPatternContains($ra2->get('id'), $rb2->get('id'));
        $inNew = ActionsIdPattern::idPatternContains($rb2->get('id'), $ra2->get('id'));
        if (!$inOld) {
            $wide[] = 'the resource id pattern is not contained in the old one';
        } elseif (!$inNew) {
            $narrow[] = 'the resource id pattern is narrower';
        }
        foreach ($na->get('params')->keys() as $k) {
            $x = $na->get('params')->get($k);
            $y = $nb->get('params')->get($k);
            if (!$y) {
                $narrow[] = "param $k removed";
                $breaking = true;
                continue;
            }
            self::paramDiff($k, $x, $y, $wide, $narrow, $incomp);
            if ($x->get('required') === false && $y->get('required') === true) {
                $breaking = true;
            }
        }
        foreach ($nb->get('params')->keys() as $k) {
            if ($na->get('params')->has($k)) {
                continue;
            }
            if (Js::truthy($nb->get('params')->get($k)->get('required'))) {
                $narrow[] = "required param $k added";
                $breaking = true;
            } else {
                $wide[] = "optional param $k added";
            }
        }
        if ($a->get('review')->get('state') === 'confirmed' && $b->get('review')->get('state') !== 'confirmed') {
            $narrow[] = 'review state left confirmed';
        }
        $cls = $incomp || ($wide && $narrow) ? 'incomparable' : ($wide ? 'widen' : ($narrow ? 'narrow' : 'equal'));
        $cmpEq = $cls === 'equal' && Actions::defDigest($a) !== Actions::defDigest($b);
        $reasons = array_merge(
            array_map(static fn($r) => "widen: $r", $wide),
            array_map(static fn($r) => "narrow: $r", $narrow),
            array_map(static fn($r) => "incomparable: $r", $incomp),
            $cmpEq ? ['equal: only title or description changed'] : [],
        );
        return ['class' => $cls, 'breaking' => $breaking, 'reasons' => $reasons];
    }

    /**
     * Per-verb diff of two sets of defs. A removed verb is `removed`; a new verb is `added`.
     *
     * @param list<Obj> $olds @param list<Obj> $news @return list<array<string,mixed>>
     */
    public static function diffPacks(array $olds, array $news, array $reg): array
    {
        $o = [];
        foreach ($olds as $d) {
            $o[$d->get('verb')] = $d;
        }
        $n = [];
        foreach ($news as $d) {
            $n[$d->get('verb')] = $d;
        }
        $verbs = array_map('strval', array_unique(array_merge(array_keys($o), array_keys($n))));
        sort($verbs, SORT_STRING);
        $out = [];
        foreach ($verbs as $v) {
            $x = $o[$v] ?? null;
            $y = $n[$v] ?? null;
            if ($x === null) {
                $out[] = ['verb' => $v, 'class' => 'added', 'breaking' => false, 'reasons' => []];
            } elseif ($y === null) {
                $out[] = ['verb' => $v, 'class' => 'removed', 'breaking' => true, 'reasons' => ['verb removed']];
            } else {
                $out[] = ['verb' => $v] + self::diffDefsAuthoring($x, $y, $reg);
            }
        }
        return $out;
    }
}
