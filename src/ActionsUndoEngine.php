<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDerive.php';
require_once __DIR__ . '/ActionsReview.php';
require_once __DIR__ . '/Approval.php';
require_once __DIR__ . '/Js.php';

/**
 * Undo windows over action definitions, the structural and planning half (native port of the definition-level functions of undo.ts of the
 * reference actions package). The window state machine, tokens and receipts are in Undo.
 */
final class ActionsUndoEngine
{
    /** The class of a reversibility declaration for concrete params (an unmapped or absent value takes `default`, else irreversible). */
    public static function reversibilityFor(Obj $d, ?Obj $params): string
    {
        $r = Actions::normalize($d)->get('reversibility');
        if (is_string($r)) {
            return $r;
        }
        $v = $params !== null && $params->has($r->get('by')) ? $params->get($r->get('by')) : null;
        $k = null;
        if (is_string($v)) {
            $k = $v;
        } elseif (is_bool($v)) {
            $k = $v ? 'true' : 'false';
        } elseif (Js::isNum($v)) {
            $f = Js::num($v);
            if (is_finite($f) && fmod($f, 1.0) == 0.0 && abs($f) <= 9007199254740991 && !($f == 0.0 && fdiv(1.0, $f) < 0)) {
                $k = (string)(int)$f;
            }
        }
        $map = $r->get('map');
        if ($k !== null && $map->has($k)) {
            return $map->get($k);
        }
        return $r->has('default') ? $r->get('default') : 'irreversible';
    }

    /** True when some value of the declaration is `reversible` (a fixed class, a map value or the default). */
    public static function mayBeReversible(Obj $d): bool
    {
        $r = $d->get('reversibility');
        if ($r === null) {
            return false;
        }
        if (is_string($r)) {
            return $r === 'reversible';
        }
        foreach ($r->get('map')->keys() as $k) {
            if ($r->get('map')->get($k) === 'reversible') {
                return true;
            }
        }
        return $r->get('default') === 'reversible';
    }

    private static function sameType(?Obj $a, Obj $b): bool
    {
        return $a !== null && $a->get('type') === $b->get('type') && Js::stringify($a->get('items')) === Js::stringify($b->get('items'));
    }

    /**
     * Can $comp undo $orig without the agent's help? {ok: true, shape: {copied, target?}} or {ok: false, reason}. Structural only.
     *
     * @return array<string,mixed>
     */
    public static function compensationShape(Obj $orig, Obj $comp): array
    {
        if (Actions::isReadOnly($comp->get('effects'))) {
            return ['ok' => false, 'reason' => 'the compensating action ' . $comp->get('verb') . ' only reads'];
        }
        if ($comp->get('resource')->get('type') !== $orig->get('resource')->get('type')) {
            return ['ok' => false, 'reason' => 'the compensating action ' . $comp->get('verb') . ' acts on ' . $comp->get('resource')->get('type') . ', not ' . $orig->get('resource')->get('type')];
        }
        $nc = Actions::normalize($comp);
        $copied = [];
        $target = null;
        $idem = $nc->get('idempotency')->get('mode') === 'key_param' ? $nc->get('idempotency')->get('param') : null;
        $names = $nc->get('params')->keys();
        usort($names, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        foreach ($names as $name) {
            $p = $nc->get('params')->get($name);
            if ($name === $idem) {
                continue;
            }
            if (self::sameType($orig->get('params')->get($name), $p)) {
                $copied[] = $name;
                continue;
            }
            if (!$p->get('required')) {
                continue;
            }
            if ($p->get('role') === 'id.' . $comp->get('resource')->get('type') && $target === null) {
                $target = $name;
                continue;
            }
            return ['ok' => false, 'reason' => 'the compensating action ' . $comp->get('verb') . " needs '$name', which neither the original call nor its result supplies"];
        }
        $shape = ['copied' => $copied];
        if ($target !== null) {
            $shape['target'] = $target;
        }
        return ['ok' => true, 'shape' => $shape];
    }

    /**
     * plan(op) -> {def_digest, compensation, render, render_digest} or null. Answers only from CONFIRMED definitions (a valid signed review by a pinned
     * reviewer key; no pins: nothing is undoable), exact verb match only. Never throws: anything undecidable is not undoable.
     *
     * @param list<Obj> $defs
     * @return \Closure(Obj):?Obj
     */
    public static function undoEngine(array $defs, mixed $pins, ?array $registry = null): \Closure
    {
        $reg = $registry ?: Actions::coreRegistry();
        $byVerb = [];
        foreach ($defs as $d) {
            if (!isset($byVerb[$d->get('verb')])) {
                $byVerb[$d->get('verb')] = $d;
            }
        }
        $review = $pins === null ? null : ActionsReview::attestationVerifier($reg, $pins);
        $confirmed = static function (Obj $d) use ($review): bool {
            try {
                return $review !== null && $review($d) === true;
            } catch (\Throwable) {
                return false;
            }
        };
        return static function (Obj $op) use ($byVerb, $reg, $review, $confirmed): ?Obj {
            try {
                $d = $byVerb[$op->get('verb')] ?? null;
                $params = $op->get('params') instanceof Obj ? $op->get('params') : new Obj();
                if ($d === null || !$confirmed($d) || Actions::isReadOnly($d->get('effects')) || $d->get('compensates') === null) {
                    return null;
                }
                if (ActionsDerive::effectiveWith($d, $reg, $review)['eff']['rev'] !== 'reversible' || self::reversibilityFor($d, $params) !== 'reversible') {
                    return null;
                }
                $c = $byVerb[$d->get('compensates')] ?? null;
                if ($c === null || !$confirmed($c)) {
                    return null;
                }
                $s = self::compensationShape($d, $c);
                if (!$s['ok']) {
                    return null;
                }
                $cparams = new Obj();
                $nc = Actions::normalize($c);
                foreach ($s['shape']['copied'] as $k) {
                    if ($params->has($k)) {
                        $cparams->set($k, $params->get($k));
                    } elseif ($nc->get('params')->get($k)->get('required')) {
                        return null;
                    }
                }
                $render = Approval::render($d, $params, true);
                $comp = Obj::of(['verb' => $c->get('verb'), 'params' => $cparams, 'def_digest' => Actions::defDigest($c)]);
                if (isset($s['shape']['target'])) {
                    $comp->set('target_param', $s['shape']['target']);
                }
                return Obj::of(['def_digest' => Actions::defDigest($d), 'compensation' => $comp, 'render' => $render, 'render_digest' => Approval::renderDigest($render)]);
            } catch (\Throwable) {
                return null;
            }
        };
    }
}
