<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentHistory.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentSchema.php';
require_once __DIR__ . '/WalletOmega.php';

/**
 * Trajectory intent as ordinary intent (trajectory.ts): the augmented outcome space (one numeric dimension per accumulator, one
 * categorical dimension per monitor), the verifier-computed lift of an action, the trajectory step rule and the wallet's default
 * accumulators. Values are the parsed-JSON model (Obj, lists, strings, numbers); Psi is `{accumulators: [..], monitors: [..]}`; a
 * history is a list of Obj events; a candidate is an Obj `{verb, resource, params, t}` (plus `id` for a step).
 */
final class IntentTrajectory
{
    public const ACC_DIM_PREFIX = 'env.acc.';
    public const MON_DIM_PREFIX = 'env.mon.';

    public static function accDimPath(string $id): string
    {
        return self::ACC_DIM_PREFIX . $id . '.post';
    }

    public static function monDimPath(string $id): string
    {
        return self::MON_DIM_PREFIX . $id . '.state';
    }

    /** The v2 dimension kind of a path (a naming convention over the v1 dimensions). */
    public static function dimKindOf(string $path): string
    {
        foreach ([['action.params.', 'param'], [self::ACC_DIM_PREFIX, 'acc'], [self::MON_DIM_PREFIX, 'mon'], ['env.canon.', 'canon'],
            ['env.world.', 'world'], ['env.rel.', 'rel'], ['env.prov.', 'prov'], ['env.class.', 'class']] as [$prefix, $kind]) {
            if (str_starts_with($path, $prefix)) {
                return $kind;
            }
        }
        return 'other';
    }

    private static function cmp(string $a, string $b): int
    {
        return IntentV2::compareUtf8($a, $b);
    }

    private static function f(mixed $x): float
    {
        return (float)Js::num($x);
    }

    private static function predicateVerbs(mixed $p): array
    {
        $v = Js::opt($p, 'verb');
        return is_array($v) && array_is_list($v) ? $v : [$v];
    }

    private static function isSafeInteger(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= 9007199254740991.0;
    }

    private static function selects(mixed $a, string $verb, mixed $schema): bool
    {
        $sel = Js::opt($a, 'sel');
        $verbs = Js::opt($sel, 'verbs');
        if (is_array($verbs) && in_array($verb, $verbs, true)) {
            return true;
        }
        if (Js::has($sel, 'accumulates_into')) {
            $v = null;
            foreach ($schema === null ? [] : Js::opt($schema, 'verbs') as $x) {
                if (Js::opt($x, 'verb') === $verb) {
                    $v = $x;
                    break;
                }
            }
            return $v !== null && count(IntentV2::accumulationParams($v, Js::opt($sel, 'accumulates_into'))) > 0;
        }
        return false;
    }

    /** The augmented space from the space and Psi (wallet-held accumulators are not dimensions). Options: `cuts`, `scope`, `schema`. */
    public static function augmentOmega(mixed $omega, mixed $psi, mixed $opts = null): Obj
    {
        $scopeSelected = Js::opt($opts, 'scope') === 'selected';
        $schema = Js::opt($opts, 'schema');
        $allCuts = Js::opt($opts, 'cuts');
        $verbs = [];
        foreach (Js::opt($omega, 'verbs') as $vs) {
            $verb = Js::opt($vs, 'verb');
            $extra = [];
            foreach (Js::opt($psi, 'accumulators') as $a) {
                if (Js::opt(Js::opt($a, 'holder'), 'kind') === 'wallet') {
                    continue;
                }
                if ($scopeSelected && !self::selects($a, $verb, $schema)) {
                    continue;
                }
                $id = Js::opt($a, 'id');
                if (!Js::has($a, 'domain_max')) {
                    throw new \InvalidArgumentException("augmentOmega: accumulator '" . Js::str($id) . "' needs domain_max (A_psi) to be a dimension of the augmented space");
                }
                $dm = Js::opt($a, 'domain_max');
                $raw = Js::opt($allCuts, (string)$id);
                $cuts = [];
                foreach ($raw === null ? [] : Js::spread($raw) as $c) {
                    if (self::isSafeInteger($c) && self::f($c) >= 0 && self::f($c) <= self::f($dm)) {
                        $cuts[(string)(self::f($c) + 0.0)] = WalletOmega::plain($c);
                    }
                }
                $cuts = array_values($cuts);
                usort($cuts, fn($x, $y) => self::f($x) <=> self::f($y));
                $extra[] = Obj::of(['kind' => 'num', 'path' => self::accDimPath((string)$id), 'lo' => 0, 'hi' => WalletOmega::plain($dm), 'cuts' => $cuts, 'dist' => 'loguniform']);
            }
            foreach (Js::opt($psi, 'monitors') as $m) {
                if ($scopeSelected) {
                    $q = Js::opt($m, 'q');
                    $in = Js::truthy($q) ? (in_array($verb, self::predicateVerbs($q), true) || in_array('*', self::predicateVerbs($q), true)) : true;
                    if (!$in) {
                        continue;
                    }
                }
                $extra[] = Obj::of(['kind' => 'cat', 'path' => self::monDimPath((string)Js::opt($m, 'id')),
                    'values' => array_map(static fn($v) => Obj::of(['kind' => 'exact', 'value' => $v]), IntentV2::monitorStates($m))]);
            }
            $dims = [];
            foreach (Js::opt($vs, 'dims') as $d) {
                $k = self::dimKindOf((string)Js::opt($d, 'path'));
                if ($k !== 'acc' && $k !== 'mon') {
                    $dims[] = $d;
                }
            }
            array_push($dims, ...$extra);
            usort($dims, fn($x, $y) => self::cmp((string)Js::opt($x, 'path'), (string)Js::opt($y, 'path')));
            $out = Jsx::spread($vs);
            $out->set('dims', $dims);
            $verbs[] = $out;
        }
        return Obj::of(['v' => 1, 'approximate' => array_values(Js::opt($omega, 'approximate')), 'verbs' => $verbs]);
    }

    private static function findVerb(mixed $space, mixed $verb): mixed
    {
        foreach (Js::opt($space, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === $verb) {
                return $v;
            }
        }
        return null;
    }

    /** lift(history, action, t) as an outcome of the augmented space; null when the verb is not in it. @param list<Obj> $history */
    public static function liftAction(mixed $omegaTilde, mixed $psi, array $history, mixed $cand, mixed $schema = null): ?Obj
    {
        $verb = Js::opt($cand, 'verb');
        $vs = self::findVerb($omegaTilde, $verb);
        if ($vs === null) {
            return null;
        }
        $decl = $schema === null ? null : self::findVerb($schema, $verb);
        $values = new Obj();
        $params = Js::get($cand, 'params');
        foreach (Js::opt($vs, 'dims') as $d) {
            $path = (string)Js::opt($d, 'path');
            $k = self::dimKindOf($path);
            if ($k === 'param') {
                $name = substr($path, strlen('action.params.'));
                $x = Js::has($params, $name) ? Js::opt($params, $name) : null;
                if (Js::isNum($x) || is_string($x)) {
                    $values->set($path, $x);
                }
            } elseif ($k === 'canon') {
                $name = substr($path, strlen('env.canon.'));
                $pd = $decl === null ? null : Js::opt(Js::opt($decl, 'params'), 'action.params.' . $name);
                if (Js::truthy($pd) && Js::has($params, $name)) {
                    $values->set($path, IntentSchema::canonValue($pd, Js::opt($params, $name)));
                }
            } elseif ($k === 'acc') {
                $id = substr($path, strlen(self::ACC_DIM_PREFIX), -strlen('.post'));
                foreach (Js::opt($psi, 'accumulators') as $a) {
                    if (Js::opt($a, 'id') === $id) {
                        $values->set($path, IntentHistory::accPost($a, $history, $verb, $params, Js::opt($cand, 't'), $schema));
                        break;
                    }
                }
            } elseif ($k === 'mon') {
                $id = substr($path, strlen(self::MON_DIM_PREFIX), -strlen('.state'));
                foreach (Js::opt($psi, 'monitors') as $m) {
                    if (Js::opt($m, 'id') === $id) {
                        $values->set($path, IntentHistory::monitorState($m, $history));
                        break;
                    }
                }
            } elseif ($path === 'action.resource') {
                $values->set($path, Js::opt($cand, 'resource'));
            }
        }
        return Obj::of(['verb' => $verb, 'values' => $values]);
    }

    /** The per-dimension cell of the lift, or null when it lies outside the space (fail closed). @return array{vs:mixed,cell:list<int>}|null */
    public static function liftedCell(mixed $omegaTilde, mixed $o): ?array
    {
        $vs = self::findVerb($omegaTilde, Js::opt($o, 'verb'));
        if ($vs === null) {
            return null;
        }
        $cell = IntentOmega::cellOf($vs, $o);
        return $cell !== null ? ['vs' => $vs, 'cell' => $cell] : null;
    }

    /**
     * Admit the action iff its lift lies in a cell the grant accepts (`$inGrant(verb, cell)`); the history grows by a `reserved` event on admission.
     * @param list<Obj> $history
     * @return array{admitted:bool,history:list<Obj>,lifted:?Obj}
     */
    public static function stepTrajectory(mixed $omegaTilde, mixed $psi, array $history, mixed $cand, \Closure $inGrant, mixed $schema = null): array
    {
        $lifted = self::liftAction($omegaTilde, $psi, $history, $cand, $schema);
        $c = $lifted !== null ? self::liftedCell($omegaTilde, $lifted) : null;
        $ok = $c !== null && (bool)$inGrant(Js::opt($cand, 'verb'), $c['cell']);
        $hist = array_values($history);
        if ($ok) {
            $hist[] = Obj::of(['id' => Js::opt($cand, 'id'), 'verb' => Js::opt($cand, 'verb'), 'resource' => Js::opt($cand, 'resource'),
                'params' => Js::opt($cand, 'params'), 't' => Js::opt($cand, 't'), 'status' => 'reserved']);
        }
        return ['admitted' => $ok, 'history' => $hist, 'lifted' => $lifted];
    }

    /** replace(/[^A-Za-z0-9_]/g, '_') over UTF-16 code units, then slice(0, 58): an astral character is two units. */
    private static function sanitize(string $u): string
    {
        $out = '';
        foreach (preg_split('//u', $u, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) {
            $out .= preg_match('/\A[A-Za-z0-9_]\z/', $ch) === 1 ? $ch : (strlen($ch) === 4 ? '__' : '_');
        }
        return substr($out, 0, 58);
    }

    /**
     * The accumulators the wallet always adds: a per-task spend sum per accumulation unit, a per-verb spend sum for every untagged
     * money.amount parameter, and the wallet-held question counter. Options: `spendDomainMax`, `questionCap`, `holder`.
     * @return list<Obj>
     */
    public static function defaultAccumulators(mixed $schema, mixed $o): array
    {
        $holder = Js::opt($o, 'holder') ?? Obj::of(['kind' => 'site_local']);
        $units = [];
        $untagged = [];
        foreach (Js::get($schema, 'verbs') as $v) {
            $params = Js::get($v, 'params');
            foreach (Jsx::keys($params) as $path) {
                $d = Js::opt($params, $path);
                $into = Js::opt($d, 'accumulates_into');
                $list = $into === null ? [] : Js::spread($into);
                foreach ($list as $u) {
                    $units[(string)$u] = true;
                }
                if (Js::opt($d, 'type') === 'integer' && Js::opt($d, 'semantic') === 'money.amount' && count($list) === 0) {
                    $untagged[] = ['verb' => Js::opt($v, 'verb'), 'path' => $path];
                }
            }
        }
        $dm = WalletOmega::plain(Js::opt($o, 'spendDomainMax'));
        $out = [];
        $us = array_map('strval', array_keys($units));
        usort($us, self::cmp(...));
        foreach ($us as $u) {
            $out[] = Obj::of(['id' => 'spend_' . self::sanitize($u), 'agg' => 'sum', 'unit' => $u, 'sel' => Obj::of(['accumulates_into' => $u]),
                'win' => Obj::of(['kind' => 'task']), 'key' => null, 'domain_max' => $dm, 'holder' => $holder]);
        }
        usort($untagged, fn($a, $b) => self::cmp($a['verb'] . $a['path'], $b['verb'] . $b['path']));
        foreach ($untagged as $x) {
            $id = substr('spend_' . self::sanitize((string)$x['verb']) . '_' . self::sanitize(substr($x['path'], strlen('action.params.'))), 0, 64);
            $out[] = Obj::of(['id' => $id, 'agg' => 'sum', 'val' => $x['path'], 'sel' => Obj::of(['verbs' => [$x['verb']]]),
                'win' => Obj::of(['kind' => 'task']), 'key' => null, 'domain_max' => $dm, 'holder' => $holder]);
        }
        $cap = Js::opt($o, 'questionCap');
        $out[] = Obj::of(['id' => 'questions', 'agg' => 'count', 'sel' => Obj::of(['event' => 'intent_required']), 'win' => Obj::of(['kind' => 'task']),
            'key' => null, 'cap' => $cap === null ? 6 : WalletOmega::plain($cap), 'holder' => Obj::of(['kind' => 'wallet'])]);
        return $out;
    }

    /** The fact line for an accumulator dimension of a cell; `$fmt` defaults to String(x). */
    public static function describeAccCell(mixed $d, mixed $cellIndex, string $label, mixed $thisAction = null, ?\Closure $fmt = null): string
    {
        $fmt ??= static fn($x) => Js::str($x);
        $cells = IntentOmega::numCells($d);
        $i = Js::num($cellIndex);
        if ($i === null || $i < 0 || $i != floor($i) || $i >= count($cells)) {
            throw new \InvalidArgumentException('describeAccCell: no such cell');
        }
        $c = $cells[(int)$i];
        $lo = $c->get('lo');
        $hi = $c->get('hi');
        $range = $lo == $hi ? 'exactly ' . $fmt($lo) : 'between ' . $fmt($lo) . ' and ' . $fmt($hi);
        return $label . ': ' . $range . ($thisAction !== null ? ' (this action: ' . $fmt($thisAction) . ')' : '');
    }

    /** The per-session harm range of a trajectory Monte Carlo estimate is [0, L_max * H_max]. */
    public static function trajectoryHarmRange(mixed $maxSessionLength, mixed $harmMax): float
    {
        $h = Js::num($harmMax);
        if (!(self::isSafeInteger($maxSessionLength) && self::f($maxSessionLength) >= 0) || !($h !== null && $h >= 0)) {
            throw new \InvalidArgumentException('trajectoryHarmRange: bad arguments');
        }
        return self::f($maxSessionLength) * $h;
    }
}
