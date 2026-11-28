<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/WalletOmega.php';

/**
 * The outcome space derived from a site's signed action schema (schema.ts + the wallet-floor helpers of the core action-schema):
 * dimensions only for parameters whose effective sensitivity (after the wallet floor) is material or critical, canonical projections
 * for boolean / set / array parameters, and default sets for silent parameters. Values are the parsed-JSON model; options are an
 * Obj or an assoc array with the reference's names (`schema`, `verbs`, `slots`, `policies`, `confirmed`, `floor`, `domains`).
 */
final class IntentSchema
{
    public const WALLET_FLOOR_PREFIXES = ['money.', 'party.', 'contact.', 'person.', 'credential.'];
    public const WALLET_FLOOR_EXACT = ['text.message'];
    private const REV_RANK = ['reversible' => 0, 'rate_limited' => 1, 'irreversible' => 2];

    private static function cmp(string $a, string $b): int
    {
        return IntentV2::compareUtf8($a, $b);
    }

    private static function nz(mixed $x, mixed $d): mixed
    {
        return $x === null ? $d : $x;
    }

    private static function floorApplies(mixed $semantic, mixed $floor): bool
    {
        $pre = self::nz(Js::opt($floor, 'prefixes'), self::WALLET_FLOOR_PREFIXES);
        $ex = self::nz(Js::opt($floor, 'exact'), self::WALLET_FLOOR_EXACT);
        if (in_array($semantic, Js::spread($ex), true)) {
            return true;
        }
        foreach (Js::spread($pre) as $p) {
            if (!is_string($semantic)) {
                throw new \TypeError('semantic.startsWith is not a function');
            }
            if (str_starts_with($semantic, (string)$p)) {
                return true;
            }
        }
        return false;
    }

    /** A site `free` on a floored semantic type becomes `material`. */
    public static function effectiveSensitivity(mixed $d, mixed $floor = null): mixed
    {
        $s = Js::get($d, 'sensitivity');
        return $s === 'free' && self::floorApplies(Js::opt($d, 'semantic'), $floor) ? 'material' : $s;
    }

    private static function rank(mixed $r): ?int
    {
        return is_string($r) ? (self::REV_RANK[$r] ?? null) : null;
    }

    /** rev(v) = max over outcomes of the declared reversibility (the conservative projection). */
    public static function verbReversibility(mixed $v): mixed
    {
        $rb = Js::opt($v, 'reversibility_by');
        if (!Js::truthy($rb)) {
            return self::nz(Js::opt($v, 'reversibility'), Js::opt($v, 'kind') === 'read' ? 'reversible' : 'irreversible');
        }
        $d = Js::opt(Js::get($v, 'params'), (string)Js::opt($rb, 'param'));
        $map = Js::opt($rb, 'map');
        $mapped = [];
        foreach (Jsx::keys($map) as $k) {
            $mapped[] = Js::opt($map, $k);
        }
        $type = Js::opt($d, 'type');
        $domain = $type === 'boolean' ? ['true', 'false'] : ($type === 'string' && Js::truthy(Js::opt($d, 'values')) ? Js::spread(Js::opt($d, 'values')) : null);
        $covered = $domain !== null;
        foreach ($domain ?? [] as $x) {
            if (!(is_string($x) && $map instanceof Obj && $map->has($x))) {
                $covered = false;
            }
        }
        $items = $covered ? $mapped : [...$mapped, self::nz(Js::opt($rb, 'default'), 'irreversible')];
        $a = 'reversible';
        foreach ($items as $b) {
            $rb2 = self::rank($b);
            if ($rb2 !== null && $rb2 > self::rank($a)) {
                $a = $b;
            }
        }
        return $a;
    }

    /** Every override the wallet floor makes on a schema. @return list<Obj> */
    public static function walletFloorOverrides(mixed $doc, mixed $floor = null): array
    {
        $out = [];
        foreach (Js::get($doc, 'verbs') as $v) {
            $params = Js::get($v, 'params');
            $paths = Jsx::keys($params);
            usort($paths, self::cmp(...));
            foreach ($paths as $path) {
                $d = Js::opt($params, $path);
                $eff = self::effectiveSensitivity($d, $floor);
                if ($eff !== Js::get($d, 'sensitivity')) {
                    $out[] = Obj::of(['verb' => Js::opt($v, 'verb'), 'path' => $path, 'semantic' => Js::opt($d, 'semantic'),
                        'declared' => Js::opt($d, 'sensitivity'), 'effective' => $eff]);
                }
            }
        }
        return $out;
    }

    private static function usesCanon(mixed $d): bool
    {
        $t = Js::opt($d, 'type');
        return $t === 'boolean' || $t === 'set' || $t === 'array';
    }

    /** The canonical text a value of a canon-projected parameter has. */
    public static function canonValue(mixed $d, mixed $x): string
    {
        $t = Js::opt($d, 'type');
        if ($t === 'boolean') {
            return $x === true ? 'true' : 'false';
        }
        if ($t === 'set') {
            $xs = Js::spread($x);
            usort($xs, self::cmp(...));
            return Json::canonicalizeNative($xs);
        }
        return Json::canonicalizeNative($x);
    }

    private static function f(mixed $x): float
    {
        return Js::num($x) ?? Jsx::toNum($x);
    }

    /** Number.isSafeInteger by value (-0 included). */
    private static function isSafeInteger(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= 9007199254740991.0;
    }

    private static function plainNum(mixed $x): mixed
    {
        return WalletOmega::plain($x);
    }

    /** @return array{omega:Obj,overrides:list<Obj>,defaults:list<Obj>,canonOf:Obj} */
    public static function deriveOmegaFromSchema(mixed $o): array
    {
        $schemaVerbs = Js::get(Js::get($o, 'schema'), 'verbs');
        $slots = Js::opt($o, 'slots');
        $verbNames = Js::opt($o, 'verbs');
        if ($verbNames === null) {
            $verbNames = [];
            foreach ($schemaVerbs as $v) {
                if (Js::opt($v, 'kind') === 'write' && !in_array(Js::opt($v, 'verb'), $verbNames, true)) {
                    $verbNames[] = Js::opt($v, 'verb');
                }
            }
            foreach (Js::opt($slots, 'verbs') ?? [] as $v) {
                if (!in_array($v, $verbNames, true)) {
                    $verbNames[] = $v;
                }
            }
        }
        $base = IntentOmega::deriveOmega(['policies' => self::nz(Js::opt($o, 'policies'), []), 'slots' => $slots, 'extraVerbs' => $verbNames]);
        $floor = Js::opt($o, 'floor');
        $confirmed = Js::opt($o, 'confirmed');
        $defaults = [];
        $canonOf = new Obj();
        $verbs = [];
        $sortedNames = array_values($verbNames);
        usort($sortedNames, self::cmp(...));
        foreach ($sortedNames as $verb) {
            $decl = null;
            foreach ($schemaVerbs as $v) {
                if (Js::opt($v, 'verb') === $verb) {
                    $decl = $v;
                    break;
                }
            }
            if ($decl === null) {
                continue; // an undeclared verb is never a cell
            }
            $lits = null;
            foreach (Js::opt($base, 'verbs') as $v) {
                if (Js::opt($v, 'verb') === $verb) {
                    $lits = $v;
                    break;
                }
            }
            $litDims = $lits === null ? [] : Js::opt($lits, 'dims');
            $dims = [];
            foreach ($litDims as $d) {
                if (!str_starts_with((string)Js::opt($d, 'path'), 'action.params.')) {
                    $dims[] = $d;
                }
            }
            $params = Js::opt($decl, 'params');
            $paths = Jsx::keys($params);
            usort($paths, self::cmp(...));
            foreach ($paths as $path) {
                $pd = Js::opt($params, $path);
                if (self::effectiveSensitivity($pd, $floor) === 'free') {
                    continue;
                }
                $lit = null;
                foreach ($litDims as $d) {
                    if (Js::opt($d, 'path') === $path) {
                        $lit = $d;
                        break;
                    }
                }
                $silent = $lit === null;
                $conf = Js::opt($confirmed, $path);
                $defaultSet = $conf === null ? [] : Js::spread($conf);
                if (Js::opt($pd, 'principal_neutral_default') === true && Js::has($pd, 'default')) {
                    $defaultSet[] = Js::opt($pd, 'default');
                }
                if (Js::opt($pd, 'type') === 'integer') {
                    $cuts = []; // a Set<number>: keyed by the JS number text (-0 is 0, no ini-precision collisions), the first entry kept
                    if ($lit !== null && Js::opt($lit, 'kind') === 'num') {
                        foreach (Js::opt($lit, 'cuts') as $c) {
                            $cuts[IntentWb::jsNumStr(self::f($c))] ??= $c;
                        }
                    }
                    foreach ($defaultSet as $x) {
                        if (Js::isNum($x) && self::isSafeInteger($x)) {
                            $cuts[IntentWb::jsNumStr(self::f($x))] ??= $x;
                        }
                    }
                    $sorted = array_values($cuts);
                    usort($sorted, fn($a, $b) => self::f($a) <=> self::f($b));
                    $maxCut = count($sorted) > 0 ? self::f($sorted[count($sorted) - 1]) : 0.0;
                    $dom = Js::opt(Js::opt($o, 'domains'), $path);
                    $lo = self::nz(Js::opt($dom, 'lo'), self::nz(Js::opt($pd, 'min'), min(0.0, count($sorted) > 0 ? self::f($sorted[0]) - 1 : 0.0)));
                    $hi = self::nz(Js::opt($dom, 'hi'), self::nz(Js::opt($pd, 'max'), max(10.0, 2 * $maxCut, $maxCut + 10)));
                    $flo = self::f($lo);
                    $fhi = self::f($hi);
                    $kept = array_values(array_filter($sorted, fn($c) => self::f($c) >= $flo && self::f($c) <= $fhi));
                    $dims[] = Obj::of(['kind' => 'num', 'path' => $path, 'lo' => self::plainNum($lo), 'hi' => self::plainNum($hi),
                        'cuts' => array_map(self::plainNum(...), $kept), 'dist' => $flo >= 0 ? 'loguniform' : 'uniform']);
                    $nums = array_values(array_filter($defaultSet, fn($x) => Js::isNum($x)));
                    if ($silent && count($nums) === 1) {
                        $defaults[] = Obj::of(['verb' => $verb, 'path' => $path, 'min' => self::plainNum($nums[0]), 'max' => self::plainNum($nums[0])]);
                    }
                    continue;
                }
                $canon = self::usesCanon($pd);
                $dimPath = $canon ? 'env.canon.' . substr((string)$path, strlen('action.params.')) : $path;
                if ($canon) {
                    $canonOf->set($dimPath, $path);
                }
                $exacts = [];
                $prefixes = [];
                if ($lit !== null && Js::opt($lit, 'kind') === 'cat') {
                    foreach (Js::opt($lit, 'values') as $v) {
                        if (Js::opt($v, 'kind') === 'exact') {
                            $exacts[(string)Js::opt($v, 'value')] = true;
                        } elseif (Js::opt($v, 'kind') === 'prefix') {
                            $prefixes[(string)Js::opt($v, 'value')] = true;
                        }
                    }
                }
                if (Js::opt($pd, 'type') === 'string' && Js::truthy(Js::opt($pd, 'values'))) {
                    foreach (Js::spread(Js::opt($pd, 'values')) as $v) {
                        $exacts[(string)$v] = true;
                    }
                }
                if (Js::opt($pd, 'type') === 'boolean') {
                    $exacts['false'] = true;
                    $exacts['true'] = true;
                }
                $defTexts = array_map(fn($x) => $canon ? self::canonValue($pd, $x) : Js::str($x), $defaultSet);
                foreach ($defTexts as $t) {
                    $exacts[$t] = true;
                }
                $ex = array_map('strval', array_keys($exacts));
                usort($ex, self::cmp(...));
                $pr = array_map('strval', array_keys($prefixes));
                usort($pr, self::cmp(...));
                $values = [];
                foreach ($ex as $x) {
                    $values[] = Obj::of(['kind' => 'exact', 'value' => $x]);
                }
                foreach ($pr as $x) {
                    $values[] = Obj::of(['kind' => 'prefix', 'value' => $x]);
                }
                $values[] = Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER]);
                $dims[] = Obj::of(['kind' => 'cat', 'path' => $dimPath, 'values' => $values]);
                if ($silent && count($defTexts) > 0) {
                    $u = array_map('strval', array_keys(array_flip($defTexts)));
                    usort($u, self::cmp(...));
                    $defaults[] = Obj::of(['verb' => $verb, 'path' => $dimPath, 'oneOf' => $u]);
                }
            }
            usort($dims, fn($a, $b) => self::cmp((string)Js::opt($a, 'path'), (string)Js::opt($b, 'path')));
            $verbs[] = Obj::of(['verb' => $verb, 'reversibility' => self::verbReversibility($decl), 'weight' => 0, 'dims' => $dims]);
        }
        foreach ($verbs as $v) {
            $v->set('weight', 1 / (count($verbs) ?: 1));
        }
        $declared = array_values(array_filter($schemaVerbs, fn($v) => in_array(Js::opt($v, 'verb'), $verbNames, true)));
        return [
            'omega' => Obj::of(['v' => 1, 'verbs' => $verbs, 'approximate' => Js::opt($base, 'approximate')]),
            'overrides' => self::walletFloorOverrides(Obj::of(['verbs' => $declared]), $floor),
            'defaults' => $defaults,
            'canonOf' => $canonOf,
        ];
    }
}
