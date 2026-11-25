<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Outcome-space dimensions filled by the verifier: world facts (env.world.*), provenance (env.prov.*) and attested classifier labels
 * (env.class.*). Every helper only adds a dimension, which refines the space.
 */
final class IntentWorld
{
    public const WORLD_PREFIX = 'env.world.';
    public const PROV_PREFIX = 'env.prov.';
    public const CLASS_PREFIX = 'env.class.';

    private static function plain(mixed $x): mixed
    {
        return WalletOmega::plain($x);
    }

    /** A numeric world dimension env.world.<name> with the given domain {lo, hi, cuts?, dist?} and cuts. */
    public static function worldDim(string $name, mixed $o): Obj
    {
        $o = self::plain($o);
        $lo = Js::opt($o, 'lo');
        $hi = Js::opt($o, 'hi');
        $cuts = [];
        foreach (Js::opt($o, 'cuts') ?? [] as $c) {
            if (!in_array($c, $cuts, false)) {
                $cuts[] = $c;
            }
        }
        $cuts = array_values(array_filter($cuts, static fn($c) => $lo <= $c && $c <= $hi));
        sort($cuts);
        $dist = Js::opt($o, 'dist');
        return Obj::of(['kind' => 'num', 'path' => self::WORLD_PREFIX . $name, 'lo' => $lo, 'hi' => $hi, 'cuts' => $cuts, 'dist' => $dist ?? 'uniform']);
    }

    /** The optimality dimension: excess >= 0, cuts at 0 and at every slack literal. */
    public static function excessDim(string $name, mixed $hi, mixed $slacks = null): Obj
    {
        return self::worldDim($name, Obj::of(['lo' => 0, 'hi' => $hi, 'cuts' => array_merge([0], self::plain($slacks) ?? []), 'dist' => 'loguniform']));
    }

    /** The default slot compiler's optimality constraint: excess <= slack. */
    public static function optimalityCondition(string $name, mixed $slack = 0): Obj
    {
        return Obj::of(['field' => self::WORLD_PREFIX . $name, 'op' => 'lte', 'value' => $slack]);
    }

    /** env.prov.<path> with the cells {first_party}, {trusted} and the OTHER cell = the tainted values. */
    public static function provenanceDim(string $paramPath): Obj
    {
        return Obj::of(['kind' => 'cat', 'path' => self::PROV_PREFIX . $paramPath, 'values' => [
            Obj::of(['kind' => 'exact', 'value' => 'first_party']), Obj::of(['kind' => 'exact', 'value' => 'trusted']),
            Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER])]]);
    }

    /** env.class.<id> over the classifier's closed label set (the OTHER cell is never output). @param list<string> $labels */
    public static function classifierDim(string $id, array $labels): Obj
    {
        $uniq = array_values(array_unique($labels));
        usort($uniq, [IntentWb::class, 'compareUtf8']);
        $values = array_map(static fn(string $v) => Obj::of(['kind' => 'exact', 'value' => $v]), $uniq);
        $values[] = Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER]);
        return Obj::of(['kind' => 'cat', 'path' => self::CLASS_PREFIX . $id, 'values' => $values]);
    }

    private static function copy(Obj $o): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $o->get($k));
        }
        return $c;
    }

    /** A copy of the space with dims added to verb (dimensions kept sorted by path). */
    public static function withDims(mixed $omega, string $verb, array $dims): Obj
    {
        $verbs = [];
        $found = false;
        foreach (Js::opt($omega, 'verbs') as $vs) {
            if (Js::opt($vs, 'verb') !== $verb) {
                $verbs[] = $vs;
                continue;
            }
            $found = true;
            $have = array_map(static fn($d) => Js::opt($d, 'path'), Js::opt($vs, 'dims'));
            foreach ($dims as $d) {
                if (in_array(Js::opt($d, 'path'), $have, true)) {
                    throw new \InvalidArgumentException("withDims: $verb already has a dimension " . Js::opt($d, 'path'));
                }
            }
            $all = array_merge(Js::opt($vs, 'dims'), $dims);
            usort($all, static fn($a, $b) => Jsx::cmp(Js::opt($a, 'path'), Js::opt($b, 'path')));
            $c = self::copy($vs);
            $c->set('dims', $all);
            $verbs[] = $c;
        }
        if (!$found) {
            throw new \InvalidArgumentException("withDims: no verb $verb in \u{03A9}");
        }
        $r = self::copy($omega);
        $r->set('verbs', $verbs);
        return $r;
    }

    /** @param list<string> $segs @return mixed the member, or Jsx::$U when absent */
    private static function walk(mixed $root, array $segs): mixed
    {
        $cur = $root;
        foreach ($segs as $s) {
            if ($cur instanceof Obj && $cur->has($s)) {
                $cur = $cur->get($s);
            } elseif (is_array($cur) && array_is_list($cur) && preg_match('/\A(?:0|[1-9][0-9]*)\z/', $s) === 1 && (int)$s < count($cur)) {
                $cur = $cur[(int)$s];
            } else {
                return Jsx::$U;
            }
        }
        return $cur;
    }

    /**
     * Lift a concrete outcome with the verifier-computed env: fill every world / prov / class dimension path from it. A provenance
     * dimension with no computed label is `agent` (fail closed: the tainted cell).
     * @param list<string> $dimPaths
     */
    public static function liftOutcome(mixed $o, mixed $env, array $dimPaths): Obj
    {
        $values = self::copy(Js::opt($o, 'values'));
        $world = Js::opt($env, 'world');
        $prov = Js::opt($env, 'prov');
        $cls = Js::opt($env, 'class');
        foreach ($dimPaths as $p) {
            if (str_starts_with($p, self::WORLD_PREFIX)) {
                $v = self::walk($world, [substr($p, strlen(self::WORLD_PREFIX))]);
                if (Js::isNum($v) || is_string($v)) {
                    $values->set($p, $v);
                }
            } elseif (str_starts_with($p, self::PROV_PREFIX)) {
                $v = self::walk($prov, explode('.', substr($p, strlen(self::PROV_PREFIX))));
                $values->set($p, is_string($v) ? $v : 'agent');
            } elseif (str_starts_with($p, self::CLASS_PREFIX)) {
                $v = self::walk($cls, [substr($p, strlen(self::CLASS_PREFIX))]);
                if (is_string($v)) {
                    $values->set($p, $v);
                }
            }
        }
        return Obj::of(['verb' => Js::opt($o, 'verb'), 'values' => $values]);
    }
}
