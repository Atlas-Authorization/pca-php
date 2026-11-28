<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalOntologiesData.php';

/**
 * The shipped intent ontologies (payments, email, calendar_travel, code_repos, data_access) and the selector catalog of each
 * domain, as data, plus the authoring helpers the shipped ontologies are built with (the reference's `ontologies` and its dsl).
 * Every lookup returns a fresh copy, so a caller never mutates the shared data.
 */
final class GoalOntologies
{
    public const NAMES = ['calendar_travel', 'code_repos', 'data_access', 'email', 'payments'];

    /** The currencies the shipped ontologies accept. */
    public const CCYS = ['USD', 'EUR', 'GBP', 'JPY'];

    private static ?Obj $data = null;

    private static function load(): Obj
    {
        if (self::$data === null) {
            $d = (new Parser(GoalOntologiesData::JSON, PHP_INT_MAX))->run();
            if (!$d instanceof Obj) {
                throw new \UnexpectedValueException('malformed ontology data');
            }
            self::$data = $d;
        }
        return self::$data;
    }

    private static function copy(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::copy($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::copy(...), $v) : $v;
    }

    private static function lookup(string $section, mixed $name): mixed
    {
        $m = self::load()->get($section);
        return is_string($name) && $m instanceof Obj && $m->has($name) ? self::copy($m->get($name)) : null;
    }

    /** The intent ontology of a shipped domain (a fresh copy), or null for an unknown name. */
    public static function shippedOntology(mixed $name): mixed
    {
        return self::lookup('ontologies', $name);
    }

    /** The selector catalog {known, verbs} of a shipped domain (a fresh copy), or null for an unknown name. */
    public static function shippedCatalog(mixed $name): mixed
    {
        return self::lookup('catalogs', $name);
    }

    /** ALL_ONTOLOGIES: every shipped ontology by domain name. */
    public static function allOntologies(): Obj
    {
        $o = new Obj();
        foreach (self::NAMES as $n) {
            $o->set($n, self::shippedOntology($n));
        }
        return $o;
    }

    public static function payments(): Obj
    {
        return self::shippedOntology('payments');
    }

    public static function email(): Obj
    {
        return self::shippedOntology('email');
    }

    public static function travel(): Obj
    {
        return self::shippedOntology('calendar_travel');
    }

    public static function code(): Obj
    {
        return self::shippedOntology('code_repos');
    }

    public static function data(): Obj
    {
        return self::shippedOntology('data_access');
    }

    // ---- the authoring helpers of the reference dsl ----

    /** The always-true condition. */
    public static function t(): Obj
    {
        return Obj::of(['k' => 'true']);
    }

    public static function cmp(string $op, string $param, string $slot): Obj
    {
        return Obj::of(['k' => 'cmp', 'op' => $op, 'l' => Obj::of(['k' => 'param', 'path' => $param]), 'r' => Obj::of(['k' => 'slot', 'slot' => $slot])]);
    }

    public static function cmpEnum(string $op, string $param, string $v): Obj
    {
        return Obj::of(['k' => 'cmp', 'op' => $op, 'l' => Obj::of(['k' => 'param', 'path' => $param]), 'r' => Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 's', 's' => $v])])]);
    }

    /** @param list<string> $vs */
    public static function inEnum(string $param, array $vs): Obj
    {
        $items = array_map(static fn(string $s): Obj => Obj::of(['k' => 's', 's' => $s]), array_values($vs));
        return Obj::of(['k' => 'cmp', 'op' => 'in', 'l' => Obj::of(['k' => 'param', 'path' => $param]), 'r' => Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'set', 'items' => $items])])]);
    }

    /** Left fold of conditions into `and`; no argument throws, as the reference's reduce does. */
    public static function and(Obj ...$args): Obj
    {
        if ($args === []) {
            throw new \TypeError('Reduce of empty array with no initial value');
        }
        $acc = array_shift($args);
        foreach ($args as $b) {
            $acc = Obj::of(['k' => 'and', 'a' => $acc, 'b' => $b]);
        }
        return $acc;
    }

    public static function exact(string $slot): Obj
    {
        return Obj::of(['k' => 'exact', 'id' => '$' . $slot]);
    }

    public static function related(string $rel, string $slot): Obj
    {
        return Obj::of(['k' => 'related', 'rel' => $rel, 'anchor' => '$' . $slot]);
    }

    /** Resource conjunction: the IR's flat `all_of`. */
    public static function both(Obj ...$parts): Obj
    {
        return Obj::of(['k' => 'all_of', 'parts' => array_values($parts)]);
    }

    public static function grant(string $gid, string $verb, Obj $res, ?Obj $cond = null): Obj
    {
        return Obj::of(['gid' => $gid, 'verb' => $verb, 'res' => $res, 'cond' => $cond ?? self::t()]);
    }

    /** @return list<Obj> one blanket prohibition per verb */
    public static function ban(string ...$verbs): array
    {
        return array_map(static fn(string $v): Obj => Obj::of([
            'pid' => "no-$v", 'target' => Obj::of(['k' => 'verb', 'verb' => $v]),
            'res' => Obj::of(['k' => 'any', 'reason' => 'blanket']), 'cond' => self::t(),
        ]), array_values($verbs));
    }

    /** @param list<string>|string $over */
    public static function countCap(string $bid, array|string $over, int $n, ?string $capSlot = null): Obj
    {
        $b = Obj::of(['bid' => $bid, 'agg' => 'count', 'over' => $over, 'cap' => Obj::of(['u' => Obj::of(['k' => 'count']), 'n' => $n]), 'onExceed' => 'deny']);
        if ($capSlot !== null && $capSlot !== '') {
            $b->set('cap_slot', $capSlot);
        }
        return $b;
    }

    /** @param list<string>|string $over */
    public static function sumCap(string $bid, array|string $over, string $param, string $ccy, string $capSlot): Obj
    {
        return Obj::of([
            'bid' => $bid, 'agg' => 'sum', 'over' => $over, 'param' => $param,
            'cap' => Obj::of(['u' => Obj::of(['k' => 'money', 'ccy' => $ccy]), 'n' => 0]), 'onExceed' => 'deny', 'cap_slot' => $capSlot,
        ]);
    }

    /** The money units of the shipped ontologies. */
    public static function unitsMoney(): Obj
    {
        $o = new Obj();
        foreach (['USD' => 2, 'EUR' => 2, 'GBP' => 2, 'JPY' => 0] as $c => $e) {
            $o->set($c, Obj::of(['kind' => 'money', 'exponent' => $e]));
        }
        return $o;
    }
}
