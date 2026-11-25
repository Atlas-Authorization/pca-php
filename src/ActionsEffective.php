<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDerive.php';

/**
 * The structural param rules and the helpers around the effective profile (native port of the remaining half of effective.ts of the
 * reference actions package; ActionsDerive holds effectiveWith). Pure.
 */
final class ActionsEffective
{
    /** Profile equality: each is at most the other. */
    public static function profileEq(array $p, array $q): bool
    {
        return Actions::leq($p, $q) && Actions::leq($q, $p);
    }

    /** The hint profile after adding trait $t to the declared traits (never lower). Analysis only. */
    public static function effWithTrait(Obj $d, string $t, array $reg): array
    {
        $d2 = new Obj();
        foreach ($d->keys() as $k) {
            $d2->set($k, $d->get($k));
        }
        $d2->set('traits', array_merge($d->get('traits') ?? [], [$t]));
        return ActionsDerive::effectiveWith($d2, $reg)['hint']['eff'];
    }

    /**
     * Structural param rules (among $ids) the def violates. A def violating a rule its traits require is not loadable.
     *
     * @param list<string>|null $ids
     * @return list<string>
     */
    public static function prulesViolations(Obj $d, ?array $ids = null): array
    {
        $ids ??= Actions::PARAM_RULE_IDS;
        $n = Actions::normalize($d);
        $params = $n->get('params');
        $ps = array_map(fn($k) => $params->get($k), $params->keys());
        $withRole = static fn(callable $pred): array => array_values(array_filter($ps, static fn(Obj $p): bool => $p->get('role') !== null && $pred($p->get('role'))));
        $moneyOk = static function (Obj $p) use ($params): bool {
            $u = $p->get('unit');
            if (!($u instanceof Obj) || $u->get('kind') !== 'money') {
                return false;
            }
            $ccy = $u->get('ccy');
            if (is_string($ccy)) {
                return true;
            }
            $c = $ccy instanceof Obj && $params->has((string)$ccy->get('from')) ? $params->get((string)$ccy->get('from')) : null;
            return $c !== null && $c->get('role') === 'money.currency' && $c->get('format') === 'iso_currency';
        };
        $bad = [];
        foreach ($ids as $rid) {
            $ok = true;
            switch ($rid) {
                case 'money_has_currency':
                    $ok = array_reduce($withRole(static fn($r) => $r === 'money.amount' || $r === 'money.fee'), static fn($a, $p) => $a && $moneyOk($p), true);
                    break;
                case 'money_amount_bounded':
                    $ok = array_reduce($withRole(static fn($r) => $r === 'money.amount'), static fn($a, Obj $p) => $a && $p->get('type') === 'integer' && $p->has('min') && $p->has('max'), true);
                    break;
                case 'id_not_wildcard':
                    $ok = !($n->get('resource')->get('id') === '*' && $n->get('resource')->get('scope') === 'one');
                    break;
                case 'recipient_param_declared':
                    $ok = $n->get('audience') === 'resource' || count($withRole(static fn($r) => $r === 'party.payee' || str_starts_with($r, 'contact.'))) > 0;
                    break;
                case 'array_bounded':
                    $ok = array_reduce(array_filter($ps, static fn(Obj $p) => $p->get('type') === 'array'), static fn($a, Obj $p) => $a && $p->get('max_items') !== null, true);
                    break;
                case 'export_bounded':
                    $ok = $n->get('resource')->get('scope') === 'one' || count(array_filter($withRole(static fn($r) => $r === 'count.limit'), static fn(Obj $p) => $p->has('max'))) > 0;
                    break;
                case 'secret_not_logged':
                    $ok = array_reduce($withRole(static fn($r) => str_starts_with($r, 'credential.')), static fn($a, Obj $p) => $a && in_array('secret', $p->get('tags') ?? [], true), true);
                    break;
                case 'pay_has_idempotency':
                    $ok = !in_array('pay', $n->get('effects'), true) || $n->get('idempotency')->get('mode') !== 'none';
                    break;
            }
            if (!$ok) {
                $bad[] = $rid;
            }
        }
        return $bad;
    }

    /** Rules the effective profile requires but the def does not satisfy (the load-time check). @return list<string> */
    public static function requiredPrulesViolated(Obj $d, array $eff): array
    {
        return self::prulesViolations($d, $eff['prules']);
    }
}
