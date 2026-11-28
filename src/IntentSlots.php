<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';

/**
 * Structured intent slots (slots.ts): the machine-readable half of an intent statement, compiled into the policy they literally
 * describe. Slots are an Obj `{verbs: [..], constraints: [{path, verb?, min?, max?, oneOf?, prefixOneOf?, noneOf?}]}`.
 */
final class IntentSlots
{
    /** `x?.length` is truthy: a non-empty array or string. */
    private static function hasLength(mixed $x): bool
    {
        return (is_array($x) && count($x) > 0) || (is_string($x) && $x !== '');
    }

    /** @return list<Obj> */
    private static function slotConds(mixed $sc): array
    {
        $out = [];
        $p = Js::opt($sc, 'path');
        if (Js::has($sc, 'min')) {
            $out[] = Obj::of(['field' => $p, 'op' => 'gte', 'value' => Js::opt($sc, 'min')]);
        }
        if (Js::has($sc, 'max')) {
            $out[] = Obj::of(['field' => $p, 'op' => 'lte', 'value' => Js::opt($sc, 'max')]);
        }
        $anyOf = [];
        $oneOf = Js::opt($sc, 'oneOf');
        if (self::hasLength($oneOf)) {
            $anyOf[] = Obj::of(['field' => $p, 'op' => 'in', 'value' => Js::spread($oneOf)]);
        }
        $pre = Js::opt($sc, 'prefixOneOf');
        foreach ($pre === null ? [] : (is_array($pre) ? $pre : throw new \TypeError('prefixOneOf is not iterable')) as $x) {
            $anyOf[] = Obj::of(['field' => $p, 'op' => 'prefix', 'value' => $x]);
        }
        if (count($anyOf) === 1) {
            $out[] = $anyOf[0];
        } elseif (count($anyOf) > 1) {
            $out[] = Obj::of(['any_of' => $anyOf]);
        }
        $none = Js::opt($sc, 'noneOf');
        if (self::hasLength($none)) {
            $out[] = Obj::of(['field' => $p, 'op' => 'nin', 'value' => Js::spread($none)]);
        }
        return $out;
    }

    /** One predicate per slot verb, each with the constraints that name it (or no verb). */
    public static function slotsToPolicy(mixed $slots): Obj
    {
        $preds = [];
        foreach (Js::get($slots, 'verbs') as $verb) {
            $where = [];
            foreach (Js::get($slots, 'constraints') as $c) {
                if (!Js::has($c, 'verb') || Js::opt($c, 'verb') === $verb) {
                    array_push($where, ...self::slotConds($c));
                }
            }
            $pr = Obj::of(['verb' => $verb, 'resource' => '*']);
            if (count($where) > 0) {
                $pr->set('where', $where);
            }
            $preds[] = $pr;
        }
        return Obj::of(['predicates' => $preds, 'caveats' => []]);
    }
}
