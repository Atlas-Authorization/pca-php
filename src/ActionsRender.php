<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDerive.php';
require_once __DIR__ . '/Approval.php';
require_once __DIR__ . '/Js.php';

/**
 * Approval-render wrappers, the facade view of a def and the provenance-gate facts (native port of the wrapper half of approval-render.ts,
 * facade-spec.ts and provenance.ts of the reference actions package). The render itself is {@see Approval::render}. $verifier is the caller's
 * confirmation verifier (absent: nothing is confirmed).
 */
final class ActionsRender
{
    private static function confirmed(Obj $d, ?\Closure $verifier): bool
    {
        return $verifier !== null && $verifier($d) === true;
    }

    /** Approval::render, with the confirmation decided by the verifier (asked only after the render itself succeeded). */
    public static function renderApprovalWith(Obj $d, mixed $params, ?\Closure $verifier = null): Obj
    {
        $r = Approval::render($d, $params, false);
        $r->set('unreviewed', !self::confirmed($d, $verifier));
        return $r;
    }

    /** H(R) for an executed action; refuses unless the params are the ones the PCActn signed and the verb is the PCActn's verb. */
    public static function renderDigestForAction(Obj $d, mixed $params, Obj $pcactn, ?\Closure $verifier = null): string
    {
        if ($pcactn->get('action')->get('verb') !== $d->get('verb')) {
            throw new ActionKitError('render_verb_mismatch', "the PCActn is for '" . IntentWb::jsStr($pcactn->get('action')->get('verb')) . "', the definition for '" . $d->get('verb') . "'");
        }
        if ($pcactn->get('action')->get('params_digest') !== Pca::paramsDigest($params)) {
            throw new ActionKitError('render_params_mismatch', 'the supplied params are not the params the PCActn signed');
        }
        return Approval::renderDigest(self::renderApprovalWith($d, $params, $verifier));
    }

    /** The approver client's check before it signs: re-render from the pinned def and require the requested digest. Returns the digest to sign. */
    public static function approverRenderCheck(Obj $d, mixed $params, string $requestedRenderDigest, ?\Closure $verifier = null): string
    {
        $dg = Approval::renderDigest(self::renderApprovalWith($d, $params, $verifier));
        if ($dg !== $requestedRenderDigest) {
            throw new ActionKitError('render_mismatch', 'the approval request commits to a render this definition and these params do not produce');
        }
        return $dg;
    }

    /** Single-tap (one-gesture) approval is allowed only for a confirmed definition. */
    public static function singleTapAllowed(Obj $r): bool
    {
        return !Js::truthy($r->get('unreviewed'));
    }

    /**
     * The step-up renderer derived from the pinned defs (found by verb or alias); an unknown verb throws, which makes the review a deny.
     *
     * @param list<Obj> $defs
     * @return \Closure(string,string,mixed):Obj
     */
    public static function renderersFromDefs(array $defs, ?\Closure $verifier = null): \Closure
    {
        $byVerb = [];
        foreach ($defs as $d) {
            $byVerb[$d->get('verb')] = $d;
            foreach ($d->get('aliases') ?? [] as $a) {
                $byVerb[$a] ??= $d;
            }
        }
        return static function (string $verb, string $resource, mixed $params = null) use ($byVerb, $verifier): Obj {
            $d = $byVerb[$verb] ?? null;
            if ($d === null) {
                throw new ActionKitError('render_unknown_verb', "no pinned action definition for '$verb'");
            }
            return self::renderApprovalWith($d, $params ?? new Obj(), $verifier);
        };
    }

    // ---- facade-spec.ts ----------------------------------------------------------------------------------------------------

    /** One def to one facade row: reversibility and blast are the EFFECTIVE values; $reviewed prices the def as reviewed (release-attested catalog only). */
    public static function specOfDef(Obj $d, ?array $reg = null, ?\Closure $verifier = null, mixed $reviewed = false): Obj
    {
        $reg ??= Actions::coreRegistry();
        $full = ActionsDerive::effectiveWith($d, $reg, $verifier);
        $e = $reviewed === true ? $full['hint'] : $full;
        $parts = explode('.', $d->get('verb'));
        try {
            $amount = ActionsDerive::paramByRole($d, 'money.amount');
        } catch (ActionKitError) {
            $amount = null;
        }
        $out = Obj::of(['connector' => $parts[0], 'action' => implode('.', array_slice($parts, 1)), 'verb' => $d->get('verb'), 'reversibility' => $e['eff']['rev'],
            'blastRadius' => $e['eff']['blast_ppm'] / 1000000]);
        if ($amount !== null) {
            $out->set('amountField', $amount);
        }
        $out->set('description', $d->get('description') ?? $d->get('title'));
        $aliases = $d->get('aliases');
        if ($aliases) {
            usort($aliases, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
            $out->set('aliases', $aliases);
        }
        $out->set('traits', $e['closure']);
        return $out;
    }

    /** @param list<Obj> $defs @return list<Obj> */
    public static function facadeSpecs(array $defs, ?array $reg = null, ?\Closure $verifier = null, mixed $reviewed = false): array
    {
        return array_map(static fn(Obj $d): Obj => self::specOfDef($d, $reg, $verifier, $reviewed), $defs);
    }

    // ---- provenance.ts -----------------------------------------------------------------------------------------------------

    /** The gate facts of one def. Unconfirmed means maximally dangerous: no effects, the top trait set, provenance relaxations ignored. */
    public static function provenanceInfoOf(Obj $d, ?array $reg = null, ?\Closure $verifier = null): Obj
    {
        $reg ??= Actions::coreRegistry();
        $confirmed = self::confirmed($d, $verifier);
        $traits = $confirmed ? Actions::hintTraits($d) : Actions::topTraits($reg);
        if (!$confirmed) {
            return Obj::of(['effects' => [], 'traits' => $traits]);
        }
        $n = Actions::normalize($d);
        $params = new Obj();
        foreach ($n->get('params')->keys() as $name) {
            $p = $n->get('params')->get($name);
            if ($p->has('provenance_min')) {
                $params->set($name, $p->get('provenance_min'));
            }
        }
        $out = Obj::of(['effects' => $n->get('effects'), 'traits' => $traits]);
        if (count($params->keys()) > 0) {
            $out->set('params', $params);
        }
        return $out;
    }

    /**
     * The `provenance.actions` resolver: the facts of the def whose verb (or alias) is the operation's verb, null for an unknown verb. Two defs
     * claiming one name throw.
     *
     * @param list<Obj> $defs
     * @return \Closure(mixed):?Obj
     */
    public static function provenanceActions(array $defs, ?array $reg = null, ?\Closure $verifier = null): \Closure
    {
        $reg ??= Actions::coreRegistry();
        $byVerb = [];
        foreach ($defs as $d) {
            $n = Actions::normalize($d);
            $info = self::provenanceInfoOf($d, $reg, $verifier);
            foreach (array_merge([$n->get('verb')], $n->get('aliases')) as $v) {
                if (isset($byVerb[$v])) {
                    throw new \InvalidArgumentException("provenanceActions: two definitions claim the verb '$v'");
                }
                $byVerb[$v] = $info;
            }
        }
        return static fn(mixed $op): ?Obj => $byVerb[Js::opt($op, 'verb')] ?? null;
    }
}
