<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDerive.php';
require_once __DIR__ . '/ActionsBuiltinData.php';
require_once __DIR__ . '/ActionsReview.php';

/**
 * The built-in connector defs and how they become confirmed (native port of the built-in defs and their release signing step of the reference
 * actions package). Without a release signing step the built-ins carry no attestation: unconfirmed, maximally dangerous.
 */
final class ActionsBuiltin
{
    /** What the old catalog said per built-in verb (recorded; the old catalog is deprecated by the migration). @var array<string,array{reversibility:string,blastRadius:float}> */
    public const LEGACY_CATALOG = [
        'stripe.charge' => ['reversibility' => 'reversible', 'blastRadius' => 0.9],
        'stripe.refund' => ['reversibility' => 'rate_limited', 'blastRadius' => 0.9],
        'stripe.payout' => ['reversibility' => 'irreversible', 'blastRadius' => 0.9],
        'stripe.create_customer' => ['reversibility' => 'reversible', 'blastRadius' => 0.2],
        'gmail.send' => ['reversibility' => 'irreversible', 'blastRadius' => 0.8],
        'gmail.draft' => ['reversibility' => 'reversible', 'blastRadius' => 0.2],
        'gmail.delete' => ['reversibility' => 'irreversible', 'blastRadius' => 0.8],
        'github.read' => ['reversibility' => 'reversible', 'blastRadius' => 0.05],
        'github.create_pr' => ['reversibility' => 'reversible', 'blastRadius' => 0.2],
        'github.comment' => ['reversibility' => 'reversible', 'blastRadius' => 0.2],
        'github.merge_pr' => ['reversibility' => 'rate_limited', 'blastRadius' => 0.5],
        'github.delete_repo' => ['reversibility' => 'irreversible', 'blastRadius' => 0.8],
        'slack.post_message' => ['reversibility' => 'rate_limited', 'blastRadius' => 0.5],
        'slack.read' => ['reversibility' => 'reversible', 'blastRadius' => 0.05],
        'calendar.create_event' => ['reversibility' => 'reversible', 'blastRadius' => 0.2],
        'calendar.delete_event' => ['reversibility' => 'rate_limited', 'blastRadius' => 0.5],
        'files.read' => ['reversibility' => 'reversible', 'blastRadius' => 0.05],
        'files.write' => ['reversibility' => 'rate_limited', 'blastRadius' => 0.5],
        'files.delete' => ['reversibility' => 'irreversible', 'blastRadius' => 0.8],
        'http.get' => ['reversibility' => 'reversible', 'blastRadius' => 0.05],
        'http.post' => ['reversibility' => 'rate_limited', 'blastRadius' => 0.5],
    ];

    /** What the old payments ontology said (effect class), for the verbs that exist in both models. @var array<string,string> */
    public const LEGACY_ONTOLOGY_EFFECT = [
        'stripe.refund' => 'irreversible',
        'stripe.charge' => 'irreversible',
        'stripe.payout' => 'irreversible',
    ];

    /** Every place the old models disagreed and how it was settled. @var list<array{verb:string,field:string,was:string,now:string,reason:string}> */
    public const RESOLUTIONS = [
        ['verb' => 'stripe.refund', 'field' => 'reversibility', 'was' => 'catalog rate_limited / ontology irreversible', 'now' => 'irreversible', 'reason' => 'the stricter class; a refund cannot be taken back'],
        ['verb' => 'stripe.charge', 'field' => 'reversibility', 'was' => 'catalog reversible / ontology irreversible', 'now' => 'irreversible', 'reason' => 'the stricter class; a refund is a new payment, not an undo'],
        ['verb' => 'stripe.charge', 'field' => 'name', 'was' => 'catalog stripe.charge / ontology charge_customer', 'now' => 'stripe.charge (aliases charge_customer, bill)', 'reason' => 'one verb, the ontology id becomes an alias'],
        ['verb' => 'stripe.refund', 'field' => 'name', 'was' => 'catalog stripe.refund / ontology refund', 'now' => 'stripe.refund (aliases refund, issue_refund, reimburse, refund_charge)', 'reason' => 'one verb, the ontology ids become aliases'],
        ['verb' => 'stripe.payout', 'field' => 'name', 'was' => 'catalog stripe.payout / ontology payout', 'now' => 'stripe.payout (aliases payout, pay_out)', 'reason' => 'one verb'],
        ['verb' => 'slack.post_message', 'field' => 'reversibility', 'was' => 'catalog rate_limited', 'now' => 'irreversible', 'reason' => 'a send carries the external_communication floor (irreversible); the declaration says what the floor makes true'],
        ['verb' => 'github.merge_pr', 'field' => 'reversibility', 'was' => 'catalog rate_limited', 'now' => 'irreversible', 'reason' => 'a merge triggers deploys and downstream effects; a revert is a new action, not an undo'],
        ['verb' => 'github.create_pr', 'field' => 'traits', 'was' => 'none (reversible)', 'now' => 'effects create+send, audience resource (irreversible)', 'reason' => 'visible to other people; the repository is the audience'],
        ['verb' => 'github.comment', 'field' => 'traits', 'was' => 'none (reversible)', 'now' => 'effects create+send, audience resource (irreversible)', 'reason' => 'visible to other people; the repository is the audience'],
        ['verb' => 'calendar.create_event', 'field' => 'traits', 'was' => 'none (reversible)', 'now' => 'effects create+send, attendees recipient param (irreversible)', 'reason' => 'it sends invites'],
        ['verb' => 'stripe.create_customer', 'field' => 'reversibility', 'was' => 'catalog reversible', 'now' => 'rate_limited', 'reason' => 'the pack has no action that undoes it, and a reversible write must name one'],
        ['verb' => '*', 'field' => 'blast', 'was' => 'catalog 0.05..0.9 floats', 'now' => 'resource radius + trait floors (ppm)', 'reason' => 'one blast model; the money floor is 700000 ppm'],
        ['verb' => '*', 'field' => 'money', 'was' => 'amountField / semantic money.* / kind money / envelope units / toolCallRisk option', 'now' => 'param role money.amount + unit {money, ccy, exp}', 'reason' => 'one definition of money'],
    ];

    /** @var array<string,mixed>|null */
    private static ?array $data = null;

    /** @return array<string,mixed> */
    private static function data(): array
    {
        if (self::$data === null) {
            $o = (new Parser(ActionsBuiltinData::JSON, PHP_INT_MAX))->run();
            $m = [];
            foreach ($o->keys() as $k) {
                $m[$k] = $o->get($k);
            }
            self::$data = $m;
        }
        return self::$data;
    }

    /** The built-in connector defs. @return list<Obj> */
    public static function builtinDefs(): array
    {
        return self::data()['builtin'];
    }

    /** The domain-vocabulary defs. @return list<Obj> */
    public static function domainDefs(): array
    {
        return self::data()['domain'];
    }

    /**
     * Release step: confirm (sign) every built-in def with the release reviewer key (confirmDef over each, final traits = its declared ones). The
     * reviewer secret (a 32-byte Ed25519 seed) is the caller's release key; it is never stored.
     *
     * @param list<Obj>|null $defs
     * @param array<string,mixed>|null $registry
     * @return list<Obj>
     */
    public static function signBuiltins(string $kid, string $secret, int $ts, ?array $registry = null, ?array $defs = null): array
    {
        $out = [];
        foreach ($defs ?? self::builtinDefs() as $d) {
            $out[] = ActionsReview::confirmDef($d, ['registry' => $registry ?? Actions::coreRegistry(), 'reviewer' => ['kid' => $kid, 'secret' => $secret],
                'finalTraits' => Actions::sortUniq($d->get('traits') ?? []), 'ts' => $ts]);
        }
        return $out;
    }

    /** The built-in connector defs plus the domain-vocabulary defs. @return list<Obj> */
    public static function corePackDefs(): array
    {
        return array_merge(self::builtinDefs(), self::domainDefs());
    }

    private static function defOf(string $verb): Obj
    {
        foreach (self::corePackDefs() as $d) {
            if ($d->get('verb') === $verb) {
                return $d;
            }
        }
        throw new \InvalidArgumentException("domain binding names unknown def '$verb'");
    }

    /**
     * The `verbs` and `aliases` of a domain ontology, derived from the defs (effect class derived, never assigned).
     *
     * @return array{verbs:list<Obj>,aliases:Obj}
     */
    public static function domainVerbs(string $domain, ?array $reg = null): array
    {
        $reg ??= Actions::coreRegistry();
        $bindings = self::data()['domainVerbs']->get($domain);
        $onto = ActionsDerive::toOntology(array_map(static fn(Obj $b): Obj => self::defOf($b->get('verb')), $bindings), $reg);
        $verbs = [];
        $aliases = new Obj();
        foreach ($bindings as $b) {
            $d = self::defOf($b->get('verb'));
            if (!in_array($b->get('id'), $d->get('aliases') ?? [], true)) {
                throw new \InvalidArgumentException("domain binding '" . $b->get('id') . "' is not an alias of '" . $b->get('verb') . "'");
            }
            $ov = null;
            foreach ($onto->get('verbs') as $v) {
                if ($v->get('id') === $b->get('verb')) {
                    $ov = $v;
                    break;
                }
            }
            $params = new Obj();
            foreach ($b->get('params')->keys() as $nl) {
                $dp = $b->get('params')->get($nl);
                $p = $ov->get('params')->get($dp);
                if (!$p) {
                    throw new \InvalidArgumentException("domain binding '" . $b->get('id') . "' surfaces unknown parameter '$dp'");
                }
                $params->set($nl, $p->get('kind') === 'money' && $b->get('ccys') !== null ? Obj::of(['kind' => 'money', 'ccys' => $b->get('ccys')]) : $p);
            }
            $verbs[] = Obj::of(['id' => $b->get('id'), 'effect' => ActionsDerive::effectClass($d), 'resource_type' => $b->get('resourceType'), 'params' => $params]);
            foreach ($d->get('aliases') ?? [] as $a) {
                if ($a !== $b->get('id')) {
                    $aliases->set($a, $b->get('id'));
                }
            }
        }
        return ['verbs' => $verbs, 'aliases' => $aliases];
    }

    /** The role map of a domain verb for the selector layer: role -> NL parameter names carrying it. */
    public static function domainRoles(string $domain): Obj
    {
        $out = new Obj();
        foreach (self::data()['domainVerbs']->get($domain) as $b) {
            $d = self::defOf($b->get('verb'));
            $roles = new Obj();
            foreach ($b->get('params')->keys() as $nl) {
                $pd = $d->get('params')->get($b->get('params')->get($nl));
                $r = $pd?->get('role');
                if ($r !== null) {
                    $roles->set($r, array_merge($roles->get($r) ?? [], [$nl]));
                }
            }
            $out->set($b->get('id'), $roles);
        }
        return $out;
    }

    /** The pinned release reviewer keys; null before the first release signing (then nothing is confirmed). */
    public static function builtinReviewerPins(): ?Obj
    {
        return null;
    }

    /** The release context ({pins, registry}) under which the built-ins count as confirmed; null before the first release signing. @return array{pins:Obj,registry:array}|null */
    public static function builtinReleaseCtx(?array $reg = null): ?array
    {
        $pins = self::builtinReviewerPins();
        return $pins === null ? null : ['pins' => $pins, 'registry' => $reg ?? Actions::coreRegistry()];
    }

    /** The confirmation verifier under which the released built-ins count as confirmed (a signature by the pinned release key, nothing else); null before the first release signing. */
    public static function builtinReviewOpts(?array $reg = null): ?\Closure
    {
        $ctx = self::builtinReleaseCtx($reg);
        return $ctx === null ? null : ActionsReview::attestationVerifier($ctx['registry'], $ctx['pins']);
    }
}
