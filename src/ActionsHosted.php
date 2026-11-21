<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsBuild.php';
require_once __DIR__ . '/ActionsDiff.php';
require_once __DIR__ . '/ActionsEffective.php';
require_once __DIR__ . '/ActionsRegistry.php';
require_once __DIR__ . '/ActionsRender.php';
require_once __DIR__ . '/ActionsReview.php';
require_once __DIR__ . '/ActionsRules.php';
require_once __DIR__ . '/ActionsUndoEngine.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Js.php';

/**
 * The hosted action registry of one instance: the publish gate and the verifier's view of the active versions (native port of hosted.ts of the
 * reference actions package). Pure: storage, keys and time are the caller's. Fail closed everywhere: an action the view does not know, that no
 * pinned reviewer key confirmed, or that is deprecated gets the top of the trait registry, no provenance facts, is irreversible and never undoable.
 */
final class ActionsHosted
{
    public const RULES_DOC_KIND = 'pca-action-rules';
    public const HOSTED_VERSION_DOMAIN = 'atlas-pca/hosted-action-version/v1';
    private const EFFECTIVE_DIMS = ['confirmation', 'effective.traits', 'effective.profile'];
    private const SERVER_CLASS = ['reversible' => 'reversible', 'rate_limited' => 'costly', 'irreversible' => 'irreversible'];

    /** The trait registry of a version: core plus its custom traits. Throws for custom traits that do not extend their implies. @param list<Obj> $traits */
    public static function registryOfTraits(array $traits): array
    {
        return count($traits) === 0 ? Actions::coreRegistry() : Actions::extendRegistry(Actions::coreRegistry(), $traits);
    }

    /** The confirmation verifier of an instance: a signature by a pinned reviewer key (no pins: nothing is confirmed). */
    public static function reviewOptsOf(mixed $pins, array $reg): ?\Closure
    {
        return $pins === null ? null : ActionsReview::attestationVerifier($reg, $pins);
    }

    /** Null iff $x is a rules document for $ns whose every verb is in $defs and whose rules lint without errors. @param list<Obj> $defs */
    public static function rulesDocError(mixed $x, string $ns, array $defs): ?string
    {
        if (!($x instanceof Obj)) {
            return 'rules must be a pca-action-rules document';
        }
        foreach ($x->keys() as $k) {
            if (!in_array($k, ['v', 'kind', 'ns', 'rules', 'reviews'], true)) {
                return "rules: unknown member '$k'";
            }
        }
        if (!Js::isNum($x->get('v')) || Js::num($x->get('v')) != 1 || $x->get('kind') !== self::RULES_DOC_KIND) {
            return 'rules: not a ' . self::RULES_DOC_KIND . ' v1 document';
        }
        if ($x->get('ns') !== $ns) {
            return "rules: ns '" . IntentWb::jsStr($x->has('ns') ? $x->get('ns') : JsUndefined::U) . "' is not the pack's '$ns'";
        }
        if (!($x->get('rules') instanceof Obj)) {
            return 'rules.rules must map verbs to rules blocks';
        }
        if ($x->has('reviews') && !($x->get('reviews') instanceof Obj)) {
            return 'rules.reviews must map verbs to rules reviews';
        }
        $byVerb = [];
        foreach ($defs as $d) {
            $byVerb[$d->get('verb')] = $d;
        }
        foreach ($x->get('rules')->keys() as $verb) {
            $d = $byVerb[$verb] ?? null;
            if ($d === null) {
                return "rules: '$verb' is not an action of the pack";
            }
            $errs = array_filter(ActionsRules::lintBusinessRules($d, $x->get('rules')->get($verb)), static fn(array $f): bool => $f['severity'] === 'error');
            if ($errs) {
                return "rules for '$verb': " . implode('; ', array_map(static fn(array $f): string => $f['message'], $errs));
            }
        }
        $reviews = $x->get('reviews');
        foreach ($reviews instanceof Obj ? $reviews->keys() : [] as $verb) {
            if (!isset($byVerb[$verb])) {
                return "rules.reviews: '$verb' is not an action of the pack";
            }
        }
        return null;
    }

    public static function hostedVersionDigest(Obj $v): string
    {
        $dep = $v->get('deprecated');
        usort($dep, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        return IntentV2::hashCanonical(Obj::of(['d' => self::HOSTED_VERSION_DOMAIN, 'pack' => $v->get('pack'), 'rules' => $v->get('rules'), 'traits' => $v->get('traits'), 'deprecated' => $dep]));
    }

    /** @param list<string>|null $verbs @return array<string,mixed> */
    private static function fail(string $code, string $reason, ?array $verbs = null): array
    {
        $out = ['ok' => false, 'code' => $code, 'reason' => $reason];
        if ($verbs) {
            $out['verbs'] = $verbs;
        }
        return $out;
    }

    private static function safeConfirmed(Obj $d, ?\Closure $review): bool
    {
        try {
            return $review !== null && $review($d) === true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** diffDefs, but each side under its own registry and review (a trait registry change shows up in the effective dimensions). @return array{class:string,reasons:list<string>} */
    private static function diffDefsAcross(Obj $o, Obj $n, array $oReg, array $nReg, bool $same, ?\Closure $oRev, ?\Closure $nRev): array
    {
        $base = ActionsDiff::diffDefs($o, $n, $nReg, $nRev);
        if ($same) {
            return $base;
        }
        $eo = ActionsDerive::effectiveWith($o, $oReg, $oRev)['eff'];
        $en = ActionsDerive::effectiveWith($n, $nReg, $nRev)['eff'];
        $rel = Actions::leq($eo, $en) ? (Actions::leq($en, $eo) ? null : 'narrow') : (Actions::leq($en, $eo) ? 'widen' : 'incomparable');
        if ($rel === null) {
            return $base;
        }
        $reasons = array_values(array_filter($base['reasons'], static fn(string $r): bool => !str_starts_with($r, 'effective.profile')));
        $reasons[] = "effective.profile: $rel";
        sort($reasons, SORT_STRING);
        $bc = $base['class'];
        $cls = $rel === 'incomparable' || $bc === 'incomparable' || ($rel === 'widen' && $bc === 'narrow') || ($rel === 'narrow' && $bc === 'widen') ? 'incomparable'
            : ($rel === 'widen' || $bc === 'widen' ? 'widen' : 'narrow');
        return ['class' => $cls, 'reasons' => $reasons];
    }

    /**
     * Decide whether a version may become the active one of its namespace and compute what it changes. $i: {current?, pack, rules?, traits?,
     * publisherKeys, pins, pin?}. Refused: bad_pack, bad_traits, bad_rules, ns_mismatch, bad_version / not_newer, widen_unreviewed (an action whose
     * effective authority or business rules widen without a reviewer signature). Removed actions become deprecated.
     *
     * @return array<string,mixed>
     */
    public static function publishGate(Obj $i): array
    {
        $traits = [];
        if ($i->has('traits')) {
            if (!is_array($i->get('traits')) || !array_is_list($i->get('traits'))) {
                return self::fail('bad_traits', 'traits must be a list of trait definitions');
            }
            $traits = $i->get('traits');
        }
        try {
            $reg = self::registryOfTraits($traits);
        } catch (\Throwable $e) {
            return self::fail('bad_traits', $e->getMessage());
        }
        $pv = ActionsBuild::verifySignedPack($i->get('pack'), $i->get('publisherKeys'), $reg);
        if (!$pv['ok']) {
            return self::fail('bad_pack', $pv['reason']);
        }
        $pack = $i->get('pack');
        if (preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+\z/', $pack->get('version')) !== 1) {
            return self::fail('bad_version', "version '" . $pack->get('version') . "' must be MAJOR.MINOR.PATCH");
        }
        $cur = $i->get('current');
        if ($cur && $cur->get('ns') !== $pack->get('ns')) {
            return self::fail('ns_mismatch', "the active namespace is '" . $cur->get('ns') . "', the pack is '" . $pack->get('ns') . "'");
        }
        if ($cur && !Js::truthy($i->get('pin')) && ActionsRegistry::compareVersions($pack->get('version'), $cur->get('version')) <= 0) {
            return self::fail('not_newer', 'version ' . $pack->get('version') . ' is not above the active ' . $cur->get('version'));
        }
        $rules = $i->has('rules') ? $i->get('rules') : Obj::of(['v' => new Num('1'), 'kind' => self::RULES_DOC_KIND, 'ns' => $pack->get('ns'), 'rules' => new Obj()]);
        $re = self::rulesDocError($rules, $pack->get('ns'), $pack->get('defs'));
        if ($re) {
            return self::fail('bad_rules', $re);
        }
        $pins = $i->get('pins');
        $review = self::reviewOptsOf($pins, $reg);
        $prevReg = $reg;
        $same = true;
        if ($cur) {
            try {
                $prevReg = self::registryOfTraits($cur->get('traits'));
                $same = count($cur->get('traits')) === 0 && count($traits) === 0;
            } catch (\Throwable) {
                $prevReg = $reg;
            }
        }
        $prevReview = self::reviewOptsOf($pins, $prevReg);
        $changes = [];
        $blocked = [];
        $reasons = [];
        $oldDefs = [];
        foreach ($cur ? $cur->get('pack')->get('defs') : [] as $d) {
            $oldDefs[$d->get('verb')] = $d;
        }
        $oldDep = $cur ? array_flip($cur->get('deprecated')) : [];
        $newVerbs = [];
        foreach ($pack->get('defs') as $d) {
            $newVerbs[$d->get('verb')] = true;
        }
        foreach ($pack->get('defs') as $n) {
            $verb = $n->get('verb');
            $o = $oldDefs[$verb] ?? null;
            $newRules = $rules->get('rules')->get($verb);
            $confirmed = self::safeConfirmed($n, $review);
            if ($o === null || isset($oldDep[$verb])) {
                $change = ['verb' => $verb, 'class' => 'added', 'reasons' => []];
                if ($confirmed) {
                    $change['reviewed'] = true;
                }
            } else {
                $d = self::diffDefsAcross($o, $n, $prevReg, $reg, $same, $prevReview, $review);
                $change = ['verb' => $verb, 'class' => $d['class'], 'reasons' => $d['reasons']];
                $widens = false;
                foreach ($d['reasons'] as $r) {
                    foreach (self::EFFECTIVE_DIMS as $dim) {
                        $widens = $widens || str_starts_with($r, "$dim: widen") || str_starts_with($r, "$dim: incomparable");
                    }
                }
                if ($widens) {
                    if ($confirmed) {
                        $change['reviewed'] = true;
                    } else {
                        $blocked[] = $verb;
                        $reasons[] = "$verb: its effective authority widens without a valid confirmation of the new definition";
                    }
                }
            }
            $oldRules = $o !== null && !isset($oldDep[$verb]) ? $cur->get('rules')->get('rules')->get($verb) : null;
            if ($oldRules !== null || $newRules !== null) {
                try {
                    $rd = ActionsRules::diffBusinessRules($n, $oldRules, $newRules);
                } catch (\Throwable $e) {
                    $rd = ['class' => 'incomparable', 'reasons' => ['rules: ' . $e->getMessage()]];
                }
                if ($rd['class'] !== 'equal') {
                    $change['rules'] = $rd;
                }
                if ($rd['class'] === 'widen' || $rd['class'] === 'incomparable') {
                    $rv = $rules->get('reviews');
                    $err = ActionsRules::rulesReviewError($rv instanceof Obj ? $rv->get($verb) : null, $n, $newRules ?? new Obj(), $pins);
                    if ($err === null) {
                        $change['reviewed'] = true;
                    } else {
                        $blocked[] = $verb;
                        $reasons[] = "$verb: its business rules widen (" . implode(', ', $rd['reasons']) . ") without a valid rules review: $err";
                    }
                }
            }
            if ($change['class'] !== 'equal' || isset($change['rules'])) {
                $changes[] = $change;
            }
        }
        $deprecated = [];
        foreach (array_keys($oldDep) as $v) {
            if (!isset($newVerbs[$v])) {
                $deprecated[(string)$v] = true;
            }
        }
        foreach (array_keys($oldDefs) as $v) {
            $v = (string)$v;
            if (isset($newVerbs[$v]) || isset($oldDep[$v])) {
                continue;
            }
            $deprecated[$v] = true;
            $changes[] = ['verb' => $v, 'class' => 'deprecated', 'reasons' => ['removed from the namespace: treated as unknown']];
        }
        usort($changes, static fn(array $a, array $b): int => Actions::u16Order($a['verb'], $b['verb']));
        if ($blocked) {
            $bl = array_values(array_unique($blocked));
            usort($bl, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
            $out = self::fail('widen_unreviewed', implode("\n", $reasons), $bl);
            $out['changes'] = $changes;
            return $out;
        }
        $dep = array_map('strval', array_keys($deprecated));
        usort($dep, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        $body = Obj::of(['pack' => $pack, 'rules' => $rules, 'traits' => $traits, 'deprecated' => $dep]);
        $version = Obj::of(['ns' => $pack->get('ns'), 'version' => $pack->get('version'), 'digest' => self::hostedVersionDigest($body), 'prev' => $cur ? $cur->get('digest') : null]);
        foreach ($body->keys() as $k) {
            $version->set($k, $body->get($k));
        }
        $version->set('changes', $changes);
        return ['ok' => true, 'version' => $version];
    }

    // ---- the verifier's view -----------------------------------------------------------------------------------------------

    /** Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers. @return array{caveats:list<string>,max_esc:int,preauth_esc:int} */
    public static function grantFactsOf(mixed $grant): array
    {
        $env = Authorize::readEnvelope($grant);
        $a = $env?->get('actions');
        $a = $a instanceof Obj ? $a : new Obj();
        $tier = static fn(mixed $v, int $d): int => Js::isNum($v) && fmod((float)Js::num($v), 1.0) == 0.0 && Js::num($v) >= 0 && Js::num($v) <= 3 ? (int)Js::num($v) : $d;
        $caveats = [];
        $cs = $env?->get('caveats');
        foreach (is_array($cs) ? $cs : [] as $c) {
            $caveats[] = $c instanceof Obj ? $c->get('type') : null;
        }
        if (is_array($a->get('caveats')) && array_is_list($a->get('caveats'))) {
            $caveats = array_merge($caveats, $a->get('caveats'));
        }
        return ['caveats' => array_values(array_filter($caveats, 'is_string')), 'max_esc' => $tier($a->get('max_esc'), 3), 'preauth_esc' => $tier($a->get('preauth_esc'), 0)];
    }

    /** A rules block that no longer compiles denies every call of its action (its tightening must not silently disappear). */
    private static function brokenRules(string $verb): Obj
    {
        return Obj::of(['v' => new Num('1'), 'verb' => $verb, 'rules_digest' => '', 'def_digest' => '', 'tighten' => [Obj::of(['id' => 'rules_broken',
            'when' => Obj::of(['field' => 'action.verb', 'op' => 'eq', 'value' => $verb]), 'signal' => 'deny', 'reason' => 'the business rules of this action no longer compile'])],
            'accumulators' => []]);
    }

    public static function hostedView(array $versions, mixed $pins): HostedView
    {
        return new HostedView($versions, $pins);
    }

    /** The context keys the hosted server itself establishes for a call: fresh revocation always; an idempotency key when one is present. @return list<string> */
    public static function hostedCallContext(mixed $l, mixed $params): array
    {
        $out = ['fresh_revocation'];
        if ($l === null) {
            throw new \TypeError("Cannot read properties of null (reading 'idempotency_param')");
        }
        $k = Js::opt($l, 'idempotency_param');
        if ($k !== null && $params === null) { // params[l.idempotency_param] on a null
            throw new \TypeError("Cannot read properties of null (reading '" . Js::str($k) . "')");
        }
        $v = $k !== null && $params instanceof Obj ? $params->get($k) : null;
        if (is_string($v) && $v !== '') {
            $out[] = 'idempotency';
        }
        return $out;
    }

    /**
     * The event keys of a rules block's rate limits: verb, window and scope id (never a rule index or the rules digest).
     *
     * @return list<Obj>
     */
    public static function rateKeysOf(Obj $c, Obj $who): array
    {
        $out = [];
        foreach ($c->get('accumulators') as $a) {
            $scope = $a->get('scope') === 'org' ? 'org' : 'principal';
            $i = $scope === 'org' ? $who->get('org') : $who->get('principal');
            $ms = $a->get('win')->get('kind') === 'task' ? 0 : (int)Js::num($a->get('win')->get('ms'));
            $e = Obj::of(['id' => $a->get('id'), 'ms' => new Num((string)$ms)]);
            if (is_string($i) && $i !== '' && $ms > 0) {
                $e->set('key', $c->get('verb') . "|$ms|$scope:$i");
            }
            $out[] = $e;
        }
        return $out;
    }

    /** @internal for HostedView */
    public static function brokenRulesOf(string $verb): Obj
    {
        return self::brokenRules($verb);
    }

    /** @internal for HostedView */
    public static function serverClassOf(string $rev): string
    {
        return self::SERVER_CLASS[$rev];
    }
}

/** The verifier's view: lookup(verb), provenance(op), undoPlan(op), floor(verb, grant, callContext). */
final class HostedView
{
    /** @var list<string> */
    public array $versions = [];
    /** @var array<string,array{def:Obj,reg:array,review:?\Closure,rules?:Obj,group:string}> */
    private array $byVerb = [];
    /** @var array<string,true> */
    private array $deprecated = [];
    /** @var array<string,true> */
    private array $broken = [];
    private array $top;
    /** @var list<string> */
    private array $topTraitIds;
    /** @var array<string,array> */
    private array $cache = [];
    /** @var array<string,Obj> */
    private array $prov = [];
    /** @var array<string,\Closure> */
    private array $undo = [];

    /** @param list<Obj> $versions */
    public function __construct(array $versions, mixed $pins)
    {
        $regs = [];
        $groupRegs = [];
        foreach ($versions as $vi => $v) {
            $this->versions[] = $v->get('ns') . '@' . $v->get('version');
            try {
                $reg = ActionsHosted::registryOfTraits($v->get('traits'));
            } catch (\Throwable) {
                $pk = $v->get('pack');
                foreach ($pk instanceof Obj && is_array($pk->get('defs')) ? $pk->get('defs') : [] as $d) {
                    if ($d instanceof Obj && is_string($d->get('verb'))) {
                        $this->broken[$d->get('verb')] = true;
                    }
                }
                continue;
            }
            $regs[] = $reg;
            $review = ActionsHosted::reviewOptsOf($pins, $reg);
            $group = count($v->get('traits')) === 0 ? 'core' : "v$vi"; // the empty-traits versions share one registry
            $groupRegs[$group] = $reg;
            foreach ($v->get('pack')->get('defs') as $d) {
                if (!isset($this->byVerb[$d->get('verb')])) {
                    $e = ['def' => $d, 'reg' => $reg, 'review' => $review, 'group' => $group];
                    $r = $v->get('rules')->get('rules')->get($d->get('verb'));
                    if (Js::truthy($r)) {
                        $e['rules'] = $r;
                    }
                    $this->byVerb[$d->get('verb')] = $e;
                }
            }
            foreach ($v->get('deprecated') as $x) {
                $this->deprecated[$x] = true;
            }
        }
        foreach (array_merge(array_keys($this->deprecated), array_keys($this->broken)) as $x) {
            unset($this->byVerb[(string)$x]);
        }
        if (!$regs) {
            $this->top = Actions::floorOf(Actions::coreRegistry(), Actions::topTraits(Actions::coreRegistry()));
        } else {
            $tops = array_map(static fn(array $r): array => Actions::floorOf($r, Actions::topTraits($r)), $regs);
            $this->top = $tops[0];
            foreach (array_slice($tops, 1) as $b) {
                $this->top = Actions::leq($this->top, $b) ? $b : (Actions::leq($b, $this->top) ? $this->top : Actions::join($this->top, $b));
            }
        }
        $ids = [];
        foreach ($regs ?: [Actions::coreRegistry()] as $r) {
            foreach (Actions::topTraits($r) as $t) {
                $ids[$t] = true;
            }
        }
        $this->topTraitIds = array_map('strval', array_keys($ids));
        usort($this->topTraitIds, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        foreach ($this->byVerb as $verb => $e) {
            try {
                if ($e['review'] !== null && ($e['review'])($e['def']) === true) {
                    $this->prov[(string)$verb] = ActionsRender::provenanceInfoOf($e['def'], $e['reg'], $e['review']);
                }
            } catch (\Throwable) {
                // unknown: sensitive
            }
        }
        $groups = [];
        foreach ($this->byVerb as $e) {
            $groups[$e['group']][] = $e['def'];
        }
        foreach ($groups as $g => $defs) {
            $this->undo[(string)$g] = ActionsUndoEngine::undoEngine($defs, $pins, $groupRegs[$g]);
        }
    }

    /** @return array<string,mixed> */
    public function lookup(string $verb): array
    {
        if (isset($this->cache[$verb])) {
            return $this->cache[$verb];
        }
        $e = $this->byVerb[$verb] ?? null;
        $out = ['verb' => $verb, 'confirmed' => false, 'known' => $e !== null, 'deprecated' => isset($this->deprecated[$verb]), 'profile' => $this->top,
            'traits' => $this->topTraitIds, 'serverClass' => 'irreversible'];
        if ($e === null && isset($this->broken[$verb]) && !isset($this->deprecated[$verb])) {
            $out = ['known' => true, 'rules' => ActionsHosted::brokenRulesOf($verb)] + $out;
        }
        if ($e !== null) {
            try {
                $eff = ActionsDerive::effectiveWith($e['def'], $e['reg'], $e['review']);
                $confirmed = $eff['confirmed'] === true;
                $idem = $e['def']->get('idempotency') instanceof Obj && $e['def']->get('idempotency')->get('mode') === 'key_param' ? $e['def']->get('idempotency')->get('param') : null;
                $nxt = ['def_digest' => Actions::defDigest($e['def']), 'confirmed' => $confirmed] + $out;
                if ($idem !== null) {
                    $nxt['idempotency_param'] = $idem;
                }
                if ($confirmed) {
                    $nxt = ['profile' => $eff['eff'], 'traits' => $eff['traits'], 'serverClass' => ActionsHosted::serverClassOf($eff['eff']['rev'])] + $nxt;
                }
                if (isset($e['rules'])) {
                    $nxt['rules'] = ActionsRules::compileBusinessRules($e['def'], $e['rules']);
                }
                $out = $nxt;
            } catch (\Throwable) {
                $out = ['confirmed' => false, 'profile' => $this->top, 'traits' => $this->topTraitIds, 'serverClass' => 'irreversible', 'rules' => ActionsHosted::brokenRulesOf($verb)] + $out;
            }
        }
        return $this->cache[$verb] = $out;
    }

    public function provenance(mixed $op): ?Obj
    {
        return $this->prov[Js::opt($op, 'verb')] ?? null;
    }

    public function undoPlan(Obj $op): ?Obj
    {
        $e = $this->byVerb[$op->get('verb')] ?? null;
        return $e === null ? null : ($this->undo[$e['group']])($op);
    }

    /** @param array<string,mixed>|Obj $grant {caveats, max_esc, preauth_esc} @param list<string> $callContext */
    public function floor(string $verb, mixed $grant, array $callContext): string
    {
        try {
            $g = static fn(string $k): mixed => $grant instanceof Obj ? $grant->get($k) : $grant[$k];
            $kinds = array_values(array_filter($g('caveats'), static fn($c) => in_array($c, Actions::CAVEAT_KINDS, true)));
            $num = static fn($x) => $x instanceof Num ? $x : new Num((string)$x);
            return Actions::floorDecision(Obj::of(['caveats' => $kinds, 'max_esc' => $num($g('max_esc')), 'preauth_esc' => $num($g('preauth_esc'))]),
                Obj::of(['context' => $callContext]), $this->lookup($verb)['profile']);
        } catch (\Throwable) {
            return 'deny';
        }
    }
}
