<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/ActionsSelector.php';
require_once __DIR__ . '/Js.php';

/**
 * What an ActionDef yields once its trait registry is known: T(d) / decl(d) / eff(d) with a caller-supplied confirmation verifier, the signed v2
 * schema verb and the deterministic policy card (native port of effective.ts and the schema-verb and card half of derive.ts of the reference
 * actions package). Actions::effective is the pinned-key form of the same effective profile. Pure.
 */
final class ActionsDerive
{
    private const REV_RANK = ['reversible' => 0, 'rate_limited' => 1, 'irreversible' => 2];
    private const ESC_TIERS = ['auto', 'confirm', 'cosign', 'stepup'];
    private const RISK_NAMES = ['low', 'elevated', 'high', 'critical'];

    /** Traits implied by a NORMALIZED def's own facts. @return list<string> */
    public static function impliedTraits(Obj $n): array
    {
        $params = array_map(fn($k) => $n->get('params')->get($k), $n->get('params')->keys());
        return Actions::impliedFromFacts($n->get('effects'), $params, $n->get('resource')->get('scope'),
            Actions::worstReversibility($n->get('reversibility'), $n->get('params')));
    }

    /**
     * {confirmed, traits, closure, floor, eff, decl, hint:{traits,closure,floor,eff}, clamps}; $verifier (def => bool) replaces the pinned keys:
     * absent = never confirmed, and only a result of exactly true counts.
     *
     * @return array<string,mixed>
     */
    public static function effectiveWith(Obj $d, array $reg, ?\Closure $verifier = null): array
    {
        $decl = Actions::declProfile($d);
        $view = function (array $traits) use ($reg, $decl): array {
            $floor = Actions::floorOf($reg, $traits);
            return ['traits' => $traits, 'closure' => Actions::closure($reg, $traits), 'floor' => $floor, 'eff' => Actions::join($decl, $floor)];
        };
        $hint = $view(Actions::hintTraits($d));
        $confirmed = $verifier !== null && $verifier($d) === true;
        $main = $confirmed ? $hint : $view(Actions::topTraits($reg));
        $clamps = [];
        if ($d->has('reversibility') && self::REV_RANK[$decl['rev']] < self::REV_RANK[$hint['floor']['rev']]) {
            $clamps[] = ['field' => 'rev', 'declared' => $decl['rev'], 'floor' => $hint['floor']['rev']];
        }
        if ($d->has('blast') && $decl['blast_ppm'] < $hint['floor']['blast_ppm']) {
            $clamps[] = ['field' => 'blast_ppm', 'declared' => $decl['blast_ppm'], 'floor' => $hint['floor']['blast_ppm']];
        }
        return $main + ['confirmed' => $confirmed, 'decl' => $decl, 'hint' => $hint, 'clamps' => $clamps];
    }

    private static function num(int $n): Num
    {
        return new Num((string)$n);
    }

    private static function unitId(Obj $p): ?string
    {
        $u = $p->get('unit');
        if ($u === null) {
            return null;
        }
        if ($u->get('kind') !== 'money') {
            return $u->get('kind');
        }
        return is_string($u->get('ccy')) ? 'money.' . mb_strtolower($u->get('ccy')) : null;
    }

    private static function unitDecl(Obj $p): ?Obj
    {
        $u = $p->get('unit');
        if ($u === null) {
            return null;
        }
        if ($u->get('kind') !== 'money') {
            return Obj::of(['kind' => $u->get('kind')]);
        }
        if (!is_string($u->get('ccy'))) {
            return null;
        }
        $out = Obj::of(['kind' => 'money', 'currency' => $u->get('ccy')]);
        if ($u->has('exp')) {
            $out->set('exponent', $u->get('exp'));
        }
        return $out;
    }

    private static function toParamDecl(Obj $n): Obj
    {
        $d = Obj::of(['type' => $n->get('type'), 'semantic' => $n->get('role') !== null ? $n->get('role') : 'generic.' . $n->get('type'),
            'sensitivity' => $n->get('sensitivity')]);
        if (!$n->get('required')) {
            $d->set('required', false);
        }
        if ($n->has('values')) {
            $d->set('values', $n->get('values'));
        }
        foreach (['min', 'max', 'max_len', 'items', 'min_items', 'max_items', 'format', 'provenance_min', 'default', 'principal_neutral_default', 'description'] as $k) {
            if ($n->has($k)) {
                $d->set($k, $n->get($k));
            }
        }
        $uid = self::unitId($n);
        if ($uid !== null) {
            $d->set('unit', $uid);
        }
        if ($n->has('accumulates')) {
            $d->set('accumulates_into', $n->get('accumulates'));
        }
        if ($n->has('role')) {
            $d->set('role', $n->get('role'));
        }
        if ($n->has('tags')) {
            $d->set('tags', $n->get('tags'));
        }
        return $d;
    }

    /** {verb, units}: the signed v2 verb declaration of a def (effects, traits, def digest, materialized floors) and the units it needs. */
    public static function toSchemaVerb(Obj $d, array $reg, ?\Closure $verifier = null): Obj
    {
        $n = Actions::normalize($d);
        $eff = self::effectiveWith($d, $reg, $verifier);
        $params = new Obj();
        $units = new Obj();
        foreach ($n->get('params')->keys() as $name) {
            $p = $n->get('params')->get($name);
            $params->set('action.params.' . $name, self::toParamDecl($p));
            $uid = self::unitId($p);
            if ($uid !== null) {
                $units->set($uid, self::unitDecl($p));
            }
        }
        $effects = $n->get('effects');
        $v = Obj::of(['verb' => $n->get('verb'), 'kind' => self::isReadOnly($effects) ? 'read' : 'write', 'params' => $params, 'effects' => $effects,
            'traits' => $eff['traits'], 'def' => Actions::defDigest($d), 'floors' => Actions::profObj($eff['eff'])]);
        $att = $d->get('review') instanceof Obj ? $d->get('review')->get('attestation') : null;
        if ($eff['confirmed'] && $att instanceof Obj && $att->has('sig')) {
            $v->set('confirmation', $att);
        }
        $r = $n->get('reversibility');
        if (is_string($r)) {
            $v->set('reversibility', $r);
        } else {
            $by = Obj::of(['param' => 'action.params.' . $r->get('by'), 'map' => $r->get('map')]);
            if ($r->has('default')) {
                $by->set('default', $r->get('default'));
            }
            $v->set('reversibility_by', $by);
        }
        $b = $n->get('bindings');
        if ($b->get('mcp') instanceof Obj) {
            $v->set('mcp', $b->get('mcp')->has('tool') ? Obj::of(['tool' => $b->get('mcp')->get('tool')]) : new Obj());
        }
        if ($b->get('openapi') instanceof Obj) {
            $v->set('openapi', $b->get('openapi')->has('operationId') ? Obj::of(['operationId' => $b->get('openapi')->get('operationId')]) : new Obj());
        }
        if ($n->has('description')) {
            $v->set('description', $n->get('description'));
        }
        return Obj::of(['verb' => $v, 'units' => $units]);
    }

    private static function isReadOnly(array $effects): bool
    {
        return count($effects) > 0 && count(array_filter($effects, fn($e) => $e === 'read')) === count($effects);
    }

    private static function sentence(string $s): string
    {
        return $s !== '' && str_contains('.!?', substr($s, -1)) ? $s : $s . '.';
    }

    /** @param list<string> $xs */
    private static function listText(array $xs): string
    {
        if (count($xs) <= 1) {
            return $xs[0] ?? '';
        }
        return implode(', ', array_slice($xs, 0, -1)) . ' and ' . $xs[count($xs) - 1];
    }

    /** The deterministic policy card: the title and the phrases of the trait closure, riskiest first. @param array<string,mixed> $eff effectiveWith result */
    public static function cardOf(Obj $d, array $eff, array $reg): Obj
    {
        $ts = array_map(fn($i) => $reg[$i], Actions::closure($reg, $eff['traits']));
        usort($ts, fn($a, $b) => ($b['floor']['risk'] <=> $a['floor']['risk']) ?: strcmp(AnalyzerJs::u16key($a['id']), AnalyzerJs::u16key($b['id'])));
        $phrases = array_values(array_unique(array_map(fn($t) => $t['card_phrase'], $ts)));
        $e = $eff['eff'];
        $second = $eff['confirmed']
            ? ($phrases ? 'This action ' . self::listText($phrases) . '.' : 'This action only reads.')
            : 'This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it ' . self::listText($phrases) . '.';
        return Obj::of(['verb' => $d->get('verb'), 'title' => $d->get('title'), 'text' => self::sentence($d->get('title')) . ' ' . $second,
            'risk' => self::RISK_NAMES[$e['risk']], 'escalation' => self::ESC_TIERS[$e['esc']], 'reversibility' => $e['rev'], 'blast_ppm' => self::num($e['blast_ppm']),
            'needs' => $e['caveats'], 'context' => $e['context']]);
    }

    /** The reversibility score of the risk inputs. */
    public const REVERSIBILITY_SCORE = ['reversible' => 1, 'rate_limited' => 0.4, 'irreversible' => 0];
    private const CORE_NAMESPACE = 'pca.';

    private static function u16(array $xs): array
    {
        usort($xs, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        return $xs;
    }

    /** Nested plain objects become dotted keys (up to 3 segments); arrays and scalars are leaves; a deeper object stays a leaf. */
    public static function flattenParams(Obj $params): Obj
    {
        $out = new Obj();
        $walk = static function (string $prefix, int $depth, mixed $v) use (&$walk, $out): void {
            if ($v instanceof Obj && $depth < Actions::MAX_PARAM_PATH_DEPTH && count($v->keys()) > 0) {
                foreach ($v->keys() as $k) {
                    $walk($prefix === '' ? $k : "$prefix.$k", $depth + 1, $v->get($k));
                }
            } else {
                $out->set($prefix, $v);
            }
        };
        foreach ($params->keys() as $k) {
            $walk($k, 1, $params->get($k));
        }
        return $out;
    }

    /** The unique param carrying $role, or throws no_param / ambiguous_param. */
    public static function paramByRole(Obj $d, string $role): string
    {
        $params = $d->get('params');
        $hits = self::u16(array_values(array_filter($params->keys(), static fn(string $n): bool => $params->get($n)->get('role') === $role)));
        if (!$hits) {
            throw new ActionKitError('no_param', "'" . $d->get('verb') . "' has no parameter with role $role");
        }
        if (count($hits) > 1) {
            throw new ActionKitError('ambiguous_param', "'" . $d->get('verb') . "' has several parameters with role $role");
        }
        return $hits[0];
    }

    /** The one adapter to the Goal IR's 4 classes: read | reversible | external_send | irreversible. */
    public static function effectClass(Obj $d): string
    {
        $n = Actions::normalize($d);
        if (self::isReadOnly($n->get('effects'))) {
            return 'read';
        }
        if (Actions::worstReversibility($n->get('reversibility'), $n->get('params')) === 'irreversible') {
            return 'irreversible';
        }
        foreach ($n->get('effects') as $e) {
            if (in_array($e, ['send', 'publish', 'export'], true)) {
                return 'external_send';
            }
        }
        return 'reversible';
    }

    /**
     * The unsigned v2 schema document of a set of defs (verbs sorted; units merged, a conflicting redefinition refused). $meta: {site, aud, version, pack?}.
     *
     * @param list<Obj> $defs
     */
    public static function toSchemaDoc(array $defs, array $reg, Obj $meta, ?\Closure $verifier = null): Obj
    {
        usort($defs, static fn(Obj $a, Obj $b): int => Actions::u16Order($a->get('verb'), $b->get('verb')));
        $verbs = [];
        $units = new Obj();
        $seen = [];
        foreach ($defs as $d) {
            if (isset($seen[$d->get('verb')])) {
                throw new ActionKitError('duplicate_verb', "verb '" . $d->get('verb') . "' appears twice");
            }
            $seen[$d->get('verb')] = true;
            $o = self::toSchemaVerb($d, $reg, $verifier);
            $verbs[] = $o->get('verb');
            foreach ($o->get('units')->keys() as $uid) {
                $u = $o->get('units')->get($uid);
                $prev = $units->get($uid);
                if ($prev !== null && (Js::stringify($prev->get('kind')) !== Js::stringify($u->get('kind')) || Js::stringify($prev->get('currency')) !== Js::stringify($u->get('currency'))
                    || Js::stringify($prev->get('exponent')) !== Js::stringify($u->get('exponent')))) {
                    throw new ActionKitError('unit_conflict', "unit '$uid' is declared with two different definitions");
                }
                $units->set($uid, $u);
            }
        }
        $custom = array_values(array_filter($reg, static fn(array $t): bool => !str_starts_with($t['id'], self::CORE_NAMESPACE)));
        usort($custom, static fn(array $a, array $b): int => Actions::u16Order($a['id'], $b['id']));
        $doc = Obj::of(['v' => new Num('2'), 'kind' => 'pca-action-schema', 'site' => $meta->get('site'), 'aud' => $meta->get('aud'), 'version' => $meta->get('version')]);
        if (count($units->keys()) > 0) {
            $doc->set('units', $units);
        }
        $doc->set('verbs', $verbs);
        $doc->set('traits_digest', Actions::traitsDigest($reg));
        if ($custom) {
            $doc->set('trait_defs', array_map(Actions::traitObj(...), $custom));
        }
        if ($meta->get('pack') !== null) {
            $doc->set('pack', $meta->get('pack'));
        }
        return $doc;
    }

    /**
     * {ok: true, op: {verb, resource, params}} or {ok: false, reason}: refuses (never guesses) a missing or non-matching id. $call: {params}.
     *
     * @return array<string,mixed>
     */
    public static function operationOf(Obj $d, Obj $call): array
    {
        $flat = self::flattenParams($call->get('params'));
        $dparams = $d->get('params');
        $declared = self::u16($dparams->keys());
        $params = new Obj();
        foreach ($declared as $k) {
            if ($flat->has($k)) {
                $params->set($k, $flat->get($k));
            }
        }
        $res = $d->get('resource');
        $rtype = $res->get('type');
        $rid = $res->get('id');
        if (!($rid === '*') && $rid->has('exact')) {
            $resource = $rtype . ':' . $rid->get('exact');
        } else {
            $idParam = null;
            foreach ($declared as $n) {
                if ($dparams->get($n)->get('role') === 'id.' . $rtype) {
                    $idParam = $n;
                    break;
                }
            }
            $val = $idParam !== null ? $params->get($idParam) : null;
            if (is_string($val)) {
                if (!ActionsIdPattern::idMatches($rid, $val)) {
                    return ['ok' => false, 'reason' => "the id '$val' does not match the resource pattern of " . $d->get('verb')];
                }
                $resource = "$rtype:$val";
            } elseif ($res->get('scope') !== 'one') {
                $resource = "$rtype:*";
            } else {
                return ['ok' => false, 'reason' => $d->get('verb') . " needs a parameter with role id.$rtype to name its resource"];
            }
        }
        return ['ok' => true, 'op' => Obj::of(['verb' => $d->get('verb'), 'resource' => $resource, 'params' => $params])];
    }

    private static function unit01(float $x): float
    {
        return min(1.0, max(0.0, $x));
    }

    /**
     * Risk inputs for a call: reversibility score and blast from the effective profile; a money.amount param makes the blast amount/kappa from the
     * signed kappa (missing or invalid: 1, the worst case). Reads nothing the agent claims.
     *
     * @return array<string,mixed>
     */
    public static function riskOf(Obj $d, array $eff, mixed $params = null, ?Obj $opts = null): array
    {
        $blast = self::unit01($eff['eff']['blast_ppm'] / 1000000);
        $dp = $d->get('params');
        $money = self::u16(array_values(array_filter($dp->keys(), static fn(string $n): bool => $dp->get($n)->get('role') === 'money.amount')));
        if ($money) {
            $flat = $params instanceof Obj && count($params->keys()) > 0 ? self::flattenParams($params) : new Obj();
            $amount = Js::num($flat->get($money[0]));
            $kappa = $opts === null ? null : Js::num($opts->get('kappa'));
            $blast = $amount !== null && is_finite($amount) && $amount >= 0 && $kappa !== null && $kappa > 0 ? self::unit01($amount / $kappa) : 1;
        }
        $out = ['reversibility' => self::REVERSIBILITY_SCORE[$eff['eff']['rev']], 'blastRadius' => $blast, 'confidence' => 1];
        $t = $opts === null ? null : Js::num($opts->get('taint'));
        if ($t !== null && is_finite($t)) {
            $out['taint'] = self::unit01($t);
        }
        return $out;
    }

    /** `<type>:<prefix>*`, `<type>:<exact>` or `<type>:*`. */
    public static function resourceMatcher(Obj $d): string
    {
        $rtype = $d->get('resource')->get('type');
        $rid = $d->get('resource')->get('id');
        if ($rid === '*') {
            return $rtype . ':*';
        }
        return $rid->has('exact') ? $rtype . ':' . $rid->get('exact') : $rtype . ':' . $rid->get('prefix') . '*';
    }

    /** The policy predicate scaffold; a money limit on a def with no money.amount parameter throws (never silently unbounded). */
    public static function predicatesOf(Obj $d, ?Obj $limits = null): Obj
    {
        $out = Obj::of(['verb' => $d->get('verb'), 'resource' => self::resourceMatcher($d)]);
        if ($limits !== null && $limits->has('max_amount')) {
            $m = $limits->get('max_amount');
            $f = Js::num($m);
            if ($f === null || !is_finite($f) || fmod($f, 1.0) != 0.0 || abs($f) > 9007199254740991 || ($f == 0.0 && fdiv(1.0, $f) < 0) || $f < 0) {
                throw new ActionKitError('bad_limit', 'max_amount must be a non-negative safe integer');
            }
            $name = self::paramByRole($d, 'money.amount');
            $out->set('where', [Obj::of(['field' => 'action.params.' . $name, 'op' => 'lte', 'value' => $m]), Obj::of(['field' => 'action.params.' . $name, 'op' => 'gte', 'value' => new Num('0')])]);
        }
        return $out;
    }

    private static function ontParam(Obj $d, Obj $p): Obj
    {
        $u = $p->get('unit');
        if ($u !== null) {
            if ($u->get('kind') === 'money') {
                $c = $u->get('ccy');
                if (is_string($c)) {
                    return Obj::of(['kind' => 'money', 'ccys' => [$c]]);
                }
                $cp = $d->get('params')->get($c->get('from'));
                return Obj::of(['kind' => 'money', 'ccys' => $cp !== null && $cp->get('values') !== null ? self::u16($cp->get('values')) : []]);
            }
            $k = $u->get('kind');
            return Obj::of(['kind' => $k === 'duration' ? 'duration' : ($k === 'bytes' ? 'bytes' : ($k === 'ratio' ? 'ratio' : 'count'))]);
        }
        $role = $p->get('role');
        $fmt = $p->get('format');
        if ($role !== null && str_starts_with($role, 'id.')) {
            return Obj::of(['kind' => 'id', 'of' => substr($role, 3)]);
        }
        if ($fmt !== null && str_starts_with($fmt, 'id:')) {
            return Obj::of(['kind' => 'id', 'of' => substr($fmt, 3)]);
        }
        switch ($p->get('type')) {
            case 'duration':
                return Obj::of(['kind' => 'duration']);
            case 'datetime':
            case 'date':
                return Obj::of(['kind' => 'instant']);
            case 'integer':
                return Obj::of(['kind' => 'count']);
            case 'boolean':
                return Obj::of(['kind' => 'enum', 'values' => ['false', 'true']]);
            case 'set':
                return Obj::of(['kind' => 'enum', 'values' => self::u16($p->get('values') ?? [])]);
            case 'string':
                return $p->get('values') !== null ? Obj::of(['kind' => 'enum', 'values' => self::u16($p->get('values'))]) : Obj::of(['kind' => 'text']);
        }
        return Obj::of(['kind' => 'text']);
    }

    /**
     * Ontology terms for a set of defs; `effect` is derived (effectClass), never overridden.
     *
     * @param list<Obj> $defs
     */
    public static function toOntology(array $defs, array $reg, ?\Closure $verifier = null): Obj
    {
        usort($defs, static fn(Obj $a, Obj $b): int => Actions::u16Order($a->get('verb'), $b->get('verb')));
        $types = new Obj();
        $units = new Obj();
        $verbs = [];
        $aliases = new Obj();
        $traits = new Obj();
        foreach ($defs as $d) {
            $rid = $d->get('resource')->get('id');
            $prefix = $rid === '*' || $rid->has('exact') ? '' : $rid->get('prefix');
            if (!$types->has($d->get('resource')->get('type'))) {
                $types->set($d->get('resource')->get('type'), $prefix);
            }
            $params = new Obj();
            foreach (self::u16($d->get('params')->keys()) as $name) {
                $p = $d->get('params')->get($name);
                $params->set($name, self::ontParam($d, $p));
                $u = $p->get('unit');
                if ($u !== null && $u->get('kind') === 'money' && is_string($u->get('ccy'))) {
                    $e = Obj::of(['kind' => 'money']);
                    if ($u->has('exp')) {
                        $e->set('exponent', $u->get('exp'));
                    }
                    $units->set($u->get('ccy'), $e);
                } elseif ($u !== null && $u->get('kind') !== 'money') {
                    $units->set($u->get('kind'), Obj::of(['kind' => $u->get('kind')]));
                }
            }
            $verbs[] = Obj::of(['id' => $d->get('verb'), 'effect' => self::effectClass($d), 'resource_type' => $d->get('resource')->get('type'), 'params' => $params]);
            foreach ($d->get('aliases') ?? [] as $a) {
                if ($aliases->has($a) && $aliases->get($a) !== $d->get('verb')) {
                    throw new ActionKitError('alias_collision', "alias '$a' names two verbs");
                }
                $aliases->set($a, $d->get('verb'));
            }
            $traits->set($d->get('verb'), self::effectiveWith($d, $reg, $verifier)['traits']);
        }
        $tl = [];
        foreach ($types->keys() as $i) {
            $tl[] = Obj::of(['id' => $i, 'id_prefix' => $types->get($i)]);
        }
        return Obj::of(['types' => $tl, 'units' => $units, 'verbs' => $verbs, 'aliases' => $aliases, 'traits' => $traits]);
    }

    /** The minimum escalation tier of the effective profile. @return array{tier:int,name:string} */
    public static function escalationOf(array $eff): array
    {
        return ['tier' => $eff['eff']['esc'], 'name' => self::ESC_TIERS[$eff['eff']['esc']]];
    }

    /** Advisory MCP tool annotations; an unreviewed def's own claim of safety is never advertised. @return array<string,bool> */
    public static function mcpAnnotationsOf(Obj $d, array $eff): array
    {
        $cl = $eff['closure'];
        $idem = $d->get('idempotency') instanceof Obj && $d->get('idempotency')->has('mode') ? $d->get('idempotency')->get('mode') : 'none';
        $ro = self::isReadOnly($d->get('effects'));
        return ['readOnlyHint' => $eff['confirmed'] && $ro, 'destructiveHint' => in_array('pca.destructive', $cl, true),
            'idempotentHint' => $eff['confirmed'] && ($idem !== 'none' || $ro),
            'openWorldHint' => in_array('pca.network_egress', $cl, true) || in_array('pca.external_communication', $cl, true)];
    }

    private static function blastText(int $ppm): string
    {
        return $ppm % 1000 === 0 ? intdiv($ppm, 1000) . 'k' : $ppm . 'ppm';
    }

    /** The plain-language profile of one def: card, effective profile, what a grant must carry, traits and review state. */
    public static function explainDef(Obj $d, array $reg, ?\Closure $verifier = null): string
    {
        $eff = self::effectiveWith($d, $reg, $verifier);
        $card = self::cardOf($d, $eff, $reg);
        $e = $eff['eff'];
        $rev = $e['rev'] === 'irreversible' ? 'irreversible' : ($e['rev'] === 'rate_limited' ? 'rate limited' : 'reversible');
        $needs = $card->get('needs');
        $ctx = $card->get('context');
        $lines = [$card->get('text'), "effective: risk {$e['risk']}, $rev, blast " . self::blastText($e['blast_ppm']) . ', escalation: ' . $card->get('escalation'),
            'grant must carry: ' . ($needs ? implode(', ', $needs) : 'nothing')];
        if ($ctx) {
            $lines[] = 'call must carry: ' . implode(', ', $ctx);
        }
        $lines[] = 'traits: ' . (implode(', ', $eff['closure']) ?: 'none');
        $state = $d->get('review')->get('state');
        $lines[] = 'review: ' . ($eff['confirmed'] ? $state : "$state, not confirmed by a signed review");
        if (!$eff['confirmed']) {
            $h = $eff['hint'];
            $lines[] = "until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk {$h['eff']['risk']}, escalation tier {$h['eff']['esc']}, traits: "
                . (implode(', ', $h['closure']) ?: 'none');
        }
        return implode("\n", $lines);
    }
}
