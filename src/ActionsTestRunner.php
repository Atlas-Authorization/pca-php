<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsAuthor.php';
require_once __DIR__ . '/ActionsDerive.php';
require_once __DIR__ . '/ActionsEffective.php';
require_once __DIR__ . '/ActionsYaml.php';
require_once __DIR__ . '/IntentV2Schema.php';
require_once __DIR__ . '/Js.php';

/**
 * Run every def's executable examples through the real pipeline in process (native port of test-runner.ts of the reference actions package):
 * derive the schema, conform the params, expand the floors, decide; plus the generic property checks of the pack: monotonicity over trait
 * additions and subsets, one digest across the JSON and YAML forms, and the schema round trip (the example conforms; every mutation of it is
 * refused). The example policy (`under`) is a small allow selector evaluated here; it can only pre-authorize.
 */
final class ActionsTestRunner
{
    private const SEL_KEYS = ['trait', 'verb', 'where', 'caveats', 'context'];

    private static function meta(): Obj
    {
        return Obj::of(['site' => 'https://example.invalid', 'aud' => 'example', 'version' => '0']);
    }

    /** Examples and property checks describe the action AS REVIEWED (its hint view): authoring tests, not enforcement. */
    private static function hintOf(Obj $d, array $reg): array
    {
        $e = ActionsDerive::effectiveWith($d, $reg);
        return array_merge($e, $e['hint'], ['confirmed' => true]);
    }

    /** @return list<Obj>|string the selectors, or the reason they are malformed */
    private static function parseUnder(Obj $ex): array|string
    {
        if (!$ex->has('under')) {
            return [];
        }
        $under = $ex->get('under');
        if (!($under instanceof Obj) || array_diff($under->keys(), ['allow']) !== []) {
            return 'under must be {allow: selector | [selector]}';
        }
        $allow = $under->get('allow');
        $out = [];
        foreach ((is_array($allow) && array_is_list($allow) ? $allow : [$allow]) as $s) {
            if (!($s instanceof Obj) || array_diff($s->keys(), self::SEL_KEYS) !== []) {
                return 'an allow selector has trait, verb, where, caveats, context';
            }
            if ($s->has('trait') === $s->has('verb')) {
                return 'an allow selector names exactly one of trait and verb';
            }
            if ($s->has('where') && !($s->get('where') instanceof Obj)) {
                return 'where must be an object';
            }
            if ($s->has('caveats')) {
                $c = $s->get('caveats');
                if (!is_array($c) || !array_is_list($c) || array_filter($c, static fn($x) => !in_array($x, Actions::CAVEAT_KINDS, true)) !== []) {
                    return 'caveats must be known caveat kinds';
                }
            }
            $out[] = $s;
        }
        return $out;
    }

    private static function domainOf(string $v): string
    {
        $i = strrpos($v, '@');
        return mb_strtolower(substr($v, $i === false ? 0 : $i + 1));
    }

    /**
     * The caveats of the grant a matching allow selector stands for, or null when it does not match this call.
     *
     * @return list<string>|null
     */
    private static function grantOf(Obj $sel, Obj $d, Obj $flat, array $eff): ?array
    {
        if ($sel->has('trait')) {
            $t = (string)$sel->get('trait');
            if (!in_array(str_contains($t, '.') ? $t : 'pca.' . $t, $eff['closure'], true)) {
                return null;
            }
        }
        if ($sel->has('verb') && $sel->get('verb') !== $d->get('verb')) {
            return null;
        }
        $caveats = [];
        foreach ($sel->get('caveats') ?? [] as $c) {
            $caveats[$c] = true;
        }
        $where = $sel->get('where');
        foreach ($where instanceof Obj ? $where->keys() : [] as $key) {
            $cond = $where->get($key);
            $dom = str_ends_with($key, '.domain');
            $name = $dom ? substr($key, 0, -strlen('.domain')) : $key;
            $pd = $d->get('params')->get($name);
            if (!$pd || !$flat->has($name)) {
                return null;
            }
            $v = $flat->get($name);
            if (is_array($cond) && array_is_list($cond)) {
                if (!is_string($v) || !in_array($dom ? self::domainOf($v) : $v, $cond, true)) {
                    return null;
                }
            } elseif ($cond instanceof Obj) {
                $f = Js::num($v);
                if ($f === null || ($cond->has('max') && $f > Js::num($cond->get('max'))) || ($cond->has('min') && $f < Js::num($cond->get('min')))) {
                    return null;
                }
            } else {
                return null;
            }
            $role = $pd->get('role') ?? '';
            if (str_starts_with($role, 'contact.') || $role === 'party.payee') {
                $caveats['recipient_scope'] = true;
            } elseif ($role === 'money.amount') {
                $caveats['amount_cap'] = true;
            } elseif ($role === 'count.limit') {
                $caveats['count_cap'] = true;
            } elseif (str_starts_with($role, 'id.')) {
                $caveats['resource_scope'] = true;
            }
        }
        return array_map('strval', array_keys($caveats));
    }

    /**
     * Decide one example: {got, why}.
     *
     * @param list<Obj> $defs
     * @return array{got:string,why:string}
     */
    public static function decideExample(Obj $d, Obj $ex, array $reg, array $defs): array
    {
        $doc = ActionsDerive::toSchemaDoc($defs, $reg, self::meta());
        $flat = ActionsDerive::flattenParams($ex->get('params'));
        $c = IntentV2::conformAction($doc, $d->get('verb'), $flat);
        if (!$c['ok']) {
            return ['got' => 'deny', 'why' => 'schema_violation ' . ($c['code'] ?? 'None') . (!empty($c['path']) ? ' (' . $c['path'] . ')' : '')];
        }
        $op = ActionsDerive::operationOf($d, Obj::of(['params' => $ex->get('params')]));
        if (!$op['ok']) {
            return ['got' => 'deny', 'why' => $op['reason']];
        }
        $sels = self::parseUnder($ex);
        if (is_string($sels)) {
            return ['got' => 'deny', 'why' => "bad example policy: $sels"];
        }
        $eff = self::hintOf($d, $reg);
        $callCtx = [];
        $idem = $d->get('idempotency');
        if ($idem instanceof Obj && $idem->get('mode') === 'natural') {
            $callCtx['idempotency'] = true;
        }
        if ($idem instanceof Obj && $idem->get('mode') === 'key_param' && $idem->get('param') !== null && $flat->has($idem->get('param'))) {
            $callCtx['idempotency'] = true;
        }
        $grantCaveats = [];
        $pre = 0;
        foreach ($sels as $s) {
            $g = self::grantOf($s, $d, $flat, $eff);
            if ($g === null) {
                continue;
            }
            $pre = 3;
            $grantCaveats = array_values(array_unique(array_merge($grantCaveats, $g)));
            foreach ($s->get('context') ?? [] as $k) {
                $callCtx[$k] = true;
            }
        }
        $got = Actions::floorDecision(Obj::of(['caveats' => $grantCaveats, 'max_esc' => new Num('3'), 'preauth_esc' => new Num((string)$pre)]),
            Obj::of(['context' => array_map('strval', array_keys($callCtx))]), $eff['eff']);
        if ($got === 'allow') {
            $why = 'floor satisfied';
        } else {
            $need = implode(', ', array_merge(array_filter($eff['eff']['caveats'], static fn($k) => !in_array($k, $grantCaveats, true)),
                array_filter($eff['eff']['context'], static fn($k) => !isset($callCtx[$k]))));
            $why = 'floor needs ' . ($need !== '' ? $need : 'escalation tier ' . $eff['eff']['esc']);
        }
        return ['got' => $got, 'why' => $why];
    }

    private static function with(Obj $flat, string $k, mixed $v): Obj
    {
        $o = $flat->without();
        $o->set($k, $v);
        return $o;
    }

    /** @return list<array{name:string,params:Obj}> */
    private static function mutations(Obj $d, Obj $flat): array
    {
        $out = [['name' => 'extra param', 'params' => self::with($flat, 'zz_undeclared', 'x')]];
        $keys = $flat->keys();
        usort($keys, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        foreach ($keys as $k) {
            $pd = $d->get('params')->get($k);
            if (!$pd) {
                continue;
            }
            if ($pd->get('required') !== false) {
                $out[] = ['name' => "missing $k", 'params' => $flat->without($k)];
            }
            $v = $flat->get($k);
            $num = Js::isNum($v);
            $out[] = ['name' => "type swap $k", 'params' => self::with($flat, $k, is_string($v) ? new Num('12345') : ($num || is_bool($v) ? 'x' : new Obj()))];
            if ($num && $pd->get('type') === 'integer') {
                if ($pd->get('max') !== null) {
                    $out[] = ['name' => "above max $k", 'params' => self::with($flat, $k, new Num((string)(Js::num($pd->get('max')) + 1)))];
                }
                if ($pd->get('min') !== null) {
                    $out[] = ['name' => "below min $k", 'params' => self::with($flat, $k, new Num((string)(Js::num($pd->get('min')) - 1)))];
                }
            }
            if (is_string($v) && $pd->get('type') === 'string') {
                if ($pd->get('values')) {
                    $out[] = ['name' => "outside values $k", 'params' => self::with($flat, $k, 'not_a_listed_value_zz')];
                }
                if ($pd->get('max_len') !== null) {
                    $out[] = ['name' => "too long $k", 'params' => self::with($flat, $k, str_repeat('x', (int)Js::num($pd->get('max_len')) + 1))];
                }
            }
        }
        return $out;
    }

    /** The def through real YAML text (written by the YAML writer, read by the YAML loader). */
    private static function yamlForm(Obj $d): Obj
    {
        $ns = explode('.', $d->get('verb'))[0];
        return ActionsAuthor::loadActionsText(ActionsYaml::stringify(Obj::of(['ns' => $ns, 'actions' => [$d]])), 'yaml');
    }

    private static function loadedOk(Obj $r, string $want): bool
    {
        return count($r->get('errors')) === 0 && count($r->get('defs')) > 0 && Actions::defDigest($r->get('defs')[0]) === $want;
    }

    private static function loadedWhy(Obj $r, bool $ok): string
    {
        return $ok ? 'ok' : (count($r->get('errors')) ? $r->get('errors')[0]->get('message') : 'digest differs');
    }

    /**
     * Run examples and property checks for a set of defs (one pack). $propLimit bounds the trait subsets tried per def; $yamlLoad(def) -> load result
     * replaces the built-in emit-and-load round trip.
     *
     * @param list<Obj> $defs
     * @return array{examples:list<array<string,mixed>>,props:list<array<string,mixed>>,ok:bool}
     */
    public static function runDefTests(array $defs, array $reg, ?int $propLimit = null, ?\Closure $yamlLoad = null): array
    {
        $examples = [];
        $props = [];
        $limit = $propLimit ?? 256;
        foreach ($defs as $d) {
            $verb = $d->get('verb');
            foreach ($d->get('examples') ?? [] as $index => $ex) {
                $r = self::decideExample($d, $ex, $reg, $defs);
                $examples[] = ['verb' => $verb, 'index' => $index, 'expect' => $ex->get('expect'), 'got' => $r['got'], 'ok' => $r['got'] === $ex->get('expect'), 'why' => $r['why']];
            }
            // T2: adding any core trait never lowers the effective profile
            $eff = self::hintOf($d, $reg);
            $lowered = array_values(array_filter(array_map('strval', array_keys(Actions::coreRegistry())), static fn(string $t): bool => !Actions::leq($eff['eff'], ActionsEffective::effWithTrait($d, $t, $reg))));
            $props[] = ['verb' => $verb, 'name' => 'adding a trait never lowers the profile', 'ok' => count($lowered) === 0, 'detail' => implode(', ', $lowered)];
            // T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
            $ts = $eff['traits'];
            $bad = 0;
            $total = min(2 ** min(count($ts), 20), $limit);
            $top = Actions::floorOf($reg, $ts);
            for ($mask = 0; $mask < $total; $mask++) {
                $sub = [];
                foreach ($ts as $i => $t) {
                    if (($mask >> ($i % 32)) & 1) { // 32-bit shift counts, as in the reference
                        $sub[] = $t;
                    }
                }
                if (!Actions::leq(Actions::floorOf($reg, $sub), $top)) {
                    $bad++;
                }
            }
            $props[] = ['verb' => $verb, 'name' => 'floors are monotone over trait subsets', 'ok' => $bad === 0, 'detail' => "$total subsets, $bad violations"];
            // one digest across the JSON and YAML forms
            $want = Actions::defDigest($d);
            $viaJson = ActionsAuthor::loadActionsText(Js::stringify($d), 'json');
            $viaYaml = $yamlLoad !== null ? $yamlLoad($d) : self::yamlForm($d);
            $okJ = self::loadedOk($viaJson, $want);
            $okY = self::loadedOk($viaYaml, $want);
            $props[] = ['verb' => $verb, 'name' => 'one digest across JSON and YAML forms', 'ok' => $okJ && $okY,
                'detail' => $okJ && $okY ? '' : 'json ' . self::loadedWhy($viaJson, $okJ) . '; yaml ' . self::loadedWhy($viaYaml, $okY)];
            // schema round trip: each example conforms, every mutation is refused
            if (count($d->get('examples') ?? []) === 0) {
                $props[] = ['verb' => $verb, 'name' => 'schema round trip', 'ok' => true, 'detail' => 'skipped: no examples'];
                continue;
            }
            $doc = ActionsDerive::toSchemaDoc($defs, $reg, self::meta());
            $accepted = [];
            $tried = 0;
            foreach ($d->get('examples') as $ex) {
                $flat = ActionsDerive::flattenParams($ex->get('params'));
                if (!IntentV2::conformAction($doc, $verb, $flat)['ok']) {
                    continue; // a deliberately non-conforming example is a deny example
                }
                foreach (self::mutations($d, $flat) as $m) {
                    $tried++;
                    if (IntentV2::conformAction($doc, $verb, $m['params'])['ok']) {
                        $accepted[] = $m['name'];
                    }
                }
            }
            $props[] = ['verb' => $verb, 'name' => 'schema round trip', 'ok' => count($accepted) === 0,
                'detail' => !$accepted ? "$tried mutations refused" : 'accepted: ' . implode(', ', array_unique($accepted))];
        }
        $ok = true;
        foreach (array_merge($examples, $props) as $x) {
            $ok = $ok && $x['ok'];
        }
        return ['examples' => $examples, 'props' => $props, 'ok' => $ok];
    }

    private static function fv(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : ($o[$k] ?? null);
    }

    /** The plain text of a run: one line per example and property, then the totals. */
    public static function testText(mixed $r): string
    {
        $lines = [];
        foreach (self::fv($r, 'examples') as $e) {
            $idx = self::fv($e, 'index');
            $lines[] = (self::fv($e, 'ok') ? 'PASS' : 'FAIL') . '  ' . self::fv($e, 'verb') . ' example ' . ((int)Js::num($idx) + 1) . ': expected ' . self::fv($e, 'expect')
                . ', got ' . self::fv($e, 'got') . ' (' . self::fv($e, 'why') . ')';
        }
        foreach (self::fv($r, 'props') as $q) {
            $detail = self::fv($q, 'detail');
            $lines[] = (self::fv($q, 'ok') ? 'PASS' : 'FAIL') . '  ' . self::fv($q, 'verb') . ' ' . self::fv($q, 'name') . ($detail ? ": $detail" : '');
        }
        $f = count(array_filter($lines, static fn(string $l): bool => str_starts_with($l, 'FAIL')));
        $lines[] = (count($lines) - $f) . " passed, $f failed";
        return implode("\n", $lines);
    }
}
