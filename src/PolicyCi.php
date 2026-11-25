<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/AnalyzerCore.php';
require_once __DIR__ . '/AnalyzerCoverage.php';
require_once __DIR__ . '/AnalyzerExposure.php';
require_once __DIR__ . '/AnalyzerValidate.php';

/**
 * The policy-safety CI gate. It drives the static analyzer over an envelope, a grant, a compiled policy, a bare
 * `{predicates, caveats}` or a delegation chain and reports findings: five toggleable rules plus schema mismatch. A hard `error`
 * is emitted only from a PROVEN analyzer verdict; any undecidable feature fails safe to a `warn` / `info` that says so. Also the
 * authoring gates (`diff`, `test`, `coverage`), the pinned lint-rule digest and the command line (`run`, `parseArgs`). Findings and
 * results are plain objects (Obj).
 */
final class PolicyCi
{
    public const DEFAULT_DANGEROUS_VERBS = ['delete', 'destroy', 'drop', 'remove', 'purge', 'transfer', 'payout', 'wire', 'withdraw', 'admin',
        'grant', 'revoke', 'deploy', 'shutdown', 'rotate'];
    public const SCOPE_NARROWING_CAVEATS = ['max_blast_radius', 'rate', 'reversibility_max', 'budget_alloc', 'delegation_depth'];
    public const BUDGET_GATE_CAVEATS = ['max_blast_radius', 'rate', 'budget_alloc'];
    public const LINT_RULES_DIGEST_DOMAIN = 'atlas-pca/action-lint-rules/v1';

    private const SEVERITY_RANK = ['info' => 1, 'warn' => 2, 'error' => 3];
    private const ORDERED_CAVEATS = [['expires', 'at', 'min'], ['not_before', 'at', 'max'], ['max_blast_radius', 'max', 'min'],
        ['delegation_depth', 'max', 'min'], ['budget_alloc', 'limit', 'min']];
    private const NUMERIC_OPS = ['lt', 'lte', 'gt', 'gte', 'eq'];
    private const SEVERITIES = ['error', 'warn', 'info'];
    private const GH_LEVEL = ['error' => 'error', 'warn' => 'warning', 'info' => 'notice'];
    private const TEXT_TAG = ['error' => 'ERROR', 'warn' => 'WARN', 'info' => 'INFO'];
    private const VALUED = ['--verb', '--amount-field', '--window-secs', '--max-exposure-increase', '--min-clauses', '--min-boundaries', '--min-mutation', '--max-survivors'];
    private const BOOLS = ['--allow-widen', '--integer', '--require-digest'];
    private const LINT_RULES = [
        ['LD-001', 'error', 'a destroy-like verb whose effects do not delete'],
        ['LD-002', 'error', 'a money parameter without a currency, or a currency without the iso_currency format'],
        ['LD-003', 'error', 'a numeric parameter without min and max'],
        ['LD-004', 'error', 'a money-moving action without idempotency'],
        ['LD-005', 'error', 'personal data can leave without the matching effect'],
        ['LD-006', 'error', 'a declared reversibility or blast below the effective floor'],
        ['LD-007', 'error', 'an unknown trait, role, format, effect or context key, or an invalid custom trait'],
        ['LD-008', 'error', "resource id '*' with scope one"],
        ['LD-009', 'error', 'a duplicate verb or alias collision'],
        ['LD-010', 'error', 'a write marked reversible with no compensating action in the pack'],
        ['LD-011', 'error', 'review state confirmed without a valid attestation for this digest'],
        ['LD-012', 'error', 'a structural param rule that the effective traits require is violated'],
        ['LD-013', 'error', 'a read-only action that can mutate or handles credentials'],
        ['LD-014', 'error', 'one binding in two defs'],
        ['LW-001', 'warning', 'description missing or too long, or title not imperative'],
        ['LW-002', 'warning', 'a string parameter without max_len'],
        ['LW-003', 'warning', 'free text flows into an outbound action without the free_text_outbound tag'],
        ['LW-004', 'warning', 'an unreviewed def in a stable pack'],
        ['LW-005', 'warning', 'a dismissed suggested trait without a reason'],
        ['LW-006', 'warning', 'an array parameter without max_items'],
        ['LW-007', 'warning', 'a critical parameter without provenance_min'],
        ['LW-008', 'warning', 'verb naming inconsistent with its siblings or with the file namespace'],
        ['LW-009', 'warning', 'a money-moving, destructive or privilege-changing action without an example'],
        ['LW-010', 'warning', 'since is missing'],
    ];

    public const HELP = <<<'EOT'
pca-policy-ci — statically catch unsafe PCA policies before they ship.

Usage:
  pca-policy-ci <files...> [options]
  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
  pca-policy-ci test <policy.json> <tests.json> [--require-digest]
  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]

Options:
  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)
  --format <text|github>            Output format (default: text; 'github' = workflow annotations)
  --schema <file>                   Also check each policy against this signed action schema (JSON)
  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>
  --quiet, -q                       Only print findings and the summary line
  --help, -h                        Show this help

Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array
treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.
EOT;

    // ---- small helpers ----------------------------------------------------------------------------------------------

    /** The JavaScript String.prototype.trim whitespace set. */
    private static function trim(string $s): string
    {
        $ws = '[\x{9}-\x{d}\x{20}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]';
        $r = preg_replace('/\A' . $ws . '+|' . $ws . '+\z/u', '', $s);
        return $r ?? $s;
    }

    private static function g(mixed $x, string $k): mixed
    {
        return $x instanceof Obj ? $x->get($k) : null;
    }

    /** @return list<string> */
    private static function verbsOf(mixed $verb): array
    {
        if (is_string($verb)) {
            return [$verb];
        }
        if (AnalyzerJs::isArr($verb)) {
            return array_values(array_filter($verb, 'is_string'));
        }
        return [];
    }

    /** A finite number (returned as given), else undefined. */
    private static function num(mixed $x): mixed
    {
        return AnalyzerJs::isFin($x) ? $x : AnalyzerJs::undef();
    }

    private static function isDangerousVerb(string $verb, mixed $dangerous): bool
    {
        $v = mb_strtolower($verb);
        foreach (AnalyzerJs::reqList($dangerous) as $kw) {
            if (!is_string($kw)) {
                throw new \TypeError('a dangerous verb keyword is not a string');
            }
            if (str_contains($v, mb_strtolower($kw))) {
                return true;
            }
        }
        return false;
    }

    private static function isWildcardResource(mixed $resource): bool
    {
        return $resource instanceof Undef || $resource === '*';
    }

    private static function hasCaveatOfType(mixed $caveats, array $types): bool
    {
        foreach (AnalyzerJs::reqList($caveats) as $c) {
            if ($c instanceof Obj && is_string($c->get('type')) && in_array($c->get('type'), $types, true)) {
                return true;
            }
        }
        return false;
    }

    /** Array.prototype.join text of one element: null and undefined are empty. */
    private static function joinPart(mixed $v): string
    {
        return ($v === null || $v instanceof Undef) ? '' : AnalyzerJs::jsStr($v);
    }

    private static function describeAction(mixed $a): string
    {
        $parts = [self::joinPart(AnalyzerJs::jget($a, 'verb')), self::joinPart(AnalyzerJs::jget($a, 'resource'))];
        $params = AnalyzerJs::jget($a, 'params');
        if (AnalyzerJs::truthy($params) && $params instanceof Obj && count($params->keys()) > 0) {
            $parts[] = AnalyzerJs::jsJson($params);
        }
        $rc = AnalyzerJs::jget($a, 'reversibilityClass');
        if (!($rc instanceof Undef)) {
            $parts[] = '[' . AnalyzerJs::jsStr($rc) . ']';
        }
        return implode(' ', $parts);
    }

    /** @param list<string> $xs @return list<string> */
    private static function uniq(array $xs): array
    {
        $seen = [];
        $out = [];
        foreach ($xs as $x) {
            if (!isset($seen['k' . $x])) {
                $seen['k' . $x] = true;
                $out[] = $x;
            }
        }
        return $out;
    }

    private static function find(string $rule, string $severity, string $message, ?string $where = null): Obj
    {
        $f = Obj::of(['rule' => $rule, 'severity' => $severity, 'message' => $message]);
        if ($where !== null) {
            $f->set('where', $where);
        }
        return $f;
    }

    private static function n(mixed $x): string
    {
        return AnalyzerJs::numStr(AnalyzerJs::jsnum($x));
    }

    // ---- normalization ----------------------------------------------------------------------------------------------

    /** A minted grant / delegation hop: the content-addressed, signed shape of a capability. */
    public static function isCapability(mixed $x): bool
    {
        return $x instanceof Obj && is_string($x->get('id')) && is_string($x->get('issuer')) && is_string($x->get('holder'))
            && is_string($x->get('body_digest')) && is_string($x->get('sig')) && AnalyzerJs::isArr($x->get('caveats'));
    }

    /** A signed policy envelope (the root intent grant payload). */
    public static function isEnvelope(mixed $x): bool
    {
        return $x instanceof Obj && is_string($x->get('goal_commit')) && AnalyzerJs::isArr($x->get('predicates'))
            && AnalyzerJs::isArr($x->get('caveats')) && $x->get('agent_binding') instanceof Obj && $x->get('risk_policy') instanceof Obj;
    }

    private static function isCompiled(mixed $x): bool
    {
        return $x instanceof Obj && AnalyzerJs::isArr($x->get('predicates')) && AnalyzerJs::isArr($x->get('caveats'))
            && $x->get('riskPolicy') instanceof Obj && AnalyzerJs::isArr($x->get('actions'));
    }

    /** Drop the envelope-carrying caveat; keep the runtime gate caveats (and any appended attenuation). @return list<mixed> */
    private static function runtimeCaveats(array $caveats): array
    {
        $out = [];
        foreach ($caveats as $c) {
            if (!($c instanceof Obj || AnalyzerJs::isArr($c))) {
                continue;
            }
            if ($c instanceof Obj && $c->get('type') === Authorize::ENVELOPE_CAVEAT) {
                continue;
            }
            $out[] = $c;
        }
        return $out;
    }

    private static function fromGrant(Obj $grant): Obj
    {
        $env = Authorize::readEnvelope($grant);
        if ($env === null) {
            return Obj::of(['ok' => false, 'reason' => 'grant has no readable `envelope` caveat (malformed or unsigned payload)']);
        }
        $cs = $grant->get('caveats');
        $appended = self::runtimeCaveats(AnalyzerJs::isArr($cs) ? $cs : []);
        return Obj::of(['ok' => true, 'policy' => AnalyzerJs::uobj([
            'predicates' => $env->get('predicates'),
            'caveats' => array_merge($env->get('caveats'), $appended),
            'riskPolicy' => AnalyzerJs::own($env, 'risk_policy'),
            'kind' => 'grant',
        ])]);
    }

    /** Reduce any single-policy input to its effective authority: {ok: true, policy: {predicates, caveats, riskPolicy?, kind}} or {ok: false, reason}. */
    public static function normalizePolicyInput(mixed $input): Obj
    {
        if (self::isCapability($input)) {
            return self::fromGrant($input);
        }
        if (self::isEnvelope($input)) {
            return Obj::of(['ok' => true, 'policy' => Obj::of(['predicates' => $input->get('predicates'), 'caveats' => $input->get('caveats'),
                'riskPolicy' => $input->get('risk_policy'), 'kind' => 'envelope'])]);
        }
        if (self::isCompiled($input)) {
            return Obj::of(['ok' => true, 'policy' => Obj::of(['predicates' => $input->get('predicates'), 'caveats' => $input->get('caveats'),
                'riskPolicy' => $input->get('riskPolicy'), 'kind' => 'compiled'])]);
        }
        if ($input instanceof Obj && AnalyzerJs::isArr($input->get('predicates'))) {
            $c = $input->get('caveats');
            return Obj::of(['ok' => true, 'policy' => Obj::of(['predicates' => $input->get('predicates'), 'caveats' => AnalyzerJs::isArr($c) ? $c : [], 'kind' => 'bare'])]);
        }
        return Obj::of(['ok' => false, 'reason' => 'unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })']);
    }

    /** Normalize a delegation chain (root to leaf) to one effective policy per hop: {ok: true, hops} or {ok: false, reason}. */
    public static function normalizeChain(mixed $chain): Obj
    {
        $chain = AnalyzerJs::reqList($chain);
        if (count($chain) === 0) {
            return Obj::of(['ok' => false, 'reason' => 'empty chain']);
        }
        $allCaps = true;
        foreach ($chain as $c) {
            if (!self::isCapability($c)) {
                $allCaps = false;
                break;
            }
        }
        if ($allCaps) {
            $env = Authorize::readEnvelope($chain[0]);
            if ($env === null) {
                return Obj::of(['ok' => false, 'reason' => 'root grant has no readable `envelope` caveat']);
            }
            $hops = [];
            foreach ($chain as $cap) {
                $cs = $cap->get('caveats');
                $hops[] = AnalyzerJs::uobj([
                    'predicates' => $env->get('predicates'),
                    'caveats' => array_merge($env->get('caveats'), self::runtimeCaveats(AnalyzerJs::isArr($cs) ? $cs : [])),
                    'riskPolicy' => AnalyzerJs::own($env, 'risk_policy'),
                    'kind' => 'chain-hop',
                ]);
            }
            return Obj::of(['ok' => true, 'hops' => $hops]);
        }
        $hops = [];
        foreach ($chain as $i => $c) {
            $r = self::normalizePolicyInput($c);
            if (!$r->get('ok')) {
                return Obj::of(['ok' => false, 'reason' => 'hop ' . $i . ': ' . $r->get('reason')]);
            }
            $h = AnalyzerJs::copy($r->get('policy'));
            $h->set('kind', 'chain-hop');
            $hops[] = $h;
        }
        return Obj::of(['ok' => true, 'hops' => $hops]);
    }

    // ---- rules ------------------------------------------------------------------------------------------------------

    private static function analyzerInput(Obj $p): Obj
    {
        return Obj::of(['predicates' => $p->get('predicates'), 'caveats' => $p->get('caveats')]);
    }

    /** @return list<string> */
    private static function declaredVerbs(array $predicates): array
    {
        $concrete = [];
        foreach ($predicates as $p) {
            if (!($p instanceof Obj || AnalyzerJs::isArr($p))) {
                continue;
            }
            foreach (self::verbsOf($p instanceof Obj ? $p->get('verb') : null) as $v) {
                if ($v !== '*') {
                    $concrete[] = $v;
                }
            }
        }
        return self::uniq($concrete);
    }

    private static function gateDescription(Obj $policy): ?string
    {
        $gates = [];
        if (self::hasCaveatOfType($policy->get('caveats'), self::BUDGET_GATE_CAVEATS)) {
            $types = [];
            foreach ($policy->get('caveats') as $c) {
                if (AnalyzerJs::includes(self::BUDGET_GATE_CAVEATS, AnalyzerJs::jget($c, 'type'))) {
                    $types[] = AnalyzerJs::jsStr(AnalyzerJs::jget($c, 'type'));
                }
            }
            $gates[] = implode('/', $types);
        }
        $rp = $policy->get('riskPolicy');
        if ($rp !== null) {
            $t2 = $rp instanceof Obj ? AnalyzerJs::own($rp, 'theta2') : AnalyzerJs::undef();
            if (AnalyzerJs::isFin($t2) && AnalyzerJs::jsnum($t2) < 1) {
                $gates[] = 'risk step-up (theta2 < 1)';
            }
        }
        return $gates ? implode(', ', $gates) : null;
    }

    /** A wildcard verb or resource, a dangerous verb with no narrowing, or a proven always-allow. @return list<Obj> */
    public static function ruleOverBroadGrant(Obj $policy, mixed $dangerous, mixed $opts): array
    {
        $out = [];
        $inp = self::analyzerInput($policy);
        $hasScopeNarrowing = self::hasCaveatOfType($policy->get('caveats'), self::SCOPE_NARROWING_CAVEATS);
        foreach ($policy->get('predicates') as $i => $p) {
            if (!($p instanceof Obj || AnalyzerJs::isArr($p))) {
                continue;
            }
            $d = $p instanceof Obj ? $p : new Obj();
            $verbs = self::verbsOf($d->get('verb'));
            $where = 'predicates[' . $i . ']';
            $w = $d->get('where');
            $hasWhere = AnalyzerJs::isArr($w) && count($w) > 0;
            if (in_array('*', $verbs, true)) {
                $out[] = self::find('over-broad-grant', 'error', "predicate grants a WILDCARD verb '*' — authority over any action", $where);
            }
            if (self::isWildcardResource(AnalyzerJs::own($d, 'resource'))) {
                $dv = [];
                foreach ($verbs as $v) {
                    if (self::isDangerousVerb($v, $dangerous)) {
                        $dv[] = $v;
                    }
                }
                if ($dv) {
                    $out[] = self::find('over-broad-grant', 'error', 'dangerous verb(s) ' . AnalyzerJs::jsJson($dv) . " granted on a WILDCARD resource ('*')", $where);
                } elseif (!in_array('*', $verbs, true)) {
                    $out[] = self::find('over-broad-grant', 'warn', "predicate matches ANY resource ('*') — consider a resource prefix", $where);
                }
            }
            foreach ($verbs as $v) {
                if ($v !== '*' && self::isDangerousVerb($v, $dangerous) && !$hasWhere && !$hasScopeNarrowing) {
                    $out[] = self::find('over-broad-grant', 'error', "dangerous verb '" . $v . "' is granted with NO narrowing `where` and no scope-narrowing caveat ("
                        . implode('/', self::SCOPE_NARROWING_CAVEATS) . ')', $where);
                }
            }
        }
        foreach (self::declaredVerbs($policy->get('predicates')) as $v) {
            $aa = AnalyzerCore::alwaysAllows($inp, $v, $opts);
            if (AnalyzerJs::truthy($aa->get('alwaysAllows')) && $aa->get('approximate') !== true) {
                $out[] = self::find('over-broad-grant', 'error', "grants EVERY action of '" . $v . "' — the authority has no effective constraint (always-allow)");
            }
        }
        return $out;
    }

    /** A delegation hop whose effective authority is not a subset of its parent's. @param list<Obj> $hops @return list<Obj> */
    public static function rulePrivilegeEscalation(array $hops, mixed $opts): array
    {
        $out = [];
        for ($i = 1; $i < count($hops); $i++) {
            $s = AnalyzerCore::subsumes(self::analyzerInput($hops[$i - 1]), self::analyzerInput($hops[$i]), $opts);
            $where = 'hop[' . $i . ']';
            if (AnalyzerJs::truthy($s->get('subsumes'))) {
                continue;
            }
            if ($s->get('approximate') === true) {
                $reason = $s->get('reason');
                $out[] = self::find('privilege-escalation', 'warn', 'could not prove hop ' . $i . ' attenuation (undecidable'
                    . (AnalyzerJs::truthy($reason) ? ': ' . AnalyzerJs::jsStr($reason) : '') . ') — attenuation not verified', $where);
            } else {
                $ce = $s->get('counterexample');
                $ex = $ce !== null ? " — child admits '" . self::describeAction($ce) . "' which its parent denies" : '';
                $out[] = self::find('privilege-escalation', 'error', 'delegation hop ' . $i
                    . ' ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)' . $ex, $where);
            }
        }
        return $out;
    }

    private static function numEq(mixed $a, mixed $b): bool
    {
        if (AnalyzerJs::isNum($a) && AnalyzerJs::isNum($b)) {
            return AnalyzerJs::jsnum($a) == AnalyzerJs::jsnum($b);
        }
        return AnalyzerJs::strictEq($a, $b);
    }

    private static function intervalEq(Obj $a, Obj $b): bool
    {
        return self::numEq($a->get('lo'), $b->get('lo')) && $a->get('loInclusive') === $b->get('loInclusive')
            && self::numEq($a->get('hi'), $b->get('hi')) && $a->get('hiInclusive') === $b->get('hiInclusive');
    }

    /** @return list<Obj> */
    private static function nonBindingConditions(array $where, int $predIndex): array
    {
        $byField = [];   // 'k'.field => [field, list of [cond, index]]
        foreach ($where as $i => $c) {
            if (!Predicates::isLeafCondition($c) || $c->has('ref')) {
                continue;
            }
            if (!is_string($c->get('op')) || !in_array($c->get('op'), self::NUMERIC_OPS, true)) {
                continue;
            }
            if (self::num(AnalyzerJs::own($c, 'value')) instanceof Undef) {
                continue;
            }
            $k = 'k' . $c->get('field');
            $byField[$k] ??= [$c->get('field'), []];
            $byField[$k][1][] = [$c, $i];
        }
        $out = [];
        foreach ($byField as [$field, $conds]) {
            if (count($conds) < 2) {
                continue;
            }
            $full = AnalyzerCore::fullInterval();
            foreach ($conds as [$c, $_i]) {
                $full = AnalyzerCore::tightenInterval($full, $c->get('op'), $c->get('value'));
            }
            if (AnalyzerCore::intervalEmpty($full)) {
                continue;   // the whole-predicate unsat case is reported separately
            }
            foreach ($conds as $ei => $e) {
                $without = AnalyzerCore::fullInterval();
                foreach ($conds as $xi => $x) {
                    if ($xi !== $ei) {
                        $without = AnalyzerCore::tightenInterval($without, $x[0]->get('op'), $x[0]->get('value'));
                    }
                }
                if (self::intervalEq($without, $full)) {
                    $out[] = self::find('redundant-caveat', 'info', "condition on '" . $field . "' (" . $e[0]->get('op') . ' ' . AnalyzerJs::jsStr($e[0]->get('value'))
                        . ') does not tighten the authority — redundant with the other bounds on this field', 'predicates[' . $predIndex . '].where[' . $e[1] . ']');
                }
            }
        }
        return $out;
    }

    /** A caveat or condition that can never bite: a duplicate, one subsumed by a stricter one, an unsatisfiable predicate, a non-binding bound. @return list<Obj> */
    public static function ruleRedundantCaveat(Obj $policy): array
    {
        $out = [];
        $caveats = $policy->get('caveats');
        $seen = [];
        foreach ($caveats as $i => $cv) {
            if (!($cv instanceof Obj || AnalyzerJs::isArr($cv))) {
                continue;
            }
            $k = 'k' . AnalyzerJs::jsJson($cv);
            if (isset($seen[$k])) {
                $out[] = self::find('redundant-caveat', 'warn', 'caveat ' . $i . " ('" . AnalyzerJs::jsStr(AnalyzerJs::jget($cv, 'type'))
                    . "') is an exact duplicate of caveat " . $seen[$k] . ' — dead policy', 'caveats[' . $i . ']');
            } else {
                $seen[$k] = $i;
            }
        }
        foreach (self::ORDERED_CAVEATS as [$typ, $field, $keep]) {
            $vals = [];
            foreach ($caveats as $i => $cv) {
                if ($cv instanceof Obj && $cv->get('type') === $typ) {
                    $v = self::num(AnalyzerJs::own($cv, $field));
                    if (!($v instanceof Undef)) {
                        $vals[] = [$i, AnalyzerJs::jsnum($v)];
                    }
                }
            }
            if (count($vals) < 2) {
                continue;
            }
            $binding = $vals[0][1];
            foreach ($vals as [$_i, $v]) {
                if ($keep === 'min' ? $v < $binding : $v > $binding) {
                    $binding = $v;
                }
            }
            foreach ($vals as [$i, $v]) {
                if ($v != $binding) {
                    $out[] = self::find('redundant-caveat', 'warn', 'caveat ' . $i . " ('" . $typ . "' " . $field . '=' . AnalyzerJs::numStr($v) . ") is subsumed by a stricter '"
                        . $typ . "' (" . $field . '=' . AnalyzerJs::numStr($binding) . ') — it can never bite', 'caveats[' . $i . ']');
                }
            }
        }
        foreach ($policy->get('predicates') as $i => $p) {
            $w = $p instanceof Obj ? AnalyzerJs::own($p, 'where') : AnalyzerJs::undef();
            if (!($p instanceof Obj || AnalyzerJs::isArr($p)) || !AnalyzerJs::isArr($w)) {
                continue;
            }
            if (!AnalyzerCore::predicateNumericSatisfiable($w)) {
                $out[] = self::find('redundant-caveat', 'warn', 'predicate ' . $i . ' can never match — its numeric `where` constraints are unsatisfiable (dead policy)', 'predicates[' . $i . ']');
            } else {
                $out = array_merge($out, self::nonBindingConditions($w, $i));
            }
        }
        return $out;
    }

    /** A dangerous (verb, resource) the analyzer PROVES reachable, with no budget / rate / step-up gate (error) or with one (info). @return list<Obj> */
    public static function ruleDangerousReachability(Obj $policy, mixed $dangerous, mixed $extraTargets, mixed $opts): array
    {
        $out = [];
        $inp = self::analyzerInput($policy);
        $derived = [];
        foreach (self::declaredVerbs($policy->get('predicates')) as $v) {
            if (self::isDangerousVerb($v, $dangerous)) {
                $derived[] = Obj::of(['verb' => $v]);
            }
        }
        $targets = array_merge($derived, AnalyzerJs::reqList($extraTargets));
        $gate = self::gateDescription($policy);
        foreach ($targets as $t) {
            $verb = AnalyzerJs::jget($t, 'verb');
            $resource = AnalyzerJs::jget($t, 'resource');
            if (!($resource instanceof Undef)) {
                $r = AnalyzerCore::reachable($inp, AnalyzerJs::uobj(['verb' => $verb, 'resource' => $resource]), $opts);
                $proven = AnalyzerJs::truthy($r->get('reachable')) && $r->get('approximate') !== true;
                $approximate = $r->get('approximate') === true;
                $reason = $r->get('reason');
                $witness = AnalyzerJs::jsStr($verb) . ' ' . AnalyzerJs::jsStr($resource);
            } else {
                $ad = AnalyzerCore::alwaysDenies($inp, $verb, $opts);
                $proven = $ad->get('alwaysDenies') === false && $ad->get('approximate') !== true;
                $approximate = $ad->get('approximate') === true;
                $reason = $ad->get('reason');
                $witness = $ad->has('witness') ? self::describeAction($ad->get('witness')) : AnalyzerJs::jsStr($verb);
            }
            if ($approximate) {
                $out[] = self::find('dangerous-reachability', 'warn', "could not decide reachability of dangerous verb '" . AnalyzerJs::jsStr($verb)
                    . "' (undecidable" . (AnalyzerJs::truthy($reason) ? ': ' . AnalyzerJs::jsStr($reason) : '') . ')');
            } elseif ($proven) {
                if ($gate === null) {
                    $out[] = self::find('dangerous-reachability', 'error', "dangerous action '" . $witness . "' is REACHABLE with no budget / rate / step-up gate");
                } else {
                    $out[] = self::find('dangerous-reachability', 'info', "dangerous action '" . $witness . "' is reachable but gated by " . $gate);
                }
            }
        }
        return $out;
    }

    private static function isNonTrivial(Obj $policy, mixed $dangerous): bool
    {
        foreach ($policy->get('predicates') as $p) {
            if (!($p instanceof Obj || AnalyzerJs::isArr($p))) {
                continue;
            }
            $d = $p instanceof Obj ? $p : new Obj();
            $verbs = self::verbsOf($d->get('verb'));
            $w = $d->get('where');
            $hasWhere = AnalyzerJs::isArr($w) && count($w) > 0;
            if (in_array('*', $verbs, true)) {
                return true;
            }
            foreach ($verbs as $v) {
                if (self::isDangerousVerb($v, $dangerous)) {
                    return true;
                }
            }
            if (self::isWildcardResource(AnalyzerJs::own($d, 'resource')) || !$hasWhere) {
                return true;
            }
        }
        return false;
    }

    /** No `expires` caveat, or no blast-radius / rate / budget gate on a non-trivial grant. @param array{requireExpiry:bool,requireScopeGate:bool} $cfg @return list<Obj> */
    public static function ruleMissingSafetyFloor(Obj $policy, array $cfg, mixed $dangerous): array
    {
        $out = [];
        if (count($policy->get('predicates')) === 0) {
            return $out;   // nothing is granted; default-deny needs no floor
        }
        if ($cfg['requireExpiry'] && !self::hasCaveatOfType($policy->get('caveats'), ['expires'])) {
            $out[] = self::find('missing-safety-floor', 'warn', 'grant has no `expires` caveat — the authority never expires');
        }
        if ($cfg['requireScopeGate'] && self::isNonTrivial($policy, $dangerous) && !self::hasCaveatOfType($policy->get('caveats'), self::BUDGET_GATE_CAVEATS)) {
            $out[] = self::find('missing-safety-floor', 'warn', 'non-trivial grant has no blast-radius / rate / budget gate (' . implode('/', self::BUDGET_GATE_CAVEATS) . ')');
        }
        return $out;
    }

    /** The policy compared with the action schema it is written for. @return list<Obj> */
    public static function ruleSchemaMismatch(Obj $policy, mixed $schema, mixed $options = null): array
    {
        $r = AnalyzerValidate::validatePolicyAgainstSchema(Obj::of(['predicates' => $policy->get('predicates'), 'caveats' => $policy->get('caveats')]), $schema, $options);
        $out = [];
        foreach ($r->get('findings') as $f) {
            $out[] = AnalyzerJs::uobj(['rule' => 'schema-mismatch', 'severity' => AnalyzerJs::jget($f, 'severity'),
                'message' => AnalyzerJs::jsStr(AnalyzerJs::jget($f, 'code')) . ': ' . AnalyzerJs::jsStr(AnalyzerJs::jget($f, 'message')),
                'where' => AnalyzerJs::own($f, 'where')]);
        }
        return $out;
    }

    // ---- lint -------------------------------------------------------------------------------------------------------

    /** A rule that throws is a finding, not a crash and not silence: a gate must not pass a policy it could not finish checking. @return list<Obj> */
    private static function guarded(string $rule, \Closure $run): array
    {
        try {
            return $run();
        } catch (\Throwable $e) {
            if ($e instanceof \RuntimeException && preg_match('/^test (deadline of|memory above) /', $e->getMessage()) === 1) {
                throw $e;   // a test-suite loop guard is never a rule failure
            }
            return [Obj::of(['rule' => 'internal-error', 'severity' => 'error', 'message' => 'rule ' . $rule . ' could not run: ' . $e->getMessage()])];
        }
    }

    private static function isTsObject(mixed $o): bool
    {
        return $o === null || $o instanceof Obj || AnalyzerJs::isArr($o);
    }

    /** `typeof o === 'object' && o.<k>`: a null throws, as property access on null does. */
    private static function objMember(mixed $o, string $k): mixed
    {
        if (!self::isTsObject($o)) {
            return AnalyzerJs::undef();
        }
        return AnalyzerJs::jget($o, $k);
    }

    private static function resolveRules(mixed $rules): array
    {
        $r = ($rules instanceof Undef || $rules === null) ? new Obj() : $rules;
        $ob = AnalyzerJs::jget($r, 'overBroadGrant');
        $dr = AnalyzerJs::jget($r, 'dangerousReachability');
        $sf = AnalyzerJs::jget($r, 'missingSafetyFloor');
        $verbs = static function (mixed $o): mixed {
            $v = self::objMember($o, 'dangerousVerbs');
            return AnalyzerJs::truthy($v) ? $v : self::DEFAULT_DANGEROUS_VERBS;
        };
        $targets = self::objMember($dr, 'targets');
        return [
            'overBroadGrant' => ['enabled' => $ob !== false, 'dangerousVerbs' => $verbs($ob)],
            'privilegeEscalation' => AnalyzerJs::jget($r, 'privilegeEscalation') !== false,
            'redundantCaveat' => AnalyzerJs::jget($r, 'redundantCaveat') !== false,
            'dangerousReachability' => ['enabled' => $dr !== false, 'dangerousVerbs' => $verbs($dr), 'targets' => AnalyzerJs::truthy($targets) ? $targets : []],
            'missingSafetyFloor' => [
                'enabled' => $sf !== false,
                'requireExpiry' => self::isTsObject($sf) ? AnalyzerJs::jget($sf, 'requireExpiry') !== false : true,
                'requireScopeGate' => self::isTsObject($sf) ? AnalyzerJs::jget($sf, 'requireScopeGate') !== false : true,
            ],
        ];
    }

    private static function analyzerOpts(mixed $opts): Obj
    {
        $mc = $opts instanceof Obj ? AnalyzerJs::jget($opts, 'maxCombinations') : AnalyzerJs::undef();
        return $mc instanceof Undef ? new Obj() : Obj::of(['maxCombinations' => $mc]);
    }

    /** @return list<Obj> */
    private static function singleRules(array $cfg, Obj $policy, Obj $ao): array
    {
        $out = [];
        if ($cfg['overBroadGrant']['enabled']) {
            $out = array_merge($out, self::guarded('over-broad-grant', static fn(): array => self::ruleOverBroadGrant($policy, $cfg['overBroadGrant']['dangerousVerbs'], $ao)));
        }
        if ($cfg['redundantCaveat']) {
            $out = array_merge($out, self::guarded('redundant-caveat', static fn(): array => self::ruleRedundantCaveat($policy)));
        }
        if ($cfg['dangerousReachability']['enabled']) {
            $dr = $cfg['dangerousReachability'];
            $out = array_merge($out, self::guarded('dangerous-reachability', static fn(): array => self::ruleDangerousReachability($policy, $dr['dangerousVerbs'], $dr['targets'], $ao)));
        }
        if ($cfg['missingSafetyFloor']['enabled']) {
            $out = array_merge($out, self::guarded('missing-safety-floor', static fn(): array => self::ruleMissingSafetyFloor($policy, $cfg['missingSafetyFloor'], $cfg['overBroadGrant']['dangerousVerbs'])));
        }
        return $out;
    }

    private static function malformed(string $reason): array
    {
        return [Obj::of(['rule' => 'malformed-policy', 'severity' => 'error', 'message' => $reason])];
    }

    /** Lint a single PCA policy (an envelope, a minted grant, a compiled policy or a bare `{predicates, caveats?}`). All findings (empty = clean). @return list<Obj> */
    public static function lintPolicy(mixed $input, mixed $opts = null): array
    {
        $opts ??= new Obj();
        $norm = self::normalizePolicyInput($input);
        if (!$norm->get('ok')) {
            return self::malformed($norm->get('reason'));
        }
        $cfg = self::resolveRules(AnalyzerJs::jget($opts, 'rules'));
        $ao = self::analyzerOpts($opts);
        $policy = $norm->get('policy');
        $out = self::singleRules($cfg, $policy, $ao);
        $schema = AnalyzerJs::jget($opts, 'schema');
        if (!($schema instanceof Undef)) {
            $so = AnalyzerJs::jget($opts, 'schemaOptions');
            $out = array_merge($out, self::guarded('schema-mismatch', static fn(): array => self::ruleSchemaMismatch($policy, $schema, $so instanceof Undef ? null : $so)));
        }
        return $out;
    }

    /** Lint a delegation chain (root to leaf): privilege escalation across every consecutive pair, then the single-policy rules on the acting LEAF. @return list<Obj> */
    public static function lintChain(mixed $chain, mixed $opts = null): array
    {
        $opts ??= new Obj();
        $norm = self::normalizeChain($chain);
        if (!$norm->get('ok')) {
            return self::malformed($norm->get('reason'));
        }
        $cfg = self::resolveRules(AnalyzerJs::jget($opts, 'rules'));
        $ao = self::analyzerOpts($opts);
        $hops = $norm->get('hops');
        $out = [];
        if ($cfg['privilegeEscalation']) {
            $out = array_merge($out, self::guarded('privilege-escalation', static fn(): array => self::rulePrivilegeEscalation($hops, $ao)));
        }
        if ($hops) {
            $out = array_merge($out, self::singleRules($cfg, $hops[count($hops) - 1], $ao));
        }
        return $out;
    }

    /** An array input is a delegation chain; anything else is a single policy. @return list<Obj> */
    public static function lint(mixed $input, mixed $opts = null): array
    {
        return AnalyzerJs::isArr($input) ? self::lintChain($input, $opts) : self::lintPolicy($input, $opts);
    }

    private static function rankKey(mixed $k): ?string
    {
        $s = AnalyzerJs::jsStr($k);
        return isset(self::SEVERITY_RANK[$s]) ? $s : null;
    }

    /** Roll labeled findings into counts and an exit code (0 ok, 1 a finding reaches the threshold, 2 nothing was linted). */
    public static function summarize(mixed $results, mixed $opts = null): Obj
    {
        $opts ??= new Obj();
        $maxSeverity = AnalyzerJs::nn(AnalyzerJs::jget($opts, 'maxSeverity'), 'error');
        $mk = self::rankKey($maxSeverity);
        if ($mk === null) {   // an unknown threshold would make every comparison false and pass everything
            throw new \RangeException('summarize: maxSeverity must be one of ' . implode(', ', array_keys(self::SEVERITY_RANK)));
        }
        $counts = ['error' => 0, 'warn' => 0, 'info' => 0];
        if (!AnalyzerJs::isArr($results) || count($results) === 0) {
            return Obj::of(['results' => [], 'counts' => Obj::of($counts), 'maxSeverity' => $maxSeverity, 'ok' => false, 'exitCode' => 2, 'reason' => 'no policies were linted']);
        }
        $failing = 0;
        $threshold = self::SEVERITY_RANK[$mk];
        foreach ($results as $r) {
            foreach (AnalyzerJs::reqList(AnalyzerJs::jget($r, 'findings')) as $f) {
                $sev = self::rankKey(AnalyzerJs::jget($f, 'severity')) ?? 'error';   // a severity that is not one of the three counts as an error
                $counts[$sev]++;
                if (self::SEVERITY_RANK[$sev] >= $threshold) {
                    $failing++;
                }
            }
        }
        $ok = $failing === 0;
        return Obj::of(['results' => $results, 'counts' => Obj::of($counts), 'maxSeverity' => $maxSeverity, 'ok' => $ok, 'exitCode' => $ok ? 0 : 1]);
    }

    /** Lint a list of labeled policies (or chains) and roll the findings into a summary. */
    public static function lintPolicies(mixed $items, mixed $opts = null): Obj
    {
        $opts ??= new Obj();
        $results = [];
        foreach (AnalyzerJs::reqList($items) as $i => $item) {
            $label = AnalyzerJs::nn(AnalyzerJs::jget($item, 'label'), 'policy[' . $i . ']');
            $results[] = Obj::of(['label' => $label, 'findings' => self::lint(AnalyzerJs::jget($item, 'policy'), $opts)]);
        }
        return self::summarize($results, $opts);
    }

    // ---- pinned lint rule list --------------------------------------------------------------------------------------

    /** The digest the CI gate pins: the ordered (id, severity, title) list of the action-kit lint rules. */
    public static function lintRulesDigest(): string
    {
        $rules = [];
        foreach (self::LINT_RULES as [$id, $sev, $title]) {
            $rules[] = Obj::of(['id' => $id, 'severity' => $sev, 'title' => $title]);
        }
        return Pca::hashCanonical(Obj::of(['d' => self::LINT_RULES_DIGEST_DOMAIN, 'rules' => $rules]));
    }

    /** Enforce the pinned digest of the lint rule list: `$pinText` is the pin file's content (one digest, surrounding whitespace ignored). */
    public static function checkLintRulesPin(string $pinText, ?string $actual = null): Obj
    {
        $actual ??= self::lintRulesDigest();
        $pinned = self::trim($pinText);
        if (preg_match('/\A[A-Za-z0-9_-]{43}\z/', $pinned) !== 1) {
            return Obj::of(['ok' => false, 'message' => 'the lint rules pin is not a digest (expected 43 base64url characters)']);
        }
        if ($pinned === $actual) {
            return Obj::of(['ok' => true, 'message' => 'lint rules digest ' . $actual . ' matches the pin']);
        }
        return Obj::of(['ok' => false, 'message' => 'lint rules digest ' . $actual . ' differs from the pin ' . $pinned . ': the rule list changed; review it and update the pin']);
    }

    // ---- authoring gates --------------------------------------------------------------------------------------------

    private static function bad(string $line): Obj
    {
        return Obj::of(['ok' => false, 'exitCode' => 2, 'lines' => [$line]]);
    }

    /** A policy document as the analyzer reads it: any shape `lint` accepts, plus optional `vetoes` and `tighten` members. */
    public static function toAnalyzerPolicy(mixed $doc): Obj
    {
        $n = self::normalizePolicyInput($doc);
        if (!$n->get('ok')) {
            return $n;
        }
        $policy = Obj::of(['predicates' => $n->get('policy')->get('predicates'), 'caveats' => $n->get('policy')->get('caveats')]);
        if ($doc instanceof Obj) {
            if (AnalyzerJs::isArr($doc->get('vetoes'))) {
                $policy->set('vetoes', $doc->get('vetoes'));
            }
            if (AnalyzerJs::isArr($doc->get('tighten'))) {
                $policy->set('tighten', $doc->get('tighten'));
            }
        }
        return Obj::of(['ok' => true, 'policy' => $policy]);
    }

    /** `diff`: does this change widen authority, or raise the most that can leave? {ok, exitCode (0 ok, 1 gate failed, 2 unusable input), lines}. */
    public static function diffCommand(mixed $oldDoc, mixed $newDoc, mixed $o = null): Obj
    {
        $o ??= new Obj();
        $a = self::toAnalyzerPolicy($oldDoc);
        $b = self::toAnalyzerPolicy($newDoc);
        if (!$a->get('ok')) {
            return self::bad('old policy: ' . $a->get('reason'));
        }
        if (!$b->get('ok')) {
            return self::bad('new policy: ' . $b->get('reason'));
        }
        $verb = AnalyzerJs::jget($o, 'verb');
        $opts = new Obj();
        if (!($verb instanceof Undef)) {
            $ex = Obj::of(['verb' => $verb]);
            if (AnalyzerJs::truthy(AnalyzerJs::jget($o, 'amountField'))) {
                $ex->set('amountField', AnalyzerJs::jget($o, 'amountField'));
            }
            if (AnalyzerJs::truthy(AnalyzerJs::jget($o, 'integer'))) {
                $ex->set('integer', true);
            }
            if (!(AnalyzerJs::jget($o, 'windowSecs') instanceof Undef)) {
                $ex->set('windowSecs', AnalyzerJs::jget($o, 'windowSecs'));
            }
            $opts = Obj::of(['exposure' => $ex]);
        }
        $d = AnalyzerExposure::diffPolicies($a->get('policy'), $b->get('policy'), $opts);
        $allow = Obj::of(['widen' => AnalyzerJs::jget($o, 'allowWiden') === true]);
        if (!(AnalyzerJs::jget($o, 'maxExposureIncrease') instanceof Undef)) {
            $allow->set('maxExposureIncrease', AnalyzerJs::jget($o, 'maxExposureIncrease'));
        }
        $gate = AnalyzerExposure::diffGate($d, $allow);
        $summary = $d->get('summary');
        $lines = AnalyzerJs::truthy($d->get('equivalent')) ? ['no change in what is admitted'] : (count($summary) > 0 ? array_values($summary) : ['no witness found']);
        if (!$gate->get('ok')) {
            foreach ($gate->get('reasons') as $r) {
                $lines[] = 'FAIL: ' . AnalyzerJs::jsStr($r);
            }
        }
        $lines[] = $gate->get('ok') ? 'PASS' : 'FAIL';
        return Obj::of(['ok' => $gate->get('ok'), 'exitCode' => $gate->get('ok') ? 0 : 1, 'lines' => $lines]);
    }

    /** `test`: a policy test document against a policy, pinned by digest with `requireDigest`. */
    public static function testCommand(mixed $policyDoc, mixed $testsDoc, mixed $o = null): Obj
    {
        $o ??= new Obj();
        $p = self::toAnalyzerPolicy($policyDoc);
        if (!$p->get('ok')) {
            return self::bad('policy: ' . $p->get('reason'));
        }
        if (!($testsDoc instanceof Obj) || $testsDoc->get('kind') !== 'pca-policy-tests' || !AnalyzerJs::isArr($testsDoc->get('cases'))) {
            return self::bad('tests: not a pca-policy-tests document');
        }
        $rd = AnalyzerJs::jget($o, 'requireDigest');
        $r = AnalyzerValidate::runPolicyTests($p->get('policy'), $testsDoc, $rd instanceof Undef ? new Obj() : Obj::of(['requireDigest' => $rd]));
        $lines = [];
        foreach ($r->get('failures') as $f) {
            $eb = $f->get('expectedDecidedBy');
            $by = $f->get('decidedBy');
            $lines[] = 'FAIL ' . AnalyzerJs::jsStr(AnalyzerJs::own($f, 'name')) . ': expected ' . AnalyzerJs::jsStr(AnalyzerJs::own($f, 'expected'))
                . (AnalyzerJs::truthy($eb) ? ' by ' . AnalyzerJs::jsStr($eb) : '') . ', got ' . AnalyzerJs::jsStr($f->get('got'))
                . ' by ' . ($by === null ? 'no clause' : AnalyzerJs::jsStr($by));
        }
        if (!$r->get('digestMatch')) {
            $lines[] = (AnalyzerJs::truthy($rd) ? 'FAIL' : 'note') . ': the policy differs from the one the examples were confirmed against';
        }
        $lines[] = self::n($r->get('passed')) . '/' . self::n($r->get('total')) . ' examples ' . ($r->get('ok') ? 'PASS' : 'FAIL');
        return Obj::of(['ok' => $r->get('ok'), 'exitCode' => $r->get('ok') ? 0 : 1, 'lines' => $lines]);
    }

    /** `coverage`: which clauses and thresholds the tests or traffic never exercise, and which mutations they cannot tell apart. */
    public static function coverageCommand(mixed $policyDoc, mixed $trafficDoc, mixed $o = null): Obj
    {
        $o ??= new Obj();
        $p = self::toAnalyzerPolicy($policyDoc);
        if (!$p->get('ok')) {
            return self::bad('policy: ' . $p->get('reason'));
        }
        $actions = null;
        if (AnalyzerJs::isArr($trafficDoc)) {
            $actions = $trafficDoc;
        } elseif ($trafficDoc instanceof Obj && AnalyzerJs::isArr($trafficDoc->get('cases'))) {
            $actions = [];
            foreach ($trafficDoc->get('cases') as $c) {
                $actions[] = $c instanceof Obj ? AnalyzerJs::own($c, 'action') : $c;
            }
        }
        if ($actions === null) {
            return self::bad('traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document');
        }
        foreach ($actions as $a) {
            if (!($a instanceof Obj) || !is_string($a->get('verb')) || !is_string($a->get('resource'))) {
                return self::bad('traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document');
            }
        }
        $r = AnalyzerCoverage::coverage($p->get('policy'), $actions);
        $mn = new Obj();
        foreach ([['minClauses', 'clauses'], ['minBoundaries', 'boundaries'], ['minMutation', 'mutation'], ['maxSurvivors', 'maxSurvivors']] as [$src, $dst]) {
            if (!(AnalyzerJs::jget($o, $src) instanceof Undef)) {
                $mn->set($dst, AnalyzerJs::jget($o, $src));
            }
        }
        $gate = AnalyzerCoverage::coverageGate($r, $mn);
        $sc = $r->get('score');
        $mu = $r->get('mutants');
        $pct = static fn(mixed $x): string => AnalyzerJs::toFixed(AnalyzerJs::jsnum($x) * 100, 0);
        $lines = ['clauses decisive ' . $pct($sc->get('clauses')) . '%, boundaries covered ' . $pct($sc->get('boundaries')) . '%, mutants killed '
            . $pct($sc->get('mutation')) . '% (' . self::n($mu->get('killed')) . '/' . self::n(AnalyzerJs::jsnum($mu->get('total')) - AnalyzerJs::jsnum($mu->get('equivalent'))) . ')'];
        foreach ($r->get('untested') as $i) {
            $lines[] = 'untested: ' . AnalyzerJs::jsStr($i);
        }
        foreach ($mu->get('survivors') as $m) {
            $lines[] = 'survives: ' . AnalyzerJs::jsStr($m->get('description')) . (AnalyzerJs::truthy($m->get('killer')) ? ' (kill with ' . AnalyzerJs::jsJson($m->get('killer')) . ')' : '');
        }
        foreach ($gate->get('reasons') as $x) {
            $lines[] = 'FAIL: ' . AnalyzerJs::jsStr($x);
        }
        $lines[] = $gate->get('ok') ? 'PASS' : 'FAIL';
        return Obj::of(['ok' => $gate->get('ok'), 'exitCode' => $gate->get('ok') ? 0 : 1, 'lines' => $lines]);
    }

    // ---- command line -----------------------------------------------------------------------------------------------

    /** The command line as {args: {files, maxSeverity, format, quiet, help, schema?, lintRulesPin?}} or {error}. */
    public static function parseArgs(mixed $argv): Obj
    {
        $files = [];
        $maxSeverity = 'error';
        $fmt = 'text';
        $quiet = false;
        $help = false;
        $schema = null;
        $pin = null;
        $argv = array_values(AnalyzerJs::reqList($argv));
        $sevErr = '--max-severity expects one of ' . implode('|', self::SEVERITIES);
        $fmtErr = "--format expects 'text' or 'github'";
        $n = count($argv);
        for ($i = 0; $i < $n; $i++) {
            $a = $argv[$i];
            if (!is_string($a)) {
                throw new \TypeError('an argument is not a string');
            }
            if ($a === '--help' || $a === '-h') {
                $help = true;
            } elseif ($a === '--quiet' || $a === '-q') {
                $quiet = true;
            } elseif ($a === '--lint-rules-pin') {
                $i++;
                $v = $argv[$i] ?? null;
                if ($v === null || str_starts_with($v, '-')) {
                    return Obj::of(['error' => '--lint-rules-pin expects a file']);
                }
                $pin = $v;
            } elseif ($a === '--max-severity') {
                $i++;
                $v = $argv[$i] ?? null;
                if ($v === null || !in_array($v, self::SEVERITIES, true)) {
                    return Obj::of(['error' => $sevErr]);
                }
                $maxSeverity = $v;
            } elseif (str_starts_with($a, '--max-severity=')) {
                $v = substr($a, strlen('--max-severity='));
                if (!in_array($v, self::SEVERITIES, true)) {
                    return Obj::of(['error' => $sevErr]);
                }
                $maxSeverity = $v;
            } elseif ($a === '--schema') {
                $i++;
                $v = $argv[$i] ?? null;
                if ($v === null) {
                    return Obj::of(['error' => '--schema expects a file']);
                }
                $schema = $v;
            } elseif (str_starts_with($a, '--schema=')) {
                $schema = substr($a, strlen('--schema='));
            } elseif ($a === '--format') {
                $i++;
                $v = $argv[$i] ?? null;
                if ($v !== 'text' && $v !== 'github') {
                    return Obj::of(['error' => $fmtErr]);
                }
                $fmt = $v;
            } elseif (str_starts_with($a, '--format=')) {
                $v = substr($a, strlen('--format='));
                if ($v !== 'text' && $v !== 'github') {
                    return Obj::of(['error' => $fmtErr]);
                }
                $fmt = $v;
            } elseif (str_starts_with($a, '-')) {
                return Obj::of(['error' => "unknown option '" . $a . "'"]);
            } else {
                $files[] = $a;
            }
        }
        $args = Obj::of(['files' => $files, 'maxSeverity' => $maxSeverity, 'format' => $fmt, 'quiet' => $quiet, 'help' => $help]);
        if ($schema !== null) {
            $args->set('schema', $schema);
        }
        if ($pin !== null) {
            $args->set('lintRulesPin', $pin);
        }
        return Obj::of(['args' => $args]);
    }

    /** A file's text as UTF-8 (an invalid sequence becomes U+FFFD). A failure carries the platform error text. */
    private static function readText(string $path): string
    {
        $fail = static fn(string $code, string $text, string $op): \RuntimeException => new \RuntimeException($code . ': ' . $text . ', ' . $op . " '" . $path . "'");
        if (is_dir($path)) {
            throw $fail('EISDIR', 'illegal operation on a directory', 'read');
        }
        if (!file_exists($path)) {
            throw $fail('ENOENT', 'no such file or directory', 'open');
        }
        $s = is_readable($path) ? @file_get_contents($path) : false;
        if ($s === false) {
            throw $fail('EACCES', 'permission denied', 'open');
        }
        if (preg_match('//u', $s) === 1) {
            return $s;
        }
        $prev = mb_substitute_character();
        mb_substitute_character(0xFFFD);
        try {
            return mb_scrub($s, 'UTF-8');
        } finally {
            mb_substitute_character($prev);
        }
    }

    /** @return list<Obj> */
    private static function lintFile(string $path, mixed $schema): array
    {
        try {
            $text = self::readText($path);
        } catch (\RuntimeException $e) {
            return self::malformed('cannot read file: ' . $e->getMessage());
        }
        try {
            $doc = Js::parse($text);
        } catch (\Throwable $e) {
            return self::malformed('invalid JSON: ' . $e->getMessage());
        }
        return self::lint($doc, $schema instanceof Undef ? new Obj() : Obj::of(['schema' => $schema]));
    }

    private static function printText(array $results, bool $quiet, callable $write): void
    {
        foreach ($results as $r) {
            if (!$quiet) {
                $write("\n" . $r->get('label') . ':');
            }
            if (!$r->get('findings')) {
                if (!$quiet) {
                    $write('  (clean)');
                }
                continue;
            }
            foreach ($r->get('findings') as $f) {
                $loc = $f->get('where') !== null ? ' [' . $f->get('where') . ']' : '';
                $tag = self::TEXT_TAG[$f->get('severity')] ?? throw new \TypeError('unknown severity');
                $write('  ' . str_pad($tag, 5) . ' ' . $f->get('rule') . $loc . ': ' . $f->get('message'));
            }
        }
    }

    private static function escapeGh(string $s): string
    {
        return str_replace(['%', "\r", "\n"], ['%25', '%0D', '%0A'], $s);
    }

    /** Workflow-command PROPERTY values must also escape `:` and `,`, or a file name can add properties or end the command. */
    private static function escapeGhProp(string $s): string
    {
        return str_replace([':', ','], ['%3A', '%2C'], self::escapeGh($s));
    }

    private static function printGithub(array $results, callable $write): void
    {
        foreach ($results as $r) {
            foreach ($r->get('findings') as $f) {
                $props = 'file=' . self::escapeGhProp($r->get('label')) . ',title=' . self::escapeGhProp($f->get('rule'));
                $loc = $f->get('where') !== null ? $f->get('where') . ': ' : '';
                $level = self::GH_LEVEL[$f->get('severity')] ?? throw new \TypeError('unknown severity');
                $write('::' . $level . ' ' . $props . '::' . self::escapeGh($loc . $f->get('message')));
            }
        }
    }

    /** @return array{ok:bool,doc?:mixed,reason?:string} */
    private static function readJson(string $path): array
    {
        try {
            return ['ok' => true, 'doc' => Js::parse(self::readText($path))];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => $path . ': ' . $e->getMessage()];
        }
    }

    /** `Number(v)` of a flag value when it is a non-blank finite number, else undefined. */
    private static function flagNumber(array $flags, string $k): mixed
    {
        $v = $flags[$k] ?? null;
        if (!is_string($v) || self::trim($v) === '') {
            return AnalyzerJs::undef();
        }
        $t = self::trim($v);
        if (preg_match('/\A0[xX][0-9a-fA-F]+\z/', $t) === 1) {
            $n = (float)hexdec(substr($t, 2));
        } elseif (preg_match('/\A0[oO][0-7]+\z/', $t) === 1) {
            $n = (float)octdec(substr($t, 2));
        } elseif (preg_match('/\A0[bB][01]+\z/', $t) === 1) {
            $n = (float)bindec(substr($t, 2));
        } elseif (preg_match('/\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/', $t) === 1) {
            $n = (float)$t;
        } else {
            return AnalyzerJs::undef();
        }
        if (!is_finite($n)) {
            return AnalyzerJs::undef();
        }
        return floor($n) === $n && abs($n) < 9007199254740992.0 ? (int)$n : $n;
    }

    private static function runAuthoring(string $cmd, array $rest, callable $write): int
    {
        $files = [];
        $flags = [];
        $n = count($rest);
        for ($i = 0; $i < $n; $i++) {
            $a = $rest[$i];
            if (in_array($a, self::VALUED, true)) {
                $i++;
                if ($i >= $n) {
                    $write($a . ' expects a value');
                    return 2;
                }
                $flags[$a] = $rest[$i];
            } elseif (in_array($a, self::BOOLS, true)) {
                $flags[$a] = true;
            } elseif (str_starts_with($a, '-')) {
                $write("unknown option '" . $a . "'");
                return 2;
            } else {
                $files[] = $a;
            }
        }
        foreach ($flags as $k => $v) {
            $k = (string)$k;
            if (in_array($k, self::VALUED, true) && $k !== '--verb' && $k !== '--amount-field' && self::flagNumber($flags, $k) instanceof Undef) {
                $write($k . " expects a number, got '" . $v . "'");
                return 2;
            }
        }
        if (count($files) !== 2) {
            $write('error: ' . $cmd . ' takes exactly two files');
            $write(self::HELP);
            return 2;
        }
        $docs = array_map(self::readJson(...), $files);
        foreach ($docs as $d) {
            if (!$d['ok']) {
                $write($d['reason']);
                return 2;
            }
        }
        $aDoc = $docs[0]['doc'];
        $bDoc = $docs[1]['doc'];
        $opt = static function (string $flag, string $key, Obj $out) use ($flags): void {
            $v = self::flagNumber($flags, $flag);
            if (!($v instanceof Undef)) {
                $out->set($key, $v);
            }
        };
        if ($cmd === 'diff') {
            $o = Obj::of(['allowWiden' => isset($flags['--allow-widen'])]);
            if (is_string($flags['--verb'] ?? null)) {
                $o->set('verb', $flags['--verb']);
            }
            if (is_string($flags['--amount-field'] ?? null)) {
                $o->set('amountField', $flags['--amount-field']);
            }
            $o->set('integer', isset($flags['--integer']));
            $opt('--window-secs', 'windowSecs', $o);
            $opt('--max-exposure-increase', 'maxExposureIncrease', $o);
            $r = self::diffCommand($aDoc, $bDoc, $o);
        } elseif ($cmd === 'test') {
            $r = self::testCommand($aDoc, $bDoc, Obj::of(['requireDigest' => isset($flags['--require-digest'])]));
        } else {
            $o = new Obj();
            $opt('--min-clauses', 'minClauses', $o);
            $opt('--min-boundaries', 'minBoundaries', $o);
            $opt('--min-mutation', 'minMutation', $o);
            $opt('--max-survivors', 'maxSurvivors', $o);
            $r = self::coverageCommand($aDoc, $bDoc, $o);
        }
        foreach ($r->get('lines') as $line) {
            $write($line);
        }
        return $r->get('exitCode');
    }

    /**
     * Run the command line (`<files...>`, `diff`, `test`, `coverage`); `$write` receives each output line (default: stdout).
     * Returns the exit code: 0 ok, 1 a gate failed, 2 unusable input.
     *
     * @param list<string> $argv
     */
    public static function run(array $argv, ?callable $write = null): int
    {
        $write ??= static function (string $s): void {
            fwrite(STDOUT, $s . "\n");
        };
        $argv = array_values($argv);
        if ($argv && in_array($argv[0], ['diff', 'test', 'coverage'], true)) {
            return self::runAuthoring($argv[0], array_slice($argv, 1), $write);
        }
        $parsed = self::parseArgs($argv);
        if ($parsed->has('error')) {
            $write($parsed->get('error'));
            $write(self::HELP);
            return 2;
        }
        $args = $parsed->get('args');
        if ($args->get('help')) {
            $write(self::HELP);
            return 0;
        }
        $pinFailed = false;
        if ($args->has('lintRulesPin')) {
            try {
                $r = self::checkLintRulesPin(self::readText($args->get('lintRulesPin')));
            } catch (\RuntimeException $e) {
                $r = Obj::of(['ok' => false, 'message' => 'cannot read the lint rules pin: ' . $e->getMessage()]);
            }
            $write(($r->get('ok') ? 'PASS' : 'FAIL') . ' — ' . $r->get('message'));
            $pinFailed = !$r->get('ok');
            if (!$args->get('files')) {
                return $pinFailed ? 1 : 0;
            }
        }
        if (!$args->get('files')) {
            $write('error: no policy files given');
            $write(self::HELP);
            return 2;
        }
        $schema = AnalyzerJs::undef();
        if ($args->has('schema')) {
            $s = self::readJson($args->get('schema'));
            if (!$s['ok']) {
                $write($s['reason']);
                return 2;
            }
            $schema = $s['doc'];
        }
        $results = [];
        foreach ($args->get('files') as $f) {
            $results[] = Obj::of(['label' => $f, 'findings' => self::lintFile($f, $schema)]);
        }
        $summary = self::summarize($results, Obj::of(['maxSeverity' => $args->get('maxSeverity')]));
        if ($args->get('format') === 'github') {
            self::printGithub($results, $write);
        } else {
            self::printText($results, $args->get('quiet'), $write);
        }
        if (AnalyzerJs::truthy($summary->get('reason'))) {
            $write('error: ' . $summary->get('reason'));
        }
        $c = $summary->get('counts');
        $write("\n" . ($summary->get('ok') ? 'PASS' : 'FAIL') . ' — ' . $c->get('error') . ' error(s), ' . $c->get('warn') . ' warning(s), ' . $c->get('info')
            . ' info across ' . count($results) . ' policy/policies (fail threshold: ' . $summary->get('maxSeverity') . ')');
        return $pinFailed ? max(1, $summary->get('exitCode')) : $summary->get('exitCode');
    }
}
