<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDerive.php';
require_once __DIR__ . '/ActionsEffective.php';
require_once __DIR__ . '/ActionsUndoEngine.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Js.php';

/**
 * The 24 stable lint rules over action definitions, SARIF output and the digest of the rule list (native port of lint.ts of the reference
 * actions package). Pure: defs in, findings out, deterministic order. A def that fails validateDef is reported as LD-000 and not linted further.
 * A finding is an array {rule, severity, verb?, param?, message, file?, line?, column?}.
 */
final class ActionsLint
{
    public const LINT_RULES = [
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
    public const NOTE_RULE = ['LN-001', 'note', 'an informational note from the loader'];
    public const STRUCTURE_RULE = ['LD-000', 'error', 'the def is not well formed and cannot be loaded'];
    public const LINT_RULES_DIGEST_DOMAIN = 'atlas-pca/action-lint-rules/v1';

    private const DESTROY_RE = '/\A(?:delete|destroy|remove|purge|drop|erase|wipe|revoke|terminate|truncate)(?:_|\z)/';
    private const SEND_RE = '/\A(?:send|email|notify|sms|message|post_to|broadcast|invite)(?:_|\z)/';
    private const EXPORT_RE = '/\A(?:export|download|dump|backup|extract)(?:_|\z)/';
    private const NAME_GROUPS = [['create_', 'new_', 'add_', 'make_'], ['delete_', 'remove_', 'destroy_']];

    /** The digest pca-policy-ci pins: the ordered (id, severity, title) list. */
    public static function lintRulesDigest(): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::LINT_RULES_DIGEST_DOMAIN, 'rules' => array_map(
            static fn(array $r): Obj => Obj::of(['id' => $r[0], 'severity' => $r[1], 'title' => $r[2]]), self::LINT_RULES)]));
    }

    private static function lastSeg(string $verb): string
    {
        $p = explode('.', $verb);
        return $p[count($p) - 1];
    }

    private static function jsTrim(string $s): string
    {
        return (string)preg_replace('/\A(?:' . IntentWb::JS_WS . ')+|(?:' . IntentWb::JS_WS . ')+\z/', '', $s);
    }

    /** @return list<string> */
    private static function bindingKeys(Obj $d): array
    {
        $b = $d->get('bindings');
        $out = [];
        if (!($b instanceof Obj)) {
            return $out;
        }
        if (Js::truthy($b->get('mcp'))) {
            $out[] = 'mcp:' . IntentWb::jsStr($b->get('mcp')->has('tool') ? $b->get('mcp')->get('tool') : JsUndefined::U);
        }
        if (Js::truthy($b->get('openapi'))) {
            $out[] = 'openapi:' . IntentWb::jsStr($b->get('openapi')->has('operationId') ? $b->get('openapi')->get('operationId') : JsUndefined::U);
        }
        if (Js::truthy($b->get('http'))) {
            $out[] = 'http:' . strtoupper($b->get('http')->get('method')) . ' ' . $b->get('http')->get('path');
        }
        if (Js::truthy($b->get('graphql'))) {
            $out[] = 'graphql:' . $b->get('graphql')->get('op') . '.' . $b->get('graphql')->get('field');
        }
        if (Js::truthy($b->get('grpc'))) {
            $out[] = 'grpc:' . $b->get('grpc')->get('service') . '/' . $b->get('grpc')->get('method');
        }
        if (Js::truthy($b->get('asyncapi'))) {
            $out[] = 'asyncapi:' . $b->get('asyncapi')->get('op') . ' ' . $b->get('asyncapi')->get('channel');
        }
        return $out;
    }

    /** Vocabulary problems of a raw def (LD-007). Reads only what a malformed def can still be asked. @return list<string> */
    private static function vocabularyIssues(mixed $x, array $reg): array
    {
        if (!($x instanceof Obj)) {
            return [];
        }
        $out = [];
        $effects = $x->get('effects');
        if (is_array($effects) && array_is_list($effects)) {
            foreach ($effects as $e) {
                if (!(is_string($e) && in_array($e, Actions::EFFECTS, true))) {
                    $out[] = "unknown effect '" . IntentWb::jsStr($e) . "'";
                }
            }
        }
        $params = $x->get('params');
        if ($params instanceof Obj) {
            foreach ($params->keys() as $n) {
                $q = $params->get($n);
                if (!($q instanceof Obj)) {
                    continue;
                }
                if ($q->has('role') && !Actions::isRole($q->get('role'))) {
                    $out[] = "$n: unknown role '" . IntentWb::jsStr($q->get('role')) . "'";
                }
                if ($q->has('format') && !Actions::isFormat($q->get('format'))) {
                    $out[] = "$n: unknown format '" . IntentWb::jsStr($q->get('format')) . "'";
                }
            }
        }
        $ctx = $x->get('context');
        if (is_array($ctx) && array_is_list($ctx)) {
            foreach ($ctx as $c) {
                if (!Actions::isContextKey($c)) {
                    $out[] = "unknown context key '" . IntentWb::jsStr($c) . "' (known: " . implode(', ', Actions::CONTEXT_KEYS) . ', session_taint_max:<level>)';
                }
            }
        }
        $traits = $x->get('traits');
        if (is_array($traits) && array_is_list($traits)) {
            foreach ($traits as $t) {
                if (is_string($t) && !isset($reg[$t])) {
                    $out[] = "unknown trait '$t'";
                }
            }
        }
        return $out;
    }

    private static function cmp16(array $a, array $b): int
    {
        foreach ([0, 1, 2, 3] as $i) {
            $c = strcmp(mb_convert_encoding($a[$i], 'UTF-16BE', 'UTF-8'), mb_convert_encoding($b[$i], 'UTF-16BE', 'UTF-8'));
            if ($c !== 0) {
                return $c;
            }
        }
        return 0;
    }

    /**
     * Lint a pack's defs (raw values, so a malformed one is still reported). $opts: {customTraits, stability, ns}. Findings are sorted by verb, rule,
     * param, message. Errors fail CI; warnings fail under strict.
     *
     * @param list<mixed> $raw
     * @return list<array<string,mixed>>
     */
    public static function lintDefs(array $raw, ?Obj $opts = null, ?\Closure $verifier = null): array
    {
        $opts ??= new Obj();
        $out = [];
        $add = static function (string $rule, ?string $verb, string $message, ?string $param = null) use (&$out): void {
            $f = ['rule' => $rule, 'severity' => $rule === self::STRUCTURE_RULE[0] ? 'error' : self::severity($rule)];
            if ($verb !== null) {
                $f['verb'] = $verb;
            }
            if ($param !== null) {
                $f['param'] = $param;
            }
            $f['message'] = $message;
            $out[] = $f;
        };
        $reg = Actions::coreRegistry();
        $ct = $opts->get('customTraits');
        if (Js::truthy($ct)) {
            try {
                $reg = Actions::extendRegistry($reg, $ct);
            } catch (\Throwable $e) {
                $add('LD-007', null, 'invalid custom traits: ' . $e->getMessage());
            }
        }
        $defs = [];
        foreach ($raw as $x) {
            $verb = $x instanceof Obj && is_string($x->get('verb')) ? $x->get('verb') : null;
            $vocab = self::vocabularyIssues($x, $reg);
            if ($vocab) {
                foreach ($vocab as $v) {
                    $add('LD-007', $verb, $v);
                }
                continue;
            }
            $bad = Actions::validateDef($x);
            if ($bad !== null) {
                $add(self::STRUCTURE_RULE[0], $verb, $bad);
                continue;
            }
            $defs[] = $x;
        }

        // ---- pack-level rules
        $byVerb = [];
        $names = [];
        foreach ($defs as $d) {
            if (isset($byVerb[$d->get('verb')])) {
                $add('LD-009', $d->get('verb'), "verb '" . $d->get('verb') . "' is defined twice");
            }
            $byVerb[$d->get('verb')] = $d;
        }
        foreach ($defs as $d) {
            foreach (array_merge([$d->get('verb')], $d->get('aliases') ?? []) as $n) {
                $owner = $names[$n] ?? null;
                if ($owner !== null && $owner !== $d->get('verb')) {
                    $add('LD-009', $d->get('verb'), "'$n' is also a name of '$owner'");
                } elseif (!isset($names[$n])) {
                    $names[$n] = $d->get('verb');
                }
            }
        }
        $bound = [];
        foreach ($defs as $d) {
            foreach (self::bindingKeys($d) as $k) {
                $owner = $bound[$k] ?? null;
                if ($owner !== null && $owner !== $d->get('verb')) {
                    $add('LD-014', $d->get('verb'), "binding $k is also bound by '$owner'");
                } else {
                    $bound[$k] = $d->get('verb');
                }
            }
        }
        foreach (self::NAME_GROUPS as $grp) {
            $group = static function (Obj $d) use ($grp): ?string {
                foreach ($grp as $p) {
                    if (str_starts_with(self::lastSeg($d->get('verb')), $p)) {
                        return $p;
                    }
                }
                return null;
            };
            $used = [];
            foreach ($defs as $d) {
                $g = $group($d);
                if ($g !== null) {
                    $used[$g] = ($used[$g] ?? 0) + 1;
                }
            }
            if (count($used) > 1) {
                $keys = array_keys($used);
                usort($keys, static fn($a, $b): int => ($used[$b] <=> $used[$a]) ?: strcmp((string)$a, (string)$b));
                $win = $keys[0];
                foreach ($defs as $d) {
                    $g = $group($d);
                    if ($g !== null && $g !== $win) {
                        $add('LW-008', $d->get('verb'), "uses '$g' where its siblings use '$win'");
                    }
                }
            }
        }
        if ($opts->get('ns') !== null) {
            foreach ($defs as $d) {
                $seg = explode('.', $d->get('verb'))[0];
                if ($seg !== $opts->get('ns')) {
                    $add('LW-008', $d->get('verb'), "verb namespace '$seg' differs from the file namespace '" . $opts->get('ns') . "'");
                }
            }
        }

        // ---- per-def rules
        foreach ($defs as $d) {
            self::lintDef($d, $reg, $opts, $verifier, $byVerb, $add);
        }
        usort($out, static fn(array $a, array $b): int => self::cmp16([$a['verb'] ?? '', $a['rule'], $a['param'] ?? '', $a['message']], [$b['verb'] ?? '', $b['rule'], $b['param'] ?? '', $b['message']]));
        return $out;
    }

    private static function severity(string $rule): string
    {
        foreach (self::LINT_RULES as $r) {
            if ($r[0] === $rule) {
                return $r[1];
            }
        }
        throw new \InvalidArgumentException("unknown lint rule $rule");
    }

    /** @param array<string,Obj> $byVerb */
    private static function lintDef(Obj $d, array $reg, Obj $opts, ?\Closure $verifier, array $byVerb, \Closure $add): void
    {
        $verb = $d->get('verb');
        $n = Actions::normalize($d);
        $np = $n->get('params');
        $pnames = $np->keys();
        usort($pnames, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        $eff = ActionsDerive::effectiveWith($d, $reg, $verifier);
        $tset = $eff['hint']['traits'];
        $cl = $eff['hint']['closure'];
        $effects = $d->get('effects');
        $params = static fn(callable $pred): array => array_values(array_filter($pnames, static fn(string $k): bool => $pred($np->get($k))));
        $role = static fn(Obj $q): ?string => $q->get('role');
        $tags = static fn(Obj $q): array => $q->get('tags') ?? [];
        $last = self::lastSeg($verb);

        if (preg_match(self::DESTROY_RE, $last) === 1 && !in_array('delete', $effects, true)) {
            $add('LD-001', $verb, "the verb says '$last' but effects do not include delete");
        }
        foreach ($params(static fn(Obj $q) => in_array($role($q), ['money.amount', 'money.fee'], true)) as $k) {
            $u = $np->get($k)->get('unit');
            if (!$u || $u->get('kind') !== 'money') {
                $add('LD-002', $verb, 'a money parameter needs a unit of kind money with a currency', $k);
            } elseif (!is_string($u->get('ccy'))) {
                $c = $np->get($u->get('ccy')->get('from'));
                if (!$c || $c->get('role') !== 'money.currency' || $c->get('format') !== 'iso_currency') {
                    $add('LD-002', $verb, "the currency parameter '" . $u->get('ccy')->get('from') . "' needs role money.currency and format iso_currency", $k);
                }
            }
        }
        foreach ($params(static fn(Obj $q) => $role($q) === 'money.currency') as $k) {
            if ($np->get($k)->get('format') !== 'iso_currency') {
                $add('LD-002', $verb, 'a currency parameter needs the iso_currency format', $k);
            }
        }
        foreach ($params(static fn(Obj $q) => in_array($q->get('type'), ['integer', 'duration'], true)) as $k) {
            $q = $np->get($k);
            if ($q->get('role') !== null && str_starts_with($q->get('role'), 'id.')) {
                continue;
            }
            if ($q->get('role') === 'count.limit' && $q->has('max')) {
                continue;
            }
            if (!$q->has('min') || !$q->has('max')) {
                $add('LD-003', $verb, 'a numeric parameter needs both min and max (has ' . (!$q->has('min') ? 'no min' : 'min') . ', ' . (!$q->has('max') ? 'no max' : 'max') . ')', $k);
            }
        }
        if ((in_array('pay', $effects, true) || in_array('pca.money_moving', $tset, true)) && $n->get('idempotency')->get('mode') === 'none') {
            $add('LD-004', $verb, 'a money-moving action needs idempotency key_param or natural');
        }
        $pii = $params(static fn(Obj $q) => in_array('pii', $tags($q), true) || ($q->get('role') !== null && (str_starts_with($q->get('role'), 'contact.') || str_starts_with($q->get('role'), 'person.'))));
        if ($pii) {
            $expected = [];
            foreach ($d->get('side_effects') ?? [] as $s) {
                if (in_array($s->get('kind'), ['send', 'export'], true)) {
                    $expected[$s->get('kind')] = true;
                }
            }
            if (preg_match(self::SEND_RE, $last) === 1) {
                $expected['send'] = true;
            }
            if (preg_match(self::EXPORT_RE, $last) === 1) {
                $expected['export'] = true;
            }
            $ex = array_keys($expected);
            sort($ex, SORT_STRING);
            foreach ($ex as $e) {
                if (!in_array($e, $effects, true)) {
                    $add('LD-005', $verb, 'personal data can ' . ($e === 'send' ? 'be sent' : 'be exported') . ' (' . implode(', ', $pii) . ") but effects do not include $e");
                }
            }
        }
        foreach ($eff['clamps'] as $c) {
            $add('LD-006', $verb, 'declared ' . ($c['field'] === 'rev' ? 'reversibility' : 'blast') . ' ' . $c['declared'] . ' is below the floor ' . $c['floor']);
        }
        if ($n->get('resource')->get('id') === '*' && $n->get('resource')->get('scope') === 'one') {
            $add('LD-008', $verb, "resource id '*' with scope one names every resource at once");
        }
        if (!Actions::isReadOnly($effects) && ActionsUndoEngine::mayBeReversible($d)) {
            $comp = $d->get('compensates');
            if ($comp === null) {
                $add('LD-010', $verb, 'a write declared reversible must name its compensating action (compensates)');
            } elseif (!isset($byVerb[$comp])) {
                $add('LD-010', $verb, "compensates '$comp', which is not in the pack");
            } else {
                $s = ActionsUndoEngine::compensationShape($d, $byVerb[$comp]);
                if (!$s['ok']) {
                    $add('LD-010', $verb, "compensates '$comp', which cannot undo it: " . $s['reason']);
                }
            }
        }
        $review = $d->get('review');
        if ($review->get('state') === 'confirmed') {
            $a = $review->get('attestation');
            if ($a === null) {
                $add('LD-011', $verb, 'confirmed without an attestation');
            } elseif ($a->get('def_digest') !== Actions::defDigest($d)) {
                $add('LD-011', $verb, 'the attestation covers a different digest of this def');
            } elseif ($a->get('traits_digest') !== Actions::traitsDigest($reg)) {
                $add('LD-011', $verb, 'the attestation was made against a different trait registry');
            } elseif ($verifier !== null ? !Js::truthy($verifier($d)) : !$a->has('sig')) {
                $add('LD-011', $verb, 'the attestation is not signed by a pinned reviewer');
            }
        }
        $att = $review->get('attestation');
        $dismissed = $review->get('state') === 'confirmed' && $att instanceof Obj ? ($att->get('dismissed') ?? []) : [];
        $dismissedNames = array_map(static fn(Obj $x) => $x->get('trait'), $dismissed);
        $prov = $review->get('provenance');
        foreach ($prov instanceof Obj ? ($prov->get('union') ?? []) : [] as $t) {
            if (!in_array($t, $cl, true) && !in_array($t, $dismissedNames, true)) {
                $add('LD-011', $verb, "the union-added trait $t was removed without a signed dismissal");
            }
        }
        $own = ['money_has_currency', 'money_amount_bounded', 'pay_has_idempotency'];
        foreach (ActionsEffective::prulesViolations($d, $eff['hint']['eff']['prules']) as $r) {
            if (!in_array($r, $own, true)) {
                $add('LD-012', $verb, "structural rule $r is required by the action's traits and violated");
            }
        }
        if (Actions::isReadOnly($effects)) {
            $enforced = in_array('sandbox_attested', $d->get('context') ?? [], true);
            foreach ($params(static fn(Obj $q) => in_array($role($q), ['code.command', 'query.sql'], true)) as $k) {
                if (!$enforced) {
                    $add('LD-013', $verb, 'a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)', $k);
                }
            }
            foreach ($params(static fn(Obj $q) => in_array('credential', $tags($q), true)) as $k) {
                $add('LD-013', $verb, 'a read-only action handles a credential', $k);
            }
        }

        // ---- warnings
        if (!$d->has('description')) {
            $add('LW-001', $verb, 'description is missing');
        } elseif (strlen($d->get('description')) > 400) {
            $add('LW-001', $verb, 'description is longer than 400 bytes');
        }
        $first = mb_strtolower(preg_split('/(?:' . IntentWb::JS_WS . ')+/', $d->get('title'))[0]);
        if (preg_match('/(?:ing|ed)\z/', $first) === 1 || (preg_match('/[^s]s\z/', $first) === 1 && preg_match('/(?:us|is)\z/', $first) !== 1) || in_array($first, ['a', 'an', 'the'], true)) {
            $add('LW-001', $verb, "title '" . $d->get('title') . "' is not imperative");
        }
        foreach ($params(static fn(Obj $q) => $q->get('type') === 'string' && !$q->has('max_len') && !$q->has('values')) as $k) {
            $add('LW-002', $verb, 'a string parameter without max_len (the default is 1024; say it)', $k);
        }
        if (in_array('pca.external_communication', $cl, true)) {
            foreach ($params(static fn(Obj $q) => $q->get('type') === 'string' && !$q->has('values') && !$q->has('format') && ($q->get('role') === null || str_starts_with($q->get('role'), 'text.'))
                && !in_array('free_text_outbound', $tags($q), true)) as $k) {
                if ($k !== $n->get('idempotency')->get('param')) {
                    $add('LW-003', $verb, 'free text flows into an outbound action without tags: [free_text_outbound]', $k);
                }
            }
        }
        if ($opts->get('stability') === 'stable' && in_array($review->get('state'), ['unreviewed', 'suggested'], true)) {
            $add('LW-004', $verb, 'a ' . $review->get('state') . ' def in a stable pack');
        }
        foreach ($att instanceof Obj ? ($att->get('dismissed') ?? []) : [] as $x) {
            if (Js::len(self::jsTrim($x->get('reason'))) < 5) {
                $add('LW-005', $verb, 'dismissed trait ' . $x->get('trait') . ' has no reason');
            }
        }
        foreach ($params(static fn(Obj $q) => $q->get('type') === 'array' && $q->get('max_items') === null) as $k) {
            $add('LW-006', $verb, 'an array parameter without max_items', $k);
        }
        foreach ($params(static fn(Obj $q) => Actions::SENSITIVITY_RANK[Actions::effectiveParamSensitivity($q)] >= Actions::SENSITIVITY_RANK['critical'] && !$q->has('provenance_min')) as $k) {
            $add('LW-007', $verb, 'a critical parameter without provenance_min', $k);
        }
        if ((in_array('pca.money_moving', $tset, true) || in_array('pca.destructive', $tset, true) || in_array('pca.privilege_change', $tset, true)) && count($d->get('examples') ?? []) === 0) {
            $add('LW-009', $verb, 'no example for a money-moving, destructive or privilege-changing action');
        }
        if (!$d->has('since')) {
            $add('LW-010', $verb, 'since is missing');
        }
    }

    /** Does the run fail? Errors always; warnings under `strict`. @param list<mixed> $fs */
    public static function lintFails(array $fs, bool $strict = false): bool
    {
        foreach ($fs as $f) {
            $s = self::fv($f, 'severity');
            if ($s === 'error' || ($strict && $s === 'warning')) {
                return true;
            }
        }
        return false;
    }

    /** A finding member from an array or an Obj (a finding that came from JSON). */
    private static function fv(mixed $f, string $k): mixed
    {
        return $f instanceof Obj ? $f->get($k) : ($f[$k] ?? null);
    }

    /** Plain text, one line per finding. @param list<mixed> $fs */
    public static function lintText(array $fs): string
    {
        if (!$fs) {
            return '0 errors, 0 warnings';
        }
        $e = count(array_filter($fs, fn($f) => self::fv($f, 'severity') === 'error'));
        $w = count(array_filter($fs, fn($f) => self::fv($f, 'severity') === 'warning'));
        $lines = [];
        foreach ($fs as $f) {
            $loc = '';
            $file = self::fv($f, 'file');
            if (Js::truthy($file)) {
                $line = self::fv($f, 'line');
                $col = self::fv($f, 'column');
                $loc = $file . ($line !== null ? ':' . IntentWb::jsStr($line) . ':' . IntentWb::jsStr($col ?? 1) : '') . ': ';
            }
            $v = self::fv($f, 'verb');
            $p = self::fv($f, 'param');
            $lines[] = str_pad(self::fv($f, 'severity'), 7) . ' ' . self::fv($f, 'rule') . '  ' . $loc . ($v ?: '') . ($p ? " [$p]" : '') . ($v || $p ? ': ' : '') . self::fv($f, 'message');
        }
        $notes = count($fs) - $e - $w;
        return implode("\n", $lines) . "\n$e error" . ($e === 1 ? '' : 's') . ", $w warning" . ($w === 1 ? '' : 's') . ($notes > 0 ? ", $notes note" . ($notes === 1 ? '' : 's') : '');
    }

    /** SARIF 2.1.0, so findings appear as pull request annotations. @param list<mixed> $fs */
    public static function toSarif(array $fs, ?Obj $tool = null): Obj
    {
        $rules = array_merge([self::STRUCTURE_RULE, self::NOTE_RULE], self::LINT_RULES);
        $level = static fn(string $s): string => $s === 'error' ? 'error' : ($s === 'warning' ? 'warning' : 'note');
        $driver = Obj::of(['name' => $tool !== null && $tool->get('name') !== null ? $tool->get('name') : 'pca actions lint']);
        if ($tool !== null && Js::truthy($tool->get('version'))) {
            $driver->set('version', $tool->get('version'));
        }
        $driver->set('rules', array_map(static fn(array $r): Obj => Obj::of(['id' => $r[0], 'shortDescription' => Obj::of(['text' => $r[2]]),
            'defaultConfiguration' => Obj::of(['level' => $level($r[1])])]), $rules));
        $results = [];
        foreach ($fs as $f) {
            $loc = new Obj();
            $file = self::fv($f, 'file');
            if (Js::truthy($file)) {
                $pl = Obj::of(['artifactLocation' => Obj::of(['uri' => $file])]);
                if (self::fv($f, 'line') !== null) {
                    $pl->set('region', Obj::of(['startLine' => self::fv($f, 'line'), 'startColumn' => self::fv($f, 'column') ?? new Num('1')]));
                }
                $loc->set('physicalLocation', $pl);
            }
            $v = self::fv($f, 'verb');
            if (Js::truthy($v)) {
                $loc->set('logicalLocations', [Obj::of(['name' => $v, 'kind' => 'member'])]);
            }
            $p = self::fv($f, 'param');
            $prefix = Js::truthy($v) ? $v . (Js::truthy($p) ? " [$p]" : '') . ': ' : '';
            $results[] = Obj::of(['ruleId' => self::fv($f, 'rule'), 'level' => $level(self::fv($f, 'severity')), 'message' => Obj::of(['text' => $prefix . self::fv($f, 'message')]), 'locations' => [$loc]]);
        }
        return Obj::of(['$schema' => 'https://json.schemastore.org/sarif-2.1.0.json', 'version' => '2.1.0',
            'runs' => [Obj::of(['tool' => Obj::of(['driver' => $driver]), 'results' => $results])]]);
    }
}
