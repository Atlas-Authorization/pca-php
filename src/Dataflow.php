<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/CaveatLang.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Jsx.php';

/** A capability: sources (lineage), isTrusted (true only if every source is trusted), readers (optional allow-list of sink ids). Sets are duplicate-free lists. */
final class FlowCapability
{
    public function __construct(public readonly mixed $sources, public readonly mixed $isTrusted, public readonly mixed $readers = null)
    {
    }
}

/** A value carrying its capability. Only {@see Dataflow} makes one (`Dataflow::isTagged` is false for a look-alike). */
final class Tagged
{
    public function __construct(public readonly mixed $value, public readonly FlowCapability $cap, mixed $mint = null)
    {
        if ($mint !== Dataflow::mintToken()) {
            throw new \TypeError('a Tagged value is made by tag(), fromTrustedQuery(), fromToolOutput(), fromSource() or derive()');
        }
    }
}

final class TraceRuleError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * The capability-tagged, positive data-flow model (CaMeL style), the trace rules that lower "never B after A" guardrails to derive
 * caveats, the lethal-trifecta lint, and the vendor detector adapters that turn guardrail responses into signed, tighten-only
 * receipts (the reference's pca-dataflow and the core model it re-exports).
 *
 * Language notes: sinks are {@see Obj} `{id, accepts: {external, require_trusted, allowed_sources, denied_sources}}`; capability sets are
 * duplicate-free lists; the sink resolver of `checkAction` is a Closure or an object with `sinkFor(action)`; a `null` entry in the
 * tagged-argument list is the "an argument was not tagged" refusal.
 */
final class Dataflow
{
    public const TRUSTED_QUERY = 'trusted-query';
    public const MAX_TRACE_CAVEATS = 64;
    private const B_CHUNK = 8; // 7 + 3k expression nodes <= DERIVE_MAX_NODES (32)
    public const PRIVATE_READ_TRAITS = ['pca.pii_access', 'pca.financial_data_read', 'pca.credential_access', 'pca.regulated_data'];
    public const EXTERNAL_SEND_TRAITS = ['pca.external_communication', 'pca.network_egress', 'pca.data_export', 'pca.public_exposure'];
    public const DETECTOR_RECEIPT_DOMAIN = "atlas-pca/detector-receipt/v1\0";
    public const DETECTOR_RECEIPT_REF_DOMAIN = 'atlas-pca/detector-receipt-ref/v1';
    public const DETECTOR_VERDICTS = ['suspicious', 'no_finding'];

    // JS \s / String.trim() whitespace as a character-class body; `.` without line terminators
    private const WS = "\\t\\n\\x{0B}\\x{0C}\\r \\x{A0}\\x{1680}\\x{2000}-\\x{200A}\\x{2028}\\x{2029}\\x{202F}\\x{205F}\\x{3000}\\x{FEFF}";
    private const DOT = "[^\\n\\r\\x{2028}\\x{2029}]";
    private const UNIT = ['ms' => 1, 's' => 1000, 'm' => 60_000, 'h' => 3_600_000, 'd' => 86_400_000];

    private static ?object $mint = null;

    public static function mintToken(): object
    {
        return self::$mint ??= new \stdClass();
    }

    // ---- provenance + tagged values ---------------------------------------------------------------------------------------

    public static function toolProvenance(string $name): string
    {
        return 'tool:' . $name;
    }

    private static function u16(mixed $s): string
    {
        return (string)mb_convert_encoding(Jsx::str($s), 'UTF-16BE', 'UTF-8');
    }

    /** Array.prototype.sort() on a list of strings (UTF-16 code-unit order). @return list<mixed> */
    public static function sorted(array $xs): array
    {
        $xs = array_values($xs);
        usort($xs, static fn($a, $b): int => strcmp(self::u16($a), self::u16($b)));
        return $xs;
    }

    private static function key(mixed $x): string
    {
        return gettype($x) . ':' . (is_scalar($x) || $x === null ? Jsx::str($x) : Js::stringify($x));
    }

    /** A duplicate-free list (a JS Set of the given values). */
    public static function toSet(mixed $xs): array
    {
        $seen = [];
        $out = [];
        foreach ($xs as $x) {
            $k = self::key($x);
            if (!isset($seen[$k])) {
                $seen[$k] = true;
                $out[] = $x;
            }
        }
        return $out;
    }

    private static function isSet(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function has(mixed $set, mixed $x): bool
    {
        if (!self::isSet($set)) {
            throw new \TypeError('has is not a function');
        }
        $k = self::key($x);
        foreach ($set as $y) {
            if (self::key($y) === $k) {
                return true;
            }
        }
        return false;
    }

    public static function isTagged(mixed $x): bool
    {
        return $x instanceof Tagged;
    }

    private static function freeze(mixed $sources, bool $isTrusted, mixed $readers): FlowCapability
    {
        return new FlowCapability(self::toSet($sources), $isTrusted, $readers === null ? null : self::toSet($readers));
    }

    /** Tag a raw value with an explicit capability (escape hatch; prefer the boundary constructors). */
    public static function tag(mixed $value, mixed $cap): Tagged
    {
        if (!($cap instanceof FlowCapability) || !self::isSet($cap->sources) || !is_bool($cap->isTrusted)) {
            throw new \TypeError('tag: a capability needs a set of sources and a boolean isTrusted');
        }
        if ($cap->readers !== null && !self::isSet($cap->readers)) {
            throw new \TypeError('tag: readers must be a Set when given');
        }
        if ($cap->isTrusted) {
            if (count($cap->sources) === 0) {
                throw new \TypeError('tag: a trusted capability needs at least one source');
            }
            foreach ($cap->sources as $src) {
                if (is_string($src) && str_starts_with($src, 'tool:')) {
                    throw new \TypeError('tag: tool output can never be trusted');
                }
            }
        }
        return new Tagged($value, self::freeze($cap->sources, $cap->isTrusted, $cap->readers), self::mintToken());
    }

    public static function fromTrustedQuery(mixed $value, ?array $readers = null): Tagged
    {
        return self::tag($value, new FlowCapability([self::TRUSTED_QUERY], true, $readers));
    }

    public static function fromToolOutput(string $name, mixed $value, ?array $readers = null): Tagged
    {
        return self::tag($value, new FlowCapability([self::toolProvenance($name)], false, $readers));
    }

    /** Untrusted unless the caller vouches (`$isTrusted === true`) at the boundary. */
    public static function fromSource(string $source, mixed $value, mixed $isTrusted = false, ?array $readers = null): Tagged
    {
        return self::tag($value, new FlowCapability([$source], $isTrusted === true, $readers));
    }

    /** @param list<FlowCapability> $caps @return list<mixed> */
    public static function unionSources(array $caps): array
    {
        $out = [];
        foreach ($caps as $c) {
            foreach ($c->sources as $s) {
                $out[] = $s;
            }
        }
        return self::toSet($out);
    }

    /** sources = union, isTrusted = AND over a non-empty list, readers = intersection of the inputs that restrict readers. @param list<FlowCapability> $caps */
    public static function combineCaps(array $caps): FlowCapability
    {
        $sources = self::unionSources($caps);
        $trusted = count($caps) > 0;
        foreach ($caps as $c) {
            $trusted = $trusted && $c->isTrusted === true;
        }
        $readers = null;
        foreach ($caps as $c) {
            if ($c->readers === null) {
                continue;
            }
            $readers = $readers === null ? self::toSet($c->readers) : array_values(array_filter($readers, static fn($r) => self::has($c->readers, $r)));
        }
        return self::freeze($sources, $trusted, $readers);
    }

    /** A new tagged value whose capability is combineCaps over the inputs: trust can only be lost. @param list<Tagged> $inputs */
    public static function derive(mixed $inputs, callable $combine): Tagged
    {
        if (!self::isSet($inputs)) {
            throw new \TypeError('derive: every input must be a tagged value made by this module');
        }
        foreach ($inputs as $t) {
            if (!self::isTagged($t)) {
                throw new \TypeError('derive: every input must be a tagged value made by this module');
            }
        }
        $value = $combine(...array_map(static fn(Tagged $t) => $t->value, $inputs));
        return new Tagged($value, self::combineCaps(array_map(static fn(Tagged $t) => $t->cap, $inputs)), self::mintToken());
    }

    // ---- sinks + the policy interpreter -----------------------------------------------------------------------------------

    /** @return list<mixed> */
    private static function sortedSources(FlowCapability $cap): array
    {
        return self::sorted($cap->sources);
    }

    private static function sstr(array $xs): string
    {
        return implode(', ', array_map(static fn($x) => Jsx::str($x), $xs));
    }

    private static function member(Obj $o, string $k): mixed
    {
        return $o->has($k) ? $o->get($k) : null;
    }

    /** One value -> sink flow: {outcome: allow|step_up|deny, reason?, path?}. Order: value readers, denied sources, allow-list, external sink, sensitive sink. */
    public static function classifyFlow(mixed $value, mixed $sink): Obj
    {
        if (!self::isTagged($value)) {
            return Obj::of(['outcome' => 'deny', 'reason' => 'value carries no provenance tag made by this module (fail closed)', 'path' => []]);
        }
        $cap = $value->cap;
        if (!($sink instanceof Obj) || !is_string($sink->get('id')) || $sink->get('id') === '' || !($sink->get('accepts') instanceof Obj)) {
            return Obj::of(['outcome' => 'deny', 'reason' => 'the sink is not a valid sink (fail closed)', 'path' => self::sortedSources($cap)]);
        }
        $p = $sink->get('accepts');
        $sid = $sink->get('id');
        if ($cap->readers !== null && !self::has($cap->readers, $sid)) {
            return Obj::of(['outcome' => 'deny',
                'reason' => sprintf("value's readers capability [%s] does not include sink '%s'", count($cap->readers) === 0 ? '∅' : self::sstr(self::sorted($cap->readers)), $sid),
                'path' => self::sortedSources($cap)]);
        }
        $denied = self::member($p, 'denied_sources');
        if ($denied !== null) {
            $bad = array_values(array_filter(self::sortedSources($cap), static fn($s) => self::has($denied, $s)));
            if ($bad !== []) {
                return Obj::of(['outcome' => 'deny', 'reason' => sprintf("provenance [%s] is forbidden at sink '%s'", self::sstr($bad), $sid), 'path' => $bad]);
            }
        }
        $allowed = self::member($p, 'allowed_sources');
        if ($allowed !== null) {
            $bad = array_values(array_filter(self::sortedSources($cap), static fn($s) => !self::has($allowed, $s)));
            if ($bad !== []) {
                return Obj::of(['outcome' => 'deny', 'reason' => sprintf("provenance [%s] is not in the allow-list of sink '%s'", self::sstr($bad), $sid), 'path' => $bad]);
            }
        }
        if (self::member($p, 'external') === true && $cap->isTrusted !== true) {
            return Obj::of(['outcome' => 'deny',
                'reason' => sprintf("untrusted value (provenance [%s]) may not flow to external-send sink '%s' — exfiltration / prompt-injection path", self::sstr(self::sortedSources($cap)), $sid),
                'path' => self::sortedSources($cap)]);
        }
        if (self::member($p, 'require_trusted') === true && $cap->isTrusted !== true) {
            return Obj::of(['outcome' => 'step_up',
                'reason' => sprintf("sink '%s' requires trusted provenance; value provenance [%s] is untrusted — needs human review", $sid, self::sstr(self::sortedSources($cap))),
                'path' => self::sortedSources($cap)]);
        }
        return Obj::of(['outcome' => 'allow']);
    }

    /** ok is true only for a clean allow (a step_up is not ok without a human). */
    public static function canFlow(mixed $value, mixed $sink): Obj
    {
        $d = self::classifyFlow($value, $sink);
        $out = Obj::of(['ok' => $d->get('outcome') === 'allow']);
        if ($d->has('reason')) {
            $out->set('reason', $d->get('reason'));
        }
        return $out;
    }

    private const SEVERITY = ['allow' => 0, 'step_up' => 1, 'deny' => 2];

    /** Gate an action by data flow: every tagged argument is checked against the sink it dispatches to; the worst outcome wins. */
    public static function checkAction(mixed $action, mixed $taggedArgs, mixed $policy, mixed $expectedArgs = null): Obj
    {
        try {
            $resolver = is_object($policy) && !($policy instanceof \Closure) && method_exists($policy, 'sinkFor') ? [$policy, 'sinkFor'] : $policy;
            $sink = $resolver($action);
        } catch (\Throwable) { // the resolver is caller code: any failure refuses
            return Obj::of(['outcome' => 'deny', 'sink' => '(unresolved)', 'reason' => 'the sink for this action could not be resolved (fail closed)']);
        }
        if (!($sink instanceof Obj) || !is_string($sink->get('id')) || $sink->get('id') === '') {
            return Obj::of(['outcome' => 'deny', 'sink' => '(unresolved)', 'reason' => 'the sink for this action is not a valid sink (fail closed)']);
        }
        $sid = $sink->get('id');
        if (!self::isSet($taggedArgs)) {
            return Obj::of(['outcome' => 'deny', 'sink' => $sid, 'reason' => 'the tagged arguments are not a list (fail closed)']);
        }
        if ($expectedArgs !== null) {
            $f = Js::isNum($expectedArgs) ? Js::num($expectedArgs) : null;
            if ($f === null || $f != count($taggedArgs)) {
                return Obj::of(['outcome' => 'deny', 'sink' => $sid,
                    'reason' => sprintf('expected %s tagged argument(s), got %d (fail closed)', Jsx::str($expectedArgs), count($taggedArgs))]);
            }
        }
        $worst = Obj::of(['outcome' => 'allow', 'sink' => $sid]);
        foreach ($taggedArgs as $i => $arg) {
            if ($arg === null) {
                return Obj::of(['outcome' => 'deny', 'sink' => $sid, 'arg' => $i, 'reason' => 'an argument was not tagged (fail closed)']);
            }
            $d = self::classifyFlow($arg, $sink);
            if (self::SEVERITY[$d->get('outcome')] > self::SEVERITY[$worst->get('outcome')]) {
                $worst = Obj::of(['outcome' => $d->get('outcome'), 'sink' => $sid, 'arg' => $i]);
                if ($d->has('reason')) {
                    $worst->set('reason', $d->get('reason'));
                }
                if ($d->has('path')) {
                    $worst->set('path', $d->get('path'));
                }
            }
        }
        return $worst;
    }

    /** Privileged planner sees only the TRUSTED query value; the quarantined handler returns a tagged result. @return array{plan:mixed,result:Tagged} */
    public static function dualContext(mixed $query, callable $plan, callable $quarantine): array
    {
        if (!self::isTagged($query)) {
            throw new \TypeError('dualContext: the query must be a tagged value made by this module');
        }
        if ($query->cap->isTrusted !== true) {
            throw new \InvalidArgumentException(sprintf('dualContext: the privileged planner may only run on a TRUSTED query; got provenance [%s]', self::sstr(self::sortedSources($query->cap))));
        }
        $p = $plan($query->value);
        $result = $quarantine($p);
        if (!self::isTagged($result)) {
            throw new \TypeError('dualContext: the quarantined handler must return a tagged value made by this module');
        }
        return ['plan' => $p, 'result' => $result];
    }

    public static function externalSendSink(string $id): Obj
    {
        return Obj::of(['id' => $id, 'accepts' => Obj::of(['external' => true])]);
    }

    public static function sensitiveSink(string $id): Obj
    {
        return Obj::of(['id' => $id, 'accepts' => Obj::of(['require_trusted' => true])]);
    }

    /** The label in the provenance lattice of the default gate: trusted, tool (every source a tool output) or agent. */
    public static function levelOf(mixed $value): string
    {
        if (!self::isTagged($value)) {
            return 'agent';
        }
        $cap = $value->cap;
        if ($cap->isTrusted === true) {
            return 'trusted';
        }
        $all = count($cap->sources) > 0;
        foreach ($cap->sources as $s) {
            $all = $all && is_string($s) && str_starts_with($s, 'tool:');
        }
        return $all ? 'tool' : 'agent';
    }

    // ---- trace rules ------------------------------------------------------------------------------------------------------

    private static function fail(string $code, string $m): never
    {
        throw new TraceRuleError($code, $m);
    }

    private static function trim(string $s): string
    {
        return preg_replace('/\A[' . self::WS . ']+|[' . self::WS . ']+\z/u', '', $s) ?? $s;
    }

    private static function match(string $re, mixed $s): ?array
    {
        $S = '[' . self::WS . ']';
        $NS = '[^' . self::WS . ']';
        $re = strtr($re, ['{S}' => $S, '{NS}' => $NS, '{DOT}' => self::DOT]);
        return is_string($s) && preg_match('/\A(?:' . $re . ')\z/u', $s, $m, PREG_UNMATCHED_AS_NULL) === 1 ? $m : null;
    }

    private static function duration(mixed $t): int
    {
        $m = self::match('([1-9][0-9]{0,9})(ms|s|m|h|d)', $t);
        if ($m === null) {
            self::fail('duration', sprintf("'%s' is not a duration like 10m, 2h or 7d", Jsx::str($t)));
        }
        $ms = (int)$m[1] * self::UNIT[$m[2]];
        if ($ms > CaveatLang::DERIVE_MAX_WINDOW_MS) {
            self::fail('window', sprintf('a window of %s exceeds the 30-day history the verifier keeps', $t));
        }
        return $ms;
    }

    private static function matches(string $re, string $s): bool
    {
        return preg_match('/\A(?:' . $re . ')\z/', $s) === 1;
    }

    private static function selector(string $text, string $side): Obj
    {
        $tools = [];
        $traits = [];
        $resources = [];
        $any = false;
        foreach (explode(',', $text) as $raw) {
            $a = self::trim($raw);
            if ($a === 'any') {
                $any = true;
            } elseif (str_starts_with($a, 'tool:') && self::matches('[A-Za-z0-9_.:\/-]{1,256}', substr($a, 5))) {
                $tools[] = substr($a, 5);
            } elseif (str_starts_with($a, 'trait:') && self::matches('[A-Za-z0-9_.:\/-]{1,256}', substr($a, 6))) {
                $traits[] = substr($a, 6);
            } elseif (str_starts_with($a, 'resource:') && Js::len($a) > 9 && Js::len($a) <= 9 + 256) {
                if ($side === 'never') {
                    self::fail('resource_on_effect', 'a resource selector can only name the earlier action (the check reads the current verb)');
                }
                $resources[] = substr($a, 9);
            } else {
                self::fail('selector', sprintf("'%s' is not tool:<verb>, trait:<id>, resource:<prefix> or any", $a));
            }
        }
        return Obj::of(['tools' => $tools, 'traits' => $traits, 'resources' => $resources, 'any' => $any]);
    }

    private static function checkId(mixed $id): void
    {
        if (!is_string($id) || !self::matches('[a-z][a-z0-9_]{0,39}', $id)) {
            self::fail('id', sprintf("rule id '%s' must match %s", Jsx::str($id), '^[a-z][a-z0-9_]{0,39}$'));
        }
    }

    /** Parse `never <B> after <A> within <duration>`. Throws {@see TraceRuleError}. */
    public static function parseTraceRule(mixed $id, mixed $text, mixed $reason = null): Obj
    {
        self::checkId($id);
        $m = self::match('{S}*never{S}+({DOT}+?){S}+after{S}+({DOT}+?){S}+within{S}+({NS}+){S}*', $text);
        if ($m === null) {
            self::fail('syntax', sprintf("expected 'never <selector> after <selector> within <duration>', got '%s'", Jsx::str($text)));
        }
        $rule = Obj::of(['id' => $id, 'never' => self::selector($m[1], 'never'), 'after' => self::selector($m[2], 'after'), 'within_ms' => self::duration($m[3])]);
        if ($reason !== null) {
            $rule->set('reason', $reason);
        }
        return $rule;
    }

    /**
     * Import the Invariant subset `raise "<msg>" if: (x: ToolCall|ToolOutput) -> (y: ToolCall)` plus `x is tool:<name>` lines.
     * `horizon` is required. Returns {rule, dropped}.
     */
    public static function parseInvariantRule(mixed $id, mixed $text, mixed $horizon = null, mixed $dropUnsupported = false): Obj
    {
        self::checkId($id);
        if (!is_string($horizon)) {
            self::fail('horizon', 'an Invariant rule has no window: pass the horizon explicitly');
        }
        $withinMs = self::duration($horizon);
        if (!is_string($text)) {
            throw new \TypeError('text.split is not a function');
        }
        $lines = [];
        foreach (explode("\n", $text) as $x) {
            $l = self::trim($x);
            if ($l !== '' && !str_starts_with($l, '#')) {
                $lines[] = $l;
            }
        }
        $head = self::match('raise{S}+(?:"([^"]*)"|\'([^\']*)\'){S}+if:', $lines[0] ?? '');
        if ($head === null) {
            self::fail('syntax', 'the first line must be raise "<message>" if:');
        }
        $flow = self::match('\(([A-Za-z0-9_]+):{S}*(ToolCall|ToolOutput|Message)\){S}*->{S}*\(([A-Za-z0-9_]+):{S}*(ToolCall|ToolOutput|Message)\)', $lines[1] ?? '');
        if ($flow === null) {
            self::fail('unsupported', "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)");
        }
        [$a, $ta, $b, $tb] = [$flow[1], $flow[2], $flow[3], $flow[4]];
        if ($ta === 'Message' || $tb !== 'ToolCall') {
            self::fail('unsupported', 'only a tool call or tool output followed by a tool call can be compiled');
        }
        if ($a === $b) {
            self::fail('syntax', 'the two events need distinct names');
        }
        $tools = [$a => [], $b => []];
        $dropped = [];
        foreach (array_slice($lines, 2) as $l) {
            $m = self::match('([A-Za-z0-9_]+){S}+is{S}+tool:([A-Za-z0-9_.:\/-]+)(\({DOT}*\))?', $l);
            if ($m !== null && isset($tools[$m[1]]) && ($m[3] ?? null) === null) {
                $tools[$m[1]][] = $m[2];
                continue;
            }
            if ($dropUnsupported === true) {
                // `x is tool:name({args})` keeps the tool and drops the argument pattern: a wider match, so more refusals
                if ($m !== null && isset($tools[$m[1]])) {
                    $tools[$m[1]][] = $m[2];
                }
                $dropped[] = $l;
                continue;
            }
            self::fail('unsupported', sprintf("'%s' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead", $l));
        }
        foreach ([$a, $b] as $v) {
            if (count($tools[$v]) > 1) {
                self::fail('unsatisfiable', sprintf("'%s' is constrained to two different tools, so the rule can never fire", $v));
            }
        }
        $sel = static fn(string $v): Obj => Obj::of(['tools' => $tools[$v], 'traits' => [], 'resources' => [], 'any' => count($tools[$v]) === 0]);
        $reason = $head[1] ?? ($head[2] ?? '');
        return Obj::of(['rule' => Obj::of(['id' => $id, 'never' => $sel($b), 'after' => $sel($a), 'within_ms' => $withinMs, 'reason' => $reason]), 'dropped' => $dropped]);
    }

    /** `o[k]` that must exist on an object (a TypeError otherwise, as reading a member of a missing selector). */
    private static function req(mixed $o, string $k): mixed
    {
        if (!($o instanceof Obj) || !$o->has($k)) {
            throw new \TypeError("cannot read '$k'");
        }
        return $o->get($k);
    }

    /** @return list<string> */
    private static function expand(mixed $s, mixed $table, string $what): array
    {
        if (!($table instanceof Obj)) {
            throw new \TypeError('table is not an object');
        }
        $verbs = self::sorted($table->keys());
        $out = [];
        if (self::req($s, 'any') === true) {
            $out = $verbs;
        }
        foreach (Jsx::iter(self::req($s, 'tools')) as $t) {
            if (!is_string($t) || !$table->has($t)) {
                self::fail('unknown_tool', sprintf("%s: tool '%s' is not an action in the verb table", $what, Jsx::str($t)));
            }
            $out[] = $t;
        }
        foreach (Jsx::iter(self::req($s, 'traits')) as $tr) {
            $hit = array_values(array_filter($verbs, static fn($v) => self::has(self::req($table->get($v), 'traits'), $tr)));
            if ($hit === []) {
                self::fail('empty_selector', sprintf("%s: trait '%s' matches no action", $what, Jsx::str($tr)));
            }
            $out = [...$out, ...$hit];
        }
        return self::sorted(self::toSet($out));
    }

    /** Lower rules to derive caveats over the verifier's history. Throws {@see TraceRuleError} on anything not expressible. */
    public static function compileTraceRules(mixed $rules, mixed $table): Obj
    {
        $caveats = [];
        $edges = [];
        $ids = [];
        foreach (Jsx::iter($rules) as $r) {
            $rid = self::req($r, 'id');
            if (!is_string($rid) || !self::matches('[a-z][a-z0-9_]{0,39}', $rid) || isset($ids[$rid])) {
                self::fail('id', sprintf("rule id '%s' is malformed or repeated", Jsx::str($rid)));
            }
            $ids[$rid] = true;
            $w = self::req($r, 'within_ms');
            if (!(IntentWb::isSafeInt($w) && Js::num($w) >= 1 && Js::num($w) <= CaveatLang::DERIVE_MAX_WINDOW_MS)) {
                self::fail('window', sprintf("rule '%s': within_ms must be 1..30 days", $rid));
            }
            $w = (int)Js::num($w);
            $never = self::req($r, 'never');
            if (count(Jsx::iter(self::req($never, 'resources'))) > 0) {
                self::fail('resource_on_effect', sprintf("rule '%s': a resource selector cannot name the later action", $rid));
            }
            $bs = self::expand($never, $table, sprintf("rule '%s' never", $rid));
            $after = self::req($r, 'after');
            $as = array_map(static fn($v) => ['verb' => $v], self::expand($after, $table, sprintf("rule '%s' after", $rid)));
            foreach (self::sorted(self::toSet(Jsx::iter(self::req($after, 'resources')))) as $p) {
                $as[] = ['resource_prefix' => $p];
            }
            if ($bs === [] || $as === []) {
                self::fail('empty_selector', sprintf("rule '%s': a side matches nothing", $rid));
            }
            $n = 0;
            foreach ($as as $a) {
                for ($i = 0; $i < count($bs); $i += self::B_CHUNK) {
                    $chunk = array_slice($bs, $i, self::B_CHUNK);
                    $isB = Obj::of(['op' => 'or', 'args' => array_map(static fn($v) => Obj::of(['op' => 'eq', 'a' => Obj::of(['ref' => 'verb']), 'b' => Obj::of(['const' => $v])]), $chunk)]);
                    $seen = Obj::of(['name' => 'seen', 'kind' => 'count', 'window_ms' => new Num((string)$w)]);
                    foreach ($a as $k => $v) {
                        $seen->set($k, $v);
                    }
                    $c = Obj::of([
                        'type' => 'derive',
                        'id' => sprintf('trace.%s.%d', $rid, $n),
                        'defs' => [$seen, Obj::of(['name' => 'verb', 'kind' => 'action', 'field' => 'verb']), Obj::of(['name' => 'is_b', 'kind' => 'expr', 'expr' => $isB])],
                        // refused iff an A happened within the window AND this action is a B; unknown (no history, no verb) refuses too
                        'check' => Obj::of(['op' => 'not', 'arg' => Obj::of(['op' => 'and', 'args' => [
                            Obj::of(['op' => 'gt', 'a' => Obj::of(['ref' => 'seen']), 'b' => Obj::of(['const' => new Num('0')])]),
                            Obj::of(['ref' => 'is_b']),
                        ]])]),
                    ]);
                    $n++;
                    $e = CaveatLang::deriveError($c);
                    if ($e !== null) {
                        self::fail('internal', sprintf("rule '%s' compiled to an invalid caveat: %s", $rid, $e));
                    }
                    $caveats[] = $c;
                    if (count($caveats) > self::MAX_TRACE_CAVEATS) {
                        self::fail('too_large', sprintf('more than %d caveats: split the rule set or narrow the selectors', self::MAX_TRACE_CAVEATS));
                    }
                }
                foreach ($bs as $v) {
                    $frm = isset($a['verb']) ? Obj::of(['tool' => $a['verb']]) : Obj::of(['resource' => $a['resource_prefix']]);
                    $edges[] = Obj::of(['rule' => $rid, 'from' => $frm, 'to' => $v, 'within_ms' => $w]);
                }
            }
        }
        return Obj::of(['caveats' => $caveats, 'edges' => $edges, 'digest' => Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/trace-rules/v1', 'caveats' => $caveats]))]);
    }

    // ---- lethal trifecta lint ---------------------------------------------------------------------------------------------

    /**
     * Private data, untrusted content and a way out in one action set; a send is cut off when every untrusted read, or every
     * private read, has an edge rule to it. A lint: it reports, it does not enforce.
     */
    public static function lethalTrifecta(mixed $table, mixed $edges, mixed $untrusted = null, mixed $untrustedTraits = null): Obj
    {
        if (!($table instanceof Obj)) {
            throw new \TypeError('table is not an object');
        }
        $verbs = self::sorted($table->keys());
        $untrusted = $untrusted === null ? [] : Jsx::iter($untrusted);
        $untrustedTraits = $untrustedTraits === null ? [] : Jsx::iter($untrustedTraits);
        $traitsOf = static fn(string $v): array => Jsx::iter(self::req($table->get($v), 'traits'));
        $has = static fn(string $v, array $ts): bool => count(array_intersect($traitsOf($v), $ts)) > 0;
        $readOnly = static function (string $v) use ($table): bool {
            $eff = Jsx::get($table->get($v), 'effects');
            $eff = Jsx::truthy($eff) ? Jsx::iter($eff) : [];
            return count($eff) > 0 && count(array_filter($eff, static fn($e) => $e !== 'read')) === 0;
        };
        $priv = array_values(array_filter($verbs, static fn($v) => $has($v, self::PRIVATE_READ_TRAITS)));
        $untr = array_values(array_filter($verbs, static fn($v) => in_array($v, $untrusted, true) || $has($v, $untrustedTraits) || ($readOnly($v) && in_array('pca.network_egress', $traitsOf($v), true))));
        $sends = array_values(array_filter($verbs, static fn($v) => $has($v, self::EXTERNAL_SEND_TRAITS) && !$readOnly($v)));
        $findings = [];
        if ($priv !== [] && $untr !== [] && $sends !== []) {
            $ruled = static function (string $frm, string $to) use ($edges): bool {
                foreach (Jsx::iter($edges) as $e) {
                    $f = self::req($e, 'from');
                    if ($f instanceof Obj && $f->has('tool') && $f->get('tool') === $frm && self::req($e, 'to') === $to) {
                        return true;
                    }
                }
                return false;
            };
            foreach ($sends as $s) {
                $fu = array_values(array_filter($untr, static fn($u) => !$ruled($u, $s)));
                $fp = array_values(array_filter($priv, static fn($p) => !$ruled($p, $s)));
                if ($fu !== [] && $fp !== []) {
                    $findings[] = Obj::of(['send' => $s, 'from_untrusted' => $fu, 'from_private' => $fp]);
                }
            }
        }
        return Obj::of(['private_reads' => $priv, 'untrusted_reads' => $untr, 'sends' => $sends, 'findings' => $findings]);
    }

    // ---- detector receipts + adapters -------------------------------------------------------------------------------------

    private static function idOk(mixed $s): bool
    {
        return is_string($s) && self::matches('[a-z][a-z0-9_]{0,63}', $s);
    }

    /** b64u(sha256(strictCanonical({d, content}))): the digest a receipt binds. */
    public static function detectorInputDigest(mixed $content): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/detector-input/v1', 'content' => $content]));
    }

    public static function detectorReceiptRef(mixed $r): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::DETECTOR_RECEIPT_REF_DOMAIN, 'receipt' => $r]));
    }

    /** Null when well-formed. */
    public static function detectorReceiptShapeError(mixed $r): ?string
    {
        if (!($r instanceof Obj)) {
            return 'receipt must be an object';
        }
        $e = IntentWb::closedMembers($r, ['v', 'kind', 'detector', 'version', 'input_digest', 'verdict', 'categories', 'iat', 'sig'],
            ['session', 'calibration_ref', 'alg', 'pq_pk', 'pq_sig'], 'receipt');
        if ($e !== null) {
            return $e;
        }
        $v = $r->get('v');
        if (!Js::isNum($v) || Js::num($v) !== 1.0 || $r->get('kind') !== 'pca-detector-receipt') {
            return 'not a pca-detector-receipt v1';
        }
        if (!self::idOk($r->get('detector'))) {
            return 'detector id is malformed';
        }
        if (!IntentWb::isBoundedString($r->get('version'), 64)) {
            return 'version must be 1..64 bytes';
        }
        if (!IntentWb::isDigest($r->get('input_digest'))) {
            return 'input_digest must be a b64u 32-byte digest';
        }
        $verdict = $r->get('verdict');
        if (!is_string($verdict) || !in_array($verdict, self::DETECTOR_VERDICTS, true)) {
            return "verdict must be 'suspicious' or 'no_finding'";
        }
        $c = $r->get('categories');
        if (!self::isSet($c) || count($c) > 8) {
            return 'categories must be 0..8 ids';
        }
        foreach ($c as $x) {
            if (!self::idOk($x)) {
                return 'categories must be 0..8 ids';
            }
        }
        for ($i = 1; $i < count($c); $i++) {
            if (!($c[$i - 1] < $c[$i])) {
                return 'categories must be sorted and distinct';
            }
        }
        if ($verdict === 'no_finding' && count($c) > 0) {
            return 'a no_finding receipt carries no categories';
        }
        if (!(IntentWb::isSafeInt($r->get('iat')) && Js::num($r->get('iat')) >= 0)) {
            return 'iat must be a non-negative integer';
        }
        if ($r->has('session') && !IntentWb::isDigest($r->get('session'))) {
            return 'session must be a b64u 32-byte id';
        }
        if ($r->has('calibration_ref') && !IntentWb::isBoundedString($r->get('calibration_ref'), 256)) {
            return 'calibration_ref must be 1..256 bytes';
        }
        if (!is_string($r->get('sig'))) {
            return 'sig must be a string';
        }
        return IntentWb::artifactSuiteError($r);
    }

    public const MAX_DETECTOR_RECEIPTS = 32;

    /** Null when the detector policy `{detectors: [{id, keys, on_suspicious, max_age_ms, categories?}]}` is well-formed. */
    public static function detectorPolicyError(mixed $p): ?string
    {
        if (!($p instanceof Obj) || IntentWb::closedMembers($p, ['detectors']) !== null) {
            return 'policy must be {detectors}';
        }
        $ds = $p->get('detectors');
        if (!is_array($ds) || !array_is_list($ds) || count($ds) > 16) {
            return 'detectors must hold at most 16 entries';
        }
        $ids = [];
        foreach ($ds as $d) {
            if (!($d instanceof Obj) || IntentWb::closedMembers($d, ['id', 'keys', 'on_suspicious', 'max_age_ms'], ['categories']) !== null) {
                return 'detector entry is malformed';
            }
            $id = $d->get('id');
            if (!self::idOk($id) || $id === 'invalid' || isset($ids[$id])) {
                return 'detector ids must be distinct ids other than "invalid"';
            }
            $ids[$id] = true;
            $keys = $d->get('keys');
            if (!is_array($keys) || !array_is_list($keys) || count($keys) < 1 || count($keys) > 8) {
                return "detector '$id': keys must hold 1..8 pins";
            }
            foreach ($keys as $k) {
                if (!($k instanceof Obj) || !is_string($k->get('pk')) || ($k->has('pq_pk') && !is_string($k->get('pq_pk')))) {
                    return "detector '$id': keys must hold 1..8 pins";
                }
            }
            $on = $d->get('on_suspicious');
            if ($on !== 'escalate' && $on !== 'deny') {
                return "detector '$id': on_suspicious must be escalate or deny";
            }
            if ($d->has('categories')) {
                $c = $d->get('categories');
                $ok = is_array($c) && array_is_list($c) && count($c) >= 1;
                foreach ($ok ? $c : [] as $x) {
                    $ok = $ok && self::idOk($x);
                }
                if (!$ok) {
                    return "detector '$id': categories must be 1+ ids";
                }
            }
            $age = $d->get('max_age_ms');
            if (!(IntentWb::isSafeInt($age) && Js::num($age) >= 1 && Js::num($age) <= 86400000)) {
                return "detector '$id': max_age_ms must be 1..86400000";
            }
        }
        return null;
    }

    private static function receiptProblem(mixed $r, Obj $policy, array $digests, mixed $session, mixed $now): ?string
    {
        $se = self::detectorReceiptShapeError($r);
        if ($se !== null) {
            return "malformed: $se";
        }
        $d = null;
        foreach ($policy->get('detectors') as $x) {
            if ($x->get('id') === $r->get('detector')) {
                $d = $x;
                break;
            }
        }
        $id = $r->get('detector');
        if ($d === null) {
            return "undeclared detector '$id'";
        }
        $signed = false;
        foreach ($d->get('keys') as $k) {
            if (IntentWb::verifyArtifactSig(self::DETECTOR_RECEIPT_DOMAIN, $r, $k)) {
                $signed = true;
                break;
            }
        }
        if (!$signed) {
            return "detector '$id': no pinned key signed it";
        }
        if (!in_array($r->get('input_digest'), $digests, true)) {
            return "detector '$id': the receipt is about other content";
        }
        if ($r->has('session') && $r->get('session') !== $session) {
            return "detector '$id': bound to another session";
        }
        $iat = Js::num($r->get('iat'));
        $nowF = Js::num($now);
        if ($iat === null || $nowF === null || !(is_finite($nowF) && $iat <= $nowF)) {
            return "detector '$id': from the future";
        }
        if ($now - $iat > Js::num($d->get('max_age_ms'))) {
            return "detector '$id': stale";
        }
        return null;
    }

    /**
     * The tighten-only fold of detector receipts (detectorSignal of the reference). Total. `$input`: `receipts` (list), `policy` (Obj),
     * `input_digests` (list of {@see detectorInputDigest} values), `session` (optional), `now` (int ms). Returns `signal` ('ok' | 'escalate' |
     * 'deny'; fold with {@see Decision::tighten}), `env` (an Obj `{detect: {<id>: bool, invalid: count}}` for `tighten[]` rules), `flagged`
     * (sorted detector ids whose valid suspicious receipt acted) and `rejected` (`['index', 'reason']` list). A malformed policy is deny; an
     * invalid receipt lowers the signal to escalate; a valid no_finding changes nothing.
     * @param array<string,mixed> $input
     * @return array{signal:string,env:Obj,flagged:list<string>,rejected:list<array{index:int,reason:string}>}
     */
    public static function detectorSignal(array $input): array
    {
        $rank = ['ok' => 2, 'escalate' => 1, 'deny' => 0];
        $signal = 'ok';
        $lower = static function (string $s) use (&$signal, $rank): void {
            if ($rank[$s] < $rank[$signal]) {
                $signal = $s;
            }
        };
        $flagged = [];
        $rejected = [];
        $env = new Obj();
        try {
            $policy = $input['policy'] ?? null;
            $pe = self::detectorPolicyError($policy);
            if ($pe !== null) {
                return ['signal' => 'deny', 'env' => Obj::of(['detect' => Obj::of(['invalid' => new Num('0')])]), 'flagged' => [],
                    'rejected' => [['index' => -1, 'reason' => "policy: $pe"]]];
            }
            foreach ($policy->get('detectors') as $d) {
                $env->set($d->get('id'), false);
            }
            $receipts = $input['receipts'] ?? [];
            $digests = $input['input_digests'] ?? [];
            $digests = is_array($digests) ? $digests : [];
            $now = $input['now'] ?? null;
            if (!is_array($receipts) || !array_is_list($receipts) || count($receipts) > self::MAX_DETECTOR_RECEIPTS || !IntentWb::isSafeInt($now)) {
                $lower('escalate');
                $rejected[] = ['index' => -1, 'reason' => 'receipt list or clock malformed'];
            } else {
                $nowN = Js::num($now);
                foreach ($receipts as $index => $r) {
                    $why = self::receiptProblem($r, $policy, $digests, $input['session'] ?? null, $nowN);
                    if ($why !== null) {
                        $rejected[] = ['index' => $index, 'reason' => $why];
                        $lower('escalate');
                        continue;
                    }
                    if ($r->get('verdict') !== 'suspicious') {
                        continue;
                    }
                    foreach ($policy->get('detectors') as $x) {
                        if ($x->get('id') === $r->get('detector')) {
                            $d = $x;
                            break;
                        }
                    }
                    $cats = $r->get('categories');
                    if ($d->has('categories') && count($cats) > 0 && count(array_intersect($cats, $d->get('categories'))) === 0) {
                        continue;
                    }
                    $flagged[$d->get('id')] = true;
                    $env->set($d->get('id'), true);
                    $lower($d->get('on_suspicious'));
                }
            }
        } catch (\Throwable $e) {
            $lower('deny');
            $rejected[] = ['index' => -1, 'reason' => 'evaluation error (fail closed): ' . ($e->getMessage() !== '' ? $e->getMessage() : 'unknown')];
        }
        $env->set('invalid', new Num((string)count($rejected)));
        $ids = array_map('strval', array_keys($flagged));
        sort($ids, SORT_STRING);
        return ['signal' => $signal, 'env' => Obj::of(['detect' => $env]), 'flagged' => $ids, 'rejected' => $rejected];
    }

    /** Sign a receipt with the detector gateway's key (a KeyPair or a 32-byte Ed25519 seed). Throws on a malformed body. */
    public static function signDetectorReceipt(mixed $body, mixed $key, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $ed = $key instanceof KeyPair ? $key : new KeyPair((string)$key);
        if (($alg === null || $alg === 'ed25519') && $pq === null) {
            // the default suite signs the body as given (an `alg` member the caller wrote is part of the signed bytes and is judged by the shape check)
            $signed = $body->without('sig', 'pq_sig');
            $signed->set('sig', Pca::b64u($ed->sign(self::DETECTOR_RECEIPT_DOMAIN . Json::canonicalizeNative($signed))));
        } else {
            $signed = Sign::signArtifact(self::DETECTOR_RECEIPT_DOMAIN, $body, $ed, $alg, $pq);
        }
        $e = self::detectorReceiptShapeError($signed);
        if ($e !== null) {
            throw new \InvalidArgumentException("signDetectorReceipt: $e");
        }
        return $signed;
    }

    /** Vendor category text to a receipt category id (lowercase, non-alphanumerics to `_`); unusable text becomes `other`. */
    public static function categoryId(mixed $s): string
    {
        if (!is_string($s)) {
            return 'other';
        }
        $c = preg_replace('/\A_+|_+\z/', '', preg_replace('/[^a-z0-9]+/', '_', mb_strtolower($s)) ?? '') ?? '';
        $c = substr(preg_replace('/\A([0-9])/', 'c_$1', $c) ?? $c, 0, 64);
        return self::idOk($c) ? $c : 'other';
    }

    /** @param array{detector:mixed,version:mixed,content:mixed,secretKey:mixed,now:mixed,session?:mixed,calibrationRef?:mixed} $ctx */
    private static function receipt(array $ctx, bool $suspicious, iterable $categories): Obj
    {
        $cats = $suspicious ? array_slice(self::sorted(self::toSet([...$categories])), 0, 8) : [];
        $body = Obj::of([
            'v' => new Num('1'), 'kind' => 'pca-detector-receipt', 'detector' => $ctx['detector'], 'version' => $ctx['version'],
            'input_digest' => self::detectorInputDigest($ctx['content']), 'verdict' => $suspicious ? 'suspicious' : 'no_finding',
            'categories' => $cats, 'iat' => $ctx['now'],
        ]);
        if (($ctx['session'] ?? null) !== null) {
            $body->set('session', $ctx['session']);
        }
        if (($ctx['calibrationRef'] ?? null) !== null) {
            $body->set('calibration_ref', $ctx['calibrationRef']);
        }
        return self::signDetectorReceipt($body, $ctx['secretKey']);
    }

    private static function errorReceipt(array $ctx): Obj
    {
        return self::receipt($ctx, true, ['detector_error']);
    }

    /** Lakera Guard v2 `/guard` response. */
    public static function lakeraReceipt(mixed $response, array $ctx): Obj
    {
        if (!($response instanceof Obj) || !is_bool($response->get('flagged'))) {
            return self::errorReceipt($ctx);
        }
        $cats = [];
        if ($response->has('breakdown')) {
            $bd = $response->get('breakdown');
            if (!self::isSet($bd)) {
                return self::errorReceipt($ctx);
            }
            foreach ($bd as $b) {
                if (!($b instanceof Obj) || !is_bool($b->get('detected'))) {
                    return self::errorReceipt($ctx);
                }
                if ($b->get('detected')) {
                    $cats[] = self::categoryId($b->get('detector_type'));
                }
            }
        }
        $cats = self::toSet($cats);
        $suspicious = $response->get('flagged') || count($cats) > 0;
        if ($suspicious && !$cats) {
            $cats[] = 'flagged';
        }
        return self::receipt($ctx, $suspicious, $cats);
    }

    /** Prompt Security `/api/protect` response (both published integration shapes accepted; clean only when no action is block or modify and no violation is listed). */
    public static function promptSecurityReceipt(mixed $response, array $ctx): Obj
    {
        $r = $response instanceof Obj && $response->get('result') instanceof Obj ? $response->get('result') : null;
        if ($r === null) {
            return self::errorReceipt($ctx);
        }
        $p = $r->get('prompt');
        if ($r->has('prompt') && !($p instanceof Obj)) {
            return self::errorReceipt($ctx);
        }
        $actions = $r->has('action') ? [$r->get('action')] : [];
        if ($p instanceof Obj && $p->has('action')) {
            $actions[] = $p->get('action');
        }
        if ($actions === [] || count(array_filter($actions, 'is_string')) !== count($actions)) {
            return self::errorReceipt($ctx);
        }
        $violations = $p instanceof Obj && $p->has('violations') ? $p->get('violations') : null;
        if ($p instanceof Obj && $p->has('violations') && !self::isSet($violations)) {
            return self::errorReceipt($ctx);
        }
        $cats = [];
        foreach ($violations ?? [] as $v) {
            $cats[] = self::categoryId($v);
        }
        if (in_array('block', $actions, true)) {
            $cats[] = 'blocked';
        }
        if (in_array('modify', $actions, true)) {
            $cats[] = 'modified';
        }
        $cats = self::toSet($cats);
        return self::receipt($ctx, count($cats) > 0, $cats);
    }

    /** Any detector that answers `{flagged, categories?}`. */
    public static function genericReceipt(mixed $response, array $ctx): Obj
    {
        if (!($response instanceof Obj) || !is_bool($response->get('flagged'))) {
            return self::errorReceipt($ctx);
        }
        if ($response->has('categories') && !self::isSet($response->get('categories'))) {
            return self::errorReceipt($ctx);
        }
        $cats = [];
        foreach ($response->has('categories') ? $response->get('categories') : [] as $c) {
            $cats[] = self::categoryId($c);
        }
        $cats = self::toSet($cats);
        $flagged = $response->get('flagged');
        if (!$flagged && $cats) {
            return self::errorReceipt($ctx); // categories on a clean answer: ambiguous
        }
        if ($flagged && !$cats) {
            $cats[] = 'flagged';
        }
        return self::receipt($ctx, $flagged, $cats);
    }
}
