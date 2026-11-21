<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/A2a.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/ActionsImport.php';
require_once __DIR__ . '/IntentV2.php';

/**
 * The MCP adapter: the WWW-Authenticate parser and step-up planner (with the typed `pca_need` requirement), the RFC 9207 `iss` table,
 * the client conformance matrix, the tool-result proof meta, the `PCA-Action` header, and the v1 action-schema draft from an MCP tool
 * list (JSON Schema flattening, the closed-world tool-call check). Values are the parsed-JSON model (Obj, lists, string, Num / int /
 * float, bool, null). withPca guards a tool handler with an Agent; withProof attaches the proof header to a `tools/call` request body
 * (the reference's fetch wrapper has no PHP equivalent: this is its request-side step for any HTTP client).
 * Whatever the draft cannot represent is flagged in `todo` and declared `string`, which rejects every non-string value, so the draft
 * fails closed until the developer refines it.
 */
final class Mcp
{
    public const PCA_ACTION_HEADER = 'PCA-Action';
    public const RESULT_META_KEY = 'x-pca-action';
    public const MCP_CLIENT_REVISIONS = ['2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28', 'draft'];
    private const MAX_REF_DEPTH = 8;
    private const MAX_REF_NODES = 20000;

    /** The reference's `undefined` (a member that is absent), distinct from null. */
    private static ?\stdClass $undef = null;

    private static function undef(): \stdClass
    {
        return self::$undef ??= new \stdClass();
    }

    // ---- JS-model helpers ----

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    /** The WTF-8 UTF-16 code units of a string (an astral character is two surrogate halves). @return list<string> */
    private static function units(string $s): array
    {
        $out = [];
        $n = strlen($s);
        for ($i = 0; $i < $n;) {
            $b = ord($s[$i]);
            $len = $b < 0x80 ? 1 : ($b < 0xE0 ? 2 : ($b < 0xF0 ? 3 : 4));
            $ch = substr($s, $i, $len);
            $i += $len;
            if ($len === 4 && strlen($ch) === 4) {
                $cp = (($b & 7) << 18 | (ord($ch[1]) & 0x3F) << 12 | (ord($ch[2]) & 0x3F) << 6 | (ord($ch[3]) & 0x3F)) - 0x10000;
                foreach ([0xD800 + ($cp >> 10), 0xDC00 + ($cp & 0x3FF)] as $u) {
                    $out[] = chr(0xE0 | ($u >> 12)) . chr(0x80 | (($u >> 6) & 0x3F)) . chr(0x80 | ($u & 0x3F));
                }
            } else {
                $out[] = $ch;
            }
        }
        return $out;
    }

    /** `{...x}`: an object copies, a list or a string gives its indices, anything else gives nothing. */
    private static function spreadObj(mixed $x): Obj
    {
        $o = new Obj();
        if ($x instanceof Obj) {
            foreach ($x->keys() as $k) {
                $o->set($k, $x->get($k));
            }
        } elseif (self::isList($x)) {
            foreach ($x as $i => $v) {
                $o->set((string)$i, $v);
            }
        } elseif (is_string($x)) {
            foreach (self::units($x) as $i => $u) {
                $o->set((string)$i, $u);
            }
        }
        return $o;
    }

    /** `[...x]` of a member: absent / null is empty, a list copies, a string spreads by code point, anything else throws. @return list<mixed> */
    private static function iter(mixed $x): array
    {
        if ($x === null) {
            return [];
        }
        if (self::isList($x)) {
            return $x;
        }
        if (is_string($x)) {
            return (preg_split('//u', $x, -1, PREG_SPLIT_NO_EMPTY) ?: str_split($x));
        }
        throw new \TypeError('value is not iterable');
    }

    /** Object.keys / Object.entries order of a parsed value. @return list<string> */
    private static function keysOf(mixed $o): array
    {
        if ($o instanceof Obj) {
            return Js::ownKeys($o->keys());
        }
        if (self::isList($o)) {
            return array_map('strval', array_keys($o));
        }
        if (is_string($o)) {
            return array_map('strval', array_keys(self::units($o)));
        }
        return [];
    }

    private static function valueOf(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        if (self::isList($o)) {
            return $o[(int)$k] ?? null;
        }
        return is_string($o) ? self::units($o)[(int)$k] : null;
    }

    private static function safeInt(mixed $o): bool
    {
        $d = Js::num($o);
        return $d !== null && is_finite($d) && $d == floor($d) && abs($d) <= 9007199254740991.0;
    }

    /** A UTF-16 code unit order sort key (what Array.prototype.sort compares). */
    private static function u16(string $s): string
    {
        $u = @mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
        return is_string($u) ? $u : $s;
    }

    private static function slice1024(mixed $d): mixed
    {
        if (is_string($d)) {
            $u = self::units($d);
            return count($u) > 1024 ? implode('', array_slice($u, 0, 1024)) : $d;
        }
        if (self::isList($d)) {
            return array_slice($d, 0, 1024);
        }
        throw new \TypeError('slice is not a function');
    }

    /** Throws the TypeError a property read on null / undefined raises. */
    private static function nn(mixed $o, string $k): void
    {
        if ($o === null) {
            throw new \TypeError("Cannot read properties of null (reading '$k')");
        }
    }

    // ---- tool results and headers ----

    /** The tool result of a refused call: one text item and isError. */
    public static function deniedResult(string $text): Obj
    {
        return Obj::of(['content' => [Obj::of(['type' => 'text', 'text' => $text])], 'isError' => true]);
    }

    /**
     * Guard an MCP tool handler: sign the action (verb, resource from the spec or its resourceOf callable) with the agent first; a
     * refused action becomes an error result instead of an exception. Spec keys: verb, resource, resourceOf, onProof, failFast (default true: an action
     * outside the grant's predicates and caveats is refused before the handler runs). The handler
     * is callable(array $args, mixed $extra): mixed.
     */
    public static function withPca(Agent $agent, array $spec, callable $handler): \Closure
    {
        return static function (mixed $args, mixed $extra = null) use ($agent, $spec, $handler): mixed {
            try {
                $resource = isset($spec['resourceOf']) ? ($spec['resourceOf'])($args) : $spec['resource'];
                if (($spec['failFast'] ?? true) !== false) {
                    $why = $agent->envelopeRefusal((string)$spec['verb'], (string)$resource, $args);
                    if ($why !== null) {
                        return self::deniedResult($why);
                    }
                }
                $pca = $agent->act((string)$spec['verb'], (string)$resource, $args);
            } catch (\InvalidArgumentException $e) {
                return self::deniedResult($e->getMessage());
            }
            if (isset($spec['onProof'])) {
                ($spec['onProof'])($pca, $args);
            }
            return $handler($args, $extra);
        };
    }

    /** The result with the proof of the call in `_meta['x-pca-action']`; `$pca` is {encoded} (an Obj or array). */
    public static function guardToolResult(mixed $pca, mixed $result): Obj
    {
        self::nn($result, '_meta');
        $prev = Js::opt($result, '_meta');
        $meta = Js::truthy($prev) && ($prev instanceof Obj || self::isList($prev)) ? self::spreadObj($prev) : new Obj();
        self::nn($pca, 'encoded');
        if (Js::has($pca, 'encoded')) {
            $meta->set(self::RESULT_META_KEY, Js::opt($pca, 'encoded'));
        } else {
            $meta = $meta->without(self::RESULT_META_KEY); // the spread assigns undefined over a previous value, which JSON drops
        }
        $out = self::spreadObj($result);
        $out->set('_meta', $meta);
        return $out;
    }

    /** The `PCA-Action` header of an encoded PCActn: base64url of its UTF-8 text. */
    public static function pcaHeaders(string $encoded): array
    {
        return [self::PCA_ACTION_HEADER => Jose::b64u(Js::utf8($encoded))];
    }

    /** The `tools/call` message in a request body: {name, arguments} (arguments that are not an object count as none), else null. */
    public static function toolCallOf(mixed $body): ?array
    {
        if (!is_string($body)) {
            return null;
        }
        try {
            $msg = Js::parse($body);
        } catch (\Throwable) {
            return null;
        }
        if (!($msg instanceof Obj) || $msg->get('method') !== 'tools/call') {
            return null;
        }
        $params = $msg->get('params');
        $name = Js::opt($params, 'name');
        $args = Js::opt($params, 'arguments');
        if (!is_string($name)) {
            return null;
        }
        return ['name' => $name, 'arguments' => $args instanceof Obj ? $args : new Obj()];
    }

    /**
     * Attach the proof of a `tools/call` request to its headers. `$toolAction` is callable(string $tool, Obj $args): ?array{0:string,1:string}
     * (verb, resource), null for a tool that needs no proof. Returns the headers, unchanged for any other request.
     * @param array<string,string> $headers @return array<string,string>
     */
    public static function withProof(Agent $agent, callable $toolAction, mixed $body, array $headers = []): array
    {
        $call = self::toolCallOf($body);
        if ($call === null) {
            return $headers;
        }
        $act = $toolAction($call['name'], $call['arguments']);
        return $act === null ? $headers : array_replace($headers, $agent->act($act[0], $act[1], $call['arguments'])->headers);
    }

    /**
     * The agent's per-call proof for an MCP client transport, over an injected fetch: `$fetch(string $url, array $init)` (init: body, headers,
     * ...). For every `tools/call` request it adds a fresh signed `PCA-Action` header (verb and resource from `$toolAction`, null = send the
     * call without a proof); every other request passes through unchanged. With a `$recorder` the response is recorded as UNTRUSTED tool output
     * before it is returned: a response with `text()` by its body, an event stream (content-type from `header('content-type')`) or an
     * unreadable body by its origin. It decides nothing: the server's verifier does. The per-call audience override of the reference is not
     * offered (the agent owns the audience).
     *
     * @param callable(string, Obj): ?array{0:string,1:string} $toolAction
     * @param callable(string, array<string,mixed>): mixed $fetch
     * @return \Closure(string, array<string,mixed>=): mixed
     */
    public static function pcaFetch(Agent $agent, callable $toolAction, callable $fetch, ?ProvenanceRecorder $recorder = null): \Closure
    {
        return static function (string $url, array $init = []) use ($agent, $toolAction, $fetch, $recorder): mixed {
            $call = self::toolCallOf($init['body'] ?? null);
            if ($call === null) {
                return $fetch($url, $init);
            }
            $act = $toolAction($call['name'], $call['arguments']);
            if ($act === null) {
                return $fetch($url, $init);
            }
            $init['headers'] = array_replace($init['headers'] ?? [], $agent->act($act[0], $act[1], $call['arguments'])->headers);
            $res = $fetch($url, $init);
            if ($recorder !== null) {
                $ct = '';
                try {
                    $ct = is_object($res) && method_exists($res, 'header') ? (string)($res->header('content-type') ?? '') : '';
                } catch (\Throwable) {
                    $ct = '';
                }
                $content = Obj::of(['tool' => $call['name'], 'stream' => $url]);
                if (stripos($ct, 'event-stream') === false && is_object($res) && method_exists($res, 'text')) {
                    try {
                        $content = $res->text();
                    } catch (\Throwable) {
                        // unreadable: keep the origin-only record
                    }
                }
                $recorder->tool($call['name'], $content);
            }
            return $res;
        };
    }

    // ---- authorization step-up (client) ----

    private const NEED_PARAM_U = '/(?:^|[\t\n\x0B\f\r ,\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}])pca_need="([^"\\\\]*)"/u';
    private const NEED_PARAM = '/(?:^|[\t\n\x0B\f\r ,])pca_need="([^"\\\\]*)"/';

    /** The need a `pca_need` auth-param carries: {ok:true, need} or {ok:false, code}; null when the header names none. */
    public static function pcaNeedFromChallenge(mixed $header): ?array
    {
        if (!is_string($header)) {
            return null;
        }
        $r = preg_match(self::NEED_PARAM_U, $header, $m);
        if ($r === false) { // not UTF-8 (a lone surrogate): the ASCII separators only
            $r = preg_match(self::NEED_PARAM, $header, $m);
        }
        if ($r !== 1) {
            return null;
        }
        [$need, $code] = A2a::decodeNeed($m[1]);
        return $need !== null ? ['ok' => true, 'need' => $need] : ['ok' => false, 'code' => $code];
    }

    /**
     * Every challenge of a WWW-Authenticate header (quoted strings, several challenges): {scheme, params}, names lower-cased, a repeated
     * parameter keeps its first value, 'constructor' and '__proto__' are never stored.
     * @return list<Obj>
     */
    public static function parseChallenges(mixed $header): array
    {
        $out = [];
        if (!is_string($header)) {
            return $out;
        }
        $n = strlen($header);
        $i = 0;
        $cur = null;
        $ws = static function () use (&$i, $n, $header): void {
            while ($i < $n && ($header[$i] === ' ' || $header[$i] === "\t" || $header[$i] === ',')) {
                $i++;
            }
        };
        $token = static function () use (&$i, $n, $header): string {
            $s = $i;
            while ($i < $n && strpos(" \t,=\"", $header[$i]) === false) {
                $i++;
            }
            return substr($header, $s, $i - $s);
        };
        $ws();
        while ($i < $n) {
            $name = $token();
            if ($name === '') {
                $i++; // a stray quote or equals sign: skip it
                continue;
            }
            while ($i < $n && ($header[$i] === ' ' || $header[$i] === "\t")) {
                $i++;
            }
            $key = mb_check_encoding($name, 'UTF-8') ? mb_strtolower($name, 'UTF-8') : strtolower($name);
            if ($i < $n && $header[$i] === '=') {
                $i++;
                while ($i < $n && ($header[$i] === ' ' || $header[$i] === "\t")) {
                    $i++;
                }
                $val = '';
                if ($i < $n && $header[$i] === '"') {
                    $i++;
                    while ($i < $n && $header[$i] !== '"') {
                        if ($header[$i] === '\\' && $i + 1 < $n) {
                            $i++;
                        }
                        $val .= $header[$i];
                        $i++;
                    }
                    $i++; // closing quote
                } else {
                    $val = $token();
                }
                if ($cur !== null && !$cur->get('params')->has($key) && $key !== 'constructor' && $key !== '__proto__') {
                    $cur->get('params')->set($key, $val);
                }
            } else {
                $cur = Obj::of(['scheme' => $key, 'params' => new Obj()]);
                $out[] = $cur;
            }
            $ws();
        }
        return $out;
    }

    /**
     * What to do with a 403 challenge: re-authorize with the union of the scopes already requested and the challenge's (sorted), hand a
     * valid `pca_need` to the approval flow (pcaAware, the scope union kept as the fallback), or give up (not an insufficient_scope
     * challenge, the retry limit, or a union that adds nothing). `$state`: requested, attempts, maxAttempts (3), pcaAware.
     * @return array<string,mixed>
     */
    public static function planStepUp(mixed $status, mixed $wwwAuthenticate, mixed $state): array
    {
        $ma = Js::opt($state, 'maxAttempts');
        $max = $ma === null ? 3.0 : (Js::num($ma) ?? NAN);
        $bearer = null;
        if (Js::num($status) === 403.0) {
            foreach (self::parseChallenges($wwwAuthenticate) as $c) {
                if ($c->get('scheme') === 'bearer') {
                    $bearer = $c;
                    break;
                }
            }
        }
        if ($bearer === null || $bearer->get('params')->get('error') !== 'insufficient_scope') {
            return ['action' => 'give_up', 'reason' => 'not_insufficient_scope'];
        }
        $attemptsIn = Js::num(Js::opt($state, 'attempts')) ?? NAN;
        if ($attemptsIn >= $max) {
            return ['action' => 'give_up', 'reason' => 'retry_limit'];
        }
        $requested = self::iter(Js::get($state, 'requested'));
        $had = [];
        $union = [];
        foreach ($requested as $r) {
            if (is_string($r)) {
                $had[$r] = true;
            }
            $union[Js::str($r)] = true;
        }
        $scope = $bearer->get('params')->get('scope');
        foreach (is_string($scope) ? explode(' ', $scope) : [] as $x) {
            if ($x !== '') {
                $union[$x] = true;
            }
        }
        $union = array_map('strval', array_keys($union));
        usort($union, static fn(string $a, string $b): int => strcmp(self::u16($a), self::u16($b)));
        $attempts = $attemptsIn + 1;
        if (Js::opt($state, 'pcaAware') === true) {
            $r = is_string($wwwAuthenticate) ? self::pcaNeedFromChallenge($wwwAuthenticate) : null;
            if ($r !== null && $r['ok']) {
                return ['action' => 'pca', 'need' => $r['need'], 'fallbackScopes' => $union, 'attempts' => $attempts];
            }
        }
        $allHad = true;
        foreach ($union as $s) {
            $allHad = $allHad && isset($had[$s]);
        }
        if ($allHad) {
            return ['action' => 'give_up', 'reason' => 'no_new_scope'];
        }
        return ['action' => 'scope', 'scopes' => $union, 'attempts' => $attempts];
    }

    /** The code of a `pca_need` that is present but unusable (for client logs), else null. */
    public static function pcaNeedProblem(mixed $wwwAuthenticate): ?string
    {
        $r = self::pcaNeedFromChallenge($wwwAuthenticate);
        return $r !== null && !$r['ok'] ? $r['code'] : null;
    }

    /**
     * The RFC 9207 `iss` table for an authorization response, with no normalization. `$a`: recordedIssuer, issParameterSupported, iss
     * (an absent iss differs from a null one).
     * @return array{proceed:bool,reason?:string}
     */
    public static function checkAuthorizationResponseIss(mixed $a): array
    {
        $rec = Js::get($a, 'recordedIssuer');
        if (!is_string($rec) || $rec === '') {
            return ['proceed' => false, 'reason' => 'no_recorded_issuer'];
        }
        if (!Js::has($a, 'iss')) {
            return Js::opt($a, 'issParameterSupported') === true ? ['proceed' => false, 'reason' => 'iss_missing'] : ['proceed' => true];
        }
        return Js::opt($a, 'iss') === $rec ? ['proceed' => true] : ['proceed' => false, 'reason' => 'iss_mismatch'];
    }

    // ---- client conformance matrix ----

    private static function row(string $id, string $requirement, string $section, string ...$levels): Obj
    {
        return Obj::of(['id' => $id, 'requirement' => $requirement, 'levels' => Obj::of(array_combine(self::MCP_CLIENT_REVISIONS, $levels)), 'section' => $section]);
    }

    /** @return list<Obj> the MCP authorization client requirements by spec revision */
    public static function mcpAuthClientRows(): array
    {
        return [
            self::row('parse-www-authenticate', 'Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.', 'Protected Resource Metadata Discovery Requirements', 'n/a', 'MUST', 'MUST', 'MUST', 'MUST'),
            self::row('step-up-on-insufficient-scope', 'Respond to 403 insufficient_scope by re-authorizing with an increased scope set.', 'Step-Up Authorization Flow', 'n/a', 'n/a', 'SHOULD', 'SHOULD', 'SHOULD'),
            self::row('scope-union', 'The new scope set is the union of the previously requested set and the challenge scopes.', 'Step-Up Authorization Flow, step 2', 'n/a', 'n/a', 'n/a', 'SHOULD', 'SHOULD'),
            self::row('retry-limit', 'Retry no more than a few times and track upgrade attempts per resource and operation.', 'Step-Up Authorization Flow, step 4', 'n/a', 'n/a', 'SHOULD', 'SHOULD', 'SHOULD'),
            self::row('iss-validation-table', 'Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.', 'Authorization Response Validation', 'n/a', 'n/a', 'n/a', 'MUST', 'MUST'),
            self::row('pca-need-ignored-by-stock-client', 'A client that does not know pca_need behaves exactly as without it.', 'RFC 9110 section 11.2 (unknown auth-params are ignored)', 'EXT', 'EXT', 'EXT', 'EXT', 'EXT'),
        ];
    }

    // ---- site action schema ----

    /** Follow a local `#/a/b` JSON pointer in `$root`; null when absent, not local, or not an object / list. */
    private static function pointer(mixed $root, string $ref): mixed
    {
        if (!str_starts_with($ref, '#/')) {
            return null;
        }
        $cur = $root;
        foreach (explode('/', substr($ref, 2)) as $raw) {
            $seg = str_replace(['~1', '~0'], ['/', '~'], $raw);
            if ($cur instanceof Obj) {
                if (!$cur->has($seg)) {
                    return null;
                }
                $cur = $cur->get($seg);
            } elseif (self::isList($cur)) {
                if (preg_match('/\A(?:0|[1-9][0-9]{0,8})\z/', $seg) !== 1 || (int)$seg >= count($cur)) {
                    return null;
                }
                $cur = $cur[(int)$seg];
            } else {
                return null;
            }
        }
        return $cur instanceof Obj || self::isList($cur) ? $cur : null;
    }

    private static function typeIsNull(Obj $m): bool
    {
        $t = $m->get('type');
        if ($t === 'null') {
            return true;
        }
        return self::isList($t) && array_filter($t, static fn(mixed $x): bool => $x !== 'null') === [];
    }

    /** The member as a list of strings when it is one (an enum), else null. @return ?list<string> */
    private static function stringEnum(Obj $m): ?array
    {
        $e = $m->get('enum');
        return Js::isStrList($e) ? $e : null;
    }

    /**
     * Flatten what a parameter declaration cannot carry: follow local `$ref`s, merge `allOf`, collapse `anyOf` / `oneOf` to its single
     * non-null variant (or to the union of string constants). `$c` is the context {root, todo (array by ref), left}.
     */
    private static function flatten(mixed $s, \stdClass $c, string $where, int $depth = 0): Obj
    {
        if (!($s instanceof Obj) && !self::isList($s)) {
            return new Obj();
        }
        $c->left = ($c->left ?? self::MAX_REF_NODES) - 1;
        if ($c->left < 0) {
            if ($c->left === -1) {
                $c->todo[] = "$where: schema expansion stopped after " . self::MAX_REF_NODES . ' nodes (declared string; refine or drop)';
            }
            return new Obj();
        }
        if ($depth > self::MAX_REF_DEPTH) {
            $c->todo[] = "$where: schema nesting or reference chain deeper than " . self::MAX_REF_DEPTH . ' (declared string; refine or drop)';
            return new Obj();
        }
        $cur = self::spreadObj($s);
        $ref = $s instanceof Obj ? $s->get('$ref') : null;
        if (is_string($ref)) {
            $target = self::pointer($c->root, $ref);
            if ($target === null) {
                $c->todo[] = "$where: reference '" . implode('', array_slice(self::units($ref), 0, 120)) . "' is not a local reference that resolves (declared string; refine or drop)";
                return new Obj();
            }
            $merged = self::flatten($target, $c, $where, $depth + 1);
            foreach ($cur->without('$ref')->keys() as $k) {
                $merged->set($k, $cur->get($k));
            }
            $cur = $merged;
        }
        $allOf = $cur->get('allOf');
        if (self::isList($allOf)) {
            $rest = $cur->without('allOf');
            $parts = array_map(fn($m) => self::flatten($m, $c, $where, $depth + 1), $allOf);
            $acc = new Obj();
            foreach ($parts as $m) {
                $next = self::spreadObj($acc);
                foreach ($m->keys() as $k) {
                    $next->set($k, $m->get($k));
                }
                $props = self::spreadObj($acc->get('properties'));
                $mp = self::spreadObj($m->get('properties'));
                foreach ($mp->keys() as $k) {
                    $props->set($k, $mp->get($k));
                }
                $next->set('properties', $props);
                $next->set('required', [...self::iter($acc->get('required')), ...self::iter($m->get('required'))]);
                $acc = $next;
            }
            $cur = self::spreadObj($acc);
            foreach ($rest->keys() as $k) {
                $cur->set($k, $rest->get($k));
            }
        }
        $alts = $cur->get('anyOf') ?? $cur->get('oneOf');
        if (self::isList($alts)) {
            $rest = $cur->without('anyOf', 'oneOf');
            $live = [];
            foreach ($alts as $m) {
                $f = self::flatten($m, $c, $where, $depth + 1);
                if (!self::typeIsNull($f)) {
                    $live[] = $f;
                }
            }
            if (count($live) === 1) {
                $out = self::spreadObj($live[0]);
                foreach ($rest->keys() as $k) {
                    $out->set($k, $rest->get($k));
                }
                return $out;
            }
            $consts = [];
            $allConst = true;
            foreach ($live as $m) {
                if (is_string($m->get('const'))) {
                    $consts[] = [$m->get('const')];
                } else {
                    $e = self::stringEnum($m);
                    $allConst = $allConst && $e !== null;
                    $consts[] = $e ?? [];
                }
            }
            if (count($live) > 1 && $allConst) {
                $out = self::spreadObj($rest);
                $out->set('type', 'string');
                $out->set('enum', array_values(array_unique(array_merge(...$consts))));
                return $out;
            }
            $c->todo[] = "$where: a union of " . count($live) . ' schemas has no schema representation (declared string; refine or drop)';
            return $rest;
        }
        if ($cur->has('const') && !$cur->has('enum') && is_string($cur->get('const'))) {
            $cur->set('enum', [$cur->get('const')]);
        }
        return $cur;
    }

    /** `Array.isArray(t) ? t.find(x => x !== 'null') : t` for the `type` member (undef when absent or no such element). */
    private static function typeOf(Obj $s): mixed
    {
        if (!$s->has('type')) {
            return self::undef();
        }
        $t = $s->get('type');
        if (self::isList($t)) {
            foreach ($t as $x) {
                if ($x !== 'null') {
                    return $x;
                }
            }
            return self::undef();
        }
        return $t;
    }

    /** A JSON Schema property as a parameter declaration; unrepresentable shapes become `string` placeholders flagged in `todo`. */
    private static function declOf(string $name, mixed $schema, bool $required, \stdClass $c): Obj
    {
        $s = self::flatten($schema, $c, "action.params.$name");
        $t = self::typeOf($s);
        $base = new Obj();
        $base->set('semantic', $s->get('x-pca-semantic') ?? 'unknown');
        $base->set('sensitivity', $s->get('x-pca-sensitivity') ?? 'material');
        if (!$required) {
            $base->set('required', false);
        }
        if (Js::truthy($s->get('description'))) {
            $base->set('description', self::slice1024($s->get('description')));
        }
        if (!Js::truthy($s->get('x-pca-semantic'))) {
            $c->todo[] = "action.params.$name: semantic type";
        }
        $enumStrings = self::stringEnum($s);
        $out = new Obj();
        $put = static function (Obj $o, Obj $b): void {
            foreach ($b->keys() as $k) {
                $o->set($k, $b->get($k));
            }
        };
        if ($t === 'integer') {
            $out->set('type', 'integer');
            $put($out, $base);
            if (self::safeInt($s->get('minimum'))) {
                $out->set('min', $s->get('minimum'));
            } elseif (self::safeInt($s->get('exclusiveMinimum'))) {
                $out->set('min', Js::num($s->get('exclusiveMinimum')) + 1);
            }
            if (self::safeInt($s->get('maximum'))) {
                $out->set('max', $s->get('maximum'));
            } elseif (self::safeInt($s->get('exclusiveMaximum'))) {
                $out->set('max', Js::num($s->get('exclusiveMaximum')) - 1);
            }
            if (Js::truthy($s->get('x-pca-unit'))) {
                $out->set('unit', $s->get('x-pca-unit'));
            }
            if (Js::truthy($s->get('x-pca-accumulates-into'))) {
                $out->set('accumulates_into', $s->get('x-pca-accumulates-into'));
            }
            return $out;
        }
        if ($t === 'boolean' || ($t === 'string' && $s->get('format') === 'date')) {
            $out->set('type', $t === 'boolean' ? 'boolean' : 'date');
            $put($out, $base);
            return $out;
        }
        if ($t === 'string') {
            $out->set('type', 'string');
            $put($out, $base);
            if ($enumStrings !== null) {
                $out->set('values', $enumStrings);
            }
            if (self::safeInt($s->get('maxLength')) && Js::num($s->get('maxLength')) > 0) {
                $out->set('max_len', $s->get('maxLength'));
            }
            return $out;
        }
        if ($t === 'array') {
            $it = self::flatten($s->get('items'), $c, "action.params.$name" . '[]');
            $itEnum = self::stringEnum($it);
            if (Js::truthy($s->get('uniqueItems')) && $itEnum !== null) {
                $out->set('type', 'set');
                $put($out, $base);
                $out->set('values', $itEnum);
                if (self::safeInt($s->get('minItems'))) {
                    $out->set('min_items', $s->get('minItems'));
                }
                if (self::safeInt($s->get('maxItems'))) {
                    $out->set('max_items', $s->get('maxItems'));
                }
                return $out;
            }
            $itType = $it->get('type');
            $itT = self::isList($itType) ? ($itType[0] ?? null) : $itType;
            $out->set('type', 'array');
            $put($out, $base);
            if ($itT === 'integer') {
                $out->set('items', 'integer');
            }
            if (self::safeInt($s->get('maxItems'))) {
                $out->set('max_items', $s->get('maxItems'));
            }
            if (self::safeInt($s->get('minItems'))) {
                $out->set('min_items', $s->get('minItems'));
            }
            return $out;
        }
        $c->todo[] = "action.params.$name: type '" . ($t === self::undef() ? 'undefined' : Js::str($t)) . "' has no schema representation (declared string; refine or drop)";
        $out->set('type', 'string');
        $put($out, $base);
        return $out;
    }

    /**
     * Draft a v1 action schema from an MCP tool list (a list of tool Obj, or an object with `tools`). Verb = verbPrefix + tool name;
     * every write verb is drafted irreversible (the fail-closed default). `$site`: site, aud, version, verbPrefix.
     * @return Obj {schema, todo}: the decisions the developer must still make are in `todo`
     */
    public static function draftActionSchemaFromMcp(mixed $tools, mixed $site): Obj
    {
        if (!self::isList($tools)) {
            $tools = Js::get($tools instanceof \Closure ? $tools() : $tools, 'tools');
            if (!self::isList($tools)) {
                throw new \TypeError('tools is not iterable');
            }
        }
        $todo = new \stdClass();
        $todo->todo = [];
        $verbs = [];
        foreach ($tools as $t) {
            self::nn($t, 'inputSchema');
            $c = new \stdClass();
            $c->root = Js::opt($t, 'inputSchema');
            $c->todo = &$todo->todo;
            $c->left = null;
            $tname = Js::has($t, 'name') ? Js::str(Js::opt($t, 'name')) : 'undefined';
            $input = self::flatten(Js::opt($t, 'inputSchema'), $c, "$tname: inputSchema");
            $props = $input->get('properties') ?? new Obj();
            $req = self::iter($input->get('required'));
            $params = new Obj();
            $names = self::keysOf($props);
            usort($names, 'strcmp');
            foreach ($names as $name) {
                if (preg_match('/\A[A-Za-z0-9_]{1,64}\z/', $name) !== 1) {
                    $todo->todo[] = "$tname: parameter '$name' is not a schema name ([A-Za-z0-9_]{1,64}); rename it";
                    continue;
                }
                $params->set("action.params.$name", self::declOf($name, self::valueOf($props, $name), in_array($name, $req, true), $c));
            }
            $ann = Js::opt($t, 'annotations');
            $read = Js::opt($ann, 'readOnlyHint') === true;
            $verb = Js::str(Js::opt($site, 'verbPrefix') ?? '') . $tname;
            if (!$read) {
                $todo->todo[] = "$verb: reversibility (drafted irreversible)";
            }
            $v = new Obj();
            $v->set('verb', $verb);
            $v->set('kind', $read ? 'read' : 'write');
            $v->set('params', $params);
            $v->set('reversibility', $read ? 'reversible' : 'irreversible');
            $mcp = new Obj();
            if (Js::has($t, 'name')) {
                $mcp->set('tool', Js::opt($t, 'name'));
            }
            $v->set('mcp', $mcp);
            if (Js::truthy(Js::opt($t, 'description'))) {
                $v->set('description', self::slice1024(Js::opt($t, 'description')));
            }
            $verbs[] = $v;
            unset($c);
        }
        usort($verbs, static fn(Obj $a, Obj $b): int => strcmp((string)$a->get('verb'), (string)$b->get('verb')));
        self::nn($site, 'site');
        $schema = new Obj();
        $schema->set('v', 1);
        $schema->set('kind', IntentV2::ACTION_SCHEMA_KIND);
        foreach (['site', 'aud', 'version'] as $k) {
            if (Js::has($site, $k)) {
                $schema->set($k, Js::opt($site, $k));
            }
        }
        $schema->set('verbs', $verbs);
        return Obj::of(['schema' => $schema, 'todo' => $todo->todo]);
    }

    /** A deep copy of a parsed value (the reference's JSON round trip). */
    private static function copy(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::copy($v->get($k)));
            }
            return $o;
        }
        return self::isList($v) ? array_map(self::copy(...), $v) : $v;
    }

    /**
     * Apply the developer's decisions to a draft: reversibility and parameter fields per verb, and unit declarations. A verb or
     * parameter the draft does not have throws. `$d`: {verbs: {verb: {reversibility?, params?: {path: fields}}}, units?}.
     */
    public static function applySchemaDecisions(mixed $draft, mixed $d): mixed
    {
        $out = self::copy($draft);
        self::nn($d, 'units');
        if (Js::truthy(Js::opt($d, 'units'))) {
            $merged = self::spreadObj(Js::opt($out, 'units') ?? new Obj());
            $du = self::spreadObj(Js::opt($d, 'units'));
            foreach ($du->keys() as $k) {
                $merged->set($k, $du->get($k));
            }
            if (!($out instanceof Obj)) {
                throw new \TypeError('draft is not an object');
            }
            $out->set('units', $merged);
        }
        $dverbs = Js::opt($d, 'verbs');
        if ($dverbs === null) {
            throw new \TypeError('Cannot convert undefined or null to object');
        }
        foreach (self::keysOf($dverbs) as $verb) {
            $dv = self::valueOf($dverbs, $verb);
            $verbsList = Js::opt($out, 'verbs');
            if (!self::isList($verbsList)) {
                throw new \TypeError('out.verbs.find is not a function');
            }
            $v = null;
            foreach ($verbsList as $x) {
                self::nn($x, 'verb');
                if ($x instanceof Obj && $x->get('verb') === $verb) {
                    $v = $x;
                    break;
                }
            }
            if ($v === null) {
                throw new \InvalidArgumentException("applySchemaDecisions: the draft has no verb '$verb'");
            }
            self::nn($dv, 'reversibility');
            if (Js::truthy(Js::opt($dv, 'reversibility'))) {
                $v->set('reversibility', Js::opt($dv, 'reversibility'));
            }
            $dp = Js::opt($dv, 'params') ?? new Obj();
            foreach (self::keysOf($dp) as $path) {
                $params = $v->get('params');
                $p = $params instanceof Obj ? $params->get($path) : null;
                if (!Js::truthy($p)) {
                    throw new \InvalidArgumentException("applySchemaDecisions: verb '$verb' has no parameter '$path'");
                }
                if ($p instanceof Obj) {
                    $add = self::spreadObj(self::valueOf($dp, $path));
                    foreach ($add->keys() as $k) {
                        $p->set($k, $add->get($k));
                    }
                }
            }
        }
        return $out;
    }

    /** The `verb` of the schema entry that declares the MCP tool, or null (undefined) when none does. */
    public static function verbOfTool(mixed $schema, mixed $toolName): mixed
    {
        $e = self::entryOfTool($schema, $toolName);
        return $e === null || !$e->has('verb') ? null : $e->get('verb');
    }

    private static function entryOfTool(mixed $schema, mixed $toolName): mixed
    {
        self::nn($schema, 'verbs');
        $verbs = Js::opt($schema, 'verbs');
        if (!self::isList($verbs)) {
            throw new \TypeError('schema.verbs.find is not a function');
        }
        foreach ($verbs as $v) {
            self::nn($v, 'mcp');
            $mcp = Js::opt($v, 'mcp');
            $tool = Js::opt($mcp, 'tool');
            if ($tool !== null && !is_array($tool) && !is_object($tool) && $tool === $toolName) {
                return $v instanceof Obj ? $v : null;
            }
        }
        return null;
    }

    /**
     * Closed-world check of an MCP tool call against the site schema: the tool must be declared by a verb, then the arguments must
     * conform to it. @return array{ok:bool,code?:string,path?:string,reason?:string,verb?:Obj}
     */
    public static function conformToolCall(mixed $schema, mixed $toolName, mixed $args): array
    {
        $e = self::entryOfTool($schema, $toolName);
        if ($e === null || !$e->has('verb')) {
            return ['ok' => false, 'code' => 'unknown_verb', 'reason' => "MCP tool '" . Js::str($toolName) . "' is not declared by the site schema"];
        }
        return IntentV2::conformAction($schema, $e->get('verb'), $args);
    }

    /**
     * Import an MCP tool list (an array of tools, a `tools/list` result Obj `{tools}`, or an object with a `listTools()` returning one) as action kit defs:
     * typed params with roles, nested bodies flattened, annotations kept as untrusted hints, every def `unreviewed` until a pinned reviewer signs it.
     * `$opts`: `ns` (required), `uri`, `licence`, `now`, `suggest` (`"rules"` default: the rule-based trait suggestions of {@see ActionsImportSuggest}, state
     * `suggested`; `"none"`: the drafts as imported). Returns {defs, todo, source}.
     */
    public static function importActionDefsFromMcp(mixed $source, mixed $opts): Obj
    {
        $tools = is_object($source) && !($source instanceof Obj) && method_exists($source, 'listTools') ? $source->listTools() : $source;
        $tools = $tools instanceof Obj ? $tools->get('tools') : $tools;
        $suggest = $opts instanceof Obj ? ($opts->get('suggest') ?? 'rules') : 'rules';
        $rest = $opts instanceof Obj ? $opts->without('suggest') : $opts;
        $r = ActionsImport::importMcp(Obj::of(['tools' => $tools]), $rest);
        $s = ActionsImport::suggestDefs($r->get('defs'), ['mode' => $suggest]);
        return Obj::of(['defs' => $s->get('defs'), 'todo' => $r->get('todo'), 'source' => $r->get('source')]);
    }
}
