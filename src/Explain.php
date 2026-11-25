<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Self-explaining PCA decisions: the verifier's per-check result, the Policy VM decision and a delegation chain become precise,
 * human-readable explanations plus renderers (the reference's pca-explain). Pure and read-only; a malformed input degrades to a
 * best-effort explanation. Explanations are {@see Obj} values with the reference's members (an absent member is a JS `undefined`).
 * Inputs are parsed-JSON values; JavaScript value semantics are reproduced where an untrusted field reaches them ({@see Jsx}).
 * `now` and the decision context use the reference's camelCase keys. An omitted `opts` is `{}`; an explicit null stays null.
 */
final class Explain
{
    public const MAX_TEXT = 400;
    public const VERIFY_CHECK_ORDER = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'];

    private const TITLE = [
        'wire' => 'wire format', 'version' => 'version', 'audience' => 'audience binding', 'validity' => 'freshness window',
        'cap_chain' => 'capability chain', 'grant_ref_bound' => 'grant reference binding', 'plan_inclusion' => 'plan inclusion',
        'leaf_signature' => 'leaf signature', 'counter_format' => 'counter format', 'counter' => 'counter format', 'replay' => 'replay',
        'plan_root_authorized' => 'plan-root authorization', 'taint_gate' => 'taint gate', 'attestation' => 'agent attestation',
        'threshold' => 'threshold signature', 'revocation' => 'revocation', 'zk_compliance' => 'zk compliance', 'bond' => 'bond',
        'malformed' => 'structure',
    ];

    // JS \s / String.trim() whitespace, as the body of a character class
    private const WS = "\\t\\n\\x{0B}\\x{0C}\\r \\x{A0}\\x{1680}\\x{2000}-\\x{200A}\\x{2028}\\x{2029}\\x{202F}\\x{205F}\\x{3000}\\x{FEFF}";
    private const W = 'A-Za-z0-9_';

    // ---- JavaScript value helpers -----------------------------------------------------------------------------------------

    private static function isUndef(mixed $v): bool
    {
        return $v instanceof Undef;
    }

    private static function nn(mixed $a, mixed $b): mixed
    {
        return $a === null || $a instanceof Undef ? $b : $a;
    }

    private static function get(mixed $o, string $k): mixed
    {
        return Jsx::get($o, $k);
    }

    private static function opt(mixed $o, string $k): mixed
    {
        return $o === null || $o instanceof Undef ? Jsx::$U : Jsx::get($o, $k);
    }

    private static function rd(mixed $o, string $k): mixed
    {
        return Jsx::rd($o, $k);
    }

    private static function truthy(mixed $v): bool
    {
        return Jsx::truthy($v);
    }

    private static function js(mixed $v): string
    {
        return Jsx::str($v);
    }

    private static function isObj(mixed $v): bool
    {
        return $v instanceof Obj || (is_array($v) && array_is_list($v));
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function put(Obj $o, string $k, mixed $v): void
    {
        if (!($v instanceof Undef)) {
            $o->set($k, $v);
        }
    }

    private static function fin(mixed $v): ?float
    {
        $f = Js::isNum($v) ? Js::num($v) : null;
        return $f !== null && is_finite($f) ? $f : null;
    }

    private static function numStr(float $f): string
    {
        return IntentWb::jsNumStr($f);
    }

    private static function len16(string $s): int
    {
        return Js::len($s);
    }

    /** The UTF-16 code units of a (WTF-8) string; a lone surrogate stays a single unit. @return list<int> */
    private static function units(string $s): array
    {
        $u = [];
        $n = strlen($s);
        for ($i = 0; $i < $n;) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $u[] = $b;
                $i++;
            } elseif ($b < 0xE0) {
                $u[] = (($b & 0x1F) << 6) | (ord($s[$i + 1] ?? "\0") & 0x3F);
                $i += 2;
            } elseif ($b < 0xF0) {
                $u[] = (($b & 0x0F) << 12) | ((ord($s[$i + 1] ?? "\0") & 0x3F) << 6) | (ord($s[$i + 2] ?? "\0") & 0x3F);
                $i += 3;
            } else {
                $cp = ((($b & 7) << 18) | ((ord($s[$i + 1] ?? "\0") & 0x3F) << 12) | ((ord($s[$i + 2] ?? "\0") & 0x3F) << 6) | (ord($s[$i + 3] ?? "\0") & 0x3F)) - 0x10000;
                $u[] = 0xD800 + ($cp >> 10);
                $u[] = 0xDC00 + ($cp & 0x3FF);
                $i += 4;
            }
        }
        return $u;
    }

    /** @param list<int> $u */
    private static function fromUnits(array $u): string
    {
        $out = '';
        $n = count($u);
        for ($i = 0; $i < $n; $i++) {
            $x = $u[$i];
            if ($x >= 0xD800 && $x <= 0xDBFF && $i + 1 < $n && $u[$i + 1] >= 0xDC00 && $u[$i + 1] <= 0xDFFF) {
                $cp = 0x10000 + (($x - 0xD800) << 10) + ($u[$i + 1] - 0xDC00);
                $out .= chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
                $i++;
            } elseif ($x < 0x80) {
                $out .= chr($x);
            } elseif ($x < 0x800) {
                $out .= chr(0xC0 | ($x >> 6)) . chr(0x80 | ($x & 0x3F));
            } else {
                $out .= self::wtf8($x);
            }
        }
        return $out;
    }

    /** s.slice(a, b) by UTF-16 units; a cut inside a surrogate pair leaves the lone half (WTF-8). */
    public static function slice16(string $s, int $a, ?int $b = null): string
    {
        return self::fromUnits(array_slice(self::units($s), $a, $b === null ? null : max(0, $b - $a)));
    }

    private static function wtf8(int $cp): string
    {
        return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    private static function trim(string $s): string
    {
        return preg_replace('/\A[' . self::WS . ']+|[' . self::WS . ']+\z/u', '', $s) ?? $s;
    }

    private static function toNum(mixed $v): float
    {
        return Jsx::toNum($v);
    }

    private static function prim(mixed $v): mixed
    {
        return is_array($v) ? Js::str($v) : ($v instanceof Obj ? '[object Object]' : $v);
    }

    private static function le(mixed $a, mixed $b): bool
    {
        $a = self::prim($a);
        $b = self::prim($b);
        if (is_string($a) && is_string($b)) {
            return !Jsx::lt($b, $a);
        }
        return self::toNum($a) <= self::toNum($b);
    }

    /** JS `a + n` for a number n. */
    private static function add(mixed $a, int $n): mixed
    {
        $a = self::prim($a);
        return is_string($a) ? $a . $n : self::toNum($a) + $n;
    }

    /** `${JSON.stringify(v)}`: undefined stringifies to the text "undefined". */
    private static function jstr(mixed $v): string
    {
        return $v instanceof Undef ? 'undefined' : Js::stringify($v);
    }

    private static function sliceFrom(mixed $v, int $n): mixed
    {
        if (self::isList($v)) {
            return array_slice($v, $n);
        }
        if (is_string($v)) {
            return self::slice16($v, $n);
        }
        throw new \TypeError('slice is not a function');
    }

    private static function length(mixed $v): mixed
    {
        return self::isList($v) ? count($v) : (is_string($v) ? self::len16($v) : Jsx::$U);
    }

    private static function padEnd(string $s, int $n): string
    {
        return $s . str_repeat(' ', max(0, $n - self::len16($s)));
    }

    // ---- cleanText --------------------------------------------------------------------------------------------------------

    /** A case-insensitive (ASCII only, like the reference's /i without the u flag) pattern for a literal word. */
    private static function ci(string $w): string
    {
        $o = '';
        foreach (str_split($w) as $ch) {
            $o .= ctype_alpha($ch) ? '[' . strtolower($ch) . strtoupper($ch) . ']' : preg_quote($ch, '#');
        }
        return $o;
    }

    /** Remove what looks like a credential from text built out of untrusted fields; the result is cut to 400 characters. */
    public static function cleanText(mixed $text): string
    {
        $t = Jsx::str($text);
        // a lone surrogate (WTF-8) is not valid UTF-8 for the regex engine: park each one on a private-use plane-15 code point and restore it after
        $t = preg_replace_callback('/\xED([\xA0-\xBF])([\x80-\xBF])/', static function (array $m): string {
            $cp = 0xD000 + (((ord($m[1]) & 0x1F) << 6) | (ord($m[2]) & 0x3F)) + 0x800;
            $x = $cp - 0xD800;
            return mb_chr(0xF0000 + $x, 'UTF-8');
        }, $t) ?? $t;
        $W = self::W;
        $S = self::WS;
        $nb = "(?<![$W])";
        $ci = static fn(string $w): string => self::ci($w);
        $t = preg_replace("#{$nb}eyJ[$W-]{5,}\\.[$W-]{5,}\\.[$W-]*#u", '[redacted]', $t) ?? $t;
        $t = preg_replace_callback(
            "#{$nb}({$ci('Bearer')}|{$ci('Basic')}|{$ci('Token')})[$S]+[$W.~+/=-]{6,}#u",
            static fn(array $m): string => $m[1] . ' [redacted]',
            $t
        ) ?? $t;
        $t = preg_replace_callback(
            "#([A-Za-z][A-Za-z0-9+.-]*://)[^$S/@]*:[^$S/@]*@#u",
            static fn(array $m): string => $m[1] . '[redacted]@',
            $t
        ) ?? $t;
        $names = implode('|', array_map($ci, ['token', 'secret', 'password', 'passwd', 'pwd']))
            . '|' . $ci('api') . '[_-]?' . $ci('key') . '|' . implode('|', array_map($ci, ['key', 'signature', 'sig', 'credential', 'authorization', 'auth']));
        $t = preg_replace_callback(
            "#{$nb}((?:$names)[\"']?[$S]*[:=][$S]*)(\"[^\"]*\"|'[^']*'|[^$S\"'&,;]+)#u",
            static fn(array $m): string => $m[1] . '[redacted]',
            $t
        ) ?? $t;
        $t = preg_replace("#[$W-]{40,}#u", '[redacted]', $t) ?? $t;
        $t = self::len16($t) > self::MAX_TEXT ? self::slice16($t, 0, self::MAX_TEXT) . '...' : $t;
        return preg_replace_callback('/\xF3\xB0[\x80-\x9F][\x80-\xBF]/', static function (array $m): string {
            $cp = mb_ord($m[0], 'UTF-8') - 0xF0000 + 0xD800;
            return self::wtf8($cp);
        }, $t) ?? $t;
    }

    // ---- shared helpers ---------------------------------------------------------------------------------------------------

    /** Abbreviate a long key for display. */
    private static function short(mixed $key, int $n = 10): string
    {
        if (!is_string($key) || $key === '') {
            return '<none>';
        }
        return self::len16($key) <= $n + 1 ? $key : self::slice16($key, 0, $n) . '…';
    }

    private static function roundJs(float $y): float
    {
        $f = floor($y);
        return $y - $f >= 0.5 ? $f + 1 : $f;
    }

    /** Compact number: integers stay integers, fractions round to 4 dp; anything else prints as String(x). */
    private static function num(mixed $x): string
    {
        $f = self::fin($x);
        if ($f === null) {
            return self::js($x);
        }
        if ($f == floor($f)) {
            return self::numStr($f);
        }
        return self::numStr(self::roundJs($f * 1e4) / 1e4);
    }

    private static function valueSummary(Obj $rest): string
    {
        $parts = [];
        foreach (array_slice(Jsx::keys($rest), 0, 6) as $k) {
            $v = $rest->get($k);
            $parts[] = $k . '=' . (self::isObj($v) ? Js::stringify($v) : self::num($v));
        }
        return implode(', ', $parts);
    }

    private static function caveatType(mixed $cv): string
    {
        $t = self::opt($cv, 'type');
        return is_string($t) ? $t : '<malformed>';
    }

    private static function caveatRest(mixed $cv): Obj
    {
        $rest = new Obj();
        if (self::isObj($cv)) {
            foreach (Jsx::keys($cv) as $k) {
                if ($k !== 'type') {
                    $rest->set($k, self::get($cv, $k));
                }
            }
        }
        return $rest;
    }

    private static function condToText(mixed $c, int $depth = 0): string
    {
        if (!self::isObj($c)) {
            return '<malformed>';
        }
        if ($depth > 6) {
            return '…';
        }
        if ($c instanceof Obj) {
            if ($c->has('all_of') && self::isList($c->get('all_of'))) {
                return '(' . implode(' AND ', array_map(fn($x) => self::condToText($x, $depth + 1), $c->get('all_of'))) . ')';
            }
            if ($c->has('any_of') && self::isList($c->get('any_of'))) {
                return '(' . implode(' OR ', array_map(fn($x) => self::condToText($x, $depth + 1), $c->get('any_of'))) . ')';
            }
            if ($c->has('not')) {
                return 'NOT ' . self::condToText($c->get('not'), $depth + 1);
            }
        }
        $ref = self::get($c, 'ref');
        $operand = !self::isUndef($ref) ? '→' . self::js($ref) : ($c instanceof Obj && $c->has('value') ? self::num($c->get('value')) : '');
        return self::trim(self::js(self::get($c, 'field')) . ' ' . self::js(self::get($c, 'op')) . ' ' . $operand);
    }

    private static function whereSummary(mixed $where): string
    {
        if (!self::isList($where) || count($where) === 0) {
            return 'any (no where-bound)';
        }
        return implode(' AND ', array_map(fn($c) => self::condToText($c), $where));
    }

    // ---- explainVerification ----------------------------------------------------------------------------------------------

    private static function reasonTail(string $name, mixed $vr): ?string
    {
        $r = self::get($vr, 'reason');
        if (!is_string($r)) {
            return null;
        }
        $pre = $name . ': ';
        return str_starts_with($r, $pre) ? substr($r, strlen($pre)) : null;
    }

    /** @return array{detail:string,remedy:string} */
    private static function validityPinpoint(mixed $p, mixed $now): array
    {
        $exp = self::get($p, 'exp');
        $iat = self::get($p, 'iat');
        $lifetime = self::toNum($exp) - self::toNum($iat);
        if (!Jsx::gt($exp, $iat)) {
            return ['detail' => sprintf('exp %s ≤ iat %s: empty validity window', self::js($exp), self::js($iat)),
                'remedy' => 'set exp strictly greater than iat.'];
        }
        if ($lifetime > Pca::MAX_LIFETIME_MS) {
            return ['detail' => sprintf('lifetime %sms exceeds the %dms maximum', self::numStr($lifetime), Pca::MAX_LIFETIME_MS),
                'remedy' => sprintf('shorten the window to ≤ %dms (buildPCActn ttlMs).', Pca::MAX_LIFETIME_MS)];
        }
        if (!self::isUndef($now)) {
            if (!(self::toNum($iat) <= self::toNum($now) + Pca::MAX_SKEW_MS)) {
                return ['detail' => sprintf('iat %s is %sms in the future (> %dms clock-skew allowance)', self::js($iat), self::numStr(self::toNum($iat) - self::toNum($now)), Pca::MAX_SKEW_MS),
                    'remedy' => 'fix the signer clock; do not pre-date actions.'];
            }
            if (!(self::toNum($now) <= self::toNum($exp))) {
                return ['detail' => sprintf('expired %sms ago (exp %s, now %s)', self::numStr(self::toNum($now) - self::toNum($exp)), self::js($exp), self::js($now)),
                    'remedy' => 'build a fresh action — a PCActn lifetime is short by design.'];
            }
        }
        return ['detail' => 'validity window invalid', 'remedy' => 'build a fresh action with a valid iat/exp window.'];
    }

    /** The core's chain refusal text with the reference's wording for the hop cap. */
    private static function chainReason(string $why): string
    {
        return $why === 'chain too long' ? 'chain too long (max 16 hops)' : $why;
    }

    /** @return array{detail:string,remedy:string,hop?:int} */
    private static function capChainPinpoint(mixed $p): array
    {
        $chain = self::get($p, 'cap_chain');
        if (self::isList($chain)) {
            [$why, $ok] = Pca::verifyChain($chain, null, false);
            $reason = $ok ? 'chain root is not the grant this verifier expects' : self::chainReason($why);
        } else {
            $reason = 'cap_chain is not an array';
        }
        $remedy = 'rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats.';
        if (str_contains($reason, 'root issuer') || str_contains($reason, 'not the grant')) {
            $remedy = 'root the chain at the principal key that minted the grant.';
        } elseif (str_contains($reason, 'widens')) {
            $remedy = 'a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation.';
        } elseif (str_contains($reason, 'caveat')) {
            $remedy = 'attenuation is append-only: never drop, reorder or edit a parent caveat.';
        } elseif (str_contains($reason, 'signature')) {
            $remedy = 're-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite).';
        }
        $out = ['detail' => $reason, 'remedy' => $remedy];
        if (preg_match('/hop ([0-9]+)/', $reason, $m) === 1) {
            $out['hop'] = (int)$m[1];
        }
        return $out;
    }

    /** @return array{detail:string,remedy:string,hop?:int} */
    private static function leafSigPinpoint(mixed $p): array
    {
        $chain = self::get($p, 'cap_chain');
        $idx = self::isList($chain) ? count($chain) - 1 : -1;
        $leaf = $idx >= 0 ? $chain[$idx] : Jsx::$U;
        $alg = self::nn(self::get($p, 'alg'), 'ed25519');
        $remedy = 'sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder.';
        if (!self::truthy($leaf)) {
            return ['detail' => 'no leaf capability to check the signature against (empty/invalid chain)', 'remedy' => $remedy];
        }
        $out = ['detail' => sprintf('leaf hop #%d signature (holder %s, suite %s) does not verify', $idx, self::short(self::get($leaf, 'holder')), self::js($alg)), 'remedy' => $remedy];
        if ($idx >= 0) {
            $out['hop'] = $idx;
        }
        return $out;
    }

    private static function nnStr(?string $tail, string $default): string
    {
        return $tail ?? $default;
    }

    /** @return array{detail:string,remedy:string,hop?:int} */
    private static function pinpoint(string $name, mixed $p, mixed $vr, mixed $now): array
    {
        $tail = self::reasonTail($name, $vr);
        $action = self::opt($p, 'action');
        $plan = self::opt($p, 'plan');
        switch ($name) {
            case 'wire':
                return ['detail' => self::nnStr($tail, 'wire structure / strict-canonical-form check failed'),
                    'remedy' => 'do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.'];
            case 'version':
                return ['detail' => self::nnStr($tail, sprintf('unsupported ver %s (verifier requires %d)', self::num(self::get($p, 'ver')), 2)),
                    'remedy' => sprintf('re-mint the action at wire version %d.', 2)];
            case 'audience':
                return ['detail' => self::nnStr($tail, sprintf('aud %s does not match this resource server / instance', self::jstr(self::get($p, 'aud')))),
                    'remedy' => 'build the action with aud = this verifier’s instance id (or verify with audience:null to accept any).'];
            case 'validity':
                $v = self::validityPinpoint($p, $now);
                return ['detail' => self::nnStr($tail, $v['detail']), 'remedy' => $v['remedy']];
            case 'cap_chain':
                $c = self::capChainPinpoint($p);
                $out = ['detail' => self::nnStr($tail, $c['detail']), 'remedy' => $c['remedy']];
                if (isset($c['hop'])) {
                    $out['hop'] = $c['hop'];
                }
                return $out;
            case 'grant_ref_bound':
                return ['detail' => self::nnStr($tail, sprintf('grant_ref %s is not the id of the root capability in cap_chain', self::short(self::get($p, 'grant_ref')))),
                    'remedy' => 'set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant.'];
            case 'plan_inclusion':
                return ['detail' => self::nnStr($tail, sprintf('action (verb %s on %s) is not node %s of committed plan %s', self::jstr(self::opt($action, 'verb')), self::jstr(self::opt($action, 'resource')), self::jstr(self::opt($plan, 'node_id')), self::short(self::opt($plan, 'root')))),
                    'remedy' => 'rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).'];
            case 'leaf_signature':
                $l = self::leafSigPinpoint($p);
                $out = ['detail' => self::nnStr($tail, $l['detail']), 'remedy' => $l['remedy']];
                if (isset($l['hop'])) {
                    $out['hop'] = $l['hop'];
                }
                return $out;
            case 'counter':
            case 'counter_format':
                return ['detail' => self::nnStr($tail, sprintf('counter %s is missing or not a non-negative safe integer', self::num(self::get($p, 'counter')))),
                    'remedy' => 'use a strictly increasing per-holder counter; a repeated counter is a replay.'];
            case 'malformed':
                return ['detail' => self::nnStr($tail, 'the PCActn is structurally malformed'),
                    'remedy' => 'rebuild the action with the SDK; do not construct the wire object by hand.'];
        }
        return ['detail' => self::nnStr($tail, $name . ' check failed'),
            'remedy' => sprintf('satisfy the %s requirement (supply the corresponding verifier hook / proof).', $name)];
    }

    private static function passDetail(string $name, mixed $p): string
    {
        switch ($name) {
            case 'wire':
                return 'wire structure + strict canonical form valid';
            case 'version':
                return sprintf('ver %s supported', self::num(self::get($p, 'ver')));
            case 'audience':
                return sprintf('aud %s matches this resource server', self::jstr(self::get($p, 'aud')));
            case 'validity':
                return sprintf('fresh: iat/exp window valid (lifetime %ss)', self::num((self::toNum(self::get($p, 'exp')) - self::toNum(self::get($p, 'iat'))) / 1000));
            case 'cap_chain':
                $chain = self::get($p, 'cap_chain');
                $n = self::isList($chain) ? count($chain) : 0;
                $root = $n > 0 ? $chain[0] : Jsx::$U;
                return sprintf('%d-hop chain verifies; root issuer %s', $n, self::short(self::opt($root, 'issuer')));
            case 'grant_ref_bound':
                return sprintf('grant_ref %s is the id of the chain root', self::short(self::get($p, 'grant_ref')));
            case 'plan_inclusion':
                $plan = self::opt($p, 'plan');
                return sprintf('action is node %s of committed plan %s', self::jstr(self::opt($plan, 'node_id')), self::short(self::opt($plan, 'root')));
            case 'leaf_signature':
                $chain = self::get($p, 'cap_chain');
                $leaf = self::isList($chain) && $chain !== [] ? $chain[count($chain) - 1] : Jsx::$U;
                return sprintf('leaf holder %s signature valid (suite %s)', self::short(self::opt($leaf, 'holder')), self::js(self::nn(self::get($p, 'alg'), 'ed25519')));
            case 'counter':
            case 'counter_format':
                return sprintf('counter %s well-formed', self::num(self::get($p, 'counter')));
        }
        return 'ok';
    }

    private static function cleanCheck(Obj $c): Obj
    {
        $o = new Obj();
        foreach ($c->keys() as $k) {
            $o->set($k, $k === 'detail' ? self::cleanText($c->get('detail')) : $c->get($k));
        }
        return $o;
    }

    /** @param list<Obj> $checks */
    private static function verification(string $verdict, bool $allow, array $checks, ?Obj $decisive, string $summary): Obj
    {
        $names = static fn(string $st): array => array_values(array_map(static fn(Obj $c) => $c->get('name'), array_filter($checks, static fn(Obj $c) => $c->get('status') === $st)));
        $o = Obj::of(['kind' => 'verification', 'verdict' => $verdict, 'allow' => $allow, 'checks' => $checks,
            'passed' => $names('pass'), 'failed' => $names('fail'), 'notEnforced' => $names('not-enforced')]);
        if ($decisive !== null) {
            $o->set('decisive', $decisive);
        }
        $o->set('summary', $summary);
        return $o;
    }

    private static function deniedVerification(string $why): Obj
    {
        $e = Obj::of(['name' => 'malformed', 'status' => 'fail', 'title' => self::TITLE['malformed'], 'detail' => $why,
            'remedy' => 'pass the PCActn and the verifier result you verified.', 'decisive' => true]);
        return self::verification('deny', false, [$e], $e, 'Denied: ' . $why);
    }

    /**
     * Walk the normative checks of an offline verification in order: summarize what held for each pass and pinpoint the first
     * failing check with a concrete remedy. Arguments: (pcaActn, verifyResult, opts?); opts may carry `now`.
     */
    public static function explainVerification(mixed ...$a): Obj
    {
        $p = $a[0] ?? Jsx::$U;
        $vr = $a[1] ?? Jsx::$U;
        $opts = array_key_exists(2, $a) ? $a[2] : new Obj();
        if (!self::isObj($p) || !self::isObj($vr)) {
            return self::deniedVerification('the PCActn or the verifier result is missing');
        }
        try {
            return self::explainVerificationInner($p, $vr, $opts);
        } catch (\Throwable) {
            return self::deniedVerification('the PCActn or the verifier result is malformed');
        }
    }

    private static function explainVerificationInner(mixed $p, mixed $vr, mixed $opts): Obj
    {
        $statuses = self::nn(self::get($vr, 'checks'), new Obj());
        $ordered = self::VERIFY_CHECK_ORDER;
        foreach (Jsx::keys($statuses) as $n) { // later-milestone / extra checks appended
            if (!in_array($n, $ordered, true)) {
                $ordered[] = $n;
            }
        }
        $decisiveName = null;
        foreach ($ordered as $n) {
            if (self::get($statuses, $n) === 'fail') {
                $decisiveName = $n;
                break;
            }
        }
        $checks = [];
        $decisive = null;
        foreach ($ordered as $name) {
            $status = self::nn(self::get($statuses, $name), 'skipped');
            $title = self::TITLE[$name] ?? $name;
            $remedy = null;
            $hop = null;
            if ($status === 'fail') {
                $pin = self::pinpoint($name, $p, $vr, self::rd($opts, 'now'));
                $detail = $pin['detail'];
                $remedy = $pin['remedy'];
                $hop = $pin['hop'] ?? null;
            } elseif ($status === 'pass') {
                $detail = self::passDetail($name, $p);
            } elseif ($status === 'not-enforced') {
                $detail = 'not enforced by this verifier (no hook / opt-out)';
            } elseif ($status === 'unsupported') {
                $detail = 'the PCActn carries a feature this verifier does not implement (never a pass)';
            } else {
                $detail = 'not reached (a terminal earlier check stopped evaluation)';
            }
            $entry = Obj::of(['name' => $name, 'status' => $status, 'title' => $title, 'detail' => $detail]);
            if ($remedy !== null) {
                $entry->set('remedy', $remedy);
            }
            if ($hop !== null) {
                $entry->set('hop', $hop);
            }
            if ($name === $decisiveName) {
                $entry->set('decisive', true);
                $decisive = $entry;
            }
            $checks[] = $entry;
        }
        // Allow only on an explicit `allow: true` that no check contradicts and that carries per-check statuses.
        $hasChecks = self::get($vr, 'checks') instanceof Obj;
        $allowClaimed = self::get($vr, 'allow') === true;
        $claimed = $allowClaimed && $hasChecks;
        $contradicted = $claimed && $decisiveName !== null;
        $verdict = $claimed && !$contradicted ? 'allow' : 'deny';
        if ($verdict === 'allow') {
            $summary = sprintf('All %d evaluated checks passed (no check failed).', count(array_filter($checks, static fn(Obj $c) => $c->get('status') === 'pass')));
        } elseif ($allowClaimed && !$hasChecks) {
            $summary = 'Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial).';
        } elseif ($contradicted) {
            $summary = sprintf('Denied: the verifier result says allow but the "%s" check failed (inconsistent result, treated as a denial).', $decisive !== null ? self::js($decisive->get('title')) : $decisiveName);
        } elseif ($decisive !== null) {
            $summary = sprintf('Denied at the "%s" check: %s', self::js($decisive->get('title')), self::js($decisive->get('detail')));
        } else {
            $reason = self::get($vr, 'reason');
            $summary = 'Denied: ' . (is_string($reason) ? $reason : 'a check failed');
        }
        return self::verification($verdict, $verdict === 'allow', array_map(self::cleanCheck(...), $checks), $decisive !== null ? self::cleanCheck($decisive) : null, self::cleanText($summary));
    }

    private const GLYPH = ['pass' => '✓', 'fail' => '✗', 'not-enforced' => '·', 'unsupported' => '?', 'skipped' => '–'];

    /** Render a verification explanation. */
    public static function verificationToText(Obj $e): string
    {
        $lines = ['PCA verification — ' . mb_strtoupper(self::js($e->get('verdict'))), self::js($e->get('summary')), ''];
        foreach ($e->get('checks') as $c) {
            $dec = self::truthy(self::get($c, 'decisive'));
            $mark = $dec ? ' ◀ DECISIVE' : '';
            $st = $c->get('status');
            $glyph = is_string($st) && isset(self::GLYPH[$st]) ? self::GLYPH[$st] : 'undefined';
            $lines[] = sprintf('  %s %s %s%s', $glyph, self::padEnd(self::js($c->get('name')), 16), self::js($c->get('detail')), $mark);
            if ($dec && self::truthy(self::get($c, 'remedy'))) {
                $lines[] = '      ↳ fix: ' . self::js($c->get('remedy'));
            }
        }
        return implode("\n", $lines);
    }

    // ---- explainDecision --------------------------------------------------------------------------------------------------

    private static function caveatRemedy(string $type, Obj $rest): string
    {
        $g = static fn(string $k): mixed => $rest->has($k) ? $rest->get($k) : Jsx::$U;
        switch ($type) {
            case 'expires':
                return sprintf("the grant expired at %s (epoch ms); obtain a fresh grant or re-mint with a later 'expires'.", self::num($g('at')));
            case 'not_before':
                return sprintf('the grant is not valid until %s (epoch ms); retry after that time.', self::num($g('at')));
            case 'rate':
                return sprintf("rate limit %s/%ss reached; wait for the window to clear or raise the 'rate' caveat.", self::num($g('max')), self::num($g('per_secs')));
            case 'max_blast_radius':
                return sprintf("the action's blast radius exceeds the caveat max %s; narrow the action or raise 'max_blast_radius'.", self::num($g('max')));
            case 'reversibility_max':
                return sprintf("the action is more severe than the allowed class '%s'; only that class or lower is permitted.", self::js($g('class')));
            case 'delegation_depth':
                return sprintf("delegation depth exceeds max %s; act from a shallower hop or raise 'delegation_depth'.", self::num($g('max')));
        }
        return sprintf("caveat '%s' is not satisfied; check its parameters against the action/context.", $type);
    }

    private static function caveatDetail(string $type, Obj $rest, mixed $satisfied): string
    {
        $bound = self::valueSummary($rest);
        $verb = self::truthy($satisfied) ? 'held' : 'NARROWED/DENIED';
        return $bound !== '' ? sprintf('%s(%s) %s', $type, $bound, $verb) : sprintf('%s %s', $type, $verb);
    }

    /** @param list<mixed> $reasons @return array<string,true> */
    private static function failedCaveatTypes(array $reasons): array
    {
        $out = [];
        foreach ($reasons as $r) {
            if (preg_match('/caveat\(s\) not satisfied: ([^\n\r\x{2028}\x{2029}]+)\z/u', self::js($r), $m) === 1) {
                foreach (explode(',', $m[1]) as $t) {
                    $t = self::trim($t);
                    if ($t !== '') {
                        $out[$t] = true;
                    }
                }
            }
        }
        return $out;
    }

    private static function riskBand(mixed $r, mixed $t1, mixed $t2, mixed $tier): string
    {
        if (self::isUndef($t1) || self::isUndef($t2)) {
            return 'effective tier t=' . self::js($tier);
        }
        if (self::le($r, $t1)) {
            return sprintf('r %s ≤ θ1 %s → claim band (t=1)', self::num($r), self::num($t1));
        }
        if (self::le($r, $t2)) {
            return sprintf('θ1 %s < r %s ≤ θ2 %s → standard band (t=2)', self::num($t1), self::num($r), self::num($t2));
        }
        return sprintf('r %s > θ2 %s → strong band (t=3)', self::num($r), self::num($t2));
    }

    private static function noDecision(string $reason): Obj
    {
        return Obj::of(['admit' => false, 'needStepUp' => false, 'releaseGuardianShare' => false, 'r' => 1,
            'requiredThreshold' => Obj::of(['t' => 3, 'proof' => 'human', 'optimisticAllowed' => false]),
            'budget' => Obj::of(['B' => 0, 'tau' => 0, 'asOf' => 0]), 'reasons' => [$reason]]);
    }

    /**
     * Explain a Policy-VM decision. Arguments: (pcaActn, decision, opts?); opts may carry `envelope` and `context`
     * ({action, caveat, chain}). A missing or malformed decision is a denial, never an allow.
     */
    public static function explainDecision(mixed ...$a): Obj
    {
        $decision = $a[1] ?? Jsx::$U;
        $o = array_key_exists(2, $a) ? $a[2] : new Obj();
        if (!self::isObj($decision) || !self::isObj(self::get($decision, 'requiredThreshold'))) {
            return self::explainDecisionInner(self::noDecision('no policy decision supplied (default-deny)'), $o);
        }
        try {
            return self::explainDecisionInner($decision, $o);
        } catch (\Throwable) {
            return self::explainDecisionInner(self::noDecision('the policy decision could not be explained (default-deny)'), new Obj());
        }
    }

    private static function includes(mixed $r, string $needle): bool
    {
        if (!is_string($r)) {
            throw new \TypeError('includes is not a function');
        }
        return str_contains($r, $needle);
    }

    /** `evaluateAgentCaveats([cv], caveatCtx, actionCtx).ok`: the reference's camelCase context mapped onto this evaluator's. */
    private static function evalCaveat(mixed $cv, mixed $caveatCtx, mixed $actionCtx): bool
    {
        $inner = self::get($actionCtx, 'action');
        $inner = $inner instanceof Obj ? $inner : new Obj();
        $c = new Obj();
        foreach ([['now', 'now'], ['delegationDepth', 'delegation_depth'], ['blastRadius', 'blast_radius'], ['reversibilityClass', 'reversibility_class'], ['recentActionTimes', 'recent_action_times']] as [$src, $dst]) {
            $v = self::get($caveatCtx, $src);
            if (!self::isUndef($v)) {
                $c->set($dst, $v);
            }
        }
        $c->set('action', $inner);
        $verb = self::get($inner, 'verb');
        $params = self::get($inner, 'params');
        $binding = self::get($actionCtx, 'toolBinding');
        $tool = ['tool' => is_string($verb) ? $verb : '', 'args' => $params instanceof Obj ? $params : new Obj()];
        if (is_string($binding)) {
            $tool['toolSignatureDigest'] = $binding;
        }
        return Authorize::evaluateAgentCaveats([$cv], $c, $actionCtx instanceof Obj ? $actionCtx : new Obj(), $tool)['ok'];
    }

    private static function explainDecisionInner(mixed $decision, mixed $opts): Obj
    {
        $env = self::rd($opts, 'envelope');
        $ctx = self::nn(self::get($opts, 'context'), new Obj());
        $reasonsRaw = self::get($decision, 'reasons');
        $reasons = self::isList($reasonsRaw) ? $reasonsRaw : [];

        $admitted = self::get($decision, 'admit') === true; // strict: a truthy non-boolean is not an admission
        $rgs = self::get($decision, 'releaseGuardianShare');
        $disposition = $admitted ? 'auto-admit' : ($rgs === true ? 'step-up' : 'denied');
        $verdict = $admitted ? 'allow' : 'deny';

        // authority: the granting predicate
        $grant = new Obj();
        self::put($grant, 'granted', $rgs);
        $chain = self::get($ctx, 'chain');
        $rootCap = self::opt($chain, '0');
        if (self::truthy($rootCap)) {
            self::put($grant, 'capabilityId', self::get($rootCap, 'id'));
        }
        $ctxAction = self::get($ctx, 'action');
        $ctxCaveat = self::get($ctx, 'caveat');
        $hasEnv = self::truthy($env);
        if ($hasEnv && self::truthy($ctxAction)) {
            $preds = self::get($env, 'predicates');
            $pr = $ctxAction instanceof Obj
                ? Predicates::evaluatePredicates(self::isList($preds) ? $preds : null, $ctxAction)
                : ['allowed' => false, 'reason' => 'predicate evaluation error (fail closed)'];
            if (!empty($pr['allowed']) && ($pr['matched'] ?? null) !== null) {
                $matched = $pr['matched'];
                $grant->set('granted', true);
                $grant->set('predicate', $matched);
                $idx = null;
                foreach ($preds as $i => $x) {
                    if ($x === $matched) {
                        $idx = $i;
                        break;
                    }
                }
                if ($idx === null) {
                    throw new \RuntimeException('matched predicate not in list');
                }
                $grant->set('predicateIndex', $idx);
                $grant->set('where', self::whereSummary(self::get($matched, 'where')));
            } else {
                $grant->set('granted', false);
                $grant->set('reason', $pr['reason'] ?? 'no predicate permits this action');
            }
        } elseif (!self::truthy($rgs)) {
            foreach ($reasons as $r) {
                if (self::includes($r, 'predicate') || self::includes($r, 'not permitted')) {
                    $grant->set('reason', $r);
                    break;
                }
            }
        }

        // caveats: per-caveat outcome
        $caveats = [];
        $failedFromReasons = self::failedCaveatTypes($reasons);
        $canEval = !self::isUndef($env) && !self::isUndef($ctxCaveat) && !self::isUndef($ctxAction);
        $grantCaveats = self::nn(self::opt($env, 'caveats'), []);
        $chain0 = self::opt($chain, '0');
        $rootCount = 0;
        if (!self::isUndef($chain0) && $chain0 !== null) {
            $cv0 = self::rd($chain0, 'caveats');
            if (self::isUndef($cv0) || $cv0 === null) {
                throw new \TypeError("cannot read 'length' of undefined");
            }
            $n0 = self::length($cv0);
            $rootCount = self::isUndef($n0) ? 0 : $n0;
        }
        $delegated = [];
        if (self::isList($chain) && count($chain) > 1) {
            $delegated = self::sliceFrom(self::nn(self::opt($chain[count($chain) - 1], 'caveats'), []), $rootCount);
        }
        $classify = function (mixed $cv, bool $isDelegated) use ($canEval, $ctxCaveat, $ctxAction, $failedFromReasons, $rgs): Obj {
            $type = self::caveatType($cv);
            $rest = self::caveatRest($cv);
            if ($canEval && self::truthy($ctxCaveat) && self::truthy($ctxAction)) {
                $satisfied = self::evalCaveat($cv, $ctxCaveat, $ctxAction);
            } else {
                $satisfied = isset($failedFromReasons[$type]) ? false : $rgs;
            }
            $out = Obj::of(['type' => $type]);
            self::put($out, 'satisfied', $satisfied);
            $out->set('value', $rest);
            $out->set('detail', self::caveatDetail($type, $rest, $satisfied));
            $out->set('delegated', $isDelegated);
            if (!self::truthy($satisfied)) {
                $out->set('remedy', self::caveatRemedy($type, $rest));
            }
            return $out;
        };
        foreach (Jsx::iter($grantCaveats) as $cv) {
            $caveats[] = $classify($cv, false);
        }
        foreach (Jsx::iter($delegated) as $cv) {
            $caveats[] = $classify($cv, true);
        }

        // risk / tier
        $rt = self::get($decision, 'requiredThreshold');
        $r = self::get($decision, 'r');
        $envNn = !self::isUndef($env) && $env !== null;
        $riskPolicy = Jsx::$U;
        if ($envNn) {
            $riskPolicy = self::rd($env, 'risk_policy');
            if (self::isUndef($riskPolicy) || $riskPolicy === null) {
                throw new \TypeError('cannot read properties of undefined');
            }
        }
        $theta1 = self::opt($riskPolicy, 'theta1');
        $theta2 = self::opt($riskPolicy, 'theta2');
        $tier = self::get($rt, 't');
        $proof = self::get($rt, 'proof');
        $optimistic = self::get($rt, 'optimisticAllowed');
        $risk = new Obj();
        self::put($risk, 'r', $r);
        self::put($risk, 'tier', $tier);
        self::put($risk, 'proof', $proof);
        self::put($risk, 'optimisticAllowed', $optimistic);
        $risk->set('band', self::riskBand($r, $theta1, $theta2, $tier));
        if ($hasEnv) {
            self::put($risk, 'theta1', $theta1);
            self::put($risk, 'theta2', $theta2);
        }

        // admission / budget
        $kappa = $envNn ? self::get($riskPolicy, 'kappa') : Jsx::$U;
        $costVal = null;
        if (!self::isUndef($kappa)) {
            $k = self::fin($kappa);
            $rf = self::fin(self::isUndef($r) ? null : $r);
            $costVal = ($k !== null && $k > 0 ? $k : 0.0) * min(1.0, max(0.0, $rf ?? 1.0));
        }
        $budgetDepleted = false;
        foreach ($reasons as $x) {
            if (self::includes($x, 'budget depleted')) {
                $budgetDepleted = true;
                break;
            }
        }
        if ($admitted) {
            $path = sprintf('auto-admitted at t=%s (%s); metered', self::js($tier), self::js($proof));
        } elseif (!self::truthy($rgs)) {
            $path = 'guardian share withheld — policy not satisfied (no autonomous or guardian path)';
        } elseif ($budgetDepleted) {
            $path = 'trust budget cannot cover the cost — step-up to t=3 (human recharge) required';
        } else {
            $path = sprintf('step-up to t=%s (%s) co-signature required', self::js($tier), self::js($proof));
        }
        $admission = Obj::of(['admit' => $admitted]);
        self::put($admission, 'needStepUp', self::get($decision, 'needStepUp'));
        self::put($admission, 'releaseGuardianShare', $rgs);
        self::put($admission, 'budget', self::get($decision, 'budget'));
        $admission->set('path', $path);
        if ($costVal !== null) {
            $admission->set('cost', $costVal);
        }
        if (!self::isUndef($kappa)) {
            $admission->set('kappa', $kappa);
        }

        // the single decisive reason
        $decisive = null;
        if (!$admitted) {
            if (!self::truthy($grant->has('granted') ? $grant->get('granted') : Jsx::$U)) {
                $decisive = Obj::of(['reason' => $grant->has('reason') && $grant->get('reason') !== null ? $grant->get('reason') : 'action not permitted by the envelope predicates (default-deny)',
                    'remedy' => 'grant a predicate that permits this verb+resource (and satisfies its where bound).']);
            } else {
                $firstFailed = null;
                foreach ($caveats as $c) {
                    if (!self::truthy($c->has('satisfied') ? $c->get('satisfied') : Jsx::$U)) {
                        $firstFailed = $c;
                        break;
                    }
                }
                if ($firstFailed !== null) {
                    $decisive = Obj::of(['reason' => sprintf("caveat '%s' narrowed the authority away: %s", $firstFailed->get('type'), $firstFailed->get('detail'))]);
                    if (self::truthy($firstFailed->has('remedy') ? $firstFailed->get('remedy') : Jsx::$U)) {
                        $decisive->set('remedy', $firstFailed->get('remedy'));
                    }
                } elseif ($budgetDepleted) {
                    $decisive = Obj::of(['reason' => sprintf('risk %s is admissible but the trust budget cannot cover cost κ·r%s', self::num($r), $costVal !== null ? '=' . self::num($costVal) : ''),
                        'remedy' => 'recharge the budget with a human co-sign, or lower the action risk.']);
                } else {
                    $tf = self::fin($tier);
                    $decisive = Obj::of(['reason' => sprintf('risk %s exceeds the auto threshold → step-up to t=%s (%s)', self::num($r), self::js($tier), self::js($proof)),
                        'remedy' => $tf !== null && $tf == 3 ? 'obtain a human step-up co-signature.' : 'obtain the guardian/principal co-signature for this tier.']);
                }
            }
        }
        if ($admitted) {
            $summary = sprintf('Auto-admitted: %s grants it, all caveats held, risk r=%s is in the t=%s band and the budget covers it.',
                self::truthy($grant->has('predicate') ? $grant->get('predicate') : Jsx::$U) ? 'predicate #' . self::js($grant->has('predicateIndex') ? $grant->get('predicateIndex') : Jsx::$U) : 'policy',
                self::num($r), self::js($tier));
        } elseif ($decisive !== null) {
            $summary = sprintf('%s: %s', $verdict === 'deny' && $disposition === 'denied' ? 'Denied' : 'Needs step-up', self::js($decisive->get('reason')));
        } else {
            $summary = sprintf('Not auto-admitted (t=%s).', self::js($tier));
        }
        $cleanedCaveats = [];
        foreach ($caveats as $c) {
            $o = new Obj();
            foreach ($c->keys() as $k) {
                $o->set($k, $k === 'detail' ? self::cleanText($c->get('detail')) : $c->get($k));
            }
            $cleanedCaveats[] = $o;
        }
        $out = Obj::of(['kind' => 'decision', 'verdict' => $verdict, 'disposition' => $disposition, 'grant' => $grant, 'caveats' => $cleanedCaveats, 'risk' => $risk, 'admission' => $admission]);
        if ($decisive !== null) {
            $d = new Obj();
            foreach ($decisive->keys() as $k) {
                $d->set($k, $k === 'reason' ? self::cleanText($decisive->get('reason')) : $decisive->get($k));
            }
            $out->set('decisive', $d);
        }
        $out->set('reasons', array_map(fn($x) => self::cleanText($x), $reasons));
        $out->set('summary', self::cleanText($summary));
        return $out;
    }

    /** Render a decision explanation. */
    public static function decisionToText(Obj $e): string
    {
        $lines = [sprintf('PCA decision — %s (%s)', mb_strtoupper(self::js($e->get('verdict'))), self::js($e->get('disposition'))), self::js($e->get('summary')), ''];
        $gr = $e->get('grant');
        $pred = self::get($gr, 'predicate');
        if (self::truthy(self::get($gr, 'granted')) && self::truthy($pred)) {
            $pv = self::get($pred, 'verb');
            $verbs = self::isList($pv) ? implode('|', array_map(static fn($x) => $x === null ? '' : self::js($x), $pv)) : self::js($pv);
            $lines[] = sprintf('  authority : predicate #%s of grant %s grants %s on %s', self::js(self::get($gr, 'predicateIndex')), self::short(self::get($gr, 'capabilityId')), $verbs, self::js(self::nn(self::get($pred, 'resource'), '*')));
            $lines[] = '              where ' . self::js(self::get($gr, 'where'));
        } else {
            $lines[] = '  authority : NOT granted — ' . self::js(self::nn(self::get($gr, 'reason'), 'no predicate permits this action'));
        }
        if (count($e->get('caveats')) === 0) {
            $lines[] = '  caveats   : none';
        } else {
            foreach ($e->get('caveats') as $c) {
                $mark = self::truthy(self::get($c, 'satisfied')) ? '✓' : '✗';
                $src = self::truthy(self::get($c, 'delegated')) ? ' [delegated]' : '';
                $lines[] = sprintf('  caveat %s  : %s%s', $mark, self::js($c->get('detail')), $src);
                if (!self::truthy(self::get($c, 'satisfied')) && self::truthy(self::get($c, 'remedy'))) {
                    $lines[] = '              ↳ fix: ' . self::js($c->get('remedy'));
                }
            }
        }
        $risk = $e->get('risk');
        $lines[] = sprintf('  risk      : %s; proof=%s, optimistic=%s', self::js(self::get($risk, 'band')), self::js(self::get($risk, 'proof')), self::js(self::get($risk, 'optimisticAllowed')));
        $a = $e->get('admission');
        $cost = self::get($a, 'cost');
        $costStr = !self::isUndef($cost) ? sprintf(', cost κ·r=%s (κ=%s)', self::num($cost), self::num(self::get($a, 'kappa'))) : '';
        $lines[] = sprintf('  budget    : %s%s; B after=%s', self::js(self::get($a, 'path')), $costStr, self::num(self::rd(self::get($a, 'budget'), 'B')));
        $dec = self::get($e, 'decisive');
        if (self::truthy($dec)) {
            $lines[] = '';
            $lines[] = '  ◀ DECISIVE: ' . self::js(self::get($dec, 'reason'));
            if (self::truthy(self::get($dec, 'remedy'))) {
                $lines[] = '      ↳ fix: ' . self::js(self::get($dec, 'remedy'));
            }
        }
        return implode("\n", $lines);
    }

    // ---- explainChain -----------------------------------------------------------------------------------------------------

    private static function isBudgetAlloc(mixed $cv): bool
    {
        if (!self::isObj($cv) || self::get($cv, 'type') !== 'budget_alloc') {
            return false;
        }
        $f = self::fin(self::get($cv, 'limit'));
        return $f !== null && $f >= 0;
    }

    /**
     * The per-node budget subtree carried by a chain: one node per well-formed `budget_alloc` caveat, in delegation order. Reads
     * the append-only caveat lineage; it does not verify signatures.
     * @return list<Obj>
     */
    public static function budgetAllocNodes(mixed $chain): array
    {
        if (!self::isList($chain) || count($chain) === 0) {
            return [];
        }
        $out = [];
        $leaf = $chain[count($chain) - 1];
        $leafCvs = self::rd($leaf, 'caveats');
        if (!self::isList($leafCvs)) {
            return [];
        }
        $hop = 0;
        foreach ($leafCvs as $ci => $cv) {
            while ($hop < count($chain) - 1) {
                $n = self::length(self::rd($chain[$hop], 'caveats'));
                if ((self::isUndef($n) ? 0 : $n) <= $ci) {
                    $hop++;
                } else {
                    break;
                }
            }
            if (!self::isBudgetAlloc($cv)) {
                continue;
            }
            $introducing = $chain[$hop];
            $capId = self::rd($introducing, 'id');
            if (self::isUndef($capId)) {
                throw new \TypeError('canonicalize: undefined member');
            }
            $node = Obj::of(['nodePath' => Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/budget-node/v1', 'cap' => $capId, 'i' => new Num((string)$ci)]))]);
            self::put($node, 'capId', $capId);
            self::put($node, 'holder', self::rd($introducing, 'holder'));
            $node->set('depth', $hop);
            $node->set('caveatIndex', $ci);
            $node->set('limit', self::get($cv, 'limit'));
            $out[] = $node;
        }
        return $out;
    }

    /** @param list<mixed> $added */
    private static function hopNarrowedSummary(bool $isRoot, array $added): string
    {
        $bits = [];
        foreach ($added as $cv) {
            $type = self::caveatType($cv);
            $rest = self::caveatRest($cv);
            if ($type === 'envelope') {
                $preds = $rest->get('predicates');
                $inner = $rest->get('caveats');
                $bits[] = sprintf('envelope (%d predicate(s), %d caveat(s))', self::isList($preds) ? count($preds) : 0, self::isList($inner) ? count($inner) : 0);
            } elseif (self::isBudgetAlloc($cv)) {
                $bits[] = sprintf('budget_alloc(B_sub=%s)', self::num(self::get($cv, 'limit')));
            } else {
                $bound = self::valueSummary($rest);
                $bits[] = $bound !== '' ? sprintf('+%s(%s)', $type, $bound) : '+' . $type;
            }
        }
        if ($bits === []) {
            return $isRoot ? 'root grant (no caveats)' : 'rebind only (no new caveats)';
        }
        return ($isRoot ? 'grants ' : 'narrows: ') . implode(', ', $bits);
    }

    private static function explainChainInner(mixed $chain): Obj
    {
        $safe = self::isList($chain) ? $chain : [];
        $hops = [];
        foreach ($safe as $i => $cap) {
            if (!self::truthy($cap)) {
                continue;
            }
            $isRoot = $i === 0;
            $parent = $i > 0 ? $safe[$i - 1] : Jsx::$U;
            $pc = self::truthy($parent) ? self::get($parent, 'caveats') : Jsx::$U;
            $parentLen = self::isList($pc) ? count($pc) : 0;
            $oc = self::get($cap, 'caveats');
            $own = self::isList($oc) ? $oc : [];
            $added = $isRoot ? $own : (count($own) >= $parentLen ? array_slice($own, $parentLen) : []);
            $budgetCv = null;
            foreach ($added as $cv) {
                if (self::isBudgetAlloc($cv)) {
                    $budgetCv = $cv;
                    break;
                }
            }
            $hop = Obj::of(['index' => $i, 'isRoot' => $isRoot]);
            self::put($hop, 'issuer', self::get($cap, 'issuer'));
            self::put($hop, 'holder', self::get($cap, 'holder'));
            $hop->set('issuerShort', self::short(self::get($cap, 'issuer')));
            $hop->set('holderShort', self::short(self::get($cap, 'holder')));
            $hop->set('alg', self::nn(self::get($cap, 'alg'), 'ed25519'));
            $hop->set('addedCaveats', array_values($added));
            $hop->set('addedCaveatTypes', array_map(fn($cv) => self::caveatType($cv), array_values($added)));
            $hop->set('narrowed', self::cleanText(self::hopNarrowedSummary($isRoot, array_values($added))));
            if ($budgetCv !== null) {
                $hop->set('budgetAlloc', self::get($budgetCv, 'limit'));
            }
            $hops[] = $hop;
        }
        $root = $safe !== [] ? $safe[0] : Jsx::$U;
        $leaf = $safe !== [] ? $safe[count($safe) - 1] : Jsx::$U;
        $nodes = self::budgetAllocNodes($safe);
        $summary = $safe === [] ? 'empty chain (no authority)'
            : sprintf('%s (principal) delegated through %d hop(s) to the acting holder %s; %d budget node(s).', self::short(self::opt($root, 'issuer')), count($safe) - 1, self::short(self::opt($leaf, 'holder')), count($nodes));
        $out = Obj::of(['kind' => 'chain', 'depth' => count($safe), 'hops' => $hops]);
        self::put($out, 'rootIssuer', self::opt($root, 'issuer'));
        self::put($out, 'leafHolder', self::opt($leaf, 'holder'));
        $out->set('budgetNodes', $nodes);
        $out->set('summary', $summary);
        return $out;
    }

    /**
     * Render a delegation chain as an ordered attenuation trace. Arguments: (chain, opts?); with `opts.verify === true` the chain
     * is also checked (`opts.expectedRootIssuer` pins the root issuer).
     */
    public static function explainChain(mixed ...$a): Obj
    {
        $chain = $a[0] ?? Jsx::$U;
        $o = array_key_exists(1, $a) ? $a[1] : new Obj();
        $out = self::explainChainInner($chain);
        if (self::rd($o, 'verify') !== true) {
            return $out;
        }
        $ok = false;
        $reason = 'chain is not an array';
        try {
            if (self::isList($chain)) {
                $exp = self::get($o, 'expectedRootIssuer');
                $haveExp = !self::isUndef($exp) && $exp !== null;
                [$why, $good] = Pca::verifyChain($chain, $haveExp ? $exp : null, $haveExp);
                $ok = $good;
                $reason = $good ? null : self::chainReason($why);
            }
        } catch (\Throwable) {
            $ok = false;
            $reason = 'chain could not be verified';
        }
        $v = Obj::of(['ok' => $ok]);
        if ($reason !== null) {
            $v->set('reason', self::cleanText($reason));
        }
        $out->set('verification', $v);
        return $out;
    }

    /** Render a chain explanation. */
    public static function chainToText(Obj $e): string
    {
        $lines = [sprintf('PCA delegation chain — %s hop(s) (attenuation trace)', self::js($e->get('depth')))];
        $v = self::get($e, 'verification');
        if (self::isUndef($v)) {
            $lines[] = 'UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.';
        } elseif ($v->get('ok') === true) {
            $lines[] = 'verified: signatures, links and caveat rules hold.';
        } else {
            $lines[] = 'NOT VALID: ' . self::js(self::nn(self::get($v, 'reason'), 'the chain failed verification'));
        }
        $lines[] = self::js($e->get('summary'));
        $lines[] = '';
        foreach ($e->get('hops') as $h) {
            $lines[] = sprintf('  #%s %s %s ──▶ %s   %s', self::js($h->get('index')), $h->get('isRoot') ? 'root ' : 'deleg', self::js($h->get('issuerShort')), self::js($h->get('holderShort')), self::js($h->get('narrowed')));
        }
        if (count($e->get('budgetNodes')) > 0) {
            $tree = implode(' → ', array_map(static fn(Obj $n) => sprintf('depth %s B_sub=%s', self::js($n->get('depth')), self::num($n->get('limit'))), $e->get('budgetNodes')));
            $lines[] = '';
            $lines[] = '  budget subtree: ' . $tree;
        }
        return implode("\n", $lines);
    }
}
