<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/Decision.php';
require_once __DIR__ . '/IntentV2.php';

/**
 * Decision obligations (the PEP side): validate, merge, gate and outcome. A PEP that cannot perform every obligation on an allow
 * turns the allow into a deny. Total. Replays packages/pca/conformance/obligations-vectors.json. A null list is the empty list.
 * Values are parsed JSON (Obj, lists, Num).
 */
final class Obligations
{
    public const KINDS = ['log', 'notify', 'redact', 'watermark', 'require_receipt'];
    public const MAX = 16;
    private const ALLOWED = ['log' => ['sink'], 'notify' => ['to'], 'redact' => ['fields'], 'watermark' => ['id'], 'require_receipt' => []];
    private const FIELD_RE = '/\A[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}\z/D';

    private static function paramsError(string $kind, Obj $p): ?string
    {
        foreach ($p->keys() as $k) {
            if (!in_array($k, self::ALLOWED[$kind], true)) {
                return "unknown parameter '$k' for '$kind'";
            }
        }
        if ($kind === 'log' && $p->has('sink') && !K3Sig::isStr($p->get('sink'), 128)) {
            return 'log.sink must be a non-empty string of at most 128 characters';
        }
        if ($kind === 'notify' && !K3Sig::isStr($p->get('to'), 256)) {
            return 'notify.to is required (a non-empty string of at most 256 characters)';
        }
        if ($kind === 'watermark' && !K3Sig::isStr($p->get('id'), 128)) {
            return 'watermark.id is required (a non-empty string of at most 128 characters)';
        }
        if ($kind === 'redact') {
            $f = $p->get('fields');
            if (!K3Sig::isList($f) || count($f) === 0 || count($f) > 32) {
                return 'redact.fields must be 1..32 dotted field paths';
            }
            foreach ($f as $x) {
                if (!is_string($x) || preg_match(self::FIELD_RE, $x) !== 1) {
                    return 'redact.fields must be 1..32 dotted field paths';
                }
            }
            if (count(array_unique($f)) !== count($f)) {
                return 'redact.fields has a duplicate';
            }
        }
        return null;
    }

    /** null = well formed. */
    public static function error(mixed $o): ?string
    {
        if (!($o instanceof Obj)) {
            return 'an obligation must be an object';
        }
        foreach ($o->keys() as $k) {
            if (!in_array($k, ['kind', 'params', 'due'], true)) {
                return "unknown member '$k'";
            }
        }
        $kind = $o->get('kind');
        if (!is_string($kind) || !in_array($kind, self::KINDS, true)) {
            return "unknown obligation kind '" . (is_string($kind) ? $kind : '') . "'";
        }
        if ($o->has('due') && !K3Sig::isSafeInt($o->get('due'))) {
            return 'due must be a non-negative safe integer';
        }
        $p = $o->has('params') ? $o->get('params') : new Obj();
        if (!($p instanceof Obj)) {
            return 'params must be an object';
        }
        return self::paramsError($kind, $p);
    }

    /** null = a well-formed, duplicate-free list of at most 16. null (absent) is the empty list. */
    public static function listError(mixed $list): ?string
    {
        if ($list === null) {
            return null;
        }
        if (!K3Sig::isList($list)) {
            return 'obligations must be an array';
        }
        if (count($list) > self::MAX) {
            return 'more than ' . self::MAX . ' obligations';
        }
        $seen = [];
        try {
            foreach ($list as $i => $o) {
                $e = self::error($o);
                if ($e !== null) {
                    return "obligations[$i]: $e";
                }
                $key = self::key($o);
                if (isset($seen[$key])) {
                    return "obligations[$i] duplicates an earlier obligation";
                }
                $seen[$key] = true;
            }
        } catch (\Throwable) {
            return 'evaluation error (fail closed)';
        }
        return null;
    }

    /** The canonical identity of a well-formed obligation (kind, parameters, due). */
    public static function key(Obj $o): string
    {
        $h = new Obj();
        $h->set('kind', $o->get('kind'));
        $h->set('params', $o->has('params') ? $o->get('params') : new Obj());
        if ($o->has('due')) {
            $h->set('due', $o->get('due'));
        }
        return Json::canonicalizeStrict($h);
    }

    /**
     * @return array{ok: bool, obligations?: list<Obj>, reason?: string}
     */
    public static function merge(mixed ...$lists): array
    {
        try {
            $by = [];
            foreach ($lists as $l) {
                $e = self::listError($l);
                if ($e !== null) {
                    return ['ok' => false, 'reason' => $e];
                }
                foreach ($l ?? [] as $o) {
                    $by[self::key($o)] = $o;
                }
            }
            if (count($by) > self::MAX) {
                return ['ok' => false, 'reason' => 'more than ' . self::MAX . ' obligations after merging'];
            }
            $keys = array_map('strval', array_keys($by));
            usort($keys, static fn (string $a, string $b): int => IntentV2::compareUtf8($a, $b));
            return ['ok' => true, 'obligations' => array_map(static fn (string $k) => $by[$k], $keys)];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'evaluation error (fail closed)'];
        }
    }

    /**
     * @return array{decision: string, perform: list<Obj>, unsupported: list<string>, reason?: string}
     */
    public static function gate(mixed $decision, mixed $answered, mixed $obligations, mixed $supported): array
    {
        $deny = static fn (array $unsupported = [], ?string $reason = null): array => ['decision' => 'deny', 'perform' => [], 'unsupported' => $unsupported] + ($reason !== null ? ['reason' => $reason] : []);
        try {
            $eff = Decision::pepDecision($decision, $answered);
            if ($eff !== 'allow') {
                return ['decision' => $eff === 'escalate' ? 'escalate' : 'deny', 'perform' => [], 'unsupported' => []];
            }
            $e = self::listError($obligations);
            if ($e !== null) {
                return $deny([], "malformed obligations: $e");
            }
            if (!K3Sig::isList($supported) || count(array_filter($supported, 'is_string')) !== count($supported)) {
                return $deny([], 'the supported obligation kinds are malformed');
            }
            $list = $obligations ?? [];
            $missing = [];
            foreach ($list as $o) {
                if (!in_array($o->get('kind'), $supported, true)) {
                    $missing[$o->get('kind')] = true;
                }
            }
            $missing = array_map('strval', array_keys($missing));
            usort($missing, static fn (string $a, string $b): int => IntentV2::compareUtf8($a, $b));
            if ($missing !== []) {
                return $deny($missing, 'the enforcement point does not support obligation(s) ' . implode(', ', $missing));
            }
            return ['decision' => 'allow', 'perform' => $list, 'unsupported' => []];
        } catch (\Throwable) {
            return $deny([], 'evaluation error (fail closed)');
        }
    }

    /**
     * @return array{outcome: string, overdue: list<int>, status?: string}
     */
    public static function outcome(mixed $obligations, mixed $fulfilled, mixed $now): array
    {
        $unmet = static fn (array $overdue): array => ['outcome' => 'escalate', 'overdue' => $overdue, 'status' => 'obligation_unmet'];
        try {
            $list = $obligations ?? [];
            $bad = self::listError($obligations) !== null || !K3Sig::isList($fulfilled) || !K3Sig::isSafeInt($now);
            if (!$bad) {
                foreach ($fulfilled as $i) {
                    $bad = $bad || !K3Sig::isSafeInt($i);
                }
            }
            if ($bad) {
                return $unmet(K3Sig::isList($list) ? array_keys($list) : []);
            }
            $done = array_map(static fn ($i) => (int)K3Sig::num($i), $fulfilled);
            $nowMs = K3Sig::num($now);
            $overdue = [];
            foreach ($list as $i => $o) {
                if ($o->has('due') && K3Sig::num($o->get('due')) <= $nowMs && !in_array($i, $done, true)) {
                    $overdue[] = $i;
                }
            }
            return $overdue === [] ? ['outcome' => 'ok', 'overdue' => []] : $unmet($overdue);
        } catch (\Throwable) {
            return $unmet([]);
        }
    }
}
