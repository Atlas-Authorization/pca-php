<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;

/**
 * Corpus loader + characterization snapshot for mutation testing. The conformance files pin only allow/checks; the
 * snapshot additionally pins the diagnostic `reason`, the strict-JSON rejection message and the canonical forms over
 * the core + full adversarial corpus and tools/pca-audit/native-mutation/inputs.jsonl.gz.
 *   php tests/Corpus.php write test-data/reasons.tsv.gz
 */
final class Corpus
{
    public const DIR = __DIR__ . '/../conformance/';
    public const INPUTS = __DIR__ . '/../../../tools/pca-audit/native-mutation/inputs.jsonl.gz';
    public const SNAP = __DIR__ . '/../test-data/reasons.tsv.gz';

    private static mixed $core = null;
    private static ?array $advDoc = null;
    private static ?array $inputs = null;
    private static ?array $snap = null;

    public static function core(): Obj
    {
        return self::$core ??= Json::parseLax(file_get_contents(self::DIR . 'vectors.json'));
    }

    /** Full adversarial set as stdClass trees (fast native decode); grants are re-parsed to Obj per use. */
    public static function adv(): array
    {
        if (self::$advDoc === null) {
            $txt = gzdecode(file_get_contents(self::DIR . 'vectors-adversarial.json.gz'));
            // PHP's native decoder rejects lone-surrogate \u escapes: map them to U+FFFD (valid pairs and escaped backslashes are kept)
            $txt = preg_replace_callback('/\\\\(?:u[dD][89abAB][0-9a-fA-F]{2}\\\\u[dD][c-fC-F][0-9a-fA-F]{2}|u[dD][89a-fA-F][0-9a-fA-F]{2}|.)/s',
                fn($m) => preg_match('/^\\\\u[dD][89a-fA-F][0-9a-fA-F]{2}$/', $m[0]) ? '\\ufffd' : $m[0], $txt);
            self::$advDoc = json_decode($txt, true, 512, JSON_BIGINT_AS_STRING);
            if (self::$advDoc === null) {
                throw new \RuntimeException('adversarial corpus: ' . json_last_error_msg());
            }
        }
        return self::$advDoc;
    }

    public static function inputs(): array
    {
        return self::$inputs ??= array_map(fn($l) => json_decode($l, true), array_values(array_filter(explode("\n", gzdecode(file_get_contents(self::INPUTS))))));
    }

    public static function snapshot(): array
    {
        if (self::$snap === null) {
            self::$snap = [];
            foreach (explode("\n", gzdecode(file_get_contents(self::SNAP))) as $l) {
                $t = strpos($l, "\t");
                if ($t !== false && $t > 0) {
                    self::$snap[substr($l, 0, $t)] = substr($l, $t + 1);
                }
            }
        }
        return self::$snap;
    }

    public static function esc(?string $s): string
    {
        if ($s === null) {
            return '<nil>';
        }
        $o = '';
        foreach (preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $c) {
            $n = mb_ord($c, 'UTF-8');
            $o .= match (true) {
                $c === '\\' => '\\\\',
                $c === "\n" => '\\n',
                $c === "\t" => '\\t',
                $c === "\r" => '\\r',
                $n < 0x20 => sprintf('\\u%04x', $n),
                default => $c,
            };
        }
        return $o;
    }

    /** @param array{allow:bool,checks:array<string,bool>,reason:string} $g */
    public static function fmt(array $g): string
    {
        $c = [];
        foreach ($g['checks'] as $k => $v) {
            $c[] = $k . '=' . ($v ? 'true' : 'false');
        }
        return ($g['allow'] ? 'true' : 'false') . '|' . implode(',', $c) . '|' . self::esc($g['reason']);
    }

    public static function toObj(mixed $decoded): mixed
    {
        return Json::parseLax(json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION));
    }

    /** Verify one adversarial/core vector given as stdClass (adv) -> [array verdict]. */
    public static function verifyAdv(array $v): array
    {
        $ctx = $v['context'];
        return Pca::verifyJson($v['pcactn_json'], self::toObj($v['grant']), (int)$ctx['now'], $ctx['aud'], $ctx['allowed_suites'] ?? null,
            self::intentPolicyOf($ctx), self::intentV2Of($ctx));
    }

    /** Intent Layer v2 checks in pipeline order (appended after `intent`, each only when reported). */
    public const V2_ORDER = ['schema', 'intent_session', 'layers', 'accumulators', 'map', 'facts', 'provenance', 'classes'];

    /**
     * Intent Layer v2 verifier state of an assoc-array context / fuzz line: `intent_v2` (a JSON object, or its JSON text),
     * re-parsed by Json::parseLax so number lexemes are kept (the v2 checks judge them by value). Null when absent / not an object.
     */
    public static function intentV2Of(array $ctx): ?Obj
    {
        if (!isset($ctx['intent_v2'])) {
            return null;
        }
        $v = is_string($ctx['intent_v2']) ? Json::parseLax($ctx['intent_v2'])
            : Json::parseLax(json_encode($ctx['intent_v2'], JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION));
        return $v instanceof Obj ? $v : null;
    }

    /** `context.intent_v2` of a core vector (an Obj), else null. */
    public static function intentV2OfObj(Obj $ctx): ?Obj
    {
        $v = $ctx->has('intent_v2') ? $ctx->get('intent_v2') : null;
        return $v instanceof Obj ? $v : null;
    }

    /** The expected check order: the core order, `intent` when expected, then the expected v2 checks in pipeline order. */
    public static function expectedOrder(array $coreOrder, Obj $wantChecks): array
    {
        $order = array_values($coreOrder);
        if ($wantChecks->has('intent')) {
            $order[] = 'intent';
        }
        foreach (self::V2_ORDER as $k) {
            if ($wantChecks->has($k)) {
                $order[] = $k;
            }
        }
        return $order;
    }

    /**
     * How a vector's `requires_suite` applies here: 'none' (no requirement), 'implemented' (in the suite manifest: compare
     * exactly) or 'unsupported' (outside it: not implemented, or its backend is unavailable here; the vector must deny, with
     * `unsupported_suite` in the reason when the first failing check is a v2 check).
     */
    public static function requiresSuite(Obj $v): string
    {
        $s = $v->has('requires_suite') ? $v->get('requires_suite') : null;
        if (!is_string($s)) {
            return 'none';
        }
        // README "Suite capability": a suite outside the manifest (Pca::supportedSuites: registered AND runnable here) is
        // not compared; the verifier must refuse it with `unsupported_suite`
        return Pca::suiteImplemented($s) ? 'implemented' : 'unsupported';
    }

    /** True when the verdict's reason (its FIRST failing check) belongs to an Intent Layer v2 check. */
    public static function firstFailureIsV2(array $got): bool
    {
        foreach ($got['checks'] as $k => $ok) {
            if ($ok === false) {
                return in_array((string)$k, self::V2_ORDER, true);
            }
        }
        return false;
    }

    /** The Intent Layer v2 primitive tables the runners compare (IntentV2::primitive kinds). */
    public const INTENT_PRIMITIVES = ['intent_schema', 'intent_revocation', 'intent_world', 'intent_provenance', 'intent_classifier',
        'intent_wb_active', 'intent_read_purpose', 'intent_map_commit', 'intent_map'];

    /**
     * The intent_* primitives (rules 13-19 on their own), each through IntentV2::primitive (the same entry the diff-fuzz
     * driver uses) and compared with its `expect` as canonical JSON (`expect.reason_contains` is asserted on the reason,
     * never compared as a member). README "Suite capability": an entry whose `requires_suite` this verifier does not
     * implement must refuse with `unsupported_suite` in the reason (counted as `unsupported`). An absent table is
     * reported as absent. `$check(bool $ok, string $msg)` records each comparison.
     * @return array<string, array{ran:int, unsupported:int, absent?:bool}>
     */
    public static function runIntentPrimitives(Obj $prim, callable $check): array
    {
        $canon = function (mixed $x): string {
            try {
                return IntentV2::canonicalize($x);
            } catch (\Throwable $t) {
                return '<no canonical form: ' . $t->getMessage() . '>';
            }
        };
        $out = [];
        foreach (self::INTENT_PRIMITIVES as $table) {
            $entries = $prim->has($table) && is_array($prim->get($table)) ? $prim->get($table) : null;
            $out[$table] = ['ran' => 0, 'unsupported' => 0];
            if ($entries === null) {
                $out[$table]['absent'] = true;
                continue;
            }
            foreach ($entries as $e) {
                $name = (string)($e->has('name') ? $e->get('name') : '?');
                $exp = $e->get('expect');
                $out[$table]['ran']++;
                try {
                    // README "Raw JSON text members": `input_json` (the whole input as raw text) wins over `input`
                    $input = $e->has('input_json') && is_string($e->get('input_json')) ? Json::parseLax($e->get('input_json'))
                        : ($e->has('input') ? $e->get('input') : IntentV2::undef());
                    $res = IntentV2::primitive($table, $input);
                } catch (\Throwable $t) {
                    $check(false, "$table $name: THREW " . get_class($t) . ': ' . $t->getMessage());
                    continue;
                }
                [$got, $why] = $res;
                $why = (string)$why;
                $wantReason = $exp instanceof Obj && $exp->has('reason_contains') ? (string)$exp->get('reason_contains') : null;
                if ($wantReason !== null) {
                    $check(str_contains($why, $wantReason), "$table $name: reason must contain $wantReason ($why)");
                }
                if (self::requiresSuite($e) === 'unsupported') {
                    $out[$table]['unsupported']++;
                    $refused = $got->has('ok') ? $got->get('ok') === false : ($got->has('outcome') ? $got->get('outcome') === 'deny' : $got->get('sig') === false);
                    $check($refused && str_contains($why, 'unsupported_suite'), "$table $name: requires_suite "
                        . json_encode($e->get('requires_suite')) . " is not implemented here: must refuse with unsupported_suite ($why)");
                    continue;
                }
                $want = $exp instanceof Obj ? $exp->without('reason_contains') : $exp;
                $check($canon($got) === $canon($want), "$table $name: got " . $canon($got) . ', want ' . $canon($want) . ($why !== '' ? " ($why)" : ''));
            }
        }
        return $out;
    }

    /**
     * Intent Layer M2 policy of an assoc-array context / fuzz line: `intent_policy_json` (raw JSON TEXT, parsed by
     * Json::parseLax so number lexemes are kept) wins over `intent_policy`.
     */
    public static function intentPolicyOf(array $ctx): mixed
    {
        return isset($ctx['intent_policy_json']) ? Json::parseLax($ctx['intent_policy_json']) : ($ctx['intent_policy'] ?? null);
    }

    public static function verifyCore(Obj $v): array
    {
        $ctx = $v->get('context');
        $now = $ctx->get('now')->int();
        $aud = $ctx->get('aud');
        $allowed = $ctx->has('allowed_suites') ? $ctx->get('allowed_suites') : null;
        $intentPolicy = $ctx->has('intent_policy_json') ? Json::parseLax($ctx->get('intent_policy_json'))
            : ($ctx->has('intent_policy') ? $ctx->get('intent_policy') : null);
        $intentV2 = self::intentV2OfObj($ctx);
        return $v->has('pcactn_json')
            ? Pca::verifyJson($v->get('pcactn_json'), $v->get('grant'), $now, $aud, $allowed, $intentPolicy, $intentV2)
            : Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $now, $aud, $allowed, $intentPolicy, $intentV2);
    }

    public static function parseOutcome(string $in, bool $lax): string
    {
        try {
            $v = $lax ? Json::parseLax($in) : Json::parseStrict($in);
            return Json::canonicalizeStrict($v);
        } catch (JsonError $e) {
            return 'err:' . self::esc($e->getMessage());
        } catch (\Throwable $e) {
            return 'THROW:' . get_class($e) . ':' . self::esc($e->getMessage());
        }
    }

    /** @return array<string,string> entries i % step == k of the shared fuzz inputs. */
    public static function computeInputs(int $k, int $step): array
    {
        $out = [];
        foreach (self::inputs() as $i => $c) {
            if ($i % $step !== $k) {
                continue;
            }
            if ($c['kind'] === 'verify') {
                try {
                    $g = Pca::verifyJson($c['raw'], Json::parseLax($c['grant']), (int)$c['now'], $c['aud'], $c['allowed_suites'] ?? null,
                        self::intentPolicyOf($c), self::intentV2Of($c));
                    $val = self::fmt($g);
                } catch (\Throwable $e) {
                    $val = 'THROW:' . get_class($e) . ':' . self::esc($e->getMessage());
                }
            } else {
                $val = self::parseOutcome($c['raw'], false) . '|len=' . self::parseOutcome($c['raw'], true);
            }
            if (strlen($val) > 600) {
                $val = substr($val, 0, 600) . '#' . strlen($val);
            }
            $out['in:' . $c['id']] = $val;
        }
        return $out;
    }

    /** Pinned outputs of vectors i % step == k (+ primitives when k == 0) of a corpus; $adv selects the stdClass doc. */
    public static function computeVectors(bool $adv, int $k, int $step): array
    {
        $out = [];
        $tag = $adv ? 'adv' : 'core';
        if ($adv) {
            $vs = self::adv()['vectors'];
            foreach ($vs as $i => $v) {
                if ($i % $step === $k) {
                    $out["$tag:v:" . $v['name']] = self::fmtSafe(fn() => self::verifyAdv($v));
                }
            }
            $prim = self::adv()['primitives'];
            if ($k === 0) {
                foreach ($prim['json_parse'] ?? [] as $n => $j) {
                    $out["$tag:jp:$n:" . self::esc(mb_substr($j['input'], 0, 80))] = self::parseOutcome($j['input'], false) . '|len=' . self::parseOutcome($j['input'], true);
                }
                foreach ($prim['b64u'] ?? [] as $n => $b) {
                    $r = Pca::unb64u($b['input'], isset($b['len']) ? (int)$b['len'] : null);
                    $out["$tag:b6:$n"] = $r === null ? 'nil' : bin2hex($r);
                }
            }
        } else {
            foreach (self::core()->get('vectors') as $i => $v) {
                if ($i % $step === $k) {
                    $out["$tag:v:" . $v->get('name')] = self::fmtSafe(fn() => self::verifyCore($v));
                }
            }
            if ($k === 0) {
                $prim = self::core()->get('primitives');
                foreach ($prim->get('json_parse') as $n => $j) {
                    $in = $j->get('input');
                    $out["$tag:jp:$n:" . self::esc(mb_substr($in, 0, 80))] = self::parseOutcome($in, false) . '|len=' . self::parseOutcome($in, true);
                }
                foreach ($prim->get('b64u') as $n => $b) {
                    $r = Pca::unb64u($b->get('input'), $b->has('len') ? $b->get('len')->int() : null);
                    $out["$tag:b6:$n"] = $r === null ? 'nil' : bin2hex($r);
                }
            }
        }
        return $out;
    }

    private static function fmtSafe(callable $f): string
    {
        try {
            return self::fmt($f());
        } catch (\Throwable $e) {
            return 'THROW:' . get_class($e) . ':' . self::esc($e->getMessage());
        }
    }

    public static function write(string $path): void
    {
        $all = self::computeVectors(false, 0, 1) + self::computeVectors(true, 0, 1) + self::computeInputs(0, 1);
        $txt = '';
        foreach ($all as $k => $v) {
            $txt .= self::esc($k) . "\t" . $v . "\n";
        }
        $gz = gzencode($txt, 9);
        // deterministic: zero the MTIME in the gzip header (bytes 4..7)
        $gz = substr($gz, 0, 4) . "\0\0\0\0" . substr($gz, 8);
        file_put_contents($path, $gz);
        echo 'wrote ' . count($all) . " lines\n";
    }
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__ && ($argv[1] ?? '') === 'write') {
    require_once __DIR__ . '/../src/Pca.php';
    ini_set('memory_limit', '4G');
    Corpus::write($argv[2]);
}
