<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/GoalIrError.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalCodec.php';
require_once __DIR__ . '/GoalKernel.php';
require_once __DIR__ . '/GoalNormalize.php';
require_once __DIR__ . '/Pca.php';

/**
 * The typed front door of the goal compiler: IR values in, IR values out, every decision made by the goal kernel over token
 * tapes (a tape is a list of `[tag, value]` tokens). Plus the canonical policy bytes and digest.
 */
final class GoalCompiler
{
    /** @param list<mixed> $t */
    private static function first(array $t): mixed
    {
        $x = $t[0] ?? null;
        if (!is_array($x) || ($x[0] ?? null) !== 'i') {
            throw new GoalIrError('malformed compiler output');
        }
        return $x[1];
    }

    /** @param list<mixed> $t @return list<string> */
    private static function reasonsOf(array $t): array
    {
        $n = (isset($t[1]) && ($t[1][0] ?? null) === 'i') ? (int)$t[1][1] : 0;
        return array_map(static fn($x) => $x[0] === 's' ? $x[1] : '', array_slice($t, 2, $n));
    }

    private static function decisionOf(mixed $n): string
    {
        return $n === 2 ? 'allow' : ($n === 1 ? 'escalate' : 'deny');
    }

    /** Type reasons of a goal against an ontology; [] = well typed. @return list<string> */
    public static function typecheck(mixed $goal, mixed $ont): array
    {
        $out = GoalKernel::kernelCall('typecheck', GoalCodec::encodeGoal($goal), GoalCodec::encodeOntology($ont));
        return match (self::first($out)) {
            0 => [],
            1 => self::reasonsOf($out),
            default => throw new GoalIrError('compiler rejected the input tape'),
        };
    }

    /** C: Goal -> {ok: true, policy} | {ok: false, reasons}. Ill-typed goals are rejected, never coerced. */
    public static function compileGoal(mixed $goal, mixed $ont): Obj
    {
        $out = GoalKernel::kernelCall('compile', GoalCodec::encodeGoal($goal), GoalCodec::encodeOntology($ont));
        return match (self::first($out)) {
            0 => AnalyzerJs::uobj(['ok' => true, 'policy' => GoalCodec::decodePolicy(array_slice($out, 1))]),
            1 => AnalyzerJs::uobj(['ok' => false, 'reasons' => self::reasonsOf($out)]),
            default => throw new GoalIrError('compiler rejected the input tape'),
        };
    }

    /** The reference semantics D_G(a, H): 'allow' | 'escalate' | 'deny'. */
    public static function decideGoal(mixed $goal, mixed $ont, mixed $act, mixed $hist): string
    {
        $out = GoalKernel::kernelCall('decideg', GoalCodec::encodeGoal($goal), GoalCodec::encodeOntology($ont), GoalCodec::encodeAct($act), GoalCodec::encodeHist($hist));
        if (self::first($out) !== 0) {
            throw new GoalIrError('compiler rejected the input tape');
        }
        return self::decisionOf($out[1][1]);
    }

    /** The compiled policy's decision, the witness of an Allow and the separate checker's verdict on it. */
    public static function decidePolicy(mixed $goal, mixed $ont, mixed $act, mixed $hist): Obj
    {
        $out = GoalKernel::kernelCall('decidep', GoalCodec::encodeGoal($goal), GoalCodec::encodeOntology($ont), GoalCodec::encodeAct($act), GoalCodec::encodeHist($hist));
        $s = self::first($out);
        if ($s === 1) {
            return AnalyzerJs::uobj(['ok' => false, 'reasons' => self::reasonsOf($out)]);
        }
        if ($s !== 0) {
            throw new GoalIrError('compiler rejected the input tape');
        }
        $d = self::decisionOf($out[1][1]);
        $n = (int)$out[3][1];
        $bids = array_map(static fn($x) => $x[0] === 's' ? $x[1] : '', array_slice($out, 4, $n));
        return AnalyzerJs::uobj([
            'ok' => true, 'decision' => $d,
            'witness' => $d === 'allow' ? AnalyzerJs::uobj(['gid' => $out[2][1], 'bids' => $bids]) : null,
            'witnessChecked' => $out[4 + $n][1] === 1,
        ]);
    }

    /** The card as a token tape: decodeGoal(renderTape(g)) equals g. @return list<mixed> */
    public static function renderTape(mixed $goal): array
    {
        $out = GoalKernel::kernelCall('render', GoalCodec::encodeGoal($goal));
        if (self::first($out) !== 0) {
            throw new GoalIrError('goal tape rejected');
        }
        return array_slice($out, 1);
    }

    /** Canonical text of a policy (sorted-key JSON, no floats), the input of the policy digest. */
    public static function canonicalPolicy(mixed $p): string
    {
        if ($p instanceof Obj) {
            $keys = array_map('strval', $p->keys());
            usort($keys, AnalyzerJs::u16cmp(...));
            return '{' . implode(',', array_map(static fn(string $k) => GoalNormalize::jq($k) . ':' . self::canonicalPolicy($p->get($k)), $keys)) . '}';
        }
        if (is_array($p) && array_is_list($p)) {
            return '[' . implode(',', array_map(self::canonicalPolicy(...), $p)) . ']';
        }
        return GoalNormalize::jq($p);
    }

    public static function policyDigest(mixed $p): string
    {
        return Pca::b64u(hash('sha256', Js::utf8(self::canonicalPolicy($p)), true));
    }

    /** The review kernel of the reference (`provedKernel`): compile, policy digest and the reference decision, as callables. */
    public static function provedKernel(): Obj
    {
        return AnalyzerJs::uobj([
            'compile' => self::compileGoal(...), 'policyDigest' => self::policyDigest(...), 'decide' => self::decideGoal(...),
        ]);
    }
}
