<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\SafeRegex;
use Atlas\Pca\SafeRegexBudget;
use PHPUnit\Framework\TestCase;

/**
 * Differential tests of SafeRegex.php against the TS reference (safe-regex.ts, predicates.ts isSafeRegexSource,
 * regex-budget.ts). test-data/killRegex.json.gz is the shared oracle (tools/pca-audit/kotlin-mutate/killRegex-oracle-gen.mjs):
 * full-match results (true / false / refused) of a pattern corpus crossed with boundary subjects, compiled sizes, the step
 * boundary, the safe-source guard and per-document budget sequences.
 */
final class RegexDifferentialKillTest extends TestCase
{
    private static ?Obj $data = null;

    private static function data(): Obj
    {
        return self::$data ??= Json::parseLax(gzdecode((string) file_get_contents(__DIR__ . '/../test-data/killRegex.json.gz')));
    }

    private static function i(mixed $v): int
    {
        return $v instanceof Num ? $v->int() : (int) $v;
    }

    private static function want(int $r): ?bool
    {
        return $r < 0 ? null : $r === 1;
    }

    public function testFullMatchAgreesWithTheReference(): void
    {
        $n = 0;
        foreach (self::data()->get('fm') as [$p, $subs, $rs]) {
            $this->assertSame(count($subs), strlen($rs), "/$p/");
            foreach ($subs as $k => $s) {
                $want = $rs[$k] === 'n' ? null : $rs[$k] === '1';
                $got = SafeRegex::fullMatch($p, $s);
                if ($got !== $want) {
                    $this->assertSame($want, $got, '/' . $p . '/ on ' . json_encode($s));
                }
                $n++;
            }
        }
        $this->assertGreaterThan(100000, $n);
    }

    public function testCompiledSizesAgree(): void
    {
        foreach (self::data()->get('size') as [$p, $want]) {
            $got = SafeRegex::progLen($p);
            $want = self::i($want);
            $this->assertSame($want < 0 ? null : $want, $got, "/$p/");
        }
    }

    public function testStepBoundaryAgrees(): void
    {
        $this->assertSame(4096, SafeRegex::MAX_NFA_INSTRUCTIONS);
        $this->assertSame(64, SafeRegex::MAX_REPEAT);
        $this->assertSame(2000000, SafeRegex::MAX_MATCH_STEPS);
        foreach (self::data()->get('steps') as [$p, $n, $r]) {
            $n = self::i($n);
            $this->assertSame(self::want(self::i($r)), SafeRegex::fullMatch($p, str_repeat('a', $n)), '/' . substr($p, 0, 20) . "/ n=$n");
        }
    }

    public function testSafeSourceGuardAgrees(): void
    {
        $safe = self::data()->get('safe');
        $this->assertGreaterThan(500, count($safe));
        foreach ($safe as [$p, $want]) {
            $got = SafeRegex::isSafeRegexSource($p);
            if ($got !== $want) {
                $this->assertSame($want, $got, "/$p/");
            }
        }
    }

    public function testBudgetSequencesAgree(): void
    {
        foreach (self::data()->get('budgets') as $k => $b) {
            $budget = new SafeRegexBudget();
            $res = $b->get('res');
            foreach ($b->get('ops') as $i => [$src, $len]) {
                $this->assertSame($res[$i], $budget->charge($src, self::i($len)), "budget #$k op $i");
            }
            [$ev, $chars, $steps, $ref] = $b->get('fin');
            $this->assertSame(self::i($ev), $budget->evaluations, "budget #$k evaluations");
            $this->assertSame(self::i($chars), $budget->chars, "budget #$k chars");
            $this->assertSame(self::i($steps), $budget->steps, "budget #$k steps");
            $this->assertSame(self::i($ref), $budget->refusals, "budget #$k refusals");
        }
    }
}
