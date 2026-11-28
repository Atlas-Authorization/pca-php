<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AnalyzerCore;
use Atlas\Pca\Json;
use Atlas\Pca\SafeRegex;
use PHPUnit\Framework\TestCase;

/**
 * The relation walk's shortcuts never change a result: the admits(a, cell) memo shared across partners (the coverage mutant
 * loop) agrees with fresh walks in either order, and the dead-block skip (taken only outside a regex budget scope) agrees with
 * the plain walk that runs inside one. The reference corpus checks the outputs themselves.
 */
final class AnalyzerGridMemoTest extends TestCase
{
    private const A = '{"predicates":[{"verb":"pay","where":[{"field":"action.params.amount","op":"lte","value":100}]},'
        . '{"verb":"refund","resource":"/orders/*"}],"caveats":[{"type":"reversibility_max","class":"rate_limited"}],'
        . '"vetoes":[{"id":"big","kind":"deny","when":{"verb":"pay","where":[{"field":"action.params.amount","op":"gt","value":50}]},'
        . '"unless":[{"field":"env.ok","op":"eq","value":true}]}]}';

    /** @return list<mixed> partners of A: itself, a raised cap, a dropped veto, a dropped permit, an unreachable policy */
    private static function partners(): array
    {
        return array_map(static fn(string $j): mixed => Json::parseLax($j), [
            self::A,
            str_replace('"value":100', '"value":101', self::A),
            str_replace(',"vetoes":[{"id":"big","kind":"deny","when":{"verb":"pay","where":[{"field":"action.params.amount","op":"gt","value":50}]},'
                . '"unless":[{"field":"env.ok","op":"eq","value":true}]}]', '', self::A),
            str_replace(',{"verb":"refund","resource":"/orders/*"}', '', self::A),
            '{"predicates":[{"verb":"read"}],"caveats":[{"type":"not_before","at":2},{"type":"expires","at":1}]}',
        ]);
    }

    public function testMemoAcrossPartnersAgreesWithFreshWalks(): void
    {
        $a = Json::parseLax(self::A);
        $fresh = array_map(static fn(mixed $b) => AnalyzerCore::equivalent($a, $b), self::partners());
        foreach ([self::partners(), array_reverse(self::partners(), true)] as $order) {
            $memo = new \ArrayObject();
            foreach ($order as $i => $b) {
                self::assertEquals($fresh[$i], AnalyzerCore::equivalentMemo($a, $b, null, $memo), "partner $i");
            }
            self::assertGreaterThan(0, count($memo));
        }
    }

    public function testDeadBlockSkipAgreesWithThePlainWalk(): void
    {
        $a = Json::parseLax(self::A);
        foreach (self::partners() as $i => $b) {
            foreach (['equivalent', 'subsumes', 'disjoint'] as $rel) {
                foreach ([[$a, $b], [$b, $a]] as [$x, $y]) {
                    $plain = SafeRegex::requestBudget()->run(static fn() => AnalyzerCore::$rel($x, $y));
                    self::assertEquals($plain, AnalyzerCore::$rel($x, $y), "$rel, partner $i");
                }
            }
        }
    }
}
