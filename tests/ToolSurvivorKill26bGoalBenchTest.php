<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalBench.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalDisambiguate;
use Atlas\Pca\GoalBench as B;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The compile-widening slice and the review step's extra truth examples. */
final class ToolSurvivorKill26bGoalBenchTest extends TestCase
{
    /** The reference case payments-0000 (its recorded single-model, meet and review levels all accept). */
    private const CASE0 = '{"id":"payments-0000","domain":"payments","template":"refund_duplicate","slots":{"customer":"cus_tu6w","charge":"ch_en8r",'
        . '"max_amount":{"ccy":"USD","minor":71000}},"text":"I need you to duplicate charge cus_tu6w for ch_en8r up to 710.00 USD.","sources":[],"flags":[]}';

    public function testCompileWideningSlice(): void
    {
        self::assertSame(25, B::COMPILE_WIDENING_CASES);
        $c = Json::parseStrict(self::CASE0);
        self::assertCount(B::COMPILE_WIDENING_CASES, B::compileWideningItems(array_fill(0, B::COMPILE_WIDENING_CASES + 1, $c)));
        self::assertCount(2, B::compileWideningItems([$c, $c]));
    }

    /**
     * The review covers the truth's own decision cells too: a truth that also grants reading the customer's charges agrees with every cell of the
     * accepted reading (it only adds a verb the reading never mentions), so only the cells of that extra verb, which the reading denies, catch it.
     */
    public function testReviewIncludesTruthCells(): void
    {
        $c = Json::parseStrict(self::CASE0);
        $comp = B::completionsFrom(B::recordFixtures([$c]));
        $tr = B::truthGoal($c);
        $control = B::evalCase($c, $comp, Obj::of(['truth' => $tr, 'reviewCap' => 1000]));
        self::assertTrue($control->get('accepted')[1]);
        self::assertTrue($control->get('accepted')[2], 'the reading agrees with its own truth on every cell');
        $read = B::truthGoal(Obj::of(['domain' => 'payments', 'template' => 'read_customer_charges', 'slots' => Obj::of(['customer' => 'cus_tu6w']), 'text' => $c->get('text')]));
        $grants = AnalyzerJs::reqList(AnalyzerJs::jget($tr, 'grants'));
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($read, 'grants')) as $g) {
            $g = AnalyzerJs::copy($g);
            $g->set('gid', 'read:' . AnalyzerJs::jsStr($g->get('gid')));
            $grants[] = $g;
        }
        $wider = AnalyzerJs::copy($tr);
        $wider->set('grants', $grants);
        $r = B::evalCase($c, $comp, Obj::of(['truth' => $wider, 'reviewCap' => 1000]));
        self::assertTrue($r->get('accepted')[1]);
        self::assertFalse($r->get('accepted')[2]);
    }

    public function testReviewCap(): void
    {
        self::assertSame(12, B::REVIEW_CAP);
    }

    private static function amountCase(int $minor): Obj
    {
        $c = Json::parseStrict(self::CASE0);
        $c->get('slots')->set('max_amount', Obj::of(['ccy' => 'USD', 'minor' => $minor]));
        return $c;
    }

    /**
     * The truth answers disambiguation questions: three readings capped at $500, $710 and $900 with the truth at $710. Every question splits
     * them one against two; answering by the truth keeps the $710 reading each time, so two questions are asked (swapped answers: one).
     */
    public function testTruthAnswersQuestions(): void
    {
        $c = Json::parseStrict(self::CASE0);
        $truth = B::truthGoal($c);
        $ont = B::truthOnt($c, $truth);
        $answer = (new \ReflectionMethod(B::class, 'truthAnswer'))->invoke(null, $truth, $ont);
        $readings = [];
        foreach (['low' => 50000, 'mid' => 71000, 'high' => 90000] as $id => $minor) {
            $readings[] = Obj::of(['id' => $id, 'goal' => B::truthGoal(self::amountCase($minor))]);
        }
        $res = GoalDisambiguate::disambiguate($readings, $answer, Obj::of(['ont' => $ont]));
        self::assertCount(2, AnalyzerJs::reqList(AnalyzerJs::jget($res, 'asked')));
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($res, 'asked')) as $q) {
            self::assertSame(GoalDisambiguate::allowsWitness($truth, $ont, $q) ? 'allow' : 'deny', $answer($q));
        }
    }
}
