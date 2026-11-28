<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalCard.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalCard;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/GoalCard.php: the per-clause phrase helpers are public API, and an idle limit of 1 ms is printed. */
final class RestSurvivorKill36cGoalCardTest extends TestCase
{
    /** The phrase helpers are callable from outside the class and print the fixed phrases. */
    public function testPhraseHelpersArePublic(): void
    {
        $qty = Obj::of(['k' => 'q', 'q' => Obj::of(['n' => 5, 'u' => Obj::of(['k' => 'count'])])]);
        $this->assertSame('undefined', GoalCard::q(AnalyzerJs::undef()));
        $this->assertSame('USD minor units', GoalCard::unit(Obj::of(['k' => 'money', 'ccy' => 'USD'])));
        $this->assertSame('5 count', GoalCard::value($qty));
        $this->assertSame('5 count', GoalCard::term(Obj::of(['k' => 'lit', 'v' => $qty])));
        $this->assertSame('per task', GoalCard::win(Obj::of(['k' => 'task'])));
        $this->assertSame('self', GoalCard::scope(Obj::of(['k' => 'self'])));
        $this->assertSame('ASK THE PRINCIPAL when always', GoalCard::escalateLine(Obj::of(['k' => 'true'])));
    }

    /** Any idle limit above 0 is printed, including 1 ms; 0 is none. */
    public function testIdleLimitOfOneMs(): void
    {
        $this->assertSame('VALID from 0 to 10; idle limit 1 ms', GoalCard::validityLine(Obj::of(['notBefore' => 0, 'notAfter' => 10, 'maxIdle' => 1])));
        $this->assertSame('VALID from 0 to 10; idle limit none', GoalCard::validityLine(Obj::of(['notBefore' => 0, 'notAfter' => 10, 'maxIdle' => 0])));
    }
}
