<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Console;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the operator console projection and the freeze set. */
final class RestSurvivorKill35ConsoleTest extends TestCase
{
    private static function typeError(\Closure $f): string
    {
        try {
            $f();
        } catch (\TypeError $e) {
            return $e->getMessage();
        }
        return 'no TypeError';
    }

    /** A cap chain without a length is refused. */
    public function testChainWithoutLength(): void
    {
        $this->assertSame('cap_chain has no length', self::typeError(static fn() => Console::eventFromPCActn(Obj::of(['cap_chain' => new Obj()]), 'auto')));
    }

    /** An empty chain has no leaf, even when it carries a member at index -1. */
    public function testEmptyChainHasNoLeaf(): void
    {
        $p = Obj::of(['cap_chain' => Obj::of(['length' => 0, '-1' => Obj::of(['holder' => 'evil'])]), 'iat' => 1,
            'action' => Obj::of(['verb' => 'v', 'resource' => 'r'])]);
        $this->assertSame('unknown', Console::eventFromPCActn($p, 'auto')->get('agent'));
    }

    /** Events that are not a list are refused with the reason. */
    public function testEventsMustBeAList(): void
    {
        $this->assertSame('events must be a list', self::typeError(static fn() => Console::buildConsole(['a' => 1])));
        $this->assertSame('events must be a list', self::typeError(static fn() => Console::buildConsole('x')));
    }

    /** The anomalies are a list. */
    public function testAnomaliesAreAList(): void
    {
        $view = Obj::of(['agents' => [Obj::of(['threat' => Obj::of(['level' => 'calm'])]), $hot = Obj::of(['threat' => Obj::of(['level' => 'hot'])])]]);
        $this->assertSame([$hot], Console::anomalies($view));
    }

    /** A string freeze set is split into code points before the agent is added. */
    public function testStringFrozenIsSplit(): void
    {
        $this->assertSame(['a', 'b', 'c'], Console::freezeAgent(Obj::of(['frozen' => 'ab']), 'c')->get('frozen'));
    }

    /** A freeze set without a frozen list is refused by both freeze and unfreeze. */
    public function testMalformedSetIsRefused(): void
    {
        $this->assertSame('freezeAgent: the set has no frozen list', self::typeError(static fn() => Console::freezeAgent(Obj::of(['frozen' => 5]), 'a')));
        $this->assertSame('unfreezeAgent: the set has no frozen list', self::typeError(static fn() => Console::unfreezeAgent(Obj::of(['frozen' => 5]), 'a')));
    }
}
