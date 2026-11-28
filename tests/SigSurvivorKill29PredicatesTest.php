<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/** Mutation kills for Predicates: mayMatchVerbResource's verb/resource steps and predicatesAllow's refusals. */
final class SigSurvivorKill29PredicatesTest extends TestCase
{
    private static function p(array $m): Obj
    {
        return Obj::of($m);
    }

    public function testMayMatchVerbResource(): void
    {
        $this->assertFalse(Predicates::mayMatchVerbResource('x', 'v', 'r'), 'predicates must be a list');
        $this->assertFalse(Predicates::mayMatchVerbResource([], 'v', 5), 'resource must be text');
        $this->assertTrue(Predicates::mayMatchVerbResource([self::p(['verb' => 'v', 'resource' => 'r'])], 'v', 'r'), 'control');
        $this->assertTrue(Predicates::mayMatchVerbResource([self::p(['verb' => 'v'])], 'v', 'r'), 'no resource member: any resource');
        $this->assertFalse(Predicates::mayMatchVerbResource([self::p(['verb' => 'other', 'resource' => 'r'])], 'v', 'r'), 'the verb must match');
        $this->assertFalse(Predicates::mayMatchVerbResource([self::p(['verb' => 'v', 'resource' => 'other'])], 'v', 'r'), 'the resource must match');
        $this->assertTrue(Predicates::mayMatchVerbResource([self::p(['verb' => 'v', 'resource' => 're:zzz'])], 'v', 'r'), 'a regex resource may match');
        $this->assertFalse(Predicates::mayMatchVerbResource(['x', self::p(['verb' => 'v', 'resource' => 'other'])], 'v', 'r'));
    }

    public function testPredicatesAllow(): void
    {
        $ctx = Obj::of(['action' => Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => new Obj()])]);
        $this->assertTrue(Predicates::predicatesAllow([self::p(['verb' => 'v', 'resource' => 'r'])], $ctx), 'control');
        $this->assertFalse(Predicates::predicatesAllow('x', $ctx));
        $this->assertFalse(Predicates::predicatesAllow([], $ctx));
        $this->assertFalse(Predicates::predicatesAllow([self::p(['verb' => 'other', 'resource' => 'r'])], $ctx));
    }
}
