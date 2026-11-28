<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Obligations.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Obligations;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Obligations.php: collect's rule-shape refusals keep their exact verdicts, and the 64-character id bound. */
final class GuardSurvivorKill33ObligationsTest extends TestCase
{
    /** @param array<string,mixed> $over */
    private static function rule(array $over = [], array $drop = []): Obj
    {
        $r = ['id' => 'r', 'when' => new Obj(), 'obligations' => [Obj::of(['kind' => 'log'])]];
        foreach ($drop as $k) {
            unset($r[$k]);
        }
        return Obj::of($over + $r);
    }

    private static function malformed(int $i): array
    {
        return ['ok' => false, 'reason' => "obligation rule $i is malformed"];
    }

    /** A rule that is not an object, or whose id is missing, not a string or empty, is malformed (never an evaluation error). */
    public function testMalformedRules(): void
    {
        $this->assertTrue(Obligations::collect([self::rule()], new Obj())['ok'], 'control');
        $this->assertSame(self::malformed(0), Obligations::collect(['x'], new Obj()));
        $this->assertSame(self::malformed(0), Obligations::collect([new Num('1')], new Obj()));
        $this->assertSame(self::malformed(1), Obligations::collect([self::rule(), self::rule(['id' => new Num('5')])], new Obj()));
        $this->assertSame(self::malformed(0), Obligations::collect([self::rule([], ['id'])], new Obj()));
        $this->assertSame(self::malformed(0), Obligations::collect([self::rule(['id' => ''])], new Obj()));
        $this->assertSame(self::malformed(0), Obligations::collect([self::rule(['id' => str_repeat('a', 65)])], new Obj()));
    }

    /** An id of exactly 64 characters is accepted. */
    public function testSixtyFourCharacterId(): void
    {
        $r = Obligations::collect([self::rule(['id' => str_repeat('a', 64)])], new Obj());
        $this->assertTrue($r['ok']);
        $this->assertCount(1, $r['obligations']);
    }

    /** A repeated id, an empty list and a malformed list are refused with their own reasons. */
    public function testRuleListRefusals(): void
    {
        $this->assertSame(['ok' => false, 'reason' => "obligation rule id 'r' is a duplicate"], Obligations::collect([self::rule(), self::rule()], new Obj()));
        $this->assertSame(['ok' => false, 'reason' => "obligation rule 'r': obligations must not be empty"], Obligations::collect([self::rule(['obligations' => []])], new Obj()));
        $this->assertSame(['ok' => false, 'reason' => "obligation rule 'r': obligations must be an array"], Obligations::collect([self::rule(['obligations' => 'x'])], new Obj()));
    }
}
