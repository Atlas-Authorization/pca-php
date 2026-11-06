<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Predicates (round 2): a predicate and an action must be JSON objects, not lookalikes. */
final class K05KillPredicates2Test extends TestCase
{
    /** A host value that only looks like an Obj (keys / has / get) is not a JSON object. */
    private static function lookalike(array $d): object
    {
        return new class ($d) {
            public function __construct(private readonly array $d)
            {
            }

            public function keys(): array
            {
                return array_map('strval', array_keys($this->d));
            }

            public function has(string $k): bool
            {
                return array_key_exists($k, $this->d);
            }

            public function get(string $k): mixed
            {
                return $this->d[$k] ?? null;
            }
        };
    }

    public function testALookalikePredicateOrActionDoesNotMatch(): void
    {
        $ctx = Json::parseLax('{"action":{"verb":"pay","resource":"acct"}}');
        $p = Json::parseLax('{"verb":"pay"}');
        $this->assertTrue(Predicates::predicateMatches($p, $ctx), 'control');
        $this->assertFalse(Predicates::predicateMatches(self::lookalike(['verb' => 'pay']), $ctx));
        $this->assertFalse(Predicates::predicateMatches($p,
            Obj::of(['action' => self::lookalike(['verb' => 'pay', 'resource' => 'acct'])])));
    }
}
