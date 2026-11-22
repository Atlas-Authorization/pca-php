<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentWb.php';

use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for src/IntentWb.php: the strict canonical form renders every number through Number::toString
 * (integral values at the safe-integer edge included); verifyArtifactSig reads members of a real Obj only (a host object
 * with has/get is not one), and a non-Obj pin is a bare Ed25519 key with no PQ pin.
 */
final class K05KillIntentWb2Test extends TestCase
{
    private static function wb(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentWbKillTest::class, $m))->invokeArgs(null, $a);
    }

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    }

    /** A host object with keys/has/get that is NOT an Obj. */
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

    public function testCanonRendersNumbersByValue(): void
    {
        $this->assertSame('[0,5,-5,9007199254740991,-9007199254740991,100,0.5,1.25]', IntentWb::canon([new Num('0.0'), new Num('5.0'),
            new Num('-5e0'), new Num('9007199254740991.0'), new Num('-9007199254740991'), new Num('1e2'), new Num('0.50'), 1.25]));
    }

    public function testVerifyArtifactSigNeedsARealObjArtifact(): void
    {
        $f = self::wb('fact', 'o1', 5);
        [$pk] = self::wb('kp', 'o1');
        $this->assertTrue(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, self::o($f), $pk), 'control');
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, self::lookalike($f), $pk));
    }
}
