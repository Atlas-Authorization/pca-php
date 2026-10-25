<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/**
 * ECMAScript Number::toString of a binary64 (used in refusal reasons that print a number): test-data/jsnum.json holds
 * [IEEE-754 big-endian hex, String(x) in JavaScript] for 3340 values (boundaries 1e21 / 1e-7, shortest-digit cases, powers,
 * random magnitudes and random bit patterns), generated with node. Every implementation (Predicates, IntentV2, IntentWb)
 * must print exactly what JavaScript prints.
 */
final class JsNumberStringKillTest extends TestCase
{
    /** @return list<array{0:float,1:string}> */
    private static function cases(): array
    {
        $raw = json_decode((string) file_get_contents(__DIR__ . '/../test-data/jsnum.json'), true, 512, JSON_THROW_ON_ERROR);
        return array_map(fn($c) => [unpack('E', (string) hex2bin($c[0]))[1], $c[1]], $raw);
    }

    public function testPredicatesPrintsNumbersLikeJavaScript(): void
    {
        $f = new \ReflectionMethod(Predicates::class, 'jsNumStr');
        $bad = [];
        foreach (self::cases() as [$x, $want]) {
            $got = $f->invoke(null, $x);
            if ($got !== $want) {
                $bad[] = "$want <> $got";
            }
        }
        $this->assertSame([], array_slice($bad, 0, 10));
        $this->assertSame('NaN', $f->invoke(null, NAN));
        $this->assertSame('Infinity', $f->invoke(null, INF));
        $this->assertSame('-Infinity', $f->invoke(null, -INF));
        $this->assertSame('0', $f->invoke(null, -0.0));
    }

    public function testIntentV2PrintsNumbersLikeJavaScript(): void
    {
        $bad = [];
        foreach (self::cases() as [$x, $want]) {
            $got = IntentV2::jsNumStr($x);
            if ($got !== $want) {
                $bad[] = "$want <> $got";
            }
        }
        $this->assertSame([], array_slice($bad, 0, 10));
    }

    public function testIntentWbPrintsNumbersLikeJavaScript(): void
    {
        $bad = [];
        foreach (self::cases() as [$x, $want]) {
            $got = IntentWb::jsNumStr($x);
            if ($got !== $want) {
                $bad[] = "$want <> $got";
            }
        }
        $this->assertSame([], array_slice($bad, 0, 10));
        $this->assertSame('NaN', IntentWb::jsNumStr(NAN));
        $this->assertSame('-Infinity', IntentWb::jsNumStr(-INF));
    }
}
