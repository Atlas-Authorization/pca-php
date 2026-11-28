<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Js.php';

use Atlas\Pca\Js;
use Atlas\Pca\JsonError;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Js.php: the stringify / spread refusals, and the parseNoDuplicates depth cap and named duplicate. */
final class GuardSurvivorKill33JsTest extends TestCase
{
    /** A value JSON.stringify cannot write is a TypeError naming its type. */
    public function testStringifyRefusesAnUnsupportedValue(): void
    {
        $this->assertSame('[]', Js::stringify([]), 'control: an empty list stringifies');
        try {
            Js::stringify(new \stdClass());
            $this->fail('stdClass stringified');
        } catch (\TypeError $e) {
            $this->assertSame('JSON.stringify: unsupported stdClass', $e->getMessage());
        }
    }

    /** Spreading a non-iterable is the reference's TypeError, not a return-type error. */
    public function testSpreadRefusesANonIterable(): void
    {
        $this->assertSame(['a', 'b'], Js::spread('ab'), 'control');
        try {
            Js::spread(5);
            $this->fail('a number spread');
        } catch (\TypeError $e) {
            $this->assertSame('value is not iterable', $e->getMessage());
        }
    }

    /** parseNoDuplicates nests exactly 4096 levels, refuses 4097, and names a repeated key the reference's way. */
    public function testParseNoDuplicatesDepthAndDuplicateText(): void
    {
        $deep = static fn(int $n): string => str_repeat('[', $n) . str_repeat(']', $n);
        $v = Js::parseNoDuplicates($deep(4096));
        $this->assertIsArray($v);
        try {
            Js::parseNoDuplicates($deep(4097));
            $this->fail('4097 levels parsed');
        } catch (JsonError $e) {
            $this->assertStringStartsWith('nesting too deep', $e->getMessage());
        }
        try {
            Js::parseNoDuplicates('{"a":1,"a":2}');
            $this->fail('a duplicate key parsed');
        } catch (JsonError $e) {
            $this->assertSame('duplicate key "a"', $e->getMessage());
        }
    }
}
