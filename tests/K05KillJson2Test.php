<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Json (round 2): lenient string escaping (every match arm, lone-surrogate bits) and the parser's end checks. */
final class K05KillJson2Test extends TestCase
{
    public function testLenientEscapesEveryShortFormAndTheDefault(): void
    {
        $this->assertSame('"\\"\\\\\\b\\f\\n\\r\\t\\u0001"', Json::canonicalizeLenient("\"\\\x08\x0c\n\r\t\x01"));
    }

    /** A lone surrogate keeps all six payload bits of both continuation bytes: ED A1 81 -> U+D841. */
    public function testLenientLoneSurrogateKeepsEveryPayloadBit(): void
    {
        $this->assertSame('"\\ud841"', Json::canonicalizeLenient("\xED\xA1\x81"));
        $this->assertSame('"\\udfbf"', Json::canonicalizeLenient("\xED\xBE\xBF"));
    }

    public function testLenientIntegers(): void
    {
        $this->assertSame('0', Json::canonicalizeLenient(0));
        $this->assertSame('-7', Json::canonicalizeLenient(-7));
    }

    public function testUnterminatedStringReportsTheEndOffset(): void
    {
        foreach (['"' => 1, '"ab' => 3, "\"\\n" => 3] as $text => $at) {
            try {
                Json::parseLax((string)$text);
                $this->fail("$text must be refused");
            } catch (JsonError $e) {
                $this->assertSame("unterminated string at byte $at", $e->getMessage());
            }
        }
    }
}
