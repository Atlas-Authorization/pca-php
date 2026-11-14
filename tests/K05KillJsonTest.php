<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Num;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Json::canonicalizeLenient: its two refusals throw a JsonError with the exact message. */
final class K05KillJsonTest extends TestCase
{
    public function testLenientCanonicalRefusesNonFiniteAndUnsupportedValues(): void
    {
        foreach ([INF, -INF, NAN, new Num('1e999'), [1, INF]] as $v) {
            try {
                Json::canonicalizeLenient($v);
                $this->fail('a non-finite number must be refused');
            } catch (JsonError $e) {
                $this->assertSame('canonicalize: non-finite number', $e->getMessage());
            }
        }
        foreach ([[new \stdClass(), 'stdClass'], [['a' => 1], 'array'], [[fopen('php://memory', 'r')], 'resource (stream)']] as [$v, $type]) {
            try {
                Json::canonicalizeLenient($v);
                $this->fail("$type must be refused");
            } catch (JsonError $e) {
                $this->assertSame('canonicalize: unsupported type ' . $type, $e->getMessage());
            }
        }
        $this->assertSame('[1,1.5]', Json::canonicalizeLenient([1, 1.5]));
    }
}
