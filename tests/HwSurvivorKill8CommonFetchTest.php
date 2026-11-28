<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\JsError;
use Atlas\Pca\Num;
use PHPUnit\Framework\TestCase;

/** Kill tests for Common::fetchJwks: the missing-transport refusal, the 2xx upper bound and a body-less response. */
final class HwSurvivorKill8CommonFetchTest extends TestCase
{
    private static function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('nothing was thrown');
    }

    /** A transport that is not callable is refused with a RuntimeException naming the verifier, never a PHP "not callable" Error. */
    public function testNoTransportIsARuntimeException(): void
    {
        $e = self::thrown(static fn() => Common::fetchJwks('Maa', 'https://x.example/k', null, []));
        $this->assertSame(\RuntimeException::class, $e::class);
        $this->assertSame('Maa: no fetch implementation available', $e->getMessage());
    }

    /** Status 299 is the last accepted code, 300 the first refused (with the status in the text). */
    public function testTheTwoXxRangeEndsAt299(): void
    {
        $ok = static fn(mixed $status): callable => static fn(string $u): array => ['status' => $status, 'body' => '{"keys":[]}'];
        $this->assertSame([], Common::fetchJwks('W', 'u', $ok(299), [])->get('keys'));
        $this->assertSame([], Common::fetchJwks('W', 'u', $ok(new Num('299')), [])->get('keys'));
        $this->assertSame([], Common::fetchJwks('W', 'u', $ok(200), [])->get('keys'));
        $e = self::thrown(static fn() => Common::fetchJwks('W', 'https://h/k', $ok(300), []));
        $this->assertSame(\RuntimeException::class, $e::class);
        $this->assertSame('W fetch failed: HTTP 300 for https://h/k', $e->getMessage());
        $e = self::thrown(static fn() => Common::fetchJwks('W', 'u', $ok(199), []));
        $this->assertSame('W fetch failed: HTTP 199 for u', $e->getMessage());
    }

    /** A 2xx response without a body is a JSON parse refusal (JsError), not a PHP TypeError from a null argument. */
    public function testAMissingBodyIsAJsonRefusal(): void
    {
        $e = self::thrown(static fn() => Common::fetchJwks('W', 'u', static fn(string $u): array => ['status' => 200], []));
        $this->assertInstanceOf(JsError::class, $e);
    }
}
