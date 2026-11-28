<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Otel.php';

use Atlas\Pca\Otel;
use PHPUnit\Framework\TestCase;

/** Group 36a mutation kills for src/Otel.php: redaction input, URL userinfo, the 256-character cut, assoc results and error class names. */
final class RestSurvivorKill36aOtelTest extends TestCase
{
    /** A non-string value is turned into its text before redaction, never a type error. */
    public function testNonStringIsRedactedAsItsText(): void
    {
        self::assertSame('12345', Otel::redactSecrets(12345));
    }

    /** URL userinfo with a password is redacted; a user name without a password is left alone. */
    public function testUrlUserinfoNeedsUserAndPassword(): void
    {
        self::assertSame('see https://[redacted]@host/x', Otel::redactSecrets('see https://user:pw@host/x'));
        self::assertSame('see https://user@host/x', Otel::redactSecrets('see https://user@host/x'));
    }

    /** Text of exactly 256 characters is kept whole; one more is cut to 256 and marked. */
    public function testCutStartsAbove256Characters(): void
    {
        $s = str_repeat('a ', 128);
        self::assertSame($s, Otel::redactSecrets($s));
        self::assertSame($s . '...', Otel::redactSecrets($s . 'b'));
    }

    /** A guard result given as an assoc array is read like an object. */
    public function testAssocResultIsRead(): void
    {
        self::assertSame(['pca.decision' => 'allow', 'pca.status' => 200], Otel::pcaSpanAttributes(['ok' => true, 'status' => 200]));
    }

    /** A thrown guard error is recorded under its own short class name; a name that is not a plain identifier becomes "Error". */
    public function testRecordedErrorKeepsAPlainClassName(): void
    {
        $span = new class {
            /** @var list<\Throwable> */
            public array $recorded = [];

            public function setAttribute(string $k, mixed $v): void
            {
            }

            public function setStatus(array $s): void
            {
            }

            public function recordException(\Throwable $e): void
            {
                $this->recorded[] = $e;
            }

            public function end(): void
            {
            }
        };
        $tracer = new class ($span) {
            public function __construct(private object $span)
            {
            }

            public function startSpan(string $n): object
            {
                return $this->span;
            }
        };
        foreach ([[new \RuntimeException('boom'), 'RuntimeException'], [new class ('boom') extends \RuntimeException {
        }, 'Error']] as [$err, $want]) {
            $g = Otel::instrumentGuard(static fn() => throw $err, ['tracer' => $tracer]);
            try {
                $g();
                self::fail('the guard error was swallowed');
            } catch (\RuntimeException $e) {
                self::assertSame($err, $e);
            }
            $rec = array_pop($span->recorded);
            self::assertSame([$want, 'boom'], [$rec->name, $rec->getMessage()]);
        }
    }
}
