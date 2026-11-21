<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Otel;
use Atlas\Pca\TelemetryError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The OpenTelemetry instrumentation against the TS reference: test-data/ref-otel.json.gz (redactSecrets, pcaSpanAttributes, instrumentGuard over scripted tracers / meters / guards). */
final class RefOtelDifferentialTest extends TestCase
{
    private const FILE = 'ref-otel.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function mode(mixed $m): ?\Closure
    {
        return match ($m) {
            'identity' => static fn(string $s): string => $s,
            'upper' => static fn(string $s): string => mb_strtoupper($s, 'UTF-8'),
            'brackets' => static fn(string $s): string => "<$s>",
            default => null,
        };
    }

    private static function scenario(Obj $spec): array
    {
        $events = [];
        $tm = $spec->get('tracerMode') ?: 'ok';
        $mm = $spec->get('meterMode') ?: 'ok';
        $boom = static function (bool $cond): void {
            if ($cond) {
                throw new \RuntimeException('exporter boom');
            }
        };
        $span = new class($events, $tm, $boom) {
            public function __construct(private array &$events, private string $tm, private \Closure $boom)
            {
            }

            public function setAttribute(string $k, mixed $v): void
            {
                $this->events[] = ['ev' => 'setAttribute', 'k' => $k, 'v' => $v];
                ($this->boom)($this->tm === 'attrThrows');
            }

            public function setStatus(array $s): void
            {
                $e = ['ev' => 'setStatus', 'code' => $s['code']];
                if (array_key_exists('message', $s)) {
                    $e['message'] = $s['message'];
                }
                $this->events[] = $e;
                ($this->boom)($this->tm === 'statusThrows');
            }

            public function recordException(\Throwable $e): void
            {
                $this->events[] = ['ev' => 'recordException', 'message' => $e->getMessage(), 'noStack' => $e instanceof TelemetryError && $e->getPrevious() === null];
                ($this->boom)($this->tm === 'recordThrows');
            }

            public function end(): void
            {
                $this->events[] = ['ev' => 'end'];
                ($this->boom)($this->tm === 'endThrows');
            }
        };
        $tracer = new class($events, $tm, $boom, $span) {
            public function __construct(private array &$events, private string $tm, private \Closure $boom, private object $span)
            {
            }

            public function startSpan(string $name): object
            {
                $this->events[] = ['ev' => 'startSpan', 'name' => $name];
                ($this->boom)($this->tm === 'startThrows');
                return $this->span;
            }
        };
        $counter = new class($events, $mm, $boom) {
            public function __construct(private array &$events, private string $mm, private \Closure $boom)
            {
            }

            public function add(mixed $v, array $a): void
            {
                $this->events[] = ['ev' => 'add', 'v' => $v, 'a' => $a];
                ($this->boom)($this->mm === 'addThrows');
            }
        };
        $histogram = new class($events, $mm, $boom) {
            public function __construct(private array &$events, private string $mm, private \Closure $boom)
            {
            }

            public function record(mixed $v, array $a): void
            {
                $this->events[] = ['ev' => 'record', 'v' => $v, 'a' => $a];
                ($this->boom)($this->mm === 'recordThrows');
            }
        };
        $meter = new class($events, $mm, $boom, $counter, $histogram) {
            public function __construct(private array &$events, private string $mm, private \Closure $boom, private object $counter, private object $histogram)
            {
            }

            public function createCounter(string $name): object
            {
                $this->events[] = ['ev' => 'createCounter', 'name' => $name];
                ($this->boom)($this->mm === 'createThrows');
                return $this->counter;
            }

            public function createHistogram(string $name): object
            {
                $this->events[] = ['ev' => 'createHistogram', 'name' => $name];
                return $this->histogram;
            }
        };
        $g = $spec->get('guard');
        $guard = static function (mixed $req) use ($g) {
            if ($g->has('throws')) {
                throw new \RuntimeException((string)$g->get('throws'));
            }
            return $g->get('result');
        };
        try {
            $wrapped = Otel::instrumentGuard($guard, [
                'tracer' => $spec->get('tracer') === true ? $tracer : null, 'meter' => $spec->get('meter') === true ? $meter : null,
                'spanName' => $spec->get('spanName'), 'redact' => $spec->get('redact') ? self::mode($spec->get('redact')) : null,
            ]);
        } catch (\Throwable $e) {
            return ['wrap' => $e->getMessage(), 'events' => $events];
        }
        try {
            $outcome = ['result' => $wrapped('req')];
        } catch (\Throwable $e) {
            $outcome = ['threw' => $e->getMessage()];
        }
        return ['outcome' => $outcome, 'events' => $events];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'redactSecrets' => fn(array $a) => Otel::redactSecrets($a[0]),
            'pcaSpanAttributes' => fn(array $a) => Otel::pcaSpanAttributes($a[0], self::mode($a[1] ?? null)),
            'instrumentScenario' => fn(array $a) => self::scenario($a[0]),
        ]);
    }
}
