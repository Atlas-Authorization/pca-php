<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Siem;
use Atlas\Pca\SiemSink;
use Atlas\Pca\SiemTimeout;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The SIEM export module against the TS reference: test-data/ref-siem.json.gz (OCSF / CEF / ECS mapping, scrubError, the HTTP and console sinks, exportBatch). */
final class RefSiemDifferentialTest extends TestCase
{
    private const FILE = 'ref-siem.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function http(Obj $spec): array
    {
        $calls = [];
        $mode = (string)$spec->get('mode');
        $fetch = static function (string $url, array $init) use (&$calls, $mode): array {
            $calls[] = Obj::of(['url' => $url, 'method' => $init['method'], 'headers' => $init['headers'], 'body' => $init['body']]);
            if ($mode === 'ok') {
                return ['ok' => true, 'status' => 200];
            }
            if (str_starts_with($mode, 'st:')) {
                $parts = explode(':', $mode);
                $res = ['ok' => false, 'status' => (int)$parts[1]];
                if (count($parts) > 2) {
                    $res['statusText'] = implode(':', array_slice($parts, 2));
                }
                return $res;
            }
            if (str_starts_with($mode, 'throws:')) {
                throw new \RuntimeException(substr($mode, 7));
            }
            throw new SiemTimeout('hang'); // a collector that never answers: the fetch gives up
        };
        $sink = Siem::httpSink((string)$spec->get('url'), $spec->get('format'), [
            'headers' => $spec->get('headers'), 'contentType' => $spec->get('contentType'), 'name' => $spec->get('name'),
            'timeoutMs' => $spec->get('timeoutMs'), 'fetch' => $fetch,
        ]);
        $events = array_map(static fn($r) => Siem::formatDecision($r, $spec->get('format')), $spec->get('events'));
        $result = ($sink->deliver)($events);
        return ['name' => $sink->name, 'format' => $sink->format, 'result' => $result, 'request' => $calls[0] ?? null];
    }

    private static function console(Obj $spec): array
    {
        $lines = [];
        $logger = static function (string $line) use (&$lines, $spec): void {
            if ($spec->get('throws') !== null) {
                throw new \RuntimeException((string)$spec->get('throws'));
            }
            $lines[] = $line;
        };
        $name = $spec->get('name');
        $sink = Siem::consoleSink($spec->get('format'), $logger, is_string($name) ? $name : null);
        $result = ($sink->deliver)(array_map(static fn($r) => Siem::formatDecision($r, $sink->format), $spec->get('records')));
        return ['name' => $sink->name, 'format' => $sink->format, 'result' => $result, 'lines' => $lines];
    }

    private static function export(Obj $spec): array
    {
        $errors = [];
        $delivered = [];
        $mode = $spec->get('sinkMode');
        $deliver = static function (array $events) use (&$delivered, $mode): array {
            foreach ($events as $e) {
                $delivered[] = $e['line'];
            }
            if ($mode === 'ok') {
                return ['ok' => true];
            }
            if ($mode === 'fail') {
                return ['ok' => false, 'error' => 'collector said no token=abcdef123'];
            }
            if ($mode === 'failNoError') {
                return ['ok' => false];
            }
            throw new \RuntimeException('deliver exploded Bearer abcdefghij');
        };
        $onError = static function (\Throwable $e, array $ctx) use (&$errors, $mode, $spec): void {
            $errors[] = ['message' => $e->getMessage(), 'sink' => $ctx['sink'], 'count' => $ctx['count']];
            if ($mode === 'throwsOnError' || $spec->get('onErrorThrows') === true) {
                throw new \RuntimeException('cb');
            }
        };
        $sink = new SiemSink('s1', $spec->get('format'), \Closure::fromCallable($deliver));
        $result = Siem::exportBatch($spec->get('records'), $sink, $onError, $spec->get('serialize'));
        return ['result' => $result, 'errors' => $errors, 'delivered' => $delivered];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'toOcsfEvent' => fn(array $a) => Siem::toOcsfEvent($a[0], $a[1] ?? null),
            'toCef' => fn(array $a) => Siem::toCef($a[0], $a[1] ?? null),
            'toEcs' => fn(array $a) => Siem::toEcs($a[0], $a[1] ?? null),
            'formatDecision' => fn(array $a) => Siem::formatDecision($a[0], $a[1], $a[2] ?? null),
            'scrubError' => fn(array $a) => Siem::scrubError($a[0]),
            'httpSinkScenario' => fn(array $a) => self::http($a[0]),
            'consoleSinkScenario' => fn(array $a) => self::console($a[0]),
            'exportScenario' => fn(array $a) => self::export($a[0]),
        ]);
    }
}
