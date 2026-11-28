<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Siem;
use PHPUnit\Framework\TestCase;

/** SIEM export: record reads, UTF-16 slicing and surrogate halves, the ISO timestamp, the clock, overrides, scrubbing, the HTTP sink and batch export. */
final class ToolSurvivorKill18SiemTest extends TestCase
{
    private const EPOCH = '1970-01-01T00:00:00.000Z';

    protected function tearDown(): void
    {
        Siem::$clockHook = null;
    }

    /** Runs $f with every reported (not @-suppressed) warning or notice turned into an exception. */
    private static function noWarnings(\Closure $f): mixed
    {
        set_error_handler(static function (int $no, string $msg): bool {
            if ((error_reporting() & $no) === 0) {
                return false;
            }
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    private static function rec(array $o = []): array
    {
        return $o + ['pcactn' => ['grant_ref' => 'g1', 'cap_chain' => [['issuer' => 'root', 'holder' => 'agent']]], 'verify' => ['allow' => true], 'now' => 5];
    }

    // ---- record reads -------------------------------------------------------------------------------------------------

    public function testAssocArrayRecordMembersAreReadAndAbsentOnesAreQuiet(): void
    {
        $ev = self::noWarnings(static fn() => Siem::toEcs(self::rec()));
        $this->assertSame('allow', $ev['pca']['outcome']);
        $this->assertSame('g1', $ev['pca']['grant_ref']);
        $this->assertSame('agent', $ev['user']['id']);
        $this->assertSame('(unknown verb)', $ev['event']['action']);
    }

    public function testRecordIsRequired(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('record is required');
        Siem::toOcsfEvent(null);
    }

    // ---- UTF-16 slicing and surrogate halves --------------------------------------------------------------------------

    public function testU16sliceCutsAnAstralCharacterToItsHighSurrogateAndStops(): void
    {
        $this->assertSame("\xED\xA0\xBD", Siem::u16slice("\u{1F600}", 1));
        $this->assertSame("\xED\xA0\x80", Siem::u16slice("\u{10000}", 1));
        $this->assertSame("\xED\xAF\xBF", Siem::u16slice("\u{10FFFF}", 1));
        $this->assertSame(str_repeat('a', 11) . "\xED\xA0\xBD", Siem::u16slice(str_repeat('a', 11) . "\u{1F600}b", 12));
        $this->assertSame("a\u{1F600}", Siem::u16slice("a\u{1F600}", 3));
        $this->assertSame('ab', Siem::u16slice('abc', 2));
        $this->assertSame('ab', Siem::u16slice('ab', 5));
    }

    private static function cs5(mixed $checks): string
    {
        $line = Siem::toCef(self::rec(['verify' => ['allow' => true, 'checks' => $checks]]));
        preg_match('/ cs5=(.*) cs6Label=/s', $line, $m);
        return $m[1];
    }

    public function testStringChecksAreListedByUtf16UnitWithBothSurrogateHalves(): void
    {
        $this->assertSame(
            "0:x;1:\xED\xA0\xBD;2:\xED\xB8\x80;3:\xED\xA0\x80;4:\xED\xB0\x80;5:\xED\xAF\xBF;6:\xED\xBF\xBF",
            self::noWarnings(static fn() => self::cs5("x\u{1F600}\u{10000}\u{10FFFF}")),
        );
    }

    public function testListAndAssocChecksAreListed(): void
    {
        $this->assertSame('0:pass;1:fail', self::noWarnings(static fn() => self::cs5(['pass', 'fail'])));
        $this->assertSame('wire:pass;replay:fail', self::noWarnings(static fn() => self::cs5(['wire' => 'pass', 'replay' => 'fail'])));
    }

    public function testShortKeyKeepsThirteenUnitsAndCutsFourteen(): void
    {
        $name = static fn(string $h): string => Siem::toOcsfEvent(self::rec(['pcactn' => ['cap_chain' => [['issuer' => 'root', 'holder' => $h]]]]))['actor']['user']['name'];
        $this->assertSame('abcdefghijklm', $name('abcdefghijklm'));
        $this->assertSame('abcdefghijkl…', $name('abcdefghijklmn'));
    }

    // ---- ISO timestamps -----------------------------------------------------------------------------------------------

    public function testIsoTimestamps(): void
    {
        $cases = [
            [951868799999, '2000-02-29T23:59:59.999Z'], [951868860000, '2000-03-01T00:01:00.000Z'],
            [-8515238400000, '1700-03-01T00:00:00.000Z'], [-5333167769500, '1800-12-31T12:30:30.500Z'],
            [253402300799999, '9999-12-31T23:59:59.999Z'], [1795774272013, '2026-11-27T10:11:12.013Z'],
            [-62135596800000, '0001-01-01T00:00:00.000Z'], [-2203977600000, '1900-02-28T00:00:00.000Z'],
            [4107542400000, '2100-03-01T00:00:00.000Z'], [-1, '1969-12-31T23:59:59.999Z'],
            [8640000000000000, '+275760-09-13T00:00:00.000Z'], [-8640000000000000, '-271821-04-20T00:00:00.000Z'],
            [8640000000000001, self::EPOCH], [-8640000000000001, self::EPOCH],
            [-62198755200000, '-000001-01-01T00:00:00.000Z'], [0, self::EPOCH], [13574563200000, '2400-02-29T00:00:00.000Z'],
            [-11670912000000, '1600-03-01T00:00:00.000Z'], [929404800000, '1999-06-15T00:00:00.000Z'],
            [15638400000, '1970-07-01T00:00:00.000Z'], [2592000000, '1970-01-31T00:00:00.000Z'],
            [-62167219200000, '0000-01-01T00:00:00.000Z'],
        ];
        foreach ($cases as [$ms, $want]) {
            $this->assertSame($want, Siem::toEcs(self::rec(['pcactn' => ['iat' => $ms]]))['@timestamp'], (string)$ms);
        }
    }

    public function testANonNumericClockReadingStampsTheEpoch(): void
    {
        $ev = Siem::toEcs(['pcactn' => [], 'verify' => ['allow' => true]], null, static fn(): string => 'x');
        $this->assertSame(self::EPOCH, $ev['@timestamp']);
    }

    // ---- the clock ----------------------------------------------------------------------------------------------------

    public function testClockSources(): void
    {
        $logged = static fn(mixed $now, array $r = ['verify' => ['allow' => true]]): mixed => Siem::toOcsfEvent($r, null, $now)['metadata']['logged_time'];
        $this->assertSame(42, $logged(static fn(): int => 42));
        $this->assertSame(7, $logged(7));
        $this->assertSame(5, $logged(7, ['verify' => ['allow' => true], 'now' => 5]));
        Siem::$clockHook = static fn(): float => 1234.5678;
        $this->assertSame(1234567, $logged(null));
        $this->assertSame(1234567, $logged('later'));
    }

    // ---- human override -----------------------------------------------------------------------------------------------

    public function testOnlyAPrincipalShareIsAHumanApproval(): void
    {
        $ev = static fn(array $shares): array => Siem::toOcsfEvent(self::rec([
            'pcactn' => ['cap_chain' => [['issuer' => 'root', 'holder' => 'agent']], 'threshold' => ['shares' => $shares]],
            'verify' => ['allow' => true, 'checks' => ['threshold' => 'pass']],
        ]))['unmapped'];
        $this->assertArrayNotHasKey('human_override', $ev([['role' => 'guardian', 'publicKey' => 'gk']]));
        $this->assertSame(
            ['human_approved' => true, 'approvers' => ['pk'], 'guardian_cosigners' => ['gk'], 'roles' => ['principal', 'guardian']],
            $ev([['role' => 'principal', 'publicKey' => 'pk'], ['role' => 'guardian', 'publicKey' => 'gk']])['human_override'],
        );
    }

    // ---- scrubbing ----------------------------------------------------------------------------------------------------

    public function testScrubErrorTextAndLength(): void
    {
        $this->assertSame('42', Siem::scrubError(42));
        $s300 = str_repeat('a ', 150);
        $this->assertSame($s300, Siem::scrubError($s300));
        $this->assertSame($s300 . '...', Siem::scrubError($s300 . 'b'));
    }

    // ---- the HTTP sink ------------------------------------------------------------------------------------------------

    private static function deliver(string $url, mixed $fmt, array $opts, array $events = [['line' => 'a'], ['line' => 'b']]): mixed
    {
        $sink = Siem::httpSink($url, $fmt, $opts);
        return self::noWarnings(static fn() => ($sink->deliver)($events));
    }

    public function testFetchResultShapes(): void
    {
        $this->assertSame(['ok' => true], self::deliver('u', 'ocsf', ['fetch' => static fn() => Obj::of(['ok' => true])]));
        $this->assertSame(['ok' => true], self::deliver('u', 'ocsf', ['fetch' => static fn() => (object)['ok' => true]]));
        $this->assertSame(['ok' => false, 'error' => 'HTTP 503'], self::deliver('u', 'ocsf', ['fetch' => static fn() => (object)['ok' => false, 'status' => 503]]));
        $this->assertSame(['ok' => false, 'error' => 'HTTP null'], self::deliver('u', 'ocsf', ['fetch' => static fn() => 5]));
    }

    public function testRequestHeadersBodyAndTimeout(): void
    {
        $seen = [];
        $fetch = static function (string $url, array $init) use (&$seen): array {
            $seen = $init;
            return ['ok' => true];
        };
        $this->assertSame(['ok' => true], self::deliver('u', 'ocsf', ['fetch' => $fetch, 'headers' => [5 => 'five', 'x-a' => 'b']]));
        $this->assertSame('POST', $seen['method']);
        $this->assertSame("a\nb", $seen['body']);
        $this->assertSame(['content-type', '5', 'x-a'], $seen['headers']->keys());
        $this->assertSame('application/x-ndjson', $seen['headers']->get('content-type'));
        $this->assertSame('five', $seen['headers']->get('5'));
        $this->assertSame(10.0, $seen['timeout']);
        foreach ([[500, 0.5], [0, 10.0], [-5, 10.0], ['x', 10.0], [INF, 10.0], [2500.0, 2.5]] as [$ms, $secs]) {
            $seen = [];
            $this->assertSame(['ok' => true], self::deliver('u', 'ocsf', ['fetch' => $fetch, 'timeoutMs' => $ms]));
            $this->assertSame($secs, $seen['timeout'], var_export($ms, true));
        }
    }

    public function testDefaultTransportOverALocalFile(): void
    {
        // a local file answers with no HTTP status line: delivered bytes, status 0
        $this->assertSame(['ok' => false, 'error' => 'HTTP 0'], self::deliver(__FILE__, 'cef', []));
        // nothing read and no status line: the fetch gave up
        $this->assertSame(['ok' => false, 'error' => 'delivery timed out'], self::deliver(__DIR__ . '/no-such-dir-g18/none', 'cef', []));
    }

    // ---- export -------------------------------------------------------------------------------------------------------

    private static function console(array &$lines): \Atlas\Pca\SiemSink
    {
        return Siem::consoleSink(null, static function (string $l) use (&$lines): void {
            $lines[] = $l;
        });
    }

    public function testExportDecisionDeliversOne(): void
    {
        $lines = [];
        $this->assertSame(['ok' => true, 'delivered' => 1, 'format' => 'ocsf'], Siem::exportDecision(self::rec(), self::console($lines)));
        $this->assertCount(1, $lines);
    }

    public function testABatchWithNoSerializableRecord(): void
    {
        $lines = [];
        $errs = [];
        $onError = static function (\Throwable $e, array $ctx) use (&$errs): void {
            $errs[] = [$e->getMessage(), $ctx];
        };
        $this->assertSame(
            ['ok' => false, 'delivered' => 0, 'format' => 'ocsf', 'error' => 'no record could be serialized', 'skipped' => 1],
            Siem::exportBatch([null], self::console($lines), $onError),
        );
        $this->assertSame([['record could not be serialized: record is required', ['sink' => 'console:ocsf', 'count' => 1]]], $errs);
        $this->assertSame([], $lines);
    }

    public function testABatchSkipsTheBadRecordAndShipsTheRest(): void
    {
        $lines = [];
        $this->assertSame(['ok' => true, 'delivered' => 1, 'format' => 'ocsf', 'skipped' => 1], Siem::exportBatch([self::rec(), null], self::console($lines)));
        $this->assertCount(1, $lines);
    }
}
