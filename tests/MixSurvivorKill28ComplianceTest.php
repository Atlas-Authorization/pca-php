<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Compliance;
use Atlas\Pca\JsSet;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 28 survivors in Compliance: JsSet identity, JS property-read errors, pretty JSON, the civil calendar, the clock, stats and periods. */
final class MixSurvivorKill28ComplianceTest extends TestCase
{
    protected function tearDown(): void
    {
        Compliance::$clockHook = null;
    }

    private static function call(string $m, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Compliance::class, $m))->invoke(null, ...$args);
    }

    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
            self::fail("expected $class");
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
        }
    }

    private static function sizeOf(mixed ...$vs): int
    {
        $s = new JsSet();
        foreach ($vs as $v) {
            $s->add($v);
        }
        return $s->size();
    }

    /** Booleans, numbers and strings are keyed by kind and value: true and false, 1 and 2, true and the string "b:1" are all distinct. */
    public function testJsSetKeys(): void
    {
        self::assertSame(2, self::sizeOf(true, false));
        self::assertSame(2, self::sizeOf(1, 2));
        self::assertSame(1, self::sizeOf(1, 1.0));
        self::assertSame(2, self::sizeOf(true, 'b:1'));
    }

    /** The mapping table is parsed once: later calls return the same objects. */
    public function testMappingTableIsCached(): void
    {
        self::assertSame(Compliance::controlMappingTable()[0], Compliance::controlMappingTable()[0]);
    }

    /** Reading through null or undefined throws the reference's TypeError, naming which. */
    public function testPropertyReadErrors(): void
    {
        self::refuses(\TypeError::class, "Cannot read properties of null (reading 'k')", static fn() => self::call('prop', null, 'k'));
        self::refuses(\TypeError::class, "Cannot read properties of undefined (reading 'k')", static fn() => self::call('prop', Jsx::$U, 'k'));
        self::refuses(\TypeError::class, "Cannot read properties of null (reading 'length')", static fn() => self::call('length', null));
        self::refuses(\TypeError::class, "Cannot read properties of undefined (reading 'length')", static fn() => self::call('length', Jsx::$U));
    }

    /** Number helpers: a non-number renders as 0, and infinity is not an integer. */
    public function testNumberHelpers(): void
    {
        self::assertSame('0', self::call('jsn', 'x'));
        self::assertFalse(self::call('isIntegerNum', INF));
        self::assertTrue(self::call('isIntegerNum', 2));
    }

    /** Pretty JSON writes an undefined list item as null and drops undefined members. */
    public function testPrettyUndefined(): void
    {
        self::assertSame("[\n  null\n]", self::call('pretty', [Jsx::$U]));
        self::assertSame("{\n  \"a\": 1\n}", self::call('pretty', Obj::of(['a' => 1, 'b' => Jsx::$U])));
    }

    /** The civil calendar matches the proleptic Gregorian one over a whole 400-year era and across the era boundaries. */
    public function testCivilCalendar(): void
    {
        $civil = \Closure::bind(static fn(int $d): array => self::civil($d), null, Compliance::class);
        $leap = static fn(int $y): bool => $y % 4 === 0 && ($y % 100 !== 0 || $y % 400 === 0);
        [$y, $m, $d] = [0, 3, 1];
        for ($z = 0; $z <= 146096; $z++) {
            if ($civil($z - 719468) !== [$y, $m, $d]) {
                self::fail("civil(" . ($z - 719468) . ") is not $y-$m-$d");
            }
            $dim = $m === 2 ? ($leap($y) ? 29 : 28) : (in_array($m, [4, 6, 9, 11], true) ? 30 : 31);
            if (++$d > $dim) {
                $d = 1;
                if (++$m > 12) {
                    $m = 1;
                    $y++;
                }
            }
        }
        self::assertSame([400, 3, 1], [$y, $m, $d]);
        self::assertSame([400, 3, 1], $civil(146097 - 719468));
        self::assertSame([0, 2, 29], $civil(-1 - 719468));
        self::assertSame([-400, 3, 1], $civil(-146097 - 719468));
    }

    /** toISOString splits hours exactly and refuses a non-number. */
    public function testIsoString(): void
    {
        self::assertSame('1970-01-01T01:00:00.000Z', self::call('isoString', 3600000));
        self::refuses(\RangeException::class, 'Invalid time value', static fn() => self::call('isoString', 'x'));
    }

    /** The clock is read in whole milliseconds, and a framework report without a time is stamped with it. */
    public function testClock(): void
    {
        Compliance::$clockHook = static fn(): float => 1800000000.0007;
        self::assertSame(1800000000000, self::call('nowMs'));
        self::assertSame(1800000000000, Compliance::frameworkReport('soc2', self::console(1))->get('generatedAt'));
    }

    private static function console(mixed $bMax): Obj
    {
        return Obj::of(['policy' => Obj::of(['riskPolicy' => Obj::of(['kappa' => 1, 'bMax' => $bMax])]), 'events' => []]);
    }

    /** With no human-reviewed action and no finite autonomous bound, human oversight is a warning. */
    public function testOversightNeedsAReviewOrABound(): void
    {
        $c = Compliance::frameworkReport('eu-ai-act', self::console('x'), 0)->get('controls');
        self::assertSame(['art14-human-oversight', 'warn'], [$c[1]->get('id'), $c[1]->get('status')]);
    }

    /** The renderers' building blocks are public. */
    public function testPublicHelpers(): void
    {
        self::assertSame('(malformed caveat)', Compliance::describeCaveat('x'));
        self::assertSame([], Compliance::buildDelegationHops(null));
        self::assertNull(Compliance::buildHumanOverride(null, null, null));
        self::assertSame('deny', Compliance::resolveOutcome(null, null)->get('outcome'));
    }

    private static function event(mixed $iat): Obj
    {
        return Compliance::toAuditEvent(Obj::of(['pcactn' => Obj::of(['iat' => $iat]), 'now' => 0]));
    }

    /** A falsy event is skipped without ending the count. */
    public function testStatsSkipFalsyEvents(): void
    {
        self::assertSame(1, self::call('computeStats', [null, self::event(5)])['denied']);
    }

    /** soc2 CC6.3 is satisfied by one attenuating hop; an unknown control is not evidenced. */
    public function testEvaluateControl(): void
    {
        $s = ['total' => 1, 'sampleDigest' => Jsx::$U, 'maxDepth' => 1, 'denied' => 0];
        self::assertSame('satisfied', self::call('evaluateControl', 'soc2:CC6.3', $s)['status']);
        self::assertSame(['status' => 'not-evidenced', 'evidence' => 'no evaluator for this control', 'findings' => ['unmapped control']],
            self::call('evaluateControl', 'nope', $s));
    }

    /** A period keeps the first of equal times (the int 5, not the float 5.0), in both reports. */
    public function testPeriodTiesKeepTheFirst(): void
    {
        $r = Compliance::toComplianceReport([self::event(5), self::event(5.0)], Obj::of(['framework' => 'soc2', 'now' => 0]));
        self::assertSame([5, 5], [$r->get('period')->get('from')->get('epochMs'), $r->get('period')->get('to')->get('epochMs')]);
        $p = self::call('period', [Obj::of(['at' => 5]), Obj::of(['at' => 5.0])]);
        self::assertSame([5, 5], [$p->get('from'), $p->get('to')]);
    }

    /** Status words are upper-cased as Unicode text, and a non-string is the reference's TypeError. */
    public function testUpper(): void
    {
        self::assertSame('PASSÉ', self::call('upper', 'passé'));
        self::refuses(\TypeError::class, 'toUpperCase is not a function', static fn() => self::call('upper', 5));
    }
}
