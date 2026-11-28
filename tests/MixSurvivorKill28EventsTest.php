<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Events;
use Atlas\Pca\JsonError;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 28 survivors in Events: event ids and field checks, the default clock, signature-header parsing, replay keys and delivery. */
final class MixSurvivorKill28EventsTest extends TestCase
{
    private const SECRET = 'a-webhook-secret-of-28-bytes';
    private const P = '{"x":1}';

    protected function tearDown(): void
    {
        Events::$clockHook = null;
    }

    private static function data(): array
    {
        return ['at' => 1700000000000, 'grant_ref' => 'g1', 'action' => ['verb' => 'stripe.refund', 'resource' => 'pi_1'], 'tier' => 2, 'actor' => 'u1'];
    }

    /** Run `$f` with PHP warnings turned into exceptions; assert it threw exactly `$class` with `$msg`. */
    private static function refuses(string $class, string $msg, callable $f): void
    {
        set_error_handler(static function (int $no, string $m): never {
            throw new \ErrorException($m, 0, $no);
        });
        try {
            $f();
            self::fail("expected $class");
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
        } finally {
            restore_error_handler();
        }
    }

    private static function eventId(array $e): string
    {
        return (new \ReflectionMethod(Events::class, 'eventId'))->invoke(null, $e);
    }

    /** The id refuses an event missing any field, the type and the action's verb included. */
    public function testEventIdRefusesMissingFields(): void
    {
        $full = ['type' => 'step_up.approved', 'at' => 1, 'grant_ref' => 'g', 'action' => ['verb' => 'v', 'resource' => 'r'], 'tier' => 2];
        self::assertIsString(self::eventId($full));
        $msg = 'canonicalize: unsupported type undefined';
        foreach (['type', 'at', 'grant_ref', 'tier'] as $k) {
            $e = $full;
            unset($e[$k]);
            self::refuses(JsonError::class, $msg, static fn() => self::eventId($e));
        }
        foreach (['verb', 'resource'] as $k) {
            $e = $full;
            unset($e['action'][$k]);
            self::refuses(JsonError::class, $msg, static fn() => self::eventId($e));
        }
    }

    /** A canonical-form error without the prefix gets it (an exponent-form `at`). */
    public function testEventIdPrefixesCanonicalErrors(): void
    {
        self::refuses(JsonError::class, 'canonicalize: exponent form is not allowed',
            static fn() => Events::buildStepUpEvent('step_up.approved', ['at' => 1.5e300] + self::data()));
    }

    /** Building from a plain array or an Obj gives the same event, and the caller's Obj is not modified. */
    public function testBuildFromArrayAndObj(): void
    {
        $ev = Events::buildStepUpEvent('step_up.approved', self::data());
        self::assertSame(['type', 'at', 'grant_ref', 'action', 'tier', 'actor', 'id'], array_keys($ev));
        self::assertSame(['verb' => 'stripe.refund', 'resource' => 'pi_1'], $ev['action']);
        $o = Obj::of(self::data());
        $o->set('action', Obj::of(self::data()['action']));
        self::assertSame($ev['id'], Events::buildStepUpEvent('step_up.approved', $o)['id']);
        self::assertFalse($o->has('type'));
    }

    /** Without `at` the event is stamped with the clock in whole milliseconds, rounded down. */
    public function testDefaultAtIsTheClock(): void
    {
        Events::$clockHook = static fn(): float => 1800000000.0007;
        $d = self::data();
        unset($d['at']);
        self::assertSame(1800000000000, Events::buildStepUpEvent('step_up.created', $d)['at']);
    }

    /** A present but non-numeric `at` is refused with the build message. */
    public function testBuildRefusesNonNumericAt(): void
    {
        self::refuses(\TypeError::class, 'buildStepUpEvent: at must be a finite number', static fn() => Events::buildStepUpEvent('step_up.approved', ['at' => 'x'] + self::data()));
    }

    /** serializeEvent accepts an event array, refuses a list or a scalar as not an object, and refuses a missing `at`. */
    public function testSerializeShapes(): void
    {
        $ev = Events::buildStepUpEvent('step_up.approved', self::data());
        self::assertSame($ev['id'], Events::parseEvent(Events::serializeEvent($ev))['id']);
        self::refuses(\TypeError::class, 'serializeEvent: not an object', static fn() => Events::serializeEvent([1, 2]));
        self::refuses(\TypeError::class, 'serializeEvent: not an object', static fn() => Events::serializeEvent('x'));
        $noAt = $ev;
        unset($noAt['at']);
        self::refuses(\TypeError::class, 'serializeEvent: at must be a finite number', static fn() => Events::serializeEvent($noAt));
    }

    /** parseEvent refuses a non-string and a non-string actor, and returns the tier as an integer. */
    public function testParseEvent(): void
    {
        self::refuses(\TypeError::class, 'parseEvent: not a string', static fn() => Events::parseEvent(5));
        $ev = Events::buildStepUpEvent('step_up.approved', self::data());
        self::assertSame(2, Events::parseEvent(Events::serializeEvent($ev))['tier']);
        $json = str_replace('"actor":"u1"', '"actor":5', Events::serializeEvent($ev));
        self::assertStringContainsString('"actor":5', $json);
        self::refuses(\InvalidArgumentException::class, 'parseEvent: bad actor', static fn() => Events::parseEvent($json));
    }

    // ---- signatures ----

    private static function hmac(string $signed): string
    {
        return hash_hmac('sha256', $signed, self::SECRET);
    }

    /** A header of exactly 2048 characters is read; one character more is refused. */
    public function testHeaderLengthBound(): void
    {
        $h = Events::signWebhook(self::SECRET, self::P, ['timestamp' => 100]);
        $at = $h . ',' . str_repeat('x', 2048 - strlen($h) - 1);
        self::assertSame(2048, strlen($at));
        self::assertTrue(Events::verifyWebhook(self::SECRET, self::P, $at, ['now' => 100]));
        self::assertFalse(Events::verifyWebhook(self::SECRET, self::P, $at . 'x', ['now' => 100]));
    }

    /** Two different timestamps are refused; the same one repeated is fine. */
    public function testConflictingTimestamps(): void
    {
        $v1 = self::hmac('200.' . self::P);
        self::assertFalse(Events::verifyWebhook(self::SECRET, self::P, "t=100,t=200,v1=$v1", ['now' => 200]));
        self::assertTrue(Events::verifyWebhook(self::SECRET, self::P, "t=200,t=200,v1=$v1", ['now' => 200]));
    }

    /** A header without a timestamp is refused, even with a v1 that signs the string form of a missing one. */
    public function testHeaderNeedsATimestamp(): void
    {
        self::assertFalse(Events::verifyWebhook(self::SECRET, self::P, 'v1=' . self::hmac('null.' . self::P), ['now' => 0]));
    }

    /** A malformed candidate does not stop the search: a valid v1 after it still verifies. */
    public function testMalformedCandidateIsSkipped(): void
    {
        self::assertTrue(Events::verifyWebhook(self::SECRET, self::P, 't=100,v1=zz,v1=' . self::hmac('100.' . self::P), ['now' => 100]));
    }

    /** A short secret is refused with the minimum length. */
    public function testShortSecret(): void
    {
        self::refuses(\RangeException::class, 'signWebhook: the secret must be at least 16 bytes', static fn() => Events::signWebhook('short', self::P));
    }

    /** replayKey is the namespace, a colon, and the hash of every length-prefixed part, the namespace included. */
    public function testReplayKey(): void
    {
        $buf = pack('N', 2) . 'ns' . pack('N', 1) . 'a' . pack('N', 3) . 'bcd';
        self::assertSame('ns:' . Pca::b64u(hash('sha256', $buf, true)), Events::replayKey('ns', 'a', 'bcd'));
        self::refuses(\TypeError::class, 'replayKey: every part must be a well-formed string (no lone surrogates)', static fn() => Events::replayKey('ns', "\xED\xA0\x80"));
    }

    /** A delivery consumes its id once, retained until (t + tolerance) s + 1 ms, at now in ms. */
    public function testDeliveryRetention(): void
    {
        $store = new class {
            /** @var list<array{string,int,int}> */
            public array $calls = [];

            public function consumeOnce(string $key, int $retainUntilMs, int $nowMs): bool
            {
                $this->calls[] = [$key, $retainUntilMs, $nowMs];
                return true;
            }
        };
        $ev = Events::buildStepUpEvent('step_up.approved', self::data());
        $payload = Events::serializeEvent($ev);
        $h = Events::signWebhook(self::SECRET, $payload, ['timestamp' => 100]);
        $r = Events::verifyDelivery(self::SECRET, $payload, $h, ['replay' => $store, 'now' => 110, 'toleranceSec' => 20]);
        self::assertSame([true, $ev['id']], [$r['ok'], $r['event']['id'] ?? null]);
        self::assertSame([[Events::replayKey('pca-stepup-event/v1', $ev['id']), 120001, 110000]], $store->calls);
    }
}
