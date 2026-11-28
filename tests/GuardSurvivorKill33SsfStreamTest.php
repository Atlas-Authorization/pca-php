<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SsfStream.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\SsfStream;
use Atlas\Pca\StreamHealth;
use Atlas\Pca\VerificationStream;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/SsfStream.php: verification state shape and expiry boundary, the health counters, config checks and the 429 gate. */
final class GuardSurvivorKill33SsfStreamTest extends TestCase
{
    /** The state is 16 random bytes as unpadded base64url (22 characters). */
    public function testVerificationStateShape(): void
    {
        $s = (new StreamHealth(new Obj()))->requestVerification(0);
        $this->assertIsString($s);
        $this->assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{22}\z/', $s);
    }

    /** A request is live through its expiry second and gone after it. */
    public function testAckExpiryBoundary(): void
    {
        $h = new StreamHealth(new Obj());
        $this->assertTrue($h->ackVerification($h->requestVerification(0), 60));
        $late = new StreamHealth(new Obj());
        $s = $late->requestVerification(0);
        $this->assertFalse($late->ackVerification($s, 61));
        $r = $late->report(61);
        $this->assertSame([1, 1, 0], [$r['consecutive_verification_failures'], $r['rejected_verifications'], $r['pending_verifications']]);
    }

    public function testNonFiniteAckCountsAsRejected(): void
    {
        $h = new StreamHealth(new Obj());
        $this->assertFalse($h->ackVerification('s', 'x'));
        $this->assertSame(1, $h->report(0)['rejected_verifications']);
    }

    /** The first event time starts from 0, and a NaN clock poisons it (Math.max semantics). */
    public function testLastEventMax(): void
    {
        $h = new StreamHealth(new Obj());
        $h->recordEvent(0.5);
        $this->assertSame(0.5, $h->report(1)['last_event_at']);
        $n = new StreamHealth(new Obj());
        $n->recordEvent('x');
        $this->assertNan($n->report(1)['last_event_at']);
        $n->recordEvent(5);
        $this->assertNan($n->report(1)['last_event_at']);
    }

    public function testSafeIntegerEdge(): void
    {
        $this->assertTrue(SsfStream::isSafeNonNegInt(new Num('9007199254740991')));
        $this->assertFalse(SsfStream::isSafeNonNegInt(new Num('9007199254740992')));
    }

    public function testEventsRequestedAndSubsetErrors(): void
    {
        $base = ['stream_id' => 's', 'iss' => 'i', 'aud' => 'a', 'events_delivered' => ['e'],
            'delivery' => Obj::of(['method' => SsfStream::DELIVERY_PUSH, 'endpoint_url' => 'https://x.example'])];
        $this->assertSame([], SsfStream::validateStreamConfig(Obj::of($base)));
        $this->assertSame([], SsfStream::validateStreamConfig(Obj::of($base + ['events_requested' => ['e']])));
        $msg = ['events_requested must be a non-empty array of URIs'];
        $this->assertSame($msg, SsfStream::validateStreamConfig(Obj::of($base + ['events_requested' => []])));
        $this->assertSame($msg, SsfStream::validateStreamConfig(Obj::of($base + ['events_requested' => 'e'])));
        $sub = $base;
        $sub['events_delivered'] = ['a', 'b'];
        $this->assertSame(['events_delivered must be a subset of events_supported'],
            SsfStream::validateStreamConfig(Obj::of($sub + ['events_supported' => ['c']])));
    }

    /** A clock behind the last verification is inside the interval: with no interval (0) and with a non-number one (0). */
    public function testTooSoonWhenTheClockIsBehind(): void
    {
        $tooSoon = ['status' => 429, 'error' => 'verification requested too soon'];
        foreach ([new Obj(), Obj::of(['min_verification_interval' => 'x'])] as $config) {
            $streams = ['s1' => new VerificationStream($config, 10.0)];
            $this->assertSame($tooSoon, SsfStream::handleVerificationRequest($streams, Obj::of(['stream_id' => 's1']), 9.5, null));
            $this->assertSame(10.0, $streams['s1']->lastVerification);
        }
    }
}
