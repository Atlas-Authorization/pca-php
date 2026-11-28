<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ConnectReplay;
use Atlas\Pca\Events;
use Atlas\Pca\InMemoryReplayStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The one-time-use PCActn guard (window, audience, nonce, counter, store failure) and the in-memory replay store's exact rules. */
final class ToolSurvivorKill18ReplayTest extends TestCase
{
    private const NOW = 1500;
    private const MAX = 9007199254740991;
    private const LONE = "\xED\xA0\x80";

    /** A PCActn with the given fields replaced; a field set to self::class is removed. */
    private static function pc(array $o = []): Obj
    {
        $a = array_merge(['aud' => 'rs', 'iat' => 1000, 'exp' => 2000, 'grant_ref' => 'g', 'nonce' => 'n1', 'counter' => 0,
            'cap_chain' => [Obj::of(['holder' => 'h'])]], $o);
        foreach ($a as $k => $v) {
            if ($v === self::class) {
                unset($a[$k]);
            }
        }
        return Obj::of($a);
    }

    private static function deny(string $code, string $reason): array
    {
        return ['ok' => false, 'code' => $code, 'reason' => $reason];
    }

    private static function guard(Obj|string|null $p, mixed $aud = 'rs', mixed $now = self::NOW, mixed $skew = null, bool $requireNonce = true, mixed $counters = null): array
    {
        return ConnectReplay::guardPcactnReplay(new InMemoryReplayStore(), $p, $aud, $now, $skew, $requireNonce, $counters);
    }

    /** A store that records what the guard hands it and accepts. */
    private static function recorder(): object
    {
        return new class {
            public array $calls = [];

            public function consumeOnce(string $key, int|float $retainUntilMs, int|float $nowMs): bool
            {
                $this->calls[] = [$key, $retainUntilMs, $nowMs];
                return true;
            }

            public function advance(string $streamKey, int $counter): bool
            {
                $this->calls[] = [$streamKey, $counter];
                return true;
            }
        };
    }

    /** replayKey is public and is the shared length-prefixed encoding. */
    public function testReplayKeyIsTheSharedEncoding(): void
    {
        $this->assertSame(Events::replayKey('ns', 'a', 'b'), ConnectReplay::replayKey('ns', 'a', 'b'));
    }

    /** A verified action is accepted once; the same nonce again is a replay. */
    public function testAcceptedOnceThenReplay(): void
    {
        $s = new InMemoryReplayStore();
        $this->assertSame(['ok' => true], ConnectReplay::guardPcactnReplay($s, self::pc(), 'rs', self::NOW));
        $this->assertSame(self::deny('replay', 'nonce already consumed'), ConnectReplay::guardPcactnReplay($s, self::pc(), 'rs', self::NOW));
    }

    /** The store receives the nonce key and integral epoch-ms as ints (exp + skew, now). */
    public function testStoreReceivesIntegerMilliseconds(): void
    {
        $r = self::recorder();
        $this->assertSame(['ok' => true], ConnectReplay::guardPcactnReplay($r, self::pc(), 'rs', self::NOW));
        $this->assertSame([[ConnectReplay::replayKey('pca-nonce/v1', 'rs', 'g', 'h', 'n1'), 62000, 1500]], $r->calls);
    }

    /** A fractional clock skew keeps the retention horizon fractional (not truncated). */
    public function testFractionalRetentionStaysFloat(): void
    {
        $r = self::recorder();
        $this->assertSame(['ok' => true], ConnectReplay::guardPcactnReplay($r, self::pc(), 'rs', self::NOW, 1000.5));
        $this->assertSame(3000.5, $r->calls[0][1]);
        $this->assertSame(1500, $r->calls[0][2]);
    }

    /** A retention horizon of exactly 2^53-1 is allowed and handed over as an int. */
    public function testRetentionAtTheSafeIntegerLimit(): void
    {
        $exp = self::MAX - 60000;
        $r = self::recorder();
        $out = ConnectReplay::guardPcactnReplay($r, self::pc(['iat' => $exp - 1000, 'exp' => $exp]), 'rs', $exp - 500);
        $this->assertSame(['ok' => true], $out);
        $this->assertSame(self::MAX, $r->calls[0][1]);
        $this->assertSame($exp - 500, $r->calls[0][2]);
    }

    /** exp + ceil(skew) beyond 2^53-1 is refused; an integral skew landing exactly on the limit is not. */
    public function testRetentionBeyondTheSafeRange(): void
    {
        $exp = self::MAX - 1000;
        $p = self::pc(['iat' => $exp - 1000, 'exp' => $exp]);
        $d = self::deny('malformed', 'exp + clock skew exceeds the safe-integer range (retention horizon not representable)');
        $this->assertSame($d, self::guard($p, 'rs', $exp));
        $this->assertSame($d, self::guard($p, 'rs', $exp, 1000.4));
        $this->assertSame(['ok' => true], self::guard($p, 'rs', $exp, 1000));
    }

    /** The counter must be a non-negative safe integer: 0 and 2^53-1 pass; -0, fractions, negatives and a missing one do not. */
    public function testCounterShape(): void
    {
        $this->assertSame(['ok' => true], self::guard(self::pc(['counter' => 0])));
        $this->assertSame(['ok' => true], self::guard(self::pc(['counter' => self::MAX])));
        $d = self::deny('malformed', 'counter is not a non-negative safe integer');
        foreach ([-0.0, 1.5, -1, self::class, 'x'] as $c) {
            $this->assertSame($d, self::guard(self::pc(['counter' => $c])), var_export($c, true));
        }
    }

    /** The verifier clock must be a safe integer. */
    public function testVerifierClock(): void
    {
        $d = self::deny('malformed', 'verifier clock is not an integer epoch-ms');
        foreach (['x', null, 1500.5, INF, NAN] as $now) {
            $this->assertSame($d, self::guard(self::pc(), 'rs', $now), var_export($now, true));
        }
        // 2^53-1 is still a valid clock: the action is judged (expired), not the clock
        $this->assertSame(self::deny('expired', 'the PCActn has expired'), self::guard(self::pc(), 'rs', self::MAX));
    }

    /** The verifier audience must be a non-empty, well-formed string of at most 256 bytes, and must match the action's. */
    public function testAudience(): void
    {
        $d = self::deny('malformed', 'verifier audience is invalid');
        $this->assertSame($d, self::guard(self::pc(), 5));
        $this->assertSame($d, self::guard(self::pc(['aud' => '']), ''));
        $a257 = str_repeat('a', 257);
        $this->assertSame($d, self::guard(self::pc(['aud' => $a257]), $a257));
        $this->assertSame($d, self::guard(self::pc(['aud' => self::LONE]), self::LONE));
        $a256 = str_repeat('a', 256);
        $this->assertSame(['ok' => true], self::guard(self::pc(['aud' => $a256]), $a256));
        $this->assertSame(self::deny('audience', 'the PCActn is for another audience'), self::guard(self::pc(), 'other'));
    }

    /** Something that is not a PCActn object is refused as such. */
    public function testNotAPcactn(): void
    {
        $d = self::deny('malformed', 'not a PCActn');
        $this->assertSame($d, self::guard('x'));
        $this->assertSame($d, self::guard(null));
    }

    /** iat / exp must be non-negative safe integers with 0 < exp - iat <= one hour. */
    public function testWindow(): void
    {
        $d = self::deny('malformed', 'iat / exp are not a valid bounded window');
        foreach ([['iat' => 'x'], ['iat' => -1], ['exp' => 'x'], ['iat' => 1500, 'exp' => 1500], ['iat' => 2000, 'exp' => 1000],
            ['iat' => 0, 'exp' => 3600001]] as $o) {
            $this->assertSame($d, self::guard(self::pc($o)), json_encode($o));
        }
        $this->assertSame(['ok' => true], self::guard(self::pc(['iat' => 0, 'exp' => 3600000])));
    }

    /** The clock-skew allowance: explicit, zero, fractional (floored), capped at 60 s, and the default when absent or negative. */
    public function testClockSkew(): void
    {
        $future = self::deny('not_yet_valid', 'iat is in the future beyond the clock-skew allowance');
        $p5 = self::pc(['iat' => 6500, 'exp' => 8000]);
        $this->assertSame(['ok' => true], self::guard($p5));
        $this->assertSame(['ok' => true], self::guard($p5, 'rs', self::NOW, -5));
        $this->assertSame($future, self::guard($p5, 'rs', self::NOW, 1000));
        $this->assertSame($future, self::guard(self::pc(['iat' => 1501, 'exp' => 2000]), 'rs', self::NOW, 0));
        $this->assertSame(['ok' => true], self::guard(self::pc(['iat' => 1500, 'exp' => 2000]), 'rs', self::NOW, 0));
        $this->assertSame($future, self::guard(self::pc(['iat' => 2501, 'exp' => 3000]), 'rs', self::NOW, 1000.5));
        $this->assertSame(['ok' => true], self::guard(self::pc(['iat' => 2500, 'exp' => 3000]), 'rs', self::NOW, 1000.5));
        $this->assertSame($future, self::guard(self::pc(['iat' => 61501, 'exp' => 62000]), 'rs', self::NOW, 120000));
    }

    /** The action is good up to and including exp. */
    public function testExpiry(): void
    {
        $this->assertSame(['ok' => true], self::guard(self::pc(), 'rs', 2000));
        $this->assertSame(self::deny('expired', 'the PCActn has expired'), self::guard(self::pc(), 'rs', 2001));
    }

    /** The leaf holder and grant ref must be present strings on a non-empty list chain. */
    public function testLeaf(): void
    {
        $d = self::deny('malformed', 'no leaf holder / grant');
        foreach ([['cap_chain' => self::class], ['cap_chain' => 'x'], ['cap_chain' => ['x']], ['cap_chain' => [Obj::of([])]],
            ['cap_chain' => []], ['grant_ref' => self::class]] as $o) {
            $this->assertSame($d, self::guard(self::pc($o)), json_encode(array_keys($o)));
        }
    }

    /** Grant ref and holder must each be non-empty, well-formed and at most 512 bytes. */
    public function testComponents(): void
    {
        $d = self::deny('malformed', 'grant / holder is not a bounded string');
        $h = static fn(string $s): array => ['cap_chain' => [Obj::of(['holder' => $s])]];
        foreach ([['grant_ref' => ''], ['grant_ref' => str_repeat('g', 513)], ['grant_ref' => self::LONE], $h(''), $h(str_repeat('h', 513)), $h(self::LONE)] as $i => $o) {
            $this->assertSame($d, self::guard(self::pc($o)), (string)$i);
        }
        $this->assertSame(['ok' => true], self::guard(self::pc($h(str_repeat('h', 512)))));
        $this->assertSame(['ok' => true], self::guard(self::pc(['grant_ref' => str_repeat('g', 512)])));
    }

    /** A nonce is required by default; when present it must be a well-formed string of 1..128 bytes. */
    public function testNonce(): void
    {
        $this->assertSame(self::deny('malformed', 'a nonce is required'), self::guard(self::pc(['nonce' => self::class])));
        $this->assertSame(['ok' => true], self::guard(self::pc(['nonce' => self::class]), 'rs', self::NOW, null, false));
        $this->assertSame(['ok' => true], self::guard(self::pc(['nonce' => str_repeat('n', 128)])));
        $d = self::deny('malformed', 'nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes');
        foreach ([str_repeat('n', 129), '', 5, null, self::LONE] as $n) {
            $this->assertSame($d, self::guard(self::pc(['nonce' => $n])), var_export($n, true));
            $this->assertSame($d, self::guard(self::pc(['nonce' => $n]), 'rs', self::NOW, null, false), var_export($n, true));
        }
    }

    /** A counter stream must strictly increase; the counter is handed over as an int under its own key. */
    public function testCounters(): void
    {
        $s = new InMemoryReplayStore();
        $c = new InMemoryReplayStore();
        $this->assertSame(['ok' => true], ConnectReplay::guardPcactnReplay($s, self::pc(['nonce' => 'a', 'counter' => 5]), 'rs', self::NOW, null, true, $c));
        $this->assertSame(self::deny('replay', 'counter is not greater than the last accepted'),
            ConnectReplay::guardPcactnReplay($s, self::pc(['nonce' => 'b', 'counter' => 5]), 'rs', self::NOW, null, true, $c));
        $this->assertSame(['ok' => true], ConnectReplay::guardPcactnReplay($s, self::pc(['nonce' => 'c', 'counter' => 6]), 'rs', self::NOW, null, true, $c));
        $r = self::recorder();
        $this->assertSame(['ok' => true], ConnectReplay::guardPcactnReplay(new InMemoryReplayStore(), self::pc(['counter' => 5]), 'rs', self::NOW, null, true, $r));
        $this->assertSame([[ConnectReplay::replayKey('pca-counter/v1', 'rs', 'g', 'h'), 5]], $r->calls);
    }

    /** A store that throws fails closed with its message (or "error" when it has none). */
    public function testStoreFailureFailsClosed(): void
    {
        foreach (['boom' => 'replay store failed closed: boom', '' => 'replay store failed closed: error'] as $msg => $reason) {
            $bad = new class ((string)$msg) {
                public function __construct(private string $m)
                {
                }

                public function consumeOnce(string $k, int|float $r, int|float $n): bool
                {
                    throw new \RuntimeException($this->m);
                }
            };
            $this->assertSame(self::deny('store_unavailable', $reason), ConnectReplay::guardPcactnReplay($bad, self::pc(), 'rs', self::NOW));
        }
    }

    /** prune removes only entries whose horizon is strictly before now, and counts them; an infinite clock prunes nothing. */
    public function testPrune(): void
    {
        $s = new InMemoryReplayStore();
        $this->assertTrue($s->consumeOnce('a', 100, 50));
        $this->assertSame(0, $s->prune(INF));
        $this->assertSame(0, $s->prune(99));
        $this->assertSame(0, $s->prune(100));
        $this->assertSame(1, $s->size());
        $this->assertSame(1, $s->prune(101));
        $this->assertSame(0, $s->size());
    }

    /** consumeOnce validates its key and horizon (horizon == now is allowed). */
    public function testConsumeOnceValidation(): void
    {
        $s = new InMemoryReplayStore();
        $this->assertTrue($s->consumeOnce('eq', 50, 50));
        foreach ([['', 100, 50], [5, 100, 50], ['k', 40, 50], ['k', INF, 50], ['k', 100, NAN]] as $args) {
            try {
                $s->consumeOnce(...$args);
                $this->fail('accepted ' . var_export($args, true));
            } catch (\InvalidArgumentException $e) {
                $this->assertSame('consumeOnce: invalid key or retention horizon', $e->getMessage());
            }
        }
        $this->assertSame(1, $s->size());
    }

    /** A key is a replay until (and at) its horizon, and is accepted again only once the horizon has passed. */
    public function testHorizon(): void
    {
        $s = new InMemoryReplayStore();
        $this->assertTrue($s->consumeOnce('k', 100, 50));
        $this->assertFalse($s->consumeOnce('k', 100, 100));
        $this->assertTrue($s->consumeOnce('k', 300, 200));
        $this->assertFalse($s->consumeOnce('k', 300, 250));
        $this->assertSame(1, $s->size());
    }

    /** Retention is floored at epoch 0: a fresh key holds until max(horizon, 0). */
    public function testRetentionFloor(): void
    {
        $s = new InMemoryReplayStore();
        $this->assertTrue($s->consumeOnce('z', 0, 0));
        $this->assertTrue($s->consumeOnce('z', 1, 0.5));
        $this->assertTrue($s->consumeOnce('n', -5, -10));
        $this->assertFalse($s->consumeOnce('n', 1, -0.5));
    }

    /** Expired entries are pruned only when the store is full. */
    public function testPruneOnlyWhenFull(): void
    {
        $s = new InMemoryReplayStore(10);
        $this->assertTrue($s->consumeOnce('a', 100, 50));
        $this->assertTrue($s->consumeOnce('b', 300, 200));
        $this->assertSame(2, $s->size());
        $t = new InMemoryReplayStore(10);
        $this->assertTrue($t->consumeOnce('a', 100, 50));
        $this->assertTrue($t->consumeOnce('b', 100, 50));
        $this->assertTrue($t->consumeOnce('a', 300, 200));
        $this->assertSame(2, $t->size());
    }

    /** A full store makes room from expired entries, and refuses a new key when every entry is live. */
    public function testFullStore(): void
    {
        $s = new InMemoryReplayStore(1);
        $this->assertTrue($s->consumeOnce('a', 100, 50));
        try {
            $s->consumeOnce('b', 100, 60);
            $this->fail('a full store took a new key');
        } catch (\RuntimeException $e) {
            $this->assertSame('replay store full of live entries', $e->getMessage());
        }
        $this->assertSame(1, $s->size());
        $this->assertTrue($s->consumeOnce('b', 300, 200));
        $this->assertSame(1, $s->size());
        $this->assertFalse($s->consumeOnce('b', 300, 250));
    }

    /** The default capacity is exactly 100000 live entries. */
    public function testDefaultCapacity(): void
    {
        $s = new InMemoryReplayStore();
        for ($i = 0; $i < 100000; $i++) {
            $s->consumeOnce('k' . $i, 10, 0);
        }
        $this->assertSame(100000, $s->size());
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('replay store full of live entries');
        $s->consumeOnce('one-more', 10, 0);
    }

    /** advance accepts a strictly increasing safe-integer counter per stream (0 and 2^53-1 included). */
    public function testAdvance(): void
    {
        $s = new InMemoryReplayStore();
        $this->assertTrue($s->advance('s', 0));
        $this->assertFalse($s->advance('s', 0));
        $this->assertTrue($s->advance('s', 1));
        $this->assertFalse($s->advance('s', 1));
        $this->assertFalse($s->advance('s', 0));
        $this->assertTrue($s->advance('s', 7));
        $this->assertTrue($s->advance('t', 5));
        $this->assertTrue($s->advance('m', self::MAX));
        foreach ([['', 1], [5, 1], ['u', 1.5], ['u', -1], ['u', INF], ['u', NAN], ['u', 9007199254740992.0], ['u', 'x'], ['u', null]] as $args) {
            try {
                $s->advance(...$args);
                $this->fail('accepted ' . var_export($args, true));
            } catch (\InvalidArgumentException $e) {
                $this->assertSame('advance: invalid stream or counter', $e->getMessage());
            }
        }
    }
}
