<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostNonceStore.php';

use Atlas\Pca\MemoryFrostNonceStore;
use Atlas\Pca\NonceRecord;
use Atlas\Pca\NonceStore;
use Atlas\Pca\NonceStoreContract;
use PHPUnit\Framework\TestCase;

/** FROST one-shot nonce storage: secrets are zeroised in place, and the store contract refuses each broken store with its exact violation. */
final class StateSurvivorKill4FrostNonceStoreTest extends TestCase
{
    private static function rec(int $n): NonceRecord
    {
        return new NonceRecord(str_repeat(chr($n), 32), str_repeat(chr($n + 1), 32), str_repeat(chr($n + 2), 32), str_repeat(chr($n + 3), 32), $n);
    }

    /** @param array<string,bool> $flags */
    private static function violation(array $flags, ?\Closure $reopen = null): string
    {
        try {
            NonceStoreContract::assert(static fn(): NonceStore => new StateKill4NonceStore($flags), $reopen);
        } catch (\RuntimeException $e) {
            return $e->getMessage();
        }
        return 'passed';
    }

    /** wipe() overwrites both secret nonces with zero bytes of the same length; the public commitments stay. */
    public function testWipeZeroisesBothSecretsAtFullLength(): void
    {
        $r = self::rec(1);
        $r->wipe();
        self::assertSame(str_repeat("\0", 32), $r->hiding);
        self::assertSame(str_repeat("\0", 32), $r->binding);
        self::assertSame(str_repeat("\x03", 32), $r->hidingCommitment);
    }

    /** spend and drop zeroise the stored secret itself before forgetting it (no live copy of a spent nonce is left in memory). */
    public function testSpendAndDropZeroiseTheStoredSecret(): void
    {
        $s = new MemoryFrostNonceStore();
        $s->create('x', self::rec(1));
        $s->create('y', self::rec(5));
        $live = (new \ReflectionProperty(MemoryFrostNonceStore::class, 'live'))->getValue($s);
        $x = $live['x'];
        $y = $live['y'];
        self::assertSame(str_repeat("\x01", 32), $x->hiding, 'control: the stored copy holds the secret');
        $s->spend('x');
        self::assertSame(str_repeat("\0", 32), $x->hiding);
        self::assertSame(str_repeat("\0", 32), $x->binding);
        $s->drop('y');
        self::assertSame(str_repeat("\0", 32), $y->hiding);
        self::assertSame(str_repeat("\0", 32), $y->binding);
        self::assertTrue($s->isSpent('x'));
        self::assertFalse($s->isSpent('y'));
    }

    /** The contract feeds the store well-formed records: four distinct 32-byte fields per record, in a fixed order of ids. */
    public function testTheContractCreatesTheDocumentedRecords(): void
    {
        $store = null;
        NonceStoreContract::assert(static function () use (&$store): NonceStore {
            return $store = new StateKill4NonceStore();
        });
        $seen = array_map(static fn(array $c): array => [$c[0], $c[1]->hiding, $c[1]->binding, $c[1]->hidingCommitment, $c[1]->bindingCommitment, $c[1]->createdAt], $store->created);
        $want = static fn(string $id, int $n): array => [$id, str_repeat(chr($n), 32), str_repeat(chr($n + 1), 32), str_repeat(chr($n + 2), 32), str_repeat(chr($n + 3), 32), $n];
        self::assertSame([$want('a', 1), $want('a', 9), $want('b', 5), $want('a', 2)], $seen);
    }

    /** A store where an unknown id already reads as spent is refused at the first check. */
    public function testAPreSpentIdIsRefused(): void
    {
        self::assertSame('nonce-store contract: an unknown id is neither live nor spent', self::violation(['preSpent' => true]));
    }

    /** A store that loses live records on restart is refused as such (not by a crash on the missing record). */
    public function testALostLiveRecordIsRefused(): void
    {
        self::assertSame('nonce-store contract: a live record survives a restart',
            self::violation([], static fn(NonceStore $s): NonceStore => new MemoryFrostNonceStore()));
    }

    /** A store that returns a wrong first secret byte fails the restart check itself. */
    public function testAWrongFirstSecretByteIsRefused(): void
    {
        self::assertSame('nonce-store contract: a live record survives a restart', self::violation(['corruptFirstByte' => true]));
    }

    /** A store whose second load corrupts the first secret byte is refused as not returning a copy. */
    public function testASecondLoadThatDiffersIsRefused(): void
    {
        self::assertSame('nonce-store contract: load returns a copy', self::violation(['corruptSecondLoad' => true]));
    }

    /** A store that hands out its own record (aliasing) is refused as not returning a copy, even when it checks the 32-byte length. */
    public function testAnAliasingStoreIsRefused(): void
    {
        self::assertSame('nonce-store contract: load returns a copy', self::violation(['alias' => true]));
    }

    /** spend must record the spent marker. */
    public function testASpendWithoutMarkerIsRefused(): void
    {
        self::assertSame('nonce-store contract: spend removes the secret and records the marker', self::violation(['spendNoMarker' => true]));
    }

    /** spend of an id that never existed must throw. */
    public function testASilentSpendOfAnUnknownIdIsRefused(): void
    {
        self::assertSame('nonce-store contract: spend of an unknown id must throw', self::violation(['spendUnknownNoop' => true]));
    }

    /** A restart that keeps the spent markers but loses the other live record is refused. */
    public function testALiveRecordLostOnTheSecondRestartIsRefused(): void
    {
        $n = 0;
        $reopen = static function (NonceStore $s) use (&$n): NonceStore {
            if (++$n === 1) {
                return $s;
            }
            $fresh = new StateKill4NonceStore();
            $fresh->spent = $s->spent;
            return $fresh;
        };
        self::assertSame('nonce-store contract: the other live record survives', self::violation([], $reopen));
    }

    /** drop of an unknown id is a no-op by contract: a store that throws there fails the contract with its own error. */
    public function testADropOfAnUnknownIdMustNotThrow(): void
    {
        self::assertSame('test-store: drop of an unknown id', self::violation(['dropUnknownThrows' => true]));
        self::assertSame('passed', self::violation([]), 'control: the well-behaved test store passes');
    }
}

/** A configurable in-memory nonce store: each flag breaks one rule of the contract. */
final class StateKill4NonceStore implements NonceStore
{
    /** @var array<string,NonceRecord> */
    public array $live = [];
    /** @var array<string,true> */
    public array $spent = [];
    /** @var list<array{0:string,1:NonceRecord}> */
    public array $created = [];
    private int $loads = 0;

    /** @param array<string,bool> $flags */
    public function __construct(private readonly array $flags = [])
    {
        if ($this->on('preSpent')) {
            $this->spent['a'] = true;
        }
    }

    private function on(string $flag): bool
    {
        return $this->flags[$flag] ?? false;
    }

    public function create(string $sessionId, NonceRecord $record): void
    {
        $this->created[] = [$sessionId, $record->copy()];
        if (isset($this->live[$sessionId]) || isset($this->spent[$sessionId])) {
            throw new \RuntimeException('test-store: session already exists');
        }
        $this->live[$sessionId] = $record->copy();
    }

    public function load(string $sessionId): ?NonceRecord
    {
        if (!isset($this->live[$sessionId])) {
            return null;
        }
        $this->loads++;
        $r = $this->live[$sessionId];
        if ($this->on('alias')) {
            if (strlen($r->hiding) !== 32) {
                throw new \RuntimeException('test-store: a hiding nonce is 32 bytes');
            }
            return $r;
        }
        $c = $r->copy();
        if ($this->on('corruptFirstByte') || ($this->on('corruptSecondLoad') && $this->loads === 2)) {
            $c->hiding = "\x07" . substr($c->hiding, 1);
        }
        return $c;
    }

    public function spend(string $sessionId): void
    {
        if (!isset($this->live[$sessionId])) {
            if (!isset($this->spent[$sessionId]) && $this->on('spendUnknownNoop')) {
                return;
            }
            throw new \RuntimeException('test-store: not live');
        }
        unset($this->live[$sessionId]);
        if (!$this->on('spendNoMarker')) {
            $this->spent[$sessionId] = true;
        }
    }

    public function drop(string $sessionId): void
    {
        if (!isset($this->live[$sessionId]) && !isset($this->spent[$sessionId]) && $this->on('dropUnknownThrows')) {
            throw new \RuntimeException('test-store: drop of an unknown id');
        }
        unset($this->live[$sessionId]);
    }

    public function isSpent(string $sessionId): bool
    {
        return isset($this->spent[$sessionId]);
    }
}
