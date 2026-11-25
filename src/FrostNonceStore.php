<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** One signer's secret nonce pair for a session plus its public commitments. A mutable object so that a store which aliases it can be detected. */
final class NonceRecord
{
    public function __construct(public string $hiding, public string $binding, public string $hidingCommitment, public string $bindingCommitment, public mixed $createdAt)
    {
    }

    public function copy(): self
    {
        return new self($this->hiding, $this->binding, $this->hidingCommitment, $this->bindingCommitment, $this->createdAt);
    }

    public function wipe(): void
    {
        $this->hiding = str_repeat("\0", strlen($this->hiding));
        $this->binding = str_repeat("\0", strlen($this->binding));
    }
}

/** Durable one-shot nonce storage: a session's nonces can be spent exactly once, and a spent id can never be created again (even after a restart). */
interface NonceStore
{
    /** Refuses an existing live or spent id; stores a COPY of the record. */
    public function create(string $sessionId, NonceRecord $record): void;

    /** A COPY of the live record, or null. */
    public function load(string $sessionId): ?NonceRecord;

    /** Removes the secret and records the spent marker; throws when the session is not live. */
    public function spend(string $sessionId): void;

    /** Removes a live record WITHOUT marking it spent; a no-op for an unknown or spent id. */
    public function drop(string $sessionId): void;

    public function isSpent(string $sessionId): bool;
}

final class MemoryFrostNonceStore implements NonceStore
{
    /** @var array<string,NonceRecord> */
    private array $live = [];
    /** @var array<string,true> */
    private array $spent = [];

    public function create(mixed $sessionId, NonceRecord $record): void
    {
        if (!is_string($sessionId) || $sessionId === '') {
            throw new \RuntimeException('nonce-store: session id must be a non-empty string');
        }
        if (isset($this->live[$sessionId]) || isset($this->spent[$sessionId])) {
            throw new \RuntimeException('nonce-store: session already exists');
        }
        $this->live[$sessionId] = $record->copy();
    }

    public function load(mixed $sessionId): ?NonceRecord
    {
        return is_string($sessionId) && isset($this->live[$sessionId]) ? $this->live[$sessionId]->copy() : null;
    }

    public function spend(mixed $sessionId): void
    {
        if (!is_string($sessionId) || !isset($this->live[$sessionId])) {
            throw new \RuntimeException('nonce-store: cannot spend a session that is not live');
        }
        $this->live[$sessionId]->wipe();
        unset($this->live[$sessionId]);
        $this->spent[$sessionId] = true;
    }

    public function drop(mixed $sessionId): void
    {
        if (is_string($sessionId) && isset($this->live[$sessionId])) {
            $this->live[$sessionId]->wipe();
            unset($this->live[$sessionId]);
        }
    }

    public function isSpent(mixed $sessionId): bool
    {
        return is_string($sessionId) && isset($this->spent[$sessionId]);
    }
}

final class NonceStoreContract
{
    /**
     * Run the behavioural contract against a store: `$make` builds a fresh store, `$reopen` simulates a restart (identity for an in-memory store).
     * Throws `nonce-store contract: <what>` on the first violation.
     * @param \Closure():NonceStore $make @param ?\Closure(NonceStore):NonceStore $reopen
     */
    public static function assert(\Closure $make, ?\Closure $reopen = null): void
    {
        $reopen ??= static fn(NonceStore $s): NonceStore => $s;
        $rec = static fn(int $n): NonceRecord => new NonceRecord(str_repeat(chr($n), 32), str_repeat(chr($n + 1), 32), str_repeat(chr($n + 2), 32), str_repeat(chr($n + 3), 32), $n);
        $must = static function (bool $ok, string $what): void {
            if (!$ok) {
                throw new \RuntimeException("nonce-store contract: $what");
            }
        };
        $throws = static function (\Closure $f): bool {
            try {
                $f();
            } catch (\Throwable) {
                return true;
            }
            return false;
        };
        $s = $make();
        $must($s->load('a') === null && !$s->isSpent('a'), 'an unknown id is neither live nor spent');
        $s->create('a', $rec(1));
        $must($throws(static fn() => $s->create('a', $rec(9))), 'create must refuse an existing live id');
        $s->create('b', $rec(5));
        $s = $reopen($s);
        $got = $s->load('a');
        $must($got !== null && ord($got->hiding[0]) === 1 && $got->createdAt === 1, 'a live record survives a restart');
        $got->hiding = str_repeat("\xee", 32);
        $again = $s->load('a');
        $must($again !== null && ord($again->hiding[0]) === 1, 'load returns a copy');
        $s->spend('a');
        $must($s->load('a') === null && $s->isSpent('a'), 'spend removes the secret and records the marker');
        $must($throws(static fn() => $s->spend('a')), 'a second spend must throw');
        $must($throws(static fn() => $s->create('a', $rec(2))), 'create must refuse a spent id');
        $must($throws(static fn() => $s->spend('zzz')), 'spend of an unknown id must throw');
        $s = $reopen($s);
        $must($s->isSpent('a') && $s->load('a') === null, 'a spent marker survives a restart');
        $must($s->load('b') !== null, 'the other live record survives');
        $s->drop('b');
        $must($s->load('b') === null && !$s->isSpent('b'), 'drop removes a live record without marking it spent');
        $s->drop('never-existed');
    }
}
