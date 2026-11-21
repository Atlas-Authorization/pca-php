<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** A transaction on ONE session's history, holding its exclusive lock. An event is `{id, verb, resource, params, t, status}`. */
interface SessionTx
{
    /** @return list<Obj> */
    public function events(): array;

    public function append(Obj $e): void;

    public function setStatus(string $id, string $status): bool;
}

/**
 * The accumulator state holder. LIN holds iff `withSession` serialises every admission of a session: the pre-state read, the verification
 * and the `reserved` append happen under one lock (a row lock in a database). `durable()` is true when the history survives a restart of
 * the process; a store that is not is refused by {@see IntentHistory::admitIntentAction} unless the caller opts out.
 */
interface IntentSessionStore
{
    public function withSession(string $session, callable $fn): mixed;

    public function durable(): bool;
}

/**
 * TEST DOUBLE for the session store: in-process and VOLATILE (`durable()` is false), a restart forgets every session's history. PHP runs one
 * request at a time per process, so `withSession` needs no lock here; production implements {@see IntentSessionStore} over its database.
 */
final class MemoryIntentSessionStore implements IntentSessionStore
{
    /** @var array<string,list<Obj>> */
    private array $logs = [];

    public function durable(): bool
    {
        return false;
    }

    public function withSession(string $session, callable $fn): mixed
    {
        $log = &$this->logs[$session];
        $log ??= [];
        $tx = new class ($log) implements SessionTx {
            /** @param list<Obj> $log */
            public function __construct(private array &$log)
            {
            }

            public function events(): array
            {
                return array_map(static fn(Obj $e): Obj => $e->without(), $this->log);
            }

            public function append(Obj $e): void
            {
                foreach ($this->log as $x) {
                    if ($x->get('id') === $e->get('id')) {
                        throw new \RuntimeException('duplicate event id');
                    }
                }
                $this->log[] = $e->without();
            }

            public function setStatus(string $id, string $status): bool
            {
                foreach ($this->log as $x) {
                    if ($x->get('id') === $id) {
                        $x->set('status', $status);
                        return true;
                    }
                }
                return false;
            }
        };
        return $fn($tx);
    }

    /** @return list<Obj> */
    public function snapshot(string $session): array
    {
        return array_map(static fn(Obj $e): Obj => $e->without(), $this->logs[$session] ?? []);
    }
}
