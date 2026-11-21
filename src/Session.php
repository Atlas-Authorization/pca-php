<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Console.php';
require_once __DIR__ . '/Facade.php';

/**
 * A multi-agent session, the delegation-tree "team" view: a root agent plus the sub-agents it delegates to share ONE signed goal. A
 * session is a value (members root first, in delegation order); every operation returns a new one.
 */
final class Session
{
    /** Deepest delegation chain a session accepts. */
    public const MAX_DEPTH = 32;

    /** @param list<AgentHandle> $members */
    public function __construct(public readonly ?AgentHandle $root, public readonly array $members, public readonly string $goalCommit)
    {
    }

    /** A session from a root agent; its goal commitment is the root grant's (empty when the grant has no readable envelope). */
    public static function start(AgentHandle $root): self
    {
        return new self($root, [$root], self::goalOf($root));
    }

    private static function goalOf(AgentHandle $a): string
    {
        $g = Authorize::readEnvelope($a->grant)?->get('goal_commit');
        return is_string($g) ? $g : '';
    }

    /** Add a sub-agent: one attenuated delegation hop under the last member; the new session and member. @return array{session:Session,member:AgentHandle} */
    public function addMember(?KeyPair $holder = null, array $addedCaveats = []): array
    {
        if (count($this->members) > self::MAX_DEPTH) {
            throw new \RangeException('addMember: a session is limited to ' . self::MAX_DEPTH . ' delegation hops');
        }
        $member = $this->members[count($this->members) - 1]->subAgent($holder, $addedCaveats);
        return ['session' => new self($this->root, [...$this->members, $member], $this->goalCommit), 'member' => $member];
    }

    /** @return list<string> the holder ids of every agent */
    public function agents(): array
    {
        return array_map(static fn(AgentHandle $m): string => $m->holder->public, $this->members);
    }

    /** A console view scoped to just this session's agents. */
    public function console(mixed $events): Obj
    {
        if (!is_array($events)) {
            throw new \TypeError('events must be a list');
        }
        $ids = $this->agents();
        $mine = [];
        foreach ($events as $e) {
            if ($e === null) {
                throw new \TypeError('event is null'); // the reference reads `.agent` of every element
            }
            if ($e instanceof Obj && in_array($e->get('agent'), $ids, true)) {
                $mine[] = $e;
            }
        }
        return Console::buildConsole($mine);
    }

    /** True iff every member shares the root's (non-empty) goal commitment. */
    public function sharesGoal(): bool
    {
        if ($this->goalCommit === '') {
            return false;
        }
        foreach ($this->members as $m) {
            if (self::goalOf($m) !== $this->goalCommit) {
                return false;
            }
        }
        return true;
    }

    /** Depth of the delegation tree (0 = root only; -1 for an empty hand-built session). */
    public function depth(): int
    {
        return count($this->members) - 1;
    }
}
