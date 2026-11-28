<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Console.php';
require_once __DIR__ . '/../src/Session.php';

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Catalog;
use Atlas\Pca\Console;
use Atlas\Pca\Facade;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Session;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Session.php: a root without a readable envelope, the depth cap message, the console filter. */
final class GuardSurvivorKill33SessionTest extends TestCase
{
    private static function handle(): AgentHandle
    {
        return Facade::createAgent(new KeyPair(hash('sha256', 'atlas-pca-conformance/g33-session-p', true)), 'g', ['files' => ['read']],
            holder: new KeyPair(hash('sha256', 'atlas-pca-conformance/g33-session-h', true)), now: 0);
    }

    /** A root whose grant carries no envelope starts a session with an empty goal commitment (no error). */
    public function testRootWithoutEnvelopeHasNoGoal(): void
    {
        $h = self::handle();
        $this->assertNotSame('', Session::start($h)->goalCommit, 'control: a real root has a goal commitment');
        $bare = new AgentHandle(new Obj(), [], 's', $h->policy, $h->holder, $h->principalPublic, new Catalog(), null, 0, null);
        $s = Session::start($bare);
        $this->assertSame('', $s->goalCommit);
        $this->assertFalse($s->sharesGoal());
    }

    /** A session already deeper than MAX_DEPTH refuses another hop with the reference's message. */
    public function testDepthCapMessage(): void
    {
        $h = self::handle();
        $s = new Session($h, array_fill(0, Session::MAX_DEPTH + 1, $h), 'x');
        try {
            $s->addMember();
            $this->fail('a 34th member was added');
        } catch (\RangeException $e) {
            $this->assertSame('addMember: a session is limited to 32 delegation hops', $e->getMessage());
        }
    }

    /** The console keeps the session's own agents' events. */
    public function testConsoleKeepsOwnEvents(): void
    {
        $h = self::handle();
        $s = Session::start($h);
        $mine = Obj::of(['agent' => $h->holder->public, 'outcome' => 'auto', 'at' => new Num('1')]);
        $other = Obj::of(['agent' => 'someone-else', 'outcome' => 'auto']);
        $this->assertEquals(Console::buildConsole([$mine]), $s->console([$mine, $other]));
        $this->assertNotEquals(Console::buildConsole([]), Console::buildConsole([$mine]), 'control: the event is visible in the console');
    }
}
