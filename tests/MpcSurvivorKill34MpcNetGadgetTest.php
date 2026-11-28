<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetCodec;
use Atlas\Pca\MpcNetExchanger;
use Atlas\Pca\MpcNetGadget;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** A socket-free mesh: a fixed session id and a keyed-hash stand-in for each party's identity signature. */
final class Mpc34GadgetMesh extends MpcNetMesh
{
    public function __construct(int $id)
    {
        \Closure::bind(function () use ($id): void {
            $this->selfId = $id;
        }, $this, MpcNetMesh::class)();
    }

    public function __destruct()
    {
    }

    public function sessionId(): string
    {
        return MpcSurvivorKill34MpcNetGadgetTest::SID;
    }

    public static function sigOf(int $signer, string $data): string
    {
        return hash('sha256', $signer . "\0" . $data, true);
    }

    public function sign(string $data): string
    {
        return self::sigOf($this->selfId, $data);
    }

    public function verify(int $peer, string $data, string $sig): bool
    {
        return $peer !== $this->selfId && hash_equals(self::sigOf($peer, $data), $sig);
    }
}

/** Raised by the scripted exchanger on a round the test did not script. */
final class Mpc34GadgetStop extends \RuntimeException
{
}

/** Answers each scripted round with fixed raw values per peer, through the caller's own mine/parse closures; bad() throws its text. */
final class Mpc34GadgetScript implements MpcNetExchanger
{
    /** @param array<string,array<int,mixed>> $script */
    public function __construct(private readonly array $script)
    {
    }

    public function exchange(string $rd, callable $mine, callable $parse, ?int $timeoutMs = null): array
    {
        $byPeer = $this->script[$rd] ?? throw new Mpc34GadgetStop($rd);
        $out = [];
        foreach ($byPeer as $p => $raw) {
            $mine($p);
            $out[$p] = $parse($p, $raw);
        }
        return $out;
    }

    public function bad(int $p, string $what): never
    {
        throw new \LogicException("$p: $what");
    }
}

/**
 * Group 34 kills for MpcNetGadget::agreeGadgetSeeds: every shape and signature refusal of the commit and reveal rounds, the opening
 * check, and the echo round's refusals with the exact equivocation abort (message and transferable evidence) for both rounds.
 */
final class MpcSurvivorKill34MpcNetGadgetTest extends TestCase
{
    public const SID = 'mpc34-gadget-session';

    private static function seed(int $p): string
    {
        return str_repeat(chr(0x40 + $p), 32);
    }

    private static function signed(int $signer, string $round, string $v): Obj
    {
        return Obj::of(['v' => $v, 's' => bin2hex(Mpc34GadgetMesh::sigOf($signer, MpcNetCodec::gadgetStatement(self::SID, $round, $signer, $v)))]);
    }

    private static function commit(int $p, ?string $seed = null): Obj
    {
        return self::signed($p, 'gd-c', MpcNetCodec::gadgetCommit(self::SID, $p, $seed ?? self::seed($p)));
    }

    private static function open(int $p, ?string $seed = null): Obj
    {
        return self::signed($p, 'gd-o', bin2hex($seed ?? self::seed($p)));
    }

    /** @param array<string,array<int,mixed>> $script */
    private static function agree(int $n, array $script): array
    {
        return MpcNetGadget::agreeGadgetSeeds(new Mpc34GadgetMesh(0), $n, new Mpc34GadgetScript($script), self::seed(0));
    }

    private static function refusedAs(string $msg, int $n, array $script): void
    {
        try {
            self::agree($n, $script);
        } catch (\Throwable $e) {
            self::assertSame(\LogicException::class, $e::class, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("expected the refusal: $msg");
    }

    /** With n = 2 an honest peer's seed is returned in party order beside mine. */
    public function testHonestTwoPartyAgreement(): void
    {
        $this->assertSame([self::seed(0), self::seed(1)], self::agree(2, ['gd-c' => [1 => self::commit(1)], 'gd-o' => [1 => self::open(1)]]));
    }

    /** A commitment that is not a signed object, has a malformed value, or carries a signature that does not verify is refused. */
    public function testCommitRoundRefusals(): void
    {
        self::refusedAs('1: bad gadget commitment', 2, ['gd-c' => [1 => 'not-an-object']]);
        self::refusedAs('1: bad gadget commitment', 2, ['gd-c' => [1 => self::signed(1, 'gd-c', 'zz')]]);
        self::refusedAs('1: gadget commitment signature does not verify', 2,
            ['gd-c' => [1 => Obj::of(['v' => self::commit(1)->get('v'), 's' => str_repeat('00', 32)])]]);
    }

    /** A seed opening with a malformed value or a bad signature is refused; a signed seed that is not the committed one aborts. */
    public function testRevealRoundRefusals(): void
    {
        $c = ['gd-c' => [1 => self::commit(1)]];
        self::refusedAs('1: bad gadget seed', 2, $c + ['gd-o' => [1 => self::signed(1, 'gd-o', 'zz')]]);
        self::refusedAs('1: gadget seed signature does not verify', 2, $c + ['gd-o' => [1 => Obj::of(['v' => bin2hex(self::seed(1)), 's' => str_repeat('00', 32)])]]);
        try {
            self::agree(2, $c + ['gd-o' => [1 => self::open(1, str_repeat("\x7f", 32))]]);
            $this->fail('an opening of another seed must abort');
        } catch (MpcNetAbort $e) {
            $this->assertSame('commitment', $e->kind);
            $this->assertSame(1, $e->blamed);
            $this->assertSame('[commitment] blamed=1 reporter=0: party 1 opened a gadget seed that does not match its commitment', $e->getMessage());
        }
    }

    /** @return array{0:Obj,1:Obj,2:Obj,3:Obj} the commitments and openings of parties 1 and 2 */
    private static function three(): array
    {
        return [self::commit(1), self::commit(2), self::open(1), self::open(2)];
    }

    /** @param list<mixed> $echoFrom1 */
    private static function threeScript(array $echoFrom1): array
    {
        [$c1, $c2, $o1, $o2] = self::three();
        return ['gd-c' => [1 => $c1, 2 => $c2], 'gd-o' => [1 => $o1, 2 => $o2],
            'gd-e' => [1 => $echoFrom1, 2 => [Obj::of(['j' => new Num('1'), 'c' => $c1, 'o' => $o1])]]];
    }

    /** With n = 3 consistent echoes complete the agreement. */
    public function testHonestThreePartyAgreement(): void
    {
        [, $c2, , $o2] = self::three();
        $this->assertSame([self::seed(0), self::seed(1), self::seed(2)], self::agree(3, self::threeScript([Obj::of(['j' => new Num('2'), 'c' => $c2, 'o' => $o2])])));
    }

    /** An echo that is not a list of the expected size, an entry about the wrong party, or a statement the signer never signed is refused. */
    public function testEchoRoundRefusals(): void
    {
        [, $c2, , $o2] = self::three();
        self::refusedAs('1: bad gadget echo', 3, self::threeScript([]));
        self::refusedAs('1: bad gadget echo entry', 3, self::threeScript([Obj::of(['j' => new Num('5'), 'c' => $c2, 'o' => $o2])]));
        $forged = Obj::of(['v' => $c2->get('v'), 's' => str_repeat('00', 32)]);
        self::refusedAs('1: gadget echo carries a statement that party 2 did not sign', 3, self::threeScript([Obj::of(['j' => new Num('2'), 'c' => $forged, 'o' => $o2])]));
    }

    /** Party 2 signing two commitments (or two seeds) is blamed on party 2, with both signed statements as the evidence. */
    public function testEquivocationIsBlamedWithBothStatements(): void
    {
        [, $c2, , $o2] = self::three();
        $otherC = self::commit(2, str_repeat("\x11", 32));
        $otherO = self::open(2, str_repeat("\x22", 32));
        $cases = [
            'commitments' => [Obj::of(['j' => new Num('2'), 'c' => $otherC, 'o' => $o2]), ['signer' => 2, 'round' => 'gd-c', 'statements' => [$c2, $otherC]]],
            'seeds' => [Obj::of(['j' => new Num('2'), 'c' => $c2, 'o' => $otherO]), ['signer' => 2, 'round' => 'gd-o', 'statements' => [$o2, $otherO]]],
        ];
        foreach ($cases as $what => [$entry, $evidence]) {
            $script = self::threeScript([$entry]);
            // the script's own commitment / opening objects are the ones the evidence must carry
            $script['gd-c'][2] = $c2;
            $script['gd-o'][2] = $o2;
            try {
                self::agree(3, $script);
                $this->fail("equivocating $what must abort");
            } catch (MpcNetAbort $e) {
                $this->assertSame('equivocation', $e->kind);
                $this->assertSame(2, $e->blamed);
                $this->assertSame(0, $e->reporter);
                $this->assertSame("[equivocation] blamed=2 reporter=0: party 2 signed different gadget $what for different parties (shown by party 1's echo)", $e->getMessage());
                $this->assertSame($evidence, $e->evidence);
            }
        }
    }
}
