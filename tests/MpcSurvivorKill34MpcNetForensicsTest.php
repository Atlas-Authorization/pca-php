<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetExchanger;
use Atlas\Pca\MpcNetForensics;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Raised by the scripted exchanger on a round the test did not script. */
final class Mpc34ForensicsStop extends \RuntimeException
{
}

/** Answers each scripted round with fixed raw values per peer, through the caller's own parse closure; bad() throws its text. */
final class Mpc34ForensicsScript implements MpcNetExchanger
{
    /** @param array<string,array<int,mixed>> $script */
    public function __construct(private readonly array $script)
    {
    }

    public function exchange(string $rd, callable $mine, callable $parse, ?int $timeoutMs = null): array
    {
        $byPeer = $this->script[$rd] ?? throw new Mpc34ForensicsStop($rd);
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
 * Group 34 kills for MpcNetForensics: the peer-table shape check of a disclosure, and the commit-first exchange's refusals (commitment
 * form, the agreed deadline, the opening nonce, an opening that does not match its commitment).
 */
final class MpcSurvivorKill34MpcNetForensicsTest extends TestCase
{
    private const SID = 'mpc34-forensics';
    private const DEADLINE = 30000;

    private static function disclose(array $script, int $slots = 0): array
    {
        return MpcNetForensics::exchangeDisclosures(self::SID, 0, 2, 3, [], $slots, 1, self::DEADLINE, new Mpc34ForensicsScript($script));
    }

    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame($class, $e::class, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("expected $class: $msg");
    }

    /** A recv table that is not a list is refused as 'bad peer table' even when the rho table is valid. */
    public function testParseRefusesABadPeerTable(): void
    {
        $slot = static fn(mixed $recv): Obj => Obj::of(['bits' => '1', 'y' => '1', 'z' => '1', 'recv' => $recv, 'rho' => [[new Num('1'), ['2']]]]);
        self::refuses(\InvalidArgumentException::class, 'bad peer table', static fn() => MpcNetForensics::parseDisclosure([$slot('nope')], 1, 1, [1]));
        $ok = MpcNetForensics::parseDisclosure([$slot([[new Num('1'), ['3']]])], 1, 1, [1]);
        $this->assertSame([1], $ok[0]['bits']);
        $this->assertSame('3', gmp_strval($ok[0]['recv'][1][0]));
        $this->assertSame('2', gmp_strval($ok[0]['rho'][1][0]));
    }

    /** A commitment that is not 64 lowercase hex digits is refused naming the peer, even with the agreed deadline. */
    public function testBadCommitmentForm(): void
    {
        self::refuses(\LogicException::class, '1: bad forensic commitment', static fn() => self::disclose(['forensic-c' => [1 => Obj::of(['c' => 'zz', 'd' => new Num('30000')])]]));
    }

    /** A peer announcing another deadline is refused with the agreed one in the message. */
    public function testDeadlineMustMatch(): void
    {
        self::refuses(\LogicException::class, '1: forensic deadline differs from the agreed 30000',
            static fn() => self::disclose(['forensic-c' => [1 => Obj::of(['c' => str_repeat('0', 64), 'd' => new Num('29999')])]]));
    }

    /** An opening whose nonce is not 64 hex digits is refused; one that does not match the commitment aborts blaming the opener. */
    public function testOpeningChecks(): void
    {
        $c = ['forensic-c' => [1 => Obj::of(['c' => str_repeat('0', 64), 'd' => new Num('30000')])]];
        self::refuses(\LogicException::class, '1: bad forensic opening', static fn() => self::disclose($c + ['forensic-o' => [1 => Obj::of(['w' => [], 'nonce' => 'xyz'])]]));
        try {
            self::disclose($c + ['forensic-o' => [1 => Obj::of(['w' => [], 'nonce' => str_repeat('a', 64)])]]);
            $this->fail('a mismatched opening must abort');
        } catch (MpcNetAbort $e) {
            $this->assertSame('commitment', $e->kind);
            $this->assertSame(1, $e->blamed);
            $this->assertSame(0, $e->reporter);
            $this->assertSame('[commitment] blamed=1 reporter=0: party 1 opened a forensic disclosure that does not match its commitment', $e->getMessage());
        }
        // control: an opening that matches its commitment is accepted and parsed
        $nonce = str_repeat('b', 64);
        $good = ['forensic-c' => [1 => Obj::of(['c' => MpcNetForensics::disclosureCommit(self::SID, 1, 3, self::DEADLINE, $nonce, []), 'd' => new Num('30000')])],
            'forensic-o' => [1 => Obj::of(['w' => [], 'nonce' => $nonce])]];
        $this->assertSame([1 => []], self::disclose($good));
    }
}
