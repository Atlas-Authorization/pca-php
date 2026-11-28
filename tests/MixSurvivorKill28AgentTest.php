<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\Fndsa;
use Atlas\Pca\JsonError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Predicates;
use Atlas\Pca\Sign;
use Atlas\Pca\UnsupportedSigner;
use PHPUnit\Framework\TestCase;

/** Group 28 survivors in Agent.php: FN-DSA key-pair checks, Sign::n's depth bound, passport times and the local envelope check. */
final class MixSurvivorKill28AgentTest extends TestCase
{
    private const NOW = 1800000000000;

    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
        Agent::$clockHook = null;
    }

    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
            self::fail("expected $class");
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
        }
    }

    // ---- PqKeyPair, FN-DSA ----

    /** A caller-supplied FN-DSA bundle checks the sign seed (when given) and the verifying key length, then signs through the backend. */
    public function testFnDsaBundle(): void
    {
        Fndsa::registerTestBackend();
        $kp = Fndsa::mockKeypair('fn-dsa-512');
        $pair = PqKeyPair::fnDsa('FN-DSA-512', $kp['pk'], $kp['sk']);
        self::assertSame([Pca::b64u($kp['pk']), 'FN-DSA-512'], [$pair->public, $pair->family]);
        self::assertSame(Fndsa::sign('fn-dsa-512', $kp['sk'], 'm'), $pair->sign('m'));
        self::assertSame(Pca::b64u($kp['pk']), PqKeyPair::fnDsa('FN-DSA-512', $kp['pk'], $kp['sk'], str_repeat("\7", 32))->public);
        self::refuses(\InvalidArgumentException::class, 'a FN-DSA-512 sign seed is 32 bytes', static fn() => PqKeyPair::fnDsa('FN-DSA-512', $kp['pk'], $kp['sk'], 'short'));
        self::refuses(\InvalidArgumentException::class, 'a FN-DSA-512 verifying key is 897 bytes', static fn() => PqKeyPair::fnDsa('FN-DSA-512', substr($kp['pk'], 1), $kp['sk']));
        unset($pair); // an FN-DSA pair holds no OpenSSL key: destruction frees nothing and must not throw
    }

    /** A key pair whose backend was removed after it was made refuses to sign. */
    public function testFnDsaSignNeedsTheBackend(): void
    {
        Fndsa::registerTestBackend();
        $kp = Fndsa::mockKeypair('fn-dsa-512');
        $pair = PqKeyPair::fnDsa('FN-DSA-512', $kp['pk'], $kp['sk']);
        Fndsa::resetFalconBackend();
        self::refuses(UnsupportedSigner::class, 'unsupported_suite: FN-DSA-512', static fn() => $pair->sign('m'));
    }

    /** A keygen seed of the wrong length is refused here; a null or a 32-byte seed passes this check (the native keygen decides). */
    public function testFnDsaKeygenSeedCheck(): void
    {
        Fndsa::registerTestBackend();
        self::refuses(\InvalidArgumentException::class, 'a FN-DSA-512 seed is 32 bytes', static fn() => new PqKeyPair('FN-DSA-512', 'short'));
        foreach ([null, str_repeat("\1", 32)] as $seed) {
            try {
                new PqKeyPair('FN-DSA-512', $seed);
            } catch (\Throwable $e) {
                self::assertNotInstanceOf(\TypeError::class, $e);
                self::assertStringNotContainsString('seed is 32 bytes', $e->getMessage());
            }
        }
    }

    // ---- Sign::n ----

    /** A value nested deeper than 1000 levels is refused before recursing further. */
    public function testNestingBound(): void
    {
        $v = 1;
        for ($i = 0; $i < 1100; $i++) {
            $v = [$v];
        }
        self::refuses(JsonError::class, 'nesting too deep', static fn() => Sign::n($v));
    }

    // ---- passports ----

    private static function passport(): Obj
    {
        return Sign::issuePassport(['model_id' => 'm', 'operator' => 'acme', 'hardware_rooted' => false, 'issued_at' => 1800000000000]);
    }

    /** iat, nbf and exp are signed as integers, also at 1e15 and above, and an exp of exactly 2^53 - 1 is accepted. */
    public function testPassportTimesStayIntegers(): void
    {
        $issuer = new KeyPair(str_repeat("\3", 32));
        $sp = Sign::signPassport(self::passport(), $issuer, 'sub', 9007199254740991, 1000000000000000, 1000000000000001);
        self::assertSame(['1000000000000000', '1000000000000001', '9007199254740991'],
            [$sp->get('iat')->lexeme, $sp->get('nbf')->lexeme, $sp->get('exp')->lexeme]);
    }

    /** An invalid iat is refused even when nbf is valid. */
    public function testPassportRefusesABadIatAlone(): void
    {
        $issuer = new KeyPair(str_repeat("\3", 32));
        self::refuses(\InvalidArgumentException::class, 'signPassport: iat/nbf/exp must be safe integers with exp > nbf',
            static fn() => Sign::signPassport(self::passport(), $issuer, 'sub', 1800003600000, 'x', 1800000000000));
    }

    // ---- envelopeRefusal ----

    private static function envelope(array $caveats = []): array
    {
        return ['type' => 'envelope', 'predicates' => [['verb' => 'refund', 'resource' => 'orders/1',
            'where' => [['field' => 'action.params.amount', 'op' => 'eq', 'value' => 5]]]], 'caveats' => $caveats];
    }

    private static function agent(array $caveats): Agent
    {
        return new Agent(new KeyPair(str_repeat("\1", 32)), Sign::n(['caveats' => $caveats]), 'rs');
    }

    /** Without an injected clock the check runs at the wall clock in whole milliseconds, and the action carries its params. */
    public function testEnvelopeAdmitsAtTheWallClock(): void
    {
        Agent::$clockHook = static fn(): float => 1800000000.0005;
        $a = self::agent([self::envelope([['type' => 'expires', 'at' => 1800000000000.25]])]);
        self::assertNull($a->envelopeRefusal('refund', 'orders/1', ['amount' => 5]));
        Agent::$clockHook = static fn(): float => 1800000001.0;
        self::assertSame('caveat(s) failed: expires', $a->envelopeRefusal('refund', 'orders/1', ['amount' => 5]));
    }

    /** Every failed caveat of an envelope is listed. */
    public function testEnvelopeListsFailedCaveats(): void
    {
        $a = new Agent(new KeyPair(str_repeat("\1", 32)), Sign::n(['caveats' => [self::envelope([['type' => 'expires', 'at' => 1],
            ['type' => 'not_before', 'at' => self::NOW + 1]])]]), 'rs', null, 0, static fn(): int => self::NOW);
        self::assertSame('caveat(s) failed: expires, not_before', $a->envelopeRefusal('refund', 'orders/1', ['amount' => 5]));
    }

    /** A predicate refusal returns the evaluator's own reason. */
    public function testEnvelopePredicateReason(): void
    {
        $a = self::agent([self::envelope()]);
        $got = $a->envelopeRefusal('refund', 'orders/1', ['amount' => 6]);
        $want = Predicates::evaluatePredicates(Sign::n([self::envelope()])[0]->get('predicates'),
            Obj::of(['action' => Sign::n(['verb' => 'refund', 'resource' => 'orders/1', 'params' => ['amount' => 6]])]))['reason'];
        self::assertSame($want, $got);
        self::assertNotSame('no predicate matched', $got);
    }

    /** Non-object and non-envelope caveats are skipped, and an envelope after them is still checked. */
    public function testEnvelopeSkipsOtherCaveats(): void
    {
        $a = self::agent(['junk', ['type' => 'expires', 'at' => 1], self::envelope()]);
        self::assertNull($a->envelopeRefusal('refund', 'orders/1', ['amount' => 5]));
        self::assertNotNull($a->envelopeRefusal('refund', 'orders/1', ['amount' => 6]));
    }
}
