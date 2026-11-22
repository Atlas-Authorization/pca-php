<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Ledger;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Mutation kills for Ledger, over heads, cosignatures and proofs signed here with fixed-seed Ed25519 keys. */
final class K05KillLedgerTest extends TestCase
{
    /** @return array{0: string, 1: string} [public b64u, secret] */
    private static function key(int $seed): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat(chr($seed), 32));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function sign(string $sk, string $msg): string
    {
        return Pca::b64u(sodium_crypto_sign_detached($msg, $sk));
    }

    private static function h(string $l, string $r): string
    {
        return hash('sha256', "\x01" . $l . $r, true);
    }

    /** A guardian-signed tree head over exactly `$f` (instance_id, principal, size, root, prev_root, timestamp). */
    private static function sth(array $f): Obj
    {
        [$g, $sk] = self::key(1);
        $o = Obj::of($f);
        $o->set('guardian', $g);
        $o->set('sig', self::sign($sk, Ledger::STH_DOMAIN . Json::canonicalizeStrict(Obj::of($f))));
        return $o;
    }

    /** A cosignature of `$sth` by the witness of seed 2 (under `$key` on the wire). */
    private static function cosig(Obj $sth, ?string $key = null): Obj
    {
        [$w, $sk] = self::key(2);
        $body = Obj::of(['instance_id' => $sth->get('instance_id'), 'principal' => $sth->get('principal'), 'size' => $sth->get('size'),
            'root' => $sth->get('root'), 'prev_root' => $sth->get('prev_root'), 'guardian_epoch' => new Num('0')]);
        return Obj::of(['key' => $key ?? $w, 'sig' => self::sign($sk, Ledger::STH_WITNESS_DOMAIN . Json::canonicalizeStrict($body))]);
    }

    /** A legacy witnessed head (witness of seed 2) signed over principal/size/root; `$root` null = the member is absent. */
    private static function wh(mixed $size, ?string $root): Obj
    {
        [$w, $sk] = self::key(2);
        $o = Obj::of(['principal' => 'p', 'size' => $size]);
        if ($root !== null) {
            $o->set('root', $root);
        }
        $o->set('witness', $w);
        $o->set('sig', self::sign($sk, Ledger::HEAD_DOMAIN . Json::canonicalizeStrict(Obj::of(['principal' => 'p', 'size' => $size, 'root' => $root]))));
        return $o;
    }

    private static function wrap(Obj $o): object
    {
        return new class($o) {
            public function __construct(private Obj $o)
            {
            }

            public function has(string $k): bool
            {
                return $this->o->has($k);
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }
        };
    }

    private static function cp(int $a, int $b, array $path): Obj
    {
        return Obj::of(['oldSize' => new Num((string)$a), 'newSize' => new Num((string)$b), 'path' => $path]);
    }

    public function testNativeNumbersAreNumbers(): void
    {
        $this->assertTrue(Ledger::verifyWitnessCosignatures(new Obj(), Obj::of(['threshold' => 0])));
        $this->assertTrue(Ledger::verifyWitnessCosignatures(new Obj(), Obj::of(['threshold' => 0.0])));
        $this->assertFalse(Ledger::verifyWitnessCosignatures(new Obj(), Obj::of(['threshold' => 0.5])));
        $e = Ledger::emptyTreeRoot();
        $this->assertTrue(Ledger::verifyConsistency($e, $e, Obj::of(['oldSize' => 0, 'newSize' => 0, 'path' => []])));
    }

    public function testPinForReadsAnArray(): void
    {
        $this->assertSame('pk', Ledger::pinFor(['id' => 'pk'], 'id'));
        $this->assertSame('pk', Ledger::pinFor(Obj::of(['id' => 'pk']), 'id'));
        $this->assertNull(Ledger::pinFor(['id' => 'pk'], 'other'));
        $this->assertNull(Ledger::pinFor(['id' => 7], 'id'));
    }

    public function testSignedRefusesANonStringIdentity(): void
    {
        [$w, $sk] = self::key(2);
        $body = Obj::of(['a' => 'b']);
        $m = Obj::of(['sig' => self::sign($sk, 'd' . Json::canonicalizeStrict($body))]);
        $this->assertTrue(Ledger::signed('d', $body, $w, $m, null));
        $this->assertFalse(Ledger::signed('d', $body, 123, $m, null));
        $this->assertFalse(Ledger::signed('d', $body, $w, Obj::of(['sig' => 5]), null));
    }

    /** Every node is 32 bytes: with oldSize 1 a 31/33-byte old root (or path node) plus a crafted new root must not verify. */
    public function testConsistencyRefusesNodesThatAreNot32Bytes(): void
    {
        $c = str_repeat("\x33", 32);
        foreach ([31, 32, 33] as $n) {
            $bad = str_repeat("\x44", $n);
            $ok = $n === 32;
            // the odd-length value as the old root
            $this->assertSame($ok, Ledger::verifyConsistency(Pca::b64u($bad), Pca::b64u(self::h($bad, $c)), self::cp(1, 2, [Pca::b64u($c)])), "old root $n");
            // the odd-length value as the path element
            $this->assertSame($ok, Ledger::verifyConsistency(Pca::b64u($c), Pca::b64u(self::h($c, $bad)), self::cp(1, 2, [Pca::b64u($bad)])), "path $n");
        }
    }

    public function testConsistencyGatesAndTheTwoLeafProof(): void
    {
        $e = Ledger::emptyTreeRoot();
        $a = str_repeat("\x11", 32);
        $b = str_repeat("\x22", 32);
        $old = Pca::b64u($a);
        $new = Pca::b64u(self::h($a, $b));
        $this->assertTrue(Ledger::verifyConsistency($old, $new, self::cp(1, 2, [Pca::b64u($b)])));
        // a non-list path is refused, even when its values would verify
        $this->assertFalse(Ledger::verifyConsistency($old, $new, self::cp(1, 2, ['k' => Pca::b64u($b)])));
        // an undecodable old root of a power-of-two old tree
        $this->assertFalse(Ledger::verifyConsistency('!!!', $new, self::cp(1, 2, [Pca::b64u($b)])));
        // a non-string new root, even where the new root is never compared (an empty old tree)
        $this->assertFalse(Ledger::verifyConsistency($e, 123, self::cp(0, 3, [])));
        $this->assertTrue(Ledger::verifyConsistency($e, 'anything', self::cp(0, 3, [])));
        // a proof that answers like an Obj but is not one
        $this->assertFalse(Ledger::verifyConsistency($e, $e, self::wrap(self::cp(0, 0, []))));
    }

    public function testOneWitnessCosignature(): void
    {
        [$w] = self::key(2);
        $sth = self::sth(['instance_id' => 'i', 'principal' => 'p', 'size' => new Num('3'), 'root' => 'r', 'prev_root' => 'q', 'timestamp' => new Num('1')]);
        $this->assertTrue(Ledger::verifyWitnessCosignature($sth, self::cosig($sth), $w));
        // a cosignature naming another key is refused although its signature verifies under the witness key
        $this->assertFalse(Ledger::verifyWitnessCosignature($sth, self::cosig($sth, 'other'), $w));
        // a head missing a signed member: the body cannot be built
        $this->assertFalse(Ledger::verifyWitnessCosignature($sth->without('instance_id'), self::cosig($sth), $w));
    }

    public function testTheWitnessThreshold(): void
    {
        [$w] = self::key(2);
        $sth = self::sth(['instance_id' => 'i', 'principal' => 'p', 'size' => new Num('3'), 'root' => 'r', 'prev_root' => 'q', 'timestamp' => new Num('1')]);
        $policy = Obj::of(['threshold' => new Num('1'), 'witnessKeys' => [$w]]);
        $listed = $sth->without();
        $listed->set('witnesses', [self::cosig($sth)]);
        $this->assertTrue(Ledger::verifyWitnessCosignatures($listed, $policy));
        $keyed = $sth->without();
        $keyed->set('witnesses', ['a' => self::cosig($sth)]);
        $this->assertFalse(Ledger::verifyWitnessCosignatures($keyed, $policy));
        // type gates, checked before the zero threshold answers
        $zero = Obj::of(['threshold' => new Num('0')]);
        $this->assertTrue(Ledger::verifyWitnessCosignatures($sth, $zero));
        $this->assertFalse(Ledger::verifyWitnessCosignatures('x', $zero));
        $this->assertFalse(Ledger::verifyWitnessCosignatures($sth, self::wrap($zero)));
    }

    public function testNonStringWitnessKeysAreDroppedQuietly(): void
    {
        $seen = [];
        set_error_handler(function (int $no, string $msg) use (&$seen): bool {
            $seen[] = $msg;
            return true;
        });
        try {
            $r = Ledger::verifyWitnessCosignatures(new Obj(), Obj::of(['threshold' => new Num('1'), 'witnessKeys' => [new Num('1'), true]]));
        } finally {
            restore_error_handler();
        }
        $this->assertFalse($r);
        $this->assertSame([], $seen);
    }

    public function testATreeHeadMissingASignedMemberIsRefused(): void
    {
        [$g] = self::key(1);
        $f = ['instance_id' => 'i', 'principal' => 'p', 'size' => new Num('3'), 'root' => 'r', 'prev_root' => 'q', 'timestamp' => new Num('1')];
        $sth = self::sth($f);
        $this->assertTrue(Ledger::verifyTreeHead($sth, $g));
        $this->assertFalse(Ledger::verifyTreeHead($sth->without('timestamp'), $g));
    }

    public function testHeadConsistencyBindsBothProofSizes(): void
    {
        [$g] = self::key(1);
        $e = Ledger::emptyTreeRoot();
        $older = self::sth(['instance_id' => 'i', 'principal' => 'p', 'size' => new Num('1'), 'root' => $e, 'prev_root' => 'z', 'timestamp' => new Num('1')]);
        $newer = self::sth(['instance_id' => 'i', 'principal' => 'p', 'size' => new Num('2'), 'root' => 'R', 'prev_root' => $e, 'timestamp' => new Num('2')]);
        $this->assertTrue(Ledger::verifyTreeHead($older, $g));
        $this->assertTrue(Ledger::verifyTreeHead($newer, $g));
        // the proof alone (0 -> 2 from the empty tree) verifies, but its old size is not the older head's
        $this->assertTrue(Ledger::verifyConsistency($e, 'R', self::cp(0, 2, [])));
        $this->assertFalse(Ledger::verifyHeadConsistency($older, $newer, self::cp(0, 2, []), $g));

        // checkpoint chains: a list only, and a non-object proof is a refusal at its index
        $this->assertSame(['ok' => false, 'at' => 0], Ledger::verifyCheckpointChain([1 => Obj::of(['sth' => $older])], $g));
        $this->assertSame(['ok' => false, 'at' => 1], Ledger::verifyCheckpointChain([Obj::of(['sth' => $older]), Obj::of(['sth' => $newer, 'proof' => 'x'])], $g));
        $this->assertSame(['ok' => false, 'at' => 1], Ledger::verifyCheckpointChain([Obj::of(['sth' => $older]), Obj::of(['sth' => $newer])], $g));
    }

    public function testWitnessedHeadsAndEquivocation(): void
    {
        [$w] = self::key(2);
        $this->assertTrue(Ledger::verifyWitnessedHead(self::wh(new Num('2'), 'r1'), $w));
        // signed over root:null, but the member is absent: refused
        $this->assertFalse(Ledger::verifyWitnessedHead(self::wh(new Num('2'), null), $w));
        $this->assertTrue(Ledger::detectEquivocation(self::wh(new Num('2'), 'r1'), self::wh(new Num('2'), 'r2'), $w));
        $this->assertFalse(Ledger::detectEquivocation(self::wh(new Num('2'), 'r1'), self::wh(new Num('3'), 'r2'), $w));
        // sizes compare like JS ===: equal strings match, different strings do not
        $this->assertTrue(Ledger::detectEquivocation(self::wh('x', 'r1'), self::wh('x', 'r2'), $w));
        $this->assertFalse(Ledger::detectEquivocation(self::wh('x', 'r1'), self::wh('y', 'r2'), $w));
        $this->assertFalse(Ledger::detectEquivocation(self::wh(new Num('2'), 'r1'), self::wh('2', 'r2'), $w));
    }

    /** Runs `$f` with Ledger's fault seam throwing inside `$target` only, always clearing it. */
    private static function faulting(string $target, \Closure $f): mixed
    {
        Ledger::$faultHook = static function (string $fn) use ($target): void {
            if ($fn === $target) {
                throw new \RuntimeException('injected fault');
            }
        };
        try {
            return $f();
        } finally {
            Ledger::$faultHook = null;
        }
    }

    public function testAThrowInsideEachVerifierIsARefusal(): void
    {
        [$g] = self::key(1);
        [$w] = self::key(2);
        $e = Ledger::emptyTreeRoot();
        $older = self::sth(['instance_id' => 'i', 'principal' => 'p', 'size' => new Num('0'), 'root' => $e, 'prev_root' => 'z', 'timestamp' => new Num('1')]);
        $newer = self::sth(['instance_id' => 'i', 'principal' => 'p', 'size' => new Num('2'), 'root' => 'R', 'prev_root' => 'q', 'timestamp' => new Num('2')]);
        $proof = self::cp(0, 2, []);
        $chain = [Obj::of(['sth' => $older]), Obj::of(['sth' => $newer, 'proof' => $proof])];
        $zero = Obj::of(['threshold' => new Num('0')]);
        $a = self::wh(new Num('2'), 'r1');
        $b = self::wh(new Num('2'), 'r2');

        // without a fault every input here verifies
        $this->assertTrue(Ledger::verifyConsistency($e, $e, self::cp(0, 0, [])));
        $this->assertTrue(Ledger::verifyWitnessCosignatures($older, $zero));
        $this->assertTrue(Ledger::verifyHeadConsistency($older, $newer, $proof, $g));
        $this->assertSame(['ok' => true], Ledger::verifyCheckpointChain($chain, $g));
        $this->assertTrue(Ledger::detectEquivocation($a, $b, $w));

        // a throw inside the verifier is its refusal
        $this->assertFalse(self::faulting('verifyConsistency', fn () => Ledger::verifyConsistency($e, $e, self::cp(0, 0, []))));
        $this->assertFalse(self::faulting('verifyWitnessCosignatures', fn () => Ledger::verifyWitnessCosignatures($older, $zero)));
        $this->assertFalse(self::faulting('verifyHeadConsistency', fn () => Ledger::verifyHeadConsistency($older, $newer, $proof, $g)));
        $this->assertSame(['ok' => false, 'at' => 0], self::faulting('verifyCheckpointChain', fn () => Ledger::verifyCheckpointChain($chain, $g)));
        $this->assertFalse(self::faulting('detectEquivocation', fn () => Ledger::detectEquivocation($a, $b, $w)));
        $this->assertNull(Ledger::$faultHook);
    }

    public function testTruthyIsPythonTruthiness(): void
    {
        $t = static fn (mixed $x): bool => (new \ReflectionMethod(Ledger::class, 'truthy'))->invoke(null, $x);
        foreach ([null, false, '', [], new Num('0'), new Num('0.0'), new Obj()] as $x) {
            $this->assertFalse($t($x));
        }
        foreach ([true, 'x', '0', [0], new Num('1'), new Num('5'), new Num('-2'), Obj::of(['k' => null])] as $x) {
            $this->assertTrue($t($x));
        }
    }
}
