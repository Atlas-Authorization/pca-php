<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\A2a;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaGrant;
use PHPUnit\Framework\TestCase;

/** Mutation kills for A2a: needError at every limit, decodeNeed's length cap, the push-token salt floor and signed task-update receipts. */
final class K05KillA2aTest extends TestCase
{
    private static function n(int $i): Num
    {
        return new Num((string)$i);
    }

    private static function need(array $set = []): Obj
    {
        $x = Obj::of(['v' => self::n(1), 'kind' => 'scope', 'verb' => 'read', 'resource' => '/r']);
        foreach ($set as $k => $v) {
            $x->set((string)$k, $v);
        }
        return $x;
    }

    /** @return array{0: string, 1: string} */
    private static function key(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x09", 32));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function rec(array $set = []): Obj
    {
        [$pk, $sk] = self::key();
        $r = Obj::of(['v' => self::n(1), 'task_id' => 't1', 'state' => 'TASK_STATE_WORKING', 'seq' => self::n(0), 'prev' => null,
            'chain' => PcaGrant::chainDigest(['a']), 'issued_at' => self::n(1000), 'signer' => $pk]);
        foreach ($set as $k => $v) {
            $r->set((string)$k, $v);
        }
        $r->set('sig', Pca::b64u(sodium_crypto_sign_detached(A2a::RECEIPT_DOMAIN . Json::canonicalizeStrict($r), $sk)));
        return $r;
    }

    public function testNeedLimits(): void
    {
        $s = static fn (int $n, string $c = 'a'): string => str_repeat($c, $n);
        self::assertNull(A2a::needError(self::need()));
        self::assertSame('bad_shape', A2a::needError('x'));
        $objOf = static function (int $n, mixed $v): Obj {
            $o = new Obj();
            for ($i = 0; $i < $n; $i++) {
                $o->set("k$i", $v);
            }
            return $o;
        };
        $d = Obj::of(['issuer' => 'i', 'claim' => 'c']);
        foreach ([
            ['verb' => $s(128)], ['resource' => $s(512)], ['scopes' => array_fill(0, 16, 'a')], ['scopes' => [$s(128)]], ['grant_ref' => $s(128)], ['scopes' => ["a\u{0085}b", "a\u{180E}b", "a\u{200B}b", "a\xED\xA0\x80b"]],
            ['policy_digest' => $s(128)], ['limits' => $objOf(16, self::n(1))], ['limits' => Obj::of([$s(64, 'k') => self::n(0)])],
            ['discharges' => array_fill(0, 16, $d)], ['discharges' => [Obj::of(['issuer' => $s(512), 'claim' => $s(256)])]],
        ] as $i => $set) {
            self::assertNull(A2a::needError(self::need($set)), "valid $i");
        }
        foreach ([
            ['verb' => $s(129)], ['resource' => $s(513)], ['scopes' => array_fill(0, 17, 'a')], ['scopes' => [$s(129)]], ['scopes' => ["a\u{3000}b"]], ['scopes' => ["a\u{FEFF}b"]], ['scopes' => ["a\u{00A0}b"]], ['scopes' => ["a\u{2029}b"]], ['scopes' => ["a b"]],
            ['grant_ref' => $s(129)], ['grant_ref' => self::n(1)], ['policy_digest' => $s(129)], ['limits' => $objOf(17, self::n(1))], ['limits' => 'x'],
            ['limits' => Obj::of([$s(65, 'k') => self::n(0)])], ['limits' => Obj::of(['k' => self::n(-1)])], ['discharges' => array_fill(0, 17, $d)],
            ['discharges' => 'x'], ['discharges' => ['x']], ['discharges' => [Obj::of(['issuer' => $s(513), 'claim' => 'c'])]],
            ['discharges' => [Obj::of(['issuer' => 'i', 'claim' => $s(257)])]],
        ] as $i => $set) {
            self::assertSame('bad_field', A2a::needError(self::need($set)), "invalid $i");
        }
    }

    public function testDecodeLengthAndPushSalt(): void
    {
        self::assertNotSame('too_long', A2a::decodeNeed(str_repeat('A', 2048))[1]);
        self::assertSame([null, 'too_long'], A2a::decodeNeed(str_repeat('A', 2049)));
        self::assertIsString(A2a::pushToken('t', ['a'], str_repeat('s', 16)));
        self::assertNull(A2a::pushToken('t', ['a'], str_repeat('s', 15)));
    }

    public function testReceipts(): void
    {
        $pk = self::key()[0];
        $r0 = self::rec();
        self::assertTrue(A2a::verifyReceipt($r0, $pk));
        self::assertFalse(A2a::verifyReceipt('x', $pk));
        self::assertTrue(A2a::verifyReceipt(self::rec(['task_id' => str_repeat('t', 4096)]), $pk));
        foreach ([['v' => self::n(2)], ['task_id' => str_repeat('t', 4097)], ['state' => 'BOGUS'], ['seq' => self::n(-1)], ['issued_at' => new Num('1.5')],
            ['chain' => 'x'], ['seq' => self::n(1), 'prev' => 'x'], ['prev' => A2a::receiptDigest($r0)]] as $i => $set) {
            self::assertFalse(A2a::verifyReceipt(self::rec($set), $pk), "receipt $i");
        }
        self::assertTrue(A2a::verifyReceipt(self::rec(['seq' => self::n(1), 'prev' => A2a::receiptDigest($r0)]), $pk));
        // a skipped seq with a correct prev link is still a broken link
        $chain = [$r0, self::rec(['seq' => self::n(2), 'prev' => A2a::receiptDigest($r0)])];
        self::assertSame(['ok' => false, 'code' => 'broken_link', 'at' => 1], A2a::checkReceiptChain($chain, $pk, 't1', ['a']));
        $chain = [$r0, self::rec(['seq' => self::n(1), 'prev' => A2a::receiptDigest($r0)])];
        self::assertSame(['ok' => true, 'terminal' => false, 'last_state' => 'TASK_STATE_WORKING'], A2a::checkReceiptChain($chain, $pk, 't1', ['a']));
    }
}
