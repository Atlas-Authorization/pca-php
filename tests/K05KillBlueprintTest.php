<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Blueprint;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Mutation kills for Blueprint: wellFormed per member, accept's operator_changed, epoch of an empty store, check's hop shape. */
final class K05KillBlueprintTest extends TestCase
{
    private static function n(int $i): Num
    {
        return new Num((string)$i);
    }

    private static function b(array $set = []): Obj
    {
        $x = Obj::of(['v' => self::n(1), 'id' => 'bp1', 'key' => 'k1', 'ceiling' => [], 'epoch' => self::n(1), 'status' => 'active',
            'issued_at' => self::n(1000), 'operator' => 'op']);
        foreach ($set as $k => $v) {
            $x->set((string)$k, $v);
        }
        return $x;
    }

    /** @return array{0: string, 1: string} */
    private static function key(int $seed): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat(chr($seed), 32));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function record(int $seed, int $epoch): Obj
    {
        [$pk, $sk] = self::key($seed);
        $r = self::b(['key' => 'K', 'operator' => $pk, 'epoch' => self::n($epoch)]);
        $r->set('sig', Pca::b64u(sodium_crypto_sign_detached(Blueprint::DOMAIN . Json::canonicalizeStrict($r), $sk)));
        return $r;
    }

    public function testWellFormed(): void
    {
        $s = static fn (int $n): string => str_repeat('a', $n);
        $t = Obj::of(['type' => 't']);
        self::assertTrue(Blueprint::wellFormed(self::b()));
        self::assertFalse(Blueprint::wellFormed('x'));
        foreach ([['id' => $s(128)], ['key' => $s(128)], ['operator' => $s(128)], ['max_depth' => self::n(1)], ['expires_at' => self::n(5)],
            ['ceiling' => array_fill(0, 32, $t)], ['status' => 'disabled']] as $i => $set) {
            self::assertTrue(Blueprint::wellFormed(self::b($set)), "valid $i");
        }
        foreach ([['v' => self::n(2)], ['id' => $s(129)], ['id' => ''], ['key' => $s(129)], ['operator' => $s(129)], ['epoch' => 'x'], ['issued_at' => 'x'],
            ['status' => 'bogus'], ['max_depth' => self::n(0)], ['max_depth' => 'x'], ['expires_at' => 'x'], ['ceiling' => array_fill(0, 33, $t)],
            ['ceiling' => 'x'], ['ceiling' => ['x']], ['ceiling' => [Obj::of(['type' => self::n(1)])]]] as $i => $set) {
            self::assertFalse(Blueprint::wellFormed(self::b($set)), "invalid $i");
        }
        self::assertFalse(Blueprint::verify(null));
    }

    public function testRuntimePinsAreWellFormedAndSigned(): void
    {
        $s = static fn(int $n): string => str_repeat('s', $n);
        $pin = Obj::of(['model_id' => 'm']);
        foreach ([[$pin], array_fill(0, 16, $pin), [Obj::of(['runtime_measurement' => $s(256), 'model_id' => 'm', 'weights_digest' => 'w', 'operator' => 'o', 'spiffe_id' => 'x'])]] as $i => $p) {
            self::assertTrue(Blueprint::wellFormed(self::b(['runtime_pins' => $p])), "valid $i");
        }
        foreach ([null, 'x', [], array_fill(0, 17, $pin), ['x'], [new Obj()], [Obj::of(['nope' => 'm'])], [Obj::of(['model_id' => self::n(1)])],
            [Obj::of(['model_id' => ''])], [Obj::of(['model_id' => $s(257)])], [$pin, Obj::of(['model_id' => 'm', 'nope' => 'x'])]] as $i => $p) {
            self::assertFalse(Blueprint::wellFormed(self::b(['runtime_pins' => $p])), "invalid $i");
        }
        // the pins are in the signed body: a record cannot lose or gain them
        $r = self::pinned(5, 1, 'active');
        self::assertTrue(Blueprint::verify($r));
        self::assertFalse(Blueprint::verify($r->without('runtime_pins')));
    }

    private static function pinned(int $seed, int $epoch, string $status, array $set = []): Obj
    {
        [$pk, $sk] = self::key($seed);
        $r = self::b(['key' => 'K', 'operator' => $pk, 'epoch' => self::n($epoch), 'status' => $status, 'runtime_pins' => [Obj::of(['model_id' => 'm'])]] + $set);
        $r->set('sig', Pca::b64u(sodium_crypto_sign_detached(Blueprint::DOMAIN . Json::canonicalizeStrict($r), $sk)));
        return $r;
    }

    /** Admission is not implemented here: a pinned blueprint is registered, then denies at the reference's position, never falls through. */
    public function testAPinnedBlueprintDeniesAdmissionRequired(): void
    {
        $r = self::pinned(5, 1, 'active');
        $op = [$r->get('operator')];
        $store = [];
        self::assertSame(['ok' => true, 'replaced' => true], Blueprint::accept($store, $op, $r));
        $hop = static fn(string $i, string $h): Obj => Obj::of(['issuer' => $i, 'holder' => $h]);
        $chain = [$hop('p', 'K'), $hop('K', 'I')];
        $deny = static fn(string $code): array => ['decision' => 'deny', 'code' => $code, 'blueprint' => $r->get('id')];
        foreach (['any', 'off', 'require'] as $mode) {
            self::assertSame($deny('admission_required'), Blueprint::check($chain, $store, self::n(2000), $mode), $mode);
        }
        // group kill carrying pins
        $kill = self::pinned(5, 2, 'disabled');
        self::assertSame(['ok' => true, 'replaced' => true], Blueprint::accept($store, $op, $kill));
        self::assertSame($deny('blueprint_disabled'), Blueprint::check($chain, $store, self::n(2000), 'any'));
        // expiry and depth come first, the ceiling after
        foreach ([[['expires_at' => self::n(1)], 'blueprint_expired'], [['max_depth' => self::n(1), 'expires_at' => self::n(5000)], null],
            [['ceiling' => [Obj::of(['type' => 't'])]], 'admission_required']] as $i => [$set, $code]) {
            $st = ['K' => self::pinned(5, 1, 'active', $set)];
            self::assertSame($deny($code ?? 'admission_required'), Blueprint::check($chain, $st, self::n(2000), 'any'), "order $i");
        }
        $st = ['K' => self::pinned(5, 1, 'active', ['max_depth' => self::n(1)])];
        self::assertSame($deny('too_deep'), Blueprint::check([$hop('p', 'K'), $hop('K', 'I'), $hop('I', 'J')], $st, self::n(2000), 'any'));
    }

    public function testAcceptAndEpoch(): void
    {
        $a = self::record(5, 1);
        $b = self::record(6, 2);
        self::assertTrue(Blueprint::verify($a));
        $store = [];
        self::assertSame(['ok' => true, 'replaced' => true], Blueprint::accept($store, [$a->get('operator'), $b->get('operator')], $a));
        self::assertSame(['ok' => false, 'code' => 'operator_changed'], Blueprint::accept($store, [$a->get('operator'), $b->get('operator')], $b));
        self::assertSame(0, Blueprint::epoch([]));
        self::assertSame(1, Blueprint::epoch($store));
    }

    public function testCheckHopShape(): void
    {
        $now = self::n(1000);
        $hop = static fn (mixed $i, mixed $h): Obj => Obj::of(['issuer' => $i, 'holder' => $h]);
        self::assertSame(['decision' => 'allow', 'governed' => []], Blueprint::check([$hop(str_repeat('i', 128), str_repeat('h', 128))], [], $now, 'off'));
        foreach ([[$hop(self::n(1), 'h')], [$hop(str_repeat('i', 129), 'h')], [$hop('i', str_repeat('h', 129))], ['x']] as $i => $chain) {
            self::assertSame(['decision' => 'deny', 'code' => 'bad_input'], Blueprint::check($chain, [], $now, 'off'), "hop $i");
        }
    }
}
