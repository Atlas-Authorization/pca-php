<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\CaveatLang;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Caveat language v2 (K1): exact outcomes for the 0.5 mutation survivors of src/CaveatLang.php. */
final class K05KillCaveatLangTest extends TestCase
{
    private const NOW = 1800000000000;

    private static function j(string $text): mixed
    {
        return Json::parseLax($text);
    }

    private static function nonce(): string
    {
        return Pca::b64u(str_repeat("\x07", 16));
    }

    /** @return array{0: string, 1: string} [b64u public key, secret key] */
    private static function ed(): array
    {
        $kp = sodium_crypto_sign_keypair();
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function edSign(string $domain, Obj $a, string $sk): Obj
    {
        $a->set('sig', Pca::b64u(sodium_crypto_sign_detached(IntentWb::artifactMessage($domain, $a), $sk)));
        return $a;
    }

    private static function caveatND(): Obj
    {
        return self::j('{"type":"needs_discharge","id":"nd","issuer":"iss","issuer_class":"org","bind":"chain_hop","ttl_ms":86400000,"require":[]}');
    }

    private static function discharge(string $cap, string $v, int $lvl): Obj
    {
        return self::j('{"v":' . $v . ',"kind":"pca-discharge","caveat_id":"nd","issuer":"iss","cap_hash":"' . $cap . '","bind":"chain_hop",'
            . '"claims":{"lvl":' . $lvl . '},"iat":' . (self::NOW - 1000) . ',"not_after":' . (self::NOW + 1000) . ',"nonce":"' . self::nonce() . '"}');
    }

    private static function narrow(string $cap, string $holder): Obj
    {
        return self::j('{"v":1,"kind":"pca-narrow","cap_hash":"' . $cap . '","holder":"' . $holder . '","caveats":[{"type":"note"}],'
            . '"iat":' . (self::NOW - 1000) . ',"not_after":' . (self::NOW + 1000) . ',"nonce":"' . self::nonce() . '"}');
    }

    public function testIsK1CaveatNeedsAnObject(): void
    {
        $this->assertFalse(CaveatLang::isK1Caveat('sealed'));
        $this->assertFalse(CaveatLang::isK1Caveat(['type' => 'sealed']));
        $this->assertFalse(CaveatLang::isK1Caveat(null));
        $this->assertTrue(CaveatLang::isK1Caveat(Obj::of(['type' => 'sealed'])));
        $this->assertFalse(CaveatLang::isK1Caveat(Obj::of(['type' => 'note'])));
    }

    public function testBoundCaveatsSkipsANonObjectHop(): void
    {
        $leaf = self::j('{"caveats":[{"type":"note"}]}');
        $r = CaveatLang::boundCaveats(null, ['junk', $leaf]);
        $this->assertIsArray($r);
        $this->assertCount(1, $r);
        $this->assertSame(1, $r[0]['hop']);
        $this->assertSame(Pca::capHash($leaf), $r[0]['cap_hash']);
        $this->assertSame('note', $r[0]['caveat']->get('type'));
        // a leaf that is not an Obj is a malformed chain, even an object with a get() method
        $fake = new class {
            public function get(string $k): mixed
            {
                return [Obj::of(['type' => 'note'])];
            }
        };
        $this->assertNull(CaveatLang::boundCaveats(null, [$leaf, $fake]));
    }

    public function testDischargeActionDigestIsPublicAndDomainSeparated(): void
    {
        $this->assertSame(
            Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/discharge-action/v1', 'pcactn' => 'x'])),
            CaveatLang::dischargeActionDigest('x')
        );
        $this->assertNotSame(Pca::hashCanonical(Obj::of(['pcactn' => 'x'])), CaveatLang::dischargeActionDigest('x'));
    }

    public function testNonNumericVersionIsRefusedNotThrown(): void
    {
        $d = self::discharge(Pca::b64u(str_repeat("\x01", 32)), '"1"', 1);
        $d->set('sig', 'x');
        $this->assertSame('not a pca-discharge v1', CaveatLang::dischargeShapeError($d));
    }

    public function testDischargeErrorIsFailClosedWithItsMessage(): void
    {
        [$pk, $sk] = self::ed();
        $cap = Pca::b64u(str_repeat("\x01", 32));
        // v = 1.0 verifies (the signature covers the JS value) but the strict content address refuses the lexeme
        $d = self::edSign(CaveatLang::DISCHARGE_DOMAIN, self::discharge($cap, '1.0', 1), $sk);
        $pins = [Obj::of(['label' => 'iss', 'class' => 'org', 'pk' => $pk])];
        $r = CaveatLang::verifyDischarge($d, self::caveatND(), ['cap_hash' => $cap, 'pins' => $pins, 'now' => self::NOW]);
        $this->assertSame(['ok' => false, 'reason' => 'discharge error (fail closed): trailing fractional zero is not canonical'], $r);
        // control: the canonical v verifies
        $ok = self::edSign(CaveatLang::DISCHARGE_DOMAIN, self::discharge($cap, '1', 1), $sk);
        $this->assertTrue(CaveatLang::verifyDischarge($ok, self::caveatND(), ['cap_hash' => $cap, 'pins' => $pins, 'now' => self::NOW])['ok']);
    }

    public function testTheFirstVerifiedDischargeSuppliesTheClaims(): void
    {
        [$pk, $sk] = self::ed();
        $grant = self::j('{"caveats":[' . Json::canonicalizeStrict(self::caveatND()) . ','
            . '{"type":"derive","id":"dv","defs":[{"name":"l","kind":"claim","caveat_id":"nd","claim":"lvl"}],'
            . '"check":{"op":"eq","a":{"ref":"l"},"b":{"const":1}}}]}');
        $cap = Pca::capHash($grant);
        $d1 = self::edSign(CaveatLang::DISCHARGE_DOMAIN, self::discharge($cap, '1', 1), $sk);
        $d2 = self::edSign(CaveatLang::DISCHARGE_DOMAIN, self::discharge($cap, '1', 2), $sk);
        $k1 = Obj::of(['pins' => [Obj::of(['label' => 'iss', 'class' => 'org', 'pk' => $pk])], 'discharges' => [$d1, $d2]]);
        $ctx = Obj::of(['now' => self::NOW]);
        $r = CaveatLang::evaluateK1($grant, null, $k1, $ctx);
        $this->assertSame([], $r['failed']);
        $this->assertTrue($r['ok']);
        $k1->set('discharges', [$d2, $d1]);
        $this->assertSame(['derive check is false'], CaveatLang::evaluateK1($grant, null, $k1, $ctx)['reasons']);
    }

    public function testActionOfAnArrayContextReachesDerive(): void
    {
        $g = self::j('{"caveats":[{"type":"derive","id":"d1","defs":[{"name":"amt","kind":"param","path":"amount"}],'
            . '"check":{"op":"lte","a":{"ref":"amt"},"b":{"const":100}}}]}');
        $action = self::j('{"verb":"pay","resource":"r/1","params":{"amount":50}}');
        $r = CaveatLang::evaluateK1($g, null, new Obj(), ['now' => self::NOW, 'action' => $action]);
        $this->assertTrue($r['ok']);
        $this->assertSame([], $r['failed']);
        $none = CaveatLang::evaluateK1($g, null, new Obj(), ['now' => self::NOW]);
        $this->assertSame(['derive check is unknown (a fact is missing)'], $none['reasons']);
    }

    public function testVerifyNarrowRefusesANonObjectLeaf(): void
    {
        [$pk] = self::ed();
        $n = self::narrow(Pca::b64u(str_repeat("\x01", 32)), $pk);
        $n->set('sig', 'x');
        $this->assertSame(['ok' => false, 'reason' => 'malformed capability chain'], CaveatLang::verifyNarrow($n, 'junk', null, ['now' => self::NOW]));
    }

    public function testNarrowErrorIsFailClosedWithItsMessage(): void
    {
        [$pk] = self::ed();
        $grant = self::j('{"issuer":"x","holder":"' . $pk . '","caveats":[],"z":1.0}');
        $n = self::narrow(Pca::b64u(str_repeat("\x01", 32)), $pk);
        $n->set('sig', 'x');
        $this->assertSame(
            ['ok' => false, 'reason' => 'narrow error (fail closed): trailing fractional zero is not canonical'],
            CaveatLang::verifyNarrow($n, $grant, null, ['now' => self::NOW])
        );
    }

    public function testEd25519NarrowIgnoresTheLeafPqCommitment(): void
    {
        [$pk, $sk] = self::ed();
        $grant = self::j('{"issuer":"x","holder":"' . $pk . '","holder_pq":"abc","caveats":[]}');
        $n = self::edSign(CaveatLang::NARROW_DOMAIN, self::narrow(Pca::capHash($grant), $pk), $sk);
        $r = CaveatLang::verifyNarrow($n, $grant, null, ['now' => self::NOW]);
        $this->assertTrue($r['ok']);
        $this->assertCount(1, $r['caveats']);
    }

    public function testPqNarrowVerifiesOnlyUnderTheCommittedKey(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->markTestSkipped('no ML-DSA-65 in this libcrypto');
        }
        $gen = OpensslPq::generate('ML-DSA-65');
        $this->assertNotNull($gen);
        [$pkey, $pqRaw] = $gen;
        try {
            [$pk] = self::ed();
            $pqPk = Pca::b64u($pqRaw);
            $mk = static function (string $commit) use ($pk): Obj {
                return self::j('{"issuer":"x","holder":"' . $pk . '","holder_pq":"' . $commit . '","caveats":[]}');
            };
            $sign = static function (Obj $grant) use ($pk, $pqPk, $pkey): Obj {
                $n = self::narrow(Pca::capHash($grant), $pk);
                $n->set('alg', 'ml-dsa-65');
                $n->set('pq_pk', $pqPk);
                $sig = OpensslPq::sign('ML-DSA-65', $pkey, IntentWb::artifactMessage(CaveatLang::NARROW_DOMAIN, $n));
                self::assertNotNull($sig);
                $n->set('sig', Pca::b64u($sig));
                return $n;
            };
            $good = $mk(Pca::holderPqCommitment($pqPk));
            $this->assertTrue(CaveatLang::verifyNarrow($sign($good), $good, null, ['now' => self::NOW])['ok']);
            $other = $mk(Pca::holderPqCommitment($pqPk . 'x'));
            $this->assertSame(['ok' => false, 'reason' => 'narrow signature invalid'], CaveatLang::verifyNarrow($sign($other), $other, null, ['now' => self::NOW]));
        } finally {
            OpensslPq::free($pkey);
        }
    }

    public function testReserveMaxUsesNativeClockAndSkipsNonObjects(): void
    {
        $this->assertSame(['ok' => true, 'spent' => 0], CaveatLang::reserveMaxUses(new MemoryStateStore(), [['caveat' => 'x', 'cap_hash' => 'c']], self::NOW));
        $bound = [['caveat' => self::j('{"type":"max_uses","id":"u","n":1,"until":5000}'), 'cap_hash' => 'c']];
        $exp = ['ok' => false, 'reason' => "max_uses 'u' has expired"];
        $this->assertSame($exp, CaveatLang::reserveMaxUses(new MemoryStateStore(), $bound, 6000));
        $this->assertSame($exp, CaveatLang::reserveMaxUses(new MemoryStateStore(), $bound, 6000.0));
        $this->assertSame(['ok' => true, 'spent' => 1], CaveatLang::reserveMaxUses(new MemoryStateStore(), $bound, 1000));
    }

    public function testReserveMaxUsesOnAClaimOnlyStore(): void
    {
        $store = new class {
            /** @var list<array{0: string, 1: int}> */
            public array $calls = [];
            private array $seen = [];

            public function claim(string $key, int $counter): object
            {
                $this->calls[] = [$key, $counter];
                $ok = !isset($this->seen[$key]);
                $this->seen[$key] = true;
                return (object)['ok' => $ok];
            }
        };
        $bound = [['caveat' => self::j('{"type":"max_uses","id":"u","n":2,"until":1900000000000}'), 'cap_hash' => 'c']];
        $this->assertSame(['ok' => true, 'spent' => 1], CaveatLang::reserveMaxUses($store, $bound, self::NOW));
        $this->assertSame([[CaveatLang::maxUsesSlotKey('c', 'u', 0), 1]], $store->calls);

        $down = new class {
            public function claim(string $key, int $counter): never
            {
                throw new \RuntimeException('down');
            }
        };
        $this->assertSame(['ok' => false, 'reason' => 'max_uses error (fail closed): down'], CaveatLang::reserveMaxUses($down, $bound, self::NOW));
    }

    public function testReserveMaxUsesPrefersConsumeOnceByDuckTyping(): void
    {
        $store = new class {
            public array $once = [];

            public function consumeOnce(string $key, int $retainUntilMs, int $nowMs): bool
            {
                $this->once[] = [$key, $retainUntilMs, $nowMs];
                return true;
            }

            public function claim(string $key, int $counter): never
            {
                throw new \RuntimeException('claim must not be used');
            }
        };
        $bound = [['caveat' => self::j('{"type":"max_uses","id":"u","n":1,"until":1900000000000}'), 'cap_hash' => 'c']];
        $this->assertSame(['ok' => true, 'spent' => 1], CaveatLang::reserveMaxUses($store, $bound, self::NOW));
        $this->assertSame([[CaveatLang::maxUsesSlotKey('c', 'u', 0), 1900000000000, self::NOW]], $store->once);
    }

    public function testWithActionDigestCopiesAnObjAndIntKeys(): void
    {
        $o = CaveatLang::withActionDigest(Obj::of(['pins' => [1], 'action_digest' => 'forged']), 'mine');
        $this->assertSame(['pins', 'action_digest'], $o->keys());
        $this->assertSame([1], $o->get('pins'));
        $this->assertSame('mine', $o->get('action_digest'));
        $i = CaveatLang::withActionDigest([5 => 'x'], 'd');
        $this->assertSame(['5', 'action_digest'], $i->keys());
        $this->assertSame('x', $i->get('5'));
    }

    public function testPresentedK1Reasons(): void
    {
        $this->assertSame([], CaveatLang::presentedK1([7 => 'v'])['value']->keys());
        $arr = ['ok' => false, 'reason' => 'PCA-Discharges must be a base64url JSON array'];
        $this->assertSame($arr, CaveatLang::presentedK1(['pca-discharges' => '!!']));
        $this->assertSame($arr, CaveatLang::presentedK1(['pca-discharges' => Pca::b64u('{"a":1}')]));
        $this->assertSame($arr, CaveatLang::presentedK1(['pca-discharges' => Pca::b64u('"x"')]));
        $msg = '';
        try {
            Json::parseStrict('{"a":1,"a":2}');
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
        }
        $this->assertNotSame('', $msg);
        $this->assertSame(
            ['ok' => false, 'reason' => 'presented K1 headers are unreadable: ' . $msg],
            CaveatLang::presentedK1(['pca-narrow' => Pca::b64u('{"a":1,"a":2}')])
        );
    }

    public function testMergePresentedK1OwnMembers(): void
    {
        $o = CaveatLang::mergePresentedK1(null, Obj::of(['pins' => [1]]));
        $this->assertSame(['pins'], $o->keys());
        $this->assertSame([1], $o->get('pins'));
        $this->assertSame([], CaveatLang::mergePresentedK1(null, null)->keys());
        $this->assertSame([], CaveatLang::mergePresentedK1(null, 'x')->keys());
        $i = CaveatLang::mergePresentedK1(null, [3 => 'x']);
        $this->assertSame('x', $i->get('3'));
    }

    public function testStockPredicatesSeeTheAction(): void
    {
        $g = self::j('{"caveats":[{"type":"predicates","allow":[{"verb":"pay","resource":"*"}]}]}');
        $ctx = self::j('{"now":' . self::NOW . ',"action":{"verb":"pay","resource":"r/1","params":{}}}');
        $this->assertSame([true, []], CaveatLang::evaluateCaveatsK1($g, null, new Obj(), $ctx));
        $this->assertSame([false, ['predicates']], CaveatLang::evaluateCaveatsK1($g, null, new Obj(), self::j('{"now":' . self::NOW . '}')));
    }

    public function testHasReadsOnlyObjectsAndStringKeyedArrays(): void
    {
        $has = new \ReflectionMethod(CaveatLang::class, 'has');
        $this->assertTrue($has->invoke(null, ['a' => 1], 'a'));
        $this->assertFalse($has->invoke(null, ['a' => 1], 'b'));
        // a list is no object even when the key names an index ('0' is key 0)
        $this->assertFalse($has->invoke(null, ['x'], '0'));
        $this->assertFalse($has->invoke(null, 'str', 'k'));
        $this->assertFalse($has->invoke(null, null, 'k'));
    }

    public function testClaimHoldsRefusesAnUnknownOperator(): void
    {
        $holds = new \ReflectionMethod(CaveatLang::class, 'claimHolds');
        $claims = self::j('{"lvl":5}');
        $this->assertTrue($holds->invoke(null, self::j('{"claim":"lvl","op":"gte","value":1}'), $claims));
        $this->assertFalse($holds->invoke(null, self::j('{"claim":"lvl","op":"gt","value":1}'), $claims));
        $this->assertFalse($holds->invoke(null, self::j('{"claim":"lvl","value":1}'), $claims));
    }

    public function testDeriveCountStopsAtTheFirstMalformedHistoryEntry(): void
    {
        // the count def is unvalidated here (resource_prefix is a number): the walk must stop at the malformed entry before it
        // ever reaches the well-formed one, whose prefix test would throw
        $c = self::j('{"type":"derive","id":"d","defs":[{"name":"n","kind":"count","window_ms":1000,"resource_prefix":5}],"check":{"ref":"n"}}');
        $inp = ['now' => new Num('100'), 'claims' => new Obj(), 'history' => ['bad', self::j('{"t":100,"verb":"v","resource":"r"}')]];
        $this->assertNull(CaveatLang::evaluateDerive($c, $inp));
    }

    public function testEvaluateK1ErrorIsFailClosedWithItsMessage(): void
    {
        CaveatLang::$evalHook = static function (string $where): void {
            if ($where === 'k1') {
                throw new \RuntimeException('boom');
            }
        };
        try {
            $this->assertSame(
                ['ok' => false, 'failed' => ['<malformed>'], 'reasons' => ['caveat language error (fail closed): boom'], 'plain' => [], 'bound' => []],
                CaveatLang::evaluateK1(new Obj(), null, new Obj(), self::j('{"now":' . self::NOW . '}'))
            );
        } finally {
            CaveatLang::$evalHook = null;
        }
    }

    public function testEvaluateCaveatsK1ErrorRefuses(): void
    {
        CaveatLang::$evalHook = static function (string $where): void {
            if ($where === 'caveats') {
                throw new \RuntimeException('boom');
            }
        };
        try {
            $this->assertSame([false, ['<evaluation error>']],
                CaveatLang::evaluateCaveatsK1(self::j('{"caveats":[]}'), null, new Obj(), self::j('{"now":' . self::NOW . '}')));
        } finally {
            CaveatLang::$evalHook = null;
        }
    }
}
