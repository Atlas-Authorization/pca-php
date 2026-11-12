<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Sign;
use Atlas\Pca\Beacons;
use Atlas\Pca\BeaconAcceptor;
use Atlas\Pca\InMemoryTaintRegistry;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use Atlas\Pca\Taint;
use PHPUnit\Framework\TestCase;

final class K05HardTaintBeaconTest extends TestCase
{
    private static function prov(array $refs): Obj
    {
        return Obj::of(['trusted_refs' => $refs]);
    }

    public function testTaintClassification(): void
    {
        $reg = (new InMemoryTaintRegistry())->recordTrusted('a')->recordTool('t', 'tool-1')->recordWeb('w');
        $this->assertSame(0.0, Taint::computeTaint(self::prov(['a']), $reg)['taint']);
        $this->assertSame(0.5, Taint::computeTaint(self::prov(['a', 't']), $reg)['taint']);
        $this->assertSame(0.75, Taint::computeTaint(self::prov(['a', 't', 'w']), $reg)['taint']);
        $this->assertSame(1.0, Taint::computeTaint(self::prov(['a', 'unknown']), $reg)['taint']);
        $this->assertSame(1.0, Taint::computeTaint(self::prov([]), $reg)['taint'], 'empty lineage is the worst case');
        $this->assertFalse(Taint::computeTaint(self::prov(['']), $reg)['valid']);
        $this->assertFalse(Taint::computeTaint(null, $reg)['valid']);
        $this->assertFalse(Taint::computeTaint(self::prov(['a']), null)['valid']);
        $g = new class { public function node(string $r): bool { return $r === 'node-1'; } };
        $this->assertSame(0.25, Taint::computeTaint(self::prov(['node-1']), $reg, $g)['taint']);
        // a registry that vouches an unknown kind is ignored
        $this->assertSame(1.0, Taint::computeTaint(self::prov(['x']), new class { public function lookup(string $d): Obj { return Obj::of(['kind' => 'super']); } })['taint']);
    }

    public function testTaintGate(): void
    {
        $reg = (new InMemoryTaintRegistry())->recordTrusted('a')->recordTool('t', 'x');
        $this->assertSame(['ok' => true], Taint::taintGate(self::prov(['a', 't']), $reg, null, 0.5));
        $r = Taint::taintGate(self::prov(['a', 't']), $reg, null, 0.25);
        $this->assertFalse($r['ok']);
        $this->assertSame('information-flow taint 0.5 exceeds policy max 0.25', $r['reason']);
        $this->assertSame(['ok' => true], Taint::taintGate(self::prov(['a']), $reg, null, 0));
        $this->assertFalse(Taint::taintGate(self::prov(['a']), $reg, null, -1)['ok']);
        $this->assertFalse(Taint::taintGate(self::prov(['a']), $reg, null, 'x')['ok']);
        $this->assertFalse(Taint::taintGate(self::prov(['a']), $reg, null, null)['ok']);
        $this->assertFalse(Taint::taintGate(null, $reg, null, 1)['ok']);
    }

    private static function beacon(KeyPair $kp, int $seq = 1, int $iat = 1800000000000, string $scope = '*', string $instance = 'inst'): Obj
    {
        return Sign::signArtifact(Beacons::DOMAIN, [
            'v' => 2, 'instance' => $instance, 'scope' => $scope, 'epoch' => intdiv($iat, 60000), 'seq' => $seq,
            'issued_at' => $iat, 'not_after' => $iat + 300000, 'issuer' => $kp->public,
        ], $kp);
    }

    public function testBeaconVerify(): void
    {
        $kp = KeyPair::generate();
        $now = 1800000000000;
        $b = self::beacon($kp);
        $this->assertSame(['ok' => true], Beacons::verify($b, [$kp->public], $now + 1000, 'inst'));
        $this->assertSame('wrong instance', Beacons::verify($b, [$kp->public], $now, 'other')['reason']);
        $this->assertSame('issuer not pinned', Beacons::verify($b, [KeyPair::generate()->public], $now, 'inst')['reason']);
        $this->assertSame('expired', Beacons::verify($b, [$kp->public], $now + 300001, 'inst')['reason']);
        $this->assertSame('not yet valid', Beacons::verify($b, [$kp->public], $now - 30001, 'inst')['reason']);
        $this->assertTrue(Beacons::verify($b, [$kp->public], $now - 30000, 'inst')['ok']);
        $this->assertTrue(Beacons::verify($b, [$kp->public], $now + 300000, 'inst')['ok']);
        $this->assertSame('malformed beacon', Beacons::verify(null, [$kp->public], $now, 'inst')['reason']);
        $b2 = Obj::of(['v' => $b->get('v')]);
        foreach ($b->keys() as $k) {
            $b2->set($k, $k === 'seq' ? Sign::n(9) : $b->get($k));
        }
        $this->assertSame('bad signature', Beacons::verify($b2, [$kp->public], $now, 'inst')['reason']);
        $sc = self::beacon($kp, 1, $now, 'grant-1');
        $this->assertTrue(Beacons::verify($sc, [$kp->public], $now, 'inst', 'grant-1')['ok']);
        $this->assertSame('scope not covered', Beacons::verify($sc, [$kp->public], $now, 'inst', 'grant-2')['reason']);
        $this->assertTrue(Beacons::verify($sc, [$kp->public], $now, 'inst')['ok']);
        $long = Sign::signArtifact(Beacons::DOMAIN, ['v' => 2, 'instance' => 'inst', 'scope' => '*', 'epoch' => intdiv($now, 60000), 'seq' => 1, 'issued_at' => $now, 'not_after' => $now + 3600001, 'issuer' => $kp->public], $kp);
        $this->assertSame('validity exceeds the hard maximum', Beacons::verify($long, [$kp->public], $now, 'inst')['reason']);
        $bad = Sign::signArtifact(Beacons::DOMAIN, ['v' => 2, 'instance' => 'inst', 'scope' => '*', 'epoch' => 5, 'seq' => 1, 'issued_at' => $now, 'not_after' => $now + 1000, 'issuer' => $kp->public], $kp);
        $this->assertSame('epoch does not match issued_at', Beacons::verify($bad, [$kp->public], $now, 'inst')['reason']);
        $this->assertTrue(Beacons::isFrozen([], ['issuers' => [$kp->public], 'now' => $now, 'instance' => 'inst']));
        $this->assertFalse(Beacons::isFrozen([$b], ['issuers' => [$kp->public], 'now' => $now, 'instance' => 'inst']));
        $this->assertSame(43, strlen(Beacons::beaconRef($b)));
    }

    public function testBeaconAcceptAndDecision(): void
    {
        $this->assertSame(['ok' => true], Beacons::accept(null, Obj::of(['seq' => Sign::n(1)])));
        $this->assertSame('replayed beacon: seq 3 <= 3', Beacons::accept(Obj::of(['seq' => Sign::n(3)]), Obj::of(['seq' => Sign::n(3)]))['reason']);
        $this->assertTrue(Beacons::accept(Obj::of(['seq' => Sign::n(3)]), Obj::of(['seq' => Sign::n(4)]))['ok']);
        $this->assertSame('malformed beacon', Beacons::accept(null, Obj::of(['seq' => Sign::n(-1)]))['reason']);
        $this->assertSame('malformed beacon', Beacons::accept(null, Obj::of(['seq' => Sign::n(1.5)]))['reason']);
        $this->assertSame('malformed beacon', Beacons::accept(null, null)['reason']);
        $this->assertSame('not-enforced', Beacons::decision(false, true, true, true));
        $this->assertSame('rejected', Beacons::decision(true, false, true, true));
        $this->assertSame('replayed', Beacons::decision(true, true, true, true));
        $this->assertSame('unbound', Beacons::decision(true, true, false, false));
        $this->assertSame('pass', Beacons::decision(true, true, false, true));
    }

    public function testBeaconAcceptorIsDurableAndMonotone(): void
    {
        $kp = KeyPair::generate();
        $now = 1800000000000;
        $kv = new MemoryAtomicKv();
        $acc = new BeaconAcceptor($kv);
        $chk = ['issuers' => [$kp->public], 'now' => $now, 'instance' => 'inst'];
        $this->assertSame(['ok' => true], $acc->accept(self::beacon($kp, 5), $chk));
        $this->assertSame('replayed beacon: seq 5 <= 5', $acc->accept(self::beacon($kp, 5), $chk)['reason']);
        $this->assertSame('replayed beacon: seq 4 <= 5', $acc->accept(self::beacon($kp, 4), $chk)['reason']);
        $this->assertTrue($acc->accept(self::beacon($kp, 6), $chk)['ok']);
        $this->assertSame('wrong instance', $acc->accept(self::beacon($kp, 9, 1800000000000, '*', 'x'), $chk)['reason']);
        // junk in the store fails closed
        $junk = new class implements \Atlas\Pca\AtomicKv {
            public function get(string $key): ?string { return 'junk'; }
            public function update(string $key, callable $fn): void { $fn('junk'); }
        };
        $this->assertSame('beacon state unavailable', (new BeaconAcceptor($junk))->accept(self::beacon($kp, 7), $chk)['reason']);
        $throwing = new class implements \Atlas\Pca\AtomicKv {
            public function get(string $key): ?string { return null; }
            public function update(string $key, callable $fn): void { throw new \RuntimeException('down'); }
        };
        $this->assertSame('beacon state unavailable', (new BeaconAcceptor($throwing))->accept(self::beacon($kp, 7), $chk)['reason']);
    }
}
