<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Sign;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Prohibitions;
use PHPUnit\Framework\TestCase;

/** prohibition-vectors.json `constitution` and `monitor`, plus the evidence / signing surface. */
final class K05HardProhibitionsTest extends TestCase
{
    private static function rows(array $evaluated): array
    {
        return array_map(static function (Obj $e): array {
            $o = [];
            foreach ($e->keys() as $k) {
                $o[$k] = $e->get($k);
            }
            return $o;
        }, $evaluated);
    }

    public function testConstitutionVectors(): void
    {
        $rows = Vectors::load('prohibition-vectors.json')->get('constitution');
        $this->assertGreaterThanOrEqual(33, count($rows));
        foreach ($rows as $c) {
            $n = $c->get('name');
            $x = $c->get('expect');
            $this->assertSame($x->get('problems'), Prohibitions::validateConstitution($c->get('constitution')), "$n problems");
            $r = Prohibitions::check($c->get('action'), $c->get('constitution'), $c->get('state'));
            $xr = $x->get('result');
            $this->assertSame($xr->get('ok'), $r['ok'], "$n ok");
            $this->assertSame($xr->get('violated'), $r['violated'], "$n violated");
            $this->assertSame($xr->get('reasons'), $r['reasons'], "$n reasons");
            $this->assertSame(self::rows($xr->get('evaluated')), self::rows($r['evaluated']), "$n evaluated");
        }
    }

    public function testMonitorVectors(): void
    {
        $rows = Vectors::load('prohibition-vectors.json')->get('monitor');
        $this->assertGreaterThanOrEqual(5, count($rows));
        foreach ($rows as $c) {
            $n = $c->get('name');
            $state = Prohibitions::emptyState(Prohibitions::fin($c->get('genesis_now')));
            foreach ($c->get('steps') as $i => $s) {
                if ($s->has('now')) {
                    $t = Prohibitions::tickState($state, $s->get('now'));
                    if (!$t['ok']) {
                        $x = $s->get('expect');
                        $this->assertFalse($x->get('allow'), "$n step $i allow");
                        $this->assertSame($x->get('decidedBy'), 'clock', "$n step $i decidedBy");
                        $this->assertSame($x->get('reason'), $t['reason'], "$n step $i reason");
                        continue;
                    }
                    $state = $t['state'];
                }
                $r = Prohibitions::checkAndAdvance(true, $s->get('action'), $c->get('constitution'), $state);
                $state = $r['next'];
                $x = $s->get('expect');
                $this->assertSame($x->get('allow'), $r['allow'], "$n step $i allow");
                $this->assertSame($x->get('decidedBy'), $r['decidedBy'], "$n step $i decidedBy");
                $this->assertSame($x->get('violated'), $r['prohibition']['violated'], "$n step $i violated");
                $this->assertSame(Prohibitions::fin($x->get('seq')), Prohibitions::fin($state->get('seq')), "$n step $i seq");
            }
        }
    }

    public function testAdvanceNowNullIsRefusedAbsentIsStateTime(): void
    {
        $c = Sign::n(['version' => 1, 'principal' => 'p', 'invariants' => [['id' => 'r', 'kind' => 'rate', 'when' => ['verb' => 'x'], 'max' => 5, 'window_secs' => 60]]]);
        $act = Sign::n(['action' => ['verb' => 'x', 'resource' => '/r']]);
        $st = Prohibitions::emptyState(1700000000000.0);
        $this->assertTrue(Prohibitions::advanceStrict($act, $c, $st)['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'clock regression'], Prohibitions::advanceStrict($act, $c, $st, null));
        $this->assertTrue(Prohibitions::advanceStrict($act, $c, $st, 1700000001000.0)['ok']);
        // contracts: `opts.now ?? state.now`, so a null option IS unset there
        $k = Sign::n(['version' => 1, 'principal' => 'p', 'clauses' => []]);
        $this->assertTrue(\Atlas\Pca\Contracts::advance($st, $act, $k, ['now' => null])['ok']);
    }

    public function testEvidenceVectors(): void
    {
        $rows = Vectors::load('prohibition-vectors.json')->get('evidence');
        $this->assertGreaterThanOrEqual(13, count($rows));
        foreach ($rows as $c) {
            $expected = [];
            foreach ($c->get('expected')->keys() as $k) {
                $expected[$k] = $c->get('expected')->get($k);
            }
            $r = Prohibitions::verifySignedSafetyEvidence($c->get('signed'), $expected);
            $x = $c->get('expect');
            $this->assertSame($x->get('ok'), $r['ok'], $c->get('name'));
            $this->assertSame($x->has('reason') ? $x->get('reason') : null, $r['reason'] ?? null, $c->get('name'));
        }
    }

    private static function constitution(KeyPair $kp): Obj
    {
        return Sign::n(['version' => 1, 'principal' => $kp->public, 'invariants' => [
            ['id' => 'big', 'kind' => 'never', 'when' => ['verb' => 'wire']],
            ['id' => 'cap', 'kind' => 'cap', 'when' => ['verb' => 'pay'], 'amount' => 'action.params.amount', 'max' => 100, 'window_secs' => 60],
        ]]);
    }

    public function testSignVerifyConstitutionAndEvidence(): void
    {
        $kp = KeyPair::generate();
        $sc = Prohibitions::signConstitution(self::constitution($kp), $kp);
        $this->assertSame(['ok' => true], Prohibitions::verifyConstitution($sc, $kp->public));
        $this->assertSame('principal mismatch', Prohibitions::verifyConstitution($sc, 'other')['reason']);
        $tam = Sign::n(['version' => 1, 'principal' => $kp->public, 'invariants' => []]);
        $tam->set('id', $sc->get('id'));
        $tam->set('sig', $sc->get('sig'));
        $this->assertSame('id does not match content', Prohibitions::verifyConstitution($tam)['reason']);
        $other = KeyPair::generate();
        $bad = Sign::n(['version' => 1, 'principal' => $kp->public, 'invariants' => []]);
        $bad->set('id', Prohibitions::constitutionId($bad));
        $bad->set('sig', Pca::b64u($other->sign('x')));
        $this->assertSame('bad signature', Prohibitions::verifyConstitution($bad)['reason']);

        $state = Prohibitions::emptyState(1700000000000.0);
        $act = Sign::n(['action' => ['verb' => 'pay', 'resource' => '/r', 'params' => ['amount' => 30]]]);
        $ev = Prohibitions::proveSafety($act, $sc, $state);
        $this->assertTrue($ev->get('ok'));
        $this->assertSame(['ok' => true], Prohibitions::verifySafetyEvidence($ev, $act, $sc, $state));
        $signed = Prohibitions::signSafetyEvidence($ev, $kp);
        $exp = ['signer' => $kp->public, 'action' => $act, 'constitution' => $sc, 'state' => $state, 'principal' => $kp->public];
        $this->assertSame(['ok' => true], Prohibitions::verifySignedSafetyEvidence($signed, $exp));
        $this->assertSame('signer not trusted', Prohibitions::verifySignedSafetyEvidence($signed, ['signer' => $other->public] + $exp)['reason']);
        $act2 = Sign::n(['action' => ['verb' => 'pay', 'resource' => '/r', 'params' => ['amount' => 31]]]);
        $this->assertStringStartsWith('action digest mismatch', Prohibitions::verifySignedSafetyEvidence($signed, ['action' => $act2] + $exp)['reason']);
        $this->assertSame('unbound: state not specified', Prohibitions::verifySignedSafetyEvidence($signed, ['state' => null] + $exp)['reason']);

        // a violated action: evidence says not ok, requireOk refuses
        $wire = Sign::n(['action' => ['verb' => 'wire', 'resource' => '/r']]);
        $evBad = Prohibitions::proveSafety($wire, $sc, $state);
        $this->assertFalse($evBad->get('ok'));
        $sBad = Prohibitions::signSafetyEvidence($evBad, $kp);
        $this->assertSame('prohibition violated: big', Prohibitions::verifySignedSafetyEvidence($sBad, ['action' => $wire] + $exp)['reason']);
        $this->assertSame(['ok' => true], Prohibitions::verifySignedSafetyEvidence($sBad, ['action' => $wire, 'requireOk' => false] + $exp));

        // checkAndAdvance guards the head
        $r = Prohibitions::checkAndAdvance(true, $act, $sc, $state, ['expectedSeq' => 5]);
        $this->assertFalse($r['allow']);
        $this->assertSame('stale state head (seq)', $r['reason']);
        $r = Prohibitions::checkAndAdvance(false, $act, $sc, $state);
        $this->assertSame('permission', $r['decidedBy']);
        $r = Prohibitions::checkAndAdvance(true, $act, $sc, $state, ['expectedStateDigest' => Prohibitions::stateDigest($state)]);
        $this->assertTrue($r['allow']);
        $this->assertSame(1.0, Prohibitions::fin($r['next']->get('seq')));
        $this->assertNull(Prohibitions::stateProblem($r['next']));
    }
}
