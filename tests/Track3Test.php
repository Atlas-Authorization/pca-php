<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\HistoryError;
use Atlas\Pca\IntentHistory;
use Atlas\Pca\Json;
use Atlas\Pca\Ledger;
use Atlas\Pca\Mesh;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Optimistic;
use PHPUnit\Framework\TestCase;

/**
 * Exact-outcome tests of the Track 3 verifiers (ledger, optimistic path, mesh, session histories) over rows of the shared
 * vectors, each mutated so that exactly one check fails: the vector replay proves the agreement, these prove the checks.
 */
final class Track3Test extends TestCase
{
    private static function row(string $file, string $table, string $name): Obj
    {
        foreach (Vectors::load($file)->get($table) as $r) {
            if ($r->get('name') === $name) {
                return $r;
            }
        }
        throw new \RuntimeException("no $table/$name");
    }

    private static function j(string $t): mixed
    {
        return Json::parseLax($t);
    }

    /** @return Obj a shallow copy with members replaced */
    private static function with(Obj $o, array $set): Obj
    {
        $c = $o->without();
        foreach ($set as $k => $v) {
            $c->set($k, $v);
        }
        return $c;
    }

    // ---- optimistic ---------------------------------------------------------------------------------------------------------------

    public function testClaimChecksFailInOrder(): void
    {
        $r = self::row('optimistic-vectors.json', 'optimistic_claim', 'ok-basic');
        $claim = $r->get('claim');
        $args = fn(Obj $c, mixed $digest = null, mixed $now = null) => Optimistic::claimCheck($c, $digest ?? $r->get('pcactn_digest'), $r->get('signer_public'), $now ?? $r->get('server_now'), null);
        $this->assertSame('ok', $args($claim));
        $this->assertSame('malformed', Optimistic::claimCheck(new Num('7'), 'x', $r->get('signer_public'), $r->get('server_now')));
        $this->assertSame('irreversible', $args(self::with($claim, ['reversibility_class' => 'irreversible'])));
        $this->assertSame('digest', $args($claim, 'other'));
        $this->assertSame('claimed_r', $args(self::with($claim, ['claimed_r' => '0.25'])));
        $this->assertSame('window', $args($claim, null, new Num((string)(1800000000000 + 6000)))); // beyond the 5 s skew
        $this->assertSame('window', $args(self::with($claim, ['challenge_window_ms' => new Num('999')])));
        $this->assertSame('window', $args(self::with($claim, ['challenge_window_ms' => new Num('86400001')])));
        $this->assertSame('signature', $args(self::with($claim, ['claimed_r' => new Num('0.26')])));
        $this->assertSame('signature', $args(self::with($claim, ['sig' => 'AAAA'])));
    }

    public function testTheChallengeWindowEndIsInclusive(): void
    {
        $c = Obj::of(['issued_at' => new Num('1000'), 'challenge_window_ms' => new Num('500')]);
        $this->assertSame(1500.0, Optimistic::challengeWindowEnd($c));
        $this->assertTrue(Optimistic::withinChallengeWindow($c, new Num('1500')));
        $this->assertFalse(Optimistic::withinChallengeWindow($c, new Num('1501')));
        $this->assertFalse(Optimistic::withinChallengeWindow($c, '1500')); // a string is not a time
        $this->assertSame('open', Optimistic::claimStatus($c, new Num('1500')));
        $this->assertSame('finalized', Optimistic::claimStatus($c, new Num('1501')));
    }

    public function testFraudProofAndSettlementShapes(): void
    {
        $r = self::row('optimistic-vectors.json', 'optimistic_fraud_proof', 'ok-policy-denied');
        $proof = $r->get('proof');
        $this->assertSame('ok', Optimistic::fraudProofWireCheck($r->get('claim'), $proof));
        $this->assertSame('malformed', Optimistic::fraudProofWireCheck($r->get('claim'), new Num('1')));
        $this->assertSame('digest', Optimistic::fraudProofWireCheck($r->get('claim'), self::with($proof, ['pcactn_digest' => 'x'])));
        $this->assertSame('bond', Optimistic::fraudProofWireCheck($r->get('claim'), self::with($proof, ['bond_ref' => 'other'])));
        $this->assertSame('kind', Optimistic::fraudProofWireCheck($r->get('claim'), self::with($proof, ['kind' => 'made-up'])));
        $this->assertSame('consistency', Optimistic::fraudProofWireCheck($r->get('claim'), self::with($proof, ['kind' => 'optimistic-not-allowed'])));
        $s = self::row('optimistic-vectors.json', 'optimistic_settlement', 'ok-open');
        $rec = $s->get('record');
        $this->assertSame('ok', Optimistic::settlementWireCheck($rec, $s->get('guardian_public')));
        $this->assertSame('malformed', Optimistic::settlementWireCheck([$rec], $s->get('guardian_public')));
        $this->assertSame('suite', Optimistic::settlementWireCheck(self::with($rec, ['alg' => 'no-such-suite']), $s->get('guardian_public')));
        $this->assertSame('shape', Optimistic::settlementWireCheck(self::with($rec, ['amount' => new Num('0')]), $s->get('guardian_public')));
        $this->assertSame('shape', Optimistic::settlementWireCheck(self::with($rec, ['evidenceDigest' => 'x']), $s->get('guardian_public')));
        $this->assertSame('signature', Optimistic::settlementWireCheck(self::with($rec, ['amount' => new Num('101')]), $s->get('guardian_public')));
    }

    // ---- ledger -------------------------------------------------------------------------------------------------------------------

    public function testConsistencyEdgeCases(): void
    {
        $empty = Ledger::emptyTreeRoot();
        $p = fn(int $a, int $b, array $path = []) => Obj::of(['oldSize' => new Num((string)$a), 'newSize' => new Num((string)$b), 'path' => $path]);
        $this->assertTrue(Ledger::verifyConsistency($empty, $empty, $p(0, 0)));
        $this->assertFalse(Ledger::verifyConsistency('x', $empty, $p(0, 0)));
        $this->assertFalse(Ledger::verifyConsistency($empty, $empty, $p(2, 1)));
        $this->assertFalse(Ledger::verifyConsistency($empty, $empty, $p(0, 0, [$empty])));
        $this->assertFalse(Ledger::verifyConsistency($empty, $empty, $p(0, 1, array_fill(0, 200, $empty))));
        $this->assertFalse(Ledger::verifyConsistency($empty, $empty, new Num('1')));
        $this->assertFalse(Ledger::verifyConsistency(1, $empty, $p(0, 0)));
    }

    public function testATamperedCheckpointNamesItsIndex(): void
    {
        $r = null;
        foreach (Vectors::load('ledger-vectors.json')->get('ledger_checkpoint_chain') as $x) {
            if (is_array($x->get('chain')) && count($x->get('chain')) >= 2 && $x->get('expect')->get('ok') === true) {
                $r = $x;
                break;
            }
        }
        $this->assertNotNull($r, 'a valid multi-checkpoint chain');
        $chain = $r->get('chain');
        $this->assertSame(['ok' => true], Ledger::verifyCheckpointChain($chain, $r->get('guardian_public'), $r->get('policy')));
        $bad = $chain;
        $bad[1] = self::with($chain[1], ['sth' => self::with($chain[1]->get('sth'), ['root' => 'AAAA'])]);
        $this->assertSame(['ok' => false, 'at' => 1], Ledger::verifyCheckpointChain($bad, $r->get('guardian_public'), $r->get('policy')));
        $this->assertSame(['ok' => false, 'at' => 0], Ledger::verifyCheckpointChain([], $r->get('guardian_public')));
        $this->assertSame(['ok' => false, 'at' => 0], Ledger::verifyCheckpointChain('x', $r->get('guardian_public')));
    }

    // ---- mesh ---------------------------------------------------------------------------------------------------------------------

    public function testMeshRefusalsHaveTheirReasonAndHop(): void
    {
        $r = self::row('mesh-vectors.json', 'mesh', 'valid/base');
        $this->assertSame(['ok' => true, 'hop' => -1], Mesh::verify($r->get('proof'), $r->get('trust')));
        $this->assertSame(['ok' => false, 'reason' => 'malformed proof', 'hop' => -1], Mesh::verify(new Num('1'), $r->get('trust')));
        $this->assertSame(['ok' => false, 'reason' => 'invalid trust configuration', 'hop' => -1], Mesh::verify($r->get('proof'), 'x'));
        $this->assertSame('malformed action', Mesh::verify(self::with($r->get('proof'), ['action_sig' => new Num('1')]), $r->get('trust'))['reason']);
        $this->assertSame('invalid trust configuration: threshold', Mesh::verify($r->get('proof'), self::with($r->get('trust'), ['threshold' => new Num('0')]))['reason']);
        $this->assertSame('action not signed by the chain tip holder', Mesh::verify(self::with($r->get('proof'), ['action_sig' => 'AAAA']), $r->get('trust'))['reason']);
        $stale = self::with($r->get('trust'), ['now' => new Num((string)(1800000000000 + 3_600_000))]);
        $v = Mesh::verify($r->get('proof'), $stale);
        $this->assertFalse($v['ok']);
        $this->assertStringContainsString('head is stale', $v['reason']);
    }

    // ---- session histories -------------------------------------------------------------------------------------------------------------

    public function testWindowsKeepFutureStampedEventsAndRefuseBadTimes(): void
    {
        $sliding = self::j('{"kind":"sliding","ms":100}');
        $period = self::j('{"kind":"period","ms":100,"t0":0}');
        $this->assertTrue(IntentHistory::inWindow(self::j('{"kind":"task"}'), new Num('1'), new Num('9999')));
        $this->assertFalse(IntentHistory::inWindow($sliding, new Num('900'), new Num('1000'))); // t - ms excluded
        $this->assertTrue(IntentHistory::inWindow($sliding, new Num('901'), new Num('1000')));
        $this->assertTrue(IntentHistory::inWindow($sliding, new Num('1001'), new Num('1000'))); // stamped after t: not yet out
        $this->assertTrue(IntentHistory::inWindow($period, new Num('101'), new Num('199')));
        $this->assertFalse(IntentHistory::inWindow($period, new Num('99'), new Num('100')));
        $this->assertFalse(IntentHistory::inWindow($sliding, new Num('1.5'), new Num('2')));
        $this->assertFalse(IntentHistory::inWindow(self::j('{"kind":"other"}'), new Num('1'), new Num('2')));
    }

    public function testAMonitorFoldAndACorruptHistory(): void
    {
        $m = self::j('{"id":"m","kind":"responds_within","p":{"verb":"a"},"q":{"verb":"b"},"within":2}');
        $ev = static fn(string $verb, string $status = 'committed') => Obj::of(['id' => $verb, 'verb' => $verb, 'resource' => 'r', 'params' => new Obj(), 'status' => $status, 't' => new Num('1')]);
        $this->assertSame('idle', IntentHistory::monitorState($m, []));
        $this->assertSame('pending:2', IntentHistory::monitorState($m, [$ev('a')]));
        $this->assertSame('pending:1', IntentHistory::monitorState($m, [$ev('a'), $ev('c')]));
        $this->assertSame('missed', IntentHistory::monitorState($m, [$ev('a'), $ev('c'), $ev('c')]));
        $this->assertSame('idle', IntentHistory::monitorState($m, [$ev('a'), $ev('b')]));
        $this->assertSame('idle', IntentHistory::monitorState($m, [$ev('a', 'released')])); // an uncounted status leaves the state alone
        $a = self::j('{"id":"s","agg":"sum","val":"action.params.x","unit":"u","sel":{"verbs":["buy"]},"win":{"kind":"task"},"key":null,"holder":{"kind":"site_local"}}');
        $buy = static fn(int $x, mixed $t) => Obj::of(['id' => 'e', 'verb' => 'buy', 'resource' => 'r', 'params' => Obj::of(['x' => new Num((string)$x)]), 'status' => 'committed', 't' => $t]);
        $this->assertSame('{"sum":12}', Json::canonicalizeStrict(IntentHistory::accPreState($a, [$buy(5, new Num('1')), $buy(7, new Num('2'))], new Obj(), new Num('3'))));
        $this->expectException(HistoryError::class);
        IntentHistory::accPreState($a, [$buy(5, new Num('1.5'))], new Obj(), new Num('3'));
    }

    // ---- lenient canonical JSON (the optimistic signatures) -------------------------------------------------------------------------

    public function testLenientCanonicalFormIsTheJavaScriptOne(): void
    {
        $v = self::j('{"b":1.0,"a":[1e3,0.25,-0,"x\\u0001\\"","\\ud800"],"é":true}');
        $this->assertSame('{"a":[1000,0.25,0,"x\\u0001\\"","\\ud800"],"b":1,"é":true}', Json::canonicalizeLenient($v));
    }
}
