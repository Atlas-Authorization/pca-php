<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Undo.php';
require_once __DIR__ . '/../src/Obligations.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Obligations;
use Atlas\Pca\Pca;
use Atlas\Pca\Undo;
use PHPUnit\Framework\TestCase;

/**
 * Undo windows (0.5), the pure layer: token check order (every code reachable, the inclusive expiry), receipt shape, the chain
 * checks, every row of the state machine, the window clamp and the `undo_window` obligation. The shared vectors are replayed by
 * VectorsTest::testUndoVectors.
 */
final class UndoTest extends TestCase
{
    private const WE = 1800000900000;

    private static function key(): KeyPair
    {
        return new KeyPair(str_repeat("\x09", 32));
    }

    private static function record(array $over = []): Obj
    {
        $r = Obj::of(['id' => 'op_1', 'aud' => 'rs', 'principal' => 'P', 'compensation_digest' => 'C', 'render_digest' => 'R',
            'window_end' => new Num((string)self::WE)]);
        foreach ($over as $k => $v) {
            $r->set($k, $v);
        }
        return $r;
    }

    private static function with(Obj $o, string $k, mixed $v): Obj
    {
        $x = $o->without();
        $x->set($k, $v);
        return $x;
    }

    public function testTokenCheckOrderReachesEveryCode(): void
    {
        $k = self::key();
        $rec = self::record();
        $t = Undo::signToken($rec, $k);
        $pk = $k->public;
        $this->assertSame('ok', Undo::tokenCheck($t, $pk, $rec, self::WE - 1));
        $this->assertSame('ok', Undo::tokenCheck($t, $pk, $rec, self::WE), 'valid through exp inclusive');
        $this->assertSame('expired', Undo::tokenCheck($t, $pk, $rec, self::WE + 1));
        $this->assertSame('expired', Undo::tokenCheck($t, $pk, $rec, 1.5));
        $this->assertSame('malformed', Undo::tokenCheck(self::with($t, 'extra', 1), $pk, $rec, 0));
        $this->assertSame('malformed', Undo::tokenCheck($t->without('render_digest'), $pk, $rec, 0));
        $this->assertSame('malformed', Undo::tokenCheck(self::with($t, 'kind', 'x'), $pk, $rec, 0));
        $this->assertSame('malformed', Undo::tokenCheck(self::with($t, 'sig', 'x'), $pk, $rec, 0));
        $this->assertSame('malformed', Undo::tokenCheck(self::with($t, 'record', ''), $pk, $rec, 0));
        $this->assertSame('malformed', Undo::tokenCheck('x', $pk, $rec, 0));
        $other = (new KeyPair(str_repeat("\x0a", 32)))->public;
        $this->assertSame('signer', Undo::tokenCheck($t, $other, $rec, 0));
        $this->assertSame('signature', Undo::tokenCheck(self::with($t, 'aud', 'other'), $pk, $rec, 0), 'the signature is checked before the binding');
        $this->assertSame('record', Undo::tokenCheck($t, $pk, self::record(['id' => 'op_2']), 0));
        foreach (['aud' => 'x', 'principal' => 'x', 'compensation_digest' => 'x', 'render_digest' => 'x', 'window_end' => new Num((string)(self::WE + 1))] as $f => $v) {
            $this->assertSame('binding', Undo::tokenCheck($t, $pk, self::record([$f => $v]), 0), $f);
        }
        // a record without a render digest binds the empty string
        $plain = self::record()->without('render_digest');
        $this->assertSame('ok', Undo::tokenCheck(Undo::signToken($plain, $k), $pk, $plain, 0));
        $this->assertSame('', Undo::signToken($plain, $k)->get('render_digest'));
    }

    public function testTokenEncodingRoundTrip(): void
    {
        $t = Undo::signToken(self::record(), self::key());
        $e = Undo::encodeToken($t);
        $this->assertSame(Pca::b64u(\Atlas\Pca\Json::canonicalizeStrict($t)), $e);
        $this->assertSame(\Atlas\Pca\Json::canonicalizeStrict($t), \Atlas\Pca\Json::canonicalizeStrict(Undo::decodeToken($e)));
        $this->assertNull(Undo::decodeToken(''));
        $this->assertNull(Undo::decodeToken(str_repeat('A', 4097)));
        $this->assertNull(Undo::decodeToken($e . '='));
        $this->assertNull(Undo::decodeToken(Pca::b64u('[1]')));
        $this->assertNull(Undo::decodeToken(Pca::b64u("\xff")));
        $this->assertNull(Undo::decodeToken(5));
        $this->assertNotSame(Undo::tokenDigest($t), Undo::tokenDigest(self::with($t, 'exp', new Num('1'))));
    }

    private static function receipt(string $event, string $state, int $at, string $prev = '', string $note = ''): Obj
    {
        return Undo::signReceipt(['record' => 'op_1', 'event' => $event, 'state' => $state, 'at' => $at, 'compensation_digest' => 'C',
            'prev' => $prev, 'note' => $note], self::key());
    }

    public function testReceiptMemberCountAndFields(): void
    {
        $pk = self::key()->public;
        $r = self::receipt('opened', 'open', 1);
        $this->assertCount(11, $r->keys());
        $this->assertTrue(Undo::verifyReceipt($r, $pk));
        $this->assertFalse(Undo::verifyReceipt(self::with($r, 'extra', 'x'), $pk), '12 members');
        $this->assertFalse(Undo::verifyReceipt($r->without('note'), $pk), '10 members');
        $this->assertFalse(Undo::verifyReceipt(self::with($r, 'note', 'changed'), $pk));
        $this->assertFalse(Undo::verifyReceipt(self::with($r, 'event', 'teleported'), $pk));
        $this->assertFalse(Undo::verifyReceipt(self::with($r, 'state', 'gone'), $pk));
        $this->assertFalse(Undo::verifyReceipt(self::with($r, 'at', new Num('-1')), $pk));
        $this->assertFalse(Undo::verifyReceipt($r, (new KeyPair(str_repeat("\x0a", 32)))->public));
        $this->assertFalse(Undo::verifyReceipt(null, $pk));
    }

    public function testReceiptChainPrevAtAndLastState(): void
    {
        $pk = self::key()->public;
        $r0 = self::receipt('opened', 'open', 10);
        $r1 = self::receipt('vetoed', 'vetoed', 10, Undo::receiptDigest($r0), 'token');
        $r2 = self::receipt('compensated', 'compensated', 12, Undo::receiptDigest($r1));
        $rec = static fn (array $rs, string $state = 'compensated'): Obj => Obj::of(['id' => 'op_1', 'compensation_digest' => 'C', 'state' => $state, 'receipts' => $rs]);
        $this->assertNull(Undo::receiptChainError($rec([$r0, $r1, $r2]), $pk), 'equal at is fine');
        $this->assertNull(Undo::receiptChainError($rec([$r0], 'open'), $pk));
        $this->assertSame('no receipts', Undo::receiptChainError($rec([]), $pk));
        $this->assertSame('the last receipt does not state the record state', Undo::receiptChainError($rec([$r0, $r1, $r2], 'vetoed'), $pk));
        $this->assertSame('receipt 0 does not link to the previous one', Undo::receiptChainError($rec([self::receipt('opened', 'open', 10, Undo::receiptDigest($r0))], 'open'), $pk));
        $this->assertSame('receipt 1 does not link to the previous one', Undo::receiptChainError($rec([$r0, $r2]), $pk));
        $this->assertSame('the first receipt is not opened', Undo::receiptChainError($rec([self::receipt('vetoed', 'vetoed', 10)], 'vetoed'), $pk));
        $back = self::receipt('vetoed', 'vetoed', 9, Undo::receiptDigest($r0));
        $this->assertSame('receipt 1 goes back in time', Undo::receiptChainError($rec([$r0, $back], 'vetoed'), $pk));
        $this->assertSame('receipt 0 does not verify', Undo::receiptChainError($rec([self::with($r0, 'note', 'x')], 'open'), $pk));
        $this->assertSame('receipt 0 is for another record', Undo::receiptChainError(Obj::of(['id' => 'op_2', 'compensation_digest' => 'C', 'state' => 'open', 'receipts' => [$r0]]), $pk));
        $this->assertSame('receipt 0 is for another record', Undo::receiptChainError(Obj::of(['id' => 'op_1', 'compensation_digest' => 'D', 'state' => 'open', 'receipts' => [$r0]]), $pk));
    }

    private static function state(string $state, array $over = []): Obj
    {
        $r = Obj::of(['id' => 'op_1', 'state' => $state, 'window_end' => new Num('1000'), 'ver' => new Num('3'), 'attempt' => new Num('0')]);
        foreach ($over as $k => $v) {
            $r->set($k, $v);
        }
        return $r;
    }

    /** @return list<mixed> outcome, then code or state + ver */
    private static function tr(Obj $rec, array $ev, int $now = 500): array
    {
        $g = Undo::transition($rec, \Atlas\Pca\Sign::n($ev), $now);
        return match ($g['outcome']) {
            'applied' => ['applied', $g['record']->get('state'), $g['record']->get('ver')->int(), $g['receipt']['event']],
            'refused' => ['refused', $g['code']],
            default => [$g['outcome']],
        };
    }

    public function testEveryTransitionRow(): void
    {
        $veto = ['kind' => 'veto', 'veto' => ['at' => 1, 'via' => 'token', 'by' => 'p']];
        // veto
        $this->assertSame(['applied', 'vetoed', 4, 'vetoed'], self::tr(self::state('open'), $veto));
        $this->assertSame(['applied', 'vetoed', 4, 'vetoed'], self::tr(self::state('open'), $veto, 1000), 'the window end is inclusive');
        $this->assertSame(['refused', 'window_closed'], self::tr(self::state('open'), $veto, 1001));
        foreach (['vetoed', 'compensated', 'compensation_failed'] as $s) {
            $this->assertSame(['replayed'], self::tr(self::state($s), $veto), $s);
        }
        $this->assertSame(['refused', 'finalized'], self::tr(self::state('finalized'), $veto));
        $this->assertSame(['refused', 'invalid'], self::tr(self::state('open'), ['kind' => 'veto', 'veto' => ['at' => 1, 'via' => 'email', 'by' => 'p']]));
        $this->assertSame(['refused', 'invalid'], self::tr(self::state('open'), ['kind' => 'veto', 'veto' => ['at' => 1, 'via' => 'token', 'by' => '']]));
        // finalize
        $this->assertSame(['refused', 'window_open'], self::tr(self::state('open'), ['kind' => 'finalize'], 1000));
        $this->assertSame(['applied', 'finalized', 4, 'finalized'], self::tr(self::state('open'), ['kind' => 'finalize'], 1001));
        $this->assertSame(['replayed'], self::tr(self::state('finalized'), ['kind' => 'finalize'], 1001));
        $this->assertSame(['refused', 'vetoed'], self::tr(self::state('vetoed'), ['kind' => 'finalize'], 1001));
        // abort
        $this->assertSame(['applied', 'finalized', 4, 'aborted'], self::tr(self::state('open'), ['kind' => 'abort', 'reason' => 'x']));
        $this->assertSame(['applied', 'finalized', 4, 'aborted'], self::tr(self::state('vetoed'), ['kind' => 'abort', 'reason' => 'x']));
        $this->assertSame(['refused', 'effect_recorded'], self::tr(self::state('open', ['effect' => Obj::of(['at' => new Num('1')])]), ['kind' => 'abort', 'reason' => 'x']));
        $this->assertSame(['replayed'], self::tr(self::state('finalized', ['outcome' => Obj::of(['status' => 'aborted'])]), ['kind' => 'abort', 'reason' => 'x']));
        $this->assertSame(['refused', 'finalized'], self::tr(self::state('finalized', ['outcome' => Obj::of(['status' => 'finalized'])]), ['kind' => 'abort', 'reason' => 'x']));
        $this->assertSame(['refused', 'finalized'], self::tr(self::state('compensated'), ['kind' => 'abort', 'reason' => 'x']));
        // effect
        $this->assertSame(['applied', 'open', 4, 'effect'], self::tr(self::state('open'), ['kind' => 'effect']));
        $this->assertSame(['applied', 'vetoed', 4, 'effect'], self::tr(self::state('vetoed'), ['kind' => 'effect']));
        $this->assertSame(['replayed'], self::tr(self::state('open', ['effect' => Obj::of(['at' => new Num('1')])]), ['kind' => 'effect']));
        $this->assertSame(['refused', 'finalized'], self::tr(self::state('compensated'), ['kind' => 'effect']));
        // compensated
        $this->assertSame(['applied', 'compensated', 4, 'compensated'], self::tr(self::state('vetoed'), ['kind' => 'compensated']));
        $this->assertSame(['applied', 'compensated', 4, 'compensated'], self::tr(self::state('compensation_failed'), ['kind' => 'compensated']));
        $this->assertSame(['replayed'], self::tr(self::state('compensated'), ['kind' => 'compensated']));
        $this->assertSame(['refused', 'not_vetoed'], self::tr(self::state('open'), ['kind' => 'compensated']));
        // compensation_failed
        $this->assertSame(['applied', 'compensation_failed', 4, 'compensation_failed'], self::tr(self::state('vetoed'), ['kind' => 'compensation_failed', 'reason' => 'x']));
        $this->assertSame(['replayed'], self::tr(self::state('compensation_failed'), ['kind' => 'compensation_failed', 'reason' => 'x']));
        $this->assertSame(['refused', 'not_vetoed'], self::tr(self::state('open'), ['kind' => 'compensation_failed', 'reason' => 'x']));
        // retry
        $g = Undo::transition(self::state('compensation_failed'), Obj::of(['kind' => 'retry']), 500);
        $this->assertSame(['applied', 'vetoed', 4, 1, 'retried'], [$g['outcome'], $g['record']->get('state'), $g['record']->get('ver')->int(), $g['record']->get('attempt')->int(), $g['receipt']['event']]);
        $this->assertSame(['refused', 'not_failed'], self::tr(self::state('vetoed'), ['kind' => 'retry']));
        // malformed
        $this->assertSame(['refused', 'invalid'], self::tr(self::state('open'), ['kind' => 'teleport']));
        $this->assertSame(['refused', 'invalid'], self::tr(self::state('gone'), ['kind' => 'finalize']));
        $this->assertSame('invalid', Undo::transition(self::state('open'), Obj::of(['kind' => 'finalize']), -0.5)['code']);
        $this->assertSame('invalid', Undo::transition(null, Obj::of(['kind' => 'finalize']), 1)['code']);
    }

    public function testTransitionsArePureAndNotesAreBounded(): void
    {
        $rec = self::state('open');
        $g = Undo::transition($rec, \Atlas\Pca\Sign::n(['kind' => 'abort', 'reason' => str_repeat('r', 600)]), 500);
        $this->assertSame('open', $rec->get('state'), 'the input record is not modified');
        $this->assertSame(512, strlen($g['record']->get('outcome')->get('reason')));
        $this->assertSame(128, strlen($g['receipt']['note']));
        $this->assertSame(500, $g['record']->get('outcome')->get('at')->int());
        $v = Undo::transition($rec, \Atlas\Pca\Sign::n(['kind' => 'veto', 'veto' => ['at' => 1, 'via' => 'operator', 'by' => 'p']]), 500);
        $this->assertSame('operator', $v['receipt']['note']);
        $this->assertSame('operator', $v['record']->get('veto')->get('via'));
        $e = Undo::transition($rec, \Atlas\Pca\Sign::n(['kind' => 'effect', 'result' => ['ok' => true]]), 7);
        $this->assertSame([7, true], [$e['record']->get('effect')->get('at')->int(), $e['record']->get('effect')->get('result')->get('ok')]);
        $this->assertSame('undefined', Undo::transition(self::state('vetoed'), Obj::of(['kind' => 'compensation_failed']), 1)['record']->get('outcome')->get('reason'));
    }

    public function testWindowClampEdges(): void
    {
        $this->assertSame(900000, Undo::resolveWindow(null));
        $this->assertSame(30000, Undo::resolveWindow(29999));
        $this->assertSame(30000, Undo::resolveWindow(30000));
        $this->assertSame(30001, Undo::resolveWindow(30001));
        $this->assertSame(86400000, Undo::resolveWindow(86400000));
        $this->assertSame(86400000, Undo::resolveWindow(86400001));
        $this->assertSame(900000, Undo::resolveWindow(NAN));
        $this->assertSame(900000, Undo::resolveWindow(INF));
        $this->assertSame(120000, Undo::resolveWindow(120000.9));
        $this->assertSame(60000, Undo::resolveWindow(null, ['defaultMs' => 60000]));
        $this->assertSame(300000, Undo::resolveWindow(600000, ['maxMs' => 300000]));
        $this->assertSame(86400000, Undo::resolveWindow(90000000, ['maxMs' => 90000000]), 'a host max cannot exceed 24 h');
        $this->assertSame(30000, Undo::resolveWindow(5, ['minMs' => 1]), 'a host min cannot go below 30 s');
        $this->assertSame(120000, Undo::resolveWindow(1, ['minMs' => 120000, 'maxMs' => 60000]));
        $this->assertSame(45000, Undo::resolveWindow(new Num('45000'), \Atlas\Pca\Sign::n(['minMs' => 40000])));
    }

    public function testUndoWindowObligationParams(): void
    {
        $ob = static fn (array $params): ?string => Obligations::error(\Atlas\Pca\Sign::n(['kind' => 'undo_window', 'params' => $params, 'due' => 5]));
        $this->assertNull($ob(['id' => 'op_1', 'window_end' => 5]));
        $this->assertNull($ob(['id' => str_repeat('i', 128), 'window_end' => 0]));
        $this->assertNotNull($ob(['id' => str_repeat('i', 129), 'window_end' => 5]));
        $this->assertNotNull($ob(['id' => 'op_1', 'window_end' => -1]));
        $this->assertNotNull($ob(['id' => 'op_1', 'window_end' => 1.5]));
        $this->assertNotNull($ob(['id' => 'op_1', 'window_end' => 5, 'extra' => 1]));
        $this->assertNotNull($ob(['window_end' => 5]));
        $this->assertNotNull($ob(['id' => 'op_1']));
        $this->assertContains('undo_window', Obligations::KINDS);
        $adm = \Atlas\Pca\Sign::n(['id' => 'op_1', 'window_end' => 5, 'compensation' => ['verb' => 'drafts.delete', 'resource' => 'd']]);
        $this->assertNull(Obligations::error(Undo::obligation($adm)));
    }

    public function testAdmissionShape(): void
    {
        $ok = ['id' => 'op_1', 'window_end' => 5, 'compensation' => ['verb' => 'v', 'resource' => '']];
        $this->assertNull(Undo::admissionError(\Atlas\Pca\Sign::n($ok)));
        foreach ([['id' => str_repeat('i', 129)], ['id' => ''], ['id' => "a\nb"], ['window_end' => -1], ['window_end' => 1.5],
                     ['compensation' => ['verb' => '', 'resource' => 'r']], ['compensation' => ['verb' => 'v']], ['compensation' => null]] as $bad) {
            $this->assertNotNull(Undo::admissionError(\Atlas\Pca\Sign::n($bad + $ok)), json_encode($bad));
        }
        $this->assertNotNull(Undo::admissionError(null));
    }
}
