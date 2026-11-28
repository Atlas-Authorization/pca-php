<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Undo.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Undo;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Undo.php: withReceipt builds the signed, chained receipt from an array or an Obj transition. */
final class GuardSurvivorKill33UndoTest extends TestCase
{
    public function testWithReceiptAppendsASignedChainedReceipt(): void
    {
        $seed = str_repeat("\x07", 32);
        $pk = (new KeyPair($seed))->public;
        $rec0 = Obj::of(['id' => 'r1', 'state' => 'open', 'compensation_digest' => 'cd', 'receipts' => []]);
        $rec1 = Undo::withReceipt($rec0, ['event' => 'opened', 'note' => 'n1'], 100, $seed);
        $this->assertSame([], $rec0->get('receipts'), 'the input record is not changed');
        $rs = $rec1->get('receipts');
        $this->assertCount(1, $rs);
        $r0 = $rs[0];
        $this->assertSame(['r1', 'opened', 'open', '100', 'cd', '', 'n1', $pk],
            [$r0->get('record'), $r0->get('event'), $r0->get('state'), $r0->get('at')->lexeme, $r0->get('compensation_digest'), $r0->get('prev'), $r0->get('note'), $r0->get('signer')]);
        $this->assertTrue(Undo::verifyReceipt($r0, $pk));

        $mid = $rec1->without();
        $mid->set('state', 'vetoed');
        $rec2 = Undo::withReceipt($mid, Obj::of(['event' => 'vetoed', 'note' => 'n2']), 200, $seed);
        $rs2 = $rec2->get('receipts');
        $this->assertCount(2, $rs2);
        $this->assertSame($r0, $rs2[0]);
        $this->assertSame(['vetoed', 'vetoed', '200', 'n2', Undo::receiptDigest($r0)],
            [$rs2[1]->get('event'), $rs2[1]->get('state'), $rs2[1]->get('at')->lexeme, $rs2[1]->get('note'), $rs2[1]->get('prev')]);
        $this->assertNull(Undo::receiptChainError($rec2, $pk));
    }
}
