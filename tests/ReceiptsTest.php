<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Receipts.php';

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Receipts;
use PHPUnit\Framework\TestCase;

/** receipt.ts: the hash-chained local receipt log. */
final class ReceiptsTest extends TestCase
{
    private static function p(string $verb, int $iat): Obj
    {
        return Json::parseLax('{"action":{"verb":"' . $verb . '","resource":"r"},"iat":' . $iat . '}');
    }

    public function testChainAppendVerifyAndHead(): void
    {
        $log = [];
        self::assertSame('', Receipts::receiptHead($log));
        $log = Receipts::appendReceipt($log, self::p('a', 10), ['allow' => true, 'checks' => ['audience' => 'pass']]);
        $log = Receipts::appendReceipt($log, self::p('b', 20), ['allow' => false], 99);
        self::assertSame(['seq', 'at', 'actionDigest', 'verb', 'resource', 'outcome', 'checks', 'prev', 'hash'], $log[0]->keys());
        self::assertSame(['seq', 'at', 'actionDigest', 'verb', 'resource', 'outcome', 'prev', 'hash'], $log[1]->keys());
        self::assertSame(['allow', 'deny'], [$log[0]->get('outcome'), $log[1]->get('outcome')]);
        self::assertSame('', $log[0]->get('prev'));
        self::assertSame($log[0]->get('hash'), $log[1]->get('prev'));
        self::assertSame('10', $log[0]->get('at')->lexeme);
        self::assertSame('99', $log[1]->get('at')->lexeme);
        self::assertSame(Pca::hashCanonical(self::p('a', 10)), $log[0]->get('actionDigest'));
        self::assertSame($log[1]->get('hash'), Receipts::receiptHead($log));
        self::assertSame(['ok' => true], Receipts::verifyReceiptChain($log));
        self::assertSame(['ok' => true], Receipts::verifyReceiptChain([]));
    }

    public function testTamperingAndGapsAreDetected(): void
    {
        $log = Receipts::appendReceipt(Receipts::appendReceipt([], self::p('a', 10), ['allow' => true]), self::p('b', 20), ['allow' => true]);
        $forged = $log[0]->without('outcome');
        $forged->set('outcome', 'deny');
        self::assertSame(['ok' => false, 'brokenAt' => 0, 'reason' => 'hash mismatch at seq 0 (tampered body)'], Receipts::verifyReceiptChain([$forged, $log[1]]));
        self::assertSame(['ok' => false, 'brokenAt' => 1.0, 'reason' => 'seq 1 out of order (expected 0)'], Receipts::verifyReceiptChain([$log[1]]));
        $relinked = Obj::of(array_combine($log[1]->keys(), array_map(fn($k) => $log[1]->get($k), $log[1]->keys())));
        $relinked->set('prev', 'x');
        self::assertSame(['ok' => false, 'brokenAt' => 1, 'reason' => 'prev link mismatch at seq 1'], Receipts::verifyReceiptChain([$log[0], $relinked]));
    }
}
