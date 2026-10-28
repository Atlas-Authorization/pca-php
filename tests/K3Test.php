<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/K3.php';

use Atlas\Pca\FreshAt;
use Atlas\Pca\Json;
use Atlas\Pca\K3;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** K3 verifiers are total: any malformed input is the failure value, never an exception. */
final class K3Test extends TestCase
{
    /** @return list<mixed> */
    private static function garbage(): array
    {
        return [null, true, 7, 'x', [], [1, 2], new Obj(), Json::parseLax('{"v":1,"signer":5,"sig":[],"revision":"1","verbs":"a"}'), Json::parseLax('[{"a":[]}]')];
    }

    public function testFailureValuesNeverThrow(): void
    {
        foreach (self::garbage() as $g) {
            $this->assertFalse(FreshAt::verify($g, $g));
            $this->assertSame('deny', FreshAt::check($g, $g, $g)['decision']);
            $this->assertNotNull(FreshAt::validateWire($g));
            $this->assertFalse(K3::verifyBundle($g, $g)['ok']);
            $this->assertFalse(K3::verifyLogHead($g, $g));
            $this->assertFalse(K3::verifyRecordInclusion($g, $g, $g, $g));
            $this->assertFalse(K3::verifyBatch($g, $g, $g)['ok']);
            $this->assertFalse(K3::verifyListReceipt($g, $g));
            $this->assertFalse(K3::verifyListCursor($g, $g, $g)['ok']);
            $this->assertFalse(K3::verifyAmendment($g, $g, true)['ok']);
            $this->assertFalse(K3::verifyRevokeSignature($g, $g, $g)['ok']);
            $this->assertFalse(K3::verifyNeedApproval($g, $g, $g, $g, true)['ok']);
        }
    }

    public function testDecideReportsNothingWithoutMemberOrPolicy(): void
    {
        $this->assertSame('none', FreshAt::decide(false, null, null, 0)['status']);
        $this->assertSame('fail', FreshAt::decide(true, new Obj(), null, 0)['status']);
    }
}
