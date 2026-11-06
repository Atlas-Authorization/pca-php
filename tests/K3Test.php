<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/K3.php';

use Atlas\Pca\FreshAt;
use Atlas\Pca\Json;
use Atlas\Pca\K3;
use Atlas\Pca\K3Sig;
use Atlas\Pca\K4;
use Atlas\Pca\Num;
use Atlas\Pca\Obligations;
use Atlas\Pca\PolicyClasses;
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

    public function testNegativeZeroIsNeverAWireInteger(): void
    {
        // strict profile: the reference isSafeInt refuses -0; 0 stays an integer
        $z = new Num('-0');
        $this->assertSame([false, true, true, true], [K3Sig::isSafeInt($z), K3Sig::isSafeInt(new Num('0')), K3Sig::isNegZero(-0.0), K3Sig::isNonNegSafeInt($z)]);
        $this->assertSame('due must be a non-negative safe integer', Obligations::error(Obj::of(['kind' => 'log', 'due' => $z])));
        $this->assertNull(Obligations::error(Obj::of(['kind' => 'log', 'due' => new Num('0')])));
        $this->assertSame('policy_classes[0].revision must be a non-negative safe integer',
            PolicyClasses::listError([Obj::of(['class' => 'org', 'decision' => 'allow', 'revision' => $z, 'digest' => 'd'])]));
        $esc = Vectors::load('k4-vectors.json')->get('escalation');
        $c = $esc->get('decisions')[0];
        foreach (['loss', 'pBadUpperPpm'] as $k) {
            $risk = Obj::of([]);
            foreach ($c->get('risk')->keys() as $a) {
                $risk->set($a, $c->get('risk')->get($a));
            }
            $risk->set($k, $z);
            $this->assertSame('risk_input_invalid', K4::decide($esc->get('config'), $c->get('calibration'), $risk)['reason'], $k);
        }
    }
}
