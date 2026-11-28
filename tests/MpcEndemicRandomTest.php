<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/MpcEndemicOt.php';

use Atlas\Pca\MpcEndemicOt;
use Atlas\Pca\MpcEndemicOtAbort;
use Atlas\Pca\MpcLweLattice;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/** endemicLweBaseOtRandom: the in-process random endemic base OT (the receiver learns exactly its chosen pad). */
#[Group('native-lib')] // runs in the lwe-ot workflow, which builds liblweot
final class MpcEndemicRandomTest extends TestCase
{
    protected function setUp(): void
    {
        if (!MpcLweLattice::available()) {
            if (getenv('ATLAS_PCA_LIBLWEOT_REQUIRED') === '1') {
                $this->fail('liblweot must load (ATLAS_PCA_LIBLWEOT, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and liblweot (ATLAS_PCA_LIBLWEOT)');
        }
    }

    public function testReceiverLearnsOnlyTheChosenPad(): void
    {
        $r = MpcEndemicOt::baseOtRandom([0, 1, 1, 0]);
        self::assertCount(4, $r['senderPads']);
        foreach ([0, 1, 1, 0] as $i => $c) {
            self::assertSame($r['senderPads'][$i][$c], $r['recvPads'][$i]);
            self::assertNotSame($r['senderPads'][$i][1 - $c], $r['recvPads'][$i]);
            self::assertSame(MpcEndemicOt::ENDEMIC_SECRET_BYTES, strlen($r['recvPads'][$i]));
        }
        self::assertSame(MpcEndemicOt::sessionId($r['message']['rn']), $r['sid']);
    }

    public function testATamperedCiphertextAborts(): void
    {
        $this->expectException(MpcEndemicOtAbort::class);
        MpcEndemicOt::baseOtRandom([0, 1], null, static fn(array $cts): array => [$cts[0]]);
    }
}
