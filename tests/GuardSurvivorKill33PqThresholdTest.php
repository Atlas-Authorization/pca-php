<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/../src/PqThreshold.php';

use Atlas\Pca\Mldsa;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\PqThreshold;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/PqThreshold.php: pool refusals, the public quorum signer and its key check, the assembler's refusals, the entry cap. */
final class GuardSurvivorKill33PqThresholdTest extends TestCase
{
    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e::class . ': ' . $e->getMessage();
        }
        return 'no error';
    }

    /** A key pair object of another family that is never asked to sign (no key material). */
    private static function wrongFamily(): PqKeyPair
    {
        $pq = (new \ReflectionClass(PqKeyPair::class))->newInstanceWithoutConstructor();
        \Closure::bind(function (): void {
            $this->family = 'ML-DSA-87';
            $this->public = 'x';
        }, $pq, PqKeyPair::class)();
        return $pq;
    }

    /** A pool that is not a list is refused with the reference's error. */
    public function testPoolMustBeAList(): void
    {
        $this->assertSame([], PqThreshold::normalizePqQuorumPool(['not-a-key']), 'control');
        foreach (['x', ['a' => 'x']] as $bad) {
            $this->assertSame('InvalidArgumentException: pqPublicKeys is not iterable', self::thrown(fn() => PqThreshold::normalizePqQuorumPool($bad)));
        }
    }

    /** signPqQuorum is public; with no signers the block is empty and pqT defaults to 0; a non-ML-DSA-65 key is refused. */
    public function testSignPqQuorum(): void
    {
        $this->assertSame(['v' => 2, 'alg' => 'ml-dsa-65', 'pqT' => 0, 'signers' => []], PqThreshold::signPqQuorum('m', []));
        $this->assertSame('InvalidArgumentException: signPqQuorum: every co-signer key must be ML-DSA-65',
            self::thrown(fn() => PqThreshold::signPqQuorum('m', [self::wrongFamily()])));
    }

    /** Each assembler refusal is raised in order with its own message. */
    public function testAssembleRefusals(): void
    {
        $a = Obj::of(['a' => 'b']);
        $k32 = str_repeat("\0", 32);
        $k31 = str_repeat("\0", 31);
        $agg = str_repeat("\0", 64);
        $w = self::wrongFamily();
        $this->assertSame('InvalidArgumentException: hybridThresholdAssemble: t must be a positive integer (got 0)',
            self::thrown(fn() => PqThreshold::hybridThresholdAssemble($a, $k32, $agg, 0, 1, [])));
        $this->assertSame('InvalidArgumentException: hybridThresholdAssemble: FROST quorum of 1 is below the threshold t=2',
            self::thrown(fn() => PqThreshold::hybridThresholdAssemble($a, $k32, $agg, 2, 1, [])));
        $this->assertSame('InvalidArgumentException: hybridThresholdAssemble: at least one ML-DSA co-signer is required',
            self::thrown(fn() => PqThreshold::hybridThresholdAssemble($a, $k31, $agg, 1, 1, [])));
        $this->assertSame('InvalidArgumentException: hybridThresholdAssemble: FROST group public key must be 32 bytes',
            self::thrown(fn() => PqThreshold::hybridThresholdAssemble($a, $k31, $agg, 1, 1, [$w])));
        $this->assertSame('InvalidArgumentException: hybridThresholdAssemble: the FROST aggregate does not verify under the group key',
            self::thrown(fn() => PqThreshold::hybridThresholdAssemble($a, $k32, $agg, 1, 1, [$w])));
    }

    /** Only the first MAX_PQ_QUORUM_ENTRIES entries are read: a valid co-signature right after them counts for nothing. */
    public function testEntryCap(): void
    {
        if (!Mldsa::available()) {
            if (getenv('PCA_REQUIRE_MLDSA') === '1') {
                $this->fail('PCA_REQUIRE_MLDSA=1 but ML-DSA-65 (OpenSSL >= 3.5 libcrypto via FFI) is not available');
            }
            $this->markTestSkipped('ML-DSA-65 unavailable');
        }
        $kp = new PqKeyPair('ML-DSA-65', hash('sha256', 'atlas-pca-conformance/g33-pq-quorum', true));
        $block = PqThreshold::signPqQuorum('m', [$kp]);
        $valid = $block['signers'][0];
        $pool = PqThreshold::normalizePqQuorumPool([$kp->public]);
        $junk = array_fill(0, PqThreshold::MAX_PQ_QUORUM_ENTRIES - 1, ['pk' => 'x', 'sig' => 'y']);
        $at = static fn(array $signers): array => PqThreshold::verifyPqQuorum(['v' => 2, 'alg' => 'ml-dsa-65', 'signers' => $signers], 'm', $pool, 1);
        $this->assertTrue($at([...$junk, $valid])['ok'], 'control: the last entry inside the cap counts');
        $over = $at([...$junk, ['pk' => 'x', 'sig' => 'y'], $valid]);
        $this->assertFalse($over['ok']);
        $this->assertSame(0, $over['count']);
    }
}
