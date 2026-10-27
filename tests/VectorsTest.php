<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The shared native-parity conformance vectors (packages/pca/conformance), one test per family: decision (rules 20 / 21 and
 * the ternary decision), escalation answers (every suite), model rules end to end through authorize(), the signed passport (stub
 * hardware rows and, from the reference's generated table, the real vendor verifiers), the vendor attestation evidence and strict
 * X.509 readers, and the Track 3 families (intent state, ledger, optimistic, mesh). A missing vector file FAILS (never skips).
 */
final class VectorsTest extends TestCase
{
    /** @param int $min the smallest acceptable number of vectors replayed */
    private function replay(string $family, int $min): void
    {
        [$n, $fails] = Vectors::run($family);
        $this->assertSame([], array_slice($fails, 0, 20), "$family: " . count($fails) . ' failure(s) of ' . $n);
        $this->assertGreaterThanOrEqual($min, $n, "$family ran too few vectors");
    }

    public function testDecisionVectors(): void
    {
        $this->replay('decision', 243);
    }

    public function testEscalationAnswerVectors(): void
    {
        $this->replay('escalation', 85);
    }

    public function testModelRulesVectors(): void
    {
        $this->replay('model-rules', 32);
    }

    public function testPassportVectors(): void
    {
        $this->replay('passport', 74);
    }

    public function testPassportHardwareVectors(): void
    {
        $this->replay('passport-hardware', 40);
    }

    public function testAttestationEvidenceVectors(): void
    {
        $this->replay('attestation', 1000);
    }

    public function testIntentStateVectors(): void
    {
        $this->replay('intent-state', 2500); // a runtime without the post-quantum suites skips the cases that name one
    }

    public function testLedgerVectors(): void
    {
        $this->replay('ledger', 365);
    }

    public function testOptimisticVectors(): void
    {
        $this->replay('optimistic', 176);
    }

    public function testMeshVectors(): void
    {
        $this->replay('mesh', 133);
    }
}
