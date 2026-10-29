<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The shared native-parity conformance vectors (packages/pca/conformance), one test per family: decision (rules 20 / 21 and
 * the ternary decision), escalation answers (every suite), the caveat language v2, model rules end to end through authorize(), the signed passport (stub
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

    public function testCaveatLanguageVectors(): void
    {
        $this->replay('caveat-lang', 280);
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

    public function testK3ArtifactVectors(): void
    {
        $this->replay('k3', 126);
    }

    public function testFreshAtMemberVectors(): void
    {
        $this->replay('fresh-at', 28);
    }

    public function testPcaGrantVectors(): void
    {
        $this->replay('pca-grant', 68);
    }

    public function testBlueprintVectors(): void
    {
        $this->replay('blueprint', 54);
    }

    public function testRuntimeClaimVectors(): void
    {
        $this->replay('runtime-claim', 11);
    }

    public function testA2aVectors(): void
    {
        $this->replay('a2a', 89);
    }

    public function testWorkflowVectors(): void
    {
        $this->replay('workflow', 113);
    }

    public function testReadsideVectors(): void
    {
        $this->replay('readside', 57);
    }

    public function testVaultAggregateVectors(): void
    {
        $this->replay('vault-aggregate', 56);
    }

    public function testAuthorizeWorkflowVectors(): void
    {
        $this->replay('authorize-workflow', 20);
    }

    public function testLeaseVectors(): void
    {
        $this->replay('lease', 75);
    }

    public function testObligationsVectors(): void
    {
        $this->replay('obligations', 53);
    }

    public function testBreakGlassVectors(): void
    {
        $this->replay('break-glass', 73);
    }

    public function testMissingContextVectors(): void
    {
        $this->replay('missing-context', 34);
    }

    public function testPolicyClassesVectors(): void
    {
        $this->replay('policy-classes', 20);
    }

    public function testProvenanceVectors(): void
    {
        $this->replay('provenance', 97);
    }

    public function testSigstoreVectors(): void
    {
        $this->replay('sigstore', 40);
    }

    /** Provenance by default: tokens, leaves, read_only, decisions (full equality), the pin and a recorder bundle byte for byte. */
    public function testArgProvenanceVectors(): void
    {
        $this->replay('arg-provenance', 75);
    }

    /** Undo windows: compensation, token (sign, encode, digest, every check), receipts, chains, transitions, window, obligation. */
    public function testUndoVectors(): void
    {
        $this->replay('undo', 81);
    }
}
