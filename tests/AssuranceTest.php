<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\AssuranceLabeler;
use Atlas\Pca\AssuranceRequirement;
use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\ClaimResult;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Assurance labels (T8, B7): replays assurance-vectors.json (signature_level, report, requirement, multi_root), then the label
 * mechanism and the `assurance` check of Authorize. A missing vector file fails the test.
 */
final class AssuranceTest extends TestCase
{
    public function testVectors(): void
    {
        [$n, $fails] = NativeParityVectors::assurance();
        $this->assertSame([], $fails);
        $this->assertSame(105, $n);
    }

    public function testLabelMechanismAndUnlabelledHooks(): void
    {
        $closure = static fn () => true;
        $this->assertNull(Assurance::labelOf($closure));
        Assurance::setLabel($closure, new AssuranceLabel('hardware', 'amd-sev-snp'));
        $this->assertSame('hardware', Assurance::labelOf($closure)->level);
        $own = new class implements AssuranceLabeler {
            public function assurance(): AssuranceLabel
            {
                return new AssuranceLabel('groth16', ceremony: 'multi-party');
            }
        };
        $r = Assurance::report(['attestation' => 'pass', 'zk_compliance' => 'pass'], null, ['zk' => $own], $closure);
        $this->assertSame(['outcome' => 'pass', 'level' => 'hardware', 'vendor' => 'amd-sev-snp'], $r['attestation']);
        $this->assertSame(['outcome' => 'pass', 'level' => 'groth16', 'ceremony' => 'multi-party'], $r['zk_compliance']);
        // an unlabelled hook is unknown and satisfies nothing
        $r = Assurance::report(['attestation' => 'pass'], null, ['attestation' => new \stdClass()]);
        $this->assertSame('unknown', $r['attestation']['level']);
        $this->assertSame('assurance: software attestation required but the evidence is unknown',
            Assurance::unmet($r, new AssuranceRequirement(attestation: 'software')));
        // a failed or absent check never meets a requirement; an unsupported feature is refused whatever else holds
        $this->assertSame('assurance: hardware attestation required but there is no attestation evidence',
            Assurance::unmet([], new AssuranceRequirement(attestation: 'hardware')));
        $r = Assurance::report(['replay' => 'pass'], Obj::of(['bond_ref' => 'x']));
        $this->assertStringStartsWith('assurance: unsupported: bond (bond verification is not implemented by this verifier)',
            (string)Assurance::unmet($r, new AssuranceRequirement()));
    }

    // ---- Authorize wiring

    private function authorizeWith(?AssuranceRequirement $req, object $store, ?array $hooks = null): AuthorizeResult
    {
        $fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $c = $fix->get('cases')[0];
        $s = $c->get('steps')[0];
        return Authorize::authorize($s->get('pcactn'), $s->get('operation'), $fix->get('audience'), fn ($r) => $c->get('grant'), $store,
            fn ($p, $g) => false, $fix->get('now')->int(), 'single-step', null, null, null, null, [], null, null, null, null, null, null, null,
            $req, $hooks);
    }

    public function testEveryResultCarriesTheReportAndEmptyRequirementAllows(): void
    {
        $r = $this->authorizeWith(null, new MemoryStateStore());
        $this->assertTrue($r->allow, (string)$r->reason);
        $this->assertSame('pass', $r->assurance['leaf_signature']['outcome']);
        $this->assertSame('ed25519', $r->assurance['leaf_signature']['level']);
        $this->assertArrayHasKey('cap_chain', $r->assurance, 'the chain check is reported under the reference name');
        $this->assertArrayNotHasKey('chain', $r->assurance);
        $this->assertTrue($this->authorizeWith(new AssuranceRequirement(), new MemoryStateStore())->allow);
    }

    public function testUnmetRequirementDeniesBeforeReplayStateIsWritten(): void
    {
        $store = new class extends \stdClass {
            public int $claims = 0;
            public function claim(string $k, int $n): ClaimResult
            {
                $this->claims++;
                return new ClaimResult(true);
            }
        };
        $r = $this->authorizeWith(new AssuranceRequirement(signature: 'pq'), $store);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['assurance']);
        $this->assertSame('assurance: post-quantum signatures required but leaf_signature is ed25519', $r->reason);
        $this->assertSame(0, $store->claims, 'a denied request never claims the counter');
        $this->assertSame('pass', $r->assurance['leaf_signature']['outcome'], 'the report is on the denial too');
        // attestation required but no attestation hook enforced it
        $r = $this->authorizeWith(new AssuranceRequirement(attestation: 'hardware'), new MemoryStateStore());
        $this->assertFalse($r->allow);
        $this->assertStringContainsString('hardware attestation required but', $r->reason);
    }

    public function testRefusalBeforeVerificationReportsTheFailedCheck(): void
    {
        $r = Authorize::authorize(null, null, 'aud', null, null, null);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', array_values($r->assurance)[0]['outcome']);
    }
}
