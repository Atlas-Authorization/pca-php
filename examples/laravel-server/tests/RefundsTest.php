<?php

namespace Tests;

use App\Guard;
use Atlas\Pca\ArgProvenance;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Pca;
use Atlas\Pca\ProvenanceRecorder;
use Atlas\Pca\Protect;
use Illuminate\Foundation\Testing\TestCase;

final class RefundsTest extends TestCase
{
    public function createApplication()
    {
        $app = require __DIR__ . '/../bootstrap/app.php';
        $app->make(\Illuminate\Contracts\Console\Kernel::class)->bootstrap();
        return $app;
    }

    /** @return array{0:string,1:array<string,mixed>} the PCA-Action header and the JSON body of the signed call */
    private function proof(): array
    {
        $raw = file_get_contents(__DIR__ . '/proof.json');
        $plain = json_decode($raw, true);
        // the proof was signed at a fixed time: pin the guard's clock to it
        $this->app->instance(Protect::class, Guard::protect(['audience' => $plain['audience'], 'clock' => fn () => $plain['now']]));
        return [Pca::b64u(Json::canonicalizeStrict(Json::parseLax($raw)->get('pcactn'))), $plain['body']];
    }

    /** The PCA-Provenance header the refunds UI presents: the user typed this refund, no model in between (key pinned in mediators.json). */
    private function provenance(array $body): string
    {
        $recorder = new ProvenanceRecorder('refunds-ui', 'k1', new KeyPair(str_repeat("\x02", 32)));
        $bundle = ArgProvenance::principalDirect($recorder, ['verb' => 'payments.send', 'resource' => 'payments/' . $body['account'],
            'params' => ['amount' => $body['amount'], 'currency' => $body['currency']]]);
        return Pca::b64u(Json::canonicalizeStrict($bundle));
    }

    public function testAllowsTheSignedRefundThenRefusesTheReplayWithADocLink(): void
    {
        [$header, $body] = $this->proof();
        $prov = $this->provenance($body);
        $first = $this->withHeaders(['PCA-Action' => $header, 'PCA-Provenance' => $prov])->postJson('/refunds', $body);
        $this->assertSame(201, $first->getStatusCode(), (string) $first->getContent()); // the body names the refusing check
        $first->assertJson(['refunded' => true, 'amount' => 50]);

        $r = $this->withHeaders(['PCA-Action' => $header, 'PCA-Provenance' => $prov])->postJson('/refunds', $body);
        $r->assertStatus(403);
        $this->assertStringContainsString('/docs/reference/refusals.md', $r->json('doc'));
    }

    public function testRefusesACallWithoutAProofOrWithAnotherOperation(): void
    {
        [$header, $body] = $this->proof();
        $this->postJson('/refunds', $body)->assertStatus(401)->assertJsonStructure(['error', 'doc']);

        $body['amount'] = 51; // not the amount that was signed
        $r = $this->withHeaders(['PCA-Action' => $header])->postJson('/refunds', $body);
        $r->assertStatus(403);
        $this->assertNotEmpty($r->json('doc'));
    }

    public function testASignedRefundWithoutProvenanceEscalates(): void
    {
        [$header, $body] = $this->proof();
        $r = $this->withHeaders(['PCA-Action' => $header])->postJson('/refunds', $body);
        $r->assertStatus(403);
        $this->assertSame('escalate', $r->json('decision'), (string) $r->getContent());
    }
}
