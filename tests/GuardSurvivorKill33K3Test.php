<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/K3.php';

use Atlas\Pca\Json;
use Atlas\Pca\K3;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/K3.php: reason rendering of plain numbers, the rollback reason text, the spread check of authorityDigest and amendMessage's refusal. */
final class GuardSurvivorKill33K3Test extends TestCase
{
    /** A plain PHP int or float expected sequence renders as its JS number text. */
    public function testPlainNumbersRender(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'gap or replay: batch starts at x, expected 5'], K3::verifyBatch(Obj::of(['from' => 'x']), Obj::of(['next' => 5]), null));
        $this->assertSame(['ok' => false, 'reason' => 'gap or replay: batch starts at x, expected 1.5'], K3::verifyBatch(Obj::of(['from' => 'x']), Obj::of(['next' => 1.5]), null));
    }

    /** A pinned last revision that is not a number is a rollback whose reason shows that value. */
    public function testRollbackReasonShowsTheAcceptedValue(): void
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca-conformance/g33-k3', true));
        $pk = Pca::b64u(sodium_crypto_sign_publickey($kp));
        $b = Obj::of(['v' => new Num('1'), 'kind' => 'pca-policy-bundle', 'revision' => new Num('1'), 'issued_at' => new Num('100'),
            'grants' => ['g'], 'template_digests' => [], 'min_verifier_version' => '1.0']);
        $b->set('sigs', [Obj::of(['signer' => $pk, 'sig' => Pca::b64u(sodium_crypto_sign_detached(K3::BUNDLE_DOMAIN . Json::canonicalizeStrict($b), sodium_crypto_sign_secretkey($kp)))])]);
        $o = ['signers' => [$pk], 'threshold' => new Num('1'), 'verifierVersion' => '1.0'];
        $this->assertTrue(K3::verifyBundle($b, Obj::of($o))['ok'], 'control');
        $this->assertSame(['ok' => false, 'code' => 'rollback', 'reason' => 'revision 1 < accepted x'],
            K3::verifyBundle($b, Obj::of($o + ['last' => Obj::of(['revision' => 'x', 'digest' => 'd'])])));
    }

    /** Both verbs and resources must be present and iterable: either missing has no digest, and amendMessage then refuses. */
    public function testAuthorityNeedsVerbsAndResources(): void
    {
        $this->assertIsString(K3::authorityDigest(Obj::of(['verbs' => ['v'], 'resources' => ['r']])), 'control');
        $this->assertNull(K3::authorityDigest(Obj::of(['resources' => ['r']])));
        $this->assertNull(K3::authorityDigest(Obj::of(['verbs' => ['v']])));
        try {
            K3::amendMessage(Obj::of(['id' => 'g', 'rev' => new Num('1')]), 'add', Obj::of(['resources' => ['r']]));
            $this->fail('an amendment message was built without an authority digest');
        } catch (\RuntimeException $e) {
            $this->assertSame('authority digest', $e->getMessage());
        }
    }
}
