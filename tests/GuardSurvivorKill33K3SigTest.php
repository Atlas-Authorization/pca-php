<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/K3Sig.php';

use Atlas\Pca\K3Sig;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/K3Sig.php: a body that cannot be canonicalized fails verification closed. */
final class GuardSurvivorKill33K3SigTest extends TestCase
{
    /** A body the canonical form refuses (a non-finite number) is not verified, never accepted. */
    public function testUncanonicalizableBodyIsRefused(): void
    {
        $kp = new KeyPair(hash('sha256', 'atlas-pca-conformance/g33-k3sig', true));
        $body = Obj::of(['a' => 'b']);
        $sig = Pca::b64u($kp->sign('dom' . Json::canonicalizeNative($body)));
        $this->assertTrue(K3Sig::verifyBody('dom', $body, $kp->public, $sig), 'control');
        $this->assertFalse(K3Sig::verifyBody('dom', NAN, $kp->public, $sig));
        $this->assertFalse(K3Sig::verifyBody('dom', NAN, $kp->public, Pca::b64u(str_repeat("\0", 64))));
    }
}
