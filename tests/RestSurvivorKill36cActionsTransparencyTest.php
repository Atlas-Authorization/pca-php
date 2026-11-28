<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsTransparency.php';

use Atlas\Pca\ActionsTransparency;
use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\JsonError;
use Atlas\Pca\Obj;
use Atlas\Pca\TransparencyService;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/ActionsTransparency.php: a pack without ns is refused, and an entry that cannot be checked is not proof. */
final class RestSurvivorKill36cActionsTransparencyTest extends TestCase
{
    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/rest36c/' . $label, true);
    }

    private static function pub(string $label): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed($label)));
    }

    private static function pack(): Obj
    {
        return Obj::of(['ns' => 'acme', 'version' => '1.0.0', 'root' => 'r', 'prev' => null]);
    }

    /** A pack without ns cannot be canonicalized: refused before anything is signed. */
    public function testPackWithoutNsRefused(): void
    {
        $p = self::pack()->without('ns');
        $svc = new TransparencyService(['alg' => 'EdDSA', 'key' => self::seed('log'), 'issuer' => 'ts']);
        $this->expectException(JsonError::class);
        $this->expectExceptionMessage('canonicalize: unsupported type undefined');
        ActionsTransparency::appendPackToLog($p, $svc, ['alg' => 'EdDSA', 'key' => self::seed('reg'), 'issuer' => 'reg']);
    }

    /** A valid entry checked against a pack whose payload cannot be built is not proof (fail closed, false). */
    public function testUncheckablePackIsNotProof(): void
    {
        $svc = new TransparencyService(['alg' => 'EdDSA', 'key' => self::seed('log'), 'issuer' => 'ts']);
        $e = ActionsTransparency::appendPackToLog(self::pack(), $svc, ['alg' => 'EdDSA', 'key' => self::seed('reg'), 'issuer' => 'reg']);
        $entry = ['statement' => $e['statement'], 'receipt' => $e['receipt']];
        $keys = ['log' => self::pub('log'), 'registry' => self::pub('reg')];
        $this->assertTrue(ActionsTransparency::verifyPackLogEntry(self::pack(), $entry, $keys), 'control');
        $bad = self::pack();
        $bad->set('root', AnalyzerJs::undef());
        $this->assertFalse(ActionsTransparency::verifyPackLogEntry($bad, $entry, $keys));
    }
}
