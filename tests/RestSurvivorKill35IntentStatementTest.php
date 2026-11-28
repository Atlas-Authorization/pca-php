<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentStatement;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Survivor kills for signed intent statements. */
final class RestSurvivorKill35IntentStatementTest extends TestCase
{
    private const SEED = "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09";

    private static function signed(): Obj
    {
        return IntentStatement::signIntent(Obj::of(['v' => 1, 'text' => 't', 'slots' => new Obj(), 'sources' => [], 'created_at' => 0, 'nonce' => 'n']), self::SEED);
    }

    private static function with(Obj $s, array $kv): Obj
    {
        $o = Obj::of([]);
        foreach ($s->keys() as $k) {
            $o->set($k, $s->get($k));
        }
        foreach ($kv as $k => $v) {
            $o->set($k, $v);
        }
        return $o;
    }

    /** statementBody is public and drops the signature. */
    public function testStatementBodyIsPublic(): void
    {
        $this->assertFalse(IntentStatement::statementBody(self::signed())->has('sig'));
    }

    /** Sources that are not a list, and a source that is not an object, are refused by shape. */
    public function testSourceShape(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'sources must be an array'], IntentStatement::verifyIntent(self::with(self::signed(), ['sources' => ['a' => 1]])));
        $this->assertSame(['ok' => false, 'reason' => 'sources[0] has an unknown kind'],
            IntentStatement::verifyIntent(self::with(self::signed(), ['sources' => [['kind' => 'ticket', 'digest' => str_repeat('A', 43)]]])));
    }

    /** Only Ed25519 is signed natively; an explicit ed25519 suite is accepted. */
    public function testSigningSuite(): void
    {
        $s = Obj::of(['v' => 1, 'text' => 't', 'slots' => new Obj(), 'sources' => [], 'created_at' => 0, 'nonce' => 'n']);
        $this->assertTrue(IntentStatement::verifyIntent(IntentStatement::signIntent($s, self::SEED, Obj::of(['alg' => 'ed25519'])))['ok']);
        $this->expectExceptionMessage('signIntentStatement: only Ed25519 signing is supported natively');
        IntentStatement::signIntent($s, self::SEED, Obj::of(['alg' => 'ml-dsa-65']));
    }

    /** A PQ-suite statement without pq_pk is malformed, with the reason. */
    public function testMissingPqKey(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'malformed intent statement: pq_pk is missing'],
            IntentStatement::verifyIntent(self::with(self::signed(), ['alg' => 'ml-dsa-65'])));
    }

    /** A hybrid statement is never accepted on its Ed25519 half alone (no pinned PQ key). */
    public function testHybridNeedsMoreThanEd25519(): void
    {
        $s = self::signed();
        $bound = self::with(IntentStatement::statementBody($s), ['alg' => 'hybrid-ed25519-ml-dsa-65', 'pq_pk' => 'x']);
        $kp = sodium_crypto_sign_seed_keypair(self::SEED);
        $sig = Pca::b64u(sodium_crypto_sign_detached(IntentStatement::SIG_DOMAIN . Json::canonicalizeNative($bound), sodium_crypto_sign_secretkey($kp)));
        $h = self::with($bound, ['sig' => $sig, 'pq_sig' => 'y']);
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], IntentStatement::verifyIntent($h));
    }
}
