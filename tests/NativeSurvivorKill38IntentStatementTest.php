<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentStatement;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Mldsa;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Survivor kills for PQ-suite intent statements: a real ML-DSA-65 signature under a pinned key (needs OpenSSL >= 3.5). */
final class NativeSurvivorKill38IntentStatementTest extends TestCase
{
    protected function setUp(): void
    {
        if (!Mldsa::available()) {
            if (getenv('PCA_REQUIRE_MLDSA') === '1') {
                $this->fail('ML-DSA unavailable');
            }
            $this->markTestSkipped('ML-DSA-65 unavailable');
        }
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    private static function copy(Obj $s, array $kv = [], array $drop = []): Obj
    {
        $o = new Obj();
        foreach ($s->keys() as $k) {
            if (!in_array($k, $drop, true)) {
                $o->set($k, $s->get($k));
            }
        }
        foreach ($kv as $k => $v) {
            $o->set($k, $v);
        }
        return $o;
    }

    /**
     * A statement signed under `$alg` the way the reference binds it: the body plus `alg` and `pq_pk`, signed over the intent domain.
     * @return array{0:Obj,1:string,2:string} [statement, principal, pq_pk]
     */
    private static function pqStatement(string $alg): array
    {
        $edSeed = self::seed('intent-38n/ed25519');
        $ed = new KeyPair($edSeed);
        $pq = new PqKeyPair('ML-DSA-65', self::seed('intent-38n/ml-dsa-65'));
        $plain = IntentStatement::signIntent(Obj::of(['v' => 1, 'text' => 'pay the invoice', 'slots' => Obj::of(['amount' => 5]),
            'sources' => [], 'created_at' => 7, 'nonce' => 'n-38n']), $edSeed);
        $bound = self::copy(IntentStatement::statementBody($plain), ['alg' => $alg, 'pq_pk' => $pq->public]);
        $parts = Sign::signWithSuite($alg, $ed, $pq, IntentStatement::SIG_DOMAIN . Json::canonicalizeNative($bound));
        return [self::copy($bound, $parts), $ed->public, $pq->public];
    }

    private static function pins(string $principal, mixed $pin): Obj
    {
        $p = new Obj();
        $p->set($principal, $pin);
        return Obj::of(['pqPins' => $p]);
    }

    /** A pure ML-DSA-65 statement verifies under its pinned key, and only there: no pin, a different pin or a non-string pin is a bad signature. */
    public function testPureMlDsaStatementVerifiesOnlyUnderItsPin(): void
    {
        [$s, $principal, $pk] = self::pqStatement('ml-dsa-65');
        $this->assertSame(['ok' => true], IntentStatement::verifyIntent($s, self::pins($principal, $pk)));
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], IntentStatement::verifyIntent($s));
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], IntentStatement::verifyIntent($s, self::pins($principal, $pk . 'A')));
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], IntentStatement::verifyIntent($s, self::pins($principal, 5)));
        $other = new Obj();
        $other->set(str_repeat('A', 43), $pk);
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], IntentStatement::verifyIntent($s, Obj::of(['pqPins' => $other])));
    }

    /** The PQ signature covers the statement body: an edited text no longer verifies under the same pin. */
    public function testPqSignatureCoversTheBody(): void
    {
        [$s, $principal, $pk] = self::pqStatement('ml-dsa-65');
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'],
            IntentStatement::verifyIntent(self::copy($s, ['text' => 'pay the invoice twice']), self::pins($principal, $pk)));
    }

    /** A hybrid statement verifies with both halves under its pin; without its pq_sig it is a bad signature. */
    public function testHybridStatementNeedsItsPqSignature(): void
    {
        [$s, $principal, $pk] = self::pqStatement('hybrid-ed25519-ml-dsa-65');
        $this->assertTrue($s->has('pq_sig'));
        $this->assertSame(['ok' => true], IntentStatement::verifyIntent($s, self::pins($principal, $pk)));
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'],
            IntentStatement::verifyIntent(self::copy($s, [], ['pq_sig']), self::pins($principal, $pk)));
    }
}
