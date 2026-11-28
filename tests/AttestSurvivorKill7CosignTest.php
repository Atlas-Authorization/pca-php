<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestCosign.php';

use Atlas\Pca\AttestCosign;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\TestCase;

/** The post-quantum co-signature of a verdict: the verdict projection, the suite refusal text, and the clock / age gates of verify. */
final class AttestSurvivorKill7CosignTest extends TestCase
{
    private const BAD_SIG = 'post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)';

    private static function cosigned(mixed $at): Obj
    {
        return Obj::of(['verdict' => Obj::of(['tier' => 't', 'trustworthy' => true]), 'cosig' => Obj::of(['cosignedAt' => $at, 'sig' => 'AAAA']),
            'suite' => 'ml-dsa-65', 'signer_pub' => Obj::of(['pq' => 'AAAA'])]);
    }

    /** An absent tier / trustworthy is projected as null (not undefined). */
    public function testAbsentResultFieldsBecomeNull(): void
    {
        $v = AttestCosign::verdictFromAppraisal(new Obj(), new Obj());
        $this->assertTrue($v->has('tier'));
        $this->assertNull($v->get('tier'));
        $this->assertNull($v->get('trustworthy'));
        $this->assertFalse($v->has('measurement'));
    }

    /** A non-empty string runtime_measurement is the verdict's measurement; a non-empty list one hides the SEV-SNP measurement without being one. */
    public function testRuntimeMeasurementWins(): void
    {
        $claims = Obj::of(['measured' => Obj::of(['runtime_measurement' => 'rm1']), 'sevsnp' => Obj::of(['measurement' => 'snp'])]);
        $this->assertSame('rm1', AttestCosign::verdictFromAppraisal(new Obj(), $claims)->get('measurement'));
        $claims = Obj::of(['measured' => Obj::of(['runtime_measurement' => ['x']]), 'sevsnp' => Obj::of(['measurement' => 'snp'])]);
        $this->assertFalse(AttestCosign::verdictFromAppraisal(new Obj(), $claims)->has('measurement'));
        $claims = Obj::of(['measured' => Obj::of(['runtime_measurement' => []]), 'sevsnp' => Obj::of(['measurement' => 'snp'])]);
        $this->assertSame('snp', AttestCosign::verdictFromAppraisal(new Obj(), $claims)->get('measurement')); // control: an empty list does not count
    }

    /** A classical suite is refused with its name in the message. */
    public function testClassicalSuiteIsRefusedByName(): void
    {
        try {
            AttestCosign::coSign(new Obj(), Obj::of(['suite' => 'ed25519']));
            $this->fail('no throw');
        } catch (\RangeException $e) {
            $this->assertSame('coSignAttestation: ed25519 is not an accepted post-quantum co-sign suite', $e->getMessage());
        }
    }

    /** The age is reported as a native int; with no maxAgeMs the signature decides. */
    public function testAgeIsAnIntAndTheSignatureDecides(): void
    {
        $r = AttestCosign::verify(self::cosigned(1000), Obj::of(['now' => 2000]));
        $this->assertFalse($r->get('ok'));
        $this->assertSame(self::BAD_SIG, $r->get('reason'));
        $this->assertSame(1000, $r->get('ageMs'));
    }

    /** maxAgeMs must be finite; a co-signature exactly at now is not in the future. */
    public function testAgeGateBounds(): void
    {
        $this->assertSame('invalid maxAgeMs', AttestCosign::verify(self::cosigned(1000), Obj::of(['now' => 2000, 'maxAgeMs' => INF]))->get('reason'));
        $this->assertSame(self::BAD_SIG, AttestCosign::verify(self::cosigned(1000), Obj::of(['now' => 1000, 'maxAgeMs' => 10]))->get('reason'));
    }

    /** Without `now` the wall clock in ms is used: a co-signature from a second ago is neither future nor stale under a 10-minute window. */
    public function testDefaultClockIsWallMilliseconds(): void
    {
        $at = (int)(microtime(true) * 1000) - 1000;
        $r = AttestCosign::verify(self::cosigned($at), Obj::of(['maxAgeMs' => 600000]));
        $this->assertSame(self::BAD_SIG, $r->get('reason'));
        $this->assertGreaterThanOrEqual(1000, $r->get('ageMs'));
        $this->assertLessThan(600000, $r->get('ageMs'));
    }

    /** coSign without `now` stamps the wall clock as integer milliseconds, and the result verifies. */
    public function testCoSignStampsIntegerWallMilliseconds(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $pq = new PqKeyPair('ML-DSA-65', hash('sha256', 'atlas-pca-conformance/kill7-cosign', true));
        $before = (int)(microtime(true) * 1000);
        $c = AttestCosign::coSign(Obj::of(['tier' => 't', 'trustworthy' => true]), Obj::of(['pq' => $pq]));
        $at = $c->get('cosig')->get('cosignedAt');
        $this->assertIsInt($at);
        $this->assertGreaterThanOrEqual($before, $at);
        $this->assertLessThan($before + 60000, $at);
        $this->assertTrue(AttestCosign::verify($c, Obj::of(['expectedSigner' => $pq->public]))->get('ok'));
    }
}
