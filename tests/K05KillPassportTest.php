<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Passport;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Exact-outcome kill tests of Passport::verify over passports this package signs (fixed seeds): boundaries, detail strings, hardware branch. */
final class K05KillPassportTest extends TestCase
{
    private const T = 1800000000000;

    private static function issuer(): KeyPair
    {
        return new KeyPair(str_repeat("\x01", 32));
    }

    private static function sub(): string
    {
        return (new KeyPair(str_repeat("\x02", 32)))->public;
    }

    private static function signed(bool $hw = false, mixed $evidence = null): Obj
    {
        $pp = Sign::issuePassport(['model_id' => 'm', 'operator' => 'op', 'hardware_rooted' => $hw]);
        return Sign::signPassport($pp, self::issuer(), self::sub(), self::T + 60000, self::T, null, $evidence);
    }

    private static function opts(array $over = []): array
    {
        return $over + ['trustedIssuers' => [self::issuer()->public], 'now' => self::T, 'revocation' => static fn() => false];
    }

    private static function hw(int $at): Obj
    {
        return self::signed(true, ['document' => ['nonce' => 'n1'], 'at' => $at]);
    }

    public function testSoftwarePassportAndFloatNow(): void
    {
        $this->assertTrue(Passport::verify(self::signed(), self::opts())['ok']);
        $this->assertTrue(Passport::verify(self::signed(), self::opts(['now' => (float)self::T]))['ok']);
        $this->assertSame(['holderPub' => 's', 'grantRef' => 'passport:i', 'epoch' => 0, 'nonce' => 'n'], Passport::evidenceBinding('i', 's', 'n'));
    }

    public function testTimesAndDetails(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'malformed'], Passport::verify('x', self::opts()));
        $noIat = self::signed()->without('iat');
        $this->assertSame(['ok' => false, 'reason' => 'malformed', 'detail' => 'times'], Passport::verify($noIat, self::opts(['trustedIssuers' => []])));
        $eq = self::signed()->without('exp');
        $eq->set('exp', new Num((string)self::T));
        $this->assertSame(['ok' => false, 'reason' => 'malformed', 'detail' => 'times'], Passport::verify($eq, self::opts(['trustedIssuers' => []])));
        // 2^53-1 is still a safe integer
        $this->assertSame(['ok' => false, 'reason' => 'unknown_issuer'], Passport::verify(self::signed(), self::opts(['trustedIssuers' => [], 'now' => 9007199254740991])));
        $arr = self::signed()->without('passport');
        $arr->set('passport', ['id' => 'x', 'model_id' => 'm', 'operator' => 'op', 'hardware_rooted' => false]);
        $this->assertSame(['ok' => false, 'reason' => 'malformed'], Passport::verify($arr, self::opts(['trustedIssuers' => []])));
        // a non-numeric skew is no skew
        $this->assertSame(['ok' => false, 'reason' => 'expired'], Passport::verify(self::signed(), self::opts(['now' => self::T + 60000, 'clockSkewMs' => 'x'])));
    }

    public function testEvidenceAgeBoundaries(): void
    {
        $missing = ['ok' => false, 'reason' => 'hardware_verifier_missing'];
        $stale = ['ok' => false, 'reason' => 'hardware_evidence_stale'];
        $this->assertSame($missing, Passport::verify(self::hw(self::T - 86400000), self::opts()));
        $this->assertSame($stale, Passport::verify(self::hw(self::T - 86400001), self::opts()));
        $this->assertSame($missing, Passport::verify(self::hw(self::T), self::opts()));
        $this->assertSame($missing, Passport::verify(self::hw(self::T), self::opts(['maxEvidenceAgeMs' => 0])));
        $this->assertSame($stale, Passport::verify(self::hw(self::T), self::opts(['maxEvidenceAgeMs' => 'x'])));
        $this->assertSame($stale, Passport::verify(self::hw(self::T), self::opts(['maxEvidenceAgeMs' => -1])));
    }

    public function testAttestCallable(): void
    {
        $doc = self::hw(self::T);
        $cap = null;
        $measured = ['model_id' => 'm', 'operator' => 'op'];
        $r = Passport::verify($doc, self::opts(['attest' => static function (Obj $d, array $e) use (&$cap, $measured): Obj {
            $cap = $e;
            return Obj::of(['ok' => true, 'bound' => true, 'measured' => Obj::of($measured)]);
        }]));
        $this->assertTrue($r['ok']);
        $this->assertTrue($r['hardware_verified']);
        $id = $doc->get('passport')->get('id');
        $this->assertSame(['holderPub' => self::sub(), 'grantRef' => 'passport:' . $id, 'epoch' => 0, 'nonce' => 'n1', 'nonceIssuedAt' => self::T], $cap);
        $this->assertTrue(Passport::verify($doc, self::opts(['attest' => static fn() => ['ok' => true, 'bound' => true, 'measured' => $measured]]))['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'hardware_attestation_failed', 'detail' => 'nope'],
            Passport::verify($doc, self::opts(['attest' => static fn() => ['ok' => false, 'reason' => 'nope']])));
        $this->assertSame(['ok' => false, 'reason' => 'hardware_attestation_failed'],
            Passport::verify($doc, self::opts(['attest' => static fn() => ['ok' => false, 'reason' => '']])));
    }
}
