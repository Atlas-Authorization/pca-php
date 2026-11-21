<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Passport;
use PHPUnit\Framework\TestCase;

/** Exact-outcome tests of the signed passport verifier over the `ok` document of the shared vectors: one reason code per check. */
final class PassportTest extends TestCase
{
    private Obj $row;

    protected function setUp(): void
    {
        foreach (Vectors::load('passport-vectors.json')->get('passport_vectors') as $r) {
            if ($r->get('name') === 'ok') {
                $this->row = $r;
            }
        }
    }

    /** @return array<string,mixed> */
    private function opts(array $over = []): array
    {
        return $over + ['trustedIssuers' => $this->row->get('trustedIssuers'), 'now' => 1800000000000, 'revocation' => static fn() => false];
    }

    private function signed(): Obj
    {
        return $this->row->get('signed');
    }

    /** A copy of the signed document with members replaced (the signature is then invalid unless the member is outside it). */
    private function with(array $set): Obj
    {
        $o = $this->signed()->without();
        foreach ($set as $k => $v) {
            $o->set($k, $v);
        }
        return $o;
    }

    public function testTheSignedDocumentVerifies(): void
    {
        $r = Passport::verify($this->signed(), $this->opts());
        $this->assertTrue($r['ok']);
        $this->assertFalse($r['hardware_verified']);
        $this->assertSame(1800000060000, $r['exp']);
    }

    public function testEveryRefusalHasItsOwnReasonCode(): void
    {
        $this->assertSame('malformed', Passport::verify('x', $this->opts())['reason']);
        $this->assertSame('malformed', Passport::verify($this->with(['typ' => 'other']), $this->opts())['reason']);
        $this->assertSame('unsupported_version', Passport::verify($this->with(['ver' => new Num('2')]), $this->opts())['reason']);
        $this->assertSame('unsupported_suite', Passport::verify($this->with(['alg' => 'no-such-suite']), $this->opts())['reason']);
        $this->assertSame('malformed', Passport::verify($this->with(['sub' => '']), $this->opts())['reason']);
        $this->assertSame('malformed', Passport::verify($this->signed(), $this->opts(['now' => 1.5]))['reason']);
        $this->assertSame('unknown_issuer', Passport::verify($this->signed(), $this->opts(['trustedIssuers' => []]))['reason']);
        $this->assertSame('bad_signature', Passport::verify($this->with(['exp' => new Num('1800000070000')]), $this->opts())['reason']);
        $this->assertSame('not_yet_valid', Passport::verify($this->signed(), $this->opts(['now' => 1799999990000]))['reason']);
        $this->assertSame('expired', Passport::verify($this->signed(), $this->opts(['now' => 1800000060000]))['reason']);
        $this->assertSame('subject_mismatch', Passport::verify($this->signed(), $this->opts(['subject' => 'someone-else']))['reason']);
        $this->assertSame('revocation_unavailable', Passport::verify($this->signed(), ['trustedIssuers' => $this->row->get('trustedIssuers'), 'now' => 1800000000000])['reason']);
        $this->assertSame('revocation_unavailable', Passport::verify($this->signed(), $this->opts(['revocation' => static function () {
            throw new \RuntimeException('down');
        }]))['reason']);
        $this->assertSame('revoked', Passport::verify($this->signed(), $this->opts(['revocation' => static fn() => true]))['reason']);
    }

    public function testTheExpiryAndNotBeforeBoundariesAreExactWithSkew(): void
    {
        $this->assertTrue(Passport::verify($this->signed(), $this->opts(['now' => 1800000059999]))['ok']);
        $this->assertTrue(Passport::verify($this->signed(), $this->opts(['now' => 1800000060000, 'clockSkewMs' => 1]))['ok']);
        $this->assertSame('expired', Passport::verify($this->signed(), $this->opts(['now' => 1800000061000, 'clockSkewMs' => 1000]))['reason']);
        // the skew is capped at 60 s: a huge one still refuses an instant two minutes past expiry
        $this->assertSame('expired', Passport::verify($this->signed(), $this->opts(['now' => 1800000180000, 'clockSkewMs' => 999999999]))['reason']);
    }

    public function testAHardwareRootedPassportIsNeverDowngraded(): void
    {
        foreach (Vectors::load('passport-vectors.json')->get('passport_vectors') as $r) {
            if ($r->get('name') === 'hardware-rooted-evidence-no-verifier') {
                $o = ['trustedIssuers' => $r->get('trustedIssuers'), 'now' => 1800000000000, 'revocation' => static fn() => false];
                $this->assertSame('hardware_verifier_missing', Passport::verify($r->get('signed'), $o)['reason']);
                return;
            }
        }
        $this->fail('the hardware-rooted-evidence-no-verifier vector is missing');
    }

    public function testFingerprintIsContentAddressed(): void
    {
        $p = $this->signed()->get('passport');
        $this->assertSame($p->get('id'), Passport::fingerprint($p));
    }
}
