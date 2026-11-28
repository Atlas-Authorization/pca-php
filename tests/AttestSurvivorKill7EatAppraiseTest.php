<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestEat;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for AttestEat.php (group 7): the RATS appraisal edges (launch measurement from sevsnp, debug status, weights case),
 * EAT admission evidence with PHP-array options, and the runtime digest slot / measurement list handling.
 */
final class AttestSurvivorKill7EatAppraiseTest extends TestCase
{
    private const NOW = 1893456000000;

    private static function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        throw new \LogicException('nothing was thrown');
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/kill7-eat-issuer', true);
    }

    private static function instanceKey(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca-conformance/kill7-eat-instance', true))));
    }

    /** A signed EAT bound to the instance key's thumbprint, issued by iss-1 for nonce-1 at NOW. */
    private static function eat(): string
    {
        return AttestEat::buildEat(Obj::of(['issuer' => 'iss-1', 'nonce' => 'nonce-1', 'key' => self::seed(), 'now' => self::NOW,
            'channelBinding' => Obj::of(['jkt' => AttestEat::ed25519Jkt(self::instanceKey())])]));
    }

    /** @return array<string,mixed> */
    private static function admissionOpts(): array
    {
        return ['verifyKey' => sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed())), 'nonce' => 'nonce-1', 'now' => self::NOW,
            'instanceKey' => self::instanceKey(), 'policy' => Obj::of(['endorsements' => Obj::of(['issuers' => ['iss-1']])])];
    }

    // ---- appraise -------------------------------------------------------------------------------------------------------------------

    /** The launch measurement may come from the sevsnp evidence, compared case-insensitively. */
    public function testLaunchMeasurementFromSevsnp(): void
    {
        $ev = Obj::of(['sevsnp' => Obj::of(['measurement' => 'ABCD'])]);
        $r = AttestEat::appraise($ev, Obj::of(['measurements' => ['abcd']]), new Obj());
        $this->assertSame('affirming', $r->get('tier'));
        $this->assertTrue($r->get('trustworthy'));
        $this->assertSame(['launch measurement matches a reference value'], $r->get('reasons'));
        $r = AttestEat::appraise($ev, Obj::of(['measurements' => ['ffff']]), new Obj());
        $this->assertSame('contraindicated', $r->get('tier'));
        $this->assertSame(['launch measurement not in reference values'], $r->get('reasons'));
        $r = AttestEat::appraise(new Obj(), Obj::of(['measurements' => ['abcd']]), new Obj());
        $this->assertSame('rejected', $r->get('tier'));
    }

    /** A measurements claim that is not a list is a TypeError, whatever its shape (scalar, assoc array), with the exact text. */
    public function testNonListMeasurementsAreATypeError(): void
    {
        foreach ([5, ['x' => 1], 'abc'] as $bad) {
            $ev = Obj::of(['measurements' => $bad]);
            $e = self::thrown(fn() => AttestEat::appraise($ev, Obj::of(['measurements' => ['abcd']]), new Obj()));
            $this->assertInstanceOf(\TypeError::class, $e);
            $this->assertSame('eat.measurements?.find is not a function', $e->getMessage());
        }
        $ev = Obj::of(['measurements' => [Obj::of(['type' => 'launch', 'value' => 'ABCD'])]]);
        $this->assertSame('affirming', AttestEat::appraise($ev, Obj::of(['measurements' => ['abcd']]), new Obj())->get('tier'));
    }

    /** An unknown debug status string fails closed (unknown), it is never read as "not enabled". */
    public function testUnknownDebugStatusFailsClosed(): void
    {
        $rv = Obj::of(['requireDebugDisabled' => true]);
        $r = AttestEat::appraise(Obj::of(['dbgstat' => 'bogus']), $rv, new Obj());
        $this->assertSame('rejected', $r->get('tier'));
        $this->assertFalse($r->get('trustworthy'));
        $this->assertSame(["debug status unknown \u{2014} failing closed"], $r->get('reasons'));
        $r = AttestEat::appraise(Obj::of(['dbgstat' => 5]), $rv, new Obj());
        $this->assertSame('rejected', $r->get('tier'));
        $r = AttestEat::appraise(Obj::of(['dbgstat' => 'disabled']), $rv, new Obj());
        $this->assertSame('affirming', $r->get('tier'));
        $this->assertSame(['debug disabled'], $r->get('reasons'));
        $r = AttestEat::appraise(Obj::of(['dbgstat' => 'enabled']), $rv, new Obj());
        $this->assertSame('contraindicated', $r->get('tier'));
    }

    /** A weights measurement is compared case-insensitively against the reference list (both sides lowered). */
    public function testWeightsMeasurementIsCaseInsensitive(): void
    {
        $ev = Obj::of(['measured' => Obj::of(['weights_digest' => 'abcd'])]);
        $r = AttestEat::appraise($ev, Obj::of(['weightsMeasurements' => ['ABCD']]), new Obj());
        $this->assertSame('affirming', $r->get('tier'));
        $this->assertSame(['weights measurement matches a reference value'], $r->get('reasons'));
        $r = AttestEat::appraise($ev, Obj::of(['weightsMeasurements' => ['ABCE']]), new Obj());
        $this->assertSame('contraindicated', $r->get('tier'));
    }

    // ---- admission evidence ---------------------------------------------------------------------------------------------------------

    /** Admission accepts a verified, fresh, endorsed EAT bound to the instance key, with options given as a plain PHP array. */
    public function testAdmissionWithPhpArrayOptions(): void
    {
        $r = AttestEat::eatAdmissionEvidence(self::eat(), self::admissionOpts());
        $this->assertSame(['ok', 'bound'], $r->keys());
        $this->assertTrue($r->get('ok'));
        $this->assertTrue($r->get('bound'));
        $r = AttestEat::eatAdmissionEvidence(self::eat(), self::admissionOpts() + [0 => 'ignored', 7 => 'ignored']); // numeric keys are carried as text, not a TypeError
        $this->assertTrue($r->get('ok'), (string)$r->get('reason'));
        $this->assertTrue($r->get('bound'));
        $opts = self::admissionOpts();
        $opts['nonce'] = 'other';
        $r = AttestEat::eatAdmissionEvidence(self::eat(), $opts);
        $this->assertFalse($r->get('ok'));
        $this->assertFalse($r->get('bound'));
        $this->assertSame('eat_nonce does not match the server-issued challenge (replayed or relayed evidence)', $r->get('reason'));
    }

    /** The same admission through an Obj; an instance key that is not the bound one is refused with the thumbprint reason. */
    public function testAdmissionWithObjOptionsAndAWrongInstanceKey(): void
    {
        $o = Obj::of(self::admissionOpts());
        $this->assertTrue(AttestEat::eatAdmissionEvidence(self::eat(), $o)->get('ok'));
        $wrong = self::admissionOpts();
        $wrong['instanceKey'] = Pca::b64u(str_repeat("\x07", 32));
        $r = AttestEat::eatAdmissionEvidence(self::eat(), Obj::of($wrong));
        $this->assertFalse($r->get('ok'));
        $this->assertSame('holder-key thumbprint (cnf.jkt) mismatch', $r->get('reason'));
    }

    /** A missing policy is a TypeError before anything is verified (the reason is "TypeError", not the token's verdict). */
    public function testAdmissionWithoutAPolicyIsRefusedUpFront(): void
    {
        $r = AttestEat::eatAdmissionEvidence('not.a.token', Obj::of(['instanceKey' => self::instanceKey(), 'verifyKey' => 'k']));
        $this->assertSame(['ok', 'bound', 'reason'], $r->keys());
        $this->assertFalse($r->get('ok'));
        $this->assertFalse($r->get('bound'));
        $this->assertSame('TypeError', $r->get('reason'));
        $r = AttestEat::eatAdmissionEvidence('not.a.token', Obj::of(['instanceKey' => self::instanceKey(), 'minTier' => 'warning']));
        $this->assertSame('invalid minTier', $r->get('reason'));
    }

    // ---- runtime digest -------------------------------------------------------------------------------------------------------------

    private static function verdict(mixed $measurements): Obj
    {
        return Obj::of(['ok' => true, 'claims' => Obj::of(['measurements' => $measurements])]);
    }

    /** The slot option picks the measurement entry (default image); exactly one entry and a lowercase hex digest of the algorithm's length. */
    public function testRuntimeDigestSlotAndAlgorithm(): void
    {
        $hex64 = str_repeat('a', 64);
        $hex128 = str_repeat('b', 128);
        $v = self::verdict([Obj::of(['type' => 'custom', 'value' => $hex64]), Obj::of(['type' => 'image', 'value' => $hex128])]);
        $d = AttestEat::runtimeDigestFromEat($v, Obj::of(['slot' => 'custom']));
        $this->assertSame(['alg', 'digest'], $d->keys());
        $this->assertSame('sha256', $d->get('alg'));
        $this->assertSame($hex64, $d->get('digest'));
        $d = AttestEat::runtimeDigestFromEat($v, Obj::of(['slot' => 'image', 'alg' => 'sha384']));
        $this->assertSame('sha384', $d->get('alg'));
        $this->assertSame($hex128, $d->get('digest'));
        $this->assertNull(AttestEat::runtimeDigestFromEat($v)); // the default slot is image, whose value is not 64 hex
        $this->assertNull(AttestEat::runtimeDigestFromEat($v, Obj::of(['slot' => 'missing'])));
        $dup = self::verdict([Obj::of(['type' => 'custom', 'value' => $hex64]), Obj::of(['type' => 'custom', 'value' => $hex64])]);
        $this->assertNull(AttestEat::runtimeDigestFromEat($dup, Obj::of(['slot' => 'custom'])));
        $this->assertNull(AttestEat::runtimeDigestFromEat(Obj::of(['ok' => false, 'claims' => Obj::of(['measurements' => []])])));
    }

    /** A measurements claim that is not a list is a TypeError with the exact text; an absent one is an empty list. */
    public function testRuntimeDigestMeasurementsMustBeAList(): void
    {
        foreach ([5, ['x' => 1], 'abc'] as $bad) {
            $e = self::thrown(fn() => AttestEat::runtimeDigestFromEat(self::verdict($bad)));
            $this->assertInstanceOf(\TypeError::class, $e);
            $this->assertSame('(verdict.claims.measurements ?? []).filter is not a function', $e->getMessage());
        }
        $this->assertNull(AttestEat::runtimeDigestFromEat(Obj::of(['ok' => true, 'claims' => new Obj()])));
    }
}
