<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FrostNet;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PoPError;
use PHPUnit\Framework\TestCase;

/** Mutation kills for FrostNet: allow-token refusals and their reasons, the strict share/commitment decoders and the enrollment refusals. */
final class SigSurvivorKill29FrostNetTest extends TestCase
{
    private static function seed(string $label): string
    {
        return hash('sha256', "atlas-pca-conformance/g29-frost/$label", true);
    }

    private static function gpk(): string
    {
        return self::seed('group');
    }

    private function threw(string $class, string $message, callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class);
            $this->assertSame($message, $e->getMessage());
            return $e;
        }
        $this->fail("expected $class: $message");
    }

    /** @return array{0:Obj,1:array} a valid token and the matching expectations */
    private static function token(): array
    {
        $t = FrostNet::issueAllowToken(self::seed('policy'), Obj::of(['message' => 'act', 'groupPublicKey' => self::gpk(), 'nonce' => 'n1']));
        $apk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed('policy')));
        return [$t, ['policyAuthorityPublicKey' => $apk, 'groupPublicKey' => self::gpk(), 'message' => 'act', 'now' => 1000]];
    }

    /** One signer's enrollment row: its raw share key and a proof of possession made for `$popId`. */
    private static function enrollment(int $id, ?int $popId = null): array
    {
        $pop = FrostNet::createSignerPoP($popId ?? $id, self::seed("share$id"), ['groupPublicKey' => self::gpk(), 'nonce' => self::seed("nonce$id")]);
        return ['identifier' => $id, 'publicKey' => Pca::unb64u($pop->get('publicKey')), 'pop' => $pop];
    }

    /** Only bytes have an action digest, and only bytes are a group key. */
    public function testBytesOnly(): void
    {
        $this->threw(\TypeError::class, 'frostActionDigest: message must be bytes', fn () => FrostNet::frostActionDigest(5));
        $this->threw(\TypeError::class, 'b64u: expected bytes',
            fn () => FrostNet::issueAllowToken(self::seed('policy'), Obj::of(['message' => 'act', 'groupPublicKey' => 5])));
    }

    /** The allow-token refusals name the cause: a wrong typ, and a verifier-side error fails closed with its message. */
    public function testAllowTokenReasons(): void
    {
        [$t, $x] = self::token();
        $this->assertSame(['ok' => true], FrostNet::verifyAllowToken($t, $x), 'control');
        $this->assertSame(['ok' => false, 'reason' => 'allow token wrong typ (x)'],
            FrostNet::verifyAllowToken(Obj::of(['body' => Obj::of(['typ' => 'x']), 'sig' => 's']), $x));
        $x['message'] = 5;
        $this->assertSame(['ok' => false, 'reason' => 'allow token verification error (fail closed): frostActionDigest: message must be bytes'],
            FrostNet::verifyAllowToken($t, $x));
    }

    /** The decoders refuse a non-object entry and a bad key encoding, each by name. */
    public function testDecoderRefusals(): void
    {
        $this->threw(\RuntimeException::class, 'bad commitment', fn () => FrostNet::decodeCommitment('x'));
        $this->threw(\RuntimeException::class, 'bad verification share', fn () => FrostNet::decodeVerificationShares(['x']));
        // an assoc array has no JS members here, so it reaches the identifier check
        $this->threw(\RuntimeException::class, 'bad verification-share identifier',
            fn () => FrostNet::decodeVerificationShares([['identifier' => 1, 'publicKey' => Pca::b64u(self::gpk())]]));
        $this->threw(\RuntimeException::class, 'bad verification-share key encoding',
            fn () => FrostNet::decodeVerificationShares([Obj::of(['identifier' => 1, 'publicKey' => 'not-b64u!'])]));
        $ok = FrostNet::decodeVerificationShares([Obj::of(['identifier' => 1, 'publicKey' => Pca::b64u(self::gpk())])]);
        $this->assertSame([['identifier' => 1, 'publicKey' => self::gpk()]], $ok, 'control');
    }

    /** createSignerPoP refuses a non-positive identifier. */
    public function testCreateSignerPoPNeedsAPositiveId(): void
    {
        $this->threw(\RuntimeException::class, 'createSignerPoP: identifier must be a positive integer',
            fn () => FrostNet::createSignerPoP(0, self::seed('share1'), ['groupPublicKey' => self::gpk()]));
    }

    /** Enrollment rows may be assoc arrays; every malformed row is refused with its reason and the signer named. */
    public function testEnrollmentRefusals(): void
    {
        $x = Obj::of(['groupPublicKey' => self::gpk()]);
        $ok = FrostNet::enrollVerificationShares([self::enrollment(1), self::enrollment(2)], $x);
        $this->assertSame([1, 2], array_column($ok, 'identifier'));
        $this->threw(PoPError::class, 'enrollVerificationShares: no signer enrollments', fn () => FrostNet::enrollVerificationShares('x', $x));
        $this->threw(PoPError::class, 'enrollVerificationShares: no signer enrollments', fn () => FrostNet::enrollVerificationShares(['a' => self::enrollment(1)], $x));
        $this->threw(PoPError::class, 'enrollVerificationShares: groupPublicKey must be 32 bytes',
            fn () => FrostNet::enrollVerificationShares([self::enrollment(1)], Obj::of(['groupPublicKey' => 'short'])));
        $bad = self::enrollment(1);
        $bad['identifier'] = 0;
        $this->threw(PoPError::class, 'enrollVerificationShares: enrollment with invalid identifier', fn () => FrostNet::enrollVerificationShares([$bad], $x));
        $short = self::enrollment(1);
        $short['publicKey'] = 'short';
        $e = $this->threw(PoPError::class, 'enrollVerificationShares: signer 1 verification share must be 32 bytes', fn () => FrostNet::enrollVerificationShares([$short], $x));
        $this->assertSame(1, $e->identifier);
        // a valid proof, but made for signer 2: the binding to the enrolled identifier is checked before the proof itself
        $this->threw(PoPError::class, 'enrollVerificationShares: signer 1 missing or mismatched proof-of-possession (rogue key rejected)',
            fn () => FrostNet::enrollVerificationShares([self::enrollment(1, 2)], $x));
    }
}
