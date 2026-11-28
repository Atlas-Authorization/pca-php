<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ap2;
use Atlas\Pca\Grants;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** A natively built inclusion proof carries Num numbers and passes the strict verifier; a whole SD-JWT resolves to its payload object. */
final class InclusionAndDisclosureTest extends TestCase
{
    public function testANativeInclusionProofVerifiesAndCarriesNumNumbers(): void
    {
        $leaves = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
        $root = Pca::merkleRoot($leaves);
        foreach (array_keys($leaves) as $i) {
            $proof = Grants::merkleProof($leaves, $i); // the index is a plain PHP int here, as a caller passes it
            self::assertInstanceOf(Num::class, $proof->get('index'));
            self::assertInstanceOf(Num::class, $proof->get('size'));
            self::assertTrue(Pca::verifyInclusion($root, $proof, $leaves[$i]), "leaf $i");
            self::assertFalse(Pca::verifyInclusion($root, $proof, $leaves[($i + 1) % 7]), "a different leaf at $i");
        }
    }

    public function testTheVerifierStillRefusesARawPhpIntegerOrAFloatInAProof(): void
    {
        $leaves = ['a', 'b', 'c'];
        $root = Pca::merkleRoot($leaves);
        $good = Grants::merkleProof($leaves, 1);
        foreach ([1, 1.0, '1'] as $raw) {
            $bad = Obj::of(['index' => $raw, 'size' => $good->get('size'), 'path' => $good->get('path')]);
            self::assertFalse(Pca::verifyInclusion($root, $bad, 'b'), 'index ' . var_export($raw, true));
        }
    }

    public function testAWholeSdJwtResolvesToItsPayloadObject(): void
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $n = 0;
        $b = Ap2::disclosureBuilder('sha-256', static function () use (&$n): string {
            return Pca::b64u(sprintf('salt-%012d', ++$n));
        });
        $digest = $b->property('amount', new Num('5'));
        $token = Ap2::signSdJwt(Obj::of(['header' => Obj::of(['typ' => 'dc+sd-jwt']), 'payload' => Obj::of(['_sd' => [$digest], '_sd_alg' => 'sha-256']),
            'disclosures' => $b->disclosures, 'privateKey' => $key]));
        $hop = Ap2::parseSdJwtHop($token);
        $out = Ap2::processDisclosures($hop->get('payload'), $hop->get('disclosures'), $hop->get('sdAlg'));
        self::assertInstanceOf(Obj::class, $out);
        self::assertSame('5', $out->get('amount')->lexeme);
        self::assertFalse($out->has('_sd'));
        self::assertFalse($out->has('_sd_alg'));
    }
}
