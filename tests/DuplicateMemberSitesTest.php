<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestEat;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Bytes;
use Atlas\Pca\Payments;
use Atlas\Pca\Sdjwt;
use Atlas\Pca\Vc;
use PHPUnit\Framework\TestCase;

/** Third-party signed JSON is refused when a member repeats (JSON.parse keeps the last, the signer saw the first); number spellings are left alone. */
final class DuplicateMemberSitesTest extends TestCase
{
    private static function b64u(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    public function testTheSharedParseNamesTheRepeatedKeyAndLeavesNumbersAlone(): void
    {
        try {
            Json::parseNoDuplicates('{"kind":"x","a":{"b":1},"kind":"y"}');
            self::fail('accepted');
        } catch (JsonError $e) {
            self::assertSame('duplicate key "kind"', $e->getMessage());
        }
        $v = Json::parseNoDuplicates('{"n":8.0,"e":1e3}');
        self::assertSame(8.0, $v->get('n')->float());
        self::assertSame(1000.0, $v->get('e')->float());
    }

    public function testAStripeWebhookBodyWithARepeatedMemberIsBadJson(): void
    {
        $handler = Payments::createStripeIssuingWebhook(['secret' => 'whsec_test', 'authorize' => static fn($a): array => ['approved' => true], 'nowSec' => static fn(): int => 1000]);
        $send = static fn(string $raw): \Atlas\Pca\Obj => $handler(['rawBody' => $raw, 'signature' => Payments::signStripePayload($raw, 'whsec_test', 1000)]);
        $dup = $send('{"type":"x","type":"issuing_authorization.request"}');
        self::assertSame(400, $dup->get('status'));
        self::assertStringContainsString('bad_json', (string) $dup->get('body'));
        $ok = $send('{"type":"other","amount":8.0,"n":1e3}');
        self::assertSame(200, $ok->get('status'));
    }

    public function testAnEatWithARepeatedHeaderOrPayloadMemberIsRefusedWithTheReferenceText(): void
    {
        $hdr = '{"alg":"EdDSA","typ":"application/eat+jwt"}';
        $mk = fn(string $h, string $p): string => self::b64u($h) . '.' . self::b64u($p) . '.' . self::b64u(str_repeat("\x01", 64));
        $key = str_repeat("\x02", 32);
        foreach ([[$hdr, '{"iss":"a","iss":"b","iat":1}', 'payload'], ['{"alg":"EdDSA","alg":"none","typ":"application/eat+jwt"}', '{"iss":"a","iat":1}', 'header']] as [$h, $p, $what]) {
            try {
                AttestEat::verifyEat($mk($h, $p), $key);
                self::fail("accepted a repeated $what member");
            } catch (\InvalidArgumentException $e) {
                // the canonical gate refuses it first, as the reference does
                self::assertStringStartsWith('EAT invalid: non-canonical compact JWS: bad-json (', $e->getMessage(), $what);
                self::assertStringContainsString('duplicate key', $e->getMessage(), $what);
            }
        }
    }

    /** A passport VC signed in-test with a throwaway key; its one disclosure carries the given JSON text. */
    private static function vcWith(string $disclosureText, string $pk, string $sk): string
    {
        $d = self::b64u($disclosureText);
        $header = self::b64u('{"alg":"EdDSA","typ":"vc+sd-jwt"}');
        $payload = self::b64u(json_encode([
            'vc' => [
                '@context' => [Vc::VC_CONTEXT, Vc::AGENT_PASSPORT_CONTEXT],
                'type' => ['VerifiableCredential', Vc::AGENT_PASSPORT_VC_TYPE],
                'credentialSubject' => ['id' => 'did:example:s', 'passport_id' => 'p', 'model_id' => 'm', 'operator' => 'o', 'hardware_rooted' => true, 'issued_at' => 1,
                    '_sd' => [self::b64u(hash('sha256', $d, true))]],
            ],
            '_sd_alg' => 'sha-256', 'iss' => 'did:example:i', 'sub' => 'did:example:s',
        ], JSON_UNESCAPED_SLASHES));
        return $header . '.' . $payload . '.' . self::b64u(sodium_crypto_sign_detached("$header.$payload", $sk)) . '~' . $d . '~';
    }

    public function testAPassportDisclosureWithARepeatedMemberIsMalformed(): void
    {
        $kp = sodium_crypto_sign_keypair();
        $pk = sodium_crypto_sign_publickey($kp);
        $sk = sodium_crypto_sign_secretkey($kp);
        self::assertNotNull(Vc::verifyPassportVC(self::vcWith('["s","weights_digest","dd"]', $pk, $sk), new Bytes($pk)));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('pca-vc: malformed disclosure');
        Vc::verifyPassportVC(self::vcWith('["s","weights_digest",{"a":1,"a":2}]', $pk, $sk), new Bytes($pk));
    }

    public function testAnSdJwtIssuerPayloadWithARepeatedMemberIsRefusedWithTheReferenceText(): void
    {
        $jwt = self::b64u('{"alg":"EdDSA"}') . '.' . self::b64u('{"_sd":[],"_sd":["x"]}') . '.' . self::b64u(str_repeat("\x01", 64)) . '~';
        try {
            Sdjwt::present($jwt, []);
            self::fail('accepted a repeated issuer payload member');
        } catch (\Throwable $e) {
            self::assertNotInstanceOf(\PHPUnit\Framework\AssertionFailedError::class, $e);
            self::assertStringContainsString('non-canonical compact JWS: bad-json (', $e->getMessage());
            self::assertStringContainsString('duplicate key', $e->getMessage());
        }
    }
}
