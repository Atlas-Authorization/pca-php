<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestVendors;
use PHPUnit\Framework\TestCase;

/** Vendor JWT segments are parsed with the duplicate-only check: a duplicate member (JSON.parse keeps the last, the signer saw the first) is refused with a fixed message. */
final class VendorDocumentStrictJsonTest extends TestCase
{
    private const HEADER = 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwiamt1IjoiaHR0cHM6Ly9tYWEuZXhhbXBsZS5uZXQvY2VydHMiLCJ0eXAiOiJKV1QiLCJ4NWMiOlsiQUFBQSIsIkJCQkIiXX0';

    private static function seg(string $json): string
    {
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    }

    /** @return iterable<string,array{string}> */
    public static function badPayloads(): iterable
    {
        yield 'duplicate member' => ['{"a":1,"a":2}'];
        yield 'not json' => ['not json'];
        yield 'truncated' => ['{"a":'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('badPayloads')]
    public function testAJwtWithAnInvalidSegmentIsRefused(string $payload): void
    {
        foreach (['parseMaaJwt', 'parseGcpCsJwt'] as $fn) {
            try {
                AttestVendors::$fn(self::HEADER . '.' . self::seg($payload) . '.c2ln');
                self::fail("$fn accepted $payload");
            } catch (\TypeError $e) {
                self::assertSame("$fn: malformed JSON segment: invalid JSON", $e->getMessage());
            }
        }
    }

    public function testNumberSpellingsAreLeftAlone(): void
    {
        foreach (['{"a":8.0,"b":1e3}', '{"svn":-0}'] as $payload) {
            foreach (['parseMaaJwt', 'parseGcpCsJwt'] as $fn) {
                self::assertNotEmpty(AttestVendors::$fn(self::HEADER . '.' . self::seg($payload) . '.c2ln'), "$fn $payload");
            }
        }
    }

    public function testADuplicateMemberInTheHeaderIsRefusedAndACleanDocumentParses(): void
    {
        $dupHeader = self::seg('{"alg":"ES256","alg":"none","kid":"k1"}');
        try {
            AttestVendors::parseMaaJwt($dupHeader . '.' . self::seg('{"a":2}') . '.c2ln');
            self::fail('accepted a duplicate header member');
        } catch (\TypeError $e) {
            self::assertSame('parseMaaJwt: malformed JSON segment: invalid JSON', $e->getMessage());
        }
        self::assertNotEmpty(AttestVendors::parseMaaJwt(self::HEADER . '.' . self::seg('{"a":2}') . '.c2ln'));
    }

    public function testASignedDocumentWithADuplicateMemberIsRefused(): void
    {
        $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $pem = openssl_pkey_get_details($k)['key'];
        $der = base64_decode(preg_replace('/-----[A-Z ]+-----|\s/', '', $pem));
        $sig = str_repeat('0', 128);
        foreach (['{"tcbInfo":{"a":1,"a":2},"signature":"' . $sig . '"}', '{"tcbInfo":{"a":1},"signature":"' . $sig . '","signature":"' . $sig . '"}'] as $text) {
            self::assertSame(['error' => 'tcbInfo document is not valid JSON'], AttestVendors::verifySignedJson($text, 'tcbInfo', $der));
        }
    }
}
