<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Gcp;
use Atlas\Pca\Attest\Maa;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** The JWT parse helpers and the injected-transport JWKS fetchers of the Azure MAA and Confidential Space verifiers. */
final class AttestJwksFetchTest extends TestCase
{
    private static function jws(array $header, array $payload): string
    {
        return Pca::b64u((string)json_encode($header)) . '.' . Pca::b64u((string)json_encode($payload)) . '.' . Pca::b64u('sig-bytes');
    }

    public function testParseReturnsTheSegmentsAndRefusesMalformedTokens(): void
    {
        foreach ([[Maa::class, 'parseMaaJwt'], [Gcp::class, 'parseGcpCsJwt']] as [$cls, $fn]) {
            $p = $cls::parseJwt(self::jws(['alg' => 'ES256', 'kid' => 'k1'], ['iss' => 'x']));
            $this->assertSame('ES256', $p['header']['alg']);
            $this->assertSame('sig-bytes', $p['signature']);
            $this->assertStringEndsWith('.' . Pca::b64u((string)json_encode(['iss' => 'x'])), $p['signingInput']);
            foreach (['' => 'empty token', 'a.b' => 'exactly three dot-separated parts', 'a..c' => 'empty JWS segment'] as $bad => $why) {
                try {
                    $cls::parseJwt($bad);
                    $this->fail('refused');
                } catch (\TypeError $e) {
                    $this->assertStringStartsWith("$fn: ", $e->getMessage());
                    $this->assertStringContainsString($why, $e->getMessage());
                }
            }
            try {
                $cls::parseJwt(self::jws(['kid' => 'k'], ['iss' => 'x']));
                $this->fail('no alg');
            } catch (\TypeError $e) {
                $this->assertStringContainsString('header has no alg', $e->getMessage());
            }
        }
    }

    public function testTheMaaJwksFetchKeepsWhatTheVerifierReads(): void
    {
        $seen = [];
        $fetch = static function (string $url) use (&$seen): array {
            $seen[] = $url;
            return ['status' => 200, 'body' => json_encode(['keys' => [['kid' => 'a', 'kty' => 'RSA', 'alg' => 'RS256', 'x5c' => ['AAA', 'BBB'], 'junk' => 1], 'x', ['kid' => 5, 'x5c' => ['ok', 7]]]])];
        };
        $jwks = Maa::fetchJwks('https://inst.example/', ['fetch' => $fetch]);
        $this->assertSame(['https://inst.example/certs'], $seen);
        $keys = $jwks->get('keys');
        $this->assertCount(2, $keys);
        $this->assertSame(['kid', 'kty', 'alg', 'x5c'], $keys[0]->keys());
        $this->assertSame([], $keys[1]->keys()); // a non-string kid and a mixed x5c are dropped
        Maa::fetchJwks('https://inst.example', ['fetch' => $fetch, 'certsPath' => '/keys']);
        $this->assertSame('https://inst.example/keys', $seen[1]);
    }

    public function testFetchFailuresThrow(): void
    {
        $bad = static fn(int $s, string $b): \Closure => static fn(string $u): array => ['status' => $s, 'body' => $b];
        foreach ([[500, '{}', 'HTTP 500'], [200, '{"nokeys":1}', 'no keys array']] as [$s, $b, $why]) {
            try {
                Maa::fetchJwks('https://i.example', ['fetch' => $bad($s, $b)]);
                $this->fail('refused');
            } catch (\RuntimeException $e) {
                $this->assertStringContainsString($why, $e->getMessage());
            }
        }
        $this->expectException(\RuntimeException::class);
        Gcp::fetchJwks('https://i.example', []);
    }

    public function testTheGcpFetchResolvesTheJwksUriFromTheOpenIdConfiguration(): void
    {
        $urls = [];
        $fetch = static function (string $url) use (&$urls): array {
            $urls[] = $url;
            return str_ends_with($url, 'openid-configuration')
                ? ['status' => 200, 'body' => json_encode(['jwks_uri' => 'https://i.example/jwks'])]
                : ['status' => 200, 'body' => json_encode(['keys' => [['kid' => 'g', 'kty' => 'RSA', 'n' => 'nn', 'e' => 'AQAB', 'use' => 'sig']]])];
        };
        $jwks = Gcp::fetchJwks('https://i.example/', ['fetch' => $fetch]);
        $this->assertSame(['https://i.example/.well-known/openid-configuration', 'https://i.example/jwks'], $urls);
        $this->assertSame(['kid', 'kty', 'use', 'n', 'e'], $jwks->get('keys')[0]->keys());
        $urls = [];
        Gcp::fetchJwks('https://i.example', ['fetch' => $fetch, 'jwksUri' => 'https://direct.example/k']);
        $this->assertSame(['https://direct.example/k'], $urls);
    }

    public function testTheIssuerChainHeaderIsUrlDecoded(): void
    {
        $this->assertSame("-----BEGIN CERTIFICATE-----\nAA+B/C==\n-----END CERTIFICATE-----\n",
            \Atlas\Pca\Attest\Intel::decodeIssuerChainHeader('-----BEGIN%20CERTIFICATE-----%0AAA%2BB%2FC%3D%3D%0A-----END%20CERTIFICATE-----%0A'));
        $this->assertSame('a+b', \Atlas\Pca\Attest\Intel::decodeIssuerChainHeader('a+b'));
    }

    public function testAP256KeyFromACompressedOrUncompressedPointIsTheSameKey(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $ec = openssl_pkey_get_details($key)['ec'];
        $x = str_pad($ec['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad($ec['y'], 32, "\0", STR_PAD_LEFT);
        $compressed = (ord($y[31]) % 2 === 1 ? "\x03" : "\x02") . $x;
        $a = \Atlas\Pca\Attest\Intel::ecdsaP256PublicKey("\x04" . $x . $y);
        $b = \Atlas\Pca\Attest\Intel::ecdsaP256PublicKey($compressed);
        $this->assertSame($a->spki, $b->spki);
        foreach (['', "\x04" . $x, "\x04" . $x . str_repeat("\x01", 32), "\x05" . $x] as $bad) {
            try {
                \Atlas\Pca\Attest\Intel::ecdsaP256PublicKey($bad);
                $this->fail('refused');
            } catch (\Throwable $e) {
                $this->assertTrue($e instanceof \InvalidArgumentException || $e instanceof \ValueError);
            }
        }
    }
}
