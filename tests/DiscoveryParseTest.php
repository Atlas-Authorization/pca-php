<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Oauth.php';

use Atlas\Pca\Json;
use Atlas\Pca\Oauth;
use PHPUnit\Framework\TestCase;

/** discovery.ts: parseDiscoveryDocument / parseDiscoveryIntent / acceptsSuite / fetchDiscovery and the intent + obligations members of the builder. */
final class DiscoveryParseTest extends TestCase
{
    private const DOC = '{"audience":"rs1","pca_versions":[2],"signature_suites":["ed25519"],"action_header":"PCA-Action","required_checks":["replay"],"endpoints":{"stepup":"https://x/s"},"trusted_roots":["a"],"metadata":{"k":1},"obligations_supported":["log"]}';

    public function testParseRoundTripAndRefusals(): void
    {
        $d = Oauth::parseDiscoveryDocument(Json::parseStrict(self::DOC));
        self::assertSame('rs1', $d->get('audience'));
        self::assertSame(['log'], $d->get('obligations_supported'));
        self::assertTrue(Oauth::acceptsSuite($d, 'ed25519'));
        self::assertFalse(Oauth::acceptsSuite($d, 'ml-dsa-65'));
        foreach ([
            '5', '{}', '{"audience":"a","pca_versions":["x"],"signature_suites":[],"action_header":"h"}',
            '{"audience":"a","pca_versions":[2],"signature_suites":[1],"action_header":"h"}',
            '{"audience":"a","pca_versions":[2],"signature_suites":[],"action_header":""}',
            '{"audience":"a","pca_versions":[2],"signature_suites":[],"action_header":"h","obligations_supported":[1]}',
            '{"audience":"a","pca_versions":[2],"signature_suites":[],"action_header":"h","intent":5}',
        ] as $bad) {
            try {
                Oauth::parseDiscoveryDocument(Json::parseStrict($bad));
                self::fail("accepted $bad");
            } catch (\InvalidArgumentException $e) {
                self::assertStringStartsWith('parseDiscoveryDocument:', $e->getMessage());
            }
        }
        $loose = Oauth::parseDiscoveryDocument(Json::parseStrict('{"audience":"a","pca_versions":[2],"signature_suites":[],"action_header":"h","endpoints":5,"required_checks":[1]}'));
        self::assertFalse($loose->has('endpoints'));
        self::assertFalse($loose->has('required_checks'));
    }

    public function testIntentBlock(): void
    {
        $i = Oauth::parseDiscoveryIntent(Json::parseStrict('{"versions":[1,2],"actions_uri":"u","question_relay":true,"tiers":{"pay":3},"schema_keys":[{"kid":"k","alg":"ed25519","pk":"p"}]}'));
        self::assertSame(['versions', 'actions_uri', 'schema_keys', 'question_relay', 'tiers'], $i->keys());
        foreach (['{"versions":[]}', '{"versions":[3]}', '{"versions":[1],"x":1}', '{"versions":[1],"tiers":{"a":5}}', '{"versions":[1],"tiers":{"a":1.5}}',
            '{"versions":[1],"question_relay":"y"}', '{"versions":[1],"schema_keys":[{"kid":"k"}]}', '{"versions":[1],"actions_uri":""}'] as $bad) {
            try {
                Oauth::parseDiscoveryIntent(Json::parseStrict($bad));
                self::fail("accepted $bad");
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        $built = Oauth::buildDiscoveryDocument(Json::parseStrict('{"audience":"a","intent":{"versions":[2]},"obligationsSupported":["log"]}'));
        self::assertSame(['versions'], $built->get('intent')->keys());
        self::assertSame(['log'], $built->get('obligations_supported'));
    }

    public function testFetchDiscoveryWithAnInjectedFetch(): void
    {
        $seen = null;
        $ok = static function (string $url, array $h) use (&$seen): array {
            $seen = $url;
            return ['ok' => true, 'status' => 200, 'body' => self::DOC];
        };
        self::assertSame('rs1', Oauth::fetchDiscovery('https://api.acme.com//', $ok)->get('audience'));
        self::assertSame('https://api.acme.com/.well-known/pca-configuration', $seen);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('returned 503');
        Oauth::fetchDiscovery('https://x', static fn() => ['ok' => false, 'status' => 503, 'body' => '']);
    }
}
