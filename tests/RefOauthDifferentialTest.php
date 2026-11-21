<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Oauth;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The OAuth / MCP-authorization bridge against the TS reference: test-data/ref-oauth.json.gz. */
final class RefOauthDifferentialTest extends TestCase
{
    private const FILE = 'ref-oauth.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'resourceIdentifierProblem' => fn(array $a) => Oauth::resourceIdentifierProblem($a[0]),
            'prmPathForResource' => fn(array $a) => Oauth::prmPathForResource($a[0]),
            'prmUrlForResource' => fn(array $a) => Oauth::prmUrlForResource($a[0]),
            'protectedResourceMetadata' => fn(array $a) => Oauth::protectedResourceMetadata($a[0]),
            'oauthDiscoveryHandler' => fn(array $a) => Oauth::oauthDiscoveryHandler($a[0]),
            'parseProtectedResourceMetadata' => fn(array $a) => Oauth::parseProtectedResourceMetadata($a[0], $a[1] ?? null),
            'wwwAuthenticate' => fn(array $a) => Oauth::wwwAuthenticate($a[0], $a[1] ?? null),
            'mcpUnauthorized' => fn(array $a) => Oauth::mcpUnauthorized($a[0], $a[1] ?? null),
            'upgradeUnauthorizedChallenge' => fn(array $a) => Oauth::upgradeUnauthorizedChallenge($a[0], $a[1], $a[2] ?? null),
            'checkResourceIndicator' => fn(array $a) => Oauth::checkResourceIndicator($a[0], $a[1]),
            'checkTokenAudience' => fn(array $a) => Oauth::checkTokenAudience($a[0], $a[1]),
            'buildPcaGrantDetail' => fn(array $a) => Oauth::buildPcaGrantDetail($a[0]),
            'pcaGrantRequestParam' => fn(array $a) => Oauth::pcaGrantRequestParam($a[0]),
            'authorizePcaGrantToken' => fn(array $a) => Oauth::authorizePcaGrantToken($a[0]),
            'oauthScopeForAction' => fn(array $a) => Oauth::oauthScopeForAction($a[0], $a[1]),
        ]);
    }
}
