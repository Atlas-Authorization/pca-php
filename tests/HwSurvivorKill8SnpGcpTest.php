<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Gcp;
use Atlas\Pca\Num;
use PHPUnit\Framework\TestCase;

/** Survivor kills for Attest/Gcp.php: the OpenID-configuration step of fetchJwks (status range, Num statuses, refusal texts, body typing). */
final class HwSurvivorKill8SnpGcpTest extends TestCase
{
    private const ISSUER = 'https://i.example/';
    private const CONF = 'https://i.example/.well-known/openid-configuration';

    /** A fetch answering the configuration URL with `$confRes` and the JWKS with an empty key set; every requested URL is appended to `$urls`. */
    private static function transport(array $confRes, array &$urls): callable
    {
        return static function (string $url) use ($confRes, &$urls): array {
            $urls[] = $url;
            return $url === self::CONF ? $confRes : ['status' => 200, 'body' => '{"keys":[]}'];
        };
    }

    public function testTheConfigurationStatusRangeIncludesTwoNinetyNine(): void
    {
        $urls = [];
        $jwks = Gcp::fetchJwks(self::ISSUER, ['fetch' => self::transport(['status' => 299, 'body' => '{"jwks_uri":"https://i.example/jwks"}'], $urls)]);
        $this->assertSame([self::CONF, 'https://i.example/jwks'], $urls);
        $this->assertSame(['keys'], $jwks->keys());
        $this->assertSame([], $jwks->get('keys'));
    }

    public function testAJsonNumberStatusIsUnderstood(): void
    {
        $urls = [];
        $jwks = Gcp::fetchJwks(self::ISSUER, ['fetch' => self::transport(['status' => new Num('200'), 'body' => '{"jwks_uri":"https://i.example/jwks"}'], $urls)]);
        $this->assertSame([self::CONF, 'https://i.example/jwks'], $urls);
        $this->assertSame([], $jwks->get('keys'));
    }

    public function testAFailedConfigurationFetchNamesItsStatus(): void
    {
        $cases = [[500, '500'], [new Num('404'), '404'], [null, 'undefined']];
        foreach ($cases as [$status, $shown]) {
            $res = ['body' => '{}'] + ($status === null ? [] : ['status' => $status]);
            $urls = [];
            try {
                Gcp::fetchJwks(self::ISSUER, ['fetch' => self::transport($res, $urls)]);
                $this->fail('refused');
            } catch (\RuntimeException $e) {
                $this->assertSame('Confidential Space OpenID config fetch failed: HTTP ' . $shown . ' for ' . self::CONF, $e->getMessage());
            }
            $this->assertSame([self::CONF], $urls);
        }
    }

    public function testANonStringConfigurationBodyIsReadAsItsText(): void
    {
        $urls = [];
        try {
            Gcp::fetchJwks(self::ISSUER, ['fetch' => self::transport(['status' => 200, 'body' => 5], $urls)]);
            $this->fail('no jwks_uri');
        } catch (\RuntimeException $e) {
            $this->assertSame('Confidential Space OpenID config carries no jwks_uri', $e->getMessage());
        }
    }
}
