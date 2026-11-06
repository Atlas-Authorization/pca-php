<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The seven cross-language ML-DSA session-root vectors (adv1563-adv1569, test-data/k05-mldsa-session-root.json): each is refused at the
 * `intent_session` check for the pin reason below, by every verifier. They also need the ML-DSA suites declared: the cross-language
 * suite judge refuses a verifier that lacks the signer's suite unless it answers `unsupported_suite`, so on a host with an
 * OpenSSL >= 3.5 libcrypto (ATLAS_PCA_LIBCRYPTO; the gate sets it to /opt/openssl35 when that exists) PHP must declare them. Cases without such a library skip the capability
 * assertion unless PCA_REQUIRE_MLDSA=1.
 */
final class MldsaSessionRootVectorsTest extends TestCase
{
    /** @return array<string, array{0:string,1:string,2:string}> id => [id, reason fragment, suite of the session root] */
    public static function vectors(): array
    {
        $pin = "needs the signer's PQ key pinned by the verifier";
        $ver = "does not match the verifier's pin";
        return [
            'adv1563' => ['adv1563', $pin, 'ml-dsa-65'],
            'adv1564' => ['adv1564', $pin, 'ml-dsa-65'],
            'adv1565' => ['adv1565', $ver, 'ml-dsa-65'],
            'adv1566' => ['adv1566', $pin, 'hybrid-ed25519-ml-dsa-65'],
            'adv1567' => ['adv1567', $pin, 'hybrid-ed25519-ml-dsa-65'],
            'adv1568' => ['adv1568', $ver, 'hybrid-ed25519-ml-dsa-65'],
            'adv1569' => ['adv1569', "does not match the signer's principals entry", 'hybrid-ed25519-ml-dsa-65'],
        ];
    }

    #[DataProvider('vectors')]
    public function testRefusedAtIntentSessionForThePinReason(string $id, string $fragment, string $suite): void
    {
        $c = null;
        foreach (json_decode(file_get_contents(__DIR__ . '/../test-data/k05-mldsa-session-root.json'), true) as $x) {
            if ($x['id'] === $id) {
                $c = $x;
            }
        }
        $this->assertNotNull($c);
        $o = json_decode(json_encode($c), false);
        $v2 = Json::parseLax(json_encode($o->intent_v2, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION));
        $g = Pca::verifyJson($c['raw'], Json::parseLax($c['grant']), (int)$c['now'], $c['aud'], null, null, $v2);
        $this->assertFalse($g['allow']);
        $this->assertFalse($g['checks']['intent_session']);
        $this->assertStringContainsString($fragment, (string)$g['reason']);

        $lib = getenv('ATLAS_PCA_LIBCRYPTO');
        if ((is_string($lib) && is_file($lib)) || getenv('PCA_REQUIRE_MLDSA') === '1') {
            $this->assertContains($suite, Pca::supportedSuites(), 'the host has OpenSSL >= 3.5 but PHP does not declare the signer suite');
        }
    }
}
