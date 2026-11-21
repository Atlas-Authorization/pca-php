<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestEatProvenance;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SigstoreBundle;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The artifact discharge (Sigstore bundle verification joined to the provenance gate, signed as a K1 discharge) against the TS
 * reference: test-data/ref-attest-eat-discharge.json.gz. The issuer key is a seed label (sha256("atlas-pca-conformance/" + label));
 * the discharge nonce is the reference oracle's: the first 16 bytes of sha256("eat-oracle-nonce/0").
 */
final class RefAttestEatDischargeTest extends TestCase
{
    private const FILE = 'ref-attest-eat-discharge.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function int(mixed $n): int
    {
        if (!$n instanceof Num || !$n->isInt()) {
            throw new \InvalidArgumentException('not an integer');
        }
        return $n->int();
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        if (!function_exists('sodium_crypto_sign_seed_keypair') || !extension_loaded('openssl')) {
            $this->markTestSkipped('needs ext-sodium and ext-openssl');
        }
        Base::run($file, $fn, $k, ['issueArtifactDischarge' => static function (array $a) {
            $o = $a[0];
            $i = ['bundle' => $o->get('bundle'), 'roots' => SigstoreBundle::parseTrustedRoot($o->get('roots')), 'policy' => $o->get('policy'),
                'request' => $o->get('request'), 'now' => self::int($o->get('now')),
                'issuerKey' => new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $o->get('issuerKey')->get('seed')->get('$seed'), true))];
            if ($o->has('runtime')) {
                $i['runtime'] = $o->get('runtime');
            }
            if ($o->get('ttl_ms') !== null) {
                $i['ttl_ms'] = self::int($o->get('ttl_ms'));
            }
            $nonce = static fn(): string => substr(hash('sha256', 'eat-oracle-nonce/0', true), 0, 16);
            return AttestEatProvenance::issueArtifactDischarge($i, $nonce);
        }]);
    }
}
