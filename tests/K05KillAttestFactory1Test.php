<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Assurance;
use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Factory;
use Atlas\Pca\Attest\HardwareVerifier;
use Atlas\Pca\Attest\WithIdentity;
use Atlas\Pca\Json;
use PHPUnit\Framework\TestCase;

/** Survivor kills of src/Attest/Factory.php. */
final class K05KillAttestFactory1Test extends TestCase
{
    private const NODE = 'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received ';

    private static function stub(array $result): HardwareVerifier
    {
        return new class($result) implements HardwareVerifier {
            public function __construct(private array $r)
            {
            }

            public function verify(mixed $document, mixed $expected, mixed $nowMs): array
            {
                return $this->r;
            }
        };
    }

    private static function gcpConfig(string $extra = ''): mixed
    {
        return Json::parseLax('{"trustedIssuers":["https://x"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["aa"]}' . $extra . '}');
    }

    private function typeErrorOf(callable $f): string
    {
        try {
            $f();
        } catch (\TypeError $e) {
            return $e->getMessage();
        }
        $this->fail('no TypeError');
    }

    // ---- WithIdentity -------------------------------------------------------------------------------------------------------------

    public function testOverridesApplyOnlyToASuccessfulMeasuredResult(): void
    {
        $ov = ['a' => 2, 'b' => 3];
        $this->assertSame(['ok' => true, 'measured' => ['a' => 2, 'b' => 3]], (new WithIdentity(self::stub(['ok' => true, 'measured' => ['a' => 1]]), $ov))->verify(null, null, 1));
        // no ok at all: not a success
        $this->assertSame(['measured' => ['a' => 1]], (new WithIdentity(self::stub(['measured' => ['a' => 1]]), $ov))->verify(null, null, 1));
        // ok but nothing measured: untouched
        $this->assertSame(['ok' => true, 'measured' => []], (new WithIdentity(self::stub(['ok' => true, 'measured' => []]), $ov))->verify(null, null, 1));
        // measured but not ok: untouched
        $this->assertSame(['ok' => false, 'measured' => ['a' => 1]], (new WithIdentity(self::stub(['ok' => false, 'measured' => ['a' => 1]]), $ov))->verify(null, null, 1));
    }

    // ---- evidenceFor --------------------------------------------------------------------------------------------------------------

    public function testBase64FieldOfTheWrongTypeNamesItsType(): void
    {
        $this->assertSame(self::NODE . 'type int', $this->typeErrorOf(fn() => Factory::evidenceFor('amd-sev-snp', ['report' => 5])));
    }

    public function testBase64FieldThatIsNullIsNull(): void
    {
        $this->assertSame(self::NODE . 'null', $this->typeErrorOf(fn() => Factory::evidenceFor('amd-sev-snp', ['report' => null])));
    }

    public function testCrlFieldsMissingAreUndefinedAndPresentNullIsNull(): void
    {
        $e = fn(array $c) => Factory::evidenceFor('intel-tdx-dcap', ['collateral' => $c]);
        $this->assertSame(self::NODE . 'undefined', $this->typeErrorOf(fn() => $e(['rootCrlDer' => ''])));
        $this->assertSame(self::NODE . 'null', $this->typeErrorOf(fn() => $e(['pckCrlDer' => null, 'rootCrlDer' => ''])));
        $this->assertSame(self::NODE . 'undefined', $this->typeErrorOf(fn() => $e(['pckCrlDer' => ''])));
        $this->assertSame(self::NODE . 'null', $this->typeErrorOf(fn() => $e(['pckCrlDer' => '', 'rootCrlDer' => null])));
        $this->assertSame(self::NODE . 'type int', $this->typeErrorOf(fn() => $e(['pckCrlDer' => 7, 'rootCrlDer' => ''])));
        $this->assertSame(self::NODE . 'type bool', $this->typeErrorOf(fn() => $e(['pckCrlDer' => '', 'rootCrlDer' => true])));
    }

    public function testUnknownVendorOfEvidenceFor(): void
    {
        try {
            Factory::evidenceFor('foo', ['x' => 1]);
        } catch (AttestConstructError $e) {
            $this->assertSame('unknown attestation vendor foo', $e->getMessage());
            return;
        }
        $this->fail('no AttestConstructError');
    }

    // ---- verifierFromConfig -------------------------------------------------------------------------------------------------------

    public function testConfigMustBeAnObject(): void
    {
        try {
            Factory::verifierFromConfig('gcp-confidential-space', 'nope');
        } catch (AttestConstructError $e) {
            $this->assertSame('verifier_from_config: config must be an object', $e->getMessage());
            return;
        }
        $this->fail('no AttestConstructError');
    }

    public function testIdentityOverridesWrapOnlyANonEmptyObject(): void
    {
        $this->assertNotInstanceOf(WithIdentity::class, Factory::verifierFromConfig('gcp-confidential-space', self::gcpConfig(',"identity_overrides":true')));
        $this->assertNotInstanceOf(WithIdentity::class, Factory::verifierFromConfig('gcp-confidential-space', self::gcpConfig(',"identity_overrides":false')));
        $this->assertNotInstanceOf(WithIdentity::class, Factory::verifierFromConfig('gcp-confidential-space', self::gcpConfig(',"identity_overrides":null')));
        $this->assertNotInstanceOf(WithIdentity::class, Factory::verifierFromConfig('gcp-confidential-space', self::gcpConfig(',"identity_overrides":{}')));
        $this->assertNotInstanceOf(WithIdentity::class, Factory::verifierFromConfig('gcp-confidential-space', self::gcpConfig()));
        $this->assertInstanceOf(WithIdentity::class, Factory::verifierFromConfig('gcp-confidential-space', self::gcpConfig(',"identity_overrides":{"k":"v"}')));
    }

    public function testEveryVerifierCarriesItsHardwareLabel(): void
    {
        $label = Assurance::labelOf(Factory::verifierFromConfig('gcp-confidential-space', self::gcpConfig()));
        $this->assertNotNull($label);
        $this->assertSame('hardware', $label->level);
        $this->assertSame('gcp-confidential-space', $label->vendor);
        $wrapped = Factory::verifierFromConfig('gcp-confidential-space', self::gcpConfig(',"identity_overrides":{"k":"v"}'));
        $this->assertSame('hardware', Assurance::labelOf($wrapped)?->level);
        $this->assertSame('gcp-confidential-space', Assurance::labelOf($wrapped)?->vendor);
    }

    // ---- runX509Vector ------------------------------------------------------------------------------------------------------------

    public function testAnAbsentCertIsTheEmptyString(): void
    {
        $this->assertSame(['ok' => false, 'error' => 'DER: truncated header'], Factory::runX509Vector('read_cert_role_info', ['cert' => null]));
    }

    public function testAnAbsentDerTimeTextIsTheEmptyString(): void
    {
        $this->assertSame(['ok' => true, 'value' => null], Factory::runX509Vector('parse_der_time', ['tag' => 23]));
    }

    public function testATypeErrorIsAReportedRow(): void
    {
        $r = Factory::runX509Vector('check_chain_roles', ['chain' => null]);
        $this->assertFalse($r['ok']);
        $this->assertIsString($r['error']);
        $this->assertStringContainsString('array_map', $r['error']);
    }
}
