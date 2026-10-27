<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Amd.php';
require_once __DIR__ . '/Maa.php';
require_once __DIR__ . '/Gcp.php';
require_once __DIR__ . '/Intel.php';
require_once __DIR__ . '/Nvidia.php';

use Atlas\Pca\Obj;

/**
 * `identity_overrides`: after a successful verification the keys of the override replace the same keys of `measured`.
 */
final class WithIdentity implements HardwareVerifier
{
    public function __construct(private HardwareVerifier $inner, private mixed $overrides)
    {
    }

    public function verify(mixed $document, mixed $expected, mixed $nowMs): array
    {
        $r = $this->inner->verify($document, $expected, $nowMs);
        if (($r['ok'] ?? false) === true && !empty($r['measured'])) {
            $merged = $r['measured'];
            foreach (Common::members($this->overrides) as $k => $v) {
                $merged[$k] = $v;
            }
            $r['measured'] = $merged;
        }
        return $r;
    }
}

/**
 * The built-in hardware verifier of {@see Passport::verify}, used when no integrator `attest` callable is given. `$evidence` maps
 * the passport's evidence document to the vendor evidence object (the wire form of the vendor, see the vector schema); with none,
 * the evidence document itself is the vendor evidence.
 */
final class DefaultHardware
{
    /** @param (callable(\Atlas\Pca\Obj): mixed)|null $evidence */
    public function __construct(private HardwareVerifier $verifier, private $evidence = null)
    {
    }

    /** @return \Closure(mixed, array): array */
    public function attest(int $nowMs): \Closure
    {
        return function (mixed $doc, array $expected) use ($nowMs): array {
            $ev = $this->evidence !== null ? ($this->evidence)($doc) : $doc;
            $wrapped = new Obj();
            $wrapped->set('evidence', $ev);
            return $this->verifier->verify($wrapped, $expected, $nowMs);
        };
    }
}

/**
 * Vendor hardware-attestation verifiers for agent passports and PCActns: the native counterpart of the vendor verifiers of
 * `@atlasauth/pca` (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, GCP Confidential Space, NVIDIA GPU SPDM).
 *
 *     $v = Factory::verifierFromConfig('amd-sev-snp', $config);   // $config: a parsed JSON object, the vector-file schema
 *     Passport::verify($signed, ['trustedIssuers' => [...], 'now' => ..., 'revocation' => ..., 'defaultHardware' => new DefaultHardware($v)]);
 *
 * `verifier->verify($document, $expected, $nowMs)` answers `{ok, bound?, reason?, measured?, hostAsserted?}` and fails CLOSED: a
 * missing pin, an empty measurement allowlist, an unverifiable chain or an unbound quote is `ok: false` with a reason, never a
 * pass. Evidence is resolved from `document.evidence` (or by the callable you pass) and is the wire object of the vendor: bytes
 * as standard base64 strings, PEM and JSON documents as strings. Needs the `openssl` and `gmp` extensions.
 */
final class Factory
{
    public const VENDORS = ['amd-sev-snp', 'intel-tdx-dcap', 'azure-maa', 'gcp-confidential-space', 'nvidia-gpu-spdm'];

    private static function unb64(mixed $v, ?string $what = null): string
    {
        if (is_string($v)) {
            return Common::nodeB64Decode($v);
        }
        throw new \TypeError('The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received '
            . ($v === null ? ($what === 'missing' ? 'undefined' : 'null') : 'type ' . get_debug_type($v)));
    }

    private static function optBytes(mixed $v): ?string
    {
        return is_string($v) ? Common::nodeB64Decode($v) : null;
    }

    /**
     * The wire evidence of `$vendor` as the verifier consumes it (base64 strings decoded to bytes); null when there is none.
     * @return array<string,mixed>|null
     */
    public static function evidenceFor(string $vendor, mixed $ev): ?array
    {
        if ($ev === null) {
            return null;
        }
        $out = [];
        switch ($vendor) {
            case 'amd-sev-snp':
                if (Common::has($ev, 'report')) {
                    $out['report'] = self::unb64(Common::g($ev, 'report'));
                }
                if (Common::has($ev, 'vcekDer')) {
                    $out['vcekDer'] = self::unb64(Common::g($ev, 'vcekDer'));
                }
                if (Common::has($ev, 'askArkPem')) {
                    $out['askArkPem'] = Common::g($ev, 'askArkPem');
                }
                $rd = self::optBytes(Common::g($ev, 'runtimeData'));
                if ($rd !== null) {
                    $out['runtimeData'] = $rd;
                }
                break;
            case 'intel-tdx-dcap':
                if (Common::has($ev, 'quote')) {
                    $out['quote'] = self::unb64(Common::g($ev, 'quote'));
                }
                $rd = self::optBytes(Common::g($ev, 'runtimeData'));
                if ($rd !== null) {
                    $out['runtimeData'] = $rd;
                }
                $c = Common::g($ev, 'collateral');
                if (Common::isObj($c)) {
                    $out['collateral'] = [
                        'tcbInfoJson' => Common::g($c, 'tcbInfoJson'), 'tcbInfoIssuerChainPem' => Common::g($c, 'tcbInfoIssuerChainPem'),
                        'qeIdentityJson' => Common::g($c, 'qeIdentityJson'), 'qeIdentityIssuerChainPem' => Common::g($c, 'qeIdentityIssuerChainPem'),
                        'pckCrlDer' => self::unb64(Common::g($c, 'pckCrlDer'), Common::has($c, 'pckCrlDer') ? null : 'missing'),
                        'rootCrlDer' => self::unb64(Common::g($c, 'rootCrlDer'), Common::has($c, 'rootCrlDer') ? null : 'missing'),
                    ];
                }
                break;
            case 'azure-maa':
            case 'gcp-confidential-space':
                if (Common::has($ev, 'token')) {
                    $out['token'] = Common::g($ev, 'token');
                }
                if (Common::has($ev, 'jwks')) {
                    $out['jwks'] = Common::g($ev, 'jwks');
                }
                break;
            case 'nvidia-gpu-spdm':
                if (Common::has($ev, 'evidence')) {
                    $out['evidence'] = self::unb64(Common::g($ev, 'evidence'));
                }
                if (Common::has($ev, 'certChainPem')) {
                    $out['certChainPem'] = Common::g($ev, 'certChainPem');
                }
                $c = Common::g($ev, 'collateral');
                if (Common::isObj($c)) {
                    $bundle = ['driverRimXml' => Common::g($c, 'driverRimXml'), 'vbiosRimXml' => Common::g($c, 'vbiosRimXml')];
                    foreach (['crls', 'ocsp'] as $k) {
                        $list = Common::g($c, $k);
                        if (Common::isList($list) && $list !== []) {
                            $bundle[$k] = array_map(static fn($x) => self::unb64($x), $list);
                        }
                    }
                    $out['collateral'] = $bundle;
                }
                break;
            default:
                throw new AttestConstructError('unknown attestation vendor ' . Common::jsStr($vendor));
        }
        return $out;
    }

    /**
     * Build the verifier of `$vendor` from a parsed-JSON `$config`. Throws AttestConstructError (or JsError) when the configuration
     * is refused (accept-all, a missing pin or allowlist, an unknown mode).
     * @param (callable(mixed): mixed)|null $resolveEvidence maps the document to the vendor evidence (default: `document.evidence`)
     */
    public static function verifierFromConfig(string $vendor, mixed $config, ?callable $resolveEvidence = null): HardwareVerifier
    {
        if (!in_array($vendor, self::VENDORS, true)) {
            throw new AttestConstructError('unknown attestation vendor ' . Common::jsStr($vendor));
        }
        if (!Common::isObj($config)) {
            throw new AttestConstructError('verifier_from_config: config must be an object');
        }
        $resolve = $resolveEvidence ?? static fn(mixed $doc): mixed => Common::g($doc, 'evidence');
        $resolved = static fn(mixed $doc): ?array => self::evidenceFor($vendor, $resolve($doc));
        $v = match ($vendor) {
            'amd-sev-snp' => new Amd($config, $resolved),
            'intel-tdx-dcap' => new Intel($config, $resolved),
            'azure-maa' => new Maa($config, $resolved),
            'gcp-confidential-space' => new Gcp($config, $resolved),
            'nvidia-gpu-spdm' => Nvidia::fromConfig($config, $resolved),
        };
        $ov = Common::g($config, 'identity_overrides');
        if ($ov !== null && $ov !== false && Common::members($ov) !== []) {
            return new WithIdentity($v, $ov);
        }
        return $v;
    }

    /**
     * Run one (hydrated) vector row `{vendor, config, evidence, now, expected_binding}` through the native verifier.
     * @return array<string,mixed>
     */
    public static function runAttestationVector(Obj $row): array
    {
        $ev = $row->get('evidence');
        try {
            $verifier = self::verifierFromConfig($row->get('vendor'), $row->get('config'), static fn(mixed $d): mixed => $ev);
        } catch (\Throwable $e) { // the factory refused the configuration
            return ['construct_error' => $e->getMessage()];
        }
        return $verifier->verify(new Obj(), $row->get('expected_binding'), $row->get('now'));
    }

    /**
     * Run one x509 unit row of the vectors: `{ok: true, value}` or `{ok: false, error}` (the exact reader message).
     * @return array<string,mixed>
     */
    public static function runX509Vector(string $fn, mixed $in): array
    {
        $b = static fn(mixed $x): string => Common::nodeB64Decode((string)$x);
        try {
            switch ($fn) {
                case 'read_cert_role_info':
                    return ['ok' => true, 'value' => Der::readCertRoleInfo($b(Common::g($in, 'cert')))];
                case 'parse_cert_extensions':
                case 'parse_tbs_extensions':
                    $m = $fn === 'parse_cert_extensions' ? Der::parseCertExtensions($b(Common::g($in, 'cert'))) : Der::parseTbsExtensions($b(Common::g($in, 'tbs')));
                    $v = [];
                    foreach ($m as $oid => $e) {
                        $v[] = ['oid' => (string)$oid, 'critical' => $e->critical, 'value' => bin2hex($e->value)];
                    }
                    return ['ok' => true, 'value' => $v];
                case 'tbs_of_certificate':
                    return ['ok' => true, 'value' => base64_encode(Der::tbsOfCertificate($b(Common::g($in, 'cert'))))];
                case 'unrecognised_critical_extension':
                    $rec = Common::g($in, 'recognised');
                    return ['ok' => true, 'value' => Der::unrecognisedCriticalExtension($b(Common::g($in, 'cert')), is_array($rec) ? $rec : null)];
                case 'check_chain_roles':
                    return ['ok' => true, 'value' => Der::checkChainRoles(array_map($b, Common::g($in, 'chain')))];
                case 'der_validity_ms':
                    [$lo, $hi] = Der::derValidityMs($b(Common::g($in, 'cert')));
                    return ['ok' => true, 'value' => ['from' => $lo, 'to' => $hi]];
                case 'parse_der_time':
                    return ['ok' => true, 'value' => Der::parseDerTime((int)Common::numOf(Common::g($in, 'tag')), (string)Common::g($in, 'text'))];
            }
            return ['ok' => false, 'error' => "unknown x509 function $fn"];
        } catch (DerError | \ValueError | \TypeError $e) {
            return ['ok' => false, 'error' => $e->getMessage()];
        }
    }
}
