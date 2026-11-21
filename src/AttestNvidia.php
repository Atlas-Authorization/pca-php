<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Attest/Cert.php';
require_once __DIR__ . '/Attest/Common.php';
require_once __DIR__ . '/Attest/Nvidia.php';
require_once __DIR__ . '/Attest/Ocsp.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Nvidia;
use Atlas\Pca\Attest\Ocsp;
use Atlas\Pca\Attest\PubKey;

/**
 * The public surface of the NVIDIA GPU confidential-computing attestation modules under the reference names: the SPDM transcript, the device chain
 * against a pinned root, the report signature, the PCA challenge, the RIM documents (XMLDSig), the golden comparison, CRL / OCSP revocation, the
 * collateral hook and the guarded fetch helpers (the transport is injected: `callable(string $url, ?Obj $init): Obj{status, body (raw bytes)}`,
 * the library carries no HTTP client). The verifiers themselves are {@see Nvidia} and {@see Ocsp}.
 */
final class AttestNvidia
{
    public const SPDM_SUITE = Nvidia::SUITE;
    public const OPAQUE = ['CERT_ISSUER_NAME' => 1, 'CERT_AUTHORITY_KEY_IDENTIFIER' => 2, 'DRIVER_VERSION' => 3, 'GPU_INFO' => 4, 'SKU' => 5, 'VBIOS_VERSION' => 6,
        'MANUFACTURER_ID' => 7, 'TAMPER_DETECTION' => 8, 'MSRSCNT' => 12, 'BOARD_ID' => 14, 'FWID' => 20, 'OPAQUE_DATA_VERSION' => 34, 'CHIP_INFO' => 35, 'FEATURE_FLAG' => 36];
    public const RIM_BASE_URL = 'https://rim.attestation.nvidia.com/v1/rim/';
    public const GH100_CRL_URLS = ['https://crl.ndis.nvidia.com/crl/l2-gh100.crl', 'https://crl.ndis.nvidia.com/crl/l1-root.crl'];
    public const GB100_CRL_URLS = ['https://crl.ndis.nvidia.com/crl/l2-gb100.crl', 'https://crl.ndis.nvidia.com/crl/l1-root.crl'];
    public const OCSP_URL = 'http://ocsp.ndis.nvidia.com/';
    public const OCSP_DEFAULT_MAX_AGE_MS = Ocsp::DEFAULT_MAX_AGE_MS;

    /** SHA-256 of a certificate's SubjectPublicKeyInfo DER, lowercase hex (the pin format of a root). Throws on an unparseable certificate. */
    public static function spkiSha256Hex(string $certPem): string
    {
        return Cert::fromPem($certPem)->spkiSha256();
    }

    /** ECDSA P-384 / SHA-384 verification of the report signature (r || s) under the device key. @param array<string,mixed> $report a parsed {@see Nvidia::parseEvidence} */
    public static function verifySpdmSignature(array $report, PubKey $devicePublicKey): bool
    {
        return Common::ecdsaVerifyRaw($devicePublicKey, $report['signature'], $report['signedBytes'], 'sha384');
    }

    /** The 32-byte SPDM challenge that carries the PCA binding: sha256(attestationBinding(expected)). Throws when the binding cannot be built. */
    public static function spdmChallenge(mixed $expected): string
    {
        return Common::challengeSha256($expected);
    }

    /**
     * NVIDIA's merge / alternatives / NVDEC0 rules for a report against the driver and VBIOS RIMs (`{golden: [{index, active, alternatives, size, hashes}]}`).
     * @param array<string,mixed> $report a parsed {@see Nvidia::parseEvidence}
     * @return array<string,mixed> `{ok: true, checked}` or `{ok: false, reason, mismatches?: [{index, source}]}`
     */
    public static function compareReportToRims(array $report, array $driver, array $vbios): array
    {
        $merged = [];
        foreach ($driver['golden'] as $g) {
            if ($g['active']) {
                $merged[$g['index']] = [$g, 'driver'];
            }
        }
        foreach ($vbios['golden'] as $g) {
            if (!$g['active']) {
                continue;
            }
            if (isset($merged[$g['index']])) {
                return ['ok' => false, 'reason' => 'driver and VBIOS RIMs both have an active measurement at index ' . $g['index']];
            }
            $merged[$g['index']] = [$g, 'vbios'];
        }
        if ($merged === []) {
            return ['ok' => false, 'reason' => 'RIMs carry no active golden measurements'];
        }
        $runtime = [];
        foreach ($report['measurements'] as $m) {
            $runtime[$m['index'] - 1] = $m['digest'];
        }
        if (count($merged) > count($runtime)) {
            return ['ok' => false, 'reason' => 'RIMs list more active measurements than the report carries'];
        }
        $nvdec = $report['opaque'][11] ?? null;
        $nvdecDisabled = $nvdec !== null && $nvdec !== '' && ord($nvdec[0]) === 0x55;
        ksort($merged);
        $mismatches = [];
        $checked = 0;
        foreach ($merged as $index => [$g, $source]) {
            if ($index + 1 === 35 && $nvdecDisabled) {
                continue;
            }
            $digest = $runtime[$index] ?? null;
            $checked++;
            if ($digest === null || strlen($digest) !== $g['size'] || !in_array(bin2hex($digest), $g['hashes'], true)) {
                $mismatches[] = ['index' => $index, 'source' => $source];
            }
        }
        if ($mismatches !== []) {
            return ['ok' => false, 'reason' => 'runtime measurements differ from the golden RIM values at ' . count($mismatches) . ' index(es)', 'mismatches' => $mismatches];
        }
        return ['ok' => true, 'checked' => $checked];
    }

    private static function transport(mixed $opts, string $who): callable
    {
        $f = Jsx::get($opts, 'fetch');
        if (!is_callable($f)) {
            throw new \RuntimeException("$who: no fetch implementation available");
        }
        return $f;
    }

    private static function okStatus(mixed $res): bool
    {
        $s = Js::num(Jsx::get($res, 'status'));
        return $s !== null && $s >= 200 && $s <= 299;
    }

    /** Fetch a RIM document from the NVIDIA RIM service and return its XML text (the response is JSON `{rim: <base64>}`). Throws on any problem. */
    public static function fetchRim(string $id, mixed $opts = null): string
    {
        $f = self::transport($opts, 'fetchNvidiaRim');
        if (preg_match('/\A[A-Za-z0-9_.-]+\z/', $id) !== 1) {
            throw new \TypeError('fetchNvidiaRim: invalid RIM id');
        }
        $base = Jsx::get($opts, 'baseUrl');
        $res = $f((is_string($base) ? $base : self::RIM_BASE_URL) . $id);
        if (!self::okStatus($res)) {
            throw new \RuntimeException('RIM fetch failed: HTTP ' . Jsx::str(Jsx::get($res, 'status')) . " for $id");
        }
        $body = Js::parse((string)Jsx::get($res, 'body'));
        $rim = Jsx::rd($body, 'rim');
        if (!is_string($rim)) {
            throw new \RuntimeException('RIM fetch: response has no rim field');
        }
        $raw = Common::nodeB64Decode($rim);
        if (preg_match('//u', $raw) === 1) {
            return $raw;
        }
        $prev = mb_substitute_character();
        mb_substitute_character(0xFFFD);
        try {
            return (string)mb_convert_encoding($raw, 'UTF-8', 'UTF-8');
        } finally {
            mb_substitute_character($prev);
        }
    }

    /** Fetch a CRL (DER bytes). Throws on any problem. */
    public static function fetchCrl(string $url, mixed $opts = null): string
    {
        $f = self::transport($opts, 'fetchNvidiaCrl');
        $res = $f($url);
        if (!self::okStatus($res)) {
            throw new \RuntimeException('CRL fetch failed: HTTP ' . Jsx::str(Jsx::get($res, 'status')) . " for $url");
        }
        return (string)Jsx::get($res, 'body');
    }

    /**
     * POST an OCSPRequest for `$cert` to NVIDIA's responder (or `opts.url`) and return `{request, response}` DER. `opts`: `{fetch, url?, nonce?}`.
     * Explicit use only. @return array{request:string,response:string}
     */
    public static function fetchOcsp(Cert $cert, Cert $issuer, mixed $opts = null): array
    {
        $f = self::transport($opts, 'fetchNvidiaOcsp');
        $nonce = Jsx::get($opts, 'nonce');
        $request = Ocsp::buildRequest($cert, $issuer, $nonce instanceof Undef || $nonce === null ? null : $nonce);
        $url = Jsx::get($opts, 'url');
        $res = $f(Jsx::truthy($url) ? (string)$url : self::OCSP_URL, Obj::of(['method' => 'POST', 'headers' => Obj::of(['content-type' => 'application/ocsp-request']), 'body' => $request]));
        if (!self::okStatus($res)) {
            throw new \RuntimeException('OCSP fetch failed: HTTP ' . Jsx::str(Jsx::get($res, 'status')));
        }
        return ['request' => $request, 'response' => (string)Jsx::get($res, 'body')];
    }
}
