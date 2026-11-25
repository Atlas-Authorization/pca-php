<?php

declare(strict_types=1);

namespace Atlas\Pca;

use Atlas\Pca\Attest\Amd;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Gcp;
use Atlas\Pca\Attest\Intel;
use Atlas\Pca\Attest\Maa;

/**
 * The public facade of the vendor attestation modules under the reference's function names: the Intel TDX / DCAP quote and report parsers, the PCK chain and
 * genuine-quote checks, the PCS collateral verification, the Azure runtime-data binding, the Azure MAA and Google Confidential Space JWT parsers, chain checks
 * and JWKS fetchers over an injected transport, and the suite / pin constants. Bytes are raw PHP strings; an object argument is an {@see Obj} or an associative
 * array; a result is an associative array shaped as the reference's. Nothing here verifies beyond what the vendor modules do: each method adapts one of them.
 */
final class AttestVendors
{
    /** @return array<string,mixed> */
    public static function constants(): array
    {
        return [
            'INTEL_DCAP_SUITE' => Intel::SUITE, 'AZURE_MAA_SUITE' => Maa::SUITE, 'AZURE_MAA_SUITES' => Maa::SUITES, 'GCP_CS_SUITE' => Gcp::SUITE,
            'GCP_CS_SUITES' => Gcp::SUITES, 'GCP_CS_DEFAULT_ISSUER' => Gcp::DEFAULT_ISSUER, 'INTEL_SGX_ROOT_CA_SPKI_SHA256' => Intel::SGX_ROOT_CA_SPKI_SHA256,
            'AMD_SNP_SUITE' => Amd::SUITE, 'AMD_ARK_SPKI_SHA384' => Amd::ARK_SPKI_SHA384, 'DEFAULT_ACCEPTED_STATUSES' => Intel::DEFAULT_ACCEPTED,
        ];
    }

    public static function toHex(string $bytes): string
    {
        return Common::toHex($bytes);
    }

    /** The DER of the FIRST certificate block of a PEM text; throws when there is none. */
    public static function pemToDer(string $pem): string
    {
        return Common::pemToDer($pem);
    }

    /** @return array{point:string} the 65-byte uncompressed SEC1 point of a P-256 key (a compressed point is expanded); throws off the curve */
    public static function ecdsaP256PublicKey(string $sec1): array
    {
        return ['point' => Common::ecPoint(Intel::ecdsaP256PublicKey($sec1), 'P-256')];
    }

    /** The TD report fields past what the vendor parser keeps (the fixed TDX 1.0 report layout). */
    private static function fullReport(string $body, array $parsed): array
    {
        return $parsed + ['mrConfigId' => substr($body, 184, 48), 'rtmr1' => substr($body, 376, 48), 'rtmr2' => substr($body, 424, 48),
            'rtmr3' => substr($body, 472, 48), 'raw' => substr($body, 0, 584)];
    }

    /** @return array<string,string> */
    public static function parseDcapTdReport(string $body): array
    {
        return self::fullReport($body, Intel::parseTdReport($body));
    }

    /** @return array<string,mixed> */
    public static function parseDcapQuote(string $quote): array
    {
        $q = Intel::parseQuote($quote);
        return $q + ['version' => (int)unpack('v', substr($quote, 0, 2))[1], 'attKeyType' => (int)unpack('v', substr($quote, 2, 2))[1],
            'teeType' => (int)unpack('V', substr($quote, 4, 4))[1]];
    }

    /** @return array{fmspc:string,sgxTcbComponents:string,pcesvn:int,cpusvn:string} */
    public static function extractPckFmspcAndTcb(string $leafDer): array
    {
        return Intel::extractPckFmspcAndTcb($leafDer);
    }

    private static function anchorOf(mixed $args): ?string
    {
        $a = Common::g($args, 'trustAnchorRootCaSpkiSha256');
        return is_string($a) ? $a : null;
    }

    /** @param mixed $args {pckChainPem, trustAnchorRootCaSpkiSha256?, nowMs} @return array<string,mixed> */
    public static function verifyIntelPckChainX509(mixed $args): array
    {
        $r = Intel::verifyPckChain(Common::g($args, 'pckChainPem'), self::anchorOf($args), Common::g($args, 'nowMs'));
        if ($r['ok'] !== true) {
            return array_intersect_key($r, ['ok' => 0, 'reason' => 0, 'failure' => 0]);
        }
        return ['ok' => true, 'leafKey' => ['point' => Common::ecPoint($r['leafKey'], 'P-256')], 'leafDer' => $r['leafDer'], 'depth' => $r['depth']];
    }

    /** @param mixed $args {quote, trustAnchorRootCaSpkiSha256?, expected?, policy?, nowMs} @return array<string,mixed> */
    public static function verifyGenuineTdxQuote(mixed $args): array
    {
        $quote = (string)Common::g($args, 'quote');
        $policy = Common::g($args, 'policy');
        $r = Intel::verifyGenuineQuote($quote, self::anchorOf($args), Common::g($args, 'expected'), Common::isObj($policy) ? Common::members($policy) : null, Common::g($args, 'nowMs'));
        if ($r['ok'] !== true) {
            return ['ok' => false, 'reason' => $r['reason']];
        }
        $q = Intel::parseQuote($quote);
        $r['report'] = self::fullReport($q['tdReportBody'], $r['report']);
        $r['pckTcb'] += ['cpusvn' => $r['pckTcb']['sgxTcbComponents']];
        $r['akPub'] = ['point' => "\x04" . $q['akPubRaw']];
        return $r;
    }

    /** @return array<string,mixed> {ok, revoked: sorted lowercase hex serials without leading zeros} or {ok: false, reason} */
    public static function verifyCrl(string $crlDer, string $spkiDer, float $nowMs): array
    {
        $r = Intel::verifyCrl($crlDer, Common::loadPublicKey($spkiDer), $nowMs);
        if ($r['ok'] !== true) {
            return $r;
        }
        $serials = array_map('strval', array_keys($r['revoked']));
        sort($serials, SORT_STRING);
        return ['ok' => true, 'revoked' => $serials];
    }

    /** @param list<string> $revoked the serials a verifyCrl result carries */
    public static function serialIsRevoked(array $revoked, string $serialHex): bool
    {
        return Intel::serialIsRevoked(array_fill_keys($revoked, true), $serialHex);
    }

    /** @return array<string,mixed> {body} or {error}: the named object's exact source bytes signed ECDSA P-256 / SHA-256 (r||s) under the key */
    public static function verifySignedJson(string $text, string $name, string $spkiDer): array
    {
        return Intel::verifySignedJson($text, $name, Common::loadPublicKey($spkiDer));
    }

    public static function decodeIssuerChainHeader(string $value): string
    {
        return Intel::decodeIssuerChainHeader($value);
    }

    /**
     * The quote, then its PCS collateral at `nowMs`.
     * @param mixed $args {quote, collateral, nowMs, policy?, trustAnchorRootCaSpkiSha256?, allowDebug?}
     * @return array<string,mixed>
     */
    public static function verifyIntelTdxCollateral(mixed $args): array
    {
        $collateral = Common::g($args, 'collateral');
        $policy = Common::g($args, 'policy');
        $detail = null;
        $r = Intel::verifyCollateral((string)Common::g($args, 'quote'), Common::isObj($collateral) ? Common::members($collateral) : [], (float)Common::numOf(Common::g($args, 'nowMs')),
            Common::isObj($policy) ? Common::members($policy) : null, self::anchorOf($args), Common::g($args, 'allowDebug') === true, $detail);
        return $detail === null ? $r : $r + $detail;
    }

    /** The failure reason of an Azure runtime-data binding, or null. */
    public static function checkAzureRuntimeDataBinding(string $reportData, string $runtimeData, mixed $expected): ?string
    {
        return Amd::checkAzureRuntimeDataBinding($reportData, $runtimeData, $expected);
    }

    /** @return array<string,mixed> {header, payload, signingInput, signature}: verifies nothing; throws on a structural violation */
    public static function parseMaaJwt(mixed $token): array
    {
        return Maa::parseJwt($token);
    }

    /** @return array<string,mixed> */
    public static function parseGcpCsJwt(mixed $token): array
    {
        return Gcp::parseJwt($token);
    }

    private static function skewOf(mixed $opts, string $key): float
    {
        $v = Common::numOf(Common::g($opts, $key));
        return $v ?? 0.0;
    }

    /** @return array<string,mixed> {ok, reason?, leafDer?, leafSpkiSha256?} @param mixed $opts {nowMs, clockSkewMs?} */
    public static function verifyX5cChain(mixed $x5c, mixed $anchors, mixed $opts): array
    {
        $r = Maa::verifyX5cChain($x5c, $anchors, (float)Common::numOf(Common::g($opts, 'nowMs')), self::skewOf($opts, 'clockSkewMs'));
        if ($r['ok'] !== true) {
            return ['ok' => false, 'reason' => $r['reason']];
        }
        return ['ok' => true, 'leafDer' => $r['leaf']->raw, 'leafSpkiSha256' => Common::spkiSha($r['leaf']->publicKey(), 'sha256')];
    }

    /** The failure reason of a JWK x5c chain, or null. @param mixed $opts {nowMs, skewMs} */
    public static function verifyJwkX5cChain(mixed $x5c, mixed $anchors, mixed $opts): ?string
    {
        return Gcp::verifyJwkX5cChain($x5c, $anchors, (float)Common::numOf(Common::g($opts, 'nowMs')), self::skewOf($opts, 'skewMs'));
    }

    public static function teeTypeOfHwModel(string $hwmodel): ?string
    {
        return Gcp::teeTypeOfHwmodel($hwmodel);
    }

    /** The MAA JWKS over `opts.fetch` (`fn(url): {status, body}`) and `certsPath?`; throws on a failed fetch or a body without a keys array. */
    public static function fetchMaaJwks(string $issuer, mixed $opts = null): Obj
    {
        return Maa::fetchJwks($issuer, $opts);
    }

    /** The Confidential Space JWKS over `opts.fetch` and `jwksUri?` (resolved from the issuer's OpenID configuration when absent). */
    public static function fetchGcpConfidentialSpaceJwks(string $issuer, mixed $opts = null): Obj
    {
        return Gcp::fetchJwks($issuer, $opts);
    }
}
