<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Amd.php';
require_once __DIR__ . '/Cert.php';
require_once __DIR__ . '/Der.php';

/**
 * The pure helpers of the AMD SEV-SNP verifier that need neither AMD hardware nor a certificate chain: the full report parser (1184
 * bytes, little-endian), the P-384 key and signature helpers, the default identity derivation, the PEM splitter, the certificate
 * helpers over a VCEK, and the KDS VCEK fetch over an INJECTED transport (the library carries no HTTP client).
 */
final class SevSnp
{
    public const SIG_ALGO_ECDSA_P384_SHA384 = 1;
    public const POLICY_DEBUG_BIT = 524288;
    public const DEFAULT_KDS_BASE = 'https://kdsintf.amd.com/vcek/v1';
    private const P384_P = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF';
    private const P384_B = 'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF';
    private const P384_N = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973';

    /** The pinned AMD Milan ARK: the SHA-384 of its DER SubjectPublicKeyInfo. */
    public static function milanArkSpkiSha384(): string
    {
        return Amd::ARK_SPKI_SHA384['milan'];
    }

    public static function toHex(string $b): string
    {
        return bin2hex($b);
    }

    /** The individual `-----BEGIN CERTIFICATE-----` blocks of a PEM bundle, text unchanged. @return list<string> */
    public static function splitPemCertificates(string $pem): array
    {
        preg_match_all('/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/', $pem, $m);
        return $m[0];
    }

    private static function u64(string $b, int $o): \GMP
    {
        return gmp_init(bin2hex(strrev(substr($b, $o, 8))), 16);
    }

    private static function u32(string $b, int $o): int
    {
        return (int)unpack('V', substr($b, $o, 4))[1];
    }

    /**
     * Every field of the report (`bytes` raw, u64 fields as GMP): the keys of {@see Amd::parseReport} plus family and image ids, platform info,
     * the key digests, report ids, CPUID, firmware versions, mitigation vectors, `signature`, and `raw`. Throws below 0x2e8 + 72 bytes.
     * @return array<string,mixed>
     */
    public static function parseReport(string $b): array
    {
        $r = Amd::parseReport($b);
        return $r + ['family_id' => substr($b, 0x10, 16), 'image_id' => substr($b, 0x20, 16), 'platform_info' => self::u64($b, 0x40),
            'id_key_digest' => substr($b, 0xE0, 48), 'author_key_digest' => substr($b, 0x110, 48), 'report_id' => substr($b, 0x140, 32), 'report_id_ma' => substr($b, 0x160, 32),
            'cpuid_fam_id' => ord($b[0x188]), 'cpuid_mod_id' => ord($b[0x189]), 'cpuid_step' => ord($b[0x18A]),
            'current_version' => ['major' => ord($b[0x1EA]), 'minor' => ord($b[0x1E9]), 'build' => ord($b[0x1E8])],
            'committed_version' => ['major' => ord($b[0x1EE]), 'minor' => ord($b[0x1ED]), 'build' => ord($b[0x1EC])],
            'launch_mit_vector' => self::u64($b, 0x1F8), 'current_mit_vector' => self::u64($b, 0x200),
            'signature' => ['r' => substr($b, 0x2A0, 72), 's' => substr($b, 0x2E8, 72)], 'raw' => $b];
    }

    /** The uncompressed 97-byte SEC1 point of a P-384 key given as an uncompressed (97) or compressed (49) SEC1 point; throws off the curve. */
    public static function ecdsaP384PublicKey(string $sec1): string
    {
        $n = strlen($sec1);
        if ($n === 49 && ($sec1[0] === "\x02" || $sec1[0] === "\x03")) {
            $p = gmp_init(self::P384_P, 16);
            $x = gmp_init(bin2hex(substr($sec1, 1)), 16);
            if (gmp_cmp($x, $p) >= 0) {
                throw new \ValueError('ecdsaP384PublicKey: x is out of range');
            }
            $rhs = gmp_mod(gmp_add(gmp_sub(gmp_powm($x, 3, $p), gmp_mul(3, $x)), gmp_init(self::P384_B, 16)), $p);
            $y = gmp_powm($rhs, gmp_div_q(gmp_add($p, 1), 4), $p);
            if (gmp_cmp(gmp_mod(gmp_mul($y, $y), $p), $rhs) !== 0) {
                throw new \ValueError('ecdsaP384PublicKey: the point is not on the curve');
            }
            if ((gmp_intval(gmp_and($y, 1)) === 1) !== ($sec1[0] === "\x03")) {
                $y = gmp_sub($p, $y);
            }
            $sec1 = "\x04" . substr($sec1, 1) . str_pad(hex2bin(str_pad(gmp_strval($y, 16), 96, '0', STR_PAD_LEFT)), 48, "\0", STR_PAD_LEFT);
        } elseif ($n !== 97 || $sec1[0] !== "\x04") {
            throw new \ValueError('ecdsaP384PublicKey: not a SEC1 point');
        }
        Common::ecKeyFromPoint('P-384', $sec1); // throws \ValueError off the curve
        return $sec1;
    }

    /** AMD's little-endian r and s (72-byte fields) as the 96-byte big-endian r || s; throws when either is zero or not below the group order. */
    public static function signatureToCompact(string $r, string $s): string
    {
        $n = gmp_init(self::P384_N, 16);
        $be = static function (string $le) use ($n): string {
            $v = gmp_init(bin2hex(strrev($le)) ?: '0', 16);
            if (gmp_cmp($v, 0) <= 0 || gmp_cmp($v, $n) >= 0) {
                throw new \RangeException('sev-snp signature: scalar out of range');
            }
            return hex2bin(str_pad(gmp_strval($v, 16), 96, '0', STR_PAD_LEFT));
        };
        return $be($r) . $be($s);
    }

    /** The default report to measured-identity mapping; `weightsFromHostData` is the INSECURE host-asserted opt-in. @param array<string,mixed> $report @return array<string,mixed> */
    public static function deriveIdentity(array $report, bool $weightsFromHostData): array
    {
        return ['model_id' => '', 'weights_digest' => $weightsFromHostData ? bin2hex($report['host_data']) : '', 'weights_measured' => false,
            'runtime_measurement' => bin2hex($report['measurement']), 'operator' => bin2hex($report['chip_id'])];
    }

    /** The tbsCertificate bytes of a DER certificate; throws on a non-SEQUENCE or trailing bytes. */
    public static function extractTbsCertificate(string $certDer): string
    {
        return Der::tbsOfCertificate($certDer);
    }

    /** @return array{point:string,tbs:string} the VCEK's P-384 point (uncompressed SEC1) and tbsCertificate; throws unless the key is EC secp384r1 */
    public static function extractVcekPublicKey(string $certDer): array
    {
        // the reference wraps the bytes as PEM: anything that is not a complete DER element is the PEM "no start line" refusal
        $noStart = new CertError('error:0480006C:PEM routines::no start line', 'ERR_OSSL_PEM_NO_START_LINE');
        if ($certDer === '' || $certDer[0] !== "\x30") {
            throw $noStart;
        }
        try {
            Der::tlvLenient($certDer, 0);
        } catch (DerError) {
            throw $noStart;
        }
        try {
            $cert = new Cert($certDer);
            $k = Common::loadPublicKey($cert->spkiDer);
        } catch (CertError $e) { // a complete element that is not a certificate is the same refusal; only the trailing-bytes check has its own text
            throw str_contains($e->getMessage(), 'trailing bytes') ? $e : $noStart;
        }
        if ($k->type !== 'ec' || $k->curve !== 'secp384r1') {
            throw new \TypeError('VCEK is not EC secp384r1 (got ' . $k->type . '/' . ($k->curve ?? 'none') . ')');
        }
        return ['point' => Common::ecPoint($k, 'P-384'), 'tbs' => self::extractTbsCertificate($certDer)];
    }

    /**
     * Fetch the VCEK certificate of a chip and TCB from the AMD KDS over `$opts['fetch']` (a callable `(string $url): array{ok:bool,status:int,body:string}`;
     * there is no default transport). `$reportedTcb` is the raw REPORTED_TCB (bootloader byte 0, TEE 1, SNP 6, microcode 7); `$opts['product']`
     * defaults to Milan. Throws on a non-2xx answer or when no transport is given.
     * @param \GMP|int $reportedTcb @param array<string,mixed> $opts
     */
    public static function fetchVcek(string $chipId, \GMP|int $reportedTcb, array $opts = []): string
    {
        $product = $opts['product'] ?? 'Milan';
        $base = $opts['baseUrl'] ?? self::DEFAULT_KDS_BASE;
        $f = $opts['fetch'] ?? null;
        if (!is_callable($f)) {
            throw new \RuntimeException('fetchVcekFromKds: no fetch implementation available');
        }
        $t = is_int($reportedTcb) ? gmp_init($reportedTcb) : $reportedTcb;
        $byteAt = static fn(int $i): int => (int)gmp_intval(gmp_and(gmp_div_q($t, gmp_pow(2, 8 * $i)), 255));
        $url = $base . '/' . $product . '/' . bin2hex($chipId) . '?blSPL=' . $byteAt(0) . '&teeSPL=' . $byteAt(1) . '&snpSPL=' . $byteAt(6) . '&ucodeSPL=' . $byteAt(7);
        $res = $f($url);
        if (!($res['ok'] ?? false)) {
            throw new \RuntimeException('KDS VCEK fetch failed: HTTP ' . ($res['status'] ?? 0) . " for $url");
        }
        return (string)$res['body'];
    }
}
