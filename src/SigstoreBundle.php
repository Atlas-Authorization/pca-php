<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/ProvenanceGate.php';
require_once __DIR__ . '/Attest/Common.php';
require_once __DIR__ . '/Attest/Der.php';
require_once __DIR__ . '/Attest/Cert.php';
require_once __DIR__ . '/Attest/JsJson.php';

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\PubKey;

/** Internal: a refusal raised inside the verifier (caught and reported with the current stage). */
final class SigstoreFail extends \RuntimeException
{
}

/**
 * Offline Sigstore bundle verification for build provenance (track K9): a port of packages/pca-attest-eat/src/sigstore.ts.
 *
 * Verifies a Sigstore bundle (v0.2 / v0.3) carrying a DSSE in-toto Statement against a pinned trusted_root.json, with no
 * network access. Same order and refusal codes as the reference: RFC 3161 timestamps and the Rekor v1 SET first, then the
 * Rekor entry (v1 dsse 0.0.1 / intoto 0.0.2, v2 hashedrekord 0.0.2), RFC 9162 inclusion and the signed-note checkpoint, the
 * Fulcio path at every verified time, the embedded SCT, the entry body, the DSSE signature, identity and the Statement. There
 * is no PHP Sigstore library; this uses the openssl extension (ECDSA, RSA) and sodium (Ed25519).
 *
 *   $roots = SigstoreBundle::parseTrustedRoot(Json::parseLax($trustedRootJson));
 *   $r = SigstoreBundle::verify(Json::parseLax($bundleJson), $roots); // ['ok' => true, 'facts' => Obj] | ['ok' => false, 'code', 'detail']
 *   if ($r['ok']) { ProvenanceGate::gate(Obj::of(['facts' => $r['facts'], 'policy' => $policy])); }
 *
 * Values are the SDK's JSON model (Obj, list arrays, strings, Num) or plain assoc arrays. Never throws on a bundle.
 */
final class SigstoreBundle
{
    public const MEDIA_TYPES = ['application/vnd.dev.sigstore.bundle+json;version=0.2', 'application/vnd.dev.sigstore.bundle+json;version=0.3',
        'application/vnd.dev.sigstore.bundle.v0.3+json'];
    public const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
    private const OID_FULCIO = '1.3.6.1.4.1.57264.1.';
    private const OID_SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';
    private const OID_SAN = '2.5.29.17';
    private const OID_EKU = '2.5.29.37';
    private const EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';
    private const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
    private const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    private const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
    private const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
    private const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
    private const DIGEST_OIDS = ['2.16.840.1.101.3.4.2.1' => 'sha256', '2.16.840.1.101.3.4.2.2' => 'sha384', '2.16.840.1.101.3.4.2.3' => 'sha512'];
    private const MAX_SAFE = 9007199254740991;

    private static function fail(string $m): never
    {
        throw new SigstoreFail($m);
    }

    private static function isObj(mixed $v): bool
    {
        return Common::isObj($v);
    }

    private static function g(mixed $v, string $k): mixed
    {
        return Common::g($v, $k);
    }

    private static function b64(mixed $s): string
    {
        if (!is_string($s) || preg_match('#\A[A-Za-z0-9+/]*={0,2}\z#', $s) !== 1 || strlen($s) % 4 !== 0) {
            self::fail('not base64');
        }
        $d = base64_decode($s, false);
        return $d === false ? self::fail('not base64') : $d;
    }

    private static function dateMs(string $s): ?int
    {
        if (preg_match('/\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})\z/', $s, $m) !== 1) {
            return null;
        }
        [$y, $mo, $d, $h, $mi, $se] = array_map('intval', array_slice($m, 1, 6));
        if ($mo < 1 || $mo > 12 || $d < 1 || $d > Der::daysInMonth($y, $mo) || $h > 23 || $mi > 59 || $se > 59) {
            return null;
        }
        $off = $m[8] === 'Z' ? 0 : ($m[8][0] === '-' ? -1 : 1) * ((int)substr($m[8], 1, 2) * 60 + (int)substr($m[8], 4, 2)) * 60000;
        $frac = (int)str_pad(substr($m[7] !== '' ? $m[7] : '0', 0, 3), 3, '0');
        return ((Der::daysFromCivil($y, $mo, $d) * 24 + $h) * 60 + $mi) * 60000 + $se * 1000 + $frac - $off;
    }

    /** @return array{0: int, 1: int|float} [start, end] in epoch ms (end INF when open) */
    private static function validity(mixed $v): array
    {
        $st = self::g($v, 'start');
        $s = is_string($st) ? self::dateMs($st) : null;
        if ($s === null) {
            self::fail('validFor.start missing');
        }
        $e = INF;
        $en = self::g($v, 'end');
        if (is_string($en)) {
            $e = self::dateMs($en) ?? self::fail('validFor.end malformed');
        }
        return [$s, $e];
    }

    private static function enc(int $tag, string $content): string
    {
        return chr($tag) . Common::derLen(strlen($content)) . $content;
    }

    /** A log key: ECDSA P-256 (id = SHA-256(SPKI)), PKCS#1 RSA (CT only), Ed25519 (Rekor v2, id = signed-note key hash). */
    private static function pinnedLog(mixed $t, bool $transparency): ?array
    {
        $pk = self::g($t, 'publicKey');
        if (!self::isObj($t) || !self::isObj($pk) || !self::isObj(self::g($t, 'logId'))) {
            self::fail('log entry malformed');
        }
        $der = self::b64(self::g($pk, 'rawBytes'));
        $keyId = self::b64(self::g(self::g($t, 'logId'), 'keyId'));
        $valid = self::validity(self::g($pk, 'validFor'));
        switch (self::g($pk, 'keyDetails')) {
            case 'PKIX_ECDSA_P256_SHA_256':
                if (hash('sha256', $der, true) !== $keyId) {
                    self::fail('log id is not the SHA-256 of its key');
                }
                return ['keyId' => $keyId, 'key' => Common::loadPublicKey($der), 'valid' => $valid, 'v2' => null];
            case 'PKCS1_RSA_PKCS1V5':
                if ($transparency) {
                    return null;
                }
                $spki = self::enc(0x30, hex2bin('300d06092a864886f70d0101010500') . self::enc(0x03, "\x00" . $der));
                $key = Common::loadPublicKey($spki);
                if (hash('sha256', $spki, true) !== $keyId) {
                    self::fail('log id is not the SHA-256 of its key');
                }
                return ['keyId' => $keyId, 'key' => $key, 'valid' => $valid, 'v2' => null];
            case 'PKIX_ED25519':
                if (!$transparency) {
                    return null;
                }
                // an Ed25519 SPKI is a fixed 12-byte header and the 32-byte key
                if (strlen($der) !== 44 || substr($der, 0, 12) !== hex2bin('302a300506032b6570032100')) {
                    self::fail('not an Ed25519 key');
                }
                $raw = substr($der, 12);
                $url = self::g($t, 'baseUrl');
                $host = is_string($url) ? parse_url($url, PHP_URL_HOST) : null;
                $name = is_string($host) ? strtolower($host) : '';
                if ($name === '' || hash('sha256', "$name\n\x01" . $raw, true) !== $keyId) {
                    self::fail('log id is not the signed-note key hash of its key');
                }
                return ['keyId' => $keyId, 'key' => $raw, 'valid' => $valid, 'v2' => $name];
            default:
                return null;
        }
    }

    private static function pinnedChain(mixed $c): array
    {
        $certs = self::g(self::g($c, 'certChain'), 'certificates');
        if (!is_array($certs) || !array_is_list($certs) || $certs === []) {
            self::fail('certificate authority entry malformed');
        }
        return ['chain' => array_map(static fn($x) => new Cert(self::b64(self::g($x, 'rawBytes'))), $certs), 'valid' => self::validity(self::g($c, 'validFor'))];
    }

    /**
     * Parse a Sigstore trusted_root.json (v0.1): transparency logs, CT logs, Fulcio CAs and timestamp authorities. Throws
     * \InvalidArgumentException on anything malformed. A root with no CT log means its owner does not require SCTs.
     * @return array{tlogs: list<array>, ctlogs: list<array>, cas: list<array>, tsas: list<array>}
     */
    public static function parseTrustedRoot(mixed $doc): array
    {
        try {
            if (!self::isObj($doc) || self::g($doc, 'mediaType') !== 'application/vnd.dev.sigstore.trustedroot+json;version=0.1') {
                self::fail('not a trusted root v0.1');
            }
            $arr = static function (string $k) use ($doc): array {
                $v = self::g($doc, $k);
                return is_array($v) && array_is_list($v) ? $v : [];
            };
            $tlogs = array_values(array_filter(array_map(static fn($t) => self::pinnedLog($t, true), $arr('tlogs'))));
            $ctlogs = array_values(array_filter(array_map(static fn($t) => self::pinnedLog($t, false), $arr('ctlogs'))));
            $cas = array_map([self::class, 'pinnedChain'], $arr('certificateAuthorities'));
            $tsas = array_map([self::class, 'pinnedChain'], $arr('timestampAuthorities'));
            if ($tlogs === [] || $cas === []) {
                self::fail('a trusted root needs a transparency log and a CA');
            }
            return ['tlogs' => $tlogs, 'ctlogs' => $ctlogs, 'cas' => $cas, 'tsas' => $tsas];
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException($e->getMessage(), 0, $e);
        }
    }

    // ---------------------------------------------------------------------------------------------- DER (as the reference)

    /** @return array{0: int, 1: int, 2: int, 3: int} [tag, start, body, end] */
    private static function tlv(string $b, int $off, ?int $limit = null): array
    {
        $limit ??= strlen($b);
        if ($off + 2 > $limit) {
            self::fail('DER truncated');
        }
        $tag = ord($b[$off]);
        if (($tag & 0x1f) === 0x1f) {
            self::fail('DER multi-byte tag');
        }
        $len = ord($b[$off + 1]);
        $body = $off + 2;
        if ($len & 0x80) {
            $n = $len & 0x7f;
            if ($n === 0 || $n > 4 || $body + $n > $limit) {
                self::fail('DER length');
            }
            $len = 0;
            for ($i = 0; $i < $n; $i++) {
                $len = $len * 256 + ord($b[$body + $i]);
            }
            $body += $n;
        }
        if ($body + $len > $limit) {
            self::fail('DER overrun');
        }
        return [$tag, $off, $body, $body + $len];
    }

    /** @return list<array{0: int, 1: int, 2: int, 3: int}> */
    private static function kids(string $b, ?array $t): array
    {
        if ($t === null) {
            self::fail('DER element missing');
        }
        $out = [];
        for ($o = $t[2]; $o < $t[3];) {
            $c = self::tlv($b, $o, $t[3]);
            $out[] = $c;
            $o = $c[3];
        }
        return $out;
    }

    private static function oid(string $b, ?array $t): string
    {
        if ($t === null || $t[0] !== 0x06 || $t[3] <= $t[2]) {
            self::fail('not an OID');
        }
        $parts = [];
        $v = 0;
        for ($i = $t[2]; $i < $t[3]; $i++) {
            $x = ord($b[$i]);
            $v = $v * 128 + ($x & 0x7f);
            if (($x & 0x80) === 0) {
                $parts[] = $v;
                $v = 0;
            }
        }
        if ($parts === []) {
            self::fail('not an OID');
        }
        $first = array_shift($parts);
        $a = min(2, intdiv($first, 40));
        return implode('.', array_merge([$a, $first - $a * 40], $parts));
    }

    private static function body(string $b, array $t): string
    {
        return substr($b, $t[2], $t[3] - $t[2]);
    }

    private static function span(string $b, array $t): string
    {
        return substr($b, $t[1], $t[3] - $t[1]);
    }

    private static function utf8Strict(string $b): string
    {
        if (preg_match('//u', $b) !== 1) {
            self::fail('not UTF-8');
        }
        return str_starts_with($b, "\xEF\xBB\xBF") ? substr($b, 3) : $b;
    }

    private static function utf8Lossy(string $b): string
    {
        return preg_match('//u', $b) === 1 ? $b : (string)mb_convert_encoding($b, 'UTF-8', 'UTF-8');
    }

    /** @return array{der: string, tbsKids: list<array>, wrapper: array, exts: list<array{oid: string, value: string, tlv: array}>} */
    private static function parseCert(string $der): array
    {
        $cert = self::tlv($der, 0);
        if ($cert[0] !== 0x30 || $cert[3] !== strlen($der)) {
            self::fail('certificate is not one SEQUENCE');
        }
        $tbs = self::kids($der, $cert)[0] ?? null;
        if ($tbs === null || $tbs[0] !== 0x30) {
            self::fail('no TBSCertificate');
        }
        $tbsKids = self::kids($der, $tbs);
        $wrapper = null;
        foreach ($tbsKids as $k) {
            if ($k[0] === 0xa3) {
                $wrapper = $k;
                break;
            }
        }
        if ($wrapper === null) {
            self::fail('no extensions');
        }
        $seq = self::kids($der, $wrapper)[0] ?? null;
        if ($seq === null || $seq[0] !== 0x30) {
            self::fail('extensions malformed');
        }
        $exts = [];
        $seen = [];
        foreach (self::kids($der, $seq) as $e) {
            $parts = self::kids($der, $e);
            $oct = $parts[count($parts) - 1] ?? null;
            if ($oct === null || $oct[0] !== 0x04) {
                self::fail('extension value is not an OCTET STRING');
            }
            $o = self::oid($der, $parts[0]);
            if (isset($seen[$o])) {
                self::fail("duplicate extension $o");
            }
            $seen[$o] = true;
            $exts[] = ['oid' => $o, 'value' => self::body($der, $oct), 'tlv' => $e];
        }
        return ['der' => $der, 'tbsKids' => $tbsKids, 'wrapper' => $wrapper, 'exts' => $exts];
    }

    private static function ext(array $c, string $oid): ?array
    {
        foreach ($c['exts'] as $x) {
            if ($x['oid'] === $oid) {
                return $x;
            }
        }
        return null;
    }

    /** Fulcio extension .1.n: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8. */
    private static function fulcioExt(array $c, int $n): ?string
    {
        $e = self::ext($c, self::OID_FULCIO . $n);
        if ($e === null) {
            return null;
        }
        if ($n <= 6) {
            return self::utf8Strict($e['value']);
        }
        $t = self::tlv($e['value'], 0);
        if ($t[0] !== 0x0c || $t[3] !== strlen($e['value'])) {
            self::fail("extension .1.$n is not a DER UTF8String");
        }
        return self::utf8Strict(self::body($e['value'], $t));
    }

    /** Exactly one SAN, a URI or an email. */
    private static function sanIdentity(array $c): string
    {
        $e = self::ext($c, self::OID_SAN) ?? self::fail('no subjectAltName');
        $seq = self::tlv($e['value'], 0);
        $names = self::kids($e['value'], $seq);
        if ($seq[0] !== 0x30 || count($names) !== 1) {
            self::fail('subjectAltName must hold exactly one name');
        }
        if ($names[0][0] !== 0x86 && $names[0][0] !== 0x81) {
            self::fail('subjectAltName must be a URI or an email');
        }
        return self::utf8Strict(self::body($e['value'], $names[0]));
    }

    /** node's X509Certificate.keyUsage: the extended key usage OIDs. @return list<string> */
    private static function eku(Cert $c): array
    {
        $e = $c->extensions()[self::OID_EKU] ?? null;
        if ($e === null) {
            return [];
        }
        return array_map(static fn($k) => self::oid($e->value, $k), self::kids($e->value, self::tlv($e->value, 0)));
    }

    private static function inside(Cert $c, int|float $at): bool
    {
        [$lo, $hi] = Der::derValidityMs($c->raw);
        return $lo !== null && $hi !== null && $lo <= $at && $at <= $hi;
    }

    /** Leaf first, self-signed root last: issuer links, signatures, CA flags; every certificate valid at `$at`. */
    private static function chainOk(array $chain, int|float $at): bool
    {
        foreach ($chain as $i => $c) {
            $up = $chain[$i + 1] ?? $c;
            if (!$c->checkIssued($up) || !$c->verify($up->publicKey()) || !self::inside($c, $at)) {
                return false;
            }
            if ($i > 0 && !$c->ca()) {
                return false;
            }
        }
        return true;
    }

    /** node's crypto.verify: ECDSA (DER), RSA PKCS#1 v1.5, or Ed25519 (a raw 32-byte key) when `$hash` is null. */
    private static function verifySig(?string $hash, string $data, PubKey|string $key, string $sig): bool
    {
        try {
            if ($hash === null) {
                return is_string($key) && strlen($key) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES && strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES
                    && sodium_crypto_sign_verify_detached($sig, $data, $key);
            }
            if (!($key instanceof PubKey)) {
                return false;
            }
            return match ($key->type) {
                'ec' => Common::ecdsaVerifyDer($key, $sig, $data, $hash),
                'rsa' => Common::rsaPkcs1Verify($key, $sig, $data, $hash),
                default => false,
            };
        } catch (\Throwable) {
            return false;
        }
    }

    // ---------------------------------------------------------------------------------------------- SCT (RFC 6962 3.2)

    private static function verifySct(array $leaf, Cert $issuer, array $roots): ?string
    {
        $e = self::ext($leaf, self::OID_SCT_LIST);
        if ($e === null) {
            return 'no embedded SCT';
        }
        $outer = self::tlv($e['value'], 0);
        if ($outer[0] !== 0x04) {
            return 'SCT list is not an OCTET STRING';
        }
        $list = self::body($e['value'], $outer);
        $ll = strlen($list);
        if ($ll < 2 || unpack('n', $list)[1] !== $ll - 2) {
            return 'SCT list length';
        }
        $der = $leaf['der'];
        $extSeq = self::kids($der, $leaf['wrapper'])[0];
        $kept = '';
        foreach (self::kids($der, $extSeq) as $k) {
            if ($k[1] !== $e['tlv'][1]) {
                $kept .= self::span($der, $k);
            }
        }
        $tbsBody = '';
        foreach ($leaf['tbsKids'] as $k) {
            $tbsBody .= $k === $leaf['wrapper'] ? self::enc(0xa3, self::enc(0x30, $kept)) : self::span($der, $k);
        }
        $tbs = self::enc(0x30, $tbsBody);
        $issuerKeyHash = hash('sha256', $issuer->spkiDer, true);
        $why = 'no SCT from a pinned CT log';
        for ($o = 2; $o < $ll;) {
            if ($o + 2 > $ll) {
                return 'SCT truncated';
            }
            $n = unpack('n', $list, $o)[1];
            $s = (string)substr($list, $o + 2, $n);
            $o += 2 + $n;
            if (strlen($s) !== $n || $n < 47) {
                return 'SCT truncated';
            }
            if (ord($s[0]) !== 0) {
                continue;
            }
            $logId = substr($s, 1, 32);
            $tsBytes = substr($s, 33, 8);
            $ts = unpack('J', $tsBytes)[1];
            $extLen = unpack('n', $s, 41)[1];
            $ext = (string)substr($s, 43, $extLen);
            $p = 43 + $extLen;
            if ($p + 4 > $n) {
                return 'SCT truncated';
            }
            $hashAlg = ord($s[$p]);
            $sigAlg = ord($s[$p + 1]);
            $sigLen = unpack('n', $s, $p + 2)[1];
            $sig = (string)substr($s, $p + 4, $sigLen);
            $p += 4 + $sigLen;
            if ($p !== $n || strlen($sig) !== $sigLen) {
                return 'SCT malformed';
            }
            $log = null;
            foreach ($roots['ctlogs'] as $l) {
                if ($l['keyId'] === $logId) {
                    $log = $l;
                    break;
                }
            }
            if ($log === null) {
                continue;
            }
            if ($hashAlg !== 4 || ($sigAlg !== 3 && $sigAlg !== 1)) {
                $why = 'SCT is not SHA-256 with ECDSA or RSA';
                continue;
            }
            if ($ts < 0 || $ts < $log['valid'][0] || $ts > $log['valid'][1]) {
                $why = 'SCT log key not valid at its timestamp';
                continue;
            }
            $signed = "\x00\x00" . $tsBytes . "\x00\x01" . $issuerKeyHash . substr(pack('N', strlen($tbs)), 1) . $tbs . pack('n', strlen($ext)) . $ext;
            if (self::verifySig('sha256', $signed, $log['key'], $sig)) {
                return null;
            }
            $why = 'SCT signature invalid';
        }
        return $why;
    }

    // ---------------------------------------------------------------------------------------------- RFC 3161 timestamps

    private static function digestOf(string $b, ?array $t): string
    {
        return self::DIGEST_OIDS[self::oid($b, self::kids($b, $t)[0] ?? null)] ?? self::fail('unsupported digest algorithm');
    }

    private static function generalizedTime(string $b, ?array $t): int
    {
        if ($t === null || $t[0] !== 0x18) {
            self::fail('genTime is not a GeneralizedTime');
        }
        if (preg_match('/\A(\d{14})(?:\.(\d{1,9}))?Z\z/', self::body($b, $t), $m) !== 1) {
            self::fail('genTime malformed');
        }
        $ms = Der::parseDerTime(0x18, $m[1] . 'Z') ?? self::fail('genTime malformed');
        return $ms + (isset($m[2]) && $m[2] !== '' ? (int)substr(str_pad($m[2], 9, '0'), 0, 3) : 0);
    }

    /**
     * Verify an RFC 3161 TimeStampResp (or bare token) over `$data` (the raw signature bytes) against a pinned TSA: CMS
     * SignedData with TSTInfo content, messageImprint, signed attributes, the TSA chain valid at genTime, the timeStamping EKU.
     * Returns genTime (epoch ms); throws on any failure.
     */
    public static function verifyRfc3161(string $token, string $data, array $tsas): int
    {
        $ci = self::tlv($token, 0);
        if ($ci[3] !== strlen($token) || $ci[0] !== 0x30) {
            self::fail('timestamp is not one SEQUENCE');
        }
        $parts = self::kids($token, $ci);
        $p0 = $parts[0] ?? null;
        if ($p0 !== null && $p0[0] === 0x30 && $p0[3] - $p0[2] >= 3 && ord($token[self::kids($token, $p0)[0][1]]) === 0x02) {
            $st = self::kids($token, $p0)[0];
            $status = self::body($token, $st);
            if (!(strlen($status) === 1 && (ord($status) === 0 || ord($status) === 1))) {
                self::fail('timestamp status is not granted');
            }
            $ci = $parts[1] ?? self::fail('no timeStampToken');
            $parts = self::kids($token, $ci);
        }
        if (self::oid($token, $parts[0] ?? null) !== self::OID_SIGNED_DATA || ($parts[1][0] ?? -1) !== 0xa0) {
            self::fail('not CMS SignedData');
        }
        $sd = self::kids($token, $parts[1])[0] ?? null;
        $sdk = self::kids($token, $sd);
        $encap = null;
        foreach ($sdk as $i => $k) {
            if ($i > 1 && $k[0] === 0x30) {
                $encap = $k;
                break;
            }
        }
        $ek = self::kids($token, $encap);
        if (self::oid($token, $ek[0] ?? null) !== self::OID_TST_INFO || ($ek[1][0] ?? -1) !== 0xa0) {
            self::fail('content is not TSTInfo');
        }
        $octet = self::kids($token, $ek[1])[0] ?? null;
        if ($octet === null || $octet[0] !== 0x04) {
            self::fail('TSTInfo is not an OCTET STRING');
        }
        $tst = self::body($token, $octet);
        $tk = self::kids($tst, self::tlv($tst, 0));
        $mi = self::kids($tst, $tk[2] ?? null);
        $miAlg = self::digestOf($tst, $mi[0] ?? null);
        if (!isset($mi[1]) || hash($miAlg, $data, true) !== self::body($tst, $mi[1])) {
            self::fail('messageImprint is not the hash of the signature');
        }
        $genTime = self::generalizedTime($tst, $tk[4] ?? null);
        $signerInfos = $sdk[count($sdk) - 1] ?? self::fail('no signerInfos');
        if ($signerInfos[0] !== 0x31) {
            self::fail('no signerInfos');
        }
        $sis = self::kids($token, $signerInfos);
        if (count($sis) !== 1) {
            self::fail('exactly one SignerInfo is required');
        }
        $si = self::kids($token, $sis[0]);
        $dAlg = self::digestOf($token, $si[2] ?? null);
        $attrs = $si[3] ?? self::fail('signed attributes are required');
        if ($attrs[0] !== 0xa0) {
            self::fail('signed attributes are required');
        }
        $ctOk = $mdOk = false;
        foreach (self::kids($token, $attrs) as $a) {
            $ak = self::kids($token, $a);
            $vals = self::kids($token, $ak[1] ?? null);
            $o = self::oid($token, $ak[0] ?? null);
            if (count($vals) !== 1) {
                self::fail('an attribute must have one value');
            }
            if ($o === self::OID_CONTENT_TYPE) {
                $ctOk = self::oid($token, $vals[0]) === self::OID_TST_INFO;
            }
            if ($o === self::OID_MESSAGE_DIGEST) {
                $mdOk = hash($dAlg, $tst, true) === self::body($token, $vals[0]);
            }
        }
        if (!$ctOk || !$mdOk) {
            self::fail('signed attributes do not commit to the TSTInfo');
        }
        $signedAttrs = "\x31" . substr($token, $attrs[1] + 1, $attrs[3] - $attrs[1] - 1);
        $sigT = $si[5] ?? self::fail('signature is not an OCTET STRING');
        if ($sigT[0] !== 0x04) {
            self::fail('signature is not an OCTET STRING');
        }
        $sig = self::body($token, $sigT);
        foreach ($tsas as $tsa) {
            if ($genTime < $tsa['valid'][0] || $genTime > $tsa['valid'][1]) {
                continue;
            }
            $leaf = $tsa['chain'][0];
            if (!in_array(self::EKU_TIME_STAMPING, self::eku($leaf), true)) {
                continue;
            }
            if (!self::verifySig($dAlg, $signedAttrs, $leaf->publicKey(), $sig) || !self::chainOk($tsa['chain'], $genTime)) {
                continue;
            }
            return $genTime;
        }
        self::fail('no pinned timestamp authority signed it (valid at its time)');
    }

    // ---------------------------------------------------------------------------------------------- Rekor

    /** Signed-note checkpoint: origin, size, root; then `— <name> <b64(hint4 || sig)>` lines (v1 ECDSA, v2 Ed25519). */
    private static function verifyCheckpoint(string $text, array $log, int $size, string $root): ?string
    {
        $cut = strpos($text, "\n\n");
        if ($cut === false) {
            return 'checkpoint has no signature block';
        }
        $body = substr($text, 0, $cut + 1);
        $lines = explode("\n", $body);
        if (count($lines) < 4 || $lines[0] === '') {
            return 'checkpoint body too short or without an origin';
        }
        if (preg_match('/\A[1-9][0-9]*\z/', $lines[1]) !== 1 || $lines[1] !== (string)$size) {
            return 'checkpoint size differs from the proof';
        }
        if (self::b64($lines[2]) !== $root) {
            return 'checkpoint root differs from the proof';
        }
        foreach (explode("\n", substr($text, $cut + 2)) as $l) {
            if (preg_match('#\A\x{2014} (\S+) ([A-Za-z0-9+/=]+)\z#u', $l, $m) !== 1) {
                continue;
            }
            $raw = self::b64($m[2]);
            if (strlen($raw) < 5 || substr($raw, 0, 4) !== substr($log['keyId'], 0, 4)) {
                continue;
            }
            if ($log['v2'] !== null && $m[1] !== $log['v2']) {
                continue;
            }
            if (self::verifySig($log['v2'] !== null ? null : 'sha256', $body, $log['key'], substr($raw, 4))) {
                return null;
            }
        }
        return 'no checkpoint signature by the pinned log key';
    }

    private static function decInt(mixed $v): int
    {
        if (!is_string($v) || preg_match('/\A(0|[1-9][0-9]{0,15})\z/', $v) !== 1) {
            self::fail('not a decimal integer string');
        }
        $n = (int)$v;
        if ($n > self::MAX_SAFE) {
            self::fail('integer out of range');
        }
        return $n;
    }

    /** DSSE PAE (secure-systems-lab/dsse protocol.md). */
    public static function dssePae(string $payloadType, string $payload): string
    {
        return 'DSSEv1 ' . strlen($payloadType) . ' ' . $payloadType . ' ' . strlen($payload) . ' ' . $payload;
    }

    private static function pemDer(string $pem): string
    {
        return preg_match('#\A-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?\z#', $pem, $m) === 1
            ? self::b64(str_replace("\n", '', $m[1])) : '';
    }

    private static function kindOf(mixed $k, mixed $v): string
    {
        return is_string($k) && is_string($v) ? "$k/$v" : '';
    }

    private static function list(mixed $v): ?array
    {
        return is_array($v) && array_is_list($v) ? $v : null;
    }

    // ---------------------------------------------------------------------------------------------- the verifier

    /**
     * Verify a Sigstore bundle carrying a DSSE in-toto statement. Never throws.
     * @return array ['ok' => true, 'core' => array (as the shared vectors), 'statement' => mixed] | ['ok' => false, 'code' => string, 'detail' => string]
     */
    public static function verifyCore(mixed $bundle, array $roots): array
    {
        $no = static fn(string $code, string $detail): array => ['ok' => false, 'code' => $code, 'detail' => $detail];
        $stage = 'malformed';
        try {
            $vm = self::g($bundle, 'verificationMaterial');
            if (!self::isObj($bundle) || !self::isObj($vm)) {
                return $no('malformed', 'not a bundle');
            }
            $mt = self::g($bundle, 'mediaType');
            if (!in_array($mt, self::MEDIA_TYPES, true)) {
                return $no('media_type', 'unsupported media type ' . (is_string($mt) ? $mt : 'undefined'));
            }
            if ($mt === self::MEDIA_TYPES[0]) {
                $certs = self::list(self::g(self::g($vm, 'x509CertificateChain'), 'certificates'));
                $certRaw = $certs !== null && $certs !== [] ? self::g($certs[0], 'rawBytes') : null;
            } else {
                $certRaw = self::g(self::g($vm, 'certificate'), 'rawBytes');
            }
            if ($certRaw === null) {
                return $no('not_keyless', 'no Fulcio certificate (public-key bundles are not supported)');
            }
            $env = self::g($bundle, 'dsseEnvelope');
            if (!self::isObj($env) || Common::has($bundle, 'messageSignature')) {
                return $no('envelope', 'not a DSSE bundle');
            }
            if (self::g($env, 'payloadType') !== self::INTOTO_PAYLOAD_TYPE) {
                return $no('envelope', 'payloadType is not application/vnd.in-toto+json');
            }
            $sigs0 = self::list(self::g($env, 'signatures'));
            if ($sigs0 === null || count($sigs0) !== 1 || !self::isObj($sigs0[0])) {
                return $no('envelope', 'a DSSE envelope must carry exactly one signature');
            }
            $payload = self::b64(self::g($env, 'payload'));
            $dsseSig = self::b64(self::g($sigs0[0], 'sig'));
            $pae = self::dssePae(self::INTOTO_PAYLOAD_TYPE, $payload);
            $stage = 'cert_parse';
            $leafDer = self::b64($certRaw);
            $leaf = new Cert($leafDer);
            $pc = self::parseCert($leafDer);
            $lk = $leaf->publicKey();
            $alg = $lk->type === 'ec' ? (['prime256v1' => 'sha256', 'secp384r1' => 'sha384'][$lk->curve ?? ''] ?? null) : null;

            // ---- the log entry and its log
            $stage = 'tlog_count';
            $entries = self::list(self::g($vm, 'tlogEntries'));
            if ($entries === null || count($entries) !== 1 || !self::isObj($entries[0])) {
                return $no('tlog_count', 'exactly one transparency log entry is required');
            }
            $t = $entries[0];
            $stage = 'tlog_kind';
            $kvo = self::g($t, 'kindVersion');
            $kv = self::kindOf(self::g($kvo, 'kind'), self::g($kvo, 'version'));
            if (!in_array($kv, ['dsse/0.0.1', 'intoto/0.0.2', 'hashedrekord/0.0.2'], true)) {
                return $no('tlog_kind', "unsupported entry $kv");
            }
            $v2 = $kv === 'hashedrekord/0.0.2';
            $stage = 'tlog_key';
            $keyId = self::b64(self::g(self::g($t, 'logId'), 'keyId'));
            $log = null;
            foreach ($roots['tlogs'] as $l) {
                if ($l['keyId'] === $keyId) {
                    $log = $l;
                    break;
                }
            }
            if ($log === null) {
                return $no('tlog_key', 'the entry names a log the verifier did not pin');
            }
            if ($v2 !== ($log['v2'] !== null)) {
                return $no('tlog_key', 'the entry type does not match the log version');
            }
            $logIndex = self::decInt(self::g($t, 'logIndex'));
            $body = self::b64(self::g($t, 'canonicalizedBody'));

            // ---- time first: every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
            $stage = 'tsa';
            $times = [];
            foreach (self::list(self::g(self::g($vm, 'timestampVerificationData'), 'rfc3161Timestamps')) ?? [] as $ts) {
                $times[] = self::verifyRfc3161(self::b64(self::g($ts, 'signedTimestamp')), $dsseSig, $roots['tsas']);
            }
            $tsaCount = count($times);
            $set = false;
            $promise = self::g($t, 'inclusionPromise');
            if (!$v2 && self::isObj($promise)) {
                $stage = 'tlog_set';
                $integrated = self::decInt(self::g($t, 'integratedTime'));
                $msg = '{"body":' . json_encode(self::g($t, 'canonicalizedBody'), JSON_UNESCAPED_SLASHES) . ',"integratedTime":' . $integrated
                    . ',"logID":"' . bin2hex($keyId) . '","logIndex":' . $logIndex . '}';
                if (!self::verifySig('sha256', $msg, $log['key'], self::b64(self::g($promise, 'signedEntryTimestamp')))) {
                    return $no('tlog_set', 'signed entry timestamp invalid');
                }
                $times[] = $integrated * 1000;
                $set = true;
            }
            if ($times === []) {
                return $no('no_verified_time', 'no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp');
            }
            foreach ($times as $at) {
                if ($at < $log['valid'][0] || $at > $log['valid'][1]) {
                    return $no('tlog_key', 'the log key was not valid at a signing time');
                }
            }

            // ---- inclusion
            $stage = 'tlog_inclusion';
            $ip = self::g($t, 'inclusionProof');
            $hashes = self::list(self::g($ip, 'hashes'));
            if (!self::isObj($ip) || $hashes === null || !self::isObj(self::g($ip, 'checkpoint'))) {
                return $no('tlog_inclusion', 'no inclusion proof');
            }
            $root = self::b64(self::g($ip, 'rootHash'));
            $size = self::decInt(self::g($ip, 'treeSize'));
            if (!ProvenanceGate::verifyRfc9162Inclusion(ProvenanceGate::rfc9162LeafHash($body), self::decInt(self::g($ip, 'logIndex')), $size,
                array_map([self::class, 'b64'], $hashes), $root)) {
                return $no('tlog_inclusion', 'the inclusion proof does not lead to the root');
            }
            $stage = 'tlog_checkpoint';
            $envelope = self::g(self::g($ip, 'checkpoint'), 'envelope');
            $cpe = is_string($envelope) ? self::verifyCheckpoint($envelope, $log, $size, $root) : 'checkpoint has no signature block';
            if ($cpe !== null) {
                return $no('tlog_checkpoint', $cpe);
            }

            // ---- certificate path at every verified time (hybrid model), CT
            $stage = 'cert_chain';
            $issuer = null;
            foreach ($roots['cas'] as $ca) {
                foreach ($times as $at) {
                    if ($at < $ca['valid'][0] || $at > $ca['valid'][1]) {
                        continue 2;
                    }
                }
                $first = $ca['chain'][0];
                if (!$leaf->checkIssued($first) || !$leaf->verify($first->publicKey())) {
                    continue;
                }
                $ok = true;
                foreach ($times as $at) {
                    $ok = $ok && self::chainOk($ca['chain'], $at);
                }
                foreach ($ca['chain'] as $c) {
                    $ok = $ok && $c->ca();
                }
                if ($ok) {
                    $issuer = $first;
                    break;
                }
            }
            if ($issuer === null) {
                return $no('cert_chain', 'no pinned CA issued the certificate, valid at every signing time');
            }
            if ($leaf->ca()) {
                return $no('cert_chain', 'the leaf is a CA certificate');
            }
            foreach ($times as $at) {
                if (!self::inside($leaf, $at)) {
                    return $no('cert_time', 'the certificate was not valid at a signing time');
                }
            }
            if (!in_array(self::EKU_CODE_SIGNING, self::eku($leaf), true)) {
                return $no('cert_eku', 'the certificate lacks the code-signing EKU');
            }
            if ($roots['ctlogs'] !== []) {
                $stage = 'sct';
                $sct = self::verifySct($pc, $issuer, $roots);
                if ($sct !== null) {
                    return $no('sct', $sct);
                }
            }

            // ---- the entry body names this envelope
            $stage = 'tlog_body';
            $eb = Json::parseLax(self::utf8Lossy($body));
            if ($eb === null) {
                self::fail('entry body is null');
            }
            $spec = self::g($eb, 'spec');
            if (self::kindOf(self::g($eb, 'kind'), self::g($eb, 'apiVersion')) !== $kv) {
                return $no('tlog_body', 'the entry body is not the kind the bundle names');
            }
            $payloadSha = hash('sha256', $payload);
            if ($kv === 'dsse/0.0.1') {
                $ph = self::g($spec, 'payloadHash');
                if (self::g($ph, 'algorithm') !== 'sha256' || self::g($ph, 'value') !== $payloadSha) {
                    return $no('tlog_body', 'the entry names another payload');
                }
                $sigs = self::list(self::g($spec, 'signatures')) ?? [];
                if (count($sigs) !== 1 || !self::isObj($sigs[0])) {
                    return $no('tlog_body', 'the entry must name exactly one signature');
                }
                if (self::b64(self::g($sigs[0], 'signature')) !== $dsseSig) {
                    return $no('tlog_body', 'the entry names another signature');
                }
                if (self::pemDer(self::utf8Lossy(self::b64(self::g($sigs[0], 'verifier')))) !== $leafDer) {
                    return $no('tlog_body', 'the entry names another certificate');
                }
            } elseif ($kv === 'intoto/0.0.2') {
                // Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
                $c = self::g($spec, 'content');
                $ph = self::g($c, 'payloadHash');
                if (self::g($ph, 'algorithm') !== 'sha256' || self::g($ph, 'value') !== $payloadSha) {
                    return $no('tlog_body', 'the entry names another payload');
                }
                $sigs = self::list(self::g(self::g($c, 'envelope'), 'signatures')) ?? [];
                if (count($sigs) !== 1 || !self::isObj($sigs[0])) {
                    return $no('tlog_body', 'the entry must name exactly one signature');
                }
                if (self::b64(self::b64(self::g($sigs[0], 'sig'))) !== $dsseSig) {
                    return $no('tlog_body', 'the entry names another signature');
                }
                if (self::pemDer(self::utf8Lossy(self::b64(self::g($sigs[0], 'publicKey')))) !== $leafDer) {
                    return $no('tlog_body', 'the entry names another certificate');
                }
            } else {
                // Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
                $h = self::g($spec, 'hashedRekordV002');
                $data = self::g($h, 'data');
                $a = self::g($data, 'algorithm');
                $hashName = is_string($a) ? (['SHA2_256' => 'sha256', 'SHA2_384' => 'sha384', 'SHA2_512' => 'sha512'][$a] ?? null) : null;
                if ($hashName === null || $hashName !== $alg) {
                    return $no('tlog_body', "the entry digest algorithm is not the signing key's");
                }
                if (self::b64(self::g($data, 'digest')) !== hash($hashName, $pae, true)) {
                    return $no('tlog_body', 'the entry names another envelope');
                }
                $sg = self::g($h, 'signature');
                if (self::b64(self::g($sg, 'content')) !== $dsseSig) {
                    return $no('tlog_body', 'the entry names another signature');
                }
                if (self::b64(self::g(self::g(self::g($sg, 'verifier'), 'x509Certificate'), 'rawBytes')) !== $leafDer) {
                    return $no('tlog_body', 'the entry names another certificate');
                }
            }

            // ---- DSSE signature
            $stage = 'signature';
            if ($alg === null) {
                return $no('signature', 'unsupported leaf key type');
            }
            if (!self::verifySig($alg, $pae, $lk, $dsseSig)) {
                return $no('signature', 'DSSE signature invalid');
            }

            // ---- identity
            $stage = 'identity';
            $identity = self::sanIdentity($pc);
            $issV2 = self::fulcioExt($pc, 8);
            $issV1 = self::fulcioExt($pc, 1);
            if ($issV2 !== null && $issV1 !== null && $issV2 !== $issV1) {
                return $no('identity', 'the two issuer extensions disagree');
            }
            $oidcIssuer = $issV2 ?? $issV1;
            if ($oidcIssuer === null || $oidcIssuer === '') {
                return $no('identity', 'no OIDC issuer extension');
            }
            $sourceRepo = self::fulcioExt($pc, 12);
            $sourceDigest = self::fulcioExt($pc, 13);
            $sourceRef = self::fulcioExt($pc, 14);

            // ---- statement
            $stage = 'statement';
            $st = Json::parseLax(self::utf8Strict($payload));
            if ($st === null) {
                self::fail('statement is null');
            }
            if (!self::isObj($st) || self::g($st, '_type') !== ProvenanceGate::INTOTO_STATEMENT_V1) {
                return $no('statement', 'not an in-toto Statement v1');
            }
            $subjectList = self::list(self::g($st, 'subject'));
            if ($subjectList === null || $subjectList === []) {
                return $no('statement', 'no subject');
            }
            $subjects = [];
            foreach ($subjectList as $s) {
                $d = self::g($s, 'digest');
                foreach (['sha256', 'sha512'] as $a) {
                    $x = self::isObj($d) ? self::g($d, $a) : null;
                    if (is_string($x)) {
                        $subjects[] = ['alg' => $a, 'digest' => $x];
                    }
                }
            }
            if ($subjects === [] || count($subjects) > 64) {
                return $no('statement', 'no sha256/sha512 subject digest (or more than 64)');
            }
            $pt = self::g($st, 'predicateType');
            if (!is_string($pt)) {
                return $no('statement', 'no predicateType');
            }
            $core = ['identity' => $identity, 'oidc_issuer' => $oidcIssuer];
            $sourceRepo !== null && $core['source_repo'] = $sourceRepo;
            $sourceRef !== null && $core['source_ref'] = $sourceRef;
            $sourceDigest !== null && $core['source_digest'] = $sourceDigest;
            $core += ['predicate_type' => $pt, 'subjects' => $subjects, 'signed_time' => intdiv(min($times), 1000), 'rekor_log_index' => $logIndex,
                'rekor' => $v2 ? 'v2' : 'v1', 'timestamps' => ['tsa' => $tsaCount, 'set' => $set]];
            return ['ok' => true, 'core' => $core, 'statement' => $st];
        } catch (\Throwable $e) {
            return $no($stage, 'fail closed: ' . $e->getMessage());
        }
    }

    /**
     * {@see verifyCore}, then the SLSA v1 predicate: the facts ProvenanceGate::gate checks (an Obj).
     * @return array ['ok' => true, 'facts' => Obj] | ['ok' => false, 'code' => string, 'detail' => string]
     */
    public static function verify(mixed $bundle, array $roots): array
    {
        $r = self::verifyCore($bundle, $roots);
        if (!$r['ok']) {
            return $r;
        }
        $st = $r['statement'];
        $c = $r['core'];
        $pt = self::g($st, 'predicateType');
        if ($pt !== ProvenanceGate::SLSA_PROVENANCE_V1) {
            return ['ok' => false, 'code' => 'predicate', 'detail' => "predicate $pt is not SLSA provenance v1"];
        }
        $pr = self::g($st, 'predicate');
        $bd = self::g($pr, 'buildDefinition');
        $builderId = self::g(self::g(self::g($pr, 'runDetails'), 'builder'), 'id');
        $buildType = self::g($bd, 'buildType');
        if (!is_string($buildType) || !is_string($builderId) || !self::isObj(self::g($bd, 'externalParameters'))) {
            return ['ok' => false, 'code' => 'predicate', 'detail' => 'buildType, externalParameters and builder.id are required (SLSA Build L1)'];
        }
        $deps = self::list(self::g($bd, 'resolvedDependencies'));
        $dep0 = $deps !== null && $deps !== [] && self::isObj($deps[0]) ? $deps[0] : null;
        $facts = ['v' => 1, 'predicate_type' => ProvenanceGate::SLSA_PROVENANCE_V1, 'build_type' => $buildType, 'builder_id' => $builderId,
            'subjects' => array_map([Obj::class, 'of'], $c['subjects']), 'identity' => $c['identity'], 'oidc_issuer' => $c['oidc_issuer']];
        foreach (['source_repo', 'source_ref', 'source_digest'] as $k) {
            if (array_key_exists($k, $c)) {
                $facts[$k] = $c[$k];
            }
        }
        $uri = self::g($dep0, 'uri');
        if (is_string($uri)) {
            $ps = ['uri' => $uri];
            $commit = self::g(self::g($dep0, 'digest'), 'gitCommit');
            if (is_string($commit)) {
                $ps['git_commit'] = $commit;
            }
            $facts['provenance_source'] = Obj::of($ps);
        }
        $facts['integrated_time'] = $c['signed_time'];
        $facts['rekor_log_index'] = $c['rekor_log_index'];
        return ['ok' => true, 'facts' => Obj::of($facts)];
    }
}
