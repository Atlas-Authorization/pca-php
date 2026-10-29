<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Intel.php';
require_once __DIR__ . '/Ocsp.php';
require_once __DIR__ . '/Xml.php';

/**
 * NVIDIA GPU (Hopper / Blackwell, CC mode) SPDM attestation verifier and its RIM / CRL / OCSP collateral hook: the native
 * counterpart of `createNvidiaSpdmVerifier` and `nvidiaCollateralHook`. The device chain to a PINNED NVIDIA root, the SPDM
 * GET_MEASUREMENTS transcript signature (ECDSA P-384), the PCA binding through the SPDM request nonce, the pinned measurement
 * blocks, and (optionally) the signed Reference Integrity Manifests, firmware policy and CRL / OCSP revocation. Fails closed with
 * the reference's reason strings.
 */
final class Nvidia implements HardwareVerifier
{
    public const SUITE = 'nvidia-gpu-spdm-ecdsa-p384-sha384';
    private const REQ_LEN = 37;
    private const NONCE_LEN = 32;
    private const SIG_LEN = 96;
    private const MAX_CHAIN = 5;
    public const OPAQUE_DRIVER_VERSION = 3;
    public const OPAQUE_VBIOS_VERSION = 6;
    public const OPAQUE_CHIP_INFO = 35;
    private const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';
    private const ALG_C14N11 = 'http://www.w3.org/2006/12/xml-c14n11';
    private const ALG_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
    private const ALG_ECDSA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
    private const ALG_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    private const NVDEC0_DISABLED = 0x55;
    private const NVDEC_BLOCK_INDEX = 35;

    private static function b(string $b, int $o): int
    {
        return $o >= 0 && $o < strlen($b) ? ord($b[$o]) : 0;
    }

    private static function u16(string $b, int $o): int
    {
        return self::b($b, $o) | (self::b($b, $o + 1) << 8);
    }

    private static function u24(string $b, int $o): int
    {
        return self::b($b, $o) | (self::b($b, $o + 1) << 8) | (self::b($b, $o + 2) << 16);
    }

    // ---- SPDM transcript ----------------------------------------------------------------------------------------------------------

    /** Parse an SPDM request || response GPU attestation transcript. Throws \ValueError on any structural problem. @return array<string,mixed> */
    /** null when the request version is >= 0x11 and the response echoes it, else the refusal reason. */
    public static function versionReason(array $report): ?string
    {
        $rq = $report['request']['version'];
        $rs = $report['response_version'];
        return $rq >= 0x11 && $rs === $rq ? null : 'SPDM version 0x' . dechex($rq) . '/0x' . dechex($rs) . ' is not an accepted GET_MEASUREMENTS version';
    }

    public static function parseEvidence(string $b): array
    {
        if (strlen($b) < self::REQ_LEN + 8 + self::NONCE_LEN + 2 + self::SIG_LEN) {
            throw new \ValueError('parseNvidiaSpdmEvidence: transcript too short (' . strlen($b) . ')');
        }
        $code = self::b($b, 1);
        if ($code !== 0xE0) {
            throw new \ValueError('parseNvidiaSpdmEvidence: request code 0x' . dechex($code) . ' is not GET_MEASUREMENTS');
        }
        $request = ['version' => self::b($b, 0), 'nonce' => substr($b, 4, self::NONCE_LEN)];
        $r = substr($b, self::REQ_LEN);
        if (self::b($r, 1) !== 0x60) {
            throw new \ValueError('parseNvidiaSpdmEvidence: response code is not MEASUREMENTS');
        }
        $numBlocks = self::b($r, 4);
        $recLen = self::u24($r, 5);
        $o = 8;
        if ($o + $recLen + self::NONCE_LEN + 2 + self::SIG_LEN > strlen($r)) {
            throw new \ValueError('parseNvidiaSpdmEvidence: measurement record length overruns transcript');
        }
        $measurements = [];
        $recEnd = $o + $recLen;
        while ($o < $recEnd) {
            if ($o + 4 > $recEnd) {
                throw new \ValueError('parseNvidiaSpdmEvidence: truncated measurement block header');
            }
            $index = self::b($r, $o);
            $size = self::u16($r, $o + 2);
            $bodyStart = $o + 4;
            if ($bodyStart + $size > $recEnd || $size < 3) {
                throw new \ValueError('parseNvidiaSpdmEvidence: measurement block overruns record');
            }
            $valueType = self::b($r, $bodyStart);
            $vsize = self::u16($r, $bodyStart + 1);
            if (3 + $vsize > $size) {
                throw new \ValueError('parseNvidiaSpdmEvidence: DMTF value overruns measurement block');
            }
            $measurements[] = ['index' => $index, 'valueType' => $valueType, 'digest' => substr($r, $bodyStart + 3, $vsize)];
            $o = $bodyStart + $size;
        }
        if (count($measurements) !== $numBlocks) {
            throw new \ValueError("parseNvidiaSpdmEvidence: header says $numBlocks blocks, parsed " . count($measurements));
        }
        $o += self::NONCE_LEN;
        $opaqueLen = self::u16($r, $o);
        $o += 2;
        if ($o + $opaqueLen + self::SIG_LEN !== strlen($r)) {
            throw new \ValueError('parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript');
        }
        $opaque = [];
        $opaqueEnd = $o + $opaqueLen;
        while ($o < $opaqueEnd) {
            if ($o + 4 > $opaqueEnd) {
                throw new \ValueError('parseNvidiaSpdmEvidence: truncated opaque TLV header');
            }
            $t = self::u16($r, $o);
            $ln = self::u16($r, $o + 2);
            $o += 4;
            if ($o + $ln > $opaqueEnd) {
                throw new \ValueError('parseNvidiaSpdmEvidence: opaque TLV overruns opaque data');
            }
            $opaque[$t] = substr($r, $o, $ln);
            $o += $ln;
        }
        return ['request' => $request, 'response_version' => self::b($r, 0), 'measurements' => $measurements, 'opaque' => $opaque, 'signature' => substr($r, strlen($r) - self::SIG_LEN),
            'signedBytes' => substr($b, 0, strlen($b) - self::SIG_LEN)];
    }

    /** NVIDIA's VBIOS version rendering: byte-reverse, then re-pair as dotted hex (e.g. `96.00.9f.00.04`). */
    public static function formatVbiosVersion(string $raw): string
    {
        $hx = bin2hex(strrev($raw));
        $half = intdiv(strlen($hx), 2);
        $temp = substr($hx, $half) . substr($hx, $half - 2, 2);
        return implode('.', str_split($temp, 2));
    }

    // ---- device chain ----------------------------------------------------------------------------------------------------------------

    /** @return list<Cert> */
    public static function parsePemChain(string $pem): array
    {
        $blocks = Common::pemBlocks($pem);
        if ($blocks === []) {
            throw new \ValueError('parsePemChain: no certificates found');
        }
        if (count($blocks) > self::MAX_CHAIN) {
            throw new \ValueError('parsePemChain: chain longer than ' . self::MAX_CHAIN);
        }
        return array_map(static fn($b) => Cert::fromPem($b), $blocks);
    }

    /**
     * Every link signature-verified, every issuer a CA, every certificate valid at `now`, the root self-signed and PINNED.
     * @param list<string> $rootSpkiSha256
     * @return array<string,mixed>
     */
    public static function verifyDeviceChain(string $pem, array $rootSpkiSha256, float $nowMs): array
    {
        try {
            $chain = self::parsePemChain($pem);
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'device chain unparseable: ' . $e->getMessage()];
        }
        foreach ($chain as $i => $c) {
            if (!Der::x509ValidAt($c->raw, $nowMs)) {
                return ['ok' => false, 'reason' => "device chain cert #$i is outside its validity window"];
            }
            $pk = $c->publicKey();
            if ($pk->type !== 'ec' || Common::nodeCurve($pk) !== 'secp384r1') {
                return ['ok' => false, 'reason' => "device chain cert #$i is not an ECDSA P-384 key"];
            }
        }
        for ($i = 0; $i < count($chain) - 1; $i++) {
            $issuer = $chain[$i + 1];
            if (!$issuer->ca()) {
                return ['ok' => false, 'reason' => 'device chain cert #' . ($i + 1) . ' issues a certificate but is not a CA'];
            }
            if (!$chain[$i]->verify($issuer->publicKey())) {
                return ['ok' => false, 'reason' => "device chain link #$i signature does not verify under its issuer"];
            }
        }
        $root = $chain[count($chain) - 1];
        if (!$root->ca() || !$root->verifySelf()) {
            return ['ok' => false, 'reason' => 'device chain root is not a self-signed CA'];
        }
        $pins = array_map(static fn($p) => strtolower((string)$p), $rootSpkiSha256);
        if (!in_array($root->spkiSha256(), $pins, true)) {
            return ['ok' => false, 'reason' => 'chain root is not a pinned NVIDIA root'];
        }
        return ['ok' => true, 'leaf' => $chain[0], 'chain' => $chain];
    }

    // ---- RIM (SWID XML, XMLDSig) ---------------------------------------------------------------------------------------------------------

    private static function pemOfDerB64(string $b64): string
    {
        $body = preg_replace('/\s+/', '', $b64) ?? '';
        return "-----BEGIN CERTIFICATE-----\n" . implode("\n", str_split($body, 64)) . "\n-----END CERTIFICATE-----";
    }

    private static function isInt(float $v): bool
    {
        return !is_nan($v) && !is_infinite($v) && floor($v) === $v;
    }

    private static function algOf(array $els): ?string
    {
        return $els === [] ? null : $els[0]->getAttribute('Algorithm');
    }

    /**
     * A RIM document (XML text): the strict XMLDSig profile, the digest, the ECDSA-P384 signature and the signer chain to the
     * pinned CoRIM signing root; golden measurements are read ONLY from the verified tree.
     * @param list<string> $rimRootSpkiSha256
     * @return array<string,mixed>
     */
    public static function verifyRim(mixed $xml, array $rimRootSpkiSha256, float $nowMs): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            if (!is_string($xml) || $xml === '' || strlen($xml) > 4_000_000) {
                return $fail('RIM: empty or oversized document');
            }
            if ($rimRootSpkiSha256 === []) {
                return $fail('RIM: no pinned RIM root configured');
            }
            $doc = Xml::parse($xml);
            if ($doc->violations !== []) {
                return $fail('RIM: ' . $doc->violations[0]);
            }
            $root = $doc->root;
            if ($root->local !== 'SoftwareIdentity') {
                return $fail('RIM: root element is not SoftwareIdentity');
            }
            if (count($root->descendants(self::NS_DSIG, 'Signature')) !== 1) {
                return $fail('RIM: expected exactly one Signature element');
            }
            $sigs = $root->elementChildren(self::NS_DSIG, 'Signature');
            if (count($sigs) !== 1) {
                return $fail('RIM: the Signature must be a direct child of the root');
            }
            $sig = $sigs[0];
            $signedInfo = $sig->elementChildren(self::NS_DSIG, 'SignedInfo');
            if (count($signedInfo) !== 1) {
                return $fail('RIM: expected exactly one SignedInfo');
            }
            $si = $signedInfo[0];
            if (self::algOf($si->elementChildren(self::NS_DSIG, 'CanonicalizationMethod')) !== self::ALG_C14N11) {
                return $fail('RIM: CanonicalizationMethod must be C14N 1.1');
            }
            if (self::algOf($si->elementChildren(self::NS_DSIG, 'SignatureMethod')) !== self::ALG_ECDSA384) {
                return $fail('RIM: SignatureMethod must be ECDSA-SHA384');
            }
            $refs = $si->elementChildren(self::NS_DSIG, 'Reference');
            if (count($refs) !== 1) {
                return $fail('RIM: expected exactly one Reference');
            }
            $ref = $refs[0];
            if ($ref->getAttribute('URI') !== '') {
                return $fail('RIM: Reference URI must be "" (the whole document)');
            }
            $tr = $ref->elementChildren(self::NS_DSIG, 'Transforms');
            $transforms = array_map(static fn($t) => $t->getAttribute('Algorithm'), ($tr !== [] ? $tr[0] : $ref)->elementChildren(self::NS_DSIG, 'Transform'));
            if (count($transforms) !== 2 || $transforms[0] !== self::ALG_ENVELOPED || $transforms[1] !== self::ALG_C14N11) {
                return $fail('RIM: transforms must be exactly [enveloped-signature, C14N 1.1]');
            }
            if (self::algOf($ref->elementChildren(self::NS_DSIG, 'DigestMethod')) !== self::ALG_SHA384) {
                return $fail('RIM: DigestMethod must be SHA-384');
            }
            $dv = $ref->elementChildren(self::NS_DSIG, 'DigestValue');
            $sv = $sig->elementChildren(self::NS_DSIG, 'SignatureValue');
            $digestValue = $dv !== [] ? preg_replace('/\s+/', '', $dv[0]->textContent()) : null;
            $sigValueB64 = $sv !== [] ? preg_replace('/\s+/', '', $sv[0]->textContent()) : null;
            if ($digestValue === null || $digestValue === '' || $sigValueB64 === null || $sigValueB64 === '') {
                return $fail('RIM: missing DigestValue / SignatureValue');
            }
            $keyInfo = $sig->elementChildren(self::NS_DSIG, 'KeyInfo');
            $x509Data = $keyInfo !== [] ? $keyInfo[0]->elementChildren(self::NS_DSIG, 'X509Data') : [];
            $certB64 = $x509Data !== [] ? array_map(static fn($c) => $c->textContent(), $x509Data[0]->elementChildren(self::NS_DSIG, 'X509Certificate')) : [];
            if ($certB64 === []) {
                return $fail('RIM: no signer certificates in KeyInfo');
            }
            $chain = self::verifyDeviceChain(implode("\n", array_map([self::class, 'pemOfDerB64'], $certB64)), $rimRootSpkiSha256, $nowMs);
            if (!$chain['ok']) {
                return $fail('RIM signer chain: ' . $chain['reason']);
            }
            $siCanon = Xml::canonicalize($si);
            $sigRaw = Common::nodeB64Decode($sigValueB64);
            if (strlen($sigRaw) !== 96) {
                return $fail('RIM: SignatureValue is not a 96-byte P-384 signature');
            }
            if (!Common::ecdsaVerifyRaw($chain['leaf']->publicKey(), $sigRaw, $siCanon, 'sha384')) {
                return $fail('RIM: SignedInfo signature does not verify under the signer certificate');
            }
            $canon = Xml::canonicalize($root, $sig);
            if (base64_encode(hash('sha384', $canon, true)) !== $digestValue) {
                return $fail('RIM: document digest does not match the signed DigestValue');
            }
            $meta = null;
            $payload = null;
            foreach ($root->elementChildren() as $c) {
                if ($meta === null && $c->local === 'Meta') {
                    $meta = $c;
                }
                if ($payload === null && $c->local === 'Payload') {
                    $payload = $c;
                }
            }
            if ($meta === null || $payload === null) {
                return $fail('RIM: missing Meta / Payload');
            }
            $golden = [];
            foreach ($payload->elementChildren() as $r) {
                if ($r->local !== 'Resource' || $r->getAttribute('type') !== 'Measurement') {
                    continue;
                }
                $index = Common::jsNumber($r->getAttribute('index'));
                $alternatives = Common::jsNumber($r->getAttribute('alternatives'));
                $size = Common::jsNumber($r->getAttribute('size'));
                $hashAttrs = array_values(array_filter($r->attrs, static fn($a) => preg_match('/\AHash[0-9]+\z/', $a->local) === 1));
                usort($hashAttrs, static fn($a, $b) => (int)substr($a->local, 4) <=> (int)substr($b->local, 4));
                $hashes = array_map(static fn($a) => strtolower($a->value), $hashAttrs);
                if (!self::isInt($index) || $index < 0 || !self::isInt($alternatives) || $alternatives < 1 || !self::isInt($size) || $size < 1) {
                    return $fail('RIM: malformed Measurement resource');
                }
                [$index, $alternatives, $size] = [(int)$index, (int)$alternatives, (int)$size];
                $bad = count($hashes) !== $alternatives;
                foreach ($hashes as $h) {
                    $bad = $bad || preg_match('/\A[0-9a-f]+\z/', $h) !== 1 || strlen($h) !== $size * 2;
                }
                if ($bad) {
                    return $fail("RIM: Measurement $index hash list is inconsistent with alternatives/size");
                }
                if (isset($golden[$index])) {
                    return $fail("RIM: duplicate Measurement index $index");
                }
                $golden[$index] = ['index' => $index, 'active' => strtolower($r->getAttribute('active')) === 'true', 'alternatives' => $alternatives, 'size' => $size, 'hashes' => $hashes];
            }
            if ($golden === []) {
                return $fail('RIM: no measurements');
            }
            return ['ok' => true, 'rim' => ['tagId' => $root->getAttribute('tagId'), 'product' => $meta->getAttribute('product'),
                'version' => $meta->getAttribute('colloquialVersion'), 'golden' => $golden]];
        } catch (\Throwable $e) {
            return $fail('RIM: verification error (fail closed): ' . $e->getMessage());
        }
    }

    // ---- RIM ids, comparison, revocation -----------------------------------------------------------------------------------------------------

    private static function ascii(?string $b): string
    {
        $s = (string)mb_convert_encoding(rtrim($b ?? '', "\0"), 'UTF-8', 'ISO-8859-1');
        return Common::jsTrim($s);
    }

    /** The RIM ids this report requires (read from the GPU's own signed opaque data); null when they cannot be named. @return array<string,string>|null */
    public static function rimIdsForReport(array $report): ?array
    {
        $o = $report['opaque'];
        $driverVersion = self::ascii($o[self::OPAQUE_DRIVER_VERSION] ?? null);
        $vb = $o[self::OPAQUE_VBIOS_VERSION] ?? null;
        $project = mb_strtoupper(self::ascii($o[17] ?? null));
        $projectSku = mb_strtoupper(self::ascii($o[18] ?? null));
        $chipSku = mb_strtoupper(self::ascii($o[15] ?? null));
        if ($driverVersion === '' || $vb === null || $project === '' || $projectSku === '' || $chipSku === '') {
            return null;
        }
        $chip = 'GH100';
        $chipRaw = $o[self::OPAQUE_CHIP_INFO] ?? null;
        if ($chipRaw !== null) {
            $chip = self::ascii($chipRaw);
            if (preg_match('/\A[A-Z][A-Z0-9]{2,11}\z/', $chip) !== 1) {
                return null;
            }
        }
        $vbiosVersion = self::formatVbiosVersion($vb);
        return ['chip' => $chip,
            'driver' => $chip === 'GH100' ? "NV_GPU_DRIVER_GH100_$driverVersion" : "NV_GPU_CC_DRIVER_{$chip}_$driverVersion",
            'vbios' => "NV_GPU_VBIOS_{$project}_{$projectSku}_{$chipSku}_" . strtoupper(str_replace('.', '', $vbiosVersion)),
            'driverVersion' => $driverVersion, 'vbiosVersion' => $vbiosVersion];
    }

    /** NVIDIA's merge / alternatives / NVDEC0 rules. @return array<string,mixed> */
    public static function compareReportToRims(array $report, array $driver, array $vbios): array
    {
        $merged = [];
        foreach ($driver['golden'] as $g) {
            if ($g['active']) {
                $merged[$g['index']] = $g;
            }
        }
        foreach ($vbios['golden'] as $g) {
            if (!$g['active']) {
                continue;
            }
            if (isset($merged[$g['index']])) {
                return ['ok' => false, 'reason' => 'driver and VBIOS RIMs both have an active measurement at index ' . $g['index']];
            }
            $merged[$g['index']] = $g;
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
        $nvdecDisabled = $nvdec !== null && strlen($nvdec) > 0 && ord($nvdec[0]) === self::NVDEC0_DISABLED;
        $mismatches = 0;
        ksort($merged);
        foreach ($merged as $index => $g) {
            if ($index + 1 === self::NVDEC_BLOCK_INDEX && $nvdecDisabled) {
                continue;
            }
            $digest = $runtime[$index] ?? null;
            $hx = $digest !== null ? bin2hex($digest) : '';
            if ($digest === null || strlen($digest) !== $g['size'] || !in_array($hx, $g['hashes'], true)) {
                $mismatches++;
            }
        }
        if ($mismatches > 0) {
            return ['ok' => false, 'reason' => "runtime measurements differ from the golden RIM values at $mismatches index(es)"];
        }
        return ['ok' => true];
    }

    /**
     * The device chain against CRLs: every supplied CRL verifies under one chain certificate and is fresh, no chain certificate
     * (other than the root) is listed by its issuer, and `$requireIssuers` each have a verified CRL.
     * @param list<Cert> $chain @param list<string> $crls @param list<string>|null $requireIssuers
     * @return array<string,mixed>
     */
    public static function checkChainRevocation(array $chain, array $crls, float $nowMs, ?array $requireIssuers = null): array
    {
        if ($crls === []) {
            return ['ok' => false, 'reason' => 'no CRLs supplied'];
        }
        $covered = [];
        foreach ($crls as $ci => $crl) {
            $issuerIdx = -1;
            $revoked = null;
            $lastReason = 'no chain certificate verifies it';
            foreach ($chain as $i => $cert) {
                $r = Intel::verifyCrl($crl, $cert->publicKey(), $nowMs);
                if ($r['ok']) {
                    $issuerIdx = $i;
                    $revoked = $r['revoked'];
                    break;
                }
                if ($lastReason === 'no chain certificate verifies it' || str_contains($lastReason, 'signature does not verify')) {
                    $lastReason = $r['reason'];
                }
            }
            if ($issuerIdx < 0 || $revoked === null) {
                return ['ok' => false, 'reason' => "CRL #$ci rejected: $lastReason"];
            }
            $covered[$issuerIdx] = true;
            for ($i = 0; $i < count($chain) - 1; $i++) {
                if ($i + 1 === $issuerIdx && Intel::serialIsRevoked($revoked, $chain[$i]->serialHex())) {
                    return ['ok' => false, 'reason' => "chain certificate '" . str_replace("\n", ', ', $chain[$i]->subject()) . "' is revoked"];
                }
            }
        }
        foreach ($requireIssuers ?? [] as $need) {
            $any = false;
            foreach (array_keys($covered) as $i) {
                $any = $any || str_contains($chain[$i]->subject(), $need);
            }
            if (!$any) {
                return ['ok' => false, 'reason' => "no verified CRL issued by a certificate matching '$need'"];
            }
        }
        return ['ok' => true, 'verifiedCrls' => count($crls)];
    }

    // ---- firmware policy ---------------------------------------------------------------------------------------------------------------------

    /** @return list<int>|null */
    private static function parseVersion(mixed $v, int $radix): ?array
    {
        $pat = $radix === 10 ? '/\A[0-9]+(\.[0-9]+)*\z/' : '/\A[0-9a-fA-F]{1,4}(\.[0-9a-fA-F]{1,4})*\z/';
        if (!is_string($v) || preg_match($pat, $v) !== 1) {
            return null;
        }
        return array_map(static fn($x) => (int)base_convert($x, $radix, 10), explode('.', $v));
    }

    private static function cmpVersion(array $a, array $b): int
    {
        for ($i = 0; $i < max(count($a), count($b)); $i++) {
            $d = ($a[$i] ?? 0) - ($b[$i] ?? 0);
            if ($d !== 0) {
                return $d < 0 ? -1 : 1;
            }
        }
        return 0;
    }

    /** @return callable(array<string,string>): ?string */
    private static function compileFirmwarePolicy(mixed $fw): callable
    {
        if (!Common::isObj($fw) || Common::members($fw) === []) {
            return static fn(array $ids): ?string => null;
        }
        $need = static function (mixed $v, int $radix, string $what): array {
            $p = self::parseVersion($v, $radix);
            if ($p === null) {
                throw new AttestConstructError("nvidiaCollateralHook: malformed $what '" . Common::jsStr($v) . "'");
            }
            return $p;
        };
        $minDv = Common::g($fw, 'minDriverVersion');
        $minVv = Common::g($fw, 'minVbiosVersion');
        $minD = is_string($minDv) && $minDv !== '' ? $need($minDv, 10, 'minDriverVersion') : null;
        $minV = is_string($minVv) && $minVv !== '' ? $need($minVv, 16, 'minVbiosVersion') : null;
        $denyD = array_map(static fn($v) => $need($v, 10, 'denyDriverVersions entry'), Common::isList(Common::g($fw, 'denyDriverVersions')) ? Common::g($fw, 'denyDriverVersions') : []);
        $denyV = array_map(static fn($v) => $need($v, 16, 'denyVbiosVersions entry'), Common::isList(Common::g($fw, 'denyVbiosVersions')) ? Common::g($fw, 'denyVbiosVersions') : []);
        return static function (array $ids) use ($minD, $minV, $denyD, $denyV, $minDv, $minVv): ?string {
            $d = self::parseVersion($ids['driverVersion'], 10);
            $v = self::parseVersion($ids['vbiosVersion'], 16);
            if ($d === null) {
                return "driver version '" . $ids['driverVersion'] . "' in the GPU report is not parseable";
            }
            if ($v === null) {
                return "VBIOS version '" . $ids['vbiosVersion'] . "' in the GPU report is not parseable";
            }
            if ($minD !== null && self::cmpVersion($d, $minD) < 0) {
                return 'driver ' . $ids['driverVersion'] . " is below the minimum $minDv";
            }
            if ($minV !== null && self::cmpVersion($v, $minV) < 0) {
                return 'VBIOS ' . $ids['vbiosVersion'] . " is below the minimum $minVv";
            }
            foreach ($denyD as $x) {
                if (self::cmpVersion($d, $x) === 0) {
                    return 'driver ' . $ids['driverVersion'] . ' is on the deny list';
                }
            }
            foreach ($denyV as $x) {
                if (self::cmpVersion($v, $x) === 0) {
                    return 'VBIOS ' . $ids['vbiosVersion'] . ' is on the deny list';
                }
            }
            return null;
        };
    }

    // ---- the collateral hook -------------------------------------------------------------------------------------------------------------------

    /**
     * The post-verification hook: RIM signature + golden comparison + driver / VBIOS version binding + revocation. Returns a closure
     * `(array $ctx): ?string` (a refusal reason or null). `$resolve` is `(array $ids, mixed $evidence): ?array` supplying the bundle
     * `{driverRimXml, vbiosRimXml, crls?, ocsp?}`.
     * @param callable $resolve
     */
    public static function collateralHook(mixed $opts, callable $resolve): \Closure
    {
        $pins = Common::g($opts, 'rimRootSpkiSha256');
        if (!Common::isList($pins) || count($pins) === 0) {
            throw new AttestConstructError('nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root');
        }
        $firmware = self::compileFirmwarePolicy(Common::g($opts, 'firmware'));
        $revocation = Common::g($opts, 'revocation');
        $requireCrls = Common::g($opts, 'requireCrls');
        $requireIssuers = Common::g($opts, 'requireCrlIssuers');
        return static function (array $ctx) use ($pins, $firmware, $resolve, $revocation, $requireCrls, $requireIssuers): ?string {
            $ids = self::rimIdsForReport($ctx['report']);
            if ($ids === null) {
                return 'GPU report does not carry the opaque fields needed to name its RIMs';
            }
            $subject = $ctx['leaf']->subject();
            if (preg_match('/(^|[^A-Za-z0-9])' . preg_quote($ids['chip'], '/') . '([^A-Za-z0-9]|$)/', $subject) !== 1) {
                return "device leaf subject '" . str_replace("\n", ', ', $subject) . "' is not a " . $ids['chip'] . ' device certificate (chip family mismatch)';
            }
            $fwWhy = $firmware($ids);
            if ($fwWhy !== null && $fwWhy !== '') {
                return "firmware policy: $fwWhy";
            }
            $bundle = $resolve($ids, $ctx['evidence'] ?? null);
            if ($bundle === null) {
                return 'no RIM collateral supplied for this report';
            }
            $now = $ctx['nowMs'];
            $d = self::verifyRim($bundle['driverRimXml'] ?? null, $pins, $now);
            $v = self::verifyRim($bundle['vbiosRimXml'] ?? null, $pins, $now);
            if (!$d['ok']) {
                return 'driver RIM: ' . $d['reason'];
            }
            if (!$v['ok']) {
                return 'VBIOS RIM: ' . $v['reason'];
            }
            if ($d['rim']['product'] !== $ids['chip']) {
                return "driver RIM product '" . $d['rim']['product'] . "' does not match the GPU chip '" . $ids['chip'] . "' (wrong-family manifest)";
            }
            if ($v['rim']['product'] !== $ids['chip']) {
                return "VBIOS RIM product '" . $v['rim']['product'] . "' does not match the GPU chip '" . $ids['chip'] . "' (wrong-family manifest)";
            }
            if ($d['rim']['version'] !== $ids['driverVersion']) {
                return "driver RIM version '" . $d['rim']['version'] . "' does not match the report's driver '" . $ids['driverVersion'] . "'";
            }
            if (strtoupper(str_replace('.', '', $v['rim']['version'])) !== strtoupper(str_replace('.', '', $ids['vbiosVersion']))) {
                return "VBIOS RIM version '" . $v['rim']['version'] . "' does not match the report's VBIOS '" . $ids['vbiosVersion'] . "'";
            }
            $cmp = self::compareReportToRims($ctx['report'], $d['rim'], $v['rim']);
            if (!$cmp['ok']) {
                return $cmp['reason'];
            }
            $mode = $revocation;
            if ($mode === null) {
                $mode = $requireCrls === false ? null : 'crl';
            }
            $crls = $bundle['crls'] ?? [];
            if (count($crls) > 0 || $mode === 'crl' || $mode === 'both') {
                $rev = self::checkChainRevocation($ctx['chain'], $crls, $now, Common::isList($requireIssuers) ? $requireIssuers : null);
                if (!$rev['ok']) {
                    return 'revocation: ' . $rev['reason'];
                }
            }
            $ocsp = $bundle['ocsp'] ?? [];
            if (count($ocsp) > 0 || $mode === 'ocsp' || $mode === 'both') {
                $o = Ocsp::checkNvidiaChain($ctx['chain'], $ocsp, $now);
                if (!$o['ok']) {
                    return 'revocation (OCSP): ' . $o['reason'];
                }
            }
            return null;
        };
    }

    // ---- the verifier ------------------------------------------------------------------------------------------------------------------------------

    /** @var list<string> */
    private array $pins;
    /** @var list<array{0:int,1:string}> */
    private array $want = [];
    private mixed $leafIncludes;
    private ?\Closure $postVerify;
    /** @var callable */
    private $resolve;

    /** Build the verifier from a vendor `config` (the schema of the vector file): rootSpkiSha256, policy, collateral. */
    public static function fromConfig(mixed $config, callable $resolve): self
    {
        $col = Common::g($config, 'collateral');
        $polIn = Common::g($config, 'policy');
        $pol = Common::isObj($polIn) ? $polIn : new \Atlas\Pca\Obj();
        $meas = Common::g($pol, 'measurements');
        $nv = ['rootSpkiSha256' => Common::g($config, 'rootSpkiSha256'), 'measurements' => $meas ?? new \Atlas\Pca\Obj(),
            'leafSubjectIncludes' => Common::g($pol, 'leafSubjectIncludes')];
        $hook = null;
        if ($col !== null && $col !== false) {
            $hookOpts = Common::isObj($col) ? Common::members($col) : [];
            $hook = self::collateralHook($hookOpts, static fn(array $ids, mixed $evidence): mixed => is_array($evidence) ? ($evidence['collateral'] ?? null) : null);
        }
        return new self($nv, $resolve, $hook);
    }

    /** @param array<string,mixed> $opts */
    public function __construct(array $opts, callable $resolve, ?\Closure $postVerify = null)
    {
        $pins = $opts['rootSpkiSha256'] ?? null;
        if (!Common::isList($pins) || count($pins) === 0) {
            throw new AttestConstructError('createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)');
        }
        $meas = $opts['measurements'] ?? null;
        $pinned = Common::isObj($meas) ? Common::members($meas) : [];
        $this->postVerify = $postVerify;
        if ($pinned === [] && $postVerify === null) {
            throw new AttestConstructError('createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)');
        }
        $want = [];
        foreach ($pinned as $i => $d) {
            $idx = Common::jsNumber((string)$i);
            if (!self::isInt($idx) || $idx < 0 || $idx > 255) {
                throw new AttestConstructError('createNvidiaSpdmVerifier: measurement index out of range');
            }
            $want[] = [(int)$idx, strtolower(Common::jsStr($d))];
        }
        $this->want = $want;
        $this->pins = array_map('strval', $pins);
        $this->leafIncludes = $opts['leafSubjectIncludes'] ?? null;
        $this->resolve = $resolve;
    }

    public function verify(mixed $document, mixed $expected, mixed $nowMs): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            $ev = ($this->resolve)($document);
            if (!is_array($ev) || !is_string($ev['evidence'] ?? null) || !is_string($ev['certChainPem'] ?? null)) {
                return $fail('no NVIDIA GPU evidence for this action');
            }
            $now = (float)Common::numOf($nowMs);
            $chain = self::verifyDeviceChain($ev['certChainPem'], $this->pins, $now);
            if (!$chain['ok']) {
                return $fail($chain['reason']);
            }
            /** @var Cert $leaf */
            $leaf = $chain['leaf'];
            $inc = $this->leafIncludes;
            if (is_string($inc) && $inc !== '' && !str_contains($leaf->subject(), $inc)) {
                return $fail("device leaf subject does not contain '$inc'");
            }
            try {
                $report = self::parseEvidence($ev['evidence']);
            } catch (\ValueError $e) {
                return $fail('GPU attestation report parse failed: ' . $e->getMessage());
            }
            // SPDM 1.1+ is the first version with the signed GET_MEASUREMENTS layout parsed here; request and response must agree
            $why = self::versionReason($report);
            if ($why !== null) {
                return $fail($why);
            }
            if (!Common::ecdsaVerifyRaw($leaf->publicKey(), $report['signature'], $report['signedBytes'], 'sha384')) {
                return $fail('GPU attestation report signature does not verify under the device identity key');
            }
            if ($expected === null) {
                return $fail('no expected attestation binding supplied');
            }
            try {
                $challenge = Common::challengeSha256($expected);
            } catch (\TypeError $e) {
                return $fail('binding not constructible: ' . $e->getMessage());
            }
            if ($report['request']['nonce'] !== $challenge) {
                return $fail('SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)');
            }
            $byIndex = [];
            foreach ($report['measurements'] as $m) {
                $byIndex[$m['index']] = $m;
            }
            foreach ($this->want as [$idx, $digestHex]) {
                $m = $byIndex[$idx] ?? null;
                if ($m === null) {
                    return $fail("measurement block $idx missing from report");
                }
                if (bin2hex($m['digest']) !== $digestHex) {
                    return $fail("measurement block $idx does not match the pinned digest");
                }
            }
            if ($this->postVerify !== null) {
                $why = ($this->postVerify)(['report' => $report, 'chain' => $chain['chain'], 'leaf' => $leaf, 'nowMs' => $now, 'evidence' => $ev]);
                if ($why !== null && $why !== '') {
                    return $fail($why);
                }
            }
            $ms = $report['measurements'];
            usort($ms, static fn($a, $b) => $a['index'] <=> $b['index']);
            $h = hash_init('sha384');
            foreach ($ms as $m) {
                hash_update($h, $m['digest']);
            }
            $host = ['attestation_type' => 'nvidia-gpu-cc', 'gpu_measurements_sha384' => hash_final($h), 'leaf_subject' => str_replace("\n", ', ', $leaf->subject())];
            $drv = $report['opaque'][self::OPAQUE_DRIVER_VERSION] ?? null;
            $vbios = $report['opaque'][self::OPAQUE_VBIOS_VERSION] ?? null;
            if ($drv !== null) {
                $host['driver_version'] = rtrim((string)mb_convert_encoding($drv, 'UTF-8', 'UTF-8'), "\0");
            }
            if ($vbios !== null) {
                $host['vbios_version'] = self::formatVbiosVersion($vbios);
            }
            return ['ok' => true, 'bound' => true, 'measured' => ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => '', 'operator' => ''],
                'hostAsserted' => $host];
        } catch (\Throwable $e) {
            return $fail('nvidia-spdm verification error (fail closed): ' . $e->getMessage());
        }
    }
}
