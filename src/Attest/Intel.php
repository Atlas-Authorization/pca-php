<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Amd.php';

/**
 * Intel TDX (DCAP v4, ECDSA-P256) attestation verifier and Intel PCS collateral evaluation: the native counterpart of
 * `createIntelDcapVerifier`, `verifyGenuineTdxQuote` and `verifyIntelTdxCollateral`. The PCK chain to the pinned Intel SGX
 * Root CA, the QE report under the PCK leaf, the attestation key endorsed by the QE, the TD quote signature, the PCA nonce
 * binding, the MRTD / FMSPC / RTMR0 allowlists and (by default REQUIRED) the signed TCB info / QE identity / CRL collateral.
 * Fails closed with the reference's reason strings.
 */
final class Intel implements HardwareVerifier
{
    public const SUITE = 'intel-tdx-dcap-ecdsa-p256';
    public const SGX_ROOT_CA_SPKI_SHA256 = 'a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e';
    private const HEADER_LEN = 48;
    private const TD_REPORT_LEN = 584;
    private const QE_ATTRIBUTES_OFF = 48;
    private const QE_REPORT_DATA_OFF = 0x140;
    private const SGX_REPORT_LEN = 384;
    private const OID_SGX_FMSPC = "\x06\x0A\x2A\x86\x48\x86\xF8\x4D\x01\x0D\x01\x04";
    private const OID_SGX_TCB = "\x06\x0A\x2A\x86\x48\x86\xF8\x4D\x01\x0D\x01\x02";
    public const STATUS_ORDER = ['UpToDate', 'SWHardeningNeeded', 'ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded',
        'OutOfDateConfigurationNeeded', 'OutOfDate', 'Revoked'];
    public const DEFAULT_ACCEPTED = ['UpToDate', 'SWHardeningNeeded'];

    private static function u16(string $b, int $o): int
    {
        return (int)unpack('v', substr($b, $o, 2))[1];
    }

    private static function u32(string $b, int $o): int
    {
        return (int)unpack('V', substr($b, $o, 4))[1];
    }

    // ---- quote parsing ---------------------------------------------------------------------------------------------------------

    /** Parse a DCAP v4 / ECDSA-P256 / TDX quote. Throws \ValueError (the reference's messages) on any structural violation. @return array<string,mixed> */
    public static function parseQuote(string $quote): array
    {
        if (strlen($quote) < self::HEADER_LEN + self::TD_REPORT_LEN + 4) {
            throw new \ValueError('parseDcapQuote: too short for header + TD report + sig length');
        }
        $version = self::u16($quote, 0);
        $akType = self::u16($quote, 2);
        $teeType = self::u32($quote, 4);
        if ($version !== 4) {
            throw new \ValueError("parseDcapQuote: unsupported quote version $version (expected 4)");
        }
        if ($akType !== 2) {
            throw new \ValueError("parseDcapQuote: unsupported attestation key type $akType (expected ECDSA-P256 = 2)");
        }
        if ($teeType !== 0x81) {
            throw new \ValueError('parseDcapQuote: unexpected TEE type 0x' . dechex($teeType) . ' (expected TDX = 0x81)');
        }
        $header = substr($quote, 0, self::HEADER_LEN);
        $tdBody = substr($quote, self::HEADER_LEN, self::TD_REPORT_LEN);
        $o = self::HEADER_LEN + self::TD_REPORT_LEN;
        $sigLen = self::u32($quote, $o);
        $o += 4;
        $sigEnd = $o + $sigLen;
        if ($sigEnd > strlen($quote)) {
            throw new \ValueError("parseDcapQuote: signature data ($sigLen) overruns the quote");
        }
        $need = static function (int $n, string $what) use (&$o, $sigEnd): void {
            if ($o + $n > $sigEnd) {
                throw new \ValueError("parseDcapQuote: truncated reading $what");
            }
        };
        $need(64, 'quote signature');
        $quoteSignature = substr($quote, $o, 64);
        $o += 64;
        $need(64, 'attestation public key');
        $akPubRaw = substr($quote, $o, 64);
        $o += 64;
        $need(6, 'outer cert-data header');
        $outerType = self::u16($quote, $o);
        $outerSize = self::u32($quote, $o + 2);
        $o += 6;
        if ($outerType !== 6) {
            throw new \ValueError("parseDcapQuote: outer cert-data type $outerType (expected QE-report-cert-data = 6)");
        }
        $outerEnd = $o + $outerSize;
        if ($outerEnd > $sigEnd) {
            throw new \ValueError('parseDcapQuote: outer cert-data overruns signature data');
        }
        $need(self::SGX_REPORT_LEN, 'QE report');
        $qeReport = substr($quote, $o, self::SGX_REPORT_LEN);
        $o += self::SGX_REPORT_LEN;
        $need(64, 'QE report signature');
        $qeSig = substr($quote, $o, 64);
        $o += 64;
        $need(2, 'QE auth-data size');
        $authSize = self::u16($quote, $o);
        $o += 2;
        $need($authSize, 'QE auth-data');
        $qeAuth = substr($quote, $o, $authSize);
        $o += $authSize;
        $need(6, 'inner cert-data header');
        $innerType = self::u16($quote, $o);
        $innerSize = self::u32($quote, $o + 2);
        $o += 6;
        if ($innerType !== 5) {
            throw new \ValueError("parseDcapQuote: inner cert-data type $innerType (expected PCK-cert-chain = 5)");
        }
        if ($o + $innerSize > $outerEnd) {
            throw new \ValueError('parseDcapQuote: inner cert-data overruns outer cert-data');
        }
        $pem = substr($quote, $o, $innerSize);
        // Azure pads the quote with zero bytes after the declared signature data; anything else is unverified data riding along
        if (trim(substr($quote, $sigEnd), "\0") !== '') {
            throw new \ValueError('parseDcapQuote: non-zero bytes after the signature data');
        }
        return ['header' => $header, 'tdReportBody' => $tdBody, 'quoteSignature' => $quoteSignature, 'akPubRaw' => $akPubRaw,
            'qeReportBody' => $qeReport, 'qeReportSignature' => $qeSig, 'qeAuthData' => $qeAuth, 'pckChainPem' => $pem];
    }

    /** @return array<string,string> */
    public static function parseTdReport(string $body): array
    {
        if (strlen($body) < self::TD_REPORT_LEN) {
            throw new \ValueError('parseDcapTdReport: body too short (' . strlen($body) . ' < ' . self::TD_REPORT_LEN . ')');
        }
        return ['teeTcbSvn' => substr($body, 0, 16), 'mrSeam' => substr($body, 16, 48), 'mrSignerSeam' => substr($body, 64, 48),
            'tdAttributes' => substr($body, 120, 8), 'mrTd' => substr($body, 136, 48), 'rtmr0' => substr($body, 328, 48), 'reportData' => substr($body, 520, 64)];
    }

    // ---- PCK certificate ---------------------------------------------------------------------------------------------------------

    private static function lenientTlv(string $buf, int $off): ?Tlv
    {
        try {
            return Der::tlvLenient($buf, $off);
        } catch (DerError) {
            return null;
        }
    }

    /** FMSPC + the PCK leaf's issued TCB, read from the Intel SGX extension (1.2.840.113741.1.13.1). Throws \ValueError on anything off. @return array<string,mixed> */
    public static function extractPckFmspcAndTcb(string $leafDer): array
    {
        $fi = strpos($leafDer, self::OID_SGX_FMSPC);
        if ($fi === false) {
            throw new \ValueError('extractPckFmspcAndTcb: FMSPC OID not found in certificate');
        }
        $fv = self::lenientTlv($leafDer, $fi + strlen(self::OID_SGX_FMSPC));
        if ($fv === null || $fv->tag !== 0x04 || $fv->end - $fv->start !== 6) {
            throw new \ValueError('extractPckFmspcAndTcb: malformed FMSPC OCTET STRING');
        }
        $fmspc = substr($leafDer, $fv->start, 6);
        $ti = strpos($leafDer, self::OID_SGX_TCB);
        if ($ti === false) {
            throw new \ValueError('extractPckFmspcAndTcb: TCB OID not found in certificate');
        }
        $seq = self::lenientTlv($leafDer, $ti + strlen(self::OID_SGX_TCB));
        if ($seq === null || $seq->tag !== 0x30) {
            throw new \ValueError('extractPckFmspcAndTcb: malformed TCB SEQUENCE');
        }
        $sgx = array_fill(0, 16, 0);
        $pcesvn = -1;
        $p = $seq->start;
        $idx = 0;
        while ($p < $seq->end) {
            $pair = self::lenientTlv($leafDer, $p);
            if ($pair === null || $pair->tag !== 0x30) {
                throw new \ValueError('extractPckFmspcAndTcb: malformed TCB component');
            }
            $oid = self::lenientTlv($leafDer, $pair->start);
            if ($oid === null || $oid->tag !== 0x06) {
                throw new \ValueError('extractPckFmspcAndTcb: TCB component missing OID');
            }
            $val = self::lenientTlv($leafDer, $oid->end);
            if ($val === null) {
                throw new \ValueError('extractPckFmspcAndTcb: TCB component missing value');
            }
            $last = ord($leafDer[$oid->end - 1]);
            if ($val->tag === 0x02) {
                $n = 0;
                for ($b = $val->start; $b < $val->end; $b++) {
                    $n = (($n << 8) | ord($leafDer[$b])) & 0xFFFFFFFFFFFF;
                }
                if ($last >= 1 && $last <= 16) {
                    $sgx[$last - 1] = $n & 0xFF;
                } elseif ($last === 17) {
                    $pcesvn = $n & 0xFFFF;
                }
            }
            $p = $pair->end;
            $idx++;
            if ($idx > 64) {
                break;
            }
        }
        if ($pcesvn < 0) {
            throw new \ValueError('extractPckFmspcAndTcb: PCESVN not found in TCB extension');
        }
        return ['fmspc' => $fmspc, 'sgxTcbComponents' => pack('C*', ...$sgx), 'pcesvn' => $pcesvn];
    }

    /** The embedded PCK chain to the PINNED Intel SGX Root CA: every certificate valid at `now`, every link signed, CA roles. @return array<string,mixed> */
    public static function verifyPckChain(mixed $pckChainPem, ?string $trustAnchor = null, mixed $nowMs = null): array
    {
        try {
            $blocks = is_string($pckChainPem) ? Common::pemBlocks($pckChainPem) : [];
            if ($blocks === []) {
                return ['ok' => false, 'reason' => 'no PEM certificates in the PCK chain'];
            }
            $certs = array_map(static fn($b) => Cert::fromPem($b), $blocks);
            $issuers = [];
            $bySubject = [];
            foreach ($certs as $c) {
                $issuers[$c->issuer()] = true;
                $bySubject[$c->subject()] = $c;
            }
            $leaf = $certs[0];
            foreach ($certs as $c) {
                if (!isset($issuers[$c->subject()])) {
                    $leaf = $c;
                    break;
                }
            }
            $ordered = [];
            $seen = [];
            $cur = $leaf;
            while ($cur !== null && !isset($seen[$cur->subject()])) {
                $ordered[] = $cur;
                $seen[$cur->subject()] = true;
                if ($cur->subject() === $cur->issuer()) {
                    break;
                }
                $cur = $bySubject[$cur->issuer()] ?? null;
            }
            $root = $ordered[count($ordered) - 1];
            if ($root->subject() !== $root->issuer()) {
                return ['ok' => false, 'reason' => 'PCK chain does not terminate in a self-signed root'];
            }
            if (count($ordered) !== count($certs)) {
                return ['ok' => false, 'reason' => 'PCK chain is not a single connected path (orphan/duplicate certificates)'];
            }
            $now = $nowMs ?? microtime(true) * 1000;
            if (!Common::isNum($now)) {
                return ['ok' => false, 'reason' => 'nowMs is not a finite number'];
            }
            $nowF = (float)Common::numOf($now);
            foreach ($ordered as $c) {
                if (!Der::x509ValidAt($c->raw, $nowF)) {
                    return ['ok' => false, 'reason' => 'PCK chain certificate outside its validity period', 'failure' => 'validity'];
                }
            }
            for ($i = 0; $i < count($ordered) - 1; $i++) {
                $child = $ordered[$i];
                $parent = $ordered[$i + 1];
                if ($child->issuer() !== $parent->subject()) {
                    return ['ok' => false, 'reason' => "certificate at depth $i issuer does not match its parent subject"];
                }
                if (!$child->verify($parent->publicKey())) {
                    return ['ok' => false, 'reason' => "certificate at depth $i is not signed by its issuer"];
                }
            }
            if (!$root->verify($root->publicKey())) {
                return ['ok' => false, 'reason' => 'root certificate is not self-signed'];
            }
            $pin = strtolower($trustAnchor ?? self::SGX_ROOT_CA_SPKI_SHA256);
            if (Common::spkiSha($root->publicKey(), 'sha256') !== $pin) {
                return ['ok' => false, 'reason' => 'Intel SGX Root CA does not match the pinned trust anchor'];
            }
            $roleFail = Der::checkChainRoles(array_map(static fn($c) => $c->raw, $ordered));
            if ($roleFail !== null) {
                return ['ok' => false, 'reason' => $roleFail];
            }
            foreach ($ordered as $i => $c) {
                $crit = Der::unrecognisedCriticalExtension($c->raw);
                if ($crit !== null) {
                    return ['ok' => false, 'reason' => "PCK chain certificate at depth $i has an unrecognised critical extension $crit"];
                }
            }
            $leafPk = $leaf->publicKey();
            if ($leafPk->type !== 'ec') {
                return ['ok' => false, 'reason' => 'PCK leaf key is not EC (got ' . $leafPk->type . ')'];
            }
            $leafKey = Common::ecKeyFromPoint('P-256', Common::ecPoint($leafPk, 'P-256'));
            return ['ok' => true, 'leafKey' => $leafKey, 'leafDer' => $leaf->raw, 'leafCert' => $leaf, 'depth' => count($ordered)];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'PCK chain X.509 verification error (fail closed): ' . $e->getMessage()];
        }
    }

    private static function verifyP256(string $msg, string $sigCompact, PubKey $key): bool
    {
        try {
            return Common::ecdsaVerifyRaw($key, $sigCompact, $msg, 'sha256');
        } catch (\Throwable) {
            return false;
        }
    }

    /** @return list<string> */
    private static function lowerList(mixed $v): array
    {
        return array_map(static fn($x) => strtolower((string)$x), Common::isList($v) ? $v : []);
    }

    /**
     * A genuine DCAP v4 TDX quote end to end, offline (no PCS collateral). Fails closed with a reason.
     * @param array<string,mixed>|null $policy
     * @return array<string,mixed>
     */
    public static function verifyGenuineQuote(string $quote, ?string $trustAnchor = null, mixed $expected = null, ?array $policy = null, mixed $nowMs = null): array
    {
        try {
            try {
                $q = self::parseQuote($quote);
            } catch (\ValueError $e) {
                return ['ok' => false, 'reason' => 'quote parse failed: ' . $e->getMessage()];
            }
            try {
                $report = self::parseTdReport($q['tdReportBody']);
            } catch (\ValueError $e) {
                return ['ok' => false, 'reason' => 'TD report parse failed: ' . $e->getMessage()];
            }
            $chain = self::verifyPckChain($q['pckChainPem'], $trustAnchor, $nowMs);
            if (!$chain['ok'] || !isset($chain['leafKey'], $chain['leafDer'])) {
                return ['ok' => false, 'reason' => 'PCK chain invalid: ' . ($chain['reason'] ?? 'unknown')];
            }
            try {
                $pckTcb = self::extractPckFmspcAndTcb($chain['leafDer']);
            } catch (\ValueError $e) {
                return ['ok' => false, 'reason' => 'PCK FMSPC/TCB extraction failed: ' . $e->getMessage()];
            }
            if (!self::verifyP256($q['qeReportBody'], $q['qeReportSignature'], $chain['leafKey'])) {
                return ['ok' => false, 'reason' => 'QE report signature does not verify under the PCK leaf'];
            }
            // a debug QE can forge endorsements (SGX REPORT.ATTRIBUTES.FLAGS bit 1)
            if ((ord($q['qeReportBody'][self::QE_ATTRIBUTES_OFF]) & 0x02) !== 0) {
                return ['ok' => false, 'reason' => 'QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)'];
            }
            $qeData = substr($q['qeReportBody'], self::QE_REPORT_DATA_OFF, 64);
            $akBinding = hash('sha256', $q['akPubRaw'] . $q['qeAuthData'], true);
            if (substr($qeData, 0, 32) !== $akBinding || trim(substr($qeData, 32, 32), "\0") !== '') {
                return ['ok' => false, 'reason' => 'QE report_data does not bind the attestation key (AK not endorsed by this QE)'];
            }
            try {
                $akPub = Common::ecKeyFromPoint('P-256', "\x04" . $q['akPubRaw']);
            } catch (\Throwable) {
                return ['ok' => false, 'reason' => 'attestation public key is not a valid P-256 point'];
            }
            if (!self::verifyP256($q['header'] . $q['tdReportBody'], $q['quoteSignature'], $akPub)) {
                return ['ok' => false, 'reason' => 'TD quote signature does not verify under the attestation key'];
            }
            if ($expected !== null) {
                try {
                    $expectedData = Common::attestationBinding($expected);
                } catch (\TypeError $e) {
                    return ['ok' => false, 'reason' => 'binding not constructible: ' . $e->getMessage()];
                }
                if ($expectedData !== $report['reportData']) {
                    return ['ok' => false, 'reason' => 'report_data does not bind holder/grant/epoch/nonce'];
                }
            }
            $pol = $policy ?? [];
            if (($pol['allowDebug'] ?? null) !== true && (ord($report['tdAttributes'][0]) & 1) !== 0) {
                return ['ok' => false, 'reason' => 'TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)'];
            }
            $fmspcHex = bin2hex($pckTcb['fmspc']);
            if ($policy !== null) {
                $allowed = static function (string $key, string $value, bool $needNonEmpty) use ($policy): bool {
                    $lst = $policy[$key] ?? null;
                    if (!Common::isList($lst) || ($needNonEmpty && count($lst) === 0)) {
                        return true;
                    }
                    return in_array(bin2hex($value), self::lowerList($lst), true);
                };
                if (!$allowed('mrtds', $report['mrTd'], true)) {
                    return ['ok' => false, 'reason' => 'MRTD not in policy allowlist'];
                }
                if (!$allowed('fmspcs', $pckTcb['fmspc'], true)) {
                    return ['ok' => false, 'reason' => 'FMSPC not in policy allowlist'];
                }
                if (!$allowed('mrSeams', $report['mrSeam'], false)) {
                    return ['ok' => false, 'reason' => 'MRSEAM not in policy allowlist'];
                }
                if (!$allowed('mrSignerSeams', $report['mrSignerSeam'], false)) {
                    return ['ok' => false, 'reason' => 'MRSIGNERSEAM not in policy allowlist'];
                }
                if (!$allowed('rtmrs', $report['rtmr0'], true)) {
                    return ['ok' => false, 'reason' => 'RTMR0 not in policy allowlist'];
                }
            }
            $measured = ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => bin2hex($report['mrTd']), 'operator' => ''];
            return ['ok' => true, 'report' => $report, 'fmspc' => $fmspcHex, 'pckTcb' => $pckTcb, 'chainDepth' => $chain['depth'], 'measured' => $measured];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'genuine TDX verification error (fail closed): ' . $e->getMessage()];
        }
    }

    // ---- collateral: CRL ------------------------------------------------------------------------------------------------------------

    private static function tlv(string $b, int $off, ?int $limit = null): Tlv
    {
        $limit ??= strlen($b);
        if ($off + 2 > $limit) {
            throw new \ValueError('DER truncated');
        }
        $tag = ord($b[$off]);
        $ln = ord($b[$off + 1]);
        $p = $off + 2;
        if (($ln & 0x80) !== 0) {
            $n = $ln & 0x7F;
            if ($n === 0 || $n > 4 || $p + $n > $limit) {
                throw new \ValueError('DER bad length');
            }
            $ln = 0;
            for ($i = 0; $i < $n; $i++) {
                $ln = $ln * 256 + ord($b[$p + $i]);
            }
            $p += $n;
        }
        if ($p + $ln > $limit) {
            throw new \ValueError('DER overrun');
        }
        return new Tlv($tag, $p, $p + $ln);
    }

    /** Date.UTC: months and days roll over, years 0..99 mean 1900..1999. */
    private static function dateUtc(int $y, int $mon0, int $d, int $h, int $mi, int $s): int
    {
        if ($y >= 0 && $y <= 99) {
            $y += 1900;
        }
        $y += intdiv($mon0 >= 0 ? $mon0 : $mon0 - 11, 12);
        $mon0 = (($mon0 % 12) + 12) % 12;
        $days = Der::daysFromCivil($y, $mon0 + 1, 1) + ($d - 1);
        return ((($days * 24 + $h) * 60 + $mi) * 60 + $s) * 1000;
    }

    private static function derTime(string $b, Tlv $t): int
    {
        $s = substr($b, $t->start, $t->end - $t->start);
        if ($t->tag === 0x17) {
            if (preg_match('/\A([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z/', $s, $m) !== 1) {
                throw new \ValueError('bad UTCTime');
            }
            $yy = (int)$m[1];
            return self::dateUtc($yy >= 50 ? 1900 + $yy : 2000 + $yy, (int)$m[2] - 1, (int)$m[3], (int)$m[4], (int)$m[5], (int)$m[6]);
        }
        if ($t->tag === 0x18) {
            if (preg_match('/\A([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z/', $s, $m) !== 1) {
                throw new \ValueError('bad GeneralizedTime');
            }
            return self::dateUtc((int)$m[1], (int)$m[2] - 1, (int)$m[3], (int)$m[4], (int)$m[5], (int)$m[6]);
        }
        throw new \ValueError('not a DER time');
    }

    public static function normSerial(string $hex): string
    {
        return ltrim(strtolower($hex), '0');
    }

    /** @return array<string,mixed> */
    private static function parseCrl(string $der): array
    {
        $outer = self::tlv($der, 0);
        if ($outer->tag !== 0x30 || $outer->end !== strlen($der)) {
            throw new \ValueError('CRL: bad outer SEQUENCE');
        }
        $tbsT = self::tlv($der, $outer->start, $outer->end);
        if ($tbsT->tag !== 0x30) {
            throw new \ValueError('CRL: bad TBSCertList');
        }
        $tbs = substr($der, $outer->start, $tbsT->end - $outer->start);
        $algT = self::tlv($der, $tbsT->end, $outer->end);
        $sigT = self::tlv($der, $algT->end, $outer->end);
        if ($sigT->tag !== 0x03 || $sigT->end !== $outer->end) {
            throw new \ValueError('CRL: bad signature');
        }
        $sigDer = substr($der, $sigT->start + 1, $sigT->end - $sigT->start - 1);
        $p = $tbsT->start;
        $t = self::tlv($der, $p, $tbsT->end);
        if ($t->tag === 0x02) {
            $p = $t->end;
            $t = self::tlv($der, $p, $tbsT->end);
        }
        $p = $t->end;
        $iss = self::tlv($der, $p, $tbsT->end);
        if ($iss->tag !== 0x30) {
            throw new \ValueError('CRL: bad issuer');
        }
        $tu = self::tlv($der, $iss->end, $tbsT->end);
        $thisUpdate = self::derTime($der, $tu);
        $q = $tu->end;
        $nextUpdate = null;
        $revoked = [];
        if ($q < $tbsT->end) {
            $n = self::tlv($der, $q, $tbsT->end);
            if ($n->tag === 0x17 || $n->tag === 0x18) {
                $nextUpdate = self::derTime($der, $n);
                $q = $n->end;
            }
            if ($q < $tbsT->end) {
                $n = self::tlv($der, $q, $tbsT->end);
                if ($n->tag === 0x30) {
                    $e = $n->start;
                    while ($e < $n->end) {
                        $ent = self::tlv($der, $e, $n->end);
                        $ser = self::tlv($der, $ent->start, $ent->end);
                        if ($ser->tag !== 0x02) {
                            throw new \ValueError('CRL: bad revoked entry');
                        }
                        $revoked[self::normSerial(bin2hex(substr($der, $ser->start, $ser->end - $ser->start)))] = true;
                        $e = $ent->end;
                    }
                }
            }
        }
        if ($nextUpdate === null) {
            throw new \ValueError('CRL: missing nextUpdate');
        }
        return ['tbs' => $tbs, 'thisUpdate' => $thisUpdate, 'nextUpdate' => $nextUpdate, 'revoked' => $revoked, 'sigDer' => $sigDer];
    }

    /** A CRL (DER) under `$issuerKey` at `now`: `{ok, revoked}` (lowercase hex serials, no leading zeros) or `{ok: false, reason}`. @return array<string,mixed> */
    public static function verifyCrl(string $crlDer, PubKey $issuerKey, float $nowMs): array
    {
        try {
            $crl = self::parseCrl($crlDer);
        } catch (\ValueError $e) {
            return ['ok' => false, 'reason' => 'CRL parse failed: ' . $e->getMessage()];
        }
        $good = match ($issuerKey->type) {
            'ec' => Common::ecdsaVerifyDer($issuerKey, $crl['sigDer'], $crl['tbs'], 'sha256'),
            'rsa' => Common::rsaPkcs1Verify($issuerKey, $crl['sigDer'], $crl['tbs'], 'sha256'),
            default => false,
        };
        if (!$good) {
            return ['ok' => false, 'reason' => 'CRL signature does not verify under the issuer'];
        }
        if ($nowMs < $crl['thisUpdate']) {
            return ['ok' => false, 'reason' => 'CRL thisUpdate is in the future'];
        }
        if ($nowMs > $crl['nextUpdate']) {
            return ['ok' => false, 'reason' => 'CRL is stale (nextUpdate passed)'];
        }
        return ['ok' => true, 'revoked' => $crl['revoked']];
    }

    /** @param array<string,true> $revoked */
    public static function serialIsRevoked(array $revoked, string $serialHex): bool
    {
        return isset($revoked[self::normSerial($serialHex)]);
    }

    // ---- collateral: signed JSON -----------------------------------------------------------------------------------------------------

    /** @param array<string,true> $rootRevoked @return array<string,mixed> */
    private static function signerKeyFromChain(string $chainPem, ?string $pin, float $nowMs, array $rootRevoked): array
    {
        $chain = self::verifyPckChain($chainPem, $pin, $nowMs);
        if (($chain['failure'] ?? null) === 'validity') {
            return ['error' => 'issuer chain certificate outside its validity period'];
        }
        if (!$chain['ok'] || !isset($chain['leafDer'])) {
            return ['error' => 'issuer chain invalid: ' . ($chain['reason'] ?? 'unknown')];
        }
        foreach (Common::pemBlocks($chainPem) as $b) {
            $c = Cert::fromPem($b);
            if (!Der::x509ValidAt($c->raw, $nowMs)) {
                return ['error' => 'issuer chain certificate outside its validity period'];
            }
            if (self::serialIsRevoked($rootRevoked, $c->serialHex())) {
                return ['error' => 'issuer chain certificate is revoked by the Intel Root CA CRL'];
            }
        }
        return ['key' => $chain['leafCert']->publicKey()];
    }

    private static function rawJsonObject(string $text, string $name): ?string
    {
        if (preg_match('/\A\s*\{\s*"' . preg_quote($name, '/') . '"\s*:\s*/', $text, $m) !== 1) {
            return null;
        }
        $s = strlen($m[0]);
        if ($s >= strlen($text) || $text[$s] !== '{') {
            return null;
        }
        $depth = 0;
        $inStr = false;
        $n = strlen($text);
        for ($i = $s; $i < $n; $i++) {
            $ch = $text[$i];
            if ($inStr) {
                if ($ch === '\\') {
                    $i++;
                } elseif ($ch === '"') {
                    $inStr = false;
                }
            } elseif ($ch === '"') {
                $inStr = true;
            } elseif ($ch === '{') {
                $depth++;
            } elseif ($ch === '}') {
                $depth--;
                if ($depth === 0) {
                    return substr($text, $s, $i - $s + 1);
                }
            }
        }
        return null;
    }

    /** @return array<string,mixed> */
    private static function verifySignedJson(string $text, string $name, PubKey $key): array
    {
        $raw = self::rawJsonObject($text, $name);
        if ($raw === null) {
            return ['error' => "$name not found / malformed"];
        }
        try {
            $doc = JsJson::parse($text);
        } catch (JsError) {
            return ['error' => "$name document is not valid JSON"];
        }
        $sig = Common::g($doc, 'signature');
        if (!is_string($sig) || preg_match('/\A[0-9a-fA-F]{128}\z/', $sig) !== 1) {
            return ['error' => "$name signature missing or malformed"];
        }
        if (!Common::ecdsaVerifyRaw($key, (string)hex2bin($sig), $raw, 'sha256')) {
            return ['error' => "$name signature does not verify under the TCB Signing certificate"];
        }
        $body = Common::g($doc, $name);
        if (!Common::isObj($body)) {
            return ['error' => "$name is not an object"];
        }
        return ['body' => $body];
    }

    /** Date.parse for the ISO 8601 forms Intel PCS emits (a zone-less date-time is read as UTC); null for anything else. */
    public static function jsDateParse(string $s): ?int
    {
        if (preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?(Z|[+-][0-9]{2}:[0-9]{2})?)?\z/', $s, $m) !== 1) {
            return null;
        }
        $y = (int)$m[1];
        $mo = (int)$m[2];
        $d = (int)$m[3];
        $h = (int)($m[4] ?? 0);
        $mi = (int)($m[5] ?? 0);
        $sec = (int)($m[6] ?? 0);
        $ms = (int)str_pad(substr($m[7] ?? '0', 0, 3), 3, '0');
        if ($mo < 1 || $mo > 12 || $d < 1 || $d > 31 || $h > 24 || $mi > 59 || $sec > 59 || ($h === 24 && ($mi !== 0 || $sec !== 0 || $ms !== 0))) {
            return null;
        }
        if ($d > Der::daysInMonth($y, $mo)) {
            return null;
        }
        $t = ((Der::daysFromCivil($y, $mo, $d) * 24 + $h) * 60 + $mi) * 60 + $sec;
        $t = $t * 1000 + $ms;
        $tz = $m[8] ?? '';
        if ($tz !== '' && $tz !== 'Z') {
            $off = ((int)substr($tz, 1, 2) * 60 + (int)substr($tz, 4, 2)) * 60_000;
            $t -= $tz[0] === '+' ? $off : -$off;
        }
        return $t;
    }

    private static function checkFresh(mixed $body, string $what, float $nowMs): ?string
    {
        $issueS = Common::g($body, 'issueDate');
        $nextS = Common::g($body, 'nextUpdate');
        $issue = is_string($issueS) ? self::jsDateParse($issueS) : null;
        $nxt = is_string($nextS) ? self::jsDateParse($nextS) : null;
        if ($issue === null || $nxt === null) {
            return "$what: issueDate/nextUpdate missing";
        }
        if ($nowMs < $issue) {
            return "$what: issueDate is in the future";
        }
        if ($nowMs > $nxt) {
            return "$what: stale (nextUpdate passed)";
        }
        return null;
    }

    // ---- collateral: status evaluation ---------------------------------------------------------------------------------------------------

    private static function asStatus(mixed $s): ?string
    {
        return is_string($s) && in_array($s, self::STATUS_ORDER, true) ? $s : null;
    }

    private static function worst(string $a, string $b): string
    {
        return array_search($a, self::STATUS_ORDER, true) >= array_search($b, self::STATUS_ORDER, true) ? $a : $b;
    }

    /** @return list<float>|null */
    private static function svns(mixed $comps): ?array
    {
        if (!Common::isList($comps) || count($comps) !== 16) {
            return null;
        }
        $out = [];
        foreach ($comps as $c) {
            $v = Common::isObj($c) ? Common::numOf(Common::g($c, 'svn')) : null;
            if ($v === null) {
                return null;
            }
            $out[] = $v;
        }
        return $out;
    }

    private static function hexBytes(mixed $s, int $ln): ?string
    {
        if (!is_string($s) || strlen($s) !== $ln * 2 || preg_match('/\A[0-9a-fA-F]+\z/', $s) !== 1) {
            return null;
        }
        return (string)hex2bin($s);
    }

    /** @return list<string> */
    private static function advisories(mixed $level): array
    {
        $a = Common::g($level, 'advisoryIDs');
        return Common::isList($a) ? array_values(array_filter($a, 'is_string')) : [];
    }

    private static function maskedEq(string $value, string $mask, string $expected): bool
    {
        for ($i = 0; $i < strlen($value); $i++) {
            if (((ord($value[$i]) & ord($mask[$i])) ^ (ord($expected[$i]) & ord($mask[$i]))) !== 0) {
                return false;
            }
        }
        return true;
    }

    /** @return list<mixed> */
    private static function listOf(mixed $v): array
    {
        return Common::isList($v) ? $v : [];
    }

    /** @param array<string,mixed> $pck @param array<string,string> $td @return array<string,mixed> */
    private static function evaluateTcb(mixed $info, array $pck, array $td): array
    {
        $levels = Common::g($info, 'tcbLevels');
        if (!Common::isList($levels) || count($levels) === 0) {
            return ['error' => 'TCB info has no tcbLevels'];
        }
        $minor = ord($td['teeTcbSvn'][1]);
        $moduleStatus = 'UpToDate';
        $adv = [];
        if ($minor > 0) {
            $identId = sprintf('TDX_%02X', $minor);
            $ids = Common::g($info, 'tdxModuleIdentities');
            $ident = null;
            foreach (self::listOf($ids) as $x) {
                if (Common::isObj($x) && Common::g($x, 'id') === $identId) {
                    $ident = $x;
                    break;
                }
            }
            if ($ident === null) {
                return ['error' => "TDX module identity $identId not present in TCB info"];
            }
            $modMr = Common::g($ident, 'mrsigner');
            $modAttr = Common::g($ident, 'attributes');
            $modMask = Common::g($ident, 'attributesMask');
            $hit = null;
            foreach (self::listOf(Common::g($ident, 'tcbLevels')) as $l) {
                $tcb = Common::isObj($l) ? Common::g($l, 'tcb') : null;
                $isv = Common::isObj($tcb) ? Common::numOf(Common::g($tcb, 'isvsvn')) : null;
                if ($isv !== null && $isv <= ord($td['teeTcbSvn'][0])) {
                    $hit = $l;
                    break;
                }
            }
            if ($hit === null) {
                return ['error' => "TDX module $identId SVN " . ord($td['teeTcbSvn'][0]) . ' is below every known level'];
            }
            $st = self::asStatus(Common::g($hit, 'tcbStatus'));
            if ($st === null) {
                return ['error' => 'TDX module level has an unknown tcbStatus'];
            }
            $moduleStatus = $st;
            foreach (self::advisories($hit) as $a) {
                $adv[$a] = true;
            }
        } else {
            $m = Common::g($info, 'tdxModule');
            if (!Common::isObj($m)) {
                return ['error' => 'TCB info missing tdxModule'];
            }
            $modMr = Common::g($m, 'mrsigner');
            $modAttr = Common::g($m, 'attributes');
            $modMask = Common::g($m, 'attributesMask');
        }
        $exMr = self::hexBytes($modMr, 48);
        $exAttr = self::hexBytes($modAttr, 8);
        $mask = self::hexBytes($modMask, 8);
        if ($exMr === null || $exAttr === null || $mask === null) {
            return ['error' => 'TDX module identity fields malformed'];
        }
        if ($exMr !== $td['mrSignerSeam']) {
            return ['error' => 'TD report MRSIGNERSEAM does not match the TDX module identity'];
        }
        if (!self::maskedEq($td['seamAttributes'], $mask, $exAttr)) {
            return ['error' => 'TD report SEAM attributes do not match the TDX module identity'];
        }
        $start = $minor > 0 ? 2 : 0;
        foreach ($levels as $l) {
            $tcb = Common::isObj($l) ? Common::g($l, 'tcb') : null;
            if (!Common::isObj($tcb)) {
                return ['error' => 'malformed TCB level'];
            }
            $sgx = self::svns(Common::g($tcb, 'sgxtcbcomponents'));
            $tdx = self::svns(Common::g($tcb, 'tdxtcbcomponents'));
            $pce = Common::numOf(Common::g($tcb, 'pcesvn'));
            if ($sgx === null || $tdx === null || $pce === null) {
                return ['error' => 'malformed TCB level components'];
            }
            $st = self::asStatus(Common::g($l, 'tcbStatus'));
            if ($st === null) {
                return ['error' => 'TCB level has an unknown tcbStatus'];
            }
            $match = $pck['pcesvn'] >= $pce;
            for ($i = 0; $match && $i < 16; $i++) {
                if (ord($pck['sgx'][$i]) < $sgx[$i]) {
                    $match = false;
                }
            }
            for ($i = $start; $match && $i < 16; $i++) {
                if (ord($td['teeTcbSvn'][$i]) < $tdx[$i]) {
                    $match = false;
                }
            }
            if (!$match) {
                continue;
            }
            foreach (self::advisories($l) as $a) {
                $adv[$a] = true;
            }
            $ids = array_map('strval', array_keys($adv));
            usort($ids, 'strcmp');
            return ['platform' => $st, 'module' => $moduleStatus, 'advisories' => $ids];
        }
        return ['error' => 'platform TCB is below every level in the TCB info'];
    }

    /** @return array<string,mixed> */
    private static function evaluateQe(mixed $ident, string $qe): array
    {
        if (Common::g($ident, 'id') !== 'TD_QE') {
            return ['error' => 'QE identity id is not TD_QE'];
        }
        $ver = Common::numOf(Common::g($ident, 'version'));
        if ($ver === null || $ver !== 2.0) {
            return ['error' => 'unsupported QE identity version'];
        }
        $miscsel = self::hexBytes(Common::g($ident, 'miscselect'), 4);
        $miscMask = self::hexBytes(Common::g($ident, 'miscselectMask'), 4);
        $attr = self::hexBytes(Common::g($ident, 'attributes'), 16);
        $attrMask = self::hexBytes(Common::g($ident, 'attributesMask'), 16);
        $mrsigner = self::hexBytes(Common::g($ident, 'mrsigner'), 32);
        $prodId = Common::numOf(Common::g($ident, 'isvprodid'));
        if ($miscsel === null || $miscMask === null || $attr === null || $attrMask === null || $mrsigner === null || $prodId === null) {
            return ['error' => 'QE identity fields malformed'];
        }
        if (strlen($qe) !== 384) {
            return ['error' => 'QE report has wrong length'];
        }
        if (!self::maskedEq(substr($qe, 16, 4), $miscMask, $miscsel)) {
            return ['error' => 'QE MISCSELECT does not match the QE identity'];
        }
        if (!self::maskedEq(substr($qe, 48, 16), $attrMask, $attr)) {
            return ['error' => 'QE ATTRIBUTES do not match the QE identity'];
        }
        if (substr($qe, 128, 32) !== $mrsigner) {
            return ['error' => 'QE MRSIGNER does not match the QE identity'];
        }
        $prod = ord($qe[256]) | (ord($qe[257]) << 8);
        $isvsvn = ord($qe[258]) | (ord($qe[259]) << 8);
        if ((float)$prod !== $prodId) {
            return ['error' => 'QE ISVPRODID does not match the QE identity'];
        }
        $hit = null;
        foreach (self::listOf(Common::g($ident, 'tcbLevels')) as $l) {
            $tcb = Common::isObj($l) ? Common::g($l, 'tcb') : null;
            $isv = Common::isObj($tcb) ? Common::numOf(Common::g($tcb, 'isvsvn')) : null;
            if ($isv !== null && $isv <= $isvsvn) {
                $hit = $l;
                break;
            }
        }
        if ($hit === null) {
            return ['error' => 'QE ISVSVN is below every known level'];
        }
        $st = self::asStatus(Common::g($hit, 'tcbStatus'));
        if ($st === null) {
            return ['error' => 'QE level has an unknown tcbStatus'];
        }
        return ['status' => $st, 'advisories' => self::advisories($hit)];
    }

    private static function text(mixed $x): string
    {
        return is_string($x) ? $x : '';
    }

    private static function truthy(mixed $x): bool
    {
        return $x !== null && $x !== false && $x !== '' && $x !== [];
    }

    /**
     * The quote, then its Intel PCS collateral (TCB info, QE identity, CRLs) at `now`: the evaluated TCB status and the policy decision.
     * @param array<string,mixed> $collateral
     * @param array<string,mixed>|null $policy
     * @return array<string,mixed>
     */
    public static function verifyCollateral(string $quote, array $collateral, float $nowMs, ?array $policy = null, ?string $trustAnchor = null, bool $allowDebug = false): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            $c = $collateral;
            foreach (['tcbInfoJson', 'qeIdentityJson', 'pckCrlDer', 'rootCrlDer', 'tcbInfoIssuerChainPem', 'qeIdentityIssuerChainPem'] as $k) {
                if (!self::truthy($c[$k] ?? null)) {
                    return $fail('collateral incomplete (fail closed)');
                }
            }
            $pin = $trustAnchor;
            $base = self::verifyGenuineQuote($quote, $pin, null, $allowDebug ? ['allowDebug' => true] : null, $nowMs);
            if (!$base['ok'] || !isset($base['pckTcb']) || ($base['fmspc'] ?? '') === '') {
                return $fail('quote invalid: ' . ($base['reason'] ?? 'unknown'));
            }
            $q = self::parseQuote($quote);
            $quoteCerts = array_map(static fn($b) => Cert::fromPem($b), Common::pemBlocks($q['pckChainPem']));
            foreach ($quoteCerts as $x) {
                if (!Der::x509ValidAt($x->raw, $nowMs)) {
                    return $fail('PCK chain certificate outside its validity period');
                }
            }
            $leaf = null;
            foreach ($quoteCerts as $x) {
                $isIssuer = false;
                foreach ($quoteCerts as $y) {
                    $isIssuer = $isIssuer || $y->issuer() === $x->subject();
                }
                if (!$isIssuer) {
                    $leaf = $x;
                    break;
                }
            }
            if ($leaf === null) {
                return $fail('PCK leaf not found');
            }
            $ca = null;
            foreach ($quoteCerts as $x) {
                if ($x->subject() === $leaf->issuer()) {
                    $ca = $x;
                    break;
                }
            }
            if ($ca === null) {
                return $fail('PCK CA not found in the quote chain');
            }
            $root = null;
            foreach ($quoteCerts as $x) {
                if ($x->subject() === $x->issuer()) {
                    $root = $x;
                    break;
                }
            }
            if ($root === null) {
                return $fail('Intel root not found in the quote chain');
            }
            $rootCrl = self::verifyCrl($c['rootCrlDer'], $root->publicKey(), $nowMs);
            if (!$rootCrl['ok']) {
                return $fail('Intel Root CA CRL: ' . $rootCrl['reason']);
            }
            $pckCrl = self::verifyCrl($c['pckCrlDer'], $ca->publicKey(), $nowMs);
            if (!$pckCrl['ok']) {
                return $fail('PCK CRL: ' . $pckCrl['reason']);
            }
            if (self::serialIsRevoked($rootCrl['revoked'], $ca->serialHex())) {
                return $fail('PCK CA certificate is revoked by the Intel Root CA CRL');
            }
            if (self::serialIsRevoked($pckCrl['revoked'], $leaf->serialHex())) {
                return $fail('PCK leaf certificate is revoked by the PCK CRL');
            }
            $tcbKey = self::signerKeyFromChain((string)$c['tcbInfoIssuerChainPem'], $pin, $nowMs, $rootCrl['revoked']);
            if (isset($tcbKey['error'])) {
                return $fail('TCB info: ' . $tcbKey['error']);
            }
            $tcbDoc = self::verifySignedJson(self::text($c['tcbInfoJson']), 'tcbInfo', $tcbKey['key']);
            if (isset($tcbDoc['error'])) {
                return $fail('TCB info: ' . $tcbDoc['error']);
            }
            $info = $tcbDoc['body'];
            $stale = self::checkFresh($info, 'TCB info', $nowMs);
            if ($stale !== null) {
                return $fail($stale);
            }
            $infoVer = Common::numOf(Common::g($info, 'version'));
            if (Common::g($info, 'id') !== 'TDX' || $infoVer === null || $infoVer !== 3.0) {
                return $fail('TCB info is not a TDX v3 document');
            }
            $fm = Common::g($info, 'fmspc');
            if (!is_string($fm) || strtolower($fm) !== $base['fmspc']) {
                return $fail('TCB info FMSPC does not match the quote PCK');
            }
            $qeKey = self::signerKeyFromChain((string)$c['qeIdentityIssuerChainPem'], $pin, $nowMs, $rootCrl['revoked']);
            if (isset($qeKey['error'])) {
                return $fail('QE identity: ' . $qeKey['error']);
            }
            $qeDoc = self::verifySignedJson(self::text($c['qeIdentityJson']), 'enclaveIdentity', $qeKey['key']);
            if (isset($qeDoc['error'])) {
                return $fail('QE identity: ' . $qeDoc['error']);
            }
            $staleQe = self::checkFresh($qeDoc['body'], 'QE identity', $nowMs);
            if ($staleQe !== null) {
                return $fail($staleQe);
            }
            $minEval = Common::numOf($policy['minTcbEvaluationDataNumber'] ?? null);
            $infoNum = Common::numOf(Common::g($info, 'tcbEvaluationDataNumber')) ?? -1.0;
            $qeNum = Common::numOf(Common::g($qeDoc['body'], 'tcbEvaluationDataNumber')) ?? -1.0;
            if ($infoNum < 0 || $qeNum < 0) {
                return $fail('tcbEvaluationDataNumber missing');
            }
            if ($minEval !== null && ($infoNum < $minEval || $qeNum < $minEval)) {
                return $fail('tcbEvaluationDataNumber below policy minimum');
            }
            $body = $q['tdReportBody'];
            $td = ['teeTcbSvn' => substr($body, 0, 16), 'mrSignerSeam' => substr($body, 64, 48), 'seamAttributes' => substr($body, 112, 8)];
            $pck = self::extractPckFmspcAndTcb($leaf->raw);
            $tcb = self::evaluateTcb($info, ['sgx' => $pck['sgxTcbComponents'], 'pcesvn' => $pck['pcesvn']], $td);
            if (isset($tcb['error'])) {
                return $fail('TCB evaluation: ' . $tcb['error']);
            }
            $qe = self::evaluateQe($qeDoc['body'], $q['qeReportBody']);
            if (isset($qe['error'])) {
                return $fail('QE identity: ' . $qe['error']);
            }
            $status = self::worst(self::worst($tcb['platform'], $tcb['module']), $qe['status']);
            $adv = array_values(array_unique(array_merge($tcb['advisories'], $qe['advisories'])));
            usort($adv, 'strcmp');
            $result = ['ok' => false, 'status' => $status, 'advisoryIds' => $adv];
            $accepted = $policy['acceptStatuses'] ?? null;
            if ($accepted === null) {
                $accepted = self::DEFAULT_ACCEPTED;
            }
            if (!in_array($status, is_array($accepted) ? $accepted : [], true)) {
                $result['reason'] = "TCB status $status is not accepted by policy";
                return $result;
            }
            $result['ok'] = true;
            return $result;
        } catch (\Throwable $e) {
            return $fail('collateral verification error (fail closed): ' . $e->getMessage());
        }
    }

    // ---- the verifier ----------------------------------------------------------------------------------------------------------------------

    private string $binding;
    private string $pin;
    /** @var array<string,mixed> */
    private array $policy;
    /** @var list<string> */
    private array $mrtds;
    private bool $allowMissing;
    /** @var callable */
    private $resolve;

    public function __construct(mixed $config, callable $resolve)
    {
        $binding = Common::g($config, 'binding');
        if ($binding !== 'report-data' && $binding !== 'azure-runtime-data') {
            throw new AttestConstructError("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'");
        }
        $this->binding = $binding;
        $polIn = Common::g($config, 'policy');
        $pol = Common::members($polIn);
        $mrtdsIn = $pol['mrtds'] ?? null;
        if (!Common::isList($mrtdsIn) || count($mrtdsIn) === 0) {
            throw new AttestConstructError('createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)');
        }
        $mrtds = array_map(static fn($m) => strtolower((string)$m), $mrtdsIn);
        foreach ($mrtds as $m) {
            if (preg_match('/\A[0-9a-f]+\z/', $m) !== 1 || strlen($m) !== 96) {
                throw new AttestConstructError('createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)');
            }
        }
        foreach (['mrSeams', 'mrSignerSeams'] as $name) {
            if (!array_key_exists($name, $pol)) {
                continue;
            }
            $lst = $pol[$name];
            if (!Common::isList($lst) || count($lst) === 0) {
                throw new AttestConstructError("createIntelDcapVerifier: policy.$name, if given, must be a NON-EMPTY list");
            }
            foreach ($lst as $m) {
                if (!is_string($m) || preg_match('/\A[0-9a-fA-F]+\z/', $m) !== 1 || strlen($m) !== 96) {
                    throw new AttestConstructError("createIntelDcapVerifier: every $name entry must be 96 hex chars (48 bytes)");
                }
            }
        }
        $anchor = Common::g($config, 'trustAnchorRootCaSpkiSha256');
        $this->pin = strtolower(is_string($anchor) ? $anchor : self::SGX_ROOT_CA_SPKI_SHA256);
        $this->policy = $pol;
        $this->mrtds = $mrtds;
        $this->allowMissing = Common::g($config, 'allowMissingCollateral') === true;
        $this->resolve = $resolve;
    }

    public function verify(mixed $document, mixed $expected, mixed $nowMs): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            $ev = ($this->resolve)($document);
            if (!is_array($ev) || !is_string($ev['quote'] ?? null)) {
                return $fail('no Intel DCAP quote for this action');
            }
            if ($expected === null) {
                return $fail('no expected attestation binding supplied');
            }
            $pol = $this->policy;
            $gp = ['mrtds' => $this->mrtds];
            foreach (['mrSeams', 'mrSignerSeams', 'fmspcs', 'rtmrs'] as $k) {
                if (self::truthy($pol[$k] ?? null)) {
                    $gp[$k] = $pol[$k];
                }
            }
            if (($pol['allowDebug'] ?? null) === true) {
                $gp['allowDebug'] = true;
            }
            $now = (float)Common::numOf($nowMs);
            $quote = $ev['quote'];
            $q = self::verifyGenuineQuote($quote, $this->pin, null, $gp, $now);
            if (!$q['ok'] || !isset($q['report'], $q['measured']) || ($q['fmspc'] ?? '') === '') {
                return $fail('DCAP quote invalid: ' . ($q['reason'] ?? 'unknown'));
            }
            if ($this->binding === 'report-data') {
                try {
                    $want = Common::attestationBinding($expected);
                } catch (\TypeError $e) {
                    return $fail('binding not constructible: ' . $e->getMessage());
                }
                if ($q['report']['reportData'] !== $want) {
                    return $fail('report_data does not bind holder/grant/epoch/nonce');
                }
            } else {
                $rd = $ev['runtimeData'] ?? null;
                if (!is_string($rd)) {
                    return $fail('azure-runtime-data binding needs the runtime-data JSON bytes');
                }
                $why = Amd::checkAzureRuntimeDataBinding($q['report']['reportData'], $rd, $expected);
                if ($why !== null) {
                    return $fail($why);
                }
            }
            $host = ['attestation_type' => 'tdx-dcap', 'fmspc' => $q['fmspc']];
            $col = $ev['collateral'] ?? null;
            if (self::truthy($col)) {
                $cp = $pol['collateral'] ?? null;
                $cpArr = Common::isObj($cp) && Common::members($cp) !== [] ? Common::members($cp) : null;
                $c = self::verifyCollateral($quote, $col, $now, $cpArr, $this->pin, ($pol['allowDebug'] ?? null) === true);
                if (!empty($c['status'])) {
                    $host['tcb_status'] = $c['status'];
                }
                if (!empty($c['advisoryIds'])) {
                    $host['advisory_ids'] = implode(',', $c['advisoryIds']);
                }
                if (!$c['ok']) {
                    return $fail('Intel collateral: ' . ($c['reason'] ?? 'rejected'));
                }
            } elseif ($this->allowMissing) {
                $host['tcb_status'] = 'unevaluated';
            } else {
                return $fail('Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)');
            }
            return ['ok' => true, 'bound' => true, 'measured' => $q['measured'], 'hostAsserted' => $host];
        } catch (\Throwable $e) {
            return $fail('intel-dcap verification error (fail closed): ' . $e->getMessage());
        }
    }
}
