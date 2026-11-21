<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Cert.php';

/** A structurally invalid OCSP response (reported as a rejection, never a pass). */
final class OcspError extends \RuntimeException
{
}

/**
 * NVIDIA device-chain revocation through OCSP (RFC 6960): the native counterpart of `checkNvidiaChainOcsp`. Verifies, offline,
 * the DER OCSPResponses a caller obtained: responseStatus SUCCESSFUL with id-pkix-ocsp-basic, the CertID (serial + issuer name /
 * key hashes), the BasicOCSPResponse signature under the issuing CA or a delegated responder certificate (signed by the supplied
 * chain, inside its validity window, with the id-kp-OCSPSigning EKU), freshness, and the certStatus. Fails closed; the reason
 * strings are those of the reference implementation.
 */
final class Ocsp
{
    /** Nesting depth and node count of the BasicOCSPResponse the time walk follows (asn1js: 100 and 10000). */
    private const MAX_DEPTH = 100;
    private const MAX_NODES = 10000;
    public const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';
    public const OID_OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';
    public const OID_AIA = '1.3.6.1.5.5.7.1.1';
    public const OID_AD_OCSP = '1.3.6.1.5.5.7.48.1';
    public const OID_EKU_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
    public const OID_EKU = '2.5.29.37';
    public const DEFAULT_MAX_AGE_MS = 7 * 24 * 3600 * 1000;
    /** Test seam: a closure called with a stage name inside the guarded verify call; whatever it throws is a failed verification. */
    public static ?\Closure $faultHook = null;
    private const HASHES = ['1.3.14.3.2.26' => 'sha1', '2.16.840.1.101.3.4.2.1' => 'sha256', '2.16.840.1.101.3.4.2.2' => 'sha384', '2.16.840.1.101.3.4.2.3' => 'sha512'];
    private const SIG_ALGS = [
        '1.2.840.10045.4.3.2' => ['sha256', 'ec'], '1.2.840.10045.4.3.3' => ['sha384', 'ec'], '1.2.840.10045.4.3.4' => ['sha512', 'ec'],
        '1.2.840.113549.1.1.11' => ['sha256', 'rsa'], '1.2.840.113549.1.1.12' => ['sha384', 'rsa'], '1.2.840.113549.1.1.13' => ['sha512', 'rsa'],
    ];
    private const GEN_TIME = '/\A([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]*[1-9]))?Z\z/';
    private const UTC_TIME = '/\A([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z/';

    private static function timeInRange(string $text, bool $utc): bool
    {
        if (preg_match($utc ? self::UTC_TIME : self::GEN_TIME, $text, $m) !== 1) {
            return false;
        }
        $y = (int)$m[1];
        if ($utc) {
            $y += $y < 50 ? 2000 : 1900;
        }
        [$mo, $d, $h, $mi, $se] = [(int)$m[2], (int)$m[3], (int)$m[4], (int)$m[5], (int)$m[6]];
        if ($mo < 1 || $mo > 12 || $d < 1 || $h > 23 || $mi > 59 || $se > 59) {
            return false;
        }
        return $d <= Der::daysInMonth($y, $mo);
    }

    /**
     * The reference's ASN.1 reader (asn1js fromBER) refuses a whole structure when any nested element is truncated or runs past its
     * parent: every constructed element's children must tile it exactly.
     */
    private static function wellFormedBer(string $der, int $start, int $end, int $depth = 0): bool
    {
        if ($depth > self::MAX_DEPTH) {
            return false;
        }
        try {
            for ($p = $start; $p < $end;) {
                $t = Der::tlvLenient($der, $p);
                if ($t->end > $end) {
                    return false;
                }
                if (($t->tag & 0x20) !== 0 && !self::wellFormedBer($der, $t->start, $t->end, $depth + 1)) {
                    return false;
                }
                $p = $t->end;
            }
        } catch (DerError) {
            return false;
        }
        return true;
    }

    /** Every UTCTime / GeneralizedTime anywhere in the (constructed) structure is a well-formed, in-range DER time. */
    private static function allTimesWellFormed(string $der, int $start, int $end, int $depth = 0, int &$nodes = 0, bool &$tooDeep = false): bool
    {
        $p = $start;
        while ($p < $end) {
            // the reference parser (asn1js) bounds depth at 100 and nodes at 10000: past either the response is not valid DER, and the
            // walk stops here, so no input recurses deeper than the cap
            if ($depth > self::MAX_DEPTH || ++$nodes > self::MAX_NODES) {
                $tooDeep = true;
                return false;
            }
            $t = Der::tlvLenient($der, $p);
            if ($t->end > $end) {
                throw new OcspError('element overruns its parent');
            }
            if (($t->tag & 0xC0) === 0 && in_array($t->tag & 0x1F, [23, 24], true) && ($t->tag & 0x20) === 0) {
                if (!self::timeInRange(substr($der, $t->start, $t->end - $t->start), ($t->tag & 0x1F) === 23)) {
                    return false;
                }
            } elseif (($t->tag & 0x20) !== 0) {
                if (!self::allTimesWellFormed($der, $t->start, $t->end, $depth + 1, $nodes, $tooDeep)) {
                    return false;
                }
            }
            $p = $t->end;
        }
        return true;
    }

    private static function genTimeMs(string $text): int
    {
        if (preg_match(self::GEN_TIME, $text, $m) === 1) {
            $y = (int)$m[1];
            $ms = (int)str_pad(substr($m[7] ?? '0', 0, 3), 3, '0');
        } elseif (preg_match(self::UTC_TIME, $text, $m) === 1) {
            $y = (int)$m[1];
            $y += $y < 50 ? 2000 : 1900;
            $ms = 0;
        } else {
            throw new OcspError('response times are not parseable');
        }
        [$mo, $d, $h, $mi, $se] = [(int)$m[2], (int)$m[3], (int)$m[4], (int)$m[5], (int)$m[6]];
        return ((((Der::daysFromCivil($y, $mo, $d) * 24 + $h) * 60 + $mi) * 60 + $se) * 1000) + $ms;
    }

    /** The child TLVs of a constructed element, each with the offset of its header. @return list<array{0: Tlv, 1: int}> */
    private static function children(string $der, Tlv $t): array
    {
        $out = [];
        $p = $t->start;
        while ($p < $t->end) {
            $c = Der::tlvLenient($der, $p);
            if ($c->end > $t->end) {
                throw new OcspError('element overruns its parent');
            }
            $out[] = [$c, $p];
            $p = $c->end;
        }
        return $out;
    }

    private static function stripZeros(string $b): string
    {
        $i = 0;
        while ($i < strlen($b) - 1 && $b[$i] === "\0") {
            $i++;
        }
        return substr($b, $i);
    }

    private static function spkiKeyBits(string $spki): string
    {
        $seq = Der::tlvLenient($spki, 0);
        $kids = self::children($spki, $seq);
        if (count($kids) < 2 || $kids[1][0]->tag !== 0x03) {
            throw new OcspError('malformed SubjectPublicKeyInfo');
        }
        $t = $kids[1][0];
        return substr($spki, $t->start + 1, $t->end - $t->start - 1);
    }

    private static function verifySig(string $algOid, string $tbs, string $sig, PubKey $key): bool
    {
        $a = self::SIG_ALGS[$algOid] ?? null;
        if ($a === null) {
            return false;
        }
        [$hname, $kind] = $a;
        if (($kind === 'ec') !== ($key->type === 'ec')) {
            return false;
        }
        try {
            self::$faultHook?->__invoke('verify_sig');
            return $kind === 'ec' ? Common::ecdsaVerifyDer($key, $sig, $tbs, $hname) : Common::rsaPkcs1Verify($key, $sig, $tbs, $hname);
        } catch (\Throwable) {
            return false;
        }
    }

    /** @return list<string>|null */
    private static function ekuOf(Cert $cert): ?array
    {
        $ext = $cert->extensions()[self::OID_EKU] ?? null;
        if ($ext === null) {
            return null;
        }
        try {
            $seq = Der::readTlv($ext->value, 0);
            if ($seq->tag !== 0x30) {
                return null;
            }
            $out = [];
            $p = $seq->start;
            while ($p < $seq->end) {
                $o = Der::readTlv($ext->value, $p, $seq->end);
                $out[] = Der::oidToDotted($ext->value, $o);
                $p = $o->end;
            }
            return $out;
        } catch (DerError) {
            return null;
        }
    }

    private static function fail(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    /**
     * One DER OCSPResponse for `$cert`. Never throws; any malformation is `{ok: false}`. `$expectedNonce` (raw bytes), when given, must be echoed exactly;
     * `$detail` adds `thisUpdate`, `producedAt`, `nextUpdate` (when present) and, for a revoked status, `revokedAt` and `revocationReason` (epoch ms / CRLReason).
     * @param list<Cert> $chain
     * @return array<string,mixed>
     */
    public static function verifyResponse(string $responseDer, Cert $cert, Cert $issuer, array $chain, float $nowMs, ?float $maxAgeMs = null, float $clockSkewMs = 0,
        ?string $expectedNonce = null, bool $detail = false): array
    {
        try {
            return self::verifyInner($responseDer, $cert, $issuer, $chain, $nowMs, $maxAgeMs, $clockSkewMs, $expectedNonce, $detail);
        } catch (\Throwable $e) {
            return self::fail('OCSP response rejected: ' . $e->getMessage());
        }
    }

    private static function verifyInner(string $der, Cert $cert, Cert $issuer, array $chain, float $nowMs, ?float $maxAgeMs, float $skew, ?string $expectedNonce, bool $detail): array
    {
        $maxAge = $maxAgeMs ?? self::DEFAULT_MAX_AGE_MS;
        // an infinite skew admits a future-dated response and a NaN age never ages one out (an unbounded +Infinity max age is the caller's choice)
        if (!is_finite($nowMs) || !is_finite($skew) || is_nan($maxAge)) {
            return self::fail('nowMs and clockSkewMs must be finite and maxAgeMs a number');
        }
        try {
            $top = Der::tlvLenient($der, 0);
        } catch (DerError) {
            return self::fail('response is not valid DER');
        }
        if ($top->end <= strlen($der) && !self::wellFormedBer($der, 0, $top->end)) {
            return self::fail('response is not valid DER');
        }
        if ($top->end !== strlen($der)) {
            return self::fail('trailing bytes after OCSPResponse');
        }
        if ($top->tag !== 0x30) {
            throw new OcspError('OCSPResponse is not a SEQUENCE');
        }
        $kids = self::children($der, $top);
        if (count($kids) < 1 || $kids[0][0]->tag !== 0x0A) {
            throw new OcspError('responseStatus is not an ENUMERATED');
        }
        // hexdec() is a float past 8 bytes; an (int) cast of 2^64 wraps to 0 and would read as SUCCESSFUL, so compare as a number
        $status = hexdec(bin2hex(substr($der, $kids[0][0]->start, $kids[0][0]->end - $kids[0][0]->start)) ?: '0');
        if ($status != 0) {
            return self::fail("OCSP responseStatus is $status (not successful)");
        }
        if (count($kids) < 2 || $kids[1][0]->tag !== 0xA0) {
            return self::fail('successful response carries no responseBytes');
        }
        $rb = self::children($der, $kids[1][0]);
        if (count($rb) < 1 || $rb[0][0]->tag !== 0x30) {
            throw new OcspError('responseBytes is not a SEQUENCE');
        }
        $rbk = self::children($der, $rb[0][0]);
        if (count($rbk) < 2 || $rbk[0][0]->tag !== 0x06 || $rbk[1][0]->tag !== 0x04) {
            throw new OcspError('responseBytes is malformed');
        }
        if (Der::oidToDotted($der, $rbk[0][0]) !== self::OID_OCSP_BASIC) {
            return self::fail('responseType is not id-pkix-ocsp-basic');
        }
        $basic = substr($der, $rbk[1][0]->start, $rbk[1][0]->end - $rbk[1][0]->start);
        try {
            $btop = Der::tlvLenient($basic, 0);
        } catch (DerError) {
            return self::fail('BasicOCSPResponse is not valid DER');
        }
        if (!self::wellFormedBer($basic, 0, $btop->end)) {
            return self::fail('BasicOCSPResponse is not valid DER');
        }
        if ($btop->tag !== 0x30) {
            throw new OcspError('BasicOCSPResponse is not a SEQUENCE');
        }
        $bk = self::children($basic, $btop);
        if (count($bk) < 3 || $bk[0][0]->tag !== 0x30 || $bk[1][0]->tag !== 0x30 || $bk[2][0]->tag !== 0x03) {
            throw new OcspError('BasicOCSPResponse is malformed');
        }
        $nodes = 0;
        $tooDeep = false;
        if (!self::allTimesWellFormed($basic, $btop->start, $btop->end, 1, $nodes, $tooDeep)) {
            return $tooDeep ? self::fail('BasicOCSPResponse is not valid DER') : self::fail('response carries a malformed (out-of-range) ASN.1 time');
        }
        [$tbsT, $tbsOff] = $bk[0];
        $tbsBytes = substr($basic, $tbsOff, $tbsT->end - $tbsOff);
        if ($tbsBytes === '') {
            return self::fail('missing tbsResponseData');
        }
        $sigAlgT = $bk[1][0];
        $sigAlgOid = Der::oidToDotted($basic, Der::tlvLenient($basic, $sigAlgT->start));
        if (!isset(self::SIG_ALGS[$sigAlgOid])) {
            return self::fail("unsupported OCSP signature algorithm $sigAlgOid");
        }
        $sig = substr($basic, $bk[2][0]->start + 1, $bk[2][0]->end - $bk[2][0]->start - 1);

        $rd = self::children($basic, $tbsT);
        $idx = 0;
        if ($idx < count($rd) && $rd[$idx][0]->tag === 0xA0) {
            $idx++;
        }
        if ($idx >= count($rd) || !in_array($rd[$idx][0]->tag, [0xA1, 0xA2], true)) {
            throw new OcspError('responderID is malformed');
        }
        $ridT = $rd[$idx][0];
        $idx++;
        if ($idx >= count($rd) || $rd[$idx][0]->tag !== 0x18) {
            throw new OcspError('producedAt is malformed');
        }
        $producedAt = self::genTimeMs(substr($basic, $rd[$idx][0]->start, $rd[$idx][0]->end - $rd[$idx][0]->start));
        $idx++;
        if ($idx >= count($rd) || $rd[$idx][0]->tag !== 0x30) {
            throw new OcspError('responses is malformed');
        }
        $responsesT = $rd[$idx][0];

        $matches = [];
        foreach (self::children($basic, $responsesT) as [$singleT, $singleOff]) {
            $sk = self::children($basic, $singleT);
            if (count($sk) < 3 || $sk[0][0]->tag !== 0x30) {
                throw new OcspError('SingleResponse is malformed');
            }
            // after thisUpdate only [0] nextUpdate, then [1] singleExtensions: an unknown element must not hide a stale nextUpdate
            if (!in_array(array_map(static fn(array $c): int => $c[0]->tag, array_slice($sk, 3)), [[], [0xA0], [0xA1], [0xA0, 0xA1]], true)) {
                throw new OcspError('SingleResponse is malformed');
            }
            $cid = self::children($basic, $sk[0][0]);
            if (count($cid) < 4) {
                throw new OcspError('CertID is malformed');
            }
            $alg = Der::tlvLenient($basic, $cid[0][0]->start);
            $hname = self::HASHES[Der::oidToDotted($basic, $alg)] ?? null;
            if ($hname === null) {
                continue;
            }
            $wantName = hash($hname, $issuer->subjectDer, true);
            $wantKey = hash($hname, self::spkiKeyBits($issuer->spkiDer), true);
            $slice = static fn(array $c): string => substr($basic, $c[0]->start, $c[0]->end - $c[0]->start);
            if (self::stripZeros($slice($cid[3])) === self::stripZeros($cert->serial) && $slice($cid[1]) === $wantName && $slice($cid[2]) === $wantKey) {
                $matches[] = [$singleT, $singleOff];
            }
        }
        if ($matches === []) {
            return self::fail('no SingleResponse matches the certificate (serial / issuer hashes differ)');
        }
        if (count($matches) > 1) {
            return self::fail('ambiguous: multiple SingleResponses match the certificate');
        }
        $singleT = $matches[0][0];
        $sk = self::children($basic, $singleT);

        $ridMatches = static function (Cert $c) use ($basic, $ridT): bool {
            if ($ridT->tag === 0xA1) { // byName
                $inner = self::children($basic, $ridT);
                return count($inner) === 1 && substr($basic, $inner[0][1], $inner[0][0]->end - $inner[0][1]) === $c->subjectDer;
            }
            $oct = Der::tlvLenient($basic, $ridT->start); // byKey [2] EXPLICIT OCTET STRING
            return $oct->tag === 0x04 && substr($basic, $oct->start, $oct->end - $oct->start) === sha1(self::spkiKeyBits($c->spkiDer), true);
        };

        $responder = 'issuer';
        $isIssuerId = $ridMatches($issuer);
        $issuerOk = $isIssuerId && self::verifySig($sigAlgOid, $tbsBytes, $sig, $issuer->publicKey());
        if (!$issuerOk) {
            $embedded = [];
            if (count($bk) > 3 && $bk[3][0]->tag === 0xA0) {
                foreach (self::children($basic, $bk[3][0]) as [$st]) {
                    foreach (self::children($basic, $st) as [$ct, $coff]) {
                        $embedded[] = new Cert(substr($basic, $coff, $ct->end - $coff));
                    }
                }
            }
            $found = false;
            $why = 'no embedded responder certificate verifies the response';
            foreach ($embedded as $cand) {
                if (!$ridMatches($cand)) {
                    $why = 'embedded certificates do not match the responderID';
                    continue;
                }
                $eku = self::ekuOf($cand);
                if ($eku === null || !in_array(self::OID_EKU_OCSP_SIGNING, $eku, true)) {
                    $why = 'delegated responder certificate lacks the id-kp-OCSPSigning EKU';
                    continue;
                }
                [$nb, $na] = Der::derValidityMs($cand->raw);
                if ($nb === null || $na === null || !($nb - $skew <= $nowMs && $nowMs <= $na)) {
                    $why = 'delegated responder certificate is outside its validity window';
                    continue;
                }
                $issuerIdx = -1;
                foreach ($chain as $i => $c) {
                    if ($c->raw === $issuer->raw) {
                        $issuerIdx = $i;
                        break;
                    }
                }
                $signers = $issuerIdx >= 0 ? array_slice($chain, $issuerIdx) : [$issuer];
                $signedOk = false;
                foreach ($signers as $s) {
                    if ($cand->checkIssued($s) && $cand->verify($s->publicKey())) {
                        $signedOk = true;
                        break;
                    }
                }
                if (!$signedOk) {
                    $why = 'delegated responder certificate is not signed by the supplied NVIDIA chain';
                    continue;
                }
                if (!self::verifySig($sigAlgOid, $tbsBytes, $sig, $cand->publicKey())) {
                    $why = 'OCSP response signature does not verify under the delegated responder key';
                    continue;
                }
                $found = true;
                break;
            }
            if (!$found) {
                return self::fail($isIssuerId ? 'OCSP response signature does not verify under the issuer key' : $why);
            }
            $responder = 'delegated';
        }

        if ($expectedNonce !== null) {
            $echo = null;
            if ($idx + 1 < count($rd) && $rd[$idx + 1][0]->tag === 0xA1) {
                foreach (self::children($basic, $rd[$idx + 1][0]) as [$seqT]) {
                    foreach (self::children($basic, $seqT) as [$extT]) {
                        $ek = self::children($basic, $extT);
                        if (count($ek) >= 2 && $ek[0][0]->tag === 0x06 && Der::oidToDotted($basic, $ek[0][0]) === self::OID_OCSP_NONCE) {
                            $val = $ek[count($ek) - 1][0];
                            $echo = substr($basic, $val->start, $val->end - $val->start);
                            break 2;
                        }
                    }
                }
            }
            if ($echo === null) {
                return self::fail('response does not echo the nonce');
            }
            $echoed = $echo;
            try {
                $in = Der::tlvLenient($echo, 0);
                if ($in->end === strlen($echo) && $in->tag === 0x04) {
                    $echoed = substr($echo, $in->start, $in->end - $in->start);
                }
            } catch (DerError) {
            }
            if ($echoed !== $expectedNonce) {
                return self::fail('response nonce does not match the request nonce');
            }
        }

        $statusT = $sk[1][0];
        $timeT = $sk[2][0];
        if ($timeT->tag !== 0x18) {
            throw new OcspError('thisUpdate is malformed');
        }
        $thisUpdate = self::genTimeMs(substr($basic, $timeT->start, $timeT->end - $timeT->start));
        $nextUpdate = null;
        if (count($sk) > 3 && $sk[3][0]->tag === 0xA0) {
            $inner = self::children($basic, $sk[3][0]);
            if (count($inner) !== 1 || $inner[0][0]->tag !== 0x18) {
                throw new OcspError('nextUpdate is malformed');
            }
            $nextUpdate = self::genTimeMs(substr($basic, $inner[0][0]->start, $inner[0][0]->end - $inner[0][0]->start));
        }
        if (!($thisUpdate <= $nowMs + $skew)) {
            return self::fail('response thisUpdate is in the future');
        }
        if (!($producedAt <= $nowMs + $skew)) {
            return self::fail('response producedAt is in the future');
        }
        if ($nextUpdate !== null) {
            if ($nextUpdate < $thisUpdate) {
                return self::fail('response nextUpdate is invalid');
            }
            if (!($nowMs <= $nextUpdate)) {
                return self::fail('response is stale (past nextUpdate)');
            }
        }
        if (!($nowMs - $thisUpdate <= $maxAge)) {
            return self::fail('response is older than the maximum accepted age');
        }
        // good and unknown are primitive, revoked is constructed: a masked tag would read a constructed 0xA0 as good
        if (($statusT->tag & 0xC0) !== 0x80 || in_array($statusT->tag, [0xA0, 0xA2, 0x81], true)) {
            return self::fail('malformed certStatus');
        }
        $num = $statusT->tag & 0x1F;
        $times = $detail ? ['thisUpdate' => $thisUpdate, 'producedAt' => $producedAt] + ($nextUpdate !== null ? ['nextUpdate' => $nextUpdate] : []) : [];
        if ($num === 0) {
            return ['ok' => true, 'status' => 'good', 'responder' => $responder] + $times;
        }
        if ($num === 2) {
            return ['ok' => true, 'status' => 'unknown', 'responder' => $responder] + $times;
        }
        if ($num === 1) {
            $kids2 = self::children($basic, $statusT);
            if (count($kids2) < 1) {
                return self::fail('malformed revoked certStatus');
            }
            $txt = substr($basic, $kids2[0][0]->start, $kids2[0][0]->end - $kids2[0][0]->start);
            if (preg_match('/\A[0-9]{14}Z\z/', $txt) !== 1) {
                return self::fail('malformed revoked certStatus');
            }
            $more = [];
            if ($detail) {
                $more = ['revokedAt' => self::genTimeMs($txt)];
                if (count($kids2) >= 2) {
                    $in2 = self::children($basic, $kids2[1][0]);
                    if ($in2 !== [] && $in2[0][0]->tag === 0x0A) {
                        $more['revocationReason'] = (int)hexdec(bin2hex(substr($basic, $in2[0][0]->start, $in2[0][0]->end - $in2[0][0]->start)) ?: '0');
                    }
                }
            }
            return ['ok' => true, 'status' => 'revoked', 'responder' => $responder] + $times + $more;
        }
        return self::fail('unrecognised certStatus');
    }

    /** OCSP responder URLs advertised in the Authority Information Access extension. @return list<string> */
    public static function certOcspUrls(Cert $cert): array
    {
        $ext = $cert->extensions()[self::OID_AIA] ?? null;
        if ($ext === null) {
            return [];
        }
        try {
            $seq = Der::readTlv($ext->value, 0);
            if ($seq->tag !== 0x30) {
                return [];
            }
            $out = [];
            $p = $seq->start;
            while ($p < $seq->end) {
                $ad = Der::readTlv($ext->value, $p, $seq->end);
                $p = $ad->end;
                $oid = Der::readTlv($ext->value, $ad->start, $ad->end);
                $loc = Der::readTlv($ext->value, $oid->end, $ad->end);
                if (Der::oidToDotted($ext->value, $oid) === self::OID_AD_OCSP && $loc->tag === 0x86) {
                    $out[] = substr($ext->value, $loc->start, $loc->end - $loc->start);
                }
            }
            return $out;
        } catch (DerError) {
            return [];
        }
    }

    private static function subj(Cert $c): string
    {
        return str_replace("\n", ', ', $c->subject());
    }

    /**
     * The device chain against OCSP responses. Every response must verify for exactly one chain certificate; any REVOKED fails; the required
     * certificates must have a GOOD response (UNKNOWN or missing fails), the others are reported but tolerated. `$opts`: `requireGood`
     * (`'aia'` default: every non-root certificate that advertises an OCSP URL; `'all'`; or a list of non-root chain indices), `clockSkewMs`,
     * `expectedNonces` (a list by chain index, null = none required for that certificate).
     * @param list<Cert> $chain
     * @param list<string> $responses
     * @param array<string,mixed> $opts
     * @return array<string,mixed>
     */
    public static function checkNvidiaChain(array $chain, array $responses, float $nowMs, ?float $maxAgeMs = null, array $opts = []): array
    {
        if (count($chain) < 2) {
            return ['ok' => false, 'reason' => 'chain too short for OCSP'];
        }
        if ($responses === []) {
            return ['ok' => false, 'reason' => 'no OCSP responses supplied'];
        }
        $last = count($chain) - 1;
        $required = [];
        $policy = $opts['requireGood'] ?? 'aia';
        if (is_array($policy)) {
            foreach ($policy as $i) {
                $f = is_int($i) || is_float($i) ? (float)$i : null;
                if ($f === null || !is_finite($f) || $f !== floor($f) || $f < 0 || $f >= $last) {
                    return ['ok' => false, 'reason' => 'requireGood index ' . (is_int($i) || is_float($i) ? \Atlas\Pca\Js::str($i) : gettype($i)) . ' is not a non-root chain certificate'];
                }
                $required[(int)$f] = true;
            }
            $required = array_keys($required);
        } else {
            for ($i = 0; $i < $last; $i++) {
                if ($policy === 'all' || self::certOcspUrls($chain[$i]) !== []) {
                    $required[] = $i;
                }
            }
        }
        $statuses = [];
        for ($i = 0; $i < $last; $i++) {
            $statuses[$i] = 'absent';
        }
        $skew = (float)($opts['clockSkewMs'] ?? 0);
        $nonces = $opts['expectedNonces'] ?? [];
        $verified = 0;
        foreach ($responses as $ri => $der) {
            $matched = false;
            $lastReason = 'matches no chain certificate';
            for ($i = 0; $i < $last; $i++) {
                $r = self::verifyResponse($der, $chain[$i], $chain[$i + 1], $chain, $nowMs, $maxAgeMs, $skew, is_string($nonces[$i] ?? null) ? $nonces[$i] : null);
                if (!$r['ok']) {
                    if (!str_starts_with($r['reason'], 'no SingleResponse matches')) {
                        return ['ok' => false, 'reason' => "OCSP response #$ri for '" . self::subj($chain[$i]) . "' rejected: " . $r['reason'], 'statuses' => $statuses];
                    }
                    $lastReason = $r['reason'];
                    continue;
                }
                if ($matched) {
                    return ['ok' => false, 'reason' => "OCSP response #$ri matches more than one chain certificate", 'statuses' => $statuses];
                }
                $matched = true;
                if ($statuses[$i] !== 'absent') {
                    return ['ok' => false, 'reason' => "duplicate OCSP responses for chain certificate #$i", 'statuses' => $statuses];
                }
                $statuses[$i] = $r['status'];
                $verified++;
                if ($r['status'] === 'revoked') {
                    return ['ok' => false, 'reason' => "chain certificate '" . self::subj($chain[$i]) . "' is revoked (OCSP)", 'statuses' => $statuses];
                }
            }
            if (!$matched) {
                return ['ok' => false, 'reason' => "OCSP response #$ri rejected: $lastReason", 'statuses' => $statuses];
            }
        }
        foreach ($required as $i) {
            if ($statuses[$i] !== 'good') {
                return ['ok' => false, 'reason' => "no GOOD OCSP response for required certificate '" . self::subj($chain[$i]) . "' (status: " . $statuses[$i] . ')', 'statuses' => $statuses];
            }
        }
        return ['ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => $verified, 'statuses' => $statuses];
    }

    private static function der(int $tag, string $body): string
    {
        $n = strlen($body);
        $len = $n < 128 ? chr($n) : (($n < 256) ? "\x81" . chr($n) : (($n < 65536) ? "\x82" . pack('n', $n) : "\x83" . substr(pack('N', $n), 1)));
        return chr($tag) . $len . $body;
    }

    /**
     * A DER OCSPRequest for `$cert` issued by `$issuer`: one Request whose CertID carries the hash of the issuer name and key (SHA-384 unless
     * `$hash` names sha1 / sha256 / sha512), no requestor and no signature, and an optional nonce extension (1..32 bytes: a string; any other
     * non-null value encodes an empty nonce, as the reference does for an object that is not a byte array). Throws on an unsupported hash or a bad nonce.
     */
    public static function buildRequest(Cert $cert, Cert $issuer, mixed $nonce = null, string $hash = 'sha384'): string
    {
        $oids = ['sha1' => "\x2b\x0e\x03\x02\x1a", 'sha256' => "\x60\x86\x48\x01\x65\x03\x04\x02\x01", 'sha384' => "\x60\x86\x48\x01\x65\x03\x04\x02\x02",
            'sha512' => "\x60\x86\x48\x01\x65\x03\x04\x02\x03", 'md5' => ''];
        if (!isset($oids[$hash])) {
            throw new OcspError("Digest method not supported");
        }
        $alg = self::der(0x30, self::der(0x06, $oids[$hash]) . "\x05\x00");
        $certId = self::der(0x30, $alg . self::der(0x04, hash($hash, $issuer->subjectDer, true))
            . self::der(0x04, hash($hash, self::spkiKeyBits($issuer->spkiDer), true)) . self::der(0x02, $cert->serial));
        $list = self::der(0x30, self::der(0x30, $certId));
        $tbs = self::der(0x30, $list);
        if ($nonce !== null) {
            if (is_string($nonce) && (strlen($nonce) < 1 || strlen($nonce) > 32)) {
                throw new \RangeException('nonce must be 1..32 bytes');
            }
            $ext = self::der(0x30, self::der(0x06, "\x2b\x06\x01\x05\x05\x07\x30\x01\x02") . self::der(0x04, self::der(0x04, is_string($nonce) ? $nonce : '')));
            $tbs = self::der(0x30, $list . self::der(0xA2, self::der(0x30, $ext)));
        }
        return self::der(0x30, $tbs);
    }

    /** True iff every GeneralizedTime / UTCTime inside the DER value is a well-formed DER time with in-range fields; unreadable DER is false. */
    public static function asn1TimesWellFormed(string $der): bool
    {
        try {
            $t = Der::tlvLenient($der, 0);
            $nodes = 0;
            $deep = false;
            return self::allTimesWellFormed($der, 0, $t->end, 0, $nodes, $deep) && !$deep;
        } catch (\Throwable) {
            return false;
        }
    }
}
