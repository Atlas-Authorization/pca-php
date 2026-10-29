<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Common.php';

/** One DER element: tag byte and the [start, end) range of its content. */
final class Tlv
{
    public function __construct(public readonly int $tag, public readonly int $start, public readonly int $end)
    {
    }
}

/** One certificate extension: the critical flag and the extnValue OCTET STRING content. */
final class CertExtension
{
    public function __construct(public readonly bool $critical, public readonly string $value)
    {
    }
}

/**
 * Strict DER / X.509 readers shared by the hardware-attestation chain verifiers: the native counterpart of x509-strict and
 * x509-validity of `@atlasauth/pca`. Every function throws or returns exactly what the reference does, including the exact
 * error text (it is part of the conformance vectors).
 */
final class Der
{
    /** One strict DER TLV at `$off` inside `[0, $limit)`: no multi-byte tags, definite minimal lengths up to 3 length bytes. */
    public static function readTlv(string $b, int $off, ?int $limit = null): Tlv
    {
        $limit ??= strlen($b);
        if ($off + 2 > $limit) {
            throw new DerError('DER: truncated header');
        }
        $tag = ord($b[$off]);
        if (($tag & 0x1F) === 0x1F) {
            throw new DerError('DER: multi-byte tags are not supported');
        }
        $ln = ord($b[$off + 1]);
        $p = $off + 2;
        if (($ln & 0x80) !== 0) {
            $n = $ln & 0x7F;
            if ($n === 0 || $n > 3) {
                throw new DerError('DER: unsupported length form');
            }
            if ($p + $n > $limit) {
                throw new DerError('DER: truncated length');
            }
            $ln = 0;
            if ($n > 1 && ord($b[$p]) === 0) {
                throw new DerError('DER: non-minimal length (leading zero)');
            }
            for ($i = 0; $i < $n; $i++) {
                $ln = ($ln << 8) | ord($b[$p + $i]);
            }
            if ($ln < 0x80) {
                throw new DerError('DER: non-minimal length (long form below 128)');
            }
            $p += $n;
        }
        if ($p + $ln > $limit) {
            throw new DerError('DER: element overruns its parent');
        }
        return new Tlv($tag, $p, $p + $ln);
    }

    private const OID_BASIC_CONSTRAINTS = "\x55\x1D\x13";
    private const OID_KEY_USAGE = "\x55\x1D\x0F";

    private static function oidEquals(string $b, Tlv $t, string $want): bool
    {
        return $t->tag === 0x06 && substr($b, $t->start, $t->end - $t->start) === $want;
    }

    /**
     * The CA-role-relevant extensions of a DER certificate.
     * @return array<string,mixed> hasBasicConstraints, ca, pathLen?, hasKeyUsage, keyCertSign
     */
    public static function readCertRoleInfo(string $certDer): array
    {
        $outer = self::readTlv($certDer, 0);
        if ($outer->tag !== 0x30) {
            throw new DerError('certificate is not a DER SEQUENCE');
        }
        if ($outer->end !== strlen($certDer)) {
            throw new DerError('trailing bytes after the certificate');
        }
        $tbs = self::readTlv($certDer, $outer->start, $outer->end);
        if ($tbs->tag !== 0x30) {
            throw new DerError('certificate has no tbsCertificate');
        }
        $info = ['hasBasicConstraints' => false, 'ca' => false, 'hasKeyUsage' => false, 'keyCertSign' => false];
        $p = $tbs->start;
        while ($p < $tbs->end) {
            $el = self::readTlv($certDer, $p, $tbs->end);
            $p = $el->end;
            if ($el->tag !== 0xA3) {
                continue; // [3] EXPLICIT extensions
            }
            $seq = self::readTlv($certDer, $el->start, $el->end);
            if ($seq->tag !== 0x30) {
                throw new DerError('extensions is not a SEQUENCE');
            }
            $q = $seq->start;
            while ($q < $seq->end) {
                $ext = self::readTlv($certDer, $q, $seq->end);
                $q = $ext->end;
                if ($ext->tag !== 0x30) {
                    throw new DerError('extension is not a SEQUENCE');
                }
                $ident = self::readTlv($certDer, $ext->start, $ext->end);
                $r = $ident->end;
                $nxt = self::readTlv($certDer, $r, $ext->end);
                if ($nxt->tag === 0x01) {
                    $r = $nxt->end;
                    $nxt = self::readTlv($certDer, $r, $ext->end);
                }
                if ($nxt->tag !== 0x04) {
                    throw new DerError('extension value is not an OCTET STRING');
                }
                if (self::oidEquals($certDer, $ident, self::OID_BASIC_CONSTRAINTS)) {
                    if ($info['hasBasicConstraints']) {
                        throw new DerError('duplicate BasicConstraints extension');
                    }
                    $info['hasBasicConstraints'] = true;
                    $bc = self::readTlv($certDer, $nxt->start, $nxt->end);
                    if ($bc->tag !== 0x30) {
                        throw new DerError('BasicConstraints is not a SEQUENCE');
                    }
                    $c = $bc->start;
                    if ($c < $bc->end) {
                        $first = self::readTlv($certDer, $c, $bc->end);
                        if ($first->tag === 0x01) {
                            if ($first->end - $first->start !== 1) {
                                throw new DerError('BasicConstraints cA is not one byte');
                            }
                            $info['ca'] = ord($certDer[$first->start]) !== 0;
                            $c = $first->end;
                        }
                    }
                    if ($c < $bc->end) {
                        $pl = self::readTlv($certDer, $c, $bc->end);
                        if ($pl->tag !== 0x02 || $pl->end - $pl->start < 1 || $pl->end - $pl->start > 2 || (ord($certDer[$pl->start]) & 0x80) !== 0) {
                            throw new DerError('BasicConstraints pathLenConstraint malformed');
                        }
                        $n = 0;
                        for ($i = $pl->start; $i < $pl->end; $i++) {
                            $n = ($n << 8) | ord($certDer[$i]);
                        }
                        $info['pathLen'] = $n;
                        $c = $pl->end;
                    }
                    if ($c !== $bc->end) {
                        throw new DerError('BasicConstraints has trailing data');
                    }
                } elseif (self::oidEquals($certDer, $ident, self::OID_KEY_USAGE)) {
                    if ($info['hasKeyUsage']) {
                        throw new DerError('duplicate keyUsage extension');
                    }
                    $info['hasKeyUsage'] = true;
                    $bs = self::readTlv($certDer, $nxt->start, $nxt->end);
                    if ($bs->tag !== 0x03 || $bs->end - $bs->start < 2) {
                        throw new DerError('keyUsage is not a BIT STRING');
                    }
                    if (ord($certDer[$bs->start]) > 7) {
                        throw new DerError('keyUsage BIT STRING has more than 7 unused bits');
                    }
                    $info['keyCertSign'] = (ord($certDer[$bs->start + 1]) & 0x04) !== 0;
                }
            }
        }
        return $info;
    }

    public static function oidToDotted(string $b, Tlv $t): string
    {
        if ($t->tag !== 0x06 || $t->end <= $t->start) {
            throw new DerError('extension OID is malformed');
        }
        $arcs = [];
        $v = 0;
        $open = false;
        for ($i = $t->start; $i < $t->end; $i++) {
            $byte = ord($b[$i]);
            if (!$open && $byte === 0x80) {
                throw new DerError('extension OID has a non-minimal arc');
            }
            $v = ($v << 7) | ($byte & 0x7F);
            $open = ($byte & 0x80) !== 0;
            if (!$open) {
                $arcs[] = $v;
                $v = 0;
            }
        }
        if ($open) {
            throw new DerError('extension OID is truncated');
        }
        $first = $arcs[0];
        $head = $first < 40 ? [0, $first] : ($first < 80 ? [1, $first - 40] : [2, $first - 80]);
        return implode('.', array_merge($head, array_slice($arcs, 1)));
    }

    /**
     * STRICT extension table of a tbsCertificate (the SEQUENCE INCLUDING its header), keyed by dotted OID.
     * @return array<string,CertExtension>
     */
    public static function parseTbsExtensions(string $tbsDer): array
    {
        $tbs = self::readTlv($tbsDer, 0);
        if ($tbs->tag !== 0x30) {
            throw new DerError('tbsCertificate is not a SEQUENCE');
        }
        if ($tbs->end !== strlen($tbsDer)) {
            throw new DerError('trailing bytes after tbsCertificate');
        }
        $out = [];
        $seen = false;
        $blockEnd = -1;
        $p = $tbs->start;
        while ($p < $tbs->end) {
            $el = self::readTlv($tbsDer, $p, $tbs->end);
            $p = $el->end;
            if ($el->tag !== 0xA3) {
                continue;
            }
            if ($seen) {
                throw new DerError('duplicate [3] extensions block');
            }
            $seen = true;
            $blockEnd = $el->end;
            $seq = self::readTlv($tbsDer, $el->start, $el->end);
            if ($seq->tag !== 0x30) {
                throw new DerError('extensions is not a SEQUENCE');
            }
            if ($seq->end !== $el->end) {
                throw new DerError('trailing bytes after the Extensions SEQUENCE');
            }
            if ($seq->start === $seq->end) {
                throw new DerError('empty Extensions SEQUENCE');
            }
            $q = $seq->start;
            while ($q < $seq->end) {
                $ext = self::readTlv($tbsDer, $q, $seq->end);
                $q = $ext->end;
                if ($ext->tag !== 0x30) {
                    throw new DerError('extension is not a SEQUENCE');
                }
                $ident = self::readTlv($tbsDer, $ext->start, $ext->end);
                $dotted = self::oidToDotted($tbsDer, $ident);
                $r = $ident->end;
                $nxt = self::readTlv($tbsDer, $r, $ext->end);
                $critical = false;
                if ($nxt->tag === 0x01) {
                    if ($nxt->end - $nxt->start !== 1 || ord($tbsDer[$nxt->start]) !== 0xFF) {
                        throw new DerError("extension $dotted has a non-DER critical flag");
                    }
                    $critical = true;
                    $r = $nxt->end;
                    $nxt = self::readTlv($tbsDer, $r, $ext->end);
                }
                if ($nxt->tag !== 0x04) {
                    throw new DerError("extension $dotted value is not an OCTET STRING");
                }
                if ($nxt->end !== $ext->end) {
                    throw new DerError("extension $dotted has trailing bytes");
                }
                if (isset($out[$dotted])) {
                    throw new DerError("duplicate extension $dotted");
                }
                $out[$dotted] = new CertExtension($critical, substr($tbsDer, $nxt->start, $nxt->end - $nxt->start));
            }
        }
        if ($seen && $blockEnd !== $tbs->end) {
            throw new DerError('extensions block is not the last TBS element');
        }
        return $out;
    }

    /** The tbsCertificate bytes (header included) of a DER certificate; rejects trailing bytes after the certificate. */
    public static function tbsOfCertificate(string $certDer): string
    {
        $outer = self::readTlv($certDer, 0);
        if ($outer->tag !== 0x30) {
            throw new DerError('certificate is not a DER SEQUENCE');
        }
        if ($outer->end !== strlen($certDer)) {
            throw new DerError('trailing bytes after the certificate');
        }
        $tbs = self::readTlv($certDer, $outer->start, $outer->end);
        if ($tbs->tag !== 0x30) {
            throw new DerError('certificate has no tbsCertificate');
        }
        return substr($certDer, $outer->start, $tbs->end - $outer->start);
    }

    /** @return array<string,CertExtension> */
    public static function parseCertExtensions(string $certDer): array
    {
        return self::parseTbsExtensions(self::tbsOfCertificate($certDer));
    }

    public const RECOGNISED_CRITICAL = ['2.5.29.19', '2.5.29.15'];

    /** RFC 5280 4.2: the first critical extension this verifier does not understand, else null. Throws on a malformed table. */
    public static function unrecognisedCriticalExtension(string $certDer, ?array $recognised = null): ?string
    {
        $ok = $recognised ?? self::RECOGNISED_CRITICAL;
        foreach (self::parseCertExtensions($certDer) as $oid => $e) {
            if ($e->critical && !in_array((string)$oid, $ok, true)) {
                return (string)$oid;
            }
        }
        return null;
    }

    /**
     * CA roles over an ordered chain (index 0 = leaf ... last = self-signed root). A failure reason or null.
     * @param list<string> $orderedDer
     */
    public static function checkChainRoles(array $orderedDer): ?string
    {
        try {
            $n = count($orderedDer);
            for ($i = 0; $i < $n; $i++) {
                $info = self::readCertRoleInfo($orderedDer[$i]);
                if ($i === 0 && $n > 1) {
                    if ($info['ca']) {
                        return 'leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)';
                    }
                    continue;
                }
                if ($i === 0) {
                    continue;
                }
                if (!$info['hasBasicConstraints']) {
                    return "issuer certificate at depth $i has no BasicConstraints (not a CA)";
                }
                if (!$info['ca']) {
                    return "issuer certificate at depth $i is not a CA (BasicConstraints CA:FALSE)";
                }
                if ($info['hasKeyUsage'] && !$info['keyCertSign']) {
                    return "issuer certificate at depth $i keyUsage lacks keyCertSign";
                }
                $pl = $info['pathLen'] ?? null;
                if ($pl !== null && $pl < $i - 1) {
                    return "issuer certificate at depth $i pathLenConstraint $pl is exceeded (" . ($i - 1) . ' intermediate(s) below)';
                }
            }
            return null;
        } catch (DerError $e) {
            return 'certificate extension parse failed: ' . $e->getMessage();
        }
    }

    // ---- validity (x509-validity) -------------------------------------------------------------------------------------------------

    /** A TLV with up to 4 length bytes (the lenient reader of the validity code). */
    private static function tlvAt(string $der, int $off): Tlv
    {
        if ($off + 2 > strlen($der)) {
            throw new DerError('truncated');
        }
        $tag = ord($der[$off]);
        $ln = ord($der[$off + 1]);
        $start = $off + 2;
        if (($ln & 0x80) !== 0) {
            $n = $ln & 0x7F;
            if ($n === 0 || $n > 4 || $start + $n > strlen($der)) {
                throw new DerError('bad length');
            }
            $ln = 0;
            for ($i = 0; $i < $n; $i++) {
                $ln = $ln * 256 + ord($der[$start + $i]);
            }
            $start += $n;
        }
        $end = $start + $ln;
        if ($end > strlen($der)) {
            throw new DerError('truncated');
        }
        return new Tlv($tag, $start, $end);
    }

    /** Lenient reader used by the certificate model (same rules as the validity code). */
    public static function tlvLenient(string $der, int $off): Tlv
    {
        return self::tlvAt($der, $off);
    }

    private static function isDigits(string $s): bool
    {
        return $s !== '' && ctype_digit($s);
    }

    /** Days since 1970-01-01 of the proleptic Gregorian date (any year). */
    public static function daysFromCivil(int $y, int $m, int $d): int
    {
        $y -= $m <= 2 ? 1 : 0;
        $era = intdiv($y >= 0 ? $y : $y - 399, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    public static function daysInMonth(int $y, int $m): int
    {
        if ($m === 2) {
            $leap = ($y % 4 === 0 && $y % 100 !== 0) || $y % 400 === 0;
            return $leap ? 29 : 28;
        }
        return in_array($m, [4, 6, 9, 11], true) ? 30 : 31;
    }

    /** Strict RFC 5280 Time (UTCTime 0x17 / GeneralizedTime 0x18) to epoch ms; null for anything else (fail closed). */
    public static function parseDerTime(int $tag, string $text): ?int
    {
        if ($tag === 0x17 && strlen($text) === 13) {
            if (!self::isDigits(substr($text, 0, 2))) {
                return null;
            }
            $yy = (int)substr($text, 0, 2);
            $y = $yy >= 50 ? 1900 + $yy : 2000 + $yy;
            $rest = substr($text, 2);
        } elseif ($tag === 0x18 && strlen($text) === 15) {
            if (!self::isDigits(substr($text, 0, 4))) {
                return null;
            }
            $y = (int)substr($text, 0, 4);
            $rest = substr($text, 4);
        } else {
            return null;
        }
        if ($rest[10] !== 'Z' || !self::isDigits(substr($text, 0, strlen($text) - 1))) {
            return null;
        }
        $mon = (int)substr($rest, 0, 2);
        $day = (int)substr($rest, 2, 2);
        $h = (int)substr($rest, 4, 2);
        $mi = (int)substr($rest, 6, 2);
        $sec = (int)substr($rest, 8, 2);
        if ($mon < 1 || $mon > 12 || $day < 1 || $h > 23 || $mi > 59 || $sec > 59) {
            return null;
        }
        if ($day > self::daysInMonth($y, $mon)) {
            return null;
        }
        return ((self::daysFromCivil($y, $mon, $day) * 24 + $h) * 60 + $mi) * 60_000 + $sec * 1000;
    }

    /**
     * The validity instants (epoch ms) of a DER certificate; null members when malformed.
     * @return array{0: ?int, 1: ?int}
     */
    public static function derValidityMs(string $der): array
    {
        try {
            $cert = self::tlvAt($der, 0);
            if ($cert->tag !== 0x30) {
                throw new DerError('not a SEQUENCE');
            }
            $tbs = self::tlvAt($der, $cert->start);
            if ($tbs->tag !== 0x30) {
                throw new DerError('not a SEQUENCE');
            }
            $off = $tbs->start;
            $el = self::tlvAt($der, $off);
            if ($el->tag === 0xA0) {
                $off = $el->end;
                $el = self::tlvAt($der, $off);
            }
            if ($el->tag !== 0x02) {
                throw new DerError('serial');
            }
            $off = $el->end;
            $el = self::tlvAt($der, $off);
            if ($el->tag !== 0x30) {
                throw new DerError('signature');
            }
            $off = $el->end;
            $el = self::tlvAt($der, $off);
            if ($el->tag !== 0x30) {
                throw new DerError('issuer');
            }
            $validity = self::tlvAt($der, $el->end);
            if ($validity->tag !== 0x30 || $validity->end > $tbs->end) {
                throw new DerError('validity');
            }
            $nb = self::tlvAt($der, $validity->start);
            $na = self::tlvAt($der, $nb->end);
            if ($na->end !== $validity->end) {
                throw new DerError('validity has extra fields');
            }
            $text = static fn(Tlv $t): string => substr($der, $t->start, $t->end - $t->start);
            return [self::parseDerTime($nb->tag, $text($nb)), self::parseDerTime($na->tag, $text($na))];
        } catch (DerError) {
            return [null, null];
        }
    }

    /** True iff both validity bounds parse and `from - skew <= now <= to + skew`; false (fail closed) for any unparseable bound. */
    public static function x509ValidAt(string $der, float $nowMs, float $skewMs = 0): bool
    {
        [$lo, $hi] = self::derValidityMs($der);
        return $lo !== null && $hi !== null && $nowMs + $skewMs >= $lo && $nowMs - $skewMs <= $hi;
    }
}
