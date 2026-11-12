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

    /** Content bytes of an OID above which it is refused before any decoding (TS and the other natives: 256). */
    public const OID_MAX_CONTENT = 256;
    /** Base-128 groups of one arc above which the OID is refused before any big-number work. */
    public const OID_MAX_ARC_GROUPS = 64;

    public static function oidToDotted(string $b, Tlv $t): string
    {
        if ($t->tag !== 0x06 || $t->end <= $t->start) {
            throw new DerError('extension OID is malformed');
        }
        if ($t->end - $t->start > self::OID_MAX_CONTENT) {
            throw new DerError('extension OID is too long');
        }
        // each arc is kept as its base-128 groups; an arc of up to 8 groups (56 bits) is a native int, a longer one (at most 64 groups) a
        // decimal string: PHP ints wrap silently at 2^63, which let 2^64 + 15 read as 15 and alias a trusted OID
        $arcs = [];
        $groups = [];
        $open = false;
        for ($i = $t->start; $i < $t->end; $i++) {
            $byte = ord($b[$i]);
            if (!$open && $byte === 0x80) {
                throw new DerError('extension OID has a non-minimal arc');
            }
            $groups[] = $byte & 0x7F;
            if (count($groups) > self::OID_MAX_ARC_GROUPS) {
                throw new DerError('extension OID has an oversized arc');
            }
            $open = ($byte & 0x80) !== 0;
            if (!$open) {
                $arcs[] = self::arcValue($groups);
                $groups = [];
            }
        }
        if ($open) {
            throw new DerError('extension OID is truncated');
        }
        $first = $arcs[0];
        if (is_string($first)) { // at least 2^56: the first two arcs are 2.(first - 80)
            return implode('.', array_merge(['2', self::decSub($first, 80)], array_slice($arcs, 1)));
        }
        $head = $first < 40 ? [0, $first] : ($first < 80 ? [1, $first - 40] : [2, $first - 80]);
        return implode('.', array_merge($head, array_slice($arcs, 1)));
    }

    /** @param list<int> $groups base-128 digits, most significant first. @return int|string an int below 2^56, else the exact decimal string */
    private static function arcValue(array $groups): int|string
    {
        if (count($groups) <= 8) {
            $v = 0;
            foreach ($groups as $g) {
                $v = ($v << 7) | $g;
            }
            return $v;
        }
        $limbs = [0]; // little-endian base 10^9
        foreach ($groups as $g) {
            $carry = $g;
            foreach ($limbs as $k => $l) {
                $x = $l * 128 + $carry;
                $limbs[$k] = $x % 1000000000;
                $carry = intdiv($x, 1000000000);
            }
            if ($carry > 0) {
                $limbs[] = $carry;
            }
        }
        $out = (string)array_pop($limbs);
        foreach (array_reverse($limbs) as $l) {
            $out .= str_pad((string)$l, 9, '0', STR_PAD_LEFT);
        }
        return $out;
    }

    /** `$dec - $n` for a decimal string of at least 2^56 and a small n (so the result stays positive). */
    private static function decSub(string $dec, int $n): string
    {
        $i = strlen($dec) - 1;
        $borrow = $n;
        while ($borrow > 0 && $i >= 0) {
            $d = (int)$dec[$i] - ($borrow % 10);
            $borrow = intdiv($borrow, 10);
            if ($d < 0) {
                $d += 10;
                $borrow++;
            }
            $dec[$i] = (string)$d;
            $i--;
        }
        return ltrim($dec, '0') === '' ? '0' : ltrim($dec, '0');
    }

    /** @return list<Tlv> */
    public static function childrenOf(string $b, Tlv $el): array
    {
        $out = [];
        for ($p = $el->start; $p < $el->end; $p = $k->end) {
            $k = self::readTlv($b, $p, $el->end);
            $out[] = $k;
        }
        return $out;
    }

    public static function minimalInteger(string $c): bool
    {
        if ($c === '') {
            return false;
        }
        if (strlen($c) === 1) {
            return true;
        }
        $hi = ord($c[0]);
        $top = ord($c[1]) & 0x80;
        return !($hi === 0 && $top === 0) && !($hi === 0xFF && $top !== 0);
    }

    /** `$kids` carry only `$tags`, each at most once and in that order. @param list<Tlv> $kids @param list<int> $tags */
    public static function inOrder(array $kids, array $tags): void
    {
        foreach ($kids as $k) {
            $i = array_search($k->tag, $tags, true);
            if ($i === false) {
                throw new DerError('member out of order or of no allowed type');
            }
            $tags = array_slice($tags, $i + 1);
        }
    }

    /** The AttributeTypeAndValues of an RDN. Refused beyond OpenSSL: value types other than UTF8, Printable, T61 and IA5. */
    private static function rdn(string $b, Tlv $el): void
    {
        foreach (self::childrenOf($b, $el) as $atv) {
            $parts = $atv->tag === 0x30 ? self::childrenOf($b, $atv) : [];
            if (count($parts) !== 2) {
                throw new DerError('attribute is not {type, value}');
            }
            self::oidToDotted($b, $parts[0]);
            $v = $parts[1];
            if (!in_array($v->tag, [0x0C, 0x13, 0x14, 0x16], true)) {
                throw new DerError('attribute value type');
            }
            if ($v->tag === 0x0C && preg_match('//u', substr($b, $v->start, $v->end - $v->start)) !== 1) {
                throw new DerError('attribute value is not UTF-8');
            }
        }
    }

    /** A GeneralName. Refused beyond OpenSSL: x400Address, ediPartyName, registeredID and the undefined constructed tags. */
    public static function generalName(string $b, Tlv $n): void
    {
        if (in_array($n->tag, [0x81, 0x82, 0x86, 0x87], true)) {
            return;
        }
        if ($n->tag === 0xA0) {
            $kids = self::childrenOf($b, $n);
            if (count($kids) !== 2 || $kids[1]->tag !== 0xA0 || count(self::childrenOf($b, $kids[1])) !== 1) {
                throw new DerError('otherName is not {type, [0] value}');
            }
            self::oidToDotted($b, $kids[0]);
            return;
        }
        if ($n->tag !== 0xA4) {
            throw new DerError('not a supported GeneralName');
        }
        $name = self::readTlv($b, $n->start, $n->end);
        if ($name->tag !== 0x30 || $name->end !== $n->end) {
            throw new DerError('directoryName is not one Name');
        }
        foreach (self::childrenOf($b, $name) as $rdn) {
            if ($rdn->tag !== 0x31) {
                throw new DerError('Name member is not an RDN');
            }
            self::rdn($b, $rdn);
        }
    }

    private static function generalNames(string $b, Tlv $el): void
    {
        foreach (self::childrenOf($b, $el) as $n) {
            self::generalName($b, $n);
        }
    }

    private static function bitStringContent(string $b, Tlv $el): void
    {
        if ($el->end === $el->start || ord($b[$el->start]) > 7) {
            throw new DerError('BIT STRING is malformed');
        }
    }

    private static function bitStringAt(string $v): void
    {
        $bits = self::readTlv($v, 0);
        if ($bits->tag !== 0x03) {
            throw new DerError('value is not a BIT STRING');
        }
        self::bitStringContent($v, $bits);
    }

    /** @return list<Tlv> */
    private static function topSequence(string $v): array
    {
        $seq = self::readTlv($v, 0);
        if ($seq->tag !== 0x30) {
            throw new DerError('extension is not a SEQUENCE');
        }
        return self::childrenOf($v, $seq);
    }

    private static function positiveInteger(string $b, Tlv $el): void
    {
        $c = substr($b, $el->start, $el->end - $el->start);
        if (!self::minimalInteger($c) || ord($c[0]) > 0x7F) {
            throw new DerError('not a positive DER INTEGER');
        }
    }

    private static function basicConstraints(string $v): void
    {
        $kids = self::topSequence($v);
        self::inOrder($kids, [0x01, 0x02]);
        foreach ($kids as $k) {
            if ($k->tag === 0x02) {
                self::positiveInteger($v, $k);
            } elseif ($k->end - $k->start !== 1) {
                throw new DerError('cA is not one byte');
            }
        }
    }

    private static function keyUsage(string $v): void
    {
        self::bitStringAt($v);
        $bits = self::readTlv($v, 0);
        if ($bits->end - $bits->start < 2) {
            throw new DerError('keyUsage has no bits');
        }
    }

    private static function nameConstraints(string $v): void
    {
        $kids = self::topSequence($v);
        self::inOrder($kids, [0xA0, 0xA1]);
        foreach ($kids as $list) {
            foreach (self::childrenOf($v, $list) as $sub) {
                $parts = $sub->tag === 0x30 ? self::childrenOf($v, $sub) : [];
                if ($parts === []) {
                    throw new DerError('GeneralSubtree has no base');
                }
                self::generalName($v, $parts[0]);
                $rest = array_slice($parts, 1);
                self::inOrder($rest, [0x80, 0x81]);
                foreach ($rest as $x) {
                    self::positiveInteger($v, $x);
                }
            }
        }
    }

    private static function distributionPoints(string $v): void
    {
        foreach (self::topSequence($v) as $dp) {
            if ($dp->tag !== 0x30) {
                throw new DerError('DistributionPoint is not a SEQUENCE');
            }
            $kids = self::childrenOf($v, $dp);
            self::inOrder($kids, [0xA0, 0x81, 0xA2]);
            // as Node reads it: reasons alone, nothing at all, or an empty cRLIssuer does not decode
            if (array_filter($kids, static fn(Tlv $k): bool => $k->tag !== 0x81) === []) {
                throw new DerError('DistributionPoint has no name or issuer');
            }
            foreach ($kids as $k) {
                if ($k->tag === 0x81) {
                    self::bitStringContent($v, $k);
                } elseif ($k->tag === 0xA2) {
                    if ($k->end === $k->start) {
                        throw new DerError('cRLIssuer is empty');
                    }
                    self::generalNames($v, $k);
                } else {
                    $inner = self::childrenOf($v, $k);
                    if (count($inner) !== 1) {
                        throw new DerError('distributionPoint is not one name');
                    }
                    if ($inner[0]->tag === 0xA0) {
                        self::generalNames($v, $inner[0]);
                    } elseif ($inner[0]->tag === 0xA1) {
                        self::rdn($v, $inner[0]);
                    } else {
                        throw new DerError('distributionPoint is not a name');
                    }
                }
            }
        }
    }

    /** What ossl_x509v3_cache_extensions decodes: one that fails makes X509_check_issued refuse. A proxyCertInfo is refused outright. */
    public static function cachedExtension(string $oid, string $v): void
    {
        match ($oid) {
            '2.5.29.19' => self::basicConstraints($v),
            '2.5.29.15' => self::keyUsage($v),
            '2.5.29.37' => array_map(static fn(Tlv $o): string => self::oidToDotted($v, $o), self::topSequence($v)),
            '2.5.29.17' => array_map(static fn(Tlv $n) => self::generalName($v, $n), self::topSequence($v)),
            '2.5.29.30' => self::nameConstraints($v),
            '2.5.29.31' => self::distributionPoints($v),
            '2.16.840.1.113730.1.1' => self::bitStringAt($v),
            '1.3.6.1.5.5.7.1.14' => throw new DerError('proxyCertInfo is not supported'),
            default => null,
        };
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
    public static function strictChainError(array $orderedDer): ?string
    {
        $roles = self::checkChainRoles($orderedDer);
        if ($roles !== null) {
            return $roles;
        }
        try {
            foreach ($orderedDer as $i => $der) {
                $oid = self::unrecognisedCriticalExtension($der, [...self::RECOGNISED_CRITICAL, '2.5.29.37']);
                if ($oid !== null) {
                    return "certificate at depth $i has an unrecognised critical extension $oid";
                }
            }
            return null;
        } catch (\Throwable $e) {
            return 'certificate extension parse failed: ' . $e->getMessage();
        }
    }

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
