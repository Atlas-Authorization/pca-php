<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Common.php';
require_once __DIR__ . '/Der.php';

/**
 * A minimal X.509 certificate model for the attestation chain verifiers. Parsing is done here (the vendor chains use
 * RSASSA-PSS with an explicit DEFAULT `trailerField` that strict ASN.1 parsers reject and OpenSSL tolerates), so only the
 * public-key and signature primitives come from OpenSSL. The behaviours the reference gets from node's OpenSSL-backed
 * X509Certificate are reproduced: DN comparison through the OpenSSL text form, `X509_verify` (outer / inner algorithm must
 * agree), `X509_check_ca == 1`, `X509_check_issued`.
 */
final class Cert
{
    private const SIG_ALGS = [
        '1.2.840.10045.4.1' => ['ec', 'sha1'],
        '1.2.840.10045.4.3.1' => ['ec', 'sha224'],
        '1.2.840.10045.4.3.2' => ['ec', 'sha256'],
        '1.2.840.10045.4.3.3' => ['ec', 'sha384'],
        '1.2.840.10045.4.3.4' => ['ec', 'sha512'],
        '1.2.840.113549.1.1.5' => ['rsa', 'sha1'],
        '1.2.840.113549.1.1.14' => ['rsa', 'sha224'],
        '1.2.840.113549.1.1.11' => ['rsa', 'sha256'],
        '1.2.840.113549.1.1.12' => ['rsa', 'sha384'],
        '1.2.840.113549.1.1.13' => ['rsa', 'sha512'],
    ];
    private const OID_PSS = '1.2.840.113549.1.1.10';
    private const OID_MGF1 = '1.2.840.113549.1.1.8';
    private const HASH_OIDS = [
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.4' => 'sha224',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];
    private const SHORT_NAMES = [
        '2.5.4.3' => 'CN', '2.5.4.4' => 'SN', '2.5.4.5' => 'serialNumber', '2.5.4.6' => 'C', '2.5.4.7' => 'L',
        '2.5.4.8' => 'ST', '2.5.4.9' => 'street', '2.5.4.10' => 'O', '2.5.4.11' => 'OU', '2.5.4.12' => 'title',
        '2.5.4.13' => 'description', '2.5.4.15' => 'businessCategory', '2.5.4.17' => 'postalCode', '2.5.4.41' => 'name',
        '2.5.4.42' => 'GN', '2.5.4.43' => 'initials', '2.5.4.44' => 'generationQualifier', '2.5.4.46' => 'dnQualifier',
        '2.5.4.65' => 'pseudonym', '1.2.840.113549.1.9.1' => 'emailAddress', '0.9.2342.19200300.100.1.25' => 'DC',
        '0.9.2342.19200300.100.1.1' => 'UID', '1.3.6.1.4.1.311.60.2.1.1' => 'jurisdictionL',
        '1.3.6.1.4.1.311.60.2.1.2' => 'jurisdictionST', '1.3.6.1.4.1.311.60.2.1.3' => 'jurisdictionC',
    ];

    public readonly string $raw;
    public readonly string $tbsDer;
    public readonly string $sigAlgDer;
    public readonly int $sigUnused;
    public readonly string $signature;
    public readonly string $serial;
    public readonly string $innerSigAlgDer;
    public readonly string $issuerDer;
    public readonly string $subjectDer;
    public readonly string $spkiDer;
    private ?PubKey $key = null;
    private ?string $subjectText = null;
    private ?string $issuerText = null;
    /** @var array<string,CertExtension>|null */
    private ?array $exts = null;
    private bool $extsFailed = false;

    private static function nested(string $what): CertError
    {
        return new CertError("error:0688010A:asn1 encoding routines::nested asn1 error ($what)");
    }

    /** Construction throws CertError on a structural problem. */
    public function __construct(string $der)
    {
        try {
            $outer = Der::tlvLenient($der, 0);
            if ($outer->tag !== 0x30) {
                throw self::nested('not a SEQUENCE');
            }
            $raw = substr($der, 0, $outer->end);
            $tbs = Der::tlvLenient($raw, $outer->start);
            if ($tbs->tag !== 0x30) {
                throw self::nested('no tbsCertificate');
            }
            $alg = Der::tlvLenient($raw, $tbs->end);
            $sigv = Der::tlvLenient($raw, $alg->end);
            if ($alg->tag !== 0x30 || $sigv->tag !== 0x03 || $sigv->end !== $outer->end || $sigv->end - $sigv->start < 1) {
                throw self::nested('bad signature wrapper');
            }
            $this->raw = $raw;
            $this->tbsDer = substr($raw, $outer->start, $tbs->end - $outer->start);
            $this->sigAlgDer = substr($raw, $tbs->end, $alg->end - $tbs->end);
            $this->sigUnused = ord($raw[$sigv->start]);
            $this->signature = substr($raw, $sigv->start + 1, $sigv->end - $sigv->start - 1);
            $off = $tbs->start;
            $el = Der::tlvLenient($raw, $off);
            if ($el->tag === 0xA0) {
                $off = $el->end;
                $el = Der::tlvLenient($raw, $off);
            }
            if ($el->tag !== 0x02) {
                throw self::nested('serial');
            }
            $this->serial = substr($raw, $el->start, $el->end - $el->start);
            $off = $el->end;
            $inner = Der::tlvLenient($raw, $off);
            if ($inner->tag !== 0x30) {
                throw self::nested('signature algorithm');
            }
            $this->innerSigAlgDer = substr($raw, $off, $inner->end - $off);
            $off = $inner->end;
            $iss = Der::tlvLenient($raw, $off);
            if ($iss->tag !== 0x30) {
                throw self::nested('issuer');
            }
            $this->issuerDer = substr($raw, $off, $iss->end - $off);
            $off = $iss->end;
            $val = Der::tlvLenient($raw, $off);
            if ($val->tag !== 0x30) {
                throw self::nested('validity');
            }
            $off = $val->end;
            $sub = Der::tlvLenient($raw, $off);
            if ($sub->tag !== 0x30) {
                throw self::nested('subject');
            }
            $this->subjectDer = substr($raw, $off, $sub->end - $off);
            $off = $sub->end;
            $spki = Der::tlvLenient($raw, $off);
            if ($spki->tag !== 0x30) {
                throw self::nested('subjectPublicKeyInfo');
            }
            // SubjectPublicKeyInfo is exactly {algorithm SEQUENCE, subjectPublicKey BIT STRING}: bytes after them are refused (OpenSSL: unexpected eoc)
            $sa = Der::tlvLenient($raw, $spki->start);
            $sb = Der::tlvLenient($raw, $sa->end);
            if ($sa->tag !== 0x30 || $sb->tag !== 0x03 || $sb->end !== $spki->end) {
                throw new CertError('error:0680009F:asn1 encoding routines::unexpected eoc');
            }
            // after the SPKI only the optional [1] issuerUID, [2] subjectUID and [3] extensions may follow, in order, filling the TBS exactly
            $prevTag = 0xA0;
            for ($q = $spki->end; $q < $tbs->end;) {
                try {
                    $x = Der::tlvLenient($raw, $q);
                } catch (DerError) {
                    throw new CertError('error:0680009F:asn1 encoding routines::unexpected eoc');
                }
                if ($x->tag <= $prevTag || $x->tag > 0xA3 || $x->end > $tbs->end) {
                    throw new CertError('error:0680009F:asn1 encoding routines::unexpected eoc');
                }
                $prevTag = $x->tag;
                $q = $x->end;
            }
            $this->spkiDer = substr($raw, $off, $spki->end - $off);
        } catch (DerError $e) {
            throw self::nested($e->getMessage());
        }
    }

    public static function fromPem(string $pem): self
    {
        try {
            $der = Common::pemToDer($pem);
            $outer = Der::tlvLenient($der, 0);
            if ($outer->end !== strlen($der)) {
                throw new CertError('error:0680007B:asn1 encoding routines::header too long'); // bytes after the certificate inside the PEM block
            }
            return new self($der);
        } catch (CertError $e) {
            throw $e;
        } catch (\InvalidArgumentException) {
            throw new CertError('error:0480006C:PEM routines::no start line');
        } catch (DerError $e) {
            throw self::nested($e->getMessage());
        }
    }

    // ---- names ---------------------------------------------------------------------------------------------------------------

    private static function escape(string $s): string
    {
        $out = '';
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $ch = $s[$i];
            $o = ord($ch);
            if ($o < 0x20 || $o === 0x7F) {
                $out .= sprintf('\\%02X', $o);
            } elseif (strpos(',+"\\<>;', $ch) !== false) {
                $out .= '\\' . $ch;
            } elseif ($i === 0 && ($ch === '#' || $ch === ' ')) {
                $out .= '\\' . $ch;
            } elseif ($i === $n - 1 && $ch === ' ') {
                $out .= '\\ ';
            } else {
                $out .= $ch;
            }
        }
        return $out;
    }

    private static function nameValue(string $der, int $off, Tlv $t): string
    {
        $raw = substr($der, $t->start, $t->end - $t->start);
        if ($t->tag === 0x0C) {
            return self::escape(self::utf8Scrub($raw));
        }
        if (in_array($t->tag, [0x13, 0x16, 0x1A, 0x12, 0x14], true)) {
            return self::escape((string)mb_convert_encoding($raw, 'UTF-8', 'ISO-8859-1'));
        }
        if ($t->tag === 0x1E) {
            return self::escape((string)mb_convert_encoding($raw, 'UTF-8', 'UTF-16BE'));
        }
        if ($t->tag === 0x1C) {
            return self::escape((string)mb_convert_encoding($raw, 'UTF-8', 'UTF-32BE'));
        }
        return '#' . strtoupper(bin2hex(substr($der, $off, $t->end - $off)));
    }

    private static function utf8Scrub(string $s): string
    {
        return preg_match('//u', $s) === 1 ? $s : (string)mb_convert_encoding($s, 'UTF-8', 'UTF-8');
    }

    /** OpenSSL's multi-line text of a DN, as node prints `subject` / `issuer` (short names, one entry per line, ' + ' joins an RDN). */
    public static function renderName(string $der): string
    {
        $seq = Der::tlvLenient($der, 0);
        if ($seq->tag !== 0x30) {
            throw new CertError('name is not a SEQUENCE');
        }
        $lines = [];
        $p = $seq->start;
        while ($p < $seq->end) {
            $rdn = Der::tlvLenient($der, $p);
            $p = $rdn->end;
            if ($rdn->tag !== 0x31) {
                throw new CertError('RDN is not a SET');
            }
            $parts = [];
            $q = $rdn->start;
            while ($q < $rdn->end) {
                $atv = Der::tlvLenient($der, $q);
                $q = $atv->end;
                $oid = Der::tlvLenient($der, $atv->start);
                $valOff = $oid->end;
                $val = Der::tlvLenient($der, $valOff);
                $dotted = Der::oidToDotted($der, $oid);
                $parts[] = (self::SHORT_NAMES[$dotted] ?? $dotted) . '=' . self::nameValue($der, $valOff, $val);
            }
            $lines[] = implode(' + ', $parts);
        }
        return implode("\n", $lines);
    }

    public function subject(): string
    {
        return $this->subjectText ??= self::renderName($this->subjectDer);
    }

    public function issuer(): string
    {
        return $this->issuerText ??= self::renderName($this->issuerDer);
    }

    /** Lowercase hex of the serial number without leading zeros (the form the CRL logic compares). */
    public function serialHex(): string
    {
        return ltrim(bin2hex($this->serial), '0');
    }

    // ---- key ---------------------------------------------------------------------------------------------------------------------

    public function publicKey(): PubKey
    {
        if ($this->key === null) {
            try {
                $this->key = Common::loadPublicKey($this->spkiDer);
            } catch (CertError $e) {
                throw new CertError('error:1E08010C:DECODER routines::unsupported (' . $e->getMessage() . ')');
            }
        }
        return $this->key;
    }

    public function spkiSha256(): string
    {
        return Common::spkiSha($this->publicKey(), 'sha256');
    }

    // ---- extensions ----------------------------------------------------------------------------------------------------------------

    /** @return array<string,CertExtension> */
    public function extensions(): array
    {
        if ($this->exts === null && !$this->extsFailed) {
            try {
                $this->exts = Der::parseTbsExtensions($this->tbsDer);
            } catch (DerError) {
                $this->extsFailed = true;
            }
        }
        return $this->exts ?? [];
    }

    /** null when keyUsage is absent, else whether keyCertSign is asserted. */
    private function keyCertSign(): ?bool
    {
        $e = $this->extensions()['2.5.29.15'] ?? null;
        if ($e === null) {
            return null;
        }
        try {
            $bs = Der::readTlv($e->value, 0);
        } catch (DerError) {
            return null;
        }
        if ($bs->tag !== 0x03 || $bs->end - $bs->start < 2) {
            return false;
        }
        return (ord($e->value[$bs->start + 1]) & 0x04) !== 0;
    }

    /** node's `ca` (X509_check_ca() == 1): BasicConstraints cA true, and keyUsage (when present) allows certificate signing. */
    public function ca(): bool
    {
        if ($this->keyCertSign() === false) {
            return false;
        }
        $e = $this->extensions()['2.5.29.19'] ?? null;
        if ($e === null) {
            return false;
        }
        try {
            $seq = Der::readTlv($e->value, 0);
            if ($seq->tag !== 0x30 || $seq->start === $seq->end) {
                return false;
            }
            $first = Der::readTlv($e->value, $seq->start, $seq->end);
            return $first->tag === 0x01 && $first->end - $first->start >= 1 && ord($e->value[$first->start]) !== 0;
        } catch (DerError) {
            return false;
        }
    }

    /** X509_check_issued: the DN link, a matching authority key identifier, and keyCertSign on the issuer. */
    public function checkIssued(self $issuer): bool
    {
        if ($this->issuer() !== $issuer->subject()) {
            return false;
        }
        $akid = $this->extensions()['2.5.29.35'] ?? null;
        $skid = $issuer->extensions()['2.5.29.14'] ?? null;
        if ($akid !== null && $skid !== null) {
            try {
                $seq = Der::readTlv($akid->value, 0);
                if ($seq->tag === 0x30 && $seq->start < $seq->end) {
                    $k = Der::readTlv($akid->value, $seq->start, $seq->end);
                    if ($k->tag === 0x80) {
                        $sk = Der::readTlv($skid->value, 0);
                        if ($sk->tag === 0x04 && substr($akid->value, $k->start, $k->end - $k->start) !== substr($skid->value, $sk->start, $sk->end - $sk->start)) {
                            return false;
                        }
                    }
                }
            } catch (DerError) {
                return false;
            }
        }
        return $issuer->keyCertSign() !== false;
    }

    // ---- signature -------------------------------------------------------------------------------------------------------------------

    /** X509_verify: the outer and inner signature algorithms must agree, then the signature over the TBS. */
    public function verify(PubKey $key): bool
    {
        try {
            if ($this->sigAlgDer !== $this->innerSigAlgDer || $this->sigUnused !== 0) {
                return false;
            }
            return self::verifySignature($this->sigAlgDer, $this->tbsDer, $this->signature, $key);
        } catch (\Throwable) {
            return false;
        }
    }

    public function verifySelf(): bool
    {
        return $this->verify($this->publicKey());
    }

    /** @return array{0: string, 1: ?Tlv} */
    private static function algParts(string $algDer): array
    {
        $seq = Der::tlvLenient($algDer, 0);
        $oid = Der::tlvLenient($algDer, $seq->start);
        $dotted = Der::oidToDotted($algDer, $oid);
        return [$dotted, $oid->end < $seq->end ? Der::tlvLenient($algDer, $oid->end) : null];
    }

    private static function hashOfAlgId(string $der, Tlv $t): string
    {
        if ($t->tag !== 0x30) {
            throw new CertError('hash algorithm is not a SEQUENCE');
        }
        $oid = Der::tlvLenient($der, $t->start);
        $h = self::HASH_OIDS[Der::oidToDotted($der, $oid)] ?? null;
        if ($h === null) {
            throw new CertError('unsupported hash algorithm');
        }
        return $h;
    }

    /** RSASSA-PSS-params with its DEFAULTs (sha1, mgf1-sha1, 20, 1); an explicitly encoded default value is tolerated. @return array{0:string,1:string,2:int} */
    private static function pssParams(string $algDer, ?Tlv $params): array
    {
        $hash = 'sha1';
        $mgfHash = 'sha1';
        $salt = 20;
        if ($params === null || $params->tag !== 0x30) {
            return [$hash, $mgfHash, $salt];
        }
        $p = $params->start;
        while ($p < $params->end) {
            $el = Der::tlvLenient($algDer, $p);
            $p = $el->end;
            if ($el->start >= $el->end) {
                throw new CertError('empty PSS parameter');
            }
            $inner = Der::tlvLenient($algDer, $el->start);
            if ($el->tag === 0xA0) {
                $hash = self::hashOfAlgId($algDer, $inner);
            } elseif ($el->tag === 0xA1) {
                if ($inner->tag !== 0x30) {
                    throw new CertError('mask generation function is not a SEQUENCE');
                }
                $oid = Der::tlvLenient($algDer, $inner->start);
                if (Der::oidToDotted($algDer, $oid) !== self::OID_MGF1) {
                    throw new CertError('unsupported mask generation function');
                }
                $mgfHash = self::hashOfAlgId($algDer, Der::tlvLenient($algDer, $oid->end));
            } elseif ($el->tag === 0xA2) {
                if ($inner->tag !== 0x02) {
                    throw new CertError('salt length is not an INTEGER');
                }
                $salt = (int)hexdec(bin2hex(substr($algDer, $inner->start, $inner->end - $inner->start)) ?: '0');
            } elseif ($el->tag === 0xA3) {
                if ($inner->tag !== 0x02 || hexdec(bin2hex(substr($algDer, $inner->start, $inner->end - $inner->start)) ?: '0') !== 1) {
                    throw new CertError('trailer field is not 1');
                }
            } else {
                throw new CertError('unknown PSS parameter');
            }
        }
        return [$hash, $mgfHash, $salt];
    }

    private static function verifySignature(string $algDer, string $msg, string $sig, PubKey $key): bool
    {
        [$dotted, $params] = self::algParts($algDer);
        if (isset(self::SIG_ALGS[$dotted])) {
            [$kind, $h] = self::SIG_ALGS[$dotted];
            return $kind === 'ec' ? Common::ecdsaVerifyDer($key, $sig, $msg, $h) : Common::rsaPkcs1Verify($key, $sig, $msg, $h);
        }
        if ($dotted === self::OID_PSS) {
            if ($key->type !== 'rsa') {
                return false;
            }
            [$h, $mgf, $salt] = self::pssParams($algDer, $params);
            return Common::rsaPssVerify($key, $sig, $msg, $h, $mgf, $salt);
        }
        return false;
    }

    /** Public entry used by the CRL / OCSP code for an AlgorithmIdentifier. */
    public static function verifyWithAlg(string $algDer, string $msg, string $sig, PubKey $key): bool
    {
        try {
            return self::verifySignature($algDer, $msg, $sig, $key);
        } catch (\Throwable) {
            return false;
        }
    }
}
