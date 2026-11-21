<?php
declare(strict_types=1);

namespace Atlas\Pca;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\CertError;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Der;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/Oidc.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Attest/Cert.php';

/** A SPIFFE validation / parse failure with a stable code (malformed_spiffe_id, chain_signature, svid_revoked, ...). */
final class SpiffeError extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/** A verified JWT-SVID (only verifyJwtSvid builds one that svidToHolder accepts). */
final class JwtSvid
{
    /** @param list<mixed> $audience */
    public function __construct(public readonly Obj $spiffeId, public readonly Obj $claims, public readonly array $audience, public readonly mixed $expiresAt)
    {
    }
}

/** A parsed X.509-SVID: the SPIFFE ID of its single URI SAN, the leaf, and the base64url SPKI DER of its key. */
final class X509Svid
{
    public function __construct(public readonly Obj $spiffeId, public readonly Cert $certificate, public readonly string $publicKeyDer)
    {
    }
}

/**
 * SPIFFE / SPIRE workload identity for PCA holders: SPIFFE ID validation, JWT-SVID and X.509-SVID verification against a trust
 * bundle, binding a verified SVID to an Ed25519 PCA holder key, fail-closed trust-bundle and revocation caches, and blueprint
 * admission evidence. Certificates are PEM text (PHP strings) or DER (Bytes).
 */
final class Spiffe
{
    public const JWT_SVID_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];
    private const SCHEME = 'spiffe://';
    private const OID_KEY_USAGE = '551d0f';
    private const OID_SAN = '551d11';
    private const OID_BASIC_CONSTRAINTS = '551d13';
    private const KNOWN_CRITICAL = ['551d0f', '551d11', '551d13', '551d25', '551d0e', '551d23'];

    /** @var \WeakMap<object, true>|null the objects verifyJwtSvid / verifyX509Svid returned */
    private static ?\WeakMap $verified = null;

    private static function verified(): \WeakMap
    {
        return self::$verified ??= new \WeakMap();
    }

    // ---- SPIFFE ID ------------------------------------------------------------------------------------------------------

    /** Validate and parse `spiffe://<trust-domain><path>`: returns {id, trustDomain, path}; throws SpiffeError. */
    public static function parseSpiffeId(mixed $s): Obj
    {
        if (!is_string($s) || $s === '') {
            throw new SpiffeError('malformed_spiffe_id', 'SPIFFE ID must be a non-empty string');
        }
        if (Js::len($s) > 2048) {
            throw new SpiffeError('id_too_long', 'SPIFFE ID exceeds 2048 bytes');
        }
        if (!str_starts_with($s, self::SCHEME)) {
            throw new SpiffeError('malformed_spiffe_id', 'SPIFFE ID must begin with "' . self::SCHEME . '"');
        }
        $rest = substr($s, strlen(self::SCHEME));
        $slash = strpos($rest, '/');
        $td = $slash === false ? $rest : substr($rest, 0, $slash);
        $path = $slash === false ? '' : substr($rest, $slash);
        if ($td === '') {
            throw new SpiffeError('empty_trust_domain', 'SPIFFE ID has an empty trust domain');
        }
        if (Js::len($td) > 255) {
            throw new SpiffeError('trust_domain_too_long', 'trust domain exceeds 255 bytes');
        }
        if (preg_match('/\A[a-z0-9._-]+\z/', $td) !== 1) {
            throw new SpiffeError('invalid_trust_domain', "trust domain \"$td\" must be lowercase and contain only [a-z0-9._-]");
        }
        if ($path !== '') {
            if (str_ends_with($path, '/')) {
                throw new SpiffeError('invalid_path', 'SPIFFE ID path must not end with a trailing slash');
            }
            foreach (array_slice(explode('/', $path), 1) as $seg) {
                if ($seg === '') {
                    throw new SpiffeError('invalid_path', 'SPIFFE ID path must not contain an empty segment');
                }
                if ($seg === '.' || $seg === '..') {
                    throw new SpiffeError('invalid_path', 'SPIFFE ID path must not contain a "." or ".." segment');
                }
                if (preg_match('/\A[a-zA-Z0-9._-]+\z/', $seg) !== 1) {
                    throw new SpiffeError('invalid_path', "SPIFFE ID path segment \"$seg\" contains an invalid character");
                }
            }
        }
        return Obj::of(['id' => self::SCHEME . $td . $path, 'trustDomain' => $td, 'path' => $path]);
    }

    // ---- DER facts ------------------------------------------------------------------------------------------------------

    /** @return array{0:int,1:int,2:int} tag, content start, content end */
    private static function tlv(string $b, int $off, int $limit): array
    {
        if ($off + 2 > $limit) {
            throw new \RangeError('der: truncated header');
        }
        $tag = ord($b[$off]);
        if (($tag & 0x1f) === 0x1f) {
            throw new \RangeError('der: high-tag-number form is not supported');
        }
        $len = ord($b[$off + 1]);
        $p = $off + 2;
        if ($len & 0x80) {
            $n = $len & 0x7f;
            if ($n === 0 || $n > 4) {
                throw new \RangeError('der: unsupported length form');
            }
            if ($p + $n > $limit) {
                throw new \RangeError('der: truncated length');
            }
            $len = 0;
            for ($i = 0; $i < $n; $i++) {
                $len = $len * 256 + ord($b[$p + $i]);
            }
            $p += $n;
        }
        if ($p + $len > $limit) {
            throw new \RangeError('der: content exceeds container');
        }
        return [$tag, $p, $p + $len];
    }

    /** @return list<array{0:int,1:int,2:int}> */
    private static function children(string $b, array $parent): array
    {
        $out = [];
        for ($off = $parent[1]; $off < $parent[2]; $off = $t[2]) {
            $t = self::tlv($b, $off, $parent[2]);
            $out[] = $t;
        }
        return $out;
    }

    private static function byteAt(string $b, int $i): ?int
    {
        return $i < strlen($b) ? ord($b[$i]) : null;
    }

    /**
     * The X.509 facts the SVID rules need, read from DER: basicConstraints / keyUsage / URI SANs and the critical extensions
     * this package does not understand. Throws \RangeError on malformed DER.
     */
    public static function readCertFacts(string $der): Obj
    {
        $cert = self::tlv($der, 0, strlen($der));
        if ($cert[0] !== 0x30 || $cert[2] !== strlen($der)) {
            throw new \RangeError('der: certificate is not a single SEQUENCE');
        }
        $tbs = self::children($der, $cert)[0] ?? null;
        if ($tbs === null || $tbs[0] !== 0x30) {
            throw new \RangeError('der: missing tbsCertificate');
        }
        $extWrap = null;
        foreach (self::children($der, $tbs) as $f) {
            if ($f[0] === 0xa3) {
                $extWrap = $f;
                break;
            }
        }
        $f = ['basicConstraintsPresent' => false, 'isCa' => false, 'pathLen' => null, 'keyUsagePresent' => false, 'digitalSignature' => false,
            'keyCertSign' => false, 'crlSign' => false, 'uriSans' => [], 'unknownCritical' => []];
        if ($extWrap === null) {
            return Obj::of($f);
        }
        $extSeq = self::children($der, $extWrap)[0] ?? null;
        if ($extSeq === null || $extSeq[0] !== 0x30) {
            throw new \RangeError('der: malformed extensions');
        }
        $seen = [];
        foreach (self::children($der, $extSeq) as $ext) {
            $parts = self::children($der, $ext);
            $oidT = $parts[0] ?? null;
            if ($oidT === null || $oidT[0] !== 0x06) {
                throw new \RangeError('der: malformed extension');
            }
            $oid = bin2hex(substr($der, $oidT[1], $oidT[2] - $oidT[1]));
            if (isset($seen[$oid])) {
                throw new \RangeError('der: duplicate extension');
            }
            $seen[$oid] = true;
            $critical = count($parts) === 3 && $parts[1][0] === 0x01 && self::byteAt($der, $parts[1][1]) === 0xff;
            $valueT = $parts[count($parts) - 1];
            if ($valueT[0] !== 0x04) {
                throw new \RangeError('der: malformed extension value');
            }
            if ($critical && !in_array($oid, self::KNOWN_CRITICAL, true)) {
                $f['unknownCritical'][] = $oid;
            }
            $inner = self::tlv($der, $valueT[1], $valueT[2]);
            if ($oid === self::OID_BASIC_CONSTRAINTS) {
                $f['basicConstraintsPresent'] = true;
                foreach (self::children($der, $inner) as $c) {
                    if ($c[0] === 0x01) {
                        $f['isCa'] = self::byteAt($der, $c[1]) === 0xff;
                    } elseif ($c[0] === 0x02) {
                        $n = 0;
                        for ($i = $c[1]; $i < $c[2]; $i++) {
                            $n = $n * 256 + ord($der[$i]);
                        }
                        $f['pathLen'] = $n;
                    }
                }
            } elseif ($oid === self::OID_KEY_USAGE) {
                if ($inner[0] !== 0x03 || $inner[2] - $inner[1] < 2) {
                    throw new \RangeError('der: malformed keyUsage');
                }
                $b0 = ord($der[$inner[1] + 1]);
                $f['keyUsagePresent'] = true;
                $f['digitalSignature'] = ($b0 & 0x80) !== 0;
                $f['keyCertSign'] = ($b0 & 0x04) !== 0;
                $f['crlSign'] = ($b0 & 0x02) !== 0;
            } elseif ($oid === self::OID_SAN) {
                foreach (self::children($der, $inner) as $gn) {
                    if ($gn[0] === 0x86) {
                        $f['uriSans'][] = (string)mb_convert_encoding(substr($der, $gn[1], $gn[2] - $gn[1]), 'UTF-8', 'ISO-8859-1');
                    }
                }
            }
        }
        return Obj::of($f);
    }

    // ---- certificates ---------------------------------------------------------------------------------------------------

    /** A certificate from PEM text (the first CERTIFICATE block) or DER bytes. */
    private static function toCertificate(mixed $c): Cert
    {
        try {
            $pem = is_string($c) ? $c : ($c instanceof Bytes && str_contains($c->raw, '-----BEGIN ') ? $c->raw : null); // a Buffer holding PEM text is read as PEM
            if ($pem !== null) {
                if (preg_match('/-----BEGIN CERTIFICATE-----\r?\n/', $pem) !== 1) { // OpenSSL wants the header line terminated
                    throw new CertError('error:0480006C:PEM routines::no start line');
                }
                return Cert::fromPem($pem)->nodeStyle();
            }
            if ($c instanceof Bytes) {
                return (new Cert($c->raw))->nodeStyle();
            }
            throw new \TypeError('The "buffer" argument must be an instance of Buffer, TypedArray, DataView or a string');
        } catch (\Throwable $e) {
            throw new SpiffeError('malformed_certificate', 'cannot parse certificate: ' . $e->getMessage());
        }
    }

    private static function factsOf(Cert $c): Obj
    {
        try {
            return self::readCertFacts($c->raw);
        } catch (\Throwable $e) {
            throw new SpiffeError('malformed_certificate', 'cannot read certificate extensions: ' . $e->getMessage());
        }
    }

    private static function validateLeaf(Cert $c): Obj
    {
        $f = self::factsOf($c);
        if ($f->get('unknownCritical') !== []) {
            throw new SpiffeError('unsupported_critical_extension', 'certificate has an unsupported critical extension (' . implode(', ', $f->get('unknownCritical')) . ')');
        }
        $sans = $f->get('uriSans');
        if ($sans === []) {
            throw new SpiffeError('no_uri_san', 'X.509-SVID certificate has no URI SAN');
        }
        if (count($sans) > 1) {
            throw new SpiffeError('multiple_uri_san', 'X.509-SVID certificate must have exactly one URI SAN, found ' . count($sans));
        }
        $id = self::parseSpiffeId($sans[0]);
        if ($id->get('path') === '') {
            throw new SpiffeError('leaf_root_path', 'X.509-SVID leaf SPIFFE ID must have a non-root path');
        }
        if ($f->get('isCa')) {
            throw new SpiffeError('leaf_is_ca', 'leaf certificate must not have the CA flag set to true');
        }
        if (!$f->get('digitalSignature')) {
            throw new SpiffeError('leaf_no_digital_signature', "leaf certificate must have 'digitalSignature' set as key usage");
        }
        if ($f->get('keyCertSign')) {
            throw new SpiffeError('leaf_cert_sign', "leaf certificate must not have 'keyCertSign' set as key usage");
        }
        if ($f->get('crlSign')) {
            throw new SpiffeError('leaf_crl_sign', "leaf certificate must not have 'cRLSign' set as key usage");
        }
        return $id;
    }

    /** Parse an X.509-SVID and apply the leaf rules (no chain, validity or revocation check: see verifyX509Svid). */
    public static function parseX509Svid(mixed $cert): X509Svid
    {
        $c = self::toCertificate($cert);
        return new X509Svid(self::validateLeaf($c), $c, Pca::b64u($c->spkiDer));
    }

    /** @return list<Cert> PEM text holds one or more certificates; DER is one */
    private static function certsOf(mixed $input): array
    {
        if (is_string($input)) {
            $blocks = Common::pemBlocks($input);
            if ($blocks === []) {
                throw new SpiffeError('malformed_certificate', 'no PEM certificate found');
            }
            return array_map(self::toCertificate(...), $blocks);
        }
        return [self::toCertificate($input)];
    }

    /** @return list<Cert> */
    private static function flatCerts(mixed $list): array
    {
        if (!is_array($list) || !array_is_list($list)) {
            throw new \TypeError('chain.flatMap is not a function');
        }
        $out = [];
        foreach ($list as $c) {
            array_push($out, ...self::certsOf($c));
        }
        return $out;
    }

    private static function validateSigner(Cert $c, string $label): Obj
    {
        $f = self::factsOf($c);
        if ($f->get('unknownCritical') !== []) {
            throw new SpiffeError('unsupported_critical_extension', "$label has an unsupported critical extension (" . implode(', ', $f->get('unknownCritical')) . ')');
        }
        if (!$f->get('isCa')) {
            throw new SpiffeError('chain_not_ca', "$label must have the CA flag set to true");
        }
        if (!$f->get('keyUsagePresent') || !$f->get('keyCertSign')) {
            throw new SpiffeError('chain_no_key_cert_sign', "$label must have 'keyCertSign' set as key usage");
        }
        return $f;
    }

    /** Node's X509Certificate.serialNumber: uppercase hex of the INTEGER value (whole bytes, "0" for zero, "-" when negative). */
    public static function serialNumber(Cert $c): string
    {
        $s = $c->serial;
        $v = gmp_import($s);
        $neg = $s !== '' && (ord($s[0]) & 0x80) !== 0;
        if ($neg) {
            $v = gmp_sub(gmp_pow(2, 8 * strlen($s)), $v);
        }
        if (gmp_sign($v) === 0) {
            return '0';
        }
        $h = strtoupper(gmp_strval($v, 16));
        return ($neg ? '-' : '') . (strlen($h) % 2 === 1 ? '0' . $h : $h);
    }

    /** Node's X509Certificate.fingerprint256: colon-separated uppercase hex of sha-256 over the DER. */
    public static function fingerprint256(Cert $c): string
    {
        return implode(':', str_split(strtoupper(hash('sha256', $c->raw)), 2));
    }

    private static function revocationOption(array $opts): void
    {
        if (array_key_exists('revocation', $opts) && !is_callable($opts['revocation'])) {
            throw new SpiffeError('revocation_unavailable', 'revocation must be a function');
        }
    }

    /**
     * Verify an X.509-SVID chain (leaf first; PEM text with several certificates, or a list of PEM / DER) against a trust bundle.
     * Options: trustDomain, roots (list of PEM / DER), nowMs (default now), maxChainLength (8), revocation (callable(Obj
     * subject): exactly false admits; true refuses; anything else or a throw is revocation_unavailable). Throws SpiffeError.
     */
    public static function verifyX509Svid(mixed $chain, array $opts): X509Svid
    {
        self::revocationOption($opts);
        $now = Js::num($opts['nowMs'] ?? null) ?? (float)($opts['nowMs'] ?? floor(microtime(true) * 1000));
        $items = is_string($chain) ? self::certsOf($chain) : self::flatCerts($chain);
        if ($items === []) {
            throw new SpiffeError('chain_empty', 'certificate chain is empty');
        }
        $max = $opts['maxChainLength'] ?? 8;
        $maxN = Js::isNum($max) ? (float)Js::num($max) : (is_string($max) ? IntentWb::jsNumber($max) : (is_bool($max) ? (float)$max : NAN));
        if (count($items) > $maxN) {
            throw new SpiffeError('chain_too_long', 'certificate chain is too long');
        }
        $leaf = $items[0];
        $id = self::validateLeaf($leaf);
        $td = $opts['trustDomain'] ?? null;
        if ($id->get('trustDomain') !== $td) {
            throw new SpiffeError('chain_trust_domain_mismatch', "SPIFFE ID trust domain '{$id->get('trustDomain')}' is not '" . Js::str($td) . "'");
        }
        $roots = self::flatCerts($opts['roots'] ?? null);
        if ($roots === []) {
            throw new SpiffeError('chain_untrusted_root', 'trust bundle has no X.509 authorities');
        }
        foreach ($items as $c) {
            if (!Der::x509ValidAt($c->raw, $now)) {
                throw new SpiffeError('chain_expired', 'a certificate in the chain is not within its validity period');
            }
        }
        $n = count($items);
        for ($i = 1; $i < $n; $i++) {
            $pl = self::validateSigner($items[$i], "signing certificate #$i")->get('pathLen');
            if ($pl !== null && $i - 1 > $pl) {
                throw new SpiffeError('chain_path_len', "signing certificate #$i pathLenConstraint exceeded");
            }
        }
        for ($i = 0; $i + 1 < $n; $i++) {
            $next = $items[$i + 1];
            if (!$items[$i]->checkIssued($next) || !$items[$i]->verify($next->publicKey())) {
                throw new SpiffeError('chain_signature', "certificate #$i is not signed by certificate #" . ($i + 1));
            }
        }
        $top = $items[$n - 1];
        $isRoot = static fn(Cert $c): bool => array_filter($roots, static fn(Cert $r) => $r->raw === $c->raw) !== [];
        if ($n === 1 && $isRoot($leaf)) {
            throw new SpiffeError('chain_untrusted_root', 'a leaf certificate cannot be its own trust anchor');
        }
        if (!($n > 1 && $isRoot($top))) {
            $signer = null;
            foreach ($roots as $r) {
                if ($top->checkIssued($r) && $top->verify($r->publicKey())) {
                    $signer = $r;
                    break;
                }
            }
            if ($signer === null) {
                throw new SpiffeError('chain_untrusted_root', 'the chain does not lead to an authority in the trust bundle');
            }
            if (!Der::x509ValidAt($signer->raw, $now)) {
                throw new SpiffeError('chain_expired', 'the trust bundle authority is not within its validity period');
            }
            $pl = self::validateSigner($signer, 'trust bundle authority')->get('pathLen');
            if ($pl !== null && $n - 1 > $pl) {
                throw new SpiffeError('chain_path_len', 'trust bundle authority pathLenConstraint exceeded');
            }
        }
        if (array_key_exists('revocation', $opts)) {
            foreach ($items as $i => $c) {
                try {
                    $verdict = ($opts['revocation'])(Obj::of(['spiffeId' => $id->get('id'), 'serialNumber' => self::serialNumber($c),
                        'fingerprint256' => self::fingerprint256($c), 'position' => $i, 'isLeaf' => $i === 0]));
                } catch (\Throwable $e) {
                    throw new SpiffeError('revocation_unavailable', 'revocation check failed: ' . $e->getMessage());
                }
                if ($verdict === true) {
                    throw $i === 0 ? new SpiffeError('svid_revoked', "X.509-SVID for {$id->get('id')} is revoked")
                        : new SpiffeError('chain_revoked', "signing certificate #$i of the chain is revoked");
                }
                if ($verdict !== false) {
                    throw new SpiffeError('revocation_unavailable', 'revocation check did not return a boolean');
                }
            }
        }
        $out = new X509Svid($id, $leaf, Pca::b64u($leaf->spkiDer));
        self::verified()[$out] = true;
        return $out;
    }

    // ---- JWT-SVID -------------------------------------------------------------------------------------------------------

    /**
     * Verify a JWT-SVID. Options: audience (string | list, required), key (public JWK, raw Ed25519 key, or a resolver Closure
     * such as a trust bundle's jwtKey), trustDomain (required), nowMs, algorithms (default JWT_SVID_ALGORITHMS; none / HS*
     * refused), clockTolerance, revocation (callable(Obj subject), run last). Throws SpiffeError or JoseError.
     */
    public static function verifyJwtSvid(mixed $token, array $opts): JwtSvid
    {
        self::revocationOption($opts);
        $td = $opts['trustDomain'] ?? null;
        if (!is_string($td) || $td === '') {
            throw new SpiffeError('missing_trust_domain', 'verifyJwtSvid requires `trustDomain` (an unpinned JWT-SVID would accept any trust domain the key signs for)');
        }
        $audience = $opts['audience'] ?? null;
        $list = is_string($audience) ? [$audience] : $audience;
        if (!is_array($list) || !array_is_list($list)) {
            throw new \TypeError("Cannot read properties of " . Js::str($list) . " (reading 'length')");
        }
        if ($list === [] || array_filter($list, static fn(mixed $a) => $a === '' || $a === []) !== []) {
            throw new SpiffeError('missing_audience', 'verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)');
        }
        $algorithms = $opts['algorithms'] ?? self::JWT_SVID_ALGORITHMS;
        if (!is_array($algorithms) || !array_is_list($algorithms)) {
            throw new \TypeError('algorithms.find is not a function');
        }
        $bad = null;
        foreach ($algorithms as $a) {
            if ($a === 'none') {
                $bad = $a;
                break;
            }
            if (!is_string($a)) {
                throw new \TypeError('a.toUpperCase is not a function');
            }
            if (str_starts_with(mb_strtoupper($a, 'UTF-8'), 'HS')) {
                $bad = $a;
                break;
            }
        }
        if ($bad !== null || $algorithms === []) {
            throw new SpiffeError('forbidden_algorithm', 'JWT-SVIDs must not use ' . ($bad ?? 'an empty algorithm list'));
        }
        $jo = ['audience' => $audience, 'algorithms' => $algorithms];
        if (isset($opts['nowMs'])) {
            $jo['nowMs'] = $opts['nowMs'];
        }
        if (array_key_exists('clockTolerance', $opts)) {
            $jo['clockTolerance'] = $opts['clockTolerance'];
        }
        try {
            Jose::assertCanonicalCompactJws($token);
        } catch (\Throwable $e) {
            throw new SpiffeError('malformed_token', $e->getMessage());
        }
        $key = $opts['key'] ?? null;
        [$payload, $header] = Jose::jwtVerify($token, $key instanceof Bytes ? $key->raw : $key, $jo);
        if ($header->has('typ') && $header->get('typ') !== 'JWT' && $header->get('typ') !== 'JOSE') {
            throw new SpiffeError('invalid_typ', "JWT-SVID header typ must be JWT or JOSE, got '" . Js::str($header->get('typ')) . "'");
        }
        if (!Js::isNum($payload->get('exp'))) {
            throw new SpiffeError('missing_exp', 'JWT-SVID is missing the required "exp" claim');
        }
        $sub = $payload->get('sub');
        if (!is_string($sub)) {
            throw new SpiffeError('invalid_subject', 'JWT-SVID "sub" must be a string SPIFFE ID');
        }
        try {
            $id = self::parseSpiffeId($sub);
        } catch (\Throwable $e) {
            throw new SpiffeError('invalid_subject', 'JWT-SVID "sub" is not a valid SPIFFE ID: ' . $e->getMessage());
        }
        if ($id->get('trustDomain') !== $td) {
            throw new SpiffeError('trust_domain_mismatch', "JWT-SVID trust domain \"{$id->get('trustDomain')}\" does not match expected \"$td\"");
        }
        $aud = $payload->has('aud') ? $payload->get('aud') : [];
        $out = new JwtSvid($id, $payload, is_string($aud) ? [$aud] : $aud, $payload->get('exp'));
        if (array_key_exists('revocation', $opts)) {
            $subject = Obj::of(['spiffeId' => $id->get('id')]);
            if (is_string($payload->get('jti'))) {
                $subject->set('jti', $payload->get('jti'));
            }
            $subject->set('expiresAt', $payload->get('exp'));
            $subject->set('tokenHash', Pca::b64u(hash('sha256', $token, true)));
            try {
                $verdict = ($opts['revocation'])($subject);
            } catch (\Throwable $e) {
                throw new SpiffeError('revocation_unavailable', 'revocation check failed: ' . $e->getMessage());
            }
            if ($verdict === true) {
                throw new SpiffeError('svid_revoked', "JWT-SVID for {$id->get('id')} is revoked");
            }
            if ($verdict !== false) {
                throw new SpiffeError('revocation_unavailable', 'revocation check did not return a boolean');
            }
        }
        self::verified()[$out] = true;
        return $out;
    }

    // ---- holder binding -------------------------------------------------------------------------------------------------

    private static function normalizeHolderKey(mixed $k): string
    {
        if ($k instanceof Bytes) {
            if (strlen($k->raw) !== 32) {
                throw new SpiffeError('invalid_holder_key', 'holder key must be a 32-byte Ed25519 public key');
            }
            return Pca::b64u($k->raw);
        }
        $raw = Pca::unb64u($k, 32);
        if ($raw === null) {
            throw new SpiffeError('invalid_holder_key', 'holder key must be a 32-byte Ed25519 public key encoded as base64url');
        }
        return Pca::b64u($raw);
    }

    /** The domain-separated message a workload signs with its SVID key to bind a PCA holder key to its SPIFFE ID. */
    public static function holderBindingMessage(mixed $spiffeId, mixed $holder): string
    {
        return Js::utf8("pca-spiffe-holder-binding-v1\n" . Js::str($spiffeId) . "\n" . Js::str($holder));
    }

    private static function ed25519OfCert(Cert $c): ?string
    {
        $spki = $c->spkiDer;
        return strlen($spki) === 44 && str_starts_with($spki, "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00") ? Pca::b64u(substr($spki, 12)) : null;
    }

    /** A proof by the SVID key over the binding message: Ed25519, ECDSA P1363 (sha-384 on P-384, else sha-256), RSA PKCS#1 v1.5 sha-256. */
    private static function proofOk(Cert $c, string $msg, ?string $sig): bool
    {
        if ($sig === null) {
            return false;
        }
        try {
            $ed = self::ed25519OfCert($c);
            if ($ed !== null) {
                return strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES && sodium_crypto_sign_verify_detached($sig, $msg, (string)Pca::unb64u($ed));
            }
            $k = $c->publicKey();
            if ($k->type === 'ec') {
                return Common::ecdsaVerifyRaw($k, $sig, $msg, $k->curve === 'secp384r1' ? 'sha384' : 'sha256');
            }
            if ($k->type === 'rsa' && !Common::isRsaPss($k)) {
                return Common::rsaPkcs1Verify($k, $sig, $msg, 'sha256');
            }
        } catch (\Throwable) {
        }
        return false;
    }

    /**
     * Bind a VERIFIED SVID to a PCA holder. `$holderKey` null means absent: an X.509-SVID with an Ed25519 key is then its own
     * holder. A holder key other than the SVID key needs opts['proof']; a JWT-SVID needs a matching cnf.jwk unless
     * opts['acceptUnboundJwtHolder'] === true. Returns {holder, spiffeId, trustDomain, path}.
     */
    public static function svidToHolder(mixed $svid, mixed $holderKey = null, mixed $opts = []): Obj
    {
        if (!is_object($svid) || !isset(self::verified()[$svid])) {
            throw new SpiffeError('unverified_svid', 'svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)');
        }
        $id = $svid->spiffeId;
        if ($svid instanceof X509Svid) {
            $certEd = self::ed25519OfCert($svid->certificate);
            if ($holderKey === null) {
                if ($certEd === null) {
                    throw new SpiffeError('invalid_holder_key', 'the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof');
                }
                $holder = self::normalizeHolderKey($certEd);
            } else {
                $holder = self::normalizeHolderKey($holderKey);
                if ($certEd === null || $certEd !== $holder) {
                    $proof = Js::opt($opts, 'proof');
                    if (!is_string($proof)) {
                        throw new SpiffeError('holder_binding_failed', 'the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required');
                    }
                    if (!self::proofOk($svid->certificate, self::holderBindingMessage($id->get('id'), $holder), Pca::unb64u($proof))) {
                        throw new SpiffeError('holder_binding_failed', 'opts.proof does not verify under the X.509-SVID key');
                    }
                }
            }
        } else {
            if ($holderKey === null) {
                throw new SpiffeError('invalid_holder_key', 'a JWT-SVID has no key of its own: pass holderKey');
            }
            $holder = self::normalizeHolderKey($holderKey);
            $jwk = Js::opt($svid->claims->get('cnf'), 'jwk');
            $bound = Js::opt($jwk, 'kty') === 'OKP' && Js::opt($jwk, 'crv') === 'Ed25519' && Js::opt($jwk, 'x') === $holder;
            if (!$bound && Js::opt($opts, 'acceptUnboundJwtHolder') !== true) {
                throw new SpiffeError('holder_binding_failed', 'the JWT-SVID carries no cnf.jwk equal to the holder key (set acceptUnboundJwtHolder only if the key is authenticated by other means)');
            }
        }
        return Obj::of(['holder' => $holder, 'spiffeId' => $id->get('id'), 'trustDomain' => $id->get('trustDomain'), 'path' => $id->get('path')]);
    }

    /** The validated SPIFFE ID a holder record was bridged from. */
    public static function holderToSpiffeId(mixed $holder): string
    {
        return self::parseSpiffeId(Js::get($holder, 'spiffeId'))->get('id');
    }

    /** The SPIFFE ID the K1 spiffe_bound caveat compares: only when the verified SVID is bound to the PCActn leaf holder. */
    public static function spiffeIdForHolder(mixed $svid, mixed $leafHolder, mixed $opts = []): string
    {
        $h = self::svidToHolder($svid, $leafHolder, $opts);
        if ($h->get('holder') !== $leafHolder) {
            throw new SpiffeError('holder_binding_failed', 'the SVID is not bound to the PCActn leaf holder');
        }
        return $h->get('spiffeId');
    }

    /** A K1 discharge-issuer pin for a workload: its own Ed25519 X.509-SVID key and SPIFFE ID, class `workload`. */
    public static function workloadDischargePin(mixed $label, mixed $svid): Obj
    {
        $h = self::svidToHolder($svid);
        return Obj::of(['label' => $label, 'class' => 'workload', 'pk' => $h->get('holder'), 'spiffe_id' => $h->get('spiffeId')]);
    }

    /** The JOSE library's error code for a JoseError (what the reference reports as the refusal reason). */
    public static function joseCode(\Throwable $e): string
    {
        if ($e instanceof OidcCodedError) {
            return $e->codeName;
        }
        if (!($e instanceof JoseError)) {
            return $e instanceof \TypeError ? 'TypeError' : 'Error';
        }
        $m = $e->getMessage();
        return match (true) {
            $m === 'signature verification failed' => 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
            $m === '"exp" claim timestamp check failed' => 'ERR_JWT_EXPIRED',
            str_contains($m, 'claim') && !str_starts_with($m, 'JWT Claims Set') => 'ERR_JWT_CLAIM_VALIDATION_FAILED',
            str_starts_with($m, 'JWT Claims Set') || str_starts_with($m, 'JWTs MUST NOT') => 'ERR_JWT_INVALID',
            $m === '"alg" (Algorithm) Header Parameter value not allowed' => 'ERR_JOSE_ALG_NOT_ALLOWED',
            str_starts_with($m, 'Unsupported') || str_ends_with($m, 'is not recognized') || str_starts_with($m, 'unsupported') => 'ERR_JOSE_NOT_SUPPORTED',
            str_starts_with($m, 'no applicable key') => 'ERR_JWKS_NO_MATCHING_KEY',
            str_starts_with($m, 'multiple matching keys') => 'ERR_JWKS_MULTIPLE_MATCHING_KEYS',
            str_starts_with($m, 'Invalid key') || str_starts_with($m, 'invalid') || str_contains($m, 'JSON Web Key') => 'TypeError',
            default => 'ERR_JWS_INVALID',
        };
    }

    /**
     * Blueprint admission evidence: verify the SVID ({kind:'x509', chain, verify, bind?} or {kind:'jwt', token, verify, bind?}),
     * bind it to `$instanceKey`. Returns {ok, bound, identity?: {spiffe_id}, reason?}; never throws.
     */
    public static function spiffeAdmissionEvidence(mixed $e, mixed $instanceKey): Obj
    {
        try {
            $verify = Js::opt($e, 'verify');
            $verify = $verify instanceof Obj ? array_combine($verify->keys(), array_map($verify->get(...), $verify->keys())) : (array)$verify;
            $svid = Js::opt($e, 'kind') === 'x509' ? self::verifyX509Svid(Js::opt($e, 'chain'), $verify) : self::verifyJwtSvid(Js::opt($e, 'token'), $verify);
            $h = self::svidToHolder($svid, $instanceKey, Js::opt($e, 'bind') ?? []);
            if ($h->get('holder') !== $instanceKey) {
                return Obj::of(['ok' => false, 'bound' => false, 'reason' => 'SVID is bound to a different key']);
            }
            return Obj::of(['ok' => true, 'bound' => true, 'identity' => Obj::of(['spiffe_id' => $h->get('spiffeId')])]);
        } catch (\Throwable $err) {
            return Obj::of(['ok' => false, 'bound' => false, 'reason' => $err instanceof SpiffeError ? $err->codeName : self::joseCode($err)]);
        }
    }

    // ---- caches ---------------------------------------------------------------------------------------------------------

    /** @return array{0: callable, 1: float, 2: float, 3: callable} fetch, refreshMs, maxStaleMs, now */
    private static function cacheOptions(array $o, string $code, string $who): array
    {
        if (!is_callable($o['fetch'] ?? null)) {
            throw new SpiffeError($code, "$who requires `fetch`");
        }
        $r = $o['refreshMs'] ?? null;
        $s = $o['maxStaleMs'] ?? null;
        $fin = static fn(mixed $v): bool => Js::isNum($v) && is_finite((float)Js::num($v));
        if (!($fin($r) && Js::num($r) > 0) || !($fin($s) && Js::num($s) >= Js::num($r))) {
            throw new SpiffeError($code, 'refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)');
        }
        $now = $o['now'] ?? static fn(): float => floor(microtime(true) * 1000);
        return [$o['fetch'], (float)Js::num($r), (float)Js::num($s), $now];
    }

    /** A fail-closed trust-bundle cache: refreshed after refreshMs, never served older than maxStaleMs. */
    public static function createTrustBundleSource(array $opts): TrustBundleSource
    {
        return new TrustBundleSource(...self::cacheOptions($opts, 'trust_bundle_unavailable', 'createTrustBundleSource'));
    }

    /** A fail-closed revocation-list cache feeding the X.509 / JWT revocation checks. */
    public static function createRevocationSource(array $opts): RevocationSource
    {
        return new RevocationSource(...self::cacheOptions($opts, 'revocation_unavailable', 'createRevocationSource'));
    }
}

/** Trust bundle cache: jwtKey is a key resolver for verifyJwtSvid's `key`; x509Roots() feeds verifyX509Svid's `roots`. */
final class TrustBundleSource
{
    private ?array $good = null;
    private ?SpiffeError $lastFailure = null;
    public readonly \Closure $jwtKey;

    /** @internal built by Spiffe::createTrustBundleSource */
    public function __construct(private readonly mixed $fetch, private readonly float $refreshMs, private readonly float $maxStaleMs, private readonly mixed $now)
    {
        $this->jwtKey = function (mixed $header): mixed {
            $jwks = Js::opt($this->current(), 'jwks');
            $keys = Js::opt($jwks, 'keys');
            if ($jwks === null || (is_array($keys) && $keys === [])) {
                throw new SpiffeError('trust_bundle_invalid', 'trust bundle has no JWT authorities');
            }
            return Oidc::createLocalJwkSet($jwks)($header);
        };
    }

    private function t(): float
    {
        return (float)($this->now)();
    }

    private static function usable(mixed $b): bool
    {
        if (!Js::isObj($b) && !(is_array($b))) {
            return false;
        }
        $j = false;
        if (Js::has($b, 'jwks')) {
            $jwks = Js::opt($b, 'jwks');
            if ($jwks === null) {
                throw new \TypeError("Cannot read properties of null (reading 'keys')");
            }
            $keys = Js::opt($jwks, 'keys');
            $j = is_array($keys) && array_is_list($keys) && $keys !== [];
        }
        $x = Js::opt($b, 'x509Authorities');
        return $j || (is_array($x) && array_is_list($x) && $x !== []);
    }

    private function refresh(): void
    {
        try {
            $b = ($this->fetch)();
            if (!self::usable($b)) {
                throw new SpiffeError('trust_bundle_invalid', 'fetched trust bundle has no authorities');
            }
            $this->good = [$b, $this->t()];
            $this->lastFailure = null;
        } catch (\Throwable $e) {
            $this->lastFailure = $e instanceof SpiffeError ? $e : new SpiffeError('trust_bundle_unavailable', 'trust bundle fetch failed: ' . $e->getMessage());
        }
    }

    private function current(): mixed
    {
        if ($this->good === null || $this->t() - $this->good[1] >= $this->refreshMs) {
            $this->refresh();
        }
        if ($this->good === null || $this->t() - $this->good[1] > $this->maxStaleMs) {
            throw $this->lastFailure ?? new SpiffeError('trust_bundle_unavailable', 'no trust bundle available');
        }
        return $this->good[0];
    }

    /** @return list<mixed> */
    public function x509Roots(): array
    {
        $roots = Js::opt($this->current(), 'x509Authorities');
        if (!is_array($roots) || $roots === []) {
            throw new SpiffeError('trust_bundle_invalid', 'trust bundle has no X.509 authorities');
        }
        return array_values($roots);
    }
}

/** Revocation-list cache: x509 / jwt are the checks verifyX509Svid / verifyJwtSvid take as `revocation`. */
final class RevocationSource
{
    private ?array $good = null;
    private ?SpiffeError $lastFailure = null;

    /** @internal built by Spiffe::createRevocationSource */
    public function __construct(private readonly mixed $fetch, private readonly float $refreshMs, private readonly float $maxStaleMs, private readonly mixed $now)
    {
    }

    private function t(): float
    {
        return (float)($this->now)();
    }

    private static function normHex(mixed $s): string
    {
        if (!is_string($s)) {
            throw new \TypeError('s.replace is not a function');
        }
        return mb_strtoupper(str_replace(':', '', $s), 'UTF-8');
    }

    private static function normSerial(mixed $s): string
    {
        return (string)preg_replace('/\A0+(?=.)/', '', self::normHex($s));
    }

    /** @return array<string,true> */
    private static function listOf(mixed $raw, string $key, ?callable $norm = null): array
    {
        if (!Js::has($raw, $key)) {
            return [];
        }
        $v = Js::opt($raw, $key);
        if (!Js::isStrList($v) && $v !== []) {
            throw new SpiffeError('revocation_unavailable', "revocation list field \"$key\" must be an array of strings");
        }
        $out = [];
        foreach ($v as $x) {
            $out['k' . ($norm === null ? $x : $norm($x))] = true;
        }
        return $out;
    }

    private static function snapshot(mixed $list): array
    {
        if (!($list instanceof Obj) && !(is_array($list) && $list !== [] && !array_is_list($list))) {
            throw new SpiffeError('revocation_unavailable', 'revocation list must be an object');
        }
        return ['fingerprints' => self::listOf($list, 'fingerprints', self::normHex(...)), 'serials' => self::listOf($list, 'serials', self::normSerial(...)),
            'spiffeIds' => self::listOf($list, 'spiffeIds'), 'jtis' => self::listOf($list, 'jtis'), 'tokenHashes' => self::listOf($list, 'tokenHashes')];
    }

    private function run(): void
    {
        try {
            $this->good = [self::snapshot(($this->fetch)()), $this->t()];
            $this->lastFailure = null;
        } catch (\Throwable $e) {
            $this->lastFailure = $e instanceof SpiffeError ? $e : new SpiffeError('revocation_unavailable', 'revocation fetch failed: ' . $e->getMessage());
        }
    }

    private function usable(): array
    {
        if ($this->good === null || $this->t() - $this->good[1] > $this->maxStaleMs) {
            throw $this->lastFailure ?? new SpiffeError('revocation_unavailable', 'no revocation snapshot available');
        }
        return $this->good[0];
    }

    public function ensureFresh(): void
    {
        if ($this->good === null || $this->t() - $this->good[1] >= $this->refreshMs) {
            $this->run();
        }
        $this->usable();
    }

    public function refresh(): void
    {
        $this->run();
        if ($this->lastFailure !== null) {
            throw $this->lastFailure;
        }
    }

    /** X.509 check from the cached snapshot (no fetch): fingerprint, serial or SPIFFE ID listed. */
    public function x509(mixed $s): bool
    {
        $snap = $this->usable();
        return isset($snap['fingerprints']['k' . self::normHex(Js::get($s, 'fingerprint256'))]) || isset($snap['serials']['k' . self::normSerial(Js::get($s, 'serialNumber'))])
            || isset($snap['spiffeIds']['k' . Js::str(Js::get($s, 'spiffeId'))]);
    }

    /** JWT check (refreshes when due): SPIFFE ID, jti or token hash listed. */
    public function jwt(mixed $s): bool
    {
        $this->ensureFresh();
        $snap = $this->usable();
        return isset($snap['spiffeIds']['k' . Js::str(Js::get($s, 'spiffeId'))]) || (Js::has($s, 'jti') && isset($snap['jtis']['k' . Js::str(Js::opt($s, 'jti'))]))
            || isset($snap['tokenHashes']['k' . Js::str(Js::get($s, 'tokenHash'))]);
    }

    /** @return \Closure(mixed): bool */
    public function x509Check(): \Closure
    {
        return $this->x509(...);
    }

    /** @return \Closure(mixed): bool */
    public function jwtCheck(): \Closure
    {
        return $this->jwt(...);
    }
}
