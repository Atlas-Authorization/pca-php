<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Jose.php';

/** A refusal of the SCITT layer; `codeName` is the stable machine-readable code when the reference names one. */
class ScittError extends \RuntimeException
{
    public function __construct(string $message, public readonly ?string $codeName = null)
    {
        parent::__construct($message);
    }
}

/** A CBOR tagged value (major type 6). */
final class CborTag
{
    public function __construct(public readonly int|float $tag, public readonly mixed $value)
    {
    }
}

/**
 * A CBOR map with int or text keys, in insertion order (JS Map semantics: setting an existing key replaces its value in place;
 * the number 1 and the text "1" are different keys). Encoding sorts the entries by encoded key.
 */
final class CborMap
{
    /** @var list<array{0:int|float|string,1:mixed}> */
    private array $entries = [];

    /** @param list<array{0:int|float|string,1:mixed}> $pairs */
    public static function of(array $pairs): self
    {
        $m = new self();
        foreach ($pairs as [$k, $v]) {
            $m->set($k, $v);
        }
        return $m;
    }

    private static function same(mixed $a, mixed $b): bool
    {
        if (is_string($a) || is_string($b)) {
            return $a === $b;
        }
        return $a == $b;
    }

    public function set(int|float|string $k, mixed $v): void
    {
        foreach ($this->entries as $i => $e) {
            if (self::same($e[0], $k)) {
                $this->entries[$i][1] = $v;
                return;
            }
        }
        $this->entries[] = [$k, $v];
    }

    public function has(int|float|string $k): bool
    {
        foreach ($this->entries as $e) {
            if (self::same($e[0], $k)) {
                return true;
            }
        }
        return false;
    }

    public function get(int|float|string $k): mixed
    {
        foreach ($this->entries as $e) {
            if (self::same($e[0], $k)) {
                return $e[1];
            }
        }
        return null;
    }

    /** @return list<array{0:int|float|string,1:mixed}> */
    public function entries(): array
    {
        return $this->entries;
    }
}

/**
 * SCITT transparency receipts for Proof-Carrying Authority: RFC 9943 Signed Statements and RFC 9942 COSE Receipts over an
 * RFC 9162 SHA-256 Merkle log, with a strict deterministic CBOR codec (RFC 8949 4.2.1) sufficient for COSE_Sign1 (the reference's
 * pca-scitt). Everything fails closed.
 *
 * Values: statements, receipts, hashes, proofs and keys' raw bytes are binary PHP strings; roots and leaves in the log API are
 * base64url strings. CBOR model: int, text = string, byte string = {@see Bytes}, bool, null, list, {@see CborMap}, {@see CborTag}.
 * Keys: EdDSA takes a raw 32-byte seed (signing) or a raw 32-byte public key (verifying); ES256 takes a JWK (Obj, private to sign,
 * public to verify) or an OpenSSL key.
 */
final class Scitt
{
    public const COSE_SIGN1_TAG = 18;
    public const HDR_ALG = 1;
    public const HDR_CONTENT_TYPE = 3;
    public const HDR_CWT_CLAIMS = 15;
    public const CWT_ISS = 1;
    public const CWT_SUB = 2;
    public const HDR_VDS = 395;
    public const HDR_VDS_PROOFS = 396;
    public const VDS_RFC9162_SHA256 = 1;
    public const PROOF_TYPE_INCLUSION = -1;
    public const DEFAULT_CONTENT_TYPE = 'application/pca+json';

    private const MAX_SAFE = 9007199254740991;
    private const ALG_LABEL = ['EdDSA' => -8, 'ES256' => -7];
    /** The P-256 group order and half of it, big-endian. */
    private const P256_N = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51";
    private const P256_HALF_N = "\x7F\xFF\xFF\xFF\x80\x00\x00\x00\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xDE\x73\x7D\x56\xD3\x8B\xCF\x42\x79\xDC\xE5\x61\x7E\x31\x92\xA8";

    // ---- number helpers ------------------------------------------------------------------------------------------------

    /** `Number.isSafeInteger` as an int (null when it is not one); negative zero is an integer here, callers refuse it. */
    private static function safeInt(mixed $v): ?int
    {
        if (is_int($v)) {
            return abs($v) <= self::MAX_SAFE ? $v : null;
        }
        $f = Js::num($v);
        if ($f === null || is_nan($f) || is_infinite($f) || $f != floor($f) || abs($f) > self::MAX_SAFE) {
            return null;
        }
        return (int)$f;
    }

    private static function negZero(mixed $v): bool
    {
        if ($v instanceof Num) {
            return $v->float() == 0.0 && str_starts_with($v->lexeme, '-');
        }
        $f = Js::num($v);
        return $f !== null && $f === 0.0 && fdiv(1.0, $f) < 0;
    }

    /** A CBOR integer: a safe integer that is not negative zero. */
    private static function cborInt(mixed $v): ?int
    {
        return self::negZero($v) ? null : self::safeInt($v);
    }

    // ---- RFC 9162 Merkle tree ------------------------------------------------------------------------------------------

    public static function emptyRoot(): string
    {
        return hash('sha256', '', true);
    }

    private static function raw(mixed $b): string
    {
        if ($b instanceof Bytes) {
            return $b->raw;
        }
        if (!is_string($b)) {
            throw new \TypeError('expected bytes');
        }
        return $b;
    }

    /** SHA-256(0x00 || entry). */
    public static function leafHash(mixed $entry): string
    {
        return hash('sha256', "\x00" . self::raw($entry), true);
    }

    /** SHA-256(0x01 || left || right). */
    public static function nodeHash(mixed $left, mixed $right): string
    {
        return hash('sha256', "\x01" . self::raw($left) . self::raw($right), true);
    }

    private static function splitPoint(int|float $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $k;
    }

    /**
     * MTH over already-hashed leaves (RFC 9162 2.1.1).
     * @param list<string> $leafHashes
     */
    public static function treeHash(array $leafHashes): string
    {
        $n = count($leafHashes);
        if ($n === 0) {
            return self::emptyRoot();
        }
        if ($n === 1) {
            return $leafHashes[0];
        }
        $k = self::splitPoint($n);
        return self::nodeHash(self::treeHash(array_slice($leafHashes, 0, $k)), self::treeHash(array_slice($leafHashes, $k)));
    }

    /**
     * Inclusion path for leaf `$index` (RFC 9162 2.1.3.1), bottom-up.
     * @param list<string> $leafHashes
     * @return list<string>
     */
    public static function inclusionPath(array $leafHashes, mixed $index): array
    {
        $n = count($leafHashes);
        $i = self::safeInt($index);
        if ($i === null || $i < 0 || $i >= $n) {
            throw new \RangeException('rfc9162: leaf index out of range');
        }
        if ($n === 1) {
            return [];
        }
        $k = self::splitPoint($n);
        if ($i < $k) {
            return [...self::inclusionPath(array_slice($leafHashes, 0, $k), $i), self::treeHash(array_slice($leafHashes, $k))];
        }
        return [...self::inclusionPath(array_slice($leafHashes, $k), $i - $k), self::treeHash(array_slice($leafHashes, 0, $k))];
    }

    /** @param list<mixed> $path */
    private static function hashesOk(array $path): bool
    {
        foreach ($path as $p) {
            if (!is_string($p) || strlen($p) !== 32) {
                return false;
            }
        }
        return true;
    }

    /**
     * Recompute the root from a leaf hash and its path (RFC 9162 2.1.3.2); null for an invalid (index, size, path).
     * @param list<string> $path
     */
    public static function rootFromInclusionPath(string $leaf, mixed $index, mixed $size, array $path): ?string
    {
        $i = self::safeInt($index);
        $n = self::safeInt($size);
        if ($i === null || $n === null || $i < 0 || self::negZero($index) || $n < 1 || $i >= $n) {
            return null;
        }
        if (strlen($leaf) !== 32 || !self::hashesOk($path)) {
            return null;
        }
        $fn = $i;
        $sn = $n - 1;
        $r = $leaf;
        foreach ($path as $p) {
            if ($sn === 0) {
                return null;
            }
            if (($fn & 1) === 1 || $fn === $sn) {
                $r = self::nodeHash($p, $r);
                if (($fn & 1) === 0) {
                    while (($fn & 1) === 0 && $fn !== 0) {
                        $fn >>= 1;
                        $sn >>= 1;
                    }
                }
            } else {
                $r = self::nodeHash($r, $p);
            }
            $fn >>= 1;
            $sn >>= 1;
        }
        return $sn === 0 ? $r : null;
    }

    /** @param list<string> $path */
    public static function verifyInclusionPath(string $leaf, mixed $index, mixed $size, array $path, string $root): bool
    {
        $computed = self::rootFromInclusionPath($leaf, $index, $size, $path);
        return $computed !== null && hash_equals($computed, $root);
    }

    /**
     * @param list<string> $d
     * @return list<string>
     */
    private static function subproof(int $m, array $d, bool $complete): array
    {
        $n = count($d);
        if ($m === $n) {
            return $complete ? [] : [self::treeHash($d)];
        }
        $k = self::splitPoint($n);
        if ($m <= $k) {
            return [...self::subproof($m, array_slice($d, 0, $k), $complete), self::treeHash(array_slice($d, $k))];
        }
        return [...self::subproof($m - $k, array_slice($d, $k), false), self::treeHash(array_slice($d, 0, $k))];
    }

    /**
     * Consistency proof between the first `$m` leaves and all of `$leafHashes` (RFC 9162 2.1.4.1).
     * @param list<string> $leafHashes
     * @return list<string>
     */
    public static function consistencyPath(array $leafHashes, mixed $m): array
    {
        $i = self::safeInt($m);
        if ($i === null || $i < 1 || $i > count($leafHashes)) {
            throw new \RangeException('rfc9162: consistency size out of range');
        }
        return self::subproof($i, $leafHashes, true);
    }

    /** ECMAScript ToInt32 (the reference tests `first & (first - 1)` with a 32-bit bitwise AND). */
    private static function i32(int $x): int
    {
        $x &= 0xFFFFFFFF;
        return $x >= (1 << 31) ? $x - (1 << 32) : $x;
    }

    /**
     * RFC 9162 2.1.4.2. A proof from an empty tree is rejected.
     * @param list<string> $path
     */
    public static function verifyConsistencyPath(mixed $first, mixed $second, string $firstRoot, string $secondRoot, array $path): bool
    {
        $a = self::safeInt($first);
        $b = self::safeInt($second);
        if ($a === null || $b === null || $a < 1 || $b < $a) {
            return false;
        }
        if (strlen($firstRoot) !== 32 || strlen($secondRoot) !== 32 || !self::hashesOk($path)) {
            return false;
        }
        if ($a === $b) {
            return count($path) === 0 && hash_equals($firstRoot, $secondRoot);
        }
        if (count($path) === 0) {
            return false;
        }
        $nodes = array_values($path);
        if ((self::i32($a) & self::i32($a - 1)) === 0) { // first is an exact power of two
            array_unshift($nodes, $firstRoot);
        }
        $fn = $a - 1;
        $sn = $b - 1;
        while (($fn & 1) === 1) {
            $fn >>= 1;
            $sn >>= 1;
        }
        $fr = $sr = $nodes[0];
        foreach (array_slice($nodes, 1) as $c) {
            if ($sn === 0) {
                return false;
            }
            if (($fn & 1) === 1 || $fn === $sn) {
                $fr = self::nodeHash($c, $fr);
                $sr = self::nodeHash($c, $sr);
                if (($fn & 1) === 0) {
                    while (($fn & 1) === 0 && $fn !== 0) {
                        $fn >>= 1;
                        $sn >>= 1;
                    }
                }
            } else {
                $sr = self::nodeHash($sr, $c);
            }
            $fn >>= 1;
            $sn >>= 1;
        }
        return $sn === 0 && hash_equals($firstRoot, $fr) && hash_equals($secondRoot, $sr);
    }

    // ---- deterministic CBOR --------------------------------------------------------------------------------------------

    private static function wellFormed(string $s): bool
    {
        return preg_match('//u', $s) === 1; // a lone surrogate is not valid UTF-8
    }

    private static function head(int $major, int $arg): string
    {
        $mt = $major << 5;
        if ($arg < 24) {
            return chr($mt | $arg);
        }
        if ($arg < 0x100) {
            return chr($mt | 24) . chr($arg);
        }
        if ($arg < 0x10000) {
            return chr($mt | 25) . pack('n', $arg);
        }
        if ($arg < 0x100000000) {
            return chr($mt | 26) . pack('N', $arg);
        }
        return chr($mt | 27) . pack('J', $arg);
    }

    private static function encodeKey(mixed $k): string
    {
        if (is_int($k) || is_float($k)) {
            $n = self::cborInt($k);
            if ($n === null) {
                throw new \TypeError('cbor: bad integer map key');
            }
            return $n >= 0 ? self::head(0, $n) : self::head(1, -1 - $n);
        }
        if (!is_string($k)) {
            throw new \TypeError('cbor: bad map key');
        }
        if (!self::wellFormed($k)) {
            throw new \TypeError('cbor: text string contains a lone surrogate');
        }
        return self::head(3, strlen($k)) . $k;
    }

    /** Deterministically encode a CBOR value. Throws TypeError on anything outside the supported profile. */
    public static function encode(mixed $v): string
    {
        if ($v === null) {
            return "\xf6";
        }
        if ($v === false) {
            return "\xf4";
        }
        if ($v === true) {
            return "\xf5";
        }
        if (is_int($v) || is_float($v) || $v instanceof Num) {
            $n = self::cborInt($v);
            if ($n === null) {
                throw new \TypeError('cbor: only safe-integer numbers are supported');
            }
            return $n >= 0 ? self::head(0, $n) : self::head(1, -1 - $n);
        }
        if (is_string($v)) {
            if (!self::wellFormed($v)) {
                throw new \TypeError('cbor: text string contains a lone surrogate');
            }
            return self::head(3, strlen($v)) . $v;
        }
        if ($v instanceof Bytes) {
            return self::head(2, strlen($v->raw)) . $v->raw;
        }
        if (is_array($v) && array_is_list($v)) {
            $out = self::head(4, count($v));
            foreach ($v as $x) {
                $out .= self::encode($x);
            }
            return $out;
        }
        if ($v instanceof CborMap) {
            $entries = [];
            foreach ($v->entries() as [$k, $val]) {
                $entries[] = [self::encodeKey($k), self::encode($val)];
            }
            usort($entries, static fn(array $a, array $b): int => strcmp($a[0], $b[0]));
            for ($i = 1; $i < count($entries); $i++) {
                if ($entries[$i - 1][0] === $entries[$i][0]) {
                    throw new \TypeError('cbor: duplicate map key');
                }
            }
            $out = self::head(5, count($entries));
            foreach ($entries as [$k, $val]) {
                $out .= $k . $val;
            }
            return $out;
        }
        if ($v instanceof CborTag) {
            $t = self::cborInt($v->tag);
            if ($t === null || $t < 0) {
                throw new \TypeError('cbor: bad tag');
            }
            return self::head(6, $t) . self::encode($v->value);
        }
        throw new \TypeError('cbor: unsupported value');
    }

    /** Strictly decode ONE canonical CBOR value; the whole buffer must be consumed. */
    public static function decode(mixed $data): mixed
    {
        if ($data instanceof Bytes) {
            $data = $data->raw;
        }
        if (!is_string($data)) {
            throw new \TypeError('cbor: input must be bytes');
        }
        $pos = 0;
        $v = self::readValue($data, $pos);
        if ($pos !== strlen($data)) {
            throw new \InvalidArgumentException('cbor: trailing bytes');
        }
        return $v;
    }

    private static function readByte(string $buf, int &$pos): int
    {
        if ($pos >= strlen($buf)) {
            throw new \InvalidArgumentException('cbor: unexpected end of input');
        }
        return ord($buf[$pos++]);
    }

    private static function readBytes(string $buf, int &$pos, int $n): string
    {
        if ($pos + $n > strlen($buf)) {
            throw new \InvalidArgumentException('cbor: unexpected end of input');
        }
        $out = substr($buf, $pos, $n);
        $pos += $n;
        return $out;
    }

    private static function readUint(string $buf, int &$pos, int $n): int
    {
        $b = self::readBytes($buf, $pos, $n);
        if ($n === 1) {
            return ord($b);
        }
        if ($n === 2) {
            return (int)unpack('n', $b)[1];
        }
        if ($n === 4) {
            return (int)unpack('N', $b)[1];
        }
        $u = unpack('Nh/Nl', $b);
        if ($u['h'] >= 0x200000) {
            throw new \InvalidArgumentException('cbor: integer out of safe range');
        }
        return ($u['h'] << 32) | $u['l'];
    }

    /** @return array{0:int,1:int} major type, argument */
    private static function readHead(string $buf, int &$pos): array
    {
        $ib = self::readByte($buf, $pos);
        $major = $ib >> 5;
        $info = $ib & 0x1F;
        if ($major === 7 && $info >= 24) {
            throw new \InvalidArgumentException('cbor: unsupported simple/float value');
        }
        if ($info < 24) {
            return [$major, $info];
        }
        foreach ([[24, 1, 24], [25, 2, 0x100], [26, 4, 0x10000], [27, 8, 0x100000000]] as [$code, $n, $floor]) {
            if ($info === $code) {
                $arg = self::readUint($buf, $pos, $n);
                if ($arg < $floor) {
                    throw new \InvalidArgumentException('cbor: non-minimal integer');
                }
                return [$major, $arg];
            }
        }
        throw new \InvalidArgumentException('cbor: unsupported additional information (indefinite/reserved)');
    }

    private static function readValue(string $buf, int &$pos): mixed
    {
        [$major, $arg] = self::readHead($buf, $pos);
        switch ($major) {
            case 0:
                return $arg;
            case 1:
                if ($arg >= self::MAX_SAFE) { // |-1 - arg| must stay within the safe range
                    throw new \InvalidArgumentException('cbor: integer out of safe range');
                }
                return -1 - $arg;
            case 2:
                return new Bytes(self::readBytes($buf, $pos, $arg));
            case 3:
                $s = self::readBytes($buf, $pos, $arg);
                if (!self::wellFormed($s)) {
                    throw new ScittError('The encoded data was not valid for encoding utf-8', 'ERR_ENCODING_INVALID_ENCODED_DATA');
                }
                return $s;
            case 4:
                $out = [];
                for ($i = 0; $i < $arg; $i++) {
                    $out[] = self::readValue($buf, $pos);
                }
                return $out;
            case 5:
                $m = new CborMap();
                $prev = null;
                for ($i = 0; $i < $arg; $i++) {
                    $start = $pos;
                    $key = self::readValue($buf, $pos);
                    if (!is_int($key) && !is_string($key)) {
                        throw new \TypeError('cbor: map key must be int or text');
                    }
                    $kb = substr($buf, $start, $pos - $start);
                    if ($prev !== null && strcmp($prev, $kb) >= 0) {
                        throw new \InvalidArgumentException('cbor: map keys not canonically ordered / duplicate');
                    }
                    $prev = $kb;
                    $m->set($key, self::readValue($buf, $pos));
                }
                return $m;
            case 6:
                return new CborTag($arg, self::readValue($buf, $pos));
            default: // 7: simple values (the head already refused floats and extended simples)
                if ($arg === 20) {
                    return false;
                }
                if ($arg === 21) {
                    return true;
                }
                if ($arg === 22) {
                    return null;
                }
                throw new \InvalidArgumentException('cbor: unsupported simple/float value');
        }
    }

    // ---- COSE ---------------------------------------------------------------------------------------------------------

    private static function algForLabel(mixed $label): ?string
    {
        $f = Js::num($label);
        return $f === -8.0 ? 'EdDSA' : ($f === -7.0 ? 'ES256' : null);
    }

    /** A 64-byte IEEE-P1363 signature with 0 < r < n and 0 < s <= n/2 (low-S). */
    private static function isCanonicalEs256(string $sig): bool
    {
        if (strlen($sig) !== 64) {
            return false;
        }
        $r = substr($sig, 0, 32);
        $s = substr($sig, 32);
        return $r !== str_repeat("\0", 32) && strcmp($r, self::P256_N) < 0 && $s !== str_repeat("\0", 32) && strcmp($s, self::P256_HALF_N) <= 0;
    }

    /** n - s over 32 big-endian bytes (s < n). */
    private static function negateS(string $s): string
    {
        $out = '';
        $borrow = 0;
        for ($i = 31; $i >= 0; $i--) {
            $d = ord(self::P256_N[$i]) - ord($s[$i]) - $borrow;
            $borrow = $d < 0 ? 1 : 0;
            $out = chr($d & 0xFF) . $out;
        }
        return $out;
    }

    private static function signBytes(string $alg, mixed $key, string $msg): string
    {
        if ($alg === 'EdDSA') {
            return Jose::jwsSign('EdDSA', $key, $msg);
        }
        $sig = Jose::jwsSign('ES256', $key, $msg);
        if (strlen($sig) !== 64) {
            throw new \RuntimeException('bad ES256 signature');
        }
        $s = substr($sig, 32);
        if (strcmp($s, self::P256_HALF_N) > 0) { // low-S: a statement has exactly one valid signature form
            $s = self::negateS($s);
        }
        return substr($sig, 0, 32) . $s;
    }

    private static function verifyBytes(string $alg, mixed $key, string $msg, string $sig, bool $allowHighS = false): bool
    {
        if ($alg === 'EdDSA') {
            return Jose::jwsVerify('EdDSA', $key, $sig, $msg);
        }
        // ECDSA is malleable: a high-S variant would be a second, distinct Merkle leaf for the same statement.
        if (!$allowHighS && !self::isCanonicalEs256($sig)) {
            return false;
        }
        if ($allowHighS && strlen($sig) !== 64) {
            return false;
        }
        return Jose::jwsVerify('ES256', $key, $sig, $msg);
    }

    /** The COSE_Sign1 Sig_structure (RFC 9052 4.4), external_aad empty. */
    private static function sigStructure(string $protectedBytes, string $payload): string
    {
        return self::encode(['Signature1', new Bytes($protectedBytes), new Bytes(''), new Bytes($payload)]);
    }

    // ---- Signed Statements --------------------------------------------------------------------------------------------

    /**
     * Sign a PCActn / verdict as a COSE Signed Statement (COSE_Sign1) whose payload is the strict canonical JSON of `$payload`.
     * `$opts`: alg ('EdDSA' | 'ES256'), key, issuer, and optionally subject and contentType.
     */
    public static function signStatement(mixed $payload, mixed $opts): string
    {
        $alg = Js::opt($opts, 'alg');
        $label = is_string($alg) ? (self::ALG_LABEL[$alg] ?? null) : null;
        $prot = CborMap::of([[self::HDR_ALG, $label], [self::HDR_CONTENT_TYPE, Js::opt($opts, 'contentType') ?? self::DEFAULT_CONTENT_TYPE]]);
        $claims = CborMap::of([[self::CWT_ISS, Js::opt($opts, 'issuer')]]);
        if (Js::has($opts, 'subject')) {
            $claims->set(self::CWT_SUB, Js::opt($opts, 'subject'));
        }
        $prot->set(self::HDR_CWT_CLAIMS, $claims);
        $protectedBytes = self::encode($prot);
        if ($label === null) { // an unsupported alg leaves a null label that no verifier accepts: refuse here
            throw new \TypeError('cbor: unsupported value');
        }
        $payloadBytes = Json::canonicalizeNative($payload);
        $sig = self::signBytes($alg, Js::opt($opts, 'key'), self::sigStructure($protectedBytes, $payloadBytes));
        return self::encode(new CborTag(self::COSE_SIGN1_TAG, [new Bytes($protectedBytes), new CborMap(), new Bytes($payloadBytes), new Bytes($sig)]));
    }

    /**
     * Decode and structurally validate a COSE_Sign1 (tag 18): protectedBytes, protectedMap, unprotected, payload (null when
     * detached), signature. Throws on any deviation.
     * @return array{protectedBytes:string,protectedMap:CborMap,unprotected:CborMap,payload:?string,signature:string}
     */
    public static function decodeCoseSign1(mixed $data): array
    {
        $top = self::decode($data);
        if (!($top instanceof CborTag) || $top->tag !== self::COSE_SIGN1_TAG) {
            throw new \TypeError('cose: not a COSE_Sign1 (tag 18)');
        }
        $arr = $top->value;
        if (!is_array($arr) || !array_is_list($arr) || count($arr) !== 4) {
            throw new \TypeError('cose: malformed COSE_Sign1 array');
        }
        [$protectedBytes, $unprotected, $payload, $signature] = $arr;
        if (!($protectedBytes instanceof Bytes)) {
            throw new \TypeError('cose: protected must be a bstr');
        }
        if (!($unprotected instanceof CborMap)) {
            throw new \TypeError('cose: unprotected must be a map');
        }
        if (!($payload instanceof Bytes) && $payload !== null) {
            throw new \TypeError('cose: payload must be a bstr or nil');
        }
        if (!($signature instanceof Bytes)) {
            throw new \TypeError('cose: signature must be a bstr');
        }
        if ($protectedBytes->raw === '') {
            $pm = new CborMap();
        } else {
            $pm = self::decode($protectedBytes->raw);
            if (!($pm instanceof CborMap)) {
                throw new \TypeError('cbor: expected a map');
            }
        }
        return ['protectedBytes' => $protectedBytes->raw, 'protectedMap' => $pm, 'unprotected' => $unprotected, 'payload' => $payload?->raw, 'signature' => $signature->raw];
    }

    private static function algOf(CborMap $protectedMap): string
    {
        if (!$protectedMap->has(self::HDR_ALG)) {
            throw new \TypeError('cose: missing alg header');
        }
        $label = $protectedMap->get(self::HDR_ALG);
        $alg = (is_int($label) || is_float($label)) ? self::algForLabel($label) : null;
        if ($alg === null) {
            throw new \TypeError('cose: unsupported alg');
        }
        return $alg;
    }

    /**
     * Verify a Signed Statement and say WHY it failed (malformed / missing alg header / unsupported alg / detached payload /
     * non-canonical signature (high-S) / bad signature). Never throws. `$opts`: allowHighS.
     * @return array{ok:bool,reason?:string}
     */
    public static function checkStatement(mixed $statement, mixed $publicKey, mixed $opts = null): array
    {
        $allowHighS = Js::opt($opts, 'allowHighS') === true;
        try {
            $s = self::decodeCoseSign1($statement);
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'malformed: ' . $e->getMessage()];
        }
        if ($s['payload'] === null) {
            return ['ok' => false, 'reason' => 'detached payload'];
        }
        try {
            $alg = self::algOf($s['protectedMap']);
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => str_contains($e->getMessage(), 'missing') ? 'missing alg header' : 'unsupported alg'];
        }
        try {
            $msg = self::sigStructure($s['protectedBytes'], $s['payload']);
            if (self::verifyBytes($alg, $publicKey, $msg, $s['signature'], $allowHighS)) {
                return ['ok' => true];
            }
            if ($alg === 'ES256' && !self::isCanonicalEs256($s['signature']) && self::verifyBytes($alg, $publicKey, $msg, $s['signature'], true)) {
                return ['ok' => false, 'reason' => 'non-canonical signature (high-S)'];
            }
            return ['ok' => false, 'reason' => 'bad signature'];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'bad signature'];
        }
    }

    public static function verifyStatement(mixed $statement, mixed $publicKey, mixed $opts = null): bool
    {
        return self::checkStatement($statement, $publicKey, $opts)['ok'];
    }

    /** The canonical payload bytes carried by a Signed Statement. Throws on a malformed or detached statement. */
    public static function statementPayload(mixed $statement): string
    {
        $payload = self::decodeCoseSign1($statement)['payload'];
        if ($payload === null) {
            throw new \TypeError('cose: statement payload is detached');
        }
        return $payload;
    }

    /** The base64url leaf a statement occupies in the transparency log. */
    public static function statementLeaf(string $statement): string
    {
        return Pca::b64u($statement);
    }

    // ---- inclusion proof codec (RFC 9162) -----------------------------------------------------------------------------

    /**
     * Sibling sides (leaf -> root) for `$index` in a tree of `$size` leaves (RFC 6962 split).
     * @return list<string>
     */
    public static function siblingSides(mixed $index, mixed $size): array
    {
        $idx = Js::num($index);
        $n = Js::num($size);
        if ($idx === null || $n === null) {
            throw new \TypeError('siblingSides: index and size must be numbers');
        }
        $out = [];
        while ($n > 1) {
            $k = (float)self::splitPoint($n);
            if ($idx < $k) {
                $out[] = 'R';
                $n = $k;
            } else {
                $out[] = 'L';
                $idx -= $k;
                $n -= $k;
            }
        }
        return array_reverse($out);
    }

    /** @return list<string> the 32-byte hashes of a proof path (b64u in, raw out) */
    private static function proofHashes(mixed $proof): array
    {
        $path = Js::opt($proof, 'path');
        if (!is_array($path) || !array_is_list($path)) {
            throw new \TypeError('scitt: proof path must be an array');
        }
        $out = [];
        foreach ($path as $step) {
            $h = Pca::unb64u(Js::opt($step, 'hash'), 32);
            if ($h === null) {
                throw new \TypeError('scitt: proof step hash is not a 32-byte b64u hash');
            }
            $out[] = $h;
        }
        return $out;
    }

    /** `proof` = {index, size, path: [{side, hash}]} with b64u hashes. */
    public static function encodeInclusionProof(mixed $proof): string
    {
        $sibs = array_map(static fn(string $h): Bytes => new Bytes($h), self::proofHashes($proof));
        foreach (['size', 'index'] as $m) {
            if ($proof instanceof Obj && !$proof->has($m)) {
                throw new \TypeError('cbor: unsupported value'); // an absent member is `undefined`, which the encoder refuses
            }
        }
        return self::encode([Js::opt($proof, 'size'), Js::opt($proof, 'index'), $sibs]);
    }

    /**
     * Decode an RFC 9162 inclusion proof into {index, size, path: [{side, hash}]} (sides re-derived).
     * @return array{index:int,size:int,path:list<array{side:string,hash:string}>}
     */
    public static function decodeInclusionProof(mixed $data): array
    {
        $v = self::decode($data);
        if (!is_array($v) || !array_is_list($v) || count($v) !== 3) {
            throw new \TypeError('scitt: malformed inclusion proof');
        }
        [$size, $index, $sibs] = $v;
        if (!is_int($size) || !is_int($index)) {
            throw new \TypeError('scitt: proof size/index must be integers');
        }
        if ($size < 1 || $index < 0 || $index >= $size) {
            throw new \InvalidArgumentException('scitt: proof size/index out of range');
        }
        if (!is_array($sibs) || !array_is_list($sibs)) {
            throw new \TypeError('scitt: inclusion path must be an array');
        }
        $sides = self::siblingSides($index, $size);
        if (count($sibs) !== count($sides)) {
            throw new \InvalidArgumentException('scitt: inclusion path length does not match (index,size)');
        }
        $path = [];
        foreach ($sibs as $i => $h) {
            if (!($h instanceof Bytes) || strlen($h->raw) !== 32) {
                throw new \TypeError('scitt: inclusion path entry must be a 32-byte bstr');
            }
            $path[] = ['side' => $sides[$i], 'hash' => Pca::b64u($h->raw)];
        }
        return ['index' => $index, 'size' => $size, 'path' => $path];
    }

    // ---- COSE Receipts (RFC 9942) -------------------------------------------------------------------------------------

    /**
     * A signed COSE Receipt for `$proof` against ledger root `$root` (b64u, 32 bytes); the payload is detached (nil).
     * `$opts`: alg, key, and optionally issuer.
     */
    public static function buildReceipt(mixed $root, mixed $proof, mixed $opts): string
    {
        $rootBytes = Pca::unb64u($root, 32);
        if ($rootBytes === null) {
            throw new \TypeError('scitt: tree root is not a 32-byte b64u hash');
        }
        $alg = Js::opt($opts, 'alg');
        $label = is_string($alg) ? (self::ALG_LABEL[$alg] ?? null) : null;
        $prot = CborMap::of([[self::HDR_ALG, $label], [self::HDR_VDS, self::VDS_RFC9162_SHA256]]);
        if (Js::has($opts, 'issuer')) {
            $prot->set(self::HDR_CWT_CLAIMS, CborMap::of([[self::CWT_ISS, Js::opt($opts, 'issuer')]]));
        }
        $protectedBytes = self::encode($prot);
        if ($label === null) {
            throw new \TypeError('cbor: unsupported value');
        }
        $unprotected = CborMap::of([[self::HDR_VDS_PROOFS, CborMap::of([[self::PROOF_TYPE_INCLUSION, [new Bytes(self::encodeInclusionProof($proof))]]])]]);
        $sig = self::signBytes($alg, Js::opt($opts, 'key'), self::sigStructure($protectedBytes, $rootBytes));
        return self::encode(new CborTag(self::COSE_SIGN1_TAG, [new Bytes($protectedBytes), $unprotected, null, new Bytes($sig)]));
    }

    /** @return array{cose:array,proof:array} */
    private static function decodeReceipt(mixed $receipt): array
    {
        $cose = self::decodeCoseSign1($receipt);
        $vds = $cose['protectedMap']->get(self::HDR_VDS);
        if (!((is_int($vds) || is_float($vds)) && $vds == self::VDS_RFC9162_SHA256)) {
            throw new \TypeError('scitt: receipt is not RFC9162_SHA256');
        }
        if ($cose['payload'] !== null && strlen($cose['payload']) !== 32) {
            throw new \TypeError('scitt: receipt payload (root) must be 32 bytes');
        }
        $proofs = $cose['unprotected']->get(self::HDR_VDS_PROOFS);
        if (!($proofs instanceof CborMap)) {
            throw new \TypeError('scitt: missing verifiable-data-structure-proofs');
        }
        $inclusion = $proofs->get(self::PROOF_TYPE_INCLUSION);
        if (!is_array($inclusion) || !array_is_list($inclusion) || count($inclusion) < 1) {
            throw new \TypeError('scitt: missing inclusion proof');
        }
        $first = $inclusion[0];
        if (!($first instanceof Bytes)) {
            throw new \TypeError('scitt: inclusion proof must be a bstr');
        }
        return ['cose' => $cose, 'proof' => self::decodeInclusionProof($first->raw)];
    }

    /**
     * Verify a COSE Receipt for a Signed Statement; fail closed (never throws). At least one anchor (`treeRoot` and/or
     * `verificationKey`) is required; the inclusion proof must bind the EXACT statement bytes to the receipt's root; a given
     * `statementKey` also verifies the statement's own signature. A key member that is present is always checked: null or an
     * empty key is refused, never skipped (only an omitted key means "no key").
     * `$opts`: treeRoot (b64u), verificationKey, statementKey, allowHighS.
     */
    public static function verifyReceipt(mixed $receipt, mixed $statement, mixed $opts = null): bool
    {
        try {
            $treeRoot = Js::opt($opts, 'treeRoot');
            $hasVk = Js::has($opts, 'verificationKey');
            $hasSk = Js::has($opts, 'statementKey');
            if ($treeRoot === null && !$hasVk) {
                return false; // no anchor
            }
            if (!is_string($statement)) {
                return false;
            }
            $dec = self::decodeReceipt($receipt);
            $proof = $dec['proof'];
            $cose = $dec['cose'];
            $root = self::rootFromInclusionPath(self::leafHash($statement), $proof['index'], $proof['size'], self::proofHashes($proof));
            if ($root === null) {
                return false;
            }
            if ($cose['payload'] !== null && !hash_equals($cose['payload'], $root)) {
                return false;
            }
            $high = Js::opt($opts, 'allowHighS') === true;
            if ($hasVk) {
                $alg = self::algOf($cose['protectedMap']);
                if (!self::verifyBytes($alg, Js::opt($opts, 'verificationKey'), self::sigStructure($cose['protectedBytes'], $root), $cose['signature'], $high)) {
                    return false;
                }
            }
            if ($treeRoot !== null && $treeRoot !== Pca::b64u($root)) {
                return false;
            }
            if ($hasSk && !self::verifyStatement($statement, Js::opt($opts, 'statementKey'), $high ? ['allowHighS' => true] : null)) {
                return false;
            }
            return true;
        } catch (\Throwable) {
            return false; // fail closed
        }
    }

    /** Verify an RFC 9942 / RFC 9162 consistency proof `[old size, new size, [+ bstr]]` between two pinned roots (b64u). */
    public static function verifyConsistencyProof(mixed $proof, mixed $oldRoot, mixed $newRoot): bool
    {
        try {
            $v = self::decode($proof);
            if (!is_array($v) || !array_is_list($v) || count($v) !== 3) {
                return false;
            }
            [$oldSize, $newSize, $path] = $v;
            if (!is_int($oldSize) || !is_int($newSize) || !is_array($path) || !array_is_list($path)) {
                return false;
            }
            $raw = [];
            foreach ($path as $h) {
                if (!($h instanceof Bytes)) {
                    return false;
                }
                $raw[] = $h->raw;
            }
            $r1 = Pca::unb64u($oldRoot, 32);
            $r2 = Pca::unb64u($newRoot, 32);
            if ($r1 === null || $r2 === null) {
                return false;
            }
            return self::verifyConsistencyPath($oldSize, $newSize, $r1, $r2, $raw);
        } catch (\Throwable) {
            return false;
        }
    }
}
