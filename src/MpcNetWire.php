<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The wire layer of the networked MPC runner: the length-prefixed JSON frame codec with strict envelope validation, the canonical hex
 * field-element encoding and the abort kinds. Sockets, TLS and the distributed protocol driver are not part of this class.
 * A frame is ['v' => mixed, 'ty' => string, 'sid' => string, 'seq' => mixed, 'rd' => string, 'd' => mixed]. A body that is not valid
 * UTF-8 is refused (fail closed; a lenient decoder would substitute characters).
 */
final class MpcNetWire
{
    public const WIRE_VERSION = 2;
    /** Largest frame body accepted or produced (4 MiB). */
    public const MAX_FRAME_BYTES = 4 * 1024 * 1024;
    public const ABORT_KINDS = ['timeout', 'disconnect', 'version', 'malformed', 'oversize', 'duplicate', 'out-of-order', 'wrong-round',
        'wrong-session', 'identity', 'commitment', 'ot-check', 'mac-check', 'dealer', 'equivocation', 'flood', 'peer-abort', 'local'];
    private const FRAME_TYPES = ['hello', 'msg', 'abort'];

    /** JSON text (JSON.stringify semantics) of the value shapes the protocol uses: Obj and string-keyed arrays keep insertion order. */
    public static function stringify(mixed $v): string
    {
        if ($v === null) {
            return 'null';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (is_string($v)) {
            return Json::lenientStr($v);
        }
        if ($v instanceof Num || is_int($v) || is_float($v)) {
            return Json::canonicalizeLenient($v);
        }
        if ($v instanceof \GMP) {
            return gmp_strval($v);
        }
        if ($v instanceof Obj) {
            $parts = [];
            foreach ($v->keys() as $k) {
                $parts[] = Json::lenientStr($k) . ':' . self::stringify($v->get($k));
            }
            return '{' . implode(',', $parts) . '}';
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return '[' . implode(',', array_map(self::stringify(...), $v)) . ']';
            }
            $parts = [];
            foreach ($v as $k => $x) {
                $parts[] = Json::lenientStr((string) $k) . ':' . self::stringify($x);
            }
            return '{' . implode(',', $parts) . '}';
        }
        throw new \InvalidArgumentException('stringify: unsupported value ' . get_debug_type($v));
    }

    /** Length-prefixed (4-byte big-endian) JSON frame; throws when the body exceeds MAX_FRAME_BYTES. @param array{v:mixed,ty:mixed,sid:mixed,seq:mixed,rd:mixed,d:mixed} $f */
    public static function encodeFrame(array $f): string
    {
        $body = self::stringify(['v' => $f['v'], 'ty' => $f['ty'], 'sid' => $f['sid'], 'seq' => $f['seq'], 'rd' => $f['rd'], 'd' => $f['d']]);
        if (strlen($body) > self::MAX_FRAME_BYTES) {
            throw new \InvalidArgumentException('frame too large');
        }
        return pack('N', strlen($body)) . $body;
    }

    /** The JavaScript number value of a parsed JSON number (null for anything else). */
    private static function num(mixed $o): ?float
    {
        return $o instanceof Num ? $o->float() : null;
    }

    private static function safeInt(?float $d): bool
    {
        return $d !== null && is_finite($d) && $d === floor($d) && abs($d) <= 9007199254740991.0;
    }

    private static function negZero(float $d): bool
    {
        return $d === 0.0 && fdiv(1, $d) < 0;
    }

    private static function parseObject(string $body): ?Obj
    {
        if (preg_match('//u', $body) !== 1) {
            return null;
        }
        try {
            $j = (new Parser($body, 512, true))->run(); // last duplicate key wins, like JSON.parse
        } catch (\Throwable) {
            return null;
        }
        return $j instanceof Obj ? $j : null;
    }

    /** The envelope version of a body, or null when it is not a JSON object with a safe-integer v. */
    public static function peekVersion(string $body): ?int
    {
        $o = self::parseObject($body);
        if ($o === null) {
            return null;
        }
        $v = self::num($o->get('v'));
        return self::safeInt($v) && !self::negZero($v) ? (int) $v : null;
    }

    private static function envelopeShapeOk(Obj $o): bool
    {
        if (count($o->keys()) !== 6 || !$o->has('v')) {
            return false;
        }
        $ty = $o->get('ty');
        if (!is_string($ty) || !in_array($ty, self::FRAME_TYPES, true) || !is_string($o->get('sid')) || !is_string($o->get('rd'))) {
            return false;
        }
        $seq = self::num($o->get('seq'));
        if (!self::safeInt($seq) || $seq < 0 || self::negZero($seq)) {
            return false;
        }
        return $o->has('d');
    }

    /** The frame (an Obj) when it is a well-formed envelope of the current version, else null. */
    public static function parseFrame(string $body): ?Obj
    {
        $o = self::parseObject($body);
        if ($o === null) {
            return null;
        }
        $v = self::num($o->get('v'));
        return $v !== null && $v === (float) self::WIRE_VERSION && self::envelopeShapeOk($o) ? $o : null;
    }

    /** The peer's version when the body is a well-formed envelope of a DIFFERENT version, else null. */
    public static function versionMismatch(string $body): ?int
    {
        $o = self::parseObject($body);
        if ($o === null) {
            return null;
        }
        $v = self::num($o->get('v'));
        if ($v === null || !self::safeInt($v) || self::negZero($v) || $v === (float) self::WIRE_VERSION) {
            return null;
        }
        return self::envelopeShapeOk($o) ? (int) $v : null;
    }

    public static function hx(\GMP $x): string
    {
        return gmp_strval($x, 16);
    }

    /** Canonical lowercase hex without leading zeros of an element below the field prime; null otherwise. */
    public static function unhx(mixed $s): ?\GMP
    {
        if (!is_string($s) || preg_match('/\A(?:0|[1-9a-f][0-9a-f]{0,15})\z/', $s) !== 1) {
            return null;
        }
        $v = gmp_init($s, 16);
        return gmp_cmp($v, MpcField::prime()) < 0 ? $v : null;
    }

    /** @return ?list<\GMP> */
    public static function unhxArray(mixed $a, int $len): ?array
    {
        if (!is_array($a) || !array_is_list($a) || count($a) !== $len) {
            return null;
        }
        $out = [];
        foreach ($a as $x) {
            $v = self::unhx($x);
            if ($v === null) {
                return null;
            }
            $out[] = $v;
        }
        return $out;
    }
}

/** Reassembles length-prefixed frames from arbitrary chunking; an oversize length prefix throws. */
final class MpcNetFrameSplitter
{
    private string $data = '';

    /** @return list<string> the complete frame bodies now available */
    public function push(string $chunk): array
    {
        $this->data .= $chunk;
        $out = [];
        $off = 0;
        $n = strlen($this->data);
        while ($n - $off >= 4) {
            $len = unpack('N', $this->data, $off)[1];
            if ($len > MpcNetWire::MAX_FRAME_BYTES) {
                throw new \LengthException('oversize');
            }
            if ($n - $off < 4 + $len) {
                break;
            }
            $out[] = substr($this->data, $off + 4, $len);
            $off += 4 + $len;
        }
        $this->data = (string) substr($this->data, $off);
        return $out;
    }
}
