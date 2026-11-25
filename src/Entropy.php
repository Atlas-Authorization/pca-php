<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/DetMath.php';
require_once __DIR__ . '/WhatwgUrl.php';
require_once __DIR__ . '/AdaUrl.php';

/**
 * QRNG (quantum random number generator) entropy as an ADD to key generation, never a trust dependency: every seed is
 * HKDF-SHA256(local CSPRNG || quantum), so a hostile or broken quantum source cannot lower the result below the local CSPRNG.
 * This is not a quantum root of trust and makes no post-quantum claim; it only improves the quality of the entropy that feeds key
 * derivation. Parts: an HTTP QRNG source (JSON, hex or base64 bodies; strict fail-closed validation; https only; the key never
 * appears in an error), unavailable-source stubs, SP 800-90B 4.4 continuous health tests (repetition count and adaptive
 * proportion), the combiner mixEntropy, secureSeed and an Ed25519 key-pair helper.
 *
 * The package ships no HTTP client: the HTTP source takes an injected transport callable (see HttpQrngSource). Sources are
 * synchronous. Errors: \TypeError and \RangeException for a bad argument (the reference's TypeError / RangeError), EntropyError for a
 * policy refusal, \RuntimeException otherwise.
 */
interface QrngSource
{
    public function name(): string;

    /** @return string exactly `$numBytes` bytes; throws when the source cannot deliver. */
    public function fetch(int $numBytes);
}

/** The response of an injected HTTP transport. */
interface QrngResponse
{
    public function ok(): bool;

    public function status(): int;

    /** The parsed JSON body (a decoded value: Obj / assoc array / list / scalar); throws when the body is not JSON. */
    public function json(): mixed;

    /** The body text; throws when it cannot be read. */
    public function text(): string;
}

/** A transport throws this when its request was cancelled by the timeout it was given (reported as `timeout`). */
final class QrngFetchAborted extends \RuntimeException
{
}

/** A transport throws this for a failure that carries no usable message (reported as `unknown error`). */
final class QrngOpaqueFailure extends \RuntimeException
{
}

/** A policy refusal; `errorCode` is quantum_required, health_test_failed or insecure_transport. */
final class EntropyError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/** A source that is not configured or not reachable: fetch always fails. */
final class NullQrngSource implements QrngSource
{
    public function __construct(private readonly string $reason = 'no QRNG source configured')
    {
    }

    public function name(): string
    {
        return 'null-qrng';
    }

    public function fetch(int $numBytes)
    {
        throw new \RuntimeException('QRNG unavailable: ' . $this->reason);
    }
}

/** The result of {@see Entropy::secureSeed}. */
final class SecureSeedResult
{
    public function __construct(
        public readonly string $seed,
        public readonly bool $usedQuantum,
        public readonly int $quantumByteCount,
        public readonly ?string $source,
    ) {
    }
}

/**
 * An HTTP QRNG source over an injected transport: `transport(string $url, array $headers, string $redirect, int $timeoutMs): QrngResponse`,
 * called with redirect "error" and the timeout the transport must enforce (throw {@see QrngFetchAborted} when it fires). Config keys:
 * url, apiKey, apiKeyHeader (default x-api-key), format (anu-uint8, hex or base64), timeoutMs (5000), maxBytes (1024), lengthParam
 * (length), extraParams (assoc array), buildUrl (callable(string $base, int $numBytes): string), allowInsecureLoopback (strict true),
 * transport.
 * The default URL builder runs on Ada (the WHATWG URL parser, {@see AdaUrl}): the release package carries libada, so that is the
 * path wherever ext-ffi is enabled. Where it is not (ffi.enable off), the builder serializes printable-ASCII URLs itself with the
 * same result (host, port, dot segments, query form encoding, userinfo, fragment: the shapes the shared corpus pins) and refuses
 * any other URL instead of guessing.
 */
final class HttpQrngSource implements QrngSource
{
    private readonly string $name;
    private readonly string $url;
    private readonly ?string $apiKey;
    private readonly string $apiKeyHeader;
    private readonly string $format;
    private readonly int $timeoutMs;
    private readonly int $maxBytes;
    private readonly string $lengthParam;
    /** @var ?array<string,string> */
    private readonly ?array $extraParams;
    private readonly mixed $buildUrl;
    private readonly bool $allowInsecureLoopback;
    private readonly mixed $transport;

    /** @param array<string,mixed> $config */
    public function __construct(array $config)
    {
        $url = $config['url'] ?? null;
        if (!is_string($url) || $url === '') {
            throw new \TypeError('HttpQrngSource: `url` must be a non-empty string');
        }
        $maxBytes = $config['maxBytes'] ?? Entropy::DEFAULT_MAX_QRNG_BYTES;
        if (!Entropy::isInteger($maxBytes) || $maxBytes <= 0) {
            throw new \TypeError('HttpQrngSource: `maxBytes` must be a positive integer');
        }
        $timeoutMs = $config['timeoutMs'] ?? Entropy::DEFAULT_TIMEOUT_MS;
        if (!Entropy::isInteger($timeoutMs) || $timeoutMs <= 0) {
            throw new \TypeError('HttpQrngSource: `timeoutMs` must be a positive integer');
        }
        $this->url = $url;
        $this->apiKey = isset($config['apiKey']) && is_string($config['apiKey']) ? $config['apiKey'] : null;
        $this->apiKeyHeader = (string) ($config['apiKeyHeader'] ?? 'x-api-key');
        $this->format = (string) ($config['format'] ?? 'anu-uint8');
        $this->timeoutMs = (int) $timeoutMs;
        $this->maxBytes = (int) $maxBytes;
        $this->lengthParam = (string) ($config['lengthParam'] ?? 'length');
        $this->extraParams = isset($config['extraParams']) && is_array($config['extraParams']) ? $config['extraParams'] : null;
        $this->buildUrl = $config['buildUrl'] ?? null;
        $this->allowInsecureLoopback = ($config['allowInsecureLoopback'] ?? null) === true;
        $this->transport = $config['transport'] ?? null;
        $p = WhatwgUrl::parse($url);
        $this->name = 'http-qrng(' . ($p !== null && $p['host'] !== '' ? $p['host'] : 'unknown') . ')';
    }

    public function name(): string
    {
        return $this->name;
    }

    public function fetch(int|float $numBytes): string
    {
        self::requireValidCount($numBytes, $this->maxBytes);
        if (!is_callable($this->transport)) {
            throw new \RuntimeException('QRNG: no fetch implementation available in this runtime');
        }
        $url = $this->makeUrl((int) $numBytes);
        self::assertSecureTransport($url, $this->allowInsecureLoopback);
        $headers = ['accept' => 'application/json, text/plain'];
        if ($this->apiKey !== null && $this->apiKey !== '') {
            $headers[$this->apiKeyHeader] = $this->apiKey;
        }
        try {
            $res = ($this->transport)($url, $headers, 'error', $this->timeoutMs);
        } catch (\Throwable $e) {
            throw new \RuntimeException('QRNG: fetch failed (' . self::scrub(self::describeError($e), $this->apiKey) . ')');
        }
        if (!$res->ok()) {
            throw new \RuntimeException('QRNG: endpoint returned HTTP ' . $res->status());
        }
        $bytes = $this->parseBody($res);
        if (strlen($bytes) !== (int) $numBytes) {
            throw new \RuntimeException("QRNG: expected " . (int) $numBytes . " bytes, response decoded to " . strlen($bytes));
        }
        return $bytes;
    }

    private static function requireValidCount(int|float $n, int $max): void
    {
        if (!Entropy::isInteger($n) || $n <= 0) {
            throw new \TypeError('QRNG: numBytes must be a positive integer, got ' . Entropy::jsNumber($n));
        }
        if ($n > $max) {
            throw new \RangeException("QRNG: requested " . Entropy::jsNumber($n) . " bytes exceeds per-request cap $max");
        }
    }

    private function parseBody(QrngResponse $res): string
    {
        if ($this->format === 'anu-uint8') {
            return Entropy::parseAnuUint8($res->json());
        }
        $text = self::trim($res->text());
        return $this->format === 'hex' ? Entropy::parseHex($text) : Entropy::parseBase64($text);
    }

    /** JavaScript String.prototype.trim (white space and line terminators, Unicode spaces included). */
    private static function trim(string $s): string
    {
        $t = preg_replace('/\A[\s\x{A0}\x{FEFF}\p{Zs}\x{2028}\x{2029}]+|[\s\x{A0}\x{FEFF}\p{Zs}\x{2028}\x{2029}]+\z/u', '', $s);
        return $t ?? trim($s);
    }

    private function makeUrl(int $n): string
    {
        if (is_callable($this->buildUrl)) {
            $r = ($this->buildUrl)($this->url, $n);
            return is_string($r) ? $r : throw new \TypeError('HttpQrngSource: buildUrl must return a string');
        }
        if (AdaUrl::available()) { // the platform URL class itself (the parser the reference runs on)
            $pairs = [[$this->lengthParam, (string) $n]];
            foreach ($this->extraParams ?? [] as $k => $v) {
                $pairs[] = [(string) $k, (string) $v];
            }
            return AdaUrl::withParams($this->url, $pairs) ?? throw new NodeTypeError('Invalid URL', 'ERR_INVALID_URL');
        }
        if (preg_match('/[^\x20-\x7E]/', $this->url) === 1) { // outside what the built-in serializer is known to reproduce: refuse, never guess
            throw new \RuntimeException('QRNG: a URL with non-ASCII characters needs the URL parser library (ext-ffi and libada)');
        }
        $raw = (string) preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', $this->url);
        $raw = str_replace(["\t", "\n", "\r"], '', $raw);
        $p = WhatwgUrl::parse($raw);
        if ($p === null) {
            throw new NodeTypeError('Invalid URL', 'ERR_INVALID_URL');
        }
        $frag = null;
        if (($h = strpos($raw, '#')) !== false) {
            $frag = substr($raw, $h + 1);
            $raw = substr($raw, 0, $h);
        }
        $query = ($q = strpos($raw, '?')) !== false ? substr($raw, $q + 1) : '';
        $pairs = [];
        foreach (explode('&', $query) as $seq) {
            if ($seq === '') {
                continue;
            }
            $eq = strpos($seq, '=');
            [$k, $v] = $eq === false ? [$seq, ''] : [substr($seq, 0, $eq), substr($seq, $eq + 1)];
            $pairs[] = [rawurldecode(str_replace('+', ' ', $k)), rawurldecode(str_replace('+', ' ', $v))];
        }
        $pairs = self::setParam($pairs, $this->lengthParam, (string) $n);
        foreach ($this->extraParams ?? [] as $k => $v) {
            $pairs = self::setParam($pairs, (string) $k, (string) $v);
        }
        $qs = implode('&', array_map(static fn(array $kv): string => self::formEncode($kv[0]) . '=' . self::formEncode($kv[1]), $pairs));
        $ui = '';
        if (preg_match('#\A[A-Za-z][A-Za-z0-9+.\-]*:[/\\\\]*([^/\\\\?\#]*)#', $raw, $m) === 1 && ($at = strrpos($m[1], '@')) !== false) {
            $cred = substr($m[1], 0, $at);
            $c = strpos($cred, ':');
            $set = " \"#<>?`{}/:;=@[\\]^|";
            $ui = WhatwgUrl::pct($c === false ? $cred : substr($cred, 0, $c), $set)
                . ($c === false || $c === strlen($cred) - 1 ? '' : ':' . WhatwgUrl::pct(substr($cred, $c + 1), $set)) . '@';
        }
        return $p['scheme'] . '://' . $ui . $p['host'] . $p['pathname'] . '?' . $qs . ($frag === null ? '' : '#' . WhatwgUrl::pct($frag, "\"<>`"));
    }

    /**
     * URLSearchParams.set: replace the first pair of that name in place, drop the others, or append.
     * @param list<array{0:string,1:string}> $pairs
     * @return list<array{0:string,1:string}>
     */
    private static function setParam(array $pairs, string $name, string $value): array
    {
        $out = [];
        $done = false;
        foreach ($pairs as $kv) {
            if ($kv[0] !== $name) {
                $out[] = $kv;
            } elseif (!$done) {
                $out[] = [$name, $value];
                $done = true;
            }
        }
        if (!$done) {
            $out[] = [$name, $value];
        }
        return $out;
    }

    /** application/x-www-form-urlencoded byte serializer: alphanumerics and *-._ stay, space becomes +, the rest %XX. */
    private static function formEncode(string $s): string
    {
        $e = preg_replace_callback('/[^A-Za-z0-9*\-._ ]/', static fn(array $m): string => sprintf('%%%02X', ord($m[0])), $s);
        return str_replace(' ', '+', (string) $e);
    }

    private static function assertSecureTransport(string $url, bool $allowLoopback): void
    {
        $p = WhatwgUrl::parse($url);
        if ($p === null) {
            throw new EntropyError('insecure_transport', 'QRNG: endpoint URL is not a valid URL');
        }
        if ($p['scheme'] === 'https') {
            return;
        }
        $host = str_starts_with($p['host'], '[') ? substr($p['host'], 0, (int) strpos($p['host'], ']') + 1) : explode(':', $p['host'])[0];
        if ($p['scheme'] === 'http' && $allowLoopback && in_array($host, ['localhost', '127.0.0.1', '[::1]'], true)) {
            return;
        }
        throw new EntropyError('insecure_transport', 'QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)');
    }

    private static function describeError(\Throwable $e): string
    {
        return $e instanceof QrngFetchAborted ? 'timeout' : ($e instanceof QrngOpaqueFailure ? 'unknown error' : $e->getMessage());
    }

    private static function scrub(string $msg, ?string $apiKey): string
    {
        return $apiKey === null || $apiKey === '' ? $msg : str_replace($apiKey, '[redacted]', $msg);
    }
}

/**
 * The entropy functions: the combiner, the health tests, the body parsers, secureSeed and the key-pair helper.
 */
final class Entropy
{
    /** HKDF-SHA256 output is capped at 255 * HashLen (RFC 5869). */
    public const MAX_HKDF_OUTPUT = 8160;
    /** The local CSPRNG share must be at least this many bytes. */
    public const MIN_LOCAL_BYTES = 16;
    public const DEFAULT_SEED_BYTES = 32;
    public const DEFAULT_MAX_QRNG_BYTES = 1024;
    public const DEFAULT_TIMEOUT_MS = 5000;

    private const MIX_LABEL = 'atlas-pca/entropy/mix/v1';
    private const MIX_SALT = 'atlas-pca/entropy/salt/v1';

    /** Number.isInteger: an int, or a finite float with no fraction. */
    public static function isInteger(mixed $v): bool
    {
        return is_int($v) || (is_float($v) && is_finite($v) && floor($v) === $v);
    }

    /** String(number) for the messages the reference words with a number in them. */
    public static function jsNumber(int|float $n): string
    {
        if (is_float($n)) {
            if (is_nan($n)) {
                return 'NaN';
            }
            if (is_infinite($n)) {
                return $n > 0 ? 'Infinity' : '-Infinity';
            }
            if (floor($n) === $n && abs($n) < 1e15) {
                return (string) (int) $n;
            }
        }
        return (string) $n;
    }

    // ---- SP 800-90B 4.4 health tests --------------------------------------------------------------

    /** Repetition-count cutoff 1 + ceil(20 / h) for a min-entropy claim of h bits per byte (NaN, Infinity and negative values pass through like the reference). */
    public static function repetitionCutoff(int|float $h): int|float
    {
        $r = 1 + ceil(fdiv(20.0, (float) $h));
        return is_finite($r) ? (int) $r : $r;
    }

    /** The largest window of {@see proportionCutoff} (the tail is exact integer arithmetic over w * 61 bits). */
    public const PROPORTION_MAX_WINDOW = 65536;

    /**
     * 2^-h for h a multiple of 1/8 in [1/8, 64], by operations every platform computes identically: 0.5 multiplied floor(8h / 8) times (exact),
     * then by sqrt(0.5), sqrt(sqrt(0.5)), sqrt(sqrt(sqrt(0.5))) when bits 4, 2, 1 of (8h mod 8) are set, in that order (IEEE `*` and sqrt are
     * exactly rounded; pow is not).
     */
    private static function proportionP(int|float $h): float
    {
        $n = (float) $h * 8;
        if (!(is_finite($n) && floor($n) === $n && $n >= 1 && $n <= 512)) {
            throw new \RangeException('proportionCutoff: h must be a multiple of 1/8 in [1/8, 64]');
        }
        $ni = (int) $n;
        $p = 1.0;
        for ($i = 0, $whole = intdiv($ni, 8); $i < $whole; $i++) {
            $p *= 0.5;
        }
        $f = $ni % 8;
        $s1 = sqrt(0.5);
        $s2 = sqrt($s1);
        $s3 = sqrt($s2);
        if (($f & 4) !== 0) {
            $p *= $s1;
        }
        if (($f & 2) !== 0) {
            $p *= $s2;
        }
        if (($f & 1) !== 0) {
            $p *= $s3;
        }
        return $p;
    }

    /**
     * SP 800-90B 4.4.2 cutoff: 1 + CRITBINOM(W, p, 1 - 2^-20) with p = 2^-h: the smallest k with P[X <= k] >= 1 - 2^-20 for X ~ Bin(W, p)
     * (k = W at most), plus one. Computed EXACTLY: p (the double proportionP gives) is the dyadic rational m / 2^e, every binomial term is an
     * integer over 2^(e*W), and the comparison with 1 - 2^-20 is an integer comparison (ext-gmp): no pow, exp or log, so no platform's libm can
     * move the cutoff. Domain: h a multiple of 1/8 in [1/8, 64] and W an integer in [2, 65536]; anything else throws (never rounded).
     */
    public static function proportionCutoff(int|float $h, int|float $w): int
    {
        $wf = (float) $w;
        if (!(is_finite($wf) && floor($wf) === $wf && $wf >= 2 && $wf <= self::PROPORTION_MAX_WINDOW)) {
            throw new \RangeException('proportionCutoff: the window must be an integer in [2, 65536]');
        }
        $p = self::proportionP($h);
        $bits = unpack('J', pack('E', $p))[1];
        $m = gmp_init(($bits & ((1 << 52) - 1)) | (1 << 52));
        $e = 1075 - ($bits >> 52); // p = m / 2^e (p is a normal double in [2^-64, 1/2])
        $D = gmp_pow(2, $e);
        $q = gmp_sub($D, $m); // 1 - p = q / D
        $W = (int) $wf;
        $scale = gmp_pow($D, $W); // every term over D^W
        $target = gmp_mul(gmp_init((1 << 20) - 1), $scale); // cdf >= 1 - 2^-20  <=>  cdf_numerator * 2^20 >= (2^20 - 1) * D^W
        $term = gmp_pow($q, $W); // C(W,0) m^0 q^W
        $cdf = $term;
        $k = 0;
        while (gmp_cmp(gmp_mul($cdf, 1 << 20), $target) < 0 && $k < $W) {
            $term = gmp_div_q(gmp_mul(gmp_mul($term, $W - $k), $m), gmp_mul($q, $k + 1), GMP_ROUND_ZERO); // exact: the next term is an integer
            $k++;
            $cdf = gmp_add($cdf, $term);
        }
        return 1 + $k;
    }

    /**
     * Repetition-count test over the whole buffer, then the adaptive-proportion test window by window (only complete windows; the
     * sample is a window's first byte; the window shrinks to the buffer). Fails CLOSED on a bad parameter (h outside [1, 8], a window
     * that is not an integer >= 2) and on an empty buffer. `$h` defaults to 8 and `$window` to 512.
     * @return array{ok:bool,test?:string}
     */
    public static function healthTestBytes(string $bytes, mixed $h = null, mixed $window = null): array
    {
        $h ??= 8;
        $w0 = $window ?? 512;
        if (!(is_int($h) || is_float($h)) || !($h >= 1 && $h <= 8 && floor((float) $h * 8) === (float) $h * 8) || !self::isInteger($w0) || $w0 < 2) {
            return ['ok' => false, 'test' => 'repetition-count'];
        }
        $n = strlen($bytes);
        if ($n === 0) {
            return ['ok' => false, 'test' => 'repetition-count'];
        }
        $rc = self::repetitionCutoff($h);
        $run = 1;
        for ($i = 1; $i < $n; $i++) {
            $run = $bytes[$i] === $bytes[$i - 1] ? $run + 1 : 1;
            if ($run >= $rc) {
                return ['ok' => false, 'test' => 'repetition-count'];
            }
        }
        $w = (int) min((float) $w0, (float) $n, (float) self::PROPORTION_MAX_WINDOW);
        if ($w < 2) { // a window of one byte can never reach the cutoff (1 + CRITBINOM >= 2 for any p above 2^-20)
            return ['ok' => true];
        }
        $ac = self::proportionCutoff($h, $w);
        for ($start = 0; $start + $w <= $n; $start += $w) {
            if (substr_count($bytes, $bytes[$start], $start, $w) >= $ac) {
                return ['ok' => false, 'test' => 'adaptive-proportion'];
            }
        }
        return ['ok' => true];
    }

    // ---- body parsers ------------------------------------------------------------------------------

    /**
     * An ANU-style JSON body `{success?: true, data: [0..255, ...]}` to bytes. Accepts a parsed Obj, an assoc array or a stdClass;
     * a number with an integral value (1.0, 2e0, -0) is an integer, as in JavaScript.
     */
    public static function parseAnuUint8(mixed $body): string
    {
        if ($body instanceof \stdClass) {
            $body = (array) $body;
        }
        if (!($body instanceof Obj) && !is_array($body)) { // a JSON array is an object too: it fails below for its missing `data`
            throw new \RuntimeException('QRNG: response body is not a JSON object');
        }
        if (Js::has($body, 'success') && Js::opt($body, 'success') !== true) {
            throw new \RuntimeException('QRNG: response reports success=false');
        }
        $data = Js::opt($body, 'data');
        if (!is_array($data) || !array_is_list($data)) {
            throw new \RuntimeException('QRNG: response `data` is not an array');
        }
        $out = '';
        foreach ($data as $i => $v) {
            $f = Js::isNum($v) ? Js::num($v) : null;
            if ($f === null || !is_finite($f) || floor($f) !== $f || $f < 0 || $f > 255) {
                throw new \RuntimeException("QRNG: response data[$i] is not a 0..255 integer");
            }
            $out .= chr((int) $f);
        }
        return $out;
    }

    /** A non-string payload is read as its JS string form (null is "null", 12 is "12", true is "true"), like the reference does. */
    private static function jsText(mixed $v, string $what): string
    {
        return match (true) {
            is_string($v) => $v,
            $v === null => 'null',
            is_bool($v) => $v ? 'true' : 'false',
            $v instanceof Num => $v->lexeme,
            is_int($v) => (string) $v,
            default => throw new \RuntimeException("QRNG: malformed $what payload"),
        };
    }

    /** Hex text (either case, even length) to bytes. */
    public static function parseHex(mixed $text): string
    {
        // the reference tests the coerced value against the pattern but then reads `.length`, which a non-string lacks: it always refuses
        $text = is_string($text) ? $text : throw new \RuntimeException('QRNG: malformed hex payload');
        if (preg_match('/\A[0-9a-fA-F]*\z/', $text) !== 1 || strlen($text) % 2 !== 0) {
            throw new \RuntimeException('QRNG: malformed hex payload');
        }
        return (string) hex2bin($text);
    }

    /** Base64 text to bytes with the WHATWG forgiving-base64 decode (atob): padding optional, trailing bits dropped. */
    public static function parseBase64(mixed $text): string
    {
        $text = self::jsText($text, 'base64');
        if (preg_match('/\A[A-Za-z0-9+\/]*={0,2}\z/', $text) !== 1) {
            throw new \RuntimeException('QRNG: malformed base64 payload');
        }
        $s = $text;
        if (strlen($s) % 4 === 0) {
            $s = preg_replace('/={1,2}\z/', '', $s) ?? $s;
        }
        if (strlen($s) % 4 === 1 || str_contains($s, '=')) {
            throw new \RuntimeException('QRNG: malformed base64 payload');
        }
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        $out = '';
        $acc = 0;
        $bits = 0;
        for ($i = 0, $n = strlen($s); $i < $n; $i++) {
            $acc = ($acc << 6) | (int) strpos($alphabet, $s[$i]);
            $bits += 6;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($acc >> $bits) & 0xff);
                $acc &= (1 << $bits) - 1;
            }
        }
        return $out;
    }

    // ---- the combiner and secureSeed ---------------------------------------------------------------

    /**
     * Mix local CSPRNG bytes with quantum bytes: HKDF-SHA256 over u32be(len local) || u32be(len quantum) || local || quantum, a fixed
     * salt and the info label `atlas-pca/entropy/mix/v1[/context]` || u32be(length). `$length` defaults to the local length (1..8160);
     * `$local` must be at least 16 bytes, `$quantum` may be empty. A context is UTF-8 text (a lone surrogate counts as U+FFFD).
     */
    public static function mixEntropy(string $local, string $quantum, mixed $length = null, ?string $context = null): string
    {
        if (strlen($local) < self::MIN_LOCAL_BYTES) {
            throw new \RangeException('mixEntropy: local CSPRNG must be >= ' . self::MIN_LOCAL_BYTES . ' bytes (fail-closed)');
        }
        $len = $length ?? strlen($local);
        if (!self::isInteger($len) || $len <= 0 || $len > self::MAX_HKDF_OUTPUT) {
            throw new \RangeException('mixEntropy: length must be an integer in 1..' . self::MAX_HKDF_OUTPUT);
        }
        $len = (int) $len;
        $ikm = pack('NN', strlen($local), strlen($quantum)) . $local . $quantum;
        $label = self::MIX_LABEL;
        if ($context !== null && $context !== '') {
            $label .= '/' . preg_replace('/\xED[\xA0-\xBF][\x80-\xBF]/', "\xEF\xBF\xBD", $context);
        }
        return hash_hkdf('sha256', $ikm, $len, $label . pack('N', $len), self::MIX_SALT);
    }

    private static function draw(?callable $impl, int $n): string
    {
        $bytes = $impl !== null ? $impl($n) : random_bytes($n);
        if (!is_string($bytes) || strlen($bytes) !== $n) {
            throw new \RuntimeException('secureSeed: local CSPRNG did not return the requested bytes (fail-closed)');
        }
        return $bytes;
    }

    /**
     * A seed that is HKDF(local CSPRNG || quantum): CSPRNG bytes always, plus best-effort health-tested QRNG bytes. Options (keys):
     * length (32), source (QrngSource|null), quantumBytes, localBytes, context, requireQuantum (strict true: refuse with EntropyError
     * quantum_required when no quantum entropy was obtained), healthTest (array{h?,window?} or false to disable),
     * onQrngError (callable(\Throwable): void, its exceptions are swallowed), randomBytesImpl (callable(int): string, for tests).
     * A source that fails, answers a wrong size or fails the health test is dropped and the seed is the local CSPRNG alone.
     * shortcut: PHP strings cannot be wiped reliably, so the local bytes are not zeroised after use.
     * @param array<string,mixed> $opts
     */
    public static function secureSeed(array $opts = []): SecureSeedResult
    {
        $length = $opts['length'] ?? self::DEFAULT_SEED_BYTES;
        if (!self::isInteger($length) || $length <= 0 || $length > self::MAX_HKDF_OUTPUT) {
            throw new \RangeException('secureSeed: length must be an integer in 1..' . self::MAX_HKDF_OUTPUT);
        }
        $length = (int) $length;
        $localBytes = $opts['localBytes'] ?? max(self::DEFAULT_SEED_BYTES, $length);
        if (!self::isInteger($localBytes) || $localBytes < self::MIN_LOCAL_BYTES) {
            throw new \RangeException('secureSeed: localBytes must be an integer >= ' . self::MIN_LOCAL_BYTES);
        }
        $quantumBytes = $opts['quantumBytes'] ?? max(self::DEFAULT_SEED_BYTES, $length);
        if (!self::isInteger($quantumBytes) || $quantumBytes <= 0) {
            throw new \RangeException('secureSeed: quantumBytes must be a positive integer');
        }
        $quantumBytes = (int) $quantumBytes;
        $impl = $opts['randomBytesImpl'] ?? null;
        $local = self::draw(is_callable($impl) ? $impl : null, (int) $localBytes);

        $quantum = '';
        $used = false;
        $sourceName = null;
        $source = $opts['source'] ?? null;
        if ($source instanceof QrngSource) {
            $sourceName = $source->name();
            try {
                $q = $source->fetch($quantumBytes);
                if (!is_string($q) || strlen($q) !== $quantumBytes) {
                    throw new \RuntimeException('QRNG: source returned ' . (is_string($q) ? (string) strlen($q) : 'non-bytes') . ", expected $quantumBytes");
                }
                $ht = $opts['healthTest'] ?? [];
                if ($ht !== false) {
                    $v = self::healthTestBytes($q, Js::opt($ht, 'h'), Js::opt($ht, 'window'));
                    if (!$v['ok']) {
                        throw new EntropyError('health_test_failed', 'QRNG: ' . ($v['test'] ?? 'health') . ' test failed; source rejected');
                    }
                }
                $quantum = $q;
                $used = true;
            } catch (\Throwable $e) {
                $used = false;
                $quantum = '';
                $hook = $opts['onQrngError'] ?? null;
                if (is_callable($hook)) {
                    try {
                        $hook($e);
                    } catch (\Throwable) {
                        // observability must never break key generation
                    }
                }
            }
        }
        if (($opts['requireQuantum'] ?? null) === true && !$used) {
            throw new EntropyError('quantum_required', 'secureSeed: quantum entropy is required but was not obtained (fail-closed)');
        }
        $context = $opts['context'] ?? null;
        $seed = self::mixEntropy($local, $quantum, $length, is_string($context) ? $context : null);
        return new SecureSeedResult($seed, $used, $used ? strlen($quantum) : 0, $sourceName);
    }

    /**
     * An Ed25519 key pair whose 32-byte seed comes from {@see secureSeed} (length 32, context `ed25519-key` unless given). Takes the
     * secureSeed options except `length`.
     * @param array<string,mixed> $opts
     * @return array{secretKey:string,publicKey:string,usedQuantum:bool}
     */
    public static function generateKeyPairWithEntropy(array $opts = []): array
    {
        $opts['length'] = 32;
        $opts['context'] = $opts['context'] ?? 'ed25519-key';
        $r = self::secureSeed($opts);
        return [
            'secretKey' => $r->seed,
            'publicKey' => sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($r->seed)),
            'usedQuantum' => $r->usedQuantum,
        ];
    }

    /** A source whose fetch always fails with `QRNG unavailable: <reason>` (default reason `no QRNG source configured`). */
    public static function unavailableSource(?string $reason = null): QrngSource
    {
        return $reason === null ? new NullQrngSource() : new NullQrngSource($reason);
    }
}
