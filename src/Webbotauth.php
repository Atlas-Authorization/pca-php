<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Oidc.php';
require_once __DIR__ . '/WhatwgUrl.php';

/** A refusal while parsing a signature header: its message is part of the verification reason. */
final class WebbotauthParseError extends \RuntimeException
{
}

/**
 * In-process single-use store for accepted signatures. claim() is true when the key is claimed for the first time (until its
 * expiry); it fails CLOSED (throws) when `$maxEntries` unexpired claims are held.
 */
final class WebbotauthMemoryReplayCache
{
    /** @var array<string,float> */
    private array $seen = [];

    public function __construct(private readonly int $maxEntries = 100000)
    {
    }

    public function claim(string $key, float $expiresAtSec, float $nowSec): bool
    {
        if (!is_finite($nowSec) || !is_finite($expiresAtSec)) {
            return false; // a non-finite clock or expiry admits nothing
        }
        if (count($this->seen) >= $this->maxEntries) {
            $this->seen = array_filter($this->seen, static fn(float $e): bool => !($e < $nowSec));
            if (count($this->seen) >= $this->maxEntries) {
                throw new \RuntimeException('replay cache full');
            }
        }
        $existing = $this->seen[$key] ?? null;
        if ($existing !== null && !($existing < $nowSec)) {
            return false;
        }
        $this->seen[$key] = $expiresAtSec;
        return true;
    }
}

/**
 * Web Bot Auth for Proof-Carrying Authority: RFC 9421 HTTP Message Signatures over outbound agent requests in the "web-bot-auth"
 * profile, so a PCA agent passes automated-traffic bot verification AND carries its per-action proof in the SAME request; the signed
 * key directory, RFC 9530 Content-Digest and the PCA proof binding. The signature base is built byte for byte as the reference does.
 * verifySignedRequest FAILS CLOSED (a parse error, a stale window, a wrong tag, an unknown key or a bad signature returns
 * {valid:false, reason}); a valid signature proves the key holder signed THIS request's covered components inside the window, not
 * that the action is authorized (the PCActn verifier's job).
 *
 * Values are the parsed-JSON model (Obj, lists, string, Num / int / float, bool, null); input and option bags are an Obj or an assoc
 * array keyed by the reference's names. A signing key is an Obj / array with a base64url `secretKey` (the 32-byte seed) or a KeyPair.
 * Key bytes are raw binary strings. resolveKey is callable(string $keyid): raw 32 bytes | public JWK | null; replayCache is an object
 * with claim(string $key, float $expiresAtSec, float $nowSec): bool (or a callable of the same shape).
 *
 * shortcut: request URLs must be http(s) / ws(s) / ftp; other schemes are refused where the reference would accept them, and a
 * @target-uri covering a URL with credentials or a fragment is refused. A directory URL with credentials is refused. Upgrade if a
 * non-HTTP request target is ever signed.
 */
final class Webbotauth
{
    public const WEB_BOT_AUTH_TAG = 'web-bot-auth';
    public const WEB_BOT_AUTH_ALG = 'ed25519';
    public const WELL_KNOWN_DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
    public const DIRECTORY_CONTENT_TYPE = 'application/http-message-signatures-directory+json';
    public const DEFAULT_SIGNATURE_LABEL = 'sig1';
    public const DEFAULT_EXPIRES_SEC = 300;
    public const SIGNATURE_AGENT_HEADER = 'Signature-Agent';
    public const PCA_HEADER = 'PCA-Action';
    public const PCA_PROOF_COMPONENT = 'pca-action';
    public const CONTENT_DIGEST_HEADER = 'Content-Digest';
    public const CONTENT_DIGEST_ALGS = ['sha-256', 'sha-512'];
    public const DIRECTORY_SIGNATURE_TAG = 'http-message-signatures-directory';
    private const DEFAULT_DIRECTORY_LIFETIME_SEC = 86400.0;
    private const WS = '\t\n\x0B\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}';

    // ---- JS-model helpers ----

    /** String.prototype.trim. */
    private static function trim(string $s): string
    {
        $r = preg_replace('/\A[' . self::WS . ']+|[' . self::WS . ']+\z/u', '', $s);
        return $r ?? trim($s, " \t\n\x0B\f\r");
    }

    private static function lower(string $s): string
    {
        return mb_check_encoding($s, 'UTF-8') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
    }

    private static function num(mixed $v): float
    {
        return Js::num($v) ?? NAN;
    }

    /** `x ?? default` for a numeric option. */
    private static function numOr(mixed $o, string $k, float $default): float
    {
        $v = Js::opt($o, $k);
        return $v === null ? $default : self::num($v);
    }

    /** String(n) of a number. */
    private static function numStr(float $d): string
    {
        return Js::str($d);
    }

    private static function sfString(mixed $s): string
    {
        if (!is_string($s)) {
            throw new \TypeError('value is not a string');
        }
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $s) . '"';
    }

    private static function now(): float
    {
        return (float)time();
    }

    /** Buffer.from(s, 'base64'): both alphabets, other characters skipped, decoding stops at the first '=', dangling bits dropped. */
    private static function nodeBase64(string $s): string
    {
        $out = '';
        $acc = 0;
        $bits = 0;
        foreach (str_split($s) as $c) {
            if ($c === '=') {
                break;
            }
            $o = ord($c);
            $v = $o >= 65 && $o <= 90 ? $o - 65 : ($o >= 97 && $o <= 122 ? $o - 71 : ($o >= 48 && $o <= 57 ? $o + 4 : ($c === '+' || $c === '-' ? 62 : ($c === '/' || $c === '_' ? 63 : -1))));
            if ($v < 0) {
                continue;
            }
            $acc = ($acc << 6) | $v;
            $bits += 6;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($acc >> $bits) & 0xff);
                $acc &= (1 << $bits) - 1;
            }
        }
        return $out;
    }

    /** An Ed25519 signing identity: the signer callable(string $msg): raw signature and the raw public key. @return array{0:callable,1:string} */
    private static function signer(mixed $k): array
    {
        if ($k instanceof KeyPair) {
            return [$k->sign(...), (string)Pca::unb64u($k->public, 32)];
        }
        $sk = Js::opt($k, 'secretKey');
        $seed = is_string($sk) ? Pca::unb64u($sk) : null;
        if ($seed === null || strlen($seed) !== 32) {
            throw new \InvalidArgumentException('key must carry a secretKey');
        }
        $kp = sodium_crypto_sign_seed_keypair($seed);
        $secret = sodium_crypto_sign_secretkey($kp);
        return [static fn(string $m): string => sodium_crypto_sign_detached($m, $secret), sodium_crypto_sign_publickey($kp)];
    }

    /** RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK). */
    public static function jwkThumbprint(string $publicKey): string
    {
        return self::thumbprintOfX(Pca::b64u($publicKey));
    }

    private static function thumbprintOfX(string $x): string
    {
        return Pca::b64u(hash('sha256', '{"crv":"Ed25519","kty":"OKP","x":"' . $x . '"}', true));
    }

    // ---- structured-field helpers (the delimiters are ASCII, so byte offsets are exact) ----

    /** @return list<string> */
    private static function splitTopLevel(string $s, string $sep): array
    {
        $out = [];
        $depth = 0;
        $start = 0;
        $inStr = false;
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $c = $s[$i];
            if ($inStr) {
                if ($c === '\\') {
                    $i++;
                } elseif ($c === '"') {
                    $inStr = false;
                }
                continue;
            }
            if ($c === '"') {
                $inStr = true;
            } elseif ($c === '(') {
                $depth++;
            } elseif ($c === ')') {
                $depth = max(0, $depth - 1);
            } elseif ($c === $sep && $depth === 0) {
                $out[] = substr($s, $start, $i - $start);
                $start = $i + 1;
            }
        }
        $out[] = substr($s, min($start, $n));
        return $out;
    }

    private static function indexOfTopLevel(string $s, string $ch): int
    {
        $depth = 0;
        $inStr = false;
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $c = $s[$i];
            if ($inStr) {
                if ($c === '\\') {
                    $i++;
                } elseif ($c === '"') {
                    $inStr = false;
                }
                continue;
            }
            if ($c === '"') {
                $inStr = true;
            } elseif ($c === '(') {
                $depth++;
            } elseif ($c === ')') {
                $depth = max(0, $depth - 1);
            } elseif ($c === $ch && $depth === 0) {
                return $i;
            }
        }
        return -1;
    }

    private static function matchingParen(string $s, int $open): int
    {
        if ($open >= strlen($s) || $s[$open] !== '(') {
            return -1;
        }
        $depth = 0;
        $inStr = false;
        $n = strlen($s);
        for ($i = $open; $i < $n; $i++) {
            $c = $s[$i];
            if ($inStr) {
                if ($c === '\\') {
                    $i++;
                } elseif ($c === '"') {
                    $inStr = false;
                }
                continue;
            }
            if ($c === '"') {
                $inStr = true;
            } elseif ($c === '(') {
                $depth++;
            } elseif ($c === ')') {
                $depth--;
                if ($depth === 0) {
                    return $i;
                }
            }
        }
        return -1;
    }

    /** @return array{0:string,1:int} the string value and the offset after the closing quote */
    private static function readSfString(string $s, int $i): array
    {
        if ($i >= strlen($s) || $s[$i] !== '"') {
            throw new WebbotauthParseError('expected a quoted string');
        }
        $out = '';
        $n = strlen($s);
        for ($j = $i + 1; $j < $n; $j++) {
            $c = $s[$j];
            if ($c === '\\') {
                if ($j + 1 >= $n || ($s[$j + 1] !== '"' && $s[$j + 1] !== '\\')) {
                    throw new WebbotauthParseError('invalid escape in string');
                }
                $out .= $s[$j + 1];
                $j++;
            } elseif ($c === '"') {
                return [$out, $j + 1];
            } else {
                $out .= $c;
            }
        }
        throw new WebbotauthParseError('unterminated string');
    }

    private static function parseParamValue(string $raw): string|bool|float
    {
        $s = self::trim($raw);
        if ($s === '') {
            return true;
        }
        if ($s[0] === '"') {
            [$v, $next] = self::readSfString($s, 0);
            if ($next !== strlen($s)) {
                throw new WebbotauthParseError('trailing characters after string parameter');
            }
            return $v;
        }
        if ($s === '?1') {
            return true;
        }
        if ($s === '?0') {
            return false;
        }
        if (preg_match('/\A-?\d+(?:\.\d+)?\z/', $s) === 1) {
            return (float)$s;
        }
        return $s;
    }

    /** @return array<string,string|bool|float> */
    private static function parseParams(string $paramStr): array
    {
        $params = [];
        $t = self::trim($paramStr);
        if ($t === '') {
            return $params;
        }
        if ($t[0] !== ';') {
            throw new WebbotauthParseError('expected parameters to start with ";"');
        }
        foreach (self::splitTopLevel(substr($t, 1), ';') as $part) {
            $seg = self::trim($part);
            if ($seg === '') {
                continue;
            }
            $eq = self::indexOfTopLevel($seg, '=');
            if ($eq === -1) {
                $params[$seg] = true;
            } else {
                $params[self::trim(substr($seg, 0, $eq))] = self::parseParamValue(substr($seg, $eq + 1));
            }
        }
        return $params;
    }

    /** @return list<array{label:string,components:list<array{id:string,raw:string,key:?string}>,paramsRaw:string,params:array<string,mixed>}> */
    private static function parseSignatureInput(string $value): array
    {
        $entries = [];
        foreach (self::splitTopLevel($value, ',') as $memberRaw) {
            $member = self::trim($memberRaw);
            if ($member === '') {
                continue;
            }
            $eq = self::indexOfTopLevel($member, '=');
            if ($eq === -1) {
                throw new WebbotauthParseError('malformed Signature-Input member');
            }
            $label = self::trim(substr($member, 0, $eq));
            $paramsRaw = self::trim(substr($member, $eq + 1));
            if ($paramsRaw === '' || $paramsRaw[0] !== '(') {
                throw new WebbotauthParseError('Signature-Input value must be an inner list');
            }
            $close = self::matchingParen($paramsRaw, 0);
            if ($close === -1) {
                throw new WebbotauthParseError('unterminated inner list');
            }
            $components = [];
            foreach (self::splitTopLevel(substr($paramsRaw, 1, $close - 1), ' ') as $chunkRaw) {
                $chunk = self::trim($chunkRaw);
                if ($chunk === '') {
                    continue;
                }
                [$name, $next] = self::readSfString($chunk, 0);
                $lowered = self::lower($name);
                $rest = self::trim(substr($chunk, $next));
                if ($rest === '') {
                    $components[] = ['id' => $lowered, 'raw' => '"' . $lowered . '"', 'key' => null];
                    continue;
                }
                // the only component parameter supported is `key` (dictionary member), on header components
                if (preg_match('/\A;key=("(?:[^"\\\\]|\\\\[^\n\r\x{2028}\x{2029}])*")\z/u', $rest, $m) !== 1 || str_starts_with($lowered, '@')) {
                    throw new WebbotauthParseError("unsupported component parameters on \"$name\"");
                }
                $key = self::readSfString($m[1], 0)[0];
                $components[] = ['id' => $lowered, 'raw' => '"' . $lowered . '";key=' . self::sfString($key), 'key' => $key];
            }
            $entries[] = ['label' => $label, 'components' => $components, 'paramsRaw' => $paramsRaw, 'params' => self::parseParams(substr($paramsRaw, $close + 1))];
        }
        return $entries;
    }

    /** @return array<string,string> label => raw signature bytes */
    private static function parseSignature(string $value): array
    {
        $out = [];
        foreach (self::splitTopLevel($value, ',') as $memberRaw) {
            $member = self::trim($memberRaw);
            if ($member === '') {
                continue;
            }
            $eq = self::indexOfTopLevel($member, '=');
            if ($eq === -1) {
                throw new WebbotauthParseError('malformed Signature member');
            }
            $label = self::trim(substr($member, 0, $eq));
            $v = self::trim(substr($member, $eq + 1));
            if (strlen($v) < 2 || $v[0] !== ':' || $v[strlen($v) - 1] !== ':') {
                throw new WebbotauthParseError('Signature value must be a byte sequence (:base64:)');
            }
            $out[$label] = self::nodeBase64(substr($v, 1, -1));
        }
        return $out;
    }

    // ---- signature base (RFC 9421 section 2.5) ----

    /** @return array<string,string> lower-cased name => value (list values trimmed and joined; repeats joined) */
    private static function normalizeHeaders(mixed $h): array
    {
        $m = [];
        if (!Js::isObj($h)) {
            return $m;
        }
        $o = $h instanceof Obj ? $h : Obj::of($h);
        foreach (Js::ownKeys($o->keys()) as $k) {
            $v = $o->get($k);
            if (self::isList($v)) {
                $parts = [];
                foreach ($v as $x) {
                    if (!is_string($x)) {
                        throw new \TypeError('x.trim is not a function');
                    }
                    $parts[] = self::trim($x);
                }
                $value = implode(', ', $parts);
            } elseif (is_string($v)) {
                $value = self::trim($v);
            } else {
                throw new \TypeError('v.trim is not a function');
            }
            $name = self::lower($k);
            $m[$name] = array_key_exists($name, $m) ? $m[$name] . ', ' . $value : $value;
        }
        return $m;
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    /** @return array<string,mixed> */
    private static function buildContext(mixed $method, mixed $url, array $headers): array
    {
        $u = is_string($url) ? WhatwgUrl::parse($url) : null;
        if ($u === null) {
            throw new NodeArgError('Invalid URL', 'ERR_INVALID_URL');
        }
        if (!in_array($u['scheme'], ['http', 'https', 'ws', 'wss', 'ftp'], true)) {
            throw new \InvalidArgumentException('unsupported URL scheme');
        }
        if (!is_string($method)) {
            throw new \TypeError('method.toUpperCase is not a function');
        }
        $hostport = $u['host'];
        $hash = strpos($url, '#');
        $noFrag = $hash === false ? $url : substr($url, 0, $hash);
        $slashes = strpos($noFrag, '//');
        $authEnd = strlen($noFrag);
        if ($slashes !== false) {
            for ($k = $slashes + 2; $k < strlen($noFrag); $k++) {
                if ($noFrag[$k] === '/' || $noFrag[$k] === '\\' || $noFrag[$k] === '?') {
                    $authEnd = $k;
                    break;
                }
            }
        }
        $plain = $hash === false && !($slashes !== false && str_contains(substr($noFrag, $slashes + 2, $authEnd - $slashes - 2), '@'));
        $search = $u['search'];
        $path = $u['pathname'] === '' ? '/' : $u['pathname'];
        return [
            'method' => mb_check_encoding($method, 'UTF-8') ? mb_strtoupper($method, 'UTF-8') : strtoupper($method),
            'authority' => self::lower($hostport),
            'path' => $path,
            'targetUri' => $plain ? $u['scheme'] . '://' . $hostport . $u['pathname'] . $search . ($search === '' && str_contains($noFrag, '?') ? '?' : '') : null,
            'scheme' => $u['scheme'],
            'query' => $search === '' ? '?' : $search,
            'requestTarget' => $path . $search,
            'headers' => $headers,
        ];
    }

    private static function deriveComponentValue(array $component, array $ctx): string
    {
        $id = $component['id'];
        switch ($id) {
            case '@method':
                return $ctx['method'];
            case '@authority':
                return $ctx['authority'];
            case '@path':
                return $ctx['path'];
            case '@target-uri':
                return $ctx['targetUri'] ?? throw new WebbotauthParseError('@target-uri is not supported for a URL with credentials or a fragment');
            case '@scheme':
                return $ctx['scheme'];
            case '@query':
                return $ctx['query'];
            case '@request-target':
                return $ctx['requestTarget'];
        }
        if (str_starts_with($id, '@')) {
            throw new WebbotauthParseError("unsupported derived component \"$id\"");
        }
        $v = $ctx['headers'][$id] ?? null;
        if ($v === null) {
            throw new WebbotauthParseError("covered header \"$id\" is absent from the request");
        }
        return $component['key'] !== null ? self::dictionaryMember($v, $component['key'], $id) : $v;
    }

    /** RFC 9421 section 2.1.2: the serialized value of dictionary member `$key` of a Structured Field dictionary header (string members only). */
    private static function dictionaryMember(string $header, string $key, string $headerName): string
    {
        foreach (self::splitTopLevel($header, ',') as $memberRaw) {
            $member = self::trim($memberRaw);
            $eq = self::indexOfTopLevel($member, '=');
            if ($eq === -1 || self::trim(substr($member, 0, $eq)) !== $key) {
                continue;
            }
            $value = self::trim(substr($member, $eq + 1));
            [, $next] = self::readSfString($value, 0);
            // parameters are allowed only in compact canonical form, so the verbatim text IS the serialization
            if (preg_match('/\A(?:;[a-z*][a-z0-9_.*-]*(?:=(?:"(?:[^"\\\\]|\\\\[^\n\r\x{2028}\x{2029}])*"|[A-Za-z0-9_.:\/*+%-]+))?)*\z/u', substr($value, $next)) !== 1) {
                throw new WebbotauthParseError("member \"$key\" of \"$headerName\" is not in canonical form");
            }
            return $value;
        }
        throw new WebbotauthParseError("\"$headerName\" has no dictionary member \"$key\"");
    }

    private static function buildSignatureBase(array $components, string $paramsRaw, array $ctx): string
    {
        $lines = [];
        foreach ($components as $c) {
            $lines[] = $c['raw'] . ': ' . self::deriveComponentValue($c, $ctx);
        }
        $lines[] = '"@signature-params": ' . $paramsRaw;
        return implode("\n", $lines);
    }

    private static function component(string $id, ?string $key = null): array
    {
        return ['id' => $id, 'raw' => $key === null ? "\"$id\"" : "\"$id\";key=" . self::sfString($key), 'key' => $key];
    }

    // ---- signRequest ----

    /**
     * Build the Signature-Input and Signature header values over the RFC 9421 signature base. `$input`: method, url, headers, key,
     * keyid, created (epoch seconds, default now), expiresInSec (300), agentDirectoryUrl (also emits and covers Signature-Agent),
     * agentDirectoryKey (dictionary form, needs agentDirectoryUrl), components (derived components replacing the default
     * `@authority @method @path`, plus `@query` for a URL with a query; `@authority` required), coverHeaders, nonce, label.
     * @return array{signatureInput:string,signature:string,signatureAgent?:string,covered:list<string>,headers:Obj}
     */
    public static function signRequest(mixed $input): array
    {
        $label = Js::opt($input, 'label') !== null ? Js::str(Js::opt($input, 'label')) : self::DEFAULT_SIGNATURE_LABEL;
        $created = Js::opt($input, 'created') !== null ? self::num(Js::opt($input, 'created')) : self::now();
        $expires = $created + self::numOr($input, 'expiresInSec', (float)self::DEFAULT_EXPIRES_SEC);

        $working = self::normalizeHeaders(Js::opt($input, 'headers'));
        $emitted = new Obj();
        $url = Js::opt($input, 'url');
        if (!is_string($url)) {
            throw new NodeTypeError('url must be a string', 'ERR_INVALID_URL');
        }

        $derived = [];
        $given = Js::opt($input, 'components');
        if ($given !== null) {
            if (!self::isList($given)) {
                throw new \TypeError('components is not iterable');
            }
            $derived = $given;
        } else {
            $derived = ['@authority', '@method', '@path'];
            if (preg_match('/\?[^#]/', $url) === 1) { // a URL with a query string also covers @query (the verifier requires it)
                $derived[] = '@query';
            }
        }
        if (!in_array('@authority', $derived, true)) {
            throw new \InvalidArgumentException('signRequest: the web-bot-auth profile requires @authority to be covered');
        }
        $components = [];
        foreach ($derived as $id) {
            $lower = self::lower(is_string($id) ? $id : throw new \TypeError('component is not a string'));
            if (!str_starts_with($lower, '@')) {
                throw new \InvalidArgumentException("signRequest: components must be derived components, got \"$id\" (use coverHeaders for headers)");
            }
            $components[] = self::component($lower);
        }

        $signatureAgent = null;
        if (Js::has($input, 'agentDirectoryUrl') && Js::opt($input, 'agentDirectoryUrl') !== null) {
            $hasKey = Js::has($input, 'agentDirectoryKey');
            $akey = Js::opt($input, 'agentDirectoryKey');
            if ($hasKey && !is_string($akey)) {
                throw new \InvalidArgumentException('signRequest: agentDirectoryKey must be a string');
            }
            $agentUrl = self::sfString(Js::opt($input, 'agentDirectoryUrl'));
            $signatureAgent = !$hasKey ? $agentUrl : $akey . '=' . $agentUrl;
            $working['signature-agent'] = $signatureAgent;
            $emitted->set(self::SIGNATURE_AGENT_HEADER, $signatureAgent);
            $components[] = !$hasKey ? self::component('signature-agent') : self::component('signature-agent', $akey);
        } elseif (Js::has($input, 'agentDirectoryUrl')) {
            throw new \TypeError('agentDirectoryUrl is not a string'); // an explicit null / undefined-like value
        } elseif (Js::has($input, 'agentDirectoryKey')) {
            throw new \InvalidArgumentException('signRequest: agentDirectoryKey requires agentDirectoryUrl');
        }

        $cover = Js::opt($input, 'coverHeaders');
        if ($cover !== null) {
            foreach (Js::spread($cover) as $name) {
                if (!is_string($name)) {
                    throw new \TypeError('header name is not a string');
                }
                $lower = self::lower($name);
                if (!array_key_exists($lower, $working)) {
                    throw new \InvalidArgumentException("signRequest: covered header \"$name\" is not present in headers");
                }
                if (!in_array($lower, array_column($components, 'id'), true)) {
                    $components[] = self::component($lower);
                }
            }
        }

        $ctx = self::buildContext(Js::opt($input, 'method'), $url, $working);

        // the parameter order follows the draft's examples: created, keyid, alg, expires, nonce, tag
        $paramsRaw = '(' . implode(' ', array_column($components, 'raw')) . ');created=' . self::numStr($created) . ';keyid=' . self::sfString(Js::opt($input, 'keyid'))
            . ';alg=' . self::sfString(self::WEB_BOT_AUTH_ALG) . ';expires=' . self::numStr($expires);
        if (Js::has($input, 'nonce')) {
            $paramsRaw .= ';nonce=' . self::sfString(Js::opt($input, 'nonce'));
        }
        $paramsRaw .= ';tag=' . self::sfString(self::WEB_BOT_AUTH_TAG);

        $base = self::buildSignatureBase($components, $paramsRaw, $ctx);
        [$sign] = self::signer(Js::opt($input, 'key'));
        $sig = $sign($base);

        $signatureInput = $label . '=' . $paramsRaw;
        $signature = $label . '=:' . base64_encode($sig) . ':';
        $emitted->set('Signature-Input', $signatureInput);
        $emitted->set('Signature', $signature);
        $out = ['signatureInput' => $signatureInput, 'signature' => $signature];
        if ($signatureAgent !== null) {
            $out['signatureAgent'] = $signatureAgent;
        }
        return $out + ['covered' => array_column($components, 'id'), 'headers' => $emitted];
    }

    // ---- verifySignedRequest ----

    /** @return ?string the base64url x of a resolved key (32 raw bytes or an Ed25519 OKP JWK), else null */
    private static function xFromResolved(mixed $k): ?string
    {
        if ($k === null) {
            return null;
        }
        if (is_string($k)) {
            return strlen($k) === 32 ? Pca::b64u($k) : null;
        }
        if (Js::isObj($k) && is_string(Js::opt($k, 'x')) && Js::opt($k, 'crv') === 'Ed25519' && Js::opt($k, 'kty') === 'OKP') {
            return Js::opt($k, 'x');
        }
        return null;
    }

    private static function resolvePublicKeyX(string $keyid, mixed $opts, float $now, float $skew): ?string
    {
        $resolve = Js::opt($opts, 'resolveKey');
        if (Js::truthy($resolve)) {
            return self::xFromResolved($resolve($keyid));
        }
        $jwks = Js::opt($opts, 'jwks');
        if (Js::truthy($jwks)) {
            $keys = Js::opt($jwks, 'keys');
            if (!self::isList($keys)) {
                throw new \TypeError('opts.jwks.keys.find is not a function');
            }
            $match = null;
            foreach ($keys as $j) {
                if (Js::opt($j, 'kid') === $keyid && is_string($keyid)) {
                    $match = $j;
                    break;
                }
            }
            if ($match === null) {
                return null;
            }
            // a published validity window is enforced; a bound that is present but not a finite number cannot be checked
            foreach (['nbf', 'exp'] as $b) {
                if (Js::has($match, $b)) {
                    $d = Js::num(Js::opt($match, $b));
                    if ($d === null || !is_finite($d)) {
                        return null;
                    }
                }
            }
            if (Js::has($match, 'nbf') && !(is_finite($now) && is_finite($skew) && $now + $skew >= self::num(Js::opt($match, 'nbf')))) {
                return null;
            }
            if (Js::has($match, 'exp') && !(is_finite($now) && is_finite($skew) && $now - $skew <= self::num(Js::opt($match, 'exp')))) {
                return null;
            }
            return self::xFromResolved($match);
        }
        return null;
    }

    /** @return array{valid:bool,reason:string} */
    private static function invalid(string $reason): array
    {
        return ['valid' => false, 'reason' => $reason];
    }

    /**
     * Verify the HTTP Message Signature of `$req` ({method, url, headers}). Options: resolveKey (callable, takes precedence) or jwks
     * (a key directory), now (epoch seconds), clockSkewSec (0), maxAgeSec, requireExpires (default true), requiredTag (default
     * web-bot-auth; null = not enforced), label, requiredComponents (default `@authority @method @path`, plus `@query` for a URL with
     * a query), maxLifetimeSec (300; INF disables), replayCache. Never throws.
     * @return array<string,mixed> {valid, reason?, label?, keyid?, covered?, created?, expires?, tag?, nonce?}
     */
    public static function verifySignedRequest(mixed $req, mixed $opts): array
    {
        try {
            if (!Js::truthy(Js::opt($opts, 'resolveKey')) && !Js::truthy(Js::opt($opts, 'jwks'))) {
                return self::invalid('verifySignedRequest: provide resolveKey or jwks');
            }
            $headers = self::normalizeHeaders(Js::opt($req, 'headers'));
            $sigInputHeader = $headers['signature-input'] ?? null;
            $sigHeader = $headers['signature'] ?? null;
            if ($sigInputHeader === null || $sigHeader === null) {
                return self::invalid('missing Signature-Input or Signature header');
            }
            $inputs = self::parseSignatureInput($sigInputHeader);
            $sigs = self::parseSignature($sigHeader);
            $requiredTag = Js::has($opts, 'requiredTag') ? Js::opt($opts, 'requiredTag') : self::WEB_BOT_AUTH_TAG;

            $chosen = null;
            if (Js::has($opts, 'label')) {
                foreach ($inputs as $e) {
                    if ($e['label'] === Js::opt($opts, 'label')) {
                        $chosen = $e;
                        break;
                    }
                }
            } elseif ($requiredTag !== null) {
                foreach ($inputs as $e) {
                    if (($e['params']['tag'] ?? null) === $requiredTag) {
                        $chosen = $e;
                        break;
                    }
                }
                $chosen ??= $inputs[0] ?? null;
            } else {
                $chosen = $inputs[0] ?? null;
            }
            if ($chosen === null) {
                return self::invalid('no matching signature in Signature-Input');
            }
            $sigBytes = $sigs[$chosen['label']] ?? null;
            if ($sigBytes === null) {
                return self::invalid('no Signature entry for label "' . $chosen['label'] . '"');
            }
            $tag = is_string($chosen['params']['tag'] ?? null) ? $chosen['params']['tag'] : null;
            if ($requiredTag !== null && $tag !== $requiredTag) {
                return self::invalid('tag "' . ($tag ?? 'undefined') . '" does not match required "' . Js::str($requiredTag) . '"');
            }

            // @authority is required by the profile; @method and @path too, so a signature for one request cannot be replayed on
            // another method or path of the same host
            $covered = array_column($chosen['components'], 'id');
            $rc = Js::opt($opts, 'requiredComponents');
            $required = $rc !== null ? (self::isList($rc) ? $rc : throw new \TypeError('requiredComponents is not iterable')) : ['@authority', '@method', '@path'];
            foreach ($required as $id) {
                if (!in_array($id, $covered, true)) {
                    return self::invalid(Js::str($id) . ' is not a covered component');
                }
            }
            if (!Js::has($opts, 'requiredComponents')) {
                $url = Js::opt($req, 'url');
                if (!is_string($url)) {
                    throw new \TypeError("Cannot read properties of undefined (reading 'indexOf')");
                }
                $q = strpos($url, '?');
                if ($q !== false && explode('#', substr($url, $q + 1))[0] !== '' && !in_array('@query', $covered, true)) {
                    return self::invalid('@query is not a covered component');
                }
            }

            $alg = $chosen['params']['alg'] ?? null;
            if ($alg !== null && $alg !== self::WEB_BOT_AUTH_ALG) {
                return self::invalid('unsupported alg "' . (is_float($alg) ? self::numStr($alg) : (is_bool($alg) ? ($alg ? 'true' : 'false') : $alg)) . '"');
            }

            // freshness
            $now = self::numOr($opts, 'now', self::now());
            $skew = self::numOr($opts, 'clockSkewSec', 0.0);
            $created = is_float($chosen['params']['created'] ?? null) ? $chosen['params']['created'] : null;
            $expires = is_float($chosen['params']['expires'] ?? null) ? $chosen['params']['expires'] : null;
            if ($expires === null && Js::opt($opts, 'requireExpires') !== false) {
                return self::invalid('missing expires parameter');
            }
            if ($expires !== null && !(is_finite($now) && is_finite($skew) && $now <= $expires + $skew)) {
                return self::invalid('signature has expired');
            }
            if ($created !== null && !(is_finite($now) && is_finite($skew) && $created <= $now + $skew)) {
                return self::invalid('signature created-time is in the future');
            }
            if (Js::opt($opts, 'maxAgeSec') !== null && $created !== null && !(is_finite($now) && is_finite($skew) && $now - $created <= self::num(Js::opt($opts, 'maxAgeSec')) + $skew)) {
                return self::invalid('signature is older than maxAgeSec');
            }
            $maxLifetime = self::numOr($opts, 'maxLifetimeSec', 300.0);
            $finite = is_finite($maxLifetime);
            if ($finite) {
                if ($created === null) {
                    return self::invalid('missing created parameter (needed to bound the signature lifetime)');
                }
                if ($expires !== null && $expires - $created > $maxLifetime) {
                    return self::invalid('signature lifetime exceeds maxLifetimeSec');
                }
            }

            $keyid = is_string($chosen['params']['keyid'] ?? null) ? $chosen['params']['keyid'] : null;
            if ($keyid === null) {
                return self::invalid('missing keyid parameter');
            }
            $x = self::resolvePublicKeyX($keyid, $opts, $now, $skew);
            if ($x === null) {
                return self::invalid("could not resolve key \"$keyid\"");
            }

            $ctx = self::buildContext(Js::opt($req, 'method'), Js::opt($req, 'url'), $headers);
            $base = self::buildSignatureBase($chosen['components'], $chosen['paramsRaw'], $ctx);
            if (strlen($sigBytes) !== 64 || !Pca::verifyEd25519B64u($x, $base, Pca::b64u($sigBytes))) {
                return self::invalid('signature does not verify under the resolved key');
            }

            $nonce = is_string($chosen['params']['nonce'] ?? null) ? $chosen['params']['nonce'] : null;
            $cache = Js::opt($opts, 'replayCache');
            if (Js::truthy($cache)) {
                $until = $expires ?? ($created !== null ? $created + ($finite ? $maxLifetime : 3600.0) : $now + 3600.0);
                $key = $keyid . '|' . ($nonce ?? Pca::b64u($sigBytes));
                $ok = is_object($cache) && method_exists($cache, 'claim') ? $cache->claim($key, $until + $skew, $now) : $cache($key, $until + $skew, $now);
                if (!$ok) {
                    return self::invalid('replayed signature');
                }
            }
            $out = ['valid' => true, 'label' => $chosen['label'], 'keyid' => $keyid, 'covered' => $covered];
            if ($created !== null) {
                $out['created'] = $created;
            }
            if ($expires !== null) {
                $out['expires'] = $expires;
            }
            if ($tag !== null) {
                $out['tag'] = $tag;
            }
            if ($nonce !== null) {
                $out['nonce'] = $nonce;
            }
            return $out;
        } catch (\Throwable $e) {
            return self::invalid('verification failed (fail closed): ' . $e->getMessage());
        }
    }

    /** A new in-process replay cache holding at most `$maxEntries` unexpired claims. */
    public static function memoryReplayCache(int $maxEntries = 100000): WebbotauthMemoryReplayCache
    {
        return new WebbotauthMemoryReplayCache($maxEntries);
    }

    // ---- key directory (JWKS) + handler ----

    /**
     * The JWKS for a list of {publicKey (raw 32 bytes), keyid, use, nbf, exp}: {keys: [{kty, crv, x, kid, use?, nbf?, exp?}]}; the kid
     * defaults to the RFC 7638 thumbprint.
     */
    public static function buildKeyDirectory(array $keys): Obj
    {
        $list = [];
        foreach ($keys as $k) {
            $pk = Js::opt($k, 'publicKey');
            if (!is_string($pk)) {
                throw new \InvalidArgumentException('publicKey must be bytes');
            }
            $e = new Obj();
            $e->set('kty', 'OKP');
            $e->set('crv', 'Ed25519');
            $e->set('x', Pca::b64u($pk));
            $e->set('kid', Js::opt($k, 'keyid') ?? self::jwkThumbprint($pk));
            foreach (['use', 'nbf', 'exp'] as $f) {
                if (Js::has($k, $f)) {
                    $e->set($f, Js::opt($k, $f));
                }
            }
            $list[] = $e;
        }
        return Obj::of(['keys' => $list]);
    }

    /** The public key JWK of a directory with this `kid`, or null. */
    public static function resolveFromDirectory(mixed $directory, mixed $keyid): mixed
    {
        $keys = Js::get($directory, 'keys');
        if (!self::isList($keys)) {
            throw new \TypeError('directory.keys.find is not a function');
        }
        foreach ($keys as $j) {
            if (Js::get($j, 'kid') === $keyid && $keyid !== null) {
                return $j;
            }
        }
        return null;
    }

    /**
     * A framework-agnostic handler for the well-known directory path: callable(string $pathname) returning {status, headers, body}
     * (200 JSON) when the path (before any `?`) is the well-known one, else null so a caller can fall through.
     */
    public static function directoryHandler(array $keys): \Closure
    {
        $body = Js::stringify(self::buildKeyDirectory($keys));
        return static function (string $pathname) use ($body): ?array {
            $q = strpos($pathname, '?');
            if (($q === false ? $pathname : substr($pathname, 0, $q)) !== self::WELL_KNOWN_DIRECTORY_PATH) {
                return null;
            }
            return ['status' => 200, 'headers' => Obj::of(['content-type' => self::DIRECTORY_CONTENT_TYPE, 'cache-control' => 'max-age=86400']), 'body' => $body];
        };
    }

    // ---- PCA proof binding ----

    /** The PCA-Action header carrying a PCActn (base64url of its canonical wire form). @return array<string,string> */
    public static function proofHeaders(mixed $pcactn): array
    {
        return [self::PCA_HEADER => Pca::b64u(Json::canonicalizeNative($pcactn))];
    }

    /** Reverse proofHeaders: the PCA-Action header value to the PCActn. Throws unless it is the strict encoding of an object within the size limit. */
    public static function decodeProofHeader(mixed $value): Obj
    {
        $text = Pca::decodePcaHeader($value);
        if ($text === null) {
            throw new NodeArgError('PCA-Action is not strict unpadded base64url of UTF-8 text', 'invalid_pca_header');
        }
        if (strlen($text) > Pca::MAX_ARTIFACT_BYTES) {
            throw new \RangeException(Pca::ARTIFACT_SIZE_REASON);
        }
        $v = Json::parseStrict($text);
        if (!($v instanceof Obj)) {
            throw new \TypeError('decodePCActn: not an object');
        }
        return $v;
    }

    /**
     * Sign a request AND bind it to a PCActn: the PCActn goes in the canonical PCA-Action header and that header is a covered
     * component. `$input` is the signRequest input plus `pcactn`; the result has the proof header merged into `headers`, plus `proofHeader`.
     */
    public static function signRequestWithProof(mixed $input): array
    {
        if (!Js::has($input, 'pcactn')) {
            throw new \InvalidArgumentException('signRequestWithProof: pcactn is required');
        }
        $proof = self::proofHeaders(Js::opt($input, 'pcactn'));
        $headers = new Obj();
        $h = Js::opt($input, 'headers');
        if (Js::isObj($h)) {
            $ho = $h instanceof Obj ? $h : Obj::of($h);
            foreach ($ho->keys() as $k) {
                $headers->set($k, $ho->get($k));
            }
        }
        foreach ($proof as $k => $v) {
            $headers->set($k, $v);
        }
        $cover = Js::opt($input, 'coverHeaders');
        $rest = new Obj();
        $io = $input instanceof Obj ? $input : Obj::of($input);
        foreach ($io->keys() as $k) {
            $rest->set($k, $io->get($k));
        }
        $rest->set('headers', $headers);
        $rest->set('coverHeaders', [...($cover === null ? [] : Js::spread($cover)), self::PCA_PROOF_COMPONENT]);
        $result = self::signRequest($rest);
        $merged = $result['headers'];
        foreach ($proof as $k => $v) {
            $merged->set($k, $v);
        }
        $result['headers'] = $merged;
        $result['proofHeader'] = Obj::of($proof);
        return $result;
    }

    /**
     * Verify the HTTP Message Signature AND extract the proof: the PCA-Action header must be a covered component (else fail closed),
     * its PCActn is decoded from it and, when `expectedPCActn` is given, must equal it by canonical digest.
     * @return array<string,mixed>
     */
    public static function verifySignedRequestWithProof(mixed $req, mixed $opts): array
    {
        $base = self::verifySignedRequest($req, $opts);
        if ($base['valid'] !== true) {
            return $base;
        }
        if (!in_array(self::PCA_PROOF_COMPONENT, $base['covered'], true)) {
            return self::invalid('the ' . self::PCA_HEADER . ' proof header is not covered by the signature');
        }
        try {
            $headerValue = self::normalizeHeaders(Js::opt($req, 'headers'))[self::PCA_PROOF_COMPONENT] ?? null;
        } catch (\Throwable $e) {
            return self::invalid('verification failed (fail closed): ' . $e->getMessage());
        }
        if ($headerValue === null) {
            return self::invalid('missing ' . self::PCA_HEADER . ' header');
        }
        try {
            $pcactn = self::decodeProofHeader($headerValue);
        } catch (\Throwable $e) {
            return self::invalid('invalid PCActn in ' . self::PCA_HEADER . ': ' . $e->getMessage());
        }
        if (Js::has($opts, 'expectedPCActn') && Js::opt($opts, 'expectedPCActn') !== null
            && Pca::hashCanonical($pcactn) !== Pca::hashCanonical(Js::opt($opts, 'expectedPCActn'))) {
            return self::invalid('carried PCActn does not match the expected proof');
        }
        return $base + ['pcactn' => $pcactn];
    }

    // ---- Content-Digest (RFC 9530) ----

    private static function nodeAlg(mixed $alg): string
    {
        return match ($alg) {
            'sha-256' => 'sha256',
            'sha-512' => 'sha512',
            default => throw new NodeArgError('unsupported algorithm', 'ERR_INVALID_ARG_TYPE'),
        };
    }

    /** The raw digest bytes of `$body` (text is hashed as UTF-8; raw bytes as they are) under sha-256 or sha-512. */
    public static function contentDigestBytes(string $body, mixed $alg): string
    {
        return hash(self::nodeAlg($alg), $body, true);
    }

    /** The Content-Digest field value, e.g. `sha-256=:X48E9q...=:` (members in the given order, repeats dropped). @param list<string> $algs */
    public static function contentDigestHeader(string $body, array $algs = ['sha-256']): string
    {
        if ($algs === []) {
            throw new \InvalidArgumentException('contentDigestHeader: name at least one algorithm');
        }
        $seen = [];
        $parts = [];
        foreach ($algs as $alg) {
            if (!in_array($alg, self::CONTENT_DIGEST_ALGS, true)) {
                throw new \InvalidArgumentException('contentDigestHeader: unsupported algorithm ' . Js::str($alg));
            }
            if (isset($seen[$alg])) {
                continue;
            }
            $seen[$alg] = true;
            $parts[] = $alg . '=:' . base64_encode(self::contentDigestBytes($body, $alg)) . ':';
        }
        return implode(', ', $parts);
    }

    /** Parse the dictionary: key => raw bytes. Throws on anything that is not `key=:base64:` (parameters refused). @return array<string,string> */
    public static function parseContentDigest(string $value): array
    {
        $out = [];
        foreach (explode(',', $value) as $raw) {
            $member = self::trim($raw);
            if ($member === '') {
                throw new \InvalidArgumentException('empty dictionary member');
            }
            if (preg_match('/\A([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+\/]*={0,2}):\z/', $member, $m) !== 1) {
                throw new \InvalidArgumentException("malformed Content-Digest member \"$member\"");
            }
            [, $key, $b64] = $m;
            if (strlen($b64) % 4 !== 0) {
                throw new \InvalidArgumentException("member \"$key\" is not canonical base64");
            }
            $bytes = self::nodeBase64($b64);
            if (base64_encode($bytes) !== $b64) {
                throw new \InvalidArgumentException("member \"$key\" is not canonical base64");
            }
            if (array_key_exists($key, $out)) {
                throw new \InvalidArgumentException("member \"$key\" appears twice");
            }
            $out[$key] = $bytes;
        }
        return $out;
    }

    /**
     * Check `$body` against a Content-Digest field value (null = absent). Every supported member present must match, unsupported
     * members are ignored (RFC 9530 section 2), at least one supported member must be present, and every algorithm in `$require`
     * must be among the matched. FAILS CLOSED; never throws on a bad header.
     * @param ?list<string> $require @return array{valid:bool,reason?:string,matched?:list<string>}
     */
    public static function verifyContentDigest(?string $header, string $body, ?array $require = null): array
    {
        $fail = static fn(string $r): array => ['valid' => false, 'reason' => $r];
        try {
            if ($header === null || self::trim($header) === '') {
                return $fail('missing Content-Digest');
            }
            $members = self::parseContentDigest($header);
            $matched = [];
            foreach (self::CONTENT_DIGEST_ALGS as $alg) {
                if (!array_key_exists($alg, $members)) {
                    continue;
                }
                if (!hash_equals($members[$alg], self::contentDigestBytes($body, $alg))) {
                    return $fail("$alg digest does not match the content");
                }
                $matched[] = $alg;
            }
            if ($matched === []) {
                return $fail('no supported digest algorithm (sha-256 or sha-512)');
            }
            foreach ($require ?? [] as $alg) {
                if (!in_array($alg, $matched, true)) {
                    return $fail("required $alg digest is absent");
                }
            }
            return ['valid' => true, 'matched' => $matched];
        } catch (\InvalidArgumentException $e) {
            return $fail('malformed Content-Digest: ' . $e->getMessage());
        }
    }

    // ---- signed key directory (draft-meunier-http-message-signatures-directory section 5.2) ----

    /** Strictly parse a directory document: every key a well-formed Ed25519 OKP JWK with a string kid. Throws otherwise. */
    public static function parseKeyDirectory(string $text): Obj
    {
        $doc = Js::parseNoDuplicates($text); // a duplicate member is refused
        $keys = $doc instanceof Obj ? $doc->get('keys') : null;
        if (!self::isList($keys) || $keys === []) {
            throw new \InvalidArgumentException('directory has no keys');
        }
        foreach ($keys as $j) {
            $bad = !($j instanceof Obj) || $j->get('kty') !== 'OKP' || $j->get('crv') !== 'Ed25519' || !is_string($j->get('kid')) || $j->get('kid') === ''
                || !is_string($j->get('x')) || preg_match('/\A[A-Za-z0-9_-]{43}\z/', $j->get('x')) !== 1;
            if (!$bad) {
                foreach (['nbf', 'exp'] as $f) {
                    if ($j->has($f)) {
                        $d = Js::num($j->get($f));
                        $bad = $bad || $d === null || !is_finite($d);
                    }
                }
            }
            if ($bad) {
                throw new \InvalidArgumentException('directory contains a malformed key');
            }
        }
        return $doc;
    }

    /**
     * Sign a directory response, one signature per key. `$input`: keys (signing keys), directory (the document to serve, as built by
     * buildKeyDirectory; every signing key must be in it), authority (lower-case host or host:port), created, expiresInSec (86400).
     * @return array{body:string,headers:Obj}
     */
    public static function signDirectoryResponse(mixed $input): array
    {
        $keys = Js::opt($input, 'keys');
        if (!self::isList($keys) || $keys === []) {
            throw new \InvalidArgumentException('signDirectoryResponse: at least one signing key is required');
        }
        $authority = Js::opt($input, 'authority');
        if (!is_string($authority) || preg_match('/\A[a-z0-9.\-\[\]:]+\z/', $authority) !== 1) {
            throw new \InvalidArgumentException('signDirectoryResponse: authority must be a lower-case host or host:port');
        }
        $created = Js::opt($input, 'created') !== null ? self::num(Js::opt($input, 'created')) : self::now();
        $expires = $created + self::numOr($input, 'expiresInSec', self::DEFAULT_DIRECTORY_LIFETIME_SEC);
        $directory = Js::opt($input, 'directory');
        $body = Js::stringify($directory);
        $inputs = [];
        $sigs = [];
        foreach ($keys as $i => $k) {
            [$sign, $pub] = self::signer($k);
            $x = Pca::b64u($pub);
            $dk = Js::opt($directory, 'keys');
            $found = false;
            foreach (self::isList($dk) ? $dk : [] as $j) {
                $found = $found || Js::opt($j, 'x') === $x;
            }
            if (!$found) {
                throw new \InvalidArgumentException('signDirectoryResponse: a signing key is not in the directory');
            }
            $label = 'sig' . ($i + 1);
            $params = '("@authority";req);created=' . self::numStr($created) . ';expires=' . self::numStr($expires) . ';keyid="' . self::thumbprintOfX($x) . '";alg="ed25519";tag="' . self::DIRECTORY_SIGNATURE_TAG . '"';
            $inputs[] = $label . '=' . $params;
            $sigs[] = $label . '=:' . base64_encode($sign("\"@authority\";req: $authority\n\"@signature-params\": $params")) . ':';
        }
        return ['body' => $body, 'headers' => Obj::of(['content-type' => self::DIRECTORY_CONTENT_TYPE, 'signature-input' => implode(', ', $inputs), 'signature' => implode(', ', $sigs)])];
    }

    /** @return array{valid:false,reason:string,keys:list<never>} */
    private static function dirFail(string $reason): array
    {
        return ['valid' => false, 'reason' => $reason, 'keys' => []];
    }

    /**
     * Verify a signed directory response. `$input`: authority, headers (signature-input, signature), body, now, clockSkewSec,
     * maxLifetimeSec (86400). Fail closed: {valid:false, reason, keys:[]} for a missing or malformed signature header, a body that
     * is not a well-formed directory, or when NO signature is valid. When valid, `keys` holds only the directory keys with a valid signature.
     * @return array{valid:bool,reason?:string,keys:list<mixed>}
     */
    public static function verifyDirectoryResponse(mixed $input): array
    {
        try {
            $hdrs = Js::opt($input, 'headers');
            $sigInput = Js::opt($hdrs, 'signature-input');
            $sigHeader = Js::opt($hdrs, 'signature');
            if (!Js::truthy($sigInput) || !Js::truthy($sigHeader)) {
                return self::dirFail('missing signature-input or signature header');
            }
            if (!is_string($sigInput) || !is_string($sigHeader) || !is_string(Js::opt($input, 'body'))) {
                throw new \TypeError('header or body is not a string');
            }
            $dir = self::parseKeyDirectory(Js::opt($input, 'body'));
            $sigs = [];
            foreach (explode(', ', $sigHeader) as $part) {
                if (preg_match('/\A([a-z][a-z0-9_.*-]*)=:([A-Za-z0-9+\/]+={0,2}):\z/', $part, $m) !== 1) {
                    return self::dirFail('malformed signature header');
                }
                $sigs[$m[1]] = self::nodeBase64($m[2]);
            }
            $now = self::numOr($input, 'now', self::now());
            $skew = self::numOr($input, 'clockSkewSec', 0.0);
            $maxLife = self::numOr($input, 'maxLifetimeSec', self::DEFAULT_DIRECTORY_LIFETIME_SEC);
            $good = [];
            $last = 'no signature entry';
            foreach (explode(', ', $sigInput) as $raw) {
                if (preg_match('/\A([a-z][a-z0-9_.*-]*)=\("@authority";req\)((?:;[a-z]+=(?:[0-9]+|"[A-Za-z0-9_.\-]*"))*)\z/', $raw, $m) !== 1) {
                    $last = 'malformed signature-input entry (must cover exactly "@authority";req)';
                    continue;
                }
                $label = $m[1];
                $params = [];
                $dup = false;
                foreach (array_slice(explode(';', $m[2]), 1) as $p) {
                    $eq = strpos($p, '=');
                    $k = substr($p, 0, $eq);
                    $dup = $dup || array_key_exists($k, $params);
                    $params[$k] = substr($p, $eq + 1);
                }
                if ($dup) {
                    $last = 'duplicate signature parameter';
                    continue;
                }
                $str = static fn(string $k): ?string => isset($params[$k]) && $params[$k][0] === '"' ? substr($params[$k], 1, -1) : null;
                $numP = static fn(string $k): ?float => isset($params[$k]) && preg_match('/\A[0-9]+\z/', $params[$k]) === 1 ? (float)$params[$k] : null;
                if ($str('tag') !== self::DIRECTORY_SIGNATURE_TAG) {
                    $last = 'wrong tag';
                    continue;
                }
                if (isset($params['alg']) && $params['alg'] !== '"ed25519"') {
                    $last = 'unsupported alg';
                    continue;
                }
                $created = $numP('created');
                $expires = $numP('expires');
                if ($created === null || $expires === null) {
                    $last = 'created and expires are required';
                    continue;
                }
                if (!(is_finite($now) && is_finite($skew) && $created <= $now + $skew)) {
                    $last = 'signature created-time is in the future';
                    continue;
                }
                if (!(is_finite($now) && is_finite($skew) && $now <= $expires + $skew)) {
                    $last = 'signature has expired';
                    continue;
                }
                if (!($expires - $created <= $maxLife)) {
                    $last = 'signature lifetime exceeds maxLifetimeSec';
                    continue;
                }
                $keyid = $str('keyid');
                if ($keyid === null) {
                    $last = 'missing keyid';
                    continue;
                }
                $key = null;
                foreach ($dir->get('keys') as $j) {
                    if (self::thumbprintOfX($j->get('x')) === $keyid) {
                        $key = $j;
                        break;
                    }
                }
                if ($key === null) {
                    $last = 'keyid is not the thumbprint of any directory key';
                    continue;
                }
                $nbf = Js::num($key->get('nbf'));
                $exp = Js::num($key->get('exp'));
                if (!(is_finite($now) && is_finite($skew)) || ($nbf !== null && !($now + $skew >= $nbf)) || ($exp !== null && !($now - $skew <= $exp))) {
                    $last = 'directory key is outside its validity window';
                    continue;
                }
                $sig = $sigs[$label] ?? null;
                if ($sig === null || strlen($sig) !== 64) {
                    $last = 'no valid signature bytes for the label';
                    continue;
                }
                $base = "\"@authority\";req: " . Js::str(Js::opt($input, 'authority')) . "\n\"@signature-params\": " . substr($raw, strlen($label) + 1);
                if (!Pca::verifyEd25519B64u(Pca::b64u(self::nodeBase64($key->get('x'))), $base, Pca::b64u($sig))) {
                    $last = 'signature does not verify';
                    continue;
                }
                $good[(string)$key->get('kid')] = $key;
            }
            if ($good === []) {
                return self::dirFail($last);
            }
            return ['valid' => true, 'keys' => array_values($good)];
        } catch (\Throwable $e) {
            return self::dirFail('verification failed (fail closed): ' . $e->getMessage());
        }
    }

    // ---- fetchKeyDirectory ----

    /**
     * Fetch and strictly parse a key directory. FAIL-CLOSED: throws on a non-https URL, a redirect, a non-200 status, a wrong content
     * type, an oversize body, invalid JSON or any malformed key; never returns a partial directory. Options: fetch (callable(string
     * $url, array $headers, int $timeoutMs): array{status,headers,body}, headers keyed lower-case; default a PHP stream GET that does
     * not follow redirects), maxBytes (characters, 65536), timeoutMs (5000), allowInsecureHttp (tests only), requireSignature (return
     * only the keys with a valid signature over the response; throws when none), now.
     */
    public static function fetchKeyDirectory(string $url, mixed $options = null): Obj
    {
        $u = WhatwgUrl::parse($url);
        if ($u === null) {
            throw new NodeArgError('Invalid URL', 'ERR_INVALID_URL');
        }
        if (!in_array($u['scheme'], ['http', 'https', 'ws', 'wss', 'ftp'], true)) {
            throw new \InvalidArgumentException('directory URL must be an http(s) URL');
        }
        if ($u['scheme'] !== 'https' && !(Js::opt($options, 'allowInsecureHttp') === true && $u['scheme'] === 'http')) {
            throw new \InvalidArgumentException('directory URL must be https');
        }
        $hash = strpos($url, '#');
        $noFrag = $hash === false ? $url : substr($url, 0, $hash);
        $slashes = strpos($noFrag, '//');
        $authEnd = strlen($noFrag);
        for ($k = ($slashes === false ? 0 : $slashes) + 2; $k < strlen($noFrag); $k++) {
            if ($noFrag[$k] === '/' || $noFrag[$k] === '\\' || $noFrag[$k] === '?') {
                $authEnd = $k;
                break;
            }
        }
        if ($slashes !== false && str_contains(substr($noFrag, $slashes + 2, $authEnd - $slashes - 2), '@')) {
            throw new \InvalidArgumentException('directory URL must not carry credentials');
        }
        $href = $u['scheme'] . '://' . $u['host'] . $u['pathname'] . $u['search'] . ($u['search'] === '' && str_contains($noFrag, '?') ? '?' : '');
        $fetch = Js::opt($options, 'fetch');
        $fetch = is_callable($fetch) && !is_string($fetch) ? $fetch : Oidc::defaultFetch(...);
        $timeout = Js::opt($options, 'timeoutMs') !== null ? (int)self::num(Js::opt($options, 'timeoutMs')) : 5000;
        $res = $fetch($href, ['accept' => self::DIRECTORY_CONTENT_TYPE], $timeout);
        $status = (int)($res['status'] ?? 0);
        if ($status !== 200) {
            throw new \RuntimeException("directory fetch returned status $status");
        }
        $hs = $res['headers'] ?? [];
        $ct = self::lower(self::trim(explode(';', (string)($hs['content-type'] ?? ''))[0]));
        if ($ct !== self::DIRECTORY_CONTENT_TYPE) {
            throw new \RuntimeException('directory has the wrong content type');
        }
        $text = (string)($res['body'] ?? '');
        if (Js::len($text) > self::numOr($options, 'maxBytes', 65536.0)) {
            throw new \RuntimeException('directory response is too large');
        }
        $directory = self::parseKeyDirectory($text);
        if (Js::opt($options, 'requireSignature') === true) {
            $in = ['authority' => self::lower($u['host']), 'headers' => Obj::of(['signature-input' => $hs['signature-input'] ?? '', 'signature' => $hs['signature'] ?? '']), 'body' => $text];
            if (Js::opt($options, 'now') !== null) {
                $in['now'] = Js::opt($options, 'now');
            }
            $v = self::verifyDirectoryResponse($in);
            if ($v['valid'] !== true) {
                throw new \RuntimeException('directory signature: ' . $v['reason']);
            }
            return Obj::of(['keys' => $v['keys']]);
        }
        return $directory;
    }
}
