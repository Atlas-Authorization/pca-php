<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';

/**
 * The subset of the WHATWG URL parser the protocol bridges need (the reference runs on the platform URL class): scheme,
 * serialized host[:port], pathname (dot segments resolved, percent-encoded as the standard does), search and origin. A special
 * scheme's domain goes through the WHATWG host parser (UTS 46 via ICU), so an IDN host serializes as its punycode form.
 */
final class WhatwgUrl
{
    private const SPECIAL = ['ftp' => 21, 'file' => null, 'http' => 80, 'https' => 443, 'ws' => 80, 'wss' => 443];
    private const PATH_ENC = "\"<>`{}?";
    private const QUERY_ENC = "\"<>'";

    /** Percent-encode the C0 controls, bytes above 0x7E and (unless $controlsOnly) space plus `$extra`; a lone surrogate becomes U+FFFD. */
    public static function pct(string $s, string $extra, bool $controlsOnly = false): string
    {
        $s = (string)preg_replace('/\xED[\xA0-\xBF][\x80-\xBF]/', "\u{FFFD}", $s);
        $out = '';
        for ($i = 0, $n = strlen($s); $i < $n; $i++) {
            $c = $s[$i];
            $o = ord($c);
            $out .= ($o < 0x20 || $o > 0x7e || (!$controlsOnly && ($o === 0x20 || str_contains($extra, $c)))) ? sprintf('%%%02X', $o) : $c;
        }
        return $out;
    }

    private static function ipv4Number(string $part): ?int
    {
        if ($part === '') {
            return null;
        }
        $radix = 10;
        if (strlen($part) >= 2 && strcasecmp(substr($part, 0, 2), '0x') === 0) {
            [$part, $radix] = [substr($part, 2), 16];
        } elseif (strlen($part) >= 2 && $part[0] === '0') {
            [$part, $radix] = [substr($part, 1), 8];
        }
        if ($part === '') {
            return 0;
        }
        $re = [10 => '/\A[0-9]+\z/', 16 => '/\A[0-9a-fA-F]+\z/', 8 => '/\A[0-7]+\z/'][$radix];
        if (preg_match($re, $part) !== 1) {
            return null;
        }
        $t = ltrim($part, '0');
        // any value of 2^32 or more fails the range checks below; cap instead of overflowing
        if (strlen($t) > [10 => 10, 16 => 8, 8 => 11][$radix]) {
            return PHP_INT_MAX;
        }
        return (int)base_convert($t === '' ? '0' : $t, $radix, 10);
    }

    private static function endsInNumber(string $host): bool
    {
        $parts = explode('.', $host);
        if (end($parts) === '') {
            if (count($parts) === 1) {
                return false;
            }
            array_pop($parts);
        }
        $last = end($parts);
        return $last !== '' && (preg_match('/\A[0-9]+\z/', $last) === 1 || self::ipv4Number($last) !== null);
    }

    private static function parseIpv4(string $host): ?string
    {
        $parts = explode('.', $host);
        if (end($parts) === '' && count($parts) > 1) {
            array_pop($parts);
        }
        if (count($parts) > 4) {
            return null;
        }
        $nums = [];
        foreach ($parts as $p) {
            $x = self::ipv4Number($p);
            if ($x === null) {
                return null;
            }
            $nums[] = $x;
        }
        $last = array_pop($nums);
        foreach ($nums as $x) {
            if ($x > 255) {
                return null;
            }
        }
        if ($last >= 256 ** (4 - count($nums))) {
            return null;
        }
        $v = $last;
        foreach ($nums as $i => $x) {
            $v += $x * (256 ** (3 - $i));
        }
        return implode('.', array_map(static fn(int $k): string => (string)(($v >> (8 * $k)) & 255), [3, 2, 1, 0]));
    }

    /** @param list<int> $h the eight 16-bit pieces */
    private static function serializeIpv6(array $h): string
    {
        $best = -1;
        $bestLen = 1;
        for ($i = 0; $i < 8;) {
            if ($h[$i] === 0) {
                $j = $i;
                while ($j < 8 && $h[$j] === 0) {
                    $j++;
                }
                if ($j - $i > $bestLen) {
                    [$best, $bestLen] = [$i, $j - $i];
                }
                $i = $j;
            } else {
                $i++;
            }
        }
        $out = '';
        for ($i = 0; $i < 8;) {
            if ($i === $best) {
                $out .= $i === 0 ? '::' : ':';
                $i += $bestLen;
                continue;
            }
            $out .= dechex($h[$i]) . ($i === 7 ? '' : ':');
            $i++;
        }
        return "[$out]";
    }

    private static function parseHost(string $text, bool $special): ?string
    {
        if (str_starts_with($text, '[')) {
            if (!str_ends_with($text, ']') || str_contains($text, '%')) {
                return null;
            }
            $inner = substr($text, 1, -1);
            if (preg_match('/\A[0-9A-Fa-f:.]+\z/', $inner) !== 1 || filter_var($inner, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                return null;
            }
            $b = inet_pton($inner);
            if ($b === false || strlen($b) !== 16) {
                return null;
            }
            return self::serializeIpv6(array_values(unpack('n8', $b)));
        }
        if (!$special) {
            return preg_match('/[\x00\t\n\r #\/<>?@\[\\\\\]^|]/', $text) === 1 ? null : self::pct($text, '', true);
        }
        $domain = self::domainToASCII($text); // percent-decode, UTS 46 (IDN to punycode), forbidden code points, IPv4
        return $domain === '' ? null : $domain;
    }

    /**
     * Parse an absolute URL. Returns {scheme, host, htu, pathname, origin?, search?} (origin and search only for a special
     * scheme), or null when the platform URL class would refuse the text.
     * @return ?array<string,string>
     */
    public static function parse(mixed $str): ?array
    {
        if (!is_string($str)) {
            return null;
        }
        $s = (string)preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', $str);
        $s = str_replace(["\t", "\n", "\r"], '', $s);
        if (preg_match('/\A([A-Za-z][A-Za-z0-9+.\-]*):/', $s, $m) !== 1) {
            return null;
        }
        $scheme = strtolower($m[1]);
        $rest = substr($s, strlen($m[0]));
        $special = array_key_exists($scheme, self::SPECIAL);
        $f = strpos($rest, '#');
        if ($f !== false) {
            $rest = substr($rest, 0, $f);
        }
        $query = null;
        $q = strpos($rest, '?');
        if ($q !== false) {
            $query = substr($rest, $q + 1);
            $rest = substr($rest, 0, $q);
        }
        $host = '';
        $port = null;
        $hasCred = false;
        $hostport = '';
        $authority = null;
        $path = '';
        if ($special && $scheme !== 'file') {
            $rest = (string)preg_replace('#\A[/\\\\]+#', '', $rest);
            [$authority, $path] = self::cut($rest, '#[/\\\\]#');
            $hasCred = str_contains($authority, '@');
            $hostport = self::afterLastAt($authority);
        } elseif (str_starts_with($rest, '//') || ($scheme === 'file' && preg_match('#\A[/\\\\]{2}#', $rest) === 1)) {
            [$authority, $path] = self::cut(substr($rest, 2), $special ? '#[/\\\\]#' : '#/#');
            $hasCred = str_contains($authority, '@') && $scheme !== 'file';
            $hostport = $scheme === 'file' ? $authority : self::afterLastAt($authority);
        } elseif ($special) { // file: without an authority
            $authority = '';
            $path = (string)preg_replace('#\A[/\\\\]#', '/', $rest);
        } else {
            $path = $rest;
        }
        if ($authority !== null) {
            if (str_starts_with($hostport, '[')) {
                $e = strpos($hostport, ']');
                if ($e === false) {
                    return null;
                }
                $htxt = substr($hostport, 0, $e + 1);
                $after = substr($hostport, $e + 1);
                if ($after !== '' && !str_starts_with($after, ':')) {
                    return null;
                }
                $ptxt = $after === '' ? null : substr($after, 1);
            } else {
                $c = strpos($hostport, ':');
                [$htxt, $ptxt] = $c === false ? [$hostport, null] : [substr($hostport, 0, $c), substr($hostport, $c + 1)];
            }
            if ($ptxt !== null && $ptxt !== '') {
                if (preg_match('/\A[0-9]+\z/', $ptxt) !== 1 || strlen(ltrim($ptxt, '0')) > 5 || (int)$ptxt > 65535) {
                    return null;
                }
                $port = self::SPECIAL[$scheme] ?? null;
                $port = $port === (int)$ptxt ? null : (int)$ptxt;
            }
            if ($special && $scheme !== 'file' && $htxt === '') {
                return null;
            }
            if ($hasCred && $htxt === '' && $ptxt === null && $hostport === '') {
                return null;
            }
            if ($htxt !== '') {
                $ph = self::parseHost($htxt, $special);
                if ($ph === null) {
                    return null;
                }
                $host = $scheme === 'file' && $ph === 'localhost' ? '' : $ph;
            }
        }
        $hp = $host . ($port === null ? '' : ":$port");
        if ($authority === null) {
            $pathname = self::pct($path, '', true); // an opaque path: only the control characters are encoded
        } else {
            $segs = $path === '' ? [] : array_slice(explode('/', $special ? str_replace('\\', '/', $path) : $path), 1);
            $out = [];
            $n = count($segs);
            foreach ($segs as $i => $seg) {
                $last = $i === $n - 1;
                $low = strtolower($seg);
                if (in_array($low, ['..', '.%2e', '%2e.', '%2e%2e'], true)) {
                    array_pop($out);
                    if ($last) {
                        $out[] = '';
                    }
                } elseif ($low === '.' || $low === '%2e') {
                    if ($last) {
                        $out[] = '';
                    }
                } else {
                    $out[] = self::pct($seg, self::PATH_ENC);
                }
            }
            $pathname = '/' . implode('/', $out);
        }
        $res = ['scheme' => $scheme, 'host' => $hp, 'htu' => "$scheme://$hp$pathname", 'pathname' => $pathname];
        if ($special) {
            $res['origin'] = "$scheme://$hp";
            $res['search'] = $query === null || $query === '' ? '' : '?' . self::pct($query, self::QUERY_ENC);
        }
        return $res;
    }

    /** @return array{0:string,1:string} the text before the first match of $re, and the rest (from the match) */
    private static function cut(string $s, string $re): array
    {
        if (preg_match($re, $s, $m, PREG_OFFSET_CAPTURE) === 1) {
            $at = $m[0][1];
            return [substr($s, 0, $at), substr($s, $at)];
        }
        return [$s, ''];
    }

    private static function afterLastAt(string $a): string
    {
        $p = strrpos($a, '@');
        return $p === false ? $a : substr($a, $p + 1);
    }

    /**
     * node:url domainToASCII: set the text as the hostname of a special (ws:) URL and read it back; '' when the setter refuses.
     * The host ends at / ? # \, a ':' outside brackets refuses (hostname state override), then the WHATWG host parser runs:
     * percent-decode, UTS 46 (non-transitional, CheckHyphens and VerifyDnsLength off, CheckBidi and CheckJoiners on), forbidden
     * domain code points, and a host ending in a number must be IPv4.
     * shortcut: a bracketed (IPv6) host is refused; upgrade if a caller needs IPv6 literals here.
     */
    public static function domainToASCII(string $input): string
    {
        $s = str_replace(["\t", "\n", "\r"], '', Js::utf8($input));
        $s = substr($s, 0, strcspn($s, '/?#\\'));
        if ($s === '' || $s[0] === '[' || str_contains($s, ':')) {
            return '';
        }
        $d = rawurldecode($s);
        if (!mb_check_encoding($d, 'UTF-8')) {
            $d = mb_convert_encoding($d, 'UTF-8', 'UTF-8'); // the UTF-8 decode without BOM or fail: invalid bytes become U+FFFD
        }
        if (preg_match('/\A[\x00-\x7f]*\z/', $d) === 1 && preg_match('/(?:\A|\.)xn--/i', $d) !== 1) {
            $a = strtolower($d);
        } else {
            idn_to_ascii($d, IDNA_NONTRANSITIONAL_TO_ASCII | IDNA_CHECK_BIDI | IDNA_CHECK_CONTEXTJ, INTL_IDNA_VARIANT_UTS46, $info);
            $ignored = IDNA_ERROR_EMPTY_LABEL | IDNA_ERROR_LABEL_TOO_LONG | IDNA_ERROR_DOMAIN_NAME_TOO_LONG | IDNA_ERROR_LEADING_HYPHEN
                | IDNA_ERROR_TRAILING_HYPHEN | IDNA_ERROR_HYPHEN_3_4;
            if (!is_array($info) || !is_string($info['result'] ?? null) || (($info['errors'] ?? 1) & ~$ignored) !== 0) {
                return '';
            }
            $a = $info['result'];
        }
        if ($a === '' || preg_match('/[\x00-\x20#%\/:<>?@\[\\\\\]^|\x7f-\xff]/', $a) === 1) {
            return '';
        }
        return self::endsInNumber($a) ? (self::parseIpv4($a) ?? '') : $a;
    }
}
