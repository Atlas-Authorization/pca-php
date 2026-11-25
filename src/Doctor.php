<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Siem.php';
require_once __DIR__ . '/WhatwgUrl.php';
require_once __DIR__ . '/AnalyzerJs.php';

/** A refusal with a stable code (Invalid URL has ERR_INVALID_URL, as the platform URL class reports it). */
final class DoctorError extends \InvalidArgumentException
{
    public function __construct(string $message, public readonly string $errorCode = '')
    {
        parent::__construct($message);
    }
}

/** The library under test: its version, where it was found and how to probe it: `probe(rootCaveat, amountUsd)` decides a payment of that amount under a root grant carrying the caveat and returns {allowed, reasons}. */
final class DoctorPca
{
    /** @param \Closure(array,int|float):mixed $probe */
    public function __construct(public readonly string $version, public readonly string $path, public readonly \Closure $probe)
    {
    }
}

/**
 * Checks a live PCA deployment's assumptions: clock skew, the replay store, trusted-proxy settings, the signature-suite policy,
 * root-caveat enforcement and the verifier's required checks. Every check returns a result {id, status, detail, remediation?,
 * observed?} (status pass / warn / fail / skip); runDoctor merges them, verdictOf reduces them, formatResults prints them, and
 * nothing printed carries a credential (scrubText). Configuration is the parsed-JSON model (an Obj or an assoc array) with the
 * reference's sections and member names (url, clock, store, proxy, verifier). Same check ids, messages and order as the reference.
 *
 * Network, clock and the deployed library are injected: `fetch(url, method, headers, timeoutMs)` returns
 * ['status' => int, 'headers' => [lower-case name => value]] (default: a PHP stream, redirects not followed), `now()` returns epoch
 * milliseconds, `load(?pcaDir)` returns a DoctorPca (default: this process's library, or the one installed under pcaDir). The
 * replay-store check needs an injected `store(cfg)` returning its results (the conformance kit's adapter interface is not shared).
 */
final class Doctor
{
    public const USAGE = 'pca-doctor [--url <deployment>] [options]

  --url URL              the live deployment (base URL of the API that verifies PCActns)
  --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it
  --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks
  --store-option k=v     passed to the adapter factory (repeatable)
  --reference URL|local  clock reference (default https://www.google.com/generate_204)
  --max-skew-ms N        clock fail threshold (default 60000)
  --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment\'s proxy settings and the real hop count
  --pca-dir DIR          the deployed application\'s directory (its installed @atlasauth/pca is probed)
  --only a,b | --skip a,b   check groups: clock, store, proxy, suites, caveats
  --no-probe             do not send forged forwarding headers to the deployment
  --strict               warnings fail too
  --json                 machine-readable output

Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,
     PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ.';
    public const DEFAULT_REFERENCE_URL = 'https://www.google.com/generate_204';
    public const ROOT_CAVEAT_MIN_VERSION = '0.4.1';
    public const SUITES_REMEDIATION = 'Set the verifier\'s allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. [\'ed25519\'] or [\'hybrid-ed25519-ml-dsa-65\'].';
    public const PQ_REMEDIATION = 'Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, from pqPinFor) or verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this).';
    public const CLOCK_REMEDIATION = 'Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. PCA tolerates at most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock outside that bound can free a nonce early or reject fresh actions.';
    public const PROXY_REMEDIATION = 'Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted header (1 behind one load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the header they write. Too high lets a client pick its own rate-limit bucket with extra X-Forwarded-For entries; too low merges every client into the proxy\'s bucket.';
    public const ATOMICITY_REMEDIATION = 'Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE until < $now RETURNING and UPDATE .. WHERE counter < $n RETURNING, Redis SET key NX PX or a Lua compare-and-set; never read, then write. Then run the full kit: pca-store-conformance --adapter <your adapter>.';
    public const DURABILITY_REMEDIATION = 'Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; Redis appendfsync always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store is only correct for a single process whose lifetime covers the action lifetime.';
    public const CAVEAT_REMEDIATION = 'Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced from 0.4.1), redeploy, and re-run pca-doctor with --pca-dir pointing at the application.';
    public const CHECK_GROUPS = ['clock', 'store', 'proxy', 'suites', 'caveats'];
    public const DEFAULT_REQUIRED = ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];
    private const PROXY_HEADERS = ['x-forwarded-for', 'forwarded', 'x-real-ip'];
    private const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
    private const ED25519_ID = '/\A[A-Za-z0-9_-]{43}\z/';
    private const B64U = '/\A[A-Za-z0-9_-]+\z/';

    // ---- JavaScript value semantics over the parsed-JSON model --------------------------------------------------------------

    /** `o?.k`: the undefined sentinel for a non-object or an absent member. */
    private static function g(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->has($k) ? $o->get($k) : Jsx::$U;
        }
        if (is_array($o) && !array_is_list($o) && array_key_exists($k, $o)) {
            return $o[$k];
        }
        return Jsx::$U;
    }

    /** `v ?? default`. */
    private static function nn(mixed $v, mixed $default): mixed
    {
        return $v === null || $v instanceof Undef ? $default : $v;
    }

    private static function isDict(mixed $v): bool
    {
        return $v instanceof Obj || (is_array($v) && !array_is_list($v));
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    /** Object.keys order of a dict. @return list<string> */
    private static function keysOf(mixed $o): array
    {
        return $o instanceof Obj ? Js::ownKeys($o->keys()) : array_map('strval', array_keys((array)$o));
    }

    private static function s(mixed $v): string
    {
        return Jsx::str($v);
    }

    private static function isInteger(mixed $v): bool
    {
        if (!Js::isNum($v)) {
            return false;
        }
        $f = (float)Js::num($v);
        return is_finite($f) && $f == floor($f);
    }

    private static function negZero(mixed $v): bool
    {
        return Js::isNum($v) && (float)Js::num($v) === 0.0 && fdiv(1.0, (float)Js::num($v)) < 0;
    }

    private static function numStr(float $f): string
    {
        return IntentWb::jsNumStr($f);
    }

    /** JS toFixed (a magnitude of 1e21 and up prints as String(x)). */
    private static function toFixed(float $x, int $digits): string
    {
        return is_finite($x) && abs($x) >= 1e21 ? IntentWb::jsNumStr($x) : AnalyzerJs::toFixed($x, $digits);
    }

    /** String.prototype.trim over a (WTF-8) string. */
    private static function jsTrim(string $s): string
    {
        $ws = '(?:' . IntentWb::JS_WS . ')++';
        return (string)preg_replace('/\A' . $ws . '|' . $ws . '\z/', '', $s);
    }

    private static function padEnd(string $s, int $n): string
    {
        return $s . str_repeat(' ', max(0, $n - Js::len($s)));
    }

    private static function res(string $id, string $status, string $detail, ?string $remediation = null, ?array $observed = null): array
    {
        $r = ['id' => $id, 'status' => $status, 'detail' => $detail];
        if ($remediation !== null) {
            $r['remediation'] = $remediation;
        }
        if ($observed !== null) {
            $r['observed'] = $observed;
        }
        return $r;
    }

    /** The assoc-array / Obj model of any nesting (a list stays a list). */
    private static function toModel(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::toModel($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::toModel(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string)$k, self::toModel($x));
            }
            return $o;
        }
        return $v;
    }

    // ---- scrub --------------------------------------------------------------------------------------------------------------

    /** @return list<array{0:string,1:string}> pattern, replacement; the regexes run byte-wise over WTF-8 with the JS \s class spelled out */
    private static function scrubRules(): array
    {
        $ws = Siem::WS;
        $nw = '(?:(?!' . $ws . ')[^/@])*';
        return [
            ['%\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*%', '[redacted]'],
            ['%\b(authorization["\']?' . $ws . '*[:=]' . $ws . '*)[^\n"\']*%i', '${1}[redacted]'],
            ['%\b(Bearer|Basic|Token)' . $ws . '+[\w.~+/=-]{6,}%i', '${1} [redacted]'],
            ['%([a-z][a-z0-9+.-]*://)' . $nw . ':' . $nw . '@%i', '${1}[redacted]@'],
            ['%\b((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth|sslpassword)["\']?' . $ws . '*[:=]' . $ws . '*)'
                . '("[^"]*"|\'[^\']*\'|(?:(?!' . $ws . ')[^"\'&,;])+)%i', '${1}[redacted]'],
            ['%[A-Za-z0-9_-]{40,}%', '[redacted]'],
        ];
    }

    /** Remove credentials from text the doctor prints: URL userinfo, token= / password= pairs, bearer credentials, JWTs and long token runs; cut to 600 UTF-16 units. */
    public static function scrubText(mixed $text): string
    {
        $t = is_string($text) ? $text : self::s($text);
        foreach (self::scrubRules() as [$rx, $rep]) {
            $r = preg_replace($rx, $rep, $t);
            if ($r === null) { // a pattern gave up: nothing unscrubbed leaves
                return '[redacted]';
            }
            $t = $r;
        }
        return Js::len($t) > 600 ? Siem::u16slice($t, 600) . '...' : $t;
    }

    /** Scrub every string inside a JSON-like value (nesting deeper than 8 is left as it is). */
    public static function scrubDeep(mixed $v, int $depth = 0): mixed
    {
        if (is_string($v)) {
            return self::scrubText($v);
        }
        if ($depth > 8 || !($v instanceof Obj || is_array($v))) {
            return $v;
        }
        if (self::isList($v) || $v === []) {
            return array_map(fn($x) => self::scrubDeep($x, $depth + 1), $v);
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::scrubDeep($v->get($k), $depth + 1));
            }
            return $o;
        }
        $out = [];
        foreach ($v as $k => $x) {
            $out[$k] = self::scrubDeep($x, $depth + 1);
        }
        return $out;
    }

    // ---- fetch and clock ----------------------------------------------------------------------------------------------------

    /** The default client: a PHP stream, redirects not followed, an HTTP error status is a response. @return array{status:int,headers:array<string,string>} */
    public static function defaultFetch(string $url, string $method = 'GET', array $headers = [], float $timeoutMs = 10000.0): array
    {
        $h = [];
        foreach ($headers as $k => $v) {
            $h[] = $k . ': ' . $v;
        }
        $ctx = stream_context_create(['http' => [
            'method' => $method, 'header' => implode("\r\n", $h), 'timeout' => $timeoutMs / 1000, 'follow_location' => 0, 'ignore_errors' => true,
        ]]);
        @file_get_contents($url, false, $ctx);
        $lines = $http_response_header ?? [];
        if ($lines === []) {
            throw new \RuntimeException((string)(error_get_last()['message'] ?? 'request failed'));
        }
        $status = preg_match('#^HTTP/\S+\s+(\d{3})#', (string)$lines[0], $m) === 1 ? (int)$m[1] : 0;
        $out = [];
        foreach (array_slice($lines, 1) as $line) {
            $c = strpos((string)$line, ':');
            if ($c !== false) {
                $out[strtolower(substr((string)$line, 0, $c))] = trim(substr((string)$line, $c + 1));
            }
        }
        return ['status' => $status, 'headers' => $out];
    }

    private static function wallMs(): float
    {
        return microtime(true) * 1000;
    }

    private static function daysFromCivil(int $y, int $m, int $d): int
    {
        $y -= $m <= 2 ? 1 : 0;
        $era = intdiv($y >= 0 ? $y : $y - 399, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    private static function epoch(int $y, int $mo, int $d, int $h, int $mi, int $s, int $ms, int $offMin): float
    {
        $days = self::daysFromCivil($y, $mo, 1) + $d - 1;
        return (float)(((($days * 24 + $h) * 60 + $mi) * 60000) + $s * 1000 + $ms - $offMin * 60000);
    }

    /**
     * `Date.parse`: NaN when unparseable. Covers the HTTP date (RFC 1123 with a zone; a weekday word is ignored, as the reference
     * engine does) and ISO 8601 with a zone or date only (UTC). shortcut: a date without a zone is local time in the reference engine
     * (host-dependent) and is NaN here; other legacy spellings are NaN; years below 1 are NaN.
     */
    public static function parseDate(string $s): float
    {
        $t = self::jsTrim($s);
        if (preg_match('/\A(?:[A-Za-z]+,?\s+)?(\d{1,2})\s+([A-Za-z]{3})[A-Za-z]*\s+(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(GMT|UTC|UT|Z|[+-]\d{4})\z/i', $t, $m) === 1) {
            $mn = array_search(strtolower($m[2]), self::MONTHS, true);
            if ($mn === false) {
                return NAN;
            }
            $h = (int)$m[4];
            $mi = (int)$m[5];
            $sec = (int)(($m[6] ?? '') === '' ? '0' : $m[6]);
            if ($h > 24 || $mi > 59 || $sec > 59 || ($h === 24 && ($mi !== 0 || $sec !== 0))) {
                return NAN;
            }
            $z = strtoupper($m[7]);
            $off = preg_match('/\A[+-]\d{4}\z/', $z) === 1 ? ($z[0] === '-' ? -1 : 1) * ((int)substr($z, 1, 2) * 60 + (int)substr($z, 3, 2)) : 0;
            $day = (int)$m[1];
            $year = (int)$m[3];
            if ($day < 1 || $day > 31 || $year < 1) {
                return NAN;
            }
            return self::epoch($year, $mn + 1, $day, $h, $mi, $sec, 0, $off);
        }
        if (preg_match('/\A(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2}))?\z/', $t, $m) === 1) {
            $y = (int)$m[1];
            $mo = (int)$m[2];
            $d = (int)$m[3];
            $leap = ($y % 4 === 0 && $y % 100 !== 0) || $y % 400 === 0;
            $dim = [31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            if ($y < 1 || $mo < 1 || $mo > 12 || $d < 1 || $d > $dim[$mo - 1]) {
                return NAN;
            }
            $h = (int)($m[4] ?? '');
            $mi = (int)($m[5] ?? '');
            $sec = (int)($m[6] ?? '');
            $frac = $m[7] ?? '';
            if ($h > 24 || $mi > 59 || $sec > 59 || ($h === 24 && ($mi !== 0 || $sec !== 0 || $frac !== ''))) {
                return NAN;
            }
            $ms = $frac !== '' ? (int)substr($frac . '00', 0, 3) : 0;
            $z = $m[8] ?? '';
            $off = 0;
            if ($z !== '' && $z !== 'Z') {
                $off = ($z[0] === '-' ? -1 : 1) * ((int)substr($z, 1, 2) * 60 + (int)substr($z, 4, 2));
            }
            return self::epoch($y, $mo, $d, $h, $mi, $sec, $ms, $off);
        }
        return NAN;
    }

    /** One reading of a server's clock from its Date header (one-second resolution: +-0.5 s plus half the round trip): {offsetMs, uncertaintyMs} (remote minus local) or {error}. */
    public static function readDate(string $url, callable $fetch, callable $now, float $timeoutMs): array
    {
        $t0 = $now();
        try {
            $res = $fetch($url, 'HEAD', [], $timeoutMs);
        } catch (\Throwable $e) { // any transport failure is an unobservable clock
            return ['error' => 'request failed: ' . $e->getMessage()];
        }
        $t1 = $now();
        $date = $res['headers']['date'] ?? null;
        $d = is_string($date) ? self::parseDate($date) : NAN;
        if (!is_finite($d)) {
            return ['error' => $date === null ? 'no Date header' : "unparseable Date header '" . self::s($date) . "'"];
        }
        return ['offsetMs' => $d + 500 - ($t0 + $t1) / 2, 'uncertaintyMs' => 500 + ($t1 - $t0) / 2];
    }

    private static function signedS(float $ms): string
    {
        return ($ms >= 0 ? '+' : '-') . self::toFixed(abs($ms) / 1000, 1) . ' s';
    }

    /**
     * Clock skew of the deployment against a reference (the Date headers of both, or this machine's clock). FAIL only when the skew is
     * beyond the limit even at the favourable end of the uncertainty interval; WARN when it is above the warning fraction or could be
     * beyond the limit.
     */
    public static function checkClock(mixed $cfg, callable $fetch, ?callable $now = null): array
    {
        $clock = $now ?? self::wallMs(...);
        $url = self::g($cfg, 'url');
        if (!Jsx::truthy($url)) {
            return self::res('clock', 'skip', 'no deployment URL given (--url)');
        }
        $cc = self::g($cfg, 'clock');
        $maxSkew = Jsx::toNum(self::nn(self::g($cc, 'maxSkewMs'), Pca::MAX_SKEW_MS));
        $warnAt = $maxSkew * Jsx::toNum(self::nn(self::g($cc, 'warnFraction'), 0.25));
        $timeout = Jsx::toNum(self::nn(self::g($cc, 'timeoutMs'), 10000));
        $dep = self::readDate(self::s($url), $fetch, $clock, $timeout);
        if (array_key_exists('error', $dep)) {
            return self::res('clock', 'warn', "cannot observe the deployment's clock at " . self::s($url) . ': ' . $dep['error'],
                "Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. " . self::CLOCK_REMEDIATION);
        }
        $refUrl = self::s(self::nn(self::g($cc, 'referenceUrl'), self::DEFAULT_REFERENCE_URL));
        $ref = ['offsetMs' => 0.0, 'uncertaintyMs' => 0.0];
        $refName = "this machine's clock";
        $refNote = '';
        if ($refUrl !== 'local') {
            $r = self::readDate($refUrl, $fetch, $clock, $timeout);
            if (array_key_exists('error', $r)) {
                $refNote = " (reference $refUrl unusable: " . $r['error'] . "; compared with this machine's clock instead)";
            } else {
                $ref = $r;
                $refName = $refUrl;
            }
        }
        $skew = $dep['offsetMs'] - $ref['offsetMs'];
        $unc = $dep['uncertaintyMs'] + $ref['uncertaintyMs'];
        $lower = abs($skew) - $unc;
        $upper = abs($skew) + $unc;
        $status = $lower > $maxSkew ? 'fail' : (abs($skew) > $warnAt || $upper > $maxSkew ? 'warn' : 'pass');
        $detail = 'deployment clock ' . self::signedS((float)$skew) . ' relative to ' . $refName . $refNote . ' (+-' . self::toFixed((float)$unc / 1000, 1)
            . ' s: Date has 1 s resolution, plus round trips); fail beyond ' . self::numStr($maxSkew / 1000) . ' s, warn above ' . self::numStr($warnAt / 1000)
            . ' s. The Date header is written by whatever answers the request (a CDN or proxy may set it).';
        return self::res('clock', $status, $detail, $status === 'pass' ? null : self::CLOCK_REMEDIATION,
            ['skewMs' => $skew, 'uncertaintyMs' => $unc, 'maxSkewMs' => $maxSkew, 'warnAtMs' => $warnAt, 'reference' => $refName]);
    }

    // ---- proxy --------------------------------------------------------------------------------------------------------------

    /** The stated TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER against the stated number of appending proxies. */
    public static function checkProxyConfig(mixed $cfg): array
    {
        $p = self::g($cfg, 'proxy');
        $n = self::g($p, 'trustedProxyCount');
        if ($n instanceof Undef) {
            return self::res('proxy.config', 'skip', 'TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)');
        }
        $header = self::nn(self::g($p, 'header'), 'x-forwarded-for');
        $hs = self::s($header);
        $ns = self::s($n);
        $fail = static fn(string $detail): array => self::res('proxy.config', 'fail', $detail, self::PROXY_REMEDIATION);
        if (!self::isInteger($n) || (float)Js::num($n) < 0 || self::negZero($n) || (float)Js::num($n) > 16) {
            return $fail("TRUSTED_PROXY_COUNT=$ns is not an integer in 0..16");
        }
        $nf = (float)Js::num($n);
        if ($header === 'x-real-ip' && $nf == 0.0) {
            return $fail('TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)');
        }
        $hops = self::g($p, 'hops');
        if ($hops instanceof Undef) {
            return self::res('proxy.config', $nf == 0.0 ? 'pass' : 'warn',
                "TRUSTED_PROXY_COUNT=$ns ($hs); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared",
                $nf == 0.0 ? null : self::PROXY_REMEDIATION);
        }
        $hp = self::s($hops);
        $h = Jsx::toNum($hops);
        if ($nf > $h) {
            return $fail("TRUSTED_PROXY_COUNT=$ns is larger than the $hp proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra $hs entries");
        }
        if ($nf < $h) {
            return self::res('proxy.config', 'warn', "TRUSTED_PROXY_COUNT=$ns is smaller than the $hp proxies in front of the API: clients are keyed by a proxy's address and share its bucket",
                self::PROXY_REMEDIATION);
        }
        return self::res('proxy.config', 'pass', "TRUSTED_PROXY_COUNT=$ns ($hs) matches the stated $hp appending proxies");
    }

    /** A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client. */
    public static function testNetIp(?callable $rand = null): string
    {
        $r = $rand ?? self::random(...);
        $net = $r() < 0.5 ? '198.51.100' : '203.0.113';
        return $net . '.' . (1 + (int)floor($r() * 254));
    }

    private static function random(): float
    {
        return random_int(0, 0xFFFFFFF) / 268435456.0;
    }

    /** Forged values for all three forwarding headers at once (the server trusts at most one of them). @return array<string,string> */
    public static function forgedHeaders(?callable $rand = null): array
    {
        $r = $rand ?? self::random(...);
        $chain = [];
        for ($i = 0; $i < 17; $i++) {
            $chain[] = self::testNetIp($r);
        }
        return ['x-forwarded-for' => implode(', ', $chain), 'forwarded' => implode(', ', array_map(static fn(string $ip): string => 'for=' . $ip, $chain)),
            'x-real-ip' => self::testNetIp($r)];
    }

    private static function remaining(callable $fetch, string $url, array $headers, float $timeoutMs): ?float
    {
        $r = $fetch($url, 'GET', $headers, $timeoutMs);
        $v = $r['headers']['ratelimit-remaining'] ?? null;
        $n = $v === null ? NAN : IntentWb::jsNumber((string)$v);
        return is_finite($n) ? $n : null;
    }

    /**
     * `new URL(path, base).href` for the shapes a probe path takes (absolute URL, rooted path, relative path).
     * shortcut: userinfo, fragment and a query-only relative path are not carried; upgrade if a probe path needs them.
     */
    private static function href(string $path, string $base): string
    {
        $b = WhatwgUrl::parse($base);
        if ($b === null) {
            throw new DoctorError('Invalid URL', 'ERR_INVALID_URL');
        }
        if (preg_match('/\A[A-Za-z][A-Za-z0-9+.\-]*:/', $path) === 1) {
            $abs = $path;
        } elseif (str_starts_with($path, '//')) {
            $abs = $b['scheme'] . ':' . $path;
        } elseif ($path !== '' && $path[0] === '/') {
            $abs = $b['scheme'] . '://' . $b['host'] . $path;
        } elseif ($path === '') {
            $abs = $b['htu'] . ($b['search'] ?? '');
        } else {
            $dir = substr($b['pathname'], 0, (int)strrpos($b['pathname'], '/') + 1);
            $abs = $b['scheme'] . '://' . $b['host'] . $dir . $path;
        }
        $u = WhatwgUrl::parse($abs);
        if ($u === null) {
            throw new DoctorError('Invalid URL', 'ERR_INVALID_URL');
        }
        return $u['htu'] . ($u['search'] ?? '');
    }

    /**
     * Forged forwarding headers sent to a public rate-limited path, watching RateLimit-Remaining: a forged request that lands in a
     * FRESH bucket while plain requests keep draining one bucket means client-written entries are trusted. A count that is too LOW is
     * not observable from one vantage point.
     */
    public static function checkProxyProbe(mixed $cfg, callable $fetch, ?callable $rand = null): array
    {
        $id = 'proxy.probe';
        $url = self::g($cfg, 'url');
        if (!Jsx::truthy($url)) {
            return self::res($id, 'skip', 'no deployment URL given (--url)');
        }
        $proxy = self::g($cfg, 'proxy');
        if (self::g($proxy, 'probe') === false) {
            return self::res($id, 'skip', 'disabled (--no-probe)');
        }
        $target = self::href(self::s(self::nn(self::g($proxy, 'probePath'), '/v1/pca/suites')), self::s($url));
        $t = Jsx::toNum(self::nn(self::g(self::g($cfg, 'clock'), 'timeoutMs'), 10000));
        try {
            $a = self::remaining($fetch, $target, [], $t);
            $b = self::remaining($fetch, $target, [], $t);
            $f = self::remaining($fetch, $target, self::forgedHeaders($rand), $t);
            $c = self::remaining($fetch, $target, [], $t);
        } catch (\Throwable $e) {
            return self::res($id, 'warn', "probe request to $target failed: " . $e->getMessage(),
                'Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.');
        }
        $observed = ['url' => $target, 'remaining' => [$a, $b, $f, $c]];
        if ($a === null || $b === null || $f === null || $c === null) {
            return self::res($id, 'skip', "not observable remotely: $target does not return a RateLimit-Remaining header on every response", null, $observed);
        }
        [$sa, $sb, $sf, $sc] = [self::numStr($a), self::numStr($b), self::numStr($f), self::numStr($c)];
        if (!($b < $a && $c < $b)) {
            return self::res($id, 'warn', "inconclusive: the plain requests' bucket did not drain monotonically ($sa, $sb, then $sc): a window rollover, a shared bucket or concurrent traffic. Re-run.",
                null, $observed);
        }
        if ($f > $b) {
            return self::res($id, 'fail', "a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining $sf, while the plain requests' bucket was at $sb): the deployment trusts client-written forwarding entries",
                self::PROXY_REMEDIATION, $observed);
        }
        return self::res($id, 'pass', "forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining $sa, $sb, forged $sf, $sc). A count that is too LOW is not observable from one client.",
            null, $observed);
    }

    // ---- suites -------------------------------------------------------------------------------------------------------------

    private static function isPq(mixed $alg): bool
    {
        return is_string($alg) && $alg !== 'ed25519' && in_array($alg, Pca::REGISTERED_SUITES, true);
    }

    /** allowedSuites against the closed suite registry (the library's registered suite names, in registry order). @param ?list<string> $registry */
    public static function checkAllowedSuites(mixed $cfg, ?array $registry = null): array
    {
        $registry ??= Pca::REGISTERED_SUITES;
        $id = 'suites.allowed';
        $v = self::g($cfg, 'verifier');
        if (!Jsx::truthy($v)) {
            return self::res($id, 'skip', 'no verifier configuration given (config verifier.*)');
        }
        $lst = self::g($v, 'allowedSuites');
        $known = implode(', ', $registry);
        if ($lst instanceof Undef) {
            return self::res($id, 'warn', 'allowedSuites is unset: every registered suite is accepted (' . count($registry) . ": $known)", self::SUITES_REMEDIATION);
        }
        if (!self::isList($lst) || $lst === []) {
            return self::res($id, 'fail', 'allowedSuites is empty or not a list: no PCActn can verify', self::SUITES_REMEDIATION);
        }
        $unknown = array_values(array_filter($lst, static fn($s): bool => !is_string($s) || !in_array($s, $registry, true)));
        if ($unknown !== []) {
            return self::res($id, 'fail', 'allowedSuites names suite(s) outside the registry: ' . implode(', ', array_map(self::s(...), $unknown)) . " (known: $known)",
                self::SUITES_REMEDIATION);
        }
        return self::res($id, 'pass', 'allowedSuites = ' . implode(', ', $lst));
    }

    /** allowUnboundPq / pqPins / trustedRoot sanity. */
    public static function checkPqBinding(mixed $cfg): array
    {
        $id = 'suites.pq-binding';
        $v = self::g($cfg, 'verifier');
        if (!Jsx::truthy($v)) {
            return self::res($id, 'skip', 'no verifier configuration given (config verifier.*)');
        }
        $fail = static fn(string $detail): array => self::res($id, 'fail', $detail, self::PQ_REMEDIATION);
        if (self::g($v, 'allowUnboundPq') === true) {
            return $fail('allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key');
        }
        $pins = self::g($v, 'pqPins');
        $pinCount = 0;
        if (!($pins instanceof Undef)) {
            if (!self::isDict($pins)) {
                return $fail('pqPins is not an object of { ed25519 identity: pq public key }');
            }
            $bad = [];
            foreach (self::keysOf($pins) as $k) {
                $val = self::g($pins, $k);
                if (preg_match(self::ED25519_ID, $k) !== 1 || !is_string($val) || preg_match(self::B64U, $val) !== 1) {
                    $bad[] = $k;
                }
            }
            if ($bad !== []) {
                return $fail('pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): ' . implode(', ', $bad));
            }
            $pinCount = count(self::keysOf($pins));
        }
        $allowed = self::nn(self::g($v, 'allowedSuites'), Pca::REGISTERED_SUITES);
        if (!self::isList($allowed)) {
            throw new \TypeError('allowedSuites.filter is not a function');
        }
        $pq = array_values(array_filter($allowed, self::isPq(...)));
        if ($pq === []) {
            return self::res($id, 'pass', 'no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)');
        }
        $pinned = $pinCount > 0;
        if (!$pinned && self::g($v, 'trustedRoot') !== true) {
            return self::res($id, 'warn', 'post-quantum suite(s) accepted (' . implode(', ', $pq) . ') with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned',
                self::PQ_REMEDIATION);
        }
        return self::res($id, 'pass', 'PQ suites (' . implode(', ', $pq) . ') are bound: ' . ($pinned ? "$pinCount pin(s)" : 'stored trustedRoot') . '; allowUnboundPq off');
    }

    // ---- root caveats and enforcement ---------------------------------------------------------------------------------------

    /** -1 / 0 / 1 for a < b / = / > over major.minor.patch (pre-release tags ignored); NaN parts compare as -1. */
    public static function compareVersion(string $a, string $b): int
    {
        $pa = array_map(IntentWb::jsNumber(...), array_slice((array)preg_split('/[.+\-]/', $a), 0, 3));
        $pb = array_map(IntentWb::jsNumber(...), array_slice((array)preg_split('/[.+\-]/', $b), 0, 3));
        for ($i = 0; $i < 3; $i++) {
            $x = $i < count($pa) && is_finite($pa[$i]) ? $pa[$i] : -1;
            $y = $i < count($pb) && is_finite($pb[$i]) ? $pb[$i] : -1;
            if ($x != $y) {
                return $x < $y ? -1 : 1;
            }
        }
        return 0;
    }

    private const PROBE_CODE = <<<'PHPCODE'
require getenv('PCA_DOCTOR_AUTOLOAD');
[$cv, $amount] = json_decode((string)getenv('PCA_DOCTOR_PROBE'), true);
$num = static fn($x) => is_int($x) || is_float($x) ? new \Atlas\Pca\Num((string)$x) : $x;
$r = \Atlas\Pca\Pca::evaluateCaveats([\Atlas\Pca\Obj::of(array_map($num, $cv))], \Atlas\Pca\Obj::of([
    'now' => $num((int)(microtime(true) * 1000)),
    'action' => \Atlas\Pca\Obj::of(['verb' => 'pay', 'resource' => 'invoice:42', 'reversibility_class' => 'reversible',
        'params' => \Atlas\Pca\Obj::of(['amount' => $num($amount), 'currency' => 'usd'])]),
]));
echo json_encode(['allowed' => $r['ok'] === true, 'reasons' => array_map('strval', $r['failed'])]);
PHPCODE;

    /**
     * Decide a payment of `$amount` USD under a root grant carrying `$rootCaveat` (the reference's probeDecision): {allowed, reasons}. The payment is
     * evaluated through this library's own caveat evaluation.
     *
     * @param array<string,mixed> $rootCaveat
     * @return array{allowed:bool,reasons:list<string>}
     */
    public static function probeDecision(array $rootCaveat, int|float $amount): array
    {
        return self::probeInProcess($rootCaveat, $amount);
    }

    /** A payment of $amount USD under a root caveat, through the loaded library's caveat evaluation. */
    private static function probeInProcess(array $rootCaveat, int|float $amount): array
    {
        $num = static fn($x) => is_int($x) || is_float($x) ? new Num((string)$x) : $x;
        $r = Pca::evaluateCaveats([Obj::of(array_map($num, $rootCaveat))], Obj::of([
            'now' => $num((int)self::wallMs()),
            'action' => Obj::of(['verb' => 'pay', 'resource' => 'invoice:42', 'reversibility_class' => 'reversible',
                'params' => Obj::of(['amount' => $num($amount), 'currency' => 'usd'])]),
        ]));
        return ['allowed' => $r['ok'] === true, 'reasons' => array_map('strval', $r['failed'])];
    }

    /**
     * The library to probe: this process's own, or (with a directory) the copy Composer installed under it, probed in a child
     * interpreter so the two never mix. Throws when none is installed there.
     */
    public static function loadPca(?string $directory = null): DoctorPca
    {
        if ($directory === null || $directory === '') {
            $v = class_exists(\Composer\InstalledVersions::class) && \Composer\InstalledVersions::isInstalled('atlas-auth/atlas-pca')
                ? (string)\Composer\InstalledVersions::getPrettyVersion('atlas-auth/atlas-pca') : 'unknown';
            return new DoctorPca($v, dirname(__DIR__), self::probeInProcess(...));
        }
        $root = (string)realpath($directory);
        $autoload = $root . '/vendor/autoload.php';
        $installed = $root . '/vendor/composer/installed.json';
        if ($root === '' || !is_file($autoload) || !is_file($installed)) {
            throw new \RuntimeException("atlas-auth/atlas-pca is not installed in $directory (no vendor/autoload.php)");
        }
        $doc = json_decode((string)file_get_contents($installed), true);
        $version = null;
        foreach (is_array($doc) ? ($doc['packages'] ?? $doc) : [] as $pkg) {
            if (is_array($pkg) && ($pkg['name'] ?? null) === 'atlas-auth/atlas-pca') {
                $version = ltrim((string)($pkg['version'] ?? 'unknown'), 'v');
            }
        }
        if ($version === null) {
            throw new \RuntimeException("atlas-auth/atlas-pca is not installed in $directory");
        }
        $probe = static function (array $cv, int|float $amount) use ($autoload): array {
            $p = proc_open([PHP_BINARY, '-d', 'display_errors=0', '-r', self::PROBE_CODE], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null,
                array_merge((array)getenv(), ['PCA_DOCTOR_AUTOLOAD' => $autoload, 'PCA_DOCTOR_PROBE' => (string)json_encode([$cv, $amount])]));
            if (!is_resource($p)) {
                throw new \RuntimeException('probe failed');
            }
            $out = (string)stream_get_contents($pipes[1]);
            $err = trim((string)stream_get_contents($pipes[2]));
            fclose($pipes[1]);
            fclose($pipes[2]);
            if (proc_close($p) !== 0) {
                $lines = explode("\n", $err);
                throw new \RuntimeException($err === '' ? 'probe failed' : end($lines));
            }
            $d = json_decode($out, true);
            if (!is_array($d)) {
                throw new \RuntimeException('probe failed');
            }
            return $d;
        };
        return new DoctorPca($version, $root . '/vendor/atlas-auth/atlas-pca', $probe);
    }

    /** @return array{allowed:bool,reasons:list<string>} */
    private static function decision(mixed $raw): array
    {
        $isObj = self::isDict($raw);
        $reasons = $isObj ? self::g($raw, 'reasons') : Jsx::$U;
        return ['allowed' => $isObj && self::g($raw, 'allowed') === true,
            'reasons' => self::isList($reasons) ? array_map(self::s(...), $reasons) : []];
    }

    /**
     * Root-caveat enforcement (0.4.1 security fix): the deployed library must be >= 0.4.1, and a functional probe through THAT
     * library must show a root max_spend of 100 denying 150 and allowing 50, and an unknown root caveat type denying (fail closed).
     */
    public static function checkRootCaveats(mixed $cfg, ?callable $load = null): array
    {
        $id = 'caveats.root';
        $d = self::g(self::g($cfg, 'verifier'), 'pcaDir');
        $pcaDir = Jsx::truthy($d) ? self::s($d) : null;
        try {
            $pca = ($load ?? self::loadPca(...))($pcaDir);
        } catch (\Throwable $e) {
            return self::res($id, 'fail', 'cannot load @atlasauth/pca' . ($pcaDir !== null ? " from $pcaDir" : '') . ': ' . $e->getMessage(), self::CAVEAT_REMEDIATION);
        }
        $where = "@atlasauth/pca {$pca->version} at {$pca->path}";
        if (self::compareVersion($pca->version, self::ROOT_CAVEAT_MIN_VERSION) < 0) {
            return self::res($id, 'fail', "$where: root caveats outside the envelope are NOT enforced before " . self::ROOT_CAVEAT_MIN_VERSION . ' (legacy behaviour)', self::CAVEAT_REMEDIATION);
        }
        try {
            $over = self::decision(($pca->probe)(['type' => 'max_spend', 'usd' => 100], 150));
            $under = self::decision(($pca->probe)(['type' => 'max_spend', 'usd' => 100], 50));
            $unknown = self::decision(($pca->probe)(['type' => 'pca-doctor-unknown-caveat'], 50));
        } catch (\Throwable $e) {
            return self::res($id, 'fail', "$where: the enforcement probe could not run: " . $e->getMessage(), self::CAVEAT_REMEDIATION);
        }
        $observed = ['version' => $pca->version, 'over' => $over, 'under' => $under, 'unknown' => $unknown];
        if ($over['allowed'] || $unknown['allowed']) {
            return self::res($id, 'fail', "$where: a root caveat was NOT enforced (" . ($over['allowed'] ? 'max_spend 100 allowed a 150 payment' : 'an unknown root caveat type was allowed') . ')',
                self::CAVEAT_REMEDIATION, $observed);
        }
        if (!$under['allowed']) {
            return self::res($id, 'warn', "$where: inconclusive: the control payment within the root max_spend was denied too (" . implode('; ', $under['reasons']) . ')', null, $observed);
        }
        return self::res($id, 'pass', "$where: root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)", null, $observed);
    }

    /** requirePCA must not run with insecureAllowUnenforced, and a custom `require` list should keep the defaults. */
    public static function checkEnforcement(mixed $cfg): array
    {
        $id = 'verifier.enforcement';
        $v = self::g($cfg, 'verifier');
        if (!Jsx::truthy($v)) {
            return self::res($id, 'skip', 'no verifier configuration given (config verifier.*)');
        }
        if (self::g($v, 'insecureAllowUnenforced') === true) {
            return self::res($id, 'fail', 'requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny',
                'Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).');
        }
        $req = self::g($v, 'require');
        if (!($req instanceof Undef)) {
            if (self::isList($req)) {
                $missing = array_values(array_filter(self::DEFAULT_REQUIRED, static fn(string $c): bool => !in_array($c, $req, true)));
            } elseif (is_string($req)) { // String.prototype.includes: a substring test
                $missing = array_values(array_filter(self::DEFAULT_REQUIRED, static fn(string $c): bool => !str_contains($req, $c)));
            } else {
                throw new \TypeError('require.includes is not a function');
            }
            if ($missing !== []) {
                return self::res($id, 'warn', 'the require list drops default check(s): ' . implode(', ', $missing),
                    'Keep every default required check (' . implode(', ', self::DEFAULT_REQUIRED) . ') and add to it.');
            }
        }
        if (Jsx::truthy($req)) {
            if (!self::isList($req)) {
                throw new \TypeError('require.join is not a function');
            }
            return self::res($id, 'pass', 'require = ' . implode(', ', array_map(static fn($x): string => $x === null ? '' : self::s($x), $req)));
        }
        return self::res($id, 'pass', 'default required checks; insecureAllowUnenforced off');
    }

    // ---- what only makes sense for a PHP install -------------------------------------------------------------------------------

    /**
     * Which registered suites this PHP runtime can verify and which extensions back them. A suite named in verifier.allowedSuites that is
     * registered but not verifiable here is refused at verification time (fail closed): that is a warning here.
     */
    public static function checkRuntime(mixed $cfg = null): array
    {
        $avail = array_values(array_filter(Pca::REGISTERED_SUITES, static fn(string $s): bool => Pca::suiteAvailable($s)));
        $missing = array_values(array_diff(Pca::REGISTERED_SUITES, $avail));
        $extras = [];
        foreach (['sodium', 'openssl', 'gmp', 'intl', 'mbstring', 'ffi'] as $ext) {
            $extras[$ext] = extension_loaded($ext);
        }
        $observed = ['available' => $avail, 'unavailable' => $missing, 'extras' => $extras];
        $allowed = self::g(self::g($cfg, 'verifier'), 'allowedSuites');
        $dead = [];
        if (self::isList($allowed)) {
            foreach ($allowed as $s) {
                if (is_string($s) && in_array($s, $missing, true)) {
                    $dead[] = $s;
                }
            }
        }
        if ($dead !== []) {
            return self::res('suites.runtime', 'warn', 'allowedSuites names suite(s) this PHP runtime cannot verify (they are refused, fail closed): '
                . implode(', ', $dead) . '. Verifiable here: ' . implode(', ', $avail),
                'Build PHP against OpenSSL >= 3.5 (post-quantum suites), enable ext-ffi for the LESS suites, or drop the suite from allowedSuites.', $observed);
        }
        return self::res('suites.runtime', 'pass', 'verifiable in this runtime (' . count($avail) . ' of ' . count(Pca::REGISTERED_SUITES) . ' registered suites): '
            . implode(', ', $avail), null, $observed);
    }

    // ---- the replay store ---------------------------------------------------------------------------------------------------

    /**
     * Replay / counter store checks. The concurrent-conflict and durability probes need a store adapter driven by the conformance kit
     * of the runtime that owns the store, so they are injected: `$store(cfg)` returns the results. With no adapter configured both
     * checks are skipped; with one configured and nothing injected they FAIL (a configured check that did not run is never a pass).
     * @return list<array>
     */
    public static function checkStore(mixed $cfg, ?callable $store = null): array
    {
        $spec = self::g(self::g($cfg, 'store'), 'adapter');
        if (!Jsx::truthy($spec)) {
            $detail = 'no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely';
            return [self::res('store.atomicity', 'skip', $detail), self::res('store.durability', 'skip', $detail)];
        }
        if ($store === null) {
            $detail = 'a store adapter is configured (' . self::s($spec) . ') but this runtime has no store check injected (deps[\'store\']): the store was NOT exercised';
            return [self::res('store.atomicity', 'fail', $detail, self::ATOMICITY_REMEDIATION), self::res('store.durability', 'fail', $detail, self::DURABILITY_REMEDIATION)];
        }
        return array_values($store($cfg));
    }

    // ---- configuration ------------------------------------------------------------------------------------------------------

    /** The scheme of `$u` when it parses as an absolute URL, else null (the reference's `new URL` throws). */
    private static function validScheme(mixed $u): ?string
    {
        $p = WhatwgUrl::parse($u);
        return $p === null ? null : $p['scheme'];
    }

    /** Numeric settings that would make a check meaningless (NaN, negative, zero where a duration is needed) are configuration errors. @return list<string> */
    public static function configProblems(mixed $cfg): array
    {
        $out = [];
        $pos = static function (string $name, mixed $v, bool $integer = false) use (&$out): void {
            if ($v instanceof Undef) {
                return;
            }
            if (!Js::isNum($v) || !is_finite((float)Js::num($v)) || (float)Js::num($v) <= 0 || ($integer && !self::isInteger($v))) {
                $out[] = "$name must be a positive " . ($integer ? 'integer' : 'number');
            }
        };
        $nonneg = static function (string $name, mixed $v) use (&$out): void {
            if ($v instanceof Undef) {
                return;
            }
            if (!Js::isNum($v) || !self::isInteger($v) || (float)Js::num($v) < 0 || self::negZero($v)) {
                $out[] = "$name must be a non-negative integer";
            }
        };
        $clock = self::g($cfg, 'clock');
        $store = self::g($cfg, 'store');
        $proxy = self::g($cfg, 'proxy');
        $pos('clock.maxSkewMs', self::g($clock, 'maxSkewMs'));
        $pos('clock.timeoutMs', self::g($clock, 'timeoutMs'));
        $wf = self::g($clock, 'warnFraction');
        if (!($wf instanceof Undef) && !(Js::isNum($wf) && (float)Js::num($wf) > 0 && (float)Js::num($wf) <= 1)) {
            $out[] = 'clock.warnFraction must be a number in (0, 1]';
        }
        $pos('store.concurrency', self::g($store, 'concurrency'), true);
        $pos('store.rounds', self::g($store, 'rounds'), true);
        $nonneg('proxy.trustedProxyCount', self::g($proxy, 'trustedProxyCount'));
        $nonneg('proxy.hops', self::g($proxy, 'hops'));
        $url = self::g($cfg, 'url');
        if (!($url instanceof Undef)) {
            $scheme = self::validScheme($url);
            if ($scheme === null) {
                $out[] = 'url is not a valid URL';
            } elseif ($scheme !== 'http' && $scheme !== 'https') {
                $out[] = 'url must be an http(s) URL';
            }
        }
        return $out;
    }

    /**
     * Run the selected check groups (all by default) and scrub everything they report. An invalid configuration is reported as
     * `config` failures and nothing else runs. A group that raises is a failed check, not a crashed run and not a skipped one.
     * `$deps`: fetch, now, load (see the class comment), store (see checkStore).
     * @param ?list<string> $only @return list<array>
     */
    public static function runDoctor(mixed $cfg, ?array $only = null, array $deps = []): array
    {
        $sel = $only === null ? self::CHECK_GROUPS : array_values($only);
        $problems = self::configProblems($cfg);
        if ($problems !== []) {
            return array_map(static fn(string $p): array => self::res('config', 'fail', self::scrubText("invalid configuration: $p"), 'Correct the setting; no check was run.'), $problems);
        }
        $fetch = $deps['fetch'] ?? self::defaultFetch(...);
        $now = $deps['now'] ?? null;
        $out = [];
        $guarded = static function (string $id, callable $run) use (&$out): void {
            try {
                $r = $run();
                foreach (self::isList($r) ? $r : [$r] as $x) {
                    $out[] = $x;
                }
            } catch (\Throwable $e) {
                $out[] = self::res($id, 'fail', "$id could not run: " . self::scrubText($e->getMessage()), 'Fix the configuration or the dependency named above and run the doctor again.');
            }
        };
        if (in_array('clock', $sel, true)) {
            $guarded('clock', static fn() => self::checkClock($cfg, $fetch, $now));
        }
        if (in_array('store', $sel, true)) {
            $guarded('store', static fn() => self::checkStore($cfg, $deps['store'] ?? null));
        }
        if (in_array('proxy', $sel, true)) {
            $guarded('proxy.config', static fn() => self::checkProxyConfig($cfg));
            $guarded('proxy.probe', static fn() => self::checkProxyProbe($cfg, $fetch));
        }
        if (in_array('suites', $sel, true)) {
            $guarded('suites.allowed', static fn() => self::checkAllowedSuites($cfg));
            $guarded('suites.pq', static fn() => self::checkPqBinding($cfg));
        }
        if (in_array('caveats', $sel, true)) {
            $guarded('caveats.root', static fn() => self::checkRootCaveats($cfg, $deps['load'] ?? null));
            $guarded('caveats.enforcement', static fn() => self::checkEnforcement($cfg));
        }
        // nothing the doctor prints may carry a credential from the deployment URL, an adapter option or an error message
        return array_map(static fn(array $r) => self::scrubDeep($r), $out);
    }

    private static function statusOf(mixed $r): mixed
    {
        return self::g($r, 'status');
    }

    /**
     * fail if any check failed; warn if any warned (fail under strict); else pass. A run in which nothing was checked (no results,
     * or every result skipped) is a fail: a doctor that looked at nothing must not report a healthy deployment.
     * @param list<mixed> $results
     */
    public static function verdictOf(array $results, bool $strict = false): string
    {
        $any = static function (callable $p) use ($results): bool {
            foreach ($results as $r) {
                if ($p(self::statusOf($r))) {
                    return true;
                }
            }
            return false;
        };
        if (!$any(static fn($s): bool => $s !== 'skip')) {
            return 'fail';
        }
        if ($any(static fn($s): bool => $s === 'fail')) {
            return 'fail';
        }
        if ($any(static fn($s): bool => $s === 'warn')) {
            return $strict ? 'fail' : 'warn';
        }
        return 'pass';
    }

    /** @param list<mixed> $results */
    public static function formatResults(array $results, mixed $target = null, bool $strict = false): string
    {
        $lines = ['pca-doctor' . (Jsx::truthy($target) ? ': ' . self::s($target) : '')];
        foreach ($results as $r) {
            $lines[] = '  ' . self::padEnd(strtoupper(self::s(self::statusOf($r))), 4) . '  ' . self::padEnd(self::s(self::g($r, 'id')), 20) . ' ' . self::s(self::g($r, 'detail'));
            if (Jsx::truthy(self::g($r, 'remediation'))) {
                $lines[] = '  ' . str_repeat(' ', 4) . '  ' . str_repeat(' ', 20) . ' fix: ' . self::s(self::g($r, 'remediation'));
            }
        }
        $n = static function (string $s) use ($results): int {
            return count(array_filter($results, static fn($r): bool => self::statusOf($r) === $s));
        };
        $checked = false;
        foreach ($results as $r) {
            $checked = $checked || self::statusOf($r) !== 'skip';
        }
        if (!$checked) {
            $lines[] = '  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified';
        }
        $lines[] = 'Summary: ' . $n('pass') . ' pass, ' . $n('warn') . ' warn, ' . $n('fail') . ' fail, ' . $n('skip') . ' skip -> ' . strtoupper(self::verdictOf($results, $strict));
        return implode("\n", $lines);
    }

    /** A non-negative integer environment value; an unset or empty one is absent (null). */
    private static function envInt(string $name, ?string $v): int|float|null
    {
        if ($v === null || $v === '') {
            return null;
        }
        $n = IntentWb::jsNumber($v);
        if (!self::isInteger($n) || $n < 0 || self::negZero($n)) {
            throw new DoctorError("$name must be a non-negative integer");
        }
        return abs($n) < 9.0e15 ? (int)$n : $n;
    }

    private static function envGet(mixed $env, string $k): ?string
    {
        $v = $env instanceof Obj ? ($env->has($k) ? $env->get($k) : null) : (is_array($env) ? ($env[$k] ?? null) : null);
        return is_string($v) ? $v : null;
    }

    /** The deployment's own environment variable names (as the API and the guides use them). @param Obj|array<string,string> $env */
    public static function configFromEnv(mixed $env): Obj
    {
        $e = static fn(string $k): ?string => self::envGet($env, $k);
        $c = new Obj();
        if (($v = $e('PCA_DOCTOR_URL')) !== null && $v !== '') {
            $c->set('url', $v);
        }
        if (($v = $e('PCA_DOCTOR_REFERENCE_URL')) !== null && $v !== '') {
            $c->set('clock', Obj::of(['referenceUrl' => $v]));
        }
        if (($v = $e('PCA_DOCTOR_STORE')) !== null && $v !== '') {
            $c->set('store', Obj::of(['adapter' => $v]));
        }
        $proxy = new Obj();
        $touched = false;
        if (($v = $e('TRUSTED_PROXY_COUNT')) !== null) {
            $touched = true;
            $n = self::envInt('TRUSTED_PROXY_COUNT', $v);
            if ($n !== null) {
                $proxy->set('trustedProxyCount', $n);
            }
        }
        if (($v = $e('TRUSTED_PROXY_HEADER')) !== null && $v !== '') {
            $touched = true;
            $h = strtolower($v);
            if (!in_array($h, self::PROXY_HEADERS, true)) {
                throw new DoctorError('TRUSTED_PROXY_HEADER must be one of ' . implode(', ', self::PROXY_HEADERS));
            }
            $proxy->set('header', $h);
        }
        if (($v = $e('PCA_TRUSTED_PROXY_HOPS')) !== null) {
            $touched = true;
            $n = self::envInt('PCA_TRUSTED_PROXY_HOPS', $v);
            if ($n !== null) {
                $proxy->set('hops', $n);
            }
        }
        if ($touched) {
            $c->set('proxy', $proxy);
        }
        $verifier = new Obj();
        if (($v = $e('PCA_ALLOWED_SUITES')) !== null) {
            $verifier->set('allowedSuites', array_values(array_filter(array_map(self::jsTrim(...), explode(',', $v)), static fn(string $t): bool => $t !== '')));
        }
        if (($v = $e('PCA_PQ_PINS')) !== null && $v !== '') {
            try {
                $pins = Js::parse($v);
            } catch (\Throwable) {
                throw new DoctorError('PCA_PQ_PINS is not valid JSON'); // never echo the value
            }
            $ok = $pins instanceof Obj;
            foreach (($ok ? $pins->keys() : []) as $k) {
                $ok = $ok && is_string($pins->get($k));
            }
            if (!$ok) {
                throw new DoctorError('PCA_PQ_PINS must be a JSON object of issuer -> public key strings');
            }
            $verifier->set('pqPins', $pins);
        }
        if (($v = $e('PCA_ALLOW_UNBOUND_PQ')) !== null) {
            $verifier->set('allowUnboundPq', preg_match('/\A(?:1|true|yes|on)\z/i', $v) === 1);
        }
        if ($verifier->keys() !== []) {
            $c->set('verifier', $verifier);
        }
        return $c;
    }

    /** Two-level merge: later sources win per field inside each section. */
    public static function mergeConfig(mixed ...$cs): Obj
    {
        $out = new Obj();
        foreach ($cs as $c0) {
            $c = self::toModel($c0);
            foreach (Jsx::keys($c) as $k) {
                if ($k === '__proto__' || $k === 'constructor' || $k === 'prototype') {
                    throw new DoctorError("config key \"$k\" is not allowed");
                }
                $val = Jsx::get($c, $k);
                if ($val instanceof Obj) {
                    $merged = Jsx::spread(self::nn($out->get($k), new Obj()));
                    foreach ($val->keys() as $vk) {
                        $merged->set($vk, $val->get($vk));
                    }
                    $out->set($k, $merged);
                } else {
                    $out->set($k, $val);
                }
            }
        }
        return $out;
    }

    /** A JSON file, or a PHP file that returns the config (an array or Obj). */
    public static function loadConfigFile(string $path): mixed
    {
        if (str_ends_with($path, '.json')) {
            $text = @file_get_contents($path);
            if ($text === false) {
                throw new DoctorError("cannot read $path");
            }
            return Js::parse($text);
        }
        if (str_ends_with($path, '.php')) {
            $cfg = (static function () use ($path) {
                return require $path;
            })();
            if (!(is_array($cfg) || $cfg instanceof Obj)) {
                throw new DoctorError("$path: defines no config");
            }
            return self::toModel($cfg);
        }
        throw new DoctorError("only a .json or .php config file can be loaded: $path");
    }

    // ---- CLI ----------------------------------------------------------------------------------------------------------------

    /** @return list<string> */
    private static function groups(string $flag, ?string $v): array
    {
        $g = array_values(array_filter(explode(',', $v ?? ''), static fn(string $x): bool => $x !== ''));
        $bad = array_values(array_filter($g, static fn(string $x): bool => !in_array($x, self::CHECK_GROUPS, true)));
        if ($bad !== [] || $g === []) {
            throw new DoctorError("$flag: unknown check group(s) " . ($bad !== [] ? implode(', ', $bad) : '(none given)'));
        }
        return $g;
    }

    private static function numArg(string $flag, ?string $v): int|float
    {
        $n = $v === null || $v === '' ? NAN : IntentWb::jsNumber($v);
        if (!is_finite($n)) {
            throw new DoctorError("$flag needs a number");
        }
        return $n == floor($n) && abs($n) < 9007199254740992.0 ? (int)$n : $n;
    }

    /** The parsed command line: {flags (a config), only, json, strict, help, config?}. @param list<string> $argv */
    public static function parseDoctorArgs(array $argv): Obj
    {
        $argv = array_values($argv);
        $f = new Obj();
        $only = self::CHECK_GROUPS;
        $json = false;
        $strict = false;
        $help = false;
        $config = null;
        $i = 0;
        $n = count($argv);
        $sub = static function (string $name) use (&$f): Obj {
            $d = $f->get($name);
            if (!($d instanceof Obj)) {
                $d = new Obj();
                $f->set($name, $d);
            }
            return $d;
        };
        $nxt = static function () use (&$i, $argv, $n): ?string {
            $i++;
            return $i < $n ? (string)$argv[$i] : null;
        };
        // `d.key = v` where an undefined value leaves the member absent
        $set = static function (?string $section, string $key, ?string $v) use (&$f, $sub): void {
            $d = $section === null ? $f : $sub($section);
            if ($v !== null) {
                $d->set($key, $v);
            } elseif ($d->has($key)) {
                if ($section === null) {
                    $f = $d->without($key);
                } else {
                    $f->set($section, $d->without($key));
                }
            }
        };
        while ($i < $n) {
            $k = (string)$argv[$i];
            switch ($k) {
                case '--url':
                    $set(null, 'url', $nxt());
                    break;
                case '--config':
                    $config = $nxt();
                    break;
                case '--store':
                    $set('store', 'adapter', $nxt());
                    break;
                case '--store-option':
                    $kv = $nxt() ?? '';
                    $eq = strpos($kv, '=');
                    if ($eq === false || $eq < 1) {
                        throw new DoctorError('--store-option needs k=v');
                    }
                    $st = $sub('store');
                    $opts = $st->get('options');
                    $opts = $opts instanceof Obj ? $opts : new Obj();
                    $opts->set(substr($kv, 0, $eq), substr($kv, $eq + 1));
                    $st->set('options', $opts);
                    break;
                case '--reference':
                    $set('clock', 'referenceUrl', $nxt());
                    break;
                case '--max-skew-ms':
                    $sub('clock')->set('maxSkewMs', self::numArg($k, $nxt()));
                    break;
                case '--trusted-proxy-count':
                    $sub('proxy')->set('trustedProxyCount', self::numArg($k, $nxt()));
                    break;
                case '--proxy-header':
                    $h = strtolower($nxt() ?? '');
                    if (!in_array($h, self::PROXY_HEADERS, true)) {
                        throw new DoctorError('--proxy-header must be x-forwarded-for, forwarded or x-real-ip');
                    }
                    $sub('proxy')->set('header', $h);
                    break;
                case '--proxy-hops':
                    $sub('proxy')->set('hops', self::numArg($k, $nxt()));
                    break;
                case '--no-probe':
                    $sub('proxy')->set('probe', false);
                    break;
                case '--pca-dir':
                    $set('verifier', 'pcaDir', $nxt());
                    break;
                case '--only':
                    $only = self::groups($k, $nxt());
                    break;
                case '--skip':
                    $skip = self::groups($k, $nxt());
                    $only = array_values(array_filter($only, static fn(string $g): bool => !in_array($g, $skip, true)));
                    break;
                case '--strict':
                    $strict = true;
                    break;
                case '--json':
                    $json = true;
                    break;
                case '-h':
                case '--help':
                    $help = true;
                    break;
                default:
                    throw new DoctorError("unknown argument $k");
            }
            $i++;
        }
        $a = Obj::of(['flags' => $f, 'only' => $only, 'json' => $json, 'strict' => $strict, 'help' => $help]);
        if ($config !== null) {
            $a->set('config', $config);
        }
        return $a;
    }

    /** `JSON.stringify(v, null, 2)` over the parsed-JSON model (assoc arrays are objects). */
    private static function stringify(mixed $v, string $ind = ''): string
    {
        if ($v === null || $v instanceof Undef) {
            return 'null';
        }
        if (!($v instanceof Obj || is_array($v))) {
            return Js::stringify($v);
        }
        $inner = $ind . '  ';
        if (self::isList($v) || $v === []) {
            return $v === [] ? '[]' : "[\n" . implode(",\n", array_map(fn($x) => $inner . self::stringify($x, $inner), $v)) . "\n" . $ind . ']';
        }
        $items = [];
        foreach (self::keysOf($v) as $k) {
            $x = self::g($v, $k);
            if (!($x instanceof Undef)) {
                $items[] = $inner . Json::lenientStr($k) . ': ' . self::stringify($x, $inner);
            }
        }
        return $items === [] ? '{}' : "{\n" . implode(",\n", $items) . "\n" . $ind . '}';
    }

    /**
     * Run the CLI: exit code 1 on any fail (and on warn with --strict), 2 on usage errors, else 0. `$env` is an Obj or an array
     * (default: the process environment); `$out` / `$err` receive the printed text (default: stdout / stderr); `$deps` are
     * runDoctor's.
     * @param list<string> $argv
     */
    public static function main(array $argv, mixed $env = null, ?callable $out = null, ?callable $err = null, array $deps = []): int
    {
        $out ??= static function (string $s): void {
            echo $s, "\n";
        };
        $err ??= static function (string $s): void {
            fwrite(STDERR, $s . "\n");
        };
        try {
            $a = self::parseDoctorArgs($argv);
            if ($a->get('help') === true) {
                $out(self::USAGE);
                return 0;
            }
            $file = $a->has('config') ? self::loadConfigFile((string)$a->get('config')) : new Obj();
            $cfg = self::mergeConfig($file, self::configFromEnv($env ?? getenv()), $a->get('flags'));
        } catch (\Throwable $e) {
            $err(self::scrubText($e->getMessage()) . "\n\n" . self::USAGE);
            return 2;
        }
        $results = self::runDoctor($cfg, $a->get('only'), $deps);
        $verdict = self::verdictOf($results, $a->get('strict') === true);
        $url = self::g($cfg, 'url');
        if ($a->get('json') === true) {
            $out(self::stringify(['target' => $url instanceof Undef ? null : $url, 'verdict' => $verdict, 'results' => $results]));
        } else {
            $out(self::formatResults($results, Jsx::truthy($url) ? self::s($url) : null, $a->get('strict') === true));
        }
        return $verdict === 'fail' ? 1 : 0;
    }
}
