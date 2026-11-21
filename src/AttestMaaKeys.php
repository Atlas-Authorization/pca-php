<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Attest/Cert.php';
require_once __DIR__ . '/Attest/Common.php';
require_once __DIR__ . '/Attest/Der.php';
require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/AttestAllowlist.php';
require_once __DIR__ . '/AttestMaaPins.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\PubKey;

/** The caller's persistence of the accepted key sets: `get` returns the stored value or null, `set` stores a state. */
interface MaaKeyStateStore
{
    public function get(string $issuer): mixed;

    public function set(string $issuer, mixed $state): void;
}

/** An in-memory store (tests, one process). */
final class MemoryMaaKeyStateStore implements MaaKeyStateStore
{
    /** @var array<string,mixed> */
    private array $m = [];

    public function __construct(mixed $initial = [])
    {
        foreach ($initial as $k => $v) {
            $this->m[(string)$k] = $v;
        }
    }

    public function get(string $issuer): mixed
    {
        return $this->m[$issuer] ?? null;
    }

    public function set(string $issuer, mixed $state): void
    {
        $this->m[$issuer] = $state;
    }

    /** @return array<string,mixed> */
    public function snapshot(): array
    {
        return $this->m;
    }
}

/**
 * The accepted key sets in an {@see AtomicKv} under `maa-keys/<issuer>`, monotone in `fetchedAtMs`: a stale writer never moves the stored
 * state backwards. A corrupt stored record is returned as is (so the trust fails closed) and overwritten by the next valid state.
 */
final class DurableMaaKeyStateStore implements MaaKeyStateStore
{
    public function __construct(private readonly AtomicKv $kv)
    {
    }

    public function get(string $issuer): mixed
    {
        $t = $this->kv->get("maa-keys/$issuer");
        return $t === null ? null : Json::parseLax($t);
    }

    public function set(string $issuer, mixed $state): void
    {
        $this->kv->update("maa-keys/$issuer", static function (?string $prev) use ($issuer, $state): ?string {
            $p = $prev === null ? null : AttestMaaKeys::parseState(Json::parseLax($prev), $issuer);
            $f = Jsx::get($state, 'fetchedAtMs');
            return $p !== null && Js::isNum($f) && $p['fetchedAtMs'] > Js::num($f) ? null : Json::canonicalizeLenient($state);
        });
    }
}

/**
 * The rotation-safe trust in Azure MAA token-signing keys: a guarded certs fetch (https issuers pinned in the policy, no redirects, a size
 * limit; the transport is injected and owns the timeout), the validation of every JWKS key (self-signed instance certificates whose subject is
 * exactly `CN=<issuer>`, or Microsoft-chained keys under pinned roots / intermediates), the persisted accepted set that may only change by
 * rotation (or under an operator-signed re-pin manifest), and multi-vantage corroboration of a first-use set.
 */
final class AttestMaaKeys
{
    private const HOUR = 3600000;
    private const DAY = 86400000;
    private const MAX_JWKS_KEYS = 32;
    private const MAX_X5C = 8;
    private const MAX_X5C_B64 = 131072;
    private const EC_CURVES = ['prime256v1', 'secp384r1', 'secp521r1'];

    public static function isIssuerUrl(mixed $s): bool
    {
        return is_string($s) && preg_match('/\Ahttps:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?\z/', $s) === 1;
    }

    private static function isSafeInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0;
    }

    private static function negZero(mixed $x): bool
    {
        $f = Js::num($x);
        return $f === 0.0 && fdiv(1.0, $f) < 0;
    }

    /** The finite number of an optional policy member, or the default. */
    private static function numOr(mixed $v, float $default): float
    {
        return $v instanceof Undef || $v === null ? $default : (Js::num($v) ?? NAN);
    }

    // ---- guarded fetch -------------------------------------------------------------------------------------------------------

    /**
     * Fetch `<issuer>/certs`: https only, the transport called with `redirect: error`, the response URL checked, a declared size over the limit
     * refused before reading, the body capped. Throws on any problem. `$opts`: `{fetch: callable(string $url, Obj $init): Obj, timeoutMs?, maxBytes?}`;
     * the response is `{status, url?, contentLength?, body (raw bytes)}`.
     * @return Obj `{keys: [{kid?, kty?, alg?, x5c}]}`
     */
    public static function fetchCerts(mixed $issuer, mixed $opts): Obj
    {
        $fetch = Jsx::get($opts, 'fetch');
        if (!is_callable($fetch)) {
            throw new \TypeError('fetchMaaCerts: a fetch implementation must be injected');
        }
        if (!self::isIssuerUrl($issuer)) {
            throw new \TypeError('fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)');
        }
        $timeout = Jsx::get($opts, 'timeoutMs');
        $max = Jsx::get($opts, 'maxBytes');
        $maxBytes = $max instanceof Undef || $max === null ? 1048576.0 : (float)Js::num($max);
        $url = "$issuer/certs";
        $res = $fetch($url, Obj::of(['redirect' => 'error', 'timeoutMs' => $timeout instanceof Undef || $timeout === null ? 10000 : $timeout,
            'headers' => Obj::of(['accept' => 'application/json'])]));
        $status = Js::num(Jsx::get($res, 'status'));
        if ($status === null || $status < 200 || $status > 299) {
            throw new \RuntimeException('MAA certs fetch failed: HTTP ' . Jsx::str(Jsx::get($res, 'status')));
        }
        $ru = Jsx::get($res, 'url');
        if (Jsx::truthy($ru) && $ru !== $url) {
            throw new \RuntimeException('MAA certs fetch: response URL differs from the request (redirect)');
        }
        $cl = Jsx::get($res, 'contentLength');
        $declared = $cl instanceof Undef || $cl === null ? 0.0 : Jsx::toNum(is_string($cl) ? $cl : Jsx::str($cl));
        if (is_finite($declared) && $declared > $maxBytes) {
            throw new \RuntimeException('MAA certs response exceeds the size limit');
        }
        $body = Jsx::get($res, 'body');
        $body = is_string($body) ? $body : '';
        if ((float)strlen($body) > $maxBytes) {
            throw new \RuntimeException('MAA certs response exceeds the size limit');
        }
        if (str_starts_with($body, "\xEF\xBB\xBF")) {
            $body = substr($body, 3);
        }
        try {
            if (preg_match('//u', $body) !== 1) {
                throw new \RuntimeException('invalid UTF-8');
            }
            $parsed = Js::parse($body);
        } catch (\Throwable) {
            throw new \RuntimeException('MAA certs response is not valid UTF-8 JSON');
        }
        return self::parseJwks($parsed);
    }

    private static function parseJwks(mixed $x): Obj
    {
        $raw = Jsx::get($x, 'keys');
        if (!($x instanceof Obj) || !is_array($raw) || !array_is_list($raw)) {
            throw new \RuntimeException('MAA certs: response has no keys array');
        }
        if (count($raw) > self::MAX_JWKS_KEYS) {
            throw new \RuntimeException('MAA certs: too many keys');
        }
        $keys = [];
        foreach ($raw as $k) {
            if (!($k instanceof Obj) && !(is_array($k))) {
                throw new \RuntimeException('MAA certs: malformed key entry');
            }
            $x5c = Jsx::get($k, 'x5c');
            $bad = !is_array($x5c) || !array_is_list($x5c) || count($x5c) === 0 || count($x5c) > self::MAX_X5C;
            foreach ($bad ? [] : $x5c as $c) {
                $bad = $bad || !is_string($c) || $c === '' || strlen($c) > self::MAX_X5C_B64;
            }
            if ($bad) {
                throw new \RuntimeException('MAA certs: key without a well-formed x5c');
            }
            $o = new Obj();
            foreach (['kid', 'kty', 'alg'] as $f) {
                if (is_string(Jsx::get($k, $f))) {
                    $o->set($f, Jsx::get($k, $f));
                }
            }
            $o->set('x5c', $x5c);
            $keys[] = $o;
        }
        return Obj::of(['keys' => $keys]);
    }

    // ---- JWKS evaluation -----------------------------------------------------------------------------------------------------

    private static function parseCert(mixed $b64): Cert
    {
        if (!is_string($b64)) {
            throw new \TypeError('The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received '
                . (Js::isNum($b64) ? 'type number (' . Jsx::str($b64) . ')' : 'an instance of ' . (is_array($b64) ? 'Array' : 'Object')));
        }
        $der = Common::nodeB64Decode($b64);
        if ($der === '' || $der[0] !== "\x30") { // the reference wraps the bytes as PEM: not even a DER SEQUENCE is "no start line"
            throw new \RuntimeException('error:0480006C:PEM routines::no start line');
        }
        try {
            return new Cert($der);
        } catch (\Throwable $e) {
            // the reference wraps the bytes as PEM: bytes that are not even a DER SEQUENCE fail as "no start line"
            throw new \RuntimeException($der === '' || $der[0] !== "\x30" ? 'error:0480006C:PEM routines::no start line' : $e->getMessage());
        }
    }

    /** The subject CN when the subject is exactly one CN RDN line (a line terminator in it does not match, as in the reference). */
    private static function soleCn(string $subject): ?string
    {
        $lines = array_values(array_filter(explode("\n", $subject), static fn(string $l): bool => $l !== ''));
        if (count($lines) !== 1 || !str_starts_with($lines[0], 'CN=')) {
            return null;
        }
        $cn = substr($lines[0], 3);
        return preg_match('/[\r\n]|\xE2\x80[\xA8\xA9]/', $cn) === 1 ? null : $cn;
    }

    private static function leafCn(string $subject): ?string
    {
        foreach (explode("\n", $subject) as $l) {
            if (str_starts_with($l, 'CN=')) {
                return substr($l, 3);
            }
        }
        return null;
    }

    private static function rsaOk(PubKey $k): bool
    {
        return $k->type !== 'rsa' || Common::rsaKeyOk($k->rsaN, $k->rsaE);
    }

    private static function safeVerify(Cert $c, PubKey $k): bool
    {
        try {
            return self::rsaOk($k) && $c->verify($k);
        } catch (\Throwable) {
            return false;
        }
    }

    private static function keyStrengthError(Cert $c): ?string
    {
        $k = $c->publicKey();
        if ($k->type === 'rsa' && Common::isRsaPss($k)) {
            return "key type 'rsa-pss' not allowed";
        }
        if ($k->type === 'rsa') {
            $bits = $k->bits();
            if (!($bits >= 2048 && $bits <= 8192)) {
                return "RSA key size $bits outside 2048..8192";
            }
            return Common::rsaKeyOk($k->rsaN, $k->rsaE) ? null : 'RSA public exponent must be odd, at least 3 and at most 32 bits';
        }
        if ($k->type === 'ec') {
            $curve = $k->curve ?? '';
            return in_array($curve, self::EC_CURVES, true) ? null : "EC curve '$curve' not allowed";
        }
        return "key type '$k->type' not allowed";
    }

    /** @return array{0:int,1:int} */
    private static function validity(Cert $c, int $j): array
    {
        [$lo, $hi] = Der::derValidityMs($c->raw);
        if ($lo === null || $hi === null) {
            // the reference's X.509 parser refuses a certificate whose validity does not parse before any validity check runs: its library error is the reason
            throw new \Atlas\Pca\Attest\CertError('error:0688010A:asn1 encoding routines::nested asn1 error (cert ' . $j . ': unparsable validity)');
        }
        return [$lo, $hi];
    }

    /**
     * Validate every key of a JWKS against the policy at `$nowMs`. @param mixed $policy a MaaKeyPolicy (`clockSkewMs`, `maxKeyAgeMs`,
     * `chainRootSpkiSha256`, `chainIntermediateSpkiSha256`, `chainLeafCn`, ...)
     * @return array{accepted:list<array<string,mixed>>,rejected:list<array<string,mixed>>}
     */
    public static function evaluateJwks(mixed $jwks, mixed $issuer, mixed $policy, mixed $nowMs): array
    {
        $now = (float)Js::num($nowMs);
        $skew = self::numOr(Jsx::get($policy, 'clockSkewMs'), 60000.0);
        $maxAge = self::numOr(Jsx::get($policy, 'maxKeyAgeMs'), 400.0 * self::DAY);
        $lower = static function (mixed $v): array {
            $out = [];
            foreach (is_array($v) ? $v : [] as $s) {
                $out[strtolower((string)$s)] = true;
            }
            return $out;
        };
        $roots = $lower(Jsx::get($policy, 'chainRootSpkiSha256'));
        $inters = $lower(Jsx::get($policy, 'chainIntermediateSpkiSha256'));
        $leafCns = Jsx::get($policy, 'chainLeafCn');
        $keys = Jsx::get($jwks, 'keys');
        if ($keys instanceof Undef || $keys === null) {
            $keys = [];
        }
        if (!is_array($keys) || !array_is_list($keys)) {
            throw new \TypeError('(jwks?.keys ?? []).entries is not a function');
        }
        $accepted = [];
        $rejected = [];
        foreach ($keys as $i => $key) {
            $kidV = Jsx::rd($key, 'kid');
            $kid = $kidV instanceof Undef || $kidV === null ? "#$i" : $kidV;
            try {
                if (!is_finite($now) || !is_finite($skew)) {
                    throw new \RuntimeException('clock and skew must be finite');
                }
                $x5c = Jsx::get($key, 'x5c');
                if (!is_array($x5c) || !array_is_list($x5c) || count($x5c) === 0) {
                    $rejected[] = ['kid' => $kid, 'reason' => 'no x5c'];
                    continue;
                }
                $certs = array_map(self::parseCert(...), $x5c);
                $leaf = $certs[0];
                foreach ($certs as $j => $c) {
                    [$from, $to] = self::validity($c, $j);
                    if (!($now + $skew >= $from)) {
                        throw new \RuntimeException("cert $j: not yet valid");
                    }
                    if (!($now - $skew <= $to)) {
                        throw new \RuntimeException("cert $j: expired");
                    }
                }
                [$lvFrom, $lvTo] = self::validity($leaf, 0);
                $strength = self::keyStrengthError($leaf);
                if ($strength !== null) {
                    throw new \RuntimeException($strength);
                }
                if (count($certs) === 1) {
                    if (!($now - $lvFrom <= $maxAge)) {
                        throw new \RuntimeException('key older than maxKeyAgeMs');
                    }
                    $cn = self::soleCn($leaf->subject());
                    if ($cn === null) {
                        throw new \RuntimeException('subject is not a single CN');
                    }
                    if (str_contains($cn, '*')) {
                        throw new \RuntimeException('wildcard CN rejected');
                    }
                    if ($cn !== $issuer) {
                        throw new \RuntimeException('subject CN does not equal the issuer URL');
                    }
                    if ($leaf->issuer() !== $leaf->subject() || !self::safeVerify($leaf, $leaf->publicKey())) {
                        throw new \RuntimeException('not a genuine self-signed cert');
                    }
                    $spki = $leaf->spkiSha256();
                    $accepted['k' . $spki] = ['spki' => $spki, 'kind' => 'self-signed', 'notBeforeMs' => $lvFrom, 'notAfterMs' => $lvTo];
                    continue;
                }
                if ($roots === []) {
                    throw new \RuntimeException('chained key ignored (no chainRootSpkiSha256 configured)');
                }
                for ($j = 0; $j < count($certs) - 1; $j++) {
                    if (!self::safeVerify($certs[$j], $certs[$j + 1]->publicKey())) {
                        throw new \RuntimeException("chain link $j is not signed by the next cert");
                    }
                }
                $profile = Der::strictChainError(array_map(static fn(Cert $c): string => $c->raw, $certs));
                if ($profile !== null) {
                    throw new \RuntimeException("chain profile: $profile");
                }
                $top = $certs[count($certs) - 1];
                if ($top->issuer() !== $top->subject() || !self::safeVerify($top, $top->publicKey())) {
                    throw new \RuntimeException('chain does not end in a self-signed root');
                }
                $rootSpki = $top->spkiSha256();
                if (!isset($roots[$rootSpki])) {
                    throw new \RuntimeException('chain root is not pinned');
                }
                if (Jsx::truthy($leafCns) && !in_array(self::leafCn($leaf->subject()) ?? "\0", is_array($leafCns) ? $leafCns : [], true)) {
                    throw new \RuntimeException('chained leaf CN not allowed');
                }
                [$aFrom, $aTo] = self::validity($top, count($certs) - 1);
                $anchorSpki = $rootSpki;
                $kind = 'chained-root';
                if ($inters !== []) {
                    $mid = null;
                    foreach (array_slice($certs, 1, -1) as $c) {
                        if (isset($inters[$c->spkiSha256()])) {
                            $mid = $c;
                            break;
                        }
                    }
                    if ($mid === null) {
                        throw new \RuntimeException('chain does not pass through a pinned intermediate');
                    }
                    [$aFrom, $aTo] = self::validity($mid, 0);
                    $anchorSpki = $mid->spkiSha256();
                    $kind = 'chained-intermediate';
                }
                $prev = $accepted['k' . $anchorSpki] ?? null;
                $accepted['k' . $anchorSpki] = ['spki' => $anchorSpki, 'kind' => $kind,
                    'notBeforeMs' => $prev !== null ? min($prev['notBeforeMs'], $aFrom) : $aFrom,
                    'notAfterMs' => min($aTo, max($prev['notAfterMs'] ?? 0, $lvTo))];
            } catch (\Throwable $e) {
                $rejected[] = ['kid' => $kid, 'reason' => $e->getMessage()];
            }
        }
        return ['accepted' => array_values($accepted), 'rejected' => $rejected];
    }

    // ---- persisted state -----------------------------------------------------------------------------------------------------

    /** The validated state `{v: 1, issuer, fetchedAtMs, anchors}` of a stored value, or null. @return array<string,mixed>|null */
    public static function parseState(mixed $x, string $issuer): ?array
    {
        if (is_array($x) && !array_is_list($x)) {
            $x = Sign::n($x); // the state this store wrote itself, as native values
        }
        if (!($x instanceof Obj)) {
            return null;
        }
        $f = Jsx::get($x, 'fetchedAtMs');
        $anchors = Jsx::get($x, 'anchors');
        $v = Jsx::get($x, 'v');
        if (!(Js::isNum($v) && Js::num($v) === 1.0) || Jsx::get($x, 'issuer') !== $issuer || !self::isSafeInt($f) || self::negZero($f) || !is_array($anchors) || !array_is_list($anchors)) {
            return null;
        }
        $out = [];
        foreach ($anchors as $a) {
            if (!($a instanceof Obj)) {
                return null;
            }
            $spki = Jsx::get($a, 'spki');
            $kind = Jsx::get($a, 'kind');
            if (!is_string($spki) || preg_match('/\A[0-9a-f]{64}\z/', $spki) !== 1 || !in_array($kind, ['self-signed', 'chained-root', 'chained-intermediate'], true)) {
                return null;
            }
            foreach (['notBeforeMs', 'notAfterMs', 'firstSeenMs'] as $m) {
                $n = Jsx::get($a, $m);
                if (!self::isSafeInt($n) || self::negZero($n)) {
                    return null;
                }
            }
            $out[] = ['spki' => $spki, 'kind' => $kind, 'notBeforeMs' => (int)Js::num(Jsx::get($a, 'notBeforeMs')), 'notAfterMs' => (int)Js::num(Jsx::get($a, 'notAfterMs')),
                'firstSeenMs' => (int)Js::num(Jsx::get($a, 'firstSeenMs'))];
        }
        return ['v' => 1, 'issuer' => $issuer, 'fetchedAtMs' => (int)Js::num($f), 'anchors' => $out];
    }

    // ---- the trust store -----------------------------------------------------------------------------------------------------

    /**
     * Build the trust. `$opts`: `{policy: MaaKeyPolicy, store: MaaKeyStateStore, fetch: callable}`. The policy needs `trustedIssuers` (a non-empty list
     * of https origin URLs); `builtinPins` is `false` (off), absent / `true` (the shipped pins) or a signed source object.
     */
    public static function createTrust(mixed $opts): MaaKeyTrust
    {
        $policy = Jsx::get($opts, 'policy');
        $store = Jsx::get($opts, 'store');
        if (!is_callable(Jsx::get($opts, 'fetch'))) {
            throw new \TypeError('createMaaKeyTrust: fetch must be injected');
        }
        $ti = Jsx::get($policy, 'trustedIssuers');
        if (!is_array($ti) || !array_is_list($ti) || $ti === [] || array_filter($ti, static fn($i): bool => !self::isIssuerUrl($i)) !== []) {
            throw new \TypeError('createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs');
        }
        return new MaaKeyTrust($policy, $store, Jsx::get($opts, 'fetch'));
    }

    // ---- multi-vantage corroboration -----------------------------------------------------------------------------------------

    /**
     * Accept a first-use key set only if at least `$k` (>= 2) distinct vantage points observed the same issuer and every observation validates to
     * the IDENTICAL SPKI set. `$sets`: `[{vantage, issuer, jwks}]`; `$opts`: `{issuer, nowMs, policy?}`. Never throws.
     * @return array<string,mixed> `{ok: true, issuer, spkis, vantages, k}` or `{ok: false, code, reason}`
     */
    public static function corroborate(mixed $sets, mixed $k, mixed $opts): array
    {
        $bad = static fn(string $code, string $reason): array => ['ok' => false, 'code' => $code, 'reason' => $reason];
        try {
            if (!self::isSafeInt($k) || Js::num($k) < 2) {
                return $bad('malformed', 'k must be an integer >= 2');
            }
            $issuer = Jsx::get($opts, 'issuer');
            if (!self::isIssuerUrl($issuer) || !self::isSafeInt(Jsx::get($opts, 'nowMs'))) {
                return $bad('malformed', 'issuer/nowMs invalid');
            }
            if (!is_array($sets) || !array_is_list($sets)) {
                return $bad('malformed', 'sets must be an array');
            }
            $policy = Obj::of(['trustedIssuers' => [$issuer]]);
            foreach (Jsx::spread(Jsx::get($opts, 'policy'))->keys() as $pk) {
                $policy->set($pk, Jsx::get(Jsx::get($opts, 'policy'), $pk));
            }
            $by = [];
            foreach ($sets as $o) {
                $v = Jsx::get($o, 'vantage');
                if (!is_string($v) || $v === '' || Js::len($v) > 100) {
                    return $bad('malformed', 'vantage label must be a non-empty string');
                }
                if (Jsx::get($o, 'issuer') !== $issuer) {
                    return $bad('malformed', "observation from '$v' is for a different issuer");
                }
                $ev = self::evaluateJwks(Jsx::get($o, 'jwks'), $issuer, $policy, Jsx::get($opts, 'nowMs'));
                if ($ev['accepted'] === []) {
                    return $bad('no-valid-keys', "vantage '$v' observed no valid key (" . (implode('; ', array_map(static fn(array $r): string => Jsx::str($r['reason']), $ev['rejected'])) ?: 'empty') . ')');
                }
                $spkis = array_map(static fn(array $a): string => $a['spki'], $ev['accepted']);
                sort($spkis, SORT_STRING);
                $fp = implode(',', $spkis);
                if (isset($by['k' . $v]) && $by['k' . $v][1] !== $fp) {
                    return $bad('vantage-disagreement', "vantage '$v' supplied two different key sets");
                }
                $by['k' . $v] = [$v, $fp];
            }
            if (count($by) < (int)Js::num($k)) {
                return $bad('insufficient-vantages', count($by) . ' distinct vantage(s) < k=' . Jsx::str($k));
            }
            $distinct = array_values(array_unique(array_map(static fn(array $e): string => $e[1], $by)));
            if (count($distinct) !== 1) {
                return $bad('vantage-disagreement', 'vantages disagree: ' . implode(' | ', array_map(static fn(array $e): string => $e[0] . '=' . implode('+', array_map(static fn(string $x): string => substr($x, 0, 8), explode(',', $e[1]))), array_values($by))));
            }
            $labels = array_map(static fn(array $e): string => $e[0], array_values($by));
            sort($labels, SORT_STRING);
            return ['ok' => true, 'issuer' => $issuer, 'spkis' => explode(',', $distinct[0]), 'vantages' => $labels, 'k' => $k];
        } catch (\Throwable $e) {
            return $bad('malformed', $e->getMessage() === '' ? 'corroboration error' : $e->getMessage());
        }
    }
}

/** The trust returned by {@see AttestMaaKeys::createTrust}. */
final class MaaKeyTrust
{
    private const HOUR = 3600000;
    private const DAY = 86400000;

    public function __construct(private readonly mixed $policy, private readonly mixed $store, private readonly mixed $fetch)
    {
        // an infinite or NaN window would admit every expired key or stale cache; a count or max-stale may be +Infinity (no cap) but never NaN
        $n = static fn(string $k, float $d): float => ($v = Jsx::get($policy, $k)) instanceof Undef || $v === null ? $d : (float)(Js::num($v) ?? NAN);
        if (!is_finite($n('ttlMs', self::HOUR)) || !is_finite($n('clockSkewMs', 60000)) || is_nan($n('maxStaleMs', self::DAY)) || is_nan($n('maxNewKeysPerFetch', 2)) || is_nan($n('maxInitialKeys', 8))) {
            throw new \TypeError('createMaaKeyTrust: ttlMs and clockSkewMs must be finite; maxStaleMs and the key-count limits must not be NaN');
        }
    }

    /** @return array<string,mixed> */
    private static function fail(string $code, string $reason): array
    {
        return ['ok' => false, 'code' => $code, 'reason' => $reason];
    }

    /**
     * The trust anchors (`trustAnchors.rootSpkiSha256`, sorted) for a pinned issuer at `$nowMs`: the fresh cache, else a fetch under the rotation
     * policy (at most `maxNewKeysPerFetch` unseen keys, an overlap with the previous set unless an operator re-pin or a built-in pin covers it,
     * a revoked key stripped), else the last accepted set for at most `maxStaleMs` when only the transport failed. `$repin`: `{manifest, verify}`.
     * @return array<string,mixed> `{ok: true, trustAnchors, source, anchors, newKeys, removedKeys, rejected}` or `{ok: false, code, reason}`
     */
    public function getTrustAnchors(mixed $issuer, mixed $nowMs, mixed $repin = null): array
    {
        $policy = $this->policy;
        $num = static fn(string $k, float $d): float => ($v = Jsx::get($policy, $k)) instanceof Undef || $v === null ? $d : (float)(Js::num($v) ?? NAN);
        $ttl = $num('ttlMs', self::HOUR);
        $maxStale = $num('maxStaleMs', self::DAY);
        $maxNew = $num('maxNewKeysPerFetch', 2);
        $maxInitial = $num('maxInitialKeys', 8);
        $skew = $num('clockSkewMs', 60000);
        $ro = Jsx::get($policy, 'requireOverlap');
        $requireOverlap = $ro instanceof Undef || $ro === null ? true : Jsx::truthy($ro);
        $live = static fn(array $a, float $now): array => array_values(array_filter($a, static fn(array $r): bool => $now - $skew <= $r['notAfterMs'] && $now + $skew >= $r['notBeforeMs']));
        $build = static function (string $source, array $anchors, array $newKeys, array $removed, array $rejected): array {
            $spkis = array_values(array_unique(array_map(static fn(array $a): string => $a['spki'], $anchors)));
            sort($spkis, SORT_STRING);
            if ($spkis === []) {
                return self::fail('no-valid-keys', 'no unexpired, un-revoked signing keys remain');
            }
            return ['ok' => true, 'trustAnchors' => Obj::of(['rootSpkiSha256' => $spkis]), 'source' => $source, 'anchors' => $anchors, 'newKeys' => $newKeys,
                'removedKeys' => $removed, 'rejected' => $rejected];
        };
        try {
            $trusted = Jsx::get($policy, 'trustedIssuers');
            if (!is_string($issuer) || !in_array($issuer, $trusted, true)) {
                return self::fail('untrusted-issuer', 'issuer is not in policy.trustedIssuers');
            }
            if (!Js::isNum($nowMs) || !is_finite(Js::num($nowMs)) || Js::num($nowMs) != floor(Js::num($nowMs)) || abs(Js::num($nowMs)) > 9007199254740991.0) {
                return self::fail('clock-regression', 'nowMs must be an integer');
            }
            $now = (float)Js::num($nowMs);
            $approved = [];
            $denied = [];
            if (Jsx::truthy($repin)) {
                $o = Jsx::spread(Jsx::get($repin, 'verify'));
                $o->set('nowMs', $nowMs);
                $v = AttestAllowlist::verify(Jsx::get($repin, 'manifest'), $o);
                if ($v['ok'] !== true) {
                    return self::fail('repin-invalid', $v['code'] . ': ' . $v['reason']);
                }
                $p = AttestAllowlist::project(Obj::of($v), Obj::of(['nowMs' => $nowMs]));
                foreach ($p['maaSigningSpkis']->has($issuer) ? $p['maaSigningSpkis']->get($issuer) : [] as $s) {
                    $approved[$s] = true;
                }
                foreach ($p['revoked'] as $r) {
                    if ($r->get('kind') === 'maa-signing-spki' && $r->get('label') === $issuer) {
                        $denied[$r->get('value')] = true;
                    }
                }
            }
            $effPolicy = $policy;
            $builtinBaseline = [];
            $builtinReason = null;
            $bp = Jsx::get($policy, 'builtinPins');
            if ($bp !== false) {
                $b = AttestMaaPins::load(Obj::of(['nowMs' => $nowMs] + ($bp instanceof Obj ? ['source' => $bp] : [])));
                if ($b['ok'] === true) {
                    $builtinBaseline = $b['maaSigningSpkis']->has($issuer) ? $b['maaSigningSpkis']->get($issuer) : [];
                    foreach ($b['revokedSigningSpkis']->has($issuer) ? $b['revokedSigningSpkis']->get($issuer) : [] as $r) {
                        $denied[$r] = true;
                    }
                    $effPolicy = Jsx::spread($policy);
                    foreach (['chainRootSpkiSha256' => $b['maaChainRootSpkis'], 'chainIntermediateSpkiSha256' => $b['maaChainIntermediateSpkis'], 'chainLeafCn' => AttestMaaPins::CHAIN_LEAF_CN] as $k => $dflt) {
                        $cur = Jsx::get($policy, $k);
                        $effPolicy->set($k, $cur instanceof Undef || $cur === null ? $dflt : $cur);
                    }
                    if ($builtinBaseline !== []) {
                        $builtinBaseline = [...$builtinBaseline, ...$b['maaChainIntermediateSpkis']];
                    }
                } else {
                    $builtinReason = $b['reason'];
                }
            }
            $allow = static fn(array $a): array => array_values(array_filter($a, static fn(array $r): bool => !isset($denied[$r['spki']])));

            $raw = $this->store->get($issuer);
            $state = null;
            if ($raw !== null) {
                $state = AttestMaaKeys::parseState($raw, $issuer);
                if ($state === null) {
                    return self::fail('corrupt-state', 'persisted MAA key state failed validation');
                }
                if (!($now >= $state['fetchedAtMs'] - $skew)) {
                    return self::fail('clock-regression', 'clock is behind the last persisted fetch time');
                }
            }

            if ($state !== null && $now - $state['fetchedAtMs'] < $ttl && $now >= $state['fetchedAtMs']) {
                $a = $allow($live($state['anchors'], $now));
                if ($a !== []) {
                    return $build('cache', $a, [], [], []);
                }
            }

            $fetchOpts = Obj::of(['fetch' => $this->fetch]);
            foreach (['fetchTimeoutMs' => 'timeoutMs', 'maxBodyBytes' => 'maxBytes'] as $from => $to) {
                $v = Jsx::get($policy, $from);
                if (!($v instanceof Undef)) {
                    $fetchOpts->set($to, $v);
                }
            }
            try {
                $jwks = AttestMaaKeys::fetchCerts($issuer, $fetchOpts);
            } catch (\Throwable $e) {
                $why = $e->getMessage();
                if ($state === null) {
                    return self::fail('fetch-failed', "$why; no cached key set");
                }
                if (!($now - $state['fetchedAtMs'] <= $maxStale)) {
                    return self::fail('stale-exceeded', "$why; cached set is older than maxStaleMs");
                }
                $a = $allow($live($state['anchors'], $now));
                if ($a === []) {
                    return self::fail('stale-exceeded', "$why; every cached key has expired or been revoked");
                }
                return $build('stale-cache', $a, [], [], []);
            }

            $ev = AttestMaaKeys::evaluateJwks($jwks, $issuer, $effPolicy, $nowMs);
            $accepted = array_values(array_filter($ev['accepted'], static fn(array $r): bool => !isset($denied[$r['spki']])));
            if ($accepted === []) {
                return self::fail('no-valid-keys', 'no JWKS key passed validation (' . (implode('; ', array_map(static fn(array $r): string => Jsx::str($r['kid']) . ': ' . $r['reason'], $ev['rejected'])) ?: 'empty JWKS') . ')');
            }

            $prevAnchors = $state !== null ? $live($state['anchors'], $now) : [];
            $baseline = [];
            foreach ($prevAnchors as $a) {
                $baseline[$a['spki']] = true;
            }
            if ($state === null) {
                $ip = Jsx::get(Jsx::get($policy, 'initialPins'), $issuer);
                foreach (is_array($ip) ? $ip : [] as $p) {
                    $baseline[strtolower((string)$p)] = true;
                }
                foreach ($builtinBaseline as $p) {
                    $baseline[$p] = true;
                }
            }
            foreach ($builtinBaseline as $p) {
                $approved[$p] = true;
            }
            $acceptedSet = [];
            foreach ($accepted as $a) {
                $acceptedSet[$a['spki']] = true;
            }
            $approvedHere = array_filter(array_keys($acceptedSet), static fn($s): bool => isset($approved[$s]));
            $unapprovedNew = array_filter(array_keys($acceptedSet), static fn($s): bool => !isset($baseline[$s]) && !isset($approved[$s]));
            if ($baseline === []) {
                if ($approvedHere === [] && !Jsx::truthy(Jsx::get($policy, 'allowTrustOnFirstUse'))) {
                    if ($builtinReason !== null) {
                        return self::fail('builtin-pins-invalid', "built-in pins unusable ($builtinReason); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use");
                    }
                    return self::fail('no-baseline', 'no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use');
                }
                if (count($acceptedSet) > $maxInitial && count($approvedHere) < count($acceptedSet)) {
                    return self::fail('too-many-new-keys', 'initial set of ' . count($acceptedSet) . ' keys exceeds maxInitialKeys');
                }
            } else {
                if (count($unapprovedNew) > $maxNew) {
                    return self::fail('too-many-new-keys', count($unapprovedNew) . ' new keys exceed maxNewKeysPerFetch=' . Jsx::str($maxNew));
                }
                $overlap = array_filter(array_keys($acceptedSet), static fn($s): bool => isset($baseline[$s])) !== [] || $approvedHere !== [];
                if ($requireOverlap && !$overlap) {
                    return self::fail('no-overlap', 'the new key set shares no key with the previous set and is not covered by a signed re-pin');
                }
            }

            $firstSeen = [];
            foreach ($state['anchors'] ?? [] as $a) {
                $firstSeen[$a['spki']] = $a['firstSeenMs'];
            }
            $records = array_map(static fn(array $a): array => $a + ['firstSeenMs' => $firstSeen[$a['spki']] ?? (int)$now], $accepted);
            $fetchedAt = $state !== null ? max($state['fetchedAtMs'], (int)$now) : (int)$now;
            $this->store->set($issuer, ['v' => 1, 'issuer' => $issuer, 'fetchedAtMs' => $fetchedAt, 'anchors' => $records]);
            $newKeys = array_values(array_map(static fn(array $r): string => $r['spki'], array_filter($records, static fn(array $r): bool => !isset($baseline[$r['spki']]))));
            $removed = array_values(array_filter(array_map('strval', array_keys($baseline)), static fn(string $s): bool => !isset($acceptedSet[$s])));
            return $build('fetched', $records, $newKeys, $removed, $ev['rejected']);
        } catch (\Throwable $e) {
            return self::fail('fetch-failed', $e->getMessage() === '' ? 'unexpected error' : $e->getMessage());
        }
    }
}
