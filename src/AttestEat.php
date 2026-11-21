<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Attest/Common.php';
require_once __DIR__ . '/Attest/Amd.php';

use Atlas\Pca\Attest\Amd;
use Atlas\Pca\Attest\Common;

/**
 * Per-session attestation freshness and channel binding for PCA (the TypeScript reference, @atlasauth/pca-attest-eat): emits attestation
 * evidence as an Entity Attestation Token (RFC 9711, a compact JWS with the `eat+jwt` typ), binds it to a live channel and a fresh nonce
 * (IETF SEAT / RA-TLS) and appraises it with the RATS (RFC 9334) split of evidence, reference values and endorsements into a trust tier.
 * The AMD SEV-SNP hardware root is delegated to Attest\Amd; this layer adds freshness, channel binding, EAT emission and appraisal, and
 * the AMD root stays a classical ECDSA/RSA chain (labelled, never upgraded).
 *
 * Options and results are Obj / assoc arrays with the reference's member names, so a claim set or verdict is JSON-identical to it.
 * Keys: EdDSA signs with a 32-byte Ed25519 seed and verifies with the 32 raw public-key bytes; ES256 signs with an OpenSSL P-256 private
 * key and verifies with a JWK (Obj) or OpenSSL public key (see Jose). The post-quantum co-signature of a verdict is {@see AttestCosign}; EAT
 * admission evidence, the runtime digest and the nonce are here. Not ported: the artifact discharge (it needs a Sigstore bundle verifier).
 */
final class AttestEat
{
    public const EAT_TYP = 'eat+jwt';
    public const DEFAULT_EAT_ALG = 'EdDSA';
    public const SUPPORTED_ALGS = ['EdDSA', 'ES256'];
    public const DEFAULT_MAX_AGE_MS = 300000;
    public const CHANNEL_BINDING_DOMAIN = 'atlas-pca/eat-channel/v1';
    public const AMD_SEV_SNP_SIGNED_REGION_END = 0x2A0;
    public const AMD_SEV_SNP_HARDWARE_ROOT_LABEL = "amd-sev-snp/ecdsa-p384 (VCEK\u{2192}ASK\u{2192}ARK; classical hardware root, not post-quantum)";
    public const KNOWN_REPORT_VERSIONS = [2, 3, 5];
    private const MAX_EAT_BYTES = 1 << 20;
    private const DEBUG_BIT = 1 << 19;
    private const DBGSTAT_VALUES = ['enabled', 'disabled', 'disabled-since-boot', 'disabled-permanently', 'disabled-fully-and-permanently'];
    private const TRUSTWORTHY = ['affirming-hw-rooted', 'affirming', 'warning'];

    // ---- JavaScript value semantics over the parsed-JSON model ---------------------------------------------------------------

    /** `o.k`: undefined for an absent member or a value without members; a TypeError on null / undefined (as JavaScript). */
    private static function g(mixed $o, string $k): mixed
    {
        if ($o === null || $o instanceof Undef) {
            throw new \TypeError("Cannot read properties of " . ($o === null ? 'null' : 'undefined') . " (reading '$k')");
        }
        if ($o instanceof Obj) {
            return $o->has($k) ? $o->get($k) : Jsx::$U;
        }
        if (is_array($o) && !array_is_list($o)) {
            return array_key_exists($k, $o) ? $o[$k] : Jsx::$U;
        }
        return Jsx::$U;
    }

    /** `o.k !== undefined` (an explicit null counts as defined). */
    private static function has(mixed $o, string $k): bool
    {
        return !(self::g($o, $k) instanceof Undef);
    }

    private static function undef(mixed $v): bool
    {
        return $v instanceof Undef;
    }

    private static function isNumber(mixed $v): bool
    {
        return ($v instanceof Num && is_finite($v->float())) || is_int($v) || (is_float($v) && is_finite($v));
    }

    private static function num(mixed $v): float
    {
        return $v instanceof Num ? $v->float() : (float)$v;
    }

    private static function nonEmptyStr(mixed $v): bool
    {
        return is_string($v) && $v !== '';
    }

    private static function jsString(mixed $v): string
    {
        if ($v instanceof Undef) {
            return 'undefined';
        }
        return $v === null ? 'null' : Common::jsStr($v); // Common reads null as undefined; here a JSON null is null
    }

    private static function strictEq(mixed $a, mixed $b): bool
    {
        if (self::isNumber($a) && self::isNumber($b)) {
            return self::num($a) == self::num($b);
        }
        if (is_string($a) && is_string($b)) {
            return $a === $b;
        }
        if (is_bool($a) || is_bool($b)) {
            return is_bool($a) && is_bool($b) && $a === $b;
        }
        return ($a === null && $b === null) || ($a instanceof Undef && $b instanceof Undef) || ($a === $b && is_object($a));
    }

    private static function includes(mixed $seq, mixed $v): bool
    {
        foreach ($seq as $x) {
            if (self::strictEq($x, $v)) {
                return true;
            }
        }
        return false;
    }

    private static function truthy(mixed $v): bool
    {
        return Jsx::truthy($v);
    }

    private static function ctEq(mixed $a, mixed $b): bool
    {
        if (!is_string($a) || !is_string($b)) {
            throw new \TypeError('the first argument must be of type string');
        }
        $x = Js::utf8($a);
        $y = Js::utf8($b);
        return strlen($x) === strlen($y) && hash_equals($x, $y);
    }

    private static function nowMs(): float
    {
        return floor(microtime(true) * 1000);
    }

    private static function numObj(int|float $n): Num
    {
        return new Num(is_float($n) ? IntentWb::jsStr($n) : (string)$n);
    }

    /** @param array<string,mixed> $m */
    private static function obj(array $m): Obj
    {
        $o = new Obj();
        foreach ($m as $k => $v) {
            $o->set((string)$k, $v);
        }
        return $o;
    }

    // ---- evidence projection ------------------------------------------------------------------------------------------------------

    /** Project a parsed SEV-SNP report (Amd::parseReport) into the JSON-safe evidence an EAT carries. */
    public static function evidenceFromReport(array $r): Obj
    {
        return self::obj(['version' => self::numObj($r['version']), 'measurement' => bin2hex($r['measurement']), 'reported_tcb' => gmp_strval($r['reported_tcb']),
            'guest_svn' => self::numObj($r['guest_svn']), 'chip_id' => bin2hex($r['chip_id']),
            'debug' => gmp_cmp(gmp_and($r['policy'], self::DEBUG_BIT), 0) !== 0]);
    }

    /** The measured identity of a report: runtime_measurement = hex(MEASUREMENT), operator = hex(CHIP_ID); no weights field. */
    public static function measuredFromReport(array $r): Obj
    {
        return self::obj(['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => bin2hex($r['measurement']),
            'operator' => bin2hex($r['chip_id'])]);
    }

    /**
     * Parse an SEV-SNP report across format versions, degrading to the version-stable header instead of raising. A known version with a
     * complete buffer gets the full parse (`report` + `evidence`, `degraded` false).
     */
    public static function parseReportTolerant(mixed $raw): Obj
    {
        $raw = $raw instanceof Bytes ? $raw->raw : $raw;
        if (!is_string($raw)) {
            return self::obj(['ok' => false, 'version' => self::numObj(0), 'known' => false, 'degraded' => true, 'notes' => ['input is not a Uint8Array']]);
        }
        $b = $raw;
        $notes = [];
        if (strlen($b) < 4) {
            return self::obj(['ok' => false, 'version' => self::numObj(0), 'known' => false, 'degraded' => true, 'notes' => ['buffer too short to read the report version']]);
        }
        $version = (int)unpack('V', $b, 0)[1];
        $known = in_array($version, self::KNOWN_REPORT_VERSIONS, true);
        $fullMin = 0x2E8 + 72;
        if ($known && strlen($b) >= $fullMin) {
            try {
                $report = Amd::parseReport($b);
                return self::obj(['ok' => true, 'version' => self::numObj($report['version']), 'known' => true, 'degraded' => false, 'notes' => $notes,
                    'hasReport' => true, 'evidence' => self::evidenceFromReport($report), 'report' => $report]);
            } catch (\Throwable $e) { // degrade, as the reference
                $notes[] = 'full parse failed, falling back to the stable header: ' . $e->getMessage();
            }
        } elseif (!$known) {
            $notes[] = "unknown report version $version \u{2014} parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)";
        } else {
            $notes[] = 'buffer length ' . strlen($b) . " < full report $fullMin \u{2014} degraded header-only parse";
        }
        if (strlen($b) < 0x090 + 48) {
            return self::obj(['ok' => false, 'version' => self::numObj($version), 'known' => $known, 'degraded' => true,
                'notes' => array_merge($notes, ['buffer too short to read the launch measurement'])]);
        }
        $ev = self::obj(['version' => self::numObj($version), 'measurement' => bin2hex(substr($b, 0x090, 48)), 'degraded' => true]);
        if (strlen($b) >= 0x004 + 4) {
            $ev->set('guest_svn', self::numObj((int)unpack('V', $b, 0x004)[1]));
        }
        if (strlen($b) >= 0x008 + 8) {
            $ev->set('debug', gmp_cmp(gmp_and(gmp_init(bin2hex(strrev(substr($b, 0x008, 8))), 16), self::DEBUG_BIT), 0) !== 0);
        }
        if (strlen($b) >= 0x180 + 8) {
            $ev->set('reported_tcb', gmp_strval(gmp_init(bin2hex(strrev(substr($b, 0x180, 8))), 16)));
        }
        if (strlen($b) >= 0x1A0 + 64) {
            $ev->set('chip_id', bin2hex(substr($b, 0x1A0, 64)));
        }
        return self::obj(['ok' => true, 'version' => self::numObj($version), 'known' => $known, 'degraded' => true, 'notes' => $notes, 'evidence' => $ev]);
    }

    // ---- channel binding -------------------------------------------------------------------------------------------------------------

    /** `cnf.tls_exporter` = b64u(sha256(DOMAIN || channelId)) (RA-TLS), plus `jkt` when a thumbprint is given. */
    public static function deriveChannelCnf(mixed $channelId, mixed $holderKeyThumbprint = null): Obj
    {
        if (!is_string($channelId) || $channelId === '') {
            throw new \InvalidArgumentException('deriveChannelCnf: channelId is required');
        }
        $cnf = self::obj(['tls_exporter' => Pca::b64u(hash('sha256', Js::utf8(self::CHANNEL_BINDING_DOMAIN) . Js::utf8($channelId), true))]);
        if (is_string($holderKeyThumbprint) && $holderKeyThumbprint !== '') {
            $cnf->set('jkt', $holderKeyThumbprint);
        }
        return $cnf;
    }

    /** Bind evidence to a TLS channel id and a per-session freshness nonce (the inputs of buildEat). */
    public static function bindChannel(mixed $evidence, mixed $channelId, mixed $nonce): Obj
    {
        if (!is_string($nonce) || $nonce === '') {
            throw new \InvalidArgumentException('bindChannel: a per-session nonce is required for freshness');
        }
        return self::obj(['evidence' => $evidence, 'nonce' => $nonce, 'cnf' => self::deriveChannelCnf($channelId)]);
    }

    // ---- build / verify ------------------------------------------------------------------------------------------------------------------

    private static function resolveCnf(mixed $args): Obj
    {
        $out = new Obj();
        if (self::has($args, 'channelId')) {
            $out->set('tls_exporter', self::deriveChannelCnf(self::g($args, 'channelId'))->get('tls_exporter'));
        }
        if (self::has($args, 'channelBinding')) {
            $cb = self::g($args, 'channelBinding');
            $te = self::g($cb, 'tls_exporter');
            $jkt = self::g($cb, 'jkt');
            if (is_string($te)) {
                $out->set('tls_exporter', $te);
            }
            if (is_string($jkt)) {
                $out->set('jkt', $jkt);
            }
        }
        return $out;
    }

    private static function isSupportedAlg(mixed $v): bool
    {
        return is_string($v) && in_array($v, self::SUPPORTED_ALGS, true);
    }

    private static function normalizeTyp(string $typ): string
    {
        $t = mb_strtolower($typ, 'UTF-8');
        return str_contains($t, '/') ? $t : 'application/' . $t;
    }

    /**
     * A signed EAT (compact JWS, typ `eat+jwt`) over the evidence: iss, iat, eat_nonce, cnf and the optional measured identity / sevsnp
     * evidence / measurements / ueid / sueid / dbgstat / oemid claims. It needs a nonce AND a channel binding: an unbound EAT would
     * re-open the replay gap. `key` is an Ed25519 seed (EdDSA) or an OpenSSL P-256 private key (ES256).
     */
    public static function buildEat(mixed $args): string
    {
        $issuer = self::g($args, 'issuer');
        $nonce = self::g($args, 'nonce');
        if (!self::nonEmptyStr($issuer)) {
            throw new \InvalidArgumentException('buildEAT: issuer is required');
        }
        if (!self::nonEmptyStr($nonce)) {
            throw new \InvalidArgumentException('buildEAT: nonce (eat_nonce) is required for freshness');
        }
        $alg = self::g($args, 'alg');
        $alg = $alg === null || $alg instanceof Undef ? self::DEFAULT_EAT_ALG : $alg;
        if (!self::isSupportedAlg($alg)) {
            throw new \InvalidArgumentException("buildEAT: unsupported alg '" . self::jsString($alg) . "'");
        }
        $cnf = self::resolveCnf($args);
        if (!$cnf->has('tls_exporter') && !$cnf->has('jkt')) {
            throw new \InvalidArgumentException("buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) \u{2014} refusing to emit unbound evidence");
        }
        $now = self::g($args, 'now');
        $iatMs = self::isNumber($now) ? self::num($now) : self::nowMs();
        $claims = self::obj(['iss' => $issuer, 'iat' => self::numObj((int)floor($iatMs / 1000)), 'eat_nonce' => $nonce, 'cnf' => $cnf]);
        foreach (['ueid', 'sueid', 'oemid', 'dbgstat', 'measurements', 'measured', 'sevsnp'] as $k) {
            if (self::has($args, $k)) {
                $claims->set($k, self::g($args, $k));
            }
        }
        $signingInput = Pca::b64u(Js::utf8(Js::stringify(self::obj(['alg' => $alg, 'typ' => self::EAT_TYP])))) . '.' . Pca::b64u(Js::utf8(Js::stringify($claims)));
        return $signingInput . '.' . Pca::b64u(Jose::jwsSign($alg, self::g($args, 'key') instanceof Undef ? null : self::g($args, 'key'), $signingInput, true));
    }

    private static function parseCnf(mixed $v): ?Obj
    {
        if (!($v instanceof Obj)) {
            return null;
        }
        $out = new Obj();
        if (is_string($v->get('tls_exporter'))) {
            $out->set('tls_exporter', $v->get('tls_exporter'));
        }
        if (is_string($v->get('jkt'))) {
            $out->set('jkt', $v->get('jkt'));
        }
        return $out->keys() === [] ? null : $out;
    }

    private static function parseMeasurements(mixed $v): ?array
    {
        if (!is_array($v) || !array_is_list($v)) {
            return null;
        }
        $out = [];
        foreach ($v as $e) {
            if ($e instanceof Obj && is_string($e->get('type')) && is_string($e->get('value'))) {
                $out[] = self::obj(['type' => $e->get('type'), 'value' => $e->get('value')]);
            }
        }
        return $out === [] ? null : $out;
    }

    private static function parseTcbVersion(mixed $v): mixed
    {
        if (self::isNumber($v) || is_string($v)) {
            return $v;
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach (['bootloader', 'tee', 'snp', 'microcode'] as $k) {
                if (self::isNumber($v->get($k))) {
                    $o->set($k, $v->get($k));
                }
            }
            return $o;
        }
        return Jsx::$U;
    }

    private static function parseMeasured(mixed $v): ?Obj
    {
        if (!($v instanceof Obj)) {
            return null;
        }
        foreach (['model_id', 'weights_digest', 'runtime_measurement', 'operator'] as $k) {
            if (!is_string($v->get($k))) {
                return null;
            }
        }
        $out = self::obj(['model_id' => $v->get('model_id'), 'weights_digest' => $v->get('weights_digest'),
            'runtime_measurement' => $v->get('runtime_measurement'), 'operator' => $v->get('operator')]);
        if (is_bool($v->get('weights_measured'))) {
            $out->set('weights_measured', $v->get('weights_measured'));
        }
        foreach (['system_prompt_digest', 'tool_manifest_digest'] as $k) {
            if (is_string($v->get($k))) {
                $out->set($k, $v->get($k));
            }
        }
        return $out;
    }

    private static function parseSevsnp(mixed $v): ?Obj
    {
        if (!($v instanceof Obj) || !self::isNumber($v->get('version')) || !is_string($v->get('measurement'))) {
            return null;
        }
        $out = self::obj(['version' => $v->get('version'), 'measurement' => $v->get('measurement')]);
        $tcb = self::parseTcbVersion($v->get('reported_tcb'));
        if (!self::undef($tcb)) {
            $out->set('reported_tcb', $tcb);
        }
        if (self::isNumber($v->get('guest_svn'))) {
            $out->set('guest_svn', $v->get('guest_svn'));
        }
        if (is_string($v->get('chip_id'))) {
            $out->set('chip_id', $v->get('chip_id'));
        }
        foreach (['debug', 'degraded'] as $k) {
            if (is_bool($v->get($k))) {
                $out->set($k, $v->get($k));
            }
        }
        return $out;
    }

    /**
     * Verify an EAT's signature and typ / iss and parse it into claims. Throws on an invalid signature, wrong key, failed iss / typ check,
     * unsupported alg, or a missing iss / iat. A claim of the wrong type is dropped, so a later check fails closed. This proves
     * AUTHENTICITY only: freshness, channel binding and appraisal are separate steps.
     */
    public static function verifyEat(mixed $eat, mixed $verifyKey, mixed $opts = null): Obj
    {
        $opts ??= new Obj();
        if (!is_string($eat)) {
            throw new \InvalidArgumentException('EAT invalid: token is not a string');
        }
        try {
            $parsed = Jose::assertCanonicalCompactJws($eat, 3, self::MAX_EAT_BYTES); // one accepted spelling per EAT
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('EAT invalid: ' . $e->getMessage());
        }
        [$h, $p, $s] = $parsed['segments'];
        $header = $parsed['header'];
        $payload = $parsed['payload'];
        if (!self::isSupportedAlg($header->get('alg'))) {
            throw new \InvalidArgumentException('EAT invalid: missing or unsupported `alg` header');
        }
        $alg = $header->get('alg');
        $allowed = Js::opt($opts, 'algorithms') ?? self::SUPPORTED_ALGS;
        if (is_string($allowed)) {
            $algOk = str_contains($allowed, $alg);
        } elseif (is_array($allowed) && array_is_list($allowed)) {
            $algOk = self::includes($allowed, $alg);
        } else {
            throw new \TypeError('allowed.includes is not a function');
        }
        if (!$algOk) {
            throw new \InvalidArgumentException("EAT invalid: alg $alg not in the allowed set");
        }
        if (Js::opt($opts, 'requireTyp') !== false) {
            $want = Js::opt($opts, 'typ') ?? self::EAT_TYP;
            $typ = $header->has('typ') ? $header->get('typ') : Jsx::$U;
            if (!is_string($typ) || !is_string($want) || self::normalizeTyp($typ) !== self::normalizeTyp($want)) {
                throw new \InvalidArgumentException('EAT invalid: typ ' . self::jsString($typ) . ' is not ' . self::jsString($want));
            }
        }
        $sig = Pca::unb64u($s) ?? '';
        if (!Jose::jwsVerify($alg, $verifyKey, $sig, "$h.$p")) {
            throw new \InvalidArgumentException('EAT invalid: signature does not verify');
        }
        $iss = $payload->get('iss');
        $iat = $payload->get('iat');
        if (!is_string($iss)) {
            throw new \InvalidArgumentException('EAT invalid: missing or non-string `iss`');
        }
        if (!self::isNumber($iat)) {
            throw new \InvalidArgumentException('EAT invalid: missing or non-numeric `iat`');
        }
        if (Js::has($opts, 'issuer')) {
            $wantIss = Js::opt($opts, 'issuer');
            if (!self::includes(is_array($wantIss) && array_is_list($wantIss) ? $wantIss : [$wantIss], $iss)) {
                throw new \InvalidArgumentException("EAT invalid: iss $iss is not an accepted issuer");
            }
        }
        $claims = self::obj(['iss' => $iss, 'iat' => $iat]);
        if (is_string($payload->get('eat_nonce'))) {
            $claims->set('eat_nonce', $payload->get('eat_nonce'));
        }
        if (($cnf = self::parseCnf($payload->get('cnf'))) !== null) {
            $claims->set('cnf', $cnf);
        }
        foreach (['ueid', 'sueid'] as $k) {
            if (is_string($payload->get($k))) {
                $claims->set($k, $payload->get($k));
            }
        }
        if (($m = self::parseMeasurements($payload->get('measurements'))) !== null) {
            $claims->set('measurements', $m);
        }
        if (is_string($payload->get('dbgstat')) && in_array($payload->get('dbgstat'), self::DBGSTAT_VALUES, true)) {
            $claims->set('dbgstat', $payload->get('dbgstat'));
        }
        if (is_string($payload->get('oemid'))) {
            $claims->set('oemid', $payload->get('oemid'));
        }
        if (($m = self::parseMeasured($payload->get('measured'))) !== null) {
            $claims->set('measured', $m);
        }
        if (($m = self::parseSevsnp($payload->get('sevsnp'))) !== null) {
            $claims->set('sevsnp', $m);
        }
        return $claims;
    }

    // ---- freshness + channel -----------------------------------------------------------------------------------------------------------------

    /**
     * ANTI-REPLAY FRESHNESS: the eat_nonce must equal the server-issued challenge and iat must lie in [now - maxAgeMs, now] (plus
     * clockSkewMs). Absent / mismatched nonce, future iat or a stale token fail closed. A present clockSkewMs that is not a finite number
     * is refused: it would disable the age window.
     */
    public static function verifyFreshness(mixed $eat, mixed $opts): Obj
    {
        $fail = static fn(string $r): Obj => self::obj(['ok' => false, 'reason' => $r]);
        $now = self::g($opts, 'now');
        $now = self::isNumber($now) ? self::num($now) : self::nowMs();
        $skew = self::g($opts, 'clockSkewMs');
        if (!self::undef($skew) && !self::isNumber($skew)) {
            return $fail('invalid clockSkewMs (must be a finite number)');
        }
        $skew = self::undef($skew) ? 0.0 : max(0.0, self::num($skew));
        $expected = self::g($opts, 'expectedNonce');
        if (!self::nonEmptyStr($expected)) {
            return $fail('no expected (server-issued) nonce supplied (fail closed)');
        }
        $nonce = self::g($eat, 'eat_nonce');
        if (!self::nonEmptyStr($nonce)) {
            return $fail("EAT carries no eat_nonce \u{2014} cannot establish freshness (replayable)");
        }
        if (!self::ctEq($nonce, $expected)) {
            return $fail('eat_nonce does not match the server-issued challenge (replayed or relayed evidence)');
        }
        $iat = self::g($eat, 'iat');
        if (!self::isNumber($iat)) {
            return $fail('EAT has no valid iat (cannot establish age)');
        }
        $maxAge = self::g($opts, 'maxAgeMs');
        if (!self::isNumber($maxAge) || self::num($maxAge) <= 0) {
            return $fail('invalid maxAgeMs');
        }
        $iatMs = self::num($iat) * 1000;
        if (!($iatMs - $skew <= $now)) {
            return $fail('EAT iat is in the future');
        }
        if (!($now - $iatMs <= self::num($maxAge) + $skew)) {
            return $fail("EAT is stale (iat older than maxAgeMs) \u{2014} expired/replayed attestation");
        }
        return self::obj(['ok' => true]);
    }

    /**
     * CHANNEL BINDING (RA-TLS): every field of the expected cnf (derived from channelId and / or an explicit expectedCnf) must be present
     * and equal in the token's cnf. No cnf, or one bound to another channel / key, fails closed.
     */
    public static function verifyChannelBinding(mixed $eat, mixed $opts): Obj
    {
        $fail = static fn(string $r): Obj => self::obj(['ok' => false, 'reason' => $r]);
        $exp = [];
        $channelId = self::g($opts, 'channelId');
        if (self::nonEmptyStr($channelId)) {
            $exp['tls_exporter'] = self::deriveChannelCnf($channelId)->get('tls_exporter');
        }
        if (self::has($opts, 'expectedCnf')) {
            $e = self::g($opts, 'expectedCnf');
            $te = self::g($e, 'tls_exporter');
            $jkt = self::g($e, 'jkt');
            if (is_string($te)) {
                $exp['tls_exporter'] = $te;
            }
            if (is_string($jkt)) {
                $exp['jkt'] = $jkt;
            }
        }
        if ($exp === []) {
            return $fail('no expected channel binding supplied (fail closed)');
        }
        $cnf = self::g($eat, 'cnf');
        $cnfOk = self::truthy($cnf) && !self::undef($cnf);
        $cTe = $cnfOk ? self::g($cnf, 'tls_exporter') : Jsx::$U;
        $cJkt = $cnfOk ? self::g($cnf, 'jkt') : Jsx::$U;
        if (self::undef($cTe) && self::undef($cJkt)) {
            return $fail("EAT carries no channel/key binding (cnf) \u{2014} evidence is not bound to a live channel (RA-TLS)");
        }
        if (isset($exp['tls_exporter']) && (self::undef($cTe) || !self::ctEq($cTe, $exp['tls_exporter']))) {
            return $fail('TLS-exporter channel binding mismatch (evidence lifted to another channel?)');
        }
        if (isset($exp['jkt']) && (self::undef($cJkt) || !self::ctEq($cJkt, $exp['jkt']))) {
            return $fail('holder-key thumbprint (cnf.jkt) mismatch');
        }
        return self::obj(['ok' => true]);
    }

    // ---- RATS appraisal ---------------------------------------------------------------------------------------------------------------------------

    private static function nonEmptyList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v) && $v !== [];
    }

    /** A TCB version as a comparable integer, or null for an unknown shape (fail closed). */
    private static function packTcb(mixed $v): ?\GMP
    {
        if (self::isNumber($v)) {
            $f = self::num($v);
            return $f >= 0 ? gmp_init(sprintf('%.0f', floor($f)), 10) : null;
        }
        if (is_string($v)) {
            $t = Common::jsTrim($v);
            return preg_match('/\A[0-9]+\z/', $t) === 1 ? gmp_init($t, 10) : null; // unknown / non-numeric format: fail closed
        }
        if (!($v instanceof Obj)) { // true / [] / null are not a TCB version
            return null;
        }
        $comp = static function (mixed $x): ?int {
            if (self::undef($x)) {
                return 0;
            }
            if (!self::isNumber($x)) {
                return null;
            }
            $f = self::num($x);
            if ($f != floor($f) || ($f == 0.0 && fdiv(1, $f) < 0)) {
                return null;
            }
            return $f >= 0 && $f <= 255 ? (int)$f : null;
        };
        $parts = [];
        foreach (['bootloader', 'tee', 'snp', 'microcode'] as $k) {
            $parts[] = $comp(self::g($v, $k));
        }
        if (in_array(null, $parts, true)) {
            return null;
        }
        [$bl, $tee, $snp, $uc] = $parts;
        return gmp_or(gmp_or(gmp_init($bl), gmp_mul($tee, 256)), gmp_or(gmp_mul($snp, gmp_pow(2, 48)), gmp_mul($uc, gmp_pow(2, 56))));
    }

    private static function lc(mixed $s): string
    {
        if (!is_string($s)) {
            throw new \TypeError('s.toLowerCase is not a function');
        }
        return mb_strtolower($s, 'UTF-8');
    }

    /** `lst?.find(pred)`: undefined for an absent list, a TypeError for a value without `find`. */
    private static function find(mixed $lst, \Closure $pred): mixed
    {
        if ($lst === null || self::undef($lst)) {
            return Jsx::$U;
        }
        if (!is_array($lst) || !array_is_list($lst)) {
            throw new \TypeError('eat.measurements?.find is not a function');
        }
        foreach ($lst as $e) {
            if ($pred($e)) {
                return $e;
            }
        }
        return Jsx::$U;
    }

    private static function launchMeasurement(mixed $eat): mixed
    {
        $measured = self::g($eat, 'measured');
        $sevsnp = self::g($eat, 'sevsnp');
        if (self::truthy($measured)) {
            $rm = self::g($measured, 'runtime_measurement');
            if (self::nonEmptyStr($rm)) {
                return $rm;
            }
        }
        if (self::truthy($sevsnp)) {
            $m = self::g($sevsnp, 'measurement');
            if (is_string($m)) {
                return $m;
            }
        }
        $hit = self::find(self::g($eat, 'measurements'), static fn($e): bool => in_array(self::g($e, 'type'), ['launch', 'measurement'], true));
        return self::undef($hit) ? Jsx::$U : self::g($hit, 'value');
    }

    private static function weightsMeasurement(mixed $eat): mixed
    {
        $measured = self::g($eat, 'measured');
        if (self::truthy($measured)) {
            $wd = self::g($measured, 'weights_digest');
            if (self::nonEmptyStr($wd)) {
                return $wd;
            }
        }
        $hit = self::find(self::g($eat, 'measurements'), static fn($e): bool => self::g($e, 'type') === 'weights');
        return self::undef($hit) ? Jsx::$U : self::g($hit, 'value');
    }

    /** True / false when the debug status is known, else null (the caller fails closed). */
    private static function isDebugDisabled(mixed $eat): ?bool
    {
        $dbg = self::g($eat, 'dbgstat');
        if (!self::undef($dbg)) {
            return is_string($dbg) && in_array($dbg, self::DBGSTAT_VALUES, true) ? $dbg !== 'enabled' : null;
        }
        $sevsnp = self::g($eat, 'sevsnp');
        if (self::truthy($sevsnp) && is_bool(self::g($sevsnp, 'debug'))) {
            return self::g($sevsnp, 'debug') === false;
        }
        return null;
    }

    /**
     * APPRAISE an EAT's evidence against RATS reference values and endorsements (RFC 9334), kept as separate inputs. Tiers:
     * affirming-hw-rooted > affirming > warning (acceptable); contraindicated (the measured state is actively bad) and rejected (empty
     * policy, or a required input absent / in an unknown format) fail closed. Endorsements gate WHO (mismatch -> rejected); reference
     * values gate WHAT (bad -> contraindicated, absent -> rejected). An omitted argument defaults to {}; an explicit null is dereferenced
     * and throws, as in the reference.
     */
    public static function appraise(mixed $evidence, mixed $referenceValues = Jsx::class, mixed $endorsements = Jsx::class, mixed $extras = Jsx::class): Obj
    {
        $rv = $referenceValues === Jsx::class ? new Obj() : $referenceValues;
        $en = $endorsements === Jsx::class ? new Obj() : $endorsements;
        $reasons = [];
        $result = static function (string $tier, string $reason) use (&$reasons): Obj {
            return self::obj(['tier' => $tier, 'trustworthy' => in_array($tier, self::TRUSTWORTHY, true), 'reasons' => array_merge($reasons, [$reason])]);
        };
        $enIssuers = self::g($en, 'issuers');
        $enOemids = self::g($en, 'oemids');
        $enOperators = self::g($en, 'operators');
        $hasEndorsements = self::nonEmptyList($enIssuers) || self::nonEmptyList($enOemids) || self::nonEmptyList($enOperators);
        $rvMeas = self::g($rv, 'measurements');
        $rvModels = self::g($rv, 'models');
        $rvWeights = self::g($rv, 'weightsMeasurements');
        $rvMinTcb = self::g($rv, 'minTcb');
        $rvMinSvn = self::g($rv, 'minGuestSvn');
        $hasRef = self::nonEmptyList($rvMeas) || self::nonEmptyList($rvModels) || self::nonEmptyList($rvWeights)
            || self::g($rv, 'requireMeasuredWeights') === true || !self::undef($rvMinTcb) || self::isNumber($rvMinSvn)
            || self::g($rv, 'requireDebugDisabled') === true;
        if (!$hasEndorsements && !$hasRef) {
            return self::obj(['tier' => 'rejected', 'trustworthy' => false,
                'reasons' => ['empty appraisal policy: no endorsements or reference values to appraise against (fail closed)']]);
        }
        $iss = self::g($evidence, 'iss');
        // endorsements (WHO) -> rejected on mismatch
        if (self::nonEmptyList($enIssuers)) {
            if (!self::includes($enIssuers, $iss)) {
                return $result('rejected', 'issuer ' . self::jsString($iss) . ' is not an endorsed attester');
            }
            $reasons[] = 'issuer endorsed';
        }
        if (self::nonEmptyList($enOemids)) {
            $oemid = self::g($evidence, 'oemid');
            if (!is_string($oemid) || !self::includes($enOemids, $oemid)) {
                return $result('rejected', 'oemid absent or not endorsed (fail closed)');
            }
            $reasons[] = 'oemid endorsed';
        }
        if (self::nonEmptyList($enOperators)) {
            $measured = self::g($evidence, 'measured');
            $op = $measured !== null && !self::undef($measured) ? self::g($measured, 'operator') : Jsx::$U;
            if (!self::nonEmptyStr($op) || !self::includes($enOperators, $op)) {
                return $result('rejected', 'hardware operator absent or not endorsed (fail closed)');
            }
            $reasons[] = 'operator endorsed';
        }
        // reference values (WHAT): bad value -> contraindicated; absent / unknown required -> rejected
        if (self::nonEmptyList($rvMeas)) {
            $m = self::launchMeasurement($evidence);
            if (self::undef($m)) {
                return $result('rejected', 'no launch measurement in evidence to compare against reference values (fail closed)');
            }
            $lowered = array_map(self::lc(...), $rvMeas);
            if (!in_array(self::lc($m), $lowered, true)) {
                return $result('contraindicated', 'launch measurement not in reference values');
            }
            $reasons[] = 'launch measurement matches a reference value';
        }
        if (self::nonEmptyList($rvModels)) {
            $measured = self::g($evidence, 'measured');
            $model = $measured !== null && !self::undef($measured) ? self::g($measured, 'model_id') : Jsx::$U;
            if (!self::nonEmptyStr($model)) {
                return $result('rejected', 'no model id in evidence (fail closed)');
            }
            if (!self::includes($rvModels, $model)) {
                return $result('contraindicated', 'model id not in reference values (model swap?)');
            }
            $reasons[] = 'model id matches a reference value';
        }
        if (self::g($rv, 'requireMeasuredWeights') === true) {
            $measured = self::g($evidence, 'measured');
            $wm = $measured !== null && !self::undef($measured) ? self::g($measured, 'weights_measured') : Jsx::$U;
            if ($wm !== true) {
                return $result('contraindicated', 'weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)');
            }
            $reasons[] = 'weights digest is hardware-measured';
        }
        if (self::nonEmptyList($rvWeights)) {
            $w = self::weightsMeasurement($evidence);
            if (self::undef($w) || $w === '') {
                return $result('rejected', 'no measured-weights digest in evidence (fail closed)');
            }
            $lowered = array_map(self::lc(...), $rvWeights);
            if (!in_array(self::lc($w), $lowered, true)) {
                return $result('contraindicated', 'weights measurement not in reference values (model swap / fine-tune?)');
            }
            $reasons[] = 'weights measurement matches a reference value';
        }
        if (!self::undef($rvMinTcb)) {
            $minimum = self::packTcb($rvMinTcb);
            if ($minimum === null) {
                return $result('rejected', 'reference minTcb is not a comparable TCB version');
            }
            $sevsnp = self::g($evidence, 'sevsnp');
            $rawTcb = $sevsnp !== null && !self::undef($sevsnp) ? self::g($sevsnp, 'reported_tcb') : Jsx::$U;
            $got = self::undef($rawTcb) ? null : self::packTcb($rawTcb);
            if ($got === null) {
                return $result('rejected', "evidence TCB version is absent or an unknown format \u{2014} failing closed (see 2025-10-27 GCP firmware drift)");
            }
            if (gmp_cmp($got, $minimum) < 0) {
                return $result('contraindicated', 'reported TCB is below the reference minimum (downgrade / rollback)');
            }
            $reasons[] = 'TCB at or above reference minimum';
        }
        if (self::isNumber($rvMinSvn)) {
            $sevsnp = self::g($evidence, 'sevsnp');
            $svn = $sevsnp !== null && !self::undef($sevsnp) ? self::g($sevsnp, 'guest_svn') : Jsx::$U;
            if (!self::isNumber($svn)) {
                return $result('rejected', 'guest_svn absent (fail closed)');
            }
            if (self::num($svn) < self::num($rvMinSvn)) {
                return $result('contraindicated', 'guest_svn ' . Common::numStr(self::num($svn)) . ' below reference minimum ' . Common::numStr(self::num($rvMinSvn)));
            }
            $reasons[] = 'guest_svn at or above reference minimum';
        }
        if (self::g($rv, 'requireDebugDisabled') === true) {
            $disabled = self::isDebugDisabled($evidence);
            if ($disabled === null) {
                return $result('rejected', "debug status unknown \u{2014} failing closed");
            }
            if (!$disabled) {
                return $result('contraindicated', "debug is enabled (host can inspect the guest \u{2014} no confidentiality)");
            }
            $reasons[] = 'debug disabled';
        }
        // all checks passed: degraded evidence -> warning; a verified AMD signature -> the hardware-rooted tier
        $sevsnp = self::g($evidence, 'sevsnp');
        if ($sevsnp !== null && !self::undef($sevsnp) && self::g($sevsnp, 'degraded') === true) {
            return self::obj(['tier' => 'warning', 'trustworthy' => true, 'reasons' => array_merge($reasons, ["evidence came from a degraded (version-tolerant) parse \u{2014} review"])]);
        }
        $ex = $extras === Jsx::class ? new Obj() : $extras;
        if (self::g($ex, 'hardwareVerified') === true) {
            $label = self::g($ex, 'hardwareRootLabel');
            $label = self::undef($label) || $label === null ? self::AMD_SEV_SNP_HARDWARE_ROOT_LABEL : $label;
            return self::obj(['tier' => 'affirming-hw-rooted', 'trustworthy' => true,
                'reasons' => array_merge($reasons, ["AMD SEV-SNP report signature + VCEK\u{2192}ASK\u{2192}ARK chain verified \u{2014} " . self::jsString($label)])]);
        }
        return self::obj(['tier' => 'affirming', 'trustworthy' => true, 'reasons' => $reasons]);
    }

    // ---- AMD delegation --------------------------------------------------------------------------------------------------------------------------------

    private static function certToDer(mixed $in): string
    {
        $in = $in instanceof Bytes ? $in->raw : $in;
        if (is_string($in) && $in !== '' && !str_contains($in, '-----BEGIN')) {
            return $in;
        }
        if (!is_string($in)) {
            throw new \TypeError('a certificate is DER bytes or a PEM string');
        }
        $blocks = Common::pemBlocks($in);
        if (count($blocks) !== 1) {
            throw new \InvalidArgumentException('expected exactly one PEM certificate, found ' . count($blocks));
        }
        return Common::pemToDer($blocks[0]);
    }

    private static function derToPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . rtrim(chunk_split(base64_encode($der), 64, "\n"), "\n") . "\n-----END CERTIFICATE-----\n";
    }

    /**
     * Compose the AMD SEV-SNP hardware root of trust into one verdict by delegating to Amd::verifyGenuineReport (per-family ARK pin, exact
     * ASK-then-ARK bundle, validity against the verifier clock `nowMs`, report signature, VCEK binding), then project the verified report
     * into EAT evidence and a measured identity. Fails closed on any failure and never throws. Supply exactly one of `family` (milan |
     * genoa | turin) or `trustAnchorArkSpkiSha384`; the root is never inferred from the evidence.
     */
    public static function verifyAmdAttestation(mixed $rawReport, mixed $opts): Obj
    {
        $root = self::AMD_SEV_SNP_HARDWARE_ROOT_LABEL;
        $fail = static fn(string $reason): Obj => self::obj(['ok' => false, 'reason' => $reason, 'hardwareRoot' => $root]);
        try {
            $hasFamily = self::has($opts, 'family');
            $hasPin = self::has($opts, 'trustAnchorArkSpkiSha384');
            if ($hasFamily === $hasPin) {
                return $fail('exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)');
            }
            if ($hasFamily) {
                $fam = self::g($opts, 'family');
                if (!is_string($fam) || !isset(Amd::ARK_SPKI_SHA384[$fam])) {
                    return $fail('unknown AMD family ' . self::jsString($fam) . ' (expected milan | genoa | turin)');
                }
                $pin = Amd::ARK_SPKI_SHA384[$fam];
            } else {
                $pin = self::g($opts, 'trustAnchorArkSpkiSha384');
            }
            try {
                $vcekDer = self::certToDer(self::g($opts, 'vcek'));
                $askArkPem = self::derToPem(self::certToDer(self::g($opts, 'ask'))) . self::derToPem(self::certToDer(self::g($opts, 'ark')));
            } catch (\Throwable $e) {
                return $fail('certificate parse failed: ' . $e->getMessage());
            }
            $raw = $rawReport instanceof Bytes ? $rawReport->raw : $rawReport;
            if (!is_string($raw)) {
                return $fail('report parse failed: parseSevSnpReport: expected Uint8Array'); // the reference's refusal of a non-Uint8Array report
            }
            $expected = self::g($opts, 'expectedMeasurement');
            $measurements = self::nonEmptyStr($expected) ? [$expected] : [];
            $skew = self::g($opts, 'clockSkewMs');
            $nowMs = self::g($opts, 'nowMs');
            $verdict = Amd::verifyGenuineReport($raw, $vcekDer, $askArkPem, is_string($pin) ? $pin : null, self::undef($nowMs) ? null : $nowMs,
                self::undef($skew) ? null : $skew, null, ['measurements' => $measurements, 'allowDebug' => self::g($opts, 'allowDebug') === true]);
            if (($verdict['ok'] ?? false) !== true || ($verdict['report'] ?? null) === null) {
                $out = ['ok' => false, 'reason' => ($verdict['reason'] ?? '') !== '' ? $verdict['reason'] : 'AMD SEV-SNP verification failed', 'hardwareRoot' => $root];
                try {
                    $out['report'] = Amd::parseReport($raw);
                } catch (\Throwable) {
                    // the verifier reported the parse failure with its own reason
                }
                return self::obj($out);
            }
            return self::obj(['ok' => true, 'hardwareRoot' => $root, 'report' => $verdict['report'], 'evidence' => self::evidenceFromReport($verdict['report']),
                'measured' => self::measuredFromReport($verdict['report'])]);
        } catch (\Throwable $e) {
            return $fail('AMD attestation verification error (fail closed): ' . $e->getMessage());
        }
    }

    // ---- composition ---------------------------------------------------------------------------------------------------------------------------------------

    /**
     * The end-to-end check a resource server runs: verify the EAT's signature, then FRESHNESS (nonce + iat), CHANNEL BINDING (cnf vs the
     * live channel) and APPRAISAL against the RATS policy. The first failing gate stops the pipeline and names the reason. With `amd` the
     * AMD report signature and chain are verified here (success lifts the tier to affirming-hw-rooted, failure is contraindicated).
     * Options: verifyKey, nonce, channelId | channelBinding, policy, now, maxAgeMs, clockSkewMs, issuer, algorithms, typ, requireTyp, amd.
     */
    public static function verifyFreshAttestedEat(mixed $eat, mixed $opts): Obj
    {
        $reasons = [];
        try {
            $vo = new Obj();
            foreach (['issuer', 'algorithms', 'typ', 'requireTyp'] as $k) {
                if (Js::has($opts, $k)) {
                    $vo->set($k, Js::opt($opts, $k));
                }
            }
            $claims = self::verifyEat($eat, ($vk = self::g($opts, 'verifyKey')) instanceof Undef ? null : $vk, $vo);
        } catch (\Throwable $e) {
            return self::obj(['ok' => false, 'reasons' => ['EAT signature/claims invalid: ' . $e->getMessage()]]);
        }
        $reasons[] = 'signature + typ/iss verified';
        $now = self::g($opts, 'now');
        $now = self::isNumber($now) ? self::num($now) : self::nowMs();
        $maxAge = self::g($opts, 'maxAgeMs');
        $fopts = self::obj(['expectedNonce' => self::g($opts, 'nonce'), 'maxAgeMs' => self::undef($maxAge) || $maxAge === null ? self::numObj(self::DEFAULT_MAX_AGE_MS) : $maxAge,
            'now' => self::numObj($now)]);
        if (self::has($opts, 'clockSkewMs')) {
            $fopts->set('clockSkewMs', self::g($opts, 'clockSkewMs'));
        }
        $fresh = self::verifyFreshness($claims, $fopts);
        if ($fresh->get('ok') !== true) {
            return self::obj(['ok' => false, 'reasons' => array_merge($reasons, [$fresh->get('reason') ?? 'not fresh']), 'claims' => $claims]);
        }
        $reasons[] = 'fresh (nonce + iat within window)';
        $copts = new Obj();
        if (self::has($opts, 'channelId')) {
            $copts->set('channelId', self::g($opts, 'channelId'));
        }
        if (self::has($opts, 'channelBinding')) {
            $copts->set('expectedCnf', self::g($opts, 'channelBinding'));
        }
        $chan = self::verifyChannelBinding($claims, $copts);
        if ($chan->get('ok') !== true) {
            return self::obj(['ok' => false, 'reasons' => array_merge($reasons, [$chan->get('reason') ?? 'channel binding failed']), 'claims' => $claims]);
        }
        $reasons[] = 'channel-bound (cnf matches live channel)';
        $extras = new Obj();
        if (self::has($opts, 'amd')) {
            $amd = self::g($opts, 'amd');
            $expected = self::g($amd, 'expectedMeasurement');
            if (self::undef($expected) || $expected === null) {
                $expected = self::launchMeasurement($claims);
            }
            $aopts = self::obj(['vcek' => self::g($amd, 'vcek'), 'ask' => self::g($amd, 'ask'), 'ark' => self::g($amd, 'ark'), 'nowMs' => self::numObj($now)]);
            foreach (['family', 'trustAnchorArkSpkiSha384', 'clockSkewMs', 'allowDebug'] as $k) {
                if (self::has($amd, $k)) {
                    $aopts->set($k, self::g($amd, $k));
                }
            }
            if (!self::undef($expected)) {
                $aopts->set('expectedMeasurement', $expected);
            }
            $hw = self::verifyAmdAttestation(self::g($amd, 'rawReport'), $aopts);
            if ($hw->get('ok') !== true) {
                return self::obj(['ok' => false, 'tier' => 'contraindicated',
                    'reasons' => array_merge($reasons, ['AMD hardware root verification failed: ' . ($hw->get('reason') ?? 'unknown')]), 'claims' => $claims]);
            }
            $reasons[] = 'AMD SEV-SNP hardware root verified (' . $hw->get('hardwareRoot') . ')';
            $extras = self::obj(['hardwareVerified' => true, 'hardwareRootLabel' => $hw->get('hardwareRoot')]);
        }
        $policy = self::g($opts, 'policy');
        $rvs = self::g($policy, 'referenceValues');
        $ens = self::g($policy, 'endorsements');
        $app = self::appraise($claims, self::undef($rvs) || $rvs === null ? new Obj() : $rvs, self::undef($ens) || $ens === null ? new Obj() : $ens, $extras);
        return self::obj(['ok' => $app->get('trustworthy'), 'tier' => $app->get('tier'), 'reasons' => array_merge($reasons, $app->get('reasons')), 'claims' => $claims]);
    }

    // ---- nonce, admission evidence, runtime digest ----------------------------------------------------------------------------------------

    /** A fresh single-use nonce for an attestation challenge: random, time-stamped (`<b64u random>.<issue time, base 36>`). @return array{value:string,issuedAt:int|float} */
    public static function issueNonce(?int $now = null, ?int $bytes = null): array
    {
        $t = $now ?? (int)(microtime(true) * 1000);
        return ['value' => Pca::b64u(random_bytes(max(16, $bytes ?? 32))) . '.' . base_convert((string)$t, 10, 36), 'issuedAt' => $t];
    }

    /** RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url (a template literal: any value prints as its string form). */
    public static function ed25519Jkt(mixed $holderPubB64u): string
    {
        return Pca::b64u(hash('sha256', Js::utf8('{"crv":"Ed25519","kty":"OKP","x":"' . Jsx::str($holderPubB64u) . '"}'), true));
    }

    private const TIER_RANK = ['rejected' => 0, 'contraindicated' => 0, 'warning' => 1, 'affirming' => 2, 'affirming-hw-rooted' => 3];

    /**
     * EAT evidence for blueprint admission: the token's signature, issuer, freshness (the server-issued nonce) and appraisal pass, and its
     * `cnf.jkt` is the thumbprint of THE INSTANCE KEY. The identity is the measured identity the verifier established. Anything unverifiable
     * is {ok:false}. `minTier` (default affirming) other than the two accepted tiers is refused (the reference admits any unknown name).
     * Options: those of verifyFreshAttestedEat (verifyKey, nonce, policy, now, ...) plus instanceKey and minTier.
     * @return Obj {ok, bound, identity?, reason?}
     */
    public static function eatAdmissionEvidence(mixed $eat, mixed $o): Obj
    {
        try {
            $rest = new Obj();
            foreach ($o instanceof Obj ? $o->keys() : (is_array($o) ? array_map('strval', array_keys($o)) : []) as $k) {
                if ($k !== 'instanceKey' && $k !== 'minTier') {
                    $rest->set($k, Js::opt($o, $k));
                }
            }
            $minIn = self::g($o, 'minTier');
            if (!self::undef($minIn) && $minIn !== 'affirming' && $minIn !== 'affirming-hw-rooted') {
                return self::obj(['ok' => false, 'bound' => false, 'reason' => 'invalid minTier']);
            }
            if (self::undef(self::g($o, 'policy'))) {
                throw new \TypeError('policy is undefined');
            }
            $rest->set('channelBinding', self::obj(['jkt' => self::ed25519Jkt(self::g($o, 'instanceKey'))]));
            $v = self::verifyFreshAttestedEat($eat, $rest);
            $reasons = $v->get('reasons');
            if ($v->get('ok') !== true || !$v->has('tier')) {
                return self::obj(['ok' => false, 'bound' => false, 'reason' => is_array($reasons) && $reasons !== [] ? $reasons[count($reasons) - 1] : 'EAT rejected']);
            }
            $min = self::g($o, 'minTier');
            $min = self::undef($min) || $min === null ? 'affirming' : $min;
            $tier = $v->get('tier');
            if (!is_string($min) || !isset(self::TIER_RANK[$min]) || !isset(self::TIER_RANK[$tier])) {
                return self::obj(['ok' => false, 'bound' => true, 'reason' => 'minTier is not an appraisal tier']);
            }
            if (self::TIER_RANK[$tier] < self::TIER_RANK[$min]) {
                return self::obj(['ok' => false, 'bound' => true, 'reason' => "appraisal tier $tier is below the minimum"]);
            }
            $claims = $v->get('claims');
            $m = $claims instanceof Obj ? self::g($claims, 'measured') : null;
            if (!($m instanceof Obj)) {
                return self::obj(['ok' => true, 'bound' => true]);
            }
            $id = new Obj();
            foreach (['runtime_measurement', 'model_id', 'weights_digest', 'operator'] as $k) {
                if ($m->has($k)) {
                    $id->set($k, $m->get($k));
                }
            }
            return self::obj(['ok' => true, 'bound' => true, 'identity' => $id]);
        } catch (\Throwable $e) {
            return self::obj(['ok' => false, 'bound' => false, 'reason' => $e instanceof \TypeError ? 'TypeError' : 'Error']);
        }
    }

    /**
     * The running image's digest from an ACCEPTED EAT verdict: exactly one `measurements` entry labelled `slot` (default `image`), lowercase
     * hex of the algorithm's length. Null when the verdict is not ok, the slot is missing or repeated, or the value is malformed.
     * @return ?Obj {alg, digest}
     */
    public static function runtimeDigestFromEat(mixed $verdict, mixed $o = null): ?Obj
    {
        if (!($verdict instanceof Obj) || $verdict->get('ok') !== true) {
            return null;
        }
        $claims = $verdict->get('claims');
        if (!Js::truthy($claims)) {
            return null;
        }
        $slot = Js::opt($o, 'slot') ?? 'image';
        $alg = Js::opt($o, 'alg') ?? 'sha256';
        $ms = Js::opt($claims, 'measurements') ?? [];
        if (!is_array($ms) || !array_is_list($ms)) {
            throw new \TypeError('(verdict.claims.measurements ?? []).filter is not a function');
        }
        $hits = array_values(array_filter($ms, static fn($m) => Jsx::get($m, 'type') === $slot));
        if (count($hits) !== 1) {
            return null;
        }
        $v = Js::opt($hits[0], 'value');
        return is_string($v) && preg_match($alg === 'sha256' ? '/\A[0-9a-f]{64}\z/' : '/\A[0-9a-f]{128}\z/', $v) === 1 ? self::obj(['alg' => $alg, 'digest' => $v]) : null;
    }
}
