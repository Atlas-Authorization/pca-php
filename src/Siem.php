<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';

/** Thrown by a collector fetch that gave up waiting (the sink reports "delivery timed out"). */
final class SiemTimeout extends \RuntimeException
{
}

/** A SIEM destination: `format` is the schema it expects, `deliver(list<array> $events)` returns ['ok' => bool, 'error'? => string]. */
final class SiemSink
{
    /** @param \Closure(list<array>):mixed $deliver */
    public function __construct(public readonly string $name, public readonly mixed $format, public readonly \Closure $deliver)
    {
    }
}

/**
 * SIEM export of PCA authorization decisions: OCSF 1.x Authorize Session, ArcSight CEF and Elastic Common Schema events plus fail-safe
 * sinks (the reference's pca-siem); outputs are byte-identical, including the JavaScript string / number / Date quirks (UTF-16
 * lengths, number formatting, toISOString). A decision record is {pcactn, verify, decision?, now?, session?} (an Obj or an assoc
 * array). Shipping an event to a SIEM never throws into the caller: sink errors are caught, scrubbed of credentials, reported through
 * onError and returned. A result object is an assoc array.
 */
final class Siem
{
    public const OCSF_SCHEMA_VERSION = '1.1.0';
    public const ECS_VERSION = '8.11.0';
    public const SECURITY_CHECKS = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'plan_inclusion', 'leaf_signature', 'counter_format', 'replay'];

    // (OCSF id, OCSF label, CEF / ECS 0-10 scale)
    private const SEV_INFO = [1, 'Informational', 1];
    private const SEV_LOW = [2, 'Low', 3];
    private const SEV_MEDIUM = [3, 'Medium', 5];
    private const SEV_HIGH = [4, 'High', 8];

    // ---- JS helpers ---------------------------------------------------------------------------------------------------

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

    private static function nullish(mixed $v): bool
    {
        return $v === null || $v instanceof Undef;
    }

    private static function str(mixed $v, string $fallback): string
    {
        return is_string($v) && $v !== '' ? $v : $fallback;
    }

    private static function finite(mixed $v): mixed
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f) ? $v : Jsx::$U;
    }

    /** A JSON number equal to `$n` (Python's `tier == 3`, never true for a bool). */
    private static function numIs(mixed $v, int $n): bool
    {
        return Js::isNum($v) && Js::num($v) === (float)$n;
    }

    /**
     * The characters of a (WTF-8) string.
     * @return list<string>
     */
    private static function chars(string $s): array
    {
        preg_match_all('/\xED[\xA0-\xBF][\x80-\xBF]|[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF4][\x80-\xBF]{3}|[\x80-\xFF]/', $s, $m);
        return $m[0];
    }

    private static function hiSurrogate(string $c): string
    {
        $hi = 0xD800 + ((mb_ord($c, 'UTF-8') - 0x10000) >> 10);
        return chr(0xE0 | ($hi >> 12)) . chr(0x80 | (($hi >> 6) & 0x3F)) . chr(0x80 | ($hi & 0x3F));
    }

    private static function loSurrogate(string $c): string
    {
        $lo = 0xDC00 + ((mb_ord($c, 'UTF-8') - 0x10000) & 0x3FF);
        return chr(0xE0 | ($lo >> 12)) . chr(0x80 | (($lo >> 6) & 0x3F)) . chr(0x80 | ($lo & 0x3F));
    }

    /** `s.slice(0, n)` by UTF-16 code units: an astral character cut in half leaves its high surrogate. */
    public static function u16slice(string $s, int $n): string
    {
        $out = '';
        $u = 0;
        foreach (self::chars($s) as $c) {
            $w = strlen($c) === 4 ? 2 : 1;
            if ($u + $w > $n) {
                if ($w === 2 && $u < $n) {
                    $out .= self::hiSurrogate($c);
                }
                break;
            }
            $out .= $c;
            $u += $w;
        }
        return $out;
    }

    /**
     * Object.entries over any JSON value.
     * @return list<array{0:string,1:mixed}>
     */
    private static function entries(mixed $x): array
    {
        $out = [];
        if ($x instanceof Obj) {
            foreach (Js::ownKeys($x->keys()) as $k) {
                $out[] = [$k, $x->get($k)];
            }
        } elseif (is_array($x) && array_is_list($x)) {
            foreach ($x as $i => $v) {
                $out[] = [(string)$i, $v];
            }
        } elseif (is_array($x)) {
            foreach ($x as $k => $v) {
                $out[] = [(string)$k, $v];
            }
        } elseif (is_string($x)) {
            $i = 0;
            foreach (self::chars($x) as $c) {
                if (strlen($c) === 4) {
                    $out[] = [(string)$i++, self::hiSurrogate($c)];
                    $out[] = [(string)$i++, self::loSurrogate($c)];
                } else {
                    $out[] = [(string)$i++, $c];
                }
            }
        }
        return $out;
    }

    private static function fdivInt(int $a, int $b): int
    {
        $q = intdiv($a, $b);
        return ($a % $b !== 0 && (($a < 0) !== ($b < 0))) ? $q - 1 : $q;
    }

    /** new Date(ms).toISOString(), or the epoch when ms is not a valid time value. */
    private static function iso(mixed $ms): string
    {
        $epoch = '1970-01-01T00:00:00.000Z';
        $f = Js::num($ms);
        if ($f === null || !is_finite($f) || abs($f) > 8.64e15) {
            return $epoch;
        }
        $t = (int)$f; // truncation toward zero, like TimeClip
        $days = self::fdivInt($t, 86400000);
        $rem = $t - $days * 86400000;
        $z = $days + 719468;
        $era = self::fdivInt($z, 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $y = $yoe + $era * 400;
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $m = $mp < 10 ? $mp + 3 : $mp - 9;
        if ($m <= 2) {
            $y++;
        }
        $ys = ($y >= 0 && $y <= 9999) ? sprintf('%04d', $y) : (($y < 0 ? '-' : '+') . sprintf('%06d', abs($y)));
        $h = intdiv($rem, 3600000);
        $rem %= 3600000;
        $mi = intdiv($rem, 60000);
        $rem %= 60000;
        $s = intdiv($rem, 1000);
        $milli = $rem % 1000;
        return sprintf('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', $ys, $m, $d, $h, $mi, $s, $milli);
    }

    private static function nowMs(mixed $now): mixed
    {
        if ($now instanceof \Closure) {
            return $now();
        }
        if (Js::isNum($now)) {
            return $now;
        }
        return (int)floor(self::clock() * 1000);
    }

    /** Drop the `undefined` members of an assoc array. */
    private static function prune(array $d): array
    {
        return array_filter($d, static fn($v) => !($v instanceof Undef));
    }

    private static function shortKey(mixed $key, int $n = 12): string
    {
        if (!is_string($key) || $key === '') {
            return '(none)';
        }
        return Js::len($key) <= $n + 1 ? $key : self::u16slice($key, $n) . '…';
    }

    private static function safeDigest(mixed $p): string
    {
        if ($p instanceof Undef) {
            return '(undigestible)';
        }
        try {
            return Pca::hashCanonical($p);
        } catch (\Throwable) { // an out-of-profile body has no digest
            return '(undigestible)';
        }
    }

    // ---- normalization ------------------------------------------------------------------------------------------------

    private static function firstReasonOr(mixed $decision, string $fallback): string
    {
        $rs = self::g($decision, 'reasons');
        $first = is_array($rs) && array_is_list($rs) && count($rs) > 0 ? $rs[0] : Jsx::$U;
        return is_string($first) && $first !== '' ? $first : $fallback;
    }

    /** @return array{0:string,1:string} */
    private static function resolveOutcome(mixed $verify, mixed $decision): array
    {
        if (!Jsx::truthy($verify) || self::g($verify, 'allow') !== true) {
            return ['deny', self::str(self::g($verify, 'reason'), 'proof failed verification')];
        }
        if (!Jsx::truthy($decision)) {
            return ['allow', 'proof verified; no policy decision supplied'];
        }
        if (Jsx::truthy(self::g($decision, 'admit'))) {
            return ['allow', self::firstReasonOr($decision, 'auto-admitted within policy and budget')];
        }
        if (Jsx::truthy(self::g($decision, 'releaseGuardianShare'))) {
            return ['step-up', self::firstReasonOr($decision, 'policy satisfied but a co-signature is required')];
        }
        return ['deny', self::firstReasonOr($decision, 'policy did not release authority (default-deny)')];
    }

    /** @return list<array<string,mixed>> */
    private static function buildHops(array $chain): array
    {
        $hops = [];
        foreach ($chain as $i => $cap) {
            if (!Jsx::truthy($cap)) {
                continue;
            }
            $parent = $i > 0 ? $chain[$i - 1] : Jsx::$U;
            $pc = Jsx::truthy($parent) ? self::g($parent, 'caveats') : Jsx::$U;
            $parentLen = is_array($pc) && array_is_list($pc) ? count($pc) : 0;
            $oc = self::g($cap, 'caveats');
            $ownLen = is_array($oc) && array_is_list($oc) ? count($oc) : 0;
            $added = $i === 0 ? $ownLen : max(0, $ownLen - $parentLen);
            $hops[] = [
                'index' => $i, 'isRoot' => $i === 0, 'issuer' => self::str(self::g($cap, 'issuer'), '(none)'),
                'holder' => self::str(self::g($cap, 'holder'), '(none)'), 'addedCaveats' => $added,
            ];
        }
        return $hops;
    }

    private static function readOverride(mixed $threshold, mixed $thresholdCheck): array
    {
        $shares = Jsx::truthy($threshold) ? self::g($threshold, 'shares') : Jsx::$U;
        $shares = is_array($shares) && array_is_list($shares) ? $shares : [];
        // threshold sits outside the signed body: its shares prove nothing until a threshold verifier passed
        if ($thresholdCheck !== 'pass') {
            return ['humanApproved' => false, 'approvers' => [], 'guardianCosigners' => [], 'roles' => []];
        }
        $approvers = [];
        $guardians = [];
        $roles = [];
        foreach ($shares as $s) {
            $role = self::g($s, 'role');
            if (!Jsx::truthy($s) || !is_string($role)) {
                continue;
            }
            $roles[] = $role;
            $pk = self::g($s, 'publicKey');
            if ($role === 'principal' && is_string($pk)) {
                $approvers[] = $pk;
            }
            if ($role === 'guardian' && is_string($pk)) {
                $guardians[] = $pk;
            }
        }
        return ['humanApproved' => count($approvers) > 0, 'approvers' => $approvers, 'guardianCosigners' => $guardians, 'roles' => $roles];
    }

    private static function severityFor(string $outcome, mixed $checks, mixed $tier): array
    {
        if ($outcome === 'deny') {
            foreach (self::SECURITY_CHECKS as $k) {
                if (self::g($checks, $k) === 'fail') {
                    return self::SEV_HIGH;
                }
            }
            return self::SEV_MEDIUM;
        }
        if ($outcome === 'step-up') {
            return self::SEV_MEDIUM;
        }
        return self::numIs($tier, 3) ? self::SEV_MEDIUM : (self::numIs($tier, 2) ? self::SEV_LOW : self::SEV_INFO);
    }

    private static function shownSignature(string $sig, mixed $mode): string
    {
        if ($mode === 'full') {
            return $sig;
        }
        if ($mode === 'omit') {
            return '(omitted)';
        }
        return Js::len($sig) <= 16 ? $sig : self::u16slice($sig, 16) . '…';
    }

    /** One total pass over the record, shared by the three exporters. */
    private static function normalize(mixed $record, mixed $opts, mixed $now): array
    {
        if ($record === null) {
            throw new \TypeError('record is required');
        }
        $p = self::g($record, 'pcactn');
        $v = self::g($record, 'verify');
        $verify = self::nullish($v) ? Obj::of(['allow' => false, 'checks' => new Obj()]) : $v;
        $c = self::g($verify, 'checks');
        $checks = self::nullish($c) ? new Obj() : $c;
        $nNow = self::finite(self::g($record, 'now'));
        if ($nNow instanceof Undef) {
            $nNow = self::nowMs($now);
        }
        $cc = self::g($p, 'cap_chain');
        $chain = is_array($cc) && array_is_list($cc) ? $cc : [];
        $hops = self::buildHops($chain);
        $leaf = $chain ? $chain[count($chain) - 1] : Jsx::$U;
        $root = $chain ? $chain[0] : Jsx::$U;

        $decision = self::g($record, 'decision');
        [$outcome, $reason] = self::resolveOutcome($verify, $decision);
        $rt = self::g($decision, 'requiredThreshold');
        $tier = self::g($rt, 't');
        $override = self::readOverride(self::g($p, 'threshold'), self::g($checks, 'threshold'));

        $grantRef = self::str(self::g($p, 'grant_ref'), '(none)');
        $agentHolder = self::str(self::g($leaf, 'holder'), '(none)');
        $ri = self::g($root, 'issuer');
        $principal = is_string($ri) && $ri !== '' ? $ri : null;
        $heads = [$principal ?? '(principal?)'];
        foreach ($hops as $h) {
            $heads[] = $h['holder'];
        }
        $chainString = implode(' -> ', array_map(static fn($k) => self::shortKey($k), $heads));

        $action = self::g($p, 'action');
        $nonce = self::g($p, 'nonce');
        $bond = self::g($p, 'bond_ref');
        $sev = self::severityFor($outcome, $checks, $tier);
        $counter = self::finite(self::g($p, 'counter'));
        $iat = self::finite(self::g($p, 'iat'));
        $exp = self::finite(self::g($p, 'exp'));
        return [
            'now' => $nNow, 'outcome' => $outcome, 'reason' => $reason,
            'cryptographicallyVerifiable' => self::g($checks, 'wire') === 'pass' && self::g($checks, 'leaf_signature') === 'pass',
            'checks' => $checks, 'agentHolder' => $agentHolder, 'principal' => $principal,
            'session' => self::str(self::g($record, 'session'), $grantRef), 'hops' => $hops, 'depth' => $hops ? count($hops) - 1 : 0,
            'chainString' => $chainString,
            'verb' => self::str(self::g($action, 'verb'), '(unknown verb)'),
            'resource' => self::str(self::g($action, 'resource'), '(unknown resource)'),
            'paramsDigest' => self::str(self::g($action, 'params_digest'), '(none)'),
            'reversibilityClass' => self::str(self::g($action, 'reversibility_class'), '(unknown)'),
            'grantRef' => $grantRef,
            'counter' => $counter instanceof Undef ? -1 : $counter,
            'nonce' => is_string($nonce) ? $nonce : Jsx::$U,
            'planRoot' => self::str(self::g(self::g($p, 'plan'), 'root'), '(none)'),
            'signatureSuite' => self::str(self::g($p, 'alg'), 'ed25519'),
            'leafSignature' => self::shownSignature(self::str(self::g($p, 'sig'), '(unsigned)'), self::g($opts, 'signature')),
            'proofDigest' => self::safeDigest($p),
            'riskScore' => self::finite(self::g($decision, 'r')), 'tier' => $tier, 'proofStrength' => self::g($rt, 'proof'),
            'caution' => self::finite(self::g($p, 'caution')), 'bondRef' => is_string($bond) ? $bond : Jsx::$U,
            'humanApproved' => $override['humanApproved'], 'approvers' => $override['approvers'],
            'guardianCosigners' => $override['guardianCosigners'], 'roles' => $override['roles'],
            'severity' => $sev,
            'iat' => $iat instanceof Undef ? $nNow : $iat,
            'exp' => $exp instanceof Undef ? $nNow : $exp,
        ];
    }

    private static function hopWire(array $h): array
    {
        return ['index' => $h['index'], 'is_root' => $h['isRoot'], 'issuer' => $h['issuer'], 'holder' => $h['holder'], 'added_caveats' => $h['addedCaveats']];
    }

    private static function humanOverride(array $n): mixed
    {
        if (!$n['humanApproved']) {
            return Jsx::$U;
        }
        return ['human_approved' => true, 'approvers' => $n['approvers'], 'guardian_cosigners' => $n['guardianCosigners'], 'roles' => $n['roles']];
    }

    private static function pcaExtensions(array $n): array
    {
        return self::prune([
            'proof_digest' => $n['proofDigest'], 'leaf_signature' => $n['leafSignature'], 'signature_suite' => $n['signatureSuite'],
            'cryptographically_verifiable' => $n['cryptographicallyVerifiable'], 'plan_root' => $n['planRoot'],
            'params_digest' => $n['paramsDigest'], 'grant_ref' => $n['grantRef'], 'counter' => $n['counter'], 'nonce' => $n['nonce'],
            'reversibility_class' => $n['reversibilityClass'], 'risk_score' => $n['riskScore'], 'risk_tier' => $n['tier'],
            'required_proof' => $n['proofStrength'], 'caution' => $n['caution'], 'bond_ref' => $n['bondRef'],
            'delegation_depth' => $n['depth'], 'delegation_chain' => array_map(self::hopWire(...), $n['hops']), 'checks' => $n['checks'],
            'human_override' => self::humanOverride($n),
        ]);
    }

    private static function narrative(array $n): string
    {
        $word = $n['outcome'] === 'allow' ? 'ALLOWED' : ($n['outcome'] === 'deny' ? 'DENIED' : 'STEP-UP');
        return sprintf(
            'Agent %s %s to %s on %s (%d-hop chain rooted at principal %s; %s%s). %s',
            self::shortKey($n['agentHolder']), $word, $n['verb'], $n['resource'], count($n['hops']), self::shortKey($n['principal']),
            $n['cryptographicallyVerifiable'] ? 'cryptographically verifiable proof' : 'proof not cryptographically verifiable',
            $n['humanApproved'] ? '; human-signed step-up' : '', $n['reason'],
        );
    }

    // ---- OCSF ---------------------------------------------------------------------------------------------------------

    /** OCSF 1.x Authorize Session (category 3, class 3003); `unmapped` carries the proof digest, tier and delegation chain. */
    public static function toOcsfEvent(mixed $record, mixed $opts = null, mixed $now = null): array
    {
        $n = self::normalize($record, $opts, $now);
        [$aid, $aname] = ['allow' => [1, 'Allow'], 'deny' => [2, 'Deny'], 'step-up' => [3, 'Step-Up']][$n['outcome']];
        [$actid, $actname] = ['allow' => [1, 'Allowed'], 'deny' => [2, 'Denied'], 'step-up' => [99, 'Other']][$n['outcome']];
        if ($n['outcome'] === 'allow') {
            $status = [1, 'Success', $n['reason']];
        } elseif ($n['outcome'] === 'deny') {
            $status = [2, 'Failure', $n['reason']];
        } else {
            $status = [99, 'Other', 'step-up / co-signature required: ' . $n['reason']];
        }
        $className = 'Authorize Session';
        $principal = $n['principal'] ?? '(none)';
        return [
            'activity_id' => $aid, 'activity_name' => $aname, 'category_uid' => 3, 'category_name' => 'Identity & Access Management',
            'class_uid' => 3003, 'class_name' => $className, 'type_uid' => 3003 * 100 + $aid, 'type_name' => "$className: $aname",
            'action_id' => $actid, 'action' => $actname, 'severity_id' => $n['severity'][0], 'severity' => $n['severity'][1],
            'status_id' => $status[0], 'status' => $status[1], 'status_detail' => $status[2], 'time' => $n['iat'],
            'actor' => [
                'user' => ['type_id' => 99, 'type' => 'Agent', 'uid' => $n['agentHolder'], 'name' => self::shortKey($n['agentHolder'])],
                'invoked_by' => $principal,
                'session' => self::prune(['uid' => $n['session'], 'issuer' => $n['principal'] === null ? Jsx::$U : $n['principal']]),
                'app_name' => 'PCA',
            ],
            'user' => ['type_id' => 1, 'type' => 'User', 'uid' => $principal, 'name' => self::shortKey($n['principal'])],
            'resources' => [['type' => 'pca.resource', 'name' => $n['resource'], 'uid' => $n['resource']]],
            'api' => ['operation' => $n['verb'], 'service' => ['name' => 'PCA']],
            'metadata' => [
                'version' => self::OCSF_SCHEMA_VERSION, 'product' => ['name' => 'PCA', 'vendor_name' => 'Atlas', 'version' => self::OCSF_SCHEMA_VERSION],
                'logged_time' => $n['now'], 'uid' => $n['proofDigest'],
                'labels' => ['pca', 'outcome:' . $n['outcome'], 'suite:' . $n['signatureSuite']],
            ],
            'observables' => [
                ['name' => 'actor.user.uid', 'type' => 'User Name', 'type_id' => 4, 'value' => $n['agentHolder']],
                ['name' => 'pca.proof.digest', 'type' => 'Hash', 'type_id' => 8, 'value' => $n['proofDigest']],
                ['name' => 'resources.uid', 'type' => 'Resource UID', 'type_id' => 10, 'value' => $n['resource']],
            ],
            'count' => 1, 'message' => self::narrative($n), 'unmapped' => self::pcaExtensions($n),
        ];
    }

    // ---- CEF ----------------------------------------------------------------------------------------------------------

    private static function cefHeaderEscape(string $s): string
    {
        return (string)preg_replace('/[\r\n]+/', ' ', str_replace(['\\', '|'], ['\\\\', '\\|'], $s));
    }

    private static function cefExtValueEscape(string $s): string
    {
        return (string)preg_replace_callback('/\r\n|\r|\n/', static fn(array $m): string => '\\n', str_replace(['\\', '='], ['\\\\', '\\='], $s));
    }

    /** One ArcSight CEF line: standard keys where they fit, the proof digest in cs1 and the delegation chain in cs2. */
    public static function toCef(mixed $record, mixed $opts = null, mixed $now = null): string
    {
        $n = self::normalize($record, $opts, $now);
        $wireVer = self::finite(self::g(self::g($record, 'pcactn'), 'ver'));
        $deviceVersion = $wireVer instanceof Undef ? '2' : Js::stringify($wireVer);
        $header = implode('|', [
            'CEF:0', self::cefHeaderEscape('Atlas'), self::cefHeaderEscape('PCA'), self::cefHeaderEscape($deviceVersion),
            self::cefHeaderEscape('pca-authz-' . $n['outcome']),
            self::cefHeaderEscape(sprintf('PCA authorization %s: %s on %s', $n['outcome'], $n['verb'], $n['resource'])),
            (string)$n['severity'][2],
        ]);
        $principal = $n['principal'] ?? '(none)';
        $checks = [];
        foreach (self::entries($n['checks']) as [$k, $v]) {
            $checks[] = $k . ':' . Jsx::str($v);
        }
        $pairs = [
            ['act', $n['outcome']], ['outcome', $n['outcome']], ['suser', $principal], ['suid', $principal],
            ['duser', $n['agentHolder']], ['duid', $n['agentHolder']], ['destinationServiceName', $n['verb']],
            ['rt', $n['now']], ['start', $n['iat']], ['end', $n['exp']],
            ['externalId', $n['nonce'] instanceof Undef ? Js::stringify($n['counter']) : $n['nonce']],
            ['request', $n['resource']], ['requestMethod', $n['verb']],
            ['cs1Label', 'pcaProofDigest'], ['cs1', $n['proofDigest']],
            ['cs2Label', 'pcaDelegationChain'], ['cs2', $n['chainString']],
            ['cs3Label', 'pcaProofStrength'], ['cs3', self::nullish($n['proofStrength']) ? 'n/a' : $n['proofStrength']],
            ['cs4Label', 'pcaSignatureSuite'], ['cs4', $n['signatureSuite']],
            ['cs5Label', 'pcaVerifyChecks'], ['cs5', implode(';', $checks)],
            ['cs6Label', 'pcaGrantRef'], ['cs6', $n['grantRef']],
            ['cn1Label', 'pcaRiskScore'], ['cn1', $n['riskScore'] instanceof Undef ? '' : $n['riskScore']],
            ['cn2Label', 'pcaDelegationDepth'], ['cn2', $n['depth']],
            ['cn3Label', 'pcaRiskTier'], ['cn3', self::nullish($n['tier']) ? '' : $n['tier']],
            ['flexString1Label', 'pcaHumanApproved'], ['flexString1', $n['humanApproved'] ? 'true' : 'false'],
            ['cat', 'authorization'], ['msg', $n['reason']],
        ];
        $ext = implode(' ', array_map(static fn(array $kv): string => $kv[0] . '=' . self::cefExtValueEscape(Jsx::str($kv[1])), $pairs));
        return $header . '|' . $ext;
    }

    // ---- ECS ----------------------------------------------------------------------------------------------------------

    /** @param list<string> $xs @return list<string> */
    private static function dedupe(array $xs): array
    {
        $out = [];
        foreach ($xs as $x) {
            if (!in_array($x, $out, true)) {
                $out[] = $x;
            }
        }
        return $out;
    }

    /** Elastic Common Schema event; the PCA edge lives under `pca.*`. */
    public static function toEcs(mixed $record, mixed $opts = null, mixed $now = null): array
    {
        $n = self::normalize($record, $opts, $now);
        $relatedUsers = self::dedupe([$n['agentHolder'], ...($n['principal'] !== null && $n['principal'] !== '' ? [$n['principal']] : []), ...$n['approvers']]);
        $relatedHashes = self::dedupe([$n['proofDigest'], $n['leafSignature']]);
        $event = [
            'kind' => 'event', 'category' => ['iam'], 'type' => ['allow' => ['allowed'], 'deny' => ['denied'], 'step-up' => ['info']][$n['outcome']],
            'action' => $n['verb'], 'outcome' => ['allow' => 'success', 'deny' => 'failure', 'step-up' => 'unknown'][$n['outcome']],
            'module' => 'pca', 'dataset' => 'pca.authorization', 'provider' => 'pca', 'id' => $n['proofDigest'], 'severity' => $n['severity'][2],
            'reason' => $n['reason'],
        ];
        if (!($n['riskScore'] instanceof Undef)) {
            $event['risk_score'] = $n['riskScore'];
        }
        $principal = $n['principal'] ?? '(none)';
        return [
            '@timestamp' => self::iso($n['iat']), 'ecs.version' => self::ECS_VERSION, 'event' => $event,
            'user' => [
                'id' => $n['agentHolder'], 'name' => self::shortKey($n['agentHolder']), 'roles' => ['agent'],
                'effective' => ['id' => $principal, 'name' => self::shortKey($n['principal'])],
            ],
            'service' => ['name' => 'pca', 'type' => 'authorization'],
            'related' => ['user' => $relatedUsers, 'hash' => $relatedHashes],
            'message' => self::narrative($n),
            'pca' => self::prune([
                'outcome' => $n['outcome'],
                'proof' => self::prune([
                    'digest' => $n['proofDigest'], 'leaf_signature' => $n['leafSignature'], 'signature_suite' => $n['signatureSuite'],
                    'cryptographically_verifiable' => $n['cryptographicallyVerifiable'], 'plan_root' => $n['planRoot'], 'params_digest' => $n['paramsDigest'],
                ]),
                'risk' => self::prune(['score' => $n['riskScore'], 'tier' => $n['tier'], 'required_proof' => $n['proofStrength'], 'caution' => $n['caution']]),
                'delegation' => ['depth' => $n['depth'], 'chain' => $n['chainString'], 'hops' => $n['hops']],
                'grant_ref' => $n['grantRef'], 'counter' => $n['counter'], 'nonce' => $n['nonce'],
                'reversibility_class' => $n['reversibilityClass'], 'bond_ref' => $n['bondRef'], 'checks' => $n['checks'],
                'human_override' => self::humanOverride($n),
            ]),
        ];
    }

    // ---- sinks --------------------------------------------------------------------------------------------------------

    private const CONTENT_TYPE = ['ocsf' => 'application/x-ndjson', 'ecs' => 'application/x-ndjson', 'cef' => 'text/plain; charset=utf-8'];
    /** The JavaScript \s class over UTF-8 bytes. */
    public const WS = '(?:[\t\n\x0b\x0c\r ]|\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF)';

    /** @return list<array{0:string,1:string}> pattern, replacement */
    private static function scrubRules(): array
    {
        $ws = self::WS;
        $nw = '(?:(?!' . $ws . ')[^/@])*';
        return [
            ['%([a-z][a-z0-9+.-]*://)' . $nw . ':' . $nw . '@%i', '${1}[redacted]@'],
            ['%\b(authorization["\']?' . $ws . '*[:=]' . $ws . '*)[^\n"\']*%i', '${1}[redacted]'],
            ['%\b(Bearer|Basic|Splunk|Token)' . $ws . '+[\w.~+/=-]{6,}%i', '${1} [redacted]'],
            ['%\b((?:token|secret|password|passwd|pwd|api[_-]?key|dd-api-key|key|signature|sig|credential)["\']?' . $ws . '*[:=]' . $ws . '*)'
                . '("[^"]*"|\'[^\']*\'|(?:(?!' . $ws . ')[^"\'&,;])+)%i', '${1}[redacted]'],
            ['%[A-Za-z0-9_-]{32,}%', '[redacted]'],
        ];
    }

    /** Remove credentials from an error message: URL userinfo, token= style pairs, bearer credentials, long token-like runs. */
    public static function scrubError(mixed $message): string
    {
        $t = is_string($message) ? $message : Jsx::str($message);
        foreach (self::scrubRules() as [$rx, $rep]) {
            $r = preg_replace($rx, $rep, $t);
            if ($r === null) { // a pattern gave up: nothing unscrubbed leaves
                return '[redacted]';
            }
            $t = $r;
        }
        return Js::len($t) > 300 ? self::u16slice($t, 300) . '...' : $t;
    }

    /** {format, object?, line}: CEF is a bare line; any format other than cef / ocsf yields ECS. */
    public static function formatDecision(mixed $record, mixed $fmt, mixed $opts = null, mixed $now = null): array
    {
        if ($fmt === 'cef') {
            return ['format' => $fmt, 'line' => self::toCef($record, $opts, $now)];
        }
        $obj = $fmt === 'ocsf' ? self::toOcsfEvent($record, $opts, $now) : self::toEcs($record, $opts, $now);
        return ['format' => $fmt, 'object' => $obj, 'line' => Js::stringify($obj)];
    }

    private static function errText(\Throwable $e): string
    {
        $m = $e->getMessage();
        return $m !== '' ? $m : (new \ReflectionClass($e))->getShortName();
    }

    private static function resp(mixed $res, string $k): mixed
    {
        if ($res instanceof Obj) {
            return $res->get($k);
        }
        if (is_array($res)) {
            return $res[$k] ?? null;
        }
        return is_object($res) && isset($res->$k) ? $res->$k : null;
    }

    /** The default collector transport: one POST, bounded by the init's `timeout` (seconds). */
    private static function streamFetch(string $url, array $init): array
    {
        $hdr = [];
        foreach ($init['headers']->keys() as $k) {
            $hdr[] = $k . ': ' . $init['headers']->get($k);
        }
        $ctx = stream_context_create(['http' => [
            'method' => $init['method'], 'header' => implode("\r\n", $hdr), 'content' => $init['body'], 'timeout' => $init['timeout'], 'ignore_errors' => true,
        ]]);
        $body = @file_get_contents($url, false, $ctx);
        $line = $http_response_header[0] ?? '';
        if ($body === false && $line === '') {
            throw new SiemTimeout('delivery timed out');
        }
        $status = preg_match('#^HTTP/\S+\s+(\d{3})(?:\s+(.*))?$#', $line, $m) === 1 ? (int)$m[1] : 0;
        return ['ok' => $status >= 200 && $status < 300, 'status' => $status, 'statusText' => $m[2] ?? ''];
    }

    /**
     * One POST per batch: NDJSON for OCSF / ECS, raw CEF lines for CEF. `fetch(url, init)` returns {ok, status, statusText?}; init
     * carries method, headers (an Obj), body and `timeout` (seconds); a fetch that gives up throws {@see SiemTimeout}. PHP cannot
     * preempt a blocked call, so the bound is the fetch's own timeout. Delivery never throws.
     * Options (an Obj or an assoc array): headers, fetch, contentType, name, timeoutMs.
     */
    public static function httpSink(string $url, mixed $fmt, mixed $options = null): SiemSink
    {
        $headers = Js::opt($options, 'headers');
        $fetch = Js::opt($options, 'fetch');
        $contentType = Js::opt($options, 'contentType');
        $name = Js::opt($options, 'name');
        $timeoutMs = Js::opt($options, 'timeoutMs');
        $deliver = static function (array $events) use ($url, $fmt, $headers, $fetch, $contentType, $timeoutMs): array {
            try {
                $body = implode("\n", array_map(static fn($e) => $e['line'], $events));
                $hdrs = new Obj();
                $ct = $contentType ?? (is_string($fmt) ? (self::CONTENT_TYPE[$fmt] ?? null) : null);
                if ($ct !== null) {
                    $hdrs->set('content-type', $ct);
                }
                if ($headers instanceof Obj) {
                    foreach ($headers->keys() as $k) {
                        $hdrs->set($k, $headers->get($k));
                    }
                } elseif (is_array($headers)) {
                    foreach ($headers as $k => $v) {
                        $hdrs->set((string)$k, $v);
                    }
                }
                $tm = $timeoutMs ?? 10000;
                $f = Js::num($tm);
                $secs = (($f !== null && is_finite($f) && $f > 0) ? $f : 10000.0) / 1000.0;
                $res = ($fetch ?? self::streamFetch(...))($url, ['method' => 'POST', 'headers' => $hdrs, 'body' => $body, 'timeout' => $secs]);
                if (Jsx::truthy(self::resp($res, 'ok'))) {
                    return ['ok' => true];
                }
                $st = self::resp($res, 'statusText');
                return ['ok' => false, 'error' => self::scrubError('HTTP ' . Jsx::str(self::resp($res, 'status')) . (Jsx::truthy($st) ? ' ' . Jsx::str($st) : ''))];
            } catch (SiemTimeout) {
                return ['ok' => false, 'error' => 'delivery timed out'];
            } catch (\Throwable $e) { // delivery never throws
                return ['ok' => false, 'error' => self::scrubError(self::errText($e))];
            }
        };
        return new SiemSink($name ?? 'http:' . Jsx::str($fmt), $fmt, \Closure::fromCallable($deliver));
    }

    /** Writes each event's serialized line to a logger (default: standard output). Never throws. */
    public static function consoleSink(mixed $fmt = null, ?callable $logger = null, ?string $name = null): SiemSink
    {
        $f = $fmt ?? 'ocsf';
        $log = $logger ?? static function (string $line): void {
            echo $line, "\n";
        };
        $deliver = static function (array $events) use ($log): array {
            try {
                foreach ($events as $e) {
                    $log($e['line']);
                }
                return ['ok' => true];
            } catch (\Throwable $e) {
                return ['ok' => false, 'error' => self::scrubError(self::errText($e))];
            }
        };
        return new SiemSink($name ?? 'console:' . Jsx::str($f), $f, \Closure::fromCallable($deliver));
    }

    // ---- export -------------------------------------------------------------------------------------------------------

    private static function safeOnError(?callable $onError, \Throwable $error, string $sink, int $count): void
    {
        if ($onError === null) {
            return;
        }
        try {
            $onError($error, ['sink' => $sink, 'count' => $count]);
        } catch (\Throwable) { // an onError that throws must never reach the auth path
        }
    }

    /**
     * Export decisions in ONE delivery. Fail-safe: any serialization or delivery error is scrubbed, reported through
     * onError($error, ['sink' => name, 'count' => n]) and returned as ['ok' => false, 'error' => ...]; nothing is thrown.
     * @param list<mixed> $records
     */
    public static function exportBatch(array $records, SiemSink $sink, ?callable $onError = null, mixed $serialize = null, mixed $now = null): array
    {
        $fmt = $sink->format;
        $count = 0;
        try {
            $events = [];
            $skipped = 0;
            foreach ($records as $r) {
                try {
                    $events[] = self::formatDecision($r, $fmt, $serialize, $now);
                } catch (\Throwable $e) { // one bad record must not take the others' audit trail
                    $skipped++;
                    self::safeOnError($onError, new \Exception(self::scrubError('record could not be serialized: ' . self::errText($e))), $sink->name, 1);
                }
            }
            $count = count($events);
            if (!$events && $skipped > 0) {
                return ['ok' => false, 'delivered' => 0, 'format' => $fmt, 'error' => 'no record could be serialized', 'skipped' => $skipped];
            }
            $res = ($sink->deliver)($events);
            $extra = $skipped > 0 ? ['skipped' => $skipped] : [];
            if (Jsx::truthy(self::resp($res, 'ok'))) {
                return ['ok' => true, 'delivered' => count($events), 'format' => $fmt] + $extra;
            }
            $er = self::resp($res, 'error');
            $err = new \Exception(self::scrubError(self::nullish($er) ? 'sink reported a delivery failure' : $er));
            self::safeOnError($onError, $err, $sink->name, count($events));
            return ['ok' => false, 'delivered' => 0, 'format' => $fmt, 'error' => $err->getMessage()] + $extra;
        } catch (\Throwable $e) {
            $err = new \Exception(self::scrubError(self::errText($e)));
            self::safeOnError($onError, $err, $sink->name, $count);
            return ['ok' => false, 'delivered' => 0, 'format' => $fmt, 'error' => $err->getMessage()];
        }
    }

    public static function exportDecision(mixed $record, SiemSink $sink, ?callable $onError = null, mixed $serialize = null, mixed $now = null): array
    {
        return self::exportBatch([$record], $sink, $onError, $serialize, $now);
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
