<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Decide.php';
require_once __DIR__ . '/Assurance.php';
require_once __DIR__ . '/Beacons.php';
require_once __DIR__ . '/RevocationStaleness.php';
require_once __DIR__ . '/IntentV2.php';

/**
 * The resource-server verifier with the full verdict (`verifyPCActn` of the reference's server module): one call answers
 * `allow`, the recomputed risk `r`, the `requiredThreshold`, every check with its status (`pass` / `fail` / `not-enforced` /
 * `unsupported`), the reasons in order, the budget after the decision (when it allows or escalates) and, when asked, the
 * per-check assurance report. It never throws: an internal error is a fail-closed verdict (`malformed: fail`).
 *
 * It is a thin layer over the existing paths: the signature / chain / plan / counter / intent checks are {@see Pca::verifyPcactnCore}
 * (its check names and reason texts are renamed to the reference's), the release decision is {@see Decide::decide}, the assurance
 * report and requirement are {@see Assurance}, the revocation epoch is {@see RevocationStaleness::checkEpoch}, the beacon is
 * {@see Beacons}. Only the fold of those results into one verdict is here.
 *
 * Options (`$opts`: an Obj or an assoc array; every key optional except `grant`): grant (the verifier's OWN stored grant), now,
 * audience (a string; an explicit null accepts any audience; absent fails closed), insecureSkipPlanRootCheck, context (params, subject,
 * env, plan, planAuthorized, reversibilityClass, risk, budget, recentActionTimes, revocationEpoch, beacon), require, allowedSuites,
 * pqPins, operation, requireRiskInputs, assurance, requireAssurance, allowUnsupported, intent, intentV2, freshAt, k1, hooks
 * (assoc array attestation / threshold / revocation / zk of callables `(array{pcactn,grant,nowEpoch}): array{enforced,ok?,reason?,t?}`),
 * enforce (assoc array: freshness {maxAgeMs, epochMs?, now?, clockSkewMs?}, attestation {verifier, required?}, taint {registry, resourceGraph, maxTaint}).
 * There is NO allowUnboundPq: it is ignored (a PQ key is never read from the artifact).
 *
 * @return array{allow: bool, r: float|int, requiredThreshold: array{t:int|float, proof:string, optimisticAllowed:bool}, checks: array<string,string>,
 *               reasons: list<string>, budget?: array, assurance?: array}
 */
final class VerifyVerdict
{
    /** The minimum enforcement profile of a stateless resource server. */
    public const DEFAULT_REQUIRED_CHECKS = ['counter_format', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];
    /** The profile of a stateful resource server: the stateless one plus the replay counter. */
    public const STATEFUL_REQUIRED_CHECKS = ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];

    private const WORST = ['t' => 3, 'proof' => 'strong', 'optimisticAllowed' => false];
    private const MAX_SAFE = 9007199254740991.0;
    /** The stage order of the reference's core (a hook that throws ends the stages after it). */
    private const STAGES = ['attestation', 'threshold', 'revocation', 'zk_compliance', 'bond'];
    /** The order in which the reference's core can fail (the first failure is its single reason). */
    private const RANK = ['wire' => 0, 'version' => 1, 'audience' => 2, 'validity' => 3, 'cap_chain' => 4, 'grant_ref_bound' => 5, 'plan_inclusion' => 6,
        'plan_root_authorized' => 7, 'leaf_signature' => 8, 'counter_format' => 9, 'intent' => 10, 'fresh_at' => 12, 'taint_gate' => 13, 'freshness' => 14,
        'attestation' => 15, 'threshold' => 16, 'revocation' => 17, 'zk_compliance' => 18, 'malformed' => 19];

    /** @return array<string,mixed> */
    public static function verify(mixed $pcactn, mixed $opts = null): array
    {
        try {
            $v = self::run($pcactn, $opts);
        } catch (\Throwable $e) {
            $v = self::failClosed('verifier error (fail closed): ' . $e->getMessage());
        }
        if ((Js::opt($opts, 'assurance') === true || Js::has($opts, 'requireAssurance') && Js::opt($opts, 'requireAssurance') !== null) && !array_key_exists('assurance', $v)) {
            $v['assurance'] = Assurance::report($v['checks']);
        }
        return $v;
    }

    /** @param array<string,string> $checks */
    private static function failClosed(string $reason, array $checks = []): array
    {
        return ['allow' => false, 'r' => 1, 'requiredThreshold' => self::WORST, 'checks' => $checks + ['malformed' => 'fail'], 'reasons' => [$reason]];
    }

    private static function num(mixed $x): ?float
    {
        $f = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $f;
    }

    private static function safeInt(?float $f): bool
    {
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= self::MAX_SAFE;
    }

    private static function list(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** The members of an Obj or assoc array as an Obj (anything else: an empty Obj). */
    private static function objOf(mixed $v): Obj
    {
        if ($v instanceof Obj) {
            return $v;
        }
        $o = new Obj();
        if (is_array($v) && !array_is_list($v)) {
            foreach ($v as $k => $x) {
                $o->set((string)$k, $x);
            }
        }
        return $o;
    }

    private static function copy(Obj $o): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $o->get($k));
        }
        return $c;
    }

    private static function hashOf(mixed $v): ?string
    {
        try {
            return Pca::hashCanonical($v);
        } catch (\Throwable) {
            return null;
        }
    }

    /** String(v) of a JSON value (a hook's t, a verb). */
    private static function str(mixed $v): string
    {
        return $v instanceof Num ? IntentWb::jsStr($v) : (is_string($v) ? $v : IntentWb::jsStr($v));
    }

    /** The reference's text for a reason of the PHP core (its check names and a few texts differ). */
    public static function text(string $r): string
    {
        $map = [
            'audience: this verifier supplied no audience (pass its audience, or Audience::Any to accept any)'
                => 'audience: PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)',
            'audience: aud does not match this verifier' => 'audience: aud does not match this resource server / instance',
            'validity: lifetime too long' => 'validity: lifetime exceeds ' . Pca::MAX_LIFETIME_MS . ' ms',
            'validity: iat is in the future' => 'validity: iat is in the future (clock skew)',
            'validity: expired' => 'validity: the PCActn has expired',
            'leaf_signature: signature does not verify under the leaf holder key' => 'leaf_signature: signature does not verify under the leaf holder key / suite',
        ];
        if (isset($map[$r])) {
            return $map[$r];
        }
        if (str_starts_with($r, 'chain: ')) {
            return 'cap_chain: ' . substr($r, 7);
        }
        if (str_starts_with($r, 'freshness_anchor: ')) {
            return 'freshness: ' . substr($r, 18);
        }
        if (str_starts_with($r, 'leaf_signature: leaf: ')) {
            return 'leaf_signature: ' . substr($r, 22);
        }
        if (preg_match('/\Aversion: unsupported ver (.*)\z/s', $r, $m) === 1) {
            return 'version: unsupported ver ' . $m[1] . ' (this verifier requires ' . Pca::PCACTN_VERSION . ')';
        }
        return $r;
    }

    /** The core's check name in the reference's vocabulary. */
    private static function nameOf(string $k): string
    {
        return $k === 'chain' ? 'cap_chain' : ($k === 'freshness_anchor' ? 'freshness' : $k);
    }

    private static function rank(string $reason): int
    {
        $c = strpos($reason, ':');
        return $c === false ? 99 : (self::RANK[substr($reason, 0, $c)] ?? 11); // the Intent v2 checks (schema ... classes) sit between intent and fresh_at
    }

    private static function run(mixed $pcactn, mixed $opts): array
    {
        // ---- decode
        if (is_string($pcactn)) {
            try {
                $p = Pca::decodePcactn($pcactn);
            } catch (\Throwable $e) {
                return self::failClosed('undecodable PCActn: ' . $e->getMessage());
            }
        } else {
            $p = $pcactn;
        }
        if ($p === null || is_scalar($p) || $p instanceof Num) {
            return self::failClosed('PCActn is not an object');
        }

        // ---- the options
        $grant = Js::opt($opts, 'grant');
        if (!($grant instanceof Obj) || !self::list($grant->get('caveats'))) {
            throw new \InvalidArgumentException('the grant is not a capability');
        }
        $nowRaw = Js::opt($opts, 'now') ?? (int)(microtime(true) * 1000);
        $nowF = self::num($nowRaw);
        if ($nowF === null || !is_finite($nowF)) { // Number.isFinite: a string, a boolean, NaN and the infinities are no clock
            return self::failClosed('the verifier clock is not a finite time');
        }
        $nowOk = self::safeInt($nowF);
        $nowInt = $nowOk ? (int)$nowF : 0;
        $nowFloat = $nowF ?? NAN;
        $nowCav = $nowF !== null && floor($nowF) === $nowF && abs($nowF) < 9.0e15 ? (int)$nowF : ($nowF ?? $nowRaw);
        $ctxIn = Js::opt($opts, 'context');
        $ctxOrig = self::objOf($ctxIn);
        $op = Js::opt($opts, 'operation');
        $hasOp = $op instanceof Obj || (is_array($op) && $op !== []);
        $opO = self::objOf($op);
        $ctx = self::copy($ctxOrig);
        if ($hasOp && $opO->get('params') !== null) {
            $ctx->set('params', $opO->get('params'));
        }
        $hooksIn = Js::opt($opts, 'hooks');
        $hook = static fn(string $n): mixed => is_array($hooksIn) && isset($hooksIn[$n]) && is_callable($hooksIn[$n]) ? $hooksIn[$n]
            : ($hooksIn instanceof Obj && is_callable($hooksIn->get($n)) ? $hooksIn->get($n) : null);
        $enforce = Js::opt($opts, 'enforce');
        $enf = static fn(string $k): mixed => is_array($enforce) ? ($enforce[$k] ?? null) : ($enforce instanceof Obj ? $enforce->get($k) : null);
        $attGate = $enf('attestation');
        $attVerifier = Js::opt($attGate, 'verifier');
        $attHook = is_callable($attVerifier) ? $attVerifier : $hook('attestation');
        $thHook = $hook('threshold');
        $requireIn = Js::opt($opts, 'require');

        // ---- the Intent v2 context (the grant's model rules need the plaintext params and the host env even without a v2 policy)
        $env = Authorize::readEnvelope($grant);
        $needsModelRules = $env !== null && ($env->has('units') || $env->has('tighten') || $env->has('model_polarity') || $env->has('actions')
            || Decision::modelPathsRead([$env->get('predicates')]) !== []);
        $v2In = Js::opt($opts, 'intentV2');
        $v2 = null;
        if (Js::truthy($v2In) || $needsModelRules) {
            $v2 = $v2In instanceof Obj ? self::copy($v2In) : new Obj();
            $prm = $v2->get('params') ?? $ctx->get('params');
            if ($prm !== null) {
                $v2->set('params', $prm);
            }
            $ev = $v2->get('env') ?? $ctx->get('env');
            if ($ev !== null) {
                $v2->set('env', $ev);
            }
        }
        $pObj = $p instanceof Obj ? $p : null;
        $v2d = $pObj !== null && ($pObj->has('intent_session') || $needsModelRules) ? IntentV2::decideIntentV2($pObj, $grant, $v2, $nowInt) : null;

        // ---- hooks as the core sees them: a hook that throws or answers null is the reference's `malformed` (later stages do not run)
        $thrown = null;
        $hookT = null;
        $ctxOf = static fn(): array => ['pcactn' => $p, 'grant' => $grant, 'nowEpoch' => $nowInt];
        $wrap = static function (string $stage, callable $h) use (&$thrown, &$hookT, $ctxOf): \Closure {
            return static function () use ($stage, $h, &$thrown, &$hookT, $ctxOf): array {
                try {
                    $r = $h($ctxOf());
                } catch (\Throwable $e) {
                    $thrown ??= [$stage, $e->getMessage()];
                    return ['enforced' => false];
                }
                if (!is_array($r)) {
                    if ($r === null) {
                        $thrown ??= [$stage, "Cannot read properties of null (reading 'enforced')"];
                    }
                    return ['enforced' => false];
                }
                if ($stage === 'threshold' && ($r['enforced'] ?? false) === true) {
                    $hookT = $r['t'] ?? null;
                }
                return $r;
            };
        };
        $coreHooks = [];
        if ($attHook !== null) {
            $coreHooks['attestation'] = $wrap('attestation', $attHook);
        }
        if ($hook('zk') !== null) {
            $coreHooks['zk'] = $wrap('zk_compliance', $hook('zk'));
        }
        $thClosure = $thHook !== null ? $wrap('threshold', $thHook) : null;

        // ---- audience: a string; an explicit null accepts any; absent fails closed; any other value never equals the signed aud
        if (!Js::has($opts, 'audience')) {
            $aud = null;
        } else {
            $a = Js::opt($opts, 'audience');
            $aud = $a === null ? Audience::Any : (is_string($a) ? $a : "\0not-a-string-audience");
        }
        $fr = $enf('freshness');
        $enforceFreshness = null;
        if ($fr !== null) {
            $enforceFreshness = [];
            foreach (['maxAgeMs', 'epochMs', 'now', 'clockSkewMs'] as $k) {
                $x = Js::opt($fr, $k);
                if ($x !== null) {
                    $enforceFreshness[$k] = $x instanceof Num ? ($x->isInt() ? $x->int() : $x->float()) : $x;
                }
            }
        }
        $allowed = Js::opt($opts, 'allowedSuites');
        $core = Pca::verifyPcactnCore($p, $grant, $nowInt, $aud, self::list($allowed) ? $allowed : null, Js::opt($opts, 'intent'), $v2,
            Js::opt($opts, 'freshAt'), null, true, $enforceFreshness, $thClosure, $coreHooks === [] ? null : $coreHooks);
        if (($core['checks']['wire'] ?? null) === false) {
            return self::failClosed($core['reason'] !== '' ? $core['reason'] : 'wire: malformed PCActn', ['wire' => 'fail']);
        }
        /** @var Obj $p */

        // ---- the core's verdict in the reference's vocabulary
        $checks = [];
        foreach ($core['checks'] as $k => $ok) {
            $checks[self::nameOf((string)$k)] = $ok ? 'pass' : 'fail';
        }
        foreach ($core['not_enforced'] ?? [] as $k) {
            $checks[self::nameOf($k)] = 'not-enforced';
        }
        if (!$nowOk) {
            $checks['validity'] = 'fail';
        }
        $coreReasons = array_map([self::class, 'text'], is_array($core['reasons'] ?? null) ? $core['reasons'] : []);
        if (!$nowOk) {
            $coreReasons = array_values(array_filter($coreReasons, static fn(string $r): bool => !str_starts_with($r, 'validity: ')));
            $coreReasons[] = 'validity: the verifier clock is not a safe integer epoch-ms';
        }
        $candidates = $coreReasons; // every failure of the core, for the first-failure rule
        $reason = null;

        // the opt-in taint gate (M1)
        $tg = $enf('taint');
        if ($tg === null) {
            $checks['taint_gate'] = 'not-enforced';
        } else {
            try {
                $t = Taint::taintGate($p->get('provenance'), Js::opt($tg, 'registry'), Js::opt($tg, 'resourceGraph'), Js::opt($tg, 'maxTaint'));
                if ($t['ok']) {
                    $checks['taint_gate'] = 'pass';
                } else {
                    $checks['taint_gate'] = 'fail';
                    $candidates[] = 'taint_gate: ' . $t['reason'];
                }
            } catch (\Throwable $e) {
                $checks['taint_gate'] = 'fail';
                $candidates[] = 'taint_gate: taint gate error (fail closed): ' . $e->getMessage();
            }
        }
        // the attestation gate: with it on, a not-enforced / absent result is a failure unless required is false
        if ($thrown === null && ($attGate instanceof Obj || (is_array($attGate) && !array_is_list($attGate)))) {
            if (($checks['attestation'] ?? 'not-enforced') === 'not-enforced' && Js::opt($attGate, 'required') !== false) {
                $checks['attestation'] = 'fail';
                $candidates[] = 'attestation: attestation required but the verifier reported not-enforced / no document (fail closed)';
            }
        }
        $checks += ['attestation' => 'not-enforced', 'threshold' => 'not-enforced'];

        // the revocation hook runs after threshold and before zk
        if ($thrown === null) {
            $rev = $hook('revocation');
            if ($rev === null) {
                $checks['revocation'] = 'not-enforced';
            } else {
                $wrapRev = $wrap('revocation', $rev)();
                if ($thrown === null) {
                    if (($wrapRev['enforced'] ?? false) !== true) {
                        $checks['revocation'] = 'not-enforced';
                    } elseif (($wrapRev['ok'] ?? false) === true) {
                        $checks['revocation'] = 'pass';
                    } else {
                        $checks['revocation'] = 'fail';
                        $candidates[] = 'revocation: ' . (is_string($wrapRev['reason'] ?? null) ? $wrapRev['reason'] : 'rejected');
                    }
                }
            }
        }
        if ($thrown !== null) {
            $from = array_search($thrown[0], self::STAGES, true);
            foreach (array_slice(self::STAGES, $from === false ? 0 : $from) as $s) {
                unset($checks[$s]);
                $candidates = array_values(array_filter($candidates, static fn(string $r): bool => !str_starts_with($r, $s . ':') && !($s === 'zk_compliance' && str_contains($r, 'zk_compliance proof'))));
            }
            $checks['malformed'] = 'fail';
            $candidates[] = 'malformed: PCActn: ' . $thrown[1];
        }
        if ($p->has('bond_ref') && $thrown === null) {
            $checks['bond'] = 'unsupported';
        }
        // the core's single reason: its first failure in the reference's own order
        $first = null;
        foreach ($candidates as $c) {
            if ($first === null || self::rank($c) < self::rank($first)) {
                $first = $c;
            }
        }
        if ($first !== null && str_starts_with($first, 'malformed: PCActn: ')) {
            $first = 'malformed PCActn: ' . substr($first, 19);
        }
        $coreAllow = !in_array('fail', $checks, true);
        $reasons = !$coreAllow && $first !== null ? [$first] : [];
        if ($v2d !== null) {
            $reasons = Decision::foldV2Reasons($reasons, $v2d['checks']);
        }
        $unsupported = isset($checks['bond']) && $checks['bond'] === 'unsupported' ? ['bond'] : [];
        $fail = static function (string $name, string $why) use (&$checks, &$reasons): void {
            $checks[$name] = 'fail';
            $reasons[] = "$name: $why";
        };

        // ---- the server-side PQ pin
        $pqPins = Js::opt($opts, 'pqPins');
        if ($pqPins !== null) {
            $alg = $grant->get('alg') ?? 'ed25519';
            $issuer = $grant->get('issuer');
            $pins = $pqPins instanceof Obj ? $pqPins : self::objOf($pqPins);
            $has = is_string($issuer) && $pins->has($issuer);
            $pin = $has ? $pins->get($issuer) : null;
            if ($alg === 'ed25519') {
                if ($pin !== null || $has) {
                    $fail('pq_pin', 'the grant issuer is pinned to a post-quantum key; a classical grant is refused');
                } else {
                    $checks['pq_pin'] = 'pass';
                }
            } elseif (is_string($pin) && is_string($grant->get('pq_pk')) && $pin === $grant->get('pq_pk')) {
                $checks['pq_pin'] = 'pass';
            } else {
                $fail('pq_pin', $pin === null ? 'no server-side PQ pin for the grant issuer (suite ' . self::str($alg) . ')' : 'the grant pq_pk does not match the server-side pin');
            }
        }

        // ---- grant_ref and the operation
        if ($p->get('grant_ref') === $grant->get('id')) {
            $checks['grant_ref'] = 'pass';
        } else {
            $fail('grant_ref', 'does not reference the supplied grant');
        }
        $action = $p->get('action') instanceof Obj ? $p->get('action') : new Obj();
        if ($hasOp) {
            $opVerb = $opO->get('verb');
            $opRes = $opO->get('resource');
            $signed = self::str($action->get('verb')) . ' on ' . self::str($action->get('resource'));
            $opParams = $opO->get('params');
            if (!is_string($opVerb) || !is_string($opRes)) {
                $fail('operation', 'the server operation has no verb / resource (fail closed)');
            } elseif ($action->get('verb') !== $opVerb || $action->get('resource') !== $opRes) {
                $fail('operation', "the proof is for $signed, but this operation is $opVerb on $opRes");
            } elseif ($opParams !== null && self::hashOf($opParams) !== $action->get('params_digest')) {
                $fail('operation', "the proof's params_digest does not match the params of this $opVerb operation");
            } elseif ($opParams !== null && $ctxOrig->has('params') && self::hashOf($ctxOrig->get('params')) !== self::hashOf($opParams)) {
                $fail('operation', 'context.params differ from the operation params');
            } else {
                $checks['operation'] = 'pass';
            }
        }
        if ($ctx->has('params')) {
            if (self::hashOf($ctx->get('params')) === $action->get('params_digest')) {
                $checks['params_digest'] = 'pass';
            } else {
                $fail('params_digest', 'supplied params do not hash to action.params_digest');
            }
        } else {
            $checks['params_digest'] = 'not-enforced';
        }

        // ---- the server's own copy of the plan
        $planV = $ctx->get('plan');
        $planSupplied = Js::truthy($planV);
        $planNodes = null;
        $rootMatches = false;
        if ($planSupplied) {
            if (!self::list($planV)) {
                throw new \TypeError('ctx.plan.map is not a function');
            }
            $leaves = [];
            foreach ($planV as $n) {
                if (!($n instanceof Obj)) {
                    throw new \TypeError('plan node is not an object');
                }
                $leaves[] = Pca::planLeaf($n->get('id'), $n, Pca::conditionsDigest($n->get('pre'), $n->get('post')));
            }
            $planNodes = $planV;
            $rootMatches = Pca::merkleRoot($leaves) === ($p->get('plan') instanceof Obj ? $p->get('plan')->get('root') : null);
        }
        $authorized = $ctx->get('planAuthorized');
        if (!$planSupplied) {
            $pd = 'not-enforced';
        } elseif (!$rootMatches) {
            $pd = 'mismatch';
        } else {
            $pd = $authorized === true ? 'pass' : ($authorized === false ? 'unauthorized' : 'not-enforced');
        }
        if ($pd === 'mismatch') {
            $fail('plan_root_authorized', 'known plan does not match plan.root');
        } elseif ($pd === 'unauthorized') {
            $fail('plan_root_authorized', 'the plan root has not been authorized by the principal');
        } elseif ($pd === 'pass') {
            $checks['plan_root_authorized'] = 'pass';
        } elseif (Js::opt($opts, 'insecureSkipPlanRootCheck') === true) {
            $checks['plan_root_authorized'] = 'not-enforced';
        } else {
            $fail('plan_root_authorized', 'default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)');
        }

        // ---- the guardian-signed revocation epoch
        $re = $ctx->get('revocationEpoch');
        if (Js::truthy($re)) {
            $r = RevocationStaleness::checkEpoch(Js::opt($re, 'epoch'), array_filter([
                'guardianPublic' => Js::opt($re, 'guardianPublic'), 'now' => $nowFloat, 'grantRef' => $grant->get('id'),
                'lastAcceptedEpoch' => self::num(Js::opt($re, 'lastAcceptedEpoch')),
                'pcactnEpoch' => self::num($p->get('freshness') instanceof Obj ? $p->get('freshness')->get('epoch') : null),
                'maxAgeMs' => self::num(Js::opt($re, 'maxAgeMs')),
            ], static fn(mixed $v): bool => $v !== null));
            if ($r['ok']) {
                if (($checks['freshness'] ?? null) !== 'fail') {
                    $checks['freshness'] = 'pass';
                }
            } else {
                $fail('freshness', $r['reason'] ?? 'revocation epoch rejected');
            }
        } elseif (!isset($checks['freshness'])) {
            $checks['freshness'] = 'not-enforced';
        }

        // ---- the dead-man liveness beacon
        $bc = $ctx->get('beacon');
        $br = null;
        $replayed = false;
        $refBinds = false;
        $bcOn = Js::truthy($bc);
        if ($bcOn) {
            $bObj = Js::opt($bc, 'beacon');
            $issuers = Js::opt($bc, 'issuers');
            $br = Beacons::verify($bObj, self::list($issuers) ? $issuers : [], $nowFloat, Js::opt($bc, 'instance'),
                is_string($grant->get('id')) ? $grant->get('id') : null, Js::opt($bc, 'pqPins'));
            $last = self::num(Js::opt($bc, 'lastAcceptedSeq'));
            $seq = self::num($bObj instanceof Obj ? $bObj->get('seq') : null);
            $replayed = $br['ok'] && $last !== null && $seq !== null && $seq < $last;
            $fresh = $p->get('freshness');
            $refBinds = $br['ok'] && !$replayed && $fresh instanceof Obj && $bObj instanceof Obj && $fresh->get('beacon_ref') === Beacons::beaconRef($bObj);
        }
        switch ($bcOn ? Beacons::decision(true, $br['ok'], $replayed, $refBinds) : 'not-enforced') {
            case 'rejected':
                $fail('beacon', $br['reason'] ?? 'beacon rejected');
                break;
            case 'replayed':
                $fail('beacon', 'beacon seq ' . IntentV2::jsNumStr((float)self::num(Js::opt(Js::opt($bc, 'beacon'), 'seq')))
                    . ' is older than the last accepted ' . IntentV2::jsNumStr((float)self::num(Js::opt($bc, 'lastAcceptedSeq'))) . ' (replay)');
                break;
            case 'unbound':
                $fail('beacon', 'PCActn freshness.beacon_ref does not bind the presented beacon');
                break;
            case 'pass':
                $checks['beacon'] = 'pass';
                break;
            default:
                $checks['beacon'] = 'not-enforced';
        }

        // ---- require-when-bound: a grant that binds the agent REQUIRES a passing attestation
        if (Authorize::requiresAttestation($env?->get('agent_binding')) && ($checks['attestation'] ?? null) !== 'pass') {
            $fail('attestation', 'the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED');
        }

        // ---- budget (an absent one fails closed to B = 0) and the risk inputs
        $hasBudget = $ctx->has('budget');
        $ctxBudget = $ctx->get('budget');
        $checks['budget'] = Js::truthy($ctxBudget) ? 'pass' : 'not-enforced';
        if (!$hasBudget) {
            $reasons[] = 'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge';
        }
        $budgetIn = $ctxBudget ?? Obj::of(['B' => 0, 'tau' => $nowRaw, 'asOf' => $nowRaw]);
        $risk = $ctx->get('risk') instanceof Obj ? self::copy($ctx->get('risk')) : new Obj();
        $reqRisk = Js::opt($opts, 'requireRiskInputs');
        if (self::list($reqRisk) && $reqRisk !== []) {
            $supplied = static function (string $k) use ($risk, $ctx): bool {
                $f = self::num($risk->get($k));
                return ($f !== null && is_finite($f)) || ($k === 'semanticDistance' && $ctx->has('plan'));
            };
            $missing = array_values(array_filter($reqRisk, static fn(mixed $k): bool => !$supplied((string)$k)));
            if ($missing !== []) {
                $fail('risk_inputs', 'required risk input(s) not supplied by the server: ' . implode(', ', array_map('strval', $missing)));
            } else {
                $checks['risk_inputs'] = 'pass';
            }
        }

        // ---- reversibility: the server's class wins; the agent may only be stricter
        $declared = $action->get('reversibility_class');
        $reversibility = $declared;
        if ($ctx->has('reversibilityClass')) {
            $sc = $ctx->get('reversibilityClass');
            $dr = Authorize::classRank($declared);
            $sr = Authorize::classRank($sc);
            if ($dr < $sr) {
                $fail('reversibility', "declared class '" . self::str($declared) . "' is less restrictive than the authoritative '" . self::str($sc) . "'");
            } else {
                $checks['reversibility'] = 'pass';
            }
            $reversibility = $dr > $sr ? $declared : $sc;
        }

        // ---- the Policy VM
        $inner = new Obj();
        $inner->set('verb', $action->get('verb'));
        $inner->set('resource', $action->get('resource'));
        if ($ctx->get('params') !== null) {
            $inner->set('params', $ctx->get('params'));
        }
        if ($reversibility !== null) {
            $inner->set('reversibility_class', $reversibility);
        }
        $actionCtx = Obj::of(['action' => $inner]);
        if ($ctx->get('subject') !== null) {
            $actionCtx->set('subject', $ctx->get('subject'));
        }
        $pe = Authorize::v2Env($p, $grant, $v2, $nowInt, $ctx->get('env'));
        if ($pe !== null) {
            $actionCtx->set('env', $pe);
        }
        if (is_string($p->get('tool_binding'))) {
            $actionCtx->set('toolBinding', $p->get('tool_binding'));
        }
        $chain = self::list($p->get('cap_chain')) ? $p->get('cap_chain') : [];
        $depth = max(0, count($chain) - 1);
        $recent = $ctx->get('recentActionTimes');
        $caveatCtx = Obj::of(['delegationDepth' => $depth]);
        if ($recent !== null) {
            $caveatCtx->set('recentActionTimes', $recent);
        }
        $plan = $p->get('plan') instanceof Obj ? $p->get('plan') : new Obj();
        $in = Obj::of(['grant' => $grant, 'trustedRoot' => $grant, 'action' => $actionCtx]);
        if ($pqPins !== null) {
            $in->set('pqPins', $pqPins instanceof Obj ? $pqPins : self::objOf($pqPins));
        }
        if ($planSupplied) {
            $in->set('plan', $planNodes);
        }
        $in->set('nodeId', $plan->get('node_id'));
        $in->set('risk', $risk);
        $in->set('budget', $hasBudget ? $budgetIn : self::withB0($budgetIn));
        $in->set('now', $nowRaw);
        $in->set('caveatContext', $caveatCtx);
        $k1In = Js::opt($opts, 'k1');
        if ($k1In !== null) {
            $k = self::copy(self::objOf($k1In));
            $k = $k->without('narrow');
            $in->set('k1', CaveatLang::withActionDigest($k, CaveatLang::dischargeActionDigest($p)));
        }
        if ($p->get('caution') instanceof Num) {
            $in->set('rFloor', $p->get('caution'));
        }
        $d = Decide::decide($in);

        // caveats added by delegation hops are conjunctive too
        $leaf = $chain !== [] ? $chain[count($chain) - 1] : null;
        if ($leaf !== null) {
            if (!($leaf instanceof Obj) || !self::list($leaf->get('caveats'))) {
                throw new \TypeError('leaf.caveats.slice is not a function');
            }
            $extra = array_slice($leaf->get('caveats'), count($grant->get('caveats')));
            $useK1 = $k1In !== null && Js::has($k1In, 'narrow');
            foreach ($leaf->get('caveats') as $c) {
                $useK1 = $useK1 || CaveatLang::isK1Caveat($c);
            }
            $k1r = null;
            if ($useK1) {
                $k1r = CaveatLang::evaluateK1($grant, $chain, $k1In === null ? null : CaveatLang::withActionDigest(self::objOf($k1In), CaveatLang::dischargeActionDigest($p)),
                    Obj::of(['now' => $nowCav, 'action' => $inner]));
            }
            $cctx = Obj::of(['now' => $nowCav, 'action' => $inner, 'delegation_depth' => $depth]);
            if ($risk->get('blastRadius') !== null) {
                $cctx->set('blast_radius', $risk->get('blastRadius'));
            }
            $rc = Decide::resolveReversibilityClass($inner, $planNodes, $plan->get('node_id'));
            if ($rc !== null) {
                $cctx->set('reversibility_class', $rc);
            }
            if ($recent !== null) {
                $cctx->set('recent_action_times', $recent);
            }
            $list = array_merge(array_values(array_filter($extra, static fn(mixed $c): bool => !CaveatLang::isK1Caveat($c))), $k1r['plain'] ?? []);
            $cv = Authorize::evaluateAgentCaveats($list, $cctx, $actionCtx, Authorize::toolCallOf($actionCtx));
            if ($cv['ok'] && ($k1r === null || $k1r['ok'])) {
                $checks['delegated_caveats'] = 'pass';
            } else {
                $fail('delegated_caveats', 'delegation caveat(s) not satisfied: ' . implode(', ', array_merge($cv['failed'], $k1r['failed'] ?? []))
                    . ($k1r !== null && !$k1r['ok'] ? ' (' . implode('; ', $k1r['reasons']) . ')' : ''));
            }
        }

        // ---- policy and threshold
        $release = $d['releaseGuardianShare'] === true;
        $checks['policy'] = $release ? 'pass' : 'fail';
        foreach ($d['reasons'] as $x) {
            $reasons[] = "policy: $x";
        }
        $tReq = $d['requiredThreshold']['t'];
        $th = $checks['threshold'] ?? null;
        $hf = self::num($hookT);
        $hookTi = $hf === null || is_nan($hf) ? null : ($hf >= self::MAX_SAFE ? self::MAX_SAFE : ($hf <= -self::MAX_SAFE ? -self::MAX_SAFE : floor($hf)));
        if ($tReq > 1 && $release && $th === 'pass' && !($hookTi !== null && $hookTi >= $tReq)) {
            $fail('threshold', 'threshold hook enforced t=' . ($hookT === null ? 'unreported' : self::str($hookT)) . " but the server requires t=$tReq (below the server-derived threshold; derive t from server-held data)");
        } elseif ($tReq > 1 && $release && $th !== 'pass') {
            $fail('threshold', $th === 'fail' ? "t=$tReq required and the threshold proof was rejected"
                : "t=$tReq ({$d['requiredThreshold']['proof']}) required but no threshold verifier is enforced");
        }

        // ---- assurance
        $required = $requireIn ?? self::DEFAULT_REQUIRED_CHECKS;
        $reqA = Js::opt($opts, 'requireAssurance');
        $wantAssurance = Js::opt($opts, 'assurance') === true || Js::has($opts, 'requireAssurance') && $reqA !== null;
        $hooksForReport = array_filter(['attestation' => $hook('attestation'), 'zk' => $hook('zk'), 'threshold' => $thHook, 'revocation' => $hook('revocation')],
            static fn(mixed $h): bool => $h !== null);
        $degraded = ($v2d['legacy_model_polarity'] ?? false) === true
            ? ['tighten' => "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)"] : [];
        $report = static fn(array $cs): array => Assurance::report($cs, $p, $hooksForReport, $attHook, $hf, false, $degraded);
        if ($reqA !== null && Js::truthy($reqA)) {
            $unmet = self::unmet($report($checks), $reqA);
            if ($unmet === null) {
                $checks['assurance'] = 'pass';
            } else {
                $checks['assurance'] = 'fail';
                $reasons[] = $unmet; // the requirement's own text, already prefixed
            }
        }

        $allow = !in_array('fail', $checks, true) && $release && $coreAllow;
        $final = $checks;
        foreach ($unsupported as $n) {
            if (($final[$n] ?? null) === 'not-enforced') {
                $final[$n] = 'unsupported';
            }
        }
        // the decision's budget: an array after a decision, the caller's own object after a refusal before the decision; a stamp the budget never had stays absent
        $budgetOf = static function (mixed $b): array {
            $o = ['B' => $b instanceof Obj ? $b->get('B') : $b['B']];
            if ($b instanceof Obj ? $b->has('tau') : array_key_exists('tau', $b)) {
                $o['tau'] = $b instanceof Obj ? $b->get('tau') : $b['tau'];
            }
            $o['asOf'] = $b instanceof Obj ? $b->get('asOf') : ($b['asOf'] ?? null);
            return $o;
        };
        $budgetOut = Js::truthy($ctxBudget) ? $budgetOf($d['budget']) : null;
        if (!self::list($required) && $required !== self::DEFAULT_REQUIRED_CHECKS) {
            throw new \TypeError('required.map is not a function');
        }
        $refused = array_values(array_filter($unsupported, static fn(string $n): bool => !in_array($n, self::allowList(Js::opt($opts, 'allowUnsupported')), true)));
        if ($refused !== []) {
            $out = ['allow' => false, 'r' => $d['r'], 'requiredThreshold' => $d['requiredThreshold'], 'checks' => $final,
                'reasons' => array_merge($reasons, array_map(static fn(string $n): string => "$n: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)", $refused))];
            $out = self::enforce($out, $required);
            if ($wantAssurance) {
                $out['assurance'] = Assurance::refresh($report($final), $out['checks']);
            }
            return $out;
        }
        $out = ['allow' => $allow, 'r' => $d['r'], 'requiredThreshold' => $d['requiredThreshold'], 'checks' => $final, 'reasons' => $reasons];
        if ($allow && $budgetOut !== null) {
            $out['budget'] = $budgetOut;
        }
        $out = self::enforce($out, $required);
        // an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
        if (!$out['allow'] && Js::truthy($ctxBudget) && Decision::decisionOf(false, $out['checks'], $out['reasons']) === 'escalate') {
            $out['budget'] = $budgetOf($d['budget']);
        }
        if (!$out['allow'] && $out['reasons'] === []) {
            $out['reasons'] = ['denied'];
        }
        if ($wantAssurance) {
            $out['assurance'] = Assurance::refresh($report($final), $out['checks']);
        }
        return $out;
    }

    private static function withB0(mixed $b): mixed
    {
        if (!($b instanceof Obj)) {
            return $b;
        }
        $c = self::copy($b);
        $c->set('B', 0);
        return $c;
    }

    /** @return list<string> */
    private static function allowList(mixed $v): array
    {
        return self::list($v) ? array_values(array_filter($v, 'is_string')) : [];
    }

    /**
     * Default-deny: every required check must be `pass`; one that is not turns the verdict to a deny and (unless already `fail`) is recorded as
     * `fail` with its reason. `counter` is the old name of `replay` (with a store) or `counter_format`.
     * @param array<string,mixed> $v
     * @param list<mixed> $required
     * @return array<string,mixed>
     */
    public static function enforce(array $v, array $required): array
    {
        $checks = $v['checks'];
        $reasons = $v['reasons'];
        $allow = $v['allow'];
        foreach ($required as $name) {
            $name = (string)$name;
            if ($name === 'counter' && !array_key_exists('counter', $checks)) {
                $name = array_key_exists('replay', $checks) ? 'replay' : 'counter_format';
            }
            $st = $checks[$name] ?? null;
            if ($st === 'pass') {
                continue;
            }
            $allow = false;
            if ($st === 'fail') {
                continue;
            }
            $reasons[] = "$name: required check is " . ($st === 'unsupported' ? 'unsupported' : ($st ?? 'absent')) . ' (default-deny: not enforced by this resource server)';
            $checks[$name] = 'fail';
        }
        $v['allow'] = $allow;
        $v['checks'] = $checks;
        $v['reasons'] = $reasons;
        return $v;
    }

    /**
     * Assurance::unmet over a requirement given as an Obj / array / {@see AssuranceRequirement}: the one function, which refuses an unknown key
     * or value (a `threshold` that is not a list included) fail closed.
     * @param array<string,array<string,mixed>> $report
     */
    private static function unmet(array $report, mixed $req): ?string
    {
        return Assurance::unmet($report, $req instanceof AssuranceRequirement ? $req : AssuranceRequirement::fromJson($req));
    }
}
