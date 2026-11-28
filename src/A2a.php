<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/PcaGrant.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Payments.php';
require_once __DIR__ . '/Agentcard.php';

/** A verifier configured without any authority (`grant` or `expectedRootIssuer`): a chain is never its own authority. */
final class A2aAuthorityError extends \RuntimeException
{
    public const CODE = 'authority_required';
    public readonly string $codeName;

    public function __construct()
    {
        $this->codeName = self::CODE;
        parent::__construct('pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority');
    }
}

/**
 * The A2A binding: typed needs (`pca_need`), per-hop chain extension, the pure gate of AUTH_REQUIRED resumption, push-token binding
 * and signed task-update receipts (replaying packages/pca/conformance/a2a-vectors.json), and the rest of the pca-a2a package surface:
 * proof-carrying tasks, signed and extended Agent Cards, the extension declaration, AUTH_REQUIRED mapping, per-hop delegation and the
 * payment-mandate envelope (see the section below). Values are parsed JSON (Obj, lists, Num).
 */
final class A2a
{
    /** The `pca_need` challenge auth-param name and the domain of a need's content address (pca-need.ts). */
    public const PCA_NEED_PARAM = 'pca_need';
    public const PCA_NEED_DOMAIN = 'atlas-pca/need/v1';
    private const NEED_MEMBERS = ['v', 'kind', 'verb', 'resource', 'scopes', 'grant_ref', 'limits', 'discharges', 'tier', 'policy_digest'];
    private const TERMINAL = ['TASK_STATE_COMPLETED', 'TASK_STATE_FAILED', 'TASK_STATE_CANCELED', 'TASK_STATE_REJECTED'];
    private const STATES = ['TASK_STATE_COMPLETED', 'TASK_STATE_FAILED', 'TASK_STATE_CANCELED', 'TASK_STATE_REJECTED', 'TASK_STATE_SUBMITTED', 'TASK_STATE_WORKING', 'TASK_STATE_INPUT_REQUIRED', 'TASK_STATE_AUTH_REQUIRED'];
    public const RECEIPT_DOMAIN = "atlas-pca/a2a-receipt/v1\0";

    /** null when valid, else the refusal code. */
    public static function needError(mixed $x): ?string
    {
        if (!($x instanceof Obj)) {
            return 'bad_shape';
        }
        foreach ($x->keys() as $k) {
            if (!in_array($k, self::NEED_MEMBERS, true)) {
                return 'unknown_member';
            }
        }
        if (!K3Sig::isNumber($x->get('v'), 1.0)) {
            return 'bad_version';
        }
        $kind = $x->get('kind');
        if (!in_array($kind, ['scope', 'grant', 'discharge', 'escalate'], true)) {
            return 'bad_kind';
        }
        if (!K3Sig::isStr($x->get('verb'), 128) || !K3Sig::isStr($x->get('resource'), 512)) {
            return 'bad_field';
        }
        if ($x->has('scopes')) {
            $sc = $x->get('scopes');
            if (!K3Sig::isList($sc) || count($sc) > 16) {
                return 'bad_field';
            }
            foreach ($sc as $s) {
                if (!K3Sig::isStr($s, 128) || preg_match('/' . IntentWb::JS_WS . '/', $s) === 1) {
                    return 'bad_field';
                }
            }
        }
        foreach (['grant_ref', 'policy_digest'] as $k) {
            if ($x->has($k) && !K3Sig::isStr($x->get($k), 128)) {
                return 'bad_field';
            }
        }
        if ($x->has('tier')) {
            $t = K3Sig::num($x->get('tier'));
            if (($t !== 2.0 && $t !== 3.0) || $kind !== 'escalate') {
                return 'bad_field';
            }
        }
        if ($x->has('limits')) {
            $l = $x->get('limits');
            if (!($l instanceof Obj) || count($l->keys()) > 16) {
                return 'bad_field';
            }
            foreach ($l->keys() as $k) {
                $v = K3Sig::num($l->get($k));
                if (!K3Sig::isStr($k, 64) || $v === null || $v < 0.0) {
                    return 'bad_field';
                }
            }
        }
        if ($x->has('discharges')) {
            $d = $x->get('discharges');
            if (!K3Sig::isList($d) || count($d) > 16) {
                return 'bad_field';
            }
            foreach ($d as $e) {
                if (!($e instanceof Obj) || array_diff($e->keys(), ['issuer', 'claim']) !== [] || !K3Sig::isStr($e->get('issuer'), 512) || !K3Sig::isStr($e->get('claim'), 256)) {
                    return 'bad_field';
                }
            }
        }
        if ($kind === 'escalate' && !$x->has('tier')) {
            return 'bad_field';
        }
        return null;
    }

    /** @return array{0: ?Obj, 1: ?string} the need, or the refusal code */
    public static function decodeNeed(mixed $value): array
    {
        if (!is_string($value) || $value === '') {
            return [null, 'bad_base64'];
        }
        if (strlen($value) > 2048) {
            return [null, 'too_long'];
        }
        $raw = Pca::unb64u($value);
        if ($raw === null) {
            return [null, 'bad_base64'];
        }
        if (!mb_check_encoding($raw, 'UTF-8')) {
            return [null, 'bad_utf8'];
        }
        try {
            $parsed = Json::parseStrict($raw);
        } catch (\Throwable) {
            return [null, 'bad_json'];
        }
        $code = self::needError($parsed);
        return $code === null ? [$parsed, null] : [null, $code];
    }

    public static function needDigest(Obj $need): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::PCA_NEED_DOMAIN, 'need' => $need]));
    }

    /** Does `$next` (capability ids, root first) extend `$prev`? Attenuation only appends hops, so the earlier chain is a prefix. */
    public static function chainExtends(mixed $prev, mixed $next): bool
    {
        if (!is_array($prev) || !array_is_list($prev) || !is_array($next) || !array_is_list($next)) {
            throw new \TypeError('chainExtends: both chains must be lists');
        }
        if (count($next) < count($prev)) {
            return false;
        }
        foreach ($prev as $k => $id) {
            if (!Payments::seq($next[$k], $id)) {
                return false;
            }
        }
        return true;
    }

    /**
     * The chain rule of verifyA2ADelegation on its own: every hop has a chain and each extends the one before it.
     * @return array{ok: bool, failedHop?: int, reason?: string}
     */
    public static function checkChainExtension(mixed $chains): array
    {
        if ($chains === null) {
            throw new \TypeError("Cannot read properties of null (reading 'length')");
        }
        if (is_string($chains)) {
            return $chains === '' ? ['ok' => true] : ['ok' => false, 'failedHop' => 0, 'reason' => 'no_chain'];
        }
        if (!is_array($chains) || !array_is_list($chains)) {
            return ['ok' => true];
        }
        foreach ($chains as $i => $ids) {
            if (!is_array($ids) || !array_is_list($ids) || count($ids) === 0) {
                return ['ok' => false, 'failedHop' => $i, 'reason' => 'no_chain'];
            }
            if ($i > 0 && !self::chainExtends($chains[$i - 1], $ids)) {
                return ['ok' => false, 'failedHop' => $i, 'reason' => 'chain_does_not_extend_previous_hop'];
            }
        }
        return ['ok' => true];
    }

    public static function resumeGate(mixed $state, mixed $needEncoded, mixed $answerDigest, mixed $proofAction): ?string
    {
        if ($state !== 'TASK_STATE_AUTH_REQUIRED' && $state !== 'auth-required') {
            return 'task_not_auth_required';
        }
        $need = $needEncoded === null ? null : self::decodeNeed($needEncoded)[0];
        if ($need === null) {
            return 'no_valid_need';
        }
        if ($answerDigest !== self::needDigest($need)) {
            return 'answer_not_bound_to_need';
        }
        if (!($proofAction instanceof Obj)) {
            return 'no_proof';
        }
        if ($proofAction->get('verb') !== $need->get('verb') || $proofAction->get('resource') !== $need->get('resource')) {
            return 'action_mismatch';
        }
        return null;
    }

    /** @param list<string> $chainIds @return ?string null where the reference throws (a salt shorter than 16 characters) */
    public static function pushToken(string $taskId, array $chainIds, mixed $salt): ?string
    {
        if (!is_string($salt) || K3Sig::utf16Len($salt) < 16) {
            return null;
        }
        return IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/a2a-push/v1', 'task_id' => $taskId, 'chain' => PcaGrant::chainDigest($chainIds), 'salt' => $salt]));
    }

    /** @param list<string> $chainIds @return array{ok: bool, reason?: string} */
    public static function checkPush(string $taskId, array $chainIds, string $salt, mixed $token, mixed $payload): array
    {
        if (!is_string($token) || $token === '') {
            return ['ok' => false, 'reason' => 'no_token'];
        }
        $want = self::pushToken($taskId, $chainIds, $salt);
        if ($want === null || !hash_equals($want, $token)) {
            return ['ok' => false, 'reason' => 'token_mismatch'];
        }
        if ($payload instanceof Obj) {
            foreach ([['task', 'id'], ['statusUpdate', 'taskId'], ['artifactUpdate', 'taskId']] as [$key, $field]) {
                $c = $payload->get($key);
                $v = $c instanceof Obj ? $c->get($field) : null;
                if ($v !== null) {
                    return $v === $taskId ? ['ok' => true] : ['ok' => false, 'reason' => 'task_mismatch'];
                }
            }
        }
        return ['ok' => false, 'reason' => 'task_mismatch'];
    }

    public static function receiptDigest(mixed $r): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/a2a-receipt-ref/v1', 'r' => $r]));
    }

    public static function verifyReceipt(mixed $r, string $signer): bool
    {
        if (!($r instanceof Obj) || !K3Sig::isNumber($r->get('v'), 1.0) || $r->get('signer') !== $signer) {
            return false;
        }
        if (!K3Sig::isStr($r->get('task_id'), 4096) || !in_array($r->get('state'), self::STATES, true) || !K3Sig::isSafeInt($r->get('seq')) || !K3Sig::isSafeInt($r->get('issued_at'))) {
            return false;
        }
        $c = $r->get('chain');
        if (!is_string($c) || Pca::unb64u($c, 32) === null) {
            return false;
        }
        $prev = $r->get('prev');
        if (!$r->has('prev') || !($prev === null || (is_string($prev) && Pca::unb64u($prev, 32) !== null)) || (K3Sig::num($r->get('seq')) === 0.0) !== ($prev === null)) {
            return false;
        }
        $body = new Obj();
        foreach (['v', 'task_id', 'state', 'seq', 'prev', 'chain', 'issued_at', 'signer'] as $k) {
            $body->set($k, $r->get($k));
        }
        return K3Sig::verifyBody(self::RECEIPT_DOMAIN, $body, $signer, $r->get('sig'));
    }

    /**
     * @param list<mixed> $receipts @param list<string> $chainIds
     * @return array<string,mixed>
     */
    public static function checkReceiptChain(array $receipts, string $signer, string $taskId, array $chainIds): array
    {
        if (count($receipts) === 0) {
            return ['ok' => false, 'code' => 'empty'];
        }
        $chain = PcaGrant::chainDigest($chainIds);
        $prev = null;
        foreach ($receipts as $i => $r) {
            if (!self::verifyReceipt($r, $signer)) {
                return ['ok' => false, 'code' => 'bad_receipt', 'at' => $i];
            }
            if ($r->get('task_id') !== $taskId) {
                return ['ok' => false, 'code' => 'wrong_task', 'at' => $i];
            }
            if ($r->get('chain') !== $chain) {
                return ['ok' => false, 'code' => 'wrong_chain', 'at' => $i];
            }
            if ($prev === null) {
                if (K3Sig::num($r->get('seq')) !== 0.0) {
                    return ['ok' => false, 'code' => 'bad_start', 'at' => $i];
                }
            } else {
                if (in_array($prev->get('state'), self::TERMINAL, true)) {
                    return ['ok' => false, 'code' => 'after_terminal', 'at' => $i];
                }
                if (K3Sig::num($r->get('seq')) !== K3Sig::num($prev->get('seq')) + 1.0 || $r->get('prev') !== self::receiptDigest($prev)) {
                    return ['ok' => false, 'code' => 'broken_link', 'at' => $i];
                }
            }
            $prev = $r;
        }
        return ['ok' => true, 'terminal' => in_array($prev->get('state'), self::TERMINAL, true), 'last_state' => $prev->get('state')];
    }

    /** @param list<mixed> $receipts @param list<string> $chainIds */
    public static function mayTriggerNext(array $receipts, string $signer, string $taskId, array $chainIds): bool
    {
        $r = self::checkReceiptChain($receipts, $signer, $taskId, $chainIds);
        return $r['ok'] === true && $r['last_state'] === 'TASK_STATE_COMPLETED';
    }

    // ==== the package surface: tasks, Agent Cards, AUTH_REQUIRED, delegation, mandate envelope, receipts ======================
    //
    // Mirrors @atlasauth/pca-a2a. Values are the parsed-JSON model; options accept an Obj or a PHP associative array with the
    // reference's names; results are Obj (or the list / bool / string the reference returns). Where the reference awaits, these are
    // synchronous. PCActn authorization takes an injected `verify` hook `(pcActn, grant, opts, context): verdict` (a verdict is
    // {allow, checks, reasons}); without one the core verifier decides, and `hooks.revocation` is called as in the reference.
    //
    // shortcut: the default verifier does not apply `pqPins`; a root that names a non-Ed25519 suite is admitted only under a stored
    // `grant` (inject `verify` to accept one by pin).
    // shortcut: human_present is derived from explicit threshold shares only; the reference also lets an Ed25519 leaf signature
    // stand for the agent share (stricter here: false where the reference says true).

    public const PCA_A2A_EXTENSION_URI = 'https://atlasauth.net/a2a/ext/pca/v2';
    public const TASK_STATE_AUTH_REQUIRED = 'TASK_STATE_AUTH_REQUIRED';
    public const TASK_STATE_INPUT_REQUIRED = 'TASK_STATE_INPUT_REQUIRED';
    public const NEED_KEY = self::PCA_A2A_EXTENSION_URI . '#need';
    public const RECEIPT_KEY = self::PCA_A2A_EXTENSION_URI . '#receipt';
    public const A2A_RECEIPT_DOMAIN = self::RECEIPT_DOMAIN;
    public const A2A_AP2_CONTEXT = ['https://www.w3.org/2018/credentials/v1', 'https://ap2-protocol.org/context/v0.2'];
    /** The stateless checks that must pass unless the caller names its own list. */
    public const DEFAULT_REQUIRED_CHECKS = ['counter_format', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];
    private const NEED_MAX_ENCODED = 2048;
    private const PARAM_KEYS = ['aud', 'suites', 'grants', 'policy_digest'];
    private const U = Payments::UNDEF;

    // ---- JavaScript semantics ----

    private static function p(mixed $o, string $k): mixed
    {
        return Payments::p($o, $k);
    }

    private static function q(mixed $o, string $k): mixed
    {
        return Payments::q($o, $k);
    }

    private static function isStr(mixed $v): bool
    {
        return is_string($v) && $v !== self::U;
    }

    private static function isRec(mixed $v): bool
    {
        return Js::isObj($v);
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function nn(mixed $v, mixed $d): mixed
    {
        return $v === null || $v === self::U ? $d : $v;
    }

    private static function obj(array $a): Obj
    {
        return Payments::obj($a);
    }

    private static function hashOf(mixed $v): string
    {
        return Payments::hash($v);
    }

    /** `new Date(v).toISOString()` for a number, null or boolean; anything else is an invalid time (RangeException). */
    private static function iso(mixed $v): string
    {
        $f = Js::num($v);
        if ($f === null) {
            $f = $v === null || $v === false ? 0.0 : ($v === true ? 1.0 : NAN);
        }
        return Agentcard::isoFromMs($f);
    }

    // ---- proof-carrying tasks ----

    private static function withPca(mixed $metadata, mixed $pcActn): Obj
    {
        $o = Payments::spreadObj(self::nn($metadata, new Obj()));
        $o->set(self::PCA_A2A_EXTENSION_URI, $pcActn);
        return $o;
    }

    private static function readPca(mixed $metadata): ?Obj
    {
        if (!Payments::truthy($metadata)) {
            return null;
        }
        $v = Js::opt($metadata, self::PCA_A2A_EXTENSION_URI);
        return $v instanceof Obj ? $v : null;
    }

    /** A copy of the task with the PCActn on its metadata (the input is not mutated). */
    public static function attachPcaToA2ATask(mixed $task, mixed $pcActn): Obj
    {
        $md = self::p($task, 'metadata');
        $out = Payments::spreadObj($task);
        $out->set('metadata', self::withPca($md, $pcActn));
        return $out;
    }

    public static function attachPcaToA2AMessage(mixed $message, mixed $pcActn): Obj
    {
        return self::attachPcaToA2ATask($message, $pcActn);
    }

    /** The PCActn a task carries: its metadata, then the status message, then the most recent history message; null if none. */
    public static function extractPca(mixed $task): ?Obj
    {
        if ($task === null) {
            return null;
        }
        $onTask = self::readPca(self::p($task, 'metadata'));
        if ($onTask !== null) {
            return $onTask;
        }
        $status = self::p($task, 'status');
        if ($status instanceof Obj || is_array($status)) {
            $onStatus = self::readPca(self::q(self::q($status, 'message'), 'metadata'));
            if ($onStatus !== null) {
                return $onStatus;
            }
        }
        $history = self::p($task, 'history');
        if (self::isList($history)) {
            for ($i = count($history) - 1; $i >= 0; $i--) {
                $onMsg = self::readPca(self::q($history[$i], 'metadata'));
                if ($onMsg !== null) {
                    return $onMsg;
                }
            }
        }
        return null;
    }

    public static function extractPcaFromMessage(mixed $message): ?Obj
    {
        return $message === null ? null : self::readPca(self::p($message, 'metadata'));
    }

    private static function assertAuthority(mixed $opts): void
    {
        $g = self::q($opts, 'grant');
        $hasGrant = $g !== self::U && $g !== null && ($g instanceof Obj || is_array($g));
        $iss = self::q($opts, 'expectedRootIssuer');
        if (!$hasGrant && !(self::isStr($iss) && $iss !== '')) {
            throw new A2aAuthorityError();
        }
    }

    /** The default verdict source: the core PCActn verifier plus the revocation hook and the params digest. */
    private static function coreVerdict(mixed $pcActn, mixed $grant, mixed $opts, mixed $context, bool $storedGrant): array
    {
        $plan = self::q($context, 'plan');
        $authorized = self::q($context, 'planAuthorized') === true;
        $root = $plan instanceof Obj ? $plan->get('root') : null;
        $roots = $authorized && is_string($root) ? [$root] : [];
        $aud = Js::opt($opts, 'aud');
        $now = Js::opt($opts, 'now');
        $nowMs = Js::isNum($now) ? (int)floor((float)Js::num($now)) : Payments::now();
        $suites = Js::opt($opts, 'allowedSuites');
        $reasons = [];
        $chain = Js::opt($pcActn, 'cap_chain');
        $rootCap = self::isList($chain) && $chain !== [] ? $chain[0] : null;
        if (!$storedGrant && $rootCap instanceof Obj && $rootCap->has('alg') && $rootCap->get('alg') !== 'ed25519') {
            return ['allow' => false, 'checks' => ['pq_pin' => false], 'reasons' => ['pq_pin: a non-Ed25519 root is admitted only under a stored grant']];
        }
        $v = Pca::verifyPcactnCore($pcActn, $grant, $nowMs, self::isStr($aud) ? $aud : null, Js::isStrList($suites) ? $suites : null,
            null, null, null, $roots);
        $checks = $v['checks'] ?? [];
        $allow = $v['allow'] === true;
        $rs = $v['reasons'] ?? (($v['reason'] ?? '') !== '' ? [$v['reason']] : []);
        foreach ($rs as $r) {
            $reasons[] = $r;
        }
        $rev = Js::opt(Js::opt($opts, 'hooks'), 'revocation');
        try {
            $res = $rev instanceof \Closure ? $rev(Obj::of(['pcactn' => $pcActn, 'grant' => $grant, 'context' => $context])) : null;
        } catch (\Throwable $e) {
            $res = Obj::of(['enforced' => true, 'ok' => false, 'reason' => 'revocation hook failed: ' . $e->getMessage()]);
        }
        if (Js::opt($res, 'enforced') === true) {
            $checks['revocation'] = Js::opt($res, 'ok') === true ? 'pass' : 'fail';
            if (Js::opt($res, 'ok') !== true) {
                $allow = false;
                $why = Js::opt($res, 'reason');
                $reasons[] = Payments::truthy($why) ? Payments::s($why) : 'rejected';
            }
        } else {
            $checks['revocation'] = 'not-enforced';
        }
        $params = self::q($context, 'params');
        $action = Js::opt($pcActn, 'action');
        if ($params instanceof Obj && $action instanceof Obj) {
            try {
                $checks['params_digest'] = Pca::paramsDigest($params) === $action->get('params_digest');
            } catch (\Throwable) {
                $checks['params_digest'] = false;
            }
        }
        return ['allow' => $allow, 'checks' => $checks, 'reasons' => $reasons];
    }

    /**
     * PCActn AUTHORIZATION shared by the task and payment-mandate surfaces: a verifier under a known authority (the stored grant, or
     * the chain root only when its issuer is the expected principal). Fail-closed. `$extraRequired` names checks that must also pass.
     * @param list<string> $extraRequired
     */
    private static function verifyPcActn(mixed $pcActn, mixed $opts, array $extraRequired = []): Obj
    {
        self::assertAuthority($opts);
        if ($pcActn === null || !($pcActn instanceof Obj || is_array($pcActn))) {
            return self::obj(['ok' => false, 'reason' => 'PCActn is not an object']);
        }
        $chain = self::p($pcActn, 'cap_chain');
        $root = self::isList($chain) && $chain !== [] ? $chain[0] : self::U;
        if ($root === self::U || !Payments::truthy($root)) {
            return self::obj(['ok' => false, 'reason' => 'PCActn carries no capability chain', 'pcActn' => $pcActn]);
        }
        $expected = self::q($opts, 'expectedRootIssuer');
        if ($expected !== self::U && !Payments::seq(self::p($root, 'issuer'), $expected)) {
            return self::obj(['ok' => false, 'reason' => 'chain root issuer does not match the expected principal', 'pcActn' => $pcActn]);
        }
        $stored = self::q($opts, 'grant');
        $grant = self::nn($stored, $root); // without a stored grant the root is admitted only under the pinned principal
        $ctx = self::q($opts, 'context');
        $context = self::nn($ctx instanceof \Closure ? $ctx($pcActn) : $ctx, new Obj());
        $hook = self::q($opts, 'verify');
        $verdict = $hook instanceof \Closure
            ? $hook($pcActn, $grant, $opts, $context)
            : self::coreVerdict($pcActn, $grant, $opts, $context, $stored !== self::U && $stored !== null);
        $require = self::q($opts, 'requireChecks');
        $names = $require === self::U || $require === null ? self::DEFAULT_REQUIRED_CHECKS : (self::isList($require) ? $require : []);
        foreach ($extraRequired as $n) {
            if (!in_array($n, $names, true)) {
                $names[] = $n;
            }
        }
        $checks = Js::opt($verdict, 'checks');
        $allow = Payments::truthy(Js::opt($verdict, 'allow'));
        foreach ($names as $n) {
            $c = Js::opt($checks, (string)$n);
            $allow = $allow && ($c === true || $c === 'pass');
        }
        $reasons = [];
        $rs = Js::opt($verdict, 'reasons');
        foreach (self::isList($rs) ? $rs : [] as $r) {
            if (Payments::truthy($r)) {
                $reasons[] = Payments::s($r);
            }
        }
        $reason = $allow ? null : ($reasons !== [] ? implode('; ', $reasons) : 'PCActn verification failed');
        $result = Payments::spreadObj($verdict);
        $result->set('allow', $allow);
        if ($reason !== null) {
            $result->set('reason', $reason);
        }
        return $allow ? Obj::of(['ok' => true, 'result' => $result, 'pcActn' => $pcActn])
            : Obj::of(['ok' => false, 'reason' => $reason, 'result' => $result, 'pcActn' => $pcActn]);
    }

    /** Verify the proof-carrying action on a task. Fail-closed: no PCActn, or one that does not verify, is refused. */
    public static function verifyA2ATask(mixed $task, mixed $opts): Obj
    {
        self::assertAuthority($opts);
        $p = self::extractPca($task);
        if ($p === null) {
            return self::obj(['ok' => false, 'reason' => 'no proof-carrying action attached to this task']);
        }
        return self::verifyPcActn($p, $opts);
    }

    /**
     * A per-task guard. `require` (default true): a task with no proof is refused; with false it passes, but a task that DOES carry a
     * proof must still verify (a present but invalid proof is always refused).
     */
    public static function pcaA2AMiddleware(mixed $opts): \Closure
    {
        self::assertAuthority($opts);
        $require = self::nn(self::q($opts, 'require'), true);
        return static function (mixed $task) use ($opts, $require): Obj {
            $p = self::extractPca($task);
            if ($p === null) {
                return Payments::truthy($require)
                    ? self::obj(['ok' => false, 'reason' => 'proof-carrying action required but none attached to task'])
                    : self::obj(['ok' => true]);
            }
            return self::verifyPcActn($p, $opts);
        };
    }

    // ---- Agent Cards (the shared card codec, JWS and A2A 1.0 schema live in Agentcard) ----

    /** RFC 8785 canonical UTF-8 bytes of a JSON value; throws for a value with no JSON form. */
    public static function jcsBytes(mixed $value): string
    {
        return Agentcard::jcsBytes($value);
    }

    /** @return list<string> the problems with an A2A 1.0 AgentCard (empty = valid) */
    public static function validateAgentCard1(mixed $card): array
    {
        return Agentcard::validateAgentCard1($card);
    }

    /** Issue a signed A2A Agent Card (options: alg, passport, kid, profile 'pca-detached' | 'a2a-1.0', schema 'a2a-1.0'). */
    public static function issueSignedAgentCard(mixed $card, mixed $signingKey, mixed $opts = null): Obj
    {
        return Agentcard::issueSignedAgentCard($card, $signingKey, $opts);
    }

    /**
     * Validate an Agent Card against its signature(s). Fail-closed: no signatures, an unresolvable key or ANY signature that does not
     * verify over the canonical card (minus `signatures`) is refused. Options: jwks, key, alg, schema.
     * @return Obj {ok, reason?, passportRef?, passport?}
     */
    public static function verifyAgentCard(mixed $card, mixed $opts): Obj
    {
        if (!($card instanceof Obj) && !is_array($card)) {
            return self::obj(['ok' => false, 'reason' => 'agent card is not an object']);
        }
        $signatures = Js::opt($card, 'signatures');
        if (!self::isList($signatures) || count($signatures) === 0) {
            return self::obj(['ok' => false, 'reason' => 'agent card carries no signatures']);
        }
        if (self::p($opts, 'schema') === 'a2a-1.0') {
            $problems = Agentcard::validateAgentCard1($card);
            if ($problems !== []) {
                return self::obj(['ok' => false, 'reason' => 'agent card does not match the A2A 1.0 schema: ' . implode('; ', $problems)]);
            }
        }
        $key = Agentcard::resolveVerifyKey($opts);
        if ($key[0] === 'error') {
            return self::obj(['ok' => false, 'reason' => $key[1]]);
        }
        try {
            $payload = Agentcard::cardSigningBytes($card);
        } catch (\Throwable $e) {
            return self::obj(['ok' => false, 'reason' => 'agent card has no canonical form: ' . $e->getMessage()]);
        }
        $passportRef = null;
        foreach ($signatures as $i => $sig) {
            if (!Payments::truthy($sig) || !is_string(Js::opt($sig, 'protected')) || !is_string(Js::opt($sig, 'signature'))) {
                return self::obj(['ok' => false, 'reason' => "signature $i is malformed"]);
            }
            $r = Agentcard::verifyDetached($payload, $sig, $key);
            if (!$r['ok']) {
                return self::obj(['ok' => false, 'reason' => "signature $i did not verify: " . $r['reason']]);
            }
            $ref = $r['protectedHeader']->get('pca_passport');
            if (is_string($ref) && $passportRef === null) {
                $passportRef = $ref;
            }
        }
        $passport = Js::opt($card, 'pcaPassport');
        return self::obj(['ok' => true, 'passportRef' => $passportRef ?? self::U, 'passport' => Payments::truthy($passport) ? $passport : self::U]);
    }

    // ---- extension declaration ----

    /** The AgentExtension object to put in `capabilities.extensions`. */
    public static function pcaExtensionDeclaration(mixed $params, mixed $required = true): Obj
    {
        return Obj::of(['uri' => self::PCA_A2A_EXTENSION_URI, 'description' => 'Per-action proofs of authority (PCActn) on tasks and messages',
            'required' => $required, 'params' => $params]);
    }

    /** Read and validate the PCA extension from an Agent Card. A malformed declaration is a refusal, never a guess. */
    public static function readPcaExtension(mixed $card): Obj
    {
        $caps = self::isRec($card) ? self::p($card, 'capabilities') : self::U;
        $exts = self::isRec($caps) ? self::p($caps, 'extensions') : self::U;
        if (!self::isList($exts)) {
            return self::obj(['ok' => false, 'code' => 'not_declared']);
        }
        $found = array_values(array_filter($exts, static fn(mixed $e): bool => self::isRec($e) && self::p($e, 'uri') === self::PCA_A2A_EXTENSION_URI));
        if ($found === []) {
            return self::obj(['ok' => false, 'code' => 'not_declared']);
        }
        if (count($found) > 1) {
            return self::obj(['ok' => false, 'code' => 'bad_declaration']);
        }
        $e = $found[0];
        $req = self::p($e, 'required');
        if ($req !== self::U && !is_bool($req)) {
            return self::obj(['ok' => false, 'code' => 'bad_declaration']);
        }
        $p = self::p($e, 'params');
        $bad = self::obj(['ok' => false, 'code' => 'bad_params']);
        if (!self::isRec($p)) {
            return $bad;
        }
        foreach (Js::ownKeys($p instanceof Obj ? $p->keys() : array_map('strval', array_keys($p))) as $k) {
            if (!in_array($k, self::PARAM_KEYS, true)) {
                return $bad;
            }
        }
        $aud = self::p($p, 'aud');
        if (!self::isStr($aud) || $aud === '' || Js::len($aud) > 512) {
            return $bad;
        }
        if (Js::has($p, 'suites')) {
            $s = Js::opt($p, 'suites');
            $ok = self::isList($s) && count($s) <= 16;
            foreach ($ok ? $s : [] as $x) {
                $ok = $ok && is_string($x) && $x !== '' && Js::len($x) <= 64;
            }
            if (!$ok) {
                return $bad;
            }
        }
        if (Js::has($p, 'policy_digest')) {
            $d = Js::opt($p, 'policy_digest');
            if (!is_string($d) || $d === '' || Js::len($d) > 128) {
                return $bad;
            }
        }
        $grants = [];
        if (Js::has($p, 'grants')) {
            [$g, $code] = PcaGrant::parse(Js::opt($p, 'grants'));
            if ($g === null) {
                return self::obj(['ok' => false, 'code' => 'bad_grants']);
            }
            $grants = $g;
        }
        return Obj::of(['ok' => true, 'required' => $req === true, 'params' => $p, 'grants' => $grants]);
    }

    /** True iff the `A2A-Extensions` service parameter lists the PCA extension (exact URI in a comma-separated list). */
    public static function clientOptsIntoPca(mixed $header): bool
    {
        if (!is_string($header)) {
            return false;
        }
        foreach (explode(',', $header) as $u) {
            if (Payments::trim($u) === self::PCA_A2A_EXTENSION_URI) {
                return true;
            }
        }
        return false;
    }

    // ---- AUTH_REQUIRED mapping ----

    /** AUTH_REQUIRED in the 1.0 enum spelling; the pre-1.0 `auth-required` is also read, never written. */
    public static function isAuthRequired(mixed $state): bool
    {
        return $state === self::TASK_STATE_AUTH_REQUIRED || $state === 'auth-required';
    }

    /** The unpadded base64url of a need's strict canonical JSON. Throws on a malformed need or an over-long value. */
    public static function encodePcaNeed(mixed $need): string
    {
        $code = self::needError($need);
        if ($code !== null) {
            throw new \InvalidArgumentException("encodePcaNeed: malformed need ($code)");
        }
        $enc = Pca::b64u(Json::canonicalizeNative($need));
        if (strlen($enc) > self::NEED_MAX_ENCODED) {
            throw new \InvalidArgumentException('encodePcaNeed: the need is too large for a header');
        }
        return $enc;
    }

    private static function needDigestOf(mixed $need): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::PCA_NEED_DOMAIN, 'need' => $need]));
    }

    /**
     * The TaskStatus an agent sets to ask for authority: AUTH_REQUIRED plus a message carrying the typed need. Throws on a need the
     * codec would refuse. `$o`: messageId, now (epoch ms), text?.
     */
    public static function authRequiredStatus(mixed $need, mixed $o): Obj
    {
        $enc = self::encodePcaNeed($need);
        $text = self::nn(self::p($o, 'text'), 'Authority needed: ' . $need->get('verb') . ' on ' . $need->get('resource'));
        $timestamp = self::iso(self::p($o, 'now'));
        $message = self::obj([
            'messageId' => self::p($o, 'messageId'),
            'role' => 'agent',
            'parts' => [Obj::of(['kind' => 'text', 'text' => $text])],
            'extensions' => [self::PCA_A2A_EXTENSION_URI],
            'metadata' => Obj::of([self::NEED_KEY => $enc]),
        ]);
        return Obj::of(['state' => self::TASK_STATE_AUTH_REQUIRED, 'timestamp' => $timestamp, 'message' => $message]);
    }

    /** The need parked in a task status message, decoded ({ok, need} or {ok: false, code}); null when there is none. */
    public static function readAuthRequiredNeed(mixed $task): ?Obj
    {
        $status = self::isRec($task) ? self::p($task, 'status') : self::U;
        $msg = self::isRec($status) ? self::p($status, 'message') : self::U;
        $md = self::isRec($msg) ? self::p($msg, 'metadata') : self::U;
        $v = self::isRec($md) ? self::p($md, self::NEED_KEY) : self::U;
        if ($v === self::U) {
            return null;
        }
        [$need, $code] = self::decodeNeed($v);
        return $need !== null ? Obj::of(['ok' => true, 'need' => $need]) : Obj::of(['ok' => false, 'code' => $code]);
    }

    /** The answer message: a PCActn for exactly the parked need, plus the need's digest. */
    public static function answerMessage(mixed $need, mixed $pcActn, mixed $messageId): Obj
    {
        return self::obj([
            'role' => 'user',
            'messageId' => $messageId,
            'parts' => [Obj::of(['kind' => 'text', 'text' => 'authority provided'])],
            'metadata' => Obj::of([self::PCA_A2A_EXTENSION_URI => $pcActn, self::NEED_KEY => self::needDigestOf($need)]),
        ]);
    }

    /**
     * The pure part of resumeAuthRequired over the reference's option object `{state, needEncoded, answerNeedDigest, proofAction}`:
     * an absent `proofAction` is no proof, a null one throws, the first refusal code or null.
     */
    public static function resumeGateObj(mixed $o): ?string
    {
        if (!self::isAuthRequired(self::p($o, 'state'))) {
            return 'task_not_auth_required';
        }
        $need = Js::has($o, 'needEncoded') ? self::decodeNeed(Js::opt($o, 'needEncoded'))[0] : null;
        if ($need === null) {
            return 'no_valid_need';
        }
        if (self::p($o, 'answerNeedDigest') !== self::needDigest($need)) {
            return 'answer_not_bound_to_need';
        }
        if (!Js::has($o, 'proofAction')) {
            return 'no_proof';
        }
        $action = Js::opt($o, 'proofAction');
        if ($action === null) {
            throw new \TypeError("Cannot read properties of null (reading 'verb')");
        }
        if (self::p($action, 'verb') !== $need->get('verb') || self::p($action, 'resource') !== $need->get('resource')) {
            return 'action_mismatch';
        }
        return null;
    }

    /**
     * Resume a Task parked in AUTH_REQUIRED. Allowed only when the task is in AUTH_REQUIRED, its status carries a decodable need,
     * the answer cites that need's digest, the answer carries a PCActn for the need's exact verb and resource, and that PCActn passes
     * the verifier for THIS agent. The state change alone, or a proof for another action, resumes nothing.
     * @return Obj {ok: true, verification} or {ok: false, reason}
     */
    public static function resumeAuthRequired(mixed $task, mixed $answer, mixed $opts): Obj
    {
        $status = self::isRec($task) ? self::p($task, 'status') : self::U;
        $smsg = self::isRec($status) ? self::p($status, 'message') : self::U;
        $smd = self::isRec($smsg) ? self::p($smsg, 'metadata') : self::U;
        $statusMd = self::isRec($smd) ? $smd : new Obj();
        $amd = self::isRec($answer) ? self::p($answer, 'metadata') : self::U;
        $md = self::isRec($amd) ? $amd : new Obj();
        $p = self::extractPcaFromMessage($answer);
        $gate = new Obj();
        if (self::isRec($status) && Js::has($status, 'state')) {
            $gate->set('state', Js::opt($status, 'state'));
        }
        if (Js::has($statusMd, self::NEED_KEY)) {
            $gate->set('needEncoded', Js::opt($statusMd, self::NEED_KEY));
        }
        if (Js::has($md, self::NEED_KEY)) {
            $gate->set('answerNeedDigest', Js::opt($md, self::NEED_KEY));
        }
        if ($p !== null && $p->has('action')) {
            $gate->set('proofAction', $p->get('action'));
        }
        $refusal = self::resumeGateObj($gate);
        if ($refusal !== null) {
            return self::obj(['ok' => false, 'reason' => $refusal]);
        }
        $v = self::verifyA2ATask(self::obj([
            'id' => self::p($task, 'id'),
            'status' => Obj::of(['state' => 'TASK_STATE_WORKING']),
            'metadata' => Obj::of([self::PCA_A2A_EXTENSION_URI => $p]),
        ]), $opts);
        return $v->get('ok') === true ? Obj::of(['ok' => true, 'verification' => $v])
            : Obj::of(['ok' => false, 'reason' => self::nn($v->get('reason'), 'proof_rejected')]);
    }

    // ---- per-hop delegation ----

    /**
     * Verify a chain of delegated tasks, one per A2A hop, each on its own (its own PCActn, audience and authority); the capability
     * chain must EXTEND the previous hop's. Stops at the first failure; empty input is refused.
     * @param mixed $hops list of {task, opts}
     */
    public static function verifyA2ADelegation(mixed $hops): Obj
    {
        $chains = [];
        if ($hops === null) {
            throw new \TypeError("Cannot read properties of null (reading 'length')");
        }
        if (!self::isList($hops)) {
            return Obj::of(['ok' => true, 'chains' => []]);
        }
        if ($hops === []) {
            return Obj::of(['ok' => false, 'reason' => 'no_hops', 'chains' => []]);
        }
        foreach ($hops as $i => $h) {
            $task = self::p($h, 'task');
            $v = self::verifyA2ATask($task, self::p($h, 'opts'));
            if ($v->get('ok') !== true) {
                return Obj::of(['ok' => false, 'failedHop' => $i, 'reason' => self::nn($v->get('reason'), 'rejected'), 'chains' => self::idsOut($chains)]);
            }
            $pc = self::extractPca($task);
            $cc = $pc !== null ? $pc->get('cap_chain') : null;
            if (!self::isList($cc)) {
                return Obj::of(['ok' => false, 'failedHop' => $i, 'reason' => 'no_chain', 'chains' => self::idsOut($chains)]);
            }
            $ids = array_map(static fn(mixed $c): mixed => self::p($c, 'id'), $cc);
            if ($chains !== [] && !self::chainExtends($chains[count($chains) - 1], $ids)) {
                return Obj::of(['ok' => false, 'failedHop' => $i, 'reason' => 'chain_does_not_extend_previous_hop', 'chains' => self::idsOut($chains)]);
            }
            $chains[] = $ids;
        }
        return Obj::of(['ok' => true, 'chains' => self::idsOut($chains)]);
    }

    /** @param list<list<mixed>> $chains the capability ids with an absent id as null (JSON.stringify of an undefined array element) */
    private static function idsOut(array $chains): array
    {
        return array_map(static fn(array $c): array => array_map(static fn(mixed $x): mixed => $x === self::U ? null : $x, $c), $chains);
    }

    // ---- push notifications and anti-enumeration ----

    /**
     * The per-task push token: a hash of the task id, the digest of the chain that authorized the task and a secret salt. Throws
     * \RangeException on a salt shorter than 16 characters.
     */
    public static function pcaPushToken(mixed $taskId, mixed $chainIds, mixed $salt): string
    {
        if (!self::isStr($salt) || Js::len($salt) < 16) {
            throw new \RangeException('pcaPushToken: the salt must be a secret of at least 16 characters');
        }
        return IntentV2::hashCanonical(self::obj(['d' => 'atlas-pca/a2a-push/v1', 'task_id' => $taskId, 'chain' => PcaGrant::chainDigest(Payments::spread($chainIds)),
            'salt' => $salt]));
    }

    /**
     * Receiver-side check of a delivered push notification: the token must be the one recomputed from the task, the chain and the
     * salt, and the payload must be about that task.
     * @param mixed $expected {taskId, chainIds, salt} @param mixed $delivered {token, payload}
     */
    public static function checkPushNotification(mixed $expected, mixed $delivered): Obj
    {
        $token = self::p($delivered, 'token');
        if (!self::isStr($token) || $token === '') {
            return self::obj(['ok' => false, 'reason' => 'no_token']);
        }
        $want = self::pcaPushToken(self::p($expected, 'taskId'), self::p($expected, 'chainIds'), self::p($expected, 'salt'));
        if (!hash_equals($want, $token)) {
            return self::obj(['ok' => false, 'reason' => 'token_mismatch']);
        }
        $pl = self::p($delivered, 'payload');
        $pl = self::isRec($pl) ? $pl : new Obj();
        $t = self::p($pl, 'task');
        $su = self::p($pl, 'statusUpdate');
        $au = self::p($pl, 'artifactUpdate');
        $id = self::nn(self::q(self::isRec($t) ? $t : self::U, 'id'),
            self::nn(self::q(self::isRec($su) ? $su : self::U, 'taskId'), self::q(self::isRec($au) ? $au : self::U, 'taskId')));
        return Payments::seq($id, self::p($expected, 'taskId')) ? self::obj(['ok' => true]) : self::obj(['ok' => false, 'reason' => 'task_mismatch']);
    }

    /** The one error servers return for "no such task" and "not yours" alike (no existence leak). */
    public static function uniformTaskNotFound(): Obj
    {
        return Obj::of(['code' => 'TaskNotFoundError', 'message' => 'task not found']);
    }

    // ---- payment mandate envelope ----

    /**
     * True only when the PCActn's threshold shares verify at t=3 for agent, guardian and principal under `$signerSet`. Never throws.
     */
    private static function humanPresent(mixed $pcActn, mixed $signerSet): bool
    {
        try {
            if (!($pcActn instanceof Obj) || !self::isList($signerSet)) {
                return false;
            }
            $roles = [];
            foreach ($signerSet as $e) {
                $r = $e instanceof Obj ? $e->get('role') : null;
                if (!is_string($r) || !in_array($r, ['agent', 'guardian', 'principal'], true)) {
                    return false;
                }
                $roles[$r] = true;
            }
            if (count($roles) !== 3) {
                return false;
            }
            $msg = Pca::b64u(Pca::thresholdMessage($pcActn));
            $th = $pcActn->get('threshold');
            $shares = $th instanceof Obj && self::isList($th->get('shares')) ? $th->get('shares') : [];
            $ok = [];
            foreach ($shares as $sh) {
                if ($sh instanceof Obj && is_string($sh->get('role')) && Pca::verifyThresholdShare(Obj::of([
                    'role' => $sh->get('role'), 't' => new Num('3'), 'share' => $sh, 'threshold_message' => $msg, 'signer_set' => $signerSet]))) {
                    $ok[$sh->get('role')] = true;
                }
            }
            return count($ok) === 3 && count(array_intersect_key($ok, $roles)) === 3;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Map a PCActn to an AP2 payment-mandate envelope whose authority is carried BY REFERENCE (`x_pca.pcactn_digest`). `$opts`:
     * amount (integer minor units), paymentMethod, merchant, humanPresent, humanSignerSet, issuerPublic, now. Throws on anything the
     * envelope cannot honestly carry.
     */
    public static function a2aPaymentMandateFromPca(mixed $pcActn, mixed $opts): Obj
    {
        $chain = self::p($pcActn, 'cap_chain');
        $leafCap = self::isList($chain) && $chain !== [] ? $chain[count($chain) - 1] : self::U;
        $leaf = $leafCap === self::U ? self::U : self::q($leafCap, 'holder');
        $issuer = self::nn(self::p($opts, 'issuerPublic'), $leaf);
        if ($issuer === self::U) {
            throw new \InvalidArgumentException('a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain');
        }
        $amount = self::p($opts, 'amount');
        $value = self::p($amount, 'value');
        if (!Payments::safeInt($value) || (float)Js::num($value) < 0) {
            throw new \InvalidArgumentException('a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units');
        }
        $hp = self::p($opts, 'humanPresent');
        if ($hp === null || $hp === self::U) {
            $set = self::p($opts, 'humanSignerSet');
            $hp = Payments::truthy($set) ? self::humanPresent($pcActn, $set) : false;
        }
        $now = self::nn(self::p($opts, 'now'), Payments::now());
        $action = self::p($pcActn, 'action');
        $xpca = self::obj([
            'pcactn_digest' => self::hashOf($pcActn),
            'aud' => self::p($pcActn, 'aud'),
            'verb' => self::p($action, 'verb'),
            'resource' => self::p($action, 'resource'),
            'params_digest' => self::p($action, 'params_digest'),
            'grant_ref' => self::p($pcActn, 'grant_ref'),
            'leaf_holder' => self::nn($leaf, $issuer),
        ]);
        $contents = self::obj([
            'amount' => Payments::spreadObj($amount),
            'payment_method' => Payments::spreadObj(self::p($opts, 'paymentMethod')),
            'human_present' => $hp,
            'merchant' => self::p($opts, 'merchant'),
            'x_pca' => $xpca,
        ]);
        return Obj::of(['@context' => self::A2A_AP2_CONTEXT, 'type' => ['VerifiableCredential', 'PaymentMandate'], 'issuer' => $issuer,
            'issuanceDate' => self::iso($now), 'credentialSubject' => $contents]);
    }

    /** The PCA binding read back out of a payment mandate (the round trip of `x_pca`). */
    public static function pcaBindingFromA2APaymentMandate(mixed $mandate): Obj
    {
        return Payments::spreadObj(self::p(self::p($mandate, 'credentialSubject'), 'x_pca'));
    }

    private static function safeNonNeg(mixed $v): bool
    {
        return Payments::safeInt($v) && (float)Js::num($v) >= 0 && !K3Sig::isNegZero($v);
    }

    private static function mandateBindingError(mixed $m, mixed $pcActn, mixed $params, mixed $opts): ?string
    {
        $x = self::p($m, 'x_pca');
        if (!self::isRec($x)) {
            return 'payment mandate carries no x_pca binding';
        }
        $chain = self::p($pcActn, 'cap_chain');
        $leaf = self::isList($chain) && $chain !== [] ? $chain[count($chain) - 1] : self::U;
        $leafHolder = self::isRec($leaf) ? self::p($leaf, 'holder') : self::U;
        $action = self::p($pcActn, 'action');
        $act = $action === null || $action === self::U ? self::U : $action;
        $bound = [
            ['aud', self::p($pcActn, 'aud')],
            ['verb', self::q($act, 'verb')],
            ['resource', self::q($act, 'resource')],
            ['params_digest', self::q($act, 'params_digest')],
            ['grant_ref', self::p($pcActn, 'grant_ref')],
            ['leaf_holder', $leafHolder],
        ];
        foreach ($bound as [$k, $v]) {
            if (!Js::has($x, $k) || !self::isStr(Js::opt($x, $k)) || !Payments::seq(Js::opt($x, $k), $v)) {
                return "payment mandate x_pca.$k is not the PCActn's";
            }
        }
        $amt = self::p($m, 'amount');
        if (!self::isRec($amt) || !self::safeNonNeg(self::p($amt, 'value')) || !self::isStr(self::p($amt, 'currency'))) {
            return 'payment mandate amount is malformed (value must be a non-negative integer in minor units)';
        }
        if (!Js::has($params, 'amount') || !self::safeNonNeg(Js::opt($params, 'amount'))) {
            return 'the PCActn params carry no integer minor-unit amount to bind the mandate amount to';
        }
        if (!Js::has($params, 'currency') || !is_string(Js::opt($params, 'currency'))) {
            return 'the PCActn params carry no currency to bind the mandate currency to';
        }
        if (!Payments::seq(self::p($amt, 'value'), Js::opt($params, 'amount')) || !Payments::seq(self::p($amt, 'currency'), Js::opt($params, 'currency'))) {
            return 'payment mandate amount / currency differ from the authorized PCActn params';
        }
        $merchant = Js::has($m, 'merchant') ? Js::opt($m, 'merchant') : self::U;
        $pMerchant = Js::has($params, 'merchant') ? Js::opt($params, 'merchant') : self::U;
        if (!Payments::seq($merchant, $pMerchant)) {
            return 'payment mandate merchant differs from the authorized PCActn params';
        }
        if (Js::has($params, 'payment_method')) {
            try {
                $same = self::hashOf(self::p($m, 'payment_method')) === self::hashOf(Js::opt($params, 'payment_method'));
            } catch (\Throwable) {
                $same = false;
            }
            if (!$same) {
                return 'payment mandate payment_method differs from the authorized PCActn params';
            }
        }
        $hp = self::p($m, 'human_present');
        if (!is_bool($hp)) {
            return 'payment mandate human_present must be a boolean';
        }
        $set = self::q($opts, 'humanSignerSet');
        if ($hp && !(self::isList($set) && self::humanPresent($pcActn, $set))) {
            return 'payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)';
        }
        return null;
    }

    /**
     * Verify a payment mandate against the PCActn it references. The mandate is NOT signed: every field a payer acts on must be
     * authorized by the PCActn (digest and `x_pca` fields, the opened params' amount, currency, merchant and payment method, a
     * verified t=3 co-signature for human_present), and the PCActn itself must verify with `params_digest` required.
     */
    public static function verifyA2APaymentMandate(mixed $mandate, mixed $pcActn, mixed $opts): Obj
    {
        self::assertAuthority($opts);
        try {
            $bound = self::p(self::p(self::p($mandate, 'credentialSubject'), 'x_pca'), 'pcactn_digest');
            $digest = self::hashOf($pcActn);
        } catch (\Throwable $e) {
            return self::obj(['ok' => false, 'reason' => 'malformed payment mandate or PCActn: ' . $e->getMessage()]);
        }
        if (!Payments::seq($bound, $digest)) {
            return self::obj(['ok' => false, 'reason' => 'payment mandate is not bound to this PCActn (pcactn_digest mismatch)', 'pcActn' => $pcActn]);
        }
        if ($pcActn === null || !($pcActn instanceof Obj || is_array($pcActn))) {
            return self::obj(['ok' => false, 'reason' => 'PCActn is not an object']);
        }
        $ctx = self::q($opts, 'context');
        $context = self::nn($ctx instanceof \Closure ? $ctx($pcActn) : $ctx, new Obj());
        $params = self::p($context, 'params');
        if (!self::isRec($params)) {
            return self::obj(['ok' => false, 'reason' => 'context.params (the PCActn params plaintext) is required to bind the payment mandate', 'pcActn' => $pcActn]);
        }
        $why = self::mandateBindingError(self::p($mandate, 'credentialSubject'), $pcActn, $params, $opts);
        if ($why !== null) {
            return self::obj(['ok' => false, 'reason' => $why, 'pcActn' => $pcActn]);
        }
        $o2 = Payments::spreadObj($opts);
        $o2->set('context', $context);
        return self::verifyPcActn($pcActn, $o2, ['params_digest']);
    }

    // ---- signed task-update receipts ----

    private static function receiptMessage(Obj $body): string
    {
        return self::RECEIPT_DOMAIN . Json::canonicalizeNative($body);
    }

    /**
     * Sign a receipt with a 32-byte Ed25519 seed. `$o`: taskId, state, chainIds, issuedAt, prev? (the previous receipt of the same
     * task). Throws on malformed input, a `prev` of another task or one already terminal.
     */
    public static function signTaskReceipt(string $secret, mixed $o): Obj
    {
        $taskId = self::p($o, 'taskId');
        $state = self::p($o, 'state');
        $issued = self::p($o, 'issuedAt');
        $ids = self::p($o, 'chainIds');
        if (!self::isStr($taskId) || $taskId === '' || Js::len($taskId) > 256 || !in_array($state, self::STATES, true) || !K3Sig::isSafeInt($issued)
            || !self::isList($ids) || count($ids) === 0) {
            throw new \RangeException('signTaskReceipt: malformed input');
        }
        $prev = self::p($o, 'prev');
        $hasPrev = Payments::truthy($prev);
        if ($hasPrev && (!Payments::seq(self::p($prev, 'task_id'), $taskId) || in_array(self::p($prev, 'state'), self::TERMINAL, true))) {
            throw new \RangeException('signTaskReceipt: prev is for another task or already terminal');
        }
        $kp = sodium_crypto_sign_seed_keypair($secret);
        $base = Obj::of([
            'v' => 1,
            'task_id' => $taskId,
            'state' => $state,
            'seq' => $hasPrev ? Payments::num(Payments::n(self::p($prev, 'seq')) + 1.0) : 0,
            'prev' => $hasPrev ? self::receiptDigest($prev) : null,
            'chain' => PcaGrant::chainDigest($ids),
            'issued_at' => $issued,
            'signer' => Pca::b64u(sodium_crypto_sign_publickey($kp)),
        ]);
        $out = Payments::spreadObj($base);
        $out->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::receiptMessage($base), sodium_crypto_sign_secretkey($kp))));
        return $out;
    }

    /** Well formed and signed by `$signer` (the key the receiver pinned) over exactly its content. Never throws. */
    public static function verifyTaskReceipt(mixed $r, mixed $signer): bool
    {
        return is_string($signer) && self::verifyReceipt($r, $signer);
    }

    /**
     * Check an ordered list of receipts for one task: each verifies under the pinned signer, is about this task and this chain,
     * starts at seq 0, links to the previous by digest, and nothing follows a terminal state.
     * @param mixed $o {signer, taskId, chainIds}
     * @return Obj {ok: true, last, terminal} or {ok: false, code, at?}
     */
    public static function checkReceiptChainOf(mixed $receipts, mixed $o): Obj
    {
        if (!self::isList($receipts) || $receipts === []) {
            return self::obj(['ok' => false, 'code' => 'empty']);
        }
        $signer = self::p($o, 'signer');
        $taskId = self::p($o, 'taskId');
        $chain = PcaGrant::chainDigest(Payments::spread(self::p($o, 'chainIds')));
        $prev = null;
        foreach ($receipts as $i => $r) {
            if (!self::verifyTaskReceipt($r, $signer)) {
                return Obj::of(['ok' => false, 'code' => 'bad_receipt', 'at' => $i]);
            }
            if (!Payments::seq($r->get('task_id'), $taskId)) {
                return Obj::of(['ok' => false, 'code' => 'wrong_task', 'at' => $i]);
            }
            if ($r->get('chain') !== $chain) {
                return Obj::of(['ok' => false, 'code' => 'wrong_chain', 'at' => $i]);
            }
            if ($prev === null) {
                if (K3Sig::num($r->get('seq')) !== 0.0) {
                    return Obj::of(['ok' => false, 'code' => 'bad_start', 'at' => $i]);
                }
            } else {
                if (in_array($prev->get('state'), self::TERMINAL, true)) {
                    return Obj::of(['ok' => false, 'code' => 'after_terminal', 'at' => $i]);
                }
                if (K3Sig::num($r->get('seq')) !== K3Sig::num($prev->get('seq')) + 1.0 || $r->get('prev') !== self::receiptDigest($prev)) {
                    return Obj::of(['ok' => false, 'code' => 'broken_link', 'at' => $i]);
                }
            }
            $prev = $r;
        }
        return Obj::of(['ok' => true, 'last' => $prev, 'terminal' => in_array($prev->get('state'), self::TERMINAL, true)]);
    }

    /**
     * May a workflow start its next step because of this task? Only on a verified, unbroken receipt chain for this task and chain
     * that ends in COMPLETED. A push payload, a status update or an unsigned "completed" is never enough.
     */
    public static function mayTriggerNextOf(mixed $receipts, mixed $o): bool
    {
        $r = self::checkReceiptChainOf($receipts, $o);
        return $r->get('ok') === true && $r->get('last')->get('state') === 'TASK_STATE_COMPLETED';
    }

    /** A copy of a status update or message with the receipt on its metadata. */
    public static function attachReceipt(mixed $carrier, mixed $receipt): Obj
    {
        $out = Payments::spreadObj($carrier);
        $md = Payments::spreadObj(self::nn(self::p($carrier, 'metadata'), new Obj()));
        $md->set(self::RECEIPT_KEY, $receipt);
        $out->set('metadata', $md);
        return $out;
    }

    /** The (unverified) receipt a push or stream payload carries (`statusUpdate`, `task` or `message` metadata), else null. */
    public static function receiptOfPayload(mixed $payload): mixed
    {
        if (!self::isRec($payload)) {
            return null;
        }
        foreach (['statusUpdate', 'task', 'message'] as $k) {
            $c = self::p($payload, $k);
            $md = self::isRec($c) ? self::p($c, 'metadata') : self::U;
            if (self::isRec($md) && Js::has($md, self::RECEIPT_KEY)) {
                return Js::opt($md, self::RECEIPT_KEY);
            }
        }
        return null;
    }

    // ---- extended Agent Card (a card from a residual policy) ----

    /** A key that tells two values apart the way a JavaScript Set does (SameValueZero; objects by identity). */
    private static function setKey(mixed $v): string
    {
        if ($v === self::U) {
            return 'u';
        }
        if ($v === null) {
            return 'n';
        }
        if (is_bool($v)) {
            return $v ? 't' : 'f';
        }
        if (Js::isNum($v)) {
            $f = (float)Js::num($v);
            return is_nan($f) ? 'dNaN' : 'd' . ($f == 0.0 ? '0' : sprintf('%.17g', $f));
        }
        if (is_string($v)) {
            return 's' . $v;
        }
        // an object by identity (all envelopes stay alive for the call, so an id is never reused); an array is a fresh JS object each time
        return 'o' . (is_object($v) ? (string)spl_object_id($v) : uniqid('', true) . random_int(0, PHP_INT_MAX));
    }

    /** `(s.tags ?? []).find(startsWith 'pca-verb:')` sliced, or UNDEF. */
    private static function defaultVerbOf(mixed $s): mixed
    {
        $tags = self::nn(self::p($s, 'tags'), []);
        if (!self::isList($tags)) {
            throw new \TypeError('(s.tags ?? []).find is not a function');
        }
        foreach ($tags as $t) {
            if (is_string($t) && $t !== self::U && str_starts_with($t, 'pca-verb:')) {
                return substr($t, 9);
            }
        }
        return self::U;
    }

    /**
     * The card a caller may see after authenticating: a hidden skill is revealed only when its verb's envelope is `autonomous` or
     * `needs-approval` (no envelope or `denied` reveals nothing); all envelopes must come from one policy, whose digest is recorded in
     * the PCA extension params. `$o`: authenticated, hiddenSkills, envelopes, verbOf? (a Closure skill => verb). Unsigned: re-sign it.
     * Discovery only; attempting a skill still needs its PCActn.
     */
    public static function extendedAgentCard(mixed $publicCard, mixed $o): Obj
    {
        if (self::p($o, 'authenticated') !== true) {
            throw new \InvalidArgumentException('extendedAgentCard: the caller must be authenticated (A2A 13.3)');
        }
        $envs = self::p($o, 'envelopes');
        if (!self::isList($envs)) {
            throw new \TypeError('o.envelopes.map is not a function');
        }
        $digests = [];
        foreach ($envs as $e) {
            $d = self::p($e, 'policyDigest');
            $digests[self::setKey($d)] ??= $d;
        }
        if (count($digests) > 1) {
            throw new \RangeException('extendedAgentCard: envelopes were computed against different policies');
        }
        $byVerb = [];
        foreach ($envs as $e) {
            $byVerb[self::setKey(self::p($e, 'verb'))] = $e;
        }
        $verbOf = self::p($o, 'verbOf');
        $hidden = self::p($o, 'hiddenSkills');
        $skillsIn = self::isList($hidden) ? $hidden : (self::isStr($hidden) ? Js::spread($hidden) : throw new \TypeError('o.hiddenSkills is not iterable'));
        $revealed = [];
        foreach ($skillsIn as $s) {
            $verb = $verbOf instanceof \Closure ? $verbOf($s) : self::defaultVerbOf($s);
            $env = $verb === self::U || $verb === null ? self::U : ($byVerb[self::setKey($verb)] ?? self::U);
            if ($env === self::U || self::p($env, 'status') === 'denied') {
                continue;
            }
            $tags = self::nn(self::p($s, 'tags'), []);
            $sk = Payments::spreadObj($s);
            $sk->set('tags', [...Payments::spread($tags), self::p($env, 'status') === 'autonomous' ? 'pca:autonomous' : 'pca:needs-approval']);
            $revealed[] = $sk;
        }
        if ($publicCard === null || $publicCard === self::U) {
            throw new \TypeError("Cannot destructure 'publicCard' as it is null.");
        }
        $rest = Payments::spreadObj($publicCard)->without('signatures');
        $capsRaw = $rest->get('capabilities');
        $caps = Payments::spreadObj(self::nn($capsRaw, new Obj()));
        $extsRaw = $capsRaw === null ? self::U : self::p($capsRaw, 'extensions');
        $exts = self::isList($extsRaw) ? $extsRaw : [];
        $policyDigest = $digests === [] ? self::U : reset($digests);
        if ($policyDigest === self::U) {
            $next = $exts;
        } else {
            $next = [];
            foreach ($exts as $e) {
                if (self::p($e, 'uri') === self::PCA_A2A_EXTENSION_URI) {
                    $params = Payments::spreadObj(self::p($e, 'params'));
                    $params->set('policy_digest', $policyDigest);
                    $ne = Payments::spreadObj($e);
                    $ne->set('params', $params);
                    $next[] = $ne;
                } else {
                    $next[] = $e;
                }
            }
        }
        $skills = $rest->get('skills');
        $caps->set('extensions', $next);
        $rest->set('capabilities', $caps);
        $rest->set('skills', [...(self::isList($skills) ? $skills : []), ...$revealed]);
        return $rest;
    }
}
