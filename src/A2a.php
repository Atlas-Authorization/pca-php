<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/PcaGrant.php';

/**
 * The A2A binding (verification side): typed needs (`pca_need`), per-hop chain extension, the pure gate of AUTH_REQUIRED
 * resumption, push-token binding and signed task-update receipts. Total. Per-hop PCActn verification is the ordinary verifier's job;
 * this is what surrounds it. Replays packages/pca/conformance/a2a-vectors.json. Values are parsed JSON (Obj, lists, Num).
 */
final class A2a
{
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
                if (!K3Sig::isStr($s, 128) || preg_match('/\s/u', $s) === 1) {
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
        return IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/need/v1', 'need' => $need]));
    }

    /**
     * @param list<list<string>> $chains
     * @return array{ok: bool, failedHop?: int, reason?: string}
     */
    public static function checkChainExtension(array $chains): array
    {
        $prev = null;
        foreach ($chains as $i => $ids) {
            if (!is_array($ids) || count($ids) === 0) {
                return ['ok' => false, 'failedHop' => $i, 'reason' => 'no_chain'];
            }
            if ($prev !== null && (count($ids) < count($prev) || array_slice($ids, 0, count($prev)) !== $prev)) {
                return ['ok' => false, 'failedHop' => $i, 'reason' => 'chain_does_not_extend_previous_hop'];
            }
            $prev = $ids;
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
        if (!($prev === null || (is_string($prev) && Pca::unb64u($prev, 32) !== null)) || (K3Sig::num($r->get('seq')) === 0.0) !== ($prev === null)) {
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
}
