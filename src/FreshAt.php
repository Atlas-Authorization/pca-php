<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';

/**
 * Consistency tokens (`fresh_at`): the signed high-water mark of verifier-side state a write returned, the PCActn member that
 * carries it and the verifier's `fresh_at` check (fresh-at.ts of the reference). A verifier refuses to decide against state
 * older than the token (`stale_state` = escalate, never allow). Verification only: this SDK does not mint tokens. Total.
 */
final class FreshAt
{
    public const DOMAIN = "atlas-pca/fresh-at/v1\0";
    public const REF_DOMAIN = 'atlas-pca/fresh-at-ref/v1';
    private const NUMERIC = ['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision'];
    private const KEYS = ['v', 'scope', 'revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision', 'policy_digest', 'issued_at', 'signer', 'sig'];
    private const SKEW_MS = 60000.0;

    /** Well formed and signed by `$signer` over exactly its content. */
    public static function verify(mixed $t, mixed $signer): bool
    {
        if (!($t instanceof Obj) || !K3Sig::isNumber($t->get('v'), 1.0) || $t->get('signer') !== $signer || !K3Sig::isStr($t->get('scope'), 256)
            || !K3Sig::isStr($t->get('policy_digest'), 128) || !K3Sig::isSafeInt($t->get('issued_at'))) {
            return false;
        }
        foreach (self::NUMERIC as $k) {
            if (!K3Sig::isSafeInt($t->get($k))) {
                return false;
            }
        }
        $body = new Obj();
        foreach (['v', 'scope', 'revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision', 'policy_digest', 'issued_at', 'signer'] as $k) {
            $body->set($k, $t->get($k));
        }
        return K3Sig::verifyBody(self::DOMAIN, $body, $signer, $t->get('sig'));
    }

    /** The content address a PCActn or request signs to bind the token it carried. */
    public static function digest(mixed $t): ?string
    {
        try {
            return Pca::hashCanonical(Obj::of(['d' => self::REF_DOMAIN, 't' => $t]));
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * May the verifier decide against `$local` for `$token`? Order (each fails closed): signature/shape, scope, issued in the
     * future (> 60 s skew), token age, policy fork, any counter behind the token => escalate `stale_state`.
     * `$o`: signer, scope, now, maxTokenAgeMs? (an Obj of the vector shape).
     *
     * @return array{decision:string, code?:string, behind?:list<string>}
     */
    public static function check(mixed $token, mixed $local, mixed $o): array
    {
        try {
            $signer = $o instanceof Obj ? $o->get('signer') : null;
            if (!self::verify($token, $signer)) {
                return ['decision' => 'deny', 'code' => 'bad_token'];
            }
            /** @var Obj $token */
            $local = $local instanceof Obj ? $local : new Obj();
            if ($token->get('scope') !== $o->get('scope')) {
                return ['decision' => 'deny', 'code' => 'wrong_scope'];
            }
            $issued = K3Sig::num($token->get('issued_at'));
            $now = K3Sig::num($o->get('now'));
            if (!($now !== null && $issued <= $now + self::SKEW_MS)) {
                return ['decision' => 'deny', 'code' => 'token_from_the_future'];
            }
            $max = $o->get('maxTokenAgeMs');
            if ($max !== null && !(K3Sig::num($max) !== null && $now - $issued <= K3Sig::num($max))) {
                return ['decision' => 'deny', 'code' => 'token_too_old'];
            }
            if (K3Sig::num($token->get('policy_revision')) === K3Sig::num($local->get('policy_revision'))
                && $token->get('policy_digest') !== $local->get('policy_digest')) {
                return ['decision' => 'deny', 'code' => 'policy_fork'];
            }
            $behind = [];
            foreach (self::NUMERIC as $k) {
                $l = K3Sig::num($local->get($k));
                if (!($l !== null && $l >= K3Sig::num($token->get($k)))) {
                    $behind[] = $k;
                }
            }
            return $behind === [] ? ['decision' => 'ok'] : ['decision' => 'escalate', 'code' => 'stale_state', 'behind' => $behind];
        } catch (\Throwable) {
            return ['decision' => 'deny', 'code' => 'bad_token'];
        }
    }

    /** Wire shape of the `fresh_at` member (not its signature): the problem, or null. */
    public static function validateWire(mixed $v): ?string
    {
        if (!($v instanceof Obj)) {
            return "'fresh_at' must be an object";
        }
        foreach ($v->keys() as $k) {
            if (!in_array($k, self::KEYS, true)) {
                return "'fresh_at' has an unknown field '$k'";
            }
        }
        if (!K3Sig::isNumber($v->get('v'), 1.0)) {
            return "'fresh_at.v' must be 1";
        }
        if (!K3Sig::isStr($v->get('scope'), 256) || !K3Sig::isStr($v->get('policy_digest'), 128)) {
            return "'fresh_at' scope and policy_digest must be non-empty strings";
        }
        foreach (['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision', 'issued_at'] as $k) {
            if (!K3Sig::isSafeInt($v->get($k))) {
                return "'fresh_at.$k' must be a non-negative safe integer";
            }
        }
        if (Pca::unb64u($v->get('signer'), 32) === null) {
            return "'fresh_at.signer' is not canonical base64url (32 bytes)";
        }
        if (Pca::unb64u($v->get('sig'), 64) === null) {
            return "'fresh_at.sig' is not canonical base64url (64 bytes)";
        }
        return null;
    }

    /**
     * The verifier's `fresh_at` check. `$policy` is the vector-shaped Obj {signer, scope, local, max_token_age_ms?, require?,
     * side_carried?} or null (none); a present `side_carried` key (even null) is a token that travelled beside the PCActn, read
     * only when the PCActn has no member. Reported only when the PCActn carries the member, a side-carried token is read, or the
     * policy requires one: otherwise 'none' (byte-identical to before).
     *
     * @return array{status:string, reason?:string}
     */
    public static function decide(bool $hasMember, mixed $member, mixed $policy, int $now): array
    {
        if (!($policy instanceof Obj)) {
            return $hasMember ? ['status' => 'fail', 'reason' => 'the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)'] : ['status' => 'none'];
        }
        $hasToken = $hasMember || $policy->has('side_carried');
        if (!$hasToken) {
            return $policy->get('require') === true
                ? ['status' => 'fail', 'reason' => 'escalate: a consistency token is required (refresh and retry with the token of your latest write)']
                : ['status' => 'none'];
        }
        $token = $hasMember ? $member : $policy->get('side_carried');
        $o = Obj::of(['signer' => $policy->get('signer'), 'scope' => $policy->get('scope'), 'now' => $now]);
        if ($policy->has('max_token_age_ms')) {
            $o->set('maxTokenAgeMs', $policy->get('max_token_age_ms'));
        }
        $v = self::check($token, $policy->get('local'), $o);
        return match ($v['decision']) {
            'ok' => ['status' => 'pass'],
            'escalate' => ['status' => 'fail', 'reason' => 'escalate: stale_state (verifier state is behind the token on ' . implode(', ', $v['behind']) . ')'],
            default => ['status' => 'fail', 'reason' => $v['code']],
        };
    }

    /**
     * The policy with the side-carried token (the `pca-fresh-at` header, JSON) added, only when there is a policy, the PCActn has
     * no `fresh_at` member and the policy names no token of its own. An unparseable header is a null token (bad_token), never a
     * missing one.
     */
    public static function withSideCarried(?Obj $policy, Obj $pcactn, string $header): ?Obj
    {
        if ($policy === null || $header === '' || $pcactn->has('fresh_at') || $policy->has('side_carried')) {
            return $policy;
        }
        try {
            $token = Json::parseStrict($header);
        } catch (\Throwable) {
            $token = null;
        }
        $out = $policy->without();
        $out->set('side_carried', $token);
        return $out;
    }
}
