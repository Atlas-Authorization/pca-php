<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Frost.php';
require_once __DIR__ . '/GroupDescriptor.php';
require_once __DIR__ . '/PqThreshold.php';

/**
 * The signing and PCActn-verifier side of the hybrid post-quantum threshold step-up: sign with a FROST quorum plus ML-DSA-65
 * co-signers, fold the classical aggregate into a PCActn's threshold container, and enforce both halves through a threshold hook. The
 * artifact formats and the standalone verifier live in {@see PqThreshold}.
 *
 * This SDK's core verifier takes no threshold hook, so {@see verifyHybridStepUp} runs the core verification and the hook side by side
 * and allows only when both pass (the hook's refusal is reported as a `threshold:` reason, as the reference's core does).
 */
final class HybridThreshold
{
    private static function groupKeyBytes(mixed $k): string
    {
        if ($k instanceof Bytes) {
            if (strlen($k->raw) !== 32) {
                throw new \InvalidArgumentException('hybridThresholdSign: FROST group public key must be 32 bytes');
            }
            return $k->raw;
        }
        $d = is_string($k) ? Pca::unb64u($k, 32) : null;
        if ($d === null) {
            throw new \InvalidArgumentException('hybridThresholdSign: FROST group public key is not canonical b64u(32)');
        }
        return $d;
    }

    /**
     * A hybrid artifact for `$action`: the FROST t-of-n aggregate over thresholdMessage(action) (produced here by {@see Frost::cosign},
     * which throws on a short quorum or an invalid share) plus one ML-DSA-65 co-signature per signer over the same message.
     * `$groupPublicKey` is a {@see Bytes} or canonical b64u(32) text; `$quorum` the dealer's participant shares.
     * @param list<array{identifier:int,share:string,publicKey:string}> $quorum
     * @param list<PqKeyPair> $pqSigners
     * @return array<string,mixed>
     */
    public static function hybridThresholdSign(Obj $action, mixed $groupPublicKey, array $quorum, int $t, array $pqSigners, ?int $pqT = null): array
    {
        if ($t < 1) {
            throw new \InvalidArgumentException("hybridThresholdSign: frost.t must be a positive integer (got $t)");
        }
        if (count($quorum) < $t) {
            throw new \InvalidArgumentException('hybridThresholdSign: FROST quorum of ' . count($quorum) . " is below the threshold t=$t");
        }
        if ($pqSigners === []) {
            throw new \InvalidArgumentException('hybridThresholdSign: at least one ML-DSA co-signer is required');
        }
        $message = Pca::thresholdMessage($action);
        $groupKey = self::groupKeyBytes($groupPublicKey);
        $aggregate = Frost::cosign($groupKey, $quorum, $message, $t);
        return PqThreshold::hybridThresholdAssemble($action, $groupKey, $aggregate, $t, count($quorum), $pqSigners, $pqT);
    }

    /**
     * Fold a hybrid artifact into a PCActn step-up: the FROST aggregate becomes a 'guardian' share (publicKey = the group key, sig =
     * the aggregate) in `threshold.shares`; thresholdMessage excludes `threshold`, so neither quorum's signed bytes change. The PQ
     * block cannot live in the signed body and rides alongside. Returns {pcactn: Obj, pq?}.
     * @return array{pcactn:Obj,pq?:mixed}
     */
    public static function foldHybridStepUp(mixed $action, mixed $artifact): array
    {
        $frost = GroupDescriptor::member($artifact, 'frost');
        if (!($action instanceof Obj) || !GroupDescriptor::isObject($frost)) {
            throw new \InvalidArgumentException('foldHybridStepUp: artifact has no FROST part');
        }
        $share = new Obj();
        $share->set('role', 'guardian');
        if (GroupDescriptor::has($frost, 'group_pk')) { // an absent member stays absent (JSON drops undefined)
            $share->set('publicKey', GroupDescriptor::member($frost, 'group_pk'));
        }
        if (GroupDescriptor::has($frost, 'sig')) {
            $share->set('sig', GroupDescriptor::member($frost, 'sig'));
        }
        $existing = GroupDescriptor::member($action->get('threshold'), 'shares');
        $shares = is_array($existing) && array_is_list($existing) ? $existing : [];
        $shares[] = $share;
        $pcactn = new Obj();
        foreach ($action->keys() as $k) {
            $pcactn->set($k, $action->get($k));
        }
        $pcactn->set('threshold', Obj::of(['shares' => $shares]));
        $out = ['pcactn' => $pcactn];
        if (GroupDescriptor::has($artifact, 'pq')) {
            $out['pq'] = GroupDescriptor::member($artifact, 'pq');
        }
        return $out;
    }

    private static function deepCopy(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::deepCopy($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::deepCopy(...), $v) : $v; // Bytes, Num and scalars are immutable
    }

    private static function normalizeGroupKeyB64u(mixed $k): ?string
    {
        $s = GroupDescriptor::asB64u($k);
        return $s !== null && Pca::unb64u($s, 32) !== null ? $s : null;
    }

    /**
     * A threshold hook enforcing the hybrid step-up: the FROST aggregate folded into `pcactn.threshold` (a plain Ed25519 signature under
     * the TRUSTED group key) AND the ML-DSA quorum block. `$opts` (an Obj or an associative array): groupKey, pqPublicKeys, t, pqT,
     * pqBlock, groupDescriptor, trustedAuthorities, signerSetCommitment?. The configuration is copied, so later edits by the caller
     * change nothing. The returned callable takes the PCActn and returns {enforced: true, ok, reason?}; every refusal is enforced.
     * @return \Closure(mixed):array<string,mixed>
     */
    public static function createHybridThresholdVerifier(mixed $opts): \Closure
    {
        $o = self::deepCopy($opts);
        $groupKey = GroupDescriptor::member($o, 'groupKey');
        $trustedGroupKey = self::normalizeGroupKeyB64u($groupKey);
        $pool = PqThreshold::normalizePqQuorumPool(GroupDescriptor::member($o, 'pqPublicKeys'));
        $refuse = static fn(string $reason): array => ['enforced' => true, 'ok' => false, 'reason' => $reason];
        return static function (mixed $pcactn) use ($o, $groupKey, $trustedGroupKey, $pool, $refuse): array {
            $t = GroupDescriptor::member($o, 't');
            $dr = GroupDescriptor::verifyGroupDescriptor(GroupDescriptor::member($o, 'groupDescriptor'), GroupDescriptor::member($o, 'trustedAuthorities'),
                $groupKey, $t, GroupDescriptor::member($o, 'signerSetCommitment'));
            if (!$dr['ok']) {
                return $refuse($dr['reason']);
            }
            if (!($pcactn instanceof Obj)) {
                return $refuse('malformed step-up');
            }
            $message = Pca::thresholdMessage($pcactn);
            if ($trustedGroupKey === null) {
                return $refuse('trusted FROST group key is not a canonical b64u(32) point');
            }
            $sig = null;
            $found = false;
            $shares = GroupDescriptor::member($pcactn->get('threshold'), 'shares');
            foreach (is_array($shares) && array_is_list($shares) ? $shares : [] as $s) {
                $ssig = GroupDescriptor::member($s, 'sig');
                if (is_string($ssig) && GroupDescriptor::member($s, 'publicKey') === $trustedGroupKey) {
                    $sig = $ssig;
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                return $refuse('no FROST aggregate for the trusted group key in the step-up');
            }
            if (!Pca::verifyEd25519B64u($trustedGroupKey, $message, $sig)) {
                return $refuse('FROST aggregate does not verify under the trusted group key (quorum short or forged)');
            }
            $pq = PqThreshold::verifyPqQuorum(GroupDescriptor::member($o, 'pqBlock'), $message, $pool, PqThreshold::opt($o, 'pqT'));
            if ($pq['ok'] !== true) {
                return $refuse($pq['reason'] ?? 'post-quantum quorum short');
            }
            return ['enforced' => true, 'ok' => true];
        };
    }

    /**
     * Verify a folded hybrid step-up end to end: the whole PCActn must verify AND both the FROST threshold and the ML-DSA quorum must
     * hold. `$stepUp` is {pcactn, pq} ({@see foldHybridStepUp}); `$opts` (an Obj or an associative array): grant, groupKey,
     * pqPublicKeys, t (the step-up tier), pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?, audience? (text = must equal;
     * null = any; absent = refused when the PCActn carries an aud), nowEpoch (ms). Returns {allow, core, pq, reason?}.
     * @return array<string,mixed>
     */
    public static function verifyHybridStepUp(mixed $stepUp, mixed $opts): array
    {
        $pcactn = GroupDescriptor::member($stepUp, 'pcactn');
        $block = GroupDescriptor::member($stepUp, 'pq');
        if (!($pcactn instanceof Obj)) {
            throw new \InvalidArgumentException('verifyHybridStepUp: step-up has no PCActn');
        }
        $pool = PqThreshold::normalizePqQuorumPool(GroupDescriptor::member($opts, 'pqPublicKeys'));
        $pqT = PqThreshold::opt($opts, 'pqT');
        $pq = PqThreshold::verifyPqQuorum($block, Pca::thresholdMessage($pcactn), $pool, $pqT);
        $o = $opts instanceof Obj ? self::deepCopy($opts) : $opts;
        $hookOpts = new Obj();
        foreach (['groupKey', 'pqPublicKeys', 't', 'pqT', 'groupDescriptor', 'trustedAuthorities', 'signerSetCommitment'] as $k) {
            if (GroupDescriptor::has($o, $k)) {
                $hookOpts->set($k, GroupDescriptor::member($o, $k));
            }
        }
        $hookOpts->set('pqBlock', $block);
        $hook = self::createHybridThresholdVerifier($hookOpts);
        $audience = !GroupDescriptor::has($o, 'audience') ? null : (GroupDescriptor::member($o, 'audience') === null ? Audience::Any : GroupDescriptor::member($o, 'audience'));
        if ($audience !== null && !($audience instanceof Audience) && !is_string($audience)) {
            $audience = null;
        }
        $now = GroupDescriptor::numOf(GroupDescriptor::member($o, 'nowEpoch'));
        $core = Pca::verifyPcactnCore($pcactn, GroupDescriptor::member($o, 'grant'), $now !== null ? (int) $now : (int) (self::clock() * 1000), $audience, insecureSkipPlanRootCheck: true, thresholdHook: $hook);
        $allow = $core['allow'] === true;
        $out = ['allow' => $allow, 'core' => $core, 'pq' => $pq];
        if (!$allow) {
            $out['reason'] = $core['reason'];
        }
        return $out;
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;
    private static function clock(): float { return self::$clockHook !== null ? (self::$clockHook)() : microtime(true); }
}
