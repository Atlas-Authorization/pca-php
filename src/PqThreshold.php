<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Mldsa.php';
require_once __DIR__ . '/GroupDescriptor.php';

/**
 * Post-quantum threshold step-up for PCActn: a hybrid of a classical FROST(Ed25519) aggregate (verified as the plain Ed25519
 * signature it is, under the verifier's pinned group key, the threshold bound by a signed {@see GroupDescriptor}) AND a pqT-of-m
 * ML-DSA-65 co-signature quorum over the same action digest. Both must hold; either short fails closed. ML-DSA is OpenSSL >= 3.5
 * libcrypto through FFI ({@see Mldsa}); without it every quorum signature is refused. The research lattice-threshold prototype of the
 * reference is not ported (it is labelled not-for-production).
 *
 * Wire values are parsed JSON (Obj / list / string / Num / bool / null) or plain PHP values; a key may be base64url text or a {@see Bytes}.
 * The result maps are plain PHP arrays in the reference's member order.
 */
final class PqThreshold
{
    public const HYBRID_ARTIFACT_VERSION = 2;
    public const PQ_QUORUM_VERSION = 2;
    public const MAX_PQ_QUORUM_ENTRIES = 256;
    /** The co-signer entry cap (MAX_PQ_SIGNER_ENTRIES): the same bound as the quorum entries. */
    public const MAX_PQ_SIGNER_ENTRIES = self::MAX_PQ_QUORUM_ENTRIES;
    public const HYBRID_CLASSICAL_ALG = 'frost-ed25519';
    public const PQ_QUORUM_ALG = 'ml-dsa-65';
    /** The PQ half of a hybrid threshold artifact (HYBRID_PQ_ALG): the quorum algorithm. */
    public const HYBRID_PQ_ALG = self::PQ_QUORUM_ALG;
    private const PQ_QUORUM_DOMAIN = "atlas-pca/pq-quorum/v2\0";
    /** Marks an option the caller did not supply at all (JavaScript `undefined`): its member is omitted from a verdict. */
    public const ABSENT = "\0absent";

    /** The member of an options object, or {@see ABSENT} when it is not there. */
    public static function opt(mixed $o, string $k): mixed
    {
        return GroupDescriptor::has($o, $k) ? GroupDescriptor::member($o, $k) : self::ABSENT;
    }

    /** @return array<string,mixed> */
    private static function verdict(bool $ok, int $count, mixed $need, ?string $reason): array
    {
        $m = ['ok' => $ok, 'count' => $count];
        if ($need !== self::ABSENT) {
            $m['need'] = $need;
        }
        if ($reason !== null) {
            $m['reason'] = $reason;
        }
        return $m;
    }

    /** The bytes every quorum co-signature covers: DOMAIN || sha256(message). */
    public static function pqQuorumRepresentative(string $message): string
    {
        return self::PQ_QUORUM_DOMAIN . hash('sha256', $message, true);
    }

    /**
     * The trusted pool as canonical b64u strings (text or Bytes entries); anything that is not a well-formed ML-DSA-65 public key is
     * ignored, repeats collapse. Throws for a non-array (the reference cannot iterate it).
     * @return list<string>
     */
    public static function normalizePqQuorumPool(mixed $pks): array
    {
        if (!is_array($pks) || !array_is_list($pks)) {
            throw new \InvalidArgumentException('pqPublicKeys is not iterable');
        }
        $pool = [];
        foreach ($pks as $p) {
            $s = GroupDescriptor::asB64u($p);
            if ($s !== null && Pca::unb64u($s, Mldsa::PUBLIC_KEY_BYTES) !== null) {
                $pool[$s] = true;
            }
        }
        return array_map('strval', array_keys($pool));
    }

    private static function mlDsa65VerifyB64u(string $pk, string $msg, string $sig): bool
    {
        $p = Pca::unb64u($pk, Mldsa::PUBLIC_KEY_BYTES);
        $s = Pca::unb64u($sig, Mldsa::SIGNATURE_BYTES);
        return $p !== null && $s !== null && Mldsa::verify($p, $msg, $s);
    }

    /**
     * One ML-DSA-65 co-signature per key pair over the representative; `$pqT` defaults to the signer count.
     * @param list<PqKeyPair> $keyPairs
     * @return array<string,mixed>
     */
    public static function signPqQuorum(string $message, array $keyPairs, ?int $pqT = null): array
    {
        $rep = self::pqQuorumRepresentative($message);
        $signers = [];
        foreach ($keyPairs as $k) {
            if ($k->family !== 'ML-DSA-65') {
                throw new \InvalidArgumentException('signPqQuorum: every co-signer key must be ML-DSA-65');
            }
            $signers[] = ['pk' => $k->public, 'sig' => Pca::b64u($k->sign($rep))];
        }
        return ['v' => self::PQ_QUORUM_VERSION, 'alg' => self::PQ_QUORUM_ALG, 'pqT' => $pqT ?? count($signers), 'signers' => $signers];
    }

    /**
     * Count DISTINCT trusted keys whose co-signature verifies over `$message`; ok iff the count reaches `$pqT`. Total: never throws. A
     * key outside the pool, a repeated key, a signature over another message and every malformed entry count for nothing; a block
     * whose version is missing, 1 or unknown is refused before any verification. `$trustedPool` is {@see normalizePqQuorumPool}'s result.
     * @param list<string> $trustedPool
     * @return array<string,mixed> {ok, count, need, reason?}
     */
    public static function verifyPqQuorum(mixed $block, string $message, array $trustedPool, mixed $pqT): array
    {
        $need = $pqT;
        if (!GroupDescriptor::isInteger($pqT) || GroupDescriptor::numOf($pqT) < 1) {
            return self::verdict(false, 0, $need, 'pqT must be a positive integer');
        }
        if (!GroupDescriptor::isObject($block)) {
            return self::verdict(false, 0, $need, 'malformed pq block');
        }
        if (!GroupDescriptor::has($block, 'v')) {
            return self::verdict(false, 0, $need, 'pq quorum version missing (pre-0.5 format is refused)');
        }
        $v = GroupDescriptor::numOf(GroupDescriptor::member($block, 'v'));
        if ($v === 1.0) {
            return self::verdict(false, 0, $need, 'pq quorum version 1 is no longer accepted (pre-0.5 format)');
        }
        if ($v === null || $v !== (float) self::PQ_QUORUM_VERSION) {
            return self::verdict(false, 0, $need, 'unsupported pq quorum version');
        }
        $signers = GroupDescriptor::member($block, 'signers');
        if (GroupDescriptor::member($block, 'alg') !== self::PQ_QUORUM_ALG || !is_array($signers) || !array_is_list($signers)) {
            return self::verdict(false, 0, $need, 'malformed pq block');
        }
        $pool = array_fill_keys($trustedPool, true);
        $rep = self::pqQuorumRepresentative($message);
        $counted = [];
        $seen = 0;
        foreach ($signers as $entry) {
            if ($seen++ >= self::MAX_PQ_QUORUM_ENTRIES) {
                break;
            }
            $pk = GroupDescriptor::member($entry, 'pk');
            $sig = GroupDescriptor::member($entry, 'sig');
            if (!is_string($pk) || !is_string($sig) || !isset($pool[$pk]) || isset($counted[$pk])) {
                continue;
            }
            if (!self::mlDsa65VerifyB64u($pk, $rep, $sig)) {
                continue;
            }
            $counted[$pk] = true;
        }
        $count = count($counted);
        if ((float) $count >= GroupDescriptor::numOf($pqT)) {
            return self::verdict(true, $count, $need, null);
        }
        return self::verdict(false, $count, $need, "post-quantum quorum short: $count of " . GroupDescriptor::show($pqT) . ' required ML-DSA co-signatures');
    }

    // ---- hybrid -----------------------------------------------------------------------------------------------------

    private static function normalizeGroupKeyB64u(mixed $k): ?string
    {
        $s = GroupDescriptor::asB64u($k);
        return $s !== null && Pca::unb64u($s, 32) !== null ? $s : null;
    }

    /** The FROST aggregate is a plain strict Ed25519 signature under the TRUSTED group key (never one the artifact declares). */
    private static function verifyFrostAggregate(mixed $sig, string $message, string $trustedGroupKey): bool
    {
        return is_string($sig) && Pca::verifyEd25519B64u($trustedGroupKey, $message, $sig);
    }

    /** @return array<string,mixed> */
    private static function malformed(): array
    {
        $reason = 'malformed action or verifier options';
        return ['ok' => false, 'frost' => false, 'pq' => self::verdict(false, 0, 0, $reason), 'reason' => $reason];
    }

    /**
     * Verify a standalone hybrid artifact over `$action` (a PCActn or body, an Obj). BOTH the classical aggregate and the pqT-of-m
     * quorum must hold; the declared classical threshold must not be below the required t (downgrade). `$opts` (an Obj or an
     * associative array): groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?. Never throws:
     * malformed input is a refusal. Returns {ok, frost, pq, reason?}.
     * @return array<string,mixed>
     */
    public static function verifyHybridThreshold(mixed $action, mixed $artifact, mixed $opts): array
    {
        try {
            return self::verifyInner($action, $artifact, $opts);
        } catch (\Throwable) {
            return self::malformed();
        }
    }

    /** @return array<string,mixed> */
    private static function verifyInner(mixed $action, mixed $artifact, mixed $opts): array
    {
        $pqT = self::opt($opts, 'pqT');
        $t = GroupDescriptor::member($opts, 't');
        $hasV = GroupDescriptor::isObject($artifact) && GroupDescriptor::has($artifact, 'v');
        $vn = GroupDescriptor::numOf(GroupDescriptor::member($artifact, 'v'));
        if (!$hasV || $vn === null || $vn !== (float) self::HYBRID_ARTIFACT_VERSION) {
            $reason = !$hasV ? 'artifact version missing (pre-0.5 format is refused)'
                : ($vn === 1.0 ? 'artifact version 1 is no longer accepted (pre-0.5 format)' : 'unsupported artifact version');
            return ['ok' => false, 'frost' => false, 'pq' => self::verdict(false, 0, $pqT, $reason), 'reason' => $reason];
        }
        if (!($action instanceof Obj)) {
            throw new \InvalidArgumentException('action is not an object');
        }
        $message = Pca::thresholdMessage($action);
        $groupKey = GroupDescriptor::member($opts, 'groupKey');
        $trustedGroupKey = self::normalizeGroupKeyB64u($groupKey);
        $pool = self::normalizePqQuorumPool(GroupDescriptor::member($opts, 'pqPublicKeys'));

        $frostOk = false;
        $frostReason = null;
        $ssc = GroupDescriptor::member($opts, 'signerSetCommitment');
        $dr = GroupDescriptor::verifyGroupDescriptor(GroupDescriptor::member($opts, 'groupDescriptor'), GroupDescriptor::member($opts, 'trustedAuthorities'), $groupKey, $t, $ssc);
        $descriptorReason = $dr['ok'] ? null : $dr['reason'];
        $frost = GroupDescriptor::member($artifact, 'frost');
        $declared = GroupDescriptor::member($frost, 't');
        if (!GroupDescriptor::isInteger($t) || GroupDescriptor::numOf($t) < 1) {
            $frostReason = 't must be a positive integer';
        } elseif ($trustedGroupKey === null) {
            $frostReason = 'trusted FROST group key is not a canonical b64u(32) point';
        } elseif (!GroupDescriptor::isObject($frost) || GroupDescriptor::member($frost, 'alg') !== self::HYBRID_CLASSICAL_ALG) {
            $frostReason = 'malformed or missing FROST part';
        } elseif ($descriptorReason !== null) {
            $frostReason = $descriptorReason;
        } elseif (!GroupDescriptor::isInteger($declared) || GroupDescriptor::numOf($declared) < GroupDescriptor::numOf($t)) {
            $frostReason = 'FROST declared threshold ' . GroupDescriptor::show($declared) . ' is below the required t=' . GroupDescriptor::show($t) . ' (downgrade)';
        } elseif (!self::verifyFrostAggregate(GroupDescriptor::member($frost, 'sig'), $message, $trustedGroupKey)) {
            $frostReason = 'FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)';
        } else {
            $frostOk = true;
        }
        $pq = self::verifyPqQuorum(GroupDescriptor::member($artifact, 'pq'), $message, $pool, $pqT);
        $ok = $frostOk && $pq['ok'] === true;
        $out = ['ok' => $ok, 'frost' => $frostOk, 'pq' => $pq];
        if (!$ok) {
            $r = $frostOk ? ($pq['reason'] ?? null) : $frostReason;
            if ($r !== null) {
                $out['reason'] = $r;
            }
        }
        return $out;
    }

    /**
     * Assemble a hybrid artifact from a FROST aggregate and the ML-DSA co-signers. Fails closed (throws): a sub-threshold quorum
     * count, no co-signer, a group key that is not 32 bytes, or an aggregate that does not verify under the group key over the action.
     * @param list<PqKeyPair> $pqSigners
     * @return array<string,mixed>
     */
    public static function hybridThresholdAssemble(Obj $action, string $groupPublicKey, string $frostAggregate, int $t, int $quorum, array $pqSigners, ?int $pqT = null): array
    {
        if ($t < 1) {
            throw new \InvalidArgumentException("hybridThresholdAssemble: t must be a positive integer (got $t)");
        }
        if ($quorum < $t) {
            throw new \InvalidArgumentException("hybridThresholdAssemble: FROST quorum of $quorum is below the threshold t=$t");
        }
        if ($pqSigners === []) {
            throw new \InvalidArgumentException('hybridThresholdAssemble: at least one ML-DSA co-signer is required');
        }
        if (strlen($groupPublicKey) !== 32) {
            throw new \InvalidArgumentException('hybridThresholdAssemble: FROST group public key must be 32 bytes');
        }
        $message = Pca::thresholdMessage($action);
        if (!Pca::verifyEd25519B64u(Pca::b64u($groupPublicKey), $message, Pca::b64u($frostAggregate))) {
            throw new \InvalidArgumentException('hybridThresholdAssemble: the FROST aggregate does not verify under the group key');
        }
        return [
            'v' => self::HYBRID_ARTIFACT_VERSION,
            'digest' => Pca::b64u(hash('sha256', $message, true)),
            'frost' => ['alg' => self::HYBRID_CLASSICAL_ALG, 'group_pk' => Pca::b64u($groupPublicKey), 'sig' => Pca::b64u($frostAggregate), 't' => $t, 'quorum' => $quorum],
            'pq' => self::signPqQuorum($message, $pqSigners, $pqT),
        ];
    }
}
