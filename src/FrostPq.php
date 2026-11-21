<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Frost.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';

/**
 * Post-quantum companions of a networked FROST group: the group-algorithm registry (`ed25519` | `hybrid-ed25519-ml-dsa-65`), the signer-set digest, the
 * hybrid co-sign (a guardian ML-DSA-65 signature over a representative that binds the group key, sha256(message) and the signer set) and the PQ quorum
 * block (t ML-DSA-65 signatures by distinct pooled keys over `DOMAIN || sha256(message)`). Verification is total: any failure is a verdict.
 */
final class FrostPq
{
    public const DEFAULT_GROUP_ALG = 'ed25519';
    public const HYBRID_GROUP_ALG = 'hybrid-ed25519-ml-dsa-65';
    public const PQ_QUORUM_VERSION = 2;
    public const PQ_QUORUM_ALG = 'ml-dsa-65';
    public const MAX_PQ_QUORUM_ENTRIES = 256;
    private const COSIGN_DOMAIN = "atlas-pca/frost-pq-cosign/v1\0";
    private const SIGNER_SET_DOMAIN = "atlas-pca/frost-signer-set/v1\0";
    private const PQ_QUORUM_DOMAIN = "atlas-pca/pq-quorum/v2\0";
    private const ML_DSA_65_PK_BYTES = 1952;

    private static function known(mixed $x): bool
    {
        return $x === self::DEFAULT_GROUP_ALG || $x === self::HYBRID_GROUP_ALG;
    }

    /** The group algorithm: absent is `ed25519`, a known name itself, anything else null (fail closed). */
    public static function resolveGroupAlg(mixed $alg): ?string
    {
        if ($alg instanceof Undef) {
            return self::DEFAULT_GROUP_ALG;
        }
        return self::known($alg) ? $alg : null;
    }

    /** sha256(domain || canonical(sorted distinct identifiers)). Throws on an empty set or an identifier that is not a positive safe integer. */
    public static function signerSetDigest(mixed $signerSet): string
    {
        if (!is_array($signerSet) || !array_is_list($signerSet) || $signerSet === []) {
            throw new \RangeException('frostSignerSetDigest: empty signer set');
        }
        $ids = [];
        foreach ($signerSet as $id) {
            $f = Js::num($id);
            if ($f === null || !is_finite($f) || $f != floor($f) || abs($f) > 9007199254740991.0 || $f <= 0) {
                throw new \RangeException('frostSignerSetDigest: participant identifiers must be positive safe integers');
            }
            $ids[(string)(int)$f] = (int)$f;
        }
        sort($ids, SORT_NUMERIC);
        return hash('sha256', self::SIGNER_SET_DOMAIN . Json::canonicalizeNative($ids), true);
    }

    /** The bytes the guardian ML-DSA key signs. Throws on a group key that is not a 32-byte base64url point. */
    public static function cosignRepresentative(mixed $groupPublicKeyB64u, string $message, mixed $signerSet, mixed $groupAlg): string
    {
        $gpk = Pca::decodeB64uStrict($groupPublicKeyB64u, 32);
        if ($gpk === null) {
            throw new \RangeException('frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point');
        }
        return self::COSIGN_DOMAIN . (is_string($groupAlg) ? $groupAlg : Jsx::str($groupAlg)) . "\0" . $gpk . hash('sha256', $message, true) . self::signerSetDigest($signerSet);
    }

    /**
     * The FROST aggregate over a quorum (`[{identifier, share, publicKey}]`, raw bytes) as `sig` (base64url); for the hybrid group algorithm also the guardian
     * ML-DSA-65 co-signature `pq_sig` and `pq_pk`. `$opts`: `groupAlg?`, `guardianMlDsa?` (a PqKeyPair), `threshold?`.
     * @return array{sig:string,groupAlg?:string,pq_sig?:string,pq_pk?:string}
     */
    public static function signHybridCosign(string $groupPublicKey, array $quorum, string $message, array $opts = []): array
    {
        $groupAlg = $opts['groupAlg'] ?? self::DEFAULT_GROUP_ALG;
        if (!self::known($groupAlg)) {
            throw new \RangeException("signHybridFrostCosign: unknown groupAlg '" . Jsx::str($groupAlg) . "'");
        }
        $sig = Pca::b64u(Frost::cosign($groupPublicKey, $quorum, $message, $opts['threshold'] ?? null));
        if ($groupAlg === self::DEFAULT_GROUP_ALG) {
            return ['sig' => $sig];
        }
        $pq = $opts['guardianMlDsa'] ?? null;
        if (!($pq instanceof PqKeyPair)) {
            throw new \TypeError("signHybridFrostCosign: '$groupAlg' requires a guardian ML-DSA-65 key pair");
        }
        $rep = self::cosignRepresentative(Pca::b64u($groupPublicKey), $message, array_map(static fn(array $p): int => $p['identifier'], $quorum), $groupAlg);
        return ['sig' => $sig, 'groupAlg' => $groupAlg, 'pq_sig' => Pq::signWithSuite('ml-dsa-65', null, $pq, $rep)['sig'], 'pq_pk' => $pq->public];
    }

    /**
     * Verify a (hybrid) FROST co-signature. `$opts`: `{guardianPqPublicKey?, expectGroupAlg?}`. A hybrid group needs BOTH halves; the guardian key is the
     * REGISTERED one (the artifact's own `pq_pk`, when present, must equal it). @return array{ok:bool,groupAlg?:string,edOk:bool,pqOk:bool,reason?:string}
     */
    public static function verifyHybridCosign(mixed $artifact, string $message, mixed $groupPublicKeyB64u, mixed $signerSet, mixed $opts = null): array
    {
        $deny = static fn(string $reason, ?string $alg = null): array => ['ok' => false, 'edOk' => false, 'pqOk' => false] + ($alg !== null ? ['groupAlg' => $alg] : []) + ['reason' => $reason];
        $sig = Jsx::get($artifact, 'sig');
        if (!Jsx::truthy($artifact) || !is_string($sig)) {
            return $deny('malformed artifact');
        }
        if (!is_string($groupPublicKeyB64u) || Pca::decodeB64uStrict($groupPublicKeyB64u, 32) === null) {
            return $deny('malformed group public key');
        }
        $ga = Jsx::get($artifact, 'groupAlg');
        $groupAlg = self::resolveGroupAlg($ga);
        if ($groupAlg === null) {
            return $deny("unknown groupAlg '" . Jsx::str($ga) . "'");
        }
        $expect = Jsx::get($opts, 'expectGroupAlg');
        if (!($expect instanceof Undef)) {
            if (!self::known($expect)) {
                return $deny("unknown expected groupAlg '" . Jsx::str($expect) . "'");
            }
            if ($expect !== $groupAlg) {
                return $deny("groupAlg '$groupAlg' does not match the required '$expect'", $groupAlg);
            }
        }
        $edOk = Pca::verifyWithSuite('ed25519', ['edPub' => $groupPublicKeyB64u], $message, ['sig' => $sig]);
        if ($groupAlg === self::DEFAULT_GROUP_ALG) {
            return $edOk ? ['ok' => true, 'groupAlg' => $groupAlg, 'edOk' => true, 'pqOk' => false] : $deny('FROST Ed25519 group signature did not verify', $groupAlg);
        }
        $registered = Jsx::get($opts, 'guardianPqPublicKey');
        if (!is_string($registered) || Pca::decodeB64uStrict($registered, self::ML_DSA_65_PK_BYTES) === null) {
            return $deny('hybrid groupAlg requires a registered guardian ML-DSA-65 public key', $groupAlg);
        }
        $apk = Jsx::get($artifact, 'pq_pk');
        if (!($apk instanceof Undef) && $apk !== $registered) {
            return $deny('artifact pq_pk does not match the registered guardian ML-DSA key', $groupAlg);
        }
        $pqSig = Jsx::get($artifact, 'pq_sig');
        if (!is_string($pqSig)) {
            return $deny('hybrid groupAlg declared but the guardian ML-DSA co-signature is missing', $groupAlg);
        }
        try {
            $rep = self::cosignRepresentative($groupPublicKeyB64u, $message, $signerSet, $groupAlg);
            $pqOk = Pca::verifyWithSuite('ml-dsa-65', ['pq' => Pca::resolvePqVerifyKey('', null, ['trustedPk' => $registered])], $rep, ['sig' => $pqSig]);
        } catch (\Throwable) {
            $pqOk = false;
        }
        if (!$edOk || !$pqOk) {
            return ['ok' => false, 'groupAlg' => $groupAlg, 'edOk' => $edOk, 'pqOk' => $pqOk,
                'reason' => !$edOk ? 'FROST Ed25519 group signature did not verify' : 'guardian ML-DSA-65 co-signature did not verify'];
        }
        return ['ok' => true, 'groupAlg' => $groupAlg, 'edOk' => true, 'pqOk' => true];
    }

    // ---- the PQ quorum block ---------------------------------------------------------------------------------------------

    public static function pqQuorumRepresentative(string $message): string
    {
        return self::PQ_QUORUM_DOMAIN . hash('sha256', $message, true);
    }

    /** @param list<PqKeyPair> $keyPairs @return Obj `{v: 2, alg: "ml-dsa-65", pqT, signers: [{pk, sig}]}` (pqT defaults to the number of signers) */
    public static function signPqQuorum(string $message, array $keyPairs, mixed $pqT = null): Obj
    {
        $rep = self::pqQuorumRepresentative($message);
        $signers = array_map(static fn(PqKeyPair $k): Obj => Obj::of(['pk' => $k->public, 'sig' => Pca::b64u(Pq::mlDsa65Sign($k, $rep))]), $keyPairs);
        return Obj::of(['v' => self::PQ_QUORUM_VERSION, 'alg' => self::PQ_QUORUM_ALG, 'pqT' => $pqT ?? count($signers), 'signers' => $signers]);
    }

    /**
     * The set of valid ML-DSA-65 public keys (base64url) of a pool: a raw key is `['bytes' => <raw>]`, anything not a well-formed key is dropped.
     * @param list<mixed> $pks @return list<string> distinct keys in first-seen order
     */
    public static function normalizePqQuorumPool(array $pks): array
    {
        $pool = [];
        foreach ($pks as $p) {
            $s = is_array($p) && isset($p['bytes']) ? Pca::b64u($p['bytes']) : $p;
            if (is_string($s) && Pca::decodeB64uStrict($s, self::ML_DSA_65_PK_BYTES) !== null) {
                $pool[$s] = true;
            }
        }
        return array_map('strval', array_keys($pool));
    }

    /**
     * At least `$pqT` distinct pooled keys must have signed the representative (a signer not in the pool, a repeated key and a bad signature are skipped;
     * at most 256 entries are read). @param list<string> $trustedPool @return array{ok:bool,count:int,need:mixed,reason?:string}
     */
    public static function verifyPqQuorum(mixed $block, string $message, array $trustedPool, mixed $pqT): array
    {
        $no = static fn(string $reason): array => ['ok' => false, 'count' => 0, 'need' => $pqT, 'reason' => $reason];
        $t = Js::num($pqT);
        if ($t === null || !is_finite($t) || $t != floor($t) || $t < 1) {
            return $no('pqT must be a positive integer');
        }
        if (!($block instanceof Obj) && !is_array($block)) {
            return $no('malformed pq block');
        }
        $v = Jsx::get($block, 'v');
        if ($v instanceof Undef) {
            return $no('pq quorum version missing (pre-0.5 format is refused)');
        }
        if (Js::isNum($v) && Js::num($v) === 1.0) {
            return $no('pq quorum version 1 is no longer accepted (pre-0.5 format)');
        }
        if (!(Js::isNum($v) && Js::num($v) === (float)self::PQ_QUORUM_VERSION)) {
            return $no('unsupported pq quorum version');
        }
        $signers = Jsx::get($block, 'signers');
        if (Jsx::get($block, 'alg') !== self::PQ_QUORUM_ALG || !is_array($signers) || !array_is_list($signers)) {
            return $no('malformed pq block');
        }
        $rep = self::pqQuorumRepresentative($message);
        $counted = [];
        foreach (array_slice($signers, 0, self::MAX_PQ_QUORUM_ENTRIES) as $e) {
            $pk = Jsx::get($e, 'pk');
            $sig = Jsx::get($e, 'sig');
            if (!($e instanceof Obj) || !is_string($pk) || !is_string($sig) || !in_array($pk, $trustedPool, true) || isset($counted[$pk]) || !Pq::mlDsa65VerifyB64u($pk, $rep, $sig)) {
                continue;
            }
            $counted[$pk] = true;
        }
        $count = count($counted);
        return $count >= $t ? ['ok' => true, 'count' => $count, 'need' => $pqT]
            : ['ok' => false, 'count' => $count, 'need' => $pqT, 'reason' => "post-quantum quorum short: $count of " . Jsx::str($pqT) . ' required ML-DSA co-signatures'];
    }
}
