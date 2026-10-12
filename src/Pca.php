<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Mldsa.php';

/**
 * An opaque PQ verification key (R3-01 choke point). Minted ONLY by Pca::resolvePqKey, so the low-level PQ verification
 * (Pca::verifySuite) cannot be reached with a `pq_pk` read straight off the artifact being verified.
 * @internal
 */
final class PinnedPq
{
    private function __construct(public readonly string $key, public readonly string $source)
    {
    }

    /** @internal callable from Pca only (anything else is a programming error and throws). */
    public static function mint(string $key, string $source): self
    {
        $caller = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['class'] ?? null;
        if ($caller !== Pca::class) {
            throw new \LogicException('PinnedPq is minted only by Pca::resolvePqKey');
        }
        return new self($key, $source);
    }
}

/**
 * Verifier for the CORE PCActn checks, wire format v2 (strict): wire, version, audience, validity, chain,
 * plan_inclusion, leaf_signature, counter. Values are Json::parse* trees (Obj / list / string / Num / bool / null).
 */
final class Pca
{
    public const SIG_DOMAIN = "atlas-pca/actn/v2\0";
    public const CAP_DOMAIN = "atlas-pca/cap/v1\0";
    public const DEFAULT_REV = 'reversible';
    public const MAX_CHAIN = 16;
    /** Shared hard caveat caps (all PCA verifiers): per-hop cumulative list, and the sum over every hop of a chain. */
    public const MAX_CAVEATS_PER_HOP = 256;
    public const MAX_CAVEATS_PER_CHAIN = 1024;
    public const CAVEAT_LIMIT_REASON = 'chain exceeds caveat limit (max 256 per hop, 1024 per chain)';
    /** Shared raw wire-size cap of a PCActn JSON document (UTF-8 bytes), checked before any parsing. */
    public const MAX_ARTIFACT_BYTES = 524288;
    public const ARTIFACT_SIZE_REASON = 'artifact exceeds size limit (max 524288 bytes)';
    public const MAX_LIFETIME_MS = 3600000;
    public const MAX_SKEW_MS = 60000;
    public const MAX_AUD_LEN = 256;
    public const MAX_NONCE_LEN = 128;

    private const REQUIRED = ['ver', 'action', 'grant_ref', 'cap_chain', 'plan', 'attestation', 'provenance',
        'freshness', 'counter', 'risk_claim', 'aud', 'iat', 'exp', 'sig'];
    private const OPTIONAL = ['nonce', 'caution', 'rationale_commitment', 'progress_step', 'prohibition_evidence',
        'tool_binding', 'threshold', 'zk_compliance', 'bond_ref',
        // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
        'alg', 'pq_pk', 'pq_sig'];

    // B4 post-quantum suites (mirrors packages/pca/src/pq.ts). alg name => [sig bytes, needs pq_pk, needs pq_sig].
    public const ED25519_SIGNATURE_BYTES = 64;
    private const SIG_SUITES = [
        'ed25519' => [self::ED25519_SIGNATURE_BYTES, false, false],
        'ml-dsa-65' => [Mldsa::SIGNATURE_BYTES, true, false],
        'hybrid-ed25519-ml-dsa-65' => [self::ED25519_SIGNATURE_BYTES, true, true],
    ];

    // ---- helpers ------------------------------------------------------------------------

    public static function b64u(string $raw): string
    {
        return sodium_bin2base64($raw, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * Strict base64url (RFC 4648 s5, no padding, alphabet only, len%4 != 1, zero trailing bits, optional exact
     * decoded byte length). Null when invalid.
     */
    public static function unb64u(mixed $s, ?int $len = null): ?string
    {
        if (!is_string($s) || preg_match('/\A[A-Za-z0-9_-]*\z/D', $s) !== 1 || strlen($s) % 4 === 1) {
            return null;
        }
        if ($len !== null && strlen($s) !== (int)ceil($len * 4 / 3)) {
            return null;
        }
        try {
            $raw = sodium_base642bin($s, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\Throwable) {
            return null;
        }
        if (self::b64u($raw) !== $s || ($len !== null && strlen($raw) !== $len)) {
            return null;
        }
        return $raw;
    }

    private static function sha(string $b): string
    {
        return hash('sha256', $b, true);
    }

    public static function hashCanonical(mixed $v): string
    {
        return self::b64u(self::sha(Json::canonicalizeStrict($v)));
    }

    private static function get(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : null;
    }

    private static function isInt(mixed $v): bool
    {
        return $v instanceof Num && $v->isInt() && $v->strictError() === null;
    }

    private static function isNum(mixed $v): bool
    {
        return $v instanceof Num && $v->strictError() === null;
    }

    // ---- Merkle -------------------------------------------------------------------------

    private static function leafHash(mixed $leaf): string
    {
        return self::sha("\x00" . Json::canonicalizeStrict($leaf));
    }

    private static function nodeHash(string $l, string $r): string
    {
        return self::sha("\x01" . $l . $r);
    }

    private static function split(int $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $k;
    }

    private static function build(array $hs): string
    {
        if (count($hs) === 1) {
            return $hs[0];
        }
        $k = self::split(count($hs));
        return self::nodeHash(self::build(array_slice($hs, 0, $k)), self::build(array_slice($hs, $k)));
    }

    public static function merkleRoot(array $leaves): string
    {
        if (count($leaves) === 0) {
            throw new \InvalidArgumentException('empty leaf set');
        }
        return self::b64u(self::build(array_map([self::class, 'leafHash'], array_values($leaves))));
    }

    /** Sibling sides (leaf -> root) determined by index/size (RFC 6962 split). */
    private static function pathShape(int $index, int $size): array
    {
        $out = [];
        $idx = $index;
        $n = $size;
        while ($n > 1) {
            $k = self::split($n);
            if ($idx < $k) {
                $out[] = 'R';
                $n = $k;
            } else {
                $out[] = 'L';
                $idx -= $k;
                $n -= $k;
            }
        }
        return array_reverse($out);
    }

    /** Never throws; malformed proofs return false. Index/size are bound to the path shape. */
    public static function verifyInclusion(string $root, mixed $proof, mixed $leaf): bool
    {
        try {
            $path = self::get($proof, 'path');
            if (!is_array($path) || !array_is_list($path)) {
                return false;
            }
            $index = self::get($proof, 'index');
            $size = self::get($proof, 'size');
            if (!self::isInt($index) || !self::isInt($size)) {
                return false;
            }
            $index = $index->int();
            $size = $size->int();
            if ($size < 1 || $index < 0 || $index >= $size) {
                return false;
            }
            $shape = self::pathShape($index, $size);
            if (count($shape) !== count($path)) {
                return false;
            }
            $h = self::leafHash($leaf);
            foreach ($path as $i => $step) {
                if (!($step instanceof Obj) || self::get($step, 'side') !== $shape[$i]) {
                    return false;
                }
                $sib = self::unb64u(self::get($step, 'hash'), 32);
                if ($sib === null) {
                    return false;
                }
                $h = $shape[$i] === 'L' ? self::nodeHash($sib, $h) : self::nodeHash($h, $sib);
            }
            return self::b64u($h) === $root;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function paramsDigest(mixed $params = null): string
    {
        return self::hashCanonical($params ?? new Obj());
    }

    private static function conditionsDigest(mixed $pre, mixed $post): string
    {
        return self::hashCanonical(Obj::of(['pre' => $pre, 'post' => $post]));
    }

    private static function planLeaf(mixed $nodeId, mixed $action, string $cond): Obj
    {
        $pd = self::get($action, 'params_digest') ?? self::paramsDigest();
        $rc = self::get($action, 'reversibility_class') ?? self::DEFAULT_REV;
        return Obj::of([
            'node_id' => $nodeId, 'verb' => self::get($action, 'verb'), 'resource' => self::get($action, 'resource'),
            'params_digest' => $pd, 'reversibility_class' => $rc, 'conditions' => $cond,
        ]);
    }

    // ---- Ed25519 (strict RFC 8032) -----------------------------------------------------

    /**
     * True iff the 32-byte encoding is a point of the PRIME-ORDER subgroup (rejects small-order, mixed-order /
     * torsioned and off-curve points). PHP exposes no raw Ed25519 scalar-mult, but libsodium's
     * crypto_sign_ed25519_pk_to_curve25519 refuses exactly: small-order points, undecodable points, and any
     * point not on the main subgroup.
     */
    private static function primeOrderPoint(string $p): bool
    {
        try {
            return strlen(sodium_crypto_sign_ed25519_pk_to_curve25519($p)) === 32;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function verifyB64u(mixed $pub, string $msg, mixed $sig): bool
    {
        $pk = self::unb64u($pub, 32);
        $sg = self::unb64u($sig, 64);
        if ($pk === null || $sg === null) {
            return false;
        }
        if (!self::primeOrderPoint($pk) || !self::primeOrderPoint(substr($sg, 0, 32))) {
            return false;
        }
        try {
            // libsodium additionally rejects non-canonical S (S >= L) and small-order/non-canonical A
            return sodium_crypto_sign_verify_detached($sg, $msg, $pk);
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- B4 crypto-agility: suite resolution, wire validation, leaf seam -----------------

    /** @return array{0:?string,1:?string} [suite name (null = fail-closed), error reason] */
    private static function resolveSuite(Obj $p): array
    {
        if (!$p->has('alg')) {
            return ['ed25519', null];
        }
        $alg = $p->get('alg');
        if (!is_string($alg)) {
            return [null, "'alg' must be a string"];
        }
        if (!isset(self::SIG_SUITES[$alg])) {
            return [null, "unknown signature alg '$alg'"];
        }
        return [$alg, null];
    }

    /** Validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. null when well-formed, else a short reason. */
    private static function validateSignatureWire(Obj $p): ?string
    {
        [$suite, $err] = self::resolveSuite($p);
        if ($suite === null) {
            return $err;
        }
        [$sigBytes, $needsPk, $needsSig] = self::SIG_SUITES[$suite];
        if (!self::b($p->get('sig'), $sigBytes)) {
            return "'sig' is not canonical base64url ($sigBytes bytes) for alg '$suite'";
        }
        if ($needsPk) {
            if (!self::b($p->get('pq_pk'), Mldsa::PUBLIC_KEY_BYTES)) {
                return "'pq_pk' is not canonical base64url (" . Mldsa::PUBLIC_KEY_BYTES . ' bytes)';
            }
        } elseif ($p->has('pq_pk')) {
            return "'pq_pk' must be absent for alg '$suite'";
        }
        if ($needsSig) {
            if (!self::b($p->get('pq_sig'), Mldsa::SIGNATURE_BYTES)) {
                return "'pq_sig' is not canonical base64url (" . Mldsa::SIGNATURE_BYTES . ' bytes)';
            }
        } elseif ($p->has('pq_sig')) {
            return "'pq_sig' must be absent for alg '$suite'";
        }
        return null;
    }

    private static function mldsaVerifyB64u(mixed $pk, string $msg, mixed $sig): bool
    {
        $pkRaw = self::unb64u($pk, Mldsa::PUBLIC_KEY_BYTES);
        $sgRaw = self::unb64u($sig, Mldsa::SIGNATURE_BYTES);
        if ($pkRaw === null || $sgRaw === null) {
            return false;
        }
        return Mldsa::verify($pkRaw, $msg, $sgRaw);
    }

    /**
     * THE choke point (R3-01), mirroring resolvePqVerifyKey in packages/pca/src/pq.ts. Returns the key to verify under, or
     * null (REFUSE) when no verifier-side authority vouches for the artifact's `pq_pk`:
     *   1. $trustedPk: a key the verifier itself holds (the stored grant). Used as is.
     *   2. $pqPins[$identity] (own entry only; an Obj or a string=>string array): the artifact key MUST equal the pin; a differing pin is a refusal.
     *   3. $holderPq: the artifact key must hash to the signer's committed `holder_pq` (F-2).
     * Natives have no allowUnboundPq: an artifact's own key is never enough.
     */
    private static function resolvePqKey(mixed $identity, mixed $artifactPk, mixed $holderPq = null, mixed $pqPins = null, mixed $trustedPk = null): ?PinnedPq
    {
        if (is_string($trustedPk) && $trustedPk !== '') {
            return PinnedPq::mint($trustedPk, 'trusted');
        }
        if (!is_string($artifactPk) || $artifactPk === '') {
            return null;
        }
        if (is_string($identity)) {
            $has = false;
            $pin = null;
            if ($pqPins instanceof Obj) {
                $has = $pqPins->has($identity);
                $pin = $has ? $pqPins->get($identity) : null;
            } elseif (is_array($pqPins) && array_key_exists($identity, $pqPins)) {
                $has = true;
                $pin = $pqPins[$identity];
            }
            if ($has) {
                return $pin === $artifactPk ? PinnedPq::mint($artifactPk, 'pin') : null;
            }
        }
        if (is_string($holderPq) && self::holderPqCommitment($artifactPk) === $holderPq) {
            return PinnedPq::mint($artifactPk, 'holder-commitment');
        }
        return null;
    }

    private static function mldsaVerifyPinned(?PinnedPq $pq, string $msg, mixed $sig): bool
    {
        return $pq !== null && self::mldsaVerifyB64u($pq->key, $msg, $sig);
    }

    /** Verify `$p`'s signature(s) under its suite. FAIL-CLOSED. The PQ half verifies ONLY under `$pq` (a PinnedPq), never under `pq_pk` read from `$p`. */
    private static function verifySuite(Obj $p, mixed $holder, string $msg, ?PinnedPq $pq): bool
    {
        [$suite] = self::resolveSuite($p);
        if ($suite === null) {
            return false;
        }
        $sig = $p->get('sig');
        return match ($suite) {
            'ed25519' => self::verifyB64u($holder, $msg, $sig),
            'ml-dsa-65' => self::mldsaVerifyPinned($pq, $msg, $sig),
            'hybrid-ed25519-ml-dsa-65' =>
                self::verifyB64u($holder, $msg, $sig) && self::mldsaVerifyPinned($pq, $msg, $p->get('pq_sig')),
            default => false,
        };
    }

    /**
     * Verify a signature under the ARTIFACT'S OWN `pq_pk`. Only for surfaces whose key is authorised elsewhere (threshold shares,
     * the pq_artifact conformance primitives): it proves nothing about who issued `$p`. The chain and the PCActn leaf never call
     * it; they resolve their key through resolvePqKey.
     */
    private static function verifyLeafSuite(Obj $p, mixed $holder, string $msg): bool
    {
        return self::verifySuite($p, $holder, $msg, self::resolvePqKey(null, $p->get('pq_pk'), null, null, $p->get('pq_pk')));
    }

    // ---- capability chain ---------------------------------------------------------------

    public static function capHash(mixed $c): string
    {
        return self::hashCanonical($c);
    }

    private static function bodyOf(Obj $c): Obj
    {
        $b = Obj::of([
            'issuer' => $c->get('issuer'), 'holder' => $c->get('holder'),
            'caveats' => $c->get('caveats'), 'parent' => $c->get('parent'),
        ]);
        if ($c->has('holder_pq')) {
            $b->set('holder_pq', $c->get('holder_pq'));
        }
        return $b;
    }

    /** F-2 commitment to a holder's PQ key: b64u(sha256("atlas-pca/holder-pq/v1\0" || utf8(pq_pk))). */
    public static function holderPqCommitment(string $pqPk): string
    {
        return self::b64u(hash('sha256', "atlas-pca/holder-pq/v1\0" . $pqPk, true));
    }

    /** allowedSuites policy (absent alg == ed25519). null == no policy; [] refuses everything. */
    private static function suitePolicyError(mixed $alg, string $label, ?array $allowed): ?string
    {
        if ($allowed === null) {
            return null;
        }
        $a = $alg ?? 'ed25519';
        if (is_string($a) && in_array($a, $allowed, true)) {
            return null;
        }
        return $label . ": signature suite '" . (is_string($a) ? $a : 'invalid') . "' is not allowed by this verifier's suite policy";
    }

    /** F-2: a PQ-carrying suite is accepted only under a pq_pk the signer's holder committed to (holder_pq). */
    private static function pqBindingError(mixed $alg, mixed $pqPk, mixed $committed, string $label): ?string
    {
        $a = $alg ?? 'ed25519';
        if (!is_string($a) || !isset(self::SIG_SUITES[$a]) || !self::SIG_SUITES[$a][1]) {
            return null;
        }
        if (!is_string($committed)) {
            return "$label: suite '$a' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)";
        }
        if (!is_string($pqPk) || !hash_equals($committed, self::holderPqCommitment($pqPk))) {
            return "$label: pq_pk does not match the signer's committed holder_pq (F-2)";
        }
        return null;
    }

    /**
     * bodyOf + the suite fields (`alg`, `pq_pk`) bound in for a non-default suite (so a downgrade or ML-DSA
     * key-swap breaks the hop digest), byte-identical to bodyOf for ed25519. Mirrors signableBody in
     * capability.ts.
     * @return array{0:?Obj,1:?string} [body (null => unknown alg, fail-closed), error reason]
     */
    private static function signableHopBody(Obj $c): array
    {
        [$suite, $err] = self::resolveSuite($c);
        if ($suite === null) {
            return [null, $err];
        }
        $body = self::bodyOf($c);
        if ($suite !== 'ed25519') {
            $body->set('alg', $suite);
            [, $needsPk] = self::SIG_SUITES[$suite];
            if ($needsPk && is_string($c->get('pq_pk'))) {
                $body->set('pq_pk', $c->get('pq_pk'));
            }
        }
        return [$body, null];
    }

    private static function checkSig(Obj $c, mixed $signer, string $label, ?PinnedPq $pq = null): string
    {
        // Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
        [$body, $err] = self::signableHopBody($c);
        if ($body === null) {
            return "$label: $err";
        }
        try {
            $digest = self::hashCanonical($body);
        } catch (JsonError) {
            return $label . ': malformed body'; // e.g. a caveat number outside the strict profile, as in the reference
        }
        $bd = $c->get('body_digest');
        $id = $c->get('id');
        if (!is_string($bd) || $digest !== $bd || $id !== $bd) {
            return $label . ': body digest mismatch';
        }
        $d = self::unb64u($bd, 32);
        // Suite-agile hop verification: ed25519 == verifyB64u(signer, msg, sig); hybrid requires BOTH the
        // Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`); pure ml-dsa-65 verifies
        // `sig` under the resolved `$pq` key (never the hop's own pq_pk); signer = expected Ed25519 key.
        if ($d === null || !self::verifySuite($c, $signer, self::CAP_DOMAIN . $d, $pq)) {
            return $label . ': bad signature (not signed by expected key)';
        }
        return '';
    }

    /** True when the chain breaks the caveat caps; reads raw list sizes only, so it runs before any hashing/signature work. */
    public static function caveatLimitExceeded(mixed $chain): bool
    {
        if (!is_array($chain)) {
            return false; // like the reference: a non-list chain has no caveats to count (verifyChain refuses it as empty)
        }
        $total = 0;
        foreach ($chain as $c) {
            $cv = $c instanceof Obj ? $c->get('caveats') : null;
            $n = is_array($cv) ? count($cv) : 0;
            if ($n > self::MAX_CAVEATS_PER_HOP) {
                return true;
            }
            $total += $n;
            if ($total > self::MAX_CAVEATS_PER_CHAIN) {
                return true;
            }
        }
        return false;
    }

    public const ROOT_PQ_PIN_REASON = "hop 0: root suite '%s' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant "
        . "(policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)";

    /**
     * The root hop has no parent holding a holder_pq commitment, so a non-ed25519 root's PQ key must come from a verifier-side
     * authority: the verifier's stored copy of this very grant ($trustedRoot, same content hash) or a pin for root.issuer.
     * Mirrors rootPq in capability.ts. @return array{0:?PinnedPq,1:?string} [key, refusal reason]
     */
    private static function resolveRootPq(Obj $root, mixed $pqPins, ?Obj $trustedRoot): array
    {
        [$suite] = self::resolveSuite($root);
        if ($suite === null || !self::SIG_SUITES[$suite][1]) {
            return [null, null];
        }
        $pk = $root->get('pq_pk');
        $trusted = null;
        if ($trustedRoot !== null && is_string($pk)) {
            try {
                $trusted = self::capHash($trustedRoot) === self::capHash($root) ? $pk : null;
            } catch (\Throwable) {
                $trusted = null;
            }
        }
        $key = self::resolvePqKey($root->get('issuer'), $pk, null, $pqPins, $trusted);
        return $key === null ? [null, sprintf(self::ROOT_PQ_PIN_REASON, $suite)] : [$key, null];
    }

    /**
     * A non-ed25519 (pure-PQ or hybrid) ROOT is accepted only if `$pqPins[root.issuer]` equals the root's `pq_pk`, or `$trustedRoot` is
     * the root itself (the verifier's own stored grant); otherwise it is refused (R4-01).
     * @param Obj|array<string,string>|null $pqPins root issuer (Ed25519 b64u) => PQ public key
     * @return array{0:string,1:bool} [reason, ok]
     */
    public static function verifyChain(mixed $chain, mixed $expectedRootIssuer, bool $haveIssuer, ?array $allowedSuites = null, mixed $pqPins = null, ?Obj $trustedRoot = null): array
    {
        // TOTAL (R6-05): a hostile chain is a verdict, never an exception. ANY JSON value is accepted: a chain that is not
        // a JSON array is the empty chain, as in the reference (Array.isArray(chain) ? chain : []).
        try {
            return self::verifyChainUnchecked(is_array($chain) && array_is_list($chain) ? $chain : [], $expectedRootIssuer, $haveIssuer, $allowedSuites, $pqPins, $trustedRoot);
        } catch (\Throwable $e) {
            return ['malformed capability chain: ' . get_class($e), false];
        }
    }

    /** Mirrors wellTyped in capability.ts (a correctly SIGNED but ill-typed hop is refused like in the reference). */
    private static function hopWellTyped(mixed $c): bool
    {
        if (!($c instanceof Obj)) {
            return false;
        }
        foreach (['id', 'issuer', 'holder', 'body_digest', 'sig'] as $k) {
            if (!is_string($c->get($k))) {
                return false;
            }
        }
        foreach (['alg', 'pq_pk', 'pq_sig', 'holder_pq', 'parent'] as $k) {
            if ($c->has($k) && !is_string($c->get($k))) {
                return false;
            }
        }
        $cv = $c->get('caveats');
        if (!is_array($cv) || !array_is_list($cv)) {
            return false;
        }
        foreach ($cv as $x) {
            if (!($x instanceof Obj) || !is_string($x->get('type'))) {
                return false;
            }
        }
        return true;
    }

    private static function verifyChainUnchecked(array $chain, mixed $expectedRootIssuer, bool $haveIssuer, ?array $allowedSuites, mixed $pqPins, ?Obj $trustedRoot): array
    {
        if (count($chain) === 0) {
            return ['empty chain', false];
        }
        if (count($chain) > self::MAX_CHAIN) { // before any signature work
            return ['chain too long', false];
        }
        if (self::caveatLimitExceeded($chain)) {
            return [self::CAVEAT_LIMIT_REASON, false];
        }
        foreach ($chain as $i => $c) {
            if (!self::hopWellTyped($c)) {
                return ["hop $i: malformed capability", false];
            }
        }
        $root = $chain[0];
        if ($root->has('parent')) {
            return ['hop 0: root must not have a parent', false];
        }
        if ($haveIssuer && $root->get('issuer') !== $expectedRootIssuer) {
            return ['hop 0: root issuer is not the expected principal', false];
        }
        if (($pe = self::suitePolicyError($root->get('alg'), 'hop 0', $allowedSuites)) !== null) {
            return [$pe, false];
        }
        [$rootPq, $rootErr] = self::resolveRootPq($root, $pqPins, $trustedRoot);
        if ($rootErr !== null) {
            return [$rootErr, false];
        }
        if (($e = self::checkSig($root, $root->get('issuer'), 'hop 0', $rootPq)) !== '') {
            return [$e, false];
        }
        for ($i = 1; $i < count($chain); $i++) {
            $parent = $chain[$i - 1];
            $c = $chain[$i];
            $label = "hop $i";
            if ($c->get('parent') !== self::capHash($parent)) {
                return [$label . ': broken parent link', false];
            }
            if ($c->get('issuer') !== $parent->get('holder')) {
                return [$label . ': issuer is not the parent\'s bound holder', false];
            }
            $pe = self::suitePolicyError($c->get('alg'), $label, $allowedSuites)
                ?? self::pqBindingError($c->get('alg'), $c->get('pq_pk'), $parent->get('holder_pq'), $label);
            if ($pe !== null) {
                return [$pe, false];
            }
            if (($e = self::checkSig($c, $parent->get('holder'), $label, self::resolvePqKey($parent->get('holder'), $c->get('pq_pk'), $parent->get('holder_pq')))) !== '') {
                return [$e, false];
            }
            $pc = $parent->get('caveats');
            $cc = $c->get('caveats');
            if (count($cc) < count($pc)) {
                return [$label . ': drops parent caveat(s)', false];
            }
            foreach ($pc as $j => $pcv) {
                if (self::hashCanonical($cc[$j]) !== self::hashCanonical($pcv)) {
                    return ["$label: caveat $j altered or reordered", false];
                }
            }
        }
        return ['', true];
    }

    // ---- wire format v2 -----------------------------------------------------------------

    private static function b(mixed $v, int $len): bool
    {
        return self::unb64u($v, $len) !== null;
    }

    private static function closed(Obj $o, array $allowed): bool
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                return false;
            }
        }
        return true;
    }

    /** null when well-formed, else a short reason. Never throws. */
    public static function validateWire(mixed $p): ?string
    {
        try {
            if (!($p instanceof Obj)) {
                return 'PCActn is not an object';
            }
            foreach ($p->keys() as $k) {
                if (!in_array($k, self::REQUIRED, true) && !in_array($k, self::OPTIONAL, true)) {
                    return "unknown field '$k'";
                }
            }
            foreach (self::REQUIRED as $k) {
                if (!$p->has($k)) {
                    return "missing field '$k'";
                }
            }
            try {
                Json::canonicalizeStrict($p->without('sig', 'threshold', 'pq_sig'));
            } catch (JsonError $e) {
                return $e->getMessage();
            }
            foreach (['ver', 'counter', 'iat', 'exp'] as $k) {
                if (!self::isInt($p->get($k))) {
                    return "'$k' must be a safe integer";
                }
            }
            $aud = $p->get('aud');
            if (!is_string($aud) || $aud === '' || strlen($aud) > self::MAX_AUD_LEN) {
                return "'aud' must be a non-empty string";
            }
            if ($p->has('nonce')) {
                $n = $p->get('nonce');
                if (!is_string($n) || $n === '' || strlen($n) > self::MAX_NONCE_LEN) {
                    return "'nonce' must be a non-empty string";
                }
            }
            // B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite (absent `alg` == classical 64-byte sig).
            $sigErr = self::validateSignatureWire($p);
            if ($sigErr !== null) {
                return $sigErr;
            }
            if (!self::b($p->get('grant_ref'), 32)) {
                return "'grant_ref' is not canonical base64url (32 bytes)";
            }

            $a = $p->get('action');
            if (!($a instanceof Obj)) {
                return "'action' must be an object";
            }
            if (!self::closed($a, ['verb', 'resource', 'params_digest', 'reversibility_class'])) {
                return 'unknown field in action';
            }
            foreach (['verb', 'resource', 'reversibility_class'] as $k) {
                if (!is_string($a->get($k))) {
                    return 'action.verb/resource/reversibility_class must be strings';
                }
            }
            if (!self::b($a->get('params_digest'), 32)) {
                return "'action.params_digest' is not canonical base64url (32 bytes)";
            }

            $pl = $p->get('plan');
            if (!($pl instanceof Obj)) {
                return "'plan' must be an object";
            }
            if (!self::closed($pl, ['root', 'inclusion_proof', 'node_id', 'conditions_digest'])) {
                return 'unknown field in plan';
            }
            if (!self::b($pl->get('root'), 32)) {
                return "'plan.root' is not canonical base64url (32 bytes)";
            }
            if (!is_string($pl->get('node_id'))) {
                return "'plan.node_id' must be a string";
            }
            if ($pl->has('conditions_digest') && !self::b($pl->get('conditions_digest'), 32)) {
                return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)";
            }
            $ip = $pl->get('inclusion_proof');
            if (!($ip instanceof Obj)) {
                return "'plan.inclusion_proof' must be an object";
            }
            if (!self::closed($ip, ['index', 'size', 'path'])) {
                return 'unknown field in plan.inclusion_proof';
            }
            if (!self::isInt($ip->get('index')) || !self::isInt($ip->get('size'))) {
                return "'plan.inclusion_proof.index/size' must be safe integers";
            }
            $path = $ip->get('path');
            if (!is_array($path)) {
                return "'plan.inclusion_proof.path' must be an array";
            }
            foreach ($path as $i => $st) {
                if (!($st instanceof Obj)) {
                    return "proof step $i must be an object";
                }
                if (!self::closed($st, ['side', 'hash'])) {
                    return "unknown field in path[$i]";
                }
                if ($st->get('side') !== 'L' && $st->get('side') !== 'R') {
                    return "proof step $i: side must be 'L' or 'R'";
                }
                if (!self::b($st->get('hash'), 32)) {
                    return "proof step $i: hash is not canonical base64url (32 bytes)";
                }
            }

            $chain = $p->get('cap_chain');
            if (!is_array($chain)) {
                return "'cap_chain' must be an array";
            }
            foreach ($chain as $i => $c) {
                if (!($c instanceof Obj)) {
                    return "cap_chain[$i] must be an object";
                }
                if (!self::closed($c, ['id', 'issuer', 'holder', 'body_digest', 'caveats', 'sig', 'parent', 'alg', 'pq_pk', 'pq_sig', 'holder_pq'])) {
                    return "unknown field in cap_chain[$i]";
                }
                foreach (['id', 'issuer', 'holder', 'body_digest'] as $k) {
                    if (!self::b($c->get($k), 32)) {
                        return "cap_chain[$i].$k is not canonical base64url (32 bytes)";
                    }
                }
                // B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the
                // leaf. Absent `alg` asserts a 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical).
                $hopSigErr = self::validateSignatureWire($c);
                if ($hopSigErr !== null) {
                    return "cap_chain[$i]: $hopSigErr";
                }
                if ($c->has('holder_pq') && !self::b($c->get('holder_pq'), 32)) {
                    return "cap_chain[$i].holder_pq is not canonical base64url (32 bytes)";
                }
                if ($c->has('parent') && !self::b($c->get('parent'), 32)) {
                    return "cap_chain[$i].parent is not canonical base64url (32 bytes)";
                }
                $cv = $c->get('caveats');
                if (!is_array($cv)) {
                    return "cap_chain[$i].caveats must be an array of {type,...} objects";
                }
                foreach ($cv as $x) {
                    if (!($x instanceof Obj) || !is_string($x->get('type'))) {
                        return "cap_chain[$i].caveats must be an array of {type,...} objects";
                    }
                }
            }

            $at = $p->get('attestation');
            if (!($at instanceof Obj) || !self::isInt($at->get('epoch'))) {
                return "'attestation' must be an object with an integer 'epoch'";
            }
            foreach (['quote_digest', 'model_id', 'measurement', 'operator'] as $k) {
                if (!is_string($at->get($k))) {
                    return 'attestation string fields must be strings';
                }
            }
            $pv = $p->get('provenance');
            if (!($pv instanceof Obj) || !is_string($pv->get('causal_hash')) || !self::isNum($pv->get('taint_level'))
                || !is_array($pv->get('trusted_refs'))) {
                return "'provenance' is malformed";
            }
            foreach ($pv->get('trusted_refs') as $r) {
                if (!is_string($r)) {
                    return "'provenance' is malformed";
                }
            }
            $fr = $p->get('freshness');
            if (!($fr instanceof Obj) || !self::isInt($fr->get('epoch')) || !is_string($fr->get('beacon_ref'))
                || !is_string($fr->get('accumulator_witness'))) {
                return "'freshness' is malformed";
            }
            $rc = $p->get('risk_claim');
            if (!($rc instanceof Obj) || !self::isNum($rc->get('r')) || !($rc->get('inputs') instanceof Obj)) {
                return "'risk_claim' is malformed";
            }

            if ($p->has('caution')) {
                $c = $p->get('caution');
                if (!self::isNum($c) || $c->float() < 0 || $c->float() > 1) {
                    return "'caution' must be a number in [0,1]";
                }
            }
            foreach (['rationale_commitment', 'tool_binding'] as $k) {
                if ($p->has($k) && !self::b($p->get($k), 32)) {
                    return "'$k' is not canonical base64url (32 bytes)";
                }
            }
            if ($p->has('progress_step') && !($p->get('progress_step') instanceof Obj)) {
                return "'progress_step' must be an object";
            }
            if ($p->has('prohibition_evidence')) {
                $pe = $p->get('prohibition_evidence');
                if (!($pe instanceof Obj) && !is_array($pe)) {
                    return "'prohibition_evidence' must be an object or array";
                }
            }
            if ($p->has('threshold')) {
                $th = $p->get('threshold');
                if (!($th instanceof Obj) || !is_array($th->get('shares'))) {
                    return "'threshold' must be {shares:[...]}";
                }
                foreach ($th->get('shares') as $i => $s) {
                    if (!($s instanceof Obj) || !is_string($s->get('role'))) {
                        return "threshold.shares[$i] is malformed";
                    }
                    if (!self::b($s->get('publicKey'), 32) || !self::b($s->get('sig'), 64)) {
                        return "threshold.shares[$i] has a non-canonical key/signature";
                    }
                }
            }
            return null;
        } catch (\Throwable $e) {
            return 'malformed: ' . $e->getMessage();
        }
    }

    // ---- PCActn -------------------------------------------------------------------------

    /** SIG_DOMAIN || sha256(strictCanonical(pcactn without `sig` and `threshold`)). */
    public static function thresholdMessage(Obj $p): string
    {
        // `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
        return self::SIG_DOMAIN . self::sha(Json::canonicalizeStrict($p->without('sig', 'threshold', 'pq_sig')));
    }

    /**
     * Verify a signed PCActn supplied as RAW JSON text (strict profile first; a parse failure is a wire failure).
     * @return array{allow:bool, checks:array<string,bool>, reason:string}
     */
    public static function verifyJson(string $text, mixed $grant, int $now, string $audience, ?array $allowedSuites = null): array
    {
        try { // TOTAL (R6-05)
            return self::verifyJsonUnchecked($text, $grant, $now, $audience, $allowedSuites);
        } catch (\Throwable $e) {
            return ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: malformed input (' . get_class($e) . ')'];
        }
    }

    private static function verifyJsonUnchecked(string $text, mixed $grant, int $now, string $audience, ?array $allowedSuites): array
    {
        if (strlen($text) > self::MAX_ARTIFACT_BYTES) { // FIRST: before any parsing (strlen = UTF-8 bytes)
            return ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: ' . self::ARTIFACT_SIZE_REASON];
        }
        try {
            $p = Json::parseStrict($text, true);
        } catch (JsonError $e) {
            return ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: ' . $e->getMessage()];
        }
        return self::verifyPcactnCore($p, $grant, $now, $audience, $allowedSuites);
    }

    /**
     * @return array{allow:bool, checks:array<string,bool>, reason:string}
     * A wire failure is terminal: checks == ['wire' => false].
     */
    public static function verifyPcactnCore(mixed $p, mixed $grant, int $now, string $audience, ?array $allowedSuites = null): array
    {
        try { // TOTAL (R6-05): a malformed input is a verdict, never an exception
            return self::verifyPcactnCoreUnchecked($p, $grant, $now, $audience, $allowedSuites);
        } catch (\Throwable $e) {
            return ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: malformed input (' . get_class($e) . ')'];
        }
    }

    private static function verifyPcactnCoreUnchecked(mixed $p, mixed $grant, int $now, string $audience, ?array $allowedSuites): array
    {
        $wire = self::validateWire($p);
        if ($wire !== null) {
            return ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: ' . $wire];
        }
        $checks = ['wire' => true, 'version' => false, 'audience' => false, 'validity' => false, 'chain' => false,
            'grant_ref_bound' => false, 'plan_inclusion' => false, 'leaf_signature' => false, 'counter' => false];
        $reason = '';
        $fail = function (string $name, string $why) use (&$reason): void {
            if ($reason === '') {
                $reason = $name . ': ' . $why;
            }
        };
        /** @var Obj $p */
        $ver = $p->get('ver')->int();
        $iat = $p->get('iat')->int();
        $exp = $p->get('exp')->int();

        if ($ver === 2) {
            $checks['version'] = true;
        } else {
            $fail('version', "unsupported ver $ver");
        }
        if ($p->get('aud') === $audience) {
            $checks['audience'] = true;
        } else {
            $fail('audience', 'aud does not match this verifier');
        }
        if (!($exp > $iat)) {
            $fail('validity', 'exp must be greater than iat');
        } elseif ($exp - $iat > self::MAX_LIFETIME_MS) {
            $fail('validity', 'lifetime too long');
        } elseif ($iat > $now + self::MAX_SKEW_MS) {
            $fail('validity', 'iat is in the future');
        } elseif ($now > $exp) {
            $fail('validity', 'expired');
        } else {
            $checks['validity'] = true;
        }

        $chain = $p->get('cap_chain');
        try {
            if (count($chain) === 0) {
                $fail('chain', 'empty chain');
            } elseif (count($chain) > self::MAX_CHAIN) {
                $fail('chain', 'chain too long');
            } elseif (self::caveatLimitExceeded($chain)) {
                $fail('chain', self::CAVEAT_LIMIT_REASON); // before any hashing or signature work
            } elseif (self::capHash($chain[0]) !== self::capHash($grant)) {
                $fail('chain', 'chain root is not the grant');
            } else {
                $gi = self::get($grant, 'issuer');
                [$why, $ok] = self::verifyChain($chain, $gi, is_string($gi), $allowedSuites, null, $grant); // chain[0] == grant was checked above
                if ($ok) {
                    $checks['chain'] = true;
                } else {
                    $fail('chain', $why);
                }
            }
        } catch (\Throwable $e) {
            $fail('chain', 'malformed: ' . $e->getMessage());
        }

        // grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
        // ROOT capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed
        // on an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
        $gref = $p->get('grant_ref');
        $rootCap = (is_array($chain) && count($chain) > 0 && $chain[0] instanceof Obj) ? $chain[0] : null;
        $rootId = $rootCap !== null ? $rootCap->get('id') : null;
        if (is_string($gref) && $gref !== '' && is_string($rootId) && $gref === $rootId) {
            $checks['grant_ref_bound'] = true;
        } else {
            $fail('grant_ref_bound', 'grant_ref is not the id of the root capability in cap_chain');
        }

        try {
            $plan = $p->get('plan');
            $cond = $plan->has('conditions_digest') ? $plan->get('conditions_digest') : self::conditionsDigest(null, null);
            $leaf = self::planLeaf($plan->get('node_id'), $p->get('action'), $cond);
            if (self::verifyInclusion($plan->get('root'), $plan->get('inclusion_proof'), $leaf)) {
                $checks['plan_inclusion'] = true;
            } else {
                $fail('plan_inclusion', 'action is not a node of the committed plan');
            }
        } catch (\Throwable $e) {
            $fail('plan_inclusion', 'malformed: ' . $e->getMessage());
        }

        try {
            $leafErr = count($chain) > 0
                ? (self::suitePolicyError($p->get('alg'), 'leaf', $allowedSuites)
                    ?? self::pqBindingError($p->get('alg'), $p->get('pq_pk'), $chain[count($chain) - 1]->get('holder_pq'), 'leaf'))
                : null;
            if ($leafErr !== null) {
                $fail('leaf_signature', $leafErr);
            } elseif (count($chain) > 0
                && self::verifySuite($p, $chain[count($chain) - 1]->get('holder'), self::thresholdMessage($p),
                    self::resolvePqKey($chain[count($chain) - 1]->get('holder'), $p->get('pq_pk'), $chain[count($chain) - 1]->get('holder_pq')))) {
                $checks['leaf_signature'] = true;
            } else {
                $fail('leaf_signature', 'signature does not verify under the leaf holder key');
            }
        } catch (\Throwable $e) {
            $fail('leaf_signature', 'malformed: ' . $e->getMessage());
        }

        if ($p->get('counter')->int() >= 0) {
            $checks['counter'] = true;
        } else {
            $fail('counter', 'not a non-negative safe integer');
        }

        return ['allow' => !in_array(false, $checks, true), 'checks' => $checks, 'reason' => $reason];
    }

    // ---- suite introspection (for suite-aware conformance driving) ----------------------

    public const SIGNERSET_DOMAIN = "atlas-pca/signerset/v1\0";
    public const SHARE_DOMAIN_PREFIX = 'atlas-pca/share/';
    public const SHARE_SUITE_TAG = "\0atlas-pca/share-suite/v1\0";

    /** The signature suites wired into this verifier (ed25519 + the ML-DSA cross-impl suites via OpenSSL FFI). */
    public static function supportedSuites(): array
    {
        return array_keys(self::SIG_SUITES);
    }

    /** True iff a genuine signature verdict under `$alg` is available (ML-DSA suites need OpenSSL >= 3.5). */
    public static function suiteAvailable(string $alg): bool
    {
        if (!isset(self::SIG_SUITES[$alg])) {
            return false;
        }
        [, $needsPk, $needsSig] = self::SIG_SUITES[$alg];
        return ($needsPk || $needsSig) ? Mldsa::available() : true;
    }

    // ---- v2.1 threshold-share binding ----------------------------------------------------

    /**
     * signerSetHash = sha256(SIGNERSET_DOMAIN || canonical(sort_by(role, publicKey)[{publicKey, role}])).
     * Returns the raw 32-byte digest, or null (fail-closed) when the set is malformed.
     */
    public static function signerSetHashRaw(mixed $signerSet): ?string
    {
        if (!is_array($signerSet) || !array_is_list($signerSet)) {
            return null;
        }
        $entries = [];
        foreach ($signerSet as $e) {
            if (!($e instanceof Obj)) {
                return null;
            }
            $role = $e->get('role');
            $pk = $e->get('publicKey');
            if (!is_string($role) || !is_string($pk)) {
                return null; // key / role validity is signerRegistry's job; the hash covers any string set like the reference
            }
            $entries[] = [$role, $pk, $e->get('pq_pk')];
        }
        usort($entries, fn($a, $b) => $a[0] !== $b[0] ? strcmp($a[0], $b[0]) : strcmp($a[1], $b[1]));
        // additive: a registered pq_pk is part of the bound set (ed25519-only sets hash as before)
        $list = array_map(fn($x) => Obj::of(['publicKey' => $x[1], 'role' => $x[0]] + (is_string($x[2]) ? ['pq_pk' => $x[2]] : [])), $entries);
        try {
            return self::sha(self::SIGNERSET_DOMAIN . Json::canonicalizeStrict($list));
        } catch (JsonError) {
            return null; // e.g. a lone surrogate in a role / key: fail-closed like every other malformed set (R6-05)
        }
    }

    /**
     * Verify a threshold share against the v2.1 role/signerSetHash/t-bound share message:
     *   "atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte)
     * where `signerSetHash` and `sha256(thresholdMessage)` are RECOMPUTED here (never trusted from the vector).
     * The pre-v2.1 bare-threshold-message agent share and any cross-signer-set replay therefore fail-closed.
     * FAIL-CLOSED: any missing/malformed field returns false. Corpus shares are Ed25519 (64-byte `sig`,
     * 32-byte `publicKey`); a share carrying a PQ `alg` routes through the same suite seam as the leaf.
     */
    /** Registered PQ public-key lengths of every suite (ml-dsa-65/87, slh-dsa-128f/256s, fn-dsa-512/1024, less-cat1). */
    private const PQ_PK_LENGTHS = [1952, 2592, 32, 64, 897, 1793, 97484];
    private const SIGNER_ROLES = ['agent', 'guardian', 'principal'];

    /**
     * R6-03: validate the WHOLE signer set like the reference (decideThreshold BuildReg): every entry an object with a
     * known role (case-sensitive) and a canonical 32-byte publicKey; a PRESENT pq_pk (JSON null is present) canonical
     * base64url of a registered PQ key length; one key per role; one role per key; a duplicate (role, key) only with the
     * same pq_pk. Returns role => [publicKey, pq_pk|null], or null when the set is malformed.
     * @return array<string, array{0:string, 1:?string}>|null
     */
    private static function signerRegistry(mixed $signerSet): ?array
    {
        if (!is_array($signerSet) || !array_is_list($signerSet)) {
            return null;
        }
        $reg = [];
        foreach ($signerSet as $e) {
            if (!($e instanceof Obj)) {
                return null;
            }
            $role = $e->get('role');
            $pk = $e->get('publicKey');
            if (!is_string($role) || !in_array($role, self::SIGNER_ROLES, true) || self::unb64u($pk, 32) === null) {
                return null;
            }
            $pq = null;
            if ($e->has('pq_pk')) {
                $pq = $e->get('pq_pk');
                $raw = self::unb64u($pq);
                if ($raw === null || !in_array(strlen($raw), self::PQ_PK_LENGTHS, true)) {
                    return null;
                }
            }
            if (isset($reg[$role])) {
                if ($reg[$role][0] !== $pk || $reg[$role][1] !== $pq) {
                    return null; // two keys for one role, or a duplicate (role, key) with a conflicting pq_pk
                }
                continue;
            }
            foreach ($reg as $r) {
                if ($r[0] === $pk) {
                    return null; // one key under two roles
                }
            }
            $reg[$role] = [$pk, $pq];
        }
        return $reg;
    }

    /** t is exactly 1, 2 or 3 (R6-04); an integral JSON number such as 1.0 counts, like the reference's Number. */
    private static function thresholdT(mixed $t): ?int
    {
        if (!($t instanceof Num)) {
            return null;
        }
        if (preg_match('/\A[123](?:\.0+)?\z/D', $t->lexeme) !== 1) {
            return null;
        }
        return (int)$t->lexeme[0];
    }

    public static function verifyThresholdShare(mixed $s): bool
    {
        try {
            if (!($s instanceof Obj)) {
                return false;
            }
            $role = $s->get('role');
            if (!is_string($role) || $role === '') {
                return false;
            }
            $tv = self::thresholdT($s->get('t'));
            if ($tv === null) {
                return false;
            }
            // R6-03: the WHOLE set is validated before the share is looked at.
            $reg = self::signerRegistry($s->get('signer_set'));
            if ($reg === null) {
                return false;
            }
            $ssh = self::signerSetHashRaw($s->get('signer_set'));
            if ($ssh === null) {
                return false;
            }
            $tmsg = self::unb64u($s->get('threshold_message'));
            if ($tmsg === null) {
                return false;
            }
            $share = $s->get('share');
            if (!($share instanceof Obj)) {
                return false;
            }
            if ($share->get('role') !== $role) {
                return false; // share.role is required and must name the verified role
            }
            // R5-A1: the share must be for the ONE key the verifier's signer set registers for `role`; the
            // share's own publicKey / pq_pk never vouch for themselves.
            if (!isset($reg[$role]) || $share->get('publicKey') !== $reg[$role][0]) {
                return false;
            }
            $regPq = $reg[$role][1];
            $alg = $share->has('alg') ? $share->get('alg') : 'ed25519';
            // A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering
            // none has nothing it could equal). The key used is always the registered one.
            if ($share->has('pq_pk') && (!is_string($regPq) || $share->get('pq_pk') !== $regPq)) {
                return false;
            }
            // R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share; an ed25519-only share
            // for it is refused (otherwise an Ed25519 break would still forge the role).
            if ($regPq !== null && $alg === 'ed25519') {
                return false;
            }
            $tag = '';
            if ($alg !== 'ed25519') {
                if (!is_string($regPq)) {
                    return false;
                }
                $pinned = $share->without('pq_pk');
                $pinned->set('pq_pk', $regPq); // verify ONLY under the registered PQ key
                $share = $pinned;
                if (is_string($alg) && isset(self::SIG_SUITES[$alg])) {
                    $tag = self::SHARE_SUITE_TAG . $alg;
                }
            }
            $message = self::SHARE_DOMAIN_PREFIX . $role . "\0" . self::sha($tmsg) . $ssh . chr($tv) . $tag;
            if ($alg === 'ed25519') {
                return self::verifyB64u($share->get('publicKey'), $message, $share->get('sig'));
            }
            return self::verifyLeafSuite($share, $share->get('publicKey'), $message);
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- non-leaf PQ artifacts (transparency / authority surfaces) ------------------------

    /**
     * Verify a `primitives.pq_artifact[]` signature over the raw `$message` bytes under the artifact's suite
     * (`alg`), via the SAME agility seam as the leaf: Ed25519 under `ed_pub`, ML-DSA under `pq_pk`, hybrid
     * requires BOTH. FAIL-CLOSED: unknown suite / malformed input returns false.
     */
    public static function verifyArtifact(mixed $a, string $message): bool
    {
        try {
            if (!($a instanceof Obj)) {
                return false;
            }
            return self::verifyLeafSuite($a, $a->get('ed_pub'), $message);
        } catch (\Throwable) {
            return false;
        }
    }
}
