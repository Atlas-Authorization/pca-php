<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/RatchetAccumulator.php';

/** A ratchet refusal; `errorCode` is invalid_depth | invalid_seed | leaf_out_of_range | leaf_punctured. */
final class RatchetError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * The live ratchet. `leafPubKeys` are public; `covering` is the SECRET co-path: disjoint GGM node seeds
 * ("level:index" => {level, nodeIndex, seed}) whose subtrees are exactly the leaves that can still sign.
 */
final class RatchetState
{
    /**
     * @param list<string> $leafPubKeys
     * @param array<string,array{level:int,nodeIndex:int,seed:string}> $covering
     */
    public function __construct(
        public readonly int $depth,
        public readonly int $leafCount,
        public readonly string $rootCommitment,
        public readonly array $leafPubKeys,
        public readonly array $covering,
    ) {
    }

    public function __debugInfo(): array
    {
        return ['depth' => $this->depth, 'rootCommitment' => $this->rootCommitment]; // never print the seeds
    }
}

/** Atomic first-claim store keyed by leaf nullifier (share one across a verifier fleet). */
interface SpentLeafStore
{
    /** @return array{first:true}|array{first:false,record:string} */
    public function claim(string $nullifier, string $record): array;
}

/** In-process {@see SpentLeafStore}. */
final class MemorySpentLeafStore implements SpentLeafStore
{
    /** @var array<string,string> */
    private array $seen = [];

    public function claim(string $nullifier, string $record): array
    {
        $k = 'k' . $nullifier;
        if (isset($this->seen[$k])) {
            return ['first' => false, 'record' => $this->seen[$k]];
        }
        $this->seen[$k] = $record;
        return ['first' => true];
    }
}

/**
 * Carry-forward quantizer: the running total of emitted units is always ceil(sum(true risk) * 1000), never below the true sum and
 * over by less than one unit in total. One instance per budget stream.
 */
final class RiskQuantizer
{
    private RatchetBigint $nano;
    private RatchetBigint $emitted;

    public function __construct()
    {
        $this->nano = RatchetBigint::of(0);
        $this->emitted = RatchetBigint::of(0);
    }

    public function next(mixed $r): RatchetBigint
    {
        $f = is_bool($r) ? null : Js::num($r);
        if ($f === null || !is_finite($f) || $f < 0) {
            throw new AccumulatorError('invalid_value', 'risk must be a finite number >= 0');
        }
        // r * SCALE in millionths of a unit, rounded UP so the total can only over-approximate.
        $nano = $this->nano->plus(RatchetBigint::fromFloat(ceil($f * Ratchet::RISK_SCALE * 1e6 - 1e-3)));
        $total = $nano->plus(RatchetBigint::of(999999))->dropDigits(6);
        $out = $total->minus($this->emitted);
        $this->nano = $nano;
        $this->emitted = $total;
        return $out;
    }

    public function totalUnits(): RatchetBigint
    {
        return $this->emitted;
    }
}

/**
 * The PCA Capability Ratchet: puncturable forward-secure capability keys (a GGM tree of one-time Ed25519 leaf keys under a Merkle
 * root commitment; signing a leaf punctures it, so "already spent" is "the key no longer exists"), the verifier-side spent-leaf and
 * attested-risk bindings, and the adapters from a PCActn counter and a risk policy. The homomorphic risk accumulator is
 * {@see RatchetAccumulator}.
 *
 * Leaf indices and counters are ints (an integral float / Num is accepted); a signature is the assoc array / Obj
 * {edSig, leafPubKey, merklePath, nullifier}.
 */
final class Ratchet
{
    public const MAX_RATCHET_DEPTH = 20;
    public const RISK_SCALE = 1000;

    private const PRG_DOMAIN = 'atlas-pca-ratchet/ggm-prg/v1';
    private const LEAFKEY_DOMAIN = 'atlas-pca-ratchet/ggm-leafkey/v1';
    private const ROOT_DOMAIN = 'atlas-pca-ratchet/ggm-root/v1';
    private const NULLIFIER_DOMAIN = "atlas-pca-ratchet/nullifier/v1\0";
    private const SIG_DOMAIN = "atlas-pca-ratchet/leaf-sig/v1\0";
    private const ATTEST_DOMAIN = "atlas-pca-ratchet/risk-attestation/v1\0";

    // ---- JS number helpers ---------------------------------------------------------------------

    private static function number(mixed $x): ?float
    {
        return is_bool($x) ? null : Js::num($x);
    }

    private static function isInteger(mixed $x): bool
    {
        $f = self::number($x);
        return $f !== null && is_finite($f) && floor($f) === $f;
    }

    private static function isSafeInteger(mixed $x): bool
    {
        return self::isInteger($x) && abs(self::number($x)) <= 9007199254740991.0;
    }

    private static function isNegZero(mixed $x): bool
    {
        $f = self::number($x);
        return $f === 0.0 && fdiv(1.0, $f) < 0;
    }

    /** JS BigInt(x) reduced to 8 big-endian bytes (two's complement), for the index forms the reference accepts. */
    private static function u64(mixed $x): string
    {
        if (is_bool($x)) {
            $n = new RatchetBigint($x ? '1' : '0');
        } elseif ($x instanceof RatchetBigint) {
            $n = $x;
        } elseif (is_string($x)) {
            $s = trim($x);
            if ($s === '') {
                $n = new RatchetBigint('0');
            } elseif (preg_match('/\A([+-]?)([0-9]+)\z/', $s, $m) === 1) {
                $digits = ltrim($m[2], '0') ?: '0';
                $n = new RatchetBigint(($m[1] === '-' && $digits !== '0' ? '-' : '') . $digits);
            } else {
                throw new \InvalidArgumentException('Cannot convert the string to a BigInt');
            }
        } else {
            $f = self::number($x);
            if ($f === null) {
                throw new \TypeError('Cannot convert the value to a BigInt');
            }
            if (!is_finite($f) || floor($f) !== $f) {
                throw new \RangeError('The number cannot be converted to a BigInt because it is not an integer');
            }
            $m = RatchetBigint::fromFloat(abs($f));
            $n = $f < 0 ? new RatchetBigint('-' . $m->decimal) : $m;
        }
        $b = str_pad(substr($n->toLe(), 0, 8), 8, "\0");
        if ($n->isNegative()) {
            $carry = 1;
            for ($i = 0; $i < 8; $i++) {
                $v = ((~ord($b[$i])) & 255) + $carry;
                $b[$i] = chr($v & 255);
                $carry = $v >> 8;
            }
        }
        return strrev($b);
    }

    // ---- GGM puncturable PRF tree -------------------------------------------------------------------

    private static function prg(string $seed, string $bit): string
    {
        return hash_hmac('sha256', self::PRG_DOMAIN . $bit, $seed, true);
    }

    private static function leafSigningSeed(string $leafSeed): string
    {
        return hash_hmac('sha256', self::LEAFKEY_DOMAIN, $leafSeed, true);
    }

    private static function leafPublicKey(string $leafSeed): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::leafSigningSeed($leafSeed))));
    }

    private static function coverKey(int $level, int $nodeIndex): string
    {
        return $level . ':' . $nodeIndex;
    }

    /** Does the subtree of node (level, nodeIndex) contain `$leaf` (a JS number, so a fraction still lands in a subtree)? */
    private static function covers(int $level, int $nodeIndex, float $leaf, int $depth): bool
    {
        return floor($leaf / (2 ** ($depth - $level))) == $nodeIndex;
    }

    private static function descendBit(int $level, int $leaf, int $depth): int
    {
        return intdiv($leaf, 1 << ($depth - $level - 1)) % 2;
    }

    private static function deriveLeafSeed(array $node, int $leaf, int $depth): string
    {
        $seed = $node['seed'];
        for ($level = $node['level']; $level < $depth; $level++) {
            $seed = self::prg($seed, self::descendBit($level, $leaf, $depth) === 0 ? "\x00" : "\x01");
        }
        return $seed;
    }

    /** The off-path siblings covering every leaf under `$node` except `$leaf`; the on-path seeds are dropped. */
    private static function punctureSiblings(array $node, int $leaf, int $depth): array
    {
        $out = [];
        $seed = $node['seed'];
        $nodeIndex = $node['nodeIndex'];
        for ($level = $node['level']; $level < $depth; $level++) {
            $bit = self::descendBit($level, $leaf, $depth);
            $left = self::prg($seed, "\x00");
            $right = self::prg($seed, "\x01");
            $base = $nodeIndex * 2;
            $out[] = ['level' => $level + 1, 'nodeIndex' => $base + (1 - $bit), 'seed' => $bit === 0 ? $right : $left];
            $seed = $bit === 0 ? $left : $right;
            $nodeIndex = $base + $bit;
        }
        return $out;
    }

    private static function allLeafPublicKeys(string $root, int $depth): array
    {
        $out = [];
        $recurse = function (string $seed, int $level) use (&$recurse, &$out, $depth): void {
            if ($level === $depth) {
                $out[] = self::leafPublicKey($seed);
                return;
            }
            $recurse(self::prg($seed, "\x00"), $level + 1);
            $recurse(self::prg($seed, "\x01"), $level + 1);
        };
        $recurse($root, 0);
        return $out;
    }

    // ---- Merkle proof (RFC 6962 shape, the core's leaf / node hashing) -----------------------------------

    private static function leafHash(string $pk): string
    {
        return hash('sha256', "\x00" . Json::canonicalizeNative($pk), true);
    }

    private static function nodeHash(string $l, string $r): string
    {
        return hash('sha256', "\x01" . $l . $r, true);
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

    private static function prove(array $hs, int $idx, array &$path): void
    {
        if (count($hs) === 1) {
            return;
        }
        $k = self::split(count($hs));
        if ($idx < $k) {
            self::prove(array_slice($hs, 0, $k), $idx, $path);
            $path[] = ['side' => 'R', 'hash' => Pca::b64u(self::build(array_slice($hs, $k)))];
        } else {
            self::prove(array_slice($hs, $k), $idx - $k, $path);
            $path[] = ['side' => 'L', 'hash' => Pca::b64u(self::build(array_slice($hs, 0, $k)))];
        }
    }

    private static function merkleProof(array $leaves, int $index): array
    {
        $path = [];
        self::prove(array_map(self::leafHash(...), $leaves), $index, $path);
        return ['index' => $index, 'size' => count($leaves), 'path' => $path];
    }

    // ---- Ed25519 verify (strict, prime-order keys and R as the core's verifier) ----------------------------

    private static function primeOrder(string $p): bool
    {
        try {
            return strlen(sodium_crypto_sign_ed25519_pk_to_curve25519($p)) === 32;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function verifyB64u(mixed $pub, string $msg, mixed $sig): bool
    {
        $pk = Pca::unb64u($pub, 32);
        $sg = Pca::unb64u($sig, 64);
        if ($pk === null || $sg === null || !self::primeOrder($pk) || !self::primeOrder(substr($sg, 0, 32))) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sg, $msg, $pk);
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- ratchet ---------------------------------------------------------------------------------------------

    /** The per-leaf nullifier a verifier records to detect leaf reuse: b64u(sha256(domain || len32(root) || root || index64)). */
    public static function leafNullifier(string $rootCommitment, mixed $leafIndex): string
    {
        return Pca::b64u(hash('sha256', self::NULLIFIER_DOMAIN . pack('N', strlen($rootCommitment)) . $rootCommitment . self::u64($leafIndex), true));
    }

    private static function leafSigMessage(mixed $leafIndex, string $message): string
    {
        return self::SIG_DOMAIN . self::u64($leafIndex) . $message;
    }

    /**
     * Build a ratchet from a root `$seed` (at least 32 bytes) and tree `$depth` in [1, 20]: the public root commitment (a Merkle
     * root over all 2^depth leaf public keys) and the live state.
     *
     * @return array{rootCommitment:string,state:RatchetState}
     */
    public static function deriveRatchetRoot(mixed $seed, mixed $depth): array
    {
        if (!self::isInteger($depth) || self::number($depth) < 1 || self::number($depth) > self::MAX_RATCHET_DEPTH) {
            throw new RatchetError('invalid_depth', 'depth must be an integer in [1, ' . self::MAX_RATCHET_DEPTH . ']');
        }
        if (!is_string($seed) || strlen($seed) < 32) {
            throw new RatchetError('invalid_seed', 'seed must be at least 32 bytes');
        }
        $d = (int) self::number($depth);
        $root = hash_hmac('sha256', self::ROOT_DOMAIN, $seed, true);
        $pubs = self::allLeafPublicKeys($root, $d);
        $commitment = Pca::merkleRoot($pubs);
        return [
            'rootCommitment' => $commitment,
            'state' => new RatchetState($d, 1 << $d, $commitment, $pubs, [self::coverKey(0, 0) => ['level' => 0, 'nodeIndex' => 0, 'seed' => $root]]),
        ];
    }

    private static function findCovering(RatchetState $state, float $leaf): ?array
    {
        foreach ($state->covering as $node) {
            if (self::covers($node['level'], $node['nodeIndex'], $leaf, $state->depth)) {
                return $node;
            }
        }
        return null;
    }

    /**
     * Sign `$message` at leaf `$leafIndex`, then puncture that leaf: the signature and a new state with the leaf's key permanently
     * dropped. Throws {@see RatchetError} for an out-of-range or already punctured leaf.
     *
     * @return array{signature:array,newState:RatchetState}
     */
    public static function signAtLeaf(RatchetState $state, mixed $leafIndex, string $message): array
    {
        if (!self::isInteger($leafIndex) || self::number($leafIndex) < 0 || self::number($leafIndex) >= $state->leafCount) {
            throw new RatchetError('leaf_out_of_range', 'the leaf is out of range [0, ' . $state->leafCount . ')');
        }
        $leaf = (int) self::number($leafIndex);
        $node = self::findCovering($state, (float) $leaf);
        if ($node === null) {
            throw new RatchetError('leaf_punctured', "leaf $leaf is already punctured (spent) and cannot sign");
        }
        $leafSeed = self::deriveLeafSeed($node, $leaf, $state->depth);
        $kp = sodium_crypto_sign_seed_keypair(self::leafSigningSeed($leafSeed));
        $edSig = Pca::b64u(sodium_crypto_sign_detached(self::leafSigMessage($leaf, $message), sodium_crypto_sign_secretkey($kp)));
        $covering = $state->covering;
        unset($covering[self::coverKey($node['level'], $node['nodeIndex'])]);
        foreach (self::punctureSiblings($node, $leaf, $state->depth) as $sib) {
            $covering[self::coverKey($sib['level'], $sib['nodeIndex'])] = $sib;
        }
        return [
            'signature' => [
                'edSig' => $edSig,
                'leafPubKey' => Pca::b64u(sodium_crypto_sign_publickey($kp)),
                'merklePath' => self::merkleProof($state->leafPubKeys, $leaf),
                'nullifier' => self::leafNullifier($state->rootCommitment, $leaf),
            ],
            'newState' => new RatchetState($state->depth, $state->leafCount, $state->rootCommitment, $state->leafPubKeys, $covering),
        ];
    }

    /**
     * Verify a ratchet signature offline against the root commitment, with no shared state. Never throws; any malformed input is
     * false.
     */
    public static function verifyLeafSignature(mixed $rootCommitment, mixed $leafIndex, string $message, mixed $signature): bool
    {
        try {
            if (!is_string($rootCommitment) || !Js::isObj($signature)) {
                return false;
            }
            $nullifier = Js::opt($signature, 'nullifier');
            if (!is_string($nullifier) || $nullifier !== self::leafNullifier($rootCommitment, $leafIndex)) {
                return false;
            }
            $edSig = Js::opt($signature, 'edSig');
            $pk = Js::opt($signature, 'leafPubKey');
            $path = Js::opt($signature, 'merklePath');
            if (!is_string($edSig) || !is_string($pk) || !Js::isObj($path)) {
                return false;
            }
            $index = Js::opt($path, 'index');
            if (!Js::isNum($index) || !Js::isNum($leafIndex) || Js::num($index) !== Js::num($leafIndex)) {
                return false;
            }
            // every proof here is SHA-256: an explicit other suite is refused, absent means SHA-256
            if (Js::has($path, 'hash_suite') && Js::opt($path, 'hash_suite') !== 'sha256') {
                return false;
            }
            if (!self::verifyB64u($pk, self::leafSigMessage($leafIndex, $message), $edSig)) {
                return false;
            }
            return Pca::verifyInclusion($rootCommitment, Sign::n($path), $pk);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Indices of the leaves that can still sign, ascending. */
    public static function availableLeaves(RatchetState $state): array
    {
        $out = [];
        foreach ($state->covering as $node) {
            $span = 1 << ($state->depth - $node['level']);
            $base = $node['nodeIndex'] * $span;
            for ($i = 0; $i < $span; $i++) {
                $out[] = $base + $i;
            }
        }
        sort($out);
        return $out;
    }

    /** Whether leaf `$leafIndex` can still sign (a non-number is never available). */
    public static function isLeafAvailable(RatchetState $state, mixed $leafIndex): bool
    {
        $f = self::number($leafIndex);
        return $f !== null && self::findCovering($state, $f) !== null;
    }

    // ---- verifier-side one-time use ------------------------------------------------------------------------

    /**
     * Verify a leaf signature AND enforce one-time use: the first valid signature at a leaf is accepted and its message digest
     * recorded; a later one is refused as `replay` (same message) or `equivocation` (different message, the evidence of a holder
     * that kept an old state). Fail closed: a store that throws denies.
     *
     * @return array<string,mixed> {ok:true} | {ok:false, reason: invalid|replay|equivocation|store-error, ...}
     */
    public static function verifyLeafSignatureOnce(mixed $rootCommitment, mixed $leafIndex, string $message, mixed $signature, SpentLeafStore $store): array
    {
        if (!self::verifyLeafSignature($rootCommitment, $leafIndex, $message, $signature)) {
            return ['ok' => false, 'reason' => 'invalid'];
        }
        $nullifier = self::leafNullifier($rootCommitment, $leafIndex);
        $mine = Pca::b64u(hash('sha256', $message, true)) . '@' . (string) (int) self::number($leafIndex);
        try {
            $r = $store->claim($nullifier, $mine);
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'store-error'];
        }
        if (($r['first'] ?? null) === true) {
            return ['ok' => true];
        }
        if (!is_string($r['record'] ?? null)) {
            return ['ok' => false, 'reason' => 'store-error'];
        }
        if ($r['record'] === $mine) {
            return ['ok' => false, 'reason' => 'replay', 'nullifier' => $nullifier];
        }
        return ['ok' => false, 'reason' => 'equivocation', 'nullifier' => $nullifier, 'firstMessageDigest' => $r['record'], 'secondMessageDigest' => $mine];
    }

    // ---- action-bound risk commitments ------------------------------------------------------------------------

    private static function attestMessage(string $actionDigest, string $commitment): string
    {
        return self::ATTEST_DOMAIN . pack('N', strlen($actionDigest)) . $actionDigest . pack('N', strlen($commitment)) . $commitment;
    }

    /**
     * RISK AUTHORITY side: commit to the risk computed for `$actionDigest`, prove the range, and sign (actionDigest, commitment)
     * with the authority's 32-byte Ed25519 seed. Hand `blinding` privately to the prover; publish the rest.
     *
     * @return array{commitment:string,blinding:RatchetBigint,rangeProof:array,attestation:array{actionDigest:string,sig:string}}
     */
    public static function issueRiskCommitment(mixed $risk, string $actionDigest, string $authoritySecretKey): array
    {
        $c = RatchetAccumulator::commitRisk($risk);
        $rangeProof = RatchetAccumulator::proveRiskRange($risk, $c['blinding']);
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($authoritySecretKey));
        $sig = Pca::b64u(sodium_crypto_sign_detached(self::attestMessage($actionDigest, $c['commitment']), $sk));
        return ['commitment' => $c['commitment'], 'blinding' => $c['blinding'], 'rangeProof' => $rangeProof, 'attestation' => ['actionDigest' => $actionDigest, 'sig' => $sig]];
    }

    /** Verify one attestation against the risk authority's public key (b64u). Never throws. */
    public static function verifyRiskAttestation(mixed $commitment, mixed $attestation, mixed $authorityPublicKey): bool
    {
        try {
            if (!Js::isObj($attestation) || !is_string($commitment)) {
                return false;
            }
            $digest = Js::opt($attestation, 'actionDigest');
            $sig = Js::opt($attestation, 'sig');
            if (!is_string($digest) || !is_string($sig)) {
                return false;
            }
            return self::verifyB64u($authorityPublicKey, self::attestMessage($digest, $commitment), $sig);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Sound end-to-end budget check over ATTESTED commitments: for the verifier's own list of action digests (in order) every item
     * carries a valid authority attestation for exactly that digest and commitment, then the bounded budget must hold. Never throws.
     */
    public static function verifyAttestedBudget(mixed $items, mixed $expectedActionDigests, mixed $authorityPublicKey, mixed $bMax, mixed $budgetProof): bool
    {
        try {
            if (!is_array($items) || !array_is_list($items) || !is_array($expectedActionDigests) || !array_is_list($expectedActionDigests)
                || count($items) !== count($expectedActionDigests)) {
                return false;
            }
            $commitments = [];
            $proofs = [];
            foreach ($items as $i => $it) {
                if (!Js::isObj($it)) {
                    return false;
                }
                $att = Js::opt($it, 'attestation');
                $digest = Js::opt($att, 'actionDigest');
                if (!is_string($digest) || $digest !== $expectedActionDigests[$i]) {
                    return false;
                }
                if (!self::verifyRiskAttestation(Js::opt($it, 'commitment'), $att, $authorityPublicKey)) {
                    return false;
                }
                $commitments[] = Js::opt($it, 'commitment');
                $proofs[] = Js::opt($it, 'rangeProof');
            }
            return RatchetAccumulator::verifyBoundedBudget($commitments, $proofs, $bMax, $budgetProof);
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- adapters: PCActn counter / risk policy -------------------------------------------------------------------

    /** Map a PCActn spend-once counter to its ratchet leaf index (spending counter c signs and punctures leaf c). */
    public static function counterToLeafIndex(mixed $counter, mixed $depth): int
    {
        if (!self::isInteger($depth) || self::number($depth) < 1 || self::number($depth) > self::MAX_RATCHET_DEPTH) {
            throw new RatchetError('invalid_depth', 'depth must be an integer in [1, ' . self::MAX_RATCHET_DEPTH . ']');
        }
        if (!self::isSafeInteger($counter) || self::isNegZero($counter) || self::number($counter) < 0) {
            throw new RatchetError('leaf_out_of_range', 'counter must be a non-negative safe integer');
        }
        $d = (int) self::number($depth);
        if (self::number($counter) >= (float) (1 << $d)) {
            throw new RatchetError('leaf_out_of_range', 'counter exceeds the ratchet capacity 2^' . $d);
        }
        return (int) self::number($counter);
    }

    /** The inverse of {@see counterToLeafIndex}: a leaf index is the spend-once counter it realizes. */
    public static function leafIndexToCounter(mixed $leafIndex): int
    {
        if (!self::isSafeInteger($leafIndex) || self::isNegZero($leafIndex) || self::number($leafIndex) < 0) {
            throw new RatchetError('leaf_out_of_range', 'leafIndex must be a non-negative safe integer');
        }
        return (int) self::number($leafIndex);
    }

    /** The ratchet leaf index for a PCActn (an Obj / assoc array with `counter`). */
    public static function leafIndexForAction(mixed $actn, mixed $depth): int
    {
        if (!Js::isObj($actn)) {
            throw new \TypeError('leafIndexForAction: the action must be an object');
        }
        return self::counterToLeafIndex(Js::opt($actn, 'counter'), $depth);
    }

    private static function jsRound(float $v): float
    {
        $f = floor($v);
        return $v - $f >= 0.5 ? $f + 1 : $f;
    }

    /**
     * Quantize a core risk score (any finite r >= 0) to integer accumulator units, rounding UP (a nonzero risk is never 0 units; a
     * sum of quantized risks never under-counts); a value within float noise of an exact unit keeps that unit.
     */
    public static function riskToUnits(mixed $r): RatchetBigint
    {
        $f = self::number($r);
        if ($f === null || !is_finite($f) || $f < 0) {
            throw new AccumulatorError('invalid_value', 'risk must be a finite number >= 0');
        }
        $v = $f * self::RISK_SCALE;
        $nearest = self::jsRound($v);
        if (abs($v - $nearest) <= 1e-9 * max(1.0, $v)) {
            return RatchetBigint::fromFloat($nearest);
        }
        return RatchetBigint::fromFloat(ceil($v));
    }

    /**
     * The accumulator's budget ceiling in integer units from a risk policy ({bMax, kappa}): the core safety bound bMax / kappa,
     * quantized. A non-numeric kappa is not positive (bound 0); a non-numeric bMax is refused.
     */
    public static function budgetCeilingUnits(mixed $policy): RatchetBigint
    {
        if (!Js::isObj($policy)) {
            throw new \TypeError('budgetCeilingUnits: the policy must be an object');
        }
        $kappa = self::number(Js::opt($policy, 'kappa'));
        $bound = 0.0;
        if ($kappa !== null && $kappa > 0) {
            $m = Js::opt($policy, 'bMax');
            $bMax = $m === null ? (Js::has($policy, 'bMax') ? 0.0 : NAN) : (self::number($m) ?? NAN);
            $bound = is_nan($bMax) ? NAN : max(0.0, $bMax) / $kappa;
        }
        if (!is_finite($bound) || $bound < 0) {
            throw new AccumulatorError('invalid_value', 'safety bound (bMax/kappa) must be finite and >= 0');
        }
        return RatchetBigint::fromFloat(floor($bound * self::RISK_SCALE));
    }
}
