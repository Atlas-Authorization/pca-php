<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Oblivious transfer, the root of the no-dealer offline phase. (1) A maliciously secure Chou-Orlandi base OT over the Ed25519
 * subgroup: the sender proves knowledge of its discrete log with a Schnorr NIZK, every received point is validated, and the core runs
 * as a random OT so there is no selective-failure surface. (2) IKNP OT extension with the KOS consistency check (MpcOtChannel; a
 * deviating receiver is caught and the protocol aborts). Both roles run in one process; the functions take both parties' inputs and
 * return the receiver's outputs plus an inspectable transcript. Byte strings are PHP strings.
 *
 * Records: a binding is ['sessionId' => string, 'senderIndex' => int, 'receiverIndex' => int, 'round' => string]; message pairs and
 * pad pairs are lists of [string, string]; a tamper (TEST-ONLY, null = honest) is an array with optional callables
 * 'tamperS' (point -> point), 'tamperProof' (proof -> proof), 'tamperR' (list<point> -> list<point>), 'tamperCiphertext'
 * (list of [ct0, ct1] -> same).
 */
final class MpcOt
{
    /** IKNP security parameter (number of base OTs / width of the selector s). */
    public const KAPPA = 128;
    /** KOS statistical parameter: extra random check rows beyond the kappa that mask the revealed combination. */
    public const SSEC = 128;
    public const SEED_BYTES = 16;

    public static function u32(int $x): string
    {
        return pack('N', $x & 0xFFFFFFFF);
    }

    public static function xorBytes(string $a, string $b): string
    {
        if (strlen($b) < strlen($a)) {
            throw new \InvalidArgumentException('xorBytes: second operand shorter than the first');
        }
        return $a ^ substr($b, 0, strlen($a));
    }

    /** Canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input). */
    public static function bindingBytes(array $b): string
    {
        $sid = $b['sessionId'] ?? null;
        if (!is_string($sid) || strlen($sid) < 8 || strlen($sid) > 64) {
            throw new \InvalidArgumentException('base-OT binding: sessionId must be 8..64 bytes');
        }
        if ($b['senderIndex'] < 0 || $b['senderIndex'] > 0xffffffff) {
            throw new \InvalidArgumentException('base-OT binding: senderIndex must be a uint32');
        }
        if ($b['receiverIndex'] < 0 || $b['receiverIndex'] > 0xffffffff) {
            throw new \InvalidArgumentException('base-OT binding: receiverIndex must be a uint32');
        }
        if ($b['senderIndex'] === $b['receiverIndex']) {
            throw new \InvalidArgumentException('base-OT binding: sender and receiver must be different parties');
        }
        $round = $b['round'];
        if (strlen($round) === 0 || strlen($round) > 64) {
            throw new \InvalidArgumentException('base-OT binding: round label must be 1..64 bytes');
        }
        return 'atlas-pca-mpc/base-ot-binding' . self::u32(strlen($sid)) . $sid . self::u32($b['senderIndex']) . self::u32($b['receiverIndex'])
            . self::u32(strlen($round)) . $round;
    }

    /** A fresh binding for an in-process OT: a random 16-byte session id from $rng. */
    public static function randomBinding(MpcOtRandom $rng, string $round, int $senderIndex = 0, int $receiverIndex = 1): array
    {
        return ['sessionId' => $rng->bytes(16), 'senderIndex' => $senderIndex, 'receiverIndex' => $receiverIndex, 'round' => $round];
    }

    /** Hash of the whole base-OT transcript: binding, S and every receiver point, in order. @param list<array> $R */
    public static function baseOtTranscriptHash(array $binding, array $S, array $R): string
    {
        $m = 'atlas-pca-mpc/base-ot-transcript' . self::bindingBytes($binding) . MpcEc::encodePoint($S) . self::u32(count($R));
        foreach ($R as $r) {
            $m .= MpcEc::encodePoint($r);
        }
        return hash('sha256', $m, true);
    }

    /** H("ot-kdf" || H(transcript) || index || R_i || P), SEED_BYTES bytes. */
    public static function baseOtKdf(string $transcriptHash, int $index, array $Ri, array $p): string
    {
        return substr(hash('sha256', 'atlas-pca-mpc/ot-kdf' . $transcriptHash . self::u32($index) . MpcEc::encodePoint($Ri) . MpcEc::encodePoint($p), true), 0, self::SEED_BYTES);
    }

    /**
     * The KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column of u.
     *
     * @param list<\GMP> $u @param ?list<string> $colBytesList @return list<int>
     */
    public static function kosChiWords(string $binding, int $round, array $u, int $mExt, ?array $colBytesList = null): array
    {
        $colBytes = intdiv($mExt + 7, 8);
        $m = 'atlas-pca-mpc/ot-kos' . self::u32(strlen($binding)) . $binding . self::u32($round) . self::u32($mExt) . self::u32(count($u));
        if ($colBytesList !== null) {
            $m .= implode('', $colBytesList);
        } else {
            foreach ($u as $col) {
                $m .= MpcOtx::bigToBytes($col, $colBytes);
            }
        }
        return MpcOtx::leWords(MpcShake256::hash($m, $mExt * 16), 0, $mExt * 4);
    }

    /** @param list<\GMP> $u @return list<\GMP> */
    public static function kosChallenges(string $binding, int $round, array $u, int $mExt): array
    {
        $w = self::kosChiWords($binding, $round, $u, $mExt);
        $chi = [];
        for ($j = 0; $j < $mExt; $j++) {
            $chi[] = MpcOtx::gfToBig($w, 4 * $j);
        }
        return $chi;
    }

    private static function otCommit(int $i, int $b, string $msg, string $pad): string
    {
        return hash('sha256', 'atlas-pca-mpc/ot-msg-commit' . self::u32($i) . chr($b & 1) . $msg . $pad, true);
    }

    /**
     * The random base OT: validated points and the two RO pads per index.
     *
     * @param list<int> $choices
     * @return array{S:array,proof:array,R:list<array>,senderPads:list<array{0:string,1:string}>,recvPads:list<string>}
     */
    public static function malBaseRandomOT(array $choices, ?MpcOtRandom $rng = null, ?array $tamper = null, ?array $binding = null): array
    {
        $rng ??= MpcOtRandom::secure();
        $binding ??= self::randomBinding($rng, 'base-ot');
        $setup = self::malBaseOtSenderSetup($rng, $binding);
        $S = isset($tamper['tamperS']) ? ($tamper['tamperS'])($setup['S']) : $setup['S'];
        $proof = isset($tamper['tamperProof']) ? ($tamper['tamperProof'])($setup['proof']) : $setup['proof'];
        $rr = self::malBaseOtReceiverRespond($S, $proof, $choices, $rng, $binding);
        $R = isset($tamper['tamperR']) ? ($tamper['tamperR'])($rr['R']) : $rr['R'];
        $pads = self::malBaseOtSenderDerive($setup['y'], $setup['T'], $R, $S, $binding);
        return ['S' => $S, 'proof' => $proof, 'R' => $R, 'senderPads' => $pads, 'recvPads' => $rr['recvPads']];
    }

    /** @return array{y:\GMP,T:array,S:array,proof:array} */
    public static function malBaseOtSenderSetup(MpcOtRandom $rng, array $binding): array
    {
        $ctx = self::bindingBytes($binding);
        $y = $rng->scalar();
        $S = MpcEc::mulBase($y);
        $T = MpcEc::mul($y, $S);
        $proof = MpcEc::schnorrProve($y, $S, static fn(): \GMP => $rng->scalar(), $ctx);
        return ['y' => $y, 'T' => $T, 'S' => $S, 'proof' => $proof];
    }

    /** @param list<int> $choices @return array{R:list<array>,recvPads:list<string>} */
    public static function malBaseOtReceiverRespond(array $S, array $proof, array $choices, MpcOtRandom $rng, array $binding): array
    {
        $ctx = self::bindingBytes($binding);
        MpcEc::assertInSubgroup($S, 'base-OT S (received by receiver)');
        if (!MpcEc::schnorrVerify($S, $proof, $ctx)) {
            throw new MpcBaseOtAbort('base OT: sender Schnorr proof-of-knowledge of S=y*B failed; aborting');
        }
        $R = [];
        $xs = [];
        foreach ($choices as $i => $c) {
            $x = $rng->scalar();
            $R[$i] = ($c & 1) === 1 ? MpcEc::addPoints(MpcEc::mulBase($x), $S) : MpcEc::mulBase($x);
            $xs[$i] = $x;
        }
        $th = self::baseOtTranscriptHash($binding, $S, $R);
        $recv = [];
        foreach ($choices as $i => $_) {
            $recv[$i] = self::baseOtKdf($th, $i, $R[$i], MpcEc::mul($xs[$i], $S));
        }
        return ['R' => $R, 'recvPads' => $recv];
    }

    /** @param list<array> $R @return list<array{0:string,1:string}> */
    public static function malBaseOtSenderDerive(\GMP $y, array $T, array $R, array $S, array $binding): array
    {
        foreach ($R as $i => $r) {
            MpcEc::assertInSubgroup($r, "base-OT R_$i (received by sender)");
        }
        $th = self::baseOtTranscriptHash($binding, $S, $R);
        $pads = [];
        foreach ($R as $i => $r) {
            $yR = MpcEc::mul($y, $r);
            $pads[$i] = [self::baseOtKdf($th, $i, $r, $yR), self::baseOtKdf($th, $i, $r, MpcEc::sub($yR, $T))];
        }
        return $pads;
    }

    /**
     * One-time-pads the messages under the sender pads and commits to each (message, pad). Returns [ct, com], each a list of [x0, x1].
     *
     * @param list<array{0:string,1:string}> $messages @param list<array{0:string,1:string}> $senderPads
     */
    public static function baseOtSenderEncrypt(array $messages, array $senderPads): array
    {
        if (count($messages) !== count($senderPads)) {
            throw new \InvalidArgumentException('baseOT: messages/pads length mismatch');
        }
        foreach ($messages as $i => $m) {
            if (strlen($m[0]) > self::SEED_BYTES || strlen($m[1]) > self::SEED_BYTES || strlen($m[0]) !== strlen($m[1])) {
                throw new \InvalidArgumentException("baseOT: message pair $i must be equal length and at most " . self::SEED_BYTES . ' bytes (pad width)');
            }
        }
        $ct = [];
        $com = [];
        foreach ($messages as $i => $m) {
            [$p0, $p1] = $senderPads[$i];
            $ct[$i] = [self::xorBytes($m[0], $p0), self::xorBytes($m[1], $p1)];
            $com[$i] = [self::otCommit($i, 0, $m[0], $p0), self::otCommit($i, 1, $m[1], $p1)];
        }
        return [$ct, $com];
    }

    /** @param list<int> $choices @param list<string> $recvPads @return list<string> */
    public static function baseOtReceiverDecrypt(array $choices, array $recvPads, array $ct, array $com): array
    {
        $n = count($choices);
        if (count($ct) !== $n || count($com) !== $n || count($recvPads) !== $n) {
            throw new MpcBaseOtAbort('base OT: ciphertext/commitment count does not match the number of choices; aborting');
        }
        $received = [];
        foreach ($choices as $i => $c) {
            $ci = $c & 1;
            if (strlen($ct[$i][0]) !== strlen($ct[$i][1]) || strlen($ct[$i][0]) > self::SEED_BYTES) {
                throw new MpcBaseOtAbort("base OT (index $i): malformed ciphertext shape; aborting");
            }
            $m = self::xorBytes($ct[$i][$ci], $recvPads[$i]);
            if (!hash_equals(self::otCommit($i, $ci, $m, $recvPads[$i]), $com[$i][$ci])) {
                throw new MpcBaseOtAbort("base OT (index $i): sender ciphertext inconsistent with its commitment; aborting");
            }
            $received[$i] = $m;
        }
        return $received;
    }

    /**
     * Chosen-message 1-of-2 OT for count($choices) transfers, built over the random base OT.
     *
     * @param list<array{0:string,1:string}> $messages @param list<int> $choices
     * @return array{received:list<string>,transcript:array{S:array,proof:array,R:list<array>,ct:array,com:array}}
     */
    public static function baseOT(array $messages, array $choices, ?MpcOtRandom $rng = null, ?array $tamper = null, ?array $binding = null): array
    {
        $rng ??= MpcOtRandom::secure();
        $binding ??= self::randomBinding($rng, 'base-ot');
        if (count($messages) !== count($choices)) {
            throw new \InvalidArgumentException('baseOT: messages/choices length mismatch');
        }
        $ro = self::malBaseRandomOT($choices, $rng, $tamper, $binding);
        [$ct, $com] = self::baseOtSenderEncrypt($messages, $ro['senderPads']);
        if (isset($tamper['tamperCiphertext'])) {
            $ct = ($tamper['tamperCiphertext'])($ct);
        }
        $received = self::baseOtReceiverDecrypt($choices, $ro['recvPads'], $ct, $com);
        return ['received' => $received, 'transcript' => ['S' => $ro['S'], 'proof' => $ro['proof'], 'R' => $ro['R'], 'ct' => $ct, 'com' => $com]];
    }

    /**
     * @param list<int> $choiceBits @param ?list<?\GMP> $msg0 @param ?list<?\GMP> $msg1
     */
    public static function checkExtInputs(array $choiceBits, ?array $msg0, ?array $msg1): void
    {
        $m = count($choiceBits);
        $limit = gmp_pow(2, 64);
        foreach ($choiceBits as $j => $b) {
            if ($b !== 0 && $b !== 1) {
                throw new \InvalidArgumentException("OtChannel.extend: choice bit $j must be 0 or 1");
            }
        }
        if ($msg0 !== null && $msg1 !== null) {
            for ($j = 0; $j < $m; $j++) {
                $a = $msg0[$j] ?? null;
                $b = $msg1[$j] ?? null;
                if ($a === null || $b === null || gmp_sign($a) < 0 || gmp_sign($b) < 0 || gmp_cmp($a, $limit) >= 0 || gmp_cmp($b, $limit) >= 0) {
                    throw new \InvalidArgumentException("OtChannel.extend: message $j must be a bigint in [0, 2^64) (the pad is 64 bits wide)");
                }
            }
        }
    }
}
