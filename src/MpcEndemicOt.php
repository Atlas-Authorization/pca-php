<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The post-quantum, maliciously-secure endemic base OT (Masny-Rindal over Module-LWE, Kyber-768 K-PKE), the TypeScript package's recommended base
 * OT. The receiver places a real key's offset-by-oracle point at its choice slot and a uniform ring vector at the other, so the sender's effective
 * key for the other slot is uniform and its ciphertext is unrecoverable; the chosen-message form pads and commits each message and aborts on any
 * inconsistency. All lattice work is MpcLweLattice (the audited pqc_kyber through liblweot); this class hashes, xors and marshals bytes. The
 * receiver's real key pair is the FIPS 203 K-PKE.KeyGen(d), the derivation the reference uses, so every receiver message matches it byte for byte.
 */
final class MpcEndemicOt
{
    public const ENDEMIC_SECRET_BYTES = 32;

    private const TAG_SID = 'atlas-pca-mpc/endemic-lwe-ot-sid';
    private const TAG_HPK = 'atlas-pca-mpc/endemic-lwe-ot-hpk';
    private const TAG_N = 'atlas-pca-mpc/endemic-lwe-ot-N';
    private const TAG_PAD = 'atlas-pca-mpc/endemic-lwe-ot-pad';
    private const TAG_COMMIT = 'atlas-pca-mpc/endemic-lwe-ot-commit';

    /** sid = H(TAG || rn): binds every oracle query to this receiver nonce. */
    public static function sessionId(string $rn): string
    {
        return hash('sha256', self::TAG_SID . $rn, true);
    }

    private static function hpk(string $sid, int $i, string $other): string
    {
        return MpcLweLattice::hashToRing(self::TAG_HPK . $sid . MpcOt::u32($i) . $other);
    }

    /** The pad for a slot: SHA-256 in counter mode over TAG || sid || i || slot || ctr || payload. */
    public static function pad(string $sid, int $index, int $slot, string $payload, int $len): string
    {
        $out = '';
        for ($ctr = 0; strlen($out) < $len; $ctr++) {
            $out .= hash('sha256', self::TAG_PAD . $sid . MpcOt::u32($index) . chr($slot & 1) . MpcOt::u32($ctr) . $payload, true);
        }
        return substr($out, 0, $len);
    }

    private static function commit(string $sid, int $i, int $slot, string $msg, string $pad): string
    {
        return hash('sha256', self::TAG_COMMIT . $sid . MpcOt::u32($i) . chr($slot & 1) . $msg . $pad, true);
    }

    /**
     * Receiver round: a real key pair per choice, a uniform vector for the other slot, and C = t_real - Hpk(sid, i, N) at the choice slot.
     *
     * @param list<int> $choices
     * @return array{message: array{rn:string, points:list<array{0:string,1:string}>, rhos:list<string>}, state: array{choices:list<int>, secretKeys:list<string>, rhos:list<string>, rn:string, sid:string}}
     */
    public static function receive(array $choices, ?MpcOtRandom $rng = null): array
    {
        $rng ??= MpcOtRandom::secure();
        $rn = $rng->bytes(MpcLweLattice::SYM_BYTES);
        $sid = self::sessionId($rn);
        $points = [];
        $rhos = [];
        $sks = [];
        $kept = [];
        foreach (array_values($choices) as $i => $ch) {
            $c = $ch & 1;
            [$pk, $sk] = MpcLweLattice::keygenFips203($rng->bytes(MpcLweLattice::SYM_BYTES));
            $nSlot = MpcLweLattice::hashToRing(self::TAG_N . $sid . MpcOt::u32($i) . $rng->bytes(MpcLweLattice::SYM_BYTES));
            $cPoint = MpcLweLattice::ringSub(substr($pk, 0, MpcLweLattice::TVEC_BYTES), self::hpk($sid, $i, $nSlot));
            $points[] = $c === 0 ? [$cPoint, $nSlot] : [$nSlot, $cPoint];
            $rhos[] = substr($pk, MpcLweLattice::TVEC_BYTES);
            $sks[] = $sk;
            $kept[] = $c;
        }
        return ['message' => ['rn' => $rn, 'points' => $points, 'rhos' => $rhos], 'state' => ['choices' => $kept, 'secretKeys' => $sks, 'rhos' => $rhos, 'rn' => $rn, 'sid' => $sid]];
    }

    private static function isBytes(mixed $x, int $n): bool
    {
        return is_string($x) && strlen($x) === $n;
    }

    private static function validate(array $m): void
    {
        if (!self::isBytes($m['rn'] ?? null, MpcLweLattice::SYM_BYTES)) {
            throw new MpcEndemicOtAbort('endemic LWE OT: malformed session nonce');
        }
        $points = $m['points'] ?? null;
        $rhos = $m['rhos'] ?? null;
        if (!is_array($points) || !is_array($rhos) || count($points) !== count($rhos)) {
            throw new MpcEndemicOtAbort('endemic LWE OT: points/rhos length mismatch');
        }
        foreach (array_values($points) as $i => $pt) {
            if (!is_array($pt) || count($pt) !== 2 || !self::isBytes($pt[0] ?? null, MpcLweLattice::TVEC_BYTES) || !self::isBytes($pt[1] ?? null, MpcLweLattice::TVEC_BYTES)) {
                throw new MpcEndemicOtAbort("endemic LWE OT: malformed point pair at index $i");
            }
            if (!self::isBytes(array_values($rhos)[$i] ?? null, MpcLweLattice::PK_BYTES - MpcLweLattice::TVEC_BYTES)) {
                throw new MpcEndemicOtAbort("endemic LWE OT: malformed rho at index $i");
            }
        }
    }

    /** pk_b = (P_b + Hpk(sid, i, P_{1-b}) || rho) */
    private static function effectiveKey(string $sid, int $i, string $own, string $other, string $rho): string
    {
        return MpcLweLattice::ringAdd($own, self::hpk($sid, $i, $other)) . $rho;
    }

    /**
     * Sender round (random-OT form): encrypt a fresh payload under each slot's effective key and output both pads. $tamper (test-only) corrupts
     * the ciphertexts on the wire.
     *
     * @return array{ciphertexts: list<array{0:string,1:string}>, senderPads: list<array{0:string,1:string}>}
     */
    public static function sendRandom(array $message, ?MpcOtRandom $rng = null, ?\Closure $tamper = null): array
    {
        $rng ??= MpcOtRandom::secure();
        self::validate($message);
        $sid = self::sessionId($message['rn']);
        $cts = [];
        $pads = [];
        foreach (array_values($message['points']) as $i => [$p0, $p1]) {
            $rho = array_values($message['rhos'])[$i];
            $pk0 = self::effectiveKey($sid, $i, $p0, $p1, $rho);
            $pk1 = self::effectiveKey($sid, $i, $p1, $p0, $rho);
            $r0 = $rng->bytes(MpcLweLattice::SYM_BYTES);
            $r1 = $rng->bytes(MpcLweLattice::SYM_BYTES);
            $ct0 = MpcLweLattice::enc($pk0, $r0, $rng->bytes(MpcLweLattice::SYM_BYTES));
            $ct1 = MpcLweLattice::enc($pk1, $r1, $rng->bytes(MpcLweLattice::SYM_BYTES));
            $cts[] = [$ct0, $ct1];
            $pads[] = [self::pad($sid, $i, 0, $r0, self::ENDEMIC_SECRET_BYTES), self::pad($sid, $i, 1, $r1, self::ENDEMIC_SECRET_BYTES)];
        }
        if ($tamper !== null) {
            $cts = $tamper($cts);
        }
        return ['ciphertexts' => $cts, 'senderPads' => $pads];
    }

    /**
     * Receiver recovery (random-OT form): decrypt only the chosen ciphertext.
     *
     * @return list<string>
     */
    public static function recoverRandom(array $state, array $senderMessage): array
    {
        $cts = $senderMessage['ciphertexts'] ?? null;
        if (!is_array($cts) || count($cts) !== count($state['choices'])) {
            throw new MpcEndemicOtAbort('endemic LWE OT: ciphertext count does not match the transfer count');
        }
        foreach (array_values($cts) as $i => $ct) {
            if (!is_array($ct) || count($ct) !== 2 || !self::isBytes($ct[0] ?? null, MpcLweLattice::CT_BYTES) || !self::isBytes($ct[1] ?? null, MpcLweLattice::CT_BYTES)) {
                throw new MpcEndemicOtAbort("endemic LWE OT: malformed ciphertext pair at index $i");
            }
        }
        $out = [];
        foreach ($state['choices'] as $i => $c) {
            $c &= 1;
            $out[] = self::pad($state['sid'], $i, $c, MpcLweLattice::dec($state['secretKeys'][$i], array_values($cts)[$i][$c]), self::ENDEMIC_SECRET_BYTES);
        }
        return $out;
    }

    /**
     * In-process chosen-message endemic base OT: $messages[i] = [m0, m1] of equal length, $choices[i] in {0,1}. The sender pads and commits each
     * message; the receiver recovers m_{choices[i]} and checks the commitment, aborting on any inconsistency. $senderRng is the sender's entropy
     * (the receiver's when null); $tamperEncrypted (test-only) corrupts the padded messages on the wire.
     *
     * @return array{received: list<string>, transcript: array<string,mixed>}
     */
    public static function baseOT(array $messages, array $choices, ?MpcOtRandom $rng = null, ?MpcOtRandom $senderRng = null, ?\Closure $tamperEncrypted = null): array
    {
        if (count($messages) !== count($choices)) {
            throw new \InvalidArgumentException('endemicBaseOT: messages/choices length mismatch');
        }
        $rng ??= MpcOtRandom::secure();
        $srng = $senderRng ?? $rng;
        $rv = self::receive($choices, $rng);
        $sid = $rv['state']['sid'];
        $cts = [];
        $enc = [];
        $com = [];
        foreach (array_values($messages) as $i => [$m0, $m1]) {
            if (strlen($m0) !== strlen($m1)) {
                throw new \InvalidArgumentException("endemicBaseOT (index $i): the two messages must be equal length");
            }
            [$p0, $p1] = $rv['message']['points'][$i];
            $rho = $rv['message']['rhos'][$i];
            $r0 = $srng->bytes(MpcLweLattice::SYM_BYTES);
            $r1 = $srng->bytes(MpcLweLattice::SYM_BYTES);
            $ct0 = MpcLweLattice::enc(self::effectiveKey($sid, $i, $p0, $p1, $rho), $r0, $srng->bytes(MpcLweLattice::SYM_BYTES));
            $ct1 = MpcLweLattice::enc(self::effectiveKey($sid, $i, $p1, $p0, $rho), $r1, $srng->bytes(MpcLweLattice::SYM_BYTES));
            $cts[] = [$ct0, $ct1];
            $pad0 = self::pad($sid, $i, 0, $r0, strlen($m0));
            $pad1 = self::pad($sid, $i, 1, $r1, strlen($m1));
            $enc[] = [$m0 ^ $pad0, $m1 ^ $pad1];
            $com[] = [self::commit($sid, $i, 0, $m0, $pad0), self::commit($sid, $i, 1, $m1, $pad1)];
        }
        if ($tamperEncrypted !== null) {
            $enc = $tamperEncrypted($enc);
        }
        $received = [];
        foreach (array_values($choices) as $i => $ch) {
            $c = $ch & 1;
            $payload = MpcLweLattice::dec($rv['state']['secretKeys'][$i], $cts[$i][$c]);
            $e = $enc[$i][$c];
            $pad = self::pad($sid, $i, $c, $payload, strlen($e));
            $m = $e ^ $pad;
            if (!hash_equals(self::commit($sid, $i, $c, $m, $pad), $com[$i][$c])) {
                throw new MpcEndemicOtAbort("endemic base OT (index $i): sender ciphertext inconsistent with its commitment; aborting");
            }
            $received[] = $m;
        }
        return ['received' => $received, 'transcript' => ['rn' => $rv['message']['rn'], 'points' => $rv['message']['points'], 'rhos' => $rv['message']['rhos'],
            'ciphertexts' => $cts, 'encrypted' => $enc, 'commitments' => $com]];
    }

    /**
     * In-process RANDOM endemic base OT (endemicLweBaseOtRandom): the receiver round, the sender round and the recovery in one call.
     * `senderPads` are the sender's `[k0, k1]` per slot (it learns both), `recvPads` the receiver's chosen pad (it learns one).
     * @param list<int> $choices
     * @return array{senderPads:list<array{0:string,1:string}>,recvPads:list<string>,sid:string,message:array<string,mixed>,ciphertexts:list<array{0:string,1:string}>}
     */
    public static function baseOtRandom(array $choices, ?MpcOtRandom $rng = null, ?\Closure $tamper = null): array
    {
        $rng ??= MpcOtRandom::secure();
        $rv = self::receive($choices, $rng);
        $sm = self::sendRandom($rv['message'], $rng, $tamper);
        return ['senderPads' => $sm['senderPads'], 'recvPads' => self::recoverRandom($rv['state'], $sm), 'sid' => $rv['state']['sid'], 'message' => $rv['message'], 'ciphertexts' => $sm['ciphertexts']];
    }

    /** The chosen-message endemic base OT as a pluggable base OT for MpcOtChannel. */
    public static function withEndemicBaseOt(): \Closure
    {
        return static fn(array $m, array $c, MpcOtRandom $r): array => self::baseOT($m, $c, $r)['received'];
    }
}
