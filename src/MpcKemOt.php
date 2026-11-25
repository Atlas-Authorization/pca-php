<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Post-quantum base OT from ML-KEM-768 (FIPS 203, MpcMlKem768): the receiver publishes a public-key pair with a known secret key for
 * only its chosen slot, the sender encapsulates to both and pads each message with the shared secret. Variants: the semi-honest
 * transfer (kemBaseOT), the commit-then-open malicious-secure transfer with a session id (kemBaseOtMal), and the random-OT form that
 * outputs fixed-width secrets for the hybrid base OT (kemBaseOtMalRandom). Byte strings throughout; records are arrays.
 * $tamper (TEST-ONLY, null = honest): ['tamperOpenedKeys' => fn(list<array{0:string,1:string}>): list<...>, 'tamperReceiverSid' => fn(string): string].
 */
final class MpcKemOt
{
    private const TAG_KEMOT = 'atlas-pca-mpc/kem-ot-pad';
    private const TAG_KEMOT_COMMIT = 'atlas-pca-mpc/kem-ot-commit';
    private const TAG_KEMOT_SID = 'atlas-pca-mpc/kem-ot-sid';
    private const TAG_KEMOT_MALPAD = 'atlas-pca-mpc/kem-ot-mal-pad';
    private const TAG_KEMOT_MALSECRET = 'atlas-pca-mpc/kem-ot-mal-secret';
    private const NONCE_BYTES = 32;
    public const SECRET_BYTES = 32;

    private static function xor(string $a, string $b): string
    {
        if (strlen($a) !== strlen($b)) {
            throw new \InvalidArgumentException('kem-ot: XOR length mismatch');
        }
        return $a ^ $b;
    }

    private static function expand(string $tag, array $prefix, int $index, int $slot, string $ss, int $len): string
    {
        $out = '';
        for ($ctr = 0; strlen($out) < $len; $ctr++) {
            $out .= hash('sha256', $tag . implode('', $prefix) . MpcOt::u32($index) . chr($slot & 1) . MpcOt::u32($ctr) . $ss, true);
        }
        return substr($out, 0, $len);
    }

    /** Pad of $len bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode. */
    public static function kemOtPad(int $index, int $slot, string $sharedSecret, int $len): string
    {
        if ($len < 0 || $len > 1 << 20) {
            throw new \InvalidArgumentException('kemOtPad: length must be an integer in [0, 1 MiB]');
        }
        return self::expand(self::TAG_KEMOT, [], $index, $slot, $sharedSecret, $len);
    }

    /**
     * Two fresh key pairs per choice; the chosen slot's secret key is retained.
     * @param list<int> $choices
     * @return array{message:array{publicKeys:list<array{0:string,1:string}>},state:array{choices:list<int>,secretKeys:list<\FFI\CData>}}
     */
    private static function keyPairs(array $choices, MpcOtRandom $rng): array
    {
        $pks = [];
        $sks = [];
        $kept = [];
        foreach ($choices as $i => $choice) {
            $c = $choice & 1;
            $chosen = MpcMlKem768::keygen($rng->bytes(MpcMlKem768::KEYGEN_SEED_BYTES));
            $other = MpcMlKem768::keygen($rng->bytes(MpcMlKem768::KEYGEN_SEED_BYTES));
            $pks[$i] = $c === 0 ? [$chosen['publicKey'], $other['publicKey']] : [$other['publicKey'], $chosen['publicKey']];
            MpcMlKem768::free($other['secretKey']);
            $sks[$i] = $chosen['secretKey'];
            $kept[$i] = $c;
        }
        return ['publicKeys' => $pks, 'secretKeys' => $sks, 'choices' => $kept];
    }

    private static function freeAll(array $sks): void
    {
        foreach ($sks as $sk) {
            MpcMlKem768::free($sk);
        }
    }

    /**
     * @param list<array{0:string,1:string}> $messages @param list<int> $choices
     * @return array{received:list<string>,transcript:array{publicKeys:array,ciphertexts:array,encrypted:array}}
     */
    public static function kemBaseOT(array $messages, array $choices, ?MpcOtRandom $rng = null): array
    {
        $rng ??= MpcOtRandom::secure();
        if (count($messages) !== count($choices)) {
            throw new \InvalidArgumentException('kemBaseOT: messages/choices length mismatch');
        }
        $r = self::keyPairs($choices, $rng);
        try {
            $cts = [];
            $enc = [];
            foreach ($messages as $i => [$m0, $m1]) {
                if (strlen($m0) !== strlen($m1)) {
                    throw new \InvalidArgumentException("kemBaseOtSend (index $i): the two messages must be equal length");
                }
                $e0 = MpcMlKem768::encapsulate($r['publicKeys'][$i][0], $rng->bytes(MpcMlKem768::MSG_BYTES));
                $e1 = MpcMlKem768::encapsulate($r['publicKeys'][$i][1], $rng->bytes(MpcMlKem768::MSG_BYTES));
                $cts[$i] = [$e0['cipherText'], $e1['cipherText']];
                $enc[$i] = [self::xor($m0, self::kemOtPad($i, 0, $e0['sharedSecret'], strlen($m0))), self::xor($m1, self::kemOtPad($i, 1, $e1['sharedSecret'], strlen($m1)))];
            }
            $received = [];
            foreach ($r['choices'] as $i => $c) {
                $ss = MpcMlKem768::decapsulate($cts[$i][$c], $r['secretKeys'][$i]);
                $received[$i] = self::xor($enc[$i][$c], self::kemOtPad($i, $c, $ss, strlen($enc[$i][$c])));
            }
            return ['received' => $received, 'transcript' => ['publicKeys' => $r['publicKeys'], 'ciphertexts' => $cts, 'encrypted' => $enc]];
        } finally {
            self::freeAll($r['secretKeys']);
        }
    }

    /** The semi-honest KEM OT as a pluggable base OT for MpcOtChannel. */
    public static function withKemBaseOt(): \Closure
    {
        return static fn(array $m, array $c, MpcOtRandom $r): array => self::kemBaseOT($m, $c, $r)['received'];
    }

    // ---- malicious-secure (commit-then-open, session id) ----

    private static function malCommit(string $rn, int $index, string $pk0, string $pk1): string
    {
        return hash('sha256', self::TAG_KEMOT_COMMIT . $rn . MpcOt::u32($index) . $pk0 . $pk1, true);
    }

    private static function malSid(string $rn, string $sn): string
    {
        return hash('sha256', self::TAG_KEMOT_SID . $rn . $sn, true);
    }

    private static function malPad(string $sid, string $com, int $index, int $slot, string $ss, int $len): string
    {
        return self::expand(self::TAG_KEMOT_MALPAD, [$sid, $com], $index, $slot, $ss, $len);
    }

    private static function malSecret(string $sid, string $com, int $index, int $slot, string $ss): string
    {
        return substr(hash('sha256', self::TAG_KEMOT_MALSECRET . $sid . $com . MpcOt::u32($index) . chr($slot & 1) . $ss, true), 0, self::SECRET_BYTES);
    }

    /**
     * Receiver commit step.
     * @param list<int> $choices
     * @return array{rn:string,commitments:list<string>,state:array}
     */
    private static function malCommitStep(array $choices, MpcOtRandom $rng): array
    {
        $rn = $rng->bytes(self::NONCE_BYTES);
        $r = self::keyPairs($choices, $rng);
        $commitments = [];
        foreach ($r['publicKeys'] as $i => [$p0, $p1]) {
            $commitments[$i] = self::malCommit($rn, $i, $p0, $p1);
        }
        return ['rn' => $rn, 'commitments' => $commitments, 'state' => $r + ['rn' => $rn]];
    }

    /** @param ?array{tamperOpenedKeys?:callable} $tamper @return list<array{0:string,1:string}> */
    private static function openKeys(array $state, ?array $tamper): array
    {
        $pk = $state['publicKeys'];
        if (isset($tamper['tamperOpenedKeys'])) {
            $pk = ($tamper['tamperOpenedKeys'])($pk);
        }
        return $pk;
    }

    /** Sender side: aborts unless every opened pair matches its commitment; returns the sid, commitments per index. */
    private static function checkOpening(string $rn, array $commitments, array $publicKeys): array
    {
        if (count($commitments) !== count($publicKeys)) {
            throw new \InvalidArgumentException('kemBaseOtMalSend: commitments/publicKeys length mismatch');
        }
        $coms = [];
        foreach ($publicKeys as $i => [$p0, $p1]) {
            $com = self::malCommit($rn, $i, $p0, $p1);
            if (!hash_equals($com, $commitments[$i])) {
                throw new MpcKemBaseOtAbort("kem base OT (index $i): opened public keys do not match the receiver's commitment; aborting");
            }
            $coms[$i] = $com;
        }
        return $coms;
    }

    /**
     * @param list<array{0:string,1:string}> $messages @param list<int> $choices @param ?array $tamper
     * @return array{received:list<string>,transcript:array}
     */
    public static function kemBaseOtMal(array $messages, array $choices, ?MpcOtRandom $rng = null, ?array $tamper = null): array
    {
        $rng ??= MpcOtRandom::secure();
        if (count($messages) !== count($choices)) {
            throw new \InvalidArgumentException('kemBaseOtMal: messages/choices length mismatch');
        }
        $cs = self::malCommitStep($choices, $rng);
        try {
            $sn = $rng->bytes(self::NONCE_BYTES);
            $pks = self::openKeys($cs['state'], $tamper);
            if (count($messages) !== count($pks)) {
                throw new \InvalidArgumentException('kemBaseOtMalSend: messages/commitments/publicKeys length mismatch');
            }
            $coms = self::checkOpening($cs['rn'], $cs['commitments'], $pks);
            $sid = self::malSid($cs['rn'], $sn);
            $cts = [];
            $enc = [];
            foreach ($messages as $i => [$m0, $m1]) {
                if (strlen($m0) !== strlen($m1)) {
                    throw new \InvalidArgumentException("kemBaseOtMalSend (index $i): the two messages must be equal length");
                }
                $e0 = MpcMlKem768::encapsulate($pks[$i][0], $rng->bytes(MpcMlKem768::MSG_BYTES));
                $e1 = MpcMlKem768::encapsulate($pks[$i][1], $rng->bytes(MpcMlKem768::MSG_BYTES));
                $cts[$i] = [$e0['cipherText'], $e1['cipherText']];
                $enc[$i] = [self::xor($m0, self::malPad($sid, $coms[$i], $i, 0, $e0['sharedSecret'], strlen($m0))),
                    self::xor($m1, self::malPad($sid, $coms[$i], $i, 1, $e1['sharedSecret'], strlen($m1)))];
            }
            $rsid = isset($tamper['tamperReceiverSid']) ? ($tamper['tamperReceiverSid'])($sid) : $sid;
            $received = [];
            foreach ($cs['state']['choices'] as $i => $c) {
                $com = self::malCommit($cs['rn'], $i, $cs['state']['publicKeys'][$i][0], $cs['state']['publicKeys'][$i][1]);
                $ss = MpcMlKem768::decapsulate($cts[$i][$c], $cs['state']['secretKeys'][$i]);
                $received[$i] = self::xor($enc[$i][$c], self::malPad($rsid, $com, $i, $c, $ss, strlen($enc[$i][$c])));
            }
            return ['received' => $received, 'transcript' => ['rn' => $cs['rn'], 'commitments' => $cs['commitments'], 'sn' => $sn,
                'publicKeys' => $pks, 'ciphertexts' => $cts, 'encrypted' => $enc]];
        } finally {
            self::freeAll($cs['state']['secretKeys']);
        }
    }

    /** The malicious-secure KEM OT as a pluggable base OT for MpcOtChannel. */
    public static function withKemBaseOtMal(): \Closure
    {
        return static fn(array $m, array $c, MpcOtRandom $r): array => self::kemBaseOtMal($m, $c, $r)['received'];
    }

    // ---- random-OT form (fixed-width secrets, for the hybrid base OT) ----

    /**
     * @param list<int> $choices @param ?array $tamper
     * @return array{senderSecrets:list<array{0:string,1:string}>,recvSecrets:list<string>,sid:string,transcript:array}
     */
    public static function kemBaseOtMalRandom(array $choices, ?MpcOtRandom $rng = null, ?array $tamper = null): array
    {
        $rng ??= MpcOtRandom::secure();
        $cs = self::malCommitStep($choices, $rng);
        try {
            $sn = $rng->bytes(self::NONCE_BYTES);
            $pks = self::openKeys($cs['state'], $tamper);
            $coms = self::checkOpening($cs['rn'], $cs['commitments'], $pks);
            $sid = self::malSid($cs['rn'], $sn);
            $cts = [];
            $secrets = [];
            foreach ($pks as $i => $pk) {
                $e0 = MpcMlKem768::encapsulate($pk[0], $rng->bytes(MpcMlKem768::MSG_BYTES));
                $e1 = MpcMlKem768::encapsulate($pk[1], $rng->bytes(MpcMlKem768::MSG_BYTES));
                $cts[$i] = [$e0['cipherText'], $e1['cipherText']];
                $secrets[$i] = [self::malSecret($sid, $coms[$i], $i, 0, $e0['sharedSecret']), self::malSecret($sid, $coms[$i], $i, 1, $e1['sharedSecret'])];
            }
            $rsid = isset($tamper['tamperReceiverSid']) ? ($tamper['tamperReceiverSid'])($sid) : $sid;
            $recv = [];
            foreach ($cs['state']['choices'] as $i => $c) {
                $com = self::malCommit($cs['rn'], $i, $cs['state']['publicKeys'][$i][0], $cs['state']['publicKeys'][$i][1]);
                $ss = MpcMlKem768::decapsulate($cts[$i][$c], $cs['state']['secretKeys'][$i]);
                $recv[$i] = self::malSecret($rsid, $com, $i, $c, $ss);
            }
            return ['senderSecrets' => $secrets, 'recvSecrets' => $recv, 'sid' => $sid, 'transcript' => ['rn' => $cs['rn'],
                'commitments' => $cs['commitments'], 'sn' => $sn, 'publicKeys' => $pks, 'ciphertexts' => $cts]];
        } finally {
            self::freeAll($cs['state']['secretKeys']);
        }
    }
}
