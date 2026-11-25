<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Hybrid base OT: the elliptic-curve random OT and the ML-KEM random OT run side by side and BOTH secrets are folded into every
 * transfer key, so the transfer is secure if either the classical or the post-quantum assumption holds. The keys encrypt the
 * messages and a per-message commitment catches an inconsistent sender.
 * $tamper (TEST-ONLY, null = honest): ['ec' => MpcOt tamper array, 'kem' => MpcKemOt tamper array, 'tamperEncrypted' => fn(list<array>): list<array>].
 */
final class MpcHybridOt
{
    private const TAG_HYBRID_SID = 'atlas-pca-mpc/hybrid-ot-sid';
    private const TAG_HYBRID_KEY = 'atlas-pca-mpc/hybrid-ot-transfer-key';
    private const TAG_HYBRID_COMMIT = 'atlas-pca-mpc/hybrid-ot-msg-commit';

    /** @param array $ecS an Ed25519 point */
    public static function hybridSessionId(string $kemSid, array $ecS): string
    {
        return hash('sha256', self::TAG_HYBRID_SID . $kemSid . MpcEc::encodePoint($ecS), true);
    }

    public static function hybridTransferKey(string $sid, int $index, int $slot, string $ssEc, string $ssKem, int $len): string
    {
        if ($len < 0 || $len > 1 << 20) {
            throw new \InvalidArgumentException('hybridTransferKey: length must be an integer in [0, 1 MiB]');
        }
        $out = '';
        for ($ctr = 0; strlen($out) < $len; $ctr++) {
            $out .= hash('sha256', self::TAG_HYBRID_KEY . $sid . MpcOt::u32($index) . chr($slot & 1) . MpcOt::u32($ctr) . $ssEc . $ssKem, true);
        }
        return substr($out, 0, $len);
    }

    private static function commit(string $sid, int $index, int $slot, string $msg, string $key): string
    {
        return hash('sha256', self::TAG_HYBRID_COMMIT . $sid . MpcOt::u32($index) . chr($slot & 1) . $msg . $key, true);
    }

    /**
     * @param list<array{0:string,1:string}> $messages @param list<array{0:string,1:string}> $ecSecrets @param list<array{0:string,1:string}> $kemSecrets
     * @return array{encrypted:list<array{0:string,1:string}>,commitments:list<array{0:string,1:string}>}
     */
    public static function hybridSenderEncrypt(string $sid, array $messages, array $ecSecrets, array $kemSecrets): array
    {
        if (count($messages) !== count($ecSecrets) || count($messages) !== count($kemSecrets)) {
            throw new \InvalidArgumentException('hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch');
        }
        $enc = [];
        $com = [];
        foreach ($messages as $i => [$m0, $m1]) {
            if (strlen($m0) !== strlen($m1)) {
                throw new \InvalidArgumentException("hybridSenderEncrypt (index $i): the two messages must be equal length");
            }
            $k0 = self::hybridTransferKey($sid, $i, 0, $ecSecrets[$i][0], $kemSecrets[$i][0], strlen($m0));
            $k1 = self::hybridTransferKey($sid, $i, 1, $ecSecrets[$i][1], $kemSecrets[$i][1], strlen($m1));
            $enc[$i] = [$m0 ^ $k0, $m1 ^ $k1];
            $com[$i] = [self::commit($sid, $i, 0, $m0, $k0), self::commit($sid, $i, 1, $m1, $k1)];
        }
        return ['encrypted' => $enc, 'commitments' => $com];
    }

    /**
     * @param list<int> $choices @param array{encrypted:array,commitments:array} $sender @param list<string> $ecRecv @param list<string> $kemRecv
     * @return list<string>
     */
    public static function hybridReceiverRecover(string $sid, array $choices, array $sender, array $ecRecv, array $kemRecv): array
    {
        $n = count($choices);
        if (count($sender['encrypted']) !== $n || count($sender['commitments']) !== $n || count($ecRecv) !== $n || count($kemRecv) !== $n) {
            throw new \InvalidArgumentException('hybridReceiverRecover: length mismatch');
        }
        $received = [];
        foreach ($choices as $i => $choice) {
            $c = $choice & 1;
            $e = $sender['encrypted'][$i][$c];
            $key = self::hybridTransferKey($sid, $i, $c, $ecRecv[$i], $kemRecv[$i], strlen($e));
            $m = $e ^ $key;
            if (!hash_equals(self::commit($sid, $i, $c, $m, $key), $sender['commitments'][$i][$c])) {
                throw new MpcHybridOtAbort("hybrid base OT (index $i): sender ciphertext inconsistent with its commitment; aborting");
            }
            $received[$i] = $m;
        }
        return $received;
    }

    /**
     * @param list<array{0:string,1:string}> $messages @param list<int> $choices
     * @return array{received:list<string>,transcript:array{sid:string,ecS:array,kemSid:string,encrypted:array,commitments:array}}
     */
    public static function hybridBaseOT(array $messages, array $choices, ?MpcOtRandom $rng = null, ?array $tamper = null): array
    {
        $rng ??= MpcOtRandom::secure();
        if (count($messages) !== count($choices)) {
            throw new \InvalidArgumentException('hybridBaseOT: messages/choices length mismatch');
        }
        $ec = MpcOt::malBaseRandomOT($choices, $rng, $tamper['ec'] ?? null);
        $kem = MpcKemOt::kemBaseOtMalRandom($choices, $rng, $tamper['kem'] ?? null);
        $sid = self::hybridSessionId($kem['sid'], $ec['S']);
        $sender = self::hybridSenderEncrypt($sid, $messages, $ec['senderPads'], $kem['senderSecrets']);
        if (isset($tamper['tamperEncrypted'])) {
            $sender['encrypted'] = ($tamper['tamperEncrypted'])($sender['encrypted']);
        }
        $received = self::hybridReceiverRecover($sid, $choices, $sender, $ec['recvPads'], $kem['recvSecrets']);
        return ['received' => $received, 'transcript' => ['sid' => $sid, 'ecS' => $ec['S'], 'kemSid' => $kem['sid'],
            'encrypted' => $sender['encrypted'], 'commitments' => $sender['commitments']]];
    }

    /** The hybrid base OT as a pluggable base OT for MpcOtChannel. */
    public static function withHybridBaseOt(): \Closure
    {
        return static fn(array $m, array $c, MpcOtRandom $r): array => self::hybridBaseOT($m, $c, $r)['received'];
    }
}
