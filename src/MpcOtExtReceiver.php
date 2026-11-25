<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The OT-extension receiver (base-OT sender): makes the seed pairs, then per round the u matrix and KOS values. A round message is
 * ['u' => list<GMP>, 'x' => GMP, 'tComb' => GMP]; the per-round state ('pending') is ['m', 'choiceBits', 't', 'W', 'rowOffset'].
 */
final class MpcOtExtReceiver
{
    /** @var list<string> */
    private array $seed0 = [];
    /** @var list<string> */
    private array $seed1 = [];
    /** @var list<int> */
    private array $blk0;
    /** @var list<int> */
    private array $blk1;
    private int $round = 0;
    private int $rowsDone = 0;
    /** @var list<int> */
    private array $tweakDomain;
    public bool $ready = false;
    /** TEST-ONLY: mutate the u columns on the wire (a malicious receiver): fn(list<GMP> $u, int $round): list<GMP>. */
    public mixed $tamperU = null;

    public function __construct(private readonly MpcOtRandom $rng, private readonly string $kosBinding)
    {
        $this->tweakDomain = MpcOtx::otTweakDomain($kosBinding);
        $this->blk0 = array_fill(0, MpcOt::KAPPA, 0);
        $this->blk1 = array_fill(0, MpcOt::KAPPA, 0);
    }

    /** The kappa seed pairs, to be transferred by the base OT with the sender's selector as choices. @return list<array{0:string,1:string}> */
    public function makeSeeds(): array
    {
        $messages = [];
        for ($i = 0; $i < MpcOt::KAPPA; $i++) {
            $k0 = $this->rng->bytes(MpcOt::SEED_BYTES);
            $k1 = $this->rng->bytes(MpcOt::SEED_BYTES);
            $this->seed0[$i] = $k0;
            $this->seed1[$i] = $k1;
            $messages[$i] = [$k0, $k1];
        }
        $this->ready = true;
        return $messages;
    }

    /** @param list<int> $choiceBits @return array{msg:array,pending:array} */
    public function begin(array $choiceBits): array
    {
        if (!$this->ready) {
            throw new \LogicException('OtExtReceiver: base OT not done');
        }
        MpcOt::checkExtInputs($choiceBits, null, null);
        $m = count($choiceBits);
        $roundIdx = $this->round++;
        $rowOffset = $this->rowsDone;
        $this->rowsDone += $m;
        $pad = MpcOt::KAPPA + MpcOt::SSEC;
        $mExt = $m + $pad;
        $W = ($mExt + 31) >> 5;
        $colBytes = intdiv($mExt + 7, 8);
        $bvec = array_fill(0, $W, 0);
        foreach ($choiceBits as $j => $b) {
            if (($b & 1) !== 0) {
                $bvec[$j >> 5] |= 1 << ($j & 31);
            }
        }
        $padBytes = $this->rng->bytes($pad);
        for ($p = 0; $p < $pad; $p++) {
            if ((ord($padBytes[$p]) & 1) !== 0) {
                $j = $m + $p;
                $bvec[$j >> 5] |= 1 << ($j & 31);
            }
        }
        $blocks = intdiv($W + 3, 4);
        $t = [];
        $u = [];
        $ubytes = [];
        for ($i = 0; $i < MpcOt::KAPPA; $i++) {
            $ti = MpcOtx::prgColumn($this->seed0[$i], $this->blk0[$i], $W);
            $gi = MpcOtx::prgColumn($this->seed1[$i], $this->blk1[$i], $W);
            $this->blk0[$i] += $blocks;
            $this->blk1[$i] += $blocks;
            MpcOtx::maskTail($ti, $mExt);
            MpcOtx::maskTail($gi, $mExt);
            array_push($t, ...$ti);
            $uw = [];
            for ($w = 0; $w < $W; $w++) {
                $uw[$w] = $gi[$w] ^ $ti[$w] ^ $bvec[$w];
            }
            $ubytes[$i] = substr(MpcOtx::leBytes($uw, $W), 0, $colBytes);
            $u[$i] = MpcOtx::bytesToBig($ubytes[$i]);
        }
        if ($this->tamperU !== null) {
            $u = ($this->tamperU)($u, $roundIdx);
        }
        $pending = ['m' => $m, 'choiceBits' => $choiceBits, 't' => $t, 'W' => $W, 'rowOffset' => $rowOffset];
        $limit = gmp_pow(2, $mExt);
        foreach ($u as $c) {
            if ($c === null || gmp_sign($c) < 0 || gmp_cmp($c, $limit) >= 0) {
                return ['msg' => ['u' => $u, 'x' => gmp_init(0), 'tComb' => gmp_init(0)], 'pending' => $pending];
            }
        }
        $chi = MpcOt::kosChiWords($this->kosBinding, $roundIdx, $u, $mExt, $this->tamperU !== null ? null : $ubytes);
        $x = [0, 0, 0, 0];
        MpcOtx::accumColumn($bvec, 0, $W, $chi, $x);
        $tComb = MpcOtx::kosCombine($t, $W, $chi);
        return ['msg' => ['u' => $u, 'x' => MpcOtx::gfToBig($x), 'tComb' => MpcOtx::gfToBig($tComb)], 'pending' => $pending];
    }

    /**
     * The receiver's outputs: m_{c_j} for every row j, from the sender's ciphertexts.
     *
     * @param list<\GMP> $y0 @param list<\GMP> $y1 @return list<\GMP>
     */
    public function finish(array $pending, array $y0, array $y1): array
    {
        $m = $pending['m'];
        if (count($y0) !== $m || count($y1) !== $m) {
            throw new MpcMalOtAbort('OT extension: ciphertext count does not match the number of rows; aborting');
        }
        $rows = MpcOtx::transposeCols($pending['t'], $pending['W'], $m);
        $h = MpcOtx::tmmoCrh($rows, $m, ['offset' => $pending['rowOffset'], 'domain' => $this->tweakDomain]);
        $received = [];
        for ($j = 0; $j < $m; $j++) {
            $received[] = gmp_xor($pending['choiceBits'][$j] === 1 ? $y1[$j] : $y0[$j], MpcOtx::word64($h, $j));
        }
        return $received;
    }
}
