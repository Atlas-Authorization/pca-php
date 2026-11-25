<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** The OT-extension sender (base-OT receiver): holds the secret selector s and answers each round after the KOS check. */
final class MpcOtExtSender
{
    /** @var list<int> */
    private array $s = [];
    private \GMP $sBits;
    /** @var list<string> */
    private array $seeds = [];
    /** @var list<int> */
    private array $blk = [];
    private int $round = 0;
    private int $rowsDone = 0;
    /** @var list<int> */
    private array $tweakDomain;
    public bool $ready = false;

    public function __construct(private readonly MpcOtRandom $rng, private readonly string $kosBinding)
    {
        $this->sBits = gmp_init(0);
        $this->tweakDomain = MpcOtx::otTweakDomain($kosBinding);
    }

    /** @return list<int> */
    public function makeSelector(): array
    {
        $this->s = [];
        for ($i = 0; $i < MpcOt::KAPPA; $i++) {
            $this->s[$i] = ord($this->rng->bytes(1)[0]) & 1;
        }
        return $this->s;
    }

    /** @param list<string> $seeds */
    public function setSeeds(array $seeds): void
    {
        if (count($seeds) !== MpcOt::KAPPA || count($this->s) !== MpcOt::KAPPA) {
            throw new \LogicException('OtExtSender: wrong base-OT output size');
        }
        $this->seeds = $seeds;
        $this->blk = array_fill(0, MpcOt::KAPPA, 0);
        $acc = gmp_init(0);
        for ($i = 0; $i < MpcOt::KAPPA; $i++) {
            if ($this->s[$i] === 1) {
                gmp_setbit($acc, $i);
            }
        }
        $this->sBits = $acc;
        $this->ready = true;
    }

    public function selector(): \GMP
    {
        return $this->sBits;
    }

    /**
     * @param array{u:?list<\GMP>,x:?\GMP,tComb:?\GMP} $msg @param list<\GMP> $msg0 @param list<\GMP> $msg1
     * @return array{y0:list<\GMP>,y1:list<\GMP>}
     */
    public function respond(array $msg, array $msg0, array $msg1): array
    {
        if (!$this->ready) {
            throw new \LogicException('OtExtSender: base OT not done');
        }
        $m = count($msg0);
        if (count($msg1) !== $m) {
            throw new \InvalidArgumentException('OtChannel.extend: length mismatch');
        }
        MpcOt::checkExtInputs(array_fill(0, $m, 0), $msg0, $msg1);
        $roundIdx = $this->round++;
        $rowOffset = $this->rowsDone;
        $this->rowsDone += $m;
        $kappa = MpcOt::KAPPA;
        $mExt = $m + $kappa + MpcOt::SSEC;
        $u = $msg['u'];
        if ($u === null || count($u) !== $kappa) {
            throw new MpcMalOtAbort("KOS check (round $roundIdx): wrong number of u columns; a cheating OT-extension receiver was detected; aborting");
        }
        $colLimit = gmp_pow(2, $mExt);
        for ($i = 0; $i < $kappa; $i++) {
            $ui = $u[$i];
            if ($ui === null || gmp_sign($ui) < 0 || gmp_cmp($ui, $colLimit) >= 0) {
                throw new MpcMalOtAbort("KOS check (round $roundIdx): malformed u column $i; a cheating OT-extension receiver was detected; aborting");
            }
        }
        $lim128 = gmp_pow(2, 128);
        $x = $msg['x'];
        $tc = $msg['tComb'];
        if ($x === null || $tc === null || gmp_sign($x) < 0 || gmp_cmp($x, $lim128) >= 0 || gmp_sign($tc) < 0 || gmp_cmp($tc, $lim128) >= 0) {
            throw new MpcMalOtAbort("KOS check (round $roundIdx): malformed (x, t); a cheating OT-extension receiver was detected; aborting");
        }
        $W = ($mExt + 31) >> 5;
        $colBytes = intdiv($mExt + 7, 8);
        $blocks = intdiv($W + 3, 4);
        $q = [];
        $ubytes = [];
        for ($i = 0; $i < $kappa; $i++) {
            $ubytes[$i] = MpcOtx::bigToBytes($u[$i], $colBytes);
            $ks = MpcOtx::prgColumn($this->seeds[$i], $this->blk[$i], $W);
            $this->blk[$i] += $blocks;
            MpcOtx::maskTail($ks, $mExt);
            if ($this->s[$i] === 1) {
                $uw = MpcOtx::leWords(str_pad($ubytes[$i], 4 * $W, "\0"), 0, $W);
                for ($w = 0; $w < $W; $w++) {
                    $ks[$w] ^= $uw[$w];
                }
            }
            array_push($q, ...$ks);
        }
        $chi = MpcOt::kosChiWords($this->kosBinding, $roundIdx, $u, $mExt, $ubytes);
        $qComb = MpcOtx::gfToBig(MpcOtx::kosCombine($q, $W, $chi));
        $expected = gmp_xor($tc, MpcGf128::mul($x, $this->sBits));
        if (gmp_cmp($qComb, $expected) !== 0) {
            throw new MpcMalOtAbort("KOS correlation check FAILED (round $roundIdx): a cheating OT-extension receiver was detected; aborting");
        }
        $rows = MpcOtx::transposeCols($q, $W, $m);
        $tweak = ['offset' => $rowOffset, 'domain' => $this->tweakDomain];
        $h0 = MpcOtx::tmmoCrh($rows, $m, $tweak);
        $sw = MpcOtx::gfFromBig($this->sBits);
        for ($j = 0; $j < $m; $j++) {
            $row = array_slice($rows, 4 * $j, 4);
            MpcOtx::gfXorInto($row, $sw, 0);
            array_splice($rows, 4 * $j, 4, $row);
        }
        $h1 = MpcOtx::tmmoCrh($rows, $m, $tweak);
        $y0 = [];
        $y1 = [];
        for ($j = 0; $j < $m; $j++) {
            $y0[] = gmp_xor($msg0[$j], MpcOtx::word64($h0, $j));
            $y1[] = gmp_xor($msg1[$j], MpcOtx::word64($h1, $j));
        }
        return ['y0' => $y0, 'y1' => $y1];
    }
}
