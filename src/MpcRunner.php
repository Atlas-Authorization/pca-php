<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The simulated multi-party runner: all N parties in one process, exchanging shares and Beaver openings through inspectable
 * structures. composeSecure computes exactly MpcCompose::composeClear under MPC.
 */
final class MpcRunner
{
    private const T_M = 3;

    /**
     * Composes under MPC. A null seed means CSPRNG sharing randomness; a seed is for reproducible tests only.
     *
     * @param list<array{allow:int,t:int,rQuant:int}> $vectors
     * @return array{composed:array,parties:int,Q:int,opened:list<array>,sharings:list<array>,views:list<array>,multiplications:int}
     *         sharings are ['label','party','secret'(GMP),'shares'], views are ['party','heldShares','opened','output']
     */
    public static function composeSecure(array $vectors, ?int $Qopt = null, ?\GMP $seed = null): array
    {
        $n = count($vectors);
        if ($n === 0) {
            throw new \InvalidArgumentException('composeSecure: no parties (fail closed)');
        }
        $Q = $Qopt ?? MpcParty::DEFAULT_Q;
        MpcCompose::assertDecisionVectors($vectors, $Q);
        $rng = $seed === null ? MpcFieldRng::secure() : new MpcFieldRng($seed);

        $opened = [];
        $sharings = [];
        $mults = 0;

        $shareBit = static function (int $bit, string $label, int $party) use ($n, $rng, &$sharings): array {
            $s = MpcSharing::share(gmp_init($bit), $n, $rng);
            $sharings[] = ['label' => $label, 'party' => $party, 'secret' => gmp_init($bit), 'shares' => $s];
            return $s;
        };
        $and = static function (array $bits) use ($n, $rng, &$opened, &$mults): array {
            if ($bits === []) {
                return MpcSharing::shareConstant(gmp_init(1), $n);
            }
            $acc = $bits[0];
            for ($i = 1; $i < count($bits); $i++) {
                $acc = MpcBeaver::beaverMul($acc, $bits[$i], MpcBeaver::genTriple($n, $rng), $opened);
                $mults++;
            }
            return $acc;
        };
        $or = static function (array $bits) use ($n, $rng, &$opened, &$mults): array {
            if ($bits === []) {
                return MpcSharing::shareConstant(gmp_init(0), $n);
            }
            $prod = MpcSharing::notBitSV($bits[0]);
            for ($i = 1; $i < count($bits); $i++) {
                $prod = MpcBeaver::beaverMul($prod, MpcSharing::notBitSV($bits[$i]), MpcBeaver::genTriple($n, $rng), $opened);
                $mults++;
            }
            return MpcSharing::notBitSV($prod);
        };
        $isOne = static fn(array $sv): int => gmp_cmp(MpcSharing::reconstruct($sv), 1) === 0 ? 1 : 0;

        $allowBits = [];
        for ($p = 0; $p < $n; $p++) {
            $allowBits[] = $shareBit($vectors[$p]['allow'], "p$p.allow", $p);
        }
        $allow = $isOne($and($allowBits));

        $tTherm = [];
        for ($p = 0; $p < $n; $p++) {
            $tTherm[$p] = MpcThermometer::thermometerEncode((float) $vectors[$p]['t'], self::T_M);
        }
        $tGe = [];
        for ($k = 0; $k < self::T_M; $k++) {
            $bitsAtK = [];
            for ($p = 0; $p < $n; $p++) {
                $bitsAtK[] = $shareBit($tTherm[$p][$k], "p$p.t.ge" . ($k + 1), $p);
            }
            $tGe[] = $isOne($or($bitsAtK));
        }
        $t = min(3, max(1, MpcThermometer::thermometerDecode($tGe)));

        $rTherm = [];
        for ($p = 0; $p < $n; $p++) {
            $rTherm[$p] = MpcThermometer::thermometerEncode((float) $vectors[$p]['rQuant'], $Q);
        }
        $rGe = [];
        for ($k = 0; $k < $Q; $k++) {
            $bitsAtK = [];
            for ($p = 0; $p < $n; $p++) {
                $bitsAtK[] = $shareBit($rTherm[$p][$k], "p$p.r.ge" . ($k + 1), $p);
            }
            $rGe[] = $isOne($or($bitsAtK));
        }
        $rQuant = MpcThermometer::thermometerDecode($rGe);

        $composed = ['allow' => $allow, 't' => $t, 'rQuant' => $rQuant];
        $views = [];
        for ($p = 0; $p < $n; $p++) {
            $held = [];
            foreach ($sharings as $s) {
                $held[] = $s['shares'][$p];
            }
            $views[] = ['party' => $p, 'heldShares' => $held, 'opened' => $opened, 'output' => $composed];
        }
        return ['composed' => $composed, 'parties' => $n, 'Q' => $Q, 'opened' => $opened, 'sharings' => $sharings, 'views' => $views, 'multiplications' => $mults];
    }
}
