<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * SPDZ-style authenticated secret sharing over F_p: the malicious-with-abort (dishonest-majority) layer. A global MAC key alpha is
 * additively shared; every authenticated value carries MAC shares summing to alpha*x under MAC_KEYS independent keys; the batched
 * commit-then-open MAC-check (MpcSpdzEngine) aborts on any deviation, so the result is correct or an abort. The authenticated
 * triples come from a trusted dealer (the explicit trust assumption); the online phase is the real thing.
 *
 * Records are arrays:
 *  - MacKey      ['alphaShares' => list<GMP>, 'alpha' => GMP]
 *  - MacContext  ['n' => int, 'alphaShares' => list<GMP>, 'alpha' => GMP, 'extraKeys' => list<MacKey>]
 *  - AuthSV      ['value' => list<GMP>, 'mac' => list<GMP>, 'extraMac' => list<list<GMP>>]
 *  - AuthTriple  ['a' => AuthSV, 'b' => AuthSV, 'c' => AuthSV]
 *  - TripleWithPartners ['keep' => AuthTriple, 'partners' => list<AuthTriple>]
 *  - DealerFault ['keepCDelta' => ?GMP, 'partnerCDelta' => ?list<?GMP>]   (TEST-ONLY lying dealer)
 *  - Deviation   ['openIndex' => int, 'party' => int, 'valueDelta' => ?GMP, 'macDelta' => ?GMP, 'macKey' => ?int]
 *  - OpenedValue ['value' => GMP, 'macShares' => list<list<GMP>>, 'label' => string]
 */
final class MpcSpdz
{
    public const MAC_KEYS = 2;
    public const MIN_MAC_SOUNDNESS_BITS = 100;
    public const SACRIFICE_PARTNERS = 2;

    /** @return list<array> */
    public static function macKeys(array $ctx): array
    {
        return array_merge([['alphaShares' => $ctx['alphaShares'], 'alpha' => $ctx['alpha']]], $ctx['extraKeys']);
    }

    /** keys * (log2 p - 1): the soundness in bits of the batched MAC-check. */
    public static function macSoundnessBits(int $keys, ?\GMP $p = null): float
    {
        $d = (float) gmp_strval($p ?? MpcField::prime());
        $l = log($d) / log(2);
        $r = round($l);
        if (abs($l - $r) < 1e-9 && 2.0 ** $r === $d) {
            $l = $r;
        }
        return $keys * ($l - 1);
    }

    public static function setupMac(int $n, MpcFieldRng $rng, int $keys = self::MAC_KEYS): array
    {
        if ($n < 1) {
            throw new \InvalidArgumentException('setupMac: n must be a positive integer');
        }
        if ($keys < 1 || $keys > 16) {
            throw new \InvalidArgumentException('setupMac: keys must be an integer in [1, 16]');
        }
        $first = self::mk($n, $rng);
        $extra = [];
        for ($i = 0; $i < $keys - 1; $i++) {
            $extra[] = self::mk($n, $rng);
        }
        return ['n' => $n, 'alphaShares' => $first['alphaShares'], 'alpha' => $first['alpha'], 'extraKeys' => $extra];
    }

    private static function mk(int $n, MpcFieldRng $rng): array
    {
        $alpha = $rng->next();
        return ['alphaShares' => MpcSharing::share($alpha, $n, $rng), 'alpha' => $alpha];
    }

    public static function authShare(\GMP $secret, array $ctx, MpcFieldRng $rng): array
    {
        $v = MpcField::mod($secret);
        $value = MpcSharing::share($v, $ctx['n'], $rng);
        $mac = MpcSharing::share(MpcField::fmul($ctx['alpha'], $v), $ctx['n'], $rng);
        $extra = [];
        foreach ($ctx['extraKeys'] as $key) {
            $extra[] = MpcSharing::share(MpcField::fmul($key['alpha'], $v), $ctx['n'], $rng);
        }
        return ['value' => $value, 'mac' => $mac, 'extraMac' => $extra];
    }

    public static function authConstant(\GMP $c, array $ctx): array
    {
        $v = MpcField::mod($c);
        $value = array_fill(0, $ctx['n'], gmp_init(0));
        $value[0] = $v;
        $extra = [];
        foreach ($ctx['extraKeys'] as $key) {
            $extra[] = self::scaleAll($key['alphaShares'], $v);
        }
        return ['value' => $value, 'mac' => self::scaleAll($ctx['alphaShares'], $v), 'extraMac' => $extra];
    }

    /** @param list<\GMP> $xs @return list<\GMP> */
    private static function scaleAll(array $xs, \GMP $c): array
    {
        return array_map(static fn(\GMP $x): \GMP => MpcField::fmul($x, $c), $xs);
    }

    /** @param list<\GMP> $x @param list<\GMP> $y @return list<\GMP> */
    private static function zip(array $x, array $y, callable $f): array
    {
        $o = [];
        foreach ($x as $i => $xi) {
            $o[] = $f($xi, $y[$i]);
        }
        return $o;
    }

    private static function zipMac(array $x, array $y, callable $f): array
    {
        $o = [];
        foreach ($x as $l => $row) {
            $o[] = self::zip($row, $y[$l], $f);
        }
        return $o;
    }

    private static function both(array $x, array $y, callable $f): array
    {
        self::requireSame($x, $y);
        return ['value' => self::zip($x['value'], $y['value'], $f), 'mac' => self::zip($x['mac'], $y['mac'], $f), 'extraMac' => self::zipMac($x['extraMac'], $y['extraMac'], $f)];
    }

    public static function addAuth(array $x, array $y): array
    {
        return self::both($x, $y, static fn(\GMP $a, \GMP $b): \GMP => MpcField::fadd($a, $b));
    }

    public static function subAuth(array $x, array $y): array
    {
        return self::both($x, $y, static fn(\GMP $a, \GMP $b): \GMP => MpcField::fsub($a, $b));
    }

    public static function negAuth(array $x): array
    {
        $neg = static fn(array $xs): array => array_map(static fn(\GMP $a): \GMP => MpcField::fneg($a), $xs);
        return ['value' => $neg($x['value']), 'mac' => $neg($x['mac']), 'extraMac' => array_map($neg, $x['extraMac'])];
    }

    public static function scaleAuth(array $x, \GMP $c): array
    {
        $k = MpcField::mod($c);
        return ['value' => self::scaleAll($x['value'], $k), 'mac' => self::scaleAll($x['mac'], $k),
            'extraMac' => array_map(fn(array $row): array => self::scaleAll($row, $k), $x['extraMac'])];
    }

    /** x + c for a PUBLIC constant c: c to one party's value share, alpha_i*c to every party's MAC share under every key. */
    public static function addPublicAuth(array $x, \GMP $c, array $ctx): array
    {
        $n = $ctx['n'];
        if (count($x['value']) !== $n || count($x['mac']) !== $n || count($ctx['alphaShares']) !== $n) {
            throw new \InvalidArgumentException('addPublicAuth: shared value and MAC context disagree on the party count');
        }
        if (count($x['extraMac']) !== count($ctx['extraKeys'])) {
            throw new \InvalidArgumentException('addPublicAuth: shared value and MAC context disagree on the key count');
        }
        $k = MpcField::mod($c);
        $value = $x['value'];
        $value[0] = MpcField::fadd($value[0], $k);
        $mac = [];
        for ($i = 0; $i < $n; $i++) {
            $mac[] = MpcField::fadd($x['mac'][$i], MpcField::fmul($ctx['alphaShares'][$i], $k));
        }
        $extra = [];
        foreach ($x['extraMac'] as $l => $row) {
            $key = $ctx['extraKeys'][$l];
            if (count($row) !== $n || count($key['alphaShares']) !== $n) {
                throw new \InvalidArgumentException('addPublicAuth: extra MAC party count mismatch');
            }
            $r = [];
            for ($i = 0; $i < $n; $i++) {
                $r[] = MpcField::fadd($row[$i], MpcField::fmul($key['alphaShares'][$i], $k));
            }
            $extra[] = $r;
        }
        return ['value' => $value, 'mac' => $mac, 'extraMac' => $extra];
    }

    public static function notBitAuth(array $b, array $ctx): array
    {
        return self::addPublicAuth(self::negAuth($b), gmp_init(1), $ctx);
    }

    public static function genAuthTriple(array $ctx, MpcFieldRng $rng): array
    {
        $a = $rng->next();
        $b = $rng->next();
        $as = self::authShare($a, $ctx, $rng);
        $bs = self::authShare($b, $ctx, $rng);
        $cs = self::authShare(MpcField::fmul($a, $b), $ctx, $rng);
        return ['a' => $as, 'b' => $bs, 'c' => $cs];
    }

    /** @param ?array $fault a DealerFault */
    public static function genTripleWithPartners(array $ctx, MpcFieldRng $rng, int $partners = self::SACRIFICE_PARTNERS, ?array $fault = null): array
    {
        if ($partners < 1 || $partners > 8) {
            throw new \InvalidArgumentException('genTripleWithPartners: partners must be in [1, 8]');
        }
        $zero = gmp_init(0);
        $a = $rng->next();
        $b = $rng->next();
        $bSV = self::authShare($b, $ctx, $rng);
        $kd = $fault !== null && ($fault['keepCDelta'] ?? null) !== null ? $fault['keepCDelta'] : $zero;
        $keepA = self::authShare($a, $ctx, $rng);
        $keepC = self::authShare(MpcField::fadd(MpcField::fmul($a, $b), $kd), $ctx, $rng);
        $keep = ['a' => $keepA, 'b' => $bSV, 'c' => $keepC];
        $pc = $fault['partnerCDelta'] ?? null;
        $ps = [];
        for ($r = 0; $r < $partners; $r++) {
            $ah = $rng->next();
            $pd = $pc !== null && $r < count($pc) && $pc[$r] !== null ? $pc[$r] : $zero;
            $pa = self::authShare($ah, $ctx, $rng);
            $pcs = self::authShare(MpcField::fadd(MpcField::fmul($ah, $b), $pd), $ctx, $rng);
            $ps[] = ['a' => $pa, 'b' => $bSV, 'c' => $pcs];
        }
        return ['keep' => $keep, 'partners' => $ps];
    }

    /** @param list<GMP> $x @param list<GMP> $y */
    private static function sameValues(array $x, array $y): bool
    {
        if (count($x) !== count($y)) {
            return false;
        }
        foreach ($x as $i => $xi) {
            if (gmp_cmp($xi, $y[$i]) !== 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Sacrifice check: certifies the kept triples or throws MpcMacCheckAbort, emitting nothing.
     *
     * @param list<array> $batch TripleWithPartners @param list<array> $deviations @return list<array> AuthTriple
     */
    public static function sacrificeVerify(array $batch, array $ctx, MpcFieldRng $rng, array $deviations): array
    {
        $engine = new MpcSpdzEngine($ctx, $deviations);
        $taus = [];
        foreach ($batch as $t) {
            $keep = $t['keep'];
            if (count($t['partners']) < 1) {
                throw new MpcMacCheckAbort('sacrifice: a triple without partners cannot be certified');
            }
            foreach ($t['partners'] as $sac) {
                if (!self::sameValues($sac['b']['value'], $keep['b']['value'])) {
                    throw new MpcMacCheckAbort('sacrifice: partner does not share b with the triple');
                }
                $e = $rng->next();
                if (gmp_sign($e) === 0) {
                    $e = gmp_init(1);
                }
                $rho = $engine->open(self::subAuth(self::scaleAuth($keep['a'], $e), $sac['a']), 'sacrifice:rho');
                $tau = self::subAuth(self::scaleAuth($keep['c'], $e), $sac['c']);
                $tau = self::subAuth($tau, self::scaleAuth($keep['b'], $rho));
                $taus[] = $engine->open($tau, 'sacrifice:tau');
            }
        }
        $engine->macCheck($rng);
        foreach ($taus as $t) {
            if (gmp_sign($t) !== 0) {
                throw new MpcMacCheckAbort('Beaver-triple sacrifice FAILED: residual tau=' . gmp_strval($t) . ' != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted');
            }
        }
        return array_map(static fn(array $t): array => $t['keep'], $batch);
    }

    /**
     * Arithmetic core of the batched MAC-check over an arbitrary modulus p; returns sigma[key][party].
     *
     * @param list<list<\GMP>> $alphaShares @param list<array> $opened OpenedValue @param list<list<\GMP>> $challenges @return list<list<\GMP>>
     */
    public static function macResiduals(\GMP $p, array $alphaShares, array $opened, array $challenges): array
    {
        $out = [];
        foreach ($alphaShares as $l => $alphas) {
            $r = $challenges[$l];
            $a = gmp_init(0);
            foreach ($opened as $j => $o) {
                $a = gmp_mod(gmp_add($a, gmp_mul($r[$j], $o['value'])), $p);
            }
            $row = [];
            foreach ($alphas as $i => $alpha) {
                $gamma = gmp_init(0);
                foreach ($opened as $j => $o) {
                    $gamma = gmp_mod(gmp_add($gamma, gmp_mul($r[$j], $o['macShares'][$l][$i])), $p);
                }
                $row[] = gmp_mod(gmp_sub($gamma, gmp_mul($alpha, $a)), $p);
            }
            $out[] = $row;
        }
        return $out;
    }

    /** Authenticated Beaver multiplication consuming $triple; the d and e openings are recorded for the MAC-check. */
    public static function beaverMulAuth(array $x, array $y, array $triple, array $ctx, MpcSpdzEngine $engine, string $label): array
    {
        self::requireSame($x, $triple['a']);
        self::requireSame($x, $triple['b']);
        self::requireSame($x, $triple['c']);
        self::requireSame($x, $y);
        $d = $engine->open(self::subAuth($x, $triple['a']), $label . ':d');
        $e = $engine->open(self::subAuth($y, $triple['b']), $label . ':e');
        $z = self::addAuth($triple['c'], self::addAuth(self::scaleAuth($triple['b'], $d), self::scaleAuth($triple['a'], $e)));
        return self::addPublicAuth($z, MpcField::fmul($d, $e), $ctx);
    }

    public static function authValue(array $x): \GMP
    {
        $a = gmp_init(0);
        foreach ($x['value'] as $s) {
            $a = MpcField::fadd($a, $s);
        }
        return $a;
    }

    /** SHA-256 binding commitment to a field element under a nonce. */
    public static function commit(\GMP $value, \GMP $nonce): string
    {
        return hash('sha256', gmp_strval($value, 16) . ':' . gmp_strval($nonce, 16));
    }

    private static function requireSame(array $x, array $y): void
    {
        if (count($x['value']) !== count($y['value']) || count($x['mac']) !== count($y['mac'])) {
            throw new \InvalidArgumentException('authenticated shared values must have the same party count');
        }
        if (count($x['extraMac']) !== count($y['extraMac'])) {
            throw new \InvalidArgumentException('authenticated shared values must carry the same number of MAC keys');
        }
        foreach ($x['extraMac'] as $l => $row) {
            if (count($row) !== count($y['extraMac'][$l])) {
                throw new \InvalidArgumentException('authenticated shared values must have the same party count');
            }
        }
    }
}
