<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/IntentLearner.php';

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Wallet.php';
require_once __DIR__ . '/WalletOmega.php';

/**
 * Opt-in, privacy-preserving population priors for the wallet (PCA Intent Layer v2): one vote per principal, cell and period; a
 * central (epsilon, delta)-DP Gaussian release; local-DP randomized response; the mixture prior for the learner (the reference's
 * pca-wallet population). Votes, releases and priors are objects with the reference's member names; the randomness source is an
 * injected Closure returning a uniform float.
 */
final class WalletPopulation
{
    public const POPULATION_VOTE_DOMAIN = 'atlas-pca/intent-population-cell/v1';
    public const BETA_MAX = 0.9;

    public static function jsRound(float $x): int
    {
        $f = floor($x);
        return (int)($x - $f >= 0.5 ? $f + 1 : $f);
    }

    private static function isInteger(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f);
    }

    private static function f(mixed $x): float
    {
        $f = Js::num($x);
        if ($f === null) {
            throw new \TypeError('a number is required');
        }
        return $f;
    }

    /**
     * The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb.
     * @param list<int> $idx
     */
    public static function populationCellKey(mixed $schemaDigest, mixed $vs, array $idx): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::POPULATION_VOTE_DOMAIN, 's' => $schemaDigest, 'v' => Js::opt($vs, 'verb'), 'c' => Wallet::coordsOfCell($vs, $idx)]));
    }

    /** Uniform (0, 1) from 53 random bits of the OS CSPRNG. */
    public static function cryptoRand(): float
    {
        $b = (self::$randomBytesHook ?? random_bytes(...))(8);
        $hi = (int)unpack('N', substr($b, 0, 4))[1] >> 5;
        $lo = (int)unpack('N', substr($b, 4, 4))[1] >> 6;
        return ($hi * 67108864 + $lo + 0.5) / 9007199254740992;
    }

    /** A standard normal draw (Box-Muller) from a uniform source. */
    public static function gaussian(\Closure $rand): float
    {
        $u = $rand();
        while ($u <= 0) {
            $u = $rand();
        }
        $v = $rand();
        return sqrt(-2 * log($u)) * cos(2 * M_PI * $v);
    }

    /** Sigma of the Gaussian mechanism for L2 sensitivity (requires epsilon in (0, 1), delta in (0, 1)). */
    public static function gaussianSigma(mixed $epsilon, mixed $delta, mixed $l2Sensitivity): float
    {
        $e = self::f($epsilon);
        $d = self::f($delta);
        $s = self::f($l2Sensitivity);
        if (!($e > 0 && $e < 1)) {
            throw new \InvalidArgumentException('gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)');
        }
        if (!($d > 0 && $d < 1)) {
            throw new \InvalidArgumentException('gaussianSigma: delta must be in (0, 1)');
        }
        if (!($s > 0)) {
            throw new \InvalidArgumentException('gaussianSigma: sensitivity must be > 0');
        }
        return fdiv($s * sqrt(2 * log(1.25 / $d)), $e);
    }

    // ---- local DP ------------------------------------------------------------------------------------------------------------

    public static function rrKeepProbability(mixed $epsilon): float
    {
        $e = self::f($epsilon);
        if (!($e > 0 && is_finite($e))) {
            throw new \InvalidArgumentException('randomized response: epsilon must be > 0');
        }
        return exp($e) / (1 + exp($e));
    }

    /** epsilon-LDP randomized response: report y with probability e^eps/(1+e^eps), else 1 - y. */
    public static function randomizedResponse(mixed $y, mixed $epsilon, ?\Closure $rand = null): mixed
    {
        $rand ??= self::cryptoRand(...);
        return $rand() < self::rrKeepProbability($epsilon) ? $y : 1 - self::f($y);
    }

    /** Unbiased estimate of the true yes-rate from randomized reports: (ybar - (1 - p)) / (2p - 1). */
    public static function debiasRandomizedResponse(mixed $yesReports, mixed $total, mixed $epsilon): float
    {
        if (!(self::isInteger($yesReports) && self::isInteger($total) && self::f($total) > 0 && self::f($yesReports) >= 0 && self::f($yesReports) <= self::f($total))) {
            throw new \InvalidArgumentException('debias: bad counts');
        }
        $p = self::rrKeepProbability($epsilon);
        return fdiv(fdiv(self::f($yesReports), self::f($total)) - (1 - $p), 2 * $p - 1);
    }

    // ---- the mixture prior ---------------------------------------------------------------------------------------------------

    /**
     * The learner's priorMix for a release: weight(theta) = prod_c q_c^{1[c in theta]} (1 - q_c)^{1[c not in theta]} over the released
     * cells of the verb (unreleased cells contribute the constant 1/2 and drop out), mixed with weight beta <= BETA_MAX < 1.
     * @return array{beta:mixed,weight:\Closure(mixed,\Closure):float}
     */
    public static function populationPrior(mixed $release, mixed $beta): array
    {
        $b = self::f($beta);
        if (!($b >= 0 && $b <= self::BETA_MAX)) {
            throw new \InvalidArgumentException('populationPrior: beta must be in [0, ' . self::BETA_MAX . '] (full support needs beta < 1)');
        }
        $cache = new \SplObjectStorage();
        $tables = static function (mixed $vs) use ($release, $cache): array {
            if (is_object($vs) && $cache->contains($vs)) {
                return $cache[$vs];
            }
            $t = ['cells' => [], 'lq' => [], 'lnq' => []];
            $cells = Wallet::req($release, 'cells');
            $n = WalletOmega::verbCellCount($vs);
            for ($c = 0; $c < $n; $c++) {
                $key = self::populationCellKey(Wallet::req($release, 'schema'), $vs, WalletOmega::decodeCell($vs, $c));
                $r = Wallet::g($cells, $key);
                if (!Jsx::truthy($r)) {
                    continue;
                }
                $q = self::f(Wallet::req($r, 'q'));
                $t['cells'][] = $c;
                $t['lq'][] = log($q);
                $t['lnq'][] = log(1 - $q);
            }
            if (is_object($vs)) {
                $cache[$vs] = $t;
            }
            return $t;
        };
        $weight = static function (mixed $vs, \Closure $contains) use ($tables): float {
            $t = $tables($vs);
            $lw = 0.0;
            foreach ($t['cells'] as $i => $c) {
                $lw += $contains($c) ? $t['lq'][$i] : $t['lnq'][$i];
            }
            return exp($lw);
        };
        return ['beta' => $beta, 'weight' => $weight];
    }

    /** @internal Test seam: when set, cryptoRand reads its random bytes from it (callable(int $length): string) instead of random_bytes. */
    public static ?\Closure $randomBytesHook = null;
}

/** One vote per principal and cell and period; the central (epsilon, delta)-DP release of the noisy per-cell yes-rates. */
final class PopulationAggregator
{
    private mixed $schemaDigest;
    private mixed $period;
    private mixed $maxCells;
    private \Closure $rand;
    /** @var array<string,array{key:mixed,yes:float,total:float}> */
    private array $votes = [];
    /** @var array<string,array<string,bool>> */
    private array $perPrincipal = [];

    /** Options (an Obj or an assoc array): maxCellsPerPrincipal, rand. */
    public function __construct(mixed $schemaDigest, mixed $period, mixed $opts = null)
    {
        if (!Wallet::isB64u32($schemaDigest)) {
            throw new \InvalidArgumentException('PopulationAggregator: schemaDigest must be a canonical b64u digest');
        }
        $this->schemaDigest = $schemaDigest;
        $this->period = $period;
        $mc = Js::opt($opts, 'maxCellsPerPrincipal');
        $this->maxCells = $mc ?? 32;
        $m = Js::num($this->maxCells);
        if ($m === null || !is_finite($m) || $m != floor($m) || !($m > 0)) {
            throw new \InvalidArgumentException('PopulationAggregator: maxCellsPerPrincipal must be a positive integer');
        }
        $rand = Js::opt($opts, 'rand');
        $this->rand = $rand ?? WalletPopulation::cryptoRand(...);
    }

    /** A set key: a hashable JSON scalar (an object or array is unhashable and throws). */
    private static function setKey(mixed $k): string
    {
        if ($k === null) {
            return 'z';
        }
        if (is_string($k)) {
            return 's:' . $k;
        }
        if (is_bool($k)) {
            return $k ? 'n:1' : 'n:0'; // True == 1 as a Python set member
        }
        if (Js::isNum($k)) {
            return 'n:' . Js::stringify($k);
        }
        throw new \TypeError('unhashable type');
    }

    /** Accept a vote; refuses a second vote on a cell, a vote past the per-principal cell cap, or a foreign schema/period. */
    public function contribute(mixed $v): array
    {
        if (!Wallet::isDict($v)) {
            throw new \TypeError('a vote must be an object');
        }
        if (Js::opt($v, 'schemaDigest') !== $this->schemaDigest) {
            return ['ok' => false, 'reason' => 'vote for another schema'];
        }
        $period = Js::opt($v, 'period');
        if (!self::sameJson($period, $this->period) || is_bool($period)) {
            return ['ok' => false, 'reason' => 'vote for another period'];
        }
        $y = Js::opt($v, 'y');
        if (!(Js::isNum($y) && (Js::num($y) === 0.0 || Js::num($y) === 1.0))) {
            return ['ok' => false, 'reason' => 'y must be 0 or 1'];
        }
        $principal = Js::opt($v, 'principal');
        if (!is_string($principal) || $principal === '') {
            return ['ok' => false, 'reason' => 'an accountable principal is required'];
        }
        $key = Js::opt($v, 'cellKey');
        $sk = self::setKey($key);
        $mine = $this->perPrincipal[$principal] ?? [];
        if (isset($mine[$sk])) {
            return ['ok' => false, 'reason' => 'one vote per principal per cell per period (sensitivity 1)'];
        }
        if (!(count($mine) < (float)Js::num($this->maxCells))) {
            return ['ok' => false, 'reason' => 'at most ' . Js::str($this->maxCells) . ' cells per principal per period'];
        }
        $mine[$sk] = true;
        $this->perPrincipal[$principal] = $mine;
        $c = $this->votes[$sk] ?? ['key' => $key, 'yes' => 0.0, 'total' => 0.0];
        $this->votes[$sk] = ['key' => $key, 'yes' => $c['yes'] + (float)Js::num($y), 'total' => $c['total'] + 1];
        return ['ok' => true];
    }

    private static function sameJson(mixed $a, mixed $b): bool
    {
        try {
            return Js::stringify($a) === Js::stringify($b);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * The (epsilon, delta)-DP release. Cells whose noisy count is below `minCount` are suppressed. Options: epsilon, delta, qMin,
     * minCount.
     */
    public function release(mixed $opts): Obj
    {
        $sensitivity = sqrt(2 * (float)Js::num($this->maxCells));
        $sigma = WalletPopulation::gaussianSigma(Wallet::req($opts, 'epsilon'), Wallet::req($opts, 'delta'), $sensitivity);
        $qMin = Js::opt($opts, 'qMin') === null ? 0.02 : self::num(Js::opt($opts, 'qMin'));
        if (!($qMin > 0 && $qMin < 0.5)) {
            throw new \InvalidArgumentException('release: qMin must be in (0, 0.5)');
        }
        $minCount = Js::opt($opts, 'minCount') === null ? 3 * $sigma : self::num(Js::opt($opts, 'minCount'));
        $cells = new Obj();
        $keys = [];
        foreach ($this->votes as $c) {
            if (!is_string($c['key'])) {
                throw new \TypeError('cell keys must be strings');
            }
            $keys[] = $c['key'];
        }
        usort($keys, static fn(string $a, string $b): int => strcmp((string)mb_convert_encoding($a, 'UTF-16BE', 'UTF-8'), (string)mb_convert_encoding($b, 'UTF-16BE', 'UTF-8')));
        foreach ($keys as $key) {
            $c = $this->votes['s:' . $key];
            $yes = $c['yes'] + $sigma * WalletPopulation::gaussian($this->rand);
            $total = $c['total'] + $sigma * WalletPopulation::gaussian($this->rand);
            if (!($total >= $minCount)) {
                continue;
            }
            $x = fdiv($yes, $total);
            $m = $x > $qMin ? $x : $qMin; // Python max(qMin, x)
            $hi = 1 - $qMin;
            $cells->set($key, Obj::of(['q' => $m < $hi ? $m : $hi, 'n' => WalletPopulation::jsRound($total)]));
        }
        return Obj::of([
            'v' => 1, 'kind' => 'pca-intent-population-prior', 'schema' => $this->schemaDigest, 'period' => $this->period,
            'epsilon' => Wallet::req($opts, 'epsilon'), 'delta' => Wallet::req($opts, 'delta'), 'sigma' => $sigma, 'sensitivity' => $sensitivity, 'cells' => $cells,
        ]);
    }

    /**
     * Mass (ppm) of cells admitted only because of the population prior: in the grant with the prior, not without it, after the same
     * observations. Zero at tau = 1 under noise-free answers. `$base` holds the learner options (without `priorMix`).
     * @param list<array<string,mixed>> $observations
     */
    public static function priorAdmittedPpm(mixed $omega, mixed $base, array $observations, mixed $mix): int
    {
        $rest = new Obj();
        foreach ($base instanceof Obj ? $base->keys() : array_keys((array)$base) as $k) {
            if ($k !== 'priorMix') {
                $rest->set((string)$k, Js::opt($base, (string)$k));
            }
        }
        $with = new Obj();
        foreach ($rest->keys() as $k) {
            $with->set($k, $rest->get($k));
        }
        $with->set('priorMix', $mix);
        $a = IntentLearner::replay($omega, $rest, $observations)->cells();
        $b = IntentLearner::replay($omega, $with, $observations)->cells();
        $mass = 0.0;
        foreach ($b as $i => $c) {
            if ($c['inGrant'] && !$a[$i]['inGrant']) {
                $mass += $c['mass'];
            }
        }
        return self::jsRound($mass * 1000000);
    }

    private static function num(mixed $v): float
    {
        $f = Js::num($v);
        if ($f === null) {
            throw new \TypeError('a number is required');
        }
        return $f;
    }
}
