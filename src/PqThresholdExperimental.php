<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * EXPERIMENTAL, NOT PRODUCTION. NO SECURITY PROOF. TIMING-UNSAFE. RESEARCH / INTEROP ONLY (the reference's `experimental` namespace of the pq-threshold package).
 *
 * A Raccoon / Ringtail-style LATTICE-THRESHOLD design plus a TOY additive secret-sharing sketch. It documents the trustless post-quantum threshold future and
 * gives a minimal interop toy; it is not a signature scheme. The sharing is n-of-n over Z_q (every share is required to reconstruct) and nothing here may
 * sign. The shippable post-quantum threshold is the hybrid in {@see FrostPq} (a classical FROST threshold plus an ML-DSA co-signature quorum). Every function
 * is gated behind an explicit opt-in and refuses with the banner without it (fail closed).
 */
final class PqThresholdExperimental
{
    public const BANNER = 'EXPERIMENTAL — NOT PRODUCTION. No security proof, timing-unsafe, for research/interop only. '
        . 'The shippable post-quantum threshold step-up is the HYBRID (classical FROST threshold + ML-DSA '
        . 'co-signature quorum) in @atlasauth/pca-pq-threshold; do NOT use this lattice-threshold prototype to sign.';

    /** Toy lattice parameters: a tiny modulus for demonstration (the ML-DSA modulus only so the arithmetic looks familiar). */
    public const TOY_DEFAULT_PARAMS = ['q' => 8380417, 'dim' => 4];

    /** A documented spec of the research design: DATA describing the approach, it performs no cryptography. */
    public static function raccoonDesign(): array
    {
        return [
            'scheme' => 'Raccoon/Ringtail-style lattice threshold (RESEARCH)',
            'status' => 'research-prototype',
            'productionReady' => false,
            'banner' => self::BANNER,
            'assumption' => 'Module-LWE / Module-SIS (the same lattice assumptions as ML-DSA / FIPS-204), believed hard for quantum adversaries.',
            'construction' => [
                '1. Distributed key generation: the signing key (a short vector / small polynomial) is SECRET-SHARED across n parties — Raccoon uses additive masking; Ringtail layers a one-time additive mask over a replicated/Shamir-style sharing to reach genuine t-of-n.',
                '2. Each party holds a share s_i such that the shares combine (additively, mod q, per coefficient) to the signing key s.',
                '3. Signing is a masked, multi-round protocol: parties jointly sample commitment randomness, each adds Gaussian NOISE FLOODING to its partial response so the partials leak nothing about the individual shares, and the masked partials are summed.',
                '4. The combined response is accepted only if it passes the standard ML-DSA-style rejection-sampling bound; otherwise the round restarts. The output is a single signature verifiable under ONE ordinary ML-DSA-style public key.',
                '5. A quantum break of a CLASSICAL threshold does not help here — forging requires solving the underlying lattice problem.',
            ],
            'whyNoLibraryYet' => [
                'Distributed discrete Gaussian / noise-flooding sampling with the right parameters is subtle and unimplemented in any audited library.',
                'Parameter selection for the threshold setting is still moving; interop test vectors are not standardised.',
                'No constant-time, side-channel-hardened reference implementation has been published and audited.',
                'The abort/restart rejection-sampling rounds complicate liveness and make a robust networked coordinator non-trivial.',
            ],
            'shippableAlternative' => 'Use the HYBRID in @atlasauth/pca-pq-threshold: a classical FROST(Ed25519) t-of-n threshold AND a pqT-of-m ML-DSA-65 co-signature quorum over the same action. It is post-quantum-protected TODAY (a classical threshold break cannot forge the step-up without ALSO forging the ML-DSA quorum) using only audited, available primitives.',
            'parameterSets' => [
                ['name' => 'Raccoon-128 (illustrative)', 'nistCategory' => 1, 'note' => 'Research parameters only; not implemented here.'],
                ['name' => 'Raccoon-192 (illustrative)', 'nistCategory' => 3, 'note' => 'Matches ML-DSA-65 category; not implemented here.'],
            ],
            'references' => [
                'Raccoon: a side-channel-resilient lattice signature (NIST additional-signatures submission).',
                'Ringtail: two-round threshold signatures from lattices.',
                'FIPS-204 (ML-DSA) — the single-party base scheme the threshold variants mirror.',
            ],
        ];
    }

    /** The explicit, loud opt-in: `['iUnderstandThisIsNotProduction' => true]` (or an Obj with it); anything else, including false or absent, refuses. */
    private static function assertOptIn(mixed $optIn): void
    {
        if (Js::opt($optIn, 'iUnderstandThisIsNotProduction') !== true) {
            throw new \RuntimeException(self::BANNER . ' Pass { iUnderstandThisIsNotProduction: true } to proceed.');
        }
    }

    private static function mod(int $x, int $q): int
    {
        $r = $x % $q;
        return $r < 0 ? $r + $q : $r;
    }

    /**
     * Additively secret-share a toy lattice key vector into `$n` shares over Z_q, per coefficient: shares 1..n-1 are random, the last absorbs the remainder so
     * the shares sum to the key (mod q). n-of-n, NOT t-of-n and NOT a signature scheme. `$params`: `['q' => int, 'dim' => int]`; `$sampler`: `fn(int $q): int`
     * (default: the OS random source), any value it returns is reduced mod q.
     * @param list<int> $key
     * @param array{q:int,dim:int} $params
     * @return list<array{index:int,coeffs:list<int>}>
     */
    public static function additiveShareLatticeKey(array $key, int $n, mixed $optIn, array $params = self::TOY_DEFAULT_PARAMS, ?\Closure $sampler = null): array
    {
        self::assertOptIn($optIn);
        if ($n < 1 || $n > 1024) {
            throw new \RangeException('additiveShareLatticeKey: n must be an integer in [1, 1024]');
        }
        if (!array_is_list($key) || count($key) !== $params['dim']) {
            throw new \RangeException("additiveShareLatticeKey: key must have {$params['dim']} coefficients");
        }
        $q = $params['q'];
        $sampler ??= static fn(int $m): int => random_int(0, $m - 1);
        $shares = array_fill(0, $n, array_fill(0, $params['dim'], 0));
        for ($c = 0; $c < $params['dim']; $c++) {
            $target = self::mod($key[$c], $q);
            $running = 0;
            for ($i = 0; $i < $n - 1; $i++) {
                $r = self::mod($sampler($q), $q);
                $shares[$i][$c] = $r;
                $running = self::mod($running + $r, $q);
            }
            $shares[$n - 1][$c] = self::mod($target - $running, $q);
        }
        $out = [];
        foreach ($shares as $i => $coeffs) {
            $out[] = ['index' => $i + 1, 'coeffs' => $coeffs];
        }
        return $out;
    }

    /**
     * Reconstruct the toy lattice key by summing ALL shares' coefficient vectors mod q (n-of-n: every share must be present, no index twice).
     * @param list<array{index:int,coeffs:list<int>}> $shares
     * @param array{q:int,dim:int} $params
     * @return list<int>
     */
    public static function reconstructLatticeKey(array $shares, mixed $optIn, array $params = self::TOY_DEFAULT_PARAMS): array
    {
        self::assertOptIn($optIn);
        if ($shares === []) {
            throw new \RangeException('reconstructLatticeKey: need at least one share');
        }
        if (count(array_unique(array_column($shares, 'index'))) !== count($shares)) {
            throw new \RangeException('reconstructLatticeKey: duplicate share index');
        }
        $out = array_fill(0, $params['dim'], 0);
        foreach ($shares as $s) {
            if (!is_array($s['coeffs']) || count($s['coeffs']) !== $params['dim']) {
                throw new \RangeException('reconstructLatticeKey: a share has the wrong dimension');
            }
            for ($c = 0; $c < $params['dim']; $c++) {
                $out[$c] = self::mod($out[$c] + $s['coeffs'][$c], $params['q']);
            }
        }
        return $out;
    }
}
