<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';

/**
 * The deterministic exports of the reference's invariant harness: key pairs from seeds, the legal-chain builder (a signed,
 * attenuating delegation chain from a model of caveat specs), the risk "worsen" helper and the registry constants. The property
 * generators, the properties and the checkInvariants runner live in InvariantsArbitraries / InvariantsProps (own seeded PRNG: the
 * reference's property-testing library has no PHP counterpart).
 */
final class Invariants
{
    public const DEFAULT_SEED = 20260108;
    public const DEFAULT_NUM_RUNS = 1000;
    public const INVARIANT_NAMES = [
        'attenuation-monotonicity', 'risk-wellformed-and-monotone', 'admission-soundness', 'cumulative-budget-bound',
        'fail-closed:undecidable-leaf', 'fail-closed:undecidable-groups', 'fail-closed:member-of-cycle-safe', 'fail-closed:unknown-caveat-type',
        'fail-closed:forged-chain-rejected', 'fail-closed:garbage-chain-rejected', 'forbid-monotone', 'determinism',
    ];
    private const BUDGET_ALLOC_BASE = 1_000_000;

    /** Any 32 bytes is a valid Ed25519 secret. @return array{secretKey:string,publicKey:string,pub:string,signer:KeyPair} raw bytes except `pub` (base64url) */
    public static function keyPairFromSeed(string $seed): array
    {
        $signer = new KeyPair($seed);
        return ['secretKey' => $seed, 'publicKey' => (string)Pca::unb64u($signer->public), 'pub' => $signer->public, 'signer' => $signer];
    }

    private static function f(mixed $v): float
    {
        return (float)Js::num($v);
    }

    /** @param array{running:float|int} $alloc */
    private static function specToCaveat(Obj $s, array &$alloc): Obj
    {
        $k = $s->get('k');
        switch ($k) {
            case 'expires':
            case 'not_before':
                return Obj::of(['type' => $k, 'at' => $s->get('at')]);
            case 'rate':
                return Obj::of(['type' => 'rate', 'max' => $s->get('max'), 'per_secs' => $s->get('per_secs')]);
            case 'max_blast_radius':
                return Obj::of(['type' => 'max_blast_radius', 'max' => $s->get('max')]);
            case 'reversibility_max':
                return Obj::of(['type' => 'reversibility_max', 'class' => $s->get('cls')]);
            case 'delegation_depth':
                return Obj::of(['type' => 'delegation_depth', 'max' => $s->get('max')]);
            case 'budget_frac':
                $base = is_finite((float)$alloc['running']) ? $alloc['running'] : self::BUDGET_ALLOC_BASE;
                // frac in [0,1] and base a non-negative integer: an integer <= the previous allocation (monotone, canonical-wire-safe)
                $limit = (int)floor($base * self::f($s->get('frac')));
                $alloc['running'] = $limit;
                return Obj::of(['type' => 'budget_alloc', 'limit' => $limit]);
        }
        throw new \InvalidArgumentException('unknown caveat spec ' . Js::str($k));
    }

    /**
     * A signed, legally-attenuating chain from a model {principalSeed, holder0Seed, rootSpecs, hops: [{holderSeed, addedSpecs}],
     * predicates} (seeds are raw bytes). @return array{caps:list<Obj>,predicates:mixed,rootIssuer:string,holders:list<string>}
     */
    public static function buildChain(Obj $m): array
    {
        $alloc = ['running' => INF];
        $principal = self::keyPairFromSeed($m->get('principalSeed'));
        $holder0 = self::keyPairFromSeed($m->get('holder0Seed'));
        $root = Sign::mintRoot($principal['signer'], $holder0['pub'], array_map(function ($s) use (&$alloc): Obj {
            return self::specToCaveat($s, $alloc);
        }, $m->get('rootSpecs')));
        $caps = [$root];
        $holders = [$holder0['pub']];
        $prev = $root;
        $signer = $holder0['signer']; // the next hop is signed by the key the parent is bound to
        foreach ($m->get('hops') as $hop) {
            $to = self::keyPairFromSeed($hop->get('holderSeed'));
            $added = [];
            foreach ($hop->get('addedSpecs') as $s) {
                $added[] = self::specToCaveat($s, $alloc);
            }
            $cap = Sign::delegate($prev, $signer, $to['pub'], $added);
            $caps[] = $cap;
            $holders[] = $to['pub'];
            $prev = $cap;
            $signer = $to['signer'];
        }
        return ['caps' => $caps, 'predicates' => $m->get('predicates'), 'rootIssuer' => $principal['pub'], 'holders' => $holders];
    }

    private static function clamp01(float $x): float
    {
        return $x < 0 ? 0.0 : ($x > 1 ? 1.0 : $x);
    }

    /** A risk input >= `base` in every risk-increasing axis and <= in every protective axis. */
    public static function worsen(Obj $base, Obj $d): Obj
    {
        $b = static fn(string $k): float => self::f($base->get($k));
        $x = static fn(string $k): float => self::f($d->get($k));
        return Obj::of([
            'semanticDistance' => self::clamp01($b('semanticDistance') + $x('dSem')),
            'blastRadius' => self::clamp01($b('blastRadius') + $x('dBlast')),
            'taint' => self::clamp01($b('taint') + $x('dTaint')),
            'age' => self::clamp01($b('age') + $x('dAge')),
            'reversibility' => self::clamp01($b('reversibility') - $x('dRev')),
            'confidence' => self::clamp01($b('confidence') - $x('dConf')),
        ]);
    }
}
