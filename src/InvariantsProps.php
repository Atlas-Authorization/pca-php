<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Invariants.php';
require_once __DIR__ . '/InvariantsArbitraries.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/Risk.php';
require_once __DIR__ . '/ForbidCertificate.php';
require_once __DIR__ . '/Prohibitions.php';

/**
 * The PCA core safety invariants as runnable property checks plus the checkInvariants runner (the reference's properties.ts), over the
 * REAL native core: Sign (mint / delegate), Pca::verifyChain / evaluateCaveats, Predicates, Risk, ForbidCertificate, Prohibitions.
 *
 * Case generation: the reference drives these properties through fast-check, whose byte stream cannot be reproduced here and for which
 * PHP has no equivalent, so this runtime draws its own cases from {@see InvariantsRng} (mulberry32): ONE stream per property, seeded
 * from (seed, property index), `numRuns` cases each, over the same domains as the reference generators. Same seed => identical cases;
 * another seed => other cases. A failure is reported WITHOUT shrinking: {property, seed, counterexample, case}.
 *
 * Differences from the reference: the core's allocationsMonotone and envelopeCaveatEvaluator have no public PHP export, so the budget
 * allocation check is the chain verifier's own (it enforces it) plus the explicit numeric check, and an unknown caveat type is checked
 * through evaluateCaveats; safetyBound has no public export either, so bMax / kappa is computed here.
 */
final class InvariantFailure extends \RuntimeException
{
    /** @param array{property:string,seed:int,counterexample:string,case:int,error:?string} $report */
    public function __construct(string $message, public readonly array $report)
    {
        parent::__construct($message);
    }
}

final class InvariantsProps
{
    public const DEFAULT_SEED = 20260108;
    public const DEFAULT_NUM_RUNS = 1000;
    private const EPS = 1e-9;
    private const KNOWN_CAVEAT_TYPES = ['expires', 'not_before', 'rate', 'max_blast_radius', 'reversibility_max', 'delegation_depth', 'budget_alloc'];
    private const MUTATIONS = ['tamper-caveat', 'drop-leaf-caveat', 'swap-holder', 'break-parent', 'bad-sig', 'wrong-root-issuer',
        'suite-mismatch', 'break-id', 'append-forged-hop'];
    private const RANKS = ['deny' => 0, 'escalate' => 1, 'allow' => 2];
    private const RISK_KEYS = ['semanticDistance', 'reversibility', 'blastRadius', 'taint', 'confidence', 'age'];

    /** @var array<string,\Closure>|null the replaced core functions of {@see withCore} (null: the real core) */
    private static ?array $override = null;

    // ---- the core seam (so a deliberately broken core can be swapped in to prove the properties have teeth) ---------------------

    /** @return array<string,\Closure> */
    private static function realCore(): array
    {
        return [
            'buildChain' => static fn(Obj $m): array => Invariants::buildChain($m),
            'delegate' => static fn(Obj $parent, KeyPair $signer, string $to, array $added): Obj => Sign::delegate($parent, $signer, $to, $added),
            'verifyChain' => static function (array $caps, ?string $issuer): array {
                [$why, $ok] = Pca::verifyChain($caps, $issuer, $issuer !== null);
                return ['ok' => $ok, 'reason' => $why];
            },
            'evaluateCaveats' => static fn(array $caveats, Obj $ctx): array => Pca::evaluateCaveats($caveats, $ctx),
            'evaluatePredicates' => static fn(array $preds, Obj $ctx): array => Predicates::evaluatePredicates($preds, $ctx),
            'evaluateConditionTri' => static fn(mixed $c, Obj $ctx): string => Predicates::evaluateConditionTri($c, $ctx),
            'evaluateCondition' => static fn(mixed $c, Obj $ctx): bool => Predicates::evaluateCondition($c, $ctx),
            'riskScore' => static fn(array $inputs, array $weights): float => Risk::score($inputs, $weights),
            'requiredThreshold' => static fn(float $r, array $p): array => Risk::requiredThreshold($r, (float)$p['theta1'], (float)$p['theta2']),
            'admit' => static function (float $r, array $b, array $p): array {
                $rt = Risk::requiredThreshold($r, (float)$p['theta1'], (float)$p['theta2']);
                return Risk::admission($rt['t'], is_finite((float)$b['B']) && $b['B'] >= Risk::cost($r, (float)$p['kappa']));
            },
            'decideClauses' => static fn(array $clauses, Obj $ctx): array => ForbidCertificate::decide($clauses, $ctx),
        ];
    }

    /** The real implementation of one seam function (what a test patch wraps). */
    public static function real(string $name): \Closure
    {
        return self::realCore()[$name] ?? throw new \InvalidArgumentException("unknown core function $name");
    }

    private static function core(string $name): \Closure
    {
        return self::$override[$name] ?? self::real($name);
    }

    /** Runs `$body` with some core functions replaced (name => closure with the real one's signature); always restored. */
    public static function withCore(array $patch, \Closure $body): mixed
    {
        $prev = self::$override;
        self::$override = $patch + ($prev ?? []);
        try {
            return $body();
        } finally {
            self::$override = $prev;
        }
    }

    // ---- helpers ----------------------------------------------------------------------

    private static function verdictOk(array $v): bool
    {
        return ($v['ok'] ?? null) === true;
    }

    private static function f(mixed $v): float
    {
        return (float)Js::num($v);
    }

    /** Caveats of `child` must begin with the full caveat array of `parent` (append-only, order-preserving). */
    private static function prefixExtension(Obj $parent, Obj $child): bool
    {
        $pc = $parent->get('caveats');
        $cc = $child->get('caveats');
        if (!is_array($pc) || !is_array($cc) || count($cc) < count($pc)) {
            return false;
        }
        foreach ($pc as $j => $pj) {
            if (Pca::hashCanonical($cc[$j]) !== Pca::hashCanonical($pj)) {
                return false;
            }
        }
        return true;
    }

    /** @return list<float> numeric budget_alloc limits in caveat order */
    private static function allocLimits(array $caveats): array
    {
        $out = [];
        foreach ($caveats as $cv) {
            if ($cv instanceof Obj && $cv->get('type') === 'budget_alloc' && Js::isNum($cv->get('limit'))) {
                $out[] = self::f($cv->get('limit'));
            }
        }
        return $out;
    }

    /** Effective authority of a hop at a probe point: the envelope predicates AND every caveat satisfied. */
    private static function authAllowed(array $caveats, array $predicates, array $pt): bool
    {
        if (self::core('evaluatePredicates')($predicates, $pt['action'])['allowed'] !== true) {
            return false;
        }
        return self::core('evaluateCaveats')($caveats, $pt['cavCtx'])['ok'] === true;
    }

    /** @param array<string,float> $inputs @return array<string,float> */
    private static function worse(array $inputs, array $deltas): array
    {
        $w = Invariants::worsen(Obj::of($inputs), Obj::of($deltas));
        $out = [];
        foreach ($w->keys() as $k) {
            $out[$k] = (float)$w->get($k);
        }
        return $out;
    }

    /** The reference's safetyBound: bMax / kappa (0 for a non-positive kappa). */
    private static function safetyBound(array $p): float
    {
        return $p['kappa'] > 0 ? max(0.0, (float)$p['bMax']) / $p['kappa'] : 0.0;
    }

    private static function ctx(string $verb, string $resource, array $extra = []): Obj
    {
        $c = Obj::of(['action' => Obj::of(['verb' => $verb, 'resource' => $resource])]);
        foreach ($extra as $k => $v) {
            $c->set($k, $v);
        }
        return $c;
    }

    // ---- 1. attenuation monotonicity --------------------------------------------------

    /** For any legal chain: it verifies, each hop's caveats extend its parent's, allocations never grow, and per-hop authority never widens root to leaf. */
    private static function attenuation(array $a): bool
    {
        [$model, $points] = $a;
        $chain = self::core('buildChain')($model);
        $caps = $chain['caps'];
        if (!self::verdictOk(self::core('verifyChain')($caps, $chain['rootIssuer']))) {
            return false;
        }
        for ($i = 1; $i < count($caps); $i++) {
            if (!self::prefixExtension($caps[$i - 1], $caps[$i])) {
                return false;
            }
        }
        $leaf = $caps[count($caps) - 1];
        $limits = self::allocLimits($leaf->get('caveats'));
        for ($i = 1; $i < count($limits); $i++) {
            if ($limits[$i] > $limits[$i - 1]) {
                return false;
            }
        }
        foreach ($points as $pt) {
            $ancestorAllowed = true;
            foreach ($caps as $cap) {
                $allowed = self::authAllowed($cap->get('caveats'), $chain['predicates'], $pt);
                if ($allowed && !$ancestorAllowed) {
                    return false; // a true after a false would be a widening
                }
                $ancestorAllowed = $allowed;
            }
        }
        return true;
    }

    // ---- 2. budget soundness ----------------------------------------------------------

    /** The risk functional is clamped to [0, 1] and monotone: a pointwise-worse input never yields a lower r. */
    private static function riskMonotone(array $a): bool
    {
        [$policy, $inputs, $deltas] = $a;
        $score = self::core('riskScore');
        $r = $score($inputs, $policy['weights']);
        if (!($r >= 0 && $r <= 1)) {
            return false;
        }
        $rWorse = $score(self::worse($inputs, $deltas), $policy['weights']);
        if (!($rWorse >= 0 && $rWorse <= 1)) {
            return false;
        }
        return $rWorse + self::EPS >= $r;
    }

    /** Whenever admit lets an action proceed without a human, the admitted cost kappa*r is covered by the budget. */
    private static function admissionSoundness(array $a): bool
    {
        [$policy, $inputs, $budget] = $a;
        if (Sign::riskPolicyError($policy) !== null) {
            return false; // the generated policy must be well formed (self-check of the generator)
        }
        $r = self::core('riskScore')($inputs, $policy['weights']);
        $c = Risk::cost($r, $policy['kappa']);
        $adm = self::core('admit')($r, $budget, $policy);
        if ($adm['metered']) {
            if ($adm['t'] >= 3 || !($budget['B'] + self::EPS >= $c)) {
                return false;
            }
        }
        if ($adm['admit']) {
            if ($adm['t'] !== 1 || !$adm['metered'] || !($budget['B'] + self::EPS >= $c)) {
                return false;
            }
        }
        return true;
    }

    /** From a full budget, any sequence of machine-only actions debiting kappa*r never overdraws and keeps Sum(r) <= bMax/kappa. */
    private static function cumulativeBudgetBound(array $a): bool
    {
        [$policy, $seq] = $a;
        $bound = self::safetyBound($policy);
        $B = max(0.0, (float)$policy['bMax']);
        $sumR = 0.0;
        foreach ($seq as $inputs) {
            $r = self::core('riskScore')($inputs, $policy['weights']);
            $adm = self::core('admit')($r, ['B' => $B, 'tau' => 0, 'asOf' => 0], $policy);
            if ($adm['metered'] && $adm['t'] < 3) {
                $c = Risk::cost($r, $policy['kappa']);
                if (!($B + self::EPS >= $c)) {
                    return false;
                }
                $B = max(0.0, $B - $c);
                $sumR += $r;
                if ($B < -self::EPS) {
                    return false;
                }
                if (!($policy['kappa'] * $sumR <= $policy['bMax'] + 1e-6) || !($sumR <= $bound + 1e-6)) {
                    return false;
                }
            }
        }
        return true;
    }

    // ---- 3. fail closed ---------------------------------------------------------------

    /** Every structurally undecidable leaf evaluates to 'unknown' (never 'true'), so a predicate carrying it never grants. */
    private static function undecidableLeaf(array $a): bool
    {
        [$pick, $verb] = $a;
        $f = 'subject.role';
        $leaf = match ($pick) {
            0 => Obj::of(['field' => "$f.definitely_absent", 'op' => 'eq', 'value' => 'x']),
            1 => Obj::of(['field' => $f, 'op' => 'lt', 'value' => Sign::n(5)]),
            2 => Obj::of(['field' => $f, 'op' => 'in', 'value' => 'not-an-array']),
            3 => Obj::of(['field' => $f, 'op' => 'eq']),
            default => Obj::of(['field' => $f, 'op' => 'member_of', 'value' => 'g', 'collection' => 'env.no_such_collection']),
        };
        $ctx = self::ctx($verb, '/x', ['subject' => Obj::of(['role' => 'admin'])]);
        if (self::core('evaluateConditionTri')($leaf, $ctx) === 'true') {
            return false;
        }
        if (self::core('evaluateCondition')($leaf, $ctx) !== false) {
            return false;
        }
        $pred = Obj::of(['verb' => $verb, 'resource' => '/x', 'where' => [$leaf]]);
        return self::core('evaluatePredicates')([$pred], $ctx)['allowed'] === false;
    }

    /** not / all_of / any_of over undecidable or empty children fail closed (never 'true'). */
    private static function undecidableGroups(array $a): bool
    {
        $ctx = self::ctx('read', '/x', ['subject' => Obj::of(['role' => 'admin'])]);
        $bad = Obj::of(['field' => 'subject.role', 'op' => 'lt', 'value' => Sign::n(5)]); // a string compared with `lt` to a number
        $tri = self::core('evaluateConditionTri');
        foreach ([Obj::of(['not' => $bad]), Obj::of(['all_of' => []]), Obj::of(['any_of' => []]), Obj::of(['all_of' => [$bad]]), Obj::of(['any_of' => [$bad]])] as $c) {
            if ($tri($c, $ctx) === 'true') {
                return false;
            }
        }
        return true;
    }

    /** member_of over a cyclic adjacency terminates with a correct verdict; an unreachable target fails closed. */
    private static function memberOfCycleSafe(array $a): bool
    {
        [$target] = $a;
        $rel = Obj::of(['a' => ['b'], 'b' => ['a', 'c']]); // a -> b -> a is a cycle; c hangs off b; z is absent
        $ctx = self::ctx('read', '/x', ['subject' => Obj::of(['g' => 'a']), 'env' => Obj::of(['rel' => $rel])]);
        $tri = self::core('evaluateConditionTri')(Obj::of(['field' => 'subject.g', 'op' => 'member_of', 'value' => $target, 'collection' => 'env.rel']), $ctx);
        return $tri === (in_array($target, ['a', 'b', 'c'], true) ? 'true' : 'false');
    }

    /** An unknown caveat type is never satisfied, so a caveat set containing it is never ok. */
    private static function unknownCaveatType(array $a): bool
    {
        [$type, $now] = $a;
        return self::core('evaluateCaveats')([Obj::of(['type' => $type])], Sign::n(Obj::of(['now' => $now])))['ok'] === false;
    }

    /** @param list<Obj> $caps @return list<Obj> a deep copy */
    private static function cloneCaps(array $caps): array
    {
        return array_map(static fn(Obj $c): Obj => Sign::n($c), $caps);
    }

    /** A legal chain mutated by one of nine attacks never verifies. */
    private static function forgedChainRejected(array $a): bool
    {
        [$model, $mutation, $pick, $auxSeed] = $a;
        $chain = self::core('buildChain')($model);
        $caps = $chain['caps'];
        $verify = self::core('verifyChain');
        if (!self::verdictOk($verify($caps, $chain['rootIssuer']))) {
            return false; // the pristine chain must verify
        }
        $n = count($caps);
        $idx = $pick % $n;
        $aux = Invariants::keyPairFromSeed($auxSeed);
        $rejected = static fn(array $m, string $issuer): bool => ($verify($m, $issuer)['ok'] ?? null) === false;
        switch ($mutation) {
            case 'tamper-caveat':
                $m = self::cloneCaps($caps);
                $m[$idx]->set('caveats', [...$m[$idx]->get('caveats'), Sign::n(['type' => 'expires', 'at' => 999])]);
                return $rejected($m, $chain['rootIssuer']);
            case 'drop-leaf-caveat':
                $m = self::cloneCaps($caps);
                $cv = $m[$n - 1]->get('caveats');
                if ($cv === []) {
                    return true; // inapplicable: trivially pass
                }
                $m[$n - 1]->set('caveats', array_slice($cv, 0, count($cv) - 1));
                return $rejected($m, $chain['rootIssuer']);
            case 'swap-holder':
                $m = self::cloneCaps($caps);
                $m[$idx]->set('holder', $aux['pub']);
                return $rejected($m, $chain['rootIssuer']);
            case 'break-parent':
                if ($n < 2) {
                    return true; // no non-root hop to detach
                }
                $m = self::cloneCaps($caps);
                $m[max(1, $idx)]->set('parent', Pca::hashCanonical(Sign::n(['bogus' => strlen($auxSeed), 'tag' => 'not-a-real-parent'])));
                return $rejected($m, $chain['rootIssuer']);
            case 'bad-sig':
                $m = self::cloneCaps($caps);
                $m[$idx]->set('sig', Pca::b64u($aux['signer']->sign("\x01\x02\x03\x04"))); // well formed, but over other bytes by another key
                return $rejected($m, $chain['rootIssuer']);
            case 'wrong-root-issuer':
                return $aux['pub'] === $chain['rootIssuer'] ? true : $rejected($caps, $aux['pub']);
            case 'suite-mismatch':
                $m = self::cloneCaps($caps);
                $m[$idx]->set('alg', 'ml-dsa-65'); // the suite is bound into body_digest
                return $rejected($m, $chain['rootIssuer']);
            case 'break-id':
                $m = self::cloneCaps($caps);
                $m[$idx]->set('id', Pca::hashCanonical(Sign::n(['not' => 'the-body-digest', 'n' => $idx])));
                return $rejected($m, $chain['rootIssuer']);
            case 'append-forged-hop':
                // issued as if from the leaf, but signed by a key that is NOT the leaf's holder
                $forged = self::core('delegate')($caps[$n - 1], $aux['signer'], $aux['pub'], []);
                return $rejected([...$caps, $forged], $chain['rootIssuer']);
        }
        return false; // an unknown mutation name (cannot happen: fail closed)
    }

    /** Well-typed but never-signed chains (including the empty chain) never verify. */
    private static function garbageChainRejected(array $a): bool
    {
        [$garbage] = $a;
        return (self::core('verifyChain')($garbage, null)['ok'] ?? null) === false;
    }

    // ---- 4. determinism ---------------------------------------------------------------

    /** verifyChain, predicates, caveats, risk score, threshold and admission are all deterministic. */
    private static function determinism(array $a): bool
    {
        [$model, $pt, $preds, $policy, $inputs, $budget] = $a;
        $chain = self::core('buildChain')($model);
        $verify = self::core('verifyChain');
        $v1 = $verify($chain['caps'], $chain['rootIssuer']);
        $v2 = $verify($chain['caps'], $chain['rootIssuer']);
        if (($v1['ok'] ?? null) !== ($v2['ok'] ?? null) || ($v1['reason'] ?? null) !== ($v2['reason'] ?? null)) {
            return false;
        }
        $p1 = self::core('evaluatePredicates')($preds, $pt['action']);
        $p2 = self::core('evaluatePredicates')($preds, $pt['action']);
        if ($p1['allowed'] !== $p2['allowed'] || ($p1['reason'] ?? null) !== ($p2['reason'] ?? null)) {
            return false;
        }
        $leaf = $chain['caps'][count($chain['caps']) - 1];
        $c1 = self::core('evaluateCaveats')($leaf->get('caveats'), $pt['cavCtx']);
        $c2 = self::core('evaluateCaveats')($leaf->get('caveats'), $pt['cavCtx']);
        if ($c1['ok'] !== $c2['ok'] || implode('|', $c1['failed']) !== implode('|', $c2['failed'])) {
            return false;
        }
        $r1 = self::core('riskScore')($inputs, $policy['weights']);
        $r2 = self::core('riskScore')($inputs, $policy['weights']);
        if ($r1 !== $r2) {
            return false;
        }
        $t1 = self::core('requiredThreshold')($r1, $policy);
        $t2 = self::core('requiredThreshold')($r1, $policy);
        if ($t1['t'] !== $t2['t'] || $t1['proof'] !== $t2['proof'] || $t1['optimisticAllowed'] !== $t2['optimisticAllowed']) {
            return false;
        }
        $a1 = self::core('admit')($r1, $budget, $policy);
        $a2 = self::core('admit')($r1, $budget, $policy);
        return $a1['admit'] === $a2['admit'] && $a1['needStepUp'] === $a2['needStepUp'] && $a1['t'] === $a2['t'] && $a1['metered'] === $a2['metered'];
    }

    /** Forbid-wins is monotone and order-independent: adding a forbid never moves a decision up, a matching forbid always denies, clause order is irrelevant. */
    private static function forbidMonotone(array $a): bool
    {
        [$permits, $forbids, $extra, $pt, $rot] = $a;
        $mk = static function (string $kind, array $ps, string $tag): array {
            $out = [];
            foreach ($ps as $i => $when) {
                $out[] = Obj::of(['id' => $tag . $i, 'kind' => $kind, 'when' => $when]);
            }
            return $out;
        };
        $decide = self::core('decideClauses');
        $base = [...$mk('permit', $permits, 'p'), ...$mk('escalate', $extra, 'e')];
        $withForbid = [...$base, ...$mk('forbid', $forbids, 'f')];
        $before = $decide($base, $pt['action'])['decision'];
        $after = $decide($withForbid, $pt['action'])['decision'];
        if (self::RANKS[$after] > self::RANKS[$before]) {
            return false; // adding a forbid must never grow the admit set
        }
        foreach ($forbids as $when) {
            if (Prohibitions::whenMatches($when, $pt['action']) && $after !== 'deny') {
                return false; // a matching forbid beats every permit
            }
        }
        $k = $rot % count($withForbid);
        $rotated = [...array_slice($withForbid, $k), ...array_slice($withForbid, 0, $k)];
        return $decide($rotated, $pt['action'])['decision'] === $after; // order independent
    }

    // ---- registry ---------------------------------------------------------------------

    /**
     * Every invariant, in the reference's order: name, the case generator (draws one case's arguments from the property's stream) and the
     * check (true = the case passes). @return list<array{name:string,gen:\Closure,check:\Closure}>
     */
    private static function registry(): array
    {
        $A = InvariantsArbitraries::class;
        $points = static function (InvariantsRng $g) use ($A): array {
            $out = [];
            for ($n = $g->int(1, 5); $n > 0; $n--) {
                $out[] = $A::evalPoint($g);
            }
            return $out;
        };
        $unsigned = static function (InvariantsRng $g): Obj {
            $caveats = [];
            for ($n = $g->int(0, 3); $n > 0; $n--) {
                $caveats[] = Obj::of(['type' => $g->string(0, 10)]);
            }
            return Obj::of(['id' => $g->string(0, 10), 'issuer' => $g->string(0, 10), 'holder' => $g->string(0, 10), 'caveats' => $caveats,
                'body_digest' => $g->string(0, 10), 'sig' => $g->string(0, 10)]);
        };
        return [
            ['name' => 'attenuation-monotonicity', 'gen' => static fn(InvariantsRng $g): array => [$A::chainModel($g), $points($g)],
                'check' => self::attenuation(...)],
            ['name' => 'risk-wellformed-and-monotone', 'gen' => static fn(InvariantsRng $g): array => [$A::riskPolicy($g), $A::riskInputs($g), $A::riskDeltas($g)],
                'check' => self::riskMonotone(...)],
            ['name' => 'admission-soundness', 'gen' => static fn(InvariantsRng $g): array => [$A::riskPolicy($g), $A::riskInputs($g), $A::trustBudget($g)],
                'check' => self::admissionSoundness(...)],
            ['name' => 'cumulative-budget-bound', 'gen' => static function (InvariantsRng $g) use ($A): array {
                $policy = $A::riskPolicy($g);
                $seq = [];
                for ($n = $g->int(1, 40); $n > 0; $n--) {
                    $seq[] = $A::riskInputs($g);
                }
                return [$policy, $seq];
            }, 'check' => self::cumulativeBudgetBound(...)],
            ['name' => 'fail-closed:undecidable-leaf', 'gen' => static fn(InvariantsRng $g): array => [$g->int(0, 4), $g->pick(['read', 'write', 'delete'])],
                'check' => self::undecidableLeaf(...)],
            ['name' => 'fail-closed:undecidable-groups', 'gen' => static fn(InvariantsRng $g): array => [0], 'check' => self::undecidableGroups(...)],
            ['name' => 'fail-closed:member-of-cycle-safe', 'gen' => static fn(InvariantsRng $g): array => [$g->pick(['a', 'b', 'c', 'z'])],
                'check' => self::memberOfCycleSafe(...)],
            ['name' => 'fail-closed:unknown-caveat-type', 'gen' => static function (InvariantsRng $g): array {
                do {
                    $type = $g->string(1, 12);
                } while (in_array($type, self::KNOWN_CAVEAT_TYPES, true));
                return [$type, $g->intB(0, InvariantsArbitraries::MAX_TIME)];
            }, 'check' => self::unknownCaveatType(...)],
            ['name' => 'fail-closed:forged-chain-rejected', 'gen' => static fn(InvariantsRng $g): array => [$A::chainModel($g), $g->pick(self::MUTATIONS),
                $g->intB(0, 1_000_000), $A::seed32($g)], 'check' => self::forgedChainRejected(...)],
            ['name' => 'fail-closed:garbage-chain-rejected', 'gen' => static function (InvariantsRng $g) use ($unsigned): array {
                $caps = [];
                for ($n = $g->int(0, 4); $n > 0; $n--) {
                    $caps[] = $unsigned($g);
                }
                return [$caps];
            }, 'check' => self::garbageChainRejected(...)],
            ['name' => 'forbid-monotone', 'gen' => static fn(InvariantsRng $g): array => [$A::predicateList($g), $A::predicateList($g), $A::predicateList($g),
                $A::evalPoint($g), $g->int(0, 5)], 'check' => self::forbidMonotone(...)],
            ['name' => 'determinism', 'gen' => static fn(InvariantsRng $g): array => [$A::chainModel($g), $A::evalPoint($g), $A::predicateList($g),
                $A::riskPolicy($g), $A::riskInputs($g), $A::trustBudget($g)], 'check' => self::determinism(...)],
        ];
    }

    /** @return list<string> the invariant names, in run order */
    public static function names(): array
    {
        return array_map(static fn(array $p): string => $p['name'], self::registry());
    }

    /** A readable, bounded rendering of a case's arguments (raw bytes as hex). */
    private static function describe(mixed $v): string
    {
        $plain = static function (mixed $x) use (&$plain): mixed {
            if ($x instanceof Num) {
                return $x->isInt() ? $x->int() : $x->float();
            }
            if ($x instanceof Obj) {
                $o = [];
                foreach ($x->keys() as $k) {
                    $o[$k] = $plain($x->get($k));
                }
                return $o === [] ? new \stdClass() : $o;
            }
            if (is_array($x)) {
                return array_map($plain, $x);
            }
            if (is_string($x) && preg_match('//u', $x) !== 1) {
                return 'hex:' . bin2hex($x);
            }
            return $x;
        };
        $s = json_encode($plain($v), JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
        return strlen($s) > 4000 ? substr($s, 0, 4000) . '...' : $s;
    }

    /**
     * Runs one invariant over `$numRuns` cases of its stream; the first failing case throws {@see InvariantFailure} (no shrinking). A check
     * that throws counts as a failure.
     */
    public static function run(string $name, int $numRuns, int $seed): void
    {
        foreach (self::registry() as $index => $p) {
            if ($p['name'] !== $name) {
                continue;
            }
            $g = InvariantsRng::forProperty($seed, $index);
            for ($i = 0; $i < $numRuns; $i++) {
                $args = $p['gen']($g);
                $error = null;
                try {
                    $ok = $p['check']($args) === true;
                } catch (\Throwable $e) {
                    $ok = false;
                    $error = get_class($e) . ': ' . $e->getMessage();
                }
                if (!$ok) {
                    $ce = self::describe($args);
                    throw new InvariantFailure("invariant $name failed at case $i (seed $seed)" . ($error === null ? '' : ": $error") . "; counterexample: $ce",
                        ['property' => $name, 'seed' => $seed, 'counterexample' => $ce, 'case' => $i, 'error' => $error]);
                }
            }
            return;
        }
        throw new \InvalidArgumentException("unknown invariant $name");
    }

    /** A digest of the cases a property would draw (generation only, nothing is checked): equal for equal (seed, numRuns), different across seeds. */
    public static function caseDigest(string $name, int $numRuns, int $seed): string
    {
        foreach (self::registry() as $index => $p) {
            if ($p['name'] === $name) {
                $g = InvariantsRng::forProperty($seed, $index);
                $h = hash_init('sha256');
                for ($i = 0; $i < $numRuns; $i++) {
                    hash_update($h, serialize($p['gen']($g)));
                }
                return hash_final($h);
            }
        }
        throw new \InvalidArgumentException("unknown invariant $name");
    }

    /**
     * Machine-checks every invariant. Options (assoc array): `numRuns` (default 1000), `seed` (default 20260108), `bail` (stop at the first
     * failure). Each result is {name, ok, numRuns, seed}; a failure adds `error` and `report` {property, seed, counterexample, case, error}.
     * A zero or non-integer numRuns (it would pass vacuously) and a non-integer seed are refused.
     * @param array{numRuns?:int,seed?:int,bail?:bool} $opts @return list<array<string,mixed>>
     */
    public static function checkInvariants(array $opts = []): array
    {
        $numRuns = $opts['numRuns'] ?? self::DEFAULT_NUM_RUNS;
        $seed = $opts['seed'] ?? self::DEFAULT_SEED;
        if (!is_int($numRuns) || $numRuns < 1) {
            throw new \RangeException('checkInvariants: numRuns must be a positive integer');
        }
        if (!is_int($seed)) {
            throw new \RangeException('checkInvariants: seed must be an integer');
        }
        $results = [];
        foreach (self::names() as $name) {
            try {
                self::run($name, $numRuns, $seed);
                $results[] = ['name' => $name, 'ok' => true, 'numRuns' => $numRuns, 'seed' => $seed];
            } catch (InvariantFailure $e) {
                $results[] = ['name' => $name, 'ok' => false, 'numRuns' => $numRuns, 'seed' => $seed, 'error' => $e->getMessage(), 'report' => $e->report];
                if (($opts['bail'] ?? false) === true) {
                    break;
                }
            }
        }
        return $results;
    }
}
