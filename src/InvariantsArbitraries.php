<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/InvariantsRng.php';

/**
 * Generators of WELL-FORMED random inputs for the PCA core (the reference's arbitraries): Ed25519 seeds, multi-hop chain models
 * whose every hop legally attenuates (turned into signed chains by {@see Invariants::buildChain}), predicates, action and caveat
 * contexts, risk policies / inputs / budgets / deltas. Every generator draws from an {@see InvariantsRng} stream, so a run is
 * reproducible from (seed, property index). Values are the parsed-JSON model (Obj / Num / list arrays / string / bool / null);
 * everything is pure data handed to the real core, nothing here re-implements the model it is meant to check.
 * The caveat context uses the PHP core's member names (blast_radius, delegation_depth, ...), the reference's camelCase ones.
 */
final class InvariantsArbitraries
{
    public const VERBS = ['read', 'write', 'delete', 'transfer', 'list', 'admin'];
    public const RESOURCES = ['/acct/a', '/acct/b', '/docs/1', '/docs/2', '/x/y', '/'];
    public const LEAF_OPS = ['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'prefix', 'exists'];
    public const LEAF_FIELDS = ['subject.role', 'subject.tier', 'env.ip', 'action.verb', 'action.resource', 'action.params.amount'];
    public const REVERSIBILITY = ['reversible', 'rate_limited', 'irreversible', 'teleport'];
    public const SPEC_REVERSIBILITY = ['reversible', 'rate_limited', 'irreversible'];
    public const MAX_TIME = 10_000_000;

    // ---- keys -------------------------------------------------------------------------

    /** 32 random bytes: a reproducible Ed25519 secret seed (any 32 bytes is valid). */
    public static function seed32(InvariantsRng $g): string
    {
        return $g->bytes(32);
    }

    // ---- predicates -------------------------------------------------------------------

    public static function verb(InvariantsRng $g): string
    {
        return $g->pick(self::VERBS);
    }

    public static function resource(InvariantsRng $g): string
    {
        return $g->bool() ? $g->pick(self::RESOURCES) : $g->string(0, 10);
    }

    /** @return list<string> */
    private static function strings(InvariantsRng $g, int $min, int $max): array
    {
        $out = [];
        for ($n = $g->int($min, $max); $n > 0; $n--) {
            $out[] = $g->string(0, 10);
        }
        return $out;
    }

    /** A decidable, well-formed leaf comparison. */
    public static function leafCondition(InvariantsRng $g): Obj
    {
        $field = $g->pick(self::LEAF_FIELDS);
        $op = $g->pick(self::LEAF_OPS);
        $value = match ($g->int(0, 3)) {
            0 => $g->string(0, 10),
            1 => $g->intB(-10, 10),
            2 => $g->bool(),
            default => self::strings($g, 0, 3),
        };
        return Obj::of(['field' => $field, 'op' => $op, 'value' => $value]);
    }

    public static function predicate(InvariantsRng $g): Obj
    {
        $verb = match ($g->int(0, 2)) {
            0 => self::verb($g),
            1 => self::verbs($g),
            default => '*',
        };
        $resource = match ($g->int(0, 3)) {
            0 => null,
            1 => '*',
            2 => $g->pick(['/acct/*', '/docs/*']),
            default => self::resource($g),
        };
        $where = null;
        if ($g->bool()) {
            $where = [];
            for ($n = $g->int(0, 2); $n > 0; $n--) {
                $where[] = self::leafCondition($g);
            }
        }
        $p = Obj::of(['verb' => $verb]);
        if ($resource !== null) {
            $p->set('resource', $resource);
        }
        if ($where !== null) {
            $p->set('where', $where);
        }
        return Sign::n($p);
    }

    /** @return list<string> 1..3 verbs */
    private static function verbs(InvariantsRng $g): array
    {
        $out = [];
        for ($n = $g->int(1, 3); $n > 0; $n--) {
            $out[] = self::verb($g);
        }
        return $out;
    }

    /** @return list<Obj> 1..4 predicates */
    public static function predicateList(InvariantsRng $g): array
    {
        $out = [];
        for ($n = $g->int(1, 4); $n > 0; $n--) {
            $out[] = self::predicate($g);
        }
        return $out;
    }

    // ---- action + caveat contexts -----------------------------------------------------

    /** An action context {action: {verb, resource, params?}, subject?, env?}. */
    public static function actionContext(InvariantsRng $g): Obj
    {
        $action = Obj::of(['verb' => self::verb($g), 'resource' => self::resource($g)]);
        if ($g->bool()) {
            $params = new Obj();
            foreach (['amount', 'target', 'reason'] as $k) {
                if ($g->bool()) {
                    $params->set($k, match ($g->int(0, 2)) {
                        0 => $g->string(0, 10),
                        1 => $g->intB(-5, 100),
                        default => $g->bool(),
                    });
                }
            }
            $action->set('params', $params);
        }
        $role = $g->pick(['admin', 'user', 'guest']);
        $tier = $g->intB(0, 5);
        $ip = $g->string(0, 10);
        $withSubject = $g->bool();
        $withEnv = $g->bool();
        $ctx = Obj::of(['action' => $action]);
        if ($withSubject) {
            $ctx->set('subject', Obj::of(['role' => $role, 'tier' => $tier]));
        }
        if ($withEnv) {
            $ctx->set('env', Obj::of(['ip' => $ip]));
        }
        return Sign::n($ctx);
    }

    /** A caveat-evaluation context (every optional member present or absent). */
    public static function caveatContext(InvariantsRng $g): Obj
    {
        $ctx = Obj::of(['now' => $g->intB(0, self::MAX_TIME)]);
        if ($g->bool()) {
            $ctx->set('blast_radius', $g->dbl(0.0, 1.0));
        }
        if ($g->bool()) {
            $ctx->set('reversibility_class', $g->pick(self::REVERSIBILITY));
        }
        if ($g->bool()) {
            $ctx->set('delegation_depth', $g->intB(0, 20));
        }
        if ($g->bool()) {
            $times = [];
            for ($n = $g->int(0, 6); $n > 0; $n--) {
                $times[] = $g->intB(0, self::MAX_TIME);
            }
            $ctx->set('recent_action_times', $times);
        }
        return Sign::n($ctx);
    }

    /** One point at which to probe a chain's effective authority. @return array{action:Obj,cavCtx:Obj} */
    public static function evalPoint(InvariantsRng $g): array
    {
        return ['action' => self::actionContext($g), 'cavCtx' => self::caveatContext($g)];
    }

    // ---- attenuating delegation chains ------------------------------------------------

    /** A built-in, evaluator-decidable caveat spec (budget_frac is materialised monotone by Invariants::buildChain). */
    public static function caveatSpec(InvariantsRng $g): Obj
    {
        return match ($g->int(0, 6)) {
            0 => Obj::of(['k' => 'expires', 'at' => $g->intB(0, self::MAX_TIME)]),
            1 => Obj::of(['k' => 'not_before', 'at' => $g->intB(0, self::MAX_TIME)]),
            2 => Obj::of(['k' => 'rate', 'max' => $g->intB(1, 10), 'per_secs' => $g->intB(1, 3600)]),
            // quantized to 3 decimals so the limit is canonical-wire-safe
            3 => Obj::of(['k' => 'max_blast_radius', 'max' => $g->intB(0, 1000) / 1000]),
            4 => Obj::of(['k' => 'reversibility_max', 'cls' => $g->pick(self::SPEC_REVERSIBILITY)]),
            5 => Obj::of(['k' => 'delegation_depth', 'max' => $g->intB(0, 20)]),
            default => Obj::of(['k' => 'budget_frac', 'frac' => $g->dbl(0.0, 1.0)]),
        };
    }

    /** @return list<Obj> */
    private static function specs(InvariantsRng $g, int $min, int $max): array
    {
        $out = [];
        for ($n = $g->int($min, $max); $n > 0; $n--) {
            $out[] = self::caveatSpec($g);
        }
        return $out;
    }

    /** The model of a legal chain (seeds are raw bytes), the input of {@see Invariants::buildChain}. */
    public static function chainModel(InvariantsRng $g): Obj
    {
        $principal = self::seed32($g);
        $holder0 = self::seed32($g);
        $rootSpecs = self::specs($g, 1, 4);
        $hops = [];
        for ($n = $g->int(0, 5); $n > 0; $n--) {
            $hops[] = Obj::of(['holderSeed' => self::seed32($g), 'addedSpecs' => self::specs($g, 0, 3)]);
        }
        return Obj::of(['principalSeed' => $principal, 'holder0Seed' => $holder0, 'rootSpecs' => $rootSpecs, 'hops' => $hops,
            'predicates' => self::predicateList($g)]);
    }

    // ---- risk policy / inputs / budget ------------------------------------------------

    /** A well-formed policy (passes the reference's validateRiskPolicy): kappa > 0, 0 <= theta1 <= theta2, the rest finite >= 0. @return array<string,mixed> */
    public static function riskPolicy(InvariantsRng $g): array
    {
        $w = [];
        foreach (['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'] as $k) {
            $w[$k] = $g->dbl(0.0, 2.0);
        }
        $theta1 = $g->dbl(0.0, 1.0);
        $gap = $g->dbl(0.0, 1.0);
        return ['weights' => $w, 'theta1' => $theta1, 'theta2' => $theta1 + $gap, 'kappa' => $g->dbl(0.001, 5.0), 'lambda' => $g->dbl(0.0, 0.01),
            'rho' => $g->dbl(0.0, 2.0), 'bMax' => $g->dbl(0.0, 10.0)];
    }

    /** @return array<string,float> */
    public static function riskInputs(InvariantsRng $g): array
    {
        $o = [];
        foreach (['semanticDistance', 'reversibility', 'blastRadius', 'taint', 'confidence', 'age'] as $k) {
            $o[$k] = $g->dbl(0.0, 1.0);
        }
        return $o;
    }

    /** @return array{B:float,tau:int,asOf?:int} */
    public static function trustBudget(InvariantsRng $g): array
    {
        $b = ['B' => $g->dbl(0.0, 10.0), 'tau' => $g->intB(0, self::MAX_TIME)];
        if ($g->bool()) {
            $b['asOf'] = $g->intB(0, self::MAX_TIME);
        }
        return $b;
    }

    /** Non-negative deltas that build a pointwise-WORSE risk input. @return array<string,float> */
    public static function riskDeltas(InvariantsRng $g): array
    {
        $o = [];
        foreach (['dSem', 'dBlast', 'dTaint', 'dAge', 'dRev', 'dConf'] as $k) {
            $o[$k] = $g->dbl(0.0, 1.0);
        }
        return $o;
    }
}
