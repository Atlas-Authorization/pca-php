<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/ObjectiveRisk.php';

/**
 * Binding of the objective-risk functional to the live decision path, without touching the signed PCActn. The facts live in the already-signed grant
 * envelope, as an optional `objective_risk` member (covered by the root signature: tampering breaks the chain check). A grant that commits nothing is
 * unaffected (the caller falls back to the heuristic). The registry, resource graph and calibration set themselves are INSTANCE-held config; their
 * digests must equal the committed ones or the result is a mismatch (fail closed per `on_mismatch`, and a grant cannot downgrade to the heuristic on its
 * own say-so: the verifier must opt in with `allow_heuristic_fallback`).
 */
final class ObjectiveBinding
{
    private static function isObj(mixed $v): bool
    {
        return $v instanceof Obj;
    }

    private static function isStr(mixed $v): bool
    {
        return is_string($v) && $v !== '';
    }

    /**
     * The committed `objective_risk` of a grant's envelope: `[]` = not committed, `['commitment' => Obj]` or `['malformed' => reason]`. Pure.
     * @return array{commitment?:Obj,malformed?:string}
     */
    public static function readObjectiveCommitment(mixed $grant): array
    {
        $env = Authorize::readEnvelope($grant);
        if ($env === null || !$env->has('objective_risk')) {
            return [];
        }
        $raw = $env->get('objective_risk');
        $v = $raw instanceof Obj ? $raw->get('v') : null;
        if (!self::isObj($raw) || Js::num($v) !== 1.0) {
            return ['malformed' => 'objective_risk: unsupported shape/version'];
        }
        $emb = $raw->get('embedder');
        if (!self::isObj($emb) || $emb->get('scheme') !== 'native' || !self::isStr($emb->get('model_id')) || !self::isObj($emb->get('config'))) {
            return ['malformed' => 'objective_risk.embedder must be { scheme: "native", model_id, config }'];
        }
        $goal = $raw->get('goal');
        if (!self::isObj($goal) || !self::isStr($goal->get('commit'))) {
            return ['malformed' => 'objective_risk.goal must be a goal commitment'];
        }
        if (!self::isStr($raw->get('registry_digest')) || !self::isStr($raw->get('graph_digest'))) {
            return ['malformed' => 'objective_risk needs registry_digest and graph_digest'];
        }
        if ($raw->has('calibration_digest') && !self::isStr($raw->get('calibration_digest'))) {
            return ['malformed' => 'objective_risk.calibration_digest must be a string'];
        }
        $kinds = $raw->get('authorized_kinds');
        if (!is_array($kinds) || !array_is_list($kinds) || count(array_filter($kinds, 'is_string')) !== count($kinds)) {
            return ['malformed' => 'objective_risk.authorized_kinds must be string[]'];
        }
        if ($raw->has('denominations') && !(is_array($raw->get('denominations')) && array_is_list($raw->get('denominations')))) {
            return ['malformed' => 'objective_risk.denominations must be an array'];
        }
        if ($raw->has('on_mismatch') && $raw->get('on_mismatch') !== 'deny' && $raw->get('on_mismatch') !== 'heuristic') {
            return ['malformed' => 'objective_risk.on_mismatch must be "deny" or "heuristic"'];
        }
        return ['commitment' => $raw];
    }

    /** @return list<float> */
    private static function floats(mixed $list): array
    {
        $out = [];
        foreach (is_array($list) ? $list : [] as $x) {
            $out[] = (float)Js::num($x);
        }
        return $out;
    }

    /**
     * The objective risk inputs for `$action` under `$grant`. Total (never throws).
     *  - nothing committed: `['mode' => 'none']` (the heuristic, unchanged)
     *  - committed and reproduced: `['mode' => 'objective', 'inputs' => Obj{reversibility, blastRadius, semanticDistance}, 'r' => float, 'evidenceDigest' => string]`
     *  - committed but not reproducible or invalid: `['mode' => 'mismatch', 'reasons' => list<string>, 'onMismatch' => 'deny'|'heuristic']` (default deny)
     * `$instance` is the instance-held config Obj `{registry?: {trusted_verifiers?, entries?: [{verb, inverse_kind, fidelity, verification?: {verifier_id,
     * evidence_digest}}]}, graph?: {nodes?, edges?}, calibration?: number[], allow_heuristic_fallback?}`; `$taint` and `$age` are verifier-supplied (they only
     * feed r; default 1).
     * @return array<string,mixed>
     */
    public static function resolveObjectiveRisk(mixed $grant, mixed $action, mixed $instance, mixed $taint = null, mixed $age = null): array
    {
        $read = self::readObjectiveCommitment($grant);
        if (isset($read['malformed'])) {
            return ['mode' => 'mismatch', 'reasons' => [$read['malformed']], 'onMismatch' => 'deny'];
        }
        if (!isset($read['commitment'])) {
            return ['mode' => 'none'];
        }
        $c = $read['commitment'];
        $requested = $c->has('on_mismatch') ? $c->get('on_mismatch') : 'deny';
        $onMismatch = $requested === 'heuristic' && Js::opt($instance, 'allow_heuristic_fallback') === true ? 'heuristic' : 'deny';
        $miss = static fn(string ...$reasons): array => ['mode' => 'mismatch', 'reasons' => array_values($reasons), 'onMismatch' => $onMismatch];
        try {
            $env = Authorize::readEnvelope($grant);
            if ($env === null) {
                return $miss('grant carries no valid envelope');
            }
            if ($instance === null) {
                return $miss('the grant commits objective-risk facts but the instance holds no objective-risk config');
            }
            $reg = new InMemoryInverseRegistry(array_values(array_filter(Js::opt(Js::opt($instance, 'registry'), 'trusted_verifiers') ?? [], 'is_string')));
            foreach (Js::opt(Js::opt($instance, 'registry'), 'entries') ?? [] as $e) {
                $entry = Obj::of(['inverseKind' => Js::opt($e, 'inverse_kind'), 'fidelity' => Js::opt($e, 'fidelity')]);
                $ver = Js::opt($e, 'verification');
                if (Js::truthy($ver)) {
                    $entry->set('verification', Obj::of(['verifierId' => Js::opt($ver, 'verifier_id'), 'evidenceDigest' => Js::opt($ver, 'evidence_digest')]));
                }
                $reg->register((string)Js::opt($e, 'verb'), $entry);
            }
            $graph = new ResourceGraph();
            foreach (Js::opt(Js::opt($instance, 'graph'), 'nodes') ?? [] as $n) {
                $graph->addNode($n);
            }
            foreach (Js::opt(Js::opt($instance, 'graph'), 'edges') ?? [] as $e) {
                $graph->addEdge($e);
            }
            $emb = $c->get('embedder');
            $embedder = new NativeHashEmbedder($emb->get('config'));
            if ($embedder->modelId() !== $emb->get('model_id')) {
                return $miss('embedder model_id does not match the committed one');
            }
            $calibration = Js::opt($instance, 'calibration');
            $calibration = is_array($calibration) ? self::floats($calibration) : null;
            $committedCal = $c->has('calibration_digest') ? $c->get('calibration_digest') : null;
            if ($committedCal !== null && ($calibration === null || ObjectiveRisk::calibrationDigest($calibration) !== $committedCal)) {
                return $miss('calibration set does not match the committed digest');
            }
            $commitments = Obj::of(['registryDigest' => $c->get('registry_digest'), 'graphDigest' => $c->get('graph_digest')]);
            if ($committedCal !== null) {
                $commitments->set('calibrationDigest', $committedCal);
            }
            $scope = $c->get('scope');
            $weights = $env->get('risk_policy') instanceof Obj ? $env->get('risk_policy')->get('weights') : throw new \TypeError("Cannot read properties of undefined (reading 'weights')");
            $res = ObjectiveRisk::objectiveRisk($action, new ObjectiveRiskContext(
                $reg, array_values(array_unique($c->get('authorized_kinds'))), $graph, $scope instanceof Obj ? $scope : null, $embedder, $c->get('goal'), $commitments,
                $c->has('denominations') ? $c->get('denominations') : [], $weights, $taint ?? 1, $age ?? 1, null, $committedCal !== null ? $calibration : null,
            ));
            if ($res->get('valid') !== true) {
                return $miss(...array_map('strval', $res->get('reasons')));
            }
            $in = $res->get('inputs');
            return ['mode' => 'objective', 'inputs' => Obj::of(['reversibility' => $in->get('reversibility'), 'blastRadius' => $in->get('blastRadius'),
                'semanticDistance' => $in->get('semanticDistance')]), 'r' => $res->get('r'), 'evidenceDigest' => $res->get('evidenceDigest')];
        } catch (\Throwable $e) {
            return $miss('objective risk evaluation error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()));
        }
    }
}
