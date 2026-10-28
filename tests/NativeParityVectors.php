<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/Vectors.php';
require_once __DIR__ . '/../src/RevocationStaleness.php';
require_once __DIR__ . '/../src/Operations.php';
require_once __DIR__ . '/../src/PlanLifecycle.php';
require_once __DIR__ . '/../src/Assurance.php';

use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\AssuranceRequirement;
use Atlas\Pca\AuthorizedOperation;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\ExecuteOptions;
use Atlas\Pca\ExecutionHandle;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\Operations;
use Atlas\Pca\PlanRegistry;
use Atlas\Pca\RecheckResult;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RevocationStaleness;
use Atlas\Pca\RevocationStalenessPolicy;

/**
 * Replay of the native-parity vector families added in 0.5 (goal binding v3, revocation staleness, operation records, plan
 * lifecycle, assurance labels). Each method returns [vectors run, failures]. A missing vector file THROWS (never skips).
 */
final class NativeParityVectors
{
    /** @return list<Obj> */
    public static function rows(Obj $doc, string $table): array
    {
        $r = $doc->get($table);
        if (!is_array($r)) {
            throw new \RuntimeException("vector table missing: $table");
        }
        return $r;
    }

    public static function intOf(mixed $n): int
    {
        return $n instanceof \Atlas\Pca\Num ? $n->int() : (int)$n;
    }

    // ---- goal-commit-vectors.json ---------------------------------------------------------------------------------------

    /** @return array{int, list<string>} */
    public static function goal(): array
    {
        $doc = Vectors::load('goal-commit-vectors.json');
        $n = 0;
        $f = [];
        if ($doc->get('goal_prefix') !== Pca::INTENT_GOAL_V3_PREFIX) {
            $f[] = 'goal_prefix differs';
        }
        foreach (self::rows($doc, 'commit') as $v) {
            $n++;
            $ref = Obj::of(['goal_digest' => $v->get('goal_digest'), 'policy_digest' => $v->get('policy_digest')]);
            try {
                if (Pca::intentGoalV3($ref) !== $v->get('goal')) {
                    $f[] = 'commit ' . $v->get('name') . ': goal differs';
                }
                if (Pca::intentGoalCommitV3($ref, $v->get('salt')) !== $v->get('commit')) {
                    $f[] = 'commit ' . $v->get('name') . ': commitment differs';
                }
            } catch (\Throwable $e) {
                $f[] = 'commit ' . $v->get('name') . ': ' . $e->getMessage();
            }
        }
        foreach (self::rows($doc, 'invalid') as $v) {
            $n++;
            $ref = Obj::of(['goal_digest' => $v->get('goal_digest'), 'policy_digest' => $v->get('policy_digest')]);
            $refused = false;
            try {
                Pca::intentGoalV3($ref);
            } catch (\InvalidArgumentException) {
                $refused = true;
            }
            if (!$refused || Pca::isApprovedGoalRef($ref)) {
                $f[] = 'invalid ' . $v->get('name') . ': accepted';
            }
        }
        foreach (self::rows($doc, 'binding') as $v) {
            $n++;
            $gc = $v->get('grant_commit');
            $grant = is_string($gc) ? Obj::of(['caveats' => [Obj::of(['type' => 'envelope', 'goal_commit' => $gc])]]) : new Obj();
            $intent = $v->get('intent') instanceof Obj ? $v->get('intent') : null;
            $session = is_string($v->get('session')) ? $v->get('session') : null;
            $d = Pca::decideIntentBinding($intent, $grant, $v->get('policy'), $session);
            if ($d['status'] !== $v->get('expect')) {
                $f[] = 'binding ' . $v->get('name') . ': got ' . $d['status'] . ' (' . $d['reason'] . ') want ' . $v->get('expect');
            }
        }
        return [$n, $f];
    }

    // ---- staleness-vectors.json (T9) ------------------------------------------------------------------------------------

    /** A vector millisecond value: the string "NaN" stands for NaN, null stays null. */
    private static function ms(mixed $v): ?float
    {
        if ($v === 'NaN') {
            return NAN;
        }
        return $v instanceof Num ? $v->float() : null;
    }

    /** @param array{ok:bool, reason?:string} $got */
    private static function wantResult(string $label, array $got, Obj $v): ?string
    {
        $exp = $v->get('result');
        $want = $exp->get('ok') === true;
        if ($got['ok'] !== $want) {
            return "$label: ok=" . json_encode($got['ok']) . ' (' . ($got['reason'] ?? '') . ') want ' . json_encode($want);
        }
        if ($v->has('ok_only') || $got['ok']) {
            return null;
        }
        return ($got['reason'] ?? '') === $exp->get('reason') ? null : "$label: reason '" . ($got['reason'] ?? '') . "' want '" . $exp->get('reason') . "'";
    }

    /** @return array{int, list<string>} */
    public static function staleness(): array
    {
        $doc = Vectors::load('staleness-vectors.json');
        $n = 0;
        $f = [];
        $c = $doc->get('constants');
        foreach ([['refresh_ms', RevocationStaleness::EPOCH_REFRESH_MS], ['validity_ms', RevocationStaleness::EPOCH_VALIDITY_MS],
                  ['irreversible_max_age_ms', RevocationStaleness::IRREVERSIBLE_MAX_AGE_MS], ['skew_ms', RevocationStaleness::SKEW_MS]] as [$k, $want]) {
            $n++;
            if (self::intOf($c->get($k)) !== $want) {
                $f[] = "constant $k differs";
            }
        }
        foreach (self::rows($doc, 'max_age') as $v) {
            $n++;
            $got = RevocationStaleness::maxAgeMs(RevocationStalenessPolicy::fromJson($v->get('policy')), $v->get('class'));
            $want = self::ms($v->get('max_age_ms'));
            if ($got !== $want) {
                $f[] = 'max_age ' . json_encode($v->get('class')) . ': ' . $got . ' want ' . $want;
            }
        }
        foreach (self::rows($doc, 'effective_reversibility') as $v) {
            $n++;
            $got = RevocationStaleness::effectiveReversibility(is_string($v->get('server_class')) ? $v->get('server_class') : null, $v->get('signed_class'));
            if ($got !== $v->get('effective')) {
                $f[] = 'effective_reversibility: ' . $got . ' want ' . $v->get('effective');
            }
        }
        foreach (self::rows($doc, 'age') as $i => $v) {
            $n++;
            $issued = $v->get('issued_at') instanceof Num ? $v->get('issued_at')->float() : null; // null, "NaN", "x": unknown
            $what = is_string($v->get('what')) ? $v->get('what') : 'revocation state';
            $e = self::wantResult("age#$i", RevocationStaleness::checkAge($issued, self::ms($v->get('now')), self::ms($v->get('max_age_ms')), $what), $v);
            if ($e !== null) {
                $f[] = $e;
            }
        }
        foreach (self::rows($doc, 'epoch') as $v) {
            $n++;
            $o = ['guardianPublic' => $v->get('guardian_public'), 'now' => self::ms($v->get('now'))];
            foreach (['grant_ref' => 'grantRef'] as $a => $b) {
                if (is_string($v->get($a))) {
                    $o[$b] = $v->get($a);
                }
            }
            foreach (['last_accepted_epoch' => 'lastAcceptedEpoch', 'pcactn_epoch' => 'pcactnEpoch', 'max_age_ms' => 'maxAgeMs'] as $a => $b) {
                if ($v->has($a)) {
                    $o[$b] = self::ms($v->get($a));
                }
            }
            $e = self::wantResult('epoch/' . $v->get('name'), RevocationStaleness::checkEpoch($v->get('epoch'), $o), $v);
            if ($e !== null) {
                $f[] = $e;
            }
        }
        $guardian = $doc->get('guardian_public');
        foreach (self::rows($doc, 'gate') as $v) {
            $n++;
            $in = ['policy' => RevocationStalenessPolicyFromVector::of($v), 'guardianPublic' => $guardian, 'grantRef' => 'g1',
                'now' => self::ms($v->get('now')), 'pcactnEpoch' => 0.0,
                'serverClass' => is_string($v->get('server_class')) ? $v->get('server_class') : null,
                'signedClass' => $v->get('signed_class')];
            switch ($v->get('mode')) {
                case 'epoch':
                    $in['epochSource'] = true;
                    $in['epoch'] = $v->get('epoch');
                    $in['root'] = is_string($v->get('bare_root')) ? $v->get('bare_root') : null;
                    break;
                case 'root':
                    $in['root'] = $doc->get('revocation_root');
                    $in['rootIssuedAt'] = self::ms($v->get('root_issued_at'));
                    break;
                case 'none':
                    $in['epochSource'] = true;
                    break;
                default:
                    $f[] = 'gate: unknown mode';
                    continue 2;
            }
            $e = self::wantResult('gate/' . $v->get('name'), RevocationStaleness::gate($in), $v);
            if ($e !== null) {
                $f[] = $e;
            }
        }
        foreach (self::rows($doc, 'membership') as $v) {
            $n++;
            if (RevocationStaleness::verifyNonMembership($v->get('root'), $v->get('proof'), $v->get('id')) !== ($v->get('ok') === true)) {
                $f[] = 'membership/' . $v->get('name') . ': wrong verdict';
            }
        }
        $set = $doc->get('revocation_set');
        foreach (self::rows($doc, 'gate_ids') as $v) {
            $n++;
            $issued = $v->get('epoch_issued_at')->int();
            // the vectors' guardian signs an epoch over the main set, issued `epoch_issued_at`
            $ep = RevocationStaleness::signEpoch(str_repeat("\x0b", 32), ['instance_id' => 'i', 'grant_ref' => 'g1', 'epoch' => 0,
                'set_size' => $set->get('size')->int(), 'root' => $set->get('root'), 'issued_at' => $issued, 'not_after' => $issued + 600000]);
            if ($ep->get('guardian') !== $guardian) {
                $f[] = 'gate_ids: the test key is not the vectors guardian';
            }
            $proofs = $v->get('proofs');
            $in = ['policy' => new RevocationStalenessPolicy(300000.0), 'guardianPublic' => $guardian, 'grantRef' => 'g1',
                'now' => self::ms($v->get('now')), 'pcactnEpoch' => 0.0, 'signedClass' => 'costly', 'epochSource' => true, 'epoch' => $ep,
                'ids' => $v->get('ids'), 'proofs' => static fn(string $id): mixed => $proofs->has($id) ? $proofs->get($id) : null];
            $e = self::wantResult('gate_ids/' . $v->get('name'), RevocationStaleness::gate($in), $v);
            if ($e !== null) {
                $f[] = $e;
            }
        }
        return [$n, $f];
    }

    // ---- operation-vectors.json (T3) ------------------------------------------------------------------------------------

    private static function str(Obj $s, string $k, string $def): string
    {
        return is_string($s->get($k)) ? $s->get($k) : $def;
    }

    private static function optInt(Obj $s, string $k): ?int
    {
        return $s->get($k) instanceof Num ? $s->get($k)->int() : null;
    }

    /** One step of an operation scenario; the answer in the reference's JSON shape. */
    private static function operationStep(\Atlas\Pca\OperationStore $store, Obj $s): mixed
    {
        $at = static fn(): int => $s->get('at')->int();
        switch ($s->get('op')) {
            case 'seed':
                $store->create(OperationRecord::fromObj($s->get('record')));
                return null;
            case 'get':
                return $store->get($s->get('id'))?->toObj();
            case 'recover':
                $store instanceof \Atlas\Pca\OpenListingStore || throw new \RuntimeException('the store cannot list open records');
                $rs = Operations::recoverOperations($store, self::optInt($s, 'older_than_ms'), $at);
                return array_map(static fn(OperationRecord $r): Obj => Obj::of(['id' => $r->id, 'state' => $r->state]), $rs);
            case 'recover_one':
                return Operations::recoverOperation($store, $s->get('id'), self::optInt($s, 'older_than_ms'), $at)?->toObj();
            case 'resolve':
                $o = $s->get('outcome');
                $out = ['state' => $o->get('state')];
                if ($o->has('result')) {
                    $out['result'] = $o->get('result');
                }
                if ($o->has('error')) {
                    $out['error'] = $o->get('error');
                }
                return Operations::resolveOperation($store, $s->get('id'), $out, $at);
        }
        // execute
        $id = $s->get('id');
        $action = new Obj();
        if ($s->has('signed_class')) {
            $action->set('reversibility_class', $s->get('signed_class'));
        }
        $pcactn = Obj::of(['action' => $action]);
        if ($s->has('exp')) {
            $pcactn->set('exp', $s->get('exp'));
        }
        $az = new AuthorizeResult($s->get('not_allowed') !== true, 200, pcactn: $pcactn, verdict: ['allow' => true],
            operation: new AuthorizedOperation(self::str($s, 'verb', 'payments.refund'), self::str($s, 'resource', '/orders/1'),
                self::str($s, 'params_digest', Pca::paramsDigest()), $id));
        $recheck = null;
        $rc = $s->get('recheck');
        if ($rc === 'ok') {
            $recheck = static fn(ExecutionHandle $h): RecheckResult => RecheckResult::ok();
        } elseif ($rc instanceof Obj && is_string($rc->get('refuse'))) {
            $recheck = static fn(ExecutionHandle $h): RecheckResult => RecheckResult::refuse($rc->get('refuse'));
        } elseif ($rc instanceof Obj) {
            $recheck = static function (ExecutionHandle $h) use ($rc): RecheckResult {
                throw new \RuntimeException((string)$rc->get('throw'));
            };
        }
        $opts = new ExecuteOptions($s->get('no_store') === true ? null : $store, null, $recheck, self::str($s, 'recheck_for', 'irreversible'),
            is_string($s->get('server_class')) ? $s->get('server_class') : null, self::optInt($s, 'timeout_ms'), $at);
        $fnSpec = $s->get('fn');
        $calls = 0;
        $out = Operations::executeAuthorized($az, function (ExecutionHandle $h) use (&$calls, $fnSpec, $az, $opts) {
            $calls++;
            switch ($fnSpec->get('kind')) {
                case 'throw':
                    throw new \RuntimeException($fnSpec->get('message'));
                case 'reenter':
                    return Operations::executeAuthorized($az, static function (): never {
                        throw new \RuntimeException('inner must not run');
                    }, $opts)->status;
            }
            return $fnSpec->has('result') ? $fnSpec->get('result') : $h->idempotencyKey;
        }, $opts);
        $rec = $s->get('no_store') === true || $s->get('not_allowed') === true ? null : $store->get($id)?->toObj();
        return Obj::of(['outcome' => $out->toObj(), 'fn_calls' => new Num((string)$calls), 'record' => $rec]);
    }

    /** @return array{int, list<string>} */
    public static function operations(?callable $newStore = null): array
    {
        $doc = Vectors::load('operation-vectors.json');
        $f = [];
        if (self::intOf($doc->get('constants')->get('pending_timeout_ms')) !== Operations::PENDING_TIMEOUT_MS) {
            $f[] = 'the default pending timeout differs from the corpus';
        }
        $n = 0;
        foreach (self::rows($doc, 'scenarios') as $sc) {
            $store = $newStore !== null ? $newStore() : new MemoryOperationStore();
            $steps = $sc->get('steps');
            $expect = $sc->get('expect');
            if (count($steps) !== count($expect)) {
                $f[] = $sc->get('name') . ': steps and expect differ in length';
                continue;
            }
            foreach ($steps as $i => $st) {
                $n++;
                $got = self::operationStep($store, $st);
                if (!Vectors::same($got, $expect[$i])) {
                    $f[] = $sc->get('name') . " step $i (" . $st->get('op') . '): got ' . Json::canonicalizeLenient($got)
                        . ' want ' . Json::canonicalizeLenient($expect[$i]);
                }
            }
        }
        return [$n, $f];
    }

    // ---- plan-vectors.json (T10) ----------------------------------------------------------------------------------------

    private static function transitionObj(array $t): Obj
    {
        return $t['ok'] ? Obj::of(['ok' => true, 'record' => $t['record']]) : Obj::of(['ok' => false, 'state' => $t['state'], 'reason' => $t['reason']]);
    }

    private static function statusObj(array $s): Obj
    {
        $o = Obj::of(['state' => $s['state'], 'executable' => $s['executable']]);
        if (isset($s['reason'])) {
            $o->set('reason', $s['reason']);
        }
        if (isset($s['record'])) {
            $o->set('record', $s['record']);
        }
        return $o;
    }

    /** @return array{int, list<string>} */
    public static function plans(): array
    {
        $doc = Vectors::load('plan-vectors.json');
        $f = [];
        $n = 0;
        foreach (self::rows($doc, 'scenarios') as $sc) {
            $now = 0;
            $validator = match ($sc->get('validator')) {
                'accept' => static fn(Obj $r): array => ['ok' => true],
                'refuse' => static fn(Obj $r): array => ['ok' => false, 'reason' => 'node outside the grant'],
                'throw' => static function (Obj $r): array {
                    throw new \RuntimeException('policy down');
                },
                default => null,
            };
            $reg = new PlanRegistry(null, 'pca-plan:', static function () use (&$now): int {
                return $now;
            }, $validator);
            $steps = $sc->get('steps');
            $expect = $sc->get('expect');
            if (count($steps) !== count($expect)) {
                $f[] = $sc->get('name') . ': steps and expect differ in length';
                continue;
            }
            foreach ($steps as $i => $s) {
                $n++;
                $now = $s->get('at')->int();
                $g = $s->get('grant');
                $root = $s->get('root');
                $got = match ($s->get('op')) {
                    'draft' => self::transitionObj($reg->draft($g, is_array($s->get('nodes')) ? $s->get('nodes') : [])),
                    'validate' => self::transitionObj($reg->validate($g, $root)),
                    'commit' => self::transitionObj($reg->commit($g, $root)),
                    'authorize' => self::transitionObj($reg->authorize($g, $root, $s->get('approval'))),
                    'revoke' => self::transitionObj($reg->revoke($g, $root, $s->get('reason'))),
                    'status' => self::statusObj($reg->status($g, $root, $now)),
                    'check' => self::statusObj($reg->check($g, $root, ['now' => $now, 'nodeId' => is_string($s->get('node_id')) ? $s->get('node_id') : null,
                        'operation' => $s->get('operation')])),
                    'is_plan_authorized' => $reg->isPlanAuthorized($g, $root),
                    'context' => (static function (?array $c): ?Obj {
                        return $c === null ? null : Obj::of(['plan' => $c['plan'], 'planAuthorized' => $c['planAuthorized'], 'status' => self::statusObj($c['status'])]);
                    })($reg->context($g, $root, $now)),
                    default => throw new \RuntimeException('unknown plan op ' . $s->get('op')),
                };
                if (!Vectors::same($got, $expect[$i])) {
                    $f[] = $sc->get('name') . " step $i (" . $s->get('op') . '): got ' . Json::canonicalizeLenient($got) . ' want ' . Json::canonicalizeLenient($expect[$i]);
                }
            }
        }
        return [$n, $f];
    }

    // ---- assurance-vectors.json (T8, B7) --------------------------------------------------------------------------------

    /** A vector hook: "unlabelled" is an object without a label, an Obj `{level, vendor?, preview?, ceremony?}` a labelled one, absent no hook. */
    private static function hook(mixed $spec): ?object
    {
        if ($spec === null) {
            return null;
        }
        $o = new \stdClass();
        if ($spec instanceof Obj) {
            Assurance::setLabel($o, new AssuranceLabel($spec->get('level'), is_string($spec->get('vendor')) ? $spec->get('vendor') : null,
                $spec->get('preview') === true, is_string($spec->get('ceremony')) ? $spec->get('ceremony') : null));
        }
        return $o;
    }

    /** A parsed-JSON tree as native PHP: an object becomes an associative array, numbers stay Num. */
    private static function native(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $a = [];
            foreach ($v->keys() as $k) {
                $a[$k] = self::native($v->get($k));
            }
            return $a;
        }
        return is_array($v) ? array_map([self::class, 'native'], $v) : $v;
    }

    /** @return array{int, list<string>} */
    public static function assurance(): array
    {
        $doc = Vectors::load('assurance-vectors.json');
        $n = 0;
        $f = [];
        foreach (self::rows($doc, 'signature_level') as $v) {
            $n++;
            if (Assurance::signatureLevel($v->get('alg')) !== $v->get('level')) {
                $f[] = 'signature_level ' . json_encode($v->get('alg')) . ': got ' . Assurance::signatureLevel($v->get('alg')) . ' want ' . $v->get('level');
            }
        }
        foreach (self::rows($doc, 'report') as $v) {
            $n++;
            $checks = [];
            foreach ($v->get('checks')->keys() as $k) {
                $checks[$k] = $v->get('checks')->get($k);
            }
            $hooks = [];
            $h = $v->get('hooks');
            foreach (['attestation', 'zk', 'threshold', 'revocation'] as $k) {
                if ($h instanceof Obj && $h->has($k)) {
                    $hooks[$k] = self::hook($h->get($k));
                }
            }
            $degraded = [];
            $d = $v->get('degraded');
            foreach ($d instanceof Obj ? $d->keys() : [] as $k) {
                $degraded[$k] = $d->get($k);
            }
            $rep = (Assurance::report($checks, $v->get('pcactn') instanceof Obj ? $v->get('pcactn') : null, $hooks,
                self::hook($v->get('attestation_hook')), $v->get('threshold_t') instanceof Num ? $v->get('threshold_t')->float() : null,
                $v->get('allow_unbound_pq') === true, $degraded));
            $got = $rep === [] ? new Obj() : Operations::jsonValue($rep);
            if (!Vectors::same($got, $v->get('report'))) {
                $f[] = 'report ' . $v->get('name') . ': got ' . Json::canonicalizeLenient($got) . ' want ' . Json::canonicalizeLenient($v->get('report'));
            }
        }
        foreach (self::rows($doc, 'requirement') as $v) {
            $n++;
            $got = Assurance::unmet(self::native($v->get('report')), AssuranceRequirement::fromJson($v->get('require')));
            if ($got !== $v->get('unmet')) {
                $f[] = 'requirement ' . $v->get('name') . ': got ' . json_encode($got) . ' want ' . json_encode($v->get('unmet'));
            }
        }
        foreach (self::rows($doc, 'multi_root') as $v) {
            $n++;
            $roots = [];
            foreach ($v->get('roots') as $r) {
                $roots[] = ['verifier' => self::hook($r), 'required' => $r->get('required') === true];
            }
            $got = Assurance::multiRootLevel($roots, self::intOf($v->get('threshold')));
            if ($got !== $v->get('level')) {
                $f[] = 'multi_root ' . $v->get('name') . ': got ' . $got . ' want ' . $v->get('level');
            }
        }
        return [$n, $f];
    }
}

/** The vector policy plus the row's `allow_unsigned_root_for_irreversible` flag. */
final class RevocationStalenessPolicyFromVector
{
    public static function of(Obj $v): RevocationStalenessPolicy
    {
        $p = RevocationStalenessPolicy::fromJson($v->get('policy'));
        return new RevocationStalenessPolicy($p->maxRevocationAgeMs, $p->staleness, $v->get('allow_unsigned_root_for_irreversible') === true);
    }
}
