<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Authorize.php';

/**
 * PCA behind the OpenID AuthZEN Authorization API 1.0: a Policy Decision Point (Access Evaluation, the Access Evaluations boxcar,
 * the COAZ MCP-tool profile, the AARP approval-required step-up), a framework-agnostic handler over {path, body} and the three
 * Search APIs. Mirrors @atlasauth/pca-authzen. Everything fails closed: an unresolved policy, a malformed PCActn, a verifier
 * rejection, a policy denial or any thrown error is `decision: false`.
 *
 * Config (assoc array, the reference's names): resolve(req) -> ctx|null (required); audience (absent = fail closed, null = accept
 * any, string = exact); authorizedPlanRoots; insecureSkipPlanRootCheck; now() -> epoch ms; toolCapability(name); requireProof
 * (default true); authorizer(input) -> {allow, reason}; requireAuthorizer (default true); maxEvaluations; decide;
 * deriveDecideInput; admitsConcrete. A ctx is {grant, chain?, policy, plan?, risk?, budget?, enforce?, toAction?}.
 * decide, deriveDecideInput and admitsConcrete default to the native policy engine (Decide) and static analyzer (AnalyzerCore); a config
 * entry overrides them. enforce.taint / enforce.attestation are refused (not wired to the native verifier).
 */
final class Authzen
{
    public const PCA_APPROVAL_KEY = 'pca_approval';
    public const PCA_ACTION_KEY = 'pca_action';
    public const PCA_PROVENANCE_KEY = 'pca_provenance';
    public const DEFAULT_MAX_EVALUATIONS = 100;
    public const EVALUATION_PATH = '/access/v1/evaluation';
    public const EVALUATIONS_PATH = '/access/v1/evaluations';
    public const COAZ_TOOL_PATH = '/access/v1/mcp/tool/evaluation';
    public const SEARCH_SUBJECT_PATH = '/access/v1/search/subject';
    public const SEARCH_RESOURCE_PATH = '/access/v1/search/resource';
    public const SEARCH_ACTION_PATH = '/access/v1/search/action';
    public const MAX_SEARCH_LIMIT = 1000;

    private static function rec(mixed $x): bool
    {
        return $x instanceof Obj || (is_array($x) && $x !== [] && !array_is_list($x));
    }

    private static function num(mixed $x): bool
    {
        $n = Js::num($x);
        return $n !== null && is_finite($n);
    }

    private static function nonEmpty(mixed $x): bool
    {
        return is_string($x) && $x !== '';
    }

    /** x.k in JavaScript: null throws, a non-object has no member (null here, `has` tells absent from null). */
    private static function prop(mixed $x, string $k): mixed
    {
        return Js::get($x, $k);
    }

    private static function errText(\Throwable $e): string
    {
        return $e->getMessage() !== '' ? $e->getMessage() : 'unknown';
    }

    // ---- guards ----

    public static function isAuthzenSubject(mixed $x): bool
    {
        return self::rec($x) && is_string(Js::opt($x, 'type')) && is_string(Js::opt($x, 'id'));
    }

    public static function isAuthzenAction(mixed $x): bool
    {
        return self::rec($x) && is_string(Js::opt($x, 'name'));
    }

    public static function isAuthzenResource(mixed $x): bool
    {
        return self::isAuthzenSubject($x);
    }

    public static function isAccessEvaluationRequest(mixed $x): bool
    {
        return self::rec($x) && self::isAuthzenSubject(Js::opt($x, 'subject')) && self::isAuthzenAction(Js::opt($x, 'action'))
            && self::isAuthzenResource(Js::opt($x, 'resource')) && (!Js::has($x, 'context') || self::rec(Js::opt($x, 'context')));
    }

    public static function isAccessEvaluationsRequest(mixed $x): bool
    {
        $e = Js::opt($x, 'evaluations');
        return self::rec($x) && is_array($e) && array_is_list($e);
    }

    public static function isCoazToolAuthorizationRequest(mixed $x): bool
    {
        $t = Js::opt($x, 'tool');
        return self::rec($x) && self::isAuthzenSubject(Js::opt($x, 'subject')) && self::rec($t) && is_string(Js::opt($t, 'name'));
    }

    private static function isRequiredThreshold(mixed $x): bool
    {
        return self::rec($x) && self::num(Js::opt($x, 't')) && in_array(Js::num(Js::opt($x, 't')), [1.0, 2.0, 3.0], true)
            && is_string(Js::opt($x, 'proof')) && is_bool(Js::opt($x, 'optimisticAllowed'));
    }

    // ---- AARP ----

    /** The AARP pending-approval reference of a decision, or null. */
    public static function approvalOf(mixed $resp): ?array
    {
        if (!Js::has($resp, 'context')) {
            self::prop($resp, 'context');
            return null;
        }
        $p = self::prop(self::prop($resp, 'context'), self::PCA_APPROVAL_KEY);
        if (!self::rec($p) || Js::opt($p, 'approval_required') !== true || !is_string(Js::opt($p, 'auth_req_id'))) {
            return null;
        }
        $tier = self::num(Js::opt($p, 'tier')) && Js::num(Js::opt($p, 'tier')) === 3.0 ? 3 : 2;
        $rt = Js::opt($p, 'required_threshold');
        $o = static fn(string $k, callable $ok, mixed $d): mixed => $ok(Js::opt($p, $k)) ? Js::opt($p, $k) : $d;
        return [
            'approval_required' => true,
            'auth_req_id' => Js::opt($p, 'auth_req_id'),
            'tier' => $tier,
            'required_threshold' => self::isRequiredThreshold($rt) ? $rt : ['t' => $tier, 'proof' => $tier === 3 ? 'strong' : 'standard', 'optimisticAllowed' => false],
            'goal_commit' => $o('goal_commit', 'is_string', ''),
            'risk' => $o('risk', self::num(...), 1),
            'reason' => $o('reason', 'is_string', 'approval required'),
            'requested_at' => $o('requested_at', self::num(...), 0),
        ];
    }

    public static function isApprovalRequired(mixed $resp): bool
    {
        return self::approvalOf($resp) !== null;
    }

    // ---- mapping ----

    private static function deny(string $reason, ?string $id = null, ?int $status = null): array
    {
        $context = ['reason_admin' => ['denied' => true, 'reason' => $reason], 'reason_user' => ['message' => $reason]];
        if ($status !== null) {
            $context['error'] = ['status' => $status, 'message' => $reason];
        }
        if ($id !== null) {
            $context['id'] = $id;
        }
        return ['decision' => false, 'context' => $context];
    }

    private static function permit(string $reason): array
    {
        return ['decision' => true, 'context' => ['reason_admin' => ['reason' => $reason]]];
    }

    private static function members(mixed $o): array
    {
        $out = [];
        foreach ($o instanceof Obj ? $o->keys() : (is_array($o) ? array_keys($o) : []) as $k) {
            $out[(string)$k] = Js::opt($o, (string)$k);
        }
        return $out;
    }

    /**
     * verb = action.name; resource = "type:id" (just the type when id is empty); params = resource.properties overlaid by
     * action.properties; subject = subject.properties; env = context minus the PCA keys.
     */
    public static function defaultToAction(mixed $req): array
    {
        $res = Js::opt($req, 'resource');
        $act = Js::opt($req, 'action');
        $id = Js::opt($res, 'id');
        $params = new Obj();
        foreach ([Js::opt($res, 'properties'), Js::opt($act, 'properties')] as $props) {
            if (self::rec($props)) {
                foreach (self::members($props) as $k => $v) {
                    $params->set($k, $v);
                }
            }
        }
        $out = ['verb' => Js::opt($act, 'name'), 'resource' => $id !== '' ? Js::opt($res, 'type') . ':' . $id : Js::opt($res, 'type'), 'params' => $params];
        $fromAction = Js::opt($act, 'properties');
        $fromCtx = Js::opt($req, 'context');
        if (self::rec($fromAction) && is_string(Js::opt($fromAction, 'reversibility_class'))) {
            $out['reversibilityClass'] = Js::opt($fromAction, 'reversibility_class');
        } elseif (self::rec($fromCtx) && is_string(Js::opt($fromCtx, 'reversibility_class'))) {
            $out['reversibilityClass'] = Js::opt($fromCtx, 'reversibility_class');
        }
        $sp = Js::opt(Js::opt($req, 'subject'), 'properties');
        if (self::rec($sp)) {
            $out['subject'] = $sp;
        }
        if (self::rec($fromCtx)) {
            $env = new Obj();
            foreach (self::members($fromCtx) as $k => $v) {
                if ($k !== self::PCA_ACTION_KEY && $k !== self::PCA_APPROVAL_KEY) {
                    $env->set($k, $v);
                }
            }
            if ($env->keys() !== []) {
                $out['env'] = $env;
            }
        }
        return $out;
    }

    /** The forwarded PCActn (an Obj), null when absent, or the string "malformed". */
    private static function pcactnFromContext(mixed $context): mixed
    {
        if (!self::rec($context)) {
            return null;
        }
        $raw = Js::opt($context, self::PCA_ACTION_KEY);
        if ($raw === null) {
            return null;
        }
        if (!is_string($raw) || strlen($raw) > Pca::MAX_ARTIFACT_BYTES) {
            return 'malformed';
        }
        try {
            $v = Json::parseStrict($raw);
            return $v instanceof Obj ? $v : 'malformed';
        } catch (\Throwable) {
            return 'malformed';
        }
    }

    private static function freshBudget(mixed $grant, int $now): array
    {
        $env = Authorize::readEnvelope($grant);
        $bMax = $env === null ? null : Js::opt($env->get('risk_policy'), 'bMax');
        return ['B' => self::num($bMax) ? $bMax : 0, 'tau' => $now, 'asOf' => $now];
    }

    private static function approvalRequired(Obj $p, mixed $decision, mixed $grant, int $now): array
    {
        $rt = Js::opt($decision, 'requiredThreshold');
        $tier = Js::num(Js::opt($rt, 't')) >= 3 ? 3 : 2;
        $reasons = Js::opt($decision, 'reasons');
        $reason = is_array($reasons) && $reasons !== [] ? $reasons[0] : "requires tier-$tier co-sign";
        $act = $p->get('action');
        $body = Obj::of(['d' => 'atlas-pca/authzen/aarp/v1', 'verb' => Js::opt($act, 'verb'), 'resource' => Js::opt($act, 'resource'),
            'params_digest' => Js::opt($act, 'params_digest'), 'at' => $now]);
        if ($p->has('counter')) {
            $body->set('counter', $p->get('counter'));
        }
        $id = Pca::hashCanonical(Sign::n($body));
        $env = Authorize::readEnvelope($grant);
        return ['decision' => false, 'context' => [
            'id' => $id,
            'reason_admin' => ['stage' => 'step_up', 'risk' => Js::opt($decision, 'r'), 'threshold' => $rt, 'reasons' => $reasons],
            'reason_user' => ['message' => 'approval required before this action can proceed'],
            self::PCA_APPROVAL_KEY => ['approval_required' => true, 'auth_req_id' => $id, 'tier' => $tier, 'required_threshold' => $rt,
                'goal_commit' => $env === null ? '' : $env->get('goal_commit'), 'risk' => Js::opt($decision, 'r'), 'reason' => $reason, 'requested_at' => $now],
        ]];
    }

    private static function mergeEvaluation(mixed $defaults, mixed $item): ?array
    {
        if ($item === null) {
            throw new \TypeError("Cannot read properties of null (reading 'subject')");
        }
        $pick = static fn(string $k): mixed => Js::opt($item, $k) ?? Js::opt($defaults, $k);
        [$s, $a, $r] = [$pick('subject'), $pick('action'), $pick('resource')];
        if (!self::isAuthzenSubject($s) || !self::isAuthzenAction($a) || !self::isAuthzenResource($r)) {
            return null;
        }
        $out = ['subject' => $s, 'action' => $a, 'resource' => $r];
        if (Js::opt($item, 'context') !== null) {
            $out['context'] = Js::opt($item, 'context');
        } elseif (Js::has($defaults, 'context')) {
            $out['context'] = Js::opt($defaults, 'context');
        }
        return $out;
    }

    private static function need(array $c, string $name): callable
    {
        $c += ['decide' => static fn(mixed $i): array => Decide::decide($i), 'deriveDecideInput' => Decide::deriveDecideInput(...),
            'admitsConcrete' => AnalyzerCore::admitsConcrete(...)];
        $fn = $c[$name] ?? null;
        if (!is_callable($fn) || is_string($fn)) {
            throw new \RuntimeException("authzen: config.$name is not provided (fail closed)");
        }
        return $fn;
    }

    /** `${o.k}`: an absent member renders as undefined. */
    private static function js(mixed $o, string $k): string
    {
        return Js::has($o, $k) ? IntentWb::jsStr(Js::opt($o, $k)) : 'undefined';
    }

    /** One Access Evaluation. */
    public static function evaluate(array $c, mixed $req): array
    {
        $now = (int)Js::num(isset($c['now']) ? ($c['now'])() : (int)floor(microtime(true) * 1000));
        try {
            $ctx = ($c['resolve'])($req);
            if ($ctx === null) {
                return self::deny('no PCA authority resolved for this request');
            }
            $ta = Js::opt($ctx, 'toAction');
            $mapped = ($ta ?? self::defaultToAction(...))($req);
            $carried = self::pcactnFromContext(Js::opt($req, 'context'));
            if ($carried === 'malformed') {
                return self::deny('context carries a malformed PCActn');
            }
            if ($carried === null) {
                if (($c['requireProof'] ?? null) !== false) {
                    return self::deny('a signed PCActn is required (requireProof)');
                }
                return self::need($c, 'admitsConcrete')(Js::opt($ctx, 'policy'), $mapped)
                    ? self::permit('statically admissible under the declared authority')
                    : self::deny('action is not admissible under the declared authority');
            }
            $p = $carried;
            if (($c['requireAuthorizer'] ?? null) !== false && ($c['authorizer'] ?? null) === null) {
                return self::deny('no replay/revocation authorizer is configured (requireAuthorizer)');
            }
            // the proof must be FOR this request: verb + resource, and the attributes must hash to the signed params_digest
            if (!$p->has('action') || $p->get('action') === null) {
                throw new \TypeError("Cannot read properties of " . ($p->has('action') ? 'null' : 'undefined') . " (reading 'verb')");
            }
            $act = $p->get('action');
            $verb = Js::opt($act, 'verb');
            $resource = Js::opt($act, 'resource');
            if (!Js::has($act, 'verb') || $verb !== Js::opt($mapped, 'verb') || !Js::has($act, 'resource') || $resource !== Js::opt($mapped, 'resource')) {
                return self::deny('the PCActn authorizes ' . self::js($act, 'verb') . ' on ' . self::js($act, 'resource')
                    . ', not the requested ' . self::js($mapped, 'verb') . ' on ' . self::js($mapped, 'resource'));
            }
            $mp = Js::opt($mapped, 'params');
            $reqParams = self::rec($mp) || $mp instanceof Obj ? $mp : new Obj();
            if (!Js::has($act, 'params_digest') || Pca::paramsDigest(Sign::n($reqParams)) !== Js::opt($act, 'params_digest')) {
                return self::deny("the request attributes do not match the PCActn's signed params_digest");
            }
            $audience = $c['audience'] ?? null;
            if (array_key_exists('audience', $c) && $audience === null && self::nonEmpty($p->get('aud'))) {
                $audience = $p->get('aud'); // explicit opt-out: accept any audience
            }
            $enforce = Js::opt($ctx, 'enforce');
            if (Js::opt($enforce, 'attestation') !== null || Js::opt($enforce, 'taint') !== null) {
                throw new \RuntimeException('authzen: enforce.attestation / enforce.taint are not supported by this verifier (fail closed)');
            }
            $fresh = Js::opt($enforce, 'freshness');
            $roots = $c['authorizedPlanRoots'] ?? null;
            $verify = Pca::verifyPcactnCore($p, Js::opt($ctx, 'grant'), $now, is_string($audience) ? $audience : '', null, null, null, null,
                is_array($roots) ? $roots : null, (bool)($c['insecureSkipPlanRootCheck'] ?? false), is_array($fresh) ? $fresh : ($fresh instanceof Obj ? self::members($fresh) : null));
            if ($verify['allow'] !== true) {
                return ['decision' => false, 'context' => [
                    'reason_admin' => ['denied' => true, 'stage' => 'verify', 'checks' => $verify['checks'], 'reason' => $verify['reason'] ?? 'PCActn verification failed'],
                    'reason_user' => ['message' => 'the proof-carrying action did not verify']]];
            }
            $dctx = ['grant' => Js::opt($ctx, 'grant'), 'chain' => Js::opt($ctx, 'chain') ?? $p->get('cap_chain'), 'params' => $reqParams,
                'risk' => Js::opt($ctx, 'risk') ?? new Obj(), 'budget' => Js::opt($ctx, 'budget') ?? self::freshBudget(Js::opt($ctx, 'grant'), $now), 'now' => $now];
            foreach (['plan' => $ctx, 'subject' => $mapped, 'env' => $mapped] as $k => $src) {
                if (Js::opt($src, $k) !== null) {
                    $dctx[$k] = Js::opt($src, $k);
                }
            }
            $decision = self::need($c, 'decide')(self::need($c, 'deriveDecideInput')($p, $dctx));
            if (!Js::truthy(Js::opt($decision, 'releaseGuardianShare'))) {
                return ['decision' => false, 'context' => [
                    'reason_admin' => ['denied' => true, 'stage' => 'policy', 'reasons' => Js::opt($decision, 'reasons'), 'risk' => Js::opt($decision, 'r')],
                    'reason_user' => ['message' => 'the policy does not permit this action']]];
            }
            if (Js::truthy(Js::opt($decision, 'admit'))) {
                if (($c['authorizer'] ?? null) !== null) {
                    $ain = ['operation' => ['verb' => Js::opt($mapped, 'verb'), 'resource' => Js::opt($mapped, 'resource'), 'params' => $reqParams], 'pcactn' => $p];
                    $rc = Js::opt($req, 'context');
                    if (self::rec($rc) && Js::has($rc, self::PCA_PROVENANCE_KEY)) {
                        $ain['provenance'] = Js::opt($rc, self::PCA_PROVENANCE_KEY);
                    }
                    $az = ($c['authorizer'])($ain);
                    $allow = is_object($az) && !($az instanceof Obj) ? ($az->allow ?? null) : Js::opt($az, 'allow');
                    if (!Js::truthy($allow)) {
                        $reason = is_object($az) && !($az instanceof Obj) ? ($az->reason ?? null) : Js::opt($az, 'reason');
                        return ['decision' => false, 'context' => [
                            'reason_admin' => ['denied' => true, 'stage' => 'authorize', 'reason' => $reason],
                            'reason_user' => ['message' => 'the proof-carrying action was not authorized']]];
                    }
                }
                return ['decision' => true, 'context' => ['reason_admin' => ['stage' => 'policy', 'risk' => Js::opt($decision, 'r'), 'threshold' => Js::opt($decision, 'requiredThreshold')]]];
            }
            return self::approvalRequired($p, $decision, Js::opt($ctx, 'grant'), $now);
        } catch (\Throwable $e) { // fail closed
            return self::deny('evaluation error (fail closed): ' . self::errText($e), null, 500);
        }
    }

    /** The Access Evaluations boxcar (execute_all, deny_on_first_deny, permit_on_first_permit). */
    public static function evaluations(array $c, mixed $req): array
    {
        $items = self::prop($req, 'evaluations');
        if (!is_array($items) || !array_is_list($items)) {
            return ['evaluations' => []];
        }
        $opts = self::prop($req, 'options');
        $semantic = self::rec($opts) ? Js::opt($opts, 'evaluations_semantic') : null;
        $semantic ??= 'execute_all';
        $refuse = static fn(string $reason): array => ['evaluations' => array_map(static fn() => self::deny($reason, null, 400), $items)];
        if (!in_array($semantic, ['execute_all', 'deny_on_first_deny', 'permit_on_first_permit'], true)) {
            return $refuse('unsupported evaluations_semantic');
        }
        $mx = $c['maxEvaluations'] ?? self::DEFAULT_MAX_EVALUATIONS;
        if (count($items) > (Js::num($mx) ?? NAN)) {
            return $refuse('too many evaluations (limit ' . IntentWb::jsStr($mx) . ')');
        }
        $merged = array_map(static fn(mixed $it): ?array => self::mergeEvaluation($req, $it), $items);
        $out = [];
        foreach ($merged as $m) {
            $r = $m === null ? self::deny('incomplete evaluation (missing subject/action/resource)', null, 400) : self::evaluate($c, $m);
            $out[] = $r;
            if (($semantic === 'deny_on_first_deny' && $r['decision'] === false) || ($semantic === 'permit_on_first_permit' && $r['decision'] === true)) {
                break;
            }
        }
        return ['evaluations' => $out];
    }

    /** The COAZ MCP-tool profile: the tool maps to a capability (config toolCapability, default the tool name). */
    public static function evaluateTool(array $c, mixed $req): array
    {
        $tool = self::prop($req, 'tool');
        $name = self::prop($tool, 'name');
        try {
            $capability = isset($c['toolCapability']) ? ($c['toolCapability'])($name) : $name;
        } catch (\Throwable $e) { // fail closed
            return ['decision' => false, 'tool' => $name, 'required_capability' => '',
                'context' => self::deny('evaluation error (fail closed): ' . self::errText($e), null, 500)['context']];
        }
        $action = ['name' => $capability];
        if (Js::has($tool, 'arguments')) {
            $action['properties'] = Js::opt($tool, 'arguments');
        }
        $mapped = ['subject' => Js::opt($req, 'subject'), 'action' => $action, 'resource' => ['type' => 'mcp_tool', 'id' => $name]];
        if (Js::has($req, 'context')) {
            $mapped['context'] = Js::opt($req, 'context');
        }
        $resp = self::evaluate($c, $mapped);
        return ['decision' => $resp['decision'], 'tool' => $name, 'required_capability' => $capability, 'context' => $resp['context']];
    }

    // ---- handler ----

    /** handler({path, body}) -> {status, body}. A malformed body is a 400; any thrown error is a 500 with no detail. */
    public static function handler(array $c): \Closure
    {
        return static function (mixed $req) use ($c): array {
            try {
                $path = Js::opt($req, 'path');
                $body = Js::opt($req, 'body');
                if ($path === self::EVALUATION_PATH) {
                    return self::isAccessEvaluationRequest($body) ? ['status' => 200, 'body' => self::evaluate($c, $body)]
                        : ['status' => 400, 'body' => ['error' => 'invalid AuthZEN Access Evaluation request']];
                }
                if ($path === self::EVALUATIONS_PATH) {
                    $ev = Js::opt($body, 'evaluations');
                    // an absent or empty `evaluations` array is a plain single Access Evaluation
                    if (self::rec($body) && (!Js::has($body, 'evaluations') || $ev === [])) {
                        return self::isAccessEvaluationRequest($body) ? ['status' => 200, 'body' => self::evaluate($c, $body)]
                            : ['status' => 400, 'body' => ['error' => 'invalid AuthZEN Access Evaluations request']];
                    }
                    return self::isAccessEvaluationsRequest($body) ? ['status' => 200, 'body' => self::evaluations($c, $body)]
                        : ['status' => 400, 'body' => ['error' => 'invalid AuthZEN Access Evaluations request']];
                }
                if ($path === self::COAZ_TOOL_PATH) {
                    return self::isCoazToolAuthorizationRequest($body) ? ['status' => 200, 'body' => self::evaluateTool($c, $body)]
                        : ['status' => 400, 'body' => ['error' => 'invalid COAZ MCP-tool authorization request']];
                }
                return ['status' => 404, 'body' => ['error' => 'unknown AuthZEN path: ' . self::js($req, 'path')]];
            } catch (\Throwable) { // a PEP treats non-200 as a deny; never leak internals
                return ['status' => 500, 'body' => ['error' => 'internal error']];
            }
        };
    }

    // ---- search ----

    private static function entity(mixed $x, bool $needId): bool
    {
        return self::rec($x) && self::nonEmpty(Js::opt($x, 'type')) && (!$needId || self::nonEmpty(Js::opt($x, 'id')))
            && (!Js::has($x, 'properties') || self::rec(Js::opt($x, 'properties')));
    }

    private static function action(mixed $x): bool
    {
        return self::rec($x) && self::nonEmpty(Js::opt($x, 'name')) && (!Js::has($x, 'properties') || self::rec(Js::opt($x, 'properties')));
    }

    private static function pageOk(mixed $b): bool
    {
        if (!Js::has($b, 'page')) {
            return true;
        }
        $p = Js::opt($b, 'page');
        if (!self::rec($p)) {
            return false;
        }
        if (Js::has($p, 'token') && !is_string(Js::opt($p, 'token'))) {
            return false;
        }
        if (Js::has($p, 'limit') && (!K3Sig::isNonNegSafeInt(Js::opt($p, 'limit')) || K3Sig::isNegZero(Js::opt($p, 'limit')))) { // -0 is refused
            return false;
        }
        return !Js::has($p, 'properties') || self::rec(Js::opt($p, 'properties'));
    }

    private static function base(mixed $b): bool
    {
        return (!Js::has($b, 'context') || self::rec(Js::opt($b, 'context'))) && self::pageOk($b);
    }

    public static function isSubjectSearch(mixed $b): bool
    {
        return self::rec($b) && self::base($b) && self::entity(Js::opt($b, 'subject'), false) && self::action(Js::opt($b, 'action'))
            && self::entity(Js::opt($b, 'resource'), true);
    }

    public static function isResourceSearch(mixed $b): bool
    {
        return self::rec($b) && self::base($b) && self::entity(Js::opt($b, 'subject'), true) && self::action(Js::opt($b, 'action'))
            && self::entity(Js::opt($b, 'resource'), false);
    }

    public static function isActionSearch(mixed $b): bool
    {
        return self::rec($b) && self::base($b) && !Js::has($b, 'action') && self::entity(Js::opt($b, 'subject'), true)
            && self::entity(Js::opt($b, 'resource'), true);
    }

    private static function providerFn(mixed $p, string $name): ?callable
    {
        $fn = is_array($p) ? ($p[$name] ?? null) : (is_object($p) && method_exists($p, $name) ? [$p, $name] : null);
        return is_callable($fn) && !is_string($fn) ? $fn : null;
    }

    /** Fragment for /.well-known/authzen-configuration; a missing endpoint means that search is unsupported. */
    public static function searchMetadata(string $base, mixed $p): Obj
    {
        $out = new Obj();
        foreach (['searchSubject' => ['search_subject_endpoint', self::SEARCH_SUBJECT_PATH], 'searchResource' => ['search_resource_endpoint', self::SEARCH_RESOURCE_PATH],
            'searchAction' => ['search_action_endpoint', self::SEARCH_ACTION_PATH]] as $fn => [$k, $path]) {
            if (self::providerFn($p, $fn) !== null) {
                $out->set($k, $base . $path);
            }
        }
        return $out;
    }

    private static function stripId(mixed $req, string $key): Obj
    {
        $e = new Obj();
        foreach (self::members(Js::opt($req, $key)) as $k => $v) {
            if ($k !== 'id') {
                $e->set($k, $v);
            }
        }
        $out = new Obj();
        foreach (self::members($req) as $k => $v) {
            $out->set($k, $k === $key ? $e : $v);
        }
        return $out;
    }

    private static function shape(mixed $r, mixed $limit, callable $typeOk): array
    {
        $in = self::prop($r, 'results');
        if (!is_array($in) || !array_is_list($in)) {
            throw new \TypeError('results.filter is not a function');
        }
        $seen = [];
        $results = [];
        foreach ($in as $t) {
            if (!$typeOk($t)) {
                continue;
            }
            $k = Js::stringify($t);
            if (isset($seen[$k])) {
                continue;
            }
            $seen[$k] = true;
            $results[] = $t;
        }
        $lim = Js::num($limit);
        $capped = $lim !== null && $lim > 0 ? array_slice($results, 0, (int)$lim) : $results;
        // a provider that ignores the limit would hide results behind a page marker we cannot resume: fail closed
        if (count($capped) < count($results)) {
            throw new \RangeException('provider returned more than the page limit');
        }
        $out = [];
        $pg = Js::opt($r, 'page');
        if (Js::truthy($pg)) {
            $page = [];
            if (Js::has($pg, 'next_token')) {
                $page['next_token'] = Js::opt($pg, 'next_token');
            }
            $page['count'] = count($capped);
            if (Js::has($pg, 'total')) {
                $page['total'] = Js::opt($pg, 'total');
            }
            if (Js::truthy(Js::opt($pg, 'properties'))) {
                $page['properties'] = Js::opt($pg, 'properties');
            }
            $out['page'] = $page;
        }
        if (Js::truthy(Js::opt($r, 'context'))) {
            $out['context'] = Js::opt($r, 'context');
        }
        $out['results'] = $capped;
        return $out;
    }

    /** The search handler; null for a path that is not a search path (so it chains after `handler`). */
    public static function searchHandler(mixed $p): \Closure
    {
        return static function (mixed $req) use ($p): ?array {
            try {
                $path = Js::opt($req, 'path');
                $body = Js::opt($req, 'body');
                $lim = static fn(): mixed => Js::has($body, 'page') ? Js::opt(Js::opt($body, 'page'), 'limit') : null;
                $ofType = static fn(string $t): \Closure => static fn(mixed $e): bool => self::prop($e, 'type') === $t;
                foreach ([[self::SEARCH_SUBJECT_PATH, 'searchSubject', 'subject', self::isSubjectSearch(...)],
                    [self::SEARCH_RESOURCE_PATH, 'searchResource', 'resource', self::isResourceSearch(...)],
                    [self::SEARCH_ACTION_PATH, 'searchAction', null, self::isActionSearch(...)]] as [$route, $fnName, $key, $valid]) {
                    if ($path !== $route) {
                        continue;
                    }
                    $what = $key ?? 'action';
                    $fn = self::providerFn($p, $fnName);
                    if ($fn === null) {
                        return ['status' => 404, 'body' => ['error' => "$what search is not supported"]];
                    }
                    if (!$valid($body)) {
                        return ['status' => 400, 'body' => ['error' => "invalid AuthZEN $what search request"]];
                    }
                    $res = $key === null ? $fn($body) : $fn(self::stripId($body, $key));
                    $ok = $key === null ? static fn(): bool => true : $ofType(Js::opt(Js::opt($body, $key), 'type'));
                    return ['status' => 200, 'body' => self::shape($res, $lim(), $ok)];
                }
                return null;
            } catch (\Throwable) {
                return ['status' => 500, 'body' => ['error' => 'internal error']];
            }
        };
    }
}
