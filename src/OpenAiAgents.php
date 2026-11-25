<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/OpenAi/ToolDispatch.php';

/**
 * A guarded tool refused to run. `kind`: missing | malformed | verify | binding | policy | replay | revoked | config. The agent SDK
 * reports a thrown tool error to the model; `checks` are the per-check verdicts of the verifier when the refusal was a verification.
 */
final class PcaToolDenied extends \RuntimeException
{
    /** @param array<mixed>|Obj|null $checks */
    public function __construct(string $message, public readonly string $verb, public readonly string $kind, public readonly mixed $checks = null)
    {
        parent::__construct("PCA tool denied ($kind) for $verb: $message");
    }
}

/**
 * A copy of an object tool with some callable members replaced (PHP has no singleton methods). Method calls go to the replacement
 * when there is one, else to the wrapped tool; property reads likewise.
 */
final class AgentToolProxy
{
    /** @param array<string,callable> $over */
    public function __construct(private readonly object $tool, private readonly array $over)
    {
    }

    /** @param array<mixed> $args */
    public function __call(string $name, array $args): mixed
    {
        if (isset($this->over[$name])) {
            return ($this->over[$name])(...$args);
        }
        return $this->tool->{$name}(...$args);
    }

    public function __get(string $name): mixed
    {
        return $this->over[$name] ?? $this->tool->{$name};
    }

    public function __isset(string $name): bool
    {
        return isset($this->over[$name]) || isset($this->tool->{$name});
    }
}

/**
 * A signature-only proof gate for an agent run or one tool call: `execute($args)` returns `['tripwireTriggered' => bool, 'outputInfo' => ...]`
 * (wrap it in your SDK's guardrail object). It trips on any denial; a verifier that throws is not a denial (the error propagates).
 */
final class PcaGuardrail
{
    /** @param \Closure(mixed): mixed $source */
    public function __construct(
        public readonly string $name,
        private readonly \Closure $source,
        private readonly mixed $verify,
        private readonly string|Audience|null $audience,
        private readonly ?string $verb,
        private readonly string $label,
    ) {
    }

    /** @return array{tripwireTriggered: bool, outputInfo: array<string,mixed>} */
    public function execute(mixed $args): array
    {
        try {
            $v = OpenAiAgents::assertProof(($this->source)($args), $this->verify, $this->audience, $this->verb, $this->label, null);
        } catch (PcaToolDenied $e) {
            $info = ['kind' => $e->kind, 'verb' => $e->verb, 'reason' => $e->getMessage()];
            if ($e->checks !== null) {
                $info['checks'] = $e->checks;
            }
            return ['tripwireTriggered' => true, 'outputInfo' => $info];
        }
        return ['tripwireTriggered' => false, 'outputInfo' => ['verb' => OpenAiAgents::verbOf($v['pcactn'])]];
    }
}

/**
 * OpenAI Agents SDK guard for Proof-Carrying Authority (the TypeScript reference, @atlasauth/pca-openai-agents). There is no PHP
 * SDK for it, so the adapter is structural: a tool is an associative array (or an {@see Obj}) with `name`, and `execute(input, runContext)`
 * and/or `onInvokeTool(ctx, jsonText)`, or an object with those methods (a copy is then an {@see AgentToolProxy}). Options are
 * associative arrays keyed like the reference.
 *
 *  - withPcaTool / pcaTools: a call first REQUIRES a proof-carrying action (found in the run context), VERIFIES it (fail closed:
 *    {@see PcaToolDenied}) and only then runs the original. Default mode 'full': `authorize` (an array of the named arguments of
 *    {@see Authorize::authorize}: resolveGrant, stateStore, isRevoked, an optional `operation` closure `(input, runContext) => {verb, resource,
 *    params}`, and any other of its options) runs the whole pipeline: the input must hash to the signed params, grant limits, revocation and
 *    single use. Mode 'signature-only' with `verify` checks only the signature, chain, audience and window, which does NOT prove the grant
 *    permits the call.
 *  - pcaInputGuardrail / pcaToolGuard: signature-only pre-filters that trip when the run or call carries no valid proof.
 *  - reviewToolCall / pendingStepUps / pcaNeedsApproval / withApproval: map a risky tool to the SDK's `needsApproval` so the run
 *    interrupts for a guardian or human co-sign.
 *  - attachPca: the agent side, a tool whose every call is signed first.
 *
 * Options of withPcaTool: mode ('full' default | 'signature-only'); verify (a callable `(Obj pcactn) => array|Obj {allow, reason?, checks?}`, or
 * ['grant' => Obj, 'nowEpoch'? => int|callable, 'allowedSuites'?, 'authorizedPlanRoots'? => list, 'insecureSkipPlanRootCheck'?, 'enforceFreshness'?]);
 * authorize; audience (a string; present as null = accept any audience in signature-only mode; omitted = refused when the proof names one);
 * verb (bind the proof to this tool; also the default operation's verb) and resource (the default operation's resource); require (callable
 * `(input, runContext) => proof`); provenance (callable `(input, runContext) => bundle`); recorder (an object with tool(name, output));
 * onDeny `(PcaToolDenied, input)`; onVerified `(result, pcactn, input)`; now (int|callable, full mode).
 *
 * Differences from the reference: the review of an intended action is injected (option `review`, as in the other native ports: the PHP
 * agent has no built-in step-up review); the signature-only verifier supports no `hooks` / `enforce` members other than `enforceFreshness`
 * (they are refused); a proof is a parsed {@see Obj} or text, never a PHP array. Values are the parsed-JSON model of src/Json.php.
 */
final class OpenAiAgents
{
    // ---- proof sources --------------------------------------------------------------------------------------------------

    private static function isRecord(mixed $v): bool
    {
        return $v instanceof Obj || is_array($v);
    }

    private static function proofFromBag(mixed $bag): ?string
    {
        if (!self::isRecord($bag)) {
            return null;
        }
        $direct = Js::opt($bag, 'pca') ?? Js::opt($bag, 'pcaProof');
        return is_string($direct) ? $direct : null;
    }

    /** The encoded PCActn from `runContext.context.{pca|pcaProof}`, then from `runContext.{pca|pcaProof}`. */
    public static function proofFromRunContext(mixed $input, mixed $runContext): ?string
    {
        return self::proofFromBag(Js::opt($runContext, 'context')) ?? self::proofFromBag($runContext);
    }

    /** The call's provenance bundle: pcaProvenance / pca_provenance / PCA-Provenance on the context, then on the run context. */
    public static function provenanceFromRunContext(mixed $input, mixed $runContext): mixed
    {
        foreach ([Js::opt($runContext, 'context'), $runContext] as $bag) {
            if (!self::isRecord($bag)) {
                continue;
            }
            $v = Js::opt($bag, 'pcaProvenance') ?? Js::opt($bag, 'pca_provenance') ?? Js::opt($bag, 'PCA-Provenance');
            if ($v !== null) {
                return $v;
            }
        }
        return null;
    }

    /** A proof source reading a PCA-Action header value from a headers-like bag on the tool input (or the guardrail args). */
    public static function proofFromInputHeaders(string $field = 'headers', string $header = 'PCA-Action'): \Closure
    {
        return static function (mixed $input, mixed $runContext = null) use ($field, $header): ?string {
            if (!self::isRecord($input)) {
                return null;
            }
            $bag = Js::opt($input, $field);
            if (!self::isRecord($bag)) {
                return null;
            }
            $v = Js::opt($bag, $header);
            return is_string($v) ? $v : null;
        };
    }

    /** The guardrail default: the proof from the run context the SDK passes as `args.context`. */
    public static function guardrailProofFromContext(mixed $args): ?string
    {
        $outer = Js::opt($args, 'context');
        $inner = self::isRecord($outer) ? Js::opt($outer, 'context') : null;
        return self::proofFromBag($inner) ?? self::proofFromBag($outer);
    }

    /** A provenance bundle from an object, a JSON text or a base64url header value; null when it is none of them. */
    private static function provenanceFrom(mixed $v): ?Obj
    {
        if ($v === null) {
            return null;
        }
        if ($v instanceof Obj) {
            return $v;
        }
        if (!is_string($v) || $v === '') {
            return null;
        }
        try {
            $p = Json::parseStrict($v);
        } catch (\Throwable) {
            $text = Pca::decodePcaHeader($v);
            if ($text === null) {
                return null;
            }
            try {
                $p = Json::parseStrict($text);
            } catch (\Throwable) {
                return null;
            }
        }
        return $p instanceof Obj ? $p : null;
    }

    // ---- the proof pipeline ---------------------------------------------------------------------------------------------

    private static function decodeText(string $text): Obj
    {
        if (strlen($text) > Pca::MAX_ARTIFACT_BYTES) {
            throw new \InvalidArgumentException(Pca::ARTIFACT_SIZE_REASON);
        }
        $v = Json::parseStrict($text);
        if (!($v instanceof Obj)) {
            throw new \TypeError('decodePCActn: not an object');
        }
        return $v;
    }

    /** A PCActn from an Obj, its JSON text, or a base64url PCA-Action header value. */
    private static function toPcactn(mixed $raw): Obj
    {
        if ($raw instanceof Obj) {
            return $raw;
        }
        if (!is_string($raw)) {
            throw new \TypeError('the proof is neither a PCActn object nor encoded text');
        }
        try {
            return self::decodeText($raw);
        } catch (\Throwable) {
            $text = Pca::decodePcaHeader($raw);
            if ($text === null) {
                throw new \InvalidArgumentException('the proof is not JSON and not a strict base64url header value');
            }
            return self::decodeText($text);
        }
    }

    /** The verb a PCActn claims, or null. */
    public static function verbOf(mixed $pcactn): mixed
    {
        return Js::opt(Js::opt($pcactn, 'action'), 'verb');
    }

    private static function wallClock(): int
    {
        return (int)(microtime(true) * 1000);
    }

    private static function audienceOf(array $options): string|Audience|null
    {
        if (!array_key_exists('audience', $options)) {
            return null;
        }
        $a = $options['audience'];
        return is_string($a) ? $a : ($a === null ? Audience::Any : null);
    }

    private static function runVerify(mixed $verify, Obj $pcactn, string|Audience|null $audience): mixed
    {
        if (is_callable($verify)) {
            return $verify($pcactn);
        }
        $grant = Js::opt($verify, 'grant');
        if (!($grant instanceof Obj)) {
            return ['allow' => false, 'checks' => [], 'reason' => 'no verifier configured'];
        }
        $now = Js::opt($verify, 'nowEpoch');
        $now = is_callable($now) ? $now() : $now;
        $now = $now instanceof Num ? $now->int() : ($now === null ? self::wallClock() : (int)$now);
        $roots = Js::opt($verify, 'authorizedPlanRoots');
        $suites = Js::opt($verify, 'allowedSuites');
        $fresh = Js::opt($verify, 'enforceFreshness');
        return Pca::verifyPcactnCore($pcactn, $grant, $now, $audience, is_array($suites) ? $suites : null, null, null, null,
            is_array($roots) ? $roots : null, Js::opt($verify, 'insecureSkipPlanRootCheck') === true, is_array($fresh) ? $fresh : null);
    }

    /**
     * Decode, bind to the verb, then verify (or run the full policy `$full(Obj): array{allow, kind?, reason?, checks?}`). Returns the verified
     * PCActn and the verdict, or throws {@see PcaToolDenied}. Not part of the public contract (the guardrail class calls it).
     *
     * @internal
     * @return array{pcactn: Obj, result: mixed}
     */
    public static function assertProof(mixed $raw, mixed $verify, string|Audience|null $audience, ?string $verb, string $label, ?\Closure $full): array
    {
        if ($raw === null) {
            throw new PcaToolDenied('no proof-carrying action present on the call', $label, 'missing');
        }
        try {
            $pcactn = self::toPcactn($raw);
        } catch (\Throwable $cause) {
            throw new PcaToolDenied('proof could not be decoded: ' . $cause->getMessage(), $label, 'malformed');
        }
        $got = self::verbOf($pcactn);
        $gotText = $got === null ? $label : Js::str($got);
        if ($verb !== null && $got !== $verb) {
            throw new PcaToolDenied("proof is for '" . ($got === null ? 'undefined' : Js::str($got)) . "', not this tool's '$verb'", $gotText, 'binding');
        }
        if ($full !== null) {
            $d = $full($pcactn);
            if ($d['allow'] !== true) {
                throw new PcaToolDenied((string)$d['reason'], $gotText, $d['kind'] === 'authn' ? 'verify' : (string)$d['kind'], $d['checks'] ?? null);
            }
            return ['pcactn' => $pcactn, 'result' => ['allow' => true, 'checks' => $d['checks'] ?? []]];
        }
        $result = self::runVerify($verify, $pcactn, $audience);
        if (Js::opt($result, 'allow') !== true) {
            $reason = Js::opt($result, 'reason');
            throw new PcaToolDenied($reason === null ? 'verification failed' : Js::str($reason), $gotText, 'verify', Js::opt($result, 'checks'));
        }
        return ['pcactn' => $pcactn, 'result' => $result];
    }

    /**
     * Binding of the proof to the operation, then {@see Authorize::authorize} (replay, revocation, limits).
     *
     * @param array<string,mixed> $auth the named arguments of Authorize::authorize (resolveGrant, stateStore, isRevoked and the rest)
     * @param array{verb: mixed, resource: mixed, params: mixed} $op
     * @return array{allow: bool, kind?: string, reason?: string, checks?: array<string,string>}
     */
    private static function authorizeExecution(array $auth, string $audience, Obj $pcactn, array $op, mixed $bundle, mixed $now): array
    {
        $a = $pcactn->get('action');
        $verb = Js::opt($a, 'verb');
        $res = Js::opt($a, 'resource');
        if ($verb !== $op['verb'] || ($op['resource'] !== null && $res !== $op['resource'])) {
            $want = $op['resource'] === null ? Js::str($op['verb']) : Js::str($op['verb']) . ' on ' . Js::str($op['resource']);
            return ['allow' => false, 'kind' => 'binding', 'reason' => 'the proof is for ' . ($verb === null ? 'undefined' : Js::str($verb))
                . ' on ' . ($res === null ? 'undefined' : Js::str($res)) . ', but this call is ' . $want];
        }
        try {
            $clock = is_callable($now) ? $now() : $now;
            $named = array_merge($auth, ['now' => $clock === null ? self::wallClock() : (int)$clock, 'provenance' => $bundle]);
            $resolve = $named['resolveGrant'] ?? null;
            $store = $named['stateStore'] ?? null;
            $revoked = $named['isRevoked'] ?? null;
            unset($named['resolveGrant'], $named['stateStore'], $named['isRevoked']);
            $r = Authorize::authorize($pcactn, $op, $audience, $resolve, $store, $revoked, ...$named);
        } catch (\Throwable $e) { // fail closed
            $short = substr(strrchr('\\' . get_class($e), '\\'), 1);
            return ['allow' => false, 'kind' => 'policy', 'reason' => 'authorization error (fail closed): ' . $short];
        }
        if ($r->allow) {
            return ['allow' => true, 'checks' => $r->checks];
        }
        $checks = $r->checks;
        if ($r->missing !== null && $r->missing !== []) {
            $kind = 'config';
        } elseif ($r->status === 401) {
            $kind = 'authn';
        } elseif (($checks['revocation'] ?? null) === 'fail') {
            $kind = 'revoked';
        } elseif (($checks['replay'] ?? null) === 'fail') {
            $kind = 'replay';
        } else {
            $kind = 'policy';
        }
        return ['allow' => false, 'kind' => $kind, 'reason' => ($r->reason !== null && $r->reason !== '') ? $r->reason : 'denied', 'checks' => $checks];
    }

    /** An options Obj / array as a PHP associative array with string keys, or null. @return array<string,mixed>|null */
    private static function assoc(mixed $o): ?array
    {
        if ($o instanceof Obj) {
            $out = [];
            foreach ($o->keys() as $k) {
                $out[$k] = $o->get($k);
            }
            return $out;
        }
        if (is_array($o) && ($o === [] || !array_is_list($o))) {
            return $o;
        }
        return null;
    }

    /**
     * Full-policy mode: check the configuration once (throws \TypeError on a missing component) and return the per-call check
     * `(Obj pcactn, input, runContext): decision`, or null for signature-only mode.
     *
     * @param array<string,mixed> $options
     */
    private static function fullPolicy(array $options): ?\Closure
    {
        $mode = $options['mode'] ?? 'full';
        if ($mode !== 'full' && $mode !== 'signature-only') {
            throw new \TypeError("withPcaTool: unknown mode '" . (is_string($mode) ? $mode : Js::str($mode)) . "'");
        }
        $authOpt = $options['authorize'] ?? null;
        if ($mode === 'signature-only') {
            if ($authOpt !== null) {
                throw new \TypeError("withPcaTool: `authorize` is the full mode; drop it, or drop mode: 'signature-only'");
            }
            if (($options['verify'] ?? null) === null) {
                throw new \TypeError("withPcaTool: mode 'signature-only' needs `verify`");
            }
            return null;
        }
        if ($authOpt === null) {
            throw new \TypeError("withPcaTool: pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only");
        }
        if (($options['verify'] ?? null) !== null) {
            throw new \TypeError("withPcaTool: `verify` checks the signature only: set mode: 'signature-only' to use it, and drop `authorize`");
        }
        $auth = self::assoc($authOpt);
        if ($auth === null) {
            throw new \TypeError('withPcaTool: `authorize` is an array of the options of Authorize::authorize');
        }
        $audience = is_string($options['audience'] ?? null) ? $options['audience'] : null;
        $operation = $auth['operation'] ?? null;
        $missing = Authorize::missingAuthorizeComponents($audience, $auth['resolveGrant'] ?? null, $auth['stateStore'] ?? null, $auth['isRevoked'] ?? null);
        $verb = $options['verb'] ?? null;
        $resource = $options['resource'] ?? null;
        if ($operation === null && ($verb === null || $resource === null)) {
            $missing[] = "operation (or the guard's verb and resource)";
        }
        if ($operation !== null && !is_callable($operation)) {
            $missing[] = 'operation (callable)';
        }
        $rest = array_diff_key($auth, array_flip(['operation', 'audience', 'now', 'provenance']));
        foreach (array_keys($rest) as $k) {
            if (!is_string($k)) {
                $missing[] = 'authorize (string keys only)';
                break;
            }
        }
        if ($missing !== []) {
            throw new \TypeError('withPcaTool: full policy mode is missing ' . implode(', ', $missing));
        }
        $prov = $options['provenance'] ?? self::provenanceFromRunContext(...);
        $now = $options['now'] ?? null;
        return static function (Obj $pcactn, mixed $input, mixed $runContext) use ($operation, $verb, $resource, $prov, $now, $rest, $audience): array {
            $op = $operation !== null ? $operation($input, $runContext) : ['verb' => $verb, 'resource' => $resource, 'params' => self::isRecord($input) ? $input : []];
            $params = Js::opt($op, 'params');
            if (is_array($params) && ($params === [] || !array_is_list($params))) {
                $params = Obj::of($params);
            }
            $bundle = Js::opt($op, 'provenance');
            if ($bundle === null) {
                $bundle = self::provenanceFrom($prov($input, $runContext));
            }
            $operationArg = ['verb' => Js::opt($op, 'verb'), 'resource' => Js::opt($op, 'resource'), 'params' => $params];
            return self::authorizeExecution($rest, (string)$audience, $pcactn, $operationArg, $bundle, $now);
        };
    }

    // ---- tool shapes ----------------------------------------------------------------------------------------------------

    /** A data member of a tool (array, Obj or object), or null. */
    private static function member(mixed $tool, string $k): mixed
    {
        if ($tool instanceof Obj || is_array($tool)) {
            return Js::opt($tool, $k);
        }
        return is_object($tool) && isset($tool->{$k}) ? $tool->{$k} : null;
    }

    /** The callable member `$name` of a tool, or null. */
    private static function callableOf(mixed $tool, string $name): ?\Closure
    {
        if ($tool instanceof Obj || is_array($tool)) {
            $c = Js::opt($tool, $name);
            return is_callable($c) ? \Closure::fromCallable($c) : null;
        }
        if (!is_object($tool)) {
            return null;
        }
        if (is_callable([$tool, $name])) {
            return \Closure::fromCallable([$tool, $name]);
        }
        $p = $tool->{$name} ?? null;
        return is_callable($p) ? \Closure::fromCallable($p) : null;
    }

    /** A copy of the tool with the given callable members replaced; every other member is kept. @param array<string,callable> $attrs */
    private static function withAttrs(mixed $tool, array $attrs): mixed
    {
        if (is_array($tool)) {
            return array_merge($tool, $attrs);
        }
        if ($tool instanceof Obj) {
            $copy = new Obj();
            foreach ($tool->keys() as $k) {
                $copy->set($k, $tool->get($k));
            }
            foreach ($attrs as $k => $v) {
                $copy->set($k, $v);
            }
            return $copy;
        }
        if (!is_object($tool)) {
            throw new \TypeError('the tool must be an array, an Obj or an object');
        }
        return new AgentToolProxy($tool, $attrs);
    }

    /** The arguments of an `onInvokeTool` call: a JSON text parsed strictly, null when it does not parse, anything else as is. */
    private static function parseArgs(mixed $raw): mixed
    {
        if (!is_string($raw)) {
            return $raw;
        }
        try {
            return Json::parseStrict($raw);
        } catch (\Throwable) {
            return null;
        }
    }

    // ---- the execution guard --------------------------------------------------------------------------------------------

    /**
     * A copy of the tool whose every call first requires and verifies a proof (see the class comment); every other member is kept.
     *
     * @param array<string,mixed> $options
     */
    public static function withPcaTool(mixed $tool, array $options = []): mixed
    {
        $source = $options['require'] ?? self::proofFromRunContext(...);
        $name = self::member($tool, 'name');
        $verbOpt = $options['verb'] ?? null;
        $label = $verbOpt !== null ? Js::str($verbOpt) : ($name !== null ? Js::str($name) : '(tool)');
        $full = self::fullPolicy($options);
        $verify = $options['verify'] ?? null;
        if (($verify instanceof Obj || (is_array($verify) && !is_callable($verify)))) {
            foreach (['enforce', 'hooks'] as $k) {
                if (Js::has($verify, $k)) {
                    throw new \TypeError("withPcaTool: verify.$k is not supported here (enforceFreshness is, or use `authorize`)");
                }
            }
            $roots = Js::opt($verify, 'authorizedPlanRoots');
            $fresh = Js::opt($verify, 'enforceFreshness');
            if (($roots !== null && !is_array($roots)) || ($fresh !== null && !is_array($fresh))) {
                throw new \TypeError('withPcaTool: verify.authorizedPlanRoots and verify.enforceFreshness are PHP arrays');
            }
        }
        $audience = self::audienceOf($options);
        $onDeny = $options['onDeny'] ?? null;
        $onVerified = $options['onVerified'] ?? null;
        $recorder = $options['recorder'] ?? null;

        $guarded = function (mixed $input, mixed $runContext, \Closure $call) use ($source, $verify, $audience, $verbOpt, $label, $full, $onDeny, $onVerified, $recorder) {
            $ctx = $runContext ?? [];
            $raw = $source($input, $ctx);
            try {
                $verified = self::assertProof($raw, $verify, $audience, $verbOpt === null ? null : Js::str($verbOpt), $label,
                    $full === null ? null : static fn(Obj $p): array => $full($p, $input, $ctx));
            } catch (PcaToolDenied $e) {
                if ($onDeny !== null) {
                    $onDeny($e, $input);
                }
                throw $e;
            }
            if ($onVerified !== null) {
                $onVerified($verified['result'], $verified['pcactn'], $input);
            }
            $out = $call();
            if ($recorder !== null) {
                $v = self::verbOf($verified['pcactn']);
                $recorder->tool($v === null ? $label : Js::str($v), $out);
            }
            return $out;
        };

        $origInvoke = self::callableOf($tool, 'onInvokeTool');
        if ($origInvoke !== null) {
            return self::withAttrs($tool, ['onInvokeTool' => static function (mixed $ctx, mixed $raw = null, mixed ...$rest) use ($guarded, $origInvoke) {
                return $guarded(self::parseArgs($raw), $ctx, static fn() => $origInvoke($ctx, $raw, ...$rest));
            }]);
        }
        $origExec = self::callableOf($tool, 'execute');
        return self::withAttrs($tool, ['execute' => static function (mixed $input, mixed $runContext = null) use ($guarded, $origExec) {
            return $guarded($input, $runContext, static function () use ($origExec, $input, $runContext) {
                if ($origExec === null) {
                    throw new \RuntimeException('withPcaTool: the wrapped tool has no execute()');
                }
                return $origExec($input, $runContext);
            });
        }]);
    }

    /**
     * @param array<string,mixed> $base
     * @param array<string,mixed>|null $over
     * @return array<string,mixed>
     */
    private static function mergeOptions(array $base, ?array $over): array
    {
        if ($over === null || $over === []) {
            return $base;
        }
        $own = ($over['authorize'] ?? null) !== null;
        $out = [];
        // a per-tool authorize or verify replaces the shared mode (the two are exclusive)
        if ($own) {
            $out['authorize'] = $over['authorize'];
        } elseif (($over['verify'] ?? null) !== null) {
            $out['verify'] = $over['verify'];
        } else {
            foreach (['verify', 'authorize'] as $k) {
                if (($base[$k] ?? null) !== null) {
                    $out[$k] = $base[$k];
                }
            }
        }
        $mode = $over['mode'] ?? ($own ? null : ($base['mode'] ?? null));
        if ($mode !== null) {
            $out['mode'] = $mode;
        }
        foreach (['require', 'verb', 'resource', 'onDeny', 'onVerified', 'provenance', 'recorder', 'now'] as $k) {
            $v = $over[$k] ?? $base[$k] ?? null;
            if ($v !== null) {
                $out[$k] = $v;
            }
        }
        if (array_key_exists('audience', $over)) {
            $out['audience'] = $over['audience'];
        } elseif (array_key_exists('audience', $base)) {
            $out['audience'] = $base['audience'];
        }
        return $out;
    }

    /**
     * Guard a `name => tool` array (or a list of tools, keyed by their name) with shared options. `options['per'][name]` overrides them for one
     * tool, `options['only']` limits the guarded set; every other tool passes through unchanged.
     *
     * @param array<mixed> $tools
     * @param array<string,mixed> $options
     * @return array<mixed>
     */
    public static function pcaTools(array $tools, array $options = []): array
    {
        $per = $options['per'] ?? [];
        $only = isset($options['only']) ? array_map(static fn($n) => (string)$n, $options['only']) : null;
        $shared = array_diff_key($options, ['per' => 1, 'only' => 1]);
        $one = static function (mixed $name, mixed $t) use ($per, $only, $shared): mixed {
            if ($only !== null && !in_array((string)$name, $only, true)) {
                return $t;
            }
            $over = $per[$name] ?? null;
            return self::withPcaTool($t, self::mergeOptions($shared, is_array($over) ? $over : null));
        };
        $out = [];
        if (array_is_list($tools)) {
            foreach ($tools as $t) {
                $out[] = $one(self::member($t, 'name'), $t);
            }
            return $out;
        }
        foreach ($tools as $name => $t) {
            $out[$name] = $one($name, $t);
        }
        return $out;
    }

    // ---- guardrails -----------------------------------------------------------------------------------------------------

    /** @param array<string,mixed> $options */
    private static function guardrail(string $default, array $options): PcaGuardrail
    {
        $verb = $options['verb'] ?? null;
        $source = $options['require'] ?? self::guardrailProofFromContext(...);
        return new PcaGuardrail((string)($options['name'] ?? $default), \Closure::fromCallable($source), $options['verify'] ?? null,
            self::audienceOf($options), $verb === null ? null : Js::str($verb), $verb === null ? '(run)' : Js::str($verb));
    }

    /**
     * An input guardrail: trips at the top of a run when the run context carries no valid proof. Options: verify (required), require,
     * audience, verb, name.
     *
     * @param array<string,mixed> $options
     */
    public static function pcaInputGuardrail(array $options = []): PcaGuardrail
    {
        return self::guardrail('pca-input-guardrail', $options);
    }

    /**
     * The same gate scoped to a tool call; prefer withPcaTool with `authorize` for the real check.
     *
     * @param array<string,mixed> $options
     */
    public static function pcaToolGuard(array $options = []): PcaGuardrail
    {
        return self::guardrail('pca-tool-guard', $options);
    }

    // ---- step-up --------------------------------------------------------------------------------------------------------

    private const REVIEW_KEYS = ['now', 'goal', 'standing', 'renderer', 'insecureUnboundApproval'];

    /**
     * Review one intended tool call: `options['intent'](tool, input)` maps it to {verb, resource, params?} (null = unguarded, auto), then
     * `options['review'](agent, verb, resource, params, opts)` returns ['kind' => 'auto'], ['kind' => 'deny', 'reason' => ...] or
     * ['kind' => 'step_up', 'request' => ...]. Other options: standing, goal, now, renderer, insecureUnboundApproval.
     *
     * @param array<string,mixed> $options
     * @return array{tool: string, review: mixed}
     */
    public static function reviewToolCall(mixed $agent, string $tool, mixed $input, array $options): array
    {
        $intent = $options['intent'] ?? null;
        if (!is_callable($intent)) {
            throw new \TypeError('reviewToolCall: pass `intent`, the mapping of a tool call to its action');
        }
        $mapped = $intent($tool, $input);
        if ($mapped === null) {
            return ['tool' => $tool, 'review' => ['kind' => 'auto']];
        }
        $review = $options['review'] ?? null;
        if (!is_callable($review)) {
            throw new \TypeError("reviewToolCall: pass `review`, the agent's review of an intended action");
        }
        $params = Js::opt($mapped, 'params');
        $opts = [];
        foreach (self::REVIEW_KEYS as $k) {
            if (($options[$k] ?? null) !== null) {
                $opts[$k] = $options[$k];
            }
        }
        return ['tool' => $tool, 'review' => $review($agent, Js::opt($mapped, 'verb'), Js::opt($mapped, 'resource'), $params ?? $input, $opts)];
    }

    /**
     * The step-up requests among reviewToolCall results (auto and deny are filtered out).
     *
     * @param iterable<mixed> $reviews
     * @return list<array{tool: mixed, request: mixed}>
     */
    public static function pendingStepUps(iterable $reviews): array
    {
        $out = [];
        foreach ($reviews as $r) {
            $review = Js::opt($r, 'review');
            if (Js::opt($review, 'kind') === 'step_up') {
                $out[] = ['tool' => Js::opt($r, 'tool'), 'request' => Js::opt($review, 'request')];
            }
        }
        return $out;
    }

    /**
     * The SDK's `needsApproval` callback `(runContext, input, callId = null): bool` from risk review: auto -> false; a step-up not yet co-signed ->
     * `options['onStepUp']({tool, request})` and true (the run interrupts); an already approved one (`options['approved'](request)`) -> false;
     * deny -> true unless `denyNeedsApproval` is false (the approver then rejects it). Options of reviewToolCall plus toolName.
     *
     * @param array<string,mixed> $options
     */
    public static function pcaNeedsApproval(mixed $agent, array $options): \Closure
    {
        $name = $options['toolName'] ?? '(tool)';
        $approved = $options['approved'] ?? null;
        $onStepUp = $options['onStepUp'] ?? null;
        $denyNeeds = (bool)($options['denyNeedsApproval'] ?? true);
        $reviewOpts = array_intersect_key($options, array_flip(array_merge(['intent', 'review'], self::REVIEW_KEYS)));
        return static function (mixed $runContext, mixed $input, mixed $callId = null) use ($agent, $name, $approved, $onStepUp, $denyNeeds, $reviewOpts): bool {
            $r = self::reviewToolCall($agent, (string)$name, $input, $reviewOpts)['review'];
            $kind = Js::opt($r, 'kind');
            if ($kind === 'auto') {
                return false;
            }
            if ($kind === 'deny') {
                return $denyNeeds;
            }
            if ($approved !== null && $approved(Js::opt($r, 'request'))) {
                return false;
            }
            if ($onStepUp !== null) {
                $onStepUp(['tool' => $name, 'request' => Js::opt($r, 'request')]);
            }
            return true;
        };
    }

    /**
     * A copy of the tool with `needsApproval` from PCA risk review (the tool's name seeds the intent lookup unless `toolName` is given).
     *
     * @param array<string,mixed> $options
     */
    public static function withApproval(mixed $tool, mixed $agent, array $options): mixed
    {
        $name = $options['toolName'] ?? self::member($tool, 'name') ?? '(tool)';
        return self::withAttrs($tool, ['needsApproval' => self::pcaNeedsApproval($agent, array_merge($options, ['toolName' => $name]))]);
    }

    // ---- agent side -----------------------------------------------------------------------------------------------------

    /**
     * A copy of an SDK tool (one with `onInvokeTool(ctx, jsonText)`) whose every call first signs a PCActn over its JSON arguments (with
     * `failFast`, a call the grant's envelope refuses never runs), hands it to `onProof(Action, params)` and runs the original. Arguments that
     * are not a JSON object are refused. `$resource` is a string or a Closure over the decoded arguments. This does NOT authorize.
     *
     * @param callable(Action, array<string,mixed>): void|null $onProof
     */
    public static function attachPca(Agent $agent, string $verb, \Closure|string $resource, mixed $tool, ?callable $onProof = null, bool $failFast = true): mixed
    {
        $orig = self::callableOf($tool, 'onInvokeTool');
        if ($orig === null) {
            throw new \TypeError('attachPca: the tool has no onInvokeTool');
        }
        return self::withAttrs($tool, ['onInvokeTool' => static function (mixed $ctx, mixed $raw = null, mixed ...$rest) use ($agent, $verb, $resource, $orig, $onProof, $failFast) {
            $params = \Atlas\Pca\OpenAi\ToolDispatch::parseArguments(is_string($raw) ? $raw : null);
            $res = $resource instanceof \Closure ? (string)$resource($params) : $resource;
            if ($failFast && ($why = $agent->envelopeRefusal($verb, $res, $params)) !== null) {
                throw new \RuntimeException("attachPca: the grant refuses this call ($why)");
            }
            $pca = $agent->act($verb, $res, $params === [] ? null : $params);
            if ($onProof !== null) {
                $onProof($pca, $params);
            }
            return $orig($ctx, $raw, ...$rest);
        }]);
    }
}
