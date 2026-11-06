<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Workflow;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for src/Authorize.php (lines before the core verdict): the result / options defaults, the value helpers
 * (head / show / normalize), the tool_schema limits, the agent caveat evaluator, rootCaveats, decisive, coerce, the workflow gate
 * and the pre-core refusals of authorize() (statuses, reasons, the intent v2 env merge, the default clock and reversibility ranks).
 */
final class K05KillAuthorize1Test extends TestCase
{
    private const LS = "\xED\xA0\x80"; // a lone surrogate (WTF-8)

    protected function setUp(): void
    {
        Authorize::$coreHook = null;
    }

    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Authorize::class, $m))->invoke(null, ...$a);
    }

    private static function op(): array
    {
        return ['verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => new Obj()];
    }

    /** authorize with a fake (wire-invalid) PCActn whose grant_ref resolves to an empty grant. */
    private static function az(mixed $pcactn, array $named = [], mixed $resolve = null, mixed $op = null): AuthorizeResult
    {
        return Authorize::authorize($pcactn, $op ?? self::op(), 'aud', $resolve ?? static fn() => new Obj(), new MemoryStateStore(),
            static fn() => false, 1000, ...$named);
    }

    private static function fake(): Obj
    {
        return Obj::of(['grant_ref' => 'g']);
    }

    /** @return array{0: Obj, 1: Obj} the authorize fixtures and the signed `envelope-max-spend-within` case */
    private static function fix(): array
    {
        $F = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($F->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                return [$F, $c];
            }
        }
        self::fail('fixture case');
    }

    private static function fixAz(?Obj $p = null, mixed $context = null, mixed $intentV2 = null, bool $clock = false): AuthorizeResult
    {
        [$F, $c] = self::fix();
        $s = $c->get('steps')[0];
        $g = $c->get('grant');
        return Authorize::authorize($p ?? $s->get('pcactn'), $s->get('operation'), $F->get('audience'), static fn() => $g,
            new MemoryStateStore(), static fn() => false, $clock ? null : $F->get('now')->int(), 'single-step', $context, null, $intentV2);
    }

    // ---- defaults ------------------------------------------------------------------------------------------------------

    public function testResultAndOptionDefaults(): void
    {
        $r = new AuthorizeResult(false, 403);
        $this->assertFalse($r->legacyModelPolarity);
        $this->assertFalse((new AuthorizeOptions())->insecureUnboundApproval);
        $this->assertFalse(self::az(null)->legacyModelPolarity);
    }

    public function testWorkflowCallMustBeCallable(): void
    {
        try {
            new AuthorizeOptions(workflowCall: 5);
            $this->fail('no exception');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('workflowCall must be a callable (ServerRequestInterface $request): array|Obj|null', $e->getMessage());
        }
        $this->assertNotNull((new AuthorizeOptions(workflowCall: static fn() => null))->workflowCall);
    }

    public function testEscalationPrincipalsNeedALastStore(): void
    {
        try {
            new AuthorizeOptions(escalationPrincipals: ['k']);
            $this->fail('no exception');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('escalationPrincipals needs a state store with last(string $key): ?int (an answer is bound to the holder '
                . 'history; a store without it cannot admit an answered escalation)', $e->getMessage());
        }
    }

    // ---- head / show (via the tool_schema "tool not authorized" reason) --------------------------------------------------

    private static function caveat(string $schemaJson, string $tool = 'pay'): Obj
    {
        $schema = Json::parseLax($schemaJson);
        $c = Obj::of(['type' => 'tool_schema', 'tool' => $tool, 'schema' => $schema, 'schema_digest' => Pca::hashCanonical($schema)]);
        $c->set('binding_digest', Pca::hashCanonical(Obj::of(['tool' => $tool, 'signature_digest' => 'undefined', 'schema' => $schema])));
        return $c;
    }

    private static function toolReason(string $tool): ?string
    {
        $r = Authorize::evaluateToolSchema(self::caveat('{"props":{}}'), ['tool' => $tool, 'args' => new Obj()]);
        return $r[0] ? null : $r[1];
    }

    private static function shown(string $inner): string
    {
        return 'tool "' . $inner . '" not authorized';
    }

    public function testShowTruncatesByUtf16Units(): void
    {
        $e = '…';
        $this->assertNull(self::toolReason('pay'));
        $this->assertSame(self::shown('a b'), self::toolReason('a b'));
        $this->assertSame(self::shown(str_repeat('é', 48) . $e), self::toolReason(str_repeat('é', 60)));
        $this->assertSame(self::shown(str_repeat('ठ', 48) . $e), self::toolReason(str_repeat('ठ', 60)));
        $this->assertSame(self::shown("\x80" . str_repeat('a', 48) . $e), self::toolReason("\x80" . str_repeat('a', 60)));
        $this->assertSame(self::shown(str_repeat("\u{1F600}", 24) . $e), self::toolReason(str_repeat("\u{1F600}", 30)));
        // an astral character that still fits in the 48 units
        $this->assertSame(self::shown(str_repeat('a', 46) . "\u{F0000}" . $e), self::toolReason(str_repeat('a', 46) . "\u{F0000}bbbb"));
        // a cut astral character leaves its high surrogate (written as its \udXXX escape)
        $this->assertSame(self::shown(str_repeat('a', 47) . '\udb80' . $e), self::toolReason(str_repeat('a', 47) . "\u{F0000}bbbb"));
        $this->assertSame(self::shown(str_repeat('a', 47) . '\udb80' . $e), self::toolReason(str_repeat('a', 47) . "\u{F03FF}bbbb"));
        $this->assertSame(self::shown(str_repeat('a', 47) . '\udac3' . $e), self::toolReason(str_repeat('a', 47) . "\u{C0C00}bbbb"));
    }

    public function testHeadNeverReadsPastTheString(): void
    {
        set_error_handler(static function (int $no, string $msg): never {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            $r = self::toolReason(str_repeat('a', 47) . "\u{F0000}"); // the astral character is the last 4 bytes
        } finally {
            restore_error_handler();
        }
        $this->assertSame(self::shown(str_repeat('a', 47) . '\udb80…'), $r);
    }

    public function testHeadNeverReadsPastATruncatedAstralLead(): void
    {
        set_error_handler(static function (int $no, string $msg): never {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            // 47 units, then a 4-byte lead with only two bytes left (utf16Len 49): the cut copies the truncated lead as is
            $r = self::toolReason(str_repeat('a', 47) . "\xF0\x9F\x98");
        } finally {
            restore_error_handler();
        }
        $this->assertSame(self::shown(str_repeat('a', 47) . "\xF0\x9F\x98…"), $r);
    }

    public function testShowEscapesOnlyLoneSurrogates(): void
    {
        $this->assertSame(self::shown("\u{D7FF}z"), self::toolReason("\u{D7FF}z"));
        $this->assertSame(self::shown('x\ud800'), self::toolReason("x\xED\xA0\x80"));
        $this->assertSame(self::shown("x\xED\xA0"), self::toolReason("x\xED\xA0"));
    }

    // ---- normalize (via operationParamsDigest) -------------------------------------------------------------------------

    private static function digestOrError(Obj $params): string
    {
        try {
            return 'ok:' . Authorize::operationParamsDigest(['params' => $params]);
        } catch (JsonError $e) {
            return 'error:' . $e->getMessage();
        }
    }

    private static function nestArr(int $k): array
    {
        $v = 1;
        for ($i = 0; $i < $k; $i++) {
            $v = [$v];
        }
        return $v;
    }

    private static function nestObj(int $k): Obj
    {
        $v = 1;
        for ($i = 0; $i < $k; $i++) {
            $v = Obj::of(['x' => $v]);
        }
        return $v;
    }

    public function testNormalizeNumbers(): void
    {
        $this->assertSame(Pca::paramsDigest(Json::parseStrict('{"a":1.5,"b":1,"c":0,"d":2,"e":[2,3]}')),
            Authorize::operationParamsDigest(['params' => Obj::of(['a' => 1.5, 'b' => 1.0, 'c' => -0.0, 'd' => 2.0, 'e' => [2.0, 3]])]));
        $this->assertSame('error:exponent form is not allowed', self::digestOrError(Obj::of(['a' => 1e21])));
    }

    public function testNormalizeDepthLimit(): void
    {
        // leaf at depth 33: normalize accepts it, so the canonicalizer's first error (the lone surrogate under "a") is reported
        $this->assertSame('error:lone surrogate in string', self::digestOrError(Obj::of(['a' => self::LS, 'b' => self::nestArr(32)])));
        // leaf at depth 34: normalize refuses it before the canonicalizer runs
        $this->assertSame('error:nesting too deep', self::digestOrError(Obj::of(['a' => self::LS, 'b' => self::nestArr(33)])));
        $this->assertSame('error:nesting too deep', self::digestOrError(Obj::of(['a' => self::LS, 'b' => self::nestObj(33)])));
        $this->assertStringStartsWith('ok:', self::digestOrError(Obj::of(['b' => self::nestArr(20)])));
        $this->assertStringStartsWith('ok:', self::digestOrError(Obj::of(['b' => self::nestObj(20)])));
    }

    public function testOperationMemberOfAScalar(): void
    {
        $this->assertNull(Authorize::operationMember(5, 'verb'));
        $this->assertNull(Authorize::operationMember(null, 'verb'));
        $this->assertSame('v', Authorize::operationMember(['verb' => 'v'], 'verb'));
    }

    public function testStateKey(): void
    {
        $this->assertSame('g:h', Authorize::stateKey('g', 'h'));
    }

    // ---- rootCaveats -----------------------------------------------------------------------------------------------------

    public function testRootCaveats(): void
    {
        $env = Obj::of(['type' => 'envelope']);
        $env2 = Obj::of(['type' => 'envelope', 'n' => 2]);
        $m = Obj::of(['type' => 'max_spend']);
        $this->assertNull(Authorize::rootCaveats(null));
        $this->assertSame('x', Authorize::rootCaveats(Obj::of(['caveats' => 'x'])));
        $this->assertSame([5, $m], Authorize::rootCaveats(Obj::of(['caveats' => [5, $env, $m]])));
        $this->assertSame([$m], Authorize::rootCaveats(Obj::of(['caveats' => [$m, $env]])));
        $this->assertSame([$env2, $m], Authorize::rootCaveats(Obj::of(['caveats' => [$env, $env2, $m]])));
    }

    // ---- tool_schema validation and evaluation -------------------------------------------------------------------------

    public function testSchemaNodeLimitIsInclusive(): void
    {
        $props = [];
        for ($o = 0; $o < 3; $o++) {
            $inner = [];
            for ($k = 0; $k < 64; $k++) {
                $inner["p$k"] = ['type' => 'string'];
            }
            $props["o$o"] = ['type' => 'object', 'props' => $inner];
        }
        for ($k = 0; $k < 59; $k++) {
            $props["s$k"] = ['type' => 'string'];
        }
        $props['z'] = ['type' => 'object', 'props' => new \stdClass()]; // the 256th node
        $this->assertNull(Authorize::validateArgSchema(Json::parseLax(json_encode(['props' => $props]))));
    }

    public function testNumberSpecBounds(): void
    {
        $v = static fn(string $spec) => Authorize::validateArgSchema(Json::parseLax('{"props":{"a":' . $spec . '}}'));
        $this->assertSame('a: min > max', $v('{"type":"integer","min":5,"max":1}'));
        $this->assertSame('a: bad min', $v('{"type":"integer","min":"x"}'));
        $this->assertNull($v('{"type":"number","min":5}'));
        $this->assertNull($v('{"type":"integer","min":5}'));
    }

    public function testNestedArrayDepth(): void
    {
        $c = self::caveat('{"props":{"a":{"type":"array","items":{"type":"array","items":{"type":"array","items":{"type":"array","items":{"type":"string"}}}}}}}');
        $this->assertSame([true, null], Authorize::evaluateToolSchema($c, ['tool' => 'pay', 'args' => Obj::of(['a' => [[[['x']]]]])]));
    }

    public function testValueNodeLimit(): void
    {
        $arr = '{"type":"array","items":{"type":"string"},"maxItems":4096}';
        $c = self::caveat('{"props":{"a":' . $arr . ',"b":' . $arr . ',"c":' . $arr . '}}');
        $args = static fn(int $n) => Obj::of(['a' => array_fill(0, 4096, 'x'), 'b' => array_fill(0, 4096, 'x'), 'c' => array_fill(0, $n, 'x')]);
        // 1 + 4096 + 1 + 4096 + 1 + 1805 = 10000 values: at the limit
        $this->assertSame([true, null], Authorize::evaluateToolSchema($c, ['tool' => 'pay', 'args' => $args(1805)]));
        $this->assertSame([false, 'args.c[1805]: too many values'], Authorize::evaluateToolSchema($c, ['tool' => 'pay', 'args' => $args(1806)]));
    }

    public function testEvaluationErrorFailsClosed(): void
    {
        $this->assertSame([false, 'evaluation error (fail closed)'],
            Authorize::evaluateToolSchema(self::caveat('{"props":{}}'), ['tool' => 'pay', 'args' => new Obj(), 'toolSignature' => new \stdClass()]));
    }

    // ---- evaluateAgentCaveats ------------------------------------------------------------------------------------------

    public function testAgentCaveats(): void
    {
        $pass = Obj::of(['type' => 'predicates', 'allow' => [Obj::of(['verb' => '*'])]]);
        $act = Obj::of(['action' => Obj::of(['verb' => 'v', 'resource' => 'r'])]);
        $ok = ['ok' => true, 'failed' => []];
        $bad = ['ok' => false, 'failed' => ['predicates']];
        $this->assertSame(['ok' => false, 'failed' => ['<malformed caveats>']], Authorize::evaluateAgentCaveats('x', null));
        $this->assertSame($ok, Authorize::evaluateAgentCaveats([$pass], null, $act));
        $this->assertSame($ok, Authorize::evaluateAgentCaveats([$pass], [], $act));
        $this->assertSame($ok, Authorize::evaluateAgentCaveats([$pass], ['x' => 1], $act));
        $this->assertSame($ok, Authorize::evaluateAgentCaveats([$pass], new Obj(), $act));
        $this->assertSame($bad, Authorize::evaluateAgentCaveats([$pass], [1], $act));
        $this->assertSame($bad, Authorize::evaluateAgentCaveats([$pass], 5, $act));
        $this->assertSame($bad, Authorize::evaluateAgentCaveats([$pass], null)); // no action context: the predicate cannot match
        $this->assertSame(['ok' => false, 'failed' => ['<malformed>']], Authorize::evaluateAgentCaveats([5], null, $act));
        $this->assertSame($bad, Authorize::evaluateAgentCaveats([Obj::of(['type' => 'predicates', 'allow' => 'x'])], null, $act));
        $this->assertSame($bad, Authorize::evaluateAgentCaveats([Obj::of(['type' => 'predicates', 'allow' => []])], null, $act));
    }

    // ---- refuse / missing components / decisive -------------------------------------------------------------------------

    public function testMissingComponentsAndPlan(): void
    {
        $this->assertSame(['audience', 'resolveGrant', 'stateStore', 'isRevoked'], Authorize::missingAuthorizeComponents('', null, null, null));
        $r = self::az(self::fake(), ['plan' => 'multi']);
        $why = "authorize_config: missing required component(s): plan (only 'single-step' or null) (fail closed)";
        $this->assertSame([false, 403, $why, [$why], ["plan (only 'single-step' or null)"]], [$r->allow, $r->status, $r->reason, $r->reasons, $r->missing]);
        $this->assertSame(['authorize_config' => ['outcome' => 'fail']], $r->assurance);
        $r = self::az(self::fake(), op: ['verb' => 'x', 'resource' => 'y']);
        $why = 'operation: authorize needs the operation to execute (verb, resource, params) (fail closed)';
        $this->assertSame([403, ['operation' => 'fail'], $why, [$why]], [$r->status, $r->checks, $r->reason, $r->reasons]);
    }

    public function testDecisive(): void
    {
        $d = static fn(array $c, array $r) => self::priv('decisive', $c, $r);
        $this->assertSame('operation: y', $d(['policy' => 'fail', 'operation' => 'fail'], ['policy: x', 'operation: y']));
        $this->assertSame('a: 1', $d(['a' => 'fail', 'b' => 'fail'], ['b: 2', 'a: 1']));
        $this->assertSame('b: 2', $d(['a' => 'pass', 'b' => 'fail'], ['a: 1', 'b: 2']));
        $this->assertSame('a: 2', $d(['a' => 'fail', 'ab' => 'fail'], ['ab: 1', 'a: 2']));
        $this->assertSame('only', $d(['a' => 'fail'], ['only']));
        $this->assertSame('denied', $d([], []));
        // more checks (the sort's other paths): `operation` first, the rest in their original order
        $c = [];
        $r = [];
        foreach (['c00', 'c01', 'c02', 'c03', 'c04', 'c05', 'operation', 'c07'] as $n) {
            $c[$n] = 'fail';
            array_unshift($r, "$n: r");
        }
        $this->assertSame('operation: r', $d($c, $r));
        $c = ['c00' => 'pass'];
        $r = [];
        for ($k = 1; $k < 20; $k++) {
            $n = sprintf('c%02d', $k);
            $c[$n] = 'fail';
            array_unshift($r, "$n: r");
        }
        $this->assertSame('c01: r', $d($c, $r));
    }

    // ---- coerce and the pre-core refusals ------------------------------------------------------------------------------

    public function testCoerce(): void
    {
        $r = self::az(null);
        $this->assertSame([401, ['wire' => 'fail'], 'wire: no PCActn presented'], [$r->status, $r->checks, $r->reason]);
        foreach ([5, '[1]', '5', str_repeat(' ', Pca::MAX_ARTIFACT_BYTES + 1)] as $x) {
            $r = self::az($x);
            $this->assertSame([401, ['pcactn' => 'fail'], 'undecodable PCActn: could not be decoded'], [$r->status, $r->checks, $r->reason]);
        }
        // exactly at the size limit: decoded (then refused for its grant_ref)
        $head = '{"grant_ref":5,"x":"';
        $text = $head . str_repeat('a', Pca::MAX_ARTIFACT_BYTES - strlen($head) - 2) . '"}';
        $this->assertSame(Pca::MAX_ARTIFACT_BYTES, strlen($text));
        $r = self::az($text);
        $this->assertSame([401, ['malformed' => 'fail'], 'malformed: grant_ref is not a string'], [$r->status, $r->checks, $r->reason]);
    }

    public function testPreCoreRefusals(): void
    {
        $r = self::az(Obj::of(['grant_ref' => 5]));
        $this->assertSame([401, 'malformed: grant_ref is not a string'], [$r->status, $r->reason]);
        $r = self::az(self::fake(), [], static function (): never {
            throw new \RuntimeException('x');
        });
        $this->assertSame([403, 'resolve_grant: grant resolution failed (fail closed)'], [$r->status, $r->reason]);
        $r = self::az(self::fake(), [], static fn() => null);
        $this->assertSame([401, ['grant_ref' => 'fail'], 'grant_ref: does not resolve to a known grant'], [$r->status, $r->checks, $r->reason]);
        $r = self::az(self::fake(), ['context' => static function (): never {
            throw new \RuntimeException('x');
        }]);
        $this->assertSame([403, 'context: the context callback failed (fail closed)'], [$r->status, $r->reason]);
        $r = self::az(self::fake(), ['context' => static fn() => 5]);
        $this->assertSame([403, 'context: the context callback must return an object (fail closed)'], [$r->status, $r->reason]);
        $v2 = 'intent_v2: verifier state unavailable (fail closed)';
        $r = self::az(self::fake(), ['intentV2' => static function (): never {
            throw new \RuntimeException('x');
        }]);
        $this->assertSame([403, $v2], [$r->status, $r->reason]);
        $r = self::az(self::fake(), ['intentV2' => 5]);
        $this->assertSame([403, ['intent_v2' => 'fail'], $v2], [$r->status, $r->checks, $r->reason]);
        // an array callable is not a callable object: it is the (malformed) state itself
        $holder = new class {
            public function m(): Obj
            {
                return new Obj();
            }
        };
        $r = self::az(self::fake(), ['intentV2' => [$holder, 'm']]);
        $this->assertSame([403, $v2], [$r->status, $r->reason]);
        // an invokable object is called; a context returning null is the empty context: both reach the core verifier (wire)
        $inv = new class {
            public function __invoke(): ?Obj
            {
                return null;
            }
        };
        foreach ([['intentV2' => $inv], ['context' => static fn() => null]] as $named) {
            $r = self::az(self::fake(), $named);
            $this->assertSame([401, ['wire' => 'fail', 'malformed' => 'fail']], [$r->status, $r->checks]);
            $this->assertStringStartsWith('wire: ', (string)$r->reason);
            $this->assertNotSame('wire: malformed PCActn', $r->reason);
            $this->assertSame([$r->reason], $r->reasons);
        }
    }

    public function testInternalErrorIsAnAuthorizeRefusal(): void
    {
        $r = self::az(self::fake(), [], null, ['verb' => 'v', 'resource' => 'r', 'params' => Obj::of(['a' => self::LS])]);
        $this->assertSame([false, 403, ['authorize' => 'fail'], 'authorize: error (fail closed): Atlas\Pca\JsonError'],
            [$r->allow, $r->status, $r->checks, $r->reason]);
    }

    // ---- the workflow gate ---------------------------------------------------------------------------------------------

    public function testWorkflowRefusalShape(): void
    {
        $p = self::fake(); // no plan: the plan root is unreadable (null), never an error
        $r = self::az($p, ['workflow' => ['principal' => 'p', 'rsSigner' => 'r'], 'workflowCall' => ['commitment' => null]]);
        $this->assertSame([false, 403, 'deny', ['workflow' => 'fail'], 'workflow: bad_workflow', ['workflow: bad_workflow']],
            [$r->allow, $r->status, $r->decision, $r->checks, $r->reason, $r->reasons]);
        $this->assertSame(['workflow' => ['outcome' => 'fail']], $r->assurance);
        $this->assertSame($p, $r->pcactn);
    }

    /** @return array{0: Obj, 1: Obj} the authorize-workflow fixtures and `pay-after-quote` step 0 (orders.quote) */
    private static function wf(): array
    {
        $F = Json::parseLax(file_get_contents(__DIR__ . '/../conformance/authorize-workflow-fixtures.json'));
        foreach ($F->get('cases') as $c) {
            if ($c->get('name') === 'pay-after-quote') {
                return [$F, $c->get('steps')[0]];
            }
        }
        self::fail('fixture case');
    }

    private static function wfAz(mixed $units, bool $withProvenance): AuthorizeResult
    {
        [$F, $s] = self::wf();
        $grant = $F->get('grant');
        $plan = $F->get('plan');
        $w = $s->get('workflow');
        $named = [
            'workflow' => Obj::of(['principal' => $F->get('principal'), 'rsSigner' => $F->get('rs_signer'), 'required' => false]),
            'workflowCall' => Obj::of(['commitment' => $w->get('commitment'), 'receipts' => $w->get('receipts'), 'step' => $w->get('step'),
                'units' => $units ?? $w->get('units'), 'goal_digest' => $w->get('goal_digest')]),
        ];
        if ($withProvenance) {
            $named += ['provenance' => ProvHarness::bundle($s->get('operation')), 'provenanceMediators' => [ProvHarness::pin()]];
        }
        return Authorize::authorize($s->get('pcactn'), $s->get('operation'), $F->get('audience'),
            static fn($ref) => $ref === $grant->get('id') ? $grant : null, new MemoryStateStore(), static fn() => false, Workflow::iv($F->get('now')),
            null, static fn() => Obj::of(['plan' => $plan, 'plan_authorized' => true]), ...$named);
    }

    public function testWorkflowUnitsAreTheCallsOwn(): void
    {
        $r = self::wfAz(5, true);
        $this->assertSame(['fail', 'workflow: bad_workflow'], [$r->checks['workflow'] ?? null, $r->reason]);
    }

    public function testAnAdmittedStepIsPrincipalControl(): void
    {
        $r = self::wfAz(null, false);
        $this->assertArrayNotHasKey('workflow', $r->checks);
        $this->assertSame('fail', $r->checks['provenance_flow']);
        $this->assertContains('provenance_flow: escalate: order derives from untrusted content [unlabelled]: the principal must confirm '
            . '(prompt-injection path)', $r->reasons);
        $this->assertStringNotContainsString('the choice of', implode("\n", $r->reasons));
    }

    // ---- the intent v2 env merge, the default clock, reversibility ranks (signed fixture, core runs) -------------------------

    public function testIntentV2EnvMerge(): void
    {
        $host = static fn() => ['env' => Obj::of(['x' => 1])];
        // a null v2 env is absent: the host env replaces it
        $this->assertArrayNotHasKey('schema', self::fixAz(null, $host, Obj::of(['env' => null]))->checks);
        $this->assertArrayNotHasKey('schema', self::fixAz(null, null, Obj::of(['env' => null]))->checks);
        // a non-object v2 env stays (and fails the v2 context check) even with a host env
        $r = self::fixAz(null, $host, Obj::of(['env' => 5]));
        $this->assertSame('fail', $r->checks['schema'] ?? null);
        $this->assertContains('schema: malformed v2 context: env must be an object', $r->reasons);
        // a v2 `params` that is set is kept (and checked)
        $r = self::fixAz(null, null, Obj::of(['params' => 5]));
        $this->assertSame('fail', $r->checks['schema'] ?? null);
        $this->assertContains('schema: malformed v2 context: params must be an object', $r->reasons);
    }

    public function testDefaultClockIsWallMilliseconds(): void
    {
        [, $c] = self::fix();
        $p = $c->get('steps')[0]->get('pcactn')->without('iat', 'exp');
        $now = (int)(microtime(true) * 1000);
        $p->set('iat', new Num((string)($now - 5000)));
        $p->set('exp', new Num((string)($now + 600000)));
        $r = self::fixAz($p, null, null, true);
        $this->assertSame('pass', $r->checks['validity'] ?? null, (string)$r->reason);
    }

    private static function rev(string $declared, mixed $server): ?string
    {
        [, $c] = self::fix();
        $p = $c->get('steps')[0]->get('pcactn');
        $a = $p->get('action')->without('reversibility_class');
        $a->set('reversibility_class', $declared);
        $p = $p->without('action');
        $p->set('action', $a);
        return self::fixAz($p, static fn() => ['reversibility_class' => $server])->checks['reversibility'] ?? null;
    }

    public function testReversibilityRanks(): void
    {
        $this->assertSame('fail', self::rev('reversible', 'irreversible'));
        $this->assertSame('fail', self::rev('costly', 'bogus'));
        $this->assertSame('fail', self::rev('costly', 5));
        $this->assertSame('pass', self::rev('irreversible', 'bogus'));
        $this->assertSame('pass', self::rev('irreversible', 5));
        $this->assertSame('pass', self::rev('irreversible', 'reversible'));
    }

    public function testPlanNodesMayBePhpArrays(): void
    {
        [, $c] = self::fix();
        $p = $c->get('steps')[0]->get('pcactn');
        $a = $p->get('action');
        $node = ['id' => $p->get('plan')->get('node_id'), 'verb' => $a->get('verb'), 'resource' => $a->get('resource'),
            'params_digest' => $a->get('params_digest'), 'reversibility_class' => $a->get('reversibility_class')];
        $r = self::fixAz(null, static fn() => ['plan' => [$node], 'plan_authorized' => true]);
        $this->assertSame('pass', $r->checks['plan_root_authorized'] ?? null, (string)$r->reason);
        $r = self::fixAz(null, static fn() => ['plan' => [Obj::of($node)], 'plan_authorized' => true]);
        $this->assertSame('pass', $r->checks['plan_root_authorized'] ?? null);
    }

    // ---- the insecureUnboundApproval default (k05 oracle scenario) -------------------------------------------------------

    public function testUnboundApprovalIsRefusedByDefault(): void
    {
        $h = gzopen(__DIR__ . '/../test-data/k05-authorize.json.gz', 'rb');
        $case = null;
        try {
            while (($l = gzgets($h)) !== false) {
                if (str_contains($l, 'verifier has no render (K7 default)')) {
                    $l = rtrim($l, "\r\n");
                    $case = Json::parseLax(str_ends_with($l, ',') ? substr($l, 0, -1) : $l);
                    break;
                }
            }
        } finally {
            gzclose($h);
        }
        $this->assertInstanceOf(Obj::class, $case);
        $sc = $case->get('args')[0];
        $cfg = $sc->get('config');
        $grant = $sc->get('grant');
        $s = $sc->get('steps')[0];
        $r = Authorize::authorize($s->get('pcactn'), $s->get('operation'), $cfg->get('audience'),
            static fn($ref) => $ref === $grant->get('id') ? $grant : null, new MemoryStateStore(), static fn() => false, $cfg->get('now')->int(),
            'single-step', escalationPrincipals: $cfg->get('escalation')->get('principals'), escalationAnswer: $s->get('escalationAnswer'),
            freshAt: $cfg->get('freshAt'), provenance: $s->get('provenance'), provenanceMediators: $cfg->get('mediators'));
        $this->assertSame([false, 'escalate'], [$r->allow, $r->decision]);
        $this->assertContains('escalation: an approval render is required and none could be recomputed (set escalation.render, or '
            . 'insecureUnboundApproval)', $r->reasons);
    }

    // ---- k05 review: helpers called directly, and the fail-closed catches through the Authorize::$evalHook seam ----------

    /** A hook that throws inside the try block labelled `$where` (and nowhere else). */
    private static function throwAt(string $where): \Closure
    {
        return static function (string $at) use ($where): void {
            if ($at === $where) {
                throw new \RuntimeException('boom');
            }
        };
    }

    public function testJsEqOnMismatchedTypes(): void
    {
        $eq = static fn(mixed $a, mixed $b): bool => self::priv('jsEq', $a, $b);
        // neither a number, a bool nor a string: never equal (the final `return false`)
        $this->assertFalse($eq(null, null));
        $this->assertFalse($eq([], []));
        $this->assertFalse($eq(new Obj(), new Obj()));
        // mixed types: never equal
        $this->assertFalse($eq(1, '1'));
        $this->assertFalse($eq('1', 1));
        $this->assertFalse($eq(true, 1));
        $this->assertFalse($eq(1, true));
        $this->assertFalse($eq('a', true));
        $this->assertFalse($eq(false, 'a'));
        $this->assertFalse($eq(null, 'a'));
        $this->assertFalse($eq(true, false));
        // same type, same value
        $this->assertTrue($eq(1, 1.0));
        $this->assertTrue($eq(new Num('2'), 2));
        $this->assertTrue($eq('a', 'a'));
        $this->assertTrue($eq(false, false));
    }

    private static function cv(string $spec, mixed $v, int $depth): ?string
    {
        $n = 0;
        return (new \ReflectionMethod(Authorize::class, 'checkValue'))->invokeArgs(null, [Json::parseLax($spec), $v, 'p', $depth, &$n]);
    }

    public function testCheckValueDepthBound(): void
    {
        // the bound is MAX_SCHEMA_DEPTH + 1 = 9: depth 9 is checked, 10 is too deep
        $this->assertNull(self::cv('{"type":"string"}', 'x', 9));
        $this->assertSame('p: too deep', self::cv('{"type":"string"}', 'x', 10));
        // array items and object props are one level deeper
        $arr = '{"type":"array","items":{"type":"string"}}';
        $this->assertNull(self::cv($arr, ['x'], 8));
        $this->assertSame('p[0]: too deep', self::cv($arr, ['x'], 9));
        $obj = '{"type":"object","props":{"a":{"type":"string"}}}';
        $this->assertNull(self::cv($obj, Obj::of(['a' => 'x']), 8));
        $this->assertSame('p.a: too deep', self::cv($obj, Obj::of(['a' => 'x']), 9));
    }

    public function testOnlyAnObjIsACaveat(): void
    {
        // an object that answers get() like a satisfied predicates caveat is still no caveat
        $fake = new class () {
            public function get(string $k): mixed
            {
                return $k === 'type' ? 'predicates' : ($k === 'allow' ? [Obj::of(['verb' => '*'])] : null);
            }
        };
        $act = Obj::of(['action' => Obj::of(['verb' => 'v', 'resource' => 'r'])]);
        $this->assertSame(['ok' => false, 'failed' => ['<malformed>']], Authorize::evaluateAgentCaveats([$fake], null, $act));
    }

    public function testAgentCaveatEvaluationErrorFailsClosed(): void
    {
        Authorize::$evalHook = self::throwAt('agent_caveats');
        try {
            $this->assertSame(['ok' => false, 'failed' => ['<evaluation error>']], Authorize::evaluateAgentCaveats([], null));
        } finally {
            Authorize::$evalHook = null;
        }
    }

    public function testWorkflowGateErrorFailsClosed(): void
    {
        Authorize::$evalHook = self::throwAt('workflow');
        try {
            $r = self::az(self::fake(), ['workflow' => [], 'workflowCall' => null]);
        } finally {
            Authorize::$evalHook = null;
        }
        $this->assertSame([false, 403, ['workflow' => 'fail'], 'workflow: error (fail closed)', ['workflow: error (fail closed)']],
            [$r->allow, $r->status, $r->checks, $r->reason, $r->reasons]);
    }

    private static function kt(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentV2KillTest::class, $m))->invokeArgs(null, $a);
    }

    public function testV2EnvAddsTheVerifierComputedMembers(): void
    {
        // a valid bound intent session (IntentV2KillTest's signed baseline): the v2 decision computes env members
        [$g, $p] = self::kt('base');
        $ctx = self::kt('ctx');
        $now = self::kt('ctxNow');
        $d = IntentV2::decideIntentV2($p, $g, $ctx, $now)['env'];
        $this->assertInstanceOf(Obj::class, $d);
        $set = array_values(array_filter($d->keys(), static fn(string $k): bool => $d->get($k) !== null));
        $this->assertNotSame([], $set);
        // the host's own members stay, the reserved ones are replaced by the verifier-computed values
        $host = Obj::of(['keep' => 1, 'acc' => 'host', 'class' => 'host']);
        $r = (new \ReflectionMethod(Authorize::class, 'v2Env'))->invoke(null, $p, $g, $ctx, $now, $host);
        $this->assertInstanceOf(Obj::class, $r);
        $this->assertSame(array_merge(['keep'], $set), $r->keys());
        $this->assertSame(1, $r->get('keep'));
        foreach ($set as $k) {
            $this->assertEquals($d->get($k), $r->get($k));
        }
    }
}
