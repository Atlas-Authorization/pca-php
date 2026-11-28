<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\AgentToolProxy;
use Atlas\Pca\Authorize;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpenAiAgents;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaToolDenied;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * The OpenAI Agents tool guard: tool shapes and copies, proof decoding, the signature-only verifier, the full-policy pipeline (binding,
 * fail-closed, denial kinds, the clock and the default operation), configuration refusals, per-tool option merging, step-up review and
 * the signing side.
 */
final class ToolSurvivorKill18OpenAiAgentsTest extends TestCase
{
    private const TEXT = '{"action":{"verb":"v"}}';
    private const RC = ['context' => ['pca' => self::TEXT]];
    private const NOPLAN = 'PCA tool denied (verify) for payments.send: plan_root_authorized: no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)';
    private const OPREF = 'operation: authorize needs the operation to execute (verb, resource, params) (fail closed)';

    private static ?array $fx = null;

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    /** @return array{grant: Obj, pcactn: Obj, op: Obj, now: int, aud: string} the envelope-max-spend-within authorize fixture */
    private static function fx(): array
    {
        if (self::$fx === null) {
            $f = Json::parseLax((string)file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
            foreach ($f->get('cases') as $c) {
                if ($c->get('name') === 'envelope-max-spend-within') {
                    $s = $c->get('steps')[0];
                    self::$fx = ['grant' => $c->get('grant'), 'pcactn' => $s->get('pcactn'), 'op' => $s->get('operation'),
                        'now' => $f->get('now')->int(), 'aud' => $f->get('audience')];
                }
            }
        }
        return self::$fx;
    }

    /** Runs $f with every PHP warning / notice turned into a thrown error. */
    private static function noWarnings(\Closure $f): mixed
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    private static function sig(array $o = []): array
    {
        return $o + ['mode' => 'signature-only', 'verify' => static fn(Obj $p): array => ['allow' => true, 'checks' => ['sig' => 'pass']]];
    }

    private static function tool(string $name = 'pay', ?array &$ran = null): array
    {
        return ['name' => $name, 'description' => 'd', 'execute' => static function (mixed $in, mixed $rc = null) use (&$ran): array {
            $ran[] = $in;
            return ['ran' => $in];
        }];
    }

    private static function missing(string $label): string
    {
        return "PCA tool denied (missing) for $label: no proof-carrying action present on the call";
    }

    private static function denied(\Closure $f): PcaToolDenied
    {
        try {
            $f();
        } catch (PcaToolDenied $e) {
            return $e;
        }
        throw new \RuntimeException('the call was not denied');
    }

    private static function typeError(\Closure $f): string
    {
        try {
            $f();
        } catch (\TypeError $e) {
            return $e->getMessage();
        }
        return '(no TypeError)';
    }

    // ---- tool shapes ------------------------------------------------------------------------------------------------

    /** An object tool with a callable property: the copy's member read and isset prefer the guarded replacement. */
    public function testProxyPrefersTheReplacement(): void
    {
        $obj = new class {
            public string $name = 'objtool';
            public string $kept = 'k';
            public mixed $execute;

            public function __construct()
            {
                $this->execute = static fn(mixed $in, mixed $rc = null): array => ['raw' => $in];
            }
        };
        $g = OpenAiAgents::withPcaTool($obj, self::sig());
        $this->assertInstanceOf(AgentToolProxy::class, $g);
        $e = self::denied(static fn() => ($g->execute)('in', null));
        $this->assertSame(self::missing('objtool'), $e->getMessage());
        $this->assertSame(['raw' => 'in'], ($g->execute)('in', self::RC));
        $this->assertTrue(isset($g->execute));
        $this->assertTrue(isset($g->kept));
        $this->assertFalse(isset($g->nope));
        $this->assertSame('k', $g->kept);
    }

    /** An object tool with methods is guarded through its method; one without a name is labelled "(tool)" without a warning. */
    public function testObjectToolWithMethods(): void
    {
        $obj = new class {
            public string $name = 'm';

            public function execute(mixed $in, mixed $rc = null): array
            {
                return ['m' => $in];
            }
        };
        $g = OpenAiAgents::withPcaTool($obj, self::sig());
        $this->assertSame(['m' => 'in'], $g->execute('in', self::RC));
        $this->assertSame(self::missing('m'), self::denied(static fn() => $g->execute('in', null))->getMessage());
        $anon = new class {
            public function execute(mixed $in, mixed $rc = null): int
            {
                return 1;
            }
        };
        $h = self::noWarnings(static fn() => OpenAiAgents::withPcaTool($anon, self::sig()));
        $this->assertSame(self::missing('(tool)'), self::denied(static fn() => $h->execute('in', null))->getMessage());
        $this->assertSame(1, $h->execute('in', self::RC));
    }

    /** An Obj tool is copied as an Obj with every member kept and execute replaced by the guard. */
    public function testObjToolCopy(): void
    {
        $o = Obj::of(['name' => 'ot', 'description' => 'd', 'execute' => static fn(mixed $in, mixed $rc = null): array => ['obj' => $in]]);
        $g = OpenAiAgents::withPcaTool($o, self::sig());
        $this->assertInstanceOf(Obj::class, $g);
        $this->assertSame(['name', 'description', 'execute'], $g->keys());
        $this->assertSame('d', $g->get('description'));
        $this->assertSame(self::missing('ot'), self::denied(static fn() => ($g->get('execute'))('in', []))->getMessage());
        $this->assertSame(['obj' => 'in'], ($g->get('execute'))('in', self::RC));
    }

    /** A tool that is neither an array, an Obj nor an object is refused. */
    public function testScalarToolRefused(): void
    {
        $this->assertSame('the tool must be an array, an Obj or an object', self::typeError(static fn() => OpenAiAgents::withPcaTool('x', self::sig())));
    }

    /** onInvokeTool: the JSON text arguments are parsed strictly for the guard, and the original's result is returned. */
    public function testOnInvokeTool(): void
    {
        $seen = [];
        $tool = ['name' => 'it', 'onInvokeTool' => static fn(mixed $ctx, mixed $raw = null): string => 'inv:' . $raw];
        $t = OpenAiAgents::withPcaTool($tool, self::sig(['onDeny' => static function (PcaToolDenied $e, mixed $in) use (&$seen): void {
            $seen[] = $in;
        }]));
        $this->assertSame(self::missing('it'), self::denied(static fn() => ($t['onInvokeTool'])([], '{"a":"b"}'))->getMessage());
        $this->assertInstanceOf(Obj::class, $seen[0]);
        $this->assertSame('b', $seen[0]->get('a'));
        self::denied(static fn() => ($t['onInvokeTool'])([], 'not json'));
        $this->assertNull($seen[1]);
        $this->assertSame('inv:{"a":"b"}', ($t['onInvokeTool'])(self::RC, '{"a":"b"}'));
    }

    // ---- decoding ---------------------------------------------------------------------------------------------------

    /** Every way a proof fails to decode is a malformed denial naming the cause. */
    public function testDecodeRefusals(): void
    {
        $v = static fn(Obj $p): array => ['allow' => true];
        $msg = static fn(mixed $raw): string => self::denied(static fn() => OpenAiAgents::assertProof($raw, $v, null, null, 'L', null))->getMessage();
        $pre = 'PCA tool denied (malformed) for L: proof could not be decoded: ';
        $this->assertSame($pre . 'the proof is neither a PCActn object nor encoded text', $msg(5));
        $this->assertSame($pre . 'the proof is not JSON and not a strict base64url header value', $msg('garbage!'));
        $this->assertSame($pre . 'decodePCActn: not an object', $msg(Pca::b64u('[1]')));
        $big = '{"pad":"' . str_repeat('x', 600000) . '"}';
        $this->assertSame($pre . 'artifact exceeds size limit (max 524288 bytes)', $msg(Pca::b64u($big)));
        $this->assertSame('PCA tool denied (missing) for L: no proof-carrying action present on the call', $msg(null));
    }

    /** A PCActn object, its JSON text of exactly the size limit, and a header value all decode. */
    public function testDecodeAccepts(): void
    {
        $v = static fn(Obj $p): array => ['allow' => true];
        $o = Obj::of(['action' => Obj::of(['verb' => 'v'])]);
        $this->assertSame($o, OpenAiAgents::assertProof($o, $v, null, null, 'L', null)['pcactn']);
        $exact = '{"pad":"' . str_repeat('x', Pca::MAX_ARTIFACT_BYTES - 10) . '"}';
        $this->assertSame(Pca::MAX_ARTIFACT_BYTES, strlen($exact));
        $this->assertSame(Pca::MAX_ARTIFACT_BYTES - 10, strlen(OpenAiAgents::assertProof($exact, $v, null, null, 'L', null)['pcactn']->get('pad')));
        $this->assertSame('v', OpenAiAgents::assertProof(Pca::b64u(self::TEXT), $v, null, null, 'L', null)['pcactn']->get('action')->get('verb'));
    }

    /** provenanceFrom: an Obj as is, a JSON object text or its header value parsed; anything else is no bundle. */
    public function testProvenanceFrom(): void
    {
        $m = new \ReflectionMethod(OpenAiAgents::class, 'provenanceFrom');
        $o = Obj::of(['a' => 'b']);
        $this->assertSame($o, $m->invoke(null, $o));
        $this->assertSame('b', $m->invoke(null, '{"a":"b"}')->get('a'));
        $this->assertSame('b', $m->invoke(null, Pca::b64u('{"a":"b"}'))->get('a'));
        foreach ([null, '', 5, '[1]', Pca::b64u('[1]'), 'not json', ['a' => 'b']] as $x) {
            $this->assertNull($m->invoke(null, $x), var_export($x, true));
        }
    }

    /** The provenance bundle names are read in order: pcaProvenance, pca_provenance, PCA-Provenance; the context before the run context. */
    public function testProvenanceFromRunContextOrder(): void
    {
        $this->assertSame('a', OpenAiAgents::provenanceFromRunContext(null, ['pcaProvenance' => 'a', 'pca_provenance' => 'b', 'PCA-Provenance' => 'c']));
        $this->assertSame('b', OpenAiAgents::provenanceFromRunContext(null, ['pca_provenance' => 'b', 'PCA-Provenance' => 'c']));
        $this->assertSame('c', OpenAiAgents::provenanceFromRunContext(null, ['PCA-Provenance' => 'c']));
        $this->assertSame('x', OpenAiAgents::provenanceFromRunContext(null, ['context' => ['PCA-Provenance' => 'x'], 'pcaProvenance' => 'y']));
    }

    // ---- the signature-only verifier configuration ------------------------------------------------------------------

    private static function grd(array $cfg, array $o = []): array
    {
        $f = self::fx();
        $p = $f['pcactn'];
        $g = OpenAiAgents::pcaInputGuardrail($o + ['verify' => $cfg + ['grant' => $f['grant'], 'nowEpoch' => $f['now'], 'insecureSkipPlanRootCheck' => true],
            'require' => static fn(mixed ...$a): Obj => $p, 'audience' => $f['aud']]);
        return $g->execute([]);
    }

    /** The grant verifier: its clock as int, float, Num or callable; the audience present-as-null means any. */
    public function testVerifierClockAndAudience(): void
    {
        $f = self::fx();
        $ok = ['tripwireTriggered' => false, 'outputInfo' => ['verb' => 'payments.send']];
        $this->assertSame($ok, self::grd([]));
        $this->assertSame($ok, self::grd(['nowEpoch' => (float)$f['now']]));
        $this->assertSame($ok, self::noWarnings(static fn() => self::grd(['nowEpoch' => new Num((string)$f['now'])])));
        $this->assertSame($ok, self::grd(['nowEpoch' => static fn(): int => $f['now']]));
        $this->assertSame($ok, self::grd([], ['audience' => null]));
        $this->assertTrue(self::grd([], ['audience' => 'other'])['tripwireTriggered']);
        $p = $f['pcactn'];
        $omitted = OpenAiAgents::pcaInputGuardrail(['verify' => ['grant' => $f['grant'], 'nowEpoch' => $f['now'], 'insecureSkipPlanRootCheck' => true],
            'require' => static fn(mixed ...$a): Obj => $p])->execute([]);
        $this->assertTrue($omitted['tripwireTriggered']);
    }

    /** allowedSuites, authorizedPlanRoots and enforceFreshness reach the verifier. */
    public function testVerifierOptionsArePassed(): void
    {
        $this->assertTrue(self::grd(['allowedSuites' => ['no-such-suite']])['tripwireTriggered']);
        $this->assertTrue(self::grd(['enforceFreshness' => ['maxAgeMs' => 1000]])['tripwireTriggered']);
        $this->assertSame(self::NOPLAN, self::grd(['insecureSkipPlanRootCheck' => false])['outputInfo']['reason']);
        $bogus = self::grd(['insecureSkipPlanRootCheck' => false, 'authorizedPlanRoots' => ['bogus']]);
        $this->assertTrue($bogus['tripwireTriggered']);
        $this->assertNotSame(self::NOPLAN, $bogus['outputInfo']['reason']);
    }

    /** A verify configuration without a grant is "no verifier configured", never an allow. */
    public function testNoVerifierConfigured(): void
    {
        $out = self::grd(['grant' => null]);
        $this->assertSame(['tripwireTriggered' => true, 'outputInfo' => ['kind' => 'verify', 'verb' => 'payments.send',
            'reason' => 'PCA tool denied (verify) for payments.send: no verifier configured', 'checks' => []]], $out);
    }

    /** verify: enforce / hooks are refused, roots and freshness must be arrays (Obj or array configurations). */
    public function testVerifyConfigurationRefusals(): void
    {
        $b = static fn(mixed $verify): string => self::typeError(static fn() => OpenAiAgents::withPcaTool(self::tool(), ['mode' => 'signature-only', 'verify' => $verify]));
        $this->assertSame('withPcaTool: verify.enforce is not supported here (enforceFreshness is, or use `authorize`)', $b(Obj::of(['enforce' => 1])));
        $this->assertSame('withPcaTool: verify.hooks is not supported here (enforceFreshness is, or use `authorize`)', $b(['hooks' => []]));
        $this->assertSame('withPcaTool: verify.enforce is not supported here (enforceFreshness is, or use `authorize`)', $b(['enforce' => 1]));
        $arr = 'withPcaTool: verify.authorizedPlanRoots and verify.enforceFreshness are PHP arrays';
        $this->assertSame($arr, $b(['authorizedPlanRoots' => 'x']));
        $this->assertSame($arr, $b(['enforceFreshness' => 'x']));
        $this->assertSame($arr, $b(Obj::of(['enforceFreshness' => 'x'])));
        $this->assertIsArray(OpenAiAgents::withPcaTool(self::tool(), ['mode' => 'signature-only', 'verify' => ['authorizedPlanRoots' => ['r'], 'enforceFreshness' => ['maxAgeMs' => 1]]]));
    }

    // ---- full-policy configuration ----------------------------------------------------------------------------------

    private static function comps(): array
    {
        return ['resolveGrant' => static fn(): ?Obj => null, 'stateStore' => new MemoryStateStore(), 'isRevoked' => static fn(): bool => false];
    }

    private static function build(array $o): string
    {
        try {
            OpenAiAgents::withPcaTool(self::tool(), $o);
        } catch (\TypeError $e) {
            return $e->getMessage();
        }
        return 'ok';
    }

    /** The authorize option: an assoc array or an Obj of the components; a list, a scalar or an incomplete one is refused. */
    public function testAuthorizeShape(): void
    {
        $base = ['audience' => 'aud', 'verb' => 'v', 'resource' => 'r'];
        $this->assertSame('ok', self::build($base + ['authorize' => self::comps()]));
        $this->assertSame('ok', self::build($base + ['authorize' => Obj::of(self::comps())]));
        $this->assertSame('withPcaTool: full policy mode is missing resolveGrant, stateStore, isRevoked', self::build($base + ['authorize' => []]));
        $shape = 'withPcaTool: `authorize` is an array of the options of Authorize::authorize';
        $this->assertSame($shape, self::build($base + ['authorize' => ['x']]));
        $this->assertSame($shape, self::build($base + ['authorize' => 'str']));
        $this->assertSame('withPcaTool: full policy mode is missing authorize (string keys only)', self::build($base + ['authorize' => self::comps() + [7 => 'a', 8 => 'b']]));
        $this->assertSame("withPcaTool: unknown mode 'true'", self::build($base + ['mode' => true, 'authorize' => self::comps()]));
    }

    /** The operation: the guard's verb and resource, or a callable `operation`. */
    public function testOperationConfiguration(): void
    {
        $a = ['audience' => 'aud'];
        $op = static fn(): array => [];
        $needs = "withPcaTool: full policy mode is missing operation (or the guard's verb and resource)";
        $this->assertSame('ok', self::build($a + ['verb' => 'v', 'resource' => 'r', 'authorize' => self::comps()]));
        $this->assertSame($needs, self::build($a + ['resource' => 'r', 'authorize' => self::comps()]));
        $this->assertSame($needs, self::build($a + ['verb' => 'v', 'authorize' => self::comps()]));
        $this->assertSame('ok', self::build($a + ['authorize' => self::comps() + ['operation' => $op]]));
        $this->assertSame('ok', self::build($a + ['verb' => 'v', 'resource' => 'r', 'authorize' => self::comps() + ['operation' => $op]]));
        $this->assertSame('withPcaTool: full policy mode is missing operation (callable)',
            self::build($a + ['verb' => 'v', 'resource' => 'r', 'authorize' => self::comps() + ['operation' => 'no such function here']]));
    }

    // ---- the full-policy pipeline -----------------------------------------------------------------------------------

    /** @param array<mixed> $ran */
    private static function full(array $auth = [], array $o = [], ?array &$ran = null, ?array &$verified = null): array
    {
        $f = self::fx();
        $g = $f['grant'];
        $p = $f['pcactn'];
        $op = $f['op'];
        $az = array_merge(['resolveGrant' => static fn(string $ref): ?Obj => $ref === $g->get('id') ? $g : null, 'stateStore' => new MemoryStateStore(),
            'isRevoked' => static fn(): bool => false, 'plan' => 'single-step', 'provenanceMediators' => [ProvHarness::pin()]], $auth);
        return OpenAiAgents::withPcaTool(self::tool('pay', $ran), array_merge([
            'authorize' => $az, 'audience' => $f['aud'], 'now' => $f['now'], 'verb' => 'payments.send', 'resource' => 'payments/acme',
            'provenance' => static fn(): ?Obj => ProvHarness::bundle($op), 'require' => static fn(mixed ...$a): Obj => $p,
            'onVerified' => static function (mixed $r, mixed $pc, mixed $in) use (&$verified): void {
                $verified[] = [$r, $pc, $in];
            },
        ], $o));
    }

    private const INPUT = ['amount' => 50, 'currency' => 'usd'];

    /** A permitted call runs once with the verdict handed to onVerified; the same proof again is a replay. */
    public function testFullAllowThenReplay(): void
    {
        $ran = [];
        $verified = [];
        $t = self::full([], [], $ran, $verified);
        $this->assertSame(['ran' => self::INPUT], self::noWarnings(static fn() => ($t['execute'])(self::INPUT, [])));
        $this->assertSame([self::INPUT], $ran);
        [$res, $pc, $in] = $verified[0];
        $this->assertSame(['allow', 'checks'], array_keys($res));
        $this->assertTrue($res['allow']);
        $this->assertSame('pass', $res['checks']['revocation']);
        $this->assertSame('pass', $res['checks']['replay']);
        $this->assertSame(self::fx()['pcactn'], $pc);
        $this->assertSame(self::INPUT, $in);
        $e = self::noWarnings(static fn() => self::denied(static fn() => ($t['execute'])(self::INPUT, [])));
        $this->assertSame('replay', $e->kind);
        $this->assertStringStartsWith('PCA tool denied (replay) for payments.send: replay: 1 is not greater than last seen 1', $e->getMessage());
        $this->assertSame('fail', $e->checks['replay']);
        $this->assertCount(1, $ran);
    }

    /** A float clock is truncated to integer epoch-ms; a callable clock is called. */
    public function testFullClockForms(): void
    {
        $now = self::fx()['now'];
        $t = self::full([], ['now' => (float)$now]);
        $this->assertSame(['ran' => self::INPUT], ($t['execute'])(self::INPUT, []));
        $t = self::full([], ['now' => static fn(): int => $now]);
        $this->assertSame(['ran' => self::INPUT], ($t['execute'])(self::INPUT, []));
    }

    /** Every refusal of the pipeline is mapped to its kind, keeps its reason and checks, and the tool never runs. */
    public function testFullDenialKinds(): void
    {
        $cases = [
            ['policy', 'resolve_grant: grant resolution failed (fail closed)', ['resolve_grant' => 'fail'],
                ['resolveGrant' => static function (): never {
                    throw new \RuntimeException('down');
                }], []],
            ['verify', 'grant_ref: does not resolve to a known grant', ['grant_ref' => 'fail'], ['resolveGrant' => static fn(): ?Obj => null], []],
            ['config', "authorize_config: missing required component(s): plan (only 'single-step' or null) (fail closed)", ['authorize_config' => 'fail'],
                ['plan' => 'bogus'], []],
            ['policy', 'authorization error (fail closed): RuntimeException', null, [], ['now' => static function (): never {
                throw new \RuntimeException('clock down');
            }]],
        ];
        foreach ($cases as [$kind, $reason, $checks, $auth, $o]) {
            $ran = [];
            $t = self::full($auth, $o, $ran);
            $e = self::noWarnings(static fn() => self::denied(static fn() => ($t['execute'])(self::INPUT, [])));
            $this->assertSame([$kind, "PCA tool denied ($kind) for payments.send: $reason", $checks], [$e->kind, $e->getMessage(), $e->checks], $reason);
            $this->assertSame([], $ran);
        }
        $ran = [];
        $t = self::full(['isRevoked' => static fn(): bool => true], [], $ran);
        $e = self::noWarnings(static fn() => self::denied(static fn() => ($t['execute'])(self::INPUT, [])));
        $this->assertSame(['revoked', 'PCA tool denied (revoked) for payments.send: revocation: the grant is revoked'], [$e->kind, $e->getMessage()]);
        $this->assertSame('fail', $e->checks['revocation']);
        $this->assertSame([], $ran);
    }

    /** A custom operation must name the proof's verb and (when it names one) resource; an exact one is authorized. */
    public function testFullOperationBinding(): void
    {
        $params = ['amount' => 50, 'currency' => 'usd'];
        $deny = static function (array $op): PcaToolDenied {
            $t = self::full(['operation' => static fn(): array => $op], ['verb' => null, 'resource' => null]);
            return self::noWarnings(static fn() => self::denied(static fn() => ($t['execute'])(self::INPUT, [])));
        };
        $pre = 'PCA tool denied (binding) for payments.send: the proof is for payments.send on payments/acme, but this call is ';
        $e = $deny(['verb' => 'other', 'resource' => 'payments/acme', 'params' => $params]);
        $this->assertSame(['binding', $pre . 'other on payments/acme'], [$e->kind, $e->getMessage()]);
        $this->assertSame($pre . 'payments.send on other', $deny(['verb' => 'payments.send', 'resource' => 'other', 'params' => $params])->getMessage());
        $this->assertSame($pre . 'other', $deny(['verb' => 'other', 'resource' => null, 'params' => $params])->getMessage());
        $e = $deny(['verb' => 'payments.send', 'resource' => null, 'params' => $params]);
        $this->assertSame(['policy', 'PCA tool denied (policy) for payments.send: ' . self::OPREF], [$e->kind, $e->getMessage()]);
        $op = self::fx()['op'];
        $t = self::full(['operation' => static fn(): Obj => $op], ['verb' => null, 'resource' => null]);
        $this->assertSame(['ran' => self::INPUT], self::noWarnings(static fn() => ($t['execute'])(self::INPUT, [])));
    }

    /** A denial whose decisive reason is empty still names a reason ("denied"), never an empty one. */
    public function testFullEmptyReasonBecomesDenied(): void
    {
        Authorize::$coreHook = static fn(array $c): array => ['allow' => false, 'checks' => $c['checks'] + ['zz' => false], 'reasons' => [''], 'reason' => ''];
        $t = self::full();
        $e = self::denied(static fn() => ($t['execute'])(self::INPUT, []));
        $this->assertStringStartsWith('PCA tool denied (', $e->getMessage());
        $this->assertNotSame('PCA tool denied (' . $e->kind . ') for payments.send: ', $e->getMessage());
    }

    /** The default operation hashes the input object; a non-object input is the empty object, a list is no params object. */
    public function testFullDefaultOperationParams(): void
    {
        $t = self::full();
        $e = self::noWarnings(static fn() => self::denied(static fn() => ($t['execute'])('x', [])));
        $this->assertSame('policy', $e->kind);
        $this->assertStringContainsString("operation: the proof's params_digest does not match", $e->getMessage());
        $t = self::full();
        $e = self::noWarnings(static fn() => self::denied(static fn() => ($t['execute'])(['a', 'b'], [])));
        $this->assertSame(['policy', 'PCA tool denied (policy) for payments.send: ' . self::OPREF], [$e->kind, $e->getMessage()]);
    }

    // ---- pcaTools / mergeOptions ------------------------------------------------------------------------------------

    /** A list of tools is guarded one by one, keyed by position. */
    public function testPcaToolsList(): void
    {
        $out = OpenAiAgents::pcaTools([self::tool('a'), self::tool('b')], self::sig());
        $this->assertCount(2, $out);
        $this->assertSame(self::missing('a'), self::denied(static fn() => ($out[0]['execute'])(1, []))->getMessage());
        $this->assertSame(self::missing('b'), self::denied(static fn() => ($out[1]['execute'])(1, []))->getMessage());
    }

    /** `only` names tools as strings (an integer key matches its string form); every other tool is left as is. */
    public function testPcaToolsOnly(): void
    {
        $out = OpenAiAgents::pcaTools([5 => self::tool('five'), 'x' => self::tool('x')], self::sig(['only' => [5]]));
        $this->assertSame(self::missing('five'), self::denied(static fn() => ($out[5]['execute'])(1, []))->getMessage());
        $this->assertSame(['ran' => 1], ($out['x']['execute'])(1, []));
        $out = OpenAiAgents::pcaTools([5 => self::tool('five')], self::sig(['only' => ['5']]));
        $this->assertSame(self::missing('five'), self::denied(static fn() => ($out[5]['execute'])(1, []))->getMessage());
    }

    /** A per-tool option wins over the shared one; a per-tool mode replaces the shared mode. */
    public function testPerToolOverrides(): void
    {
        $out = OpenAiAgents::pcaTools(['t' => self::tool('t')], self::sig(['verb' => 'a', 'per' => ['t' => ['verb' => 'b']]]));
        $this->assertSame(self::missing('b'), self::denied(static fn() => ($out['t']['execute'])(1, []))->getMessage());
        $this->assertSame("withPcaTool: unknown mode 'bogus'", self::typeError(static fn() => OpenAiAgents::pcaTools(['t' => self::tool('t')],
            self::sig(['per' => ['t' => ['mode' => 'bogus']]]))));
    }

    /** The shared audience reaches a tool with an override (null = any audience); none stays none, without a warning. */
    public function testPerToolAudience(): void
    {
        $f = self::fx();
        $p = $f['pcactn'];
        $shared = ['mode' => 'signature-only', 'verify' => ['grant' => $f['grant'], 'nowEpoch' => $f['now'], 'insecureSkipPlanRootCheck' => true],
            'require' => static fn(mixed ...$a): Obj => $p, 'per' => ['t' => ['verb' => 'payments.send']]];
        $out = OpenAiAgents::pcaTools(['t' => self::tool('t')], $shared + ['audience' => null]);
        $this->assertSame(['ran' => 1], ($out['t']['execute'])(1, []));
        $none = self::noWarnings(static fn() => OpenAiAgents::pcaTools(['t' => self::tool('t')], $shared));
        $this->assertSame('verify', self::denied(static fn() => ($none['t']['execute'])(1, []))->kind);
    }

    /** A guardrail's name is its string form. */
    public function testGuardrailName(): void
    {
        $this->assertSame('5', OpenAiAgents::pcaInputGuardrail(['name' => 5, 'verify' => static fn() => ['allow' => true]])->name);
    }

    // ---- step-up review ---------------------------------------------------------------------------------------------

    /** reviewToolCall hands the review the mapped verb / resource / params and only the review options that are set. */
    public function testReviewToolCall(): void
    {
        $o = ['intent' => static fn(string $t, mixed $in): array => ['verb' => 'v', 'resource' => 'r', 'params' => 'P'],
            'review' => static fn(mixed ...$a): array => $a, 'now' => 5, 'goal' => 'g', 'standing' => null, 'other' => 1];
        $this->assertSame(['tool' => 't', 'review' => ['A', 'v', 'r', 'P', ['now' => 5, 'goal' => 'g']]], OpenAiAgents::reviewToolCall('A', 't', 'I', $o));
        $o['intent'] = static fn(): array => ['verb' => 'v', 'resource' => 'r'];
        $this->assertSame('I', OpenAiAgents::reviewToolCall('A', 't', 'I', $o)['review'][3]);
        $this->assertSame(['tool' => 't', 'review' => ['kind' => 'auto']], OpenAiAgents::reviewToolCall('A', 't', 'I', ['intent' => static fn() => null]));
        $this->assertSame('reviewToolCall: pass `intent`, the mapping of a tool call to its action', self::typeError(static fn() => OpenAiAgents::reviewToolCall('A', 't', 'I', [])));
        $this->assertSame("reviewToolCall: pass `review`, the agent's review of an intended action",
            self::typeError(static fn() => OpenAiAgents::reviewToolCall('A', 't', 'I', ['intent' => static fn() => ['verb' => 'v']])));
    }

    private static function needs(array $o): \Closure
    {
        return OpenAiAgents::pcaNeedsApproval('A', $o + ['toolName' => 'tn', 'intent' => static fn(): array => ['verb' => 'v', 'resource' => 'r'],
            'review' => static fn(mixed $ag, mixed $v, mixed $r, mixed $params): mixed => $params]);
    }

    /** needsApproval: auto never interrupts; deny interrupts unless denyNeedsApproval is falsy. */
    public function testNeedsApprovalAutoAndDeny(): void
    {
        $step = [];
        $on = static function (array $x) use (&$step): void {
            $step[] = $x;
        };
        $this->assertFalse(self::needs([])(null, ['kind' => 'auto']));
        $this->assertTrue(self::needs(['onStepUp' => $on])(null, ['kind' => 'deny']));
        $this->assertFalse(self::needs(['denyNeedsApproval' => false, 'onStepUp' => $on])(null, ['kind' => 'deny']));
        $this->assertFalse(self::needs(['denyNeedsApproval' => 0])(null, ['kind' => 'deny']));
        $this->assertSame([], $step);
    }

    /** needsApproval on a step-up: an approved request passes, otherwise onStepUp hears {tool, request} and the run interrupts. */
    public function testNeedsApprovalStepUp(): void
    {
        $step = [];
        $on = static function (array $x) use (&$step): void {
            $step[] = $x;
        };
        $req = ['kind' => 'step_up', 'request' => 'R'];
        $this->assertTrue(self::needs([])(null, $req));
        $this->assertTrue(self::needs(['onStepUp' => $on])(null, $req));
        $this->assertSame([['tool' => 'tn', 'request' => 'R']], $step);
        $this->assertFalse(self::needs(['onStepUp' => $on, 'approved' => static fn(mixed $r): bool => $r === 'R'])(null, $req));
        $this->assertCount(1, $step);
        $this->assertTrue(self::needs(['onStepUp' => $on, 'approved' => static fn(): bool => false])(null, $req));
        $this->assertCount(2, $step);
        $step = [];
        $this->assertTrue(self::needs(['toolName' => 5, 'onStepUp' => $on])(null, $req));
        $this->assertSame([['tool' => 5, 'request' => 'R']], $step);
    }

    /** needsApproval passes the review options (goal, now, ...) through to the review. */
    public function testNeedsApprovalReviewOptions(): void
    {
        $seen = null;
        $f = OpenAiAgents::pcaNeedsApproval('A', ['intent' => static fn(): array => ['verb' => 'v', 'resource' => 'r'], 'goal' => 'g',
            'review' => static function (mixed $ag, mixed $v, mixed $r, mixed $p, array $opts) use (&$seen): array {
                $seen = $opts;
                return ['kind' => 'auto'];
            }]);
        $this->assertFalse($f(null, 'in'));
        $this->assertSame(['goal' => 'g'], $seen);
    }

    // ---- attachPca --------------------------------------------------------------------------------------------------

    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    private static function invokeTool(): array
    {
        return ['name' => 'refund', 'onInvokeTool' => static fn(mixed $ctx, mixed $raw = null): array => ['ctx' => $ctx, 'raw' => $raw]];
    }

    /** A permitted call is signed over its JSON arguments, handed to onProof, and the original's result is returned. */
    public function testAttachPcaSignsThenRuns(): void
    {
        $seen = [];
        $t = OpenAiAgents::attachPca(self::agent(), 'refund', 'orders/1', self::invokeTool(), static function (Action $a, array $p) use (&$seen): void {
            $seen[] = [$a, $p];
        });
        $this->assertSame(['ctx' => 'ctx', 'raw' => '{"amount":5}'], ($t['onInvokeTool'])('ctx', '{"amount":5}'));
        $this->assertCount(1, $seen);
        $this->assertSame(['amount' => 5], $seen[0][1]);
        $act = $seen[0][0]->pcactn->get('action');
        $this->assertSame(['refund', 'orders/1'], [$act->get('verb'), $act->get('resource')]);
        $this->assertSame(Pca::paramsDigest(Sign::n(['amount' => 5])), $act->get('params_digest'));
    }

    /** By default a call the grant refuses never runs; with failFast off it is signed and run anyway. */
    public function testAttachPcaFailFast(): void
    {
        $ran = false;
        $tool = ['name' => 'refund', 'onInvokeTool' => static function () use (&$ran): string {
            $ran = true;
            return 'ran';
        }];
        $t = OpenAiAgents::attachPca(self::agent(), 'refund', 'users/1', $tool);
        try {
            ($t['onInvokeTool'])('ctx', '{}');
            $this->fail('a refused call ran');
        } catch (\RuntimeException $e) {
            $this->assertStringStartsWith('attachPca: the grant refuses this call (', $e->getMessage());
        }
        $this->assertFalse($ran);
        $t = OpenAiAgents::attachPca(self::agent(), 'refund', 'users/1', $tool, null, false);
        $this->assertSame('ran', ($t['onInvokeTool'])('ctx', '{}'));
        $this->assertTrue($ran);
    }

    /** A resource closure's result is used as a string; non-text arguments are no arguments; a tool without onInvokeTool is refused. */
    public function testAttachPcaResourceAndShape(): void
    {
        $seen = [];
        $t = OpenAiAgents::attachPca(self::agent(), 'refund', static fn(array $p): int => 5, self::invokeTool(), static function (Action $a, array $p) use (&$seen): void {
            $seen[] = [$a, $p];
        }, false);
        $this->assertSame(['ctx' => 'ctx', 'raw' => ['k' => 1]], ($t['onInvokeTool'])('ctx', ['k' => 1]));
        $this->assertSame([], $seen[0][1]);
        $this->assertSame('5', $seen[0][0]->pcactn->get('action')->get('resource'));
        $this->assertSame('attachPca: the tool has no onInvokeTool', self::typeError(static fn() => OpenAiAgents::attachPca(self::agent(), 'refund', 'orders/1', ['name' => 'x'])));
    }
}
