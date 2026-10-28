<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\ClaimResult;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\PdoStateStore;
use Atlas\Pca\Predicates;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Authorize::authorize (0.5). The signed fixtures (test-data/authorize-fixtures.json, `pca-authorize-fixtures/1`) come from
 * the TypeScript reference, which also recorded its authorize() outcome of every step (`ts`): each case asserts the exact
 * outcome (allow, status, failing checks) and that it equals the TypeScript decision, with one fresh store per case, once
 * with the memory store and once with the SQLite (PDO) store.
 */
final class AuthorizeTest extends TestCase
{
    private Obj $fix;
    /** @var array<string,Obj> */
    private array $cases = [];

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            $this->cases[$c->get('name')] = $c;
        }
    }

    private function aud(): string
    {
        return $this->fix->get('audience');
    }

    private function now(): int
    {
        return $this->fix->get('now')->int();
    }

    private function az(Obj $c, int $step = 0, array $o = []): AuthorizeResult
    {
        $s = $c->get('steps')[$step];
        $o += [
            'operation' => $s->get('operation'), 'audience' => $this->aud(), 'resolve' => fn ($r) => $c->get('grant'),
            'store' => new MemoryStateStore(), 'revoked' => fn ($p, $g) => false, 'plan' => 'single-step', 'context' => null,
        ];
        return Authorize::authorize($s->get('pcactn'), $o['operation'], $o['audience'], $o['resolve'], $o['store'], $o['revoked'],
            $this->now(), $o['plan'], $o['context']);
    }

    /** @return array{bool,int,list<string>} */
    private static function settle(AuthorizeResult $r): array
    {
        $failed = array_keys(array_filter($r->checks, fn ($v) => $v === 'fail'));
        sort($failed);
        return [$r->allow, $r->status, $failed];
    }

    /** @var list<?string> the decisive reason of every step of the last runCase */
    private array $reasons = [];

    private function runCase(Obj $c, object $store): array
    {
        $out = [];
        $this->reasons = [];
        $g = $c->get('grant');
        foreach ($c->get('steps') as $s) {
            $revoked = $s->get('revoked') === true;
            $r = Authorize::authorize($s->get('pcactn'), $s->get('operation'), $this->aud(),
                fn ($ref) => $ref === $g->get('id') ? $g : null, $store, fn ($p, $gr) => $revoked, $this->now(), 'single-step');
            $out[] = self::settle($r);
            $this->reasons[] = $r->reason;
        }
        return $out;
    }

    private function assertParity(object $store, string $name, Obj $c): void
    {
        $got = $this->runCase($c, $store);
        foreach ($c->get('steps') as $i => $s) {
            $e = $s->get('expect');
            $failed = [];
            foreach ($e->get('failed') as $f) {
                $failed[] = $f;
            }
            $this->assertSame([$e->get('allow'), $e->get('status')->int(), $failed], $got[$i], "$name step $i");
            if ($e->has('reason')) { // a step that records `expect.reason` pins a substring of the decisive reason
                $this->assertStringContainsString($e->get('reason'), (string)$this->reasons[$i], "$name step $i reason");
            }
            $ts = $s->get('ts');
            $this->assertSame([$ts->get('allow'), $ts->get('status')->int()], [$got[$i][0], $got[$i][1]], "$name step $i vs TS");
        }
    }

    public function testFixtureShape(): void
    {
        $this->assertSame('pca-authorize-fixtures/1', $this->fix->get('format'));
        $this->assertCount(31, $this->cases);
        $this->assertSame(35, array_sum(array_map(fn ($c) => count($c->get('steps')), $this->cases)));
    }

    public function testFixturesMemoryStore(): void
    {
        foreach ($this->cases as $n => $c) {
            $this->assertParity(new MemoryStateStore(), $n, $c);
        }
    }

    public function testFixturesPdoStore(): void
    {
        $i = 0;
        foreach ($this->cases as $n => $c) {
            $store = new PdoStateStore(new \PDO('sqlite::memory:'));
            $store->createTable();
            $this->assertParity($store, $n, $c);
            $i++;
        }
        $this->assertSame(31, $i);
    }

    public function testAcceptanceReasons(): void
    {
        $r = $this->az($this->cases['envelope-max-spend-400-refused']);
        $this->assertSame([false, 403, ['policy']], self::settle($r));
        $this->assertSame('policy: caveat(s) not satisfied: max_spend', $r->reason);
        $this->assertSame('policy: root caveat(s) not satisfied: max_spend', $this->az($this->cases['root-max-spend-400-refused'])->reason);
        $this->assertSame('delegated_caveats: delegation caveat(s) not satisfied: max_spend',
            $this->az($this->cases['delegated-max-spend-400-refused'])->reason);
        $this->assertSame("operation: the proof's params_digest does not match the params of this payments.send operation",
            $this->az($this->cases['envelope-max-spend-signed-50-executes-400'])->reason);
        $this->assertSame('operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme',
            $this->az($this->cases['operation-other-verb'])->reason);
        $this->assertStringStartsWith('policy: root caveat(s) not satisfied: ', $this->az($this->cases['root-unknown-caveat'])->reason);
        $this->assertStringStartsWith('delegated_caveats: delegation caveat(s) not satisfied: ', $this->az($this->cases['delegated-unknown-caveat'])->reason);
    }

    public function testAllowBindsTheOperation(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        $s = $c->get('steps')[0];
        $r = $this->az($c);
        $this->assertSame([true, 200, null], [$r->allow, $r->status, $r->reason]);
        $this->assertSame(['payments.send', 'payments/acme'], [$r->operation->verb, $r->operation->resource]);
        $this->assertSame($s->get('pcactn')->get('action')->get('params_digest'), $r->operation->paramsDigest);
        $this->assertSame(Pca::hashCanonical($s->get('pcactn')), $r->operation->id);
        $this->assertTrue(Authorize::isAuthorizedFor($r, $s->get('operation')));
        $this->assertTrue(Authorize::isAuthorizedFor($r, ['verb' => 'payments.send', 'resource' => 'payments/acme',
            'params' => Obj::of(['amount' => 50, 'currency' => 'usd'])]));
        $this->assertFalse(Authorize::isAuthorizedFor($r, ['verb' => 'payments.send', 'resource' => 'payments/acme',
            'params' => Obj::of(['amount' => 400, 'currency' => 'usd'])]));
        $this->assertFalse(Authorize::isAuthorizedFor($r, ['verb' => 'payments.refund', 'resource' => 'payments/acme', 'params' => $s->get('operation')->get('params')]));
        $this->assertFalse(Authorize::isAuthorizedFor($r, null));
        $this->assertFalse(Authorize::isAuthorizedFor($this->az($this->cases['envelope-max-spend-400-refused']),
            $this->cases['envelope-max-spend-400-refused']->get('steps')[0]->get('operation')));
    }

    public function testMissingComponentsRefusedBeforeVerification(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        $cases = [
            ['audience', ['audience' => '']], ['audience', ['audience' => null]], ['resolveGrant', ['resolve' => null]],
            ['stateStore', ['store' => null]], ['stateStore', ['store' => new \stdClass()]],
            ['isRevoked', ['revoked' => null]], ['isRevoked', ['revoked' => true]],
        ];
        foreach ($cases as [$missing, $o]) {
            $seen = 0;
            $o += ['resolve' => function () use (&$seen, $c) { $seen++; return $c->get('grant'); }];
            $r = $this->az($c, 0, $o);
            $this->assertSame([false, 403, ['authorize_config']], self::settle($r), $missing);
            $this->assertSame([$missing], $r->missing);
            $this->assertSame(0, $seen);
        }
    }

    public function testOperationRequiredAndNoPlanSource(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        $seen = 0;
        foreach ([null, 5, Obj::of([]), Obj::of(['verb' => 'payments.send', 'resource' => 'payments/acme']),
                  Obj::of(['verb' => '', 'resource' => 'x', 'params' => Obj::of([])])] as $op) {
            $r = $this->az($c, 0, ['operation' => $op, 'resolve' => function () use (&$seen, $c) { $seen++; return $c->get('grant'); }]);
            $this->assertSame([false, 403, ['operation']], self::settle($r));
        }
        $this->assertSame(0, $seen);
        $r = $this->az($c, 0, ['plan' => null]);
        $this->assertSame([false, 403, ['plan_root_authorized']], self::settle($r));
        // K5: a missing plan configuration is a default-deny with the exact reason, never 'not-enforced'
        $this->assertSame('plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)', $r->reason);
        $this->assertNotSame('not-enforced', $r->checks['plan_root_authorized'] ?? null);
    }

    public function testNoPlanRootOptOutAndConfiguredPlanPasses(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        // the pipeline has no insecureSkipPlanRootCheck parameter: passing one is an error, not a silent skip
        $names = array_map(fn ($p) => $p->getName(), (new \ReflectionMethod(Authorize::class, 'authorize'))->getParameters());
        $this->assertNotContains('insecureSkipPlanRootCheck', $names);
        $r = $this->az($c);
        $this->assertTrue($r->allow);
        $this->assertSame('pass', $r->checks['plan_root_authorized']);
    }

    public function testRevocationMustBeExactlyFalse(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        foreach ([null, 0, 'no', [], fn () => throw new \RuntimeException('down')] as $ret) {
            $r = $this->az($c, 0, ['revoked' => $ret instanceof \Closure ? $ret : fn () => $ret]);
            $this->assertSame([false, 403, ['revocation']], self::settle($r));
            $this->assertSame('revocation: the revocation check failed (fail closed)', $r->reason);
        }
        $this->assertSame('revocation: the grant is revoked', $this->az($c, 0, ['revoked' => fn () => true])->reason);
    }

    public function testStoreFailureDeniesAndDeniedNeverClaims(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        $broken = new class { public function claim(string $k, int $n) { throw new \RuntimeException('locked'); } };
        $null = new class { public function claim(string $k, int $n) { return null; } };
        $garbage = new class { public function claim(string $k, int $n) { return 'yes'; } };
        foreach ([$broken, $null] as $st) {
            $r = $this->az($c, 0, ['store' => $st]);
            $this->assertSame([false, 403, ['replay']], self::settle($r));
            $this->assertSame('replay: the replay store failed (fail closed)', $r->reason);
        }
        $this->assertFalse($this->az($c, 0, ['store' => $garbage])->allow);
        $seen = [];
        $rec = new class($seen) { public function __construct(public array &$s) {} public function claim(string $k, int $n) { $this->s[] = $k; return new ClaimResult(true); } };
        foreach ($this->cases as $cc) {
            $s = $cc->get('steps')[0];
            if ($s->get('expect')->get('allow') === true) {
                continue;
            }
            $this->assertFalse($this->az($cc, 0, ['store' => $rec, 'revoked' => fn () => $s->get('revoked') === true])->allow);
        }
        $this->assertSame([], $seen);
    }

    public function testClaimTable(): void
    {
        $mk = [new MemoryStateStore(), (function () {
            $s = new PdoStateStore(new \PDO('sqlite::memory:'));
            $s->createTable();
            return $s;
        })()];
        foreach ($mk as $st) {
            $got = [];
            foreach ([['a', 5], ['a', 5], ['a', 4], ['a', 6], ['b', 0], ['b', 0]] as [$k, $n]) {
                $r = $st->claim($k, $n);
                $got[] = [$r->ok, $r->lastCounter];
            }
            $this->assertSame([[true, null], [false, 5], [false, 5], [true, null], [true, null], [false, 0]], $got);
        }
    }

    public function testReplayAcrossProcessesSharingTheDatabase(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl not available');
        }
        $db = tempnam(sys_get_temp_dir(), 'pca');
        $seed = new PdoStateStore(new \PDO('sqlite:' . $db));
        $seed->createTable();
        unset($seed);
        $pids = [];
        for ($i = 0; $i < 16; $i++) {
            $pid = pcntl_fork();
            if ($pid === 0) {
                $pdo = new \PDO('sqlite:' . $db);
                $pdo->exec('PRAGMA busy_timeout = 10000');
                exit((new PdoStateStore($pdo))->claim('k', 1)->ok ? 10 : 11);
            }
            $pids[] = $pid;
        }
        $codes = [];
        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
            $codes[] = pcntl_wexitstatus($status);
        }
        @unlink($db);
        $this->assertSame(1, count(array_filter($codes, fn ($c) => $c === 10)));
        $this->assertSame(15, count(array_filter($codes, fn ($c) => $c === 11)));
    }

    public function testConcurrentSameProofOneWinsSequentially(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        $store = new MemoryStateStore();
        $wins = 0;
        for ($i = 0; $i < 8; $i++) {
            $wins += $this->az($c, 0, ['store' => $store])->allow ? 1 : 0;
        }
        $this->assertSame(1, $wins);
        $this->assertSame('replay: 1 is not greater than last seen 1 (replay)', $this->az($c, 0, ['store' => $store])->reason);
    }

    // ---- middleware ----------------------------------------------------------------------------------------------------

    private function grants(): array
    {
        $out = [];
        foreach (['envelope-max-spend-within', 'envelope-max-spend-400-refused'] as $n) {
            $g = $this->cases[$n]->get('grant');
            $out[$g->get('id')] = $g;
        }
        return $out;
    }

    private function mw(string $verb = 'payments.send', ?MemoryStateStore $store = null, bool $revoked = false): PcaMiddleware
    {
        $f = new HttpFactory();
        $grants = $this->grants();
        $opts = new AuthorizeOptions(
            stateStore: $store ?? new MemoryStateStore(),
            isRevoked: fn () => $revoked,
            operation: fn (ServerRequestInterface $r) => ['verb' => $verb, 'resource' => 'payments/acme',
                'params' => Json::parseLax((string)$r->getBody())],
        );
        return new PcaMiddleware($this->aud(), fn ($ref) => $grants[$ref] ?? null, fn () => $this->now(), $f, $f, authorize: $opts);
    }

    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public int $calls = 0;
            public ?ServerRequestInterface $got = null;
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;
                $this->got = $request;
                return new Response(200, [], 'ok');
            }
        };
    }

    private function post(PcaMiddleware $mw, RequestHandlerInterface $h, string $case, string $body): array
    {
        $p = $this->cases[$case]->get('steps')[0]->get('pcactn');
        $res = $mw->process((new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => Pca::b64u(Json::canonicalizeStrict($p))]))
            ->withBody(Utils::streamFor($body)), $h);
        return [$res->getStatusCode(), json_decode((string)$res->getBody(), true)];
    }

    public function testMiddlewareAcceptance(): void
    {
        $h = $this->handler();
        [$st, $b] = $this->post($this->mw(), $h, 'envelope-max-spend-400-refused', '{"amount":400,"currency":"usd"}');
        $this->assertSame(403, $st);
        $this->assertSame('policy: caveat(s) not satisfied: max_spend', $b['error_description']);

        [$st, $b] = $this->post($this->mw(), $h, 'envelope-max-spend-within', '{"amount":400,"currency":"usd"}');
        $this->assertSame(403, $st);
        $this->assertStringStartsWith('operation: the proof\'s params_digest', $b['error_description']);

        [$st, $b] = $this->post($this->mw('payments.refund'), $h, 'envelope-max-spend-within', '{"amount":50,"currency":"usd"}');
        $this->assertSame(403, $st);
        $this->assertStringStartsWith('operation: the proof is for payments.send', $b['error_description']);

        [$st] = $this->post($this->mw(revoked: true), $h, 'envelope-max-spend-within', '{"amount":50,"currency":"usd"}');
        $this->assertSame(403, $st);
        $this->assertSame(0, $h->calls);

        $store = new MemoryStateStore();
        $mw = $this->mw(store: $store);
        [$st] = $this->post($mw, $h, 'envelope-max-spend-within', '{"amount":50,"currency":"usd"}');
        $this->assertSame(200, $st);
        $this->assertSame(1, $h->calls);
        $this->assertSame('payments.send', $h->got->getAttribute('pca.operation')->verb);
        $this->assertTrue($h->got->getAttribute('pca.authorization')->allow);
        [$st, $b] = $this->post($mw, $h, 'envelope-max-spend-within', '{"amount":50,"currency":"usd"}');
        $this->assertSame(403, $st);
        $this->assertSame('replay: 1 is not greater than last seen 1 (replay)', $b['error_description']);
        $this->assertSame(1, $h->calls);
    }

    public function testMiddlewareMissingOperationMappingDenies(): void
    {
        $f = new HttpFactory();
        $grants = $this->grants();
        $mw = new PcaMiddleware($this->aud(), fn ($ref) => $grants[$ref] ?? null, fn () => $this->now(), $f, $f,
            authorize: new AuthorizeOptions(new MemoryStateStore(), fn () => false));
        $h = $this->handler();
        [$st] = $this->post($mw, $h, 'envelope-max-spend-within', '{"amount":50,"currency":"usd"}');
        $this->assertSame(403, $st);
        $this->assertSame(0, $h->calls);
    }

    // ---- B3: the default is the full authorize path ----------------------------------------------------------------

    private function overRequest(): array
    {
        return ['envelope-max-spend-400-refused', '{"amount":400,"currency":"usd"}'];
    }

    private function mwWith(mixed ...$o): PcaMiddleware
    {
        $f = new HttpFactory();
        $grants = $this->grants();
        return new PcaMiddleware($this->aud(), fn ($ref) => $grants[$ref] ?? null, fn () => $this->now(), $f, $f, ...$o);
    }

    public function testSignatureOnlyIsTheExplicitOptIn(): void
    {
        $h = $this->handler();
        [$case, $body] = $this->overRequest();
        [$st] = $this->post($this->mwWith(signatureOnly: true), $h, $case, $body);
        $this->assertSame(200, $st); // the core verifier only: a $400 body under a $100 proof reaches the handler
        [$st] = $this->post($this->mwWith(signatureOnly: true), $h, $case, $body);
        $this->assertSame(200, $st); // and there is no replay store
        $this->assertSame(2, $h->calls);
        $this->assertFalse($h->got->getAttribute('pca.authorization') !== null);
    }

    public function testDefaultWithoutOptionsRefusesWithAuthorizeConfig(): void
    {
        $h = $this->handler();
        [$case, $body] = $this->overRequest();
        [$st, $b] = $this->post($this->mwWith(), $h, $case, $body);
        $this->assertSame(403, $st);
        $this->assertSame('insufficient_authority', $b['error']);
        $this->assertSame('authorize_config: missing required component(s): stateStore, isRevoked (fail closed)', $b['error_description']);
        $this->assertSame(["stateStore", "isRevoked"], $b["missing"]);
        $this->assertSame(0, $h->calls);
        [$st] = $this->post($this->mwWith(authorize: new AuthorizeOptions()), $h, $case, $body);
        $this->assertSame(403, $st);
        $this->assertSame(0, $h->calls);
    }

    public function testSignatureOnlyWithAuthorizeIsAConstructionError(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mutually exclusive');
        $this->mwWith(signatureOnly: true, authorize: new AuthorizeOptions());
    }

    // ---- B6: check names and limit-naming reasons ---------------------------------------------------------------------

    public function testCoreVerifierReportsCounterFormatOnly(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        $s = $c->get('steps')[0];
        $v = Pca::verifyPcactnCore($s->get('pcactn'), $c->get('grant'), $this->now(), $this->aud());
        $this->assertSame(['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion',
            'leaf_signature', 'counter_format'], array_keys($v['checks']));
        $p = $s->get('pcactn')->without('counter');
        $p->set('counter', new Num('-1'));
        $bad = Pca::verifyPcactnCore($p, $c->get('grant'), $this->now(), $this->aud());
        $this->assertFalse($bad['allow']);
        $this->assertFalse($bad['checks']['counter_format']);
        $this->assertArrayNotHasKey('counter', $bad['checks']);
    }

    public function testAuthorizeReportsReplayNotCounter(): void
    {
        $r = $this->az($this->cases['envelope-max-spend-within']);
        $this->assertSame('pass', $r->checks['replay']);
        $this->assertSame('pass', $r->checks['counter_format']);
        $this->assertArrayNotHasKey('counter', $r->checks);
        $this->assertSame(['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity',
            'grant_ref_bound', 'operation', 'params_digest', 'policy'], Authorize::DEFAULT_REQUIRED_CHECKS);
    }

    public function testRequireCounterIsAnAliasOfReplay(): void
    {
        $c = $this->cases['envelope-max-spend-within'];
        $s = $c->get('steps')[0];
        $store = new MemoryStateStore();
        $call = fn () => Authorize::authorize($s->get('pcactn'), $s->get('operation'), $this->aud(), fn ($r) => $c->get('grant'),
            $store, fn () => false, $this->now(), 'single-step', null, null, null, null, ['counter']);
        $first = $call();
        $this->assertTrue($first->allow, (string)$first->reason);
        $this->assertArrayNotHasKey('counter', $first->checks);
        $second = $call();
        $this->assertSame('replay: 1 is not greater than last seen 1 (replay)', $second->reason);
        $this->assertSame('fail', $second->checks['replay']);
    }

    public function testLimitIsNamedInThePolicyReason(): void
    {
        $this->assertSame('policy: amount <= 100 not satisfied for payments.send on payments/acme',
            $this->az($this->cases['envelope-predicate-400-refused'])->reason);
    }

    public function testLimitReasonTableMatchesTypeScript(): void
    {
        $table = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/limit-reasons.json'));
        $this->assertSame('pca-limit-reasons/1', $table->get('format'));
        $n = 0;
        foreach ($table->get('cases') as $c) {
            $ctx = new Obj();
            $ctx->set('action', $c->get('action'));
            $r = Predicates::evaluatePredicates($c->get('predicates'), $ctx);
            $this->assertSame($c->get('allowed'), $r['allowed'], $c->get('name'));
            if (!$c->get('allowed')) {
                $this->assertSame($c->get('reason'), $r['reason'], $c->get('name'));
            }
            $n++;
        }
        $this->assertGreaterThan(50, $n);
    }
}
