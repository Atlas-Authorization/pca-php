<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ArgProvenance;
use Atlas\Pca\Gateway;
use Atlas\Pca\GatewayProvenanceLog;
use Atlas\Pca\GatewayReplayGuard;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** A replay guard that records every claim the gateway makes and admits it. */
final class Kill9GwGuard
{
    /** @var list<array{0:string,1:mixed,2:mixed}> */
    public array $calls = [];

    public function claim(string $key, mixed $exp, mixed $now): bool
    {
        $this->calls[] = [$key, $exp, $now];
        return true;
    }
}

/** A provenance log double: the session keys the gateway reads and writes. */
final class Kill9GwLog
{
    /** @var list<string> */
    public array $seen = [];
    /** @var list<string> */
    public array $added = [];

    public function seen(string $k): array
    {
        $this->seen[] = $k;
        return [];
    }

    public function add(string $k, mixed $o): void
    {
        $this->added[] = $k;
    }
}

/** Behaviour kills for src/Gateway.php: replay guard, provenance log, request binding, the decision pipeline, full policy and the adapters. */
final class EdgeSurvivorKill9GatewayTest extends TestCase
{
    private const AUD = 'https://api.example';
    private const NOW = 1700000000000;
    private const CAP = ['verb' => 'read', 'resource' => 'docs/1'];
    private const LACKS = 'request lacks an attribute the proof must bind (authority / body hash)';
    private const REVOKED = 'revocation: the grant is revoked';

    private static ?Obj $grant = null;

    private static function kp(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/kill9-gw-' . $label, true));
    }

    private static function grant(): Obj
    {
        return self::$grant ??= Sign::mintGrant(self::kp('principal'), self::kp('agent')->public,
            ['predicates' => [['verb' => 'read', 'resource' => 'docs/1']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()],
            'read the document', 'c2FsdA')['grant'];
    }

    private static function gid(): string
    {
        return self::grant()->get('id');
    }

    /** A signed read of docs/1 whose action params are `$params` (one-node plan). */
    private static function proof(mixed $params, int $iat = self::NOW - 1000, ?string $rc = null, string $aud = self::AUD): Obj
    {
        $node = ['id' => 'n1', 'verb' => 'read', 'resource' => 'docs/1', 'params_digest' => Pca::paramsDigest(Sign::n($params))];
        if ($rc !== null) {
            $node['reversibility_class'] = $rc;
        }
        return Sign::buildPcactn(self::grant(), [self::grant()], [$node], 'n1', 1, self::kp('agent'), $aud, $params, $iat, $iat + 60000);
    }

    private static function hdr(Obj $p): string
    {
        return Sign::headers($p)['PCA-Action'];
    }

    private static function req(Obj $p, array $over = []): array
    {
        return array_merge(['method' => 'GET', 'path' => '/docs/1', 'query' => '', 'headers' => ['PCA-Action' => self::hdr($p)]], $over);
    }

    private static function bound(array $over = [], mixed $bind = null): Obj
    {
        return Gateway::requestBinding(array_merge(['method' => 'GET', 'path' => '/docs/1', 'query' => ''], $over), $bind);
    }

    private static function sig(array $over = []): array
    {
        $g = self::grant();
        return array_merge([
            'audience' => self::AUD,
            'routes' => [['method' => 'GET', 'path' => '/docs/*', 'capability' => self::CAP]],
            'resolveGrant' => static fn($ref, $p = null) => $ref === $g->get('id') ? $g : null,
            'insecureSkipPlanRootCheck' => true,
            'now' => static fn() => self::NOW,
            'policy' => ['mode' => 'signature-only'],
            'replayGuard' => Gateway::memoryReplayGuard(1000, static fn() => self::NOW),
            'hooks' => ['revocation' => static fn($c) => ['enforced' => true, 'ok' => true]],
        ], $over);
    }

    /** Full-policy options: params from the body, a revoked grant (a deterministic deny), the request binding off unless overridden. */
    private static function full(array $policy = [], array $over = []): array
    {
        $o = self::sig(array_merge(['policy' => array_merge(['mode' => 'full', 'params' => 'body', 'state' => new MemoryStateStore(),
            'isRevoked' => static fn($p = null, $g = null) => true], $policy), 'bindRequest' => false], $over));
        unset($o['replayGuard'], $o['hooks']);
        return $o;
    }

    private static function body(string $json = '{"a":1}'): Obj
    {
        return Json::parseStrict($json);
    }

    private static function fullReq(Obj $p, string $body = '{"a":1}', array $over = []): array
    {
        return self::req($p, array_merge(['body' => $body], $over));
    }

    private static function logKey(?Obj $bundle = null): string
    {
        return self::gid() . "\n" . self::kp('agent')->public . "\n" . ($bundle === null ? '-' : (ArgProvenance::bundleSession($bundle) ?? '-'));
    }

    /** Run $fn with the gateway wall clock pinned to $seconds (epoch seconds, as microtime(true)). */
    private static function atClock(float $seconds, callable $fn): mixed
    {
        Gateway::$clockHook = static fn(): float => $seconds;
        try {
            return $fn();
        } finally {
            Gateway::$clockHook = null;
        }
    }

    /** @return list<string> the messages of every PHP error raised by `$fn` */
    private static function errorsOf(callable $fn): array
    {
        $errs = [];
        set_error_handler(static function (int $no, string $msg) use (&$errs): bool {
            $errs[] = $msg;
            return true;
        });
        try {
            $fn();
        } finally {
            restore_error_handler();
        }
        return $errs;
    }

    private static function refuses(string $class, string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            self::assertInstanceOf($class, $e, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("no exception: $msg");
    }

    private static function deny(array $d, string $code, int $status, string $reason): void
    {
        self::assertSame([false, $code, $status, $reason], [$d['allow'], $d['code'], $d['status'], $d['reason']]);
    }

    // ---- replay guard --------------------------------------------------------------------------------------------------------

    /** The default capacity holds exactly 100000 live claims, for the constructor and the factory alike. */
    public function testDefaultReplayCapacityIsExactly100000(): void
    {
        foreach ([new GatewayReplayGuard(), Gateway::memoryReplayGuard()] as $g) {
            for ($i = 0; $i < 100000; $i++) {
                if (!$g->claim("k$i", 10, 0)) {
                    self::fail("claim $i was refused");
                }
            }
            try {
                $g->claim('one-more', 10, 0);
                self::fail('the 100001st live claim was accepted');
            } catch (\RuntimeException $e) {
                self::assertSame('replay guard full', $e->getMessage());
            }
        }
    }

    /** The default clock is the wall clock in whole milliseconds, floored: a claim is live through its expiry millisecond. */
    public function testDefaultReplayClockIsFlooredWallMilliseconds(): void
    {
        foreach ([new GatewayReplayGuard(), Gateway::memoryReplayGuard()] as $g) {
            self::atClock(1700000000.1237, static function () use ($g): void {
                self::assertTrue($g->claim('live', 1700000000123));
                self::assertFalse($g->claim('live', 1700000000123), 'a claim is live through its expiry millisecond');
                self::assertTrue($g->claim('old', 1700000000122));
                self::assertTrue($g->claim('old', 1700000000122), 'a claim that expired a millisecond ago is claimable again');
            });
        }
    }

    // ---- provenance log ------------------------------------------------------------------------------------------------------

    /** The default log keeps exactly 10000 sessions, dropping the oldest first. */
    public function testDefaultProvenanceLogKeeps10000Sessions(): void
    {
        foreach ([new GatewayProvenanceLog(), Gateway::memoryProvenanceLog()] as $log) {
            for ($i = 0; $i <= 10000; $i++) {
                $log->add("s$i", Obj::of(['origin' => 'tool', 'source' => 'v']));
            }
            self::assertSame([], $log->seen('s0'));
            self::assertCount(1, $log->seen('s1'));
            self::assertCount(1, $log->seen('s10000'));
        }
    }

    /** Duplicate observations compare like JavaScript ===: numbers by value, booleans by value, objects and lists by identity. */
    public function testObservationDedupeIsStrictEquality(): void
    {
        $count = static function (array $origins): int {
            $log = new GatewayProvenanceLog();
            foreach ($origins as $o) {
                $log->add('s', Obj::of(['origin' => $o]));
            }
            return count($log->seen('s'));
        };
        $shared = Obj::of(['k' => 'v']);
        self::assertSame(1, $count([new Num('1'), new Num('1')]), 'equal numbers are one observation');
        self::assertSame(1, $count([true, true]), 'equal booleans are one observation');
        self::assertSame(2, $count([true, false]));
        self::assertSame(2, $count([new Num('0'), null]), 'zero is not null');
        self::assertSame(2, $count([[1], [1]]), 'a list is its own identity');
        self::assertSame(1, $count([$shared, $shared]), 'the same object is one observation');
        self::assertSame(2, $count([$shared, Obj::of(['k' => 'v'])]), 'an equal but distinct object is another');
        self::assertSame(1, $count(['x', 'x']));
    }

    // ---- small helpers -------------------------------------------------------------------------------------------------------

    /** Header lookup is public, case-insensitive and reads an integer-like name of an assoc array. */
    public function testGetHeaderReadsIntegerLikeNames(): void
    {
        self::assertSame('v', Gateway::getHeader([7 => 'v'], '7'));
        self::assertSame('a', Gateway::getHeader(['X-Y' => ['a', 'b']], 'x-y'));
    }

    /** A non-string method is refused with the gateway's own message. */
    public function testNonStringMethodRefused(): void
    {
        self::refuses(\TypeError::class, 'method is not a string', static fn() => Gateway::requestBinding(['method' => 5, 'path' => '/']));
    }

    /** Percent escapes decode from their two hex digits only (no PHP conversion notice), in query names and path checks. */
    public function testPercentEscapesDecodeWithoutNotices(): void
    {
        $out = [];
        $errs = self::errorsOf(static function () use (&$out): void {
            $out[] = Gateway::canonicalQuery('%41=1&b=2');
            try {
                Gateway::canonicalQuery('%41=1&a=2');
            } catch (\InvalidArgumentException $e) {
                $out[] = $e->getMessage();
            }
            $out[] = Gateway::ambiguousPathReason('/x%41');
            $out[] = Gateway::ambiguousPathReason('/x%2F');
        });
        self::assertSame([], $errs);
        self::assertSame(['%41=1&b=2', "duplicate query parameter 'a'", 'non-canonical percent-encoding in path', 'percent-encoded slash in path'], $out);
    }

    // ---- configuration -------------------------------------------------------------------------------------------------------

    /** Signature-only mode names every missing component. */
    public function testSignatureOnlyNamesAllMissingComponents(): void
    {
        $o = self::sig();
        unset($o['replayGuard'], $o['hooks']);
        self::refuses(\TypeError::class, "pca-gateway: the gateway is missing replayGuard (signature-only mode needs a single-use guard), hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)",
            static fn() => Gateway::createGateway($o));
    }

    /** Full policy mode names a missing audience, resolveGrant, budget claim and params source; a params function is accepted. */
    public function testFullPolicyMissingComponents(): void
    {
        $o = self::full();
        unset($o['audience']);
        self::refuses(\TypeError::class, 'pca-gateway: full policy mode is missing audience', static fn() => Gateway::createGateway($o));
        $o = self::full([], ['audience' => '']);
        self::refuses(\TypeError::class, 'pca-gateway: full policy mode is missing audience', static fn() => Gateway::createGateway($o));
        $o = self::full();
        unset($o['resolveGrant']);
        self::refuses(\TypeError::class, 'pca-gateway: full policy mode is missing resolveGrant', static fn() => Gateway::createGateway($o));
        $claimOnly = new class {
            public function claim(string $k, int $n): bool
            {
                return true;
            }

            public function budget(string $k): ?array
            {
                return null;
            }
        };
        self::refuses(\TypeError::class, 'pca-gateway: full policy mode is missing state.claimWithBudget (the trust budget is decided and debited with the replay claim)',
            static fn() => Gateway::createGateway(self::full(['state' => $claimOnly])));
        self::refuses(\TypeError::class, "pca-gateway: full policy mode is missing params ('body' or a function)",
            static fn() => Gateway::createGateway(self::full(['params' => null])));
        self::assertInstanceOf(\Closure::class, Gateway::createGateway(self::full(['params' => static fn($r) => new Obj()])));
    }

    /** Hooks and enforcement gates the port cannot run are refused by name; freshness alone is accepted. */
    public function testUnsupportedHooksAndGatesRefused(): void
    {
        self::refuses(\InvalidArgumentException::class, 'pca-gateway: hooks attestation, zk are not supported by this port',
            static fn() => Gateway::createGateway(self::sig(['hooks' => ['revocation' => static fn($c) => null, 'attestation' => static fn($c) => null, 'zk' => static fn($c) => null]])));
        self::refuses(\InvalidArgumentException::class, 'pca-gateway: the taint enforcement gate is not supported by this port',
            static fn() => Gateway::createGateway(self::sig(['enforce' => ['freshness' => [], 'taint' => []]])));
        self::assertInstanceOf(\Closure::class, Gateway::createGateway(self::sig(['enforce' => ['freshness' => []]])));
    }

    /** A non-array enforce.freshness refuses the request with the gateway's own error. */
    public function testFreshnessMustBeAnArray(): void
    {
        $gw = Gateway::createGateway(self::sig(['enforce' => ['freshness' => 'x']]));
        $r = self::req(self::proof(self::bound()));
        self::refuses(\InvalidArgumentException::class, 'pca-gateway: enforce.freshness must be an array', static fn() => $gw($r));
    }

    /** A clock that returns no number refuses the request. */
    public function testClockMustReturnANumber(): void
    {
        $gw = Gateway::createGateway(self::sig(['now' => static fn() => 'soon']));
        $r = self::req(self::proof(self::bound()));
        self::refuses(\TypeError::class, 'the clock did not return a number', static fn() => $gw($r));
    }

    // ---- authorize: signature-only -------------------------------------------------------------------------------------------

    /** A bound, verified proof is allowed with the verdict headers; the guard claims grant_ref:sig at the gateway clock. */
    public function testSignatureOnlyAllow(): void
    {
        $guard = new Kill9GwGuard();
        $p = self::proof(self::bound());
        $d = Gateway::createGateway(self::sig(['replayGuard' => $guard]))(self::req($p));
        self::assertTrue($d['allow'], $d['reason']);
        self::assertSame(['allow', 200, 'proof-carrying action verified', self::CAP], [$d['code'], $d['status'], $d['reason'], $d['matched']]);
        self::assertCount(1, $guard->calls);
        self::assertSame([self::gid() . ':' . $p->get('sig'), self::NOW], [$guard->calls[0][0], $guard->calls[0][2]]);
        $c = $d['verdict']['checks'];
        self::assertSame(['pass', 'pass', 'pass', 'not-enforced', 'not-enforced', 'not-enforced'],
            [$c->get('revocation'), $c->get('cap_chain'), $c->get('leaf_signature'), $c->get('plan_root_authorized'), $c->get('attestation'), $c->get('threshold')]);
        $h = $d['headers'];
        self::assertSame([Js::stringify($d['verdict']), 'read', self::gid()], [$h->get('x-pca-verdict'), $h->get('x-pca-verb'), $h->get('x-pca-grant')]);
        $d2 = Gateway::authorize(self::req($p), self::sig(['requireChecks' => ['plan_root_authorized']]));
        self::deny($d2, 'proof-rejected', 403, "required check 'plan_root_authorized' is not-enforced");
    }

    /** A fractional clock is floored to the millisecond the guard and the verifier see. */
    public function testFractionalClockIsFloored(): void
    {
        $guard = new Kill9GwGuard();
        $d = Gateway::createGateway(self::sig(['replayGuard' => $guard, 'now' => static fn() => self::NOW + 0.6]))(self::req(self::proof(self::bound())));
        self::assertTrue($d['allow'], $d['reason']);
        self::assertSame(self::NOW, $guard->calls[0][2]);
    }

    /** With no clock option the gateway reads the wall clock in whole, floored milliseconds. */
    public function testDefaultClockIsFlooredWallMilliseconds(): void
    {
        $guard = new Kill9GwGuard();
        $o = self::sig(['replayGuard' => $guard]);
        unset($o['now']);
        $d = self::atClock((self::NOW + 0.6) / 1000, static fn() => Gateway::authorize(self::req(self::proof(self::bound())), $o));
        self::assertTrue($d['allow'], $d['reason']);
        self::assertSame(self::NOW, $guard->calls[0][2]);
    }

    /** An undecodable, non-string PCA-Action header is reported as empty. */
    public function testNonStringHeaderIsEmpty(): void
    {
        $d = Gateway::createGateway(self::sig())(['method' => 'GET', 'path' => '/docs/1', 'headers' => ['PCA-Action' => 5]]);
        self::deny($d, 'invalid-proof', 401, 'undecodable PCA-Action header: PCA-Action header is empty');
    }

    /** A trailing-star route matches its literal prefix only. */
    public function testStarRouteMatchesItsPrefix(): void
    {
        $o = ['audience' => self::AUD, 'routes' => [['path' => '/do*', 'capability' => self::CAP]]];
        self::assertSame('unmapped-route', Gateway::authorize(['method' => 'GET', 'path' => '/dx', 'headers' => []], $o)['code']);
        self::assertSame('no-proof', Gateway::authorize(['method' => 'GET', 'path' => '/dox', 'headers' => []], $o)['code']);
    }

    /** With no realm and a non-string audience the challenge realm is String(audience). */
    public function testRealmOfANonStringAudience(): void
    {
        $d = Gateway::authorize(['method' => 'GET', 'path' => '/x', 'headers' => []], ['routes' => []]);
        self::assertSame('PCA realm="null", error="access_denied"', $d['headers']->get('www-authenticate'));
    }

    /** A gateway with no resolveGrant function refuses the request. */
    public function testResolveGrantMustBeAFunction(): void
    {
        $o = self::sig();
        unset($o['resolveGrant']);
        $r = self::req(self::proof(self::bound()));
        self::refuses(\TypeError::class, 'pca-gateway: resolveGrant is not a function', static fn() => Gateway::authorize($r, $o));
    }

    /** A configuration with no policy denies every request (fail closed), naming what is missing. */
    public function testMissingPolicyDenies(): void
    {
        $o = self::sig();
        unset($o['policy']);
        $d = Gateway::authorize(self::req(self::proof(self::bound())), $o);
        self::deny($d, 'proof-rejected', 403, "the gateway is missing policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' }) (fail closed)");
        self::assertSame(self::gid(), $d['pcactn']->get('grant_ref'));
    }

    /** The revocation hook receives the PCActn; a refusal or a throw names itself unless verification already failed. */
    public function testRevocationHookReasons(): void
    {
        $p = self::proof(self::bound());
        $sig = $p->get('sig');
        $sees = Gateway::createGateway(self::sig(['hooks' => ['revocation' => static fn($c) => ['enforced' => true,
            'ok' => $c->get('pcactn') instanceof Obj && $c->get('pcactn')->get('sig') === $sig]]]))(self::req($p));
        self::assertTrue($sees['allow'], $sees['reason']);

        $revoked = ['revocation' => static fn($c) => ['enforced' => true, 'ok' => false, 'reason' => 'grant revoked']];
        $throws = ['revocation' => static function ($c) {
            throw new \RuntimeException('rev down');
        }];
        $other = self::proof(self::bound(), self::NOW - 1000, null, 'https://other.example');
        $audience = 'audience: aud does not match this resource server / instance';
        self::deny(Gateway::createGateway(self::sig(['hooks' => $revoked]))(self::req($p)), 'verify-failed', 401, 'revocation: grant revoked');
        self::deny(Gateway::createGateway(self::sig(['hooks' => $revoked]))(self::req($other)), 'wrong-audience', 403, $audience);
        self::deny(Gateway::createGateway(self::sig(['hooks' => $throws]))(self::req($p)), 'verify-failed', 401, 'malformed PCActn: rev down');
        self::deny(Gateway::createGateway(self::sig(['hooks' => $throws]))(self::req($other)), 'wrong-audience', 403, $audience);
    }

    /** checkProof sees the PCActn, and the route's capability only when a route matched. */
    public function testCheckProofContext(): void
    {
        $seen = [];
        $cp = static function (array $c) use (&$seen): bool {
            $seen[] = [$c['pcactn'] instanceof Obj, array_key_exists('required', $c), $c['required'] ?? null];
            return true;
        };
        $p = self::proof(self::bound());
        self::assertTrue(Gateway::createGateway(self::sig(['checkProof' => $cp]))(self::req($p))['allow']);
        $d = Gateway::createGateway(self::sig(['checkProof' => $cp, 'routes' => [], 'unmatchedRoute' => 'verify']))(self::req(self::proof(self::bound())));
        self::assertTrue($d['allow'], $d['reason']);
        self::assertSame([[true, true, self::CAP], [true, false, null]], $seen);
    }

    // ---- authorize: full policy ----------------------------------------------------------------------------------------------

    /** Full policy runs the core pipeline (here: a revoked grant), reports its verdict, reads the session log and never writes it on a deny. */
    public function testFullPolicyDenyReport(): void
    {
        $rec = new Kill9GwLog();
        $d = Gateway::createGateway(self::full(['provenanceLog' => $rec]))(self::fullReq(self::proof(self::body())));
        self::deny($d, 'proof-rejected', 403, self::REVOKED);
        self::assertTrue($d['verdict']['allow']);
        $pv = $d['policyVerdict'];
        self::assertSame([false, self::REVOKED], [$pv->get('allow'), $pv->get('reason')]);
        $checks = $pv->get('checks');
        self::assertSame(['fail', 'pass', false], [$checks->get('revocation'), $checks->get('operation'), $checks->has('principal')]);
        self::assertSame([self::logKey()], $rec->seen);
        self::assertSame([], $rec->added);
        // no session log: the deny path never touches one
        $off = Gateway::createGateway(self::full(['provenanceLog' => false]))(self::fullReq(self::proof(self::body())));
        self::deny($off, 'proof-rejected', 403, self::REVOKED);
    }

    /** The operation priced by the pipeline takes the route's verb, its resource when the route names one, else the proof's own. */
    public function testFullPolicyOperationFromRouteOrProof(): void
    {
        $p = self::proof(self::body());
        $verbOnly = self::full([], ['routes' => [['method' => 'GET', 'path' => '/docs/*', 'capability' => ['verb' => 'read']]]]);
        self::deny(Gateway::createGateway($verbOnly)(self::fullReq($p)), 'proof-rejected', 403, self::REVOKED);
        $unmapped = self::full([], ['routes' => [], 'unmatchedRoute' => 'verify']);
        self::deny(Gateway::createGateway($unmapped)(self::fullReq($p)), 'proof-rejected', 403, self::REVOKED);
    }

    /** The core pipeline's 401 maps to verify-failed (here: a suite allowlist without Ed25519). */
    public function testFullPolicyAuthnFailureIsVerifyFailed(): void
    {
        $d = Gateway::createGateway(self::full(['allowedSuites' => ['ml-dsa-65']]))(self::fullReq(self::proof(self::body())));
        self::assertSame([false, 'verify-failed', 401], [$d['allow'], $d['code'], $d['status']]);
    }

    /** A pipeline that cannot even be called is a fail-closed proof-rejected deny naming the error. */
    public function testFullPolicyCallFailureFailsClosed(): void
    {
        $d = Gateway::createGateway(self::full(['allowedSuites' => 'ed25519']))(self::fullReq(self::proof(self::body())));
        self::assertSame([false, 'proof-rejected', 403], [$d['allow'], $d['code'], $d['status']]);
        self::assertStringStartsWith('full policy failed: ', $d['reason']);
        self::assertStringEndsWith(' (fail closed)', $d['reason']);
        self::assertStringContainsString('allowedSuites', $d['reason']);
        self::assertTrue($d['verdict']['allow']);
    }

    /** A k1 input that throws fails closed with its message; a k1 value that is not a function is used as given. */
    public function testK1Input(): void
    {
        $d = Gateway::createGateway(self::full(['k1' => static function ($r, $p) {
            throw new \RuntimeException('k1 boom');
        }]))(self::fullReq(self::proof(self::body())));
        self::deny($d, 'proof-rejected', 403, 'k1 input failed: k1 boom (fail closed)');
        self::assertTrue($d['verdict']['allow']);
        $v = Gateway::createGateway(self::full(['k1' => Obj::of(['x' => 1])]))(self::fullReq(self::proof(self::body())));
        self::assertFalse($v['allow']);
        self::assertStringStartsNotWith('k1 input failed', $v['reason']);
    }

    /** Extra required checks (a list or one name) join the defaults; requireVerifiedPrincipal is forwarded. */
    public function testRequireAndPrincipalForwarded(): void
    {
        foreach ([['kill9_custom'], 'kill9_custom'] as $req) {
            $d = Gateway::createGateway(self::full(['require' => $req]))(self::fullReq(self::proof(self::body())));
            self::assertSame('fail', $d['policyVerdict']->get('checks')->get('kill9_custom'));
        }
        $d = Gateway::createGateway(self::full(['requireVerifiedPrincipal' => true]))(self::fullReq(self::proof(self::body())));
        self::assertSame('fail', $d['policyVerdict']->get('checks')->get('principal'));
    }

    /** A host risk function is called with the grant and the rebuilt params; without one the amount pricing runs to the same effect. */
    public function testRiskFunctionForwarded(): void
    {
        $calls = [];
        $risk = static function (mixed $g, mixed $params, mixed $pc) use (&$calls): array {
            $calls[] = [$g->get('id'), Js::stringify($params), $pc->get('sig')];
            return [];
        };
        $p = self::proof(self::body());
        $with = Gateway::createGateway(self::full(['risk' => $risk]))(self::fullReq($p));
        self::assertSame([[self::gid(), '{"a":1}', $p->get('sig')]], $calls);
        $without = Gateway::createGateway(self::full())(self::fullReq($p));
        self::assertSame($with['policyVerdict']->get('checks')->get('policy'), $without['policyVerdict']->get('checks')->get('policy'));
    }

    /** isPlanAuthorized decides the plan root from the signed node (id, verb, resource, digest, class). */
    public function testIsPlanAuthorizedContext(): void
    {
        $p = self::proof(self::body(), self::NOW - 1000, 'irreversible');
        foreach ([true, false] as $answer) {
            $calls = [];
            $isPlan = static function ($ref, $root) use (&$calls, $answer): bool {
                $calls[] = [$ref, $root];
                return $answer;
            };
            $d = Gateway::createGateway(self::full(['isPlanAuthorized' => $isPlan]))(self::fullReq($p));
            self::assertSame([[self::gid(), $p->get('plan')->get('root')]], $calls);
            self::assertSame($answer ? 'pass' : 'fail', $d['policyVerdict']->get('checks')->get('plan_root_authorized'));
        }
    }

    /** The session key is grant, leaf holder and the first receipt's session; the configured log wins over the gateway's own. */
    public function testProvenanceSessionKeyAndObservers(): void
    {
        $p = self::proof(self::body());
        $bundle = Obj::of(['receipts' => [Obj::of(['session' => 'sess-1'])]]);
        $withBundle = self::fullReq($p);
        $withBundle['headers']['pca-provenance'] = Pca::b64u(Json::canonicalizeNative($bundle));
        $rec = new Kill9GwLog();
        Gateway::createGateway(self::full(['provenanceLog' => $rec]))($withBundle);
        self::assertSame([self::gid() . "\n" . self::kp('agent')->public . "\nsess-1"], $rec->seen);

        $odd = self::fullReq($p);
        $odd['headers']['pca-provenance'] = Pca::b64u(Json::canonicalizeNative(Obj::of(['receipts' => ['not-an-object']])));
        $rec = new Kill9GwLog();
        Gateway::createGateway(self::full(['provenanceLog' => $rec]))($odd);
        self::assertSame([self::logKey()], $rec->seen);

        // a host observer and the log are both consulted, the observer first
        $order = [];
        $log = new class($order) {
            public function __construct(private array &$o)
            {
            }

            public function seen(string $k): array
            {
                $this->o[] = 'log';
                return [];
            }

            public function add(string $k, mixed $o): void
            {
            }
        };
        $user = static function (mixed ...$a) use (&$order): ?array {
            $order[] = 'user';
            return null;
        };
        Gateway::createGateway(self::full(['provenanceLog' => $log, 'provenance' => ['observed' => $user]]))(self::fullReq($p));
        self::assertSame(['user', 'log'], $order);
        $order = [];
        Gateway::createGateway(self::full(['provenanceLog' => false, 'provenance' => ['observed' => $user]]))(self::fullReq($p));
        self::assertSame(['user'], $order);
    }

    /** The session log only feeds the gate when configured or defaulted; false turns it off (provenance gate over a pinned bundle). */
    public function testProvenanceLogSelection(): void
    {
        $op = ['verb' => 'read', 'resource' => 'docs/1', 'params' => self::body()];
        $bundle = ProvHarness::bundle($op);
        self::assertInstanceOf(Obj::class, $bundle);
        $p = self::proof(self::body());
        $r = self::fullReq($p);
        $r['headers'] = Sign::headers($p, [], null, null, $bundle);
        $key = self::logKey($bundle);
        $poisoned = static function (string $at): GatewayProvenanceLog {
            $l = new GatewayProvenanceLog();
            $l->add($at, Obj::of(['origin' => INF, 'source' => 'x']));
            return $l;
        };
        $flow = static function (array $policy, ?GatewayProvenanceLog $default = null) use ($r): mixed {
            $o = self::full(array_merge(['provenance' => ['mediators' => [ProvHarness::pin()]]], $policy));
            return Gateway::authorize($r, $o, $default)['policyVerdict']->get('checks')->get('provenance_flow');
        };
        self::assertSame('pass', $flow(['provenanceLog' => $poisoned($key . 'x')]), 'a clean session passes the gate');
        self::assertSame('fail', $flow(['provenanceLog' => $poisoned($key)]), 'the configured log is read at the session key');
        self::assertSame('fail', $flow(['provenanceLog' => $poisoned($key)], $poisoned($key . 'x')), 'the configured log wins over the default');
        self::assertSame('fail', $flow([], $poisoned($key)), 'without one the default log is read');
        self::assertSame('pass', $flow(['provenanceLog' => false], $poisoned($key)), 'false turns the log off');
    }

    /** The params the agent signed are rebuilt from the body and refused with exact reasons when they cannot be. */
    public function testSignedParamsRefusals(): void
    {
        $p = self::proof(self::body());
        $gw = Gateway::createGateway(self::full());
        $mismatch = static function (array $d, string $why): void {
            self::deny($d, 'request-mismatch', 403, $why);
            self::assertTrue($d['verdict']['allow']);
        };
        $mismatch($gw(self::req($p)), 'full policy mode reads the params from the body, and the request carries none');
        try {
            Json::parseStrict('{bad');
            self::fail('{bad parsed');
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
        }
        $mismatch($gw(self::fullReq($p, '{bad')), 'the body is not strict JSON: ' . $msg);
        $mismatch($gw(self::fullReq($p, '[1]')), 'the request params are not a JSON object');
        $mismatch($gw(self::fullReq($p, '{"a":2}')), 'the proof is not bound to this request (params/method/path/query/authority)');

        $bindOn = Gateway::createGateway(self::full([], ['bindRequest' => null]));
        $mismatch($bindOn(self::fullReq($p, '{"binding":1}')), "the request params carry a 'binding' member (reserved for the request binding)");
        $mismatch($bindOn(self::fullReq($p, '{"a":1}', ['query' => 'a=1;b=2'])), "the request cannot be bound: query contains ';' (parsers disagree on it as a separator)");
        $mismatch(Gateway::createGateway(self::full([], ['bindRequest' => ['authority' => true]]))(self::fullReq($p)), self::LACKS);
        $mismatch(Gateway::createGateway(self::full([], ['bindRequest' => ['body' => true]]))(self::fullReq($p)), self::LACKS);
    }

    /** The rebuilt params carry the request binding: authority and body hash only when asked for; a params function is modelled. */
    public function testSignedParamsBinding(): void
    {
        // default binding: method, path and query only, even when the request has an authority and a body hash
        $params = self::body();
        $params->set('binding', self::bound([], ['body' => false]));
        $d = Gateway::createGateway(self::full([], ['bindRequest' => null]))(self::fullReq(self::proof($params), '{"a":1}', ['authority' => 'api.example', 'bodySha256' => 'abcd']));
        self::deny($d, 'proof-rejected', 403, self::REVOKED);

        // both asked for: the authority (lower-cased) and the body hash join the binding
        $both = ['authority' => true, 'body' => true];
        $params = self::body();
        $params->set('binding', self::bound(['authority' => 'API.example', 'bodySha256' => 'ABCD'], $both));
        $d = Gateway::createGateway(self::full([], ['bindRequest' => $both]))(self::fullReq(self::proof($params), '{"a":1}', ['authority' => 'API.example', 'bodySha256' => 'ABCD']));
        self::deny($d, 'proof-rejected', 403, self::REVOKED);

        // a params function: an assoc array is modelled, an Obj is used, a list is refused
        $p = self::proof(self::body());
        $fn = static fn(mixed $ret): array => self::full(['params' => static fn($r) => $ret]);
        self::deny(Gateway::createGateway($fn(['a' => 2]))(self::req($p)), 'request-mismatch', 403, 'the proof is not bound to this request (params/method/path/query/authority)');
        self::deny(Gateway::createGateway($fn([1, 2]))(self::req($p)), 'request-mismatch', 403, 'the request params are not a JSON object');
        self::deny(Gateway::createGateway($fn(self::body()))(self::req($p)), 'proof-rejected', 403, self::REVOKED);
    }

    // ---- adapters ------------------------------------------------------------------------------------------------------------

    /** The proxy forwards an allowed request with client x-pca-* headers replaced by the verdict's; a deny never reaches the upstream. */
    public function testGatewayProxy(): void
    {
        $got = [];
        $up = static function (mixed $r, array $d) use (&$got): string {
            $got[] = $r;
            return 'upstream';
        };
        $proxy = Gateway::gatewayProxy(self::sig(), $up);
        $p = self::proof(self::bound());
        $r = self::req($p);
        $r['headers'] += ['X-PCA-Verdict' => 'forged', 'X-Other' => 'kept'];
        self::assertSame('upstream', $proxy($r));
        $want = ['PCA-Action', 'X-Other', 'x-pca-verdict', 'x-pca-verb', 'x-pca-grant'];
        self::assertSame(['GET', '/docs/1'], [$got[0]['method'], $got[0]['path']]);
        self::assertSame($want, $got[0]['headers']->keys());
        self::assertSame(['kept', 'read'], [$got[0]['headers']->get('X-Other'), $got[0]['headers']->get('x-pca-verb')]);

        $proxy2 = Gateway::gatewayProxy(self::sig(), $up);
        $o = Obj::of(['method' => 'GET', 'path' => '/docs/1', 'query' => '', 'headers' => Obj::of($r['headers'])]);
        self::assertSame('upstream', $proxy2($o));
        self::assertInstanceOf(Obj::class, $got[1]);
        self::assertSame(['method', 'path', 'query', 'headers'], $got[1]->keys());
        self::assertSame('GET', $got[1]->get('method'));
        self::assertSame($want, $got[1]->get('headers')->keys());

        $res = $proxy(['method' => 'GET', 'path' => '/docs/1', 'headers' => []]);
        self::assertCount(2, $got);
        self::assertSame([401, '{"error":"no-proof","reason":"no PCA-Action header"}'], [$res['status'], $res['body']]);
        self::assertSame(['content-type', 'www-authenticate'], $res['headers']->keys());
    }

    /** The Worker parses relative and absolute URLs (authority bound), strips forged headers from an array request, and passes no body in signature-only mode. */
    public function testCloudflareWorker(): void
    {
        $nexts = [];
        $next = static function (mixed $r) use (&$nexts): string {
            $nexts[] = $r;
            return 'next';
        };
        $resps = [];
        $respond = static function (string $body, array $init) use (&$resps): string {
            $resps[] = [$body, $init['status']];
            return 'respond';
        };
        $hasBody = [];
        $cp = static function (array $c) use (&$hasBody): bool {
            $hasBody[] = $c['request']->has('body');
            return true;
        };
        $p = self::proof(self::bound());
        $w = Gateway::cloudflareWorker(self::sig(['checkProof' => $cp]), $next, $respond);
        self::assertSame('next', $w(['method' => 'GET', 'url' => '/docs/1', 'headers' => ['PCA-Action' => self::hdr($p)]]));
        self::assertSame('next', $w(['method' => 'GET', 'url' => '/docs/1', 'headers' => ['PCA-Action' => self::hdr(self::proof(self::bound(), self::NOW - 1001))], 'body' => 'xyz']));
        self::assertSame([false, false], $hasBody);

        $bind = ['authority' => true];
        $pa = self::proof(self::bound(['authority' => 'api.example'], $bind));
        $wa = Gateway::cloudflareWorker(self::sig(['bindRequest' => $bind]), $next, $respond);
        self::assertSame('next', $wa(['method' => 'GET', 'url' => 'https://api.example/docs/1', 'headers' => ['PCA-Action' => self::hdr($pa)]]));

        $forged = ['method' => 'GET', 'url' => '/docs/1', 'headers' => ['PCA-Action' => self::hdr(self::proof(self::bound())), 'X-PCA-Grant' => 'forged', 'Accept' => '*/*']];
        self::assertSame('next', Gateway::cloudflareWorker(self::sig(), $next, $respond)($forged));
        $clean = $nexts[count($nexts) - 1];
        self::assertSame(['GET', '/docs/1'], [$clean['method'], $clean['url']]);
        self::assertSame(['PCA-Action', 'Accept'], $clean['headers']->keys());
        self::assertSame([], $resps);
    }

    /** A full-policy Worker with params from the body forwards the body; with a params function it never does. */
    public function testCloudflareWorkerFullPolicyBody(): void
    {
        $resps = [];
        $respond = static function (string $body, array $init) use (&$resps): string {
            $resps[] = [$body, $init['status']];
            return 'respond';
        };
        $next = static fn(mixed $r): string => 'next';
        $p = self::proof(self::body());
        $w = Gateway::cloudflareWorker(self::full(), $next, $respond);
        self::assertSame('respond', $w(['method' => 'GET', 'url' => '/docs/1', 'headers' => ['PCA-Action' => self::hdr($p)], 'body' => '{"a":1}']));
        self::assertSame([['{"error":"proof-rejected","reason":"revocation: the grant is revoked"}', 403]], $resps);

        $bodies = [];
        $fn = static function (mixed $r) use (&$bodies): Obj {
            $bodies[] = [Js::has($r, 'body'), Js::opt($r, 'body')];
            return Json::parseStrict('{"a":1}');
        };
        Gateway::cloudflareWorker(self::full(['params' => $fn]), $next, $respond)(['method' => 'GET', 'url' => '/docs/1', 'headers' => ['PCA-Action' => self::hdr($p)], 'body' => '{"a":1}']);
        self::assertSame([[false, null]], $bodies);
    }

    /** Envoy HTTP: the query stops at the fragment and drops one leading '?', the :authority and the body reach the gateway. */
    public function testEnvoyRequestShape(): void
    {
        $ok = static function (array $over, array $check, array $opts = []): array {
            return Gateway::envoyExtAuthz(self::sig($opts))($check + ['headers' => ['PCA-Action' => self::hdr(self::proof(self::bound($over, $opts['bindRequest'] ?? null)))]]);
        };
        self::assertSame(200, $ok(['query' => 'a=1'], ['method' => 'GET', 'path' => '/docs/1?a=1#frag'])['status']);
        self::assertSame(200, $ok(['query' => 'x=1'], ['method' => 'GET', 'path' => '/docs/1??x=1'])['status']);
        $bind = ['authority' => true];
        $p = self::proof(self::bound(['authority' => 'api.example'], $bind));
        $res = Gateway::envoyExtAuthz(self::sig(['bindRequest' => $bind]))(['method' => 'GET', 'path' => '/docs/1',
            'headers' => [':authority' => 'api.example', 'PCA-Action' => self::hdr($p)]]);
        self::assertSame(200, $res['status']);

        $seen = [];
        $cp = static function (array $c) use (&$seen): bool {
            $seen[] = $c['request']['body'] ?? null;
            return true;
        };
        $res = Gateway::envoyExtAuthz(self::sig(['checkProof' => $cp]))(['method' => 'GET', 'path' => '/docs/1', 'body' => 'xyz',
            'headers' => ['PCA-Action' => self::hdr(self::proof(self::bound()))]]);
        self::assertSame([200, ['xyz']], [$res['status'], $seen]);
    }

    /** Envoy gRPC: the host becomes the authority and the body is forwarded. */
    public function testGrpcRequestShape(): void
    {
        $seen = [];
        $cp = static function (array $c) use (&$seen): bool {
            $seen[] = [$c['request']['authority'] ?? null, $c['request']['body'] ?? null];
            return true;
        };
        $res = Gateway::envoyGrpcExtAuthz(self::sig(['checkProof' => $cp]))(['attributes' => ['request' => ['http' => [
            'method' => 'GET', 'path' => '/docs/1', 'host' => 'api.example', 'body' => 'xyz',
            'headers' => ['pca-action' => self::hdr(self::proof(self::bound()))]]]]]);
        self::assertSame(0, $res['status']['code']);
        self::assertSame([['api.example', 'xyz']], $seen);
    }

    /** Lambda: no method falls back to '*', the method ARN keeps the resource path after the fifth ':', a list of multi-values does not hide the single ones. */
    public function testLambdaRequestShape(): void
    {
        $auth = Gateway::lambdaAuthorizer(self::sig());
        $p = self::proof(self::bound());
        $noMethod = $auth(['path' => '/docs/1', 'headers' => ['PCA-Action' => self::hdr($p)]]);
        self::assertSame('Deny', $noMethod['policyDocument']['Statement'][0]['Effect']);
        self::assertSame('unmapped-route', $noMethod['context']->get('pcaCode'));

        $arn = $auth(['methodArn' => 'arn:aws:execute-api:us-east-1:12/34:abc/prod/GET/docs/1', 'headers' => ['PCA-Action' => self::hdr(self::proof(self::bound()))]]);
        self::assertSame('Allow', $arn['policyDocument']['Statement'][0]['Effect'], (string)$arn['context']->get('pcaReason'));

        $q = self::proof(self::bound(['query' => 'a=1']));
        $multi = $auth(['httpMethod' => 'GET', 'path' => '/docs/1', 'multiValueQueryStringParameters' => [], 'queryStringParameters' => ['a' => '1'],
            'headers' => ['PCA-Action' => self::hdr($q)]]);
        self::assertSame('Allow', $multi['policyDocument']['Statement'][0]['Effect'], (string)$multi['context']->get('pcaReason'));
    }
}
