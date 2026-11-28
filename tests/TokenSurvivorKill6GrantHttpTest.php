<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AtomicKv;
use Atlas\Pca\GrantApiError;
use Atlas\Pca\GrantClient;
use Atlas\Pca\GrantHttp;
use Atlas\Pca\GrantService;
use Atlas\Pca\Grants;
use Atlas\Pca\Js;
use Atlas\Pca\K3;
use Atlas\Pca\KeyPair;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryGrantStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The grant and lease HTTP bindings (routing, filters, status codes, refusals) and the grant client (requests it sends, answers it maps). */
final class TokenSurvivorKill6GrantHttpTest extends TestCase
{
    private static function kp(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $label, true));
    }

    private static function grant(string $id, array $extra = []): Obj
    {
        return Obj::of(['id' => $id, 'principal' => self::kp('P')->public, 'agent' => self::kp('A')->public,
            'authority' => Obj::of(['verbs' => ['read', 'write'], 'resources' => ['doc/1']])] + $extra);
    }

    private static function svc(): GrantService
    {
        $ctr = 0;
        return new GrantService(['store' => new MemoryGrantStore(), 'now' => static fn(): int => 1_800_000_000_000,
            'newId' => static function (string $kind) use (&$ctr): string {
                $ctr++;
                return $kind . '_' . $ctr;
            }, 'verifyStepUp' => static fn(mixed $ref): bool => $ref === 'ok']);
    }

    private static function handler(GrantService $svc): \Closure
    {
        return GrantHttp::grantResourceHandler($svc, static fn(mixed $req): mixed => Js::opt($req, 'who'));
    }

    private const ADMIN = ['admin' => true];

    /** @param list<Obj> $grants @return list<mixed> */
    private static function ids(array $grants): array
    {
        return array_map(static fn(Obj $g) => $g->get('id'), $grants);
    }

    /** @return list<string> the warnings / notices raised while `$f` ran */
    private static function warnings(callable $f): array
    {
        $seen = [];
        set_error_handler(static function (int $no, string $msg) use (&$seen): bool {
            $seen[] = $msg;
            return true;
        });
        try {
            $f();
        } finally {
            restore_error_handler();
        }
        return $seen;
    }

    // ---- grant routes ----------------------------------------------------------------------------------------------------------

    /** GET /pca/grants filters by status and agent; active is an accepted status. */
    public function testListFilters(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $svc->register(self::grant('g2', ['status' => 'revoked']));
        $svc->register(self::grant('g3', ['agent' => 'agent-b']));
        $h = self::handler($svc);
        $get = static fn(array $q): array => $h(['method' => 'GET', 'path' => '/pca/grants', 'query' => $q, 'who' => self::ADMIN]);
        $r = $get(['status' => 'active']);
        self::assertSame(200, $r['status']);
        self::assertSame(['g1', 'g3'], self::ids($r['body']->get('grants')));
        self::assertSame(['g2'], self::ids($get(['status' => 'revoked'])['body']->get('grants')));
        self::assertSame(['g3'], self::ids($get(['agent' => 'agent-b'])['body']->get('grants')));
        self::assertSame(['g1', 'g2', 'g3'], self::ids($get([])['body']->get('grants')));
    }

    /** A principal revokes its own grant with its signature in the body. */
    public function testPrincipalSignedDelete(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $sig = Grants::signBody(K3::GRANT_REVOKE_DOMAIN, K3::grantRevokeMessage('g1', 'grant'), self::kp('P'));
        $r = self::handler($svc)(['method' => 'DELETE', 'path' => '/pca/grants/g1', 'query' => ['scope' => 'grant'], 'body' => Obj::of(['sig' => $sig]),
            'who' => ['principal' => self::kp('P')->public]]);
        self::assertSame(200, $r['status']);
        self::assertSame(['g1'], $r['body']->get('revoked'));
    }

    /** POST .../amend answers 200 for an in-place amendment and 201 for a superseding one. */
    public function testAmendStatusCodes(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $h = self::handler($svc);
        $amend = static function (string $action, Obj $auth, string $by, ?string $stepUp) use ($svc, $h): array {
            $g = $svc->inspect('g1');
            $body = Obj::of(['action' => $action, 'authority' => $auth, 'signed_by' => $by,
                'sig' => Grants::signBody(K3::GRANT_AMEND_DOMAIN, K3::amendMessage($g, $action, $auth), self::kp($by === 'principal' ? 'P' : 'A'))]);
            if ($stepUp !== null) {
                $body->set('step_up_ref', $stepUp);
            }
            return $h(['method' => 'POST', 'path' => '/pca/grants/g1/amend', 'body' => $body, 'who' => self::ADMIN]);
        };
        $r = $amend('narrow', Obj::of(['verbs' => ['read'], 'resources' => ['doc/1']]), 'holder', null);
        self::assertSame(200, $r['status']);
        self::assertSame('g1', $r['body']->get('id'));
        $r = $amend('replace', Obj::of(['verbs' => ['read', 'admin'], 'resources' => ['doc/1']]), 'principal', 'ok');
        self::assertSame(201, $r['status']);
        self::assertNotSame('g1', $r['body']->get('id'));
    }

    /** A POST to a route that does not exist is a bare 404 (no service call behind it), and raises no warning. */
    public function testUnknownPostRoutesAreBare404(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $nid = $svc->requestNeeds('g1', [Obj::of(['verb' => 'read', 'resource' => 'doc/2'])])->get('id');
        $h = self::handler($svc);
        $out = [];
        $w = self::warnings(static function () use ($h, $nid, &$out): void {
            foreach (['/pca/grants/g1', '/pca/grants/g1/approve', '/pca/grants/g1/deny', '/pca/needs/' . $nid] as $p) {
                $out[$p] = $h(['method' => 'POST', 'path' => $p, 'body' => new Obj(), 'who' => self::ADMIN]);
            }
        });
        self::assertSame([], $w);
        foreach ($out as $p => $r) {
            self::assertSame(404, $r['status'], $p);
            self::assertSame('{"error":"not_found"}', Js::stringify($r['body']), $p);
        }
        self::assertSame('pending', $svc->store->getNeed($nid)->get('status'));
    }

    /** POST .../approve needs both sig and approved; a stepped-up approval through the route is 201. */
    public function testApproveRoute(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $approved = [Obj::of(['verb' => 'admin', 'resource' => 'doc/1'])];
        $nr = $svc->requestNeeds('g1', $approved);
        $h = self::handler($svc);
        $path = '/pca/needs/' . $nr->get('id') . '/approve';
        $r = $h(['method' => 'POST', 'path' => $path, 'body' => Obj::of(['approved' => $approved]), 'who' => self::ADMIN]);
        self::assertSame(400, $r['status']);
        self::assertSame('bad_request', $r['body']->get('error'));
        self::assertSame('sig and approved are required', $r['body']->get('message'));
        $sig = Grants::signBody(K3::NEED_APPROVE_DOMAIN, K3::needApproveMessage($nr, $svc->inspect('g1')->get('rev'), $approved), self::kp('P'));
        $r = $h(['method' => 'POST', 'path' => $path, 'body' => Obj::of(['approved' => $approved, 'sig' => $sig, 'step_up_ref' => 'ok']), 'who' => self::ADMIN]);
        self::assertSame(201, $r['status']);
        self::assertSame('superseded', $svc->store->get('g1')->get('status'));
        self::assertSame($r['body']->get('id'), $svc->store->getNeed($nr->get('id'))->get('result_grant_id'));
    }

    /** A failure that is not a grant refusal is a bare 500 server_error. */
    public function testUnexpectedFailureIs500(): void
    {
        $h = GrantHttp::grantResourceHandler(self::svc(), static function (): never {
            throw new \RuntimeException('auth backend down');
        });
        $r = $h(['method' => 'GET', 'path' => '/pca/grants']);
        self::assertSame(500, $r['status']);
        self::assertSame('{"error":"server_error"}', Js::stringify($r['body']));
    }

    // ---- lease routes ----------------------------------------------------------------------------------------------------------

    private static function lease(int $issued, array $over = []): Obj
    {
        return Grants::signLease(self::kp('auth'), Obj::of($over + ['lease_id' => 'L1', 'path' => 'svc/a', 'grant_ref' => 'g1', 'holder' => 'holder-1',
            'requester' => 'req-1', 'approvers' => ['appr-1'], 'justification_digest' => 'jd-1', 'seq' => 1, 'issued_at' => $issued, 'renewed_at' => $issued,
            'expires_at' => $issued + 600_000, 'max_ttl' => 3_600_000]));
    }

    private static function registry(?AtomicKv $kv = null): LeaseRegistry
    {
        return new LeaseRegistry(['authorities' => [self::kp('auth')->public]], $kv ?? new MemoryAtomicKv(), ['shards' => 1]);
    }

    /** With no injected clock the check route reads the wall clock in milliseconds: a lease valid now is allowed (200). */
    public function testLeaseCheckOnTheDefaultClock(): void
    {
        $reg = self::registry();
        $h = GrantHttp::leaseResourceHandler($reg, static fn(mixed $req): mixed => Js::opt($req, 'who'));
        $l = self::lease((int)(microtime(true) * 1000) - 1000);
        self::assertSame(201, $h(['method' => 'POST', 'path' => '/pca/leases', 'body' => Obj::of(['lease' => $l]), 'who' => self::ADMIN])['status']);
        $r = $h(['method' => 'POST', 'path' => '/pca/leases/L1/check', 'body' => Obj::of(['lease' => $l]), 'who' => self::ADMIN]);
        self::assertSame(200, $r['status']);
        self::assertSame('allow', $r['body']['decision']);
    }

    /** An injected clock is the one the check route uses (a lease valid only at that time is allowed). */
    public function testLeaseCheckOnAnInjectedClock(): void
    {
        $at = 2_500_000_000_000;
        $reg = self::registry();
        $h = GrantHttp::leaseResourceHandler($reg, static fn(mixed $req): mixed => Js::opt($req, 'who'), static fn(): int => $at);
        $l = self::lease($at - 1000);
        self::assertSame(201, $h(['method' => 'POST', 'path' => '/pca/leases', 'body' => Obj::of(['lease' => $l]), 'who' => self::ADMIN])['status']);
        $r = $h(['method' => 'POST', 'path' => '/pca/leases/L1/check', 'body' => Obj::of(['lease' => $l]), 'who' => self::ADMIN]);
        self::assertSame(200, $r['status']);
        self::assertSame('allow', $r['body']['decision']);
        // a POST to the lease itself is not the check route
        self::assertSame(404, $h(['method' => 'POST', 'path' => '/pca/leases/L1', 'body' => Obj::of(['lease' => $l]), 'who' => self::ADMIN])['status']);
    }

    /** Lease routes live only under /pca/leases. */
    public function testLeaseRoutesNeedThePcaPrefix(): void
    {
        $reg = self::registry();
        $h = GrantHttp::leaseResourceHandler($reg, static fn(mixed $req): mixed => Js::opt($req, 'who'), static fn(): int => 1_800_000_000_000);
        $r = $h(['method' => 'POST', 'path' => '/x/leases', 'body' => Obj::of(['lease' => self::lease(1_800_000_000_000)]), 'who' => self::ADMIN]);
        self::assertSame(404, $r['status']);
        self::assertNull($reg->current('L1'));
    }

    /** The delegation chain sent with a lease is honoured only when every entry is a string. */
    public function testLeaseChainIsSeparationOfDutiesInput(): void
    {
        $post = static function (mixed $chain): array {
            $h = GrantHttp::leaseResourceHandler(self::registry(), static fn(mixed $req): mixed => Js::opt($req, 'who'), static fn(): int => 1_800_000_000_000);
            return $h(['method' => 'POST', 'path' => '/pca/leases', 'body' => Obj::of(['lease' => self::lease(1_800_000_000_000), 'chain' => $chain]), 'who' => self::ADMIN]);
        };
        $r = $post(['appr-1']);
        self::assertSame(403, $r['status']);
        self::assertSame('sod', $r['body']->get('error'));
        self::assertSame("an approver appears in the holder's delegation chain", $r['body']->get('message'));
        self::assertSame(201, $post([5, 'appr-1'])['status']);
    }

    /** A revocation the store cannot take is 503 store_unreachable. */
    public function testLeaseRevokeOnAFailedStoreIs503(): void
    {
        $down = new class implements AtomicKv {
            public function get(string $key): ?string
            {
                throw new \RuntimeException('down');
            }

            public function update(string $key, callable $fn): void
            {
                throw new \RuntimeException('down');
            }
        };
        $h = GrantHttp::leaseResourceHandler(self::registry($down), static fn(mixed $req): mixed => Js::opt($req, 'who'), static fn(): int => 1_800_000_000_000);
        $rev = Grants::signLeaseRevocation(self::kp('auth'), Obj::of(['target' => 'lease', 'value' => 'L1', 'revoked_at' => 1_800_000_000_000]));
        $r = $h(['method' => 'POST', 'path' => '/pca/leases/revoke', 'body' => Obj::of(['revocation' => $rev]), 'who' => self::ADMIN]);
        self::assertSame(503, $r['status']);
        self::assertSame('{"error":"store_unreachable"}', Js::stringify($r['body']));
    }

    /** A failure inside the lease handler is a bare 500 server_error. */
    public function testLeaseUnexpectedFailureIs500(): void
    {
        $h = GrantHttp::leaseResourceHandler(self::registry(), static function (): never {
            throw new \RuntimeException('auth backend down');
        });
        $r = $h(['method' => 'GET', 'path' => '/pca/leases/L1']);
        self::assertSame(500, $r['status']);
        self::assertSame('{"error":"server_error"}', Js::stringify($r['body']));
    }

    // ---- client ----------------------------------------------------------------------------------------------------------------

    /** @return array{0: GrantClient, 1: \Closure(): list<array>} a client over a recording transport answering `$answer` */
    private static function client(array $answer = ['status' => 200, 'headers' => [], 'body' => '{}'], ?callable $headers = null): array
    {
        $sent = [];
        $fetch = static function (array $req) use (&$sent, $answer): array {
            $sent[] = $req;
            return $answer;
        };
        return [new GrantClient('https://as.example/', $fetch, null, $headers), static function () use (&$sent): array {
            return $sent;
        }];
    }

    /** Every write method sends its method, URL and JSON body; a request without a body sends none. */
    public function testClientRequests(): void
    {
        [$c, $sent] = self::client();
        $c->amend('g/1', Obj::of(['action' => 'narrow']));
        $c->revoke('g1', 'agent', 'SIG');
        $c->revoke('g1');
        $c->requestNeeds('g1', [Obj::of(['verb' => 'read'])]);
        $c->approveNeeds('n1', [], 'S', 'su');
        $c->approveNeeds('n1', [], 'S');
        $c->denyNeeds('n1');
        $c->inspect('g1');
        $want = [
            ['POST', 'https://as.example/pca/grants/g%2F1/amend', '{"action":"narrow"}'],
            ['DELETE', 'https://as.example/pca/grants/g1?scope=agent', '{"sig":"SIG"}'],
            ['DELETE', 'https://as.example/pca/grants/g1?scope=grant', null],
            ['POST', 'https://as.example/pca/grants/g1/needs', '{"needs":[{"verb":"read"}]}'],
            ['POST', 'https://as.example/pca/needs/n1/approve', '{"approved":[],"sig":"S","step_up_ref":"su"}'],
            ['POST', 'https://as.example/pca/needs/n1/approve', '{"approved":[],"sig":"S"}'],
            ['POST', 'https://as.example/pca/needs/n1/deny', null],
            ['GET', 'https://as.example/pca/grants/g1', null],
        ];
        $got = array_map(static fn(array $r): array => [$r['method'], $r['url'], $r['body'] ?? null], $sent());
        self::assertSame($want, $got);
        self::assertArrayNotHasKey('body', $sent()[2]);
        self::assertSame(['content-type' => 'application/json'], $sent()[0]['headers']);
    }

    /** Extra headers from the callback are sent and win over the defaults. */
    public function testClientExtraHeaders(): void
    {
        [$c, $sent] = self::client(headers: static fn(): array => ['content-type' => 'text/x', 'authorization' => 'Bearer t']);
        $c->inspect('g1');
        self::assertSame(['content-type' => 'text/x', 'authorization' => 'Bearer t'], $sent()[0]['headers']);
    }

    /** Query values are form-encoded with `*` kept, booleans spelled out, nulls dropped and list keys numbered. */
    public function testClientQueryEncoding(): void
    {
        [$c, $sent] = self::client();
        $c->list(['agent' => 'a*b c', 'flag' => true, 'off' => false, 'skip' => null]);
        $c->list(['x']);
        self::assertSame('https://as.example/pca/grants?agent=a*b+c&flag=true&off=false', $sent()[0]['url']);
        self::assertSame('https://as.example/pca/grants?0=x', $sent()[1]['url']);
    }

    /** An already parsed body is returned as is; a response header map with an integer key is tolerated. */
    public function testClientParsedBodyAndOddHeaders(): void
    {
        $body = Obj::of(['grants' => []]);
        [$c] = self::client(['status' => 200, 'headers' => [7 => 'x'], 'body' => $body]);
        self::assertSame($body, $c->list());
    }

    private static function apiError(array $answer): GrantApiError
    {
        [$c] = self::client($answer);
        try {
            $c->inspect('g1');
        } catch (GrantApiError $e) {
            return $e;
        }
        self::fail('expected a GrantApiError');
    }

    /** A non-2xx answer maps to GrantApiError: status (also from a numeric string), code, and message from the body, reason or status. */
    public function testClientApiErrors(): void
    {
        $e = self::apiError(['status' => 409, 'headers' => [], 'body' => '{"error":"conflict","message":"m"}', 'reason' => 'Conflict']);
        self::assertSame([409, 'conflict', 'm'], [$e->status, $e->errorCode, $e->getMessage()]);
        $e = self::apiError(['status' => '404', 'headers' => [], 'body' => '{"error":"not_found"}']);
        self::assertSame([404, 'not_found', '404'], [$e->status, $e->errorCode, $e->getMessage()]);
        $e = self::apiError(['status' => 502, 'headers' => [], 'body' => '{}', 'reason' => 'Bad Gateway']);
        self::assertSame([502, 'error', 'Bad Gateway'], [$e->status, $e->errorCode, $e->getMessage()]);
        $e = self::apiError(['status' => 500, 'headers' => [], 'body' => '"oops"']);
        self::assertSame([500, 'error', '500'], [$e->status, $e->errorCode, $e->getMessage()]);
        $e = self::apiError(['status' => 300, 'headers' => [], 'body' => '{}']);
        self::assertSame([300, 'error', '300'], [$e->status, $e->errorCode, $e->getMessage()]);
    }

    /** A token with equal counters replaces the held one (newest wins ties); an older one does not; folding needs a held token. */
    public function testClientFreshnessFold(): void
    {
        $tok = static fn(int $epoch, string $digest): string => Js::stringify(Obj::of(['revocation_epoch' => $epoch, 'policy_revision' => 1,
            'ledger_tree_size' => 1, 'budget_version' => 1, 'policy_digest' => $digest]));
        $toks = [$tok(1, 'a'), $tok(1, 'b'), $tok(0, 'c')];
        $fetch = static function (array $req) use (&$toks): array {
            return ['status' => 200, 'headers' => ['pca-fresh-at' => array_shift($toks)], 'body' => '{}'];
        };
        $c = new GrantClient('https://as.example', $fetch);
        $probe = Obj::of(['revocation_epoch' => 5, 'policy_revision' => 0, 'ledger_tree_size' => 0, 'budget_version' => 0, 'policy_digest' => 'z']);
        self::assertNull($c->foldFreshAt($probe));
        $c->inspect('g1');
        self::assertSame('a', $c->freshAt()->get('policy_digest'));
        $c->inspect('g1');
        self::assertSame('b', $c->freshAt()->get('policy_digest'));
        $c->inspect('g1');
        self::assertSame('b', $c->freshAt()->get('policy_digest'));
        $f = $c->foldFreshAt($probe);
        self::assertSame(5.0, Js::num($f->get('revocation_epoch')));
        self::assertSame('b', $f->get('policy_digest'));
    }
}
