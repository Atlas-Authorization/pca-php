<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GrantError;
use Atlas\Pca\GrantHttp;
use Atlas\Pca\GrantService;
use Atlas\Pca\Grants;
use Atlas\Pca\K3;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryGrantStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Grant store copies, the grant management service (register, list, amend, revoke, needs) and its discovery metadata and Number parser. */
final class TokenSurvivorKill6GrantTest extends TestCase
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

    /** @param array<string,mixed> $o */
    private static function svc(array $o = []): GrantService
    {
        $ctr = 0;
        return new GrantService($o + ['store' => new MemoryGrantStore(), 'now' => static fn(): int => 1_800_000_000_000,
            'newId' => static function (string $kind) use (&$ctr): string {
                $ctr++;
                return $kind . '_' . $ctr;
            }]);
    }

    /** @param list<Obj> $grants @return list<mixed> */
    private static function ids(array $grants): array
    {
        return array_map(static fn(Obj $g) => $g->get('id'), $grants);
    }

    private static function code(callable $f): GrantError
    {
        try {
            $f();
        } catch (GrantError $e) {
            return $e;
        }
        self::fail('expected a GrantError');
    }

    // ---- MemoryGrantStore ---------------------------------------------------------------------------------------------------------

    /** list() is a list of deep copies: editing a listed grant never edits the store. */
    public function testStoreListIsAListOfCopies(): void
    {
        $s = new MemoryGrantStore();
        $s->put(self::grant('b'));
        $s->put(self::grant('a'));
        $l = $s->list();
        self::assertSame([0, 1], array_keys($l));
        self::assertSame(['b', 'a'], self::ids($l));
        $l[0]->set('status', 'tampered');
        self::assertNull($s->get('b')->get('status'));
    }

    /** listNeeds() returns only that grant's needs, as a list of copies. */
    public function testStoreListNeedsFiltersAndCopies(): void
    {
        $s = new MemoryGrantStore();
        $s->putNeed(Obj::of(['id' => 'n1', 'grant_id' => 'x', 'status' => 'pending']));
        $s->putNeed(Obj::of(['id' => 'n2', 'grant_id' => 'y', 'status' => 'pending']));
        $s->putNeed(Obj::of(['id' => 'n3', 'grant_id' => 'y', 'status' => 'pending']));
        $l = $s->listNeeds('y');
        self::assertSame([0, 1], array_keys($l));
        self::assertSame(['n2', 'n3'], self::ids($l));
        $l[0]->set('status', 'tampered');
        self::assertSame('pending', $s->getNeed('n2')->get('status'));
    }

    // ---- register / list -----------------------------------------------------------------------------------------------------

    /** A registered status is kept; only an absent one defaults to active. */
    public function testRegisterKeepsAGivenStatus(): void
    {
        $svc = self::svc();
        self::assertSame('revoked', $svc->register(self::grant('g1', ['status' => 'revoked']))->get('status'));
        self::assertSame('active', $svc->register(self::grant('g2'))->get('status'));
    }

    /** list() orders by id whatever the registration order. */
    public function testListSortsReverseRegistrationOrder(): void
    {
        $svc = self::svc();
        foreach (['c', 'b', 'a'] as $id) {
            $svc->register(self::grant($id));
        }
        self::assertSame(['a', 'b', 'c'], self::ids($svc->list()->get('grants')));
        $svc2 = self::svc();
        foreach (['b', 'c', 'a'] as $id) {
            $svc2->register(self::grant($id));
        }
        self::assertSame(['a', 'b', 'c'], self::ids($svc2->list()->get('grants')));
    }

    /**
     * Ids that are equal in UTF-16 order (two invalid UTF-8 bytes both read as the same substitute) keep their registration order: the sort is
     * stable, a tie is never broken either way.
     */
    public function testListKeepsTiesInRegistrationOrder(): void
    {
        $svc = self::svc();
        $svc->register(self::grant("\xFF"));
        $svc->register(self::grant("\xFE"));
        self::assertSame(["\xFF", "\xFE"], self::ids($svc->list()->get('grants')));
        // U+FFFF sorts after any substitute character
        $svc2 = self::svc();
        $svc2->register(self::grant("\u{FFFF}"));
        $svc2->register(self::grant("\xFF"));
        $svc2->register(self::grant("\xFE"));
        self::assertSame(["\xFF", "\xFE", "\u{FFFF}"], self::ids($svc2->list()->get('grants')));
    }

    /** A grant's pending_needs lists only its pending requests, as a list. */
    public function testPendingNeedsIsAListOfPendingIds(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $n1 = $svc->requestNeeds('g1', [Obj::of(['verb' => 'read', 'resource' => 'doc/2'])])->get('id');
        $n2 = $svc->requestNeeds('g1', [Obj::of(['verb' => 'read', 'resource' => 'doc/3'])])->get('id');
        $svc->denyNeeds($n1);
        self::assertSame([$n2], $svc->inspect('g1')->get('pending_needs'));
    }

    // ---- amend ---------------------------------------------------------------------------------------------------------------

    private static function amendReq(GrantService $svc, string $gid, string $action, Obj $authority, string $by, ?string $stepUp = null): Obj
    {
        $g = $svc->inspect($gid);
        $req = Obj::of(['action' => $action, 'authority' => $authority, 'signed_by' => $by,
            'sig' => Grants::signBody(K3::GRANT_AMEND_DOMAIN, K3::amendMessage($g, $action, $authority), self::kp($by === 'principal' ? 'P' : 'A'))]);
        if ($stepUp !== null) {
            $req->set('step_up_ref', $stepUp);
        }
        return $req;
    }

    private static function richSvc(): GrantService
    {
        return self::svc(['providers' => ['usage' => static fn(Obj $g): string => 'usage:' . $g->get('id')],
            'verifyStepUp' => static fn(mixed $ref): bool => $ref === 'ok']);
    }

    /** A narrowing amendment bumps the integer revision in place and answers with the rich view. */
    public function testNarrowingAmendIsInPlaceAndRich(): void
    {
        $svc = self::richSvc();
        $svc->register(self::grant('g1'));
        $narrow = Obj::of(['verbs' => ['read'], 'resources' => ['doc/1']]);
        $r = $svc->amend('g1', self::amendReq($svc, 'g1', 'narrow', $narrow, 'holder'));
        self::assertFalse($r['created']);
        self::assertSame(2, $r['grant']->get('rev'));
        self::assertSame('usage:g1', $r['grant']->get('usage'));
        self::assertSame(2, $svc->store->get('g1')->get('rev'));
    }

    /** A widening amendment creates a successor and marks the old grant superseded by it in the store. */
    public function testWideningAmendSupersedes(): void
    {
        $svc = self::richSvc();
        $svc->register(self::grant('g1'));
        $wide = Obj::of(['verbs' => ['read', 'write', 'admin'], 'resources' => ['doc/1']]);
        $r = $svc->amend('g1', self::amendReq($svc, 'g1', 'replace', $wide, 'principal', 'ok'));
        self::assertTrue($r['created']);
        $nid = $r['grant']->get('id');
        self::assertNotSame('g1', $nid);
        self::assertSame('usage:' . $nid, $r['grant']->get('usage'));
        $old = $svc->store->get('g1');
        self::assertSame('superseded', $old->get('status'));
        self::assertSame($nid, $old->get('superseded_by'));
        self::assertSame('active', $svc->store->get($nid)->get('status'));
        self::assertSame('g1', $svc->store->get($nid)->get('supersedes'));
    }

    // ---- revoke --------------------------------------------------------------------------------------------------------------

    /** A subtree revocation reaches a grandchild registered before its parent. */
    public function testSubtreeRevokeReachesOutOfOrderDescendants(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('r'));
        $svc->register(self::grant('gc', ['parent' => 'c']));
        $svc->register(self::grant('c', ['parent' => 'r']));
        $svc->register(self::grant('other'));
        self::assertSame(['r', 'gc', 'c'], $svc->revoke('r', 'subtree', ['admin' => true])->get('revoked'));
        self::assertSame('revoked', $svc->store->get('gc')->get('status'));
        self::assertSame('active', $svc->store->get('other')->get('status'));
    }

    // ---- requestNeeds --------------------------------------------------------------------------------------------------------

    /** Needs on an inactive grant are refused naming its status. */
    public function testNeedsOnInactiveGrantNameTheStatus(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1', ['status' => 'revoked']));
        $e = self::code(static fn() => $svc->requestNeeds('g1', [Obj::of(['verb' => 'read', 'resource' => 'doc/2'])]));
        self::assertSame('not_active', $e->errorCode);
        self::assertSame('grant is revoked', $e->getMessage());
    }

    /** 32 needs are accepted, 33 are not. */
    public function testNeedCountBoundary(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $need = static fn(): Obj => Obj::of(['verb' => 'read', 'resource' => 'doc/2']);
        self::assertCount(32, $svc->requestNeeds('g1', array_map(static fn() => $need(), range(1, 32)))->get('needs'));
        $e = self::code(static fn() => $svc->requestNeeds('g1', array_map(static fn() => $need(), range(1, 33))));
        self::assertSame('bad_request', $e->errorCode);
        self::assertSame('1..32 needs', $e->getMessage());
    }

    /** A verb holds 128 characters and a resource 512; one more is a malformed need. */
    public function testNeedStringLengthBoundaries(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $ok = $svc->requestNeeds('g1', [Obj::of(['verb' => str_repeat('v', 128), 'resource' => str_repeat('r', 512)])]);
        self::assertSame('pending', $ok->get('status'));
        foreach ([[129, 512], [128, 513]] as [$v, $r]) {
            $e = self::code(static fn() => $svc->requestNeeds('g1', [Obj::of(['verb' => str_repeat('v', $v), 'resource' => str_repeat('r', $r)])]));
            self::assertSame('bad_request', $e->errorCode);
            self::assertSame('malformed need', $e->getMessage());
        }
    }

    /** A non-object need, non-object limits, or a negative / non-number limit are malformed; a zero limit is fine. */
    public function testNeedShapeRefusals(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $zero = $svc->requestNeeds('g1', [Obj::of(['verb' => 'read', 'resource' => 'doc/2', 'limits' => Obj::of(['n' => 0])])]);
        self::assertSame('pending', $zero->get('status'));
        $bad = ['not an object', Obj::of(['verb' => 'read', 'resource' => 'doc/2', 'limits' => 5]),
            Obj::of(['verb' => 'read', 'resource' => 'doc/2', 'limits' => Obj::of(['n' => -1])]),
            Obj::of(['verb' => 'read', 'resource' => 'doc/2', 'limits' => Obj::of(['n' => 'x'])]),
            Obj::of(['verb' => 'read', 'resource' => 'doc/2', 'limits' => Obj::of(['a' => -1, 'b' => 1])])];
        foreach ($bad as $n) {
            $e = self::code(static fn() => $svc->requestNeeds('g1', [$n]));
            self::assertSame('bad_request', $e->errorCode);
            self::assertSame('malformed need', $e->getMessage());
        }
    }

    /** A validateNeed answer that is not a string still becomes the refusal message. */
    public function testValidateNeedNonStringMessage(): void
    {
        $svc = self::svc(['validateNeed' => static fn(Obj $n): int => 42]);
        $svc->register(self::grant('g1'));
        $e = self::code(static fn() => $svc->requestNeeds('g1', [Obj::of(['verb' => 'read', 'resource' => 'doc/2'])]));
        self::assertSame('bad_request', $e->errorCode);
        self::assertSame('42', $e->getMessage());
    }

    // ---- approve / deny needs ------------------------------------------------------------------------------------------------

    /** An unknown need is not_found; an already denied one is a conflict naming its status. */
    public function testApproveUnknownAndDecidedNeeds(): void
    {
        $svc = self::svc();
        $svc->register(self::grant('g1'));
        $e = self::code(static fn() => $svc->approveNeeds('missing', [], 'x'));
        self::assertSame('not_found', $e->errorCode);
        self::assertSame('no such need request', $e->getMessage());
        $nid = $svc->requestNeeds('g1', [Obj::of(['verb' => 'read', 'resource' => 'doc/2'])])->get('id');
        $svc->denyNeeds($nid);
        $e = self::code(static fn() => $svc->approveNeeds($nid, [], 'x'));
        self::assertSame('conflict', $e->errorCode);
        self::assertSame('need request is denied', $e->getMessage());
    }

    /** A badly signed approval never consults (and so never consumes) the step-up. */
    public function testBadSignatureNeverConsultsStepUp(): void
    {
        $calls = 0;
        $svc = self::svc(['verifyStepUp' => static function () use (&$calls): bool {
            $calls++;
            return true;
        }]);
        $svc->register(self::grant('g1'));
        $nid = $svc->requestNeeds('g1', [Obj::of(['verb' => 'read', 'resource' => 'doc/2'])])->get('id');
        $e = self::code(static fn() => $svc->approveNeeds($nid, [Obj::of(['verb' => 'read', 'resource' => 'doc/2'])], 'bad', 'ok'));
        self::assertSame('bad_signature', $e->errorCode);
        self::assertSame(0, $calls);
    }

    /** An approval supersedes the grant, records the result grant on the need, and answers with the rich view. */
    public function testApprovalRecordsResultGrant(): void
    {
        $svc = self::richSvc();
        $svc->register(self::grant('g1'));
        $approved = [Obj::of(['verb' => 'admin', 'resource' => 'doc/1'])];
        $nr = $svc->requestNeeds('g1', $approved);
        $sig = Grants::signBody(K3::NEED_APPROVE_DOMAIN, K3::needApproveMessage($nr, $svc->inspect('g1')->get('rev'), $approved), self::kp('P'));
        $r = $svc->approveNeeds($nr->get('id'), $approved, $sig, 'ok');
        self::assertTrue($r['created']);
        $nid = $r['grant']->get('id');
        self::assertSame('usage:' . $nid, $r['grant']->get('usage'));
        $need = $svc->store->getNeed($nr->get('id'));
        self::assertSame('approved', $need->get('status'));
        self::assertSame($nid, $need->get('result_grant_id'));
        self::assertSame('superseded', $svc->store->get('g1')->get('status'));
    }

    // ---- metadata / Number -----------------------------------------------------------------------------------------------------

    /** The discovery fragments carry every endpoint under the base, and the fixed vocabularies. */
    public function testDiscoveryMetadata(): void
    {
        $m = GrantHttp::grantManagementMetadata('https://as.example')->get('grant_management');
        self::assertSame(['grants_endpoint', 'needs_endpoint', 'amend_actions', 'revoke_scopes', 'widening'], $m->keys());
        self::assertSame('https://as.example/pca/grants', $m->get('grants_endpoint'));
        self::assertSame('https://as.example/pca/needs', $m->get('needs_endpoint'));
        self::assertSame(['narrow', 'merge', 'replace'], $m->get('amend_actions'));
        self::assertSame(['grant', 'agent', 'subtree'], $m->get('revoke_scopes'));
        self::assertSame('new_grant_id_with_supersedes', $m->get('widening'));
        $l = GrantHttp::leaseManagementMetadata('https://as.example')->get('leases');
        self::assertSame(['leases_endpoint', 'revoke_targets'], $l->keys());
        self::assertSame('https://as.example/pca/leases', $l->get('leases_endpoint'));
        self::assertSame(['lease', 'prefix', 'grant'], $l->get('revoke_targets'));
    }

    /** Number(string): signed Infinity and the 0x / 0o / 0b forms in either letter case; a digit outside the base is NaN. */
    public function testJsNumberSpecialForms(): void
    {
        self::assertSame(INF, GrantHttp::jsNumber('Infinity'));
        self::assertSame(INF, GrantHttp::jsNumber('+Infinity'));
        self::assertSame(-INF, GrantHttp::jsNumber('-Infinity'));
        self::assertSame(31.0, GrantHttp::jsNumber('0X1f'));
        self::assertSame(15.0, GrantHttp::jsNumber('0o17'));
        self::assertSame(15.0, GrantHttp::jsNumber('0O17'));
        self::assertSame(5.0, GrantHttp::jsNumber('0b101'));
        self::assertSame(5.0, GrantHttp::jsNumber('0B101'));
        self::assertNan(GrantHttp::jsNumber('0b2'));
        self::assertNan(GrantHttp::jsNumber('0o8'));
    }
}
