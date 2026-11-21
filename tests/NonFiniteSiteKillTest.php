<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Acp;
use Atlas\Pca\AdmissionRegistry;
use Atlas\Pca\AnalyzerCoverage;
use Atlas\Pca\Ap2;
use Atlas\Pca\AuthorizedOperation;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\ExecuteOptions;
use Atlas\Pca\ExecutionHandle;
use Atlas\Pca\GrantClient;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\K3;
use Atlas\Pca\KeyPair;
use Atlas\Pca\KvDoc;
use Atlas\Pca\Lease;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MeshIssue;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Operations;
use Atlas\Pca\Pca;
use Atlas\Pca\RecheckResult;
use Atlas\Pca\SandboxEgressPolicy;
use Atlas\Pca\SandboxHandleTable;
use Atlas\Pca\SandboxReceiptLog;
use Atlas\Pca\Sign;
use Atlas\Pca\WindowReadAccumulator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A NaN or infinite value at a decision site refuses: a plain `a > b` or `a >= b` is false against NaN, so each site is written as the
 * negation of its admitting comparison (and, where a helper would hide the value as zero, reads it directly).
 */
final class NonFiniteSiteKillTest extends TestCase
{
    /** @return list<array{float}> */
    public static function nonFinite(): array
    {
        return [[NAN], [INF], [-INF]];
    }

    #[DataProvider('nonFinite')]
    public function testAp2BudgetRefusesANonFiniteMax(float $max): void
    {
        $open = Obj::of(['constraints' => [Obj::of(['type' => 'payment.budget', 'currency' => 'USD', 'max' => $max])]]);
        $closed = Obj::of(['payment_amount' => Obj::of(['currency' => 'USD', 'amount' => 5])]);
        $o = Obj::of(['context' => Obj::of(['totalAmount' => 0, 'totalUses' => 0]), 'now' => 0]);
        $this->assertSame(['budget.max is not a whole number of minor units'], Ap2::checkPaymentConstraints($open, $closed, $o)); // was admitted
        $fine = Obj::of(['constraints' => [Obj::of(['type' => 'payment.budget', 'currency' => 'USD', 'max' => 100])]]);
        $this->assertSame([], Ap2::checkPaymentConstraints($fine, $closed, $o));
    }

    private static function sptToken(): Obj
    {
        $t = Json::parseLax('{"id":"spt_123","object":"shared_payment.granted_token","created":1700000000,"livemode":true,"deactivated_at":null,"deactivated_reason":null,'
            . '"usage_limits":{"currency":"usd","max_amount":10000,"expires_at":1800000000},"usage_details":{"amount_captured":{"value":2000,"currency":"usd"}},'
            . '"payment_method_details":{"type":"card","card":{"last4":"4242"}},"agent_details":{"name":"a"},"shared_metadata":{"k":"v"},"risk_details":null}');
        self::assertInstanceOf(Obj::class, $t);
        return $t;
    }

    public function testStripeSptWithinClaimsRefusesANaNDelegatedAmountOrExpiry(): void
    {
        $ok = Acp::stripeSptWithinClaims(self::sptToken(), Obj::of(['amount' => 10000, 'currency' => 'USD', 'exp' => 1800000000000]));
        $this->assertTrue($ok->get('ok'));
        $amount = Acp::stripeSptWithinClaims(self::sptToken(), Obj::of(['amount' => NAN, 'currency' => 'USD', 'exp' => 1800000000000]));
        $this->assertFalse($amount->get('ok')); // NaN is not above the token cap, so the old `max > amount` admitted it
        $this->assertStringStartsWith('max_amount 10000 exceeds the delegated amount', $amount->get('reason'));
        $exp = Acp::stripeSptWithinClaims(self::sptToken(), Obj::of(['amount' => 10000, 'currency' => 'USD', 'exp' => NAN]));
        $this->assertFalse($exp->get('ok'));
        $this->assertSame('the token outlives the delegated payment token', $exp->get('reason'));
    }

    private const FLIP_POLICY = '{"predicates":[{"verb":"pay","resource":"/vendors/*","where":[{"field":"action.params.amount","op":"lte","value":1000},'
        . '{"field":"action.params.currency","op":"in","value":["usd","eur"]}]},{"verb":["read","list"],"resource":"*"}],'
        . '"caveats":[{"type":"expires","at":1900000000000},{"type":"rate","max":5,"per_secs":60}]}';
    private const FLIP_ACTION = '{"verb":"pay","resource":"/vendors/a","params":{"amount":5000,"currency":"usd"}}';

    /** @param array<string,mixed> $probe */
    private static function flip(array $probe): Obj
    {
        $base = ['limit' => 3, 'windowSecs' => 60, 'history' => [1799999900000, 1799999995000], 'now' => 1800000000000];
        return AnalyzerCoverage::minimalFlip(Json::parseLax(self::FLIP_POLICY), Json::parseLax(self::FLIP_ACTION),
            Obj::of(['holderAuthenticated' => true, 'probe' => Obj::of(array_merge($base, $probe))]));
    }

    /** @return list<array{array<string,mixed>}> */
    public static function badProbes(): array
    {
        return [
            [['now' => NAN]], [['now' => INF]], [['now' => -INF]],
            [['windowSecs' => NAN]], [['windowSecs' => INF]],
            [['history' => [1799999995000, NAN]]], [['history' => [INF]]], [['history' => [-INF]]],
            [['limit' => NAN]],
        ];
    }

    /** @param array<string,mixed> $probe */
    #[DataProvider('badProbes')]
    public function testMinimalFlipRefusesANonFiniteProbeBudget(array $probe): void
    {
        $r = self::flip($probe);
        $this->assertSame('probe budget exhausted', $r->get('refused')); // the stamps compared false, so the old code counted none and admitted
        $this->assertFalse($r->get('repairExists'));
        $this->assertSame([], $r->get('repairs'));
        $this->assertInstanceOf(Obj::class, $r->get('probe'));
    }

    public function testMinimalFlipKeepsAFiniteProbeBudget(): void
    {
        $r = self::flip([]);
        $this->assertNull($r->get('refused'));
        $this->assertTrue($r->get('repairExists'));
        $this->assertSame([1799999995000, 1800000000000], $r->get('probe')->get('history'));
        $this->assertSame('probe budget exhausted', self::flip(['limit' => 1])->get('refused'));
    }

    private static function egressPolicy(\Closure $clock): SandboxEgressPolicy
    {
        $policy = new SandboxEgressPolicy($clock);
        $op = Obj::of(['verb' => 'net.ok', 'resource' => 'api.example.com', 'params' => new Obj()]);
        $result = Obj::of(['allow' => true, 'operation' => Obj::of(['verb' => 'net.ok', 'resource' => 'api.example.com',
            'params_digest' => Pca::hashCanonical($op->get('params')), 'id' => 'op'])]);
        $policy->admit($result, $op, static fn($o) => Obj::of(['method' => 'GET', 'scheme' => 'https', 'host' => 'api.example.com', 'path' => '/v1']),
            Obj::of(['expiresAt' => 5000]));
        return $policy;
    }

    #[DataProvider('nonFinite')]
    public function testEgressAdmissionIsSpentOnANonFiniteClock(float $now): void
    {
        $req = Obj::of(['method' => 'GET', 'url' => 'https://api.example.com/v1']);
        $d = self::egressPolicy(static fn() => $now)->claim($req); // a non-finite clock was read as epoch 0, inside every window
        $this->assertFalse($d->get('allow'));
        $this->assertSame('spent', $d->get('reason'));
        $this->assertTrue(self::egressPolicy(static fn() => 1000)->claim($req)->get('allow'));
        $this->assertSame('spent', self::egressPolicy(static fn() => 5000)->claim($req)->get('reason'));
    }

    private static function irreversible(string $id, Num $exp): AuthorizeResult
    {
        return new AuthorizeResult(true, 200, pcactn: Obj::of(['action' => Obj::of(['reversibility_class' => 'irreversible']), 'exp' => $exp]), verdict: ['allow' => true],
            operation: new AuthorizedOperation('v', '/r', Pca::paramsDigest(), $id));
    }

    public function testRecheckRefusesAnInfinitePcactnExpiry(): void
    {
        $opts = static fn(): ExecuteOptions => new ExecuteOptions(new MemoryOperationStore(),
            recheck: static fn(ExecutionHandle $h): RecheckResult => RecheckResult::ok(), now: static fn(): int => 1000);
        $ok = Operations::executeAuthorized(self::irreversible('op-fin', new Num('2000')), static fn() => 'done', $opts());
        $this->assertSame('committed', $ok->status);
        $calls = 0;
        $o = Operations::executeAuthorized(self::irreversible('op-inf', new Num('1e999')), static function () use (&$calls) {
            $calls++;
            return 'done';
        }, $opts()); // 1000 > Infinity is false: the infinite expiry used to pass
        $this->assertSame('aborted', $o->status);
        $this->assertSame('recheck: the PCActn expired at Infinity', $o->reason);
        $this->assertSame(0, $calls);
    }

    public function testTranslatedCapabilityIsRefusedOnANaNClock(): void
    {
        $chain = MeshIssue::buildMeshExample()['chain'];
        $tc = MeshIssue::translateCapability($chain, 'org-A', 'org-B', KeyPair::generate(), Sign::n(1800000000000), Sign::n([['type' => 'expires', 'at' => 1800000005000]]));
        $this->assertTrue(MeshIssue::verifyTranslatedCapability($tc, Obj::of(['now' => 1800000000000]))['ok']);
        $this->assertTrue(MeshIssue::verifyTranslatedCapability($tc, Obj::of(['now' => 1800000005000]))['ok']);
        foreach ([1800000005001, INF, NAN] as $now) {
            $r = MeshIssue::verifyTranslatedCapability($tc, Obj::of(['now' => $now]));
            $this->assertFalse($r['ok']);
            $this->assertSame('translated capability expired', $r['reason']);
        }
    }

    /** @return list<array{mixed}> a delegated amount or expiry that is not a finite number (the reference tests Number.isFinite, no coercion) */
    public static function notFiniteNumbers(): array
    {
        return [['10000'], [[10000]], [INF], [-INF], [NAN], [new Num('1e999')], [null], [true], [new Obj()]];
    }

    #[DataProvider('notFiniteNumbers')]
    public function testStripeSptWithinClaimsRefusesAnAmountThatIsNotAFiniteNumber(mixed $amount): void
    {
        $r = Acp::stripeSptWithinClaims(self::sptToken(), Obj::of(['amount' => $amount, 'currency' => 'USD', 'exp' => 1800000000000]));
        $this->assertFalse($r->get('ok'));
        $this->assertStringStartsWith('max_amount 10000 exceeds the delegated amount', $r->get('reason'));
    }

    #[DataProvider('notFiniteNumbers')]
    public function testStripeSptWithinClaimsRefusesAnExpiryThatIsNotAFiniteNumber(mixed $exp): void
    {
        $r = Acp::stripeSptWithinClaims(self::sptToken(), Obj::of(['amount' => 10000, 'currency' => 'USD', 'exp' => $exp]));
        $this->assertFalse($r->get('ok'));
        $this->assertSame('the token outlives the delegated payment token', $r->get('reason'));
    }

    public function testStripeSptWithinClaimsRefusesAMissingAmountOrExpiry(): void
    {
        $noAmount = Acp::stripeSptWithinClaims(self::sptToken(), Obj::of(['currency' => 'USD', 'exp' => 1800000000000]));
        $this->assertFalse($noAmount->get('ok'));
        $this->assertSame('max_amount 10000 exceeds the delegated amount undefined', $noAmount->get('reason'));
        $noExp = Acp::stripeSptWithinClaims(self::sptToken(), Obj::of(['amount' => 10000, 'currency' => 'USD']));
        $this->assertFalse($noExp->get('ok'));
        $this->assertSame('the token outlives the delegated payment token', $noExp->get('reason'));
        $ok = Acp::stripeSptWithinClaims(self::sptToken(), Obj::of(['amount' => new Num('10000'), 'currency' => 'USD', 'exp' => new Num('1800000000000')]));
        $this->assertTrue($ok->get('ok')); // a finite JSON number is still accepted
    }

    private static function sandboxTable(\Closure $clock): SandboxHandleTable
    {
        return new SandboxHandleTable('wasm', new SandboxReceiptLog(), [], $clock);
    }

    /** @return array{0: Obj, 1: Obj} [result, operation] */
    private static function sandboxOp(): array
    {
        $op = Obj::of(['verb' => 'net.ok', 'resource' => 'api.example.com', 'params' => new Obj()]);
        $result = Obj::of(['allow' => true, 'operation' => Obj::of(['verb' => 'net.ok', 'resource' => 'api.example.com',
            'params_digest' => Pca::hashCanonical($op->get('params')), 'id' => 'op'])]);
        return [$result, $op];
    }

    public function testSandboxAttenuateRefusesAnInfiniteExpiryUnderAFiniteParent(): void
    {
        [$result, $op] = self::sandboxOp();
        $t = self::sandboxTable(static fn() => 1000);
        $h = $t->mint($result, $op, Obj::of(['expiresAt' => 5000]));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('attenuate_widens'); // +Infinity read as 0 and so looked narrower than the parent
        $t->attenuate($h, Obj::of(['expiresAt' => new Num('1e999')]));
    }

    public function testSandboxAttenuateKeepsAnInfiniteExpiryUnderAnUnboundedParent(): void
    {
        [$result, $op] = self::sandboxOp();
        $t = self::sandboxTable(static fn() => 1000);
        $h = $t->mint($result, $op);
        $child = $t->attenuate($h, Obj::of(['expiresAt' => new Num('1e999')]));
        $this->assertSame($child + 1, $t->attenuate($child)); // the child is live: its expiry is Infinity, not 0
    }

    #[DataProvider('nonFinite')]
    public function testSandboxHandleIsNotLiveOnANonFiniteClock(float $now): void
    {
        [$result, $op] = self::sandboxOp();
        $t = self::sandboxTable(static fn() => $now);
        $h = $t->mint($result, $op, Obj::of(['expiresAt' => 5000]));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('unknown_handle'); // a non-finite clock read as epoch 0, inside every window
        $t->attenuate($h);
    }

    public function testAdmissionRegistryRefusesAnInfiniteClockAndKeepsAnUnboundedAdmission(): void
    {
        $reg = new AdmissionRegistry();
        $bp = Obj::of(['key' => 'k', 'epoch' => 1]);
        $reg->admit('i', $bp, 1000);
        $reg->admit('u', $bp, new Num('1e999'));
        $this->assertFalse($reg->checker(new Num('1e999'))('i', $bp));
        $this->assertFalse($reg->checker(new Num('1e999'))('u', $bp));
        $this->assertFalse($reg->checker(null)('u', $bp));
        $this->assertTrue($reg->checker(5)('u', $bp)); // +Infinity until is a legitimate unbounded admission
        $this->assertTrue($reg->checker(999)('i', $bp));
        $this->assertFalse($reg->checker(1000)('i', $bp));
    }

    public function testReadAccumulatorWindowAndCapReadRaw(): void
    {
        $never = new WindowReadAccumulator(5, new Num('1e999')); // an infinite window never rolls: the cap holds for ever
        $this->assertTrue($never->charge('k', 3, 0));
        $this->assertFalse($never->charge('k', 3, 1_000_000_000_000)); // a window read as 0 rolled every time and reset the count
        $open = new WindowReadAccumulator(new Num('1e999'), 1000); // an infinite cap admits (the reference compares n + units <= Infinity)
        $this->assertTrue($open->charge('k', 1_000_000_000_000, 0));
        $nan = new WindowReadAccumulator('x', 1000); // a cap that is not a number admits nothing
        $this->assertFalse($nan->charge('k', 1, 0));
    }

    public function testGrantClientDoesNotFoldATokenWithANonNumberField(): void
    {
        $tok = static fn(mixed $epoch, int $rest): string => Js::stringify(Obj::of(['revocation_epoch' => $epoch, 'ledger_tree_size' => $rest,
            'budget_version' => $rest, 'policy_revision' => $rest, 'policy_digest' => 'pd']));
        $first = $tok(0, 0);
        $toks = [$first, $tok('x', 0), $tok(null, 0), $tok(1, 1)];
        $fetch = static function (array $req) use (&$toks): array {
            return ['status' => 200, 'headers' => ['Pca-Fresh-At' => array_shift($toks)], 'body' => '{"grants":[]}'];
        };
        $c = new GrantClient('https://as.example', $fetch); // unsigned: the fold is the only guard
        $c->inspect('a');
        $c->inspect('a');
        $this->assertSame($first, Js::stringify($c->freshAt())); // a field read as 0 would have replaced the token
        $c->inspect('a');
        $this->assertSame($first, Js::stringify($c->freshAt()));
        $c->inspect('a');
        $this->assertSame($tok(1, 1), Js::stringify($c->freshAt()));
    }

    private static function kp(int $b): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    private static function revocation(string $value, int $at, KeyPair $k): Obj
    {
        $o = Obj::of(['v' => new Num('1'), 'target' => 'lease', 'value' => $value, 'revoked_at' => new Num((string)$at), 'authority' => $k->public]);
        $o->set('sig', Pca::b64u($k->sign(Lease::REVOKE_DOMAIN . Json::canonicalizeStrict($o))));
        return $o;
    }

    #[DataProvider('nonFinite')]
    public function testLeasePruneKeepsRevocationsOnANonFiniteClock(float $now): void
    {
        $a = self::kp(1);
        $kv = new MemoryAtomicKv();
        $old = self::revocation('x1', 9899, $a); // 9899 + 100 < 10000: pruned by a finite clock
        $key = 'lease/16/' . KvDoc::shardOf('L1', 16);
        $kv->update($key, static fn(?string $prev): string => '{"leases":{},"revocations":[' . KvDoc::enc($old) . ']}');
        $reg = new LeaseRegistry(['authorities' => [$a->public], 'maxTtlCeiling' => 100], $kv, ['clock' => static fn(): float => $now]);
        $third = self::revocation('L1', 10000, $a);
        $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($third));
        $raw = json_decode((string)$kv->get($key), true);
        $this->assertSame([$old->get('sig'), $third->get('sig')], array_column($raw['revocations'], 'sig')); // dropped on a reading that is no time
    }

    /** @return list<array{mixed}> a pinned last revision that is not a finite number */
    public static function badLastRevisions(): array
    {
        return [[new Num('1e999')], [new Num('-1e999')], ['x'], [null], [true]];
    }

    #[DataProvider('badLastRevisions')]
    public function testVerifyBundleRefusesAPinnedLastRevisionThatIsNotFinite(mixed $lastRevision): void
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat(chr(3), 32));
        $pk = Pca::b64u(sodium_crypto_sign_publickey($kp));
        $b = Obj::of(['v' => new Num('1'), 'kind' => 'pca-policy-bundle', 'revision' => new Num('1'), 'issued_at' => new Num('100'),
            'grants' => ['g'], 'template_digests' => [], 'min_verifier_version' => '1.0']);
        $b->set('sigs', [Obj::of(['signer' => $pk, 'sig' => Pca::b64u(sodium_crypto_sign_detached(K3::BUNDLE_DOMAIN . Json::canonicalizeStrict($b), sodium_crypto_sign_secretkey($kp)))])]);
        $o = Obj::of(['signers' => [$pk], 'threshold' => new Num('1'), 'verifierVersion' => '1.0']);
        $this->assertTrue(K3::verifyBundle($b, $o)['ok']);
        $o->set('last', Obj::of(['revision' => $lastRevision, 'digest' => 'd']));
        $r = K3::verifyBundle($b, $o);
        $this->assertFalse($r['ok']); // the check was skipped, so any rollback was accepted
        $this->assertSame('rollback', $r['code']);
        $this->assertStringStartsWith('revision 1 < accepted ', $r['reason']);
    }
}
