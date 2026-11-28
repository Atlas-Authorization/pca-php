<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\A2a;
use Atlas\Pca\A2aAuthorityError;
use Atlas\Pca\Agent;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Payments;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for the A2A binding: the default verdict (pq pin, clock, plan root, audience, suites, revocation hook, params digest),
 * the shared PCActn authorization (authority, context, verify hook, required checks, reasons, result shape), chain extension and
 * per-hop delegation, the t=3 human-present co-signature, the payment-mandate binding, receipts, needs and the extended card.
 */
final class AgentSurvivorKill13A2aTest extends TestCase
{
    private static ?array $fx = null;

    /** @return array{header: string, grant: Obj, issuer: string} one signed PCActn (fresh copies are parsed from the header) */
    private static function fx(): array
    {
        if (self::$fx === null) {
            $principal = new KeyPair(str_repeat("\x01", 32));
            $key = new KeyPair(str_repeat("\x02", 32));
            $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
            $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'];
            $a = (new Agent($key, $grant, 'rs-test'))->act('refund', 'orders/1', ['amount_cents' => 500]);
            self::$fx = ['header' => $a->headers['PCA-Action'], 'grant' => $grant, 'issuer' => $principal->public];
        }
        return self::$fx;
    }

    private static function pc(): Obj
    {
        return Json::parseStrict(Pca::decodePcaHeader(self::fx()['header']));
    }

    private static function int(mixed $n): int
    {
        return $n instanceof Num ? $n->int() : (int)$n;
    }

    private static function task(mixed $p): Obj
    {
        return Obj::of(['metadata' => Obj::of([A2a::PCA_A2A_EXTENSION_URI => $p])]);
    }

    /** Options under which the fixture PCActn passes every default check. */
    private static function opts(array $set = [], ?Obj $p = null): array
    {
        $p ??= self::pc();
        $o = ['grant' => self::fx()['grant'], 'aud' => 'rs-test', 'now' => self::int($p->get('iat')),
            'context' => ['plan' => Obj::of(['root' => $p->get('plan')->get('root')]), 'planAuthorized' => true],
            'hooks' => ['revocation' => static fn(): Obj => Obj::of(['enforced' => true, 'ok' => true])]];
        foreach ($set as $k => $v) {
            if ($v === Payments::UNDEF) {
                unset($o[$k]);
            } else {
                $o[$k] = $v;
            }
        }
        return $o;
    }

    private static function verify(array $set = [], ?Obj $p = null): Obj
    {
        $p ??= self::pc();
        return self::quiet(static fn() => A2a::verifyA2ATask(self::task($p), self::opts($set, $p)));
    }

    /** Runs $f and asserts it raised no PHP warning or notice. */
    private static function quiet(callable $f): mixed
    {
        $w = [];
        set_error_handler(static function (int $no, string $msg) use (&$w): bool {
            $w[] = $msg;
            return true;
        });
        try {
            $r = $f();
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $w);
        return $r;
    }

    private static function checks(Obj $v): array
    {
        return $v->get('result')->get('checks');
    }

    // ---- the default verdict ----

    /** A fully authorized PCActn: exact result shape, every default check passing, the revocation hook's pass. */
    public function testDefaultVerdictAllows(): void
    {
        $p = self::pc();
        $v = self::verify([], $p);
        self::assertSame(['ok', 'result', 'pcActn'], $v->keys());
        self::assertTrue($v->get('ok'));
        self::assertSame($p, $v->get('pcActn'));
        self::assertSame(['allow', 'checks', 'reasons'], $v->get('result')->keys());
        self::assertTrue($v->get('result')->get('allow'));
        self::assertSame([], $v->get('result')->get('reasons'));
        $c = self::checks($v);
        self::assertSame(['pass', true, true, true], [$c['revocation'], $c['audience'], $c['plan_root_authorized'], $c['counter_format']]);
        self::assertArrayNotHasKey('pq_pin', $c);
    }

    /** Without the explicit plan authorization the plan root is not authorized, even when the plan names it. */
    public function testPlanRootNeedsExplicitAuthorization(): void
    {
        $p = self::pc();
        foreach ([false, 'yes', 1] as $flag) {
            $v = self::verify(['context' => ['plan' => Obj::of(['root' => $p->get('plan')->get('root')]), 'planAuthorized' => $flag]], $p);
            self::assertFalse($v->get('ok'));
            self::assertFalse(self::checks($v)['plan_root_authorized']);
        }
        foreach ([['plan' => ['root' => $p->get('plan')->get('root')], 'planAuthorized' => true], ['plan' => Obj::of(['root' => new Num('1')]), 'planAuthorized' => true]] as $ctx) {
            self::assertFalse(self::checks(self::verify(['context' => $ctx], $p))['plan_root_authorized']);
        }
    }

    /** `now` is floored to an integer millisecond: half a millisecond past exp is still valid; a whole one is expired, whatever the wall clock says. */
    public function testNowIsFlooredAndOverridesTheClock(): void
    {
        $p = self::pc();
        $exp = self::int($p->get('exp'));
        self::assertTrue(self::verify(['now' => $exp + 0.5], $p)->get('ok'));
        $v = self::verify(['now' => $exp + 1], $p);
        self::assertFalse($v->get('ok'));
        self::assertStringContainsString('validity: the PCActn has expired', $v->get('reason'));
    }

    /** Every core reason is carried (not only the first), joined with "; ". */
    public function testAllCoreReasonsAreJoined(): void
    {
        $p = self::pc();
        $v = self::verify(['now' => self::int($p->get('exp')) + 1, 'context' => ['planAuthorized' => false]], $p);
        $r = $v->get('reason');
        self::assertStringContainsString('validity: the PCActn has expired', $r);
        self::assertStringContainsString('plan_root_authorized: ', $r);
        self::assertStringContainsString('; ', $r);
        self::assertSame($r, implode('; ', $v->get('result')->get('reasons')));
    }

    /** A wire failure carries the core's single `reason` (it has no `reasons` list). */
    public function testWireReasonIsCarried(): void
    {
        $p = Obj::of(['cap_chain' => [Obj::of(['issuer' => 'I'])]]);
        $v = self::quiet(static fn() => A2a::verifyA2ATask(self::task($p), ['grant' => Obj::of(['g' => 1])]));
        self::assertFalse($v->get('ok'));
        self::assertStringStartsWith('wire: ', $v->get('reason'));
        self::assertSame([$v->get('reason')], $v->get('result')->get('reasons'));
        self::assertSame('not-enforced', self::checks($v)['revocation']);
    }

    /** The audience option is passed through; a non-string one is no audience. */
    public function testAudienceAndSuites(): void
    {
        $p = self::pc();
        self::assertFalse(self::checks(self::verify(['aud' => 5], $p))['audience']);
        self::assertFalse(self::verify(['allowedSuites' => ['ml-dsa-65']], $p)->get('ok'));
        self::assertTrue(self::verify(['allowedSuites' => ['ed25519']], $p)->get('ok'));
    }

    /** pq pin: a non-Ed25519 root without a stored grant is refused before verification, with an exact verdict. */
    public function testPqPinWithoutStoredGrant(): void
    {
        foreach ([[], ['requireChecks' => []]] as $extra) {
            $p = self::pc();
            $p->get('cap_chain')[0]->set('alg', 'ml-dsa-65');
            $v = self::verify(['grant' => Payments::UNDEF, 'expectedRootIssuer' => self::fx()['issuer']] + $extra, $p);
            $why = 'pq_pin: a non-Ed25519 root is admitted only under a stored grant';
            self::assertSame(['ok', 'reason', 'result', 'pcActn'], $v->keys());
            self::assertSame([false, $why], [$v->get('ok'), $v->get('reason')]);
            self::assertSame(['allow', 'checks', 'reasons', 'reason'], $v->get('result')->keys());
            self::assertSame([false, ['pq_pin' => false], [$why]], [$v->get('result')->get('allow'), self::checks($v), $v->get('result')->get('reasons')]);
        }
    }

    /** The pin applies only without a stored grant, only to a root naming a suite, and never to an explicit ed25519 root. */
    public function testPqPinScope(): void
    {
        $p = self::pc();
        $p->get('cap_chain')[0]->set('alg', 'ml-dsa-65');
        self::assertArrayNotHasKey('pq_pin', self::checks(self::verify([], $p)));
        $p = self::pc();
        $p->get('cap_chain')[0]->set('alg', 'ed25519');
        self::assertArrayNotHasKey('pq_pin', self::checks(self::verify(['grant' => Payments::UNDEF, 'expectedRootIssuer' => self::fx()['issuer']], $p)));
        $v = self::verify(['grant' => Payments::UNDEF, 'expectedRootIssuer' => self::fx()['issuer']]);
        self::assertTrue($v->get('ok'), (string)$v->get('reason'));
        self::assertTrue(self::verify(['grant' => null, 'expectedRootIssuer' => self::fx()['issuer']])->get('ok'));
    }

    /** Revocation: the hook sees {pcactn, grant, context}; its verdict, a throw and its absence each land exactly. */
    public function testRevocationHook(): void
    {
        $p = self::pc();
        $seen = null;
        $o = self::opts([], $p);
        $o['hooks'] = ['revocation' => static function (Obj $x) use (&$seen): Obj {
            $seen = $x;
            return Obj::of(['enforced' => true, 'ok' => true]);
        }];
        self::assertTrue(A2a::verifyA2ATask(self::task($p), $o)->get('ok'));
        self::assertSame(['pcactn', 'grant', 'context'], $seen->keys());
        self::assertSame([$p, self::fx()['grant']], [$seen->get('pcactn'), $seen->get('grant')]);

        $rev = static fn(mixed $f): array => ['hooks' => ['revocation' => $f]];
        $v = self::verify($rev(static fn() => throw new \RuntimeException('boom')), $p);
        self::assertSame(['fail', 'revocation hook failed: boom'], [self::checks($v)['revocation'], $v->get('reason')]);
        $v = self::verify($rev(static fn() => Obj::of(['enforced' => true, 'ok' => false, 'reason' => 'gone'])), $p);
        self::assertSame(['fail', 'gone'], [self::checks($v)['revocation'], $v->get('reason')]);
        $v = self::verify($rev(static fn() => Obj::of(['enforced' => true, 'ok' => 'x'])), $p);
        self::assertSame(['fail', 'rejected'], [self::checks($v)['revocation'], $v->get('reason')]);
        $v = self::verify($rev(static fn() => Obj::of(['enforced' => 'yes', 'ok' => false])), $p);
        self::assertSame(['not-enforced', false], [self::checks($v)['revocation'], $v->get('ok')]);
        $v = self::verify(['hooks' => Payments::UNDEF], $p);
        self::assertSame('not-enforced', self::checks($v)['revocation']);
        // a failing hook refuses even when revocation is not a required check
        $v = self::verify($rev(static fn() => Obj::of(['enforced' => true, 'ok' => false])) + ['requireChecks' => ['audience']], $p);
        self::assertSame([false, 'rejected'], [$v->get('ok'), $v->get('reason')]);
        self::assertTrue(self::verify(['requireChecks' => ['audience']], $p)->get('ok'));
    }

    /** params_digest is checked only with object params AND an object action; a params value with no canonical form is false. */
    public function testParamsDigest(): void
    {
        $p = self::pc();
        $ctx = static fn(mixed $params): array => ['context' => ['plan' => Obj::of(['root' => $p->get('plan')->get('root')]), 'planAuthorized' => true, 'params' => $params]];
        self::assertTrue(self::checks(self::verify($ctx(Sign::n(['amount_cents' => 500])), $p))['params_digest']);
        self::assertFalse(self::checks(self::verify($ctx(Sign::n(['amount_cents' => 501])), $p))['params_digest']);
        self::assertFalse(self::checks(self::verify($ctx(Obj::of(['x' => INF])), $p))['params_digest']);
        self::assertArrayNotHasKey('params_digest', self::checks(self::verify($ctx(['amount_cents' => 500]), $p)));
        $bad = Obj::of(['cap_chain' => [Obj::of(['issuer' => 'I'])], 'action' => 'x']);
        $v = self::quiet(static fn() => A2a::verifyA2ATask(self::task($bad), ['grant' => Obj::of(['g' => 1]), 'context' => ['params' => Obj::of(['a' => 1])]]));
        self::assertArrayNotHasKey('params_digest', self::checks($v));
    }

    // ---- verifyPcActn with an injected verify hook ----

    private static function hooked(mixed $verdict, array $set = [], ?Obj $p = null): Obj
    {
        $p ??= Obj::of(['cap_chain' => [Obj::of(['id' => 'a', 'issuer' => 'I'])]]);
        $o = ['grant' => Obj::of(['g' => 1]), 'verify' => static fn() => $verdict] + $set;
        return self::quiet(static fn() => A2a::verifyA2ATask(self::task($p), $o));
    }

    private static function all(mixed $v = true): array
    {
        return array_fill_keys(A2a::DEFAULT_REQUIRED_CHECKS, $v);
    }

    /** The verify hook gets (pcActn, grant, opts, context); a context closure is called once with the PCActn. */
    public function testVerifyHookArguments(): void
    {
        $p = Obj::of(['cap_chain' => [Obj::of(['id' => 'a', 'issuer' => 'I'])]]);
        $g = Obj::of(['g' => 1]);
        $ctxArgs = [];
        $args = null;
        $o = ['grant' => $g, 'requireChecks' => [], 'context' => static function ($x) use (&$ctxArgs): array {
            $ctxArgs[] = $x;
            return ['c' => 1];
        }, 'verify' => static function (...$a) use (&$args): array {
            $args = $a;
            return ['allow' => true];
        }];
        self::assertTrue(A2a::verifyA2ATask(self::task($p), $o)->get('ok'));
        self::assertSame([$p], $ctxArgs);
        self::assertSame([$p, $g, $o, ['c' => 1]], $args);
        // no context: an empty object
        unset($o['context']);
        A2a::verifyA2ATask(self::task($p), $o);
        self::assertInstanceOf(Obj::class, $args[3]);
        self::assertSame([], $args[3]->keys());
        // an array context is used as is (never called)
        $o['context'] = ['c' => 2];
        A2a::verifyA2ATask(self::task($p), $o);
        self::assertSame(['c' => 2], $args[3]);
    }

    /** The authorized result: ok, allow forced to a boolean true, no reason member. */
    public function testHookAllowShape(): void
    {
        $v = self::hooked(['allow' => 1, 'checks' => [], 'reasons' => []], ['requireChecks' => []]);
        self::assertSame(['ok', 'result', 'pcActn'], $v->keys());
        self::assertTrue($v->get('ok'));
        self::assertTrue($v->get('result')->get('allow'));
        self::assertFalse($v->get('result')->has('reason'));
    }

    /** Required checks: each must be true or 'pass'; the verdict's own allow must also hold. */
    public function testRequiredChecks(): void
    {
        $pass = self::all('pass');
        self::assertTrue(self::hooked(['allow' => true, 'checks' => self::all()])->get('ok'));
        self::assertTrue(self::hooked(['allow' => true, 'checks' => $pass])->get('ok'));
        foreach (['yes', false, 1] as $bad) {
            $c = self::all();
            $c['audience'] = $bad;
            $v = self::hooked(['allow' => true, 'checks' => $c]);
            self::assertSame(['ok', 'reason', 'result', 'pcActn'], $v->keys());
            self::assertSame([false, 'PCActn verification failed'], [$v->get('ok'), $v->get('reason')]);
            self::assertSame('PCActn verification failed', $v->get('result')->get('reason'));
            self::assertFalse($v->get('result')->get('allow'));
        }
        self::assertFalse(self::hooked(['allow' => false, 'checks' => self::all()])->get('ok'));
        self::assertFalse(self::hooked(['allow' => true, 'checks' => []], ['requireChecks' => null])->get('ok'));
        self::assertTrue(self::hooked(['allow' => true, 'checks' => ['x' => true]], ['requireChecks' => ['x']])->get('ok'));
        self::assertFalse(self::hooked(['allow' => true, 'checks' => []], ['requireChecks' => ['x']])->get('ok'));
        self::assertTrue(self::hooked(['allow' => true, 'checks' => []], ['requireChecks' => 'x'])->get('ok'));
        self::assertTrue(self::hooked(['allow' => true, 'checks' => Obj::of(['5' => true])], ['requireChecks' => [5]])->get('ok'));
    }

    /** Reasons: truthy entries only, joined with "; "; a non-list is the generic failure. */
    public function testReasons(): void
    {
        self::assertSame('a; b', self::hooked(['allow' => false, 'reasons' => ['a', '', 0, 'b']])->get('reason'));
        self::assertSame('PCActn verification failed', self::hooked(['allow' => false, 'reasons' => 'r'])->get('reason'));
    }

    /** Authority: a chain is never its own authority; a string grant is none; without an expected issuer any root issuer passes. */
    public function testAuthority(): void
    {
        $p = Obj::of(['cap_chain' => [Obj::of(['id' => 'a', 'issuer' => 'I'])]]);
        foreach (['x', 5, null] as $g) {
            try {
                A2a::verifyA2ATask(self::task($p), ['grant' => $g]);
                self::fail('no authority');
            } catch (A2aAuthorityError $e) {
                self::assertSame('pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority', $e->getMessage());
            }
        }
        $ok = ['verify' => static fn() => ['allow' => true], 'requireChecks' => []];
        self::assertTrue(A2a::verifyA2ATask(self::task($p), ['grant' => ['g' => 1]] + $ok)->get('ok'));
        self::assertTrue(A2a::verifyA2ATask(self::task($p), ['grant' => Obj::of(['g' => 1])] + $ok)->get('ok'));
        self::assertTrue(A2a::verifyA2ATask(self::task($p), ['expectedRootIssuer' => 'I'] + $ok)->get('ok'));
        self::assertSame('chain root issuer does not match the expected principal', A2a::verifyA2ATask(self::task($p), ['expectedRootIssuer' => 'J'] + $ok)->get('reason'));
    }

    /** extractPca reads a status given as a PHP array too. */
    public function testExtractPcaFromArrayStatus(): void
    {
        $p = Obj::of(['x' => 1]);
        self::assertSame($p, A2a::extractPca(['status' => ['message' => ['metadata' => Obj::of([A2a::PCA_A2A_EXTENSION_URI => $p])]]]));
        self::assertSame($p, A2a::extractPca(Obj::of(['status' => Obj::of(['message' => Obj::of(['metadata' => Obj::of([A2a::PCA_A2A_EXTENSION_URI => $p])])])])));
    }

    // ---- chain extension and delegation ----

    /** chainExtends refuses anything but two lists with its own TypeError. */
    public function testChainExtendsNeedsLists(): void
    {
        foreach ([[['a' => 1], []], [[], ['a' => 1]], ['x', []], [[], 'x']] as [$a, $b]) {
            try {
                A2a::chainExtends($a, $b);
                self::fail('not lists');
            } catch (\TypeError $e) {
                self::assertSame('chainExtends: both chains must be lists', $e->getMessage());
            }
        }
        self::assertTrue(A2a::chainExtends(['a'], ['a', 'b']));
    }

    /** checkChainExtension: the empty string and a non-list are vacuously ok; a non-empty string is hop 0 without a chain. */
    public function testCheckChainExtensionShapes(): void
    {
        self::assertSame(['ok' => true], A2a::checkChainExtension(''));
        self::assertSame(['ok' => false, 'failedHop' => 0, 'reason' => 'no_chain'], A2a::checkChainExtension('x'));
        self::assertSame(['ok' => true], A2a::checkChainExtension(['a' => 'x']));
        self::assertSame(['ok' => true], A2a::checkChainExtension(5));
    }

    private static function hop(array $caps): array
    {
        return ['task' => self::task(Obj::of(['cap_chain' => $caps])), 'opts' => ['grant' => Obj::of(['g' => 1]), 'verify' => static fn() => ['allow' => true], 'requireChecks' => []]];
    }

    /** Delegation: each hop's ids must extend the previous hop's; exact success and failure objects; an absent id reads as null. */
    /** A verify hook that rewrites the PCActn's chain after the chain check leaves that hop without a chain. */
    public function testDelegationHopWhoseChainIsRewritten(): void
    {
        $hop = ['task' => self::task(Obj::of(['cap_chain' => [Obj::of(['id' => 'a'])]])), 'opts' => ['grant' => Obj::of(['g' => 1]), 'requireChecks' => [],
            'verify' => static function (Obj $p): array {
                $p->set('cap_chain', 'x');
                return ['allow' => true];
            }]];
        $v = A2a::verifyA2ADelegation([$hop]);
        self::assertSame(['ok', 'failedHop', 'reason', 'chains'], $v->keys());
        self::assertSame([false, 0, 'no_chain', []], [$v->get('ok'), $v->get('failedHop'), $v->get('reason'), $v->get('chains')]);
    }

    public function testDelegation(): void
    {
        $a = Obj::of(['id' => 'a']);
        $b = Obj::of(['id' => 'b']);
        $v = self::quiet(static fn() => A2a::verifyA2ADelegation([self::hop([$a]), self::hop([$a, $b]), self::hop([$a, $b, Obj::of(['id' => 'c'])])]));
        self::assertSame(['ok', 'chains'], $v->keys());
        self::assertSame([true, [['a'], ['a', 'b'], ['a', 'b', 'c']]], [$v->get('ok'), $v->get('chains')]);
        $v = self::quiet(static fn() => A2a::verifyA2ADelegation([self::hop([$a]), self::hop([Obj::of(['id' => 'x'])])]));
        self::assertSame(['ok', 'failedHop', 'reason', 'chains'], $v->keys());
        self::assertSame([false, 1, 'chain_does_not_extend_previous_hop', [['a']]], [$v->get('ok'), $v->get('failedHop'), $v->get('reason'), $v->get('chains')]);
        self::assertSame([[null]], A2a::verifyA2ADelegation([self::hop([Obj::of(['x' => 1])])])->get('chains'));
        $v = A2a::verifyA2ADelegation('x');
        self::assertSame([['ok', 'chains'], true, []], [$v->keys(), $v->get('ok'), $v->get('chains')]);
        try {
            A2a::verifyA2ADelegation(null);
            self::fail('null hops');
        } catch (\TypeError $e) {
            self::assertSame("Cannot read properties of null (reading 'length')", $e->getMessage());
        }
    }

    // ---- human present and the payment mandate ----

    /** @return array{0: Obj, 1: list<Obj>} a PCActn carrying three valid t=3 shares, and its signer set */
    private static function coSigned(?callable $shape = null): array
    {
        $p = Obj::of(['ver' => new Num('2'), 'aud' => 'rs', 'cap_chain' => [Obj::of(['id' => 'a', 'issuer' => 'I', 'holder' => 'H'])],
            'action' => Obj::of(['verb' => 'pay', 'resource' => 'r', 'params_digest' => 'pd']), 'grant_ref' => 'g']);
        $keys = ['agent' => new KeyPair(str_repeat("\x05", 32)), 'guardian' => new KeyPair(str_repeat("\x06", 32)), 'principal' => new KeyPair(str_repeat("\x07", 32))];
        $set = [];
        foreach ($keys as $role => $k) {
            $set[] = Obj::of(['role' => $role, 'publicKey' => $k->public]);
        }
        $msg = Pca::thresholdMessage($p);
        $shares = [];
        foreach ($keys as $role => $k) {
            $shares[] = SignersMore::signThresholdShare($role, $k, $msg, $set, 3);
        }
        $p->set('threshold', Obj::of(['shares' => $shape === null ? $shares : $shape($shares)]));
        return [$p, $set];
    }

    private static function hp(Obj $p, mixed $set): mixed
    {
        return self::quiet(static fn() => A2a::a2aPaymentMandateFromPca($p, ['issuerPublic' => 'i', 'amount' => ['value' => 1], 'humanSignerSet' => $set, 'now' => 0])
            ->get('credentialSubject')->get('human_present'));
    }

    /** human_present is true only for three verified shares (agent, guardian, principal) under a three-role signer set. */
    public function testHumanPresent(): void
    {
        [$p, $set] = self::coSigned();
        self::assertTrue(self::hp($p, $set));
        self::assertTrue(self::hp(self::coSigned(static fn(array $s): array => ['x', ...$s])[0], $set));
        self::assertFalse(self::hp(self::coSigned(static fn(array $s): array => array_slice($s, 0, 2))[0], $set));
        self::assertFalse(self::hp(self::coSigned(static fn(array $s): array => 'x')[0], $set));
        self::assertFalse(self::hp($p, [...$set, Obj::of(['role' => 'x', 'publicKey' => 'k'])]));
        self::assertFalse(self::hp($p, array_slice($set, 0, 2)));
        self::assertFalse(self::hp($p, [$set[0], $set[1], $set[1]]));
        self::assertFalse(self::hp($p, ['agent' => $set[0]]));
        self::assertFalse(A2a::a2aPaymentMandateFromPca($p, ['issuerPublic' => 'i', 'amount' => ['value' => 1], 'now' => 0])->get('credentialSubject')->get('human_present'));
    }

    private static function mandateFor(mixed $p, array $extra = []): mixed
    {
        return A2a::a2aPaymentMandateFromPca($p, ['amount' => ['value' => 5, 'currency' => 'USD'], 'merchant' => 'm', 'now' => 0] + $extra);
    }

    private static function mandateOpts(mixed $pd, int &$calls, array $extra = []): array
    {
        return ['grant' => Obj::of(['g' => 1]), 'requireChecks' => [], 'verify' => static fn() => ['allow' => true, 'checks' => ['params_digest' => $pd]],
            'context' => static function () use (&$calls): array {
                $calls++;
                return ['params' => ['amount' => 5, 'currency' => 'USD', 'merchant' => 'm']];
            }] + $extra;
    }

    /** The mandate path resolves the context once, always requires params_digest, and backs human_present by the co-signature. */
    public function testMandateVerification(): void
    {
        [$p, $set] = self::coSigned();
        $calls = 0;
        $v = A2a::verifyA2APaymentMandate(self::mandateFor($p), $p, self::mandateOpts(true, $calls));
        self::assertTrue($v->get('ok'), (string)$v->get('reason'));
        self::assertSame(1, $calls);
        self::assertFalse(A2a::verifyA2APaymentMandate(self::mandateFor($p), $p, self::mandateOpts(false, $calls))->get('ok'));
        $hp = ['humanSignerSet' => $set];
        $m = self::mandateFor($p, $hp);
        self::assertTrue($m->get('credentialSubject')->get('human_present'));
        self::assertTrue(A2a::verifyA2APaymentMandate($m, $p, self::mandateOpts(true, $calls, $hp))->get('ok'));
        self::assertSame('payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)',
            A2a::verifyA2APaymentMandate($m, $p, self::mandateOpts(true, $calls))->get('reason'));
    }

    /** A mandate over a PCActn given as a PHP array reaches the default verdict (whose root is then not an object). */
    public function testMandateOverArrayPcActn(): void
    {
        $p = ['cap_chain' => [['issuer' => 'I', 'holder' => 'H', 'alg' => 'ml-dsa-65']], 'aud' => 'a', 'action' => ['verb' => 'v', 'resource' => 'r', 'params_digest' => 'pd'], 'grant_ref' => 'g'];
        $v = A2a::verifyA2APaymentMandate(self::mandateFor($p), $p, ['expectedRootIssuer' => 'I', 'context' => ['params' => ['amount' => 5, 'currency' => 'USD', 'merchant' => 'm']]]);
        self::assertFalse($v->get('ok'));
        self::assertStringStartsWith('wire: ', $v->get('reason'));
    }

    /** Mandate refusals before the PCActn verifier, with their exact texts. */
    public function testMandateRefusals(): void
    {
        $o = ['grant' => Obj::of(['g' => 1])];
        $v = A2a::verifyA2APaymentMandate(['credentialSubject' => ['x_pca' => ['pcactn_digest' => Payments::hash('x')]]], 'x', $o);
        self::assertSame(['ok', 'reason'], $v->keys());
        self::assertSame([false, 'PCActn is not an object'], [$v->get('ok'), $v->get('reason')]);
        self::assertSame("malformed payment mandate or PCActn: Cannot read properties of null (reading 'credentialSubject')",
            A2a::verifyA2APaymentMandate(null, 'x', $o)->get('reason'));
        $p = Obj::of(['aud' => new Num('5'), 'cap_chain' => [Obj::of(['issuer' => 'I'])]]);
        $m = ['credentialSubject' => ['x_pca' => ['pcactn_digest' => Payments::hash($p), 'aud' => new Num('5')]]];
        self::assertSame("payment mandate x_pca.aud is not the PCActn's", A2a::verifyA2APaymentMandate($m, $p, $o + ['context' => ['params' => ['a' => 1]]])->get('reason'));
        self::assertSame('context.params (the PCActn params plaintext) is required to bind the payment mandate',
            A2a::verifyA2APaymentMandate($m, $p, $o + ['context' => static fn() => 'x'])->get('reason'));
        self::assertSame("payment mandate x_pca.aud is not the PCActn's",
            A2a::verifyA2APaymentMandate($m, $p, $o + ['context' => static fn() => ['params' => ['a' => 1]]])->get('reason'));
        // a cap_chain that is not a list has no leaf (it is never indexed)
        $p = Obj::of(['aud' => 'a', 'cap_chain' => 'x']);
        $m = ['credentialSubject' => ['x_pca' => ['pcactn_digest' => Payments::hash($p), 'aud' => 'a']]];
        self::assertSame("payment mandate x_pca.verb is not the PCActn's", A2a::verifyA2APaymentMandate($m, $p, $o + ['context' => ['params' => ['a' => 1]]])->get('reason'));
    }

    // ---- receipts ----

    /** A receipt with the next seq but a prev digest of another receipt is a broken link. */
    public function testReceiptLinkNeedsTheDigest(): void
    {
        $sk = str_repeat("\x08", 32);
        $base = ['taskId' => 't', 'state' => 'TASK_STATE_WORKING', 'chainIds' => ['a']];
        $r0 = A2a::signTaskReceipt($sk, $base + ['issuedAt' => 1]);
        $other = A2a::signTaskReceipt($sk, $base + ['issuedAt' => 2]);
        $r1 = A2a::signTaskReceipt($sk, $base + ['issuedAt' => 3, 'prev' => $other]);
        $o = ['signer' => $r0->get('signer'), 'taskId' => 't', 'chainIds' => ['a']];
        $v = A2a::checkReceiptChainOf([$r0, $r1], $o);
        self::assertSame([false, 'broken_link', 1], [$v->get('ok'), $v->get('code'), $v->get('at')]);
        self::assertTrue(A2a::checkReceiptChainOf([$r0, A2a::signTaskReceipt($sk, $base + ['issuedAt' => 3, 'prev' => $r0])], $o)->get('ok'));
    }

    // ---- needs, AUTH_REQUIRED ----

    private static function need(array $set = []): Obj
    {
        $x = Obj::of(['v' => new Num('1'), 'kind' => 'scope', 'verb' => 'read', 'resource' => '/r']);
        foreach ($set as $k => $v) {
            $x->set($k, $v);
        }
        return $x;
    }

    /** The encoded need may be exactly 2048 characters; one byte more is refused. */
    public function testEncodedNeedLimit(): void
    {
        $sc = static fn(int $last): array => [...array_fill(0, 6, str_repeat('a', 128)), str_repeat('b', $last)];
        $need = static fn(int $last): Obj => self::need(['verb' => str_repeat('v', 128), 'resource' => str_repeat('r', 512), 'scopes' => $sc($last)]);
        self::assertSame(2048, strlen(A2a::encodePcaNeed($need(50))));
        try {
            A2a::encodePcaNeed($need(51));
            self::fail('over-long need');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('encodePcaNeed: the need is too large for a header', $e->getMessage());
        }
    }

    /** The status timestamp maps null and false to 0 ms and true to 1 ms (new Date semantics). */
    public function testAuthRequiredTimestamp(): void
    {
        $ts = static fn(mixed $now): string => A2a::authRequiredStatus(self::need(), ['messageId' => 'm', 'now' => $now])->get('timestamp');
        self::assertSame(['1970-01-01T00:00:00.000Z', '1970-01-01T00:00:00.000Z', '1970-01-01T00:00:00.001Z'], [$ts(null), $ts(false), $ts(true)]);
    }

    /** A null proofAction is the reference's TypeError. */
    public function testResumeGateNullProof(): void
    {
        $need = self::need();
        try {
            A2a::resumeGateObj(['state' => A2a::TASK_STATE_AUTH_REQUIRED, 'needEncoded' => A2a::encodePcaNeed($need), 'answerNeedDigest' => A2a::needDigest($need), 'proofAction' => null]);
            self::fail('null proof');
        } catch (\TypeError $e) {
            self::assertSame("Cannot read properties of null (reading 'verb')", $e->getMessage());
        }
    }

    /** A resumed task returns exactly {ok: true, verification}. */
    public function testResumeAuthRequiredSuccess(): void
    {
        $need = self::need();
        $p = Obj::of(['cap_chain' => [Obj::of(['id' => 'a'])], 'action' => Obj::of(['verb' => 'read', 'resource' => '/r'])]);
        $task = Obj::of(['id' => 't', 'status' => A2a::authRequiredStatus($need, ['messageId' => 'm', 'now' => 0])]);
        $answer = A2a::answerMessage($need, $p, 'a1');
        $v = A2a::resumeAuthRequired($task, $answer, ['grant' => Obj::of(['g' => 1]), 'verify' => static fn() => ['allow' => true], 'requireChecks' => []]);
        self::assertSame(['ok', 'verification'], $v->keys());
        self::assertTrue($v->get('ok'));
        self::assertTrue($v->get('verification')->get('ok'));
    }

    // ---- extension declaration ----

    private static function ext(mixed $params): Obj
    {
        return A2a::readPcaExtension(Obj::of(['capabilities' => Obj::of(['extensions' => [Obj::of(['uri' => A2a::PCA_A2A_EXTENSION_URI, 'params' => $params])]])]));
    }

    /** Params limits at their edges: 16 suites, a 64-unit suite, a 128-unit policy digest; params may be a PHP array. */
    public function testExtensionParamLimits(): void
    {
        self::assertTrue(self::ext(Obj::of(['aud' => 'a', 'suites' => array_fill(0, 16, 's')]))->get('ok'));
        self::assertFalse(self::ext(Obj::of(['aud' => 'a', 'suites' => array_fill(0, 17, 's')]))->get('ok'));
        self::assertTrue(self::ext(Obj::of(['aud' => 'a', 'suites' => [str_repeat('s', 64)]]))->get('ok'));
        self::assertTrue(self::ext(Obj::of(['aud' => 'a', 'policy_digest' => str_repeat('d', 128)]))->get('ok'));
        self::assertTrue(self::ext(Obj::of(['aud' => 'a', 'policy_digest' => 'd']))->get('ok'));
        self::assertTrue(self::ext(['aud' => 'a', 'suites' => ['s']])->get('ok'));
        self::assertSame('bad_params', self::ext(['aud' => 'a', 5 => 'x'])->get('code'));
    }

    // ---- extended Agent Card ----

    private static function extended(array $envs, array $o = []): Obj
    {
        return A2a::extendedAgentCard(Obj::of(['name' => 'c']), ['authenticated' => true, 'envelopes' => $envs, 'hiddenSkills' => []] + $o);
    }

    /** Policy digests compare like a JavaScript Set: numbers by value (0 == -0), strings apart from numbers, an object by identity. */
    public function testPolicyDigestSetSemantics(): void
    {
        $env = static fn(mixed $d): array => ['policyDigest' => $d, 'verb' => 'v'];
        // two equal but distinct objects (or arrays: each is a fresh JS object) are two Set members
        foreach ([[1, 2], [0, 1], ['d1', 1], ['n', null], ['u', Payments::UNDEF], [Obj::of(['x' => 1]), Obj::of(['x' => 1])], [[1], [1]]] as [$a, $b]) {
            try {
                self::extended([$env($a), $env($b)]);
                self::fail('different policies');
            } catch (\RangeException $e) {
                self::assertSame('extendedAgentCard: envelopes were computed against different policies', $e->getMessage());
            }
        }
        self::assertInstanceOf(Obj::class, self::extended([$env(0), $env(-0.0)]));
        self::assertInstanceOf(Obj::class, self::extended([$env([1])]));
        // ONE policy object shared by both envelopes is one Set member, and it is the digest recorded
        $d = Obj::of(['x' => 1]);
        $card = Obj::of(['capabilities' => Obj::of(['extensions' => [Obj::of(['uri' => A2a::PCA_A2A_EXTENSION_URI, 'params' => Obj::of(['aud' => 'a'])])]])]);
        $out = A2a::extendedAgentCard($card, ['authenticated' => true, 'hiddenSkills' => [], 'envelopes' => [$env($d), ['policyDigest' => $d, 'verb' => 'w']]]);
        self::assertSame($d, $out->get('capabilities')->get('extensions')[0]->get('params')->get('policy_digest'));
        try {
            A2a::extendedAgentCard(Obj::of([]), ['authenticated' => true, 'envelopes' => 'x']);
            self::fail('envelopes');
        } catch (\TypeError $e) {
            self::assertSame('o.envelopes.map is not a function', $e->getMessage());
        }
    }

    /** Of two SameValueZero-equal digests the FIRST is recorded (0, not -0). */
    public function testFirstPolicyDigestIsRecorded(): void
    {
        $card = Obj::of(['capabilities' => Obj::of(['extensions' => [Obj::of(['uri' => A2a::PCA_A2A_EXTENSION_URI, 'params' => Obj::of(['aud' => 'a'])])]])]);
        $out = A2a::extendedAgentCard($card, ['authenticated' => true, 'hiddenSkills' => [],
            'envelopes' => [['policyDigest' => 0, 'verb' => 'v'], ['policyDigest' => -0.0, 'verb' => 'w']]]);
        self::assertSame(0, $out->get('capabilities')->get('extensions')[0]->get('params')->get('policy_digest'));
    }

    /** Hidden skills: a string spreads into characters, anything else non-iterable throws; a verbOf closure picks the verb. */
    public function testHiddenSkills(): void
    {
        self::assertSame([], self::extended([], ['hiddenSkills' => 'ab'])->get('skills'));
        try {
            self::extended([], ['hiddenSkills' => 5]);
            self::fail('not iterable');
        } catch (\TypeError $e) {
            self::assertSame('o.hiddenSkills is not iterable', $e->getMessage());
        }
        $card = self::extended([['verb' => 'v', 'status' => 'autonomous']], ['hiddenSkills' => [Obj::of(['id' => 's'])], 'verbOf' => static fn($s) => 'v']);
        self::assertSame(['pca:autonomous'], $card->get('skills')[0]->get('tags'));
    }
}
