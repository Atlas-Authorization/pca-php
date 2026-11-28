<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AgentNative;
use Atlas\Pca\Authorize;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for the agent-native surface: signed caution claims forged byte-for-byte (bounds, reason, smuggled keys, a claim that
 * cannot be canonicalized), rationale commitments, tool_schema building and evaluation, the envelope introspection (hints, scopes,
 * resource intersection, malformed caveats, the PQ root pin) and its pre-flights, and the authority lease.
 */
final class ProtoSurvivorKill17AgentNativeTest extends TestCase
{
    private static function kp(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/k17-' . $label, true));
    }

    private static function priv(string $name): \ReflectionMethod
    {
        return new \ReflectionMethod(AgentNative::class, $name);
    }

    /** A caution claim over exactly these members, signed by $kp the way the verifier rebuilds the message. */
    private static function claim(KeyPair $kp, array $members): Obj
    {
        $body = Obj::of(['action_digest' => 'ad', 'holder' => $kp->public] + $members);
        $sig = Pca::b64u($kp->sign(Json::canonicalizeNative(Obj::of(['d' => SignersMore::CAUTION_DOMAIN, 'b' => $body]))));
        $c = $body->without();
        $c->set('sig', $sig);
        return $c;
    }

    /** @param list<mixed> $envCaveats */
    private static function grant(array $envCaveats = []): Obj
    {
        return Sign::mintGrant(self::kp('principal'), self::kp('agent')->public, ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']],
            'caveats' => $envCaveats, 'risk_policy' => Sign::defaultRiskPolicy()], 'refund an order', 'c2FsdA')['grant'];
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'no exception';
    }

    /** A JSON-number declaration counts: max(0.5, 0.2) is 0.5. */
    public function testCombineCautionReadsANum(): void
    {
        $this->assertSame(0.5, AgentNative::combineCaution(new Num('0.5'), 0.2));
        $this->assertSame(0.7, AgentNative::combineCaution(0.3, 0.7));
    }

    /** Caution bounds are inclusive [0, 1]; a non-number or a negative caution is refused even when correctly signed. */
    public function testCautionBounds(): void
    {
        $kp = self::kp('holder');
        $this->assertTrue(AgentNative::verifyCaution(self::claim($kp, ['caution' => 1])));
        $this->assertTrue(AgentNative::verifyCaution(self::claim($kp, ['caution' => 0])));
        $this->assertTrue(AgentNative::verifyCaution(self::claim($kp, ['caution' => new Num('0.25')]), 'ad', $kp->public));
        $this->assertFalse(AgentNative::verifyCaution(self::claim($kp, ['caution' => 'x'])));
        $this->assertFalse(AgentNative::verifyCaution(self::claim($kp, ['caution' => new Num('-0.5')])));
        $this->assertFalse(AgentNative::verifyCaution(self::claim($kp, ['caution' => new Num('1.5')])));
    }

    /** The reason is at most 64 UTF-16 units of the token alphabet; a smuggled member fails a correct signature. */
    public function testCautionReasonAndClosedShape(): void
    {
        $kp = self::kp('holder');
        $this->assertTrue(AgentNative::verifyCaution(self::claim($kp, ['caution' => 0, 'reason' => str_repeat('a', 64)])));
        $this->assertFalse(AgentNative::verifyCaution(self::claim($kp, ['caution' => 0, 'reason' => str_repeat('a', 65)])));
        $this->assertFalse(AgentNative::verifyCaution(self::claim($kp, ['caution' => 0, 'reason' => 'a b'])));
        $this->assertFalse(AgentNative::verifyCaution(self::claim($kp, ['caution' => 0, 'extra' => 'x'])));
    }

    /** A claim whose caution cannot be canonicalized (exponent form) is refused, not accepted by the error path. */
    public function testUncanonicalizableClaimIsRefused(): void
    {
        $kp = self::kp('holder');
        $c = Obj::of(['action_digest' => 'ad', 'holder' => $kp->public, 'caution' => new Num('5e-1'), 'sig' => 'AAAA']);
        $this->assertFalse(AgentNative::verifyCaution($c));
    }

    /** A non-array grid is the empty grid: ok. */
    public function testMonotoneCheckOnANonArray(): void
    {
        $this->assertTrue(AgentNative::checkCautionMonotone('x')->get('ok'));
    }

    /** A salt of exactly 256 characters is still in range. */
    public function testSaltLengthCeiling(): void
    {
        $b = implode('', array_map('chr', range(0, 191)));
        $salt = Pca::b64u($b);
        $this->assertSame(256, strlen($salt));
        $this->assertTrue(AgentNative::isStrongSalt($salt));
        $this->assertFalse(AgentNative::isStrongSalt($salt . 'A'));
    }

    /** bindRationale: a 32-byte default salt, and the exact refusal texts. */
    public function testBindRationale(): void
    {
        $this->assertSame(43, strlen(AgentNative::bindRationale('act', 'why')->get('reveal')->get('salt')));
        $this->assertSame('InvalidArgumentException: bindRationale: rationale must be a string', self::thrown(static fn() => AgentNative::bindRationale('act', 5, 'x')));
        $this->assertSame('InvalidArgumentException: bindRationale: salt must be b64u of >=16 bytes with >=8 distinct values',
            self::thrown(static fn() => AgentNative::bindRationale('act', 'why', 'AAAA')));
    }

    /** An over-long rationale does not open even a commitment that matches it; 8192 units does. */
    public function testOverlongRationaleNeverOpens(): void
    {
        $salt = Pca::b64u(implode('', array_map('chr', range(0, 31))));
        $cd = self::priv('commitDigest');
        foreach ([8192 => true, 8193 => false] as $len => $want) {
            $r = str_repeat('a', $len);
            $commitment = Obj::of(['v' => 1, 'action_digest' => 'ad', 'commitment' => $cd->invoke(null, 'ad', $salt, $r)]);
            $this->assertSame($want, AgentNative::verifyRationale($commitment, Obj::of(['rationale' => $r, 'salt' => $salt])), "len $len");
        }
    }

    /** A signature with no tool name (a number, an object without `name`) is refused for that reason. */
    public function testToolSchemaCaveatNeedsAName(): void
    {
        $msg = 'InvalidArgumentException: toolSchemaCaveat: tool name required';
        $this->assertSame($msg, self::thrown(static fn() => AgentNative::toolSchemaCaveat(5, null)));
        $this->assertSame($msg, self::thrown(static fn() => AgentNative::toolSchemaCaveat(new Obj(), null)));
    }

    /** The evaluator hook takes only an object toolCall. */
    public function testToolSchemaEvaluatorNeedsAnObjectCall(): void
    {
        $cv = AgentNative::toolSchemaCaveat('refund', Obj::of(['props' => new Obj()]));
        $this->assertTrue(AgentNative::toolSchemaEvaluator($cv, Obj::of(['toolCall' => Obj::of(['tool' => 'refund', 'args' => new Obj()])])));
        $this->assertFalse(AgentNative::toolSchemaEvaluator($cv, Obj::of(['toolCall' => ['tool' => 'refund', 'args' => new Obj()]])));
    }

    /** predicatesCaveat: the canonical (sorted) form, and a value JSON cannot carry is refused with its type. */
    public function testPredicatesCaveatCanonicalForm(): void
    {
        $c = AgentNative::predicatesCaveat(Obj::of(['b' => 1, 'a' => 2]));
        $this->assertSame(['a', 'b'], $c->get('allow')->keys());
        try {
            AgentNative::predicatesCaveat(new \stdClass());
            $this->fail('expected a refusal');
        } catch (JsonError $e) {
            $this->assertSame('canonicalize: unsupported type stdClass', $e->getMessage());
        }
    }

    /** A predicates caveat none of whose predicates match is unsatisfied. */
    public function testPredicatesEvaluatorNoMatch(): void
    {
        $cv = Obj::of(['type' => 'predicates', 'allow' => [Obj::of(['verb' => 'refund', 'resource' => 'orders/*'])]]);
        $act = Obj::of(['action' => Obj::of(['verb' => 'delete', 'resource' => 'users/1']), 'verb' => 'delete', 'resource' => 'users/1']);
        $this->assertFalse(AgentNative::agentNativeCaveatEvaluator($cv, Obj::of(['action' => $act])));
    }

    /** Resource-pattern intersection: regex undecidable, prefixes nest or are disjoint, literals must sit under a prefix. */
    public function testInterRes(): void
    {
        $m = self::priv('interRes');
        $cases = [
            [['re:a', 'b'], false], [['a*', 'b'], null], [['x', 'y'], null], [['ab*', 'a*'], 'ab*'], [['ab*', 'ac*'], null],
            [['abc*', 'ab*'], 'abc*'], [['a*', 'ab*'], 'ab*'], [['ab*', 'ac'], null], [['ab*', 'abc'], 'abc'], [['abc', 'ab*'], 'abc'],
            [['ac', 'ab*'], null], [['bx', 'ab*'], null], [['*', 'q'], 'q'], [['q', '*'], 'q'], [['q', 'q'], 'q'],
        ];
        foreach ($cases as [[$a, $b], $want]) {
            $this->assertSame($want, $m->invoke(null, $a, $b), "$a ^ $b");
        }
    }

    /** Collapsing a conjunction: any disjoint pair empties it, regexes are kept sorted, '*' drops out. */
    public function testCollapseResources(): void
    {
        $m = self::priv('collapseResources');
        $this->assertNull($m->invoke(null, ['re:x', 'a', 'b']));
        $this->assertSame(['re:a', 're:b'], $m->invoke(null, ['re:b', 're:a']));
        $this->assertSame(['re:a'], $m->invoke(null, ['*', 're:a']));
        $this->assertSame(['re:a'], $m->invoke(null, ['re:a']));
        $this->assertSame(['*'], $m->invoke(null, ['*']));
    }

    /** A predicate as a scope: verbs sorted and unique; non-string verbs, a non-string resource and a non-object are malformed. */
    public function testScopeOfPredicate(): void
    {
        $m = self::priv('scopeOfPredicate');
        $s = $m->invoke(null, Obj::of(['verb' => ['b', 'a', 'b']]));
        $this->assertSame(['a', 'b'], $s->get('verbs'));
        $this->assertSame(['*'], $s->get('resources'));
        $this->assertSame([], $s->get('where'));
        $this->assertSame(['a'], $m->invoke(null, Obj::of(['verb' => ['a']]))->get('verbs'));
        $this->assertNull($m->invoke(null, 'x'));
        $this->assertNull($m->invoke(null, Obj::of(['verb' => ['a', 5]])));
        $this->assertNull($m->invoke(null, Obj::of(['verb' => 'a', 'resource' => 5])));
    }

    private static function scope(array $verbs, array $res): Obj
    {
        return Obj::of(['verbs' => $verbs, 'resources' => $res, 'where' => []]);
    }

    /** Scope intersection skips empty pairs and keeps going, and its output order does not depend on the input order. */
    public function testIntersectScopes(): void
    {
        $m = self::priv('intersectScopes');
        $r = $m->invoke(null, [self::scope(['a'], ['*'])], [self::scope(['b'], ['*']), self::scope(['a'], ['*'])]);
        $this->assertCount(1, $r);
        $this->assertSame(['a'], $r[0]->get('verbs'));
        $r = $m->invoke(null, [self::scope(['a'], ['p'])], [self::scope(['a'], ['q']), self::scope(['a'], ['p'])]);
        $this->assertCount(1, $r);
        $this->assertSame(['p'], $r[0]->get('resources'));
        $all = [self::scope(['*'], ['*'])];
        $verbsOf = static fn(array $xs): array => array_map(static fn(Obj $s): array => $s->get('verbs'), $xs);
        $one = $verbsOf($m->invoke(null, [self::scope(['a'], ['*']), self::scope(['b'], ['*'])], $all));
        $two = $verbsOf($m->invoke(null, [self::scope(['b'], ['*']), self::scope(['a'], ['*'])], $all));
        $this->assertCount(2, $one);
        $this->assertSame($one, $two);
    }

    /** Well-formedness: rate needs max, a zero budget_alloc / max_spend is a legitimate (empty) ceiling, a missing one is not. */
    public function testWellFormedCaveat(): void
    {
        $m = self::priv('wellFormedCaveat');
        $this->assertFalse($m->invoke(null, Obj::of(['type' => 'rate', 'per_secs' => 5])));
        $this->assertTrue($m->invoke(null, Obj::of(['type' => 'rate', 'max' => 1, 'per_secs' => 5])));
        $this->assertTrue($m->invoke(null, Obj::of(['type' => 'budget_alloc', 'limit' => 0])));
        $this->assertFalse($m->invoke(null, Obj::of(['type' => 'budget_alloc'])));
        $this->assertTrue($m->invoke(null, Obj::of(['type' => 'max_spend', 'usd' => 0])));
    }

    /** Envelope hints are the tightest bound over every caveat: earliest expiry, latest not-before, smallest allocation and spend cap. */
    public function testEnvelopeHintsTakeTheTightestBound(): void
    {
        $g = self::grant([['type' => 'expires', 'at' => 50], ['type' => 'expires', 'at' => 100], ['type' => 'not_before', 'at' => 100],
            ['type' => 'not_before', 'at' => 50], ['type' => 'budget_alloc', 'limit' => 5], ['type' => 'budget_alloc', 'limit' => 10],
            ['type' => 'max_spend', 'usd' => 5], ['type' => 'max_spend', 'usd' => 10]]);
        $env = AgentNative::describeEnvelope([$g]);
        $this->assertTrue($env->get('ok'), (string)$env->get('reason'));
        $this->assertSame([], $env->get('unsatisfiable'));
        $h = $env->get('remainingBudgetHints');
        $this->assertSame(50.0, $h->get('expiresAt'));
        $this->assertSame(100.0, $h->get('notBefore'));
        $this->assertSame(5.0, $h->get('budgetAlloc'));
        $this->assertSame(5.0, $h->get('maxSpendUsd'));
    }

    /** A plain grant is fully satisfiable (its own envelope caveat is not a nested one). */
    public function testPlainGrantIsSatisfiable(): void
    {
        $env = AgentNative::describeEnvelope([self::grant()]);
        $this->assertTrue($env->get('ok'), (string)$env->get('reason'));
        $this->assertTrue($env->get('hasEnvelope'));
        $this->assertSame([], $env->get('unsatisfiable'));
        $this->assertSame(['refund'], $env->get('verbs'));
        $this->assertSame(['orders/*'], $env->get('resources'));
    }

    /** A non-object or untyped envelope caveat is '<malformed>'; an unknown string type is named (as a string). */
    public function testMalformedEnvelopeCaveats(): void
    {
        foreach ([['x'], [['type' => 5]]] as $i => $cvs) {
            $env = AgentNative::describeEnvelope([self::grant($cvs)]);
            $this->assertSame(['<malformed>'], $env->get('unsatisfiable'), "case $i");
            $this->assertSame('unsatisfiable caveat(s): <malformed>', $env->get('reason'));
        }
        $env = AgentNative::describeEnvelope([self::grant([['type' => '5']])]);
        $this->assertSame(['5'], $env->get('unsatisfiable'));
    }

    /** A PQ root needs a pin: the stored grant (policy.trustedRoot, an object) is one; anything else leaves the pin refusal. */
    public function testPqRootPinThroughTrustedRoot(): void
    {
        $root = Obj::of(['id' => 'i', 'issuer' => 'iss', 'holder' => 'h', 'body_digest' => 'b', 'sig' => 's', 'alg' => 'ml-dsa-65',
            'pq_pk' => 'pk', 'caveats' => []]);
        $pin = sprintf(Pca::ROOT_PQ_PIN_REASON, 'ml-dsa-65');
        $this->assertSame($pin, AgentNative::describeEnvelope([$root])->get('reason'));
        $this->assertSame($pin, AgentNative::describeEnvelope([$root], null, null, Obj::of(['trustedRoot' => 'x']))->get('reason'));
        $env = AgentNative::describeEnvelope([$root], null, null, Obj::of(['trustedRoot' => $root]));
        $this->assertFalse($env->get('ok'));
        $this->assertIsString($env->get('reason'));
        $this->assertNotSame($pin, $env->get('reason'));
        $this->assertNotSame('introspection error (fail closed)', $env->get('reason'));
    }

    private static function env(mixed $ok, ?Obj $hints = null): Obj
    {
        return Obj::of(['ok' => $ok, 'unsatisfiable' => [], 'scopes' => null, 'remainingBudgetHints' => $hints ?? new Obj()]);
    }

    /** `ok` is read with JavaScript truthiness: 0, -0, NaN, '' and false are falsy; any other number is truthy. */
    public function testEnvelopeOkTruthiness(): void
    {
        foreach ([0, 0.0, new Num('0'), NAN, '', false, null] as $i => $ok) {
            $this->assertFalse(AgentNative::envelopePermits(self::env($ok), 'v', 'r'), "falsy $i");
        }
        foreach ([5, 1, new Num('2'), 0.5, true, 'x'] as $i => $ok) {
            $this->assertTrue(AgentNative::envelopePermits(self::env($ok), 'v', 'r'), "truthy $i");
        }
        $bad = self::env(true);
        $bad->set('unsatisfiable', ['x']);
        $this->assertFalse(AgentNative::envelopePermits($bad, 'v', 'r'));
    }

    /** Hint boundaries: zero delegations left still permits, an unreadable spend is refused under a cap, now == notBefore permits. */
    public function testEnvelopeHintBoundaries(): void
    {
        $this->assertTrue(AgentNative::envelopePermits(self::env(true, Obj::of(['delegationDepthRemaining' => 0])), 'v', 'r'));
        $this->assertFalse(AgentNative::envelopePermits(self::env(true, Obj::of(['delegationDepthRemaining' => -1])), 'v', 'r'));
        $cap = Obj::of(['maxSpendUsd' => 5]);
        $this->assertFalse(AgentNative::envelopePermits(self::env(true, $cap), 'v', 'r', null, new Obj()));
        $this->assertTrue(AgentNative::envelopePermits(self::env(true, $cap), 'v', 'r', null, Obj::of(['amount' => 3])));
        $nb = Obj::of(['notBefore' => 100]);
        $this->assertTrue(AgentNative::envelopePermits(self::env(true, $nb), 'v', 'r', 100));
        $this->assertFalse(AgentNative::envelopePermits(self::env(true, $nb), 'v', 'r', 99));
    }

    /** A non-object tool call has no `tool`: the reason names it undefined. */
    public function testToolCallWithoutATool(): void
    {
        $env = Obj::of(['ok' => true, 'unsatisfiable' => [], 'tools' => ['a'], 'toolSchemas' => []]);
        $r = AgentNative::envelopePermitsToolCall($env, 'x');
        $this->assertFalse($r->get('ok'));
        $this->assertSame('tool ' . Authorize::show('undefined') . ' not authorized', $r->get('reason'));
    }

    /** grantLease: integral times stay integers (to 2^53-1), and the refusal texts. */
    public function testGrantLease(): void
    {
        $l = AgentNative::grantLease(['cap_id' => 'c', 'holder' => 'h', 'now' => 1000, 'ttl_ms' => 500]);
        $this->assertSame(1000, $l->get('issued_at'));
        $this->assertSame(1500, $l->get('expires_at'));
        $this->assertSame(500, $l->get('ttl_ms'));
        $big = AgentNative::grantLease(['cap_id' => 'c', 'holder' => 'h', 'now' => 9007199254740991, 'ttl_ms' => 500]);
        $this->assertSame(9007199254740991, $big->get('issued_at'));
        $this->assertSame('InvalidArgumentException: grantLease: cap_id and holder required', self::thrown(static fn() => AgentNative::grantLease('x')));
        $this->assertSame('InvalidArgumentException: grantLease: invalid now/ttl_ms',
            self::thrown(static fn() => AgentNative::grantLease(['cap_id' => 'c', 'holder' => 'h', 'ttl_ms' => 500])));
    }

    /** A lease of native PHP numbers is read like JSON numbers; a -0 renewal count is malformed. */
    public function testLeaseOfNativeNumbers(): void
    {
        $f = ['cap_id' => 'c', 'holder' => 'h', 'issued_at' => 1000, 'renewed_at' => 1000, 'ttl_ms' => 500, 'renewals' => 0, 'last_seq' => 0, 'expires_at' => 1300];
        $st = AgentNative::leaseState(Obj::of($f), 1000);
        $this->assertTrue($st->get('live'));
        $this->assertSame(300, $st->get('expiresIn'));
        $st = AgentNative::leaseState(Obj::of(['renewals' => -0.0] + $f), 1000);
        $this->assertFalse($st->get('live'));
        $this->assertSame('malformed lease', $st->get('reason'));
    }

    /** A heartbeat without `at` is outside the skew window (checked before the signature). */
    public function testHeartbeatWithoutATime(): void
    {
        $l = AgentNative::grantLease(['cap_id' => 'c', 'holder' => 'h', 'now' => 1000, 'ttl_ms' => 500]);
        $hb = Obj::of(['cap_id' => 'c', 'seq' => 1, 'holder' => 'h', 'lease_issued_at' => 1000, 'sig' => 'x']);
        $r = AgentNative::renewCapabilityLease($l, $hb, 1000);
        $this->assertFalse($r->get('ok'));
        $this->assertSame('heartbeat outside skew window', $r->get('reason'));
    }
}
