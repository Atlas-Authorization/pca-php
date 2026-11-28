<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ArgProvenance;
use Atlas\Pca\AuthorizedOperation;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaTesting;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/PcaTesting.php: testAgent defaults, the fake verifier's refusals and clock, the expect* messages, tamper paths, the route mapping and the acceptance-matrix inputs. */
final class LedgerSurvivorKill19PcaTestingTest extends TestCase
{
    private const NO_GRANT = 'fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant';
    private const WIRE = ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: the grant is not an object'];

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return (new \ReflectionClass($e))->getShortName() . ': ' . $e->getMessage();
        }
        return 'nothing thrown';
    }

    private static function canon(mixed $v): string
    {
        return Json::canonicalizeLenient($v instanceof Obj || is_string($v) ? $v : Sign::n($v));
    }

    /** testAgent keeps the caller's principal, goal and permissions; the default limit is $500 per refund. */
    public function testTestAgentOptionsAndDefaults(): void
    {
        $principal = new KeyPair(hash('sha256', 'atlas-pca-conformance/testing19-principal', true));
        $a = PcaTesting::testAgent(['principal' => $principal, 'goal' => 'other goal', 'permissions' => ['stripe' => ['create_customer']], 'limits' => []]);
        $this->assertSame($principal->public, $a->principalPublic);
        $this->assertSame(Sign::goalCommit('other goal', $a->goalSalt), $a->grant->get('caveats')[0]->get('goal_commit'));
        $this->assertSame('stripe.create_customer', $a->policy['predicates'][0]['verb']);
        $d = PcaTesting::testAgent();
        $this->assertSame('stripe.refund', $d->policy['predicates'][0]['verb']);
        $this->assertSame(Sign::goalCommit('test', $d->goalSalt), $d->grant->get('caveats')[0]->get('goal_commit'));
        $this->assertEquals(500, $d->policy['predicates'][0]['where'][0]['value']);
    }

    /** No grant to root at: a non-object, a numeric chain; a string or object chain lifts a non-object root (the wire refusal). */
    public function testFakeVerifyLiftsTheRoot(): void
    {
        $this->assertSame('InvalidArgumentException: ' . self::NO_GRANT, self::thrown(fn() => PcaTesting::fakeVerify('x')));
        $this->assertSame('InvalidArgumentException: ' . self::NO_GRANT, self::thrown(fn() => PcaTesting::fakeVerify(Obj::of(['cap_chain' => 5]))));
        $this->assertSame(self::WIRE, PcaTesting::fakeVerify(Obj::of(['cap_chain' => 'ab'])));
        $this->assertSame(self::WIRE, PcaTesting::fakeVerify(Obj::of(['cap_chain' => Obj::of(['0' => 'x'])])));
        $this->assertSame(self::WIRE, PcaTesting::fakeVerify('str', Obj::of(['grant' => 5])));
        $this->assertSame('InvalidArgumentException: fakeVerify: no PCActn', self::thrown(fn() => PcaTesting::fakeVerify(null, Obj::of(['grant' => new Obj()]))));
        $this->assertSame(['allow' => false, 'checks' => ['cap_chain' => false],
            'reason' => 'cap_chain: root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it'],
            PcaTesting::fakeVerify(Obj::of(['cap_chain' => [Obj::of(['alg' => 'ml-dsa-65'])]])));
        $this->assertSame(self::WIRE, PcaTesting::expectDenied(Obj::of(['cap_chain' => 'ab'])));
    }

    /** Without `now` (or with a null one) the fake verifier reads epoch milliseconds; the expect* helpers return the whole verdict or name the failing checks. */
    public function testFakeVerifyClockAndExpectations(): void
    {
        $p = PcaTesting::makePCActn(PcaTesting::testAgent(), 'stripe.refund', 'ch_12345678', ['amount' => 100])['pcactn'];
        $this->assertTrue(PcaTesting::fakeVerify($p)['allow']);
        $this->assertTrue(PcaTesting::fakeVerify($p, Obj::of(['now' => null]))['allow']);
        $at = Obj::of(['now' => $p->get('iat')]);
        $this->assertSame(PcaTesting::fakeVerify($p, $at), PcaTesting::expectVerifies($p, $at));
        $res = PcaTesting::fakeVerify($p, $at);
        $this->assertSame('RuntimeException: expectDenied: PCActn verified but was expected to be denied. checks: ' . json_encode($res['checks']),
            self::thrown(fn() => PcaTesting::expectDenied($p, $at)));
        $wrong = Obj::of(['now' => $p->get('iat'), 'audience' => 'wrong']);
        $bad = PcaTesting::fakeVerify($p, $wrong);
        $this->assertContains(true, $bad['checks'], 'control: some checks pass');
        $failing = array_keys(array_filter($bad['checks'], static fn(bool $ok): bool => !$ok));
        $this->assertContains('audience', $failing);
        $this->assertSame('RuntimeException: expectVerifies: PCActn was denied. failing checks: [' . implode(', ', $failing) . '] — ' . $bad['reason'],
            self::thrown(fn() => PcaTesting::expectVerifies($p, $wrong)));
    }

    /** tamper: the size cap is strictly above the limit, a non-object is refused, and a callable mutator is applied as is. */
    public function testTamperDecoding(): void
    {
        $this->assertSame('InvalidArgumentException: ' . Pca::ARTIFACT_SIZE_REASON, self::thrown(fn() => PcaTesting::tamper(str_repeat(' ', Pca::MAX_ARTIFACT_BYTES + 1), fn($r) => $r)));
        $this->assertNotSame('InvalidArgumentException: ' . Pca::ARTIFACT_SIZE_REASON, self::thrown(fn() => PcaTesting::tamper(str_repeat(' ', Pca::MAX_ARTIFACT_BYTES), fn($r) => $r)));
        $this->assertSame('TypeError: decodePCActn: not an object', self::thrown(fn() => PcaTesting::tamper('[]', fn($r) => $r)));
        $enc = PcaTesting::makePCActn(PcaTesting::testAgent(), 'stripe.refund', 'ch_12345678', ['amount' => 100], null, 1800000000000)['encoded'];
        $this->assertSame($enc, PcaTesting::tamper($enc, static fn(Obj $r): Obj => $r));
    }

    /** applyMutation: list indexes (append only on set, a hole on delete), nested descent, index coercion, and refusals by name. */
    public function testApplyMutationPaths(): void
    {
        $rec = Json::parseStrict('{"a":["x","y"],"b":5,"c":[{"x":1}]}');
        $m = static fn(string $op, array $path, mixed $value = null): Obj => Obj::of(['op' => $op, 'path' => $path, 'value' => $value]);
        $run = static fn(Obj $mut): string => Json::canonicalizeLenient(PcaTesting::applyMutation($rec, $mut));
        $this->assertSame('{"a":["x","y","z"],"b":5,"c":[{"x":1}]}', $run($m('set', ['a', new Num('2')], 'z')));
        $this->assertSame('{"a":["q","y"],"b":5,"c":[{"x":1}]}', $run($m('set', ['a', new Num('0')], 'q')));
        $this->assertSame('{"a":["q","y"],"b":5,"c":[{"x":1}]}', $run($m('set', ['a', new Num('-0.5')], 'q')));
        $this->assertSame('{"a":["x","q"],"b":5,"c":[{"x":1}]}', $run($m('set', ['a', '1'], 'q')));
        $this->assertSame('{"a":["x",null],"b":5,"c":[{"x":1}]}', $run($m('delete', ['a', new Num('1')])));
        $this->assertSame('{"a":["x","y"],"b":5,"c":[{"x":"n"}]}', $run($m('set', ['c', new Num('0'), 'x'], 'n')));
        $this->assertSame('{"a":["x","y"],"b":"v","c":[{"x":1}]}', $run($m('set', [1 => 'b'], 'v')));
        $this->assertSame($rec, PcaTesting::applyMutation($rec, Obj::of(['op' => 'none'])));
        $range = 'OutOfBoundsException: tamper: index out of range';
        foreach ([$m('delete', ['a', new Num('2')]), $m('set', ['a', new Num('3')], 'z'), $m('set', ['a', new Num('-1')], 'z'), $m('set', ['c', new Num('1'), 'x'], 'n')] as $mut) {
            $this->assertSame($range, self::thrown(fn() => PcaTesting::applyMutation($rec, $mut)));
        }
        $this->assertSame('TypeError: tamper: cannot descend into a scalar', self::thrown(fn() => PcaTesting::applyMutation($rec, $m('set', ['b', 'z'], 'n'))));
    }

    /** The route mapping resolves URLs as a WHATWG parser does: scheme case, empty hosts, dot segments, backslashes, file URLs, and Unicode upper-casing of the method. */
    public function testAcceptanceOperationPathnames(): void
    {
        $body = Obj::of(['amount' => new Num('5')]);
        $op = static fn(string $url, string $method = 'POST'): ?Obj => PcaTesting::acceptanceOperation(Obj::of(['method' => $method, 'url' => $url, 'body' => $body]));
        $verb = static fn(?Obj $o): string => $o === null ? 'none' : $o->get('verb');
        foreach (['HTTP:payments', 'myapp:///payments', 'myapp:/a/../payments', 'file:\\payments', 'https:\\\\h\\payments', '/payments'] as $url) {
            $this->assertSame('payments.send', $verb($op($url)), $url);
        }
        $this->assertSame('payments.send', $verb($op('/payments', "po\u{17F}t")));
        $this->assertNull($op('file://h'));
        $this->assertNull(PcaTesting::acceptanceOperation(null));
    }

    /** The acceptance matrix sends exactly the documented requests (signed and sent amounts, paths, counters, grants) with the documented options. */
    public function testAcceptanceMatrixInputs(): void
    {
        $calls = [];
        $mismatch = new AuthorizedOperation('payments.send', 'payments', 'not-the-digest', 'op-1');
        $out = PcaTesting::runAdapterAcceptance(static function (array $opts) use (&$calls, $mismatch): callable {
            return static function (array $req) use ($opts, &$calls, $mismatch): array {
                $calls[] = [$opts, $req];
                return ['status' => 200, 'handlerRan' => true, 'operation' => $mismatch];
            };
        });
        foreach ($out->keys() as $k) {
            $this->assertSame([200, true, false], [$out->get($k)->get('status')->int(), $out->get($k)->get('handlerRan'), $out->get($k)->get('bound')], $k);
        }
        // [path, signed amount, sent amount, counter, fixture]
        $want = [['/payments', 400, 400, 1, 'p'], ['/payments', 400, 400, 1, 's'], ['/payments', 50, 400, 2, 'p'], ['/refunds', 50, 50, 3, 'p'],
            ['/payments', 70, 70, 1, 'e'], ['/payments', 50, 50, 4, 'p'], ['/payments', 50, 50, 5, 'p'], ['/payments', 50, 50, 6, 'p'], ['/payments', 50, 50, 6, 'p']];
        $this->assertCount(9, $calls);
        $rp = ['weights' => ['alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0], 'theta1' => 1, 'theta2' => 1, 'kappa' => 100,
            'lambda' => 0, 'rho' => 0.5, 'bMax' => 1000000];
        $keys = ['audience', 'resolveGrant', 'stateStore', 'isRevoked', 'plan', 'hard', 'provenanceMediators'];
        foreach ($calls as $i => [$opts, $req]) {
            [$path, $signed, $sent, $counter, $fx] = $want[$i];
            $this->assertSame(['POST', $path, 'application/json'], [$req['method'], $req['path'], $req['headers']['content-type']], "call $i");
            $this->assertArrayHasKey(ArgProvenance::HEADER, $req['headers']);
            $this->assertSame(['acme', (string)$sent], [$req['body']->get('payee'), $req['body']->get('amount')->lexeme], "call $i");
            $p = Json::parseStrict((string)Pca::decodePcaHeader($req['headers']['PCA-Action']));
            $this->assertSame(Pca::paramsDigest(Obj::of(['payee' => 'acme', 'amount' => new Num((string)$signed)])), $p->get('action')->get('params_digest'), "call $i");
            $this->assertSame([(string)$counter, 'payments-rs', 'payments.send'], [$p->get('counter')->lexeme, $p->get('aud'), $p->get('action')->get('verb')], "call $i");
            $grant = $p->get('cap_chain')[0];
            $cav = $grant->get('caveats');
            $env = $cav[0];
            $this->assertSame('envelope', $env->get('type'));
            $this->assertSame(self::canon($rp), self::canon($env->get('risk_policy')), "call $i");
            $where = $fx === 's' ? [] : [['field' => 'action.params.amount', 'op' => 'lte', 'value' => 100]];
            $this->assertSame(self::canon([['verb' => ['payments.send', 'payments.refund'], 'resource' => 'payments', 'where' => $where]]), self::canon($env->get('predicates')), "call $i");
            $this->assertSame($fx === 'e' ? self::canon([['id' => 'big_payment', 'when' => ['field' => 'action.params.amount', 'op' => 'gt', 'value' => 50], 'signal' => 'escalate']]) : null,
                $env->has('tighten') ? self::canon($env->get('tighten')) : null, "call $i");
            $this->assertSame($fx === 's' ? 2 : 1, count($cav), "call $i");
            if ($fx === 's') {
                $this->assertSame(self::canon(['type' => 'max_spend', 'usd' => 100]), self::canon($cav[1]));
            }
            $this->assertSame($keys, array_keys($opts), "call $i");
            $this->assertSame(['payments-rs', 'single-step'], [$opts['audience'], $opts['plan']]);
            $this->assertSame($i === 5 ? null : false, $i === 5 ? $opts['isRevoked'] : ($opts['isRevoked'])());
            if ($i === 6) {
                $this->assertNull($opts['stateStore']);
            } else {
                $this->assertInstanceOf(MemoryStateStore::class, $opts['stateStore']);
            }
            $this->assertSame(self::canon($grant), self::canon(($opts['resolveGrant'])($p->get('grant_ref'))));
            $this->assertNull(($opts['resolveGrant'])('other'));
            $risk = $opts['hard']['risk'];
            $base = ['semanticDistance' => 0, 'reversibility' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0];
            $this->assertSame(['blastRadius' => 0.5] + $base, $risk(['params' => Obj::of(['amount' => new Num('50')])], null, null));
            $this->assertSame(['blastRadius' => 1] + $base, $risk(['params' => Obj::of(['amount' => new Num('400')])], null, null));
            $this->assertSame(['blastRadius' => 0.0] + $base, $risk(['params' => null], null, null));
        }
    }
}
