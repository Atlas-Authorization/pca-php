<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Workflow;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for Workflow: the public strict helpers at their boundaries, every body/step/edge shape conjunct failing alone,
 * and admitStep over workflows and receipt chains built and signed here with fixed-seed keys.
 */
final class K05KillWorkflowTest extends TestCase
{
    private static function n(int $i): Num
    {
        return new Num((string)$i);
    }

    private static function o(array $a): Obj
    {
        return Obj::of($a);
    }

    /** @return array{0: string, 1: string} [public b64u, secret] */
    private static function key(int $seed): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat(chr($seed), 32));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function sign(string $sk, string $msg): string
    {
        return Pca::b64u(sodium_crypto_sign_detached($msg, $sk));
    }

    private static function p(): string
    {
        return self::key(1)[0];
    }

    private static function rs(): string
    {
        return self::key(2)[0];
    }

    private static function with(Obj $x, array $set): Obj
    {
        $c = $x->without();
        foreach ($set as $k => $v) {
            $c->set((string)$k, $v);
        }
        return $c;
    }

    private static function step(string $id, array $set = []): Obj
    {
        return self::with(self::o(['id' => $id, 'verb' => 'read', 'resource' => '/r', 'params_digest' => null, 'deps' => [], 'sink' => null,
            'deny_labels' => [], 'escalate_labels' => [], 'fresh_ms' => null, 'cost' => new Obj()]), $set);
    }

    private static function edge(string $fs, string $ff, string $ts, string $tp, array $set = []): Obj
    {
        return self::with(self::o(['from' => self::o(['step' => $fs, 'field' => $ff]), 'to' => self::o(['step' => $ts, 'param' => $tp]), 'op' => 'eq',
            'unit' => null, 'deny_labels' => [], 'promise' => null]), $set);
    }

    private static function body(array $steps, array $edges = [], array $set = []): Obj
    {
        return self::with(self::o(['v' => self::n(1), 'id' => 'wf1', 'principal' => self::p(), 'goal_digest' => null, 'plan_root' => null,
            'issued_at' => self::n(1000), 'expires_at' => self::n(2000), 'steps' => $steps, 'edges' => $edges,
            'budget' => self::o(['max_steps' => self::n(10), 'caps' => self::o(['usd' => self::n(10)])])]), $set);
    }

    private static function signed(Obj $body): Obj
    {
        return self::o(['body' => $body, 'sig' => self::sign(self::key(1)[1], Workflow::WORKFLOW_DOMAIN . Json::canonicalizeStrict($body))]);
    }

    /** A step output: the digest of the integer `$v`, its num, no unit, the labels. */
    private static function out(int $v, array $labels = []): Obj
    {
        return self::o(['digest' => Workflow::valueDigest(self::n($v)), 'num' => self::n($v), 'unit' => null, 'labels' => $labels]);
    }

    /** @param list<array{0: string, 1?: array}> $specs [step, overrides] @return list<Obj> a signed receipt chain */
    private static function receipts(Obj $body, array $specs): array
    {
        $out = [];
        $prev = null;
        foreach ($specs as $i => $sp) {
            $r = self::with(self::o(['v' => self::n(1), 'wf' => Workflow::workflowDigest($body), 'step' => $sp[0], 'seq' => self::n($i),
                'prev' => $prev === null ? null : Workflow::receiptRef($prev), 'outcome' => 'ok', 'params_digest' => IntentV2::hashCanonical(new Obj()),
                'outputs' => new Obj(), 'issued_at' => self::n(1100), 'signer' => self::rs()]), $sp[1] ?? []);
            $r->set('sig', self::sign(self::key(2)[1], Workflow::WF_RECEIPT_DOMAIN . Json::canonicalizeStrict($r)));
            $out[] = $r;
            $prev = $r;
        }
        return $out;
    }

    private static function req(string $step, array $params = [], array $set = []): Obj
    {
        return self::with(self::o(['step' => $step, 'verb' => 'read', 'resource' => '/r', 'params' => self::o($params), 'units' => new Obj(),
            'goal_digest' => null, 'plan_root' => null]), $set);
    }

    private static function input(Obj $sw, array $receipts, Obj $req, int $now = 1500): Obj
    {
        return self::o(['workflow' => $sw, 'principal' => self::p(), 'rsSigner' => self::rs(), 'receipts' => $receipts, 'now' => self::n($now), 'request' => $req]);
    }

    private static function admit(Obj $sw, array $receipts, Obj $req, int $now = 1500): array
    {
        return Workflow::admitStep(self::input($sw, $receipts, $req, $now));
    }

    private static function deny(string $code, ?string $step, ?int $at = null): array
    {
        return ['decision' => 'deny', 'code' => $code, 'step' => $step, 'at' => $at, 'pending' => []];
    }

    private static function allow(string $step, array $pending = []): array
    {
        return ['decision' => 'allow', 'code' => null, 'step' => $step, 'at' => null, 'pending' => $pending];
    }

    /** An object that answers get/has/keys like the wrapped Obj but is not an Obj. */
    private static function wrap(Obj $x): object
    {
        return new class($x) {
            public function __construct(private Obj $x)
            {
            }

            public function has(string $k): bool
            {
                return $this->x->has($k);
            }

            public function get(string $k): mixed
            {
                return $this->x->get($k);
            }

            public function keys(): array
            {
                return $this->x->keys();
            }
        };
    }

    private static function b32(): string
    {
        return Pca::b64u(str_repeat("\x07", 32));
    }

    public function testStrictHelpers(): void
    {
        self::assertTrue(Workflow::isObj(new Obj()));
        self::assertFalse(Workflow::isObj([]));
        self::assertTrue(Workflow::isList(['a']));
        self::assertFalse(Workflow::isList(['k' => 'a']));
        self::assertFalse(Workflow::isList('x'));
        self::assertTrue(Workflow::isUint(9007199254740991));
        self::assertFalse(Workflow::isUint(9007199254740992));
        self::assertTrue(Workflow::isSafeInt(-9007199254740991));
        self::assertTrue(Workflow::isSafeInt(9007199254740991));
        self::assertFalse(Workflow::isSafeInt(1.5));
        self::assertSame(7, Workflow::iv('7'));
        self::assertSame(3, Workflow::iv(self::n(3)));
        self::assertTrue(Workflow::isScalar('x'));
        self::assertFalse(Workflow::isScalar(null));
        self::assertTrue(Workflow::sortedUnique(['a', 'b'], Workflow::ID_RE, 2));
        self::assertFalse(Workflow::sortedUnique(['a', 'b', 'c'], Workflow::ID_RE, 2));
        self::assertFalse(Workflow::sortedUnique('x', Workflow::ID_RE, 2));
        self::assertFalse(Workflow::sortedUnique(['k' => 'a'], Workflow::ID_RE, 5));
        self::assertTrue(Workflow::onlyKeys(self::o(['a' => 1, 'b' => 2]), ['a', 'b']));
        self::assertFalse(Workflow::onlyKeys(self::o(['a' => 1, 'b' => 2]), ['a', 'c']));
        $m = new Obj();
        for ($i = 0; $i < 32; $i++) {
            $m->set("p$i", 'x');
        }
        self::assertTrue(Workflow::isScalarMap($m));
        self::assertFalse(Workflow::isScalarMap(self::with($m, ['p32' => 'x'])));
        self::assertFalse(Workflow::isScalarMap('x'));
    }

    public function testBodyShape(): void
    {
        $ok = static fn (Obj $b): bool => Workflow::validWorkflowBody($b);
        $a = self::step('a');
        self::assertTrue($ok(self::body([$a])));
        self::assertFalse(Workflow::validWorkflowBody('x'));
        // body members, each failing alone
        foreach (['id' => 'bad id!', 'principal' => 'x', 'goal_digest' => 'x', 'plan_root' => 'x', 'issued_at' => '1', 'expires_at' => '1', 'v' => self::n(2)] as $k => $v) {
            self::assertFalse($ok(self::body([$a], [], [$k => $v])), "body $k");
        }
        self::assertTrue($ok(self::body([$a], [], ['goal_digest' => self::b32(), 'plan_root' => self::b32()])));
        // steps
        self::assertFalse($ok(self::body([])));
        self::assertFalse($ok(self::body(['k' => $a])));
        self::assertFalse($ok(self::body(['x'])));
        self::assertTrue($ok(self::body(array_fill(0, 64, $a))));
        self::assertFalse($ok(self::body(array_fill(0, 65, $a))));
        // step members, each failing alone
        $long = static fn (int $n): string => str_repeat('v', $n);
        foreach ([['verb', $long(128)], ['resource', '/' . $long(511)], ['params_digest', self::b32()], ['deps', ['a', 'b']], ['sink', 'x'], ['fresh_ms', self::n(5)],
            ['deny_labels', ['a', 'b']], ['escalate_labels', ['a']]] as [$k, $v]) {
            self::assertTrue($ok(self::body([self::step('a', [$k => $v])])), "step $k valid");
        }
        foreach ([['id', 'bad id!'], ['verb', $long(129)], ['resource', '/' . $long(512)], ['params_digest', 'x'], ['deps', ['b', 'a']], ['sink', 'bad id!'],
            ['deny_labels', ['A']], ['escalate_labels', ['A']], ['fresh_ms', new Num('1.5')], ['cost', self::o(['usd' => 'x'])], ['extra', 1]] as [$k, $v]) {
            self::assertFalse($ok(self::body([self::step('a', [$k => $v])])), "step $k");
        }
        // cost: up to 8 names (all capped), and an uncapped name
        $c8 = new Obj();
        for ($i = 0; $i < 8; $i++) {
            $c8->set("c$i", self::n(1));
        }
        $budget8 = self::o(['max_steps' => self::n(10), 'caps' => $c8]);
        self::assertTrue($ok(self::body([self::step('a', ['cost' => $c8])], [], ['budget' => $budget8])));
        self::assertFalse($ok(self::body([self::step('a', ['cost' => self::o(['eur' => self::n(1)])])])));
        // edges
        $e = self::edge('a', 'n', 'b', 'x');
        self::assertTrue($ok(self::body([$a], [$e])));
        self::assertTrue($ok(self::body([$a], array_fill(0, 256, $e))));
        self::assertFalse($ok(self::body([$a], array_fill(0, 257, $e))));
        self::assertFalse($ok(self::body([$a], ['k' => $e])));
        self::assertFalse($ok(self::body([$a], ['x'])));
        self::assertFalse($ok(self::body([$a], [self::with($e, ['z' => 1])])));
        foreach ([['op', 'le'], ['unit', 'usd'], ['deny_labels', ['pii']], ['promise', 'p1']] as [$k, $v]) {
            self::assertTrue($ok(self::body([$a], [self::with($e, [$k => $v])])), "edge $k valid");
        }
        foreach ([
            ['from', 'x'], ['from', self::o(['step' => 'a', 'field' => 'n', 'z' => 1])], ['from', self::o(['step' => 'bad id!', 'field' => 'n'])],
            ['from', self::o(['step' => 'a', 'field' => 'bad name'])], ['to', 'x'], ['to', self::o(['step' => 'b', 'param' => 'x', 'z' => 1])],
            ['to', self::o(['step' => 'bad id!', 'param' => 'x'])], ['to', self::o(['step' => 'b', 'param' => 'bad name'])], ['op', self::n(1)], ['op', 'ne'],
            ['unit', 'bad unit!'], ['deny_labels', ['A']], ['promise', 'bad id!'],
        ] as [$k, $v]) {
            self::assertFalse($ok(self::body([$a], [self::with($e, [$k => $v])])), "edge $k");
        }
        // budget
        foreach (['x', self::o(['max_steps' => self::n(1), 'caps' => new Obj(), 'z' => 1]), self::o(['max_steps' => new Num('1.5'), 'caps' => new Obj()]),
            self::o(['max_steps' => self::n(1), 'caps' => 'x']), self::o(['max_steps' => self::n(1), 'caps' => self::o(['bad name' => self::n(1)])]),
            self::o(['max_steps' => self::n(1), 'caps' => self::o(['usd' => 'x'])])] as $i => $bg) {
            self::assertFalse($ok(self::body([$a], [], ['budget' => $bg])), "budget $i");
        }
        self::assertTrue($ok(self::body([$a], [], ['budget' => self::o(['max_steps' => self::n(1), 'caps' => new Obj()])])));
    }

    public function testDagAndAncestors(): void
    {
        self::assertNull(Workflow::dagError(self::body([self::step('a'), self::step('b', ['deps' => ['a']])], [self::edge('a', 'n', 'b', 'x')])));
        // a 48-step ladder (each step depends on the previous two): memoized it is linear, without the memo exponential
        $steps = [];
        for ($i = 0; $i < 48; $i++) {
            $deps = $i === 0 ? [] : ($i === 1 ? ['s00'] : [sprintf('s%02d', $i - 2), sprintf('s%02d', $i - 1)]);
            $steps[] = self::o(['id' => sprintf('s%02d', $i), 'deps' => $deps]);
        }
        $anc = Workflow::ancestors(self::o(['steps' => $steps]));
        self::assertNotNull($anc);
        self::assertCount(47, $anc['ks47']);
        self::assertSame(true, $anc['ks47']['ks00']);
        self::assertSame(true, $anc['ks47']['ks46']);
        self::assertSame([], $anc['ks00']);
        self::assertNull(Workflow::ancestors(self::o(['steps' => [self::o(['id' => 'a', 'deps' => ['b']]), self::o(['id' => 'b', 'deps' => ['a']])]])));
    }

    public function testPlanRootAuthorized(): void
    {
        $sw = self::signed(self::body([self::step('a')]));
        self::assertTrue(Workflow::planRootAuthorized($sw, self::p(), self::n(1500), null));
        self::assertTrue(Workflow::planRootAuthorized($sw, self::p(), self::n(1000), null));
        self::assertFalse(Workflow::planRootAuthorized($sw, self::p(), self::n(2000), null));
        self::assertFalse(Workflow::planRootAuthorized($sw, self::p(), '1500', null));
        self::assertFalse(Workflow::planRootAuthorized($sw, null, self::n(1500), null));
        self::assertFalse(Workflow::planRootAuthorized(self::wrap($sw), self::p(), self::n(1500), null));
        self::assertFalse(Workflow::planRootAuthorized('x', self::p(), self::n(1500), null));
    }

    public function testAdmitInputAndRequestShape(): void
    {
        $sw = self::signed(self::body([self::step('a')]));
        self::assertSame(self::allow('a'), self::admit($sw, [], self::req('a')));
        self::assertSame(self::allow('a'), self::admit($sw, [], self::req('a'), 1000));
        self::assertSame(self::deny('not_yet', 'a'), self::admit($sw, [], self::req('a'), 999));
        self::assertSame(self::deny('bad_workflow', null), Workflow::admitStep(self::wrap(self::input($sw, [], self::req('a')))));
        self::assertSame(self::deny('bad_workflow', null), self::admit(self::with($sw, ['x' => 1]), [], self::req('a')));
        foreach (['x', self::o(['x' => 'bad unit!']), self::o(['bad name' => 'usd']), self::wrap(new Obj())] as $i => $u) {
            self::assertSame(self::deny('bad_workflow', null), self::admit($sw, [], self::req('a', [], ['units' => $u])), "units $i");
        }
        self::assertSame(self::allow('a'), self::admit($sw, [], self::req('a', [], ['units' => self::o(['x' => 'usd'])])));
        self::assertSame(self::deny('bad_workflow', null), self::admit($sw, [], self::req('a', [], ['plan_root' => 'x'])));
        self::assertSame(self::deny('bad_workflow', null), self::admit($sw, [], self::req('a', [], ['goal_digest' => 'x'])));
        self::assertSame(self::deny('step_mismatch', 'a'), self::admit($sw, [], self::req('a', [], ['verb' => str_repeat('v', 128)])));
        self::assertSame(self::deny('bad_workflow', null), self::admit($sw, [], self::req('a', [], ['verb' => str_repeat('v', 129)])));
        self::assertSame(self::deny('step_mismatch', 'a'), self::admit($sw, [], self::req('a', [], ['resource' => str_repeat('r', 512)])));
        self::assertSame(self::deny('bad_workflow', null), self::admit($sw, [], self::req('a', [], ['resource' => str_repeat('r', 513)])));
    }

    public function testReceiptShape(): void
    {
        $body = self::body([self::step('a'), self::step('b', ['deps' => ['a']])]);
        $sw = self::signed($body);
        $one = static fn (array $set, int $now = 1500): array => self::admit($sw, self::receipts($body, [['a', $set]]), self::req('b'), $now);
        self::assertSame(self::allow('b'), $one([]));
        self::assertSame(self::allow('b'), $one(['issued_at' => self::n(1500)]));
        $bad = self::deny('bad_receipt', 'b', 0);
        $vo = self::o(['digest' => Workflow::valueDigest('x'), 'num' => null, 'unit' => null, 'labels' => []]);
        $o32 = new Obj();
        for ($i = 0; $i < 32; $i++) {
            $o32->set("o$i", $vo);
        }
        self::assertSame(self::allow('b'), $one(['outputs' => $o32]));
        self::assertSame(self::allow('b'), $one(['outputs' => self::o(['o' => self::with($vo, ['num' => self::n(3), 'unit' => 'usd', 'labels' => ['pii']])])]));
        foreach ([
            'step' => ['step' => self::n(1)], 'seq' => ['seq' => new Num('0.5')], 'outcome' => ['outcome' => 'weird'], 'pd' => ['params_digest' => 'x'],
            'issued_at' => ['issued_at' => new Num('1.5')], 'outputs' => ['outputs' => 'x'], 'outputs33' => ['outputs' => self::with($o32, ['o32' => $vo])],
            'outname' => ['outputs' => self::o(['bad name' => $vo])], 'outval' => ['outputs' => self::o(['o' => 'x'])],
            'outextra' => ['outputs' => self::o(['o' => self::with($vo, ['z' => self::n(1)])])], 'outdigest' => ['outputs' => self::o(['o' => self::with($vo, ['digest' => 'x'])])],
            'outnum' => ['outputs' => self::o(['o' => self::with($vo, ['num' => new Num('1.5')])])],
            'outunit' => ['outputs' => self::o(['o' => self::with($vo, ['unit' => 'bad unit!'])])],
            'outlabels' => ['outputs' => self::o(['o' => self::with($vo, ['labels' => ['B']])])],
            'wf' => ['wf' => 'x'], 'signer' => ['signer' => self::key(3)[0]], 'v' => ['v' => self::n(2)],
        ] as $name => $set) {
            self::assertSame($bad, $one($set), "receipt $name");
        }
        self::assertSame($bad, $one([], 1099));
        // a receipt ahead of its dependency's, with no edge (or a non-promised one) between them
        self::assertSame($bad, self::admit($sw, self::receipts($body, [['b']]), self::req('b')));
        $body3 = self::body([self::step('a'), self::step('b', ['deps' => ['a']])], [self::edge('a', 'n', 'b', 'x', ['promise' => 'p']), self::edge('a', 'm', 'b', 'y')]);
        self::assertSame($bad, self::admit(self::signed($body3), self::receipts($body3, [['b']]), self::req('b')));
        $body4 = self::body([self::step('a'), self::step('b'), self::step('c', ['deps' => ['a', 'b']])]);
        self::assertSame(self::deny('bad_receipt', 'c', 1), self::admit(self::signed($body4), self::receipts($body4, [['a'], ['c']]), self::req('c')));
    }

    public function testBudget(): void
    {
        $run = static function (array $costs): array {
            $steps = [];
            foreach ($costs as $id => $c) {
                $steps[] = self::step($id, ['cost' => self::o(array_map(static fn (int $v): Num => self::n($v), $c))]);
            }
            $body = self::body($steps);
            return self::admit(self::signed($body), self::receipts($body, [['a'], ['b']]), self::req('c'));
        };
        self::assertSame(self::deny('budget_exceeded', 'c'), $run(['a' => ['usd' => 5], 'b' => ['usd' => 5], 'c' => ['usd' => 1]]));
        self::assertSame(self::allow('c'), $run(['a' => ['usd' => 4], 'b' => ['usd' => 5], 'c' => ['usd' => 1]]));
        self::assertSame(self::deny('budget_exceeded', 'c'), $run(['a' => ['usd' => 6], 'b' => ['usd' => 5], 'c' => []]));
        self::assertSame(self::allow('c'), $run(['a' => ['usd' => 5], 'b' => ['usd' => 5], 'c' => []]));
    }

    public function testEdgeOps(): void
    {
        $run = static function (string $op, int $v, array $labels = [], array $deny = []): array {
            $body = self::body([self::step('a'), self::step('b', ['deps' => ['a']])], [self::edge('a', 'n', 'b', 'x', ['op' => $op, 'deny_labels' => $deny])]);
            return self::admit(self::signed($body), self::receipts($body, [['a', ['outputs' => self::o(['n' => self::out(10, $labels)])]]]), self::req('b', ['x' => self::n($v)]));
        };
        $ok = self::allow('b');
        $rel = self::deny('edge_relation', 'b', 0);
        foreach ([['le', 5, $ok], ['le', 10, $ok], ['le', 11, $rel], ['ge', 10, $ok], ['ge', 11, $ok], ['ge', 9, $rel], ['lt', 9, $ok], ['lt', 10, $rel],
            ['gt', 11, $ok], ['gt', 10, $rel], ['eq', 10, $ok], ['eq', 11, self::deny('edge_digest', 'b', 0)]] as [$op, $v, $want]) {
            self::assertSame($want, $run($op, $v), "$op $v");
        }
        self::assertSame(self::deny('taint_flow', 'b', 0), $run('eq', 10, ['pii'], ['pii']));
        self::assertSame($ok, $run('eq', 10, ['pii'], ['x']));
    }

    public function testDepsEdgesTaintLoops(): void
    {
        $promised = self::edge('a', 'n', 'c', 'x', ['promise' => 'p']);
        $mk = static fn (array $edges, array $cset = []): Obj => self::body([self::step('a'), self::step('b'), self::step('c', ['deps' => ['a', 'b']] + $cset)], $edges);
        // a pending (promised) dependency is skipped, the next one is still checked
        $b1 = $mk([$promised]);
        self::assertSame(self::deny('dep_failed', 'c'), self::admit(self::signed($b1), self::receipts($b1, [['b', ['outcome' => 'failed']]]), self::req('c', ['x' => self::n(1)])));
        self::assertSame(self::allow('c', [0]), self::admit(self::signed($b1), self::receipts($b1, [['b']]), self::req('c', ['x' => self::n(1)])));
        // a pending edge is skipped, the next edge is still checked
        $b2 = $mk([$promised, self::edge('b', 'm', 'c', 'y')]);
        $r2 = self::receipts($b2, [['b', ['outputs' => self::o(['m' => self::out(5)])]]]);
        self::assertSame(self::deny('edge_digest', 'c', 1), self::admit(self::signed($b2), $r2, self::req('c', ['x' => self::n(1), 'y' => self::n(6)])));
        self::assertSame(self::allow('c', [0]), self::admit(self::signed($b2), $r2, self::req('c', ['x' => self::n(1), 'y' => self::n(5)])));
        // an unexecuted ancestor is skipped, a later executed one still taints
        $b3 = $mk([$promised], ['deny_labels' => ['pii']]);
        self::assertSame(self::deny('taint_flow', 'c'), self::admit(self::signed($b3), self::receipts($b3, [['b', ['outputs' => self::o(['m' => self::out(5, ['pii'])])]]]),
            self::req('c', ['x' => self::n(1)])));
    }

    public function testPlanRootAuthorizedFailsClosedOnAThrow(): void
    {
        $sw = self::signed(self::body([self::step('a')]));
        Workflow::$planRootHook = static function (): void {
            throw new \RuntimeException('boom');
        };
        try {
            self::assertFalse(Workflow::planRootAuthorized($sw, self::p(), self::n(1500), null));
        } finally {
            Workflow::$planRootHook = null;
        }
        self::assertTrue(Workflow::planRootAuthorized($sw, self::p(), self::n(1500), null));
    }

    /** The private shape checks refuse a non-Obj themselves (no TypeError from onlyKeys). */
    public function testPrivateShapeChecksRefuseNonObj(): void
    {
        self::assertFalse((new \ReflectionMethod(Workflow::class, 'validRequest'))->invoke(null, 'x'));
        self::assertSame(['decision' => 'deny', 'code' => 'bad_workflow', 'step' => null, 'at' => null, 'pending' => []],
            (new \ReflectionMethod(Workflow::class, 'evaluate'))->invoke(null, Obj::of(['workflow' => 'x']), false));
    }
}
