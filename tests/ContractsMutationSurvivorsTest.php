<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AtomicKv;
use Atlas\Pca\ContractEnforcer;
use Atlas\Pca\ContractEnforcerError;
use Atlas\Pca\Contracts;
use Atlas\Pca\KeyPair;
use Atlas\Pca\KvDoc;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Prohibitions;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Exact-value tests for the behavioural-contract validator, clause evaluator, monitor and durable enforcer. */
final class ContractsMutationSurvivorsTest extends TestCase
{
    // ---- helpers ------------------------------------------------------------------------------------------------------

    private static function w(string $verb): array
    {
        return ['verb' => $verb];
    }

    private static function cl(string $id, string $kind, array $x = []): array
    {
        return ['id' => $id, 'kind' => $kind] + $x;
    }

    private static function neverC(string $id, string $verb): array
    {
        return self::cl($id, 'never', ['p' => self::w($verb)]);
    }

    private static function act(string $verb, string $res = '/r'): Obj
    {
        return Sign::n(['action' => ['verb' => $verb, 'resource' => $res]]);
    }

    private static function contract(array $clauses, ?array $invs = null): Obj
    {
        $a = ['version' => 1, 'principal' => 'pk'];
        if ($invs !== null) {
            $a['invariants'] = $invs;
        }
        $a['clauses'] = $clauses;
        return Sign::n($a);
    }

    private static function rowArr(Obj $o): array
    {
        $a = [];
        foreach ($o->keys() as $k) {
            $a[$k] = $o->get($k);
        }
        return $a;
    }

    private static function rows(array $rs): array
    {
        return array_map(static fn(Obj $o): array => self::rowArr($o), $rs);
    }

    private static function row(string $id, string $kind, bool $ok, ?string $reason = null): array
    {
        $r = ['id' => $id, 'kind' => $kind, 'result' => $ok ? 'pass' : 'violated'];
        if ($reason !== null) {
            $r['reason'] = $reason;
        }
        return $r;
    }

    private static function exp(bool $ok, ?string $reason, array $rows, array $latch = [], array $dl = []): array
    {
        return ['ok' => $ok, 'reason' => $reason, 'rows' => $rows, 'latch_set' => $latch, 'deadline_set' => $dl];
    }

    private static function st(array $deadlines = [], array $latched = []): Obj
    {
        $s = Prohibitions::emptyState(100.0);
        if ($deadlines !== []) {
            $d = new Obj();
            foreach ($deadlines as $k => $v) {
                $d->set((string)$k, Prohibitions::num((float)$v));
            }
            $s->set('deadlines', $d);
        }
        foreach ($latched as $k => $v) {
            $s->get('latched')->set((string)$k, Prohibitions::num((float)$v));
        }
        return $s;
    }

    private static function ev(array $cl, Obj $ctx, Obj $st, float $now = 100.0): array
    {
        $r = (new \ReflectionMethod(Contracts::class, 'evalClause'))->invoke(null, Sign::n($cl), $ctx, $st, $now);
        $r['rows'] = self::rows($r['rows']);
        return $r;
    }

    private static function chk(mixed $action, mixed $contract, mixed $state): array
    {
        $r = Contracts::check($action, $contract, $state);
        $r['evaluated'] = self::rows($r['evaluated']);
        return $r;
    }

    private static function chain(int $n): array
    {
        $cur = [Sign::n(self::neverC('leaf', 'x'))];
        for ($i = $n; $i >= 1; $i--) {
            $cur = [Sign::n(self::cl("a$i", 'and', ['clauses' => $cur]))];
        }
        return $cur;
    }

    private static function vc(mixed $cl, int $depth = 1, array $seen = []): array
    {
        return Contracts::validateClause(is_array($cl) ? Sign::n($cl) : $cl, $seen, $depth);
    }

    // ---- validateClause -----------------------------------------------------------------------------------------------

    public function testValidateClauseRecordsIdsAndBoundaries(): void
    {
        $seen = [];
        $this->assertSame([], Contracts::validateClause(Sign::n(self::neverC('a', 'x')), $seen, 1));
        $this->assertSame(['ka' => true], $seen);
        $this->assertSame(['a: duplicate id'], Contracts::validateClause(Sign::n(self::neverC('a', 'x')), $seen, 1));

        $id128 = str_repeat('a', 128);
        $this->assertSame([], self::vc(self::neverC($id128, 'x')));
        $this->assertSame(["{$id128}a: id too long"], self::vc(self::neverC($id128 . 'a', 'x')));
        $this->assertSame(['__proto__: forbidden id'], self::vc(self::neverC('__proto__', 'x')));
        $this->assertSame(['<no id>: missing clause id'], self::vc(['kind' => 'never']));
        $this->assertSame(['<no id>: missing clause id'], self::vc(self::neverC('', 'x')));
        $this->assertSame(['clause not an object'], self::vc('x'));
        $this->assertSame([], self::vc(self::neverC('a', 'x'), 16));
        $this->assertSame(['clause nesting too deep'], self::vc(self::neverC('a', 'x'), 17));
    }

    public function testValidateClauseEveryKind(): void
    {
        $p = self::w('a');
        $q = self::w('b');
        foreach ([
            self::cl('k1', 'always', ['p' => $p]),
            self::cl('k2', 'never', ['p' => $p]),
            self::cl('k3', 'precedes', ['p' => $p, 'q' => $q]),
            self::cl('k4', 'requires_prior', ['p' => $p, 'q' => $q]),
            self::cl('k5', 'responds_within', ['p' => $p, 'q' => $q, 'within' => 1]),
            self::cl('k6', 'responds_within', ['p' => $p, 'q' => $q, 'within' => 1000000]),
            self::cl('k7', 'and', ['clauses' => [self::neverC('k8', 'a')]]),
        ] as $c) {
            $this->assertSame([], self::vc($c), $c['id']);
        }
        foreach (['always', 'never'] as $k) {
            $this->assertSame(["z: p: not an object"], self::vc(self::cl('z', $k)), $k);
        }
        foreach (['precedes', 'requires_prior'] as $k) {
            $this->assertSame(['z: p: not an object'], self::vc(self::cl('z', $k)), "$k both bad");
            $this->assertSame(['z: q: not an object'], self::vc(self::cl('z', $k, ['p' => $p])), "$k q bad");
        }
        $this->assertSame(['z: p: not an object'], self::vc(self::cl('z', 'responds_within', ['within' => 1])));
        $this->assertSame(['z: q: not an object'], self::vc(self::cl('z', 'responds_within', ['p' => $p, 'within' => 1])));
    }

    public function testValidateClauseWithin(): void
    {
        $msg = 'z: within must be an integer in [1, MAX_DEADLINE]';
        $base = ['p' => self::w('a'), 'q' => self::w('b')];
        foreach ([0, 1000001, 1.5, '3', -1] as $bad) {
            $this->assertSame([$msg], self::vc(self::cl('z', 'responds_within', $base + ['within' => $bad])), json_encode($bad));
        }
        $this->assertSame([$msg], self::vc(self::cl('z', 'responds_within', $base)));
        foreach ([1, 2, 999999, 1000000] as $ok) {
            $this->assertSame([], self::vc(self::cl('z', 'responds_within', $base + ['within' => $ok])), (string)$ok);
        }
    }

    public function testValidateClauseAndAggregatesEveryProblem(): void
    {
        $two = self::cl('a', 'and', ['clauses' => [self::cl('b1', 'bogus'), self::cl('b2', 'bogus')]]);
        $this->assertSame(['b1: unknown clause kind bogus', 'b2: unknown clause kind bogus'], self::vc($two));
        $this->assertSame(['a: and.clauses must be a non-empty array'], self::vc(self::cl('a', 'and', ['clauses' => []])));
        $this->assertSame(['a: and.clauses must be a non-empty array'], self::vc(self::cl('a', 'and')));
        $this->assertSame(['a: and.clauses must be a non-empty array'], self::vc(self::cl('a', 'and', ['clauses' => self::neverC('b', 'x')])));
    }

    public function testUnknownKindMessagePrintsLikeJs(): void
    {
        $this->assertSame(['a: unknown clause kind undefined'], self::vc(['id' => 'a']));
        $this->assertSame(['a: unknown clause kind null'], self::vc(['id' => 'a', 'kind' => null]));
        $this->assertSame(['a: unknown clause kind 5'], self::vc(['id' => 'a', 'kind' => 5]));
        $this->assertSame(['a: unknown clause kind true'], self::vc(['id' => 'a', 'kind' => true]));
        $this->assertSame(['a: unknown clause kind bogus'], self::vc(['id' => 'a', 'kind' => 'bogus']));
        $this->assertSame(['a: unknown clause kind 1e+21'], self::vc(['id' => 'a', 'kind' => 1e21]));
        $this->assertSame(['a: unknown clause kind 0'], self::vc(['id' => 'a', 'kind' => -0.0]));
        $this->assertSame(['a: unknown clause kind [object Object]'], self::vc(['id' => 'a', 'kind' => ['x' => 1]]));
    }

    // ---- countClauses / validateContract ------------------------------------------------------------------------------

    public function testCountClauses(): void
    {
        $this->assertSame(0, Contracts::countClauses([]));
        $and = Sign::n(self::cl('a', 'and', ['clauses' => [self::neverC('b', 'x'), self::neverC('c', 'x')]]));
        $this->assertSame(5, Contracts::countClauses([Sign::n(self::neverC('n', 'x')), $and, Sign::n(self::cl('o', 'and', ['clauses' => 'x']))]));
        $this->assertSame(5, Contracts::countClauses(['x', 5, $and]));
        // only an `and` with a list of clauses recurses
        $this->assertSame(1, Contracts::countClauses([Sign::n(self::cl('a', 'always', ['clauses' => [self::neverC('b', 'x')]]))]));
        $this->assertSame(1, Contracts::countClauses([Sign::n(self::cl('a', 'and', ['clauses' => self::neverC('b', 'x')]))]));
        $this->assertSame(17, Contracts::countClauses(self::chain(16)));
        $this->assertSame(274, Contracts::countClauses(self::chain(17)));
        $this->assertSame(274, Contracts::countClauses(self::chain(20)));
    }

    public function testValidateContractVersionMessages(): void
    {
        $v = static fn(array $c): array => Contracts::validateContract(Sign::n($c));
        $this->assertSame(['unsupported version undefined'], $v(['principal' => 'p']));
        $this->assertSame(['unsupported version null'], $v(['version' => null, 'principal' => 'p']));
        $this->assertSame(['unsupported version true'], $v(['version' => true, 'principal' => 'p']));
        $this->assertSame(['unsupported version 1'], $v(['version' => '1', 'principal' => 'p']));
        $this->assertSame(['unsupported version 2'], $v(['version' => 2, 'principal' => 'p']));
        $this->assertSame(['unsupported version 1.5'], $v(['version' => 1.5, 'principal' => 'p']));
        $this->assertSame(['unsupported version 1e+21'], $v(['version' => 1e21, 'principal' => 'p']));
        $this->assertSame(['unsupported version 0'], $v(['version' => -0.0, 'principal' => 'p']));
        $this->assertSame([], $v(['version' => 1, 'principal' => 'p']));
        $this->assertSame([], Contracts::validateContract(Obj::of(['version' => new Num('1.0'), 'principal' => 'p'])));
        // a raw PHP 1 is not a parsed JSON number
        $this->assertSame(['unsupported version 1'], Contracts::validateContract(Obj::of(['version' => 1, 'principal' => 'p'])));
        $this->assertSame(['unsupported version 1'], Contracts::validateContract(Obj::of(['version' => 1.0, 'principal' => 'p'])));
        $this->assertSame(['contract not an object'], Contracts::validateContract('x'));
        $this->assertSame(['principal missing'], $v(['version' => 1, 'principal' => '']));
        $this->assertSame(['principal missing'], $v(['version' => 1, 'principal' => 5]));
    }

    public function testValidateContractKeepsEarlierProblemsOnEarlyReturn(): void
    {
        $v = static fn(array $c): array => Contracts::validateContract(Sign::n($c));
        $this->assertSame(['unsupported version 2', 'principal missing', 'invariants not an array'], $v(['version' => 2, 'principal' => '', 'invariants' => 5]));
        $this->assertSame(['unsupported version 2', 'clauses not an array'], $v(['version' => 2, 'principal' => 'p', 'clauses' => 5]));
        $this->assertSame(['invariants not an array'], $v(['version' => 1, 'principal' => 'p', 'invariants' => 5]));
        $this->assertSame(['clauses not an array'], $v(['version' => 1, 'principal' => 'p', 'clauses' => self::neverC('c', 'x')]));
    }

    public function testValidateContractAggregatesInvariantAndClauseProblems(): void
    {
        $v = static fn(array $c): array => Contracts::validateContract(Sign::n($c));
        $this->assertSame(
            ['unsupported version 2', 'i1: unknown invariant kind zzz', 'i2: unknown invariant kind qqq'],
            $v(['version' => 2, 'principal' => 'p', 'invariants' => [self::cl('i1', 'zzz'), self::cl('i2', 'qqq')]]),
        );
        $this->assertSame(['invariant not an object'], $v(['version' => 1, 'principal' => 'p', 'invariants' => [5]]));
        $this->assertSame(
            ['unsupported version 2', 'c1: unknown clause kind bogus', 'c2: unknown clause kind bogus'],
            $v(['version' => 2, 'principal' => 'p', 'clauses' => [self::cl('c1', 'bogus'), self::cl('c2', 'bogus')]]),
        );
        // an invariant without a usable id does not stop the duplicate scan of the ones after it
        $inv = ['id' => 'i1', 'kind' => 'never', 'when' => self::w('x')];
        $this->assertSame(
            ['<no id>: missing id', 'i1: duplicate id'],
            $v(['version' => 1, 'principal' => 'p', 'invariants' => [['kind' => 'never'], $inv, $inv]]),
        );
        $this->assertSame(
            ['<no id>: missing id', 'i1: duplicate id'],
            $v(['version' => 1, 'principal' => 'p', 'invariants' => [['id' => 5, 'kind' => 'never'], $inv, $inv]]),
        );
        // clause ids are disjoint from invariant ids
        $this->assertSame(['i1: duplicate id'], $v(['version' => 1, 'principal' => 'p', 'invariants' => [$inv], 'clauses' => [self::neverC('i1', 'x')]]));
        $this->assertSame([], $v(['version' => 1, 'principal' => 'p', 'invariants' => [$inv], 'clauses' => [self::neverC('c1', 'x')]]));
    }

    public function testValidateContractBounds(): void
    {
        $v = static fn(array $c): array => Contracts::validateContract(Sign::n($c));
        $invs = static function (int $n): array {
            $o = [];
            for ($i = 0; $i < $n; $i++) {
                $o[] = ['id' => "i$i", 'kind' => 'never', 'when' => self::w('x')];
            }
            return $o;
        };
        $cls = static function (int $n): array {
            $o = [];
            for ($i = 0; $i < $n; $i++) {
                $o[] = self::neverC("c$i", 'x');
            }
            return $o;
        };
        $this->assertSame([], $v(['version' => 1, 'principal' => 'p', 'invariants' => $invs(256)]));
        $this->assertSame(['too many invariants'], $v(['version' => 1, 'principal' => 'p', 'invariants' => $invs(257)]));
        $this->assertSame([], $v(['version' => 1, 'principal' => 'p', 'clauses' => $cls(256)]));
        $this->assertSame(['too many clauses'], $v(['version' => 1, 'principal' => 'p', 'clauses' => $cls(257)]));
    }

    // ---- sign / verify ------------------------------------------------------------------------------------------------

    public function testSignContractRefusalMessage(): void
    {
        $kp = KeyPair::generate();
        try {
            Contracts::signContract(Sign::n(['version' => 2, 'principal' => '']), $kp);
            $this->fail('expected a refusal');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('signContract: unsupported version 2; principal missing', $e->getMessage());
        }
    }

    public function testVerifyContractReasonsAndFailClosed(): void
    {
        $kp = KeyPair::generate();
        $body = Sign::n(['version' => 1, 'principal' => $kp->public, 'clauses' => [self::neverC('n1', 'x')]]);
        $sc = Contracts::signContract($body, $kp);
        $this->assertSame(['ok' => true], Contracts::verifyContract($sc));
        $this->assertSame(['ok' => true], Contracts::verifyContract($sc, $kp->public));
        $this->assertSame(['ok' => false, 'reason' => 'principal mismatch'], Contracts::verifyContract($sc, KeyPair::generate()->public));
        $this->assertSame(['ok' => false, 'reason' => 'unsupported version 2'], Contracts::verifyContract(Sign::n(['version' => 2, 'principal' => 'p'])));

        $tampered = $sc->without('zz');
        $tampered->set('clauses', [Sign::n(self::neverC('n1', 'y'))]);
        $this->assertSame(['ok' => false, 'reason' => 'id does not match content'], Contracts::verifyContract($tampered));
        $this->assertSame(['ok' => false, 'reason' => 'id does not match content'], Contracts::verifyContract($sc->without('id')));
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], Contracts::verifyContract($sc->without('sig')));
        $other = Contracts::signContract($body, KeyPair::generate());
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], Contracts::verifyContract($other));

        $unhashable = $sc->without('zz');
        $unhashable->set('extra', new \stdClass());
        $this->assertSame(['ok' => false, 'reason' => 'verification error (fail closed)'], Contracts::verifyContract($unhashable));
    }

    public function testEmbeddedConstitutionAndLift(): void
    {
        $inv = ['id' => 'i1', 'kind' => 'never', 'when' => self::w('x')];
        $c = Sign::n(['version' => 1, 'principal' => 'pk', 'invariants' => [$inv], 'clauses' => [self::neverC('c1', 'x')]]);
        $e = Contracts::embeddedConstitution($c);
        $this->assertSame(['version', 'principal', 'invariants'], $e->keys());
        $this->assertInstanceOf(Num::class, $e->get('version'));
        $this->assertSame('1', $e->get('version')->lexeme);
        $this->assertSame('pk', $e->get('principal'));
        $this->assertSame($c->get('invariants'), $e->get('invariants'));
        $this->assertSame([], Contracts::embeddedConstitution(Sign::n(['version' => 1, 'principal' => 'pk']))->get('invariants'));
        $this->assertSame([], Contracts::embeddedConstitution(Sign::n(['version' => 1, 'principal' => 'pk', 'invariants' => 5]))->get('invariants'));

        $lift = Contracts::contractFromConstitution($e);
        $this->assertSame(['version', 'principal', 'invariants', 'clauses'], $lift->keys());
        $this->assertSame('1', $lift->get('version')->lexeme);
        $this->assertSame('pk', $lift->get('principal'));
        $this->assertSame($e->get('invariants'), $lift->get('invariants'));
        $this->assertSame([], $lift->get('clauses'));
    }

    // ---- clause evaluation --------------------------------------------------------------------------------------------

    public function testEvalAlwaysAndNever(): void
    {
        $always = self::cl('a1', 'always', ['p' => self::w('x')]);
        $this->assertSame(self::exp(true, null, [self::row('a1', 'always', true)]), self::ev($always, self::act('x'), self::st()));
        $r = 'always-invariant violated (action does not satisfy p)';
        $this->assertSame(self::exp(false, $r, [self::row('a1', 'always', false, $r)]), self::ev($always, self::act('y'), self::st()));
        $this->assertSame(self::exp(false, 'D', [self::row('a1', 'always', false, 'D')]), self::ev($always + ['description' => 'D'], self::act('y'), self::st()));

        $never = self::cl('n1', 'never', ['p' => self::w('x')]);
        $nr = 'never-invariant violated (forbidden action)';
        $this->assertSame(self::exp(false, $nr, [self::row('n1', 'never', false, $nr)]), self::ev($never, self::act('x'), self::st()));
        $this->assertSame(self::exp(true, null, [self::row('n1', 'never', true)]), self::ev($never, self::act('y'), self::st()));
        $this->assertSame(self::exp(false, 'D', [self::row('n1', 'never', false, 'D')]), self::ev($never + ['description' => 'D'], self::act('x'), self::st()));
    }

    public function testEvalPrecedence(): void
    {
        $viol = 'precedence violated (prerequisite p not yet admitted before q)';
        foreach (['precedes', 'requires_prior'] as $kind) {
            $c = self::cl('p1', $kind, ['p' => self::w('a'), 'q' => self::w('b')]);
            $pass = self::row('p1', $kind, true);
            $this->assertSame(self::exp(true, null, [$pass]), self::ev($c, self::act('z'), self::st()), "$kind other");
            $this->assertSame(self::exp(true, null, [$pass], ['p1' => 100.0]), self::ev($c, self::act('a'), self::st()), "$kind prerequisite");
            $this->assertSame(self::exp(false, $viol, [self::row('p1', $kind, false, $viol)]), self::ev($c, self::act('b'), self::st()), "$kind guarded");
            $this->assertSame(self::exp(false, 'D', [self::row('p1', $kind, false, 'D')]), self::ev($c + ['description' => 'D'], self::act('b'), self::st()), "$kind described");
            $this->assertSame(self::exp(true, null, [$pass]), self::ev($c, self::act('b'), self::st([], ['p1' => 50])), "$kind latched guarded");
            $this->assertSame(self::exp(true, null, [$pass]), self::ev($c, self::act('a'), self::st([], ['p1' => 50])), "$kind latched prerequisite");
        }
    }

    public function testEvalRespondsWithin(): void
    {
        $c = self::cl('r1', 'responds_within', ['p' => self::w('a'), 'q' => self::w('b'), 'within' => 3]);
        $pass = self::row('r1', 'responds_within', true);
        $this->assertSame(self::exp(true, null, [$pass], [], ['r1' => null]), self::ev($c, self::act('z'), self::st()));
        $this->assertSame(self::exp(true, null, [$pass], [], ['r1' => 3.0]), self::ev($c, self::act('a'), self::st()));
        $this->assertSame(self::exp(true, null, [$pass], [], ['r1' => 1.0]), self::ev($c, self::act('z'), self::st(['r1' => 2])));
        $this->assertSame(self::exp(true, null, [$pass], [], ['r1' => null]), self::ev($c, self::act('b'), self::st(['r1' => 2])));
        $this->assertSame(self::exp(true, null, [$pass], [], ['r1' => 1.0]), self::ev($c, self::act('a'), self::st(['r1' => 2])));
        $this->assertSame(self::exp(true, null, [$pass], [], ['r1' => 3.0]), self::ev($c, self::act('a'), self::st(['r1' => 5])));
        $miss = 'bounded-liveness deadline missed (no q within 3 actions of p)';
        $this->assertSame(self::exp(false, $miss, [self::row('r1', 'responds_within', false, $miss)]), self::ev($c, self::act('z'), self::st(['r1' => 1])));
        $this->assertSame(self::exp(false, $miss, [self::row('r1', 'responds_within', false, $miss)]), self::ev($c, self::act('a'), self::st(['r1' => 1])));
        $this->assertSame(self::exp(false, 'D', [self::row('r1', 'responds_within', false, 'D')]), self::ev($c + ['description' => 'D'], self::act('z'), self::st(['r1' => 1])));
    }

    public function testEvalAndMergesChildren(): void
    {
        $p1 = self::cl('p1', 'precedes', ['p' => self::w('a'), 'q' => self::w('b')]);
        $p2 = self::cl('p2', 'requires_prior', ['p' => self::w('a'), 'q' => self::w('c')]);
        $r1 = self::cl('r1', 'responds_within', ['p' => self::w('a'), 'q' => self::w('b'), 'within' => 3]);
        $r2 = self::cl('r2', 'responds_within', ['p' => self::w('a'), 'q' => self::w('b'), 'within' => 5]);
        $n1 = self::neverC('n1', 'x');
        $and = self::cl('g', 'and', ['clauses' => [$p1, $r1, $n1, $p2, $r2]]);
        $this->assertSame(
            self::exp(true, null, [
                self::row('p1', 'precedes', true), self::row('r1', 'responds_within', true), self::row('n1', 'never', true),
                self::row('p2', 'requires_prior', true), self::row('r2', 'responds_within', true),
            ], ['p1' => 100.0, 'p2' => 100.0], ['r1' => 3.0, 'r2' => 5.0]),
            self::ev($and, self::act('a'), self::st()),
        );

        $a1 = self::cl('a1', 'always', ['p' => self::w('x')]);
        $a2 = self::cl('a2', 'always', ['p' => self::w('zzz')]);
        $nr = 'never-invariant violated (forbidden action)';
        $ar = 'always-invariant violated (action does not satisfy p)';
        $this->assertSame(
            self::exp(false, $nr, [self::row('a1', 'always', true), self::row('n1', 'never', false, $nr), self::row('a2', 'always', false, $ar)]),
            self::ev(self::cl('g', 'and', ['clauses' => [$a1, $n1, $a2]]), self::act('x'), self::st()),
        );
        $this->assertSame(
            self::exp(false, $nr, [self::row('n1', 'never', false, $nr), self::row('a1', 'always', true)]),
            self::ev(self::cl('g', 'and', ['clauses' => [$n1, $a1]]), self::act('x'), self::st()),
        );
        // a nested `and` rolls its children's rows up
        $inner = self::cl('h', 'and', ['clauses' => [$n1]]);
        $this->assertSame(
            self::exp(false, $nr, [self::row('n1', 'never', false, $nr), self::row('a1', 'always', true)]),
            self::ev(self::cl('g', 'and', ['clauses' => [$inner, $a1]]), self::act('x'), self::st()),
        );
    }

    public function testEvalUnknownKindAndEvaluationErrorFailClosed(): void
    {
        $u = 'unknown clause kind (fail closed)';
        $this->assertSame(self::exp(false, $u, [self::row('b1', 'bogus', false, $u)]), self::ev(self::cl('b1', 'bogus'), self::act('x'), self::st()));
        // a state with no `latched` map makes the precedence branch throw: the clause is denied
        $e = 'clause evaluation error (fail closed)';
        $broken = Obj::of(['now' => Prohibitions::num(1), 'seq' => Prohibitions::num(0)]);
        $c = self::cl('p1', 'precedes', ['p' => self::w('a'), 'q' => self::w('b')]);
        $this->assertSame(self::exp(false, $e, [self::row('p1', 'precedes', false, $e)]), self::ev($c, self::act('z'), $broken));
    }

    // ---- check --------------------------------------------------------------------------------------------------------

    public function testCheckEvaluatesInvariantsThenClauses(): void
    {
        $c = self::contract([self::cl('c1', 'always', ['p' => self::w('y')])], [['id' => 'i1', 'kind' => 'never', 'when' => self::w('x')]]);
        $cr = 'always-invariant violated (action does not satisfy p)';
        $this->assertSame([
            'ok' => false,
            'violated' => ['i1', 'c1'],
            'reasons' => ['i1: forbidden action', "c1: $cr"],
            'evaluated' => [self::row('i1', 'never', false, 'forbidden action'), self::row('c1', 'always', false, $cr)],
        ], self::chk(self::act('x'), $c, self::st()));
        $this->assertSame([
            'ok' => true,
            'violated' => [],
            'reasons' => [],
            'evaluated' => [self::row('i1', 'never', true), self::row('c1', 'always', true)],
        ], self::chk(self::act('y'), $c, self::st()));
        $none = self::contract([self::cl('c1', 'always', ['p' => self::w('y')])], []);
        $this->assertSame(['ok' => true, 'violated' => [], 'reasons' => [], 'evaluated' => [self::row('c1', 'always', true)]], self::chk(self::act('y'), $none, self::st()));
    }

    public function testCheckStructuralRefusals(): void
    {
        $c = self::contract([self::neverC('n1', 'x')]);
        $fail = static fn(string $id, string $reason): array => [
            'ok' => false, 'violated' => [$id], 'reasons' => ["$id: $reason"], 'evaluated' => [self::row($id, 'structural', false, $reason)],
        ];
        $this->assertSame($fail('<contract>', 'contract not an object'), self::chk(self::act('x'), 'x', self::st()));
        $this->assertSame($fail('<contract>', 'unsupported version 2'), self::chk(self::act('x'), Sign::n(['version' => 2, 'principal' => 'p']), self::st()));
        $this->assertSame($fail('<action>', 'malformed action'), self::chk(5, $c, self::st()));
        $this->assertSame($fail('<action>', 'malformed action'), self::chk(null, $c, self::st()));
        $this->assertSame($fail('<action>', 'malformed action'), self::chk(Obj::of([]), $c, self::st()));
        $this->assertSame($fail('<action>', 'malformed action'), self::chk(Sign::n(['action' => ['verb' => 5, 'resource' => '/r']]), $c, self::st()));
        $this->assertSame($fail('<action>', 'malformed action'), self::chk(Sign::n(['action' => ['verb' => 'x', 'resource' => 5]]), $c, self::st()));
        $this->assertSame($fail('<state>', 'malformed monitor state'), self::chk(self::act('x'), $c, null));
        // contract is judged before the action, the action before the state
        $this->assertSame($fail('<contract>', 'contract not an object'), self::chk(5, 'x', null));
        $this->assertSame($fail('<action>', 'malformed action'), self::chk(5, $c, null));
    }

    // ---- advance ------------------------------------------------------------------------------------------------------

    private static function fl(Obj $o, string $k): ?float
    {
        return Prohibitions::fin($o->get($k));
    }

    public function testAdvanceCarriesLatchesAndDeadlines(): void
    {
        $ca = self::contract([
            self::cl('7', 'precedes', ['p' => self::w('a'), 'q' => self::w('b')]),
            self::cl('8', 'responds_within', ['p' => self::w('a'), 'q' => self::w('b'), 'within' => 3]),
        ]);
        $s0 = self::st();
        $r1 = Contracts::advance($s0, self::act('a'), $ca, ['now' => 150.0]);
        $this->assertTrue($r1['ok']);
        $this->assertSame('none', $r1['decidedBy']);
        $this->assertSame([], $r1['violated']);
        $s1 = $r1['next'];
        $this->assertNull(Prohibitions::stateProblem($s1));
        $this->assertSame(1.0, self::fl($s1, 'seq'));
        $this->assertSame(150.0, self::fl($s1, 'now'));
        $this->assertSame(['7'], $s1->get('latched')->keys());
        $this->assertSame(150.0, self::fl($s1->get('latched'), '7'));
        $this->assertSame(['8'], $s1->get('deadlines')->keys());
        $this->assertSame(3.0, self::fl($s1->get('deadlines'), '8'));
        $this->assertSame(0.0, self::fl($s0, 'seq'));

        $s2 = Contracts::advance($s1, self::act('a'), $ca, ['now' => 160.0])['next'];
        $this->assertSame(150.0, self::fl($s2->get('latched'), '7'));
        $this->assertSame(2.0, self::fl($s2->get('deadlines'), '8'));
        $this->assertSame(2.0, self::fl($s2, 'seq'));

        $s3 = Contracts::advance($s2, self::act('z'), $ca, ['now' => 170.0])['next'];
        $this->assertSame(1.0, self::fl($s3->get('deadlines'), '8'));

        $miss = Contracts::advance($s3, self::act('z'), $ca, ['now' => 190.0]);
        $this->assertFalse($miss['ok']);
        $this->assertSame('contract', $miss['decidedBy']);
        $this->assertSame(['8'], $miss['violated']);
        $this->assertSame(['8: bounded-liveness deadline missed (no q within 3 actions of p)'], $miss['reasons']);
        $this->assertSame($s3, $miss['next']);

        $s4 = Contracts::advance($s3, self::act('b'), $ca, ['now' => 180.0])['next'];
        $this->assertFalse($s4->has('deadlines'));
        $this->assertSame(['7'], $s4->get('latched')->keys());
        $this->assertSame(180.0, self::fl($s4, 'now'));
        // `now` defaults to the state's own clock
        $this->assertSame(100.0, self::fl(Contracts::advance($s0, self::act('z'), $ca)['next'], 'now'));
    }

    public function testAdvanceKeepsForeignDeadlines(): void
    {
        $c = self::contract([self::cl('c1', 'always', ['p' => self::w('z')])]);
        $r = Contracts::advance(self::st(['zz' => 4]), self::act('z'), $c);
        $this->assertTrue($r['ok']);
        $this->assertSame(['zz'], $r['next']->get('deadlines')->keys());
        $this->assertSame(4.0, self::fl($r['next']->get('deadlines'), 'zz'));
    }

    public function testAdvanceExpectedSeqIsStrict(): void
    {
        $c = self::contract([self::neverC('n1', 'x')]);
        $stale = '<state>: stale state head (seq)';
        foreach ([true, '0', 1, 0.5, NAN, [], new Num('1')] as $bad) {
            $r = Contracts::advance(self::st(), self::act('z'), $c, ['expectedSeq' => $bad]);
            $this->assertFalse($r['ok'], var_export($bad, true));
            $this->assertSame('state', $r['decidedBy']);
            $this->assertSame(['<state>'], $r['violated']);
            $this->assertSame([$stale], $r['reasons']);
        }
        foreach ([0, 0.0, new Num('0'), new Num('0.0')] as $good) {
            $this->assertTrue(Contracts::advance(self::st(), self::act('z'), $c, ['expectedSeq' => $good])['ok']);
        }
        // an explicit null is a stale head (the reference checks `!== undefined`); only an absent option skips the check
        $this->assertSame([$stale], Contracts::advance(self::st(), self::act('z'), $c, ['expectedSeq' => null])['reasons']);
        $this->assertSame(['<state>: stale state head (digest)'], Contracts::advance(self::st(), self::act('z'), $c, ['expectedStateDigest' => null])['reasons']);
        $this->assertTrue(Contracts::advance(self::st(), self::act('z'), $c, [])['ok']);
        $this->assertTrue(Contracts::advance(self::st(), self::act('z'), $c, ['expectedStateDigest' => Prohibitions::stateDigest(self::st())])['ok']);
    }

    public function testAnExplicitNullContractPinNeverMatches(): void
    {
        $kp = KeyPair::generate();
        $sc = Contracts::signContract(Sign::n(['version' => 1, 'principal' => $kp->public, 'clauses' => [self::neverC('n1', 'x')]]), $kp);
        $this->assertSame(['ok' => true], Contracts::verifyContract($sc));
        $this->assertSame(['ok' => false, 'reason' => 'principal mismatch'], Contracts::verifyContract($sc, null));
        $this->assertSame(['ok' => true], Contracts::verifyContract($sc, $kp->public));
    }

    public function testAdvanceRefusalsMergeStateReasons(): void
    {
        $c = self::contract([self::neverC('n1', 'x')]);
        $s0 = self::st();
        $r = Contracts::advance($s0, self::act('x'), $c, ['expectedSeq' => 5]);
        $this->assertFalse($r['ok']);
        $this->assertSame('state', $r['decidedBy']);
        $this->assertSame(['n1', '<state>'], $r['violated']);
        $this->assertSame(['n1: never-invariant violated (forbidden action)', '<state>: stale state head (seq)'], $r['reasons']);
        $this->assertSame($s0, $r['next']);
        $this->assertSame([self::row('n1', 'never', false, 'never-invariant violated (forbidden action)')], self::rows($r['evaluated']));

        $r = Contracts::advance($s0, self::act('z'), $c, ['expectedStateDigest' => 'nope']);
        $this->assertSame(['<state>'], $r['violated']);
        $this->assertSame(['<state>: stale state head (digest)'], $r['reasons']);
        $this->assertTrue(Contracts::advance($s0, self::act('z'), $c, ['expectedStateDigest' => Prohibitions::stateDigest($s0)])['ok']);

        $r = Contracts::advance($s0, self::act('z'), $c, ['now' => 50.0]);
        $this->assertSame('state', $r['decidedBy']);
        $this->assertSame(['<state>'], $r['violated']);
        $this->assertSame(['<state>: advance failed: clock regression'], $r['reasons']);

        // an unusable state: the verdict already says so, the stale head is added once
        $r = Contracts::advance(null, self::act('z'), $c);
        $this->assertSame('state', $r['decidedBy']);
        $this->assertSame(['<state>'], $r['violated']);
        $this->assertSame(['<state>: malformed monitor state'], $r['reasons']);
        $this->assertNull($r['next']);
        $r = Contracts::advance(null, self::act('z'), $c, ['expectedSeq' => 0]);
        $this->assertSame(['<state>'], $r['violated']);
        $this->assertSame(['<state>: malformed monitor state', '<state>: stale state head (seq)'], $r['reasons']);
        $this->assertSame(['ok', 'violated', 'reasons', 'evaluated', 'next', 'decidedBy'], array_keys($r));
    }

    public function testAdvanceDecidedByDistinguishesStructuralFromContract(): void
    {
        $s0 = self::st();
        $this->assertSame('state', Contracts::advance($s0, 5, self::contract([]))['decidedBy']);
        $this->assertSame('state', Contracts::advance($s0, self::act('x'), 'x')['decidedBy']);
        foreach (['n1', '<a', 'b>', 'a>b', '<>x'] as $id) {
            $r = Contracts::advance($s0, self::act('x'), self::contract([self::neverC($id, 'x')]));
            $this->assertSame([$id], $r['violated'], $id);
            $this->assertSame('contract', $r['decidedBy'], $id);
        }
        $r = Contracts::advance($s0, self::act('x'), self::contract([self::neverC('<a', 'x'), self::neverC('b>', 'x')]));
        $this->assertSame('contract', $r['decidedBy']);
        $this->assertSame('state', Contracts::advance($s0, self::act('x'), self::contract([self::neverC('<a>', 'x')]))['decidedBy']);
    }

    public function testCheckAndAdvanceShapes(): void
    {
        $c = self::contract([self::neverC('n1', 'x')]);
        $s0 = self::st();
        $ok = Contracts::checkAndAdvance(true, $s0, self::act('z'), $c);
        $this->assertSame(['allow', 'permitted', 'ok', 'violated', 'reasons', 'evaluated', 'next', 'decidedBy'], array_keys($ok));
        $this->assertTrue($ok['allow']);
        $this->assertTrue($ok['permitted']);
        $this->assertSame('none', $ok['decidedBy']);

        foreach ([false, 1, 'true', null] as $perm) {
            $r = Contracts::checkAndAdvance($perm, $s0, self::act('z'), $c);
            $this->assertSame(['ok', 'violated', 'reasons', 'evaluated', 'next', 'decidedBy', 'allow', 'permitted'], array_keys($r));
            $this->assertFalse($r['ok']);
            $this->assertFalse($r['allow']);
            $this->assertFalse($r['permitted']);
            $this->assertSame([], $r['violated']);
            $this->assertSame(['<permission>: not permitted'], $r['reasons']);
            $this->assertSame($s0, $r['next']);
            $this->assertSame('contract', $r['decidedBy']);
        }
        $bad = Contracts::checkAndAdvance(false, $s0, self::act('x'), $c);
        // a real violation is reported on its own: the permission note is only added to an otherwise allowed action
        $this->assertSame(['n1: never-invariant violated (forbidden action)'], $bad['reasons']);
        $this->assertSame(['n1'], $bad['violated']);

        $deny = Contracts::checkAndAdvance(true, $s0, self::act('x'), $c);
        $this->assertSame(['allow', 'permitted', 'ok', 'violated', 'reasons', 'evaluated', 'next', 'decidedBy'], array_keys($deny));
        $this->assertFalse($deny['allow']);
        $this->assertTrue($deny['permitted']);
        $this->assertFalse($deny['ok']);
    }

    // ---- enforcer document --------------------------------------------------------------------------------------------

    public function testEnforcerDocValidation(): void
    {
        $doc = static function (array $over = []): Obj {
            $d = Obj::of(['v' => Prohibitions::num(1), 'contract_id' => 'cid', 'state' => Prohibitions::emptyState(1.0)]);
            foreach ($over as $k => $v) {
                $d->set($k, $v);
            }
            return $d;
        };
        $lat = static fn(array $a): Obj => $doc(['latched' => Obj::of($a)]);
        $n = static fn(string $s): Num => new Num($s);

        $this->assertFalse(Contracts::enforcerDoc(null, 'cid'));
        $this->assertFalse(Contracts::enforcerDoc(5, 'cid'));
        $this->assertFalse(Contracts::enforcerDoc('x', 'cid'));
        $this->assertTrue(Contracts::enforcerDoc($doc(), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($doc(), 'other'));
        $this->assertFalse(Contracts::enforcerDoc($doc(['v' => $n('2')]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($doc(['state' => null]), 'cid'));

        $this->assertTrue(Contracts::enforcerDoc($lat(['seq' => $n('0'), 'violated' => []]), 'cid'));
        $this->assertTrue(Contracts::enforcerDoc($lat(['seq' => $n('3'), 'violated' => ['a', 'b']]), 'cid'));
        $this->assertTrue(Contracts::enforcerDoc($lat(['seq' => 0, 'violated' => []]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($doc(['latched' => 'x']), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($doc(['latched' => null]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['violated' => []]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('-1'), 'violated' => []]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('1.5'), 'violated' => []]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('-0'), 'violated' => []]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => 'x', 'violated' => []]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('0')]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('0'), 'violated' => 'a']), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('0'), 'violated' => Obj::of(['a' => 'b'])]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('0'), 'violated' => ['k' => 'a']]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('0'), 'violated' => ['a', 5]]), 'cid'));
        $this->assertFalse(Contracts::enforcerDoc($lat(['seq' => $n('0'), 'violated' => [null]]), 'cid'));
    }

    public function testEnforcerResultSeqCoercion(): void
    {
        $m = new \ReflectionMethod(ContractEnforcer::class, 'result');
        $call = static fn(mixed $seq): array => $m->invoke(null, false, 'r', ['v'], ['w'], $seq);
        $this->assertSame(['allow' => false, 'reason' => 'r', 'violated' => ['v'], 'reasons' => ['w'], 'seq' => 0], $call(null));
        $this->assertSame(0, $call('abc')['seq']);
        $this->assertSame(0, $call(true)['seq']);
        $this->assertSame(5, $call(new Num('5'))['seq']);
        $this->assertSame(7, $call(7.0)['seq']);
        $this->assertSame(9, $call(9)['seq']);
    }

    // ---- enforcer -----------------------------------------------------------------------------------------------------

    /** @return array{0: ContractEnforcer, 1: MemoryAtomicKv, 2: Obj, 3: KeyPair} */
    private static function enf(?callable $now = null, ?bool $latch = null, ?string $key = null): array
    {
        $kp = KeyPair::generate();
        $sc = Contracts::signContract(Sign::n(['version' => 1, 'principal' => $kp->public, 'clauses' => [self::neverC('n1', 'bad')]]), $kp);
        $kv = new MemoryAtomicKv();
        $e = $latch === null
            ? ContractEnforcer::open($kv, $sc, $kp->public, $key, $now)
            : ContractEnforcer::open($kv, $sc, $kp->public, $key, $now, $latch);
        return [$e, $kv, $sc, $kp];
    }

    private static function res(bool $allow, string $reason, array $violated, array $reasons, int $seq): array
    {
        return ['allow' => $allow, 'reason' => $reason, 'violated' => $violated, 'reasons' => $reasons, 'seq' => $seq];
    }

    public function testDefaultClockIsIntegerEpochMilliseconds(): void
    {
        for ($i = 0; $i < 12; $i++) {
            [$e, $kv, $sc] = self::enf();
            $before = microtime(true) * 1000;
            $r = $e->check(self::act('ok'));
            $after = microtime(true) * 1000;
            $this->assertSame(self::res(true, 'ok', [], [], 1), $r);
            $now = $e->state()['state']->get('now');
            $f = Prohibitions::fin($now);
            $this->assertGreaterThanOrEqual(floor($before), $f);
            $this->assertLessThanOrEqual($after, $f);
            $this->assertSame(floor($f), $f);
            $this->assertMatchesRegularExpression('/\A[0-9]+\z/', $now->lexeme);
            $this->assertNotNull($kv->get('contract/' . $sc->get('id')));
        }
    }

    public function testKeyDefaultsAndOverride(): void
    {
        $t = 1000.0;
        $clock = static function () use (&$t): float {
            return $t;
        };
        [$e, $kv, $sc] = self::enf($clock, null, 'custom/key');
        $e->check(self::act('ok'));
        $this->assertNotNull($kv->get('custom/key'));
        $this->assertNull($kv->get('contract/' . $sc->get('id')));
        [$e2, $kv2, $sc2] = self::enf($clock);
        $e2->check(self::act('ok'));
        $this->assertNotNull($kv2->get('contract/' . $sc2->get('id')));
    }

    public function testCheckPermissionAndLatching(): void
    {
        $t = 1000.0;
        $clock = static function () use (&$t): float {
            return $t;
        };
        [$e, , $sc, $kp] = self::enf($clock);
        $id = $sc->get('id');
        $this->assertSame(self::res(false, 'permission', [], ['<permission>: not permitted'], 0), $e->check(self::act('ok'), false));
        $this->assertNull($e->state());
        $this->assertSame(self::res(true, 'ok', [], [], 1), $e->check(self::act('ok')));
        $this->assertSame(self::res(true, 'ok', [], [], 1), $e->peek(self::act('ok')));
        $this->assertSame(self::res(false, 'violated', ['n1'], ['n1: never-invariant violated (forbidden action)'], 1), $e->peek(self::act('bad')));
        $this->assertFalse($e->state()['latched']);

        $viol = self::res(false, 'violated', ['n1'], ['n1: never-invariant violated (forbidden action)'], 1);
        $this->assertSame($viol, $e->check(self::act('bad')));
        $this->assertTrue($e->state()['latched']);
        $latched = self::res(false, 'latched', ['n1'], ['<latched>: contract violated at seq 1'], 1);
        $this->assertSame($latched, $e->check(self::act('ok')));
        $this->assertSame($latched, $e->peek(self::act('ok')));

        $this->assertFalse($e->reset(Contracts::signContractReset(KeyPair::generate(), $id, 1)));
        $this->assertFalse($e->reset(Contracts::signContractReset($kp, $id, 0)));
        $this->assertFalse($e->reset(Contracts::signContractReset($kp, $id . 'x', 1)));
        $this->assertFalse($e->reset(5));
        $this->assertFalse($e->reset(null));
        $this->assertTrue($e->state()['latched']);
        $this->assertTrue($e->reset(Contracts::signContractReset($kp, $id, 1)));
        $this->assertFalse($e->state()['latched']);
        $this->assertFalse($e->reset(Contracts::signContractReset($kp, $id, 1)));
        $this->assertSame(self::res(true, 'ok', [], [], 2), $e->check(self::act('ok')));
    }

    public function testViolationWithoutLatching(): void
    {
        $clock = static fn(): float => 1000.0;
        [$e] = self::enf($clock, false);
        $this->assertSame(self::res(false, 'violated', ['n1'], ['n1: never-invariant violated (forbidden action)'], 0), $e->check(self::act('bad')));
        $this->assertNull($e->state());
        $this->assertSame(self::res(true, 'ok', [], [], 1), $e->check(self::act('ok')));
        $this->assertFalse($e->state()['latched']);
        // a later violation still just denies
        $this->assertSame('violated', $e->check(self::act('bad'))['reason']);
        $this->assertFalse($e->state()['latched']);
    }

    public function testStateClockNeverGoesBack(): void
    {
        $t = 1000.0;
        $clock = static function () use (&$t): float {
            return $t;
        };
        [$e] = self::enf($clock);
        $e->check(self::act('ok'));
        $this->assertSame(1000.0, Prohibitions::fin($e->state()['state']->get('now')));
        $t = 2000.0;
        $e->check(self::act('ok'));
        $this->assertSame(2000.0, Prohibitions::fin($e->state()['state']->get('now')));
        $t = 500.0;
        $this->assertSame(self::res(true, 'ok', [], [], 3), $e->check(self::act('ok')));
        $this->assertSame(2000.0, Prohibitions::fin($e->state()['state']->get('now')));
    }

    public function testNonFiniteClock(): void
    {
        $t = 1000.0;
        $clock = static function () use (&$t): float {
            return $t;
        };
        // first ever call: the advance refuses the unusable clock
        [$e] = self::enf(static fn(): float => NAN);
        $this->assertSame(self::res(false, 'state-error', [], ['<state>: advance failed: clock regression'], 0), $e->check(self::act('ok')));
        $this->assertNull($e->state());
        // a violation is still recorded, against a state that starts at time 0
        $this->assertSame(self::res(false, 'violated', ['n1'], ['n1: never-invariant violated (forbidden action)'], 0), $e->check(self::act('bad')));
        $s = $e->state();
        $this->assertTrue($s['latched']);
        $this->assertSame(0.0, Prohibitions::fin($s['state']->get('now')));

        // an existing state refuses before anything else
        [$e2] = self::enf($clock);
        $this->assertTrue($e2->check(self::act('ok'))['allow']);
        $t = NAN;
        $this->assertSame(self::res(false, 'state-error', [], ['<state>: clock is not finite'], 1), $e2->check(self::act('ok')));
        $t = INF;
        $this->assertSame(self::res(false, 'state-error', [], ['<state>: clock is not finite'], 1), $e2->check(self::act('ok')));
    }

    public function testCorruptOrForeignStoredState(): void
    {
        $clock = static fn(): float => 1000.0;
        [$e, $kv, $sc, $kp] = self::enf($clock);
        $key = 'contract/' . $sc->get('id');
        $foreign = KvDoc::enc(Obj::of([
            'v' => Prohibitions::num(1), 'contract_id' => 'other', 'state' => Prohibitions::emptyState(1.0),
            'latched' => Obj::of(['seq' => Prohibitions::num(0), 'violated' => ['x']]),
        ]));
        $kv->update($key, static fn(?string $p): string => $foreign);
        $msg = '<state>: stored state is corrupt or belongs to another contract';
        $this->assertSame(self::res(false, 'state-error', [], [$msg], 0), $e->check(self::act('ok')));
        $this->assertSame(self::res(false, 'state-error', [], [$msg], 0), $e->peek(self::act('ok')));
        try {
            $e->state();
            $this->fail('expected a corrupt-state error');
        } catch (ContractEnforcerError $x) {
            $this->assertSame('ContractEnforcer: stored state is corrupt or belongs to another contract', $x->getMessage());
        }
        // a latched document of another contract is never un-latched by this contract's reset
        $this->assertFalse($e->reset(Contracts::signContractReset($kp, $sc->get('id'), 0)));
        $this->assertSame($foreign, $kv->get($key));

        [$e2, $kv2, $sc2] = self::enf($clock);
        $kv2->update('contract/' . $sc2->get('id'), static fn(?string $p): string => '[1]');
        $this->assertSame(self::res(false, 'state-error', [], [$msg], 0), $e2->check(self::act('ok')));
        $this->assertSame(self::res(false, 'state-error', [], [$msg], 0), $e2->peek(self::act('ok')));
    }

    public function testPeekOnFreshStoreAndStateOfFreshStore(): void
    {
        [$e] = self::enf(static fn(): float => 1000.0);
        $this->assertNull($e->state());
        $this->assertSame(self::res(true, 'ok', [], [], 0), $e->peek(self::act('ok')));
        $this->assertSame(self::res(false, 'violated', ['n1'], ['n1: never-invariant violated (forbidden action)'], 0), $e->peek(self::act('bad')));
        $this->assertNull($e->state());
        $this->assertFalse($e->reset(Contracts::signContractReset(KeyPair::generate(), 'x', 0)));
    }

    public function testStoreFaultsFailClosed(): void
    {
        $noop = new class implements AtomicKv {
            public function get(string $key): ?string
            {
                return null;
            }

            public function update(string $key, callable $fn): void
            {
            }
        };
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
        $kp = KeyPair::generate();
        $sc = Contracts::signContract(Sign::n(['version' => 1, 'principal' => $kp->public, 'clauses' => [self::neverC('n1', 'bad')]]), $kp);
        $clock = static fn(): float => 1000.0;

        $e = ContractEnforcer::open($noop, $sc, $kp->public, null, $clock);
        $this->assertSame(self::res(false, 'store-error', [], ['store unavailable'], 0), $e->check(self::act('ok')));

        $e = ContractEnforcer::open($down, $sc, $kp->public, null, $clock);
        $closed = self::res(false, 'store-error', [], ['store error (fail closed)'], 0);
        $this->assertSame($closed, $e->check(self::act('ok')));
        $this->assertSame($closed, $e->peek(self::act('ok')));
        $this->assertFalse($e->reset(Contracts::signContractReset($kp, $sc->get('id'), 0)));

        $boom = static function (): float {
            throw new \RuntimeException('clock');
        };
        [$e2] = self::enf($boom);
        $this->assertSame($closed, $e2->check(self::act('ok')));
        $this->assertSame($closed, $e2->peek(self::act('ok')));
    }

    public function testEnforcerCoercesTheRetainedContractIdToString(): void
    {
        $clock = static fn(): float => 1000.0;
        [$e, , $sc, $kp] = self::enf($clock);
        // the enforcer keeps a reference to the verified contract object; a later numeric id is read as its string form
        $sc->set('id', 5);
        $this->assertSame(self::res(true, 'ok', [], [], 1), $e->check(self::act('ok')));
        $this->assertSame(self::res(true, 'ok', [], [], 2), $e->check(self::act('ok')));
        $this->assertSame(self::res(true, 'ok', [], [], 2), $e->peek(self::act('ok')));
        $this->assertFalse($e->state()['latched']);
        $this->assertSame('violated', $e->check(self::act('bad'))['reason']);
        $this->assertTrue($e->reset(Contracts::signContractReset($kp, '5', 2)));
        $this->assertFalse($e->state()['latched']);
    }
}
