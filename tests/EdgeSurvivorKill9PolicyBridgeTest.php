<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\PolicyBridge;
use PHPUnit\Framework\TestCase;

/** Behaviour-level kills for the Cedar / Rego / OpenFGA translators and decide() (text scanning, UTF-16 order, depth guards). */
final class EdgeSurvivorKill9PolicyBridgeTest extends TestCase
{
    /** Assoc arrays become Obj (recursively); lists stay lists. */
    private static function o(mixed $v): mixed
    {
        if ($v instanceof Obj || !is_array($v)) {
            return $v;
        }
        if (array_is_list($v)) {
            return array_map(static fn($x) => self::o($x), $v);
        }
        $r = new Obj();
        foreach ($v as $k => $x) {
            $r->set((string)$k, self::o($x));
        }
        return $r;
    }

    /** The result tree back as plain PHP arrays. */
    private static function arr(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $r = [];
            foreach ($v->keys() as $k) {
                $r[$k] = self::arr($v->get($k));
            }
            return $r;
        }
        return is_array($v) ? array_map(static fn($x) => self::arr($x), $v) : $v;
    }

    /** @return list<array<string,mixed>> */
    private static function preds(Obj $r): array
    {
        return self::arr($r->get('predicates'));
    }

    /** @return list<string> */
    private static function report(Obj $r, string $k): array
    {
        return self::arr($r->get('report'))[$k];
    }

    /** Predicates of a one-rule Rego module whose body is $stmt. */
    private static function rego(string $stmt): int
    {
        return count(self::preds(PolicyBridge::regoToPca("default allow = false\nallow {\n" . $stmt . "\n}\n")));
    }

    private static function cedarWhen(string $cond): Obj
    {
        return PolicyBridge::cedarToPca('permit(principal, action, resource) when { ' . $cond . ' }');
    }

    // ---- text semantics ---------------------------------------------------------------------------------------------------

    public function testLoneSurrogatesRoundTripThroughTheTranslator(): void
    {
        $id = "\xED\xA0\x80x\xED\xAF\xBFx\xED\xB0\x80x\xED\xBF\xBFx\xED\xAA\xAAx\xED\xB5\x95";
        $r = PolicyBridge::cedarToPca('permit(principal, action, resource == Doc::"' . $id . '");');
        $p = self::preds($r);
        $this->assertCount(1, $p);
        $this->assertSame('Doc::"' . $id . '"', $p[0]['resource']);
        $this->assertSame([], self::report($r, 'errors'));
        $this->assertSame(["permit \u{2192} verb \"*\" on Doc::\"" . $id . '" (0 condition(s))'], self::report($r, 'translated'));
    }

    public function testInvalidUtf8IsARegexFailure(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('regular expression failure');
        PolicyBridge::cedarToPca("permit\xFF");
    }

    /** chopLast drops the low half of a trailing astral character and keeps the lone high half (UTF-16 s[:-1]). */
    public function testChopLastLeavesTheLoneHighSurrogate(): void
    {
        foreach (["\u{1F7FF}" => "\xED\xA0\xBD", "\u{10000}" => "\xED\xA0\x80"] as $astral => $high) {
            $stmt = 'permit(action in [Action::"é"' . $astral . ')';
            $r = PolicyBridge::cedarToPca($stmt);
            $this->assertSame([], self::preds($r));
            $this->assertSame(
                ['policy "' . $stmt . '": action in [...] expects Action entities, got "Action::"é"' . $high . '"'],
                self::report($r, 'errors'),
            );
        }
    }

    /** Names are ordered by UTF-16 code units of their WTF-8 bytes (stable for equal unit sequences). */
    public function testUsersAreOrderedByUtf16Units(): void
    {
        $model = self::o(['type_definitions' => [['type' => 'doc', 'relations' => ['viewer' => ['this' => new Obj()]]]]]);
        $rows = [
            [["\xED\xAF\xBF\xED\xBF\xBF", "\xF4\x8F\xBF\xBF"], ["\xED\xAF\xBF\xED\xBF\xBF", "\xF4\x8F\xBF\xBF"]],
            [["\xF4\x8F\xBF\xBF", "\xED\xAF\xBF\xED\xBF\xBF"], ["\xF4\x8F\xBF\xBF", "\xED\xAF\xBF\xED\xBF\xBF"]],
            [["\x81\xBF\x80", "\xE0\x41\xBF\x80"], ["\x81\xBF\x80", "\xE0\x41\xBF\x80"]],
            [["\xE0\x41\xBF\x80", "\x81\xBF\x80"], ["\xE0\x41\xBF\x80", "\x81\xBF\x80"]],
            [["\xED\xA0\x80\xED\xB0\x81", "\xF0\x90\x80\x81"], ["\xED\xA0\x80\xED\xB0\x81", "\xF0\x90\x80\x81"]],
            [["\xF0\x90\x80\x81", "\xED\xA0\x80\xED\xB0\x81"], ["\xF0\x90\x80\x81", "\xED\xA0\x80\xED\xB0\x81"]],
            [["\x41\x41\x41\x41\xF0\x90\x80\x80", "\x80"], ["\x80", "\x41\x41\x41\x41\xF0\x90\x80\x80"]],
            [["\x80", "\x41\x41\x41\x41\xF0\x90\x80\x80"], ["\x80", "\x41\x41\x41\x41\xF0\x90\x80\x80"]],
            [["\xED\xA0\x81\xED\xB0\x80", "\xF0\x90\x90\x80\x41"], ["\xED\xA0\x81\xED\xB0\x80", "\xF0\x90\x90\x80\x41"]],
            [["\xF0\x90\x90\x80\x41", "\xED\xA0\x81\xED\xB0\x80"], ["\xED\xA0\x81\xED\xB0\x80", "\xF0\x90\x90\x80\x41"]],
            [["\xED\x9F\xBF", "\xF1\x80\x80\x80"], ["\xED\x9F\xBF", "\xF1\x80\x80\x80"]],
            [["\xF1\x80\x80\x80", "\xED\x9F\xBF"], ["\xED\x9F\xBF", "\xF1\x80\x80\x80"]],
        ];
        foreach ($rows as [$in, $want]) {
            $tuples = array_map(static fn(string $u) => self::o(['user' => $u, 'relation' => 'viewer', 'object' => 'doc:d']), $in);
            $got = array_map(static fn(array $p) => $p['where'][0]['value'], self::preds(PolicyBridge::openfgaToPca($model, $tuples)));
            $this->assertSame(array_map('bin2hex', $want), array_map('bin2hex', $got));
        }
    }

    public function testNumbersBecomeIntegersUpToTheSafeRange(): void
    {
        foreach (['5' => 5, '9007199254740991' => 9007199254740991, '9007199254740993' => 9007199254740992.0] as $lit => $want) {
            $p = self::preds(self::cedarWhen('context.a == ' . $lit));
            $this->assertSame($want, $p[0]['where'][0]['value']);
        }
    }

    // ---- Cedar --------------------------------------------------------------------------------------------------------------

    public function testAnnotationsAreStripped(): void
    {
        $this->assertCount(1, self::preds(PolicyBridge::cedarToPca('@id("x") permit(principal, action, resource)')));
        $r = PolicyBridge::cedarToPca('@id]("x") permit(principal, action, resource)');
        $this->assertSame([], self::preds($r));
        $this->assertSame(['unrecognized statement: "@id]("x") permit(principal, action, resource)"'], self::report($r, 'skipped'));
    }

    public function testEffectIsCaseInsensitive(): void
    {
        $r = PolicyBridge::cedarToPca('FORBID(principal, action, resource)');
        $this->assertSame([], self::preds($r));
        $this->assertSame([['verb' => '*']], self::arr($r->get('denies')));
    }

    public function testConditionBlocksStartRightAfterTheScope(): void
    {
        $p = self::preds(PolicyBridge::cedarToPca('permit(principal, action, resource)when { context.a == 1 }'));
        $this->assertSame([['field' => 'env.a', 'op' => 'eq', 'value' => 1], ['field' => 'env.a', 'op' => 'exists']], $p[0]['where']);
        // a "when {" inside the scope's string is not a condition block
        $p = self::preds(PolicyBridge::cedarToPca('permit(principal, action, resource == Doc::"when {context.a == 1}")'));
        $this->assertSame([['verb' => '*', 'resource' => 'Doc::"when {context.a == 1}"']], $p);
        // back-to-back blocks are both read
        $p = self::preds(PolicyBridge::cedarToPca('permit(principal, action, resource) when { context.a == 1 }when { context.b == 2 }'));
        $this->assertCount(3, $p[0]['where']);
        // "xwhen" is not the keyword
        $p = self::preds(PolicyBridge::cedarToPca('permit(principal, action, resource) xwhen { context.a == 1 }'));
        $this->assertSame([['verb' => '*']], $p);
    }

    public function testResourceEqualsNeedsAnEntity(): void
    {
        $stmt = 'permit(principal, action, resource == "x")';
        $r = PolicyBridge::cedarToPca($stmt);
        $this->assertSame([], self::preds($r));
        $this->assertSame(['policy "' . $stmt . '": resource == expects an entity, got ""x""'], self::report($r, 'errors'));
    }

    public function testParenthesesOnlyUnwrapAWholeGroup(): void
    {
        $r = self::cedarWhen('Xprincipal == (U::"a")');
        $this->assertSame([], self::preds($r));
        $this->assertCount(1, self::report($r, 'skipped'));
    }

    public function testWordOperatorsNeedWhitespace(): void
    {
        $this->assertSame([], self::preds(self::cedarWhen('context.a hasb')));
    }

    public function testActionInLists(): void
    {
        $p = self::preds(self::cedarWhen('action in [A::"a",Action::"b"]'));
        $this->assertSame([['field' => 'action.verb', 'op' => 'in', 'value' => ['a', 'b']]], $p[0]['where']);
        $this->assertSame([], self::preds(self::cedarWhen('action in Action::"a"]')));
        $this->assertSame([], self::preds(self::cedarWhen('action in [Action::"a", x]')));
    }

    public function testMemberOfAnUnclosedList(): void
    {
        $p = self::preds(self::cedarWhen('principal in [Group::"a"'));
        $this->assertSame([['field' => 'subject.id', 'op' => 'member_of', 'value' => ['Group::"a"'], 'collection' => 'env.entity_parents']], $p[0]['where']);
    }

    /** Comparison tokens are found only outside strings and brackets. */
    public function testTopLevelTokenScan(): void
    {
        $p = self::preds(self::cedarWhen('context.a like "a==b"'));
        $this->assertSame(['field' => 'env.a', 'op' => 'like', 'value' => 'a==b'], $p[0]['where'][0]);
        $this->assertSame([], self::preds(self::cedarWhen('context.a like "x" == "y"')));
        $p = self::preds(self::cedarWhen('principal in [A<B::"x"]'));
        $this->assertSame([['field' => 'subject.id', 'op' => 'member_of', 'value' => ['A<B::"x"'], 'collection' => 'env.entity_parents']], $p[0]['where']);
        $this->assertSame([], self::preds(self::cedarWhen('principal in [A::"x"]<B::"y"')));
    }

    public function testLikeKeepsATrailingBackslash(): void
    {
        $p = self::preds(self::cedarWhen('context.a like "ab\\"'));
        $this->assertSame('ab\\\\', $p[0]['where'][0]['value']);
    }

    public function testHasGuardsItsParentPath(): void
    {
        $p = self::preds(self::cedarWhen('context.a has b'));
        $this->assertSame([['field' => 'env.a.b', 'op' => 'exists'], ['field' => 'env.a', 'op' => 'exists']], $p[0]['where']);
        $p = self::preds(self::cedarWhen('resource.a has b'));
        $this->assertSame([['field' => 'env.resource.a.b', 'op' => 'exists'], ['field' => 'env.resource.a', 'op' => 'exists']], $p[0]['where']);
    }

    /** The recursion counter is restored after every sub-expression, so a wide disjunction never trips it. */
    public function testWideDisjunctionDoesNotExhaustTheDepthGuard(): void
    {
        $r = self::cedarWhen(implode(' || ', array_fill(0, 2000, 'principal == U::"a"')));
        $this->assertSame([], self::report($r, 'errors'));
        $p = self::preds($r);
        $this->assertCount(2000, $p[0]['where'][0]['any_of']);
    }

    // ---- Rego ---------------------------------------------------------------------------------------------------------------

    public function testAllowHeads(): void
    {
        $this->assertSame(1, self::rego('input.a == 1'));
        $this->assertSame(0, count(self::preds(PolicyBridge::regoToPca("allow true { input.a == 1 }"))));
        $this->assertSame(1, count(self::preds(PolicyBridge::regoToPca("allow :=true { input.a == 1 }"))));
        $this->assertSame(0, count(self::preds(PolicyBridge::regoToPca("allow = { input.a == 1 }"))));
        $this->assertSame(2, count(self::preds(PolicyBridge::regoToPca("allow {input.a == 1}allow {input.b == 2}"))));
    }

    public function testPackageNameIsAWord(): void
    {
        $this->assertSame(['package p'], self::report(PolicyBridge::regoToPca("package p\n"), 'translated'));
        $this->assertSame([], self::report(PolicyBridge::regoToPca("mypackage x\n"), 'translated'));
    }

    public function testRepeatedResourceSelectorIsNotAContradiction(): void
    {
        $this->assertSame(1, self::rego("input.resource == \"r\"\ninput.resource == \"r\""));
    }

    /** @return list<array{0:string,1:int}> */
    private static function regoCases(): array
    {
        return [
            ['notinput.a == 1', 0],
            ['input.a == "some"', 0], ['input.a == "every"', 0], ['input.a == "[x|y]"', 0],
            ['input.a == "awesome"', 1], ['input.a == "somebody"', 1], ['input.a == "xevery"', 1], ['input.a == "everyone"', 1],
            ['input.a == "|x]"', 1],
            ['input.a == "input.b["', 0], ['input.a == "xinput.b["', 1],
            ['input.a 1', 0], ['input.a < input.b', 0],
            ['input.a in 1}', 0], ['input.a in 1]', 0], ['input.a in 515', 0],
            ['startswith(input.a,"x")', 1], ['startswith( input.a, "x")', 1], ['startswith(input.a , "x")', 1], ['startswith(input.a, "x" )', 1],
            ['glob.match("a*",null,input.a)', 1], ['glob.match( "a*", null, input.a)', 1], ['glob.match("a*" , null, input.a)', 1],
            ['glob.match("a", [ ], input.a)', 1], ['glob.match("a*", null , input.a)', 1], ['glob.match("a*", null, input.a )', 1],
        ];
    }

    public function testRegoStatementShapes(): void
    {
        foreach (self::regoCases() as [$stmt, $want]) {
            $this->assertSame($want, self::rego($stmt), $stmt);
        }
    }

    // ---- OpenFGA ------------------------------------------------------------------------------------------------------------

    /** @return list<array{0:string,1:string,2:mixed}> verb, resource, first where condition */
    private static function triples(Obj $r): array
    {
        return array_map(static fn(array $p) => [$p['verb'], $p['resource'], $p['where'][0]['value']], self::preds($r));
    }

    private static function tuple(string $user, string $relation, string $object): Obj
    {
        return self::o(['user' => $user, 'relation' => $relation, 'object' => $object]);
    }

    public function testNonStringTuplesetRelationIsSkipped(): void
    {
        $model = self::o(['type_definitions' => [['type' => 'doc', 'relations' => [
            'viewer' => ['tupleToUserset' => ['tupleset' => ['relation' => 5], 'computedUserset' => ['relation' => 'v']]],
        ]]]]);
        $r = PolicyBridge::openfgaToPca($model, []);
        $this->assertSame(["relation doc#viewer: tupleToUserset without a tupleset relation \u{2014} skipped"], self::report($r, 'skipped'));
    }

    public function testUsersetParentResolvesToItsObject(): void
    {
        $model = self::o(['type_definitions' => [
            ['type' => 'folder', 'relations' => ['viewer' => ['this' => new Obj()]]],
            ['type' => 'doc', 'relations' => [
                'parent' => ['this' => new Obj()],
                'viewer' => ['tupleToUserset' => ['tupleset' => ['relation' => 'parent'], 'computedUserset' => ['relation' => 'viewer']]],
            ]],
        ]]);
        $r = PolicyBridge::openfgaToPca($model, [self::tuple('user:u', 'viewer', 'folder:f'), self::tuple('folder:f#x', 'parent', 'doc:d')]);
        $this->assertSame([['viewer', 'doc:d', 'user:u'], ['viewer', 'folder:f', 'user:u']], self::triples($r));
    }

    /** The cycle guard keys (object, relation) unambiguously: "x:a"+"bc" is not "x:ab"+"c". */
    public function testVisitedKeysDoNotCollide(): void
    {
        $model = self::o(['type_definitions' => [['type' => 'x', 'relations' => [
            'bc' => ['tupleToUserset' => ['tupleset' => ['relation' => 'p'], 'computedUserset' => ['relation' => 'c']]],
            'p' => ['this' => new Obj()],
            'c' => ['this' => new Obj()],
        ]]]]);
        $r = PolicyBridge::openfgaToPca($model, [self::tuple('x:ab', 'p', 'x:a'), self::tuple('user:u', 'c', 'x:ab')]);
        $this->assertSame([['bc', 'x:a', 'user:u'], ['p', 'x:a', 'x:ab'], ['c', 'x:ab', 'user:u']], self::triples($r));
    }

    /** A computed chain resolves to depth 32 and no further, for named users and for a public (type:*) tuple. */
    public function testComputedChainDepthBound(): void
    {
        $rels = [];
        for ($i = 0; $i < 33; $i++) {
            $rels['r' . $i] = ['computedUserset' => ['relation' => 'r' . ($i + 1)]];
        }
        $rels['r33'] = ['this' => new Obj()];
        $model = self::o(['type_definitions' => [['type' => 'c', 'relations' => $rels]]]);
        $r = PolicyBridge::openfgaToPca($model, [self::tuple('user:u', 'r33', 'c:x'), self::tuple('w:*', 'r33', 'c:x')]);
        $named = [];
        $public = [];
        foreach (self::preds($r) as $p) {
            if ($p['where'][0]['op'] === 'eq') {
                $named[] = $p['verb'];
            } else {
                $public[] = $p['verb'];
            }
        }
        sort($named);
        sort($public);
        $want = array_map(static fn(int $i) => 'r' . $i, range(1, 33));
        sort($want);
        $this->assertSame($want, $named);
        $this->assertSame($want, $public);
    }

    public function testTupleToUsersetChainDepthBound(): void
    {
        $model = self::o(['type_definitions' => [['type' => 't', 'relations' => ['v' => ['union' => ['child' => [
            ['this' => new Obj()],
            ['tupleToUserset' => ['tupleset' => ['relation' => 'parent'], 'computedUserset' => ['relation' => 'v']]],
        ]]]]]]]);
        $tuples = [self::tuple('user:u', 'v', 't:33')];
        for ($k = 0; $k < 33; $k++) {
            $tuples[] = self::tuple('t:' . ($k + 1), 'parent', 't:' . $k);
        }
        $objs = [];
        foreach (self::triples(PolicyBridge::openfgaToPca($model, $tuples)) as [$verb, $obj, $user]) {
            $this->assertSame(['v', 'user:u'], [$verb, $user]);
            $objs[] = $obj;
        }
        sort($objs);
        $want = array_map(static fn(int $k) => 't:' . $k, range(1, 33));
        sort($want);
        $this->assertSame($want, $objs);
    }

    /**
     * The cycle guard cuts a relation that reaches itself: a = b, b = this - a. Re-entering a inside b is false, so b and a hold for a
     * direct b tuple; without the guard the walk alternates to the depth bound and a comes out false.
     */
    public function testCycleGuardCutsSelfReference(): void
    {
        $model = self::o(['type_definitions' => [['type' => 'doc', 'relations' => [
            'a' => ['computedUserset' => ['relation' => 'b']],
            'b' => ['difference' => ['base' => ['this' => new Obj()], 'subtract' => ['computedUserset' => ['relation' => 'a']]]],
        ]]]]);
        $r = PolicyBridge::openfgaToPca($model, [self::tuple('user:u', 'b', 'doc:d')]);
        $this->assertSame([['a', 'doc:d', 'user:u'], ['b', 'doc:d', 'user:u']], self::triples($r));
    }

    public function testPublicTupleIsCheckedWithAnUnnamedSubject(): void
    {
        $model = self::o(['type_definitions' => [['type' => 'doc', 'relations' => ['viewer' => ['this' => new Obj()]]]]]);
        $r = PolicyBridge::openfgaToPca($model, [self::tuple('user:*', 'viewer', 'doc:a'), self::tuple('user', 'viewer', 'doc:b')]);
        $p = self::preds($r);
        $this->assertSame([
            ['verb' => 'viewer', 'resource' => 'doc:a', 'where' => [['field' => 'subject.id', 'op' => 'eq', 'value' => 'user']]],
            ['verb' => 'viewer', 'resource' => 'doc:a', 'where' => [
                ['field' => 'subject.id', 'op' => 'like', 'value' => 'user:*'],
                ['not' => ['field' => 'subject.id', 'op' => 'in', 'value' => ['user']]],
            ]],
            ['verb' => 'viewer', 'resource' => 'doc:b', 'where' => [['field' => 'subject.id', 'op' => 'eq', 'value' => 'user']]],
        ], $p);
    }

    // ---- decide -------------------------------------------------------------------------------------------------------------

    private static function typeErrorOf(mixed $result, mixed $ctx): string
    {
        try {
            PolicyBridge::decide($result, $ctx);
        } catch (\TypeError $e) {
            return $e->getMessage();
        }
        return 'no error';
    }

    public function testDecideShapeErrors(): void
    {
        $this->assertSame("cannot read properties of null (reading 'length')", self::typeErrorOf(self::o(['report' => true, 'denies' => [], 'predicates' => []]), null));
        $this->assertSame("cannot read properties of undefined (reading 'length')", self::typeErrorOf(self::o(['report' => new Obj(), 'denies' => []]), null));
        $this->assertSame('cannot read properties of undefined', self::typeErrorOf(null, null));
        $this->assertSame('cannot read properties of undefined', self::typeErrorOf(self::o(['report' => ['errors' => []]]), null));
    }

    public function testDecideFailsClosedAndToleratesAMissingContext(): void
    {
        $none = ['allowed' => false, 'reason' => 'envelope grants no predicates'];
        $this->assertSame(['allowed' => false, 'reason' => 'translation incomplete (fail closed)'],
            PolicyBridge::decide(self::o(['report' => ['errors' => 'x'], 'denies' => [], 'predicates' => []]), new Obj()));
        $this->assertSame($none, PolicyBridge::decide(self::o(['report' => false, 'denies' => [], 'predicates' => []]), new Obj()));
        $this->assertSame($none, PolicyBridge::decide(self::o(['report' => ['errors' => []], 'denies' => [], 'predicates' => []]), null));
    }
}
