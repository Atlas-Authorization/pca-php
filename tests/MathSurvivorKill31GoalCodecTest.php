<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalCodec;
use Atlas\Pca\GoalIrError;
use Atlas\Pca\GoalTapeReader;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of the goal token tape (codec.ts): every encoder arm, every decoder refusal with its exact message. */
final class MathSurvivorKill31GoalCodecTest extends TestCase
{
    private static function j(mixed $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    private static function err(string $msg, callable $f): void
    {
        try {
            $f();
        } catch (GoalIrError $e) {
            self::assertSame("pca-goal: $msg", $e->getMessage());
            return;
        }
        self::fail("no GoalIrError ($msg)");
    }

    private static function dec(string $fn, array $tape): mixed
    {
        return (new \ReflectionMethod(GoalCodec::class, $fn))->invoke(null, new GoalTapeReader($tape));
    }

    /** @return array<string,mixed> */
    private static function goal(): array
    {
        return ['v' => 1, 'principal' => 'p', 'ontDigest' => 'o', 'nlDigest' => 'n', 'sources' => ['s1'], 'grants' => [], 'prohibits' => [], 'bounds' => [],
            'validity' => ['notBefore' => 0, 'notAfter' => 10, 'maxIdle' => 0], 'deleg' => ['maxDepth' => 0, 'narrowOnly' => false, 'mayTouch' => []],
            'escalateOn' => [], 'wildcardAck' => [], 'holes' => []];
    }

    private static function cnt(): array
    {
        return ['k' => 'count'];
    }

    private static function hist(): array
    {
        return ['k' => 'hist', 'bid' => 'b1', 'u' => self::cnt()];
    }

    private static function lit3(): array
    {
        return ['k' => 'lit', 'v' => ['k' => 'q', 'q' => ['u' => self::cnt(), 'n' => 3]]];
    }

    private static function bound(string $bid, array $window, array $scope, mixed $agg = 'count'): array
    {
        return ['bid' => $bid, 'sel' => ['k' => 'gids', 'gids' => ['g1']], 'agg' => $agg, 'value' => ['k' => 'param', 'path' => 'amt', 'ty' => ['k' => 'q', 'u' => ['k' => 'money', 'ccy' => 'USD']]],
            'key' => '', 'window' => $window, 'scope' => $scope, 'cap' => ['u' => self::cnt(), 'n' => 3], 'onExceed' => 'deny'];
    }

    /** A goal using every condition, resource selector, resource part, window and scope kind encodes, and decodes back to the same tape. */
    public function testEveryEncoderArmRoundTrips(): void
    {
        $g = self::goal();
        $t = ['k' => 'true'];
        $g['grants'] = [
            ['gid' => 'g1', 'verb' => 'v', 'res' => ['k' => 'exact', 'id' => 'r1'], 'cond' => $t],
            ['gid' => 'g2', 'verb' => 'v', 'res' => ['k' => 'oneof', 'ids' => ['r1', 'r2']], 'cond' => ['k' => 'and', 'a' => $t, 'b' => ['k' => 'or', 'a' => $t, 'b' => ['k' => 'not', 'c' => $t]]]],
            ['gid' => 'g3', 'verb' => 'v', 'res' => ['k' => 'related', 'rel' => 'owns', 'anchor' => 'A'], 'cond' => $t],
            ['gid' => 'g4', 'verb' => 'v', 'res' => ['k' => 'any', 'reason' => 'why'], 'cond' => $t],
            ['gid' => 'g5', 'verb' => 'v', 'res' => ['k' => 'all_of', 'parts' => [['k' => 'exact', 'id' => 'r1'], ['k' => 'oneof', 'ids' => ['r2']], ['k' => 'related', 'rel' => 'owns', 'anchor' => 'A']]], 'cond' => $t],
        ];
        $g['prohibits'] = [['pid' => 'x1', 'target' => ['k' => 'verb', 'verb' => 'v'], 'res' => ['k' => 'any', 'reason' => 'r'], 'cond' => $t],
            ['pid' => 'x2', 'target' => ['k' => 'effect', 'cls' => 'pay'], 'res' => ['k' => 'exact', 'id' => 'r1'], 'cond' => $t]];
        $g['bounds'] = [self::bound('b1', ['k' => 'task'], ['k' => 'session']), self::bound('b2', ['k' => 'sliding', 'ms' => 100], ['k' => 'principal'], 'sum'),
            self::bound('b3', ['k' => 'period', 'ms' => 100, 't0' => 5], ['k' => 'org'], 'max'), self::bound('b4', ['k' => 'lifetime'], ['k' => 'fleet', 'agents' => ['a1']], 'distinct')];
        $g['escalateOn'] = [['k' => 'cmp', 'op' => 'eq', 'l' => self::hist(), 'r' => self::lit3()]];
        $g['holes'] = [['hid' => 'h1', 'q' => 'which?', 'domain' => ['x'], 'affects' => ['g1'], 'global' => true]];
        $tape = GoalCodec::encodeGoal(self::j($g));
        self::assertSame(['i', 1], $tape[1]);
        self::assertStringContainsString('["k",361],["k",350],["k",342],["s","b1"],["k",301],["k",341],["k",330],["k",301],["i",3]', json_encode($tape));
        self::assertSame($tape, GoalCodec::encodeGoal(GoalCodec::decodeGoal($tape)));
        $h = self::dec('dTerm', [['k', 342], ['s', 'b1'], ['k', 301]]);
        self::assertSame(['k', 'bid', 'u'], $h->keys());
        self::assertSame(['hist', 'b1', 'count'], [$h->get('k'), $h->get('bid'), $h->get('u')->get('k')]);
    }

    /** Each encoder refusal carries its message. */
    public function testEncoderRefusals(): void
    {
        $g = self::goal();
        $g['sources'] = 'x';
        self::err('array expected', fn() => GoalCodec::encodeGoal(self::j($g)));
        $esc = function (array $l, array $r) {
            $g = self::goal();
            $g['escalateOn'] = [['k' => 'cmp', 'op' => 'eq', 'l' => $l, 'r' => $r]];
            return GoalCodec::encodeGoal(self::j($g));
        };
        self::err('unknown unit', fn() => $esc(['k' => 'hist', 'bid' => 'b1', 'u' => ['k' => 'weird']], self::lit3()));
        self::err('unknown set member (sets hold quantities and strings only)', fn() => $esc(self::hist(), ['k' => 'lit', 'v' => ['k' => 'set', 'items' => [['k' => 'zz']]]]));
        self::err('unknown value', fn() => $esc(self::hist(), ['k' => 'lit', 'v' => ['k' => 'zz']]));
        self::err('unknown term', fn() => $esc(['k' => 'zz'], self::lit3()));
        $g = self::goal();
        $g['grants'] = [['gid' => 'g1', 'verb' => 'v', 'res' => ['k' => 'all_of', 'parts' => [['k' => 'zz']]], 'cond' => ['k' => 'true']]];
        self::err('unknown resource part', fn() => GoalCodec::encodeGoal(self::j($g)));
        foreach (['x', 5] as $agg) {
            $g = self::goal();
            $g['bounds'] = [self::bound('b1', ['k' => 'task'], ['k' => 'session'], $agg)];
            self::err('unknown aggregate', fn() => GoalCodec::encodeGoal(self::j($g)));
        }
    }

    /** -0 is not a safe integer (the reference's Number.isSafeInteger plus the -0 rule); 0 and 2^53 - 1 are. */
    public function testSafeIntRejectsNegativeZero(): void
    {
        self::assertFalse(GoalCodec::safeInt(new Num('-0')));
        self::assertFalse(GoalCodec::safeInt(-0.0));
        self::assertTrue(GoalCodec::safeInt(0));
        self::assertTrue(GoalCodec::safeInt(9007199254740991));
    }

    /** Each decoder refuses an unknown tag with its exact message; operator and aggregate tags are bounded on both sides. */
    public function testDecoderTagRefusals(): void
    {
        $bad = [['dUnit', 'bad unit tag 999'], ['dTy', 'bad type tag 999'], ['dAtom', 'bad atom tag 999'], ['dV', 'bad value tag 999'], ['dTerm', 'bad term tag 999'],
            ['dN', 'bad condition tag 999'], ['dCond', 'bad condition tag 999'], ['dResPat', 'bad resource pattern tag 999'], ['dWindow', 'bad window tag 999'],
            ['dScope', 'bad scope tag 999'], ['dOnExceed', 'bad on_exceed'], ['dCeil', 'ceiling expected'], ['dPart', 'bad resource part tag 999'],
            ['dRes', 'bad resource selector tag 999']];
        foreach ($bad as [$fn, $msg]) {
            self::err($msg, fn() => self::dec($fn, [['k', 999]]));
        }
        self::err('bad operator', fn() => self::dec('dOp', [['k', 358]]));
        self::err('bad operator', fn() => self::dec('dOp', [['k', 349]]));
        self::assertSame(['eq', 'nin'], [self::dec('dOp', [['k', 350]]), self::dec('dOp', [['k', 357]])]);
        self::err('bad aggregate', fn() => self::dec('dAgg', [['k', 404]]));
        self::err('bad aggregate', fn() => self::dec('dAgg', [['k', 399]]));
        self::assertSame(['count', 'distinct'], [self::dec('dAgg', [['k', 400]]), self::dec('dAgg', [['k', 403]])]);
        self::assertSame(['deny', 'escalate'], [self::dec('dOnExceed', [['k', 440]]), self::dec('dOnExceed', [['k', 441]])]);
        self::err('bound core expected', fn() => self::dec('dCeil', [['k', 610], ['s', 'b'], ['i', 0], ['i', 0], ['k', 999]]));
    }

    /** decodePolicy and decodeGoal refuse a misplaced section with its exact message. */
    public function testDecoderSectionRefusals(): void
    {
        self::err('prohibition', fn() => GoalCodec::decodePolicy([['k', 650], ['i', 0], ['i', 1], ['k', 999]]));
        self::err('validity', fn() => GoalCodec::decodePolicy([['k', 650], ['i', 0], ['i', 0], ['i', 0], ['i', 0], ['k', 999]]));
        self::err('delegation', fn() => GoalCodec::decodePolicy([['k', 650], ['i', 0], ['i', 0], ['i', 0], ['i', 0], ['k', 460], ['i', 0], ['i', 0], ['i', 0], ['k', 999]]));
        $p = [['k', 480], ['i', 1], ['s', 'p'], ['s', 'o'], ['s', 'n'], ['i', 0], ['i', 0]];
        self::err('bad prohibit target', fn() => GoalCodec::decodeGoal(array_merge($p, [['i', 1], ['k', 392], ['s', 'x'], ['k', 999]])));
        self::err('bad selection', fn() => GoalCodec::decodeGoal(array_merge($p, [['i', 0], ['i', 1], ['k', 451], ['s', 'b'], ['k', 999]])));
    }

    /** The tape reader refuses a non-list tape, a non-list token, a non-string string token and a negative length. */
    public function testReaderRefusals(): void
    {
        self::err('truncated tape', fn() => (new GoalTapeReader('x'))->k());
        self::err('malformed token', fn() => (new GoalTapeReader(['x']))->k());
        self::err('string expected', fn() => (new GoalTapeReader([['s', 5]]))->str());
        self::err('negative length', fn() => (new GoalTapeReader([['i', -1]]))->lst(fn() => 1));
    }
}
