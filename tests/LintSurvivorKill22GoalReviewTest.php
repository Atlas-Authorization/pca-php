<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalDigests;
use Atlas\Pca\GoalExamples;
use Atlas\Pca\GoalReview;
use Atlas\Pca\GoalReviewError;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Undef;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/GoalReview.php';

/** Goal review: card caps and refusals with their exact text, the semantic-diff directions, and the approval loader's reasons. */
final class LintSurvivorKill22GoalReviewTest extends TestCase
{
    private const NL = 'do it';

    protected function tearDown(): void
    {
        GoalReview::$clockHook = null;
    }

    private static function p(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(GoalReview::class, $m))->invoke(null, ...$a);
    }

    private static function n(int|string $v): Num
    {
        return new Num((string)$v);
    }

    /** A renderable Goal IR (one exact grant) with these members replaced. @param array<string,mixed> $over */
    private static function goal(array $over = []): Obj
    {
        $g = Obj::of([
            'principal' => 'p',
            'grants' => [Obj::of(['gid' => 'g1', 'verb' => 'a.b.c', 'res' => Obj::of(['k' => 'exact', 'id' => 'r1']), 'cond' => Obj::of(['k' => 'true'])])],
            'prohibits' => [], 'bounds' => [], 'escalateOn' => [], 'holes' => [],
            'validity' => Obj::of(['notBefore' => self::n(0), 'notAfter' => self::n(10), 'maxIdle' => self::n(0)]),
            'deleg' => Obj::of(['maxDepth' => self::n(0), 'narrowOnly' => true, 'mayTouch' => []]),
            'wildcardAck' => [], 'ontDigest' => 'ont', 'nlDigest' => GoalDigests::nlDigest(self::NL),
        ]);
        foreach ($over as $k => $v) {
            $g->set($k, $v);
        }
        return $g;
    }

    /** @param array<string,mixed> $over */
    private static function sub(array $over = []): Obj
    {
        $s = Obj::of(['goal' => self::goal(), 'ontology' => new Obj(), 'instruction' => self::NL, 'model_set' => ['m']]);
        foreach ($over as $k => $v) {
            $s->set($k, $v);
        }
        return $s;
    }

    /** A stub kernel: compile always succeeds, the policy digest is 'pd'; `analyze` / `decide` only when given. */
    private static function kernel(?\Closure $analyze = null, ?\Closure $decide = null): Obj
    {
        $k = Obj::of(['compile' => static fn($g, $o) => Obj::of(['ok' => true, 'policy' => Obj::of(['n' => new Num('1')])]), 'policyDigest' => static fn($p) => 'pd']);
        if ($analyze !== null) {
            $k->set('analyze', $analyze);
        }
        if ($decide !== null) {
            $k->set('decide', $decide);
        }
        return $k;
    }

    /** An approval of the default submission; `$real` carries the digests the loader re-derives, else placeholders. @param array<string,mixed> $over */
    private static function approval(bool $real, array $over = []): Obj
    {
        $g = self::goal();
        $d = $real ? [
            'goal_digest' => GoalDigests::goalDigest($g), 'policy_digest' => 'pd', 'ontology_digest' => 'ont', 'tests_digest' => GoalExamples::testsDigest([]),
            'nl_digest' => GoalDigests::nlDigest(self::NL), 'model_set_digest' => GoalDigests::modelSetDigest(['m']),
            'card_digest' => GoalReview::cardDigest(GoalReview::renderPolicyCard($g, [], null)),
        ] : array_fill_keys(['goal_digest', 'policy_digest', 'ontology_digest', 'tests_digest', 'nl_digest', 'model_set_digest', 'card_digest'], 'x');
        $a = Obj::of(['v' => self::n(1), 'sig' => 's', 'reviewer' => 'r', 'approved_at' => self::n(1000), 'expires_at' => self::n(2000)] + $d);
        foreach ($over as $k => $v) {
            $a->set($k, $v);
        }
        return $a;
    }

    private static function load(Obj $sub, Obj $approval, array $opts = []): Obj
    {
        return GoalReview::loadApprovedGoal($sub, $approval, Obj::of($opts + ['reviewers' => ['r'], 'now' => self::n(1000), 'kernel' => self::kernel()]));
    }

    private function refusal(callable $f): GoalReviewError
    {
        try {
            $f();
        } catch (GoalReviewError $e) {
            return $e;
        }
        $this->fail('no GoalReviewError');
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/goal-review-22', true);
    }

    // ---- helpers ----------------------------------------------------------------------------------------------------------

    /** `x.length`: arrays and strings measure, other values have none, null / undefined throw. */
    public function testLength(): void
    {
        $this->assertSame(2, self::p('len', [1, 2]));
        $this->assertSame(3, self::p('len', 'abc'));
        $this->assertNull(self::p('len', self::n(5)));
        foreach ([null, new Undef()] as $x) {
            try {
                self::p('len', $x);
                $this->fail('no TypeError');
            } catch (\TypeError $e) {
                $this->assertSame('cannot read properties of null or undefined (reading length)', $e->getMessage());
            }
        }
    }

    /** Number.isSafeInteger: -0 is 0 unless refused, negatives and the largest safe integer pass, fractions do not. */
    public function testSafeInt(): void
    {
        $this->assertSame(0, self::p('safeInt', self::n('-0')));
        $this->assertNull(self::p('safeInt', self::n('-0'), true));
        $this->assertSame(-5, self::p('safeInt', self::n(-5)));
        $this->assertSame(9007199254740991, self::p('safeInt', self::n('9007199254740991')));
        $this->assertNull(self::p('safeInt', self::n('1.5')));
        $this->assertSame(0, GoalReview::limitsOf(Obj::of(['max_grants' => self::n('-0')]))['max_grants']);
        $this->assertSame(32, GoalReview::limitsOf(Obj::of(['max_grants' => self::n(40)]))['max_grants']);
    }

    /** JS `>=`: strings compare as strings, a NaN side is false, numbers compare by value. */
    public function testGreaterOrEqual(): void
    {
        $this->assertTrue(self::p('ge', 'b', 'a'));
        $this->assertFalse(self::p('ge', 'a', 'b'));
        $this->assertFalse(self::p('ge', 'abc', self::n(1)));
        $this->assertFalse(self::p('ge', new Undef(), self::n(1)));
        $this->assertFalse(self::p('ge', self::n(1), self::n(2)));
        $this->assertTrue(self::p('ge', self::n(2), self::n(1)));
    }

    /** maxIdle 0 is the widest (Infinity); any other value is itself. */
    public function testIdle(): void
    {
        $five = self::n(5);
        $this->assertSame($five, self::p('idle', $five));
        $this->assertSame('x', self::p('idle', 'x'));
        $this->assertSame(INF, self::p('idle', self::n(0)));
    }

    /** new Set(x): null and undefined are empty, a list is itself, anything else throws. */
    public function testSetOf(): void
    {
        $this->assertSame([], self::p('setOf', null));
        $this->assertSame([], self::p('setOf', new Undef()));
        $this->assertSame(['a'], self::p('setOf', ['a']));
        $this->expectException(\TypeError::class);
        self::p('setOf', self::n(5));
    }

    // ---- the card ---------------------------------------------------------------------------------------------------------

    /** Every refusal carries the "goal review: <code>: <detail>" message. */
    public function testRefusalMessage(): void
    {
        $e = $this->refusal(fn() => GoalReview::renderPolicyCard(5));
        $this->assertSame('unrenderable', $e->errorCode);
        $this->assertSame('goal review: unrenderable: not a Goal IR', $e->getMessage());
    }

    /** The per-kind caps and the line cap (3 + every clause + every example) refuse with the exact count. */
    public function testCardCaps(): void
    {
        $o = static fn(array $l) => Obj::of(['limits' => Obj::of(array_map(static fn(int $n) => new Num((string)$n), $l))]);
        $split = ': split the goal into smaller goals';
        $one = [new Obj()];
        foreach ([['prohibits', 'max_prohibits', 'prohibitions'], ['bounds', 'max_bounds', 'bounds'], ['escalateOn', 'max_escalate_on', 'escalation triggers']] as [$k, $cap, $what]) {
            $e = $this->refusal(fn() => GoalReview::renderPolicyCard(self::goal([$k => $one]), [], $o([$cap => 0])));
            $this->assertSame("goal review: card_too_large: 1 $what exceed the cap of 0$split", $e->getMessage(), $k);
        }
        $all = self::goal(['prohibits' => $one, 'bounds' => $one, 'escalateOn' => $one, 'holes' => $one]);
        $this->assertSame("goal review: card_too_large: 9 card lines exceed the cap of 8$split", $this->refusal(fn() => GoalReview::renderPolicyCard($all, $one, $o(['max_card_lines' => 8])))->getMessage());
        $empty = self::goal(['grants' => []]);
        $this->assertSame("goal review: card_too_large: 3 card lines exceed the cap of 2$split", $this->refusal(fn() => GoalReview::renderPolicyCard($empty, self::n(5), $o(['max_card_lines' => 2])))->getMessage());
        try {
            GoalReview::renderPolicyCard($empty, self::n(5), $o(['max_examples' => 0]));
            $this->fail('no TypeError');
        } catch (\TypeError $e) {
            $this->assertSame('not an array', $e->getMessage());
        }
    }

    /** Holes, an unacknowledged wildcard and a goal with no canonical form are refused with their exact text. */
    public function testCardRefusals(): void
    {
        $this->assertSame('goal review: holes: 1 unresolved question(s): a goal with holes is a draft and cannot be signed',
            $this->refusal(fn() => GoalReview::renderPolicyCard(self::goal(['holes' => [new Obj()]])))->getMessage());
        $wild = self::goal(['grants' => [Obj::of(['gid' => 'g1', 'res' => Obj::of(['k' => 'any'])])]]);
        $this->assertSame('goal review: wildcard_unacknowledged: grant "g1" allows ANY resource without a wildcard acknowledgement',
            $this->refusal(fn() => GoalReview::renderPolicyCard($wild))->getMessage());
        $this->assertSame('goal review: unrenderable: the Goal has no canonical form (float, undefined or cycle)',
            $this->refusal(fn() => GoalReview::renderPolicyCard(self::goal(['zz' => INF])))->getMessage());
    }

    /** A prohibition is red only over ANY resource (none and an exact one are info); an escalation line ends with its period. */
    public function testProhibitSeverityAndEscalationText(): void
    {
        $t = Obj::of(['k' => 'verb', 'verb' => 'x.y']);
        $tr = Obj::of(['k' => 'true']);
        $g = self::goal([
            'prohibits' => [
                Obj::of(['pid' => 'p1', 'target' => $t, 'cond' => $tr]),
                Obj::of(['pid' => 'p2', 'target' => $t, 'res' => Obj::of(['k' => 'exact', 'id' => 'r']), 'cond' => $tr]),
                Obj::of(['pid' => 'p3', 'target' => $t, 'res' => Obj::of(['k' => 'any']), 'cond' => $tr]),
            ],
            'escalateOn' => [$tr],
        ]);
        $sev = [];
        $esc = [];
        foreach (GoalReview::renderPolicyCard($g)->get('lines') as $l) {
            if ($l->get('kind') === 'prohibit') {
                $sev[] = $l->get('severity');
            }
            if ($l->get('kind') === 'escalate') {
                $esc[] = $l->get('text');
            }
        }
        $this->assertSame(['info', 'info', 'red'], $sev);
        $this->assertSame(['ASK THE PRINCIPAL when always.'], $esc);
    }

    // ---- semantic diff ----------------------------------------------------------------------------------------------------

    /** A conjunction splits into both sides; a prohibition whose condition drops a conjunct triggers on more (narrow). */
    public function testConjunctsAndProhibitionDirection(): void
    {
        $a = Obj::of(['k' => 'cmp', 'op' => 'eq', 'l' => 'x', 'r' => 'y']);
        $b = Obj::of(['k' => 'cmp', 'op' => 'eq', 'l' => 'u', 'r' => 'v']);
        $and = Obj::of(['k' => 'and', 'a' => $a, 'b' => $b]);
        $this->assertSame([$a, $b], self::p('conjuncts', $and));
        $t = Obj::of(['k' => 'verb', 'verb' => 'x.y']);
        $o = Obj::of(['pid' => 'p', 'target' => $t, 'res' => 'r', 'cond' => $and]);
        $n = Obj::of(['pid' => 'p', 'target' => $t, 'res' => 'r', 'cond' => $a]);
        $this->assertSame('narrow', self::p('prohibitDir', $o, $n));
    }

    /** Validity: inside the old window is narrow, around it is widen, a mix is unknown. */
    public function testValidityDirection(): void
    {
        $v = static fn(int $b, int $a, int $i) => Obj::of(['notBefore' => new Num((string)$b), 'notAfter' => new Num((string)$a), 'maxIdle' => new Num((string)$i)]);
        $o = $v(10, 20, 5);
        $this->assertSame('narrow', self::p('validityDir', $o, $v(12, 18, 4)));
        $this->assertSame('widen', self::p('validityDir', $o, $v(8, 22, 6)));
        $this->assertSame('unknown', self::p('validityDir', $o, $v(12, 22, 5)));
        $this->assertSame('unknown', self::p('validityDir', $o, $v(8, 22, 4)));
    }

    /** Delegation: depth, the touched grants (subset / superset) and narrowOnly each decide narrow, widen or unknown. */
    public function testDelegationDirection(): void
    {
        $d = static function (int $depth, ?bool $narrowOnly, array $touch): Obj {
            $o = Obj::of(['maxDepth' => new Num((string)$depth), 'mayTouch' => $touch]);
            if ($narrowOnly !== null) {
                $o->set('narrowOnly', $narrowOnly);
            }
            return $o;
        };
        $cases = [
            ['narrow', $d(2, false, ['a', 'b']), $d(1, true, ['a'])],
            ['widen', $d(1, true, ['a']), $d(2, false, ['a', 'b'])],
            ['unknown', $d(2, null, ['a']), $d(1, null, ['b'])],
            ['unknown', $d(1, null, ['a', 'c']), $d(2, null, ['a', 'b'])],
            ['narrow', $d(2, null, ['a', 'b']), $d(1, null, ['a'])],
            ['narrow', $d(2, true, ['a', 'b']), $d(1, true, ['a'])],
            ['unknown', $d(2, null, ['a']), $d(1, null, ['a', 'b'])],
            ['widen', $d(1, null, ['a']), $d(2, null, ['a', 'b'])],
            ['widen', $d(1, true, ['a']), $d(2, true, ['a', 'b'])],
        ];
        foreach ($cases as $i => [$want, $o, $n]) {
            $this->assertSame($want, self::p('delegationDir', $o, $n), "case $i");
        }
    }

    /** Clause ids match by identity, and a NaN id matches only a NaN id. */
    public function testPairsMatchNaNIds(): void
    {
        $kinds = fn(array $prev, array $next) => array_map(static fn(Obj $c) => $c->get('change'),
            self::p('pairs', $prev, $next, 'grant', 'widen', 'narrow', static fn($a, $b) => 'unknown', static fn($id, $v) => 't'));
        $this->assertSame([], $kinds([[NAN, 'v']], [[NAN, 'v']]));
        $this->assertSame(['added', 'removed'], $kinds([['x', 'p']], [[NAN, 'n']]));
        $this->assertSame(['added', 'removed'], $kinds([[self::n(5), 'p']], [[NAN, 'n']]));
    }

    /** An added class prohibition names its effect class; the change cap refuses with the count; witnesses are capped and the kernel's completeness kept. */
    public function testDiffGoals(): void
    {
        $p = Obj::of(['pid' => 'p1', 'target' => Obj::of(['k' => 'cls', 'cls' => 'pay']), 'res' => Obj::of(['k' => 'exact', 'id' => 'r']), 'cond' => Obj::of(['k' => 'true'])]);
        $d = GoalReview::diffGoals(self::goal(), self::goal(['prohibits' => [$p]]));
        $this->assertCount(1, $d->get('changes'));
        $this->assertStringContainsString('effect class "pay" on ', $d->get('changes')[0]->get('text'));
        $e = $this->refusal(fn() => GoalReview::diffGoals(self::goal(['nlDigest' => 'a']), self::goal(['nlDigest' => 'b']), null, Obj::of(['limits' => Obj::of(['max_diff_changes' => self::n(0)])])));
        $this->assertSame('goal review: diff_too_large: 1 changes exceed the cap of 0: review the new goal as a whole instead', $e->getMessage());
        $w1 = Obj::of(['verb' => 'v1']);
        $w2 = Obj::of(['verb' => 'v2']);
        $k = static fn(array $ws, bool $complete) => Obj::of(['newlyAllowed' => static fn($a, $b, $o, $m) => Obj::of(['witnesses' => $ws, 'complete' => $complete])]);
        $opts = static fn(int $max) => Obj::of(['ontology' => Obj::of(['x' => 1]), 'limits' => Obj::of(['max_witnesses' => self::n($max)])]);
        $r = GoalReview::diffGoals(self::goal(), self::goal(), $k([$w1, $w2], true), $opts(1));
        $this->assertSame([$w1], $r->get('newly_allowed'));
        $this->assertFalse($r->get('newly_allowed_complete'));
        $this->assertFalse(GoalReview::diffGoals(self::goal(), self::goal(), $k([], false), $opts(5))->get('newly_allowed_complete'));
        $this->assertTrue(GoalReview::diffGoals(self::goal(), self::goal(), $k([], true), $opts(5))->get('newly_allowed_complete'));
    }

    // ---- approval -----------------------------------------------------------------------------------------------------------

    /** approveGoal: a bad time, a malformed submission and a post-quantum suite without its key are refused with their reason. */
    public function testApproveGoalRefusals(): void
    {
        $refuse = function (callable $f): string {
            try {
                $f();
            } catch (\InvalidArgumentException $e) {
                return $e->getMessage();
            }
            $this->fail('no refusal');
        };
        $this->assertSame('approveGoal: invalid time or ttl', $refuse(fn() => GoalReview::approveGoal(5, self::seed(), Obj::of(['now' => 'x', 'kernel' => self::kernel()]))));
        $this->assertSame('approveGoal: malformed_submission', $refuse(fn() => GoalReview::approveGoal(self::sub(['goal' => 5]), self::seed(), Obj::of(['now' => self::n(1000), 'kernel' => self::kernel()]))));
        $this->assertSame('ml-dsa-65 needs a post-quantum key pair',
            $refuse(fn() => GoalReview::approveGoal(self::sub(), self::seed(), Obj::of(['now' => self::n(1000), 'kernel' => self::kernel(), 'alg' => 'ml-dsa-65']))));
    }

    /** Without `now` the approval time is the wall clock in whole milliseconds, rounded down. */
    public function testApprovalTimeIsFlooredMilliseconds(): void
    {
        GoalReview::$clockHook = static fn(): float => 1.0007;
        $a = GoalReview::approveGoal(self::sub(), self::seed(), Obj::of(['kernel' => self::kernel()]));
        $this->assertSame('1000', $a->get('approved_at')->lexeme);
        $this->assertSame('3601000', $a->get('expires_at')->lexeme);
    }

    /** The loader re-derives the submission: shape, card, analyzer findings and confirmed examples each fail with their own reason. */
    public function testLoaderDerivationReasons(): void
    {
        $bogus = self::approval(false);
        $reason = fn(Obj $sub, array $opts = []) => self::load($sub, $bogus, $opts)->get('reason');
        $this->assertSame('goal_digest_mismatch', $reason(self::sub()));
        $this->assertSame('malformed_submission', $reason(self::sub(['goal' => 5])));
        $this->assertSame('unrenderable', $reason(self::sub(['goal' => new Obj()])));
        $this->assertSame('malformed_goal', $reason(self::sub(['tests' => [new Obj()]])));
        $this->assertSame('analyzer_error', $reason(self::sub(), ['kernel' => self::kernel(static fn($p) => ['x'])]));
        $this->assertSame('goal_digest_mismatch', $reason(self::sub(), ['kernel' => self::kernel(static fn($p) => null)]));
        $this->assertSame('goal_digest_mismatch', $reason(self::sub(), ['kernel' => self::kernel(static fn($p) => self::n(5))]));
        $this->assertSame('goal_digest_mismatch', $reason(self::sub(), ['kernel' => self::kernel(static fn($p) => [])]));
        // examples: the ontology carries the example's relations exactly when it has some
        $decide = static fn(?array $rels) => static fn($g, $ont, $act, $hist) => ($rels === null ? !$ont->has('rels') : $ont->get('rels') === $rels) ? 'allow' : 'deny';
        $t = static fn(array $extra) => Obj::of(['id' => 't1', 'act' => Obj::of(['verb' => 'a.b.c', 'res' => 'r1', 'params' => new Obj()]), 'hist' => Obj::of(['adms' => []]), 'answer' => 'allow'] + $extra);
        $this->assertSame('goal_digest_mismatch', $reason(self::sub(['tests' => [$t([])]]), ['kernel' => self::kernel(null, $decide(null))]));
        $this->assertSame('goal_digest_mismatch', $reason(self::sub(['tests' => [$t(['rels' => ['x']])]]), ['kernel' => self::kernel(null, $decide(['x']))]));
        $this->assertSame('tests_contradicted', $reason(self::sub(['tests' => [$t(['rels' => ['y']])]]), ['kernel' => self::kernel(null, $decide(['x']))]));
    }

    /** The loader's own checks: a -0 expiry is malformed; equal times are a zero TTL; now equal to approved_at is valid; a non-finite now is not. */
    public function testLoaderTimeChecks(): void
    {
        $this->assertSame('malformed_approval', self::load(self::sub(), self::approval(false, ['expires_at' => self::n('-0')]))->get('reason'));
        $this->assertSame('ttl_too_long', self::load(self::sub(), self::approval(true, ['expires_at' => self::n(1000)]))->get('reason'));
        $this->assertSame('bad_signature', self::load(self::sub(), self::approval(true))->get('reason'));
        $this->assertSame('not_yet_valid', self::load(self::sub(), self::approval(true), ['now' => INF])->get('reason'));
    }

    /** Without `now` the loader reads the wall clock (and without `kernel` the proved kernel) and still answers with a refusal object. */
    public function testLoaderDefaults(): void
    {
        $this->assertSame('goal_digest_mismatch', GoalReview::loadApprovedGoal(self::sub(), self::approval(false), Obj::of(['reviewers' => ['r'], 'kernel' => self::kernel()]))->get('reason'));
        $r = GoalReview::loadApprovedGoal(self::sub(), self::approval(false), Obj::of(['reviewers' => ['r'], 'now' => self::n(1000)]));
        $this->assertFalse($r->get('ok'));
        $this->assertIsString($r->get('reason'));
    }
}
