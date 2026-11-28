<?php
declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\InvariantFailure;
use Atlas\Pca\Invariants;
use Atlas\Pca\InvariantsProps;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/InvariantsProps.php';

/**
 * Property verdicts of the invariant checks on known-good and known-bad inputs (through a patched core, so each verdict hangs on
 * one condition), the exact inputs each check hands the core, and the exact runner output (messages, reports, digests).
 */
final class LintSurvivorKill22InvariantsPropsTest extends TestCase
{
    /** @var list<mixed> what the patched core functions saw */
    private static array $calls = [];

    protected function setUp(): void
    {
        self::$calls = [];
    }

    private static function p(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(InvariantsProps::class, $m))->invoke(null, ...$a);
    }

    /** JSON of the model: Obj as an object, Num as its number. */
    private static function js(mixed $v): string
    {
        $plain = static function (mixed $x) use (&$plain): mixed {
            if ($x instanceof Num) {
                return $x->isInt() ? $x->int() : $x->float();
            }
            if ($x instanceof Obj) {
                $o = [];
                foreach ($x->keys() as $k) {
                    $o[$k] = $plain($x->get($k));
                }
                return $o === [] ? new \stdClass() : $o;
            }
            return is_array($x) ? array_map($plain, $x) : $x;
        };
        return json_encode($plain($v), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private static function cv(string $t): Obj
    {
        return Obj::of(['type' => $t]);
    }

    // ---- the real core ----------------------------------------------------------------

    public function testTheRealCoreCastsThePolicyNumbers(): void
    {
        $this->assertSame(['t' => 2, 'proof' => 'standard', 'optimisticAllowed' => false],
            InvariantsProps::real('requiredThreshold')(0.5, ['theta1' => '0.4', 'theta2' => '0.6']));
        $admit = InvariantsProps::real('admit');
        $yes = ['admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true];
        $no = ['admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false];
        $p = ['theta1' => '1', 'theta2' => '1', 'kappa' => '2'];
        $this->assertSame($yes, $admit(0.5, ['B' => '1'], $p)); // the budget exactly covers kappa * r = 1
        $this->assertSame($no, $admit(0.5, ['B' => 0.99], $p));
        $this->assertSame($no, $admit(0.5, ['B' => INF], $p));
        $this->assertSame($no, $admit(0.5, ['B' => NAN], $p));
    }

    public function testAnUnknownCoreFunctionIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('unknown core function nope');
        InvariantsProps::real('nope');
    }

    public function testANestedPatchKeepsTheOuterOne(): void
    {
        $failed = InvariantsProps::withCore(['verifyChain' => static fn(): array => ['ok' => true, 'reason' => '']],
            static fn(): bool => InvariantsProps::withCore([], static function (): bool {
                try {
                    InvariantsProps::run('fail-closed:garbage-chain-rejected', 1, 1);
                    return false;
                } catch (InvariantFailure) {
                    return true;
                }
            }));
        $this->assertTrue($failed);
    }

    // ---- helpers ----------------------------------------------------------------------

    public function testHelpers(): void
    {
        $this->assertSame(0.0, self::p('f', 'x'));
        $this->assertSame(2.0, self::p('f', new Num('2')));

        $a = self::cv('a');
        $b = self::cv('b');
        $c = Obj::of(['caveats' => [$a]]);
        $this->assertTrue(self::p('prefixExtension', $c, Obj::of(['caveats' => [$a, $b]])));
        $this->assertFalse(self::p('prefixExtension', Obj::of(['caveats' => [$a, $b]]), $c));
        $this->assertFalse(self::p('prefixExtension', $c, Obj::of(['caveats' => [$b]])));
        $this->assertFalse(self::p('prefixExtension', Obj::of(['caveats' => 'x']), $c));

        $lim = static fn(mixed $l): Obj => Obj::of(['type' => 'budget_alloc', 'limit' => $l]);
        $this->assertSame([5.0, 2.5], self::p('allocLimits', [$lim(new Num('5')), $lim('x'), Obj::of(['type' => 'expires', 'limit' => new Num('3')]),
            'notobj', $lim(2.5)]));

        $pt = ['action' => Obj::of([]), 'cavCtx' => Obj::of([])];
        $got = InvariantsProps::withCore([
            'evaluatePredicates' => static fn(array $p, Obj $ctx): array => ['allowed' => $p[0]],
            'evaluateCaveats' => static fn(array $cv, Obj $ctx): array => ['ok' => $cv[0], 'failed' => []],
        ], static fn(): array => [self::p('authAllowed', [true], [true], $pt), self::p('authAllowed', [false], [true], $pt),
            self::p('authAllowed', [true], [false], $pt)]);
        $this->assertSame([true, false, false], $got);

        $in = ['semanticDistance' => 0.5, 'reversibility' => 0.5, 'blastRadius' => 0.5, 'taint' => 0.5, 'confidence' => 0.5, 'age' => 0.5];
        $d = ['dSem' => 0.25, 'dBlast' => 0.25, 'dTaint' => 0.25, 'dAge' => 0.25, 'dRev' => 0.25, 'dConf' => 0.25];
        $this->assertSame(['semanticDistance' => 0.75, 'blastRadius' => 0.75, 'taint' => 0.75, 'age' => 0.75, 'reversibility' => 0.25,
            'confidence' => 0.25], self::p('worse', $in, $d));

        $this->assertSame(2.0, self::p('safetyBound', ['kappa' => 2, 'bMax' => 4]));
        $this->assertSame(0.25, self::p('safetyBound', ['kappa' => 2, 'bMax' => 0.5]));
        $this->assertSame(0.0, self::p('safetyBound', ['kappa' => 0, 'bMax' => 4]));
        $this->assertSame(0.0, self::p('safetyBound', ['kappa' => -1, 'bMax' => 4]));
        $this->assertSame(0.0, self::p('safetyBound', ['kappa' => 2, 'bMax' => 'abc']));

        $this->assertSame('{"action":{"verb":"read","resource":"/x"},"subject":"s"}', self::js(self::p('ctx', 'read', '/x', ['subject' => 's'])));

        $o = Obj::of(['a' => [self::cv('z')]]);
        $copy = self::p('cloneCaps', [$o]);
        $this->assertNotSame($o, $copy[0]);
        $this->assertSame(self::js($o), self::js($copy[0]));
    }

    // ---- attenuation ------------------------------------------------------------------

    private static function attenuates(array $caps, array $points, ?\Closure $cav = null): bool
    {
        return InvariantsProps::withCore([
            'buildChain' => static fn(Obj $m): array => ['caps' => $caps, 'rootIssuer' => 'r', 'predicates' => []],
            'verifyChain' => static fn(): array => ['ok' => true, 'reason' => ''],
            'evaluatePredicates' => static fn(): array => ['allowed' => true],
            'evaluateCaveats' => $cav ?? static fn(): array => ['ok' => true, 'failed' => []],
        ], static fn(): bool => self::p('attenuation', [Obj::of([]), $points]));
    }

    public function testAttenuationVerdicts(): void
    {
        [$a, $b, $c] = [self::cv('a'), self::cv('b'), self::cv('c')];
        $cap = static fn(array $cv): Obj => Obj::of(['caveats' => $cv]);
        // the first hop does not extend the root; the second extends the first
        $this->assertFalse(self::attenuates([$cap([$a]), $cap([$b]), $cap([$b, $c])], []));
        $lim = static fn(int $l): Obj => Obj::of(['type' => 'budget_alloc', 'limit' => new Num((string)$l)]);
        // the second allocation grows; the third shrinks again
        $this->assertFalse(self::attenuates([$cap([$lim(5), $lim(7), $lim(6)])], []));
        $this->assertTrue(self::attenuates([$cap([$lim(7), $lim(6), $lim(6)])], []));
        $pt = ['action' => Obj::of([]), 'cavCtx' => Obj::of([])];
        $widens = static fn(array $cv): array => ['ok' => count($cv) === 2, 'failed' => []];
        $this->assertFalse(self::attenuates([$cap([$a]), $cap([$a, $b])], [$pt], $widens));
        $this->assertTrue(self::attenuates([$cap([$a]), $cap([$a, $b])], [$pt]));
    }

    // ---- risk -------------------------------------------------------------------------

    private static function scores(array $rs): \Closure
    {
        $i = 0;
        return static function () use (&$i, $rs): float {
            return $rs[$i++];
        };
    }

    public function testRiskMonotoneVerdicts(): void
    {
        $run = static fn(array $rs): bool => InvariantsProps::withCore(['riskScore' => self::scores($rs)],
            static fn(): bool => self::p('riskMonotone', [['weights' => []], [], []]));
        $this->assertTrue($run([0.0, 0.0]));
        $this->assertFalse($run([-0.5, 0.0]));
        $this->assertFalse($run([0.0, 1.5]));
        $this->assertTrue($run([1e-9, 0.0])); // exactly within the tolerance
    }

    private const POLICY = ['weights' => ['alpha' => 0, 'beta' => 0, 'gamma' => 0, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0],
        'theta1' => 0.5, 'theta2' => 0.5, 'kappa' => 1, 'lambda' => 0, 'rho' => 0, 'bMax' => 1];

    private static function sound(float $r, float $budget, array $adm, array $policy = self::POLICY): bool
    {
        return InvariantsProps::withCore(['riskScore' => static fn(): float => $r, 'admit' => static fn(): array => $adm],
            static fn(): bool => self::p('admissionSoundness', [$policy, [], ['B' => $budget]]));
    }

    public function testAdmissionSoundnessVerdicts(): void
    {
        $adm = static fn(bool $admit, int $t, bool $metered): array => ['admit' => $admit, 'needStepUp' => !$admit, 't' => $t, 'metered' => $metered];
        $this->assertFalse(self::sound(0.5, 10.0, $adm(true, 1, true), ['kappa' => 0] + self::POLICY));
        $this->assertTrue(self::sound(0.5, 10.0, $adm(true, 1, true)));
        $this->assertFalse(self::sound(0.5, 10.0, $adm(false, 3, true)));
        $this->assertTrue(self::sound(1e-9, 0.0, $adm(true, 1, true))); // the budget covers the cost only through the tolerance
        $this->assertFalse(self::sound(0.5, 10.0, $adm(true, 2, true)));
        $this->assertFalse(self::sound(0.5, 10.0, $adm(true, 1, false)));
    }

    private static function cumulative(array $policy, array $rs, array $adm): bool
    {
        return InvariantsProps::withCore([
            'riskScore' => self::scores($rs),
            'admit' => static function (float $r, array $b) use ($adm): array {
                self::$calls[] = $b;
                return $adm;
            },
        ], static fn(): bool => self::p('cumulativeBudgetBound', [$policy, array_fill(0, count($rs), [])]));
    }

    public function testCumulativeBudgetVerdicts(): void
    {
        $metered = ['admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true];
        $unmetered = ['admit' => false, 'needStepUp' => true, 't' => 1, 'metered' => false];
        $strong = ['admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => true];
        $pol = static fn(mixed $kappa, mixed $bMax): array => ['weights' => [], 'kappa' => $kappa, 'bMax' => $bMax];

        $this->assertTrue(self::cumulative($pol(1, 'abc'), [0.5], $unmetered));
        $this->assertSame([['B' => 0.0, 'tau' => 0, 'asOf' => 0]], self::$calls);

        $this->assertTrue(self::cumulative($pol(1, 0), [0.5], $strong));
        $this->assertTrue(self::cumulative($pol(1, 0), [0.5], $unmetered));
        $this->assertTrue(self::cumulative($pol(1, 0), [1e-9], $metered)); // covered only through the tolerance
        // r above 1 costs kappa * 1, but Sum(r) counts the raw r: the third step passes the bound
        $this->assertFalse(self::cumulative($pol(1, 5), [2.0, 2.0, 2.0], $metered));
        $this->assertTrue(self::cumulative($pol(1, 5), [2.0, 2.0], $metered));
        // kappa 0: nothing is debited, but the safety bound is 0
        $this->assertFalse(self::cumulative($pol(0, 5), [0.5], $metered));
        $this->assertTrue(self::cumulative($pol(0, 5), [1e-6], $metered));
        $this->assertTrue(self::cumulative($pol(1, 1), [1.0 + 1e-6], $metered)); // kappa * Sum(r) equals bMax + 1e-6 exactly
    }

    // ---- fail closed: the exact inputs ------------------------------------------------

    public function testUndecidableLeafHandsTheCoreEachLeaf(): void
    {
        $expect = [
            '{"field":"subject.role.definitely_absent","op":"eq","value":"x"}',
            '{"field":"subject.role","op":"lt","value":5}',
            '{"field":"subject.role","op":"in","value":"not-an-array"}',
            '{"field":"subject.role","op":"eq"}',
            '{"field":"subject.role","op":"member_of","value":"g","collection":"env.no_such_collection"}',
        ];
        $patch = [
            'evaluateConditionTri' => static function (mixed $c, Obj $ctx): string {
                self::$calls[] = ['tri', self::js($c), self::js($ctx)];
                return 'unknown';
            },
            'evaluateCondition' => static fn(): bool => false,
            'evaluatePredicates' => static function (array $preds, Obj $ctx): array {
                self::$calls[] = ['preds', self::js($preds)];
                return ['allowed' => false];
            },
        ];
        foreach ($expect as $pick => $leaf) {
            self::$calls = [];
            $this->assertTrue(InvariantsProps::withCore($patch, static fn(): bool => self::p('undecidableLeaf', [$pick, 'write'])));
            $this->assertSame([
                ['tri', $leaf, '{"action":{"verb":"write","resource":"/x"},"subject":{"role":"admin"}}'],
                ['preds', '[{"verb":"write","resource":"/x","where":[' . $leaf . ']}]'],
            ], self::$calls, "pick $pick");
        }
        $this->assertFalse(InvariantsProps::withCore(['evaluateCondition' => static fn(): bool => true] + $patch,
            static fn(): bool => self::p('undecidableLeaf', [0, 'read'])));
    }

    public function testUndecidableGroupsHandTheCoreEachGroup(): void
    {
        InvariantsProps::withCore(['evaluateConditionTri' => static function (mixed $c, Obj $ctx): string {
            self::$calls[] = self::js($c);
            self::$calls[] = self::js($ctx);
            return 'unknown';
        }], static fn(): bool => self::p('undecidableGroups', [0]));
        $bad = '{"field":"subject.role","op":"lt","value":5}';
        $ctx = '{"action":{"verb":"read","resource":"/x"},"subject":{"role":"admin"}}';
        $this->assertSame(['{"not":' . $bad . '}', $ctx, '{"all_of":[]}', $ctx, '{"any_of":[]}', $ctx, '{"all_of":[' . $bad . ']}', $ctx,
            '{"any_of":[' . $bad . ']}', $ctx], self::$calls);
    }

    public function testMemberOfAndUnknownCaveatHandTheCoreTheirInputs(): void
    {
        $this->assertTrue(InvariantsProps::withCore(['evaluateConditionTri' => static function (mixed $c, Obj $ctx): string {
            self::$calls[] = self::js($c);
            self::$calls[] = self::js($ctx);
            return 'true';
        }], static fn(): bool => self::p('memberOfCycleSafe', ['c'])));
        $this->assertSame(['{"field":"subject.g","op":"member_of","value":"c","collection":"env.rel"}',
            '{"action":{"verb":"read","resource":"/x"},"subject":{"g":"a"},"env":{"rel":{"a":["b"],"b":["a","c"]}}}'], self::$calls);
        $this->assertTrue(self::p('memberOfCycleSafe', ['c'])); // the real core reaches c through the cycle

        self::$calls = [];
        $this->assertTrue(InvariantsProps::withCore(['evaluateCaveats' => static function (array $cv, Obj $ctx): array {
            self::$calls[] = self::js($cv);
            self::$calls[] = self::js($ctx);
            return ['ok' => false, 'failed' => []];
        }], static fn(): bool => self::p('unknownCaveatType', ['zz', 7])));
        $this->assertSame(['[{"type":"zz"}]', '{"now":7}'], self::$calls);
    }

    // ---- forged chains ----------------------------------------------------------------

    private const AUX = "\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07";

    /** Runs one attack on a synthetic chain: the first verification is ok, every later one answers `$laterOk`. */
    private static function forged(array $caps, string $mutation, int $pick, bool $laterOk, string $root = 'root'): bool
    {
        return InvariantsProps::withCore([
            'buildChain' => static fn(Obj $m): array => ['caps' => $caps, 'rootIssuer' => $root, 'predicates' => []],
            'verifyChain' => static function (array $c, ?string $issuer) use ($laterOk): array {
                self::$calls[] = [$c, $issuer];
                return ['ok' => count(self::$calls) === 1 ? true : $laterOk, 'reason' => ''];
            },
            'delegate' => static fn(): Obj => Obj::of(['forged' => true]),
        ], static fn(): bool => self::p('forgedChainRejected', [Obj::of([]), $mutation, $pick, self::AUX]));
    }

    private static function hop(array $cv): Obj
    {
        return Obj::of(['id' => 'i', 'holder' => 'h', 'parent' => 'p', 'caveats' => $cv]);
    }

    public function testThePristineChainMustVerify(): void
    {
        $this->assertFalse(InvariantsProps::withCore([
            'buildChain' => static fn(Obj $m): array => ['caps' => [self::hop([])], 'rootIssuer' => 'r', 'predicates' => []],
            'verifyChain' => static fn(): array => ['ok' => false, 'reason' => 'no'],
        ], static fn(): bool => self::p('forgedChainRejected', [Obj::of([]), 'tamper-caveat', 0, self::AUX])));
    }

    public function testTamperCaveatAppendsOneCaveat(): void
    {
        [$a, $b] = [self::cv('a'), self::cv('b')];
        $this->assertTrue(self::forged([self::hop([$a]), self::hop([$a, $b])], 'tamper-caveat', 1, false));
        $this->assertCount(2, self::$calls);
        [$caps, $issuer] = self::$calls[1];
        $this->assertSame('root', $issuer);
        $this->assertSame('[{"type":"a"}]', self::js($caps[0]->get('caveats')));
        $this->assertSame('[{"type":"a"},{"type":"b"},{"type":"expires","at":999}]', self::js($caps[1]->get('caveats')));
    }

    public function testDropLeafCaveat(): void
    {
        $this->assertTrue(self::forged([self::hop([])], 'drop-leaf-caveat', 0, true)); // nothing to drop
        $this->assertCount(1, self::$calls);
        self::$calls = [];
        $this->assertTrue(self::forged([self::hop([self::cv('a'), self::cv('b'), self::cv('c')])], 'drop-leaf-caveat', 0, false));
        $this->assertSame('[{"type":"a"},{"type":"b"}]', self::js(self::$calls[1][0][0]->get('caveats')));
        self::$calls = [];
        $this->assertFalse(self::forged([self::hop([self::cv('a')])], 'drop-leaf-caveat', 0, true));
    }

    public function testBreakParentDetachesTheFirstNonRootHop(): void
    {
        $this->assertTrue(self::forged([self::hop([])], 'break-parent', 0, true)); // no non-root hop
        self::$calls = [];
        $this->assertFalse(self::forged([self::hop([]), self::hop([])], 'break-parent', 0, true));
        $caps = self::$calls[1][0];
        $this->assertSame('p', $caps[0]->get('parent'));
        $this->assertSame(Pca::hashCanonical(Sign::n(['bogus' => 32, 'tag' => 'not-a-real-parent'])), $caps[1]->get('parent'));
    }

    public function testWrongRootIssuer(): void
    {
        $aux = Invariants::keyPairFromSeed(self::AUX)['pub'];
        $this->assertTrue(self::forged([self::hop([])], 'wrong-root-issuer', 0, true, $aux)); // the aux key IS the root: inapplicable
        $this->assertCount(1, self::$calls);
        self::$calls = [];
        $this->assertFalse(self::forged([self::hop([])], 'wrong-root-issuer', 0, true));
        $this->assertSame($aux, self::$calls[1][1]);
    }

    public function testBreakIdAndAppendForgedHopAndUnknown(): void
    {
        $this->assertTrue(self::forged([self::hop([]), self::hop([])], 'break-id', 3, false));
        $this->assertSame('i', self::$calls[1][0][0]->get('id'));
        $this->assertSame(Pca::hashCanonical(Sign::n(['not' => 'the-body-digest', 'n' => 1])), self::$calls[1][0][1]->get('id'));

        self::$calls = [];
        $h0 = self::hop([]);
        $h1 = self::hop([]);
        $this->assertTrue(self::forged([$h0, $h1], 'append-forged-hop', 0, false));
        $sent = self::$calls[1][0];
        $this->assertCount(3, $sent);
        $this->assertSame($h0, $sent[0]);
        $this->assertSame($h1, $sent[1]);
        $this->assertSame('{"forged":true}', self::js($sent[2]));

        self::$calls = [];
        $this->assertFalse(self::forged([self::hop([])], 'no-such-attack', 0, false));
    }

    // ---- determinism ------------------------------------------------------------------

    private static function alt(mixed $a, mixed $b): \Closure
    {
        $i = 0;
        return static function () use (&$i, $a, $b): mixed {
            return $i++ % 2 === 0 ? $a : $b;
        };
    }

    private static function deterministic(array $patch): bool
    {
        $base = [
            'buildChain' => static fn(Obj $m): array => ['caps' => [Obj::of(['caveats' => []])], 'rootIssuer' => 'r', 'predicates' => []],
            'verifyChain' => static fn(): array => ['ok' => true, 'reason' => ''],
            'evaluatePredicates' => static fn(): array => ['allowed' => true, 'reason' => null],
            'evaluateCaveats' => static fn(): array => ['ok' => true, 'failed' => []],
            'riskScore' => static fn(): float => 0.5,
            'requiredThreshold' => static fn(): array => ['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => true],
            'admit' => static fn(): array => ['admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true],
        ];
        $pt = ['action' => Obj::of([]), 'cavCtx' => Obj::of([])];
        return InvariantsProps::withCore($patch + $base,
            static fn(): bool => self::p('determinism', [Obj::of([]), $pt, [], ['weights' => []], [], []]));
    }

    public function testDeterminismNoticesEachSingleDifference(): void
    {
        $this->assertTrue(self::deterministic([]));
        $this->assertFalse(self::deterministic(['verifyChain' => self::alt(['ok' => true, 'reason' => 'a'], ['ok' => true, 'reason' => 'b'])]));
        $this->assertFalse(self::deterministic(['evaluatePredicates' => self::alt(['allowed' => true, 'reason' => 'a'], ['allowed' => true, 'reason' => 'b'])]));
        $this->assertFalse(self::deterministic(['evaluateCaveats' => self::alt(['ok' => true, 'failed' => ['a']], ['ok' => true, 'failed' => ['b']])]));
        $this->assertFalse(self::deterministic(['requiredThreshold' => self::alt(['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => true],
            ['t' => 1, 'proof' => 'other', 'optimisticAllowed' => true])]));
        $this->assertFalse(self::deterministic(['admit' => self::alt(['admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true],
            ['admit' => true, 'needStepUp' => true, 't' => 1, 'metered' => true])]));
    }

    // ---- forbid monotone --------------------------------------------------------------

    private static function forbid(array $decisions, int $rot): bool
    {
        return InvariantsProps::withCore(['decideClauses' => static function (array $clauses) use ($decisions): array {
            self::$calls[] = implode(',', array_map(static fn(Obj $c): string => $c->get('id') . '/' . $c->get('kind') . '/' . $c->get('when'), $clauses));
            return ['decision' => $decisions[count(self::$calls) - 1]];
        }], static fn(): bool => self::p('forbidMonotone', [['w1', 'w2'], ['w3'], ['w4'], ['action' => 'any', 'cavCtx' => Obj::of([])], $rot]));
    }

    public function testForbidMonotoneClausesAndVerdicts(): void
    {
        $this->assertTrue(self::forbid(['allow', 'deny', 'deny'], 1));
        $this->assertSame([
            'p0/permit/w1,p1/permit/w2,e0/escalate/w4',
            'p0/permit/w1,p1/permit/w2,e0/escalate/w4,f0/forbid/w3',
            'p1/permit/w2,e0/escalate/w4,f0/forbid/w3,p0/permit/w1',
        ], self::$calls);
        self::$calls = [];
        $this->assertFalse(self::forbid(['deny', 'allow', 'allow'], 0)); // adding a forbid moved the decision up
    }

    // ---- describe / run / caseDigest / checkInvariants --------------------------------

    public function testDescribe(): void
    {
        $v = [new Num('5'), new Num('1.5'), new Obj(), Obj::of(['a' => new Num('1')]), ['x/y', new Num('7')], "\xff", Obj::of(["\xff" => 'v'])];
        $this->assertSame('[5,1.5,{},{"a":1},["x/y",7],"hex:ff",{"�":"v"}]', self::p('describe', $v));
        $this->assertSame('"' . str_repeat('a', 3999) . '...', self::p('describe', str_repeat('a', 4100)));
        $exact = '"' . str_repeat('a', 3998) . '"'; // exactly 4000 bytes: not cut
        $this->assertSame($exact, self::p('describe', str_repeat('a', 3998)));
    }

    public function testRunDrawsExactlyNumRunsCases(): void
    {
        InvariantsProps::withCore(['evaluateConditionTri' => static function (): string {
            self::$calls[] = 1;
            return 'unknown';
        }], static fn() => InvariantsProps::run('fail-closed:undecidable-groups', 2, 1));
        $this->assertCount(10, self::$calls); // 2 cases x 5 groups
    }

    public function testFailureMessagesAndReports(): void
    {
        $catch = static function (\Closure $tri): InvariantFailure {
            try {
                InvariantsProps::withCore(['evaluateConditionTri' => $tri], static fn() => InvariantsProps::run('fail-closed:undecidable-groups', 3, 3));
            } catch (InvariantFailure $e) {
                return $e;
            }
            throw new \LogicException('no failure');
        };
        $e = $catch(static function (): string {
            throw new \RuntimeException('boom');
        });
        $this->assertSame('invariant fail-closed:undecidable-groups failed at case 0 (seed 3): RuntimeException: boom; counterexample: [0]', $e->getMessage());
        $this->assertSame(['property' => 'fail-closed:undecidable-groups', 'seed' => 3, 'counterexample' => '[0]', 'case' => 0,
            'error' => 'RuntimeException: boom'], $e->report);
        $e = $catch(static fn(): string => 'true');
        $this->assertSame('invariant fail-closed:undecidable-groups failed at case 0 (seed 3); counterexample: [0]', $e->getMessage());
        $this->assertNull($e->report['error']);
    }

    public function testCaseDigest(): void
    {
        // the groups property draws the constant case [0]: the digest is sha256 of its serialization, once per run
        $this->assertSame('38adc7d3ae76c7924ca2a4b5d6514cc84de96a79d5d73612c7687a56817acd77', InvariantsProps::caseDigest('fail-closed:undecidable-groups', 2, 1));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('unknown invariant nope');
        InvariantsProps::caseDigest('nope', 1, 1);
    }

    public function testOneRunIsEnough(): void
    {
        $results = InvariantsProps::checkInvariants(['numRuns' => 1, 'seed' => 7]);
        $this->assertCount(12, $results);
        foreach ($results as $r) {
            $this->assertSame(['name' => $r['name'], 'ok' => true, 'numRuns' => 1, 'seed' => 7], $r);
        }
    }
}
