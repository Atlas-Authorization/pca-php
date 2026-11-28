<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AtomicKv;
use Atlas\Pca\Immune;
use Atlas\Pca\Json;
use Atlas\Pca\Jsx;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 25 kills for src/Immune.php: baseline and decay edges, state bounds, threat thresholds, policy gates, no-widen, proposals, the store. */
final class SysSurvivorKill25ImmuneTest extends TestCase
{
    private const CFG = ['driftZSat' => 1, 'stepUpSat' => 1, 'denySat' => 1];

    /** @param array<string,mixed> $over */
    private static function pol(array $over = []): Obj
    {
        $w = Obj::of(['alpha' => 0.1, 'beta' => 0.1, 'gamma' => 0.1, 'delta' => 0.1, 'epsilon' => 0.1, 'zeta' => 0.1]);
        return Obj::of($over + ['weights' => $w, 'theta1' => 0.3, 'theta2' => 0.6, 'kappa' => 1.0, 'lambda' => 0, 'rho' => 0, 'bMax' => 0]);
    }

    /** @param array<string,mixed> $over @param array<string,mixed> $base */
    private static function state(array $over = [], array $base = []): Obj
    {
        $s = Immune::initialState();
        foreach ($over as $k => $v) {
            $s->set($k, $v);
        }
        foreach ($base as $k => $v) {
            $s->get('baseline')->set($k, $v);
        }
        return $s;
    }

    /** @param \Closure():mixed $f */
    private function throwsExactly(string $class, string $message, \Closure $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class, $e->getMessage());
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected $class: $message");
    }

    public function testBaseline(): void
    {
        $b = Immune::emptyBaseline();
        $this->assertSame([0, 0, 0], [$b->get('n'), $b->get('mean'), $b->get('m2')]);
        $this->assertSame(0.0, Immune::updateBaseline($b, 'x')->get('mean'), 'a sample that is not a number counts as 0');
        $this->assertSame(0.5, Immune::baselineStd(Obj::of(['n' => 2, 'mean' => 0.5, 'm2' => 0.5])));
    }

    /** No time passes for a first observation or a repeated timestamp; an unknown last time poisons the counters (NaN), as the reference. */
    public function testObserveElapsedTime(): void
    {
        $fast = ['halfLifeMs' => 1];
        $this->assertSame(2.0, Immune::observe(self::state(['stepUps' => 2]), Obj::of(['r' => 0]), $fast)->get('stepUps'));
        $this->assertSame(2.0, Immune::observe(self::state(['stepUps' => 2, 'seeded' => true, 'lastAt' => 100]), Obj::of(['r' => 0, 'at' => 100]), $fast)->get('stepUps'));
        $this->assertNan(Immune::observe(self::state(['stepUps' => 2, 'seeded' => true, 'lastAt' => 'x']), Obj::of(['r' => 0]), $fast)->get('stepUps'));
        $this->assertSame(0.0, Immune::observe(self::state(['seeded' => true, 'lastAt' => 'x']), Obj::of(['r' => 0]), $fast)->get('stepUps'), 'a zero counter stays 0 even then');
        // control: one half-life later the counter halves
        $this->assertSame(1.0, Immune::observe(self::state(['stepUps' => 2, 'seeded' => true, 'lastAt' => 100]), Obj::of(['r' => 0, 'at' => 101]), $fast)->get('stepUps'));
    }

    /** A config member is coerced as the reference's arithmetic does: '0.5' is 0.5, 'x' is NaN. */
    public function testConfigCoercion(): void
    {
        $seeded = self::state(['seeded' => true]);
        $this->assertSame(0.5, Immune::observe($seeded, Obj::of(['r' => 1]), ['alpha' => '0.5'])->get('ewma'));
        $this->assertNan(Immune::observe($seeded, Obj::of(['r' => 1]), ['alpha' => 'x'])->get('ewma'));
    }

    public function testStateBounds(): void
    {
        $this->assertNull(Immune::validateImmuneState(self::state()));
        $this->assertSame('baseline.n must be an integer in [0, 1e9]', Immune::validateImmuneState(self::state([], ['n' => -1])));
        $this->assertSame('baseline.mean must be in [0, 1]', Immune::validateImmuneState(self::state([], ['mean' => -0.5])));
        $this->assertSame('ewma must be in [0, 1]', Immune::validateImmuneState(self::state(['ewma' => -0.5])));
        $this->assertSame('denies must be finite and >= 0', Immune::validateImmuneState(self::state(['denies' => -0.5])));
    }

    /** The thresholds are strict for signals (> 0.33) and inclusive for levels (>= 0.33, >= 0.66); drift needs n >= 5 and std > 1e-9. */
    public function testThreatThresholds(): void
    {
        $a = Immune::assess(self::state(['stepUps' => 0.33]), self::CFG);
        $this->assertSame(['elevated', []], [$a->get('level'), $a->get('signals')]);
        $a = Immune::assess(self::state(['denies' => 0.33]), self::CFG);
        $this->assertSame(['elevated', []], [$a->get('level'), $a->get('signals')]);
        $this->assertSame('high', Immune::assess(self::state(['stepUps' => 0.66]), self::CFG)->get('level'));
        $a = Immune::assess(self::state(['ewma' => 0.33], ['n' => 5, 'mean' => 0, 'm2' => 5]), self::CFG);
        $this->assertSame(0.33, $a->get('components')->get('drift'));
        $this->assertSame([], $a->get('signals'));
        $a = Immune::assess(self::state(['ewma' => 1], ['n' => 5, 'mean' => 0, 'm2' => 5e-18]), self::CFG); // std is exactly 1e-9
        $this->assertSame(0.0, $a->get('components')->get('drift'));
    }

    public function testPolicyGates(): void
    {
        $seed = str_repeat("\x05", 32);
        $this->assertInstanceOf(Obj::class, Immune::issueTighteningProposal(self::pol(), Immune::initialState(), 1, 1000, $seed), 'lambda, rho and bMax of 0 are valid');
        $this->throwsExactly(\InvalidArgumentException::class, 'issueTighteningProposal: risk_policy.theta1 must be finite',
            static fn() => Immune::issueTighteningProposal(self::pol()->without('theta1'), Immune::initialState(), 1, 1000, $seed));
        $this->throwsExactly(\InvalidArgumentException::class, 'issueTighteningProposal: risk_policy lambda/rho/bMax must be >= 0',
            static fn() => Immune::issueTighteningProposal(self::pol(['lambda' => -1]), Immune::initialState(), 1, 1000, $seed));
        $this->throwsExactly(\InvalidArgumentException::class, 'issueTighteningProposal: epoch must be an integer >= 1',
            static fn() => Immune::issueTighteningProposal(self::pol(), Immune::initialState(), INF, 1000, $seed));
    }

    /** The rationale reads the signals as the reference does: null throws, a string is not joinable, a non-list reads as empty. */
    public function testAdaptSignals(): void
    {
        $as = static fn(mixed $sig): Obj => Obj::of(['level' => 'elevated', 'score' => 0.5, 'signals' => $sig]);
        $this->throwsExactly(\TypeError::class, "Cannot read properties of null or undefined (reading 'length')", static fn() => Immune::adapt(self::pol(), $as(null)));
        $this->throwsExactly(\TypeError::class, 'assessment.signals.join is not a function', static fn() => Immune::adapt(self::pol(), $as('a')));
        foreach ([5, ''] as $sig) {
            $this->assertStringStartsWith('elevated: threat score 0.50 → κ ×', Immune::adapt(self::pol(), $as($sig))->get('rationale'));
        }
        $this->assertStringStartsWith('elevated: true; b → κ ×', Immune::adapt(self::pol(), $as([true, 'b']))->get('rationale'));
    }

    public function testNoWiden(): void
    {
        $this->assertSame('kappa decreased', Immune::noWidenViolation(self::pol(['kappa' => 'x']), self::pol()));
        $this->assertSame('kappa decreased', Immune::noWidenViolation(self::pol(['kappa' => NAN]), self::pol()));
        $this->assertSame('theta1 increased', Immune::noWidenViolation(self::pol(['theta1' => 'x']), self::pol()));
        $this->assertNull(Immune::noWidenViolation(self::pol(['lambda' => 'x']), self::pol(['lambda' => 'x'])));
        $this->assertSame('lambda changed', Immune::noWidenViolation(self::pol(['lambda' => null]), self::pol(['lambda' => 0])));
        $this->assertSame('lambda changed', Immune::noWidenViolation(self::pol(['lambda' => [1]]), self::pol(['lambda' => [1]])));
        $this->throwsExactly(\TypeError::class, 'Cannot convert undefined or null to object', static fn() => Immune::noWidenViolation(self::pol()->without('weights'), self::pol()));
        Immune::assertNoWiden(self::pol(), self::pol(['kappa' => 2.0]));
        $this->throwsExactly(\RuntimeException::class, 'immune: adaptation widens the policy (kappa decreased)', static fn() => Immune::assertNoWiden(self::pol(), self::pol(['kappa' => 0.5])));
    }

    public function testStaleWhenNowIsNotFinite(): void
    {
        $p = Immune::issueTighteningProposal(self::pol(), Immune::initialState(), 1, 1000, str_repeat("\x05", 32));
        $o = Obj::of(['guardian' => $p->get('guardian'), 'now' => 1000, 'maxAgeMs' => 10, 'lastEpoch' => 0]);
        $this->assertTrue(Immune::applyTightening(self::pol(), $p, $o)->get('ok'));
        $o->set('now', INF);
        $o->set('maxAgeMs', INF);
        $this->assertSame([false, 'stale'], [Immune::applyTightening(self::pol(), $p, $o)->get('ok'), Immune::applyTightening(self::pol(), $p, $o)->get('reason')]);
    }

    public function testStore(): void
    {
        $kv = new MemoryAtomicKv();
        $kv->update('immune/state/s', static fn(?string $prev): string => '{"bad":1}');
        $this->throwsExactly(\RuntimeException::class, 'immune store: stored state invalid (baseline missing)', static fn() => Immune::createImmuneStore($kv, 's')->observe(Obj::of(['r' => 0])));

        $idle = new class () implements AtomicKv {
            public function get(string $key): ?string
            {
                return null;
            }

            public function update(string $key, callable $fn): void
            {
            }
        };
        $store = Immune::createImmuneStore($idle, 's');
        $this->throwsExactly(\RuntimeException::class, 'immune store: the update did not run', static fn() => $store->observe(Obj::of(['r' => 0])));
        $out = $store->apply(self::pol(), new Obj(), new Obj());
        $this->assertSame([false, 'malformed'], [$out->get('ok'), $out->get('reason')]);

        // with nothing applied yet the floor is 0: an epoch-0 proposal (validly signed) is a replay
        $seed = str_repeat("\x05", 32);
        $p = Immune::issueTighteningProposal(self::pol(), Immune::initialState(), 1, 1000, $seed);
        $claim = $p->without('sig');
        $claim->set('epoch', 0);
        $p0 = Jsx::spread($claim);
        $p0->set('sig', Pca::b64u((new KeyPair($seed))->sign(Immune::TIGHTENING_DOMAIN . Json::canonicalizeLenient($claim))));
        $o = Obj::of(['guardian' => $p->get('guardian'), 'now' => 1000, 'maxAgeMs' => 10]);
        $s = Immune::createImmuneStore(new MemoryAtomicKv(), 's');
        $this->assertSame('replayed-epoch', $s->apply(self::pol(), $p0, $o)->get('reason'));
        $this->assertTrue($s->apply(self::pol(), $p, $o)->get('ok'));
        $this->assertSame(1.0, $s->lastEpoch());
    }
}
