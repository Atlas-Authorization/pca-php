<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SlidingWindowCounter;
use Atlas\Pca\Undef;
use Atlas\Pca\Wallet;
use PHPUnit\Framework\TestCase;

/** group 15 mutation kills for src/Wallet.php: the answer wire checks, friction and provenance, cell coordinates, canaries, the noise statistics. */
final class ConsentSurvivorKill15WalletTest extends TestCase
{
    private static function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('expected a throw');
    }

    private static function assertThrown(string $class, string $message, callable $f): void
    {
        $e = self::thrown($f);
        self::assertSame($class, get_class($e), $e->getMessage());
        self::assertSame($message, $e->getMessage());
    }

    private static function d32(int $n): string
    {
        return Pca::b64u(str_repeat(chr($n), 32));
    }

    /** A well-formed unsigned tap-tier yes answer, with `$set` members and `$ux` members over the defaults. */
    private static function answer(array $set = [], array $ux = []): Obj
    {
        $a = Obj::of(['v' => 2, 'kind' => 'pca-intent-observation', 'map_digest' => self::d32(1), 'session' => self::d32(2), 'question_id' => 'q1', 'verb' => 'v',
            'cell' => Obj::of(['x' => ['a']]), 'y' => 1, 'source' => 'elicitation', 'observed_at' => 0,
            'ux' => Obj::of($ux + ['tier' => 'tap', 'rendered_digest' => self::d32(3), 'canary' => false]), 'signer' => self::d32(4), 'alg' => 'ed25519']);
        foreach ($set as $k => $v) {
            $a->set($k, $v);
        }
        return $a;
    }

    // ---- the sliding window and the value helpers ---------------------------------------------------------------------------------

    /** The default window is one hour: an event at 0 still counts at 3599999 and is gone at 3600000; bad numbers are refused. */
    public function testSlidingWindow(): void
    {
        $w = new SlidingWindowCounter();
        $this->assertTrue($w->tryAdd(0, 10));
        $this->assertSame(1, $w->count(3599999));
        $this->assertSame(0, $w->count(3600000));
        self::assertThrown(\InvalidArgumentException::class, 'SlidingWindowCounter: windowMs must be a positive integer', static fn() => new SlidingWindowCounter('x'));
        self::assertThrown(\TypeError::class, 'SlidingWindowCounter: a number is required', static fn() => $w->count('x'));
    }

    /** g reads only dict members; req and reqNum refuse an absent or non-numeric member; dictKeys gives string keys. */
    public function testMemberHelpers(): void
    {
        $this->assertInstanceOf(Undef::class, Wallet::g(['a'], '0'));
        $this->assertInstanceOf(Undef::class, Wallet::g('x', 'k'));
        $this->assertSame(1, Wallet::g(['k' => 1], 'k'));
        self::assertThrown(\OutOfBoundsException::class, 'missing member k', static fn() => Wallet::req([], 'k'));
        self::assertThrown(\TypeError::class, 'member k is not a number', static fn() => Wallet::reqNum(['k' => 'x'], 'k'));
        $this->assertSame(['5', 'a'], Wallet::dictKeys([5 => 'x', 'a' => 1]));
        $this->assertSame(['b'], Wallet::dictKeys(Obj::of(['b' => 1])));
    }

    /** entries yields string indices for lists, keyed arrays and strings (by code point; invalid UTF-8 by byte). */
    public function testEntries(): void
    {
        $this->assertSame([['0', 'a'], ['1', 'b']], Wallet::entries(['a', 'b']));
        $this->assertSame([['5', 'a']], Wallet::entries([5 => 'a']));
        $this->assertSame([['0', 'a'], ['1', "\u{e9}"]], Wallet::entries("a\u{e9}"));
        $this->assertSame([['0', "\xFF"]], Wallet::entries("\xFF"));
        $this->assertSame([], Wallet::entries(''));
    }

    /** jsPlain turns the largest safe integer into a Num. */
    public function testJsPlainMaxSafe(): void
    {
        $n = Wallet::jsPlain(9007199254740991);
        $this->assertInstanceOf(Num::class, $n);
        $this->assertSame('9007199254740991', $n->lexeme);
    }

    // ---- friction and provenance --------------------------------------------------------------------------------------------------

    /** worstProvenance refuses a non-list. */
    public function testWorstProvenanceRefusals(): void
    {
        self::assertThrown(\TypeError::class, 'levels is not iterable', static fn() => Wallet::worstProvenance(5));
        self::assertThrown(\TypeError::class, 'levels is not iterable', static fn() => Wallet::worstProvenance(['a' => 'trusted']));
    }

    /** frictionFor: provenance must be iterable and made of dicts; a tainted critical source raises to typed and stops the scan. */
    public function testFrictionProvenance(): void
    {
        $f = static fn(mixed $prov) => static fn() => Wallet::frictionFor(['expectedHarm' => 1, 'provenance' => $prov]);
        self::assertThrown(\TypeError::class, 'provenance is not iterable', $f(5));
        self::assertThrown(\TypeError::class, 'provenance entry is not an object', $f(Obj::of(['k' => 1])));
        self::assertThrown(\TypeError::class, 'provenance entry is not an object', $f('ab'));
        self::assertThrown(\TypeError::class, 'provenance entry is not an object', $f("\xFF")); // invalid UTF-8 iterates by byte
        $tainted = ['sensitivity' => 'critical', 'levels' => ['web']];
        $this->assertSame(['tier' => 'typed', 'rules' => ['tainted-critical']], Wallet::frictionFor(['expectedHarm' => 1, 'provenance' => [$tainted, 'x']]));
    }

    // ---- action digests and projections -------------------------------------------------------------------------------------------

    /** An action without a verb has no digest; only finite numbers and strings are projected. */
    public function testActionHelpers(): void
    {
        self::assertThrown(\TypeError::class, 'canonicalize: undefined', static fn() => Wallet::pcaActionDigest(['resource' => 'r', 'params' => [], 'reversibility_class' => 'reversible']));
        $out = Wallet::actionValuesOf(['verb' => 'v', 'params' => ['x' => INF, 'y' => 2]]);
        $this->assertSame(['action.params.y'], $out->get('values')->keys());
        $this->assertSame('v', $out->get('verb'));
    }

    // ---- the answer wire ----------------------------------------------------------------------------------------------------------

    /** Optional ux members must be well formed when present; hold_ms 0 is allowed off the hold tier, and the hold tier needs 2000 ms. */
    public function testUxMembers(): void
    {
        $this->assertNull(Wallet::answerShapeError(self::answer()));
        $this->assertSame('ux.typed_digest is not canonical base64url (32 bytes)', Wallet::answerShapeError(self::answer([], ['typed_digest' => 'x'])));
        $this->assertNull(Wallet::answerShapeError(self::answer([], ['hold_ms' => 0])));
        foreach ([1.5, -1] as $h) {
            $this->assertSame('ux.hold_ms must be a non-negative integer', Wallet::answerShapeError(self::answer([], ['hold_ms' => $h])));
        }
        $this->assertSame('ux.action_digest is not canonical base64url (32 bytes)', Wallet::answerShapeError(self::answer([], ['action_digest' => 'x'])));
        $this->assertSame('ux.consent_for_action must be a boolean', Wallet::answerShapeError(self::answer([], ['consent_for_action' => 'x'])));
        $this->assertNull(Wallet::answerShapeError(self::answer([], ['tier' => 'hold', 'hold_ms' => 2000])));
        $this->assertSame('hold tier needs hold_ms >= 2000', Wallet::answerShapeError(self::answer([], ['tier' => 'hold', 'hold_ms' => 1999])));
    }

    /** A partial answer needs a string path and exactly one well-formed part. */
    public function testPartialShapes(): void
    {
        $e = static fn(array $p): ?string => Wallet::answerShapeError(self::answer(['partial' => $p]));
        $this->assertNull($e(['path' => 'p', 'notFor' => ['x']]));
        $this->assertSame('partial.path must be a non-empty string', $e(['path' => 5]));
        foreach ([5, ['x']] as $v) {
            $this->assertSame('partial.except must be a non-empty integer array', $e(['path' => 'p', 'except' => $v]));
        }
        foreach ([[], ['a' => 'x'], 5] as $v) {
            $this->assertSame('partial.notFor must be a non-empty string array', $e(['path' => 'p', 'notFor' => $v]));
        }
    }

    /** signIntentAnswer names the shape error; a principal list that is not a list restricts to nobody. */
    public function testSignAndPrincipals(): void
    {
        self::assertThrown(\InvalidArgumentException::class, 'signIntentAnswer: map_digest is not canonical base64url (32 bytes)',
            static fn() => Wallet::signIntentAnswer(new Obj(), str_repeat("\x07", 32)));
        $no = ['ok' => false, 'reason' => 'signer is not a principal of the session'];
        $this->assertSame($no, Wallet::verifyIntentAnswer(self::answer(), 'x'));
        $this->assertSame($no, Wallet::verifyIntentAnswer(self::answer(), ['p' => self::d32(4)]));
    }

    // ---- cell coordinates ---------------------------------------------------------------------------------------------------------

    private static function cat(mixed $path, array $labels = ['a']): Obj
    {
        return Obj::of(['path' => $path, 'kind' => 'cat', 'values' => array_map(static fn(string $l): Obj => Obj::of(['kind' => 'exact', 'value' => $l]), $labels)]);
    }

    private static function num(string $path, array $cuts): Obj
    {
        return Obj::of(['path' => $path, 'kind' => 'num', 'lo' => 0, 'hi' => 10, 'cuts' => $cuts]);
    }

    private static function omega(Obj ...$verbs): Obj
    {
        return Obj::of(['verbs' => $verbs]);
    }

    private static function vs(string $verb, Obj ...$dims): Obj
    {
        return Obj::of(['verb' => $verb, 'dims' => $dims]);
    }

    /** The first matching verb space is used; a float path is looked up as its text; null and non-list coordinates are refused. */
    public function testResolveCoords(): void
    {
        $a = self::vs('v', self::cat('x'));
        $r = Wallet::resolveCoords(self::omega($a, self::vs('v', self::cat('y'))), 'v', Obj::of(['x' => ['a']]));
        $this->assertTrue($r['ok']);
        $this->assertSame($a, $r['vs']);
        $this->assertSame([[0]], $r['box']);
        $fl = self::omega(self::vs('v', self::cat(1.5)));
        $this->assertSame(['ok' => false, 'reason' => 'unknown dimension 1'], Wallet::resolveCoords($fl, 'v', Obj::of(['1' => ['a']])));
        $r = Wallet::resolveCoords($fl, 'v', Obj::of(['1.5' => ['a']]));
        $this->assertTrue($r['ok']);
        $this->assertSame([[0]], $r['box']);
        $one = self::omega(self::vs('v', self::cat('x')));
        self::assertThrown(\TypeError::class, 'Cannot read properties of null', static fn() => Wallet::resolveCoords($one, 'v', Obj::of(['x' => null])));
        self::assertThrown(\TypeError::class, 'c.every is not a function', static fn() => Wallet::resolveCoords($one, 'v', Obj::of(['x' => 'a'])));
        $two = self::omega(self::vs('v', self::cat('x', ['a', 'a'])));
        $this->assertSame(['ok' => false, 'reason' => 'value "a" names two cells of x'], Wallet::resolveCoords($two, 'v', Obj::of(['x' => ['a']])));
    }

    /** A numeric side of a box must be contiguous. */
    public function testCoordsOfBox(): void
    {
        self::assertThrown(\InvalidArgumentException::class, 'coordsOfBox: numeric side of n is not contiguous', static fn() => Wallet::coordsOfBox(self::vs('v', self::num('n', [])), [[0, 2]]));
    }

    /** cellOfAction refuses a non-object action or values, uses the first matching verb space, and reads a numeric path as its text. */
    public function testCellOfAction(): void
    {
        $a = self::vs('v', self::cat('x'));
        $om = self::omega($a, self::vs('v', self::cat('y')));
        self::assertThrown(\TypeError::class, 'action is not an object', static fn() => Wallet::cellOfAction($om, 'x'));
        $this->assertSame(['vs' => $a, 'idx' => [0]], Wallet::cellOfAction($om, Obj::of(['verb' => 'v', 'values' => Obj::of(['x' => 'a'])])));
        self::assertThrown(\TypeError::class, "Cannot use 'in' operator", static fn() => Wallet::cellOfAction($om, Obj::of(['verb' => 'v', 'values' => 'x'])));
        $this->assertNull(Wallet::cellOfAction(self::omega(self::vs('v', self::cat(5))), Obj::of(['verb' => 'v', 'values' => Obj::of(['x' => 1])])));
    }

    // ---- canaries ----------------------------------------------------------------------------------------------------------------

    /** cellKey prints an integral index as integer digits, any other value as its JavaScript text. */
    public function testCellKey(): void
    {
        $this->assertSame('v|1000000000000000,1.5,a', Wallet::cellKey('v', [1e15, 1.5, 'a']));
    }

    /** Omega with a 2-cell numeric dimension and a 1-value categorical one (and, when `$dup`, a second space of the same verb with 3 cells). */
    private static function canaryOmega(bool $dup = false): Obj
    {
        $vs = [self::vs('v', self::num('n', [0]), self::cat('c'))];
        if ($dup) {
            $vs[] = self::vs('v', self::num('n', [0, 1]), self::cat('c'));
        }
        return self::omega(...$vs);
    }

    /** Neighbours stay inside the dimension, are integer indices, skip unknown verbs without stopping, and use the first verb space. */
    public function testBoundaryNeighbours(): void
    {
        $want = [['verb' => 'v', 'idx' => [0, 0]]];
        $c = Obj::of(['verb' => 'v', 'idx' => [new Num('1'), new Num('0')]]);
        $this->assertSame($want, Wallet::boundaryNeighbours(self::canaryOmega(), [$c]));
        $this->assertSame($want, Wallet::boundaryNeighbours(self::canaryOmega(true), [Obj::of(['verb' => 'zz', 'idx' => [0]]), $c]));
    }

    /** A scripted random source. */
    private static function rand(array $seq): \Closure
    {
        return static function () use (&$seq): float {
            return array_shift($seq);
        };
    }

    private static function ctx(array $over): array
    {
        return $over + ['omega' => self::canaryOmega(), 'confirmed' => [], 'knownNo' => static fn() => null, 'knownYes' => [], 'exclude' => []];
    }

    /** rho must be in [0, 1]; a draw equal to rho inserts nothing; exclude keys are compared as text; known-yes cells become integer indices. */
    public function testPickCanaryDraws(): void
    {
        self::assertThrown(\InvalidArgumentException::class, 'pickCanary: rho must be in [0, 1]', static fn() => Wallet::pickCanary(self::ctx(['rho' => 2, 'rand' => self::rand([0.0])])));
        $yes = [Obj::of(['verb' => 'v', 'idx' => [new Num('0'), new Num('0')]])];
        $this->assertNull(Wallet::pickCanary(self::ctx(['rho' => 0.5, 'rand' => self::rand([0.5, 0.0]), 'knownYes' => $yes])));
        $want = ['verb' => 'v', 'idx' => [0, 0], 'expected' => 1, 'source' => 'confirmed-yes'];
        $this->assertSame($want, Wallet::pickCanary(self::ctx(['rand' => self::rand([0.0, 0.0]), 'knownYes' => $yes, 'exclude' => [1.5]])));
    }

    /** With both pools a draw of exactly 0.5 picks the yes pool; the index is clamped to the pool and an infinite draw reads as 0. */
    public function testPickCanaryPools(): void
    {
        $conf = [Obj::of(['verb' => 'v', 'idx' => [1, 0]])];
        $yesB = ['verb' => 'v', 'idx' => [1, 0], 'expected' => 1, 'source' => 'confirmed-yes'];
        $this->assertSame($yesB, Wallet::pickCanary(self::ctx(['confirmed' => $conf, 'knownNo' => static fn() => 'veto', 'knownYes' => $conf, 'rand' => self::rand([0.0, 0.5, 0.0])])));
        $two = [Obj::of(['verb' => 'v', 'idx' => [0, 0]]), Obj::of(['verb' => 'v', 'idx' => [1, 0]])];
        $yesA = ['verb' => 'v', 'idx' => [0, 0], 'expected' => 1, 'source' => 'confirmed-yes'];
        $this->assertSame($yesA, Wallet::pickCanary(self::ctx(['knownYes' => $two, 'rand' => self::rand([0.0, INF])])));
        $this->assertSame($yesB, Wallet::pickCanary(self::ctx(['knownYes' => $two, 'rand' => self::rand([0.0, 1.0])])));
    }

    // ---- statistics ---------------------------------------------------------------------------------------------------------------

    /** The continued fraction stops once a step changes it by under 1e-15, and otherwise runs exactly 300 steps (exact IEEE arithmetic). */
    public function testBetacf(): void
    {
        $this->assertSame(1.8804664723032063, Wallet::betacf(2.0, 3.0, 0.3));
        $this->assertSame(1772.455419979301, Wallet::betacf(1e6, 1e6, 0.5));
        self::assertThrown(\TypeError::class, 'a number is required', static fn() => Wallet::lnGamma('x'));
    }

    /** I_x(a, b) below the mean-based switch point (a+1)/(a+b+2) is the direct fraction, at or above it the reflected one. */
    public function testBetaIncBranch(): void
    {
        $a = 1e5;
        $b = 1e5;
        foreach ([[0.499999, true], [0.500001, false], [0.5, false]] as [$x, $direct]) {
            $bt = exp(Wallet::lnGamma($a + $b) - Wallet::lnGamma($a) - Wallet::lnGamma($b) + $a * log($x) + $b * log(1 - $x));
            $want = $direct ? ($bt * Wallet::betacf($a, $b, $x)) / $a : 1 - ($bt * Wallet::betacf($b, $a, 1 - $x)) / $b;
            $this->assertSame($want, Wallet::betaInc($x, $a, $b), "x = $x");
        }
    }

    /** betaInc refuses a or b of 0, and returns the exact ends at x = 0 and x = 1 even where the formula overflows. */
    public function testBetaIncEdges(): void
    {
        foreach ([[0, 1], [1, 0]] as [$a, $b]) {
            self::assertThrown(\InvalidArgumentException::class, 'betaInc: a and b must be > 0', static fn() => Wallet::betaInc(0.5, $a, $b));
        }
        $this->assertSame(0.0, Wallet::betaInc(0, 1e308, 1e308));
        $this->assertSame(1.0, Wallet::betaInc(1, 1e308, 1e308));
    }

    /** betaQuantile returns 1 at q = 1, bisects exactly 200 times, and moves down when the CDF equals q. */
    public function testBetaQuantile(): void
    {
        $this->assertSame(1.0, Wallet::betaQuantile(1, 1, 100));
        $e = 1.0;
        for ($i = 0; $i < 200; $i++) {
            $e /= 2;
        }
        $this->assertSame($e, Wallet::betaQuantile(1e-300, 1, 1));
        $q = Wallet::betaInc(0.5, 2.0, 3.0);
        $this->assertLessThanOrEqual(0.5, Wallet::betaQuantile($q, 2.0, 3.0));
    }

    /** deltaC must be strictly inside (0, 1); with no known answers the Clopper-Pearson bounds are the integer 1. */
    public function testEstimateNoise(): void
    {
        foreach ([0, 1, 2] as $dc) {
            self::assertThrown(\InvalidArgumentException::class, 'estimateNoise: deltaC must be in (0, 1)', static fn() => Wallet::estimateNoise(Wallet::EMPTY_NOISE, $dc));
        }
        $e = Wallet::estimateNoise(Wallet::EMPTY_NOISE);
        $this->assertSame(1, $e['etaPosCP']);
        $this->assertSame(1, $e['etaNegCP']);
    }

    /** etaUnderLoad needs both numbers; freezing needs the statistic strictly above etaStop; admission refuses delta 1 and needs eta+ > 0 to double-confirm. */
    public function testFatigue(): void
    {
        self::assertThrown(\InvalidArgumentException::class, 'etaUnderLoad: bad arguments', static fn() => Wallet::etaUnderLoad(null, 0.1, 0));
        $s = Wallet::noiseState(Wallet::EMPTY_NOISE, 0, ['deltaC' => 0.05, 'betaF' => 0, 'freezeOn' => 'mean', 'etaStop' => 0.1]);
        $this->assertSame(0.1, $s['etaPos']);
        $this->assertFalse($s['frozen']);
        self::assertThrown(\InvalidArgumentException::class, 'admissionPolicy: delta must be in (0, 1)',
            static fn() => Wallet::admissionPolicy(['etaPosBar' => 0, 'etaNegBar' => 0], ['assumeNoiseFree' => false, 'delta' => 1]));
        $this->assertFalse(Wallet::admissionPolicy(['etaPosBar' => 0, 'etaNegBar' => 0], ['assumeNoiseFree' => false, 'delta' => 0.05])['doubleConfirmIrreversible']);
    }
}
