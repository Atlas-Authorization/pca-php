<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Vdf;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for the Wesolowski VDF and the PCA timelock with small, fast parameters: the verifier's refusal order and reasons,
 * proofs that verify (300 squarings mod a 60-bit N), the strong Lucas Jacobi walk, the challenge-prime width, the dev modulus maker
 * driven by a deterministic byte source, the timelock input, refusal texts and calibrateSteps under an injected clock.
 */
final class ProtoSurvivorKill17VdfTest extends TestCase
{
    private const RSA_2048 = '25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357';

    private static function n(): \GMP
    {
        return gmp_mul(gmp_init(1000000007), gmp_init(998244353));
    }

    private static function refusal(callable $f): string
    {
        try {
            $f();
        } catch (\InvalidArgumentException | \RuntimeException $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'accepted';
    }

    /** @return array{0:\Closure,1:\ArrayObject} a byte source sha256("k17-<call index>") truncated to the request, and its request log */
    private static function source(): array
    {
        $log = new \ArrayObject();
        $rnd = static function (int $n) use ($log): string {
            $i = count($log);
            $log[] = $n;
            return substr(hash('sha256', "k17-$i", true), 0, $n);
        };
        return [$rnd, $log];
    }

    /** The RSA-2048 challenge number, read in base 10. */
    public function testRsa2048ChallengeModulus(): void
    {
        $n = Vdf::rsa2048ChallengeModulus();
        $this->assertSame(self::RSA_2048, gmp_strval($n));
        $this->assertSame(2048, strlen(gmp_strval($n, 2)));
    }

    /** Steps may be an integral float up to 2^53-1 inclusive; a numeric string or a fraction is bad-steps. */
    public function testVerifierStepsReading(): void
    {
        $x = gmp_init(2);
        $y = gmp_init(0); // not a unit: an accepted step count stops at the y check
        $pi = gmp_init(1);
        $n = gmp_init(15);
        $nonUnitY = ['ok' => false, 'reason' => 'non-canonical-y'];
        $this->assertSame($nonUnitY, Vdf::vdfVerifyDetailed($x, $y, $pi, 9007199254740991.0, $n));
        $this->assertSame($nonUnitY, Vdf::vdfVerifyDetailed($x, $y, $pi, 5.0, $n));
        $this->assertSame($nonUnitY, Vdf::vdfVerifyDetailed($x, $y, $pi, new Num('5'), $n));
        $this->assertSame(['ok' => false, 'reason' => 'bad-steps'], Vdf::vdfVerifyDetailed($x, $y, $pi, '5', $n));
        $this->assertSame(['ok' => false, 'reason' => 'bad-steps'], Vdf::vdfVerifyDetailed($x, $y, $pi, 5.5, $n));
    }

    /** Each of x, y, pi and N must be a bigint: that is checked first (malformed-input), before the steps. */
    public function testVerifierRefusesNonBigintsFirst(): void
    {
        $g = gmp_init(7);
        $n = gmp_init(15);
        $malformed = ['ok' => false, 'reason' => 'malformed-input'];
        $this->assertSame(['ok' => false, 'reason' => 'bad-steps'], Vdf::vdfVerifyDetailed($g, $g, $g, -1, $n));
        $this->assertSame($malformed, Vdf::vdfVerifyDetailed(7, $g, $g, -1, $n));
        $this->assertSame($malformed, Vdf::vdfVerifyDetailed($g, 7, $g, -1, $n));
        $this->assertSame($malformed, Vdf::vdfVerifyDetailed($g, $g, 7, -1, $n));
        $this->assertSame($malformed, Vdf::vdfVerifyDetailed($g, $g, $g, -1, 15));
        $this->assertSame($malformed, Vdf::vdfVerifyCanonicalDetailed($g, $g, $g, -1, 15));
    }

    /** Eval proofs verify (plain and canonical), and a perturbed proof does not: T = 300 > 256 makes the proof non-trivial. */
    public function testEvalProofsVerify(): void
    {
        $n = self::n();
        $x = gmp_init(5);
        $e = Vdf::vdfEval($x, 300, $n);
        $this->assertTrue(Vdf::vdfVerify($x, $e['y'], $e['pi'], 300, $n));
        $this->assertFalse(Vdf::vdfVerify($x, $e['y'], gmp_mod(gmp_add($e['pi'], 1), $n), 300, $n));
        $this->assertSame(gmp_strval(Vdf::sequentialSquare($x, 300, $n)), gmp_strval($e['y']));
        $c = Vdf::vdfEvalCanonical($x, 300, $n);
        $this->assertTrue(Vdf::vdfVerifyCanonical($x, $c['y'], $c['pi'], 300, $n));
        $this->assertSame(gmp_strval(Vdf::canonicalVdfOutput($e['y'], $n)), gmp_strval($c['y']));
    }

    /** N = 3 is refused by both evaluators with the modulus reason (not the input reason). */
    public function testEvalRefusesModulusThree(): void
    {
        $msg = 'InvalidArgumentException: VDF: modulus N must be odd and > 3';
        $this->assertSame($msg, self::refusal(static fn() => Vdf::vdfEval(gmp_init(2), 1, gmp_init(3))));
        $this->assertSame($msg, self::refusal(static fn() => Vdf::vdfEvalCanonical(gmp_init(2), 1, gmp_init(3))));
        $this->assertSame('InvalidArgumentException: VDF: steps T must be a non-negative safe integer, got -1',
            self::refusal(static fn() => Vdf::vdfEval(gmp_init(2), -1, gmp_init(15))));
    }

    /** modpow: a non-positive modulus and a negative exponent are refused; modulus 1 is 0 (even for a negative exponent). */
    public function testModpow(): void
    {
        $this->assertSame('InvalidArgumentException: modpow: modulus must be positive', self::refusal(static fn() => Vdf::modpow(gmp_init(2), gmp_init(3), gmp_init(0))));
        $this->assertSame('InvalidArgumentException: modpow: modulus must be positive', self::refusal(static fn() => Vdf::modpow(gmp_init(2), gmp_init(3), gmp_init(-5))));
        $this->assertSame('0', gmp_strval(Vdf::modpow(gmp_init(3), gmp_init(-1), gmp_init(1))));
        $this->assertSame('1', gmp_strval(Vdf::modpow(gmp_init(3), gmp_init(1), gmp_init(2))));
        $this->assertSame('4', gmp_strval(Vdf::modpow(gmp_init(3), gmp_init(4), gmp_init(7))));
        $this->assertSame('InvalidArgumentException: modpow: negative exponent (no inverse in a group of unknown order)',
            self::refusal(static fn() => Vdf::modpow(gmp_init(2), gmp_init(-1), gmp_init(7))));
    }

    /** A D that shares a factor with n ends the strong Lucas test: 22786799 = 7*137*23761 would pass with the later D = -11. */
    public function testStrongLucasStopsOnASharedFactor(): void
    {
        $this->assertFalse(Vdf::isStrongLucasProbablePrime(gmp_init(22786799)));
        $this->assertTrue(Vdf::isStrongLucasProbablePrime(gmp_init(5459))); // a strong Lucas pseudoprime: the test itself runs
        $this->assertTrue(Vdf::isStrongLucasProbablePrime(gmp_init(1000003)));
    }

    /** A 9-bit challenge prime takes two hash bytes (ceil(9/8)); value from an independent port of the transcript. */
    public function testHashToPrimeOddWidth(): void
    {
        $this->assertSame('271', gmp_strval(Vdf::hashToPrime(gmp_init(5), gmp_init(7), 3, gmp_init(1000003), 9)));
    }

    /** randomPrime refuses fewer than 16 bits. */
    public function testRandomPrimeFloor(): void
    {
        $m = new \ReflectionMethod(Vdf::class, 'randomPrime');
        $this->assertSame('InvalidArgumentException: randomPrime: bits too small',
            self::refusal(static fn() => $m->invoke(null, 15, static fn(int $n): string => str_repeat("\xff", $n))));
    }

    /** insecureDevSetup(33): a 16-bit and a 17-bit prime from the caller's byte source (2- and 3-byte draws), registered as dev. */
    public function testDevSetupFromTheCallersSource(): void
    {
        [$rnd, $log] = self::source();
        $d = Vdf::insecureDevSetup(33, $rnd);
        $this->assertSame(['insecureDevOnly', 'N', 'p', 'q', 'bits'], array_keys($d));
        $this->assertTrue($d['insecureDevOnly']);
        $this->assertSame('35281', gmp_strval($d['p']));
        $this->assertSame('81457', gmp_strval($d['q']));
        $this->assertSame('2873884417', gmp_strval($d['N']));
        $this->assertSame(32, $d['bits']);
        $this->assertSame(array_merge([2], array_fill(0, 19, 3)), $log->getArrayCopy());
        $this->assertSame(['ok' => false, 'reason' => 'modulus came from insecureDevSetup(): its factors are known, so it provides no delay'],
            Vdf::checkProductionModulus($d['N']));
    }

    /** 32 bits is the floor (accepted), 31 is refused before any draw. */
    public function testDevSetupBitsFloor(): void
    {
        [$rnd, $log] = self::source();
        $d = Vdf::insecureDevSetup(32, $rnd);
        $this->assertSame('35281', gmp_strval($d['p']));
        $this->assertSame('38083', gmp_strval($d['q']));
        $this->assertSame([2, 2, 2], $log->getArrayCopy());
        [$rnd2, $log2] = self::source();
        $this->assertSame('InvalidArgumentException: insecureDevSetup: bits must be a safe integer >= 32', self::refusal(static fn() => Vdf::insecureDevSetup(31, $rnd2)));
        $this->assertSame([], $log2->getArrayCopy());
    }

    /** A source that repeats one prime gets 8 redraws for q and then a refusal; one repeat is redrawn once. */
    public function testDevSetupSamePrime(): void
    {
        $calls = 0;
        $same = static function (int $n) use (&$calls): string {
            $calls++;
            return "\x80\x03"; // 32771, prime
        };
        $this->assertSame('RuntimeException: insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)',
            self::refusal(static fn() => Vdf::insecureDevSetup(32, $same)));
        $this->assertSame(10, $calls);
        $seq = ["\x80\x03", "\x80\x03", "\x80\x0b"]; // 32771, 32771, 32779
        $k = 0;
        $once = static function (int $n) use (&$k, $seq): string {
            return $seq[$k++];
        };
        $d = Vdf::insecureDevSetup(32, $once);
        $this->assertSame('32771', gmp_strval($d['p']));
        $this->assertSame('32779', gmp_strval($d['q']));
        $this->assertSame((string)(32771 * 32779), gmp_strval($d['N']));
        $this->assertSame(31, $d['bits']);
        $this->assertSame(3, $k);
    }

    /** A source that never yields a prime is given up on after exactly 50000 draws. */
    public function testRandomPrimeGivesUp(): void
    {
        $calls = 0;
        $stuck = static function (int $n) use (&$calls): string {
            $calls++;
            return "\x00\x00"; // 0x8001 = 32769 = 3 * 10923
        };
        $this->assertSame('RuntimeException: insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)',
            self::refusal(static fn() => Vdf::insecureDevSetup(32, $stuck)));
        $this->assertSame(50000, $calls);
    }

    /** The production screen: a non-bigint is named as such. */
    public function testProductionScreenNonBigint(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'modulus is not a bigint'], Vdf::checkProductionModulus(5));
    }

    /** x = H(action, beacon) mod N lifted out of {0, 1} by +2; a Bytes beacon is its raw bytes; N must be a bigint > 3. */
    public function testTimelockInput(): void
    {
        $five = gmp_init(5);
        // residues mod 5 from an independent port: b0 -> 4, b1 -> 0, b2 -> 2, b3 -> 1
        $this->assertSame('4', gmp_strval(Vdf::deriveTimelockInput('act', $five, 'b0')));
        $this->assertSame('2', gmp_strval(Vdf::deriveTimelockInput('act', $five, 'b1')));
        $this->assertSame('2', gmp_strval(Vdf::deriveTimelockInput('act', $five, 'b2')));
        $this->assertSame('3', gmp_strval(Vdf::deriveTimelockInput('act', $five, 'b3')));
        $this->assertSame('3', gmp_strval(Vdf::deriveTimelockInput('act', $five, new Bytes('b3'))));
        $this->assertSame('act', Vdf::actionDigest('act'));
        $this->assertSame('InvalidArgumentException: deriveTimelockInput: modulus N must be a bigint > 3', self::refusal(static fn() => Vdf::deriveTimelockInput('act', 5, 'b0')));
    }

    /** The timelock refusal texts: the screen's reason inside the fixed advice, and the shown step value for each JS type. */
    public function testTimelockRefusalTexts(): void
    {
        $this->assertSame('InvalidArgumentException: timelock: refusing this modulus: modulus is below 2048 bits. Use RSA_2048_CHALLENGE_MODULUS or a '
            . 'ceremony modulus; tests may pass allowInsecureDevModulus: true.', self::refusal(static fn() => Vdf::requireTimelock('a', 1, gmp_init(5), 'b')));
        $cases = [[0, '0'], [true, 'true'], [false, 'false'], [null, 'null'], [[], 'object'], ['abc', 'abc'], [new Num('1.5'), '1.5'], [2.5, '2.5']];
        foreach ($cases as [$steps, $shown]) {
            $this->assertSame('InvalidArgumentException: timelock: steps must be a safe integer >= 1, got ' . $shown,
                self::refusal(static fn() => Vdf::requireTimelock('a', $steps, gmp_init(5), 'b')), $shown);
        }
    }

    /** A timelock proof verifies as an assoc array and as an Obj; a list is not a proof. */
    public function testVerifyTimelockProofShapes(): void
    {
        $n = self::n();
        $proof = Vdf::proveTimelockElapsed('act', 3, $n, 'beacon', true);
        $this->assertTrue(Vdf::verifyTimelock('act', $proof, 3, $n, 'beacon', true));
        $this->assertTrue(Vdf::verifyTimelock('act', Obj::of($proof), 3, $n, 'beacon', true));
        $this->assertFalse(Vdf::verifyTimelock('act', array_values($proof), 3, $n, 'beacon', true));
        $this->assertFalse(Vdf::verifyTimelock('act', $proof, 4, $n, 'beacon', true));
    }

    /** calibrateSteps with an injected clock: the default 50000-squaring sample, the rates and steps = ceil(adversary rate x seconds). */
    public function testCalibrateWithAnInjectedClock(): void
    {
        $n = gmp_init(1000003);
        $ticks = [1000.0, 3000.0];
        $calls = 0;
        $clock = static function () use (&$calls, $ticks): float {
            return $ticks[$calls++];
        };
        $this->assertSame(['steps' => 250000, 'measuredSquaringsPerSecond' => 25000.0, 'assumedAdversarySquaringsPerSecond' => 250000.0],
            Vdf::calibrateSteps($n, 1.0, now: $clock));
        $this->assertSame(2, $calls);

        $t2 = [0.0, 1024.0];
        $c2 = 0;
        $clock2 = static function () use (&$c2, $t2): float {
            return $t2[$c2++];
        };
        // 1 / 1024 ms * 1000 = 0.9765625 /s; x 4 = 3.90625; x 0.5625 s = 2.197265625 -> 3 steps
        $this->assertSame(['steps' => 3, 'measuredSquaringsPerSecond' => 0.9765625, 'assumedAdversarySquaringsPerSecond' => 3.90625],
            Vdf::calibrateSteps($n, 0.5625, 1, 4.0, $clock2));

        $t3 = [0.0, 1.0e9];
        $c3 = 0;
        $clock3 = static function () use (&$c3, $t3): float {
            return $t3[$c3++];
        };
        // an advantage of exactly 1 is allowed; a product that underflows to 0 still asks for one step
        $this->assertSame(1, Vdf::calibrateSteps($n, 5e-324, 1, 1.0, $clock3)['steps']);
    }

    /** calibrateSteps refuses N <= 3, a non-positive or non-finite duration, no samples and an advantage below 1 or non-finite. */
    public function testCalibrateRefusals(): void
    {
        $n = gmp_init(1000003);
        $clock = static fn(): float => 0.0;
        $e = 'InvalidArgumentException: calibrateSteps: ';
        $this->assertSame($e . 'modulus N must be a bigint > 3', self::refusal(static fn() => Vdf::calibrateSteps(gmp_init(3), 1.0, 1, 10.0, $clock)));
        foreach ([0.0, -1.0, INF, NAN] as $s) {
            $this->assertSame($e . 'desiredSeconds must be > 0', self::refusal(static fn() => Vdf::calibrateSteps($n, $s, 1, 10.0, $clock)));
        }
        $this->assertSame($e . 'sampleSquarings must be a safe integer >= 1', self::refusal(static fn() => Vdf::calibrateSteps($n, 1.0, 0, 10.0, $clock)));
        foreach ([0.5, INF, NAN] as $a) {
            $this->assertSame($e . 'adversaryAdvantage must be >= 1', self::refusal(static fn() => Vdf::calibrateSteps($n, 1.0, 1, $a, $clock)));
        }
    }

    /** The default clock is milliseconds: 1000 squarings of a 20-bit N run far faster than 10 per second (fails only past the test deadline). */
    public function testCalibrateDefaultClockIsMilliseconds(): void
    {
        $r = Vdf::calibrateSteps(gmp_init(1000003), 1.0, 1000);
        $this->assertGreaterThan(10.0, $r['measuredSquaringsPerSecond']);
    }
}
