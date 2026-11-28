<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';

/**
 * Wesolowski VDF over an RSA group plus the PCA timelock, on ext-gmp (a vetted big-integer library; no hand-rolled arithmetic).
 * Same domains, transcript, error texts and check order as the TypeScript reference, so challenge primes, proofs and timelock inputs
 * are byte-identical. Big integers are \GMP values; a step count / bit count is a PHP int, float or Num (a JS number). A VDF in an RSA
 * group needs a modulus of unknown factorisation (see RSA_2048_CHALLENGE_MODULUS / checkProductionModulus); insecureDevSetup is for tests.
 */
final class Vdf
{
    public const CHALLENGE_PRIME_BITS = 256;
    public const INSECURE_DEV_SETUP_DEFAULT_BITS = 2048;
    public const MIN_PRODUCTION_MODULUS_BITS = 2048;
    private const RSA_2048 = '25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357';
    private const SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];
    private const HASH_TO_PRIME_DOMAIN = "atlas-pca/vdf/wesolowski/hash-to-prime/v1\x00";
    private const X_DERIVATION_DOMAIN = "atlas-pca/vdf/timelock/input/v2\x00";
    private const MAX_SAFE = 9007199254740991;

    /** @var array<string,true> decimal strings of the moduli insecureDevSetup made */
    private static array $devModuli = [];
    /** @var array<string,true> */
    private static array $screenPassed = [];

    public static function rsa2048ChallengeModulus(): \GMP
    {
        return gmp_init(self::RSA_2048, 10);
    }

    // ---- small helpers -------------------------------------------------------------------------------------------------------

    /** The value as a JS-safe integer when it is one (a float with an integral value counts, as in JS), else null. */
    private static function safeInt(mixed $v): ?int
    {
        if ($v instanceof Num) {
            $v = $v->isInt() ? $v->int() : $v->float();
        }
        if (is_int($v)) {
            return abs($v) <= self::MAX_SAFE ? $v : null;
        }
        if (is_float($v) && is_finite($v) && abs($v) <= self::MAX_SAFE && $v == floor($v)) {
            return (int)$v;
        }
        return null;
    }

    /** JS BigInt `%`: the sign follows the dividend; a zero divisor throws. */
    private static function rem(\GMP $a, \GMP $n): \GMP
    {
        return gmp_div_r($a, $n, GMP_ROUND_ZERO);
    }

    private static function umod(\GMP $x, \GMP $n): \GMP
    {
        return self::rem(self::rem($x, $n) + $n, $n);
    }

    public static function bytesToBigInt(string $b): \GMP
    {
        return $b === '' ? gmp_init(0) : gmp_import($b);
    }

    public static function bigIntToBytes(\GMP|int $v): string
    {
        $v = $v instanceof \GMP ? $v : gmp_init($v);
        if ($v < 0) {
            throw new \InvalidArgumentException('bigIntToBytes: negative value');
        }
        return $v == 0 ? "\x00" : gmp_export($v);
    }

    private static function u32(int $n): string
    {
        return pack('N', $n & 0xFFFFFFFF);
    }

    private static function lp(string $b): string
    {
        return self::u32(strlen($b)) . $b;
    }

    private static function normalizeSteps(mixed $t): int
    {
        $s = self::safeInt($t);
        if ($s === null || $s < 0) {
            throw new \InvalidArgumentException('VDF: steps T must be a non-negative safe integer, got ' . self::show($t));
        }
        return $s;
    }

    private static function show(mixed $v): string
    {
        return $v instanceof Num ? $v->lexeme : (is_scalar($v) ? (is_bool($v) ? ($v ? 'true' : 'false') : (string)$v) : ($v === null ? 'null' : 'object'));
    }

    public static function gcd(\GMP $a, \GMP $b): \GMP
    {
        return gmp_gcd($a, $b);
    }

    private static function isUnit(\GMP $v, \GMP $n): bool
    {
        return $v > 0 && $v < $n && gmp_gcd($v, $n) == 1;
    }

    public static function modpow(\GMP $base, \GMP $exp, \GMP $mod): \GMP
    {
        if ($mod <= 0) {
            throw new \InvalidArgumentException('modpow: modulus must be positive');
        }
        if ($mod == 1) {
            return gmp_init(0);
        }
        if ($exp < 0) {
            throw new \InvalidArgumentException('modpow: negative exponent (no inverse in a group of unknown order)');
        }
        return gmp_powm($base, $exp, $mod);
    }

    // ---- primality: Baillie-PSW (strong Miller-Rabin on the first 25 primes + strong Lucas) -----------------------------------------

    private static function isPerfectSquare(\GMP $n): bool
    {
        return $n >= 0 && gmp_perfect_square($n);
    }

    public static function isStrongLucasProbablePrime(\GMP $n): bool
    {
        if ($n < 3 || gmp_testbit($n, 0) === false || self::isPerfectSquare($n)) {
            return false;
        }
        $d = 5;
        while (true) {
            $j = gmp_jacobi($d, $n);
            if ($j === -1) {
                break;
            }
            if ($j === 0 && gmp_abs($d) != $n) {
                return false;
            }
            $d = $d > 0 ? -($d + 2) : -$d + 2;
        }
        $p = gmp_init(1);
        $q = gmp_init(intdiv(1 - $d, 4)); // exact: D = 1 (mod 4)
        $dd = gmp_init($d);
        $mod = static fn(\GMP $x): \GMP => gmp_mod($x, $n);
        $half = static fn(\GMP $x): \GMP => gmp_div_q(gmp_testbit($x, 0) ? $x + $n : $x, 2);
        $e = $n + 1;
        $s = 0;
        while (!gmp_testbit($e, 0)) {
            $e = gmp_div_q($e, 2);
            $s++;
        }
        $u = gmp_init(1);
        $v = $p;
        $qk = $mod($q);
        $bits = gmp_strval($e, 2);
        $len = strlen($bits);
        for ($i = 1; $i < $len; $i++) {
            $u = $mod($u * $v);
            $v = $mod($v * $v - 2 * $qk);
            $qk = $mod($qk * $qk);
            if ($bits[$i] === '1') {
                $u1 = $half($mod($p * $u + $v));
                $v1 = $half($mod($dd * $u + $p * $v));
                $u = $u1;
                $v = $v1;
                $qk = $mod($qk * $q);
            }
        }
        if ($u == 0 || $v == 0) {
            return true;
        }
        for ($i = 1; $i < $s; $i++) {
            $v = $mod($v * $v - 2 * $qk);
            if ($v == 0) {
                return true;
            }
            $qk = $mod($qk * $qk);
        }
        return false;
    }

    public static function isMillerRabinProbablePrime(\GMP $n): bool
    {
        if ($n < 3 || !gmp_testbit($n, 0)) {
            return false;
        }
        $d = $n - 1;
        $s = 0;
        while (!gmp_testbit($d, 0)) {
            $d = gmp_div_q($d, 2);
            $s++;
        }
        foreach (self::SMALL_PRIMES as $a) {
            $base = gmp_mod($a, $n);
            if ($base == 0) {
                continue;
            }
            $x = gmp_powm($base, $d, $n);
            if ($x == 1 || $x == $n - 1) {
                continue;
            }
            $composite = true;
            for ($i = 1; $i < $s; $i++) {
                $x = gmp_mod($x * $x, $n);
                if ($x == $n - 1) {
                    $composite = false;
                    break;
                }
            }
            if ($composite) {
                return false;
            }
        }
        return true;
    }

    public static function isProbablePrime(\GMP $n): bool
    {
        if ($n < 2) {
            return false;
        }
        foreach (self::SMALL_PRIMES as $p) {
            if ($n == $p) {
                return true;
            }
            if (gmp_mod($n, $p) == 0) {
                return false;
            }
        }
        return self::isMillerRabinProbablePrime($n) && self::isStrongLucasProbablePrime($n);
    }

    // ---- Fiat-Shamir challenge prime ------------------------------------------------------------------------------------------------

    public static function hashToPrime(\GMP $x, \GMP $y, mixed $t, \GMP $n, mixed $bits = self::CHALLENGE_PRIME_BITS): \GMP
    {
        $b = self::safeInt($bits);
        if ($b === null || $b < 8 || $b > 8192) {
            throw new \InvalidArgumentException('hashToPrime: bits must be an integer in [8, 8192]');
        }
        $steps = self::normalizeSteps($t);
        $xr = self::umod($x, $n);
        $yr = self::umod($y, $n);
        $transcript = self::HASH_TO_PRIME_DOMAIN . self::lp(self::bigIntToBytes($xr)) . self::lp(self::bigIntToBytes($yr))
            . self::lp(self::bigIntToBytes($steps)) . self::lp(self::bigIntToBytes($n)) . self::lp(self::u32($b));
        $seed = hash('sha256', $transcript, true);
        $need = intdiv($b + 7, 8);
        $top = gmp_pow(2, $b - 1);
        $mask = gmp_pow(2, $b) - 1;
        for ($counter = 0;; $counter++) {
            $chunks = '';
            for ($block = 0; strlen($chunks) < $need; $block++) {
                $chunks .= hash('sha256', $seed . pack('J', $counter) . self::u32($block), true);
            }
            $cand = gmp_or(gmp_or(gmp_and(self::bytesToBigInt(substr($chunks, 0, $need)), $mask), $top), 1);
            if (self::isProbablePrime($cand)) {
                return $cand;
            }
        }
    }

    // ---- the VDF -------------------------------------------------------------------------------------------------------------------

    public static function sequentialSquare(\GMP $x, mixed $t, \GMP $n): \GMP
    {
        if ($n <= 1) {
            throw new \InvalidArgumentException('VDF: modulus N must be > 1');
        }
        $steps = self::normalizeSteps($t);
        $y = self::umod($x, $n);
        for ($i = 0; $i < $steps; $i++) {
            $y = gmp_mod($y * $y, $n);
        }
        return $y;
    }

    private static function wesolowskiProof(\GMP $x, int $t, \GMP $l, \GMP $n): \GMP
    {
        $xr = self::umod($x, $n);
        $pi = gmp_mod(1, $n);
        $r = gmp_mod(1, $l);
        for ($i = 0; $i < $t; $i++) {
            $twoR = $r * 2;
            $b = gmp_div_q($twoR, $l);
            $r = gmp_mod($twoR, $l);
            $pi = gmp_mod($pi * $pi, $n);
            if ($b == 1) {
                $pi = gmp_mod($pi * $xr, $n);
            }
        }
        return $pi;
    }

    private static function checkEvalInput(\GMP $x, \GMP $n): void
    {
        $xr = self::umod($x, $n);
        if (!self::isUnit($xr, $n) || $xr == 1 || $xr == $n - 1) {
            throw new \InvalidArgumentException('VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)');
        }
    }

    /** @return array{y:\GMP,pi:\GMP} */
    public static function vdfEval(\GMP $x, mixed $t, \GMP $n): array
    {
        if ($n <= 3 || !gmp_testbit($n, 0)) {
            throw new \InvalidArgumentException('VDF: modulus N must be odd and > 3');
        }
        $steps = self::normalizeSteps($t);
        self::checkEvalInput($x, $n);
        $y = self::sequentialSquare($x, $t, $n);
        $l = self::hashToPrime($x, $y, $t, $n);
        return ['y' => $y, 'pi' => self::wesolowskiProof($x, $steps, $l, $n)];
    }

    /** @return array{ok:bool,reason?:string} */
    private static function verdict(bool $ok, string $reason = ''): array
    {
        return $ok ? ['ok' => true] : ['ok' => false, 'reason' => $reason];
    }

    private static function verify(mixed $x, mixed $y, mixed $pi, mixed $t, mixed $n, bool $canonical): array
    {
        try {
            if (!($x instanceof \GMP && $y instanceof \GMP && $pi instanceof \GMP && $n instanceof \GMP)) {
                return self::verdict(false, 'malformed-input');
            }
            if ($n <= 3 || !gmp_testbit($n, 0)) {
                return self::verdict(false, 'bad-modulus');
            }
            $steps = self::safeInt($t);
            if ($steps === null || $steps < 0) {
                return self::verdict(false, 'bad-steps');
            }
            if (!self::isUnit($y, $n) || ($canonical && $y > $n - $y)) {
                return self::verdict(false, 'non-canonical-y');
            }
            if (!self::isUnit($pi, $n) || ($canonical && $pi > $n - $pi)) {
                return self::verdict(false, 'non-canonical-pi');
            }
            $xr = self::umod($x, $n);
            if (!self::isUnit($xr, $n) || $xr == 1 || $xr == $n - 1) {
                return self::verdict(false, 'bad-input-x');
            }
            $l = self::hashToPrime($x, $y, $steps, $n);
            $r = self::modpow(gmp_init(2), gmp_init($steps), $l);
            $lhs = gmp_mod(self::modpow($pi, $l, $n) * self::modpow($xr, $r, $n), $n);
            $good = $canonical ? ($lhs == $y || $lhs == $n - $y) : $lhs == $y;
            return self::verdict($good, 'equation-mismatch');
        } catch (\Throwable) { // fail closed, like the reference catch
            return self::verdict(false, 'malformed-input');
        }
    }

    public static function vdfVerifyDetailed(mixed $x, mixed $y, mixed $pi, mixed $t, mixed $n): array
    {
        return self::verify($x, $y, $pi, $t, $n, false);
    }

    public static function canonicalVdfOutput(\GMP $y, \GMP $n): \GMP
    {
        return $y > $n - $y ? $n - $y : $y;
    }

    /** @return array{y:\GMP,pi:\GMP} */
    public static function vdfEvalCanonical(\GMP $x, mixed $t, \GMP $n): array
    {
        if ($n <= 3 || !gmp_testbit($n, 0)) {
            throw new \InvalidArgumentException('VDF: modulus N must be odd and > 3');
        }
        $steps = self::normalizeSteps($t);
        self::checkEvalInput($x, $n);
        $y = self::canonicalVdfOutput(self::sequentialSquare($x, $t, $n), $n);
        $l = self::hashToPrime($x, $y, $t, $n);
        return ['y' => $y, 'pi' => self::canonicalVdfOutput(self::wesolowskiProof($x, $steps, $l, $n), $n)];
    }

    public static function vdfVerifyCanonicalDetailed(mixed $x, mixed $y, mixed $pi, mixed $t, mixed $n): array
    {
        return self::verify($x, $y, $pi, $t, $n, true);
    }

    public static function vdfVerifyCanonical(mixed $x, mixed $y, mixed $pi, mixed $t, mixed $n): bool
    {
        return self::vdfVerifyCanonicalDetailed($x, $y, $pi, $t, $n)['ok'];
    }

    public static function vdfVerify(mixed $x, mixed $y, mixed $pi, mixed $t, mixed $n): bool
    {
        return self::vdfVerifyDetailed($x, $y, $pi, $t, $n)['ok'];
    }

    // ---- modulus screening (an RSA-group VDF is only as good as the modulus's unknown factorisation) --------------------------------

    private static function randomPrime(int $bits, \Closure $rnd): \GMP
    {
        if ($bits < 16) {
            throw new \InvalidArgumentException('randomPrime: bits too small');
        }
        $nbytes = intdiv($bits + 7, 8);
        $top = gmp_pow(2, $bits - 1);
        $mask = gmp_pow(2, $bits) - 1;
        for ($i = 0; $i < 50000; $i++) {
            $cand = gmp_or(gmp_or(gmp_and(self::bytesToBigInt($rnd($nbytes)), $mask), $top), 1);
            if (self::isProbablePrime($cand)) {
                return $cand;
            }
        }
        throw new \RuntimeException('insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)');
    }

    /** TEST ONLY: a modulus whose factors the caller knows (so it delays nobody). Registered so the production screen refuses it. */
    public static function insecureDevSetup(?int $bits = null, ?\Closure $randomBytes = null): array
    {
        $bits ??= self::INSECURE_DEV_SETUP_DEFAULT_BITS;
        if ($bits < 32) {
            throw new \InvalidArgumentException('insecureDevSetup: bits must be a safe integer >= 32');
        }
        $rnd = $randomBytes ?? static fn(int $n): string => random_bytes($n);
        $half = intdiv($bits, 2);
        $p = self::randomPrime($half, $rnd);
        $q = self::randomPrime($bits - $half, $rnd);
        for ($i = 0; $p == $q; $i++) {
            if ($i >= 8) {
                throw new \RuntimeException('insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)');
            }
            $q = self::randomPrime($bits - $half, $rnd);
        }
        $n = $p * $q;
        self::$devModuli[gmp_strval($n)] = true;
        return ['insecureDevOnly' => true, 'N' => $n, 'p' => $p, 'q' => $q, 'bits' => strlen(gmp_strval($n, 2))];
    }

    /** @return array{ok:bool,reason?:string} */
    public static function checkProductionModulus(mixed $n): array
    {
        if (!($n instanceof \GMP)) {
            return ['ok' => false, 'reason' => 'modulus is not a bigint'];
        }
        $key = gmp_strval($n);
        if (isset(self::$devModuli[$key])) {
            return ['ok' => false, 'reason' => 'modulus came from insecureDevSetup(): its factors are known, so it provides no delay'];
        }
        if (isset(self::$screenPassed[$key])) {
            return ['ok' => true];
        }
        if ($n <= 3) {
            return ['ok' => false, 'reason' => 'modulus is too small'];
        }
        if (strlen(gmp_strval($n, 2)) < self::MIN_PRODUCTION_MODULUS_BITS) {
            return ['ok' => false, 'reason' => 'modulus is below ' . self::MIN_PRODUCTION_MODULUS_BITS . ' bits'];
        }
        if (!gmp_testbit($n, 0)) {
            return ['ok' => false, 'reason' => 'modulus is even'];
        }
        if (self::isPerfectSquare($n)) {
            return ['ok' => false, 'reason' => 'modulus is a perfect square'];
        }
        if (self::isProbablePrime($n)) {
            return ['ok' => false, 'reason' => 'modulus is prime (group order N-1 is public)'];
        }
        for ($p = 2; $p < 65536; $p++) { // every integer below 2^16 that divides N: the smallest one is a prime
            if (gmp_mod($n, $p) == 0) {
                return ['ok' => false, 'reason' => "modulus has the small prime factor $p"];
            }
        }
        self::$screenPassed[$key] = true;
        return ['ok' => true];
    }

    // ---- PCA timelock: the VDF challenge is bound to the action and to an unpredictable beacon ------------------------------------

    /** A string is an opaque, precomputed digest; anything else is a PCActn digested like the ledger (strict canonical sha256). */
    public static function actionDigest(mixed $action): string
    {
        return is_string($action) ? $action : Pca::hashCanonical($action);
    }

    private static function beaconBytes(mixed $beacon): string
    {
        $b = $beacon instanceof Bytes ? $beacon->raw : (is_string($beacon) ? Js::utf8($beacon) : null);
        if ($b === null || $b === '') {
            throw new \InvalidArgumentException('timelock: a non-empty beacon (unpredictable, post-action value) is required');
        }
        return $b;
    }

    /** x in [2, N) bound to the action and the beacon; deterministic. */
    public static function deriveTimelockInput(mixed $action, mixed $n, mixed $beacon): \GMP
    {
        if (!($n instanceof \GMP) || $n <= 3) {
            throw new \InvalidArgumentException('deriveTimelockInput: modulus N must be a bigint > 3');
        }
        $digest = Js::utf8(self::actionDigest($action));
        $msg = Js::utf8(self::X_DERIVATION_DOMAIN) . self::lp($digest) . self::lp(self::beaconBytes($beacon));
        $raw = gmp_mod(self::bytesToBigInt(hash('sha256', $msg, true)), $n);
        return $raw <= 1 ? $raw + 2 : $raw;
    }

    private static function requireProductionModulus(mixed $n, mixed $allowInsecureDevModulus): void
    {
        if ($allowInsecureDevModulus === true) {
            return;
        }
        $check = self::checkProductionModulus($n);
        if (!$check['ok']) {
            throw new \InvalidArgumentException('timelock: refusing this modulus: ' . $check['reason']
                . '. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; tests may pass allowInsecureDevModulus: true.');
        }
    }

    private static function requireSteps(mixed $steps): int
    {
        $s = self::safeInt($steps);
        if ($s === null || $s < 1) {
            throw new \InvalidArgumentException('timelock: steps must be a safe integer >= 1, got ' . self::show($steps));
        }
        return $s;
    }

    /** @return array{kind:string,x:\GMP,steps:int,N:\GMP,actionDigest:string} */
    public static function requireTimelock(mixed $action, mixed $steps, mixed $n, mixed $beacon, mixed $allowInsecureDevModulus = null): array
    {
        $s = self::requireSteps($steps);
        self::requireProductionModulus($n, $allowInsecureDevModulus);
        $x = self::deriveTimelockInput($action, $n, $beacon);
        return ['kind' => 'vdf-timelock', 'x' => $x, 'steps' => $s, 'N' => $n, 'actionDigest' => self::actionDigest($action)];
    }

    /** Runs the VDF: the squarings ARE the cooling-off, so this is deliberately slow. @return array{kind:string,y:\GMP,pi:\GMP,steps:int} */
    public static function proveTimelockElapsed(mixed $action, mixed $steps, mixed $n, mixed $beacon, mixed $allowInsecureDevModulus = null): array
    {
        $s = self::requireSteps($steps);
        self::requireProductionModulus($n, $allowInsecureDevModulus);
        $x = self::deriveTimelockInput($action, $n, $beacon);
        $proof = self::vdfEvalCanonical($x, $s, $n);
        return ['kind' => 'vdf-timelock-proof', 'y' => $proof['y'], 'pi' => $proof['pi'], 'steps' => $s];
    }

    /**
     * Fail closed: any malformed input or refused modulus is false. Offline, no clock. `$proof` is an assoc array or Obj with
     * kind / steps / y / pi (y and pi \GMP values; anything else is not a bigint and is refused).
     */
    public static function verifyTimelock(mixed $action, mixed $proof, mixed $steps, mixed $n, mixed $beacon, mixed $allowInsecureDevModulus = null): bool
    {
        try {
            $required = self::requireSteps($steps);
            self::requireProductionModulus($n, $allowInsecureDevModulus);
            if (!($proof instanceof Obj || (is_array($proof) && !array_is_list($proof))) || Js::opt($proof, 'kind') !== 'vdf-timelock-proof') {
                return false;
            }
            $ps = self::safeInt(Js::opt($proof, 'steps'));
            if ($ps === null || $ps !== $required) {
                return false;
            }
            $y = Js::opt($proof, 'y');
            $pi = Js::opt($proof, 'pi');
            if (!($y instanceof \GMP) || !($pi instanceof \GMP)) {
                return false;
            }
            $x = self::deriveTimelockInput($action, $n, $beacon);
            return self::vdfVerifyCanonical($x, $y, $pi, $required, $n);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Operator helper: squarings measured here times a conservative adversary advantage, so the delay is a floor. `$now` is in ms.
     * @return array{steps:int,measuredSquaringsPerSecond:float,assumedAdversarySquaringsPerSecond:float}
     */
    public static function calibrateSteps(\GMP $n, float $desiredSeconds, int $sampleSquarings = 50000, float $adversaryAdvantage = 10.0, ?\Closure $now = null): array
    {
        if ($n <= 3) {
            throw new \InvalidArgumentException('calibrateSteps: modulus N must be a bigint > 3');
        }
        if (!is_finite($desiredSeconds) || $desiredSeconds <= 0) {
            throw new \InvalidArgumentException('calibrateSteps: desiredSeconds must be > 0');
        }
        if ($sampleSquarings < 1) {
            throw new \InvalidArgumentException('calibrateSteps: sampleSquarings must be a safe integer >= 1');
        }
        if (!is_finite($adversaryAdvantage) || $adversaryAdvantage < 1) {
            throw new \InvalidArgumentException('calibrateSteps: adversaryAdvantage must be >= 1');
        }
        $clock = $now ?? static fn(): float => hrtime(true) / 1e6;
        $y = gmp_mod(2, $n);
        $t0 = $clock();
        for ($i = 0; $i < $sampleSquarings; $i++) {
            $y = gmp_mod($y * $y, $n);
            if (self::$sampleHook !== null) {
                (self::$sampleHook)($i, $y);
            }
        }
        $elapsed = max($clock() - $t0, 2.220446049250313e-16);
        $perS = $sampleSquarings / $elapsed * 1000.0;
        $adv = $perS * $adversaryAdvantage;
        return ['steps' => max(1, (int)ceil($adv * $desiredSeconds)), 'measuredSquaringsPerSecond' => $perS, 'assumedAdversarySquaringsPerSecond' => $adv];
    }

    /** @internal Test seam: when set, calibrateSteps calls it after each timed squaring with (index, value). */
    public static ?\Closure $sampleHook = null;
}
