<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';

/** A refusal of the risk accumulator; `errorCode` is invalid_value | length_mismatch. */
final class AccumulatorError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * An arbitrary-size integer in canonical decimal form (optional leading "-"), for the risk units and blinding scalars that
 * exceed a PHP int. Only the few operations the accumulator needs: non-negative add / subtract, comparison, and conversion to and
 * from little-endian bytes. Needs no extension.
 */
final class RatchetBigint
{
    public readonly string $decimal;

    public function __construct(string $decimal)
    {
        if (preg_match('/\A-?(?:0|[1-9][0-9]*)\z/', $decimal) !== 1) {
            throw new \InvalidArgumentException('not a canonical decimal integer');
        }
        $this->decimal = $decimal === '-0' ? '0' : $decimal;
    }

    public static function of(int $n): self
    {
        return new self((string) $n);
    }

    /** The exact value of an integral, finite, non-negative double. */
    public static function fromFloat(float $f): self
    {
        if (!is_finite($f) || $f < 0 || floor($f) !== $f) {
            throw new \RangeException('The number ' . $f . ' cannot be converted to a BigInt because it is not an integer');
        }
        if ($f < 9.0e15) {
            return new self((string) (int) $f);
        }
        $bits = unpack('J', pack('E', $f))[1];
        $exp = ($bits >> 52) & 0x7ff;
        $m = ($bits & ((1 << 52) - 1)) | (1 << 52);
        $shift = $exp - 1075; // value = m * 2^shift, shift >= 0 here (f >= 2^53)
        $le = pack('P', $m);
        $bitShift = $shift % 8;
        if ($bitShift !== 0) {
            $carry = 0;
            $o = '';
            foreach (str_split($le) as $c) {
                $x = (ord($c) << $bitShift) | $carry;
                $o .= chr($x & 255);
                $carry = $x >> 8;
            }
            $le = $o . ($carry !== 0 ? chr($carry) : '');
        }
        return self::fromLe(str_repeat("\0", intdiv($shift, 8)) . $le);
    }

    /** The non-negative integer in little-endian bytes. */
    public static function fromLe(string $le): self
    {
        $b = $le === '' ? [] : array_reverse(array_values(unpack('C*', $le)));
        while ($b !== [] && $b[0] === 0) {
            array_shift($b);
        }
        if ($b === []) {
            return new self('0');
        }
        $chunks = [];
        while ($b !== []) {
            $rem = 0;
            $next = [];
            foreach ($b as $v) {
                $cur = $rem * 256 + $v;
                $q = intdiv($cur, 1000000000);
                $rem = $cur % 1000000000;
                if ($next !== [] || $q > 0) {
                    $next[] = $q;
                }
            }
            $chunks[] = $rem;
            $b = $next;
        }
        $s = (string) array_pop($chunks);
        while ($chunks !== []) {
            $s .= str_pad((string) array_pop($chunks), 9, '0', STR_PAD_LEFT);
        }
        return new self($s);
    }

    public function isNegative(): bool
    {
        return $this->decimal[0] === '-';
    }

    private function mag(): string
    {
        return ltrim($this->decimal, '-');
    }

    /** The magnitude in little-endian bytes (empty for zero). */
    public function toLe(): string
    {
        $b = [];
        foreach (str_split($this->mag()) as $ch) {
            $carry = ord($ch) - 48;
            foreach ($b as $i => $v) {
                $x = $v * 10 + $carry;
                $b[$i] = $x & 255;
                $carry = $x >> 8;
            }
            while ($carry > 0) {
                $b[] = $carry & 255;
                $carry >>= 8;
            }
        }
        return $b === [] ? '' : pack('C*', ...$b);
    }

    public function compare(self $o): int
    {
        if ($this->isNegative() || $o->isNegative()) {
            throw new \InvalidArgumentException('negative operand');
        }
        $a = $this->decimal;
        $b = $o->decimal;
        return strlen($a) <=> strlen($b) ?: strcmp($a, $b) <=> 0;
    }

    public function plus(self $o): self
    {
        if ($this->isNegative() || $o->isNegative()) {
            throw new \InvalidArgumentException('negative operand');
        }
        $a = strrev($this->decimal);
        $b = strrev($o->decimal);
        $n = max(strlen($a), strlen($b));
        $carry = 0;
        $out = '';
        for ($i = 0; $i < $n; $i++) {
            $s = (int) ($a[$i] ?? 0) + (int) ($b[$i] ?? 0) + $carry;
            $out .= (string) ($s % 10);
            $carry = intdiv($s, 10);
        }
        return new self(strrev($out . ($carry > 0 ? '1' : '')));
    }

    /** $this - $o, which must not be negative. */
    public function minus(self $o): self
    {
        if ($this->compare($o) < 0) {
            throw new \InvalidArgumentException('negative result');
        }
        $a = strrev($this->decimal);
        $b = strrev($o->decimal);
        $borrow = 0;
        $out = '';
        for ($i = 0, $n = strlen($a); $i < $n; $i++) {
            $d = (int) $a[$i] - (int) ($b[$i] ?? 0) - $borrow;
            $borrow = $d < 0 ? 1 : 0;
            $out .= (string) ($d + 10 * $borrow);
        }
        return new self(ltrim(strrev($out), '0') ?: '0');
    }

    /** floor(this / 10^k) for a non-negative value. */
    public function dropDigits(int $k): self
    {
        return new self(strlen($this->decimal) <= $k ? '0' : substr($this->decimal, 0, -$k));
    }

    public function __toString(): string
    {
        return $this->decimal;
    }
}

/**
 * Homomorphic risk accumulator with a zero-knowledge spend ceiling: Pedersen commitments C = risk*G + blinding*H on ristretto255
 * (libsodium's crypto_core_ristretto255_* / crypto_scalarmult_ristretto255, no hand-rolled field arithmetic), and a bit-decomposition
 * range proof (Fiat-Shamir OR proof per bit plus a Schnorr aggregation proof) that the slack bMax - sum(risk) lies in [0, 2^32).
 *
 * Risk units are an int, an integral float / Num, or a {@see RatchetBigint}; a blinding is a {@see RatchetBigint} (any integer,
 * reduced mod the group order; an int is refused as in the reference). Wire points and scalars are canonical base64url. Provers draw
 * fresh randomness, so two proofs of the same statement differ; the verdicts match the reference.
 */
final class RatchetAccumulator
{
    public const N_BITS = 32;
    /** The largest ceiling the range proof can express; a larger ceiling is clamped to it (a strictly stronger statement). */
    public const MAX_PROVABLE_CEILING = 4294967295;

    private const H_LABEL = 'atlas-pca-ratchet/pedersen-generator-H/v1';
    private const CTX_DOMAIN = 'atlas-pca-ratchet/budget/ctx/v1';
    private const RISK_CTX_DOMAIN = 'atlas-pca-ratchet/risk-range/ctx/v1';
    private const OR_DOMAIN = 'atlas-pca-ratchet/budget/bit-or/v1';
    private const AGG_DOMAIN = 'atlas-pca-ratchet/budget/agg/v1';

    private static ?string $g = null;
    private static ?string $h = null;
    private static ?string $r256 = null;

    private static function zero(): string
    {
        return str_repeat("\0", 32);
    }

    private static function g(): string
    {
        return self::$g ??= sodium_crypto_scalarmult_ristretto255_base("\x01" . str_repeat("\0", 31));
    }

    private static function h(): string
    {
        return self::$h ??= sodium_crypto_core_ristretto255_from_hash(hash('sha512', self::H_LABEL, true));
    }

    // ---- scalars (32 bytes little-endian, always reduced) ---------------------------------

    private static function reduceLe(string $le): string
    {
        if (strlen($le) <= 64) {
            return sodium_crypto_core_ristretto255_scalar_reduce(str_pad($le, 64, "\0"));
        }
        self::$r256 ??= sodium_crypto_core_ristretto255_scalar_reduce(str_repeat("\0", 32) . "\x01" . str_repeat("\0", 31));
        $acc = self::zero();
        $chunks = str_split($le, 32);
        for ($i = count($chunks) - 1; $i >= 0; $i--) {
            $acc = sodium_crypto_core_ristretto255_scalar_add(
                sodium_crypto_core_ristretto255_scalar_mul($acc, self::$r256),
                sodium_crypto_core_ristretto255_scalar_reduce(str_pad($chunks[$i], 64, "\0")),
            );
        }
        return $acc;
    }

    /** An integer of any size and sign, reduced into [0, L). */
    private static function scalarOf(RatchetBigint $x): string
    {
        $s = self::reduceLe($x->toLe());
        return $x->isNegative() && $s !== self::zero() ? sodium_crypto_core_ristretto255_scalar_negate($s) : $s;
    }

    private static function scalarOfInt(int $n): string
    {
        return pack('P', $n) . str_repeat("\0", 24);
    }

    private static function scalarAdd(string $a, string $b): string
    {
        return sodium_crypto_core_ristretto255_scalar_add($a, $b);
    }

    private static function scalarSub(string $a, string $b): string
    {
        return sodium_crypto_core_ristretto255_scalar_sub($a, $b);
    }

    private static function scalarMul(string $a, string $b): string
    {
        return sodium_crypto_core_ristretto255_scalar_mul($a, $b);
    }

    /** A uniformly random non-zero scalar. */
    private static function randScalar(): string
    {
        do {
            $s = sodium_crypto_core_ristretto255_scalar_reduce(random_bytes(64));
        } while ($s === self::zero());
        return $s;
    }

    // ---- points (32 raw bytes) --------------------------------------------------------------

    /** k*P, tolerating k = 0 and P = identity (libsodium refuses an identity result). */
    private static function mul(string $p, string $k): string
    {
        if ($k === self::zero() || $p === self::zero()) {
            return self::zero();
        }
        return sodium_crypto_scalarmult_ristretto255($k, $p);
    }

    private static function add(string $a, string $b): string
    {
        if ($a === self::zero()) {
            return $b;
        }
        return $b === self::zero() ? $a : sodium_crypto_core_ristretto255_add($a, $b);
    }

    private static function sub(string $a, string $b): string
    {
        return $b === self::zero() ? $a : sodium_crypto_core_ristretto255_sub($a, $b);
    }

    /** Canonical 32-byte base64url ristretto255 point; throws otherwise. */
    private static function decodePoint(mixed $s): string
    {
        $b = Pca::unb64u($s, 32);
        if ($b === null || ($b !== self::zero() && (!Oprf::ristrettoCanonical($b) || !sodium_crypto_core_ristretto255_is_valid_point($b)))) {
            throw new \RangeException('decodePoint: not a canonical ristretto255 point');
        }
        return $b;
    }

    /** Canonical 32-byte base64url scalar below the group order; throws otherwise. */
    private static function decodeScalar(mixed $s): string
    {
        $b = Pca::unb64u($s, 32);
        if ($b === null || sodium_crypto_core_ristretto255_scalar_reduce($b . str_repeat("\0", 32)) !== $b) {
            throw new \RangeException('decodeScalar: not a canonical scalar');
        }
        return $b;
    }

    private static function hashToScalar(array $parts): string
    {
        $buf = '';
        foreach ($parts as $p) {
            $buf .= pack('N', strlen($p)) . $p;
        }
        return sodium_crypto_core_ristretto255_scalar_reduce(hash('sha512', $buf, true));
    }

    // ---- units ----------------------------------------------------------------------------------

    /** A non-negative integer risk / budget (int, integral float or Num, RatchetBigint); invalid_value otherwise. */
    public static function asUnits(mixed $x): RatchetBigint
    {
        if ($x instanceof RatchetBigint) {
            if ($x->isNegative()) {
                throw new AccumulatorError('invalid_value', 'risk/budget must be >= 0');
            }
            return $x;
        }
        $f = is_bool($x) ? null : Js::num($x);
        if ($f === null || !is_finite($f) || floor($f) !== $f || $f < 0) {
            throw new AccumulatorError('invalid_value', 'risk/budget must be a non-negative integer');
        }
        return RatchetBigint::fromFloat($f);
    }

    private static function blindingOf(mixed $b): string
    {
        if (!($b instanceof RatchetBigint)) {
            throw new \TypeError('blinding must be a RatchetBigint');
        }
        return self::scalarOf($b);
    }

    private static function ceiling(mixed $bMax): int
    {
        $u = self::asUnits($bMax);
        return $u->compare(RatchetBigint::of(self::MAX_PROVABLE_CEILING)) > 0 ? self::MAX_PROVABLE_CEILING : (int) $u->decimal;
    }

    private static function leInt(int $n): string
    {
        return pack('P', $n) . str_repeat("\0", 24);
    }

    // ---- commitments ------------------------------------------------------------------------------

    /**
     * Commit to a non-negative integer `$risk` with the given blinding (omit it for a fresh random one).
     *
     * @return array{commitment:string,blinding:RatchetBigint}
     */
    public static function commitRisk(mixed $risk, mixed $blinding = null): array
    {
        $v = self::asUnits($risk);
        $b = func_num_args() < 2 ? self::randScalar() : self::blindingOf($blinding);
        $c = self::add(self::mul(self::g(), self::scalarOf($v)), self::mul(self::h(), $b));
        return ['commitment' => Pca::b64u($c), 'blinding' => RatchetBigint::fromLe($b)];
    }

    /** Homomorphic sum of canonical commitments (a commitment to the summed risk and blinding); empty = the identity. */
    public static function addCommitments(mixed $commitments): string
    {
        if (!is_array($commitments) || !array_is_list($commitments)) {
            throw new \TypeError('addCommitments: commitments must be a list');
        }
        $acc = self::zero();
        foreach ($commitments as $c) {
            $acc = self::add($acc, self::decodePoint($c));
        }
        return Pca::b64u($acc);
    }

    /** Whether `$commitment` opens to (`$risk`, `$blinding`). Never throws; malformed input is false. */
    public static function openCommitment(mixed $commitment, mixed $risk, mixed $blinding): bool
    {
        try {
            $v = self::asUnits($risk);
            $expected = self::add(self::mul(self::g(), self::scalarOf($v)), self::mul(self::h(), self::blindingOf($blinding)));
            return hash_equals($expected, self::decodePoint($commitment));
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- range proof ------------------------------------------------------------------------------

    private static function contextHash(int $ceiling, string $cSum, array $bits): string
    {
        return self::hashToScalar([self::CTX_DOMAIN, chr(self::N_BITS & 0xff), self::leInt($ceiling), $cSum, ...$bits]);
    }

    private static function riskContextHash(string $commitment, array $bits): string
    {
        return self::hashToScalar([self::RISK_CTX_DOMAIN, chr(self::N_BITS & 0xff), $commitment, ...$bits]);
    }

    /** @return array{e0:string,e1:string,z0:string,z1:string} */
    private static function proveBit(string $ctx, int $index, string $b, int $bit, string $s): array
    {
        $p0 = $b;
        $p1 = self::sub($b, self::g());
        $eFake = self::randScalar();
        $zFake = self::randScalar();
        $pFake = $bit === 1 ? $p0 : $p1;
        $aFake = self::sub(self::mul(self::h(), $zFake), self::mul($pFake, $eFake));
        $k = self::randScalar();
        $aReal = self::mul(self::h(), $k);
        $a0 = $bit === 0 ? $aReal : $aFake;
        $a1 = $bit === 1 ? $aReal : $aFake;
        $e = self::hashToScalar([self::OR_DOMAIN, $ctx, chr($index & 0xff), $a0, $a1]);
        $eReal = self::scalarSub($e, $eFake);
        $zReal = self::scalarAdd($k, self::scalarMul($eReal, $s));
        $e0 = $bit === 0 ? $eReal : $eFake;
        $e1 = $bit === 1 ? $eReal : $eFake;
        $z0 = $bit === 0 ? $zReal : $zFake;
        $z1 = $bit === 1 ? $zReal : $zFake;
        return ['e0' => Pca::b64u($e0), 'e1' => Pca::b64u($e1), 'z0' => Pca::b64u($z0), 'z1' => Pca::b64u($z1)];
    }

    private static function verifyBit(string $ctx, int $index, string $b, mixed $proof): bool
    {
        $e0 = self::decodeScalar(Js::opt($proof, 'e0'));
        $e1 = self::decodeScalar(Js::opt($proof, 'e1'));
        $z0 = self::decodeScalar(Js::opt($proof, 'z0'));
        $z1 = self::decodeScalar(Js::opt($proof, 'z1'));
        $a0 = self::sub(self::mul(self::h(), $z0), self::mul($b, $e0));
        $a1 = self::sub(self::mul(self::h(), $z1), self::mul(self::sub($b, self::g()), $e1));
        $e = self::hashToScalar([self::OR_DOMAIN, $ctx, chr($index & 0xff), $a0, $a1]);
        return hash_equals($e, self::scalarAdd($e0, $e1));
    }

    /** @return array{a:string,z:string} */
    private static function proveSchnorr(string $ctx, string $d, string $w): array
    {
        $k = self::randScalar();
        $a = self::mul(self::h(), $k);
        $e = self::hashToScalar([self::AGG_DOMAIN, $ctx, $d, $a]);
        return ['a' => Pca::b64u($a), 'z' => Pca::b64u(self::scalarAdd($k, self::scalarMul($e, $w)))];
    }

    private static function verifySchnorr(string $ctx, string $d, mixed $proof): bool
    {
        $a = self::decodePoint(Js::opt($proof, 'a'));
        $z = self::decodeScalar(Js::opt($proof, 'z'));
        $e = self::hashToScalar([self::AGG_DOMAIN, $ctx, $d, $a]);
        return hash_equals(self::mul(self::h(), $z), self::add($a, self::mul($d, $e)));
    }

    /**
     * Prove V = value*G + gamma*H commits to a value in [0, 2^32): `$low` is the value modulo 2^32 (an out-of-range value yields a
     * well-formed proof the verifier rejects).
     *
     * @return array{bitCommitments:list<string>,or:list<array>,agg:array}
     */
    private static function rangeProve(callable $makeCtx, string $v, int $low, string $gamma): array
    {
        $bc = [];
        $bb = [];
        $bits = [];
        for ($i = 0; $i < self::N_BITS; $i++) {
            $bit = ($low >> $i) & 1;
            $s = self::randScalar();
            $bits[] = $bit;
            $bb[] = $s;
            $bc[] = self::add($bit === 1 ? self::g() : self::zero(), self::mul(self::h(), $s));
        }
        $ctx = $makeCtx($bc);
        $or = [];
        for ($i = 0; $i < self::N_BITS; $i++) {
            $or[] = self::proveBit($ctx, $i, $bc[$i], $bits[$i], $bb[$i]);
        }
        $sStar = self::zero();
        $agg = self::zero();
        for ($i = 0; $i < self::N_BITS; $i++) {
            $w = self::scalarOfInt(1 << $i);
            $sStar = self::scalarAdd($sStar, self::scalarMul($w, $bb[$i]));
            $agg = self::add($agg, self::mul($bc[$i], $w));
        }
        return ['bitCommitments' => $bc, 'or' => $or, 'agg' => self::proveSchnorr($ctx, self::sub($agg, $v), self::scalarSub($sStar, $gamma))];
    }

    private static function rangeVerify(callable $makeCtx, string $v, mixed $proof): bool
    {
        if (!Js::isObj($proof)) {
            return false;
        }
        $n = Js::opt($proof, 'n');
        $bc = Js::opt($proof, 'bitCommitments');
        $or = Js::opt($proof, 'or');
        $agg = Js::opt($proof, 'agg');
        if (!Js::isNum($n) || Js::num($n) !== (float) self::N_BITS || !is_array($bc) || !array_is_list($bc) || !is_array($or) || !array_is_list($or)) {
            return false;
        }
        if (count($bc) !== self::N_BITS || count($or) !== self::N_BITS || !(Js::isObj($agg) || is_array($agg))) {
            return false;
        }
        $b = array_map(self::decodePoint(...), $bc);
        $ctx = $makeCtx($b);
        for ($i = 0; $i < self::N_BITS; $i++) {
            if (!self::verifyBit($ctx, $i, $b[$i], $or[$i])) {
                return false;
            }
        }
        $sum = self::zero();
        for ($i = 0; $i < self::N_BITS; $i++) {
            $sum = self::add($sum, self::mul($b[$i], self::scalarOfInt(1 << $i)));
        }
        return self::verifySchnorr($ctx, self::sub($sum, $v), $agg);
    }

    private static function proofOut(array $r): array
    {
        return ['n' => self::N_BITS, 'bitCommitments' => array_map(Pca::b64u(...), $r['bitCommitments']), 'or' => $r['or'], 'agg' => $r['agg']];
    }

    /** The low 32 bits of a non-negative integer. */
    private static function low32(RatchetBigint $x): int
    {
        return (int) unpack('V', str_pad(substr($x->toLe(), 0, 4), 4, "\0"))[1];
    }

    /**
     * Prove sum(risks) <= bMax in zero knowledge over the individual risks (`$blindings` are the RatchetBigint blindings of the
     * commitments whose sum goes to {@see verifyBudget}). An over-budget aggregate yields a well-formed proof the verifier rejects.
     * Pair it with {@see proveRiskRange} per addend, or a prover can offset real risk with a "negative" commitment.
     *
     * @return array{n:int,bitCommitments:list<string>,or:list<array>,agg:array}
     */
    public static function proveBudget(array $risks, array $blindings, mixed $bMax): array
    {
        if (count($risks) !== count($blindings)) {
            throw new AccumulatorError('length_mismatch', 'risks and blindings must have equal length');
        }
        $ceiling = self::ceiling($bMax);
        $sum = RatchetBigint::of(0);
        $sumBlind = self::zero();
        $bl = array_values($blindings);
        foreach (array_values($risks) as $i => $r) {
            $sum = $sum->plus(self::asUnits($r));
            $sumBlind = self::scalarAdd($sumBlind, self::blindingOf($bl[$i]));
        }
        $cSum = self::add(self::mul(self::g(), self::scalarOf($sum)), self::mul(self::h(), $sumBlind));
        $v = self::sub(self::mul(self::g(), self::scalarOfInt($ceiling)), $cSum);
        $low = ($ceiling - self::low32($sum)) & 0xffffffff; // the slack modulo 2^32 (two's complement when over budget)
        $r = self::rangeProve(fn(array $bits) => self::contextHash($ceiling, $cSum, $bits), $v, $low, sodium_crypto_core_ristretto255_scalar_negate($sumBlind));
        return self::proofOut($r);
    }

    /** Whether the proof shows the committed sum satisfies sum(risk) <= bMax (ceilings above 2^32 - 1 clamp). Never throws. */
    public static function verifyBudget(mixed $commitmentSum, mixed $bMax, mixed $proof): bool
    {
        try {
            $ceiling = self::ceiling($bMax);
            $cSum = self::decodePoint($commitmentSum);
            $v = self::sub(self::mul(self::g(), self::scalarOfInt($ceiling)), $cSum);
            return self::rangeVerify(fn(array $bits) => self::contextHash($ceiling, $cSum, $bits), $v, $proof);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Prove the commitment of (`$risk`, `$blinding`) holds a value in [0, 2^32): each addend needs one, or the budget proof alone
     * (which only constrains the sum) could be cancelled by a commitment near the group order.
     *
     * @return array{n:int,bitCommitments:list<string>,or:list<array>,agg:array}
     */
    public static function proveRiskRange(mixed $risk, mixed $blinding): array
    {
        $v = self::asUnits($risk);
        $b = self::blindingOf($blinding);
        $c = self::add(self::mul(self::g(), self::scalarOf($v)), self::mul(self::h(), $b));
        return self::proofOut(self::rangeProve(fn(array $bits) => self::riskContextHash($c, $bits), $c, self::low32($v), $b));
    }

    /** Verify {@see proveRiskRange} for `$commitment`. Never throws. */
    public static function verifyRiskRange(mixed $commitment, mixed $proof): bool
    {
        try {
            $c = self::decodePoint($commitment);
            return self::rangeVerify(fn(array $bits) => self::riskContextHash($c, $bits), $c, $proof);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * The sound end-to-end check for a budget over per-action commitments: every commitment carries a valid range proof and the
     * budget proof verifies for their sum. Never throws.
     */
    public static function verifyBoundedBudget(mixed $commitments, mixed $rangeProofs, mixed $bMax, mixed $budgetProof): bool
    {
        try {
            if (!is_array($commitments) || !array_is_list($commitments) || !is_array($rangeProofs) || !array_is_list($rangeProofs)
                || count($commitments) !== count($rangeProofs)) {
                return false;
            }
            foreach ($commitments as $i => $c) {
                if (!self::verifyRiskRange($c, $rangeProofs[$i])) {
                    return false;
                }
            }
            return self::verifyBudget(self::addCommitments($commitments), $bMax, $budgetProof);
        } catch (\Throwable) {
            return false;
        }
    }
}
