<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';

/** The argument was not passed (an explicit null is a value the reference distinguishes from "absent": it is refused). */
enum OprfAbsent
{
    case Absent;
}

/**
 * RFC 9497 OPRF / VOPRF / POPRF on ristretto255-SHA512 plus the PCA private-revocation and private-rate-limit layer. The group is
 * libsodium's ristretto255 (ext-sodium, vetted; no hand-rolled curve code): an element is its 32-byte encoding, a scalar its 32-byte
 * little-endian encoding, and scalar arithmetic runs in libsodium too.
 *
 * Native-stricter than the reference: it silently routes any mode other than 'oprf' through the verifiable path in blindEvaluate and
 * skips proof verification in finalize for anything but 'voprf'; here an unknown mode (or 'poprf' on the non-POPRF entry points) is
 * refused. Byte arguments are PHP strings; anything else (null, an array, a number) is refused.
 */
final class Oprf
{
    public const ELEMENT_BYTES = 32;
    public const SCALAR_BYTES = 32;
    public const OUTPUT_BYTES = 64;
    public const SUITE_ID = 'ristretto255-SHA512';
    private const MODE = ['oprf' => 0x00, 'voprf' => 0x01, 'poprf' => 0x02];
    private const MAX_FRAMED = 0xFFFF;
    private const ORDER = '7237005577332262213973186563042994240857116359379907606001950938285454250989';
    private const ZERO32 = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    // ---- plumbing ----------------------------------------------------------------------------------------------------------

    private static function bytes(mixed $v, string $what, ?int $max = null): string
    {
        if (!is_string($v)) {
            throw new \TypeError("$what: expected bytes");
        }
        if ($max !== null && strlen($v) > $max) {
            throw new \InvalidArgumentException("$what: " . strlen($v) . " bytes exceeds the $max-byte limit (RFC 9497 2-byte length framing)");
        }
        return $v;
    }

    private static function i2osp(int $n, int $len): string
    {
        if ($n < 0 || ($len < 8 && $n >= (1 << (8 * $len)))) {
            throw new \OverflowException('i2osp: integer too large');
        }
        return substr(pack('J', $n), 8 - $len);
    }

    private static function context(mixed $mode): string
    {
        if (!is_string($mode) || !isset(self::MODE[$mode])) {
            throw new \InvalidArgumentException('unknown OPRF mode ' . (is_string($mode) ? $mode : gettype($mode)));
        }
        return 'OPRFV1-' . self::i2osp(self::MODE[$mode], 1) . '-' . self::SUITE_ID;
    }

    private static function requireServerModes(mixed $mode): string
    {
        if ($mode !== 'oprf' && $mode !== 'voprf') {
            throw new \InvalidArgumentException("mode must be 'oprf' or 'voprf'");
        }
        return $mode;
    }

    private static function order(): \GMP
    {
        return gmp_init(self::ORDER);
    }

    private static function isZero(string $s): bool
    {
        return hash_equals(self::ZERO32, $s);
    }

    /** Scalar multiplication; the reference's multiply() rejects 0 (and anything >= the group order, which a canonical scalar never is). */
    private static function mul(string $pt, string $k): string
    {
        if (self::isZero($k)) {
            throw new \InvalidArgumentException('expected valid scalar: 1 <= n < the group order, got 0');
        }
        return sodium_crypto_scalarmult_ristretto255($k, $pt);
    }

    /** As {@see mul} but 0 is allowed (the result is the identity), and the identity times anything is the identity. */
    private static function mulUnsafe(string $pt, string $k): string
    {
        if (self::isZero($k) || self::isZero($pt)) {
            return self::ZERO32;
        }
        return sodium_crypto_scalarmult_ristretto255($k, $pt);
    }

    private static function add(string $a, string $b): string
    {
        return sodium_crypto_core_ristretto255_add($a, $b);
    }

    private static function isIdentity(string $p): bool
    {
        return self::isZero($p);
    }

    private static function baseMult(string $k): string
    {
        if (self::isZero($k)) {
            throw new \InvalidArgumentException('expected valid scalar: 1 <= n < the group order, got 0');
        }
        return sodium_crypto_scalarmult_ristretto255_base($k);
    }

    /** RFC 9380 expand_message_xmd with SHA-512 for the 64-byte output every suite step needs (a single block). */
    private static function expandMessageXmd(string $msg, string $dst): string
    {
        if (strlen($dst) > 255) {
            $dst = hash('sha512', 'H2C-OVERSIZE-DST-' . $dst, true);
        }
        $dstPrime = $dst . chr(strlen($dst));
        $b0 = hash('sha512', str_repeat("\0", 128) . $msg . "\x00\x40" . "\x00" . $dstPrime, true);
        return hash('sha512', $b0 . "\x01" . $dstPrime, true);
    }

    private static function hashToScalarDst(string $data, string $dst): string
    {
        return sodium_crypto_core_ristretto255_scalar_reduce(self::expandMessageXmd($data, $dst));
    }

    private static function hashToScalar(string $data, string $mode): string
    {
        return self::hashToScalarDst($data, 'HashToScalar-' . self::context($mode));
    }

    private static function scalarInvert(string $s): string
    {
        if (self::isZero($s)) {
            throw new \InvalidArgumentException('scalarInvert: inverse of zero');
        }
        return sodium_crypto_core_ristretto255_scalar_invert($s);
    }

    // ---- (de)serialisation -------------------------------------------------------------------------------------------------------

    public static function serializeElement(string $p): string
    {
        return $p;
    }

    public static function deserializeElement(mixed $b): string
    {
        $raw = self::bytes($b, 'DeserializeElement');
        // RFC 9496 section 4.3.1 decoding, explicitly (canonical field element, non-negative s, a square root that exists, non-negative t, non-zero y),
        // before libsodium's own check: the encoding must be refused here whatever the linked libsodium accepts
        if (strlen($raw) !== self::ELEMENT_BYTES || !self::ristrettoCanonical($raw) || !sodium_crypto_core_ristretto255_is_valid_point($raw)) {
            throw new \InvalidArgumentException('RistrettoPoint.fromHex: the hex is not valid encoding of RistrettoPoint');
        }
        if (self::isIdentity($raw)) {
            throw new \InvalidArgumentException('DeserializeElement: identity element is not a valid input');
        }
        return $raw;
    }

    /** RFC 9496 decode of a 32-byte ristretto255 encoding: true iff it is the canonical encoding of a group element. */
    public static function ristrettoCanonical(string $b): bool
    {
        $p = gmp_sub(gmp_pow(2, 255), 19);
        $s = gmp_init(bin2hex(strrev($b)), 16);
        if (gmp_cmp($s, $p) >= 0 || gmp_intval(gmp_and($s, 1)) === 1) {
            return false; // not reduced, or negative
        }
        $mod = static fn(\GMP $x): \GMP => gmp_mod($x, gmp_init('57896044618658097711785492504343953926634992332820282019728792003956564819949'));
        $neg = static fn(\GMP $x): bool => gmp_intval(gmp_and($x, 1)) === 1;
        $d = $mod(gmp_mul(gmp_init('-121665'), gmp_invert(gmp_init(121666), $p)));
        $i = gmp_powm(gmp_init(2), gmp_div_q(gmp_sub($p, 1), 4), $p);
        $ss = $mod(gmp_mul($s, $s));
        $u1 = $mod(gmp_sub(1, $ss));
        $u2 = $mod(gmp_add(1, $ss));
        $u2s = $mod(gmp_mul($u2, $u2));
        $v = $mod(gmp_sub(gmp_mul(gmp_mul(gmp_neg($d), $u1), $u1), $u2s));
        // SQRT_RATIO_M1(1, v * u2^2)
        $vv = $mod(gmp_mul($v, $u2s));
        $v3 = $mod(gmp_mul($mod(gmp_mul($vv, $vv)), $vv));
        $v7 = $mod(gmp_mul($mod(gmp_mul($v3, $v3)), $vv));
        $r = $mod(gmp_mul(gmp_mul(gmp_init(1), $v3), gmp_powm($v7, gmp_div_q(gmp_sub($p, 5), 8), $p)));
        $check = $mod(gmp_mul($mod(gmp_mul($vv, $r)), $r));
        $correct = gmp_cmp($check, 1) === 0;
        $flipped = gmp_cmp($check, $mod(gmp_neg(gmp_init(1)))) === 0;
        $flippedI = gmp_cmp($check, $mod(gmp_neg($i))) === 0;
        if ($flipped || $flippedI) {
            $r = $mod(gmp_mul($r, $i));
        }
        if ($neg($r)) {
            $r = $mod(gmp_neg($r));
        }
        if (!($correct || $flipped)) {
            return false;
        }
        $dx = $mod(gmp_mul($r, $u2));
        $dy = $mod(gmp_mul($mod(gmp_mul($r, $dx)), $v));
        $x = $mod(gmp_mul(gmp_mul(gmp_init(2), $s), $dx));
        if ($neg($x)) {
            $x = $mod(gmp_neg($x));
        }
        $y = $mod(gmp_mul($u1, $dy));
        $t = $mod(gmp_mul($x, $y));
        return !$neg($t) && gmp_cmp($y, 0) !== 0;
    }

    /** The 32-byte little-endian scalar for an integer (reduced mod the group order). @param \GMP|int|string $s */
    public static function serializeScalar(\GMP|int|string $s): string
    {
        $v = gmp_mod($s instanceof \GMP ? $s : gmp_init($s, 10), self::order());
        return str_pad(strrev(gmp_export($v)), self::SCALAR_BYTES, "\0"); // gmp_export is big-endian; of zero it is empty
    }

    /** The scalar as a 32-byte little-endian string, refusing a non-canonical one (>= the group order). */
    private static function scalarOf(mixed $b): string
    {
        $raw = self::bytes($b, 'DeserializeScalar');
        if (strlen($raw) !== self::SCALAR_BYTES) {
            throw new \InvalidArgumentException('DeserializeScalar: expected ' . self::SCALAR_BYTES . ' bytes, got ' . strlen($raw));
        }
        if (gmp_cmp(gmp_import(strrev($raw)), self::order()) >= 0) {
            throw new \InvalidArgumentException('DeserializeScalar: non-canonical scalar (value >= group order)');
        }
        return $raw;
    }

    public static function deserializeScalar(mixed $b): \GMP
    {
        return gmp_import(strrev(self::scalarOf($b)));
    }

    public static function hashToGroup(mixed $data, string $mode): string
    {
        $msg = self::bytes($data, 'HashToGroup');
        return sodium_crypto_core_ristretto255_from_hash(self::expandMessageXmd($msg, 'HashToGroup-' . self::context($mode)));
    }

    public static function randomScalar(): string
    {
        for ($i = 0; $i < 8; $i++) {
            $s = sodium_crypto_core_ristretto255_scalar_random();
            if (!self::isZero($s)) {
                return $s;
            }
        }
        throw new \RuntimeException('randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue');
    }

    // ---- keys (server secret) ----------------------------------------------------------------------------------------------------

    /** @return array{secret_key:string,public_key:string} */
    public static function deriveKeyPair(mixed $seed, mixed $info, mixed $mode): array
    {
        if (!is_string($seed) || strlen($seed) !== self::SCALAR_BYTES) {
            throw new \InvalidArgumentException('DeriveKeyPair: seed must be exactly ' . self::SCALAR_BYTES . ' bytes');
        }
        $info = self::bytes($info, 'DeriveKeyPair(info)');
        $dst = 'DeriveKeyPair' . self::context($mode);
        $input = $seed . self::i2osp(strlen($info), 2) . $info;
        for ($counter = 0; $counter < 256; $counter++) {
            $sk = self::hashToScalarDst($input . chr($counter), $dst);
            if (!self::isZero($sk)) {
                return ['secret_key' => $sk, 'public_key' => self::baseMult($sk)];
            }
        }
        throw new \RuntimeException('DeriveKeyPair: failed to derive a non-zero key after 256 attempts');
    }

    /** @return array{secret_key:string,public_key:string} */
    public static function randomKeyPair(): array
    {
        $sk = self::randomScalar();
        return ['secret_key' => $sk, 'public_key' => self::baseMult($sk)];
    }

    public static function publicKeyFor(mixed $secretKey): string
    {
        return self::baseMult(self::scalarOf($secretKey));
    }

    // ---- DLEQ proofs (RFC 9497 section 2.2.1) --------------------------------------------------------------------------------------

    private static function compositesSeed(string $bSer, string $mode): string
    {
        $seedDst = 'Seed-' . self::context($mode);
        return hash('sha512', self::i2osp(strlen($bSer), 2) . $bSer . self::i2osp(strlen($seedDst), 2) . $seedDst, true);
    }

    private static function compositeCoefficient(string $seed, int $index, string $cSer, string $dSer, string $mode): string
    {
        $transcript = self::i2osp(strlen($seed), 2) . $seed . self::i2osp($index, 2) . self::i2osp(strlen($cSer), 2) . $cSer
            . self::i2osp(strlen($dSer), 2) . $dSer . 'Composite';
        return self::hashToScalar($transcript, $mode);
    }

    /** @return array{0:string,1:string} */
    private static function composites(string $b, string $c, string $d, string $mode): array
    {
        $seed = self::compositesSeed($b, $mode);
        $coeff = self::compositeCoefficient($seed, 0, $c, $d, $mode);
        return [self::mulUnsafe($c, $coeff), self::mulUnsafe($d, $coeff)];
    }

    private static function challenge(string $b, string $m, string $z, string $t2, string $t3, string $mode): string
    {
        $parts = '';
        foreach ([$b, $m, $z, $t2, $t3] as $p) {
            $parts .= self::i2osp(strlen($p), 2) . $p;
        }
        return self::hashToScalar($parts . 'Challenge', $mode);
    }

    private static function generateProof(string $k, string $a, string $b, string $c, string $d, string $mode, mixed $fixed): string
    {
        [$m] = self::composites($b, $c, $d, $mode);
        $z = self::mul($m, $k);
        $r = $fixed === OprfAbsent::Absent ? self::randomScalar() : self::scalarOf($fixed);
        $t2 = self::mul($a, $r);
        $t3 = self::mul($m, $r);
        $cc = self::challenge($b, $m, $z, $t2, $t3, $mode);
        $s = sodium_crypto_core_ristretto255_scalar_sub($r, sodium_crypto_core_ristretto255_scalar_mul($cc, $k));
        return $cc . $s;
    }

    private static function verifyProof(string $a, string $b, string $c, string $d, mixed $proof, string $mode): bool
    {
        $proof = self::bytes($proof, 'proof');
        if (strlen($proof) !== 2 * self::SCALAR_BYTES) {
            return false;
        }
        $cc = self::scalarOf(substr($proof, 0, self::SCALAR_BYTES));
        $s = self::scalarOf(substr($proof, self::SCALAR_BYTES));
        [$m, $z] = self::composites($b, $c, $d, $mode);
        $t2 = self::add(self::mulUnsafe($a, $s), self::mulUnsafe($b, $cc));
        $t3 = self::add(self::mulUnsafe($m, $s), self::mulUnsafe($z, $cc));
        return hash_equals($cc, self::challenge($b, $m, $z, $t2, $t3, $mode));
    }

    private static function finalizeHash(string $data, string $issued): string
    {
        return hash('sha512', self::i2osp(strlen($data), 2) . $data . self::i2osp(strlen($issued), 2) . $issued . 'Finalize', true);
    }

    private static function finalizeHashPoprf(string $data, string $info, string $issued): string
    {
        return hash('sha512', self::i2osp(strlen($data), 2) . $data . self::i2osp(strlen($info), 2) . $info
            . self::i2osp(strlen($issued), 2) . $issued . 'Finalize', true);
    }

    // ---- OPRF / VOPRF ---------------------------------------------------------------------------------------------------------------

    /** Client step 1. The blind is the client's secret. @return array{blind:string,blinded_element:string} */
    public static function blind(mixed $data, mixed $mode = 'oprf', mixed $fixedBlind = OprfAbsent::Absent): array
    {
        $data = self::bytes($data, 'Blind(input)', self::MAX_FRAMED);
        $r = $fixedBlind === OprfAbsent::Absent ? self::randomScalar() : self::scalarOf($fixedBlind);
        $element = self::hashToGroup($data, (string)(is_string($mode) ? $mode : ''));
        if (self::isIdentity($element)) {
            throw new \InvalidArgumentException('Blind: input maps to identity');
        }
        return ['blind' => $r, 'blinded_element' => self::mul($element, $r)];
    }

    /** @return array{evaluated_element:string,proof?:string} */
    public static function blindEvaluate(mixed $secretKey, mixed $blindedElement, mixed $mode = 'oprf', mixed $publicKey = OprfAbsent::Absent,
                                         mixed $fixedProofRandomness = OprfAbsent::Absent): array
    {
        self::requireServerModes($mode);
        $sk = self::scalarOf($secretKey);
        $r = self::deserializeElement($blindedElement);
        $evaluated = self::mul($r, $sk);
        if ($mode === 'oprf') {
            return ['evaluated_element' => $evaluated];
        }
        $pk = $publicKey === OprfAbsent::Absent ? self::baseMult($sk) : self::deserializeElement($publicKey);
        return ['evaluated_element' => $evaluated, 'proof' => self::generateProof($sk, self::generator(), $pk, $r, $evaluated, 'voprf', $fixedProofRandomness)];
    }

    public static function finalize(mixed $data, mixed $blindScalar, mixed $evaluatedElement, mixed $mode = 'oprf', mixed $proof = null,
                                    mixed $publicKey = null, mixed $blindedElement = null): string
    {
        $data = self::bytes($data, 'Finalize(input)', self::MAX_FRAMED);
        self::requireServerModes($mode);
        $r = self::scalarOf($blindScalar);
        $evaluated = self::deserializeElement($evaluatedElement);
        if ($mode === 'voprf') {
            if ($proof === null || $publicKey === null || $blindedElement === null) {
                throw new \InvalidArgumentException('Finalize(voprf): proof, publicKey and blindedElement are required');
            }
            $pk = self::deserializeElement($publicKey);
            $blinded = self::deserializeElement($blindedElement);
            if (!self::verifyProof(self::generator(), $pk, $blinded, $evaluated, $proof, 'voprf')) {
                throw new \InvalidArgumentException('Finalize(voprf): DLEQ proof verification failed');
            }
        }
        return self::finalizeHash($data, self::mul($evaluated, self::scalarInvert($r)));
    }

    private static function generator(): string
    {
        return sodium_crypto_scalarmult_ristretto255_base(self::serializeScalar(1));
    }

    public static function evaluate(mixed $secretKey, mixed $data, mixed $mode = 'oprf'): string
    {
        $data = self::bytes($data, 'Evaluate(input)', self::MAX_FRAMED);
        self::requireServerModes($mode);
        $sk = self::scalarOf($secretKey);
        $element = self::hashToGroup($data, $mode);
        if (self::isIdentity($element)) {
            throw new \InvalidArgumentException('Evaluate: input maps to identity');
        }
        return self::finalizeHash($data, self::mul($element, $sk));
    }

    // ---- POPRF (the public input `info` is bound into the evaluation) ----------------------------------------------------------------

    private static function poprfInfoScalar(mixed $info): string
    {
        $info = self::bytes($info, 'info', self::MAX_FRAMED);
        return self::hashToScalar('Info' . self::i2osp(strlen($info), 2) . $info, 'poprf');
    }

    /** @return array{blind:string,blinded_element:string,tweaked_key:string} */
    public static function blindPoprf(mixed $data, mixed $info, mixed $publicKey, mixed $fixedBlind = OprfAbsent::Absent): array
    {
        $data = self::bytes($data, 'Blind(input)', self::MAX_FRAMED);
        $m = self::poprfInfoScalar($info);
        $tweaked = self::add(self::baseMult($m), self::deserializeElement($publicKey));
        if (self::isIdentity($tweaked)) {
            throw new \InvalidArgumentException('Blind(poprf): tweaked key is identity');
        }
        return self::blind($data, 'poprf', $fixedBlind) + ['tweaked_key' => $tweaked];
    }

    /** @return array{evaluated_element:string,proof:string} */
    public static function blindEvaluatePoprf(mixed $secretKey, mixed $blindedElement, mixed $info, mixed $fixedProofRandomness = OprfAbsent::Absent): array
    {
        $sk = self::scalarOf($secretKey);
        $t = sodium_crypto_core_ristretto255_scalar_add($sk, self::poprfInfoScalar($info));
        if (self::isZero($t)) {
            throw new \InvalidArgumentException('BlindEvaluate(poprf): inverse of zero (bad info/key)');
        }
        $blinded = self::deserializeElement($blindedElement);
        $evaluated = self::mul($blinded, self::scalarInvert($t));
        $tweakedKey = self::baseMult($t);
        return ['evaluated_element' => $evaluated,
            'proof' => self::generateProof($t, self::generator(), $tweakedKey, $evaluated, $blinded, 'poprf', $fixedProofRandomness)];
    }

    public static function finalizePoprf(mixed $data, mixed $blindScalar, mixed $evaluatedElement, mixed $info, mixed $proof, mixed $blindedElement, mixed $tweakedKey): string
    {
        $data = self::bytes($data, 'Finalize(input)', self::MAX_FRAMED);
        $info = self::bytes($info, 'info', self::MAX_FRAMED);
        $r = self::scalarOf($blindScalar);
        $evaluated = self::deserializeElement($evaluatedElement);
        $blinded = self::deserializeElement($blindedElement);
        $tweaked = self::deserializeElement($tweakedKey);
        if (!self::verifyProof(self::generator(), $tweaked, $evaluated, $blinded, $proof, 'poprf')) {
            throw new \InvalidArgumentException('Finalize(poprf): DLEQ proof verification failed');
        }
        return self::finalizeHashPoprf($data, $info, self::mul($evaluated, self::scalarInvert($r)));
    }

    public static function evaluatePoprf(mixed $secretKey, mixed $data, mixed $info): string
    {
        $data = self::bytes($data, 'Evaluate(input)', self::MAX_FRAMED);
        $sk = self::scalarOf($secretKey);
        $t = sodium_crypto_core_ristretto255_scalar_add($sk, self::poprfInfoScalar($info));
        if (self::isZero($t)) {
            throw new \InvalidArgumentException('Evaluate(poprf): inverse of zero (bad info/key)');
        }
        $element = self::hashToGroup($data, 'poprf');
        if (self::isIdentity($element)) {
            throw new \InvalidArgumentException('Evaluate(poprf): input maps to identity');
        }
        return self::finalizeHashPoprf($data, self::bytes($info, 'info'), self::mul($element, self::scalarInvert($t)));
    }

    public static function toHex(mixed $b): string
    {
        return bin2hex(self::bytes($b, 'toHex'));
    }

    public static function bytesEqual(mixed $a, mixed $b): bool
    {
        $a = self::bytes($a, 'bytesEqual');
        $b = self::bytes($b, 'bytesEqual');
        return strlen($a) === strlen($b) && hash_equals($a, $b);
    }

    // ---- PCA layer: private revocation (does my capability id appear in the revoked set, without telling the service which id?) ----------

    private static function encodeStrict(mixed $s, string $what): string
    {
        if (!is_string($s)) {
            throw new \TypeError("$what must be a string");
        }
        if (Json::hasLoneSurrogate($s)) {
            throw new \InvalidArgumentException("$what contains an unpaired surrogate (ill-formed UTF-16)");
        }
        return $s;
    }

    /** @param iterable<mixed> $revokedCapIds @return array{outputs:array<string,true>,mode:string,public_key?:string} outputs: hex PRF outputs as keys */
    public static function buildRevocationSet(mixed $secretKey, iterable $revokedCapIds, mixed $mode = 'oprf'): array
    {
        self::requireServerModes($mode);
        $outputs = [];
        foreach ($revokedCapIds as $capId) {
            $outputs[self::toHex(self::evaluate($secretKey, self::encodeStrict($capId, 'capability id'), $mode))] = true;
        }
        $out = ['outputs' => $outputs, 'mode' => $mode];
        if ($mode === 'voprf') {
            $out['public_key'] = self::publicKeyFor($secretKey);
        }
        return $out;
    }

    /** @return \Closure(string): array{evaluated_element:string,proof?:string} */
    public static function makeRevocationEvaluator(mixed $secretKey, mixed $mode = 'oprf'): \Closure
    {
        self::requireServerModes($mode);
        $pk = $mode === 'voprf' ? self::publicKeyFor($secretKey) : OprfAbsent::Absent;
        return static fn(string $blinded): array => self::blindEvaluate($secretKey, $blinded, $mode, $pk);
    }

    /** @param \Closure(string): array<string,mixed> $blindEval @param array<string,mixed> $revokedSet */
    public static function isRevokedPrivate(mixed $capId, \Closure $blindEval, array $revokedSet): bool
    {
        $data = self::encodeStrict($capId, 'capability id');
        $mode = $revokedSet['mode'];
        $b = self::blind($data, $mode);
        $res = $blindEval($b['blinded_element']);
        if ($mode === 'voprf') {
            $pk = $revokedSet['public_key'] ?? null;
            if (($res['proof'] ?? null) === null || $pk === null) {
                throw new \InvalidArgumentException('isRevokedPrivate(voprf): missing DLEQ proof or service public key');
            }
            $out = self::finalize($data, $b['blind'], $res['evaluated_element'], 'voprf', $res['proof'], $pk, $b['blinded_element']);
        } else {
            $out = self::finalize($data, $b['blind'], $res['evaluated_element'], 'oprf');
        }
        return isset($revokedSet['outputs'][self::toHex($out)]);
    }

    // ---- PCA layer: private rate limiting (a per-window POPRF token the service cannot link to the identifier) -----------------------------

    public static function rateToken(mixed $secretKey, mixed $identifier, mixed $window): string
    {
        return self::evaluatePoprf($secretKey, self::encodeStrict($identifier, 'identifier'), self::encodeStrict($window, 'window'));
    }

    public static function rateTokenHex(mixed $secretKey, mixed $identifier, mixed $window): string
    {
        return self::toHex(self::rateToken($secretKey, $identifier, $window));
    }

    /** @return \Closure(string,string): array{evaluated_element:string,proof:string} */
    public static function makeRateEvaluator(mixed $secretKey): \Closure
    {
        return static fn(string $blinded, string $window): array => self::blindEvaluatePoprf($secretKey, $blinded, self::encodeStrict($window, 'window'));
    }

    public static function privateRateToken(mixed $identifier, mixed $window, \Closure $blindEval, mixed $publicKey): string
    {
        $data = self::encodeStrict($identifier, 'identifier');
        $info = self::encodeStrict($window, 'window');
        $b = self::blindPoprf($data, $info, $publicKey);
        $res = $blindEval($b['blinded_element'], $window);
        if (($res['proof'] ?? null) === null) {
            throw new \InvalidArgumentException('privateRateToken: POPRF blind-evaluation did not return a DLEQ proof');
        }
        return self::finalizePoprf($data, $b['blind'], $res['evaluated_element'], $info, $res['proof'], $b['blinded_element'], $b['tweaked_key']);
    }
}

/** Counts hits per token (hex) in one window and reports whether the count is within the limit. */
final class OprfRateWindowCounter
{
    private int|float $limit;
    /** @var array<string,int> */
    private array $counts = [];

    public function __construct(mixed $limit)
    {
        if ($limit instanceof Num) {
            $limit = $limit->isInt() ? $limit->int() : $limit->float();
        }
        $ok = is_int($limit) || (is_float($limit) && is_finite($limit) && $limit == floor($limit));
        if (!$ok || $limit < 1) {
            throw new \TypeError('RateWindowCounter: limit must be a positive integer');
        }
        $this->limit = $limit;
    }

    /** @return array{count:int,allowed:bool} */
    public function hit(string $token): array
    {
        $key = bin2hex($token);
        $this->counts[$key] = ($this->counts[$key] ?? 0) + 1;
        return ['count' => $this->counts[$key], 'allowed' => $this->counts[$key] <= $this->limit];
    }

    public function count(string $token): int
    {
        return $this->counts[bin2hex($token)] ?? 0;
    }

    public function reset(): void
    {
        $this->counts = [];
    }
}
