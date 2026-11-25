<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

/** The public gate policy: fixed-point weights, kappa-weighted weights and the budget bound (scale S, budget at S^2). */
final class FheRiskPolicy
{
    /** @param list<int> $weightsScaled @param list<int> $kappaWeightsScaled */
    public function __construct(
        public readonly int $scale,
        public readonly int $dim,
        public readonly array $weightsScaled,
        public readonly array $kappaWeightsScaled,
        public readonly int $budgetScaled,
        public readonly float $kappa = 1.0,
    ) {
    }
}

/** Full key material (each a base64 SEAL stream). The key holder keeps secretKey; the evaluator only ever gets the public key and Galois keys. */
final class FheKeyset
{
    public function __construct(
        public readonly string $secretKey,
        public readonly string $publicKey,
        public readonly string $relinKeys,
        public readonly string $galoisKeys,
    ) {
    }
}

/** The two encrypted gate outputs, each a base64 SEAL stream. */
final class FheEncryptedGate
{
    public function __construct(public readonly string $encRiskRaw, public readonly string $encSlack)
    {
    }
}

/** The opened verdict: rScaled is r at scale S^2 clamped to [0, S^2]; admit is slack >= 0. */
final class FheVerdict
{
    public function __construct(public readonly int $rScaled, public readonly int $slack, public readonly bool $admit)
    {
    }
}

/**
 * Homomorphic evaluation of PCA's risk gate (BFV on Microsoft SEAL), wire-compatible with the TypeScript package (node-seal 5.1.x bundles SEAL 4.1.x).
 * BFV is never reimplemented here: this binds SEAL's own C export API (native/src/seal/c, the one SEAL.NET binds) through ext-ffi, so the optional
 * native library libsealc (built from the pinned SEAL tag) is the only extra requirement: point ATLAS_PCA_LIBSEALC at it (needs ffi.enable=true or
 * preload). Every SEAL object crosses the API as the base64 of its SEAL native stream.
 */
final class FheSeal
{
    public const POLY_MODULUS_DEGREE = 8192;
    public const PLAIN_MODULUS_BITS = 30;
    public const PLAIN_MODULUS = 1073692673;
    public const SIGNED_BOUND = 536846336; // PLAIN_MODULUS // 2
    public const RISK_DIM = 6;
    private const MIN_NOISE_BUDGET_BITS = 16;
    private const BFV = 1;
    private const TC128 = 128;
    private const COMPR_NONE = 0;
    private const COMPR_ZSTD = 2;

    /** The slice of SEAL's C export API the gate uses (SEAL 4.1.x prototypes; HRESULT is long off Windows). */
    private const CDEF = <<<'C'

long EncParams_Create1(uint8_t scheme, void **enc_params);
long EncParams_Destroy(void *thisptr);
long EncParams_SetPolyModulusDegree(void *thisptr, uint64_t degree);
long EncParams_SetCoeffModulus(void *thisptr, uint64_t length, void **coeffs);
long EncParams_SetPlainModulus1(void *thisptr, void *modulus);
long CoeffModulus_BFVDefault(uint64_t poly_modulus_degree, int sec_level, uint64_t *length, void **coeffs);
long CoeffModulus_Create1(uint64_t poly_modulus_degree, uint64_t length, int *bit_sizes, void **coeffs);
long Modulus_Destroy(void *thisptr);
long Modulus_Value(void *thisptr, uint64_t *value);
long SEALContext_Create(void *encryptionParams, bool expand_mod_chain, int sec_level, void **context);
long SEALContext_Destroy(void *thisptr);
long SEALContext_ParametersSet(void *thisptr, bool *params_set);
long BatchEncoder_Create(void *context, void **batch_encoder);
long BatchEncoder_Destroy(void *thisptr);
long BatchEncoder_Encode2(void *thisptr, uint64_t count, int64_t *values, void *destination);
long BatchEncoder_Decode2(void *thisptr, void *plain, uint64_t *count, int64_t *destination, void *pool);
long BatchEncoder_GetSlotCount(void *thisptr, uint64_t *slot_count);
long KeyGenerator_Create1(void *context, void **key_generator);
long KeyGenerator_Destroy(void *thisptr);
long KeyGenerator_SecretKey(void *thisptr, void **secret_key);
long KeyGenerator_CreatePublicKey(void *thisptr, bool save_seed, void **public_key);
long KeyGenerator_CreateRelinKeys(void *thisptr, bool save_seed, void **relin_keys);
long KeyGenerator_CreateGaloisKeysAll(void *thisptr, bool save_seed, void **galois_keys);
long PublicKey_Create1(void **public_key);
long PublicKey_Destroy(void *thisptr);
long PublicKey_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);
long PublicKey_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);
long PublicKey_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
long SecretKey_Create1(void **secret_key);
long SecretKey_Destroy(void *thisptr);
long SecretKey_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);
long SecretKey_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);
long SecretKey_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
long KSwitchKeys_Create1(void **kswitch_keys);
long KSwitchKeys_Destroy(void *thisptr);
long KSwitchKeys_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);
long KSwitchKeys_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);
long KSwitchKeys_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
long Ciphertext_Create1(void *pool, void **cipher);
long Ciphertext_Create2(void *copy, void **cipher);
long Ciphertext_Destroy(void *thisptr);
long Ciphertext_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);
long Ciphertext_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);
long Ciphertext_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
long Plaintext_Create1(void *memoryPoolHandle, void **plaintext);
long Plaintext_Destroy(void *thisptr);
long Encryptor_Create(void *context, void *public_key, void *secret_key, void **encryptor);
long Encryptor_Encrypt(void *thisptr, void *plaintext, void *destination, void *pool_handle);
long Encryptor_Destroy(void *thisptr);
long Decryptor_Create(void *context, void *secret_key, void **decryptor);
long Decryptor_Destroy(void *thisptr);
long Decryptor_Decrypt(void *thisptr, void *encrypted, void *destination);
long Decryptor_InvariantNoiseBudget(void *thisptr, void *encrypted, int *invariant_noise_budget);
long Evaluator_Create(void *context, void **evaluator);
long Evaluator_Destroy(void *thisptr);
long Evaluator_Negate(void *thisptr, void *encrypted, void *destination);
long Evaluator_Add(void *thisptr, void *encrypted1, void *encrypted2, void *destination);
long Evaluator_AddPlain(void *thisptr, void *encrypted, void *plain, void *destination);
long Evaluator_MultiplyPlain(void *thisptr, void *encrypted, void *plain, void *destination, void *pool);
long Evaluator_RotateRows(void *thisptr, void *encrypted, int steps, void *galoisKeys, void *destination, void *pool);
long Evaluator_RotateColumns(void *thisptr, void *encrypted, void *galois_keys, void *destination, void *pool);

C;

    private static ?\FFI $lib = null;

    /** True when libsealc and ext-ffi are usable. */
    public static function available(): bool
    {
        try {
            self::lib();
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function lib(): \FFI
    {
        if (self::$lib === null) {
            if (!extension_loaded('ffi')) {
                throw new \RuntimeException('ext-ffi is required for FheSeal');
            }
            $path = getenv('ATLAS_PCA_LIBSEALC');
            self::$lib = \FFI::cdef(self::CDEF, $path !== false && $path !== '' ? $path : (NativeDir::lib('sealc') ?? 'libsealc.so'));
        }
        return self::$lib;
    }

    /** @param list<mixed> $args */
    private static function call(string $name, array $args): void
    {
        $hr = self::lib()->$name(...$args);
        if ($hr < 0) { // SEAL's HRESULT convention: negative is failure, S_FALSE (1) is success
            throw new \RuntimeException(sprintf('seal %s failed: 0x%08x', $name, $hr & 0xFFFFFFFF));
        }
    }

    /** Creates a handle with its create function and queues its destroy; handles are released in reverse order by release(). */
    private static function make(array &$scope, string $create, string $destroy, mixed ...$args): \FFI\CData
    {
        $h = self::lib()->new('void*');
        $args[] = \FFI::addr($h);
        self::call($create, $args);
        $scope[] = [$destroy, $h];
        return $h;
    }

    private static function release(array &$scope): void
    {
        foreach (array_reverse($scope) as [$destroy, $h]) {
            if ($destroy !== null) { // a null destroy only keeps a C array alive until the handles read out of it are released
                self::lib()->$destroy($h);
            }
        }
        $scope = [];
    }

    private static function bytes(int $n): \FFI\CData
    {
        return self::lib()->new("uint8_t[$n]");
    }

    /** Rejects anything that is not a well-formed SEAL stream envelope (magic, header size, compression mode, declared size == length). */
    public static function assertSealBlob(mixed $blob, string $what): string
    {
        if (!is_string($blob) || strlen($blob) < 24 || strlen($blob) % 4 !== 0 || preg_match('/^[A-Za-z0-9+\/]*={0,2}$/D', $blob) !== 1) {
            throw new \InvalidArgumentException("$what: not a serialized SEAL object (bad encoding)");
        }
        $b = base64_decode($blob, true);
        if ($b === false || strlen($b) < 16 || ord($b[0]) !== 0x5E || ord($b[1]) !== 0xA1 || ord($b[2]) !== 16 || ord($b[5]) > 2 || ord($b[6]) !== 0 || ord($b[7]) !== 0) {
            throw new \InvalidArgumentException("$what: not a serialized SEAL object (bad header)");
        }
        $size = unpack('P', substr($b, 8, 8))[1]; // a size over PHP_INT_MAX comes back negative and never equals the length
        if ($size !== strlen($b)) {
            throw new \InvalidArgumentException("$what: truncated or padded SEAL object (declared $size bytes, got " . strlen($b) . ')');
        }
        return $b;
    }

    /** The policy crosses a trust boundary: validate every coefficient exactly as the policy builder would have produced it. */
    public static function requirePolicy(mixed $p): void
    {
        if (!$p instanceof FheRiskPolicy) {
            throw new \InvalidArgumentException('policy must be an FheRiskPolicy');
        }
        foreach ([$p->weightsScaled, $p->kappaWeightsScaled] as $v) {
            foreach ($v as $x) {
                if (!is_int($x)) {
                    throw new \InvalidArgumentException('policy coefficients must be integers');
                }
            }
        }
        if ($p->scale <= 0) {
            throw new \InvalidArgumentException('policy.scale must be a positive integer');
        }
        foreach ([$p->budgetScaled, ...$p->weightsScaled, ...$p->kappaWeightsScaled] as $x) {
            if ($x <= -self::SIGNED_BOUND || $x >= self::SIGNED_BOUND) {
                throw new \InvalidArgumentException('policy coefficients must be integers with |value| < SIGNED_BOUND');
            }
        }
        if ($p->dim !== self::RISK_DIM) {
            throw new \InvalidArgumentException('policy.dim must be ' . self::RISK_DIM);
        }
        if (count($p->weightsScaled) !== self::RISK_DIM || count($p->kappaWeightsScaled) !== self::RISK_DIM) {
            throw new \InvalidArgumentException('policy weight vectors must have length ' . self::RISK_DIM);
        }
    }

    /** @return array{context: \FFI\CData, encoder: \FFI\CData, slots: int} */
    private static function context(array &$s): array
    {
        $f = self::lib();
        $parms = self::make($s, 'EncParams_Create1', 'EncParams_Destroy', self::BFV);
        self::call('EncParams_SetPolyModulusDegree', [$parms, self::POLY_MODULUS_DEGREE]);
        $n = $f->new('uint64_t');
        self::call('CoeffModulus_BFVDefault', [self::POLY_MODULUS_DEGREE, self::TC128, \FFI::addr($n), null]);
        $count = (int) $n->cdata;
        $coeffs = $f->new("void*[$count]");
        self::call('CoeffModulus_BFVDefault', [self::POLY_MODULUS_DEGREE, self::TC128, \FFI::addr($n), $coeffs]);
        $s[] = [null, $coeffs];
        for ($i = 0; $i < $count; $i++) {
            $s[] = ['Modulus_Destroy', $coeffs[$i]];
        }
        self::call('EncParams_SetCoeffModulus', [$parms, $count, $coeffs]);
        $bits = $f->new('int[1]');
        $bits[0] = self::PLAIN_MODULUS_BITS;
        $plain = $f->new('void*[1]');
        self::call('CoeffModulus_Create1', [self::POLY_MODULUS_DEGREE, 1, $bits, $plain]);
        $s[] = [null, $plain];
        $s[] = ['Modulus_Destroy', $plain[0]];
        $live = $f->new('uint64_t');
        self::call('Modulus_Value', [$plain[0], \FFI::addr($live)]);
        if ((int) $live->cdata !== self::PLAIN_MODULUS) {
            throw new \RuntimeException("plain modulus drift: live {$live->cdata} != documented " . self::PLAIN_MODULUS);
        }
        self::call('EncParams_SetPlainModulus1', [$parms, $plain[0]]);
        $ctx = self::make($s, 'SEALContext_Create', 'SEALContext_Destroy', $parms, true, self::TC128);
        $ok = $f->new('bool');
        self::call('SEALContext_ParametersSet', [$ctx, \FFI::addr($ok)]);
        if (!$ok->cdata) {
            throw new \RuntimeException('SEAL rejected the BFV parameters');
        }
        $enc = self::make($s, 'BatchEncoder_Create', 'BatchEncoder_Destroy', $ctx);
        $sc = $f->new('uint64_t');
        self::call('BatchEncoder_GetSlotCount', [$enc, \FFI::addr($sc)]);
        return ['context' => $ctx, 'encoder' => $enc, 'slots' => (int) $sc->cdata];
    }

    private const KINDS = ['public' => 'PublicKey', 'secret' => 'SecretKey', 'keys' => 'KSwitchKeys', 'cipher' => 'Ciphertext'];

    private static function newObj(array &$s, string $kind): \FFI\CData
    {
        $t = self::KINDS[$kind];
        return $kind === 'cipher' ? self::make($s, 'Ciphertext_Create1', 'Ciphertext_Destroy', null) : self::make($s, "{$t}_Create1", "{$t}_Destroy");
    }

    private static function loadObj(array $ctx, array &$s, string $kind, string $blob, string $what): \FFI\CData
    {
        $raw = self::assertSealBlob($blob, $what);
        $buf = self::bytes(strlen($raw));
        \FFI::memcpy($buf, $raw, strlen($raw));
        $p = self::newObj($s, $kind);
        $used = self::lib()->new('int64_t');
        self::call(self::KINDS[$kind] . '_Load', [$p, $ctx['context'], $buf, strlen($raw), \FFI::addr($used)]);
        return $p;
    }

    private static function saveObj(string $kind, \FFI\CData $p, int $compr = self::COMPR_ZSTD): string
    {
        $t = self::KINDS[$kind];
        $size = self::lib()->new('int64_t');
        self::call("{$t}_SaveSize", [$p, $compr, \FFI::addr($size)]);
        $n = (int) $size->cdata;
        $buf = self::bytes($n);
        $out = self::lib()->new('int64_t');
        self::call("{$t}_Save", [$p, $buf, $n, $compr, \FFI::addr($out)]);
        return base64_encode(\FFI::string($buf, (int) $out->cdata));
    }

    /** @param list<int> $values */
    private static function encode(array $ctx, array &$s, array $values): \FFI\CData
    {
        $slots = self::lib()->new('int64_t[' . $ctx['slots'] . ']');
        foreach (array_values($values) as $i => $v) {
            $slots[$i] = $v;
        }
        $pt = self::make($s, 'Plaintext_Create1', 'Plaintext_Destroy', null);
        self::call('BatchEncoder_Encode2', [$ctx['encoder'], $ctx['slots'], $slots, $pt]);
        return $pt;
    }

    /** Generates the key material (the secret key stays with the policy owner). */
    public static function keygen(): FheKeyset
    {
        $s = [];
        try {
            $ctx = self::context($s);
            $gen = self::make($s, 'KeyGenerator_Create1', 'KeyGenerator_Destroy', $ctx['context']);
            $sk = self::make($s, 'KeyGenerator_SecretKey', 'SecretKey_Destroy', $gen);
            $pk = self::make($s, 'KeyGenerator_CreatePublicKey', 'PublicKey_Destroy', $gen, false);
            $rk = self::make($s, 'KeyGenerator_CreateRelinKeys', 'KSwitchKeys_Destroy', $gen, false);
            $gk = self::make($s, 'KeyGenerator_CreateGaloisKeysAll', 'KSwitchKeys_Destroy', $gen, false);
            return new FheKeyset(self::saveObj('secret', $sk), self::saveObj('public', $pk), self::saveObj('keys', $rk), self::saveObj('keys', $gk));
        } finally {
            self::release($s);
        }
    }

    /** BFV-encrypts the quantized risk-input vector (length 6, each a non-negative integer below the signed bound). @param list<int> $inputsScaled */
    public static function encryptRiskInputs(string $publicKey, array $inputsScaled): string
    {
        if (count($inputsScaled) !== self::RISK_DIM) {
            throw new \InvalidArgumentException('inputsScaled must have length ' . self::RISK_DIM);
        }
        foreach ($inputsScaled as $v) {
            if (!is_int($v) || $v < 0 || $v >= self::SIGNED_BOUND) {
                throw new \InvalidArgumentException('each scaled input must be a non-negative integer below the signed bound');
            }
        }
        $s = [];
        try {
            $ctx = self::context($s);
            $pk = self::loadObj($ctx, $s, 'public', $publicKey, 'publicKey');
            $enc = self::make($s, 'Encryptor_Create', 'Encryptor_Destroy', $ctx['context'], $pk, null);
            $pt = self::encode($ctx, $s, $inputsScaled);
            $ct = self::newObj($s, 'cipher');
            self::call('Encryptor_Encrypt', [$enc, $pt, $ct, null]);
            return self::saveObj('cipher', $ct);
        } finally {
            self::release($s);
        }
    }

    /** Evaluates the gate blind with the reference's operation order (multiplyPlain, sumElements, negate, addPlain). Never builds a decryptor. */
    public static function evalRiskGate(string $publicKey, string $galoisKeys, string $encInputs, FheRiskPolicy $policy): FheEncryptedGate
    {
        self::requirePolicy($policy);
        $s = [];
        try {
            $ctx = self::context($s);
            $gk = self::loadObj($ctx, $s, 'keys', $galoisKeys, 'galoisKeys');
            $pk = self::loadObj($ctx, $s, 'public', $publicKey, 'publicKey');
            $ev = self::make($s, 'Evaluator_Create', 'Evaluator_Destroy', $ctx['context']);
            $enc = self::make($s, 'Encryptor_Create', 'Encryptor_Destroy', $ctx['context'], $pk, null);
            $x = self::loadObj($ctx, $s, 'cipher', $encInputs, 'encInputs');

            $total = static function (\FFI\CData $prod) use (&$s, $ev, $gk): \FFI\CData {
                $temp = self::make($s, 'Ciphertext_Create2', 'Ciphertext_Destroy', $prod);
                $dest = self::newObj($s, 'cipher');
                self::call('Evaluator_RotateColumns', [$ev, $temp, $gk, $dest, null]);
                self::call('Evaluator_Add', [$ev, $temp, $dest, $temp]);
                for ($steps = intdiv(self::POLY_MODULUS_DEGREE, 4); $steps >= 1; $steps = intdiv($steps, 2)) {
                    self::call('Evaluator_RotateRows', [$ev, $temp, $steps, $gk, $dest, null]);
                    self::call('Evaluator_RotateColumns', [$ev, $dest, $gk, $dest, null]);
                    self::call('Evaluator_Add', [$ev, $temp, $dest, $temp]);
                }
                return $temp;
            };
            $dot = static function (array $coeffs) use (&$s, $ctx, $ev, $enc, $x, $total): \FFI\CData {
                // SEAL refuses multiplyPlain by an all-zero plaintext (transparent result): the dot product is then a fresh encryption of zero.
                if (count(array_filter($coeffs, static fn(int $c): bool => $c !== 0)) === 0) {
                    $ct = self::newObj($s, 'cipher');
                    self::call('Encryptor_Encrypt', [$enc, self::encode($ctx, $s, []), $ct, null]);
                    return $ct;
                }
                $prod = self::newObj($s, 'cipher');
                self::call('Evaluator_MultiplyPlain', [$ev, $x, self::encode($ctx, $s, $coeffs), $prod, null]);
                return $total($prod);
            };

            $riskRaw = $dot($policy->weightsScaled);
            $kappaRisk = $dot($policy->kappaWeightsScaled);
            $neg = self::newObj($s, 'cipher');
            $slack = self::newObj($s, 'cipher');
            self::call('Evaluator_Negate', [$ev, $kappaRisk, $neg]);
            self::call('Evaluator_AddPlain', [$ev, $neg, self::encode($ctx, $s, [$policy->budgetScaled]), $slack]);
            return new FheEncryptedGate(self::saveObj('cipher', $riskRaw), self::saveObj('cipher', $slack));
        } finally {
            self::release($s);
        }
    }

    /** Decrypts the gate outputs and reads the verdict; fails closed when the noise budget is exhausted (wrong key, corrupt or foreign ciphertext). */
    public static function decryptVerdict(string $secretKey, string $encRiskRaw, string $encSlack, FheRiskPolicy $policy): FheVerdict
    {
        self::requirePolicy($policy);
        $s = [];
        try {
            $ctx = self::context($s);
            $sk = self::loadObj($ctx, $s, 'secret', $secretKey, 'secretKey');
            $dec = self::make($s, 'Decryptor_Create', 'Decryptor_Destroy', $ctx['context'], $sk);
            $cts = [self::loadObj($ctx, $s, 'cipher', $encRiskRaw, 'encRiskRaw'), self::loadObj($ctx, $s, 'cipher', $encSlack, 'encSlack')];
            foreach ($cts as $ct) {
                $nb = self::lib()->new('int');
                self::call('Decryptor_InvariantNoiseBudget', [$dec, $ct, \FFI::addr($nb)]);
                if ($nb->cdata < self::MIN_NOISE_BUDGET_BITS) {
                    throw new \InvalidArgumentException('decryptVerdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)');
                }
            }
            $first = function (\FFI\CData $ct) use (&$s, $ctx, $dec): int {
                $pt = self::make($s, 'Plaintext_Create1', 'Plaintext_Destroy', null);
                self::call('Decryptor_Decrypt', [$dec, $ct, $pt]);
                $n = self::lib()->new('uint64_t'); // in: the destination capacity (the slot count); the call fills the buffer
                $n->cdata = $ctx['slots'];
                $out = self::lib()->new('int64_t[' . $ctx['slots'] . ']');
                self::call('BatchEncoder_Decode2', [$ctx['encoder'], $pt, \FFI::addr($n), $out, null]);
                return (int) $out[0];
            };
            $raw = $first($cts[0]);
            $slack = $first($cts[1]);
            return new FheVerdict(min(max($raw, 0), $policy->scale * $policy->scale), $slack, $slack >= 0);
        } finally {
            self::release($s);
        }
    }

    /** Re-saves a base64 SEAL ciphertext uncompressed, for byte comparison independent of the zstd build. */
    public static function canonicalCipher(string $blob): string
    {
        $s = [];
        try {
            $ctx = self::context($s);
            return self::saveObj('cipher', self::loadObj($ctx, $s, 'cipher', $blob, 'ciphertext'), self::COMPR_NONE);
        } finally {
            self::release($s);
        }
    }
}
