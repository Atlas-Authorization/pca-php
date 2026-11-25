<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

/** The Groth16 library behind {@see ZkNative} cannot be loaded. */
final class ZkBackendMissing extends \RuntimeException
{
}

/**
 * Groth16 over BN254 and BLS12-381 for snarkjs artifacts through ext-ffi over `libpcazk` (arkworks behind a small C library,
 * pca_zk.h): the pairing check of a proof and the prover (circom witness wasm + snarkjs zkey). Opt-in: point ATLAS_PCA_LIBPCAZK at
 * the library (needs ffi.enable=true or preload), else the packaged native directory, else libpcazk.so. No pairing arithmetic is
 * implemented in PHP. A missing or mismatched library throws {@see ZkBackendMissing}; it never reports a proof valid or invalid.
 *
 * verify() answers the pairing question only: the caller keeps its own gates (envelope shape, circuit and system tags, pinned public
 * signals) in front. The default mode accepts what snarkjs `groth16.verify` accepts (it ignores the key's `nPublic` and `protocol`
 * and extra IC entries); `$strict` refuses those keys.
 */
final class ZkNative
{
    public const CURVE_BN254 = 0;
    public const CURVE_BLS12_381 = 1;
    /** verify() in the default mode only: the curve is the one the key names, read as snarkjs reads it (BN128, BN254, alt_bn128, bls12-381, ...). */
    public const CURVE_FROM_KEY = 2;

    private const FLAG_SNARKJS_COMPAT = 1;
    private const SEED_BYTES = 32;

    /** The prototypes of the library's header (pca_zk.h), unchanged. */
    private const CDEF = <<<'C'
        const char *pca_zk_version(void);
        const char *pca_zk_reason_text(int32_t reason);
        int32_t pca_zk_verify(int32_t curve, uint32_t flags, const uint8_t *vkey, size_t vkey_len, const uint8_t *proof, size_t proof_len,
                              const uint8_t *signals, size_t signals_len, int32_t *reason);
        int32_t pca_zk_prove(int32_t curve, const uint8_t *wasm, size_t wasm_len, const uint8_t *zkey, size_t zkey_len, const uint8_t *input,
                             size_t input_len, const uint8_t *seed, size_t seed_len, uint8_t **out, size_t *out_len);
        void pca_zk_free(uint8_t *ptr, size_t len);
        C;

    private static ?\FFI $lib = null;

    private static function lib(): \FFI
    {
        if (self::$lib !== null) {
            return self::$lib;
        }
        if (!extension_loaded('FFI')) {
            throw new ZkBackendMissing('Groth16 needs ext-ffi (ffi.enable=true)');
        }
        $env = getenv('ATLAS_PCA_LIBPCAZK');
        try {
            $lib = \FFI::cdef(self::CDEF, $env !== false && $env !== '' ? $env : (NativeDir::lib('pcazk') ?? 'libpcazk.so'));
            if (self::text($lib->pca_zk_version()) === '') {
                throw new ZkBackendMissing('libpcazk reports no version');
            }
        } catch (ZkBackendMissing $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new ZkBackendMissing('libpcazk could not be loaded (set ATLAS_PCA_LIBPCAZK to the library): ' . $e->getMessage(), 0, $e);
        }
        return self::$lib = $lib;
    }

    /** A `const char *` result: ext-ffi hands it over as a PHP string, or as a pointer on some builds. */
    private static function text(mixed $v): string
    {
        return is_string($v) ? $v : ($v === null ? '' : \FFI::string($v));
    }

    /** True when libpcazk can be loaded. */
    public static function available(): bool
    {
        try {
            self::lib();
            return true;
        } catch (ZkBackendMissing) {
            return false;
        }
    }

    /** The library's version text. */
    public static function version(): string
    {
        return self::text(self::lib()->pca_zk_version());
    }

    private static function in(string $b): ?\FFI\CData
    {
        if ($b === '') {
            return null;
        }
        $buf = self::lib()->new('uint8_t[' . strlen($b) . ']');
        \FFI::memcpy($buf, $b, strlen($b));
        return $buf;
    }

    private static function curve(int $curve, bool $fromKeyAllowed = false): void
    {
        if ($curve !== self::CURVE_BN254 && $curve !== self::CURVE_BLS12_381 && !($fromKeyAllowed && $curve === self::CURVE_FROM_KEY)) {
            throw new \InvalidArgumentException('zk native: the curve is CURVE_BN254 or CURVE_BLS12_381 (CURVE_FROM_KEY only for verify in the default mode)');
        }
    }

    /**
     * The Groth16 pairing check of a snarkjs proof: `$vkeyJson` is the verification_key.json object, `$proofJson` the proof.json object,
     * `$signalsJson` the public.json array of decimal strings (all UTF-8 JSON text). `reason` names why a proof was refused
     * (bad_json, bad_curve, not_in_subgroup, pairing_failed, ...). Throws {@see ZkBackendMissing} without the library and
     * \RuntimeException when the library reports an internal error: neither is ever turned into a verdict. With CURVE_FROM_KEY (default
     * mode only) the key's curve name alone picks the curve, as snarkjs does; an unknown name is refused.
     * @return array{ok:bool,reason:?string}
     */
    public static function verify(int $curve, string $vkeyJson, string $proofJson, string $signalsJson, bool $strict = false): array
    {
        self::curve($curve, !$strict);
        $lib = self::lib();
        if ($vkeyJson === '' || $proofJson === '' || $signalsJson === '') {
            return ['ok' => false, 'reason' => 'bad_json'];
        }
        $reason = $lib->new('int32_t');
        $rc = $lib->pca_zk_verify($curve, $strict ? 0 : self::FLAG_SNARKJS_COMPAT, self::in($vkeyJson), strlen($vkeyJson), self::in($proofJson), strlen($proofJson),
            self::in($signalsJson), strlen($signalsJson), \FFI::addr($reason));
        if ($rc === 1) {
            return ['ok' => true, 'reason' => null];
        }
        if ($rc === 0) {
            return ['ok' => false, 'reason' => self::text($lib->pca_zk_reason_text($reason->cdata))];
        }
        throw new \RuntimeException("zk native: verify failed with code $rc");
    }

    /**
     * Prove with Groth16: `$wasm` is circom's witness calculator (`<circuit>_js/<circuit>.wasm`), `$zkey` the snarkjs proving key,
     * `$inputJson` the circuit's input object. Returns the JSON text `{"proof":{...},"publicSignals":[...]}`. `$seed` (exactly 32 bytes)
     * makes the blinding deterministic and is for tests only; production passes null (operating-system randomness). Throws
     * \RuntimeException with the library's message when the witness, the key or the proof fails.
     * shortcut: the whole proving key is copied into native memory once more (a large circuit's key is gigabytes); map the file in
     * the library instead if that ever matters.
     */
    public static function prove(int $curve, string $wasm, string $zkey, string $inputJson, ?string $seed = null): string
    {
        self::curve($curve);
        if ($seed !== null && strlen($seed) !== self::SEED_BYTES) {
            throw new \InvalidArgumentException('zk native: a seed is ' . self::SEED_BYTES . ' bytes');
        }
        if ($wasm === '' || $zkey === '' || $inputJson === '') {
            throw new \InvalidArgumentException('zk native: the wasm, the zkey and the input must not be empty');
        }
        $lib = self::lib();
        $out = $lib->new('uint8_t*');
        $len = $lib->new('size_t');
        $rc = $lib->pca_zk_prove($curve, self::in($wasm), strlen($wasm), self::in($zkey), strlen($zkey), self::in($inputJson), strlen($inputJson),
            $seed === null ? null : self::in($seed), $seed === null ? 0 : self::SEED_BYTES, \FFI::addr($out), \FFI::addr($len));
        $text = '';
        if (!\FFI::isNull($out)) {
            $n = (int) $len->cdata;
            $text = $n === 0 ? '' : \FFI::string($out, $n);
            $lib->pca_zk_free($out, $n);
        }
        if ($rc !== 0) {
            throw new \RuntimeException("zk native: prove failed with code $rc" . ($text === '' ? '' : ": $text"));
        }
        return $text;
    }
}
