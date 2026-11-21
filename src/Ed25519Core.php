<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * libsodium's Ed25519 group and scalar primitives. ext-sodium exposes only some of them (never crypto_core_ed25519_*), so each call
 * uses the extension function when it exists and otherwise the same libsodium routine over ext-ffi. Failures throw SodiumException,
 * as the extension functions do.
 */
final class Ed25519Core
{
    private static bool $tried = false;
    private static ?\FFI $ffi = null;

    private const CDEF = <<<'CDEF'
        int crypto_core_ed25519_add(char *r, const char *p, const char *q);
        int crypto_core_ed25519_sub(char *r, const char *p, const char *q);
        int crypto_core_ed25519_is_valid_point(const char *p);
        void crypto_core_ed25519_scalar_add(char *z, const char *x, const char *y);
        void crypto_core_ed25519_scalar_sub(char *z, const char *x, const char *y);
        void crypto_core_ed25519_scalar_mul(char *z, const char *x, const char *y);
        int crypto_core_ed25519_scalar_invert(char *recip, const char *s);
        void crypto_core_ed25519_scalar_reduce(char *r, const char *s);
        int crypto_scalarmult_ed25519_base_noclamp(char *q, const char *n);
        int crypto_scalarmult_ed25519_noclamp(char *q, const char *n, const char *p);
        int sodium_init(void);
        CDEF;

    public static function available(): bool
    {
        return function_exists('sodium_crypto_core_ed25519_add') || self::ffi() !== null;
    }

    private static function ffi(): ?\FFI
    {
        if (self::$tried) {
            return self::$ffi;
        }
        self::$tried = true;
        if (!extension_loaded('FFI')) {
            return null;
        }
        $paths = [null, 'libsodium.so.26', 'libsodium.so.23', 'libsodium.so', 'libsodium.dylib', 'libsodium.dll', 'libsodium-26.dll'];
        foreach (['/usr/lib/*-linux-gnu/libsodium.so*', '/usr/lib64/libsodium.so*', '/usr/lib/libsodium.so*', '/usr/local/lib/libsodium*.dylib',
            '/opt/homebrew/lib/libsodium*.dylib', '/opt/homebrew/opt/libsodium/lib/libsodium*.dylib'] as $g) {
            foreach (glob($g) ?: [] as $f) {
                $paths[] = $f;
            }
        }
        foreach ($paths as $p) {
            try {
                $f = $p === null ? \FFI::cdef(self::CDEF) : \FFI::cdef(self::CDEF, $p);
                $f->sodium_init();
                $f->crypto_core_ed25519_is_valid_point(str_repeat("\0", 32));
                return self::$ffi = $f;
            } catch (\Throwable) {
                // try the next candidate
            }
        }
        return null;
    }

    private static function lib(): \FFI
    {
        return self::ffi() ?? throw new \SodiumException('libsodium is not reachable over ext-ffi');
    }

    private static function out(int $rc, \FFI\CData $buf, int $n = 32): string
    {
        if ($rc !== 0) {
            throw new \SodiumException('libsodium refused the operation');
        }
        return \FFI::string($buf, $n);
    }

    public static function add(string $p, string $q): string
    {
        if (function_exists('sodium_crypto_core_ed25519_add')) {
            return sodium_crypto_core_ed25519_add($p, $q);
        }
        self::len($p, 32);
        self::len($q, 32);
        $o = \FFI::new('char[32]');
        return self::out(self::lib()->crypto_core_ed25519_add($o, $p, $q), $o);
    }

    public static function sub(string $p, string $q): string
    {
        if (function_exists('sodium_crypto_core_ed25519_sub')) {
            return sodium_crypto_core_ed25519_sub($p, $q);
        }
        self::len($p, 32);
        self::len($q, 32);
        $o = \FFI::new('char[32]');
        return self::out(self::lib()->crypto_core_ed25519_sub($o, $p, $q), $o);
    }

    public static function isValidPoint(string $p): bool
    {
        if (!self::isSafePoint($p)) {
            return false;
        }
        if (function_exists('sodium_crypto_core_ed25519_is_valid_point')) {
            return sodium_crypto_core_ed25519_is_valid_point($p);
        }
        return strlen($p) === 32 && self::lib()->crypto_core_ed25519_is_valid_point($p) === 1;
    }

    /**
     * Strict point check by the group law alone: canonical 32-byte encoding on the curve, not small order (8P is not the identity, so
     * not the identity itself) and L*P is the identity compared in full. libsodium 1.0.20 and older accept a mixed-order point (P plus
     * order-2 torsion) through is_valid_point because their subgroup test reads only X of L*P, so this never trusts that query.
     */
    public static function isSafePoint(string $p): bool
    {
        if (strlen($p) !== 32) {
            return false;
        }
        $id = "\x01" . str_repeat("\0", 31);
        try {
            if (self::add($p, $id) !== $p) {
                return false;
            }
            $q = $p;
            for ($i = 0; $i < 3; $i++) {
                $q = self::add($q, $q);
            }
            if ($q === $id) {
                return false;
            }
            $acc = $id;
            foreach (str_split(hex2bin('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed')) as $byte) {
                for ($bit = 7; $bit >= 0; $bit--) {
                    $acc = self::add($acc, $acc);
                    if ((ord($byte) >> $bit) & 1) {
                        $acc = self::add($acc, $p);
                    }
                }
            }
            return $acc === $id;
        } catch (\SodiumException) {
            return false;
        }
    }

    public static function scalarAdd(string $a, string $b): string
    {
        return function_exists('sodium_crypto_core_ed25519_scalar_add') ? sodium_crypto_core_ed25519_scalar_add($a, $b) : self::scalar2('add', $a, $b);
    }

    public static function scalarSub(string $a, string $b): string
    {
        return function_exists('sodium_crypto_core_ed25519_scalar_sub') ? sodium_crypto_core_ed25519_scalar_sub($a, $b) : self::scalar2('sub', $a, $b);
    }

    public static function scalarMul(string $a, string $b): string
    {
        return function_exists('sodium_crypto_core_ed25519_scalar_mul') ? sodium_crypto_core_ed25519_scalar_mul($a, $b) : self::scalar2('mul', $a, $b);
    }

    public static function scalarInvert(string $a): string
    {
        if (function_exists('sodium_crypto_core_ed25519_scalar_invert')) {
            return sodium_crypto_core_ed25519_scalar_invert($a);
        }
        self::len($a, 32);
        $o = \FFI::new('char[32]');
        return self::out(self::lib()->crypto_core_ed25519_scalar_invert($o, $a), $o);
    }

    /** A 64-byte little-endian value reduced mod L. */
    public static function scalarReduce(string $a): string
    {
        if (function_exists('sodium_crypto_core_ed25519_scalar_reduce')) {
            return sodium_crypto_core_ed25519_scalar_reduce($a);
        }
        self::len($a, 64);
        $o = \FFI::new('char[32]');
        self::lib()->crypto_core_ed25519_scalar_reduce($o, $a);
        return \FFI::string($o, 32);
    }

    public static function mulBaseNoclamp(string $n): string
    {
        if (function_exists('sodium_crypto_scalarmult_ed25519_base_noclamp')) {
            return sodium_crypto_scalarmult_ed25519_base_noclamp($n);
        }
        self::len($n, 32);
        $o = \FFI::new('char[32]');
        return self::out(self::lib()->crypto_scalarmult_ed25519_base_noclamp($o, $n), $o);
    }

    public static function mulNoclamp(string $n, string $p): string
    {
        if (function_exists('sodium_crypto_scalarmult_ed25519_noclamp')) {
            return sodium_crypto_scalarmult_ed25519_noclamp($n, $p);
        }
        self::len($n, 32);
        self::len($p, 32);
        $o = \FFI::new('char[32]');
        return self::out(self::lib()->crypto_scalarmult_ed25519_noclamp($o, $n, $p), $o);
    }

    private static function scalar2(string $op, string $a, string $b): string
    {
        self::len($a, 32);
        self::len($b, 32);
        $o = \FFI::new('char[32]');
        self::lib()->{'crypto_core_ed25519_scalar_' . $op}($o, $a, $b);
        return \FFI::string($o, 32);
    }

    private static function len(string $s, int $n): void
    {
        if (strlen($s) !== $n) {
            throw new \SodiumException("expected $n bytes");
        }
    }
}
