<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';

/**
 * Shared helpers of the K3 artifacts (FreshAt, K3): the JS-shaped predicates the TypeScript reference uses (isObj / isSafeInt /
 * isStr) and the domain-separated strict Ed25519 body signature (domain bytes || strict canonical JSON). Total: never throws.
 */
final class K3Sig
{
    private const MAX_SAFE = 9007199254740991.0;

    public static function isObj(mixed $x): bool
    {
        return $x instanceof Obj;
    }

    public static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** A JSON number (Num or native) as a finite float, else null. */
    public static function num(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $v !== null && is_finite($v) ? $v : null;
    }

    /** Number.isSafeInteger */
    public static function anySafeInt(mixed $x): bool
    {
        $v = self::num($x);
        return $v !== null && floor($v) === $v && abs($v) <= self::MAX_SAFE;
    }

    /** isSafeInt of the reference: a non-negative safe integer. */
    public static function isSafeInt(mixed $x): bool
    {
        return self::anySafeInt($x) && self::num($x) >= 0;
    }

    /** UTF-16 code units of a string (what JS `.length` counts). */
    public static function utf16Len(string $s): int
    {
        return intdiv(strlen((string)mb_convert_encoding($s, 'UTF-16LE', 'UTF-8')), 2);
    }

    public static function isStr(mixed $x, int $max = 512): bool
    {
        return is_string($x) && $x !== '' && self::utf16Len($x) <= $max;
    }

    /** True iff the value is the number `$n`. */
    public static function isNumber(mixed $x, float $n): bool
    {
        return self::num($x) === $n;
    }

    /** True iff `$sig` is a canonical 64-byte b64u signature by `$signer` over `$domain . strictCanonical($body)`. */
    public static function verifyBody(string $domain, mixed $body, mixed $signer, mixed $sig): bool
    {
        try {
            return is_string($sig) && is_string($signer) && Pca::unb64u($sig, 64) !== null
                && Pca::verifyEd25519B64u($signer, $domain . Json::canonicalizeStrict($body), $sig);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Ordering of JS `Array.prototype.sort()` on strings (UTF-16 code units). */
    public static function sortedUtf16(array $strings): array
    {
        usort($strings, static fn(string $a, string $b): int => strcmp(
            (string)mb_convert_encoding($a, 'UTF-16BE', 'UTF-8'), (string)mb_convert_encoding($b, 'UTF-16BE', 'UTF-8')));
        return $strings;
    }
}
