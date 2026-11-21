<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

/**
 * The WHATWG URL class through Ada's C API (the parser Node uses; ext-ffi over libada): parse a URL, apply
 * URLSearchParams.set to its query and serialize it. The release package carries libada for every platform, so this is the
 * default path wherever ext-ffi is enabled; ATLAS_PCA_LIBADA overrides the packaged copy (a source checkout falls back to
 * libada.so). Without a loadable library available() is false. Nothing here is on a verification path.
 * The declarations below are the ones of ada_c.h in the pinned Ada 4.0.0 release (`ada_url` and `ada_url_search_params` are
 * `void*` there).
 */
final class AdaUrl
{
    private const CDEF = <<<'C'
        typedef struct { const char* data; size_t length; } ada_string;
        typedef struct { const char* data; size_t length; } ada_owned_string;
        void* ada_parse(const char* input, size_t length);
        bool ada_is_valid(void* url);
        void ada_free(void* url);
        void ada_free_owned_string(ada_owned_string owned);
        ada_string ada_get_href(void* url);
        ada_string ada_get_search(void* url);
        void ada_set_search(void* url, const char* input, size_t length);
        void* ada_parse_search_params(const char* input, size_t length);
        void ada_free_search_params(void* params);
        void ada_search_params_set(void* params, const char* key, size_t key_length, const char* value, size_t value_length);
        ada_owned_string ada_search_params_to_string(void* params);
        C;

    private static ?\FFI $lib = null;
    private static bool $tried = false;

    private static function lib(): ?\FFI
    {
        if (self::$tried) {
            return self::$lib;
        }
        self::$tried = true;
        if (!extension_loaded('FFI')) {
            return null;
        }
        $env = getenv('ATLAS_PCA_LIBADA');
        try {
            $lib = \FFI::cdef(self::CDEF, $env !== false && $env !== '' ? $env : (NativeDir::lib('ada') ?? 'libada.so'));
            self::$lib = $lib;
            // a real probe: a library that does not serialize as the standard does is never reported available
            if (self::withParams('HTTPS://Example.COM/a/../b?x=1', [['x', 'a b']]) !== 'https://example.com/b?x=a+b') {
                self::$lib = null;
            }
        } catch (\Throwable) {
            self::$lib = null;
        }
        return self::$lib;
    }

    /** True iff ext-ffi and a libada exposing the C API are loadable. */
    public static function available(): bool
    {
        return self::lib() !== null;
    }

    private static function buf(\FFI $f, string $s): \FFI\CData
    {
        $b = $f->new('char[' . (strlen($s) + 1) . ']');
        \FFI::memcpy($b, $s, strlen($s));
        return $b;
    }

    private static function str(\FFI\CData $s): string
    {
        return $s->length === 0 ? '' : \FFI::string($s->data, $s->length);
    }

    /**
     * `u = new URL($url)`, `u.searchParams.set(name, value)` for each pair in order, `u.toString()`; null when the URL does not parse.
     * Throws when libada is not available.
     * @param list<array{0:string,1:string}> $pairs
     */
    public static function withParams(string $url, array $pairs): ?string
    {
        $f = self::$lib ?? self::lib() ?? throw new \RuntimeException('AdaUrl: set ATLAS_PCA_LIBADA to a libada build');
        $u = $f->ada_parse(self::buf($f, $url), strlen($url));
        if ($u === null || \FFI::isNull($u)) {
            return null;
        }
        try {
            if (!$f->ada_is_valid($u)) {
                return null;
            }
            $search = ltrim(self::str($f->ada_get_search($u)), '?');
            $sp = $f->ada_parse_search_params(self::buf($f, $search), strlen($search));
            try {
                foreach ($pairs as [$k, $v]) {
                    $f->ada_search_params_set($sp, self::buf($f, $k), strlen($k), self::buf($f, $v), strlen($v));
                }
                $owned = $f->ada_search_params_to_string($sp);
                $qs = self::str($owned);
                $f->ada_free_owned_string($owned);
            } finally {
                $f->ada_free_search_params($sp);
            }
            $f->ada_set_search($u, self::buf($f, $qs), strlen($qs));
            return self::str($f->ada_get_href($u));
        } finally {
            $f->ada_free($u);
        }
    }
}
