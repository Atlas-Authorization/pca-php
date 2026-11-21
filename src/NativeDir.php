<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Where the release package keeps its prebuilt native libraries: native/<os>-<arch>/ (linux-x64, linux-arm64, darwin-x64, darwin-arm64,
 * windows-x64). The FFI loaders look here first, then at their environment variable and the system paths. A source checkout has no
 * such directory, so nothing changes there.
 */
final class NativeDir
{
    public static function dir(): string
    {
        $os = match (PHP_OS_FAMILY) {
            'Windows' => 'windows',
            'Darwin' => 'darwin',
            default => 'linux',
        };
        $arch = match (strtolower(php_uname('m'))) {
            'x86_64', 'amd64' => 'x64',
            'arm64', 'aarch64' => 'arm64',
            default => php_uname('m'),
        };
        return __DIR__ . '/../native/' . $os . '-' . $arch;
    }

    /** The packaged library for a stem ('blst', 'fndsa', 'lweot', 'pcazk', 'ada', 'sealc', 'atlas_less', 'crypto'), or null when this package has none. */
    public static function lib(string $stem): ?string
    {
        $names = PHP_OS_FAMILY === 'Windows' ? [$stem . '.dll'] : (PHP_OS_FAMILY === 'Darwin' ? ["lib$stem.dylib"] : ["lib$stem.so"]);
        foreach ($names as $n) {
            $p = self::dir() . '/' . $n;
            if (is_file($p)) {
                return $p;
            }
        }
        return null;
    }
}
