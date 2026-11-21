<?php

declare(strict_types=1);

namespace Atlas\Pca;

/** Private state could not be created owner-only (and so was not created at all: the writers fail closed). */
final class PrivateFileError extends \RuntimeException
{
}

/**
 * Every private file and directory the library writes (approval stores, KV and revocation state, the mesh witness, SCITT log,
 * key material, harness files) is created through this class, owner-only AT CREATION.
 *
 * POSIX: the file or directory is created under a 0077 umask and then pinned to 0600 / 0700.
 *
 * Windows: a POSIX mode does nothing there, so the object is created through CreateFileW / CreateDirectoryW with a protected DACL
 * holding exactly one entry, full access for the current user, in the SECURITY_ATTRIBUTES of the creating call (there is no window
 * in which another process could open it first). PHP has no ACL API of its own, so this uses ext-ffi (kernel32, advapi32). Where
 * ext-ffi is not loaded on Windows, creating private state THROWS {@see PrivateFileError}: it never falls back to a file that
 * other local users can read. A file that already exists keeps the descriptor it was created with.
 *
 * Writers keep their own I/O: {@see create} makes the (empty) private file, then they open it by path as before; opening an existing
 * file never changes its descriptor. Exclusive-create writers pass `$exclusive = true` (CREATE_NEW / `x`).
 */
final class PrivateFile
{
    private const FILE_ALL = 'FA';

    private static ?\FFI $kernel = null;
    private static ?\FFI $advapi = null;
    /** @var array<string,mixed> */
    private static array $sa = [];
    private static ?string $sid = null;

    public static function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }

    /** Create a private directory (and, when `$recursive`, every missing parent the same way). False when it could not be created. */
    public static function mkdir(string $dir, bool $recursive = false): bool
    {
        if (is_dir($dir)) {
            return true;
        }
        if ($recursive) {
            $parent = dirname($dir);
            if ($parent !== $dir && $parent !== '' && !is_dir($parent) && !self::mkdir($parent, true)) {
                return false;
            }
        }
        if (!self::isWindows()) {
            return @mkdir($dir, 0700) || is_dir($dir);
        }
        $k = self::kernel();
        $ok = $k->CreateDirectoryW(self::wide($dir), self::attributes(true)) !== 0;
        return $ok || is_dir($dir);
    }

    /**
     * Make `$path` exist as an empty private file. With `$exclusive` an existing file is a failure (false), as `fopen($path, 'x')`
     * is; otherwise an existing file is left as it is. Throws {@see PrivateFileError} when owner-only creation is impossible.
     */
    public static function create(string $path, bool $exclusive = false): bool
    {
        if (!self::isWindows()) {
            $old = umask(0077);
            try {
                $fd = @fopen($path, $exclusive ? 'xb' : 'ab');
            } finally {
                umask($old);
            }
            if ($fd === false) {
                return false;
            }
            fclose($fd);
            @chmod($path, 0600);
            return true;
        }
        $k = self::kernel();
        // GENERIC_WRITE, shared read / write / delete, CREATE_NEW or OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL
        $h = $k->CreateFileW(self::wide($path), 0x40000000, 7, self::attributes(false), $exclusive ? 1 : 4, 0x80, null);
        if (\FFI::cast('intptr_t', $h)->cdata === -1) {
            return false;
        }
        $k->CloseHandle($h);
        return true;
    }

    /** fopen for a private file: a creating mode makes the file owner-only first (`x` stays exclusive). False on failure. @return resource|false */
    public static function open(string $path, string $mode)
    {
        $creates = $mode !== '' && in_array($mode[0], ['w', 'x', 'a', 'c'], true);
        if ($creates) {
            if (!self::create($path, $mode[0] === 'x')) {
                return false;
            }
            if ($mode[0] === 'x') {
                $mode = 'w' . substr($mode, 1); // the exclusive create above already made it: truncate the empty file
            }
        }
        return @fopen($path, $mode);
    }

    /** file_put_contents for a private file (created owner-only when missing; an existing file keeps its descriptor). */
    public static function write(string $path, string $data): int|false
    {
        if (!self::create($path)) {
            return false;
        }
        return @file_put_contents($path, $data);
    }

    /** A unique private file in `$dir` (tempnam, owner-only at creation). */
    public static function tempnam(string $dir, string $prefix): string|false
    {
        for ($i = 0; $i < 16; $i++) {
            $path = rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . $prefix . bin2hex(random_bytes(6));
            if (self::create($path, true)) {
                return $path;
            }
        }
        return false;
    }

    /** The current user's SID as a string (Windows). */
    public static function currentSid(): string
    {
        if (self::$sid !== null) {
            return self::$sid;
        }
        $a = self::advapi();
        $k = self::kernel();
        $tok = $a->new('void*');
        if ($a->OpenProcessToken($k->GetCurrentProcess(), 8, \FFI::addr($tok)) === 0) { // TOKEN_QUERY
            throw new PrivateFileError('owner-only files: cannot open the process token');
        }
        $len = $a->new('unsigned long');
        $a->GetTokenInformation($tok, 1, null, 0, \FFI::addr($len)); // TokenUser: the first call reports the size
        $buf = $a->new('char[' . max(1, (int)$len->cdata) . ']');
        if ($a->GetTokenInformation($tok, 1, $buf, (int)$len->cdata, \FFI::addr($len)) === 0) {
            throw new PrivateFileError('owner-only files: cannot read the current user from the process token');
        }
        $sidp = \FFI::cast('void**', $buf); // TOKEN_USER begins with the SID pointer
        $str = $a->new('char*');
        if ($a->ConvertSidToStringSidW($sidp[0], \FFI::addr($str)) === 0) {
            throw new PrivateFileError('owner-only files: cannot format the current user SID');
        }
        self::$sid = self::readWide($str);
        $k->LocalFree($str);
        return self::$sid;
    }

    /**
     * The DACL of `$path` as SDDL text (Windows), for read-back: an owner-only object reads `D:P(A;;FA;;;<current user SID>)`
     * (protected, so no inherited entries, and exactly one entry).
     */
    public static function aclSddl(string $path): string
    {
        $a = self::advapi();
        $psd = $a->new('void*');
        if ($a->GetNamedSecurityInfoW(self::wide($path), 1, 4, null, null, null, null, \FFI::addr($psd)) !== 0) { // SE_FILE_OBJECT, DACL
            throw new PrivateFileError('owner-only files: cannot read the security descriptor');
        }
        $str = $a->new('char*');
        if ($a->ConvertSecurityDescriptorToStringSecurityDescriptorW($psd, 1, 4, \FFI::addr($str), null) === 0) {
            throw new PrivateFileError('owner-only files: cannot format the security descriptor');
        }
        $text = self::readWide($str);
        self::kernel()->LocalFree($str);
        self::kernel()->LocalFree($psd);
        return $text;
    }

    /**
     * SECURITY_ATTRIBUTES holding the one-entry protected DACL. A directory's entry is inherited by what is created inside it
     * (container and object inherit), so files other code creates there, such as a database's journal, are owner-only too.
     */
    private static function attributes(bool $dir): mixed
    {
        $key = $dir ? 'dir' : 'file';
        if (isset(self::$sa[$key])) {
            return \FFI::addr(self::$sa[$key]);
        }
        $k = self::kernel();
        $a = self::advapi();
        $sddl = 'D:P(A;' . ($dir ? 'OICI' : '') . ';' . self::FILE_ALL . ';;;' . self::currentSid() . ')';
        $psd = $a->new('void*');
        $b = self::wide($sddl);
        if ($a->ConvertStringSecurityDescriptorToSecurityDescriptorW($b, 1, \FFI::addr($psd), null) === 0) {
            throw new PrivateFileError('owner-only files: cannot build the security descriptor');
        }
        $sa = $k->new('SECURITY_ATTRIBUTES', false); // owned by the process for its lifetime
        $sa->nLength = \FFI::sizeof($sa);
        $sa->lpSecurityDescriptor = $psd;
        $sa->bInheritHandle = 0;
        self::$sa[$key] = $sa;
        return \FFI::addr($sa);
    }

    private static function kernel(): \FFI
    {
        self::needFfi();
        return self::$kernel ??= \FFI::cdef(
            'typedef struct { unsigned long nLength; void* lpSecurityDescriptor; int bInheritHandle; } SECURITY_ATTRIBUTES;
             void* CreateFileW(const char* name, unsigned long access, unsigned long share, SECURITY_ATTRIBUTES* sa, unsigned long disposition, unsigned long flags, void* tmpl);
             int CreateDirectoryW(const char* name, SECURITY_ATTRIBUTES* sa);
             int CloseHandle(void* h);
             void* GetCurrentProcess(void);
             void* LocalFree(void* p);',
            'kernel32.dll'
        );
    }

    private static function advapi(): \FFI
    {
        self::needFfi();
        return self::$advapi ??= \FFI::cdef(
            'int OpenProcessToken(void* process, unsigned long access, void** token);
             int GetTokenInformation(void* token, int cls, void* info, unsigned long len, unsigned long* ret);
             int ConvertSidToStringSidW(void* sid, char** out);
             int ConvertStringSecurityDescriptorToSecurityDescriptorW(const char* sddl, unsigned long rev, void** sd, unsigned long* size);
             int ConvertSecurityDescriptorToStringSecurityDescriptorW(void* sd, unsigned long rev, unsigned long info, char** out, unsigned long* size);
             unsigned long GetNamedSecurityInfoW(const char* name, int type, unsigned long info, void** owner, void** group, void** dacl, void** sacl, void** sd);',
            'advapi32.dll'
        );
    }

    private static function needFfi(): void
    {
        if (!extension_loaded('ffi')) {
            throw new PrivateFileError('owner-only private state on Windows needs the FFI extension (it is not loaded): refusing to write a file other local users could read');
        }
    }

    /** A NUL-terminated UTF-16LE copy of `$s` in C memory (LPCWSTR). */
    private static function wide(string $s): mixed
    {
        $w = function_exists('mb_convert_encoding') ? mb_convert_encoding($s, 'UTF-16LE', 'UTF-8') : iconv('UTF-8', 'UTF-16LE', $s);
        $n = strlen((string)$w) + 2;
        $buf = \FFI::new('char[' . $n . ']', false);
        \FFI::memset($buf, 0, $n);
        \FFI::memcpy($buf, (string)$w, $n - 2);
        return $buf;
    }

    /** Read a NUL-terminated UTF-16LE string from C memory. */
    private static function readWide(mixed $p): string
    {
        $u = \FFI::cast('unsigned short*', $p);
        $raw = '';
        for ($i = 0; $u[$i] !== 0; $i++) {
            $raw .= pack('v', $u[$i]);
        }
        return (string)(function_exists('mb_convert_encoding') ? mb_convert_encoding($raw, 'UTF-8', 'UTF-16LE') : iconv('UTF-16LE', 'UTF-8', $raw));
    }
}
