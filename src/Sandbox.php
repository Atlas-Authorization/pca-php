<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/WhatwgUrl.php';

/** One slot of the capability table. */
final class SandboxSlot
{
    /** @param list<int> $children */
    public function __construct(
        public Obj $op,
        public string $paramsDigest,
        public mixed $opId,
        public float $uses,
        public float $expiresAt,
        public bool $revoked = false,
        public array $children = [],
    ) {
    }
}

/** Append-only hash chain of use receipts: every handle use and every egress decision, refusals included. */
final class SandboxReceiptLog
{
    /** @var list<Obj> */
    public array $entries = [];
    private \Closure $now;
    private ?\Closure $sign;

    /** @param ?\Closure(): mixed $now the clock (a Num / int of milliseconds) @param ?\Closure(string): string $sign */
    public function __construct(?\Closure $now = null, ?\Closure $sign = null)
    {
        $this->now = $now ?? static fn() => new Num((string)(int)floor(microtime(true) * 1000));
        $this->sign = $sign;
    }

    public function append(mixed $runtimeClass, Obj $body): Obj
    {
        $r = new Obj();
        $r->set('v', new Num('1'));
        $r->set('seq', new Num((string)count($this->entries)));
        $r->set('prev', $this->entries === [] ? Sandbox::GENESIS : $this->entries[count($this->entries) - 1]->get('digest'));
        $r->set('at', ($this->now)());
        $r->set('runtime_class', $runtimeClass);
        foreach ($body->keys() as $k) { // the body is spread last, as in the reference
            $r->set($k, $body->get($k));
        }
        $digest = Pca::hashCanonical($r);
        $r->set('digest', $digest);
        if ($this->sign !== null) {
            $r->set('sig', ($this->sign)($digest));
        }
        $this->entries[] = $r;
        return $r;
    }
}

/**
 * Policy logic of the PCA sandbox (the reference's pca-sandbox): runtime classes and signed runtime claims, the receipt hash
 * chain, the capability handle table, the egress admission policy, the OS-profile generators (seccomp / Landlock / macOS) and
 * the reference WebAssembly tool builders. Not ported: the WebAssembly / component hosts (they run a wasm engine) and the
 * attestation-verifier glue. A class is a claim by the host operator; nothing here proves an OS profile was applied.
 * The egress forward proxy server is {@see SandboxEgress}.
 */
final class Sandbox
{
    public const IMPORT_MODULE = 'pca:act';
    public const ALLOWED_IMPORTS = ['invoke', 'handle_count', 'handle_verb'];
    public const USE_ERR = ['unknown_handle' => -1, 'spent' => -2, 'out_too_small' => -3, 'bad_memory' => -4, 'executor_error' => -5, 'no_executor' => -6];
    public const RUNTIME_CLASSES = ['none', 'os_confined', 'egress_default_deny', 'wasi_no_ambient'];
    public const GENESIS = 'genesis';
    public const RUNTIME_CLAIM_DOMAIN = "atlas-pca/runtime-class-claim/v1\0";

    // ---- helpers ------------------------------------------------------------------------------------------------------------

    private static function nullish(mixed $v): bool
    {
        return $v === null || $v instanceof Undef;
    }

    /** Number.isInteger of a JSON number. */
    private static function isInt(mixed $v): bool
    {
        $f = K3Sig::num($v);
        return $f !== null && floor($f) === $f;
    }

    private static function fl(mixed $v): float
    {
        return (float)K3Sig::num($v);
    }

    /** Own member of an object value (undefined for anything else). */
    private static function get(mixed $o, string $k): mixed
    {
        return Jsx::get($o, $k);
    }

    private static function jsText(mixed $v): string
    {
        return $v instanceof Undef ? 'undefined' : Js::str($v);
    }

    /** Obj tree of a PHP assoc / list structure. */
    private static function obj(mixed $v): mixed
    {
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::obj(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string)$k, self::obj($x));
            }
            return $o;
        }
        return $v;
    }

    // ---- runtime classes / receipts -------------------------------------------------------------------------------------------

    /** True only when both names are known and `$attested` is at least `$required`. An unknown name never satisfies. */
    public static function satisfiesRuntimeClass(mixed $attested, mixed $required): bool
    {
        $a = is_string($attested) ? array_search($attested, self::RUNTIME_CLASSES, true) : false;
        $r = is_string($required) ? array_search($required, self::RUNTIME_CLASSES, true) : false;
        return $a !== false && $r !== false && $a >= $r;
    }

    public static function moduleConsts(): Obj
    {
        return self::obj([
            'IMPORT_MODULE' => self::IMPORT_MODULE, 'ALLOWED_IMPORTS' => self::ALLOWED_IMPORTS, 'USE_ERR' => self::USE_ERR,
            'GENESIS' => self::GENESIS, 'RUNTIME_CLASSES' => self::RUNTIME_CLASSES, 'DOMAIN' => self::RUNTIME_CLAIM_DOMAIN,
        ]);
    }

    /** Recompute the chain. Fails on a bad digest, a broken link, a gap, a reorder, or (with `$verifySig`) a bad signature. */
    public static function verifyReceiptChain(mixed $receipts, ?\Closure $verifySig = null): Obj
    {
        if (!is_array($receipts) || !array_is_list($receipts)) {
            throw new \TypeError('receipts is not iterable');
        }
        $prev = self::GENESIS;
        foreach ($receipts as $i => $r) {
            if ($r === null) {
                throw new \TypeError('receipt is null');
            }
            $fail = static fn(string $why): Obj => Obj::of(['ok' => false, 'at' => new Num((string)$i), 'reason' => $why]);
            $v = K3Sig::num(self::get($r, 'v'));
            $seq = K3Sig::num(self::get($r, 'seq'));
            if ($v !== 1.0 || $seq === null || $seq !== (float)$i) {
                return $fail('bad_seq');
            }
            $p = self::get($r, 'prev');
            if (!is_string($p) || $p !== $prev) {
                return $fail('broken_link');
            }
            $digest = $r->get('digest');
            $sig = $r->get('sig');
            if (!is_string($digest) || Pca::hashCanonical($r->without('digest', 'sig')) !== $digest) {
                return $fail('bad_digest');
            }
            if ($verifySig !== null && (!is_string($sig) || !$verifySig($digest, $sig))) {
                return $fail('bad_sig');
            }
            $prev = $digest;
        }
        return Obj::of(['ok' => true]);
    }

    // ---- authorized operations ------------------------------------------------------------------------------------------------

    /**
     * True only if `$result` allowed exactly this operation (verb, resource, params digest). `$result` is an object with `allow`
     * (or `ok`) and a bound `operation` {verb, resource, params_digest}.
     */
    public static function isAuthorizedFor(mixed $result, mixed $operation): bool
    {
        $allow = self::get($result, 'allow');
        $ok = $allow instanceof Undef ? self::get($result, 'ok') : $allow;
        $bound = self::get($result, 'operation');
        $valid = $operation instanceof Obj && is_string($operation->get('verb')) && $operation->get('verb') !== ''
            && is_string($operation->get('resource')) && $operation->get('resource') !== '' && $operation->get('params') instanceof Obj;
        if (!Jsx::truthy($ok) || !Jsx::truthy($bound) || !$valid) {
            return false;
        }
        try {
            return self::get($bound, 'verb') === $operation->get('verb') && self::get($bound, 'resource') === $operation->get('resource')
                && self::get($bound, 'params_digest') === Pca::hashCanonical($operation->get('params'));
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- OS policy ------------------------------------------------------------------------------------------------------------

    private static function checkPath(mixed $p): string
    {
        // absolute, normalized, and only characters that need no escaping in a seccomp / Landlock / SBPL string: refuse, never escape
        if (!is_string($p) || preg_match('#\A/[A-Za-z0-9._+@=,:~ /-]*\z#', $p) !== 1 || str_contains($p, '//') || (strlen($p) > 1 && str_ends_with($p, '/'))
            || array_intersect(explode('/', $p), ['.', '..']) !== []) {
            throw new \InvalidArgumentException('bad_path');
        }
        return $p;
    }

    /** `for (const v of x ?? [])`: an array or a string iterates, any other value is not iterable. @return list<mixed> */
    private static function iterate(mixed $x): array
    {
        if (self::nullish($x)) {
            return [];
        }
        if (is_array($x) && array_is_list($x)) {
            return $x;
        }
        if (is_string($x)) {
            return $x === '' ? [] : [new Undef()]; // a character is not an object: its path is undefined
        }
        throw new \TypeError('not iterable');
    }

    /**
     * Validate, merge and sort the needs of the authorized operations into a sandbox policy {v, fs: {read, write, exec},
     * net: {proxy, hosts}}. `write` implies read of the same path; network access exists only through the egress proxy.
     */
    public static function policyFromNeeds(mixed $needs, mixed $proxyPort = null): Obj
    {
        if (!is_array($needs) || !array_is_list($needs)) {
            throw new \TypeError('needs is not iterable');
        }
        $read = [];
        $write = [];
        $ex = [];
        $hosts = [];
        foreach ($needs as $n) {
            if ($n === null) {
                throw new \TypeError('need is null');
            }
            foreach (self::iterate(self::get($n, 'fs')) as $f) {
                if ($f === null) {
                    throw new \TypeError('fs entry is null');
                }
                $p = self::checkPath(self::get($f, 'path'));
                $mode = self::get($f, 'mode');
                if ($mode === 'x') {
                    $ex[$p] = true;
                } elseif ($mode === 'r' || $mode === 'rw') {
                    $read[$p] = true;
                    if ($mode === 'rw') {
                        $write[$p] = true;
                    }
                } else {
                    throw new \InvalidArgumentException('bad_mode');
                }
            }
            foreach (self::iterate(self::get($n, 'net')) as $h) {
                if ($h === null) {
                    throw new \TypeError('net entry is null');
                }
                $host = self::get($h, 'host');
                $port = self::get($h, 'port');
                $text = self::jsText($host);
                $pf = K3Sig::num($port);
                if (preg_match('/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/', $text) !== 1 || !self::isInt($port) || $pf < 1 || $pf > 65535) {
                    throw new \InvalidArgumentException('bad_net_need');
                }
                $hosts[$text . ':' . Js::str($port)] = true;
            }
        }
        if ($hosts !== [] && $proxyPort === null) {
            throw new \InvalidArgumentException('net_needs_proxy: network access exists only through the egress proxy; pass its port');
        }
        if ($proxyPort !== null) {
            $pf = K3Sig::num($proxyPort);
            if (!self::isInt($proxyPort) || $pf < 1 || $pf > 65535) {
                throw new \InvalidArgumentException('bad_proxy_port');
            }
        }
        $keys = static function (array $s): array {
            $k = array_map('strval', array_keys($s));
            sort($k, SORT_STRING);
            return $k;
        };
        return self::obj([
            'v' => 1, 'fs' => ['read' => $keys($read), 'write' => $keys($write), 'exec' => $keys($ex)],
            'net' => ['proxy' => $proxyPort === null ? null : ['host' => '127.0.0.1', 'port' => $proxyPort], 'hosts' => $keys($hosts)],
        ]);
    }

    /**
     * Compile the OS policy from what was actually authorized: only operations that isAuthorizedFor allows contribute.
     * `$items` are Obj {result, operation}; `$needsOf(operation)` is the tool author's mapping (a falsy value contributes nothing).
     */
    public static function compilePolicy(mixed $items, \Closure $needsOf, mixed $proxyPort = null): Obj
    {
        $needs = [];
        foreach ($items as $it) {
            $result = $it->get('result');
            $operation = $it->get('operation');
            if (!self::isAuthorizedFor($result, $operation)) {
                throw new \InvalidArgumentException('not_authorized: result does not allow exactly this operation');
            }
            $n = $needsOf($operation);
            if (Jsx::truthy($n)) {
                $needs[] = $n;
            }
        }
        return self::policyFromNeeds($needs, $proxyPort);
    }

    private const BASE = ['read', 'write', 'close', 'fstat', 'newfstatat', 'statx', 'lseek', 'mmap', 'mprotect', 'munmap', 'mremap', 'brk', 'madvise',
        'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'sigaltstack', 'pread64', 'pwrite64', 'readv', 'writev', 'openat', 'getdents64',
        'fcntl', 'getcwd', 'readlink', 'readlinkat', 'dup', 'dup3', 'pipe2', 'poll', 'ppoll', 'epoll_create1', 'epoll_ctl', 'epoll_pwait',
        'eventfd2', 'futex', 'set_tid_address', 'set_robust_list', 'rseq', 'arch_prctl', 'prlimit64', 'sched_yield', 'nanosleep',
        'clock_nanosleep', 'clock_gettime', 'gettimeofday', 'getrandom', 'getpid', 'gettid', 'getuid', 'geteuid', 'getgid', 'getegid',
        'uname', 'tgkill', 'exit', 'exit_group'];
    private const NET = ['connect', 'getsockopt', 'setsockopt', 'getsockname', 'getpeername', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg', 'shutdown'];
    private const EXEC = ['execve', 'execveat'];

    /** @param list<string> $a @return list<string> */
    private static function sorted(array $a): array
    {
        sort($a, SORT_STRING);
        return $a;
    }

    private static function proxyOf(Obj $p): mixed
    {
        return $p->get('net')->get('proxy');
    }

    /** @return array<string,mixed> */
    private static function seccomp(Obj $p): array
    {
        $syscalls = [['names' => self::sorted(self::BASE), 'action' => 'SCMP_ACT_ALLOW']];
        if (Jsx::truthy(self::proxyOf($p))) {
            $syscalls[] = ['names' => self::sorted(self::NET), 'action' => 'SCMP_ACT_ALLOW'];
            foreach ([2, 10] as $d) {
                $syscalls[] = ['names' => ['socket'], 'action' => 'SCMP_ACT_ALLOW', 'args' => [['index' => 0, 'value' => $d, 'op' => 'SCMP_CMP_EQ']]];
            }
        }
        if (count($p->get('fs')->get('exec')) > 0) {
            $syscalls[] = ['names' => self::EXEC, 'action' => 'SCMP_ACT_ALLOW'];
        }
        return [
            'defaultAction' => 'SCMP_ACT_ERRNO', 'defaultErrnoRet' => 1,
            'archMap' => [['architecture' => 'SCMP_ARCH_X86_64', 'subArchitectures' => []], ['architecture' => 'SCMP_ARCH_AARCH64', 'subArchitectures' => []]],
            'syscalls' => $syscalls,
        ];
    }

    /** Docker / OCI-format seccomp profile: deny by default; network syscalls only with a proxy; `socket` only for AF_INET / AF_INET6. */
    public static function seccompProfile(mixed $p): Obj
    {
        return self::obj(self::seccomp($p));
    }

    private const FS_HANDLED = ['EXECUTE', 'WRITE_FILE', 'READ_FILE', 'READ_DIR', 'REMOVE_DIR', 'REMOVE_FILE', 'MAKE_CHAR', 'MAKE_DIR', 'MAKE_REG',
        'MAKE_SOCK', 'MAKE_FIFO', 'MAKE_BLOCK', 'MAKE_SYM', 'REFER', 'TRUNCATE'];

    /** @return array<string,mixed> */
    private static function landlock(Obj $p): array
    {
        $fp = $p->get('fs');
        $read = $fp->get('read');
        $write = $fp->get('write');
        $exec = $fp->get('exec');
        $paths = [];
        foreach ([...$read, ...$write, ...$exec] as $x) {
            $paths[$x] = true;
        }
        $fs = [];
        foreach (self::sorted(array_map('strval', array_keys($paths))) as $path) {
            $access = [];
            if (in_array($path, $exec, true)) {
                array_push($access, 'EXECUTE', 'READ_FILE'); // execve opens the binary for reading, so the kernel also demands READ_FILE
            }
            if (in_array($path, $read, true)) {
                array_push($access, 'READ_FILE', 'READ_DIR');
            }
            if (in_array($path, $write, true)) {
                array_push($access, 'WRITE_FILE', 'TRUNCATE', 'MAKE_REG', 'MAKE_DIR', 'REMOVE_FILE', 'REMOVE_DIR');
            }
            $fs[] = ['path' => $path, 'access' => array_map(static fn($x) => 'LANDLOCK_ACCESS_FS_' . $x, array_values(array_unique($access)))];
        }
        $proxy = self::proxyOf($p);
        return [
            'v' => 1, 'abi_min' => 4, 'handled_access_fs' => array_map(static fn($x) => 'LANDLOCK_ACCESS_FS_' . $x, self::FS_HANDLED),
            'handled_access_net' => ['LANDLOCK_ACCESS_NET_BIND_TCP', 'LANDLOCK_ACCESS_NET_CONNECT_TCP'],
            'rules' => ['fs' => $fs, 'net' => Jsx::truthy($proxy) ? [['port' => $proxy->get('port'), 'access' => ['LANDLOCK_ACCESS_NET_CONNECT_TCP']]] : []],
        ];
    }

    /** Landlock ruleset: handle every right, allow only what the grant names (network rules need ABI 4). */
    public static function landlockRuleset(mixed $p): Obj
    {
        return self::obj(self::landlock($p));
    }

    /** macOS sandbox profile (SBPL for sandbox-exec(1)): deny by default; paths were validated to need no escaping. */
    public static function macosProfile(mixed $p): string
    {
        $q = static fn(mixed $s): string => '"' . Js::str($s) . '"';
        $lines = ['(version 1)', '(deny default)', '(allow sysctl-read)', '(allow process-fork)', '(allow mach-lookup)', '(allow file-read-metadata)',
            '(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (subpath "/usr/lib") '
            . '(subpath "/System/Library") (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes"))'];
        $fs = $p->get('fs');
        foreach ($fs->get('exec') as $x) {
            $lines[] = '(allow process-exec (literal ' . $q($x) . '))';
            $lines[] = '(allow file-read* (literal ' . $q($x) . '))';
        }
        foreach ($fs->get('read') as $r) {
            $lines[] = '(allow file-read* (subpath ' . $q($r) . '))';
        }
        foreach ($fs->get('write') as $w) {
            $lines[] = '(allow file-write* (subpath ' . $q($w) . '))';
        }
        $proxy = self::proxyOf($p);
        if (Jsx::truthy($proxy)) {
            $lines[] = '(allow network-outbound (remote tcp ' . $q('localhost:' . Js::str($proxy->get('port'))) . '))';
        }
        return implode("\n", $lines) . "\n";
    }

    /** Flatten the generated seccomp and Landlock profiles into the flags of a reference `pca-confine <flags> -- <command>` helper. @return list<string> */
    public static function confineArgs(mixed $policy): array
    {
        $ll = self::landlock($policy);
        $sc = self::seccomp($policy);
        $short = static fn(string $n): string => str_starts_with($n, 'LANDLOCK_ACCESS_') ? substr($n, strlen('LANDLOCK_ACCESS_')) : $n;
        $args = ['--fs-handled', implode(',', array_map($short, $ll['handled_access_fs']))];
        if (count($ll['rules']['net']) > 0 || Jsx::truthy(self::proxyOf($policy))) {
            array_push($args, '--net-handled', implode(',', array_map($short, $ll['handled_access_net'])));
        }
        foreach ($ll['rules']['fs'] as $r) {
            array_push($args, '--fs', $r['path'] . ':' . implode(',', array_map($short, $r['access'])));
        }
        foreach ($ll['rules']['net'] as $r) {
            array_push($args, '--net', Js::str($r['port']) . ':' . implode(',', array_map($short, $r['access'])));
        }
        foreach ($sc['syscalls'] as $s) {
            if (!empty($s['args'])) {
                foreach ($s['args'] as $a) {
                    foreach ($s['names'] as $n) {
                        array_push($args, '--allow-arg', $n . ':' . $a['index'] . ':' . $a['value']);
                    }
                }
            } else {
                foreach ($s['names'] as $n) {
                    array_push($args, '--allow', $n);
                }
            }
        }
        return $args;
    }

    // ---- runtime claims -------------------------------------------------------------------------------------------------------

    /**
     * A signed statement that a sandbox runs at `class`, bound to the signed passport (by digest) of the agent it contains. The
     * signer is an attestor the verifier pins. Signs `domain || canonical(claim without sig)` with Ed25519; throws on a key that is
     * not a 32-byte seed or a claim outside the strict canonical profile.
     */
    public static function signRuntimeClaim(string $secretKey, string $publicKey, mixed $c): Obj
    {
        if (strlen($secretKey) !== 32) {
            throw new \InvalidArgumentException('secret key must be a 32-byte seed');
        }
        $u = new Obj();
        $u->set('v', new Num('1'));
        foreach ($c->keys() as $k) {
            $u->set($k, $c->get($k));
        }
        $u->set('attestor', Pca::b64u($publicKey));
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($secretKey));
        $u->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::RUNTIME_CLAIM_DOMAIN . Json::canonicalizeNative($u), $sk)));
        return $u;
    }

    /** `coll.includes(x)` for a string x: an array (strict equality) or a string (substring); anything else is not callable. */
    private static function includes(mixed $coll, string $x): bool
    {
        if (is_array($coll) && array_is_list($coll)) {
            return in_array($x, $coll, true);
        }
        if (is_string($coll)) {
            return str_contains($coll, $x);
        }
        throw new \TypeError('includes is not a function');
    }

    /**
     * The class the claim proves, or `none` for anything missing, unsigned, unpinned, expired, for another passport, over evidence
     * nobody verified, or malformed. `$trust` is {pinnedAttestors, passportDigest, verifiedEvidenceDigests, now}. Total.
     */
    public static function verifiedRuntimeClass(mixed $claim, mixed $trust): string
    {
        try {
            $c = $claim;
            $keys = ['v', 'class', 'passport_digest', 'evidence_digest', 'iat', 'exp', 'attestor', 'sig'];
            if (!($c instanceof Obj) || count($c->keys()) !== count($keys) || array_diff($c->keys(), $keys) !== []) {
                return 'none';
            }
            if (!K3Sig::isNumber($c->get('v'), 1.0) || !is_string($c->get('class')) || !in_array($c->get('class'), self::RUNTIME_CLASSES, true)) {
                return 'none';
            }
            if (!is_string($c->get('sig')) || !K3Sig::isStr($c->get('attestor'), 128) || !K3Sig::isStr($c->get('passport_digest'), 128)
                || !K3Sig::isStr($c->get('evidence_digest'), 128) || !self::includes(self::get($trust, 'pinnedAttestors'), $c->get('attestor'))) {
                return 'none';
            }
            $now = self::get($trust, 'now');
            if ($c->get('passport_digest') !== self::get($trust, 'passportDigest') || !K3Sig::isSafeInt($c->get('iat')) || !K3Sig::isSafeInt($c->get('exp'))
                || !K3Sig::isSafeInt($now) || K3Sig::num($now) < K3Sig::num($c->get('iat')) || K3Sig::num($now) >= K3Sig::num($c->get('exp'))) {
                return 'none';
            }
            if (!self::includes(self::get($trust, 'verifiedEvidenceDigests'), $c->get('evidence_digest')) || Pca::unb64u($c->get('attestor'), 32) === null) {
                return 'none';
            }
            if (Pca::unb64u($c->get('sig'), 64) === null) {
                return 'none';
            }
            return K3Sig::verifyBody(self::RUNTIME_CLAIM_DOMAIN, $c->without('sig'), $c->get('attestor'), $c->get('sig')) ? $c->get('class') : 'none';
        } catch (\Throwable) {
            return 'none';
        }
    }

    public static function passportDigest(mixed $signedPassport): string
    {
        return Pca::hashCanonical($signedPassport);
    }

    /** The digest a claim's `evidence_digest` must equal for this attestation document. */
    public static function evidenceDigest(mixed $document): string
    {
        return Pca::hashCanonical($document);
    }

    /**
     * Run an existing hardware attestation verifier over the evidence; only if it says `ok` and `bound` is the evidence's digest admitted into the trust.
     * Anything else (a throw, a malformed answer, not bound) leaves the list empty, so every claim is `none`. `$o`: document, verifier (a callable, or an
     * object with a `verify` method, given {document, ctx, nowMs, expected} as an Obj and answering {ok, bound}), ctx, expected, nowMs, pinnedAttestors,
     * passportDigest. Returns the ClaimTrust {pinnedAttestors, passportDigest, verifiedEvidenceDigests, now}.
     *
     * @param Obj|array<string,mixed> $o
     */
    public static function trustFromAttestation(mixed $o): Obj
    {
        $ok = false;
        try {
            $v = Js::opt($o, 'verifier');
            $input = Obj::of(['document' => Js::opt($o, 'document'), 'ctx' => Js::opt($o, 'ctx'), 'nowMs' => Js::opt($o, 'nowMs'), 'expected' => Js::opt($o, 'expected')]);
            $h = is_callable($v) ? $v($input) : $v->verify($input);
            $ok = Js::opt($h, 'ok') === true && Js::opt($h, 'bound') === true;
        } catch (\Throwable) {
            $ok = false;
        }
        return Obj::of(['pinnedAttestors' => Js::opt($o, 'pinnedAttestors'), 'passportDigest' => Js::opt($o, 'passportDigest'),
            'verifiedEvidenceDigests' => $ok ? [self::evidenceDigest(Js::opt($o, 'document'))] : [], 'now' => Js::opt($o, 'nowMs')]);
    }

    // ---- egress address rule --------------------------------------------------------------------------------------------------

    private const V4_SEG = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])';
    private const V4 = '(?:' . self::V4_SEG . '\.){3}' . self::V4_SEG;
    private const V6_SEG = '(?:[0-9a-fA-F]{1,4})';

    private static function v6Pattern(): string
    {
        $s = self::V6_SEG;
        $v = self::V4;
        return '\A(?:'
            . "(?:$s:){7}(?:$s|:)|"
            . "(?:$s:){6}(?:$v|:$s|:)|"
            . "(?:$s:){5}(?::$v|(?::$s){1,2}|:)|"
            . "(?:$s:){4}(?:(?::$s){0,1}:$v|(?::$s){1,3}|:)|"
            . "(?:$s:){3}(?:(?::$s){0,2}:$v|(?::$s){1,4}|:)|"
            . "(?:$s:){2}(?:(?::$s){0,3}:$v|(?::$s){1,5}|:)|"
            . "(?:$s:){1}(?:(?::$s){0,4}:$v|(?::$s){1,6}|:)|"
            . "(?::(?:(?::$s){0,5}:$v|(?::$s){1,7}|:))"
            . ')(?:%[0-9a-zA-Z.:-]{1,})?\z';
    }

    public static function isIpv4(string $s): bool
    {
        return preg_match('/\A' . self::V4 . '\z/', $s) === 1;
    }

    public static function isIpv6(string $s): bool
    {
        return preg_match('/' . self::v6Pattern() . '/', $s) === 1;
    }

    private static function isPrivateV4(int $a, int $b): bool
    {
        return $a === 0 || $a === 10 || $a === 127 || ($a === 169 && $b === 254) || ($a === 172 && $b >= 16 && $b <= 31) || ($a === 192 && $b === 168)
            || ($a === 100 && $b >= 64 && $b <= 127) || $a >= 224;
    }

    /**
     * Loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses, classified on the parsed address, not
     * its spelling. IPv6: only global unicast (2000::/3) is public; an IPv4-mapped, IPv4-compatible or NAT64 (64:ff9b::/96) address
     * follows its embedded IPv4 address; a zoned address (`%id`) is link-scoped, so private. Anything that is not an IP literal
     * (or not a string) counts as private (refused).
     */
    public static function isPrivateAddress(mixed $ip): bool
    {
        if (!is_string($ip)) {
            return true;
        }
        if (self::isIpv4($ip)) {
            [$a, $b] = array_map('intval', array_slice(explode('.', $ip), 0, 2));
            return self::isPrivateV4($a, $b);
        }
        if (str_contains($ip, '%') || !self::isIpv6($ip)) {
            return true;
        }
        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 16) {
            return true;
        }
        $w = array_values(unpack('n8', $packed));
        $zero80 = $w[0] === 0 && $w[1] === 0 && $w[2] === 0 && $w[3] === 0 && $w[4] === 0;
        $nat64 = $w[0] === 0x64 && $w[1] === 0xff9b && $w[2] === 0 && $w[3] === 0 && $w[4] === 0 && $w[5] === 0;
        if (($zero80 && ($w[5] === 0 || $w[5] === 0xffff)) || $nat64) {
            return self::isPrivateV4($w[6] >> 8, $w[6] & 0xff);
        }
        return $w[0] < 0x2000 || $w[0] >= 0x4000;
    }

    public static function sha256B64u(string $b): string
    {
        return Pca::b64u(hash('sha256', $b, true));
    }

    // ---- WebAssembly tool builders --------------------------------------------------------------------------------------------

    /** @return list<int> */
    private static function u(int $n): array
    {
        $out = [];
        while (true) {
            $b = $n & 0x7F;
            $n = intdiv($n, 128);
            if ($n > 0) {
                $b |= 0x80;
            }
            $out[] = $b;
            if ($n <= 0) {
                return $out;
            }
        }
    }

    /** @return list<int> */
    private static function s(string $x): array
    {
        return [...self::u(Js::len($x)), ...array_values(unpack('C*', Js::utf8($x)) ?: [])];
    }

    /** @param list<int> $body @return list<int> */
    private static function section(int $i, array $body): array
    {
        return [$i, ...self::u(count($body)), ...$body];
    }

    /** @param list<list<int>> $items @return list<int> */
    private static function vec(array $items): array
    {
        return [...self::u(count($items)), ...array_merge([], ...$items)];
    }

    /** @return list<int> */
    private static function sleb(int $n): array
    {
        $n = ((($n + 2147483648) % 4294967296) + 4294967296) % 4294967296 - 2147483648; // the reference shifts int32 values
        $out = [];
        while (true) {
            $b = $n & 0x7F;
            $n >>= 7;
            if (($n === 0 && ($b & 0x40) === 0) || ($n === -1 && ($b & 0x40) !== 0)) {
                return [...$out, $b];
            }
            $out[] = $b | 0x80;
        }
    }

    /** @return list<int> */
    private static function i32c(int $n): array
    {
        return [0x41, ...self::sleb($n)];
    }

    private static function bytes(array $out): string
    {
        return pack('C*', ...array_map(static fn(int $b): int => $b & 0xFF, $out));
    }

    private static function intOf(mixed $v): int
    {
        return (int)K3Sig::num($v);
    }

    /**
     * A hand-assembled core-WebAssembly module that calls `pca:act.invoke(handle, ptr, cap)` for each given call and returns either
     * the last call's return code or the first byte of linear memory. `$spec`: {calls: [{handle, ptr, cap}], returns?: 'last' | 'byte0',
     * extraImports?: [{module, name}], memory?: {min, max}, spin?: bool}. Returns the module bytes.
     */
    public static function buildTool(mixed $spec): string
    {
        $extra = Jsx::truthy(Js::opt($spec, 'extraImports')) ? Js::opt($spec, 'extraImports') : [];
        $types = self::vec([[0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F], [0x60, 0, 1, 0x7F], [0x60, 4, 0x7F, 0x7F, 0x7F, 0x7F, 1, 0x7F]]);
        $imps = [[...self::s('pca:act'), ...self::s('invoke'), 0, 0]];
        foreach ($extra as $e) {
            $imps[] = [...self::s($e->get('module')), ...self::s($e->get('name')), 0, 2];
        }
        $imports = self::vec($imps);
        $mem = Jsx::truthy(Js::opt($spec, 'memory')) ? Js::opt($spec, 'memory') : Obj::of(['min' => new Num('1'), 'max' => new Num('1')]);
        $min = self::intOf($mem->get('min'));
        $memory = self::vec([$mem->get('max') === null ? [0, ...self::u($min)] : [1, ...self::u($min), ...self::u(self::intOf($mem->get('max')))]]);
        $runIndex = 1 + count($extra);
        $calls = $spec->get('calls');
        $returns = Jsx::truthy(Js::opt($spec, 'returns')) ? Js::opt($spec, 'returns') : 'last';
        $body = [0];
        foreach ($calls as $i => $c) {
            array_push($body, ...self::i32c(self::intOf($c->get('handle'))), ...self::i32c(self::intOf($c->get('ptr'))), ...self::i32c(self::intOf($c->get('cap'))), ...[0x10, 0]);
            if (!($i === count($calls) - 1 && $returns === 'last')) {
                $body[] = 0x1A;
            }
        }
        if (Jsx::truthy(Js::opt($spec, 'spin'))) {
            array_push($body, 0x03, 0x40, 0x0C, 0x00, 0x0B);
        }
        if (Js::opt($spec, 'returns') === 'byte0') {
            array_push($body, ...self::i32c(0), ...[0x2D, 0, 0]);
        }
        if (count($calls) === 0) {
            array_push($body, ...self::i32c(0));
        }
        $body[] = 0x0B;
        $out = [0, 0x61, 0x73, 0x6D, 1, 0, 0, 0, ...self::section(1, $types), ...self::section(2, $imports), ...self::section(3, self::vec([[1]])),
            ...self::section(5, $memory),
            ...self::section(7, self::vec([[...self::s('memory'), 2, 0], [...self::s('run'), 0, ...self::u($runIndex)]])),
            ...self::section(10, self::vec([[...self::u(count($body)), ...$body]]))];
        return self::bytes($out);
    }

    /** A tool that asks the table what it holds: returns `handle_count() * 256 + first byte of handle 1's verb`. */
    public static function buildProbeTool(int $cap = 64): string
    {
        $types = self::vec([[0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F], [0x60, 0, 1, 0x7F]]);
        $imports = self::vec([[...self::s('pca:act'), ...self::s('invoke'), 0, 0], [...self::s('pca:act'), ...self::s('handle_count'), 0, 1],
            [...self::s('pca:act'), ...self::s('handle_verb'), 0, 0]]);
        $body = [0, ...self::i32c(1), ...self::i32c(0), ...self::i32c($cap), 0x10, 2, 0x1A, 0x10, 1, ...self::i32c(256), 0x6C, ...self::i32c(0), 0x2D, 0, 0, 0x6A, 0x0B];
        $out = [0, 0x61, 0x73, 0x6D, 1, 0, 0, 0, ...self::section(1, $types), ...self::section(2, $imports), ...self::section(3, self::vec([[1]])),
            ...self::section(5, self::vec([[1, 1, 1]])), ...self::section(7, self::vec([[...self::s('memory'), 2, 0], [...self::s('run'), 0, 3]])),
            ...self::section(10, self::vec([[...self::u(count($body)), ...$body]]))];
        return self::bytes($out);
    }

    /**
     * The reference tool as a component in the WebAssembly text format: imports only `pca:act/invoke@0.1.0` and exports
     * `run: func() -> s32`. Options: {handle?: default 1, spin?: loop forever, extraImport?: an import the host must refuse}.
     */
    public static function referenceComponentWat(mixed $o = null): string
    {
        $imp = Js::opt($o, 'extraImport');
        $extra = Jsx::truthy($imp) ? '(import "' . Js::str($imp) . '" (instance (export "get-arguments" (func (result (list string))))))' : '';
        $handle = Js::opt($o, 'handle');
        $handle = $handle === null ? 1 : $handle;
        if (Jsx::truthy(Js::opt($o, 'spin'))) {
            $body = '(loop $l (br $l)) (i32.const 0)';
        } else {
            $body = '(call $invoke (i32.const ' . Js::str($handle) . ") (i32.const 16))\n"
                . "       (if (result i32) (i32.load8_u (i32.const 16))\n"
                . "         (then (i32.load (i32.const 20)))\n"
                . '         (else (i32.load8_u (i32.load (i32.const 20)))))';
        }
        return "(component\n"
            . "  (import \"pca:act/invoke@0.1.0\" (instance \$inv\n"
            . "    (export \"handle-count\" (func (result u32)))\n"
            . "    (export \"invoke\" (func (param \"handle\" u32) (result (result (list u8) (error s32)))))))\n"
            . '  ' . $extra . "\n"
            . "  (core module \$libc\n"
            . "    (memory (export \"memory\") 1 1)\n"
            . "    (global \$bump (mut i32) (i32.const 1024))\n"
            . "    (func (export \"realloc\") (param \$old i32) (param \$oldsz i32) (param \$align i32) (param \$new i32) (result i32)\n"
            . "      (local \$p i32)\n"
            . "      (local.set \$p (global.get \$bump))\n"
            . "      (global.set \$bump (i32.add (local.get \$p) (local.get \$new)))\n"
            . "      (local.get \$p)))\n"
            . "  (core instance \$libc (instantiate \$libc))\n"
            . "  (alias core export \$libc \"memory\" (core memory \$mem))\n"
            . "  (alias core export \$libc \"realloc\" (core func \$realloc))\n"
            . "  (core func \$count (canon lower (func \$inv \"handle-count\")))\n"
            . "  (core func \$invoke (canon lower (func \$inv \"invoke\") (memory \$mem) (realloc \$realloc)))\n"
            . "  (core module \$main\n"
            . "    (import \"libc\" \"memory\" (memory 1))\n"
            . "    (import \"host\" \"count\" (func \$count (result i32)))\n"
            . "    (import \"host\" \"invoke\" (func \$invoke (param i32 i32)))\n"
            . "    (func (export \"run\") (result i32)\n"
            . '      ' . $body . "))\n"
            . "  (core instance \$host (export \"count\" (func \$count)) (export \"invoke\" (func \$invoke)))\n"
            . "  (core instance \$main (instantiate \$main (with \"libc\" (instance \$libc)) (with \"host\" (instance \$host))))\n"
            . "  (alias core export \$main \"run\" (core func \$run))\n"
            . "  (func \$lifted (result s32) (canon lift (core func \$run)))\n"
            . "  (export \"run\" (func \$lifted)))\n";
    }
}
