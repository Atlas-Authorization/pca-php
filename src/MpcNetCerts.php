<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Per-run identity material for the TLS mesh: one fresh P-256 key and self-signed certificate per node, generated with the vetted
 * `openssl` command line (no X.509 code of our own). The key lives only on the node that generated it; only the PUBLIC certificates
 * are exchanged and pinned. An identity is ['keyPem' => string, 'certPem' => string].
 */
final class MpcNetCerts
{
    /** @return array{keyPem:string,certPem:string} a throw-away identity for $cn (valid 2 days); fails closed when openssl is missing or errors */
    public static function generate(string $cn, string $openssl = 'openssl'): array
    {
        if (preg_match('/\A[A-Za-z0-9._-]{1,64}\z/', $cn) !== 1) {
            throw new \InvalidArgumentException('certs: bad common name');
        }
        $dir = self::tempDir();
        try {
            $key = $dir . '/key.pem';
            $cert = $dir . '/cert.pem';
            self::run([$openssl, 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', $key]);
            self::run([$openssl, 'req', '-new', '-x509', '-key', $key, '-subj', '/CN=' . $cn, '-days', '2', '-sha256',
                '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature',
                '-addext', 'extendedKeyUsage=serverAuth,clientAuth', '-out', $cert]);
            $k = file_get_contents($key);
            $c = file_get_contents($cert);
            if ($k === false || $c === false) {
                throw new \RuntimeException('certs: identity files unreadable');
            }
            return ['keyPem' => $k, 'certPem' => $c];
        } finally {
            self::rmTree($dir);
        }
    }

    /** Generate an identity into `<dir>/key.pem` + `<dir>/cert.pem` (for the party-main keygen command). @return array{keyPath:string,certPath:string} */
    public static function generateFiles(string $dir, string $cn, string $openssl = 'openssl'): array
    {
        $id = self::generate($cn, $openssl);
        if (!PrivateFile::mkdir($dir, true)) {
            throw new \RuntimeException('certs: cannot create ' . $dir);
        }
        $keyPath = $dir . '/key.pem';
        $certPath = $dir . '/cert.pem';
        self::writeSecret($keyPath, $id['keyPem']);
        PrivateFile::write($certPath, $id['certPem']);
        return ['keyPath' => $keyPath, 'certPath' => $certPath];
    }

    /** SHA-256 fingerprint (lowercase hex, no separators) of a PEM certificate; throws on anything that is not a certificate. */
    public static function fingerprintOf(string $certPem): string
    {
        $fp = @openssl_x509_fingerprint($certPem, 'sha256');
        if (!is_string($fp)) {
            throw new \InvalidArgumentException('certs: not a certificate');
        }
        return strtolower($fp);
    }

    public static function readPem(string $path): string
    {
        $s = @file_get_contents($path);
        if ($s === false) {
            throw new \RuntimeException('certs: cannot read ' . $path);
        }
        return $s;
    }

    /** A new private (0700) temporary directory. */
    public static function tempDir(): string
    {
        $dir = sys_get_temp_dir() . '/pca-mpc-' . bin2hex(random_bytes(8));
        if (!PrivateFile::mkdir($dir)) {
            throw new \RuntimeException('certs: cannot create a temporary directory');
        }
        return $dir;
    }

    public static function writeSecret(string $path, string $data): void
    {
        if (PrivateFile::write($path, $data) === false) {
            throw new \RuntimeException('certs: cannot write ' . $path);
        }
    }

    /** Remove a directory tree, hidden files included (only the process that created it calls this: see MpcNetMesh::close). */
    public static function rmTree(string $dir): void
    {
        self::removeTree($dir);
    }

    private static function removeTree(string $dir): void
    {
        $names = is_dir($dir) ? scandir($dir) : false; // scandir lists dotfiles too
        foreach ($names === false ? [] : $names as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $f = $dir . '/' . $name;
            is_dir($f) && !is_link($f) ? self::removeTree($f) : unlink($f);
        }
        if ($names !== false) {
            rmdir($dir);
        }
    }

    /** @param list<string> $cmd */
    private static function run(array $cmd): void
    {
        $p = proc_open($cmd, [0 => ['file', PrivateFile::nullDevice(), 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($p)) {
            throw new \RuntimeException('certs: cannot start ' . $cmd[0]);
        }
        stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        if (proc_close($p) !== 0) {
            throw new \RuntimeException('certs: ' . $cmd[0] . ' failed: ' . substr($err, 0, 200));
        }
    }
}
