<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Every TCP listener the library opens for a local protocol (MPC mesh, fault proxy, sandbox relay, DKG node, FROST HTTP, egress proxy) is bound here.
 *
 * POSIX: a plain bind (a second bind to an in-use port is refused by the kernel).
 * Windows: a plain bind is NOT exclusive. SO_REUSEADDR there lets another process bind the same port and take over connections, and a wildcard
 * listener can be shadowed by a specific-address one. So the socket is created through ext-sockets with SO_EXCLUSIVEADDRUSE (no one else may bind
 * the port while it is held) and handed to streams with socket_export_stream; `so_reuseaddr` is also switched off in the stream context. Without
 * ext-sockets the fallback is a plain stream bind with `so_reuseaddr => false`, which stops a same-address second bind but NOT a shadowing bind;
 * callers that need the guarantee must run with ext-sockets (CI's Windows PHP enables it).
 */
final class ExclusiveListener
{
    /** @param array<string,array<string,mixed>> $context stream context options (e.g. ssl) @return resource|false */
    public static function bind(string $host, int $port, array $context = [], ?int &$errno = null, ?string &$errstr = null)
    {
        if (PHP_OS_FAMILY === 'Windows' && function_exists('socket_create') && !str_contains($host, ':')) {
            $s = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            if ($s !== false) {
                // SO_EXCLUSIVEADDRUSE is ~SO_REUSEADDR (0xFFFFFFFB); PHP does not define it, and as a C int it is -5
                $opt = defined('SO_EXCLUSIVEADDRUSE') ? constant('SO_EXCLUSIVEADDRUSE') : -5;
                if (@socket_set_option($s, SOL_SOCKET, $opt, 1) && @socket_bind($s, $host, $port) && @socket_listen($s, 128)) {
                    $stream = @socket_export_stream($s);
                    if ($stream !== false) {
                        foreach ($context as $wrapper => $opts) {
                            foreach ($opts as $k => $v) {
                                stream_context_set_option($stream, $wrapper, $k, $v);
                            }
                        }
                        return $stream;
                    }
                }
                $errno = socket_last_error($s);
                $errstr = socket_strerror($errno);
                @socket_close($s);
                return false;
            }
        }
        if (PHP_OS_FAMILY === 'Windows') {
            $context['socket']['so_reuseaddr'] = false;
        }
        $srv = @stream_socket_server('tcp://' . $host . ':' . $port, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, stream_context_create($context));
        if ($srv === false && !$errno) {
            $errno = -1; // some PHP builds fill errstr ("Address already in use") but leave errno 0: a failure never reports 0
        }
        return $srv;
    }
}
