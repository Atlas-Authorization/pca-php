<?php

declare(strict_types=1);

// Windows only: the sandbox host client starts the host through this relay (`php SandboxWasmRelay.php <port> <host stdout file> <host> [args...]`, with the run's token
// in PCA_RELAY_TOKEN). A Windows pipe cannot be written without blocking, so the client sends over a loopback socket (which has a real non-blocking write and
// stream_select) and this process, which may block, copies the bytes into the host's stdin. The client kills this process and the host under it at its deadline.
$port = (int)($argv[1] ?? 0);
$out = (string)($argv[2] ?? '');
$cmd = array_slice($argv, 3);
$token = (string)getenv('PCA_RELAY_TOKEN');
if ($port < 1 || $out === '' || $cmd === [] || $token === '') {
    exit(2);
}
$s = @stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 5);
if ($s === false) {
    exit(3);
}
fwrite($s, $token . "\n"); // the client accepts one connection, and only with this token
$proc = @proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['file', $out, 'w'], 2 => ['file', 'NUL', 'w']], $pipes, null, []);
if (!is_resource($proc)) {
    exit(4);
}
while (proc_get_status($proc)['running']) {
    $r = [$s];
    $w = $e = null;
    if (@stream_select($r, $w, $e, 0, 100000) > 0) {
        $d = fread($s, 65536);
        if ($d === false || $d === '') {
            break; // the client closed the channel
        }
        for ($o = 0; $o < strlen($d);) {
            $n = @fwrite($pipes[0], substr($d, $o));
            if ($n === false || $n === 0) {
                break 2; // the host closed its stdin
            }
            $o += $n;
        }
    }
}
@fclose($pipes[0]);
@proc_terminate($proc, 9);
@proc_close($proc);
