<?php
declare(strict_types=1);

// Driven by SandboxWasmHostTest: `php sandbox-hung-host-probe.php <host path> <host sha256> <hang|deaf>` runs a component on a host that never answers (hang) or never
// reads its input while asking for a 1 MiB result (deaf), and prints the refusal reason.
require __DIR__ . '/../vendor/autoload.php';

use Atlas\Pca\Bytes;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SandboxHandleTable;
use Atlas\Pca\SandboxReceiptLog;
use Atlas\Pca\SandboxWasmHost;

$host = new SandboxWasmHost($argv[1], $argv[2]);
$table = new SandboxHandleTable('wasi_no_ambient', new SandboxReceiptLog(), ['fs.read' => static fn($op) => new Bytes(str_repeat("\x07", 1 << 20))]);
if (($argv[3] ?? 'hang') === 'deaf') {
    $op = Obj::of(['verb' => 'fs.read', 'resource' => '/x', 'params' => new Obj()]);
    $table->mint(Obj::of(['allow' => true, 'operation' => Obj::of(['verb' => 'fs.read', 'resource' => '/x', 'params_digest' => Pca::hashCanonical($op->get('params')), 'id' => 'op'])]), $op);
}
echo (string)$host->runComponent($table, 'x', 1000, 1000)->get('reason'), "\n";
