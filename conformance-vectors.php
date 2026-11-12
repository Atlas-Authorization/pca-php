<?php
declare(strict_types=1);

// Native-parity vector replay (no PHPUnit, no Composer): php conformance-vectors.php [family ...]
// Families: decision escalation passport attestation intent-state ledger optimistic mesh goal (default: all).
// A missing vector file or a family that runs zero vectors FAILS. Exit status 1 on any failure.
require_once __DIR__ . '/tests/Vectors.php';

use Atlas\Pca\Tests\Vectors;

$families = array_slice($argv, 1) ?: Vectors::FAMILIES;
$bad = 0;
foreach ($families as $f) {
    [$n, $fails] = Vectors::run($f);
    if ($n === 0 && $fails === []) {
        $fails[] = "$f: no vectors ran";
    }
    fwrite(STDOUT, sprintf("%-12s %5d vectors, %d failure(s)\n", $f, $n, count($fails)));
    foreach (array_slice($fails, 0, 40) as $m) {
        fwrite(STDERR, "FAIL: $m\n");
    }
    $bad += count($fails);
}
exit($bad === 0 ? 0 : 1);
