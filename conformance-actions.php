<?php
declare(strict_types=1);

// Action-kit vector replay (no PHPUnit, no Composer): php conformance-actions.php
// A missing vector directory or a kind with too few vectors FAILS. Exit status 1 on any failure.
require_once __DIR__ . '/tests/ActionVectors.php';
require_once __DIR__ . '/tests/ActionsOracle.php';

use Atlas\Pca\Tests\ActionVectors;

[$n, $fails] = ActionVectors::run();
fwrite(STDOUT, sprintf("actions %5d vectors, %d failure(s)\n", $n, count($fails)));
foreach (array_slice($fails, 0, 40) as $m) {
    fwrite(STDERR, "FAIL: $m\n");
}
[$pn, $pfails] = ActionVectors::runProfiles();
fwrite(STDOUT, sprintf("approval profiles %3d vectors, %d failure(s)\n", $pn, count($pfails)));
foreach (array_slice($pfails, 0, 40) as $m) {
    fwrite(STDERR, "FAIL: $m\n");
}
$oracle = \Atlas\Pca\Tests\ActionsOracle::run();
fwrite(STDOUT, sprintf("actions oracles, %d failure(s)\n", count($oracle)));
foreach (array_slice($oracle, 0, 40) as $m) {
    fwrite(STDERR, "FAIL: $m\n");
}
exit($fails === [] && $pfails === [] && $oracle === [] ? 0 : 1);
