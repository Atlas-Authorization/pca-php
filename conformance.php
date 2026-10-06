<?php
declare(strict_types=1);

// Plain conformance runner (no PHPUnit, no Composer): php conformance.php
require_once __DIR__ . '/src/Pca.php';

use Atlas\Pca\Json;
use Atlas\Pca\Pca;

$dir = __DIR__ . '/conformance/';
$doc = Json::parse(file_get_contents($dir . 'vectors.json'));
json_decode(file_get_contents($dir . 'keys.json')); // keys.json must at least parse

$fails = 0;
$total = 0;
$check = function (bool $ok, string $msg) use (&$fails): void {
    if (!$ok) {
        $fails++;
        fwrite(STDERR, "FAIL: $msg\n");
    }
};

if (count($doc->vectors) === 0) {
    fwrite(STDERR, "no vectors\n");
    exit(1);
}
foreach ($doc->vectors as $v) {
    $total++;
    $got = Pca::verifyPcactnCore($v->pcactn, $v->grant);
    $check($got['allow'] === $v->expect->allow, "{$v->name}: allow = " . var_export($got['allow'], true)
        . ", want " . var_export($v->expect->allow, true) . " ({$got['reason']})");
    foreach ($v->expect->checks as $k => $want) {
        $check(($got['checks'][$k] ?? null) === $want, "{$v->name}: check $k = "
            . var_export($got['checks'][$k] ?? null, true) . ", want " . var_export($want, true));
    }
    echo "vector {$v->name}: allow=" . ($got['allow'] ? 'true' : 'false') . "\n";
}

$prim = $doc->primitives;
foreach ($prim->canonical as $c) {
    $s = Json::canonicalize($c->value);
    $check($s === $c->expect, "canonical mismatch: $s vs {$c->expect}");
    $check(Pca::hashCanonical($c->value) === $c->hash, "hash mismatch for $s");
}
foreach ($prim->merkle as $m) {
    $root = Pca::merkleRoot($m->leaves);
    $check($root === $m->root, "merkle root mismatch: $root vs {$m->root}");
    foreach ($m->proofs as $i => $p) {
        $check(Pca::verifyInclusion($root, $p, $m->leaves[$i]), "proof $i does not verify");
    }
}
$check(Pca::paramsDigest() === $prim->params_digest_empty, 'empty params digest mismatch');

if ($fails > 0) {
    fwrite(STDERR, "$fails failure(s) across $total vectors\n");
    exit(1);
}
echo "OK: $total/$total vectors + primitives pass\n";
