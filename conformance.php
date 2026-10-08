<?php
declare(strict_types=1);

// Plain conformance runner (no PHPUnit, no Composer): php conformance.php
require_once __DIR__ . '/src/Pca.php';

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Mldsa;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;

$dir = __DIR__ . '/conformance/';
$doc = Json::parseLax(file_get_contents($dir . 'vectors.json'));
Json::parseLax(file_get_contents($dir . 'keys.json')); // keys.json must at least parse

$fails = 0;
$total = 0;
$check = function (bool $ok, string $msg) use (&$fails): void {
    if (!$ok) {
        $fails++;
        fwrite(STDERR, "FAIL: $msg\n");
    }
};
$str = fn($x) => $x instanceof Obj || is_array($x) ? 'json' : var_export($x, true);

if ($doc->get('format')->int() !== 2) {
    fwrite(STDERR, "unexpected vectors format\n");
    exit(1);
}
$order = array_map(fn($x) => $x, $doc->get('check_order'));

// ---------------------------------------------------------------------------------------
// Suite support. This verifier implements the THREE cross-impl suites every conformant PCA
// impl must agree on: classical Ed25519, the pure lattice ML-DSA-65 (FIPS-204) and the hybrid
// Ed25519+ML-DSA-65 — the ML-DSA ones via OpenSSL >= 3.5 libcrypto (FFI). The other seven
// registered suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their hybrids, and the SUF-CMA nested
// hybrid) are NOT wired here, so a vector whose expected verdict needs a GENUINE signature
// outcome under one of them is skipped explicitly (never silently passed). If the running
// OpenSSL/PHP lacks ML-DSA, the ML-DSA suites drop out of the supported set too and are skipped.
// ---------------------------------------------------------------------------------------
$mldsa = Mldsa::available();
$supported = array_values(array_filter(Pca::supportedSuites(), fn($a) => Pca::suiteAvailable($a)));
fwrite(STDERR, 'ML-DSA (OpenSSL >= 3.5 FFI): ' . ($mldsa ? 'AVAILABLE' : 'NOT available') . "\n");
fwrite(STDERR, 'supported signature suites: ' . implode(', ', $supported) . "\n");

$algOf = function (mixed $o): string {
    $a = ($o instanceof Obj && $o->has('alg')) ? $o->get('alg') : 'ed25519';
    return is_string($a) ? $a : 'ed25519';
};
// The concrete suite a vector exercises that this verifier does NOT support, or null. Looks at the leaf
// `alg` for requires:"pq" and every capability-hop `alg` for requires:"pq-nonleaf". Core vectors (incl. the
// raw pcactn_json wire negatives, which carry no `pcactn`) and vectors that stay within $supported => null.
$unsupportedSuite = function (Obj $v) use ($algOf, $supported): ?string {
    if (!$v->has('pcactn')) {
        return null;
    }
    $p = $v->get('pcactn');
    if (!($p instanceof Obj)) {
        return null;
    }
    $req = $v->has('requires') ? $v->get('requires') : null;
    if ($req === 'pq') {
        $a = $algOf($p);
        return in_array($a, $supported, true) ? null : $a;
    }
    if ($req === 'pq-nonleaf') {
        $chain = $p->get('cap_chain');
        foreach (is_array($chain) ? $chain : [] as $h) {
            $a = $algOf($h);
            if (!in_array($a, $supported, true)) {
                return $a;
            }
        }
        return null;
    }
    return null;
};

$skipped = 0;
$skippedSuites = [];                      // suite => skipped count
$ranByBucket = ['core' => 0, 'pq' => 0, 'pq-nonleaf' => 0];
$vectors = $doc->get('vectors');
foreach ($vectors as $v) {
    $bucket = $v->has('requires') && is_string($v->get('requires')) && $v->get('requires') !== ''
        ? $v->get('requires') : 'core';
    $wantChecks = $v->get('expect')->get('checks');
    // A terminal {wire:false} is suite-agnostic: this verifier rejects an unknown / unimplemented suite at
    // the wire stage (unknown `alg`, or a `pq_sig`/`pq_pk` the suite requires but we cannot size), which IS
    // the correct contract verdict for those negatives, so we still RUN them. Only a vector whose expected
    // verdict needs a real signature outcome under an unsupported suite is skipped.
    $terminalWireFalse = $wantChecks->keys() === ['wire'] && $wantChecks->get('wire') === false;
    $us = $unsupportedSuite($v);
    if ($us !== null && !$terminalWireFalse) {
        $skipped++;
        $skippedSuites[$us] = ($skippedSuites[$us] ?? 0) + 1;
        continue;
    }

    $total++;
    $ranByBucket[$bucket] = ($ranByBucket[$bucket] ?? 0) + 1;
    $name = $v->get('name');
    $ctx = $v->get('context');
    $now = $ctx->get('now')->int();
    $aud = $ctx->get('aud');
    if ($v->has('pcactn_json')) {
        $got = Pca::verifyJson($v->get('pcactn_json'), $v->get('grant'), $now, $aud);
    } else {
        $got = Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $now, $aud);
    }
    $expect = $v->get('expect');
    $check($got['allow'] === $expect->get('allow'), "$name: allow = " . $str($got['allow'])
        . ", want " . $str($expect->get('allow')) . " ({$got['reason']})");
    foreach ($wantChecks->keys() as $k) {
        $check(($got['checks'][$k] ?? null) === $wantChecks->get($k), "$name: check $k = "
            . $str($got['checks'][$k] ?? null) . ", want " . $str($wantChecks->get($k)) . " ({$got['reason']})");
    }
    if ($wantChecks->get('wire') === false) {
        $check(array_keys($got['checks']) === ['wire'], "$name: wire failure must be the only check");
    } else {
        $check(array_keys($got['checks']) === $order, "$name: checks not in normative order");
    }
}

// ---------------------------------------------------------------------------------------
// primitives: canonical / json_parse / b64u / merkle / params_digest
// ---------------------------------------------------------------------------------------
$prim = $doc->get('primitives');
$n = 0;
foreach ($prim->get('canonical') as $c) {
    $s = Json::canonicalizeStrict($c->get('value'));
    $check($s === $c->get('expect'), "canonical mismatch: $s vs {$c->get('expect')}");
    $check(Pca::hashCanonical($c->get('value')) === $c->get('hash'), "hash mismatch for $s");
    $n++;
}
foreach ($prim->get('json_parse') as $j) {
    $n++;
    $in = $j->get('input');
    try {
        $out = Json::canonicalizeStrict(Json::parseStrict($in));
        if ($j->get('accept')) {
            $check($out === $j->get('canonical'), "json_parse: canonical $out vs " . $j->get('canonical'));
        } else {
            $check(false, 'json_parse: should reject ' . json_encode($in));
        }
    } catch (JsonError $e) {
        $check(!$j->get('accept'), 'json_parse: should accept ' . json_encode($in) . ' (' . $e->getMessage() . ')');
    }
}
foreach ($prim->get('b64u') as $b) {
    $n++;
    $len = $b->has('len') ? $b->get('len')->int() : null;
    $check((Pca::unb64u($b->get('input'), $len) !== null) === $b->get('valid'), 'b64u: ' . json_encode($b->get('input')));
}
foreach ($prim->get('merkle') as $m) {
    $root = Pca::merkleRoot($m->get('leaves'));
    $check($root === $m->get('root'), "merkle root mismatch: $root vs {$m->get('root')}");
    foreach ($m->get('proofs') as $i => $p) {
        $check(Pca::verifyInclusion($root, $p, $m->get('leaves')[$i]), "proof $i does not verify");
    }
}
$check(Pca::paramsDigest() === $prim->get('params_digest_empty'), 'empty params digest mismatch');

// ---------------------------------------------------------------------------------------
// v2.1 agent-leaf threshold-share binding. Every primitives.threshold_share[] entry must verify over the
// signerSetHash|t-bound share message iff `valid`. In particular the pre-v2.1 BARE agent share and a
// cross-signer-set replay MUST be rejected. All corpus shares are Ed25519, so no PQ suite is needed here.
// ---------------------------------------------------------------------------------------
$shareAccepted = 0;
$shareRejected = 0;
$bareRejected = false;
$wrongSetRejected = false;
foreach ($prim->get('threshold_share') as $sh) {
    $nm = $sh->has('name') ? $sh->get('name') : $sh->get('role');
    $want = $sh->has('valid') ? $sh->get('valid') : true;
    $got = Pca::verifyThresholdShare($sh);
    $check($got === $want, "threshold_share $nm: verified = " . var_export($got, true)
        . ", want valid = " . var_export($want, true));
    if ($want) {
        $shareAccepted++;
    } else {
        $shareRejected++;
    }
    if ($nm === 'agent-bare-rejected') {
        $bareRejected = ($got === false);
    }
    if ($nm === 'agent-bound-wrong-set') {
        $wrongSetRejected = ($got === false);
    }
}
$check($bareRejected, 'v2.1 binding: the pre-v2.1 BARE agent share (agent-bare-rejected) MUST be rejected');
$check($wrongSetRejected, 'v2.1 binding: a cross-signer-set agent share replay (agent-bound-wrong-set) MUST be rejected');

// ---------------------------------------------------------------------------------------
// Non-leaf PQ artifacts (sth / revocation / beacon / bond-settlement / safety-certificate / judge-verdict /
// software-attestation). Each must verify over its raw `message` bytes under the suite `alg` iff `valid`.
// Spans all 10 suites; those outside $supported need a genuine crypto verdict and are skipped explicitly.
// ---------------------------------------------------------------------------------------
$artRan = 0;
$artSkipped = 0;
$artSkippedSuites = [];
foreach ($prim->get('pq_artifact') as $a) {
    $alg = $a->has('alg') ? $a->get('alg') : 'ed25519';
    if (!is_string($alg) || !in_array($alg, $supported, true)) {
        $artSkipped++;
        $artSkippedSuites[is_string($alg) ? $alg : '<non-string alg>'] =
            ($artSkippedSuites[is_string($alg) ? $alg : '<non-string alg>'] ?? 0) + 1;
        continue;
    }
    $artRan++;
    $want = $a->has('valid') ? $a->get('valid') : true;
    $msg = Pca::unb64u($a->get('message'));
    $got = $msg !== null && Pca::verifyArtifact($a, $msg);
    $label = ($a->has('artifact') ? $a->get('artifact') : '?') . "/$alg";
    $check($got === $want, "pq_artifact $label: verified = " . var_export($got, true)
        . ", want valid = " . var_export($want, true));
}

// ---------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------
echo "\n== PCA PHP conformance (wire format v2, 154-vector corpus) ==\n";
echo "CORE PCActn vectors: $total passed, $skipped skipped\n";
echo "  ran:     core={$ranByBucket['core']}  pq(leaf)={$ranByBucket['pq']}  pq-nonleaf(hops)={$ranByBucket['pq-nonleaf']}\n";
if ($skipped > 0) {
    ksort($skippedSuites);
    $parts = [];
    foreach ($skippedSuites as $suite => $cnt) {
        $parts[] = "$suite=$cnt";
    }
    echo "  skipped (unsupported suites needing a real crypto verdict): " . implode('  ', $parts) . "\n";
    echo "  NOTE: terminal {wire:false} negatives under these suites STILL RAN (unknown-alg => wire fail is the correct verdict).\n";
}
echo "primitives: $n canonical/json_parse/b64u cases + merkle + params_digest pass\n";
echo "threshold shares (v2.1 binding): $shareAccepted valid accepted, $shareRejected invalid rejected"
    . " (incl. bare-agent-share + cross-signer-set replay rejection)\n";
echo "pq_artifacts: $artRan verified, $artSkipped skipped";
if ($artSkipped > 0) {
    ksort($artSkippedSuites);
    $parts = [];
    foreach ($artSkippedSuites as $suite => $cnt) {
        $parts[] = "$suite=$cnt";
    }
    echo ' (' . implode('  ', $parts) . ')';
}
echo "\n";

if ($fails > 0) {
    fwrite(STDERR, "\n$fails failure(s)\n");
    exit(1);
}
echo "\nOK: $total/$total run vectors ($skipped skipped) + primitives + {$shareAccepted}+{$shareRejected} threshold shares + $artRan pq_artifacts pass\n";
