<?php
declare(strict_types=1);

// Plain conformance runner (no PHPUnit, no Composer): php conformance.php
require_once __DIR__ . '/src/Pca.php';
require_once __DIR__ . '/tests/Corpus.php';

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Mldsa;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Tests\Corpus;

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
// Suite support: this verifier's capability manifest (Pca::supportedSuites(): ed25519 + every ML-DSA / SLH-DSA suite whose
// key type the loaded OpenSSL >= 3.5 libcrypto builds; packages/pca/conformance/SUITES.md). A vector whose expected verdict
// needs a suite outside it is NOT skipped silently: the verifier must deny it with the distinct reason unsupported_suite
// (asserted below, counted).
// ---------------------------------------------------------------------------------------
$mldsa = Mldsa::available();
$supported = Pca::supportedSuites();
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
    // 0.4.1: a vector that names one concrete suite (`requires: "ml-dsa-87"`, `"slh-dsa-sha2-128f"`) this verifier lacks.
    if (is_string($req) && $req !== '' && !in_array($req, $supported, true)) {
        return $req;
    }
    // 0.4.1 PQ threshold shares: a `threshold.shares[].alg` outside the manifest needs a real signature verdict too. The
    // r041 ML-DSA-65 share vectors carry no `requires` (only the ML-DSA-87 / SLH-DSA ones do), so read the shares.
    $th = $p->has('threshold') ? $p->get('threshold') : null;
    $shares = ($th instanceof Obj && $th->has('shares')) ? $th->get('shares') : null;
    foreach (is_array($shares) ? $shares : [] as $s) {
        $a = $algOf($s);
        if (!in_array($a, $supported, true)) {
            return $a;
        }
    }
    return null;
};

$skipped = 0;
$v2Unsupported = 0;    // requires_suite: a suite this verifier does not implement (must deny with unsupported_suite)
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
        if ($v->has('pcactn')) {
            $ctx = $v->get('context');
            $got = Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'));
            $check($got['allow'] === false && str_contains((string)$got['reason'], Pca::UNSUPPORTED_SUITE),
                $v->get('name') . ": suite $us is not supported here: want a deny with unsupported_suite ({$got['reason']})");
        }
        continue;
    }

    // Intent Layer v2: `requires_suite` (README "suite capability").
    $rs = Corpus::requiresSuite($v);

    $total++;
    $ranByBucket[$bucket] = ($ranByBucket[$bucket] ?? 0) + 1;
    $name = $v->get('name');
    $ctx = $v->get('context');
    $now = $ctx->get('now')->int();
    $aud = $ctx->get('aud');
    $allowed = $ctx->has('allowed_suites') ? $ctx->get('allowed_suites') : null;
    // Intent Layer M2: an `intent-*` vector may carry `context.intent_policy` (passed through as the parsed Obj) or
    // `context.intent_policy_json` (raw JSON TEXT, which wins; parsed by Json::parseLax, which keeps every number lexeme,
    // so 950000.0 / 1e6 stay integral values and a bare -0 stays negative zero, exactly like JSON.parse in the reference).
    $intentPolicy = $ctx->has('intent_policy_json') ? Json::parseLax($ctx->get('intent_policy_json'))
        : ($ctx->has('intent_policy') ? $ctx->get('intent_policy') : null);
    // Intent Layer v2: `context.intent_v2` (the verifier state, an Obj with number lexemes kept) is passed through.
    $intentV2 = Corpus::intentV2OfObj($ctx);
    if ($v->has('pcactn_json')) {
        $got = Pca::verifyJson($v->get('pcactn_json'), $v->get('grant'), $now, $aud, $allowed, $intentPolicy, $intentV2);
    } else {
        $got = Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $now, $aud, $allowed, $intentPolicy, $intentV2);
    }
    $expect = $v->get('expect');
    if ($expect->has('reason_contains')) {
        $check(str_contains($got['reason'], (string)$expect->get('reason_contains')), "$name: reason must contain "
            . $str($expect->get('reason_contains')) . " ({$got['reason']})");
    }
    if ($rs === 'unsupported') {
        // a suite this verifier does not implement: deny; `unsupported_suite` is required when a v2 check fails first,
        // unless the vector names its refusal (reason_contains, asserted above): that refusal precedes the suite work
        $v2Unsupported++;
        $check($got['allow'] === false, "$name: requires_suite " . $str($v->get('requires_suite')) . ' not implemented, must deny');
        if (Corpus::firstFailureIsV2($got) && !$expect->has('reason_contains')) {
            $check(str_contains($got['reason'], 'unsupported_suite'), "$name: reason must contain unsupported_suite ({$got['reason']})");
        }
        continue;
    }
    $check($got['allow'] === $expect->get('allow'), "$name: allow = " . $str($got['allow'])
        . ", want " . $str($expect->get('allow')) . " ({$got['reason']})");
    foreach ($wantChecks->keys() as $k) {
        $check(($got['checks'][$k] ?? null) === $wantChecks->get($k), "$name: check $k = "
            . $str($got['checks'][$k] ?? null) . ", want " . $str($wantChecks->get($k)) . " ({$got['reason']})");
    }
    if ($wantChecks->get('wire') === false) {
        $check(array_keys($got['checks']) === ['wire'], "$name: wire failure must be the only check");
    } else {
        // `intent` (rule 12) and the v2 checks (rules 13-18, pipeline order) are reported exactly when the vector expects them.
        $wantOrder = Corpus::expectedOrder($order, $wantChecks);
        $check(array_keys($got['checks']) === $wantOrder, "$name: checks not in normative order");
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
// cross-signer-set replay MUST be rejected. Valid shares under a suite outside the manifest are skipped (counted).
// ---------------------------------------------------------------------------------------
$shareAccepted = 0;
$shareRejected = 0;
$shareSkipped = 0;
$bareRejected = false;
$wrongSetRejected = false;
foreach ($prim->get('threshold_share') as $sh) {
    $nm = $sh->has('name') ? $sh->get('name') : $sh->get('role');
    $want = $sh->has('valid') ? $sh->get('valid') : true;
    $got = Pca::verifyThresholdShare($sh);
    // a VALID share under a suite outside the manifest (e.g. hybrid-ed25519-ml-dsa-65 without OpenSSL >= 3.5) needs a real
    // signature verdict: skipped (counted), but it must still be refused (fail closed). Invalid entries always run.
    $shAlg = $sh->get('share') instanceof Obj ? $algOf($sh->get('share')) : 'ed25519';
    if ($want === true && !in_array($shAlg, $supported, true)) {
        $check($got === false, "threshold_share $nm: suite $shAlg is not supported here, yet the share verified");
        $shareSkipped++;
        continue;
    }
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
echo "\n== PCA PHP conformance (wire format v2, golden + adversarial corpus) ==\n";
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
// ---------------------------------------------------------------------------------------
// Standalone chain API: root PQ authority (R4-01). primitives.chain_pin[]: Pca::verifyChain(chain, expected_root_issuer, true,
// allowed_suites, pq_pins, trusted_root). A non-ed25519 ROOT needs a verifier-side pin or the stored grant. Vectors that need a genuine
// ML-DSA-65 verdict are skipped (counted) when OpenSSL lacks it; the hop-0 pin refusals need no crypto and always run.
// ---------------------------------------------------------------------------------------
$chainPins = $prim->has('chain_pin') ? $prim->get('chain_pin') : [];
$check(count($chainPins) >= 25, 'primitives.chain_pin: expected at least 25 vectors, got ' . count($chainPins));
$cpRan = 0;
$cpSkipped = 0;
foreach ($chainPins as $v) {
    $exp = $v->get('expect');
    $reason = $exp->has('reason') ? $exp->get('reason') : '';
    $pinRefusal = str_starts_with($reason, 'hop 0: root suite');
    $needsPq = false;
    foreach ($v->get('chain') as $hop) {
        if ($algOf($hop) !== 'ed25519') {
            $needsPq = true;
        }
    }
    if ($needsPq && !$pinRefusal && !$mldsa) {
        $cpSkipped++;
        continue;
    }
    $cpRan++;
    $eri = $v->get('expected_root_issuer');
    [$why, $ok] = Pca::verifyChain(
        $v->get('chain'), $eri, is_string($eri),
        $v->has('allowed_suites') ? $v->get('allowed_suites') : null,
        $v->has('pq_pins') ? $v->get('pq_pins') : null,
        $v->has('trusted_root') ? $v->get('trusted_root') : null,
    );
    $check($ok === $exp->get('ok'), $v->get('name') . ': ok = ' . $str($ok) . ", want " . $str($exp->get('ok')) . " ($why)");
    if ($pinRefusal) {
        $check($why === $reason, $v->get('name') . ': reason ' . $str($why) . ', want ' . $str($reason));
    }
}
$check($cpRan + $cpSkipped === count($chainPins), 'chain_pin accounting');
echo "chain_pin: $cpRan ran, $cpSkipped skipped of " . count($chainPins) . "\n";

// ---------------------------------------------------------------------------------------
// Round 6 (gen-conformance-r6.mjs): whole signer-set validation (threshold_set), the signer-set hash in UTF-8 byte
// order (signer_set_hash), and malformed input that must be a clean deny, never an exception (malformed).
// ---------------------------------------------------------------------------------------
$r6Supported = $mldsa ? ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'] : ['ed25519'];
$tsRan = 0;
$tsSkipped = 0;
foreach ($prim->get('threshold_set') as $e) {
    $req = $e->has('requires') ? $e->get('requires') : null;
    if (is_string($req) && !in_array($req, $r6Supported, true)) {
        $tsSkipped++;
        continue;
    }
    $tsRan++;
    try {
        $got = Pca::verifyThresholdShare($e);
    } catch (\Throwable $t) {
        $check(false, 'threshold_set ' . $e->get('name') . ': THREW ' . get_class($t));
        continue;
    }
    $check($got === $e->get('valid'), 'threshold_set ' . $e->get('name') . ': verified = ' . $str($got) . ', want ' . $str($e->get('valid')));
}
$check($tsRan + $tsSkipped >= 55, 'threshold_set shrank');
foreach ($prim->get('signer_set_hash') as $e) {
    $h = Pca::signerSetHashRaw($e->get('signer_set'));
    $got = $h === null ? null : Pca::b64u($h);
    $check($got === $e->get('hash'), 'signer_set_hash ' . $e->get('name') . ': got ' . $str($got));
}
$malformed = $prim->get('malformed');
$check(count($malformed) >= 80, 'malformed shrank');
foreach ($malformed as $m) {
    $nm = $m->get('name');
    $in = $m->has('input_json') && is_string($m->get('input_json')) ? Json::parseLax($m->get('input_json')) : $m->get('input'); // README *_json
    try {
        switch ($m->get('api')) {
            case 'chain':
                [$why, $ok] = Pca::verifyChain($in->get('chain'), $in->get('expected_root_issuer'), true);
                $check($ok === false, "malformed $nm: accepted");
                break;
            case 'threshold_share':
                $check(Pca::verifyThresholdShare($in) === false, "malformed $nm: accepted");
                break;
            case 'pcactn_json':
                $v = Pca::verifyJson($in->get('text'), $in->get('grant'), $in->get('now')->int(), $in->get('aud'));
                $check($v['allow'] === false, "malformed $nm: allowed");
                break;
            default:
                $check(false, "malformed $nm: unknown api");
        }
    } catch (\Throwable $t) {
        $check(false, "malformed $nm: THREW " . get_class($t) . ': ' . $t->getMessage());
    }
}
echo "round 6: threshold_set $tsRan ran, $tsSkipped skipped; signer_set_hash " . count($prim->get('signer_set_hash')) . '; malformed ' . count($malformed) . "\n";

// ---------------------------------------------------------------------------------------
// Nesting depth (gen-conformance-depth.mjs): every untrusted entry point at MAX_JSON_DEPTH-1 / limit / limit+1 and
// ~100000 deep (`expand` cases, expanded iteratively by tests/DepthCases.php). Verdict == `valid`; nothing may throw.
// ---------------------------------------------------------------------------------------
require_once __DIR__ . '/tests/DepthCases.php';
$depthCases = $prim->has('depth') ? $prim->get('depth') : [];
$check(count($depthCases) >= 29, 'primitives.depth: expected at least 29 vectors, got ' . count($depthCases));
foreach ($depthCases as $d) {
    try {
        [$got, $why] = \Atlas\Pca\Tests\DepthCases::run($d);
        $check($got === $d->get('valid'), 'depth ' . $d->get('name') . ': ' . $str($got) . ', want ' . $str($d->get('valid')) . " ($why)");
    } catch (\Throwable $t) {
        $check(false, 'depth ' . $d->get('name') . ': THREW ' . get_class($t) . ': ' . $t->getMessage());
    }
}
echo 'depth: ' . count($depthCases) . " cases\n";

// ---------------------------------------------------------------------------------------
// 0.4.1 (gen-conformance-041.mjs). primitives.caveat_eval: the policy-layer helpers, evaluateCaveats(policyCaveats(grant,
// chain), context) == expect {allow, failed} (root caveats outside the envelope are evaluated like delegated ones).
// primitives.pca_header: the PCA-Action header is strict unpadded base64url of strict UTF-8 (decodePcaHeader).
// ---------------------------------------------------------------------------------------
$caveatEval = $prim->has('caveat_eval') ? $prim->get('caveat_eval') : [];
$check(count($caveatEval) >= 40, 'primitives.caveat_eval: expected at least 40 cases, got ' . count($caveatEval));
$ceFails = 0;
foreach ($caveatEval as $c) {
    $exp = $c->get('expect');
    try {
        $r = Pca::evaluateCaveats(Pca::policyCaveats($c->get('grant'), $c->get('chain')), $c->get('context'));
        $ok = $r['ok'] === $exp->get('allow') && $r['failed'] === $exp->get('failed');
        $check($ok, 'caveat_eval ' . $c->get('name') . ': got ' . json_encode($r) . ', want allow=' . $str($exp->get('allow'))
            . ' failed=' . json_encode($exp->get('failed')));
    } catch (\Throwable $t) {
        $ok = false;
        $check(false, 'caveat_eval ' . $c->get('name') . ': THREW ' . get_class($t) . ': ' . $t->getMessage());
    }
    $ceFails += $ok ? 0 : 1;
}
$pcaHeader = $prim->has('pca_header') ? $prim->get('pca_header') : [];
$check(count($pcaHeader) >= 27, 'primitives.pca_header: expected at least 27 cases, got ' . count($pcaHeader));
$phFails = 0;
foreach ($pcaHeader as $c) {
    try {
        $got = Pca::decodePcaHeader($c->get('input'));
        $ok = ($got !== null) === $c->get('valid') && ($got === null || $got === $c->get('text'));
        $check($ok, 'pca_header ' . $c->get('name') . ': got ' . $str($got) . ', want valid=' . $str($c->get('valid')));
    } catch (\Throwable $t) {
        $ok = false;
        $check(false, 'pca_header ' . $c->get('name') . ': THREW ' . get_class($t) . ': ' . $t->getMessage());
    }
    $phFails += $ok ? 0 : 1;
}
echo 'caveat_eval: ' . (count($caveatEval) - $ceFails) . '/' . count($caveatEval) . ' pass; pca_header: '
    . (count($pcaHeader) - $phFails) . '/' . count($pcaHeader) . " pass\n";

// ---------------------------------------------------------------------------------------
// Intent Layer v2 primitives (rules 13-19 on their own; Corpus::INTENT_PRIMITIVES through IntentV2::primitive). Compared as
// canonical JSON; reasons never compared (expect.reason_contains is asserted); requires_suite outside the manifest must refuse
// with unsupported_suite; absent tables are reported.
// ---------------------------------------------------------------------------------------
$intentPrims = Corpus::runIntentPrimitives($prim, $check);
$parts = [];
foreach ($intentPrims as $table => $c) {
    $parts[] = !empty($c['absent']) ? "$table=absent" : "$table={$c['ran']}" . ($c['unsupported'] > 0 ? " ({$c['unsupported']} unsupported_suite)" : '');
}
echo 'intent primitives: ' . implode('  ', $parts) . "\n";
echo "intent v2 requires_suite: $v2Unsupported vectors outside the suite manifest denied with unsupported_suite\n";

echo "primitives: $n canonical/json_parse/b64u cases + merkle + params_digest pass\n";
echo "threshold shares (v2.1 binding): $shareAccepted valid accepted, $shareRejected invalid rejected, $shareSkipped valid skipped (unsupported suite)"
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
