<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Core + adversarial conformance corpus and the characterization snapshot (oracle for mutation testing). */
final class CorpusTest extends TestCase
{
    private const CHUNKS = 16;
    private const SUPPORTED = Pca::REGISTERED_SUITES; // filtered by Pca::suiteAvailable (the runtime capability manifest)

    public static function chunks(): array
    {
        return array_map(fn($i) => [$i], range(0, self::CHUNKS - 1));
    }

    private static function algOf(mixed $o): string
    {
        $a = ($o instanceof Obj && $o->has('alg')) ? $o->get('alg') : 'ed25519';
        return is_string($a) ? $a : 'ed25519';
    }

    private static function unsupported(Obj $v, bool $adv): ?string
    {
        if ($adv) {
            return null; // adversarial vectors are raw pcactn_json
        }
        /** @var Obj $v */
        if (!$v->has('pcactn') || !($v->get('pcactn') instanceof Obj)) {
            return null;
        }
        $p = $v->get('pcactn');
        $req = $v->has('requires') ? $v->get('requires') : null;
        $suiteOk = fn($a) => in_array($a, self::SUPPORTED, true) && Pca::suiteAvailable($a);
        if ($req === 'pq') {
            $a = self::algOf($p);
            return $suiteOk($a) ? null : $a;
        }
        if ($req === 'pq-nonleaf') {
            foreach (is_array($p->get('cap_chain')) ? $p->get('cap_chain') : [] as $h) {
                $a = self::algOf($h);
                if (!$suiteOk($a)) {
                    return $a;
                }
            }
            return null;
        }
        // 0.4.1: a vector that names one concrete suite (`requires: "ml-dsa-87"`) this verifier lacks.
        if (is_string($req) && $req !== '' && !$suiteOk($req)) {
            return $req;
        }
        // the r041 ML-DSA-65 threshold-share vectors carry no `requires`: read the share suites
        $th = $p->has('threshold') ? $p->get('threshold') : null;
        $shares = ($th instanceof Obj && $th->has('shares')) ? $th->get('shares') : null;
        foreach (is_array($shares) ? $shares : [] as $sh) {
            $a = self::algOf($sh);
            if (!$suiteOk($a)) {
                return $a;
            }
        }
        return null;
    }

    private function checkSnapshot(array $computed): void
    {
        $exp = Corpus::snapshot();
        foreach ($computed as $k => $v) {
            $key = Corpus::esc($k);
            if (isset($exp[$key])) {
                // The snapshot was recorded with every OpenSSL PQ suite available. On a host without one (ubuntu-24.04's
                // OpenSSL 3.0, Windows) the verifier refuses that suite instead: tolerated only as a DENY whose reason
                // names a suite this host really lacks, never as a different allow.
                if ($exp[$key] !== $v && is_string($v) && str_starts_with($v, 'false|') && str_contains($v, 'unsupported_suite')) {
                    // the named suite must really be missing here; an unnamed one (accumulator receipts) needs ML-DSA-65 missing
                    $named = preg_match("/unsupported_suite: '?([a-z0-9-]+)/", $v, $m) === 1 ? $m[1] : 'ml-dsa-65';
                    if (!Pca::suiteAvailable($named)) {
                        continue;
                    }
                }
                $this->assertSame($exp[$key], $v, $key);
            }
        }
    }

    public function testCoreVectors(): void
    {
        foreach (Corpus::core()->get('vectors') as $v) {
            $wantChecks = $v->get('expect')->get('checks');
            $terminalWire = $wantChecks->keys() === ['wire'] && $wantChecks->get('wire') === false;
            if (self::unsupported($v, false) !== null && !$terminalWire) {
                continue;
            }
            $rs = Corpus::requiresSuite($v);
            $got = Corpus::verifyCore($v);
            $name = $v->get('name');
            $expect = $v->get('expect');
            if ($expect->has('reason_contains')) {
                $this->assertStringContainsString((string)$expect->get('reason_contains'), $got['reason'], $name);
            }
            if ($rs === 'unsupported') {
                $this->assertFalse($got['allow'], $name);
                // a named refusal (reason_contains, asserted above) precedes the suite work: no unsupported_suite needed
                if (Corpus::firstFailureIsV2($got) && !$expect->has('reason_contains')) {
                    $this->assertStringContainsString('unsupported_suite', $got['reason'], $name);
                }
                continue;
            }
            $this->assertSame($expect->get('allow'), $got['allow'], $name);
            foreach ($wantChecks->keys() as $k) {
                $this->assertSame($wantChecks->get($k), $got['checks'][$k] ?? null, "$name $k");
            }
            // Intent Layer M2 / v2: `intent` and the v2 checks are appended after `counter` exactly when the vector expects them.
            $order = Corpus::expectedOrder(array_map(fn($x) => $x, Corpus::core()->get('check_order')), $wantChecks);
            $this->assertSame(array_keys($got['checks']), $terminalWire ? ['wire'] : $order, $name);
        }
        $this->checkSnapshot(Corpus::computeVectors(false, 0, 1));
    }

    #[DataProvider('chunks')]
    public function testAdversarialChunk(int $k): void
    {
        foreach (Corpus::adv()['vectors'] as $i => $v) {
            if ($i % self::CHUNKS !== $k) {
                continue;
            }
            $got = Corpus::verifyAdv($v);
            $this->assertSame($v['expect']['allow'], $got['allow'], $v['name']);
            foreach ($v['expect']['checks'] as $c => $want) {
                $this->assertSame($want, $got['checks'][$c] ?? null, $v['name'] . ' ' . $c);
            }
        }
        $this->checkSnapshot(Corpus::computeVectors(true, $k, self::CHUNKS));
    }

    #[DataProvider('chunks')]
    public function testInputsChunk(int $k): void
    {
        $this->checkSnapshot(Corpus::computeInputs($k, self::CHUNKS));
    }

    public function testPrimitives(): void
    {
        $prim = Corpus::core()->get('primitives');
        foreach ($prim->get('canonical') as $c) {
            $this->assertSame($c->get('expect'), Json::canonicalizeStrict($c->get('value')));
            $this->assertSame($c->get('hash'), Pca::hashCanonical($c->get('value')));
        }
        foreach ($prim->get('merkle') as $m) {
            $root = Pca::merkleRoot($m->get('leaves'));
            $this->assertSame($m->get('root'), $root);
            foreach ($m->get('proofs') as $i => $p) {
                $this->assertTrue(Pca::verifyInclusion($root, $p, $m->get('leaves')[$i]));
            }
        }
        $this->assertSame($prim->get('params_digest_empty'), Pca::paramsDigest());
        $advp = Corpus::adv()['primitives'];
        foreach ($advp['b64u'] as $b) {
            $this->assertSame($b['valid'], Pca::unb64u($b['input'], isset($b['len']) ? (int)$b['len'] : null) !== null, json_encode($b['input']));
        }
        foreach ($advp['json_parse'] as $j) {
            $ok = true;
            $out = null;
            try {
                $out = Json::canonicalizeStrict(Json::parseStrict($j['input']));
            } catch (\Atlas\Pca\JsonError) {
                $ok = false;
            }
            $this->assertSame($j['accept'], $ok, json_encode($j['input']));
            if ($ok && isset($j['canonical'])) {
                $this->assertSame($j['canonical'], $out);
            }
        }
    }

    /** Intent Layer v2 primitives (rules 13-19 on their own): every comparison of Corpus::runIntentPrimitives must hold. */
    public function testIntentPrimitives(): void
    {
        $fails = [];
        $counts = Corpus::runIntentPrimitives(Corpus::core()->get('primitives'), function (bool $ok, string $msg) use (&$fails): void {
            if (!$ok) {
                $fails[] = $msg;
            }
        });
        $this->assertSame([], $fails);
        $this->assertArrayHasKey('intent_schema', $counts);
    }

    public function testThresholdSharesAndArtifacts(): void
    {
        $prim = Corpus::core()->get('primitives');
        foreach ($prim->get('threshold_share') as $sh) {
            $alg = $sh->get('share')->has('alg') ? $sh->get('share')->get('alg') : 'ed25519';
            if (!in_array($alg, self::SUPPORTED, true) || !Pca::suiteAvailable($alg)) {
                continue;
            }
            $want = $sh->has('valid') ? $sh->get('valid') : true;
            $this->assertSame($want, Pca::verifyThresholdShare($sh), (string)($sh->has('name') ? $sh->get('name') : $sh->get('role')));
        }
    }
}
