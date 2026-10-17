<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Mldsa;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * The shared-corpus sections that exercise the PQ threshold-share, PQ artifact and PQ chain-pin paths with REAL ML-DSA-65
 * signatures from the TypeScript reference (primitives.threshold_set / signer_set_hash / malformed / pq_artifact /
 * chain_pin of packages/pca/conformance/vectors.json), so the PHPUnit oracle (and Infection) reaches Mldsa.php and the
 * pure-PQ / hybrid branches of verifyThresholdShare, not only conformance.php. ML-DSA needs OpenSSL >= 3.5 via FFI
 * (ATLAS_PCA_LIBCRYPTO); with PCA_REQUIRE_MLDSA=1 (the mutation run sets it) an unavailable ML-DSA is a FAILURE, never a
 * silent skip.
 */
final class PqThresholdCorpusTest extends TestCase
{
    private const CROSS = Pca::REGISTERED_SUITES; // filtered by Pca::suiteAvailable (the runtime capability manifest)

    private function mldsa(): bool
    {
        if (Mldsa::available()) {
            return true;
        }
        if (getenv('PCA_REQUIRE_MLDSA') === '1') {
            $this->fail('PCA_REQUIRE_MLDSA=1 but ML-DSA-65 (OpenSSL >= 3.5 libcrypto via FFI) is not available');
        }
        return false;
    }

    private static function prim(): Obj
    {
        return Corpus::core()->get('primitives');
    }

    public function testThresholdSetWholeSignerSet(): void
    {
        $have = $this->mldsa();
        $ran = $pq = $pqValid = 0;
        foreach (self::prim()->get('threshold_set') as $e) {
            $req = $e->has('requires') ? $e->get('requires') : null;
            if (is_string($req) && (!in_array($req, self::CROSS, true) || ($req !== 'ed25519' && !$have))) {
                continue;
            }
            $ran++;
            if ($req === 'ml-dsa-65') {
                $pq++;
                $pqValid += $e->get('valid') ? 1 : 0;
            }
            $this->assertSame($e->get('valid'), Pca::verifyThresholdShare($e), (string)$e->get('name'));
        }
        $this->assertGreaterThanOrEqual($have ? 57 : 41, $ran);
        if ($have) {
            $this->assertGreaterThanOrEqual(16, $pq, 'ML-DSA threshold_set vectors ran');
            $this->assertGreaterThanOrEqual(3, $pqValid, 'valid ML-DSA / hybrid threshold shares');
        }
    }

    /** A valid PQ / hybrid share stops verifying when ANY byte of its pq_sig, sig or the bound message changes. */
    public function testValidPqSharesAreBoundToEveryInput(): void
    {
        if (!$this->mldsa()) {
            $this->markTestSkipped('ML-DSA-65 unavailable');
        }
        $n = 0;
        foreach (self::prim()->get('threshold_set') as $e) {
            if (!$e->get('valid') || ($e->has('requires') ? $e->get('requires') : null) !== 'ml-dsa-65') {
                continue;
            }
            $n++;
            $name = (string)$e->get('name');
            $this->assertTrue(Pca::verifyThresholdShare($e), $name);
            $share = $e->get('share');
            foreach (['pq_sig', 'sig'] as $f) {
                if (!$share->has($f)) {
                    continue;
                }
                $raw = Pca::unb64u($share->get($f));
                $raw[10] = chr(ord($raw[10]) ^ 1);
                $bad = $e->without('share');
                $bad->set('share', $share->without($f));
                $bad->get('share')->set($f, Pca::b64u($raw));
                $this->assertFalse(Pca::verifyThresholdShare($bad), "$name: flipped $f");
            }
            $m = Pca::unb64u($e->get('threshold_message'));
            $m[0] = chr(ord($m[0]) ^ 1);
            $bad = $e->without('threshold_message');
            $bad->set('threshold_message', Pca::b64u($m));
            $this->assertFalse(Pca::verifyThresholdShare($bad), "$name: other threshold message");
            foreach (['2', '3'] as $t) {
                $bad = $e->without('t');
                $bad->set('t', new \Atlas\Pca\Num($t));
                $this->assertFalse(Pca::verifyThresholdShare($bad), "$name: t=$t");
            }
        }
        $this->assertGreaterThanOrEqual(3, $n);
    }

    public function testSignerSetHash(): void
    {
        foreach (self::prim()->get('signer_set_hash') as $e) {
            $h = Pca::signerSetHashRaw($e->get('signer_set'));
            $this->assertSame($e->get('hash'), $h === null ? null : Pca::b64u($h), (string)$e->get('name'));
        }
    }

    /** R6-05: every malformed entry is a clean deny through the public entry point (no exception escapes). */
    public function testMalformedAreCleanDenies(): void
    {
        $n = 0;
        foreach (self::prim()->get('malformed') as $m) {
            $n++;
            $nm = (string)$m->get('name');
            $in = $m->get('input');
            switch ($m->get('api')) {
                case 'chain':
                    [$why, $ok] = Pca::verifyChain($in->get('chain'), $in->get('expected_root_issuer'), true);
                    $this->assertFalse($ok, $nm);
                    $this->assertIsString($why, $nm);
                    break;
                case 'threshold_share':
                    $this->assertFalse(Pca::verifyThresholdShare($in), $nm);
                    break;
                case 'pcactn_json':
                    $v = Pca::verifyJson($in->get('text'), $in->get('grant'), $in->get('now')->int(), $in->get('aud'));
                    $this->assertFalse($v['allow'], $nm);
                    break;
                default:
                    $this->fail("$nm: unknown api");
            }
        }
        $this->assertGreaterThanOrEqual(80, $n);
    }

    public function testPqArtifacts(): void
    {
        $have = $this->mldsa();
        $ran = 0;
        foreach (self::prim()->get('pq_artifact') as $a) {
            $alg = $a->has('alg') ? $a->get('alg') : 'ed25519';
            if (!in_array($alg, self::CROSS, true) || !Pca::suiteAvailable($alg)) {
                continue;
            }
            $ran++;
            $msg = Pca::unb64u($a->get('message'));
            $want = $a->has('valid') ? $a->get('valid') : true;
            $this->assertSame($want, $msg !== null && Pca::verifyArtifact($a, $msg), ($a->has('artifact') ? $a->get('artifact') : '?') . "/$alg");
        }
        $this->assertGreaterThan(0, $ran);
    }

    public function testChainPins(): void
    {
        $have = $this->mldsa();
        $ran = 0;
        foreach (self::prim()->get('chain_pin') as $v) {
            $exp = $v->get('expect');
            $reason = $exp->has('reason') ? $exp->get('reason') : '';
            $pinRefusal = str_starts_with($reason, 'hop 0: root suite');
            $needsPq = false;
            foreach ($v->get('chain') as $hop) {
                $a = ($hop instanceof Obj && $hop->has('alg')) ? $hop->get('alg') : 'ed25519';
                $needsPq = $needsPq || $a !== 'ed25519';
            }
            if ($needsPq && !$pinRefusal && !$have) {
                continue;
            }
            $ran++;
            $eri = $v->get('expected_root_issuer');
            [$why, $ok] = Pca::verifyChain(
                $v->get('chain'), $eri, is_string($eri),
                $v->has('allowed_suites') ? $v->get('allowed_suites') : null,
                $v->has('pq_pins') ? $v->get('pq_pins') : null,
                $v->has('trusted_root') ? $v->get('trusted_root') : null,
            );
            $this->assertSame($exp->get('ok'), $ok, $v->get('name') . " ($why)");
            if ($pinRefusal) {
                $this->assertSame($reason, $why, (string)$v->get('name'));
            }
        }
        // without ML-DSA only the ed25519 chains and the hop-0 pin refusals (which need no crypto) run
        $this->assertGreaterThanOrEqual($have ? 25 : 14, $ran);
    }
}
