<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ZkNative.php';

use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\ZkBackendMissing;
use Atlas\Pca\ZkNative;
use PHPUnit\Framework\TestCase;

/**
 * The Groth16 pairing check through libpcazk against the TS reference: the verifyPolicyVmProof cases of test-data/ref-zk.json.gz
 * on BN254 and BLS12-381. The corpus holds end-to-end verdicts, which include gates that run before the pairing (envelope shape,
 * circuit and system tags, pinned signals); the refusals those gates alone decide (including the proof's protocol and curve labels) are left out here (GATE_ONLY). Every other case
 * must agree: in the default mode with the reference, in strict mode with the reference except the quirk-* cases, which the
 * reference accepts and strict mode refuses. Skipped without the library; ATLAS_PCA_LIBPCAZK_REQUIRED=1 makes that a failure.
 */
final class RefZkNativeDifferentialTest extends TestCase
{
    private const FILE = 'ref-zk.json.gz';
    private const GATE_ONLY = ['expect-now-wrong', 'expect-thunk-throws', 'expectRiskHash', 'circuit-', 'system-', 'extra-key', 'proof-extra-key', 'protocol-plonk', 'proof-curve-wrong'];

    protected function setUp(): void
    {
        if (ZkNative::available()) {
            return;
        }
        if (getenv('ATLAS_PCA_LIBPCAZK_REQUIRED') === '1') {
            $this->fail('libpcazk is required here (ATLAS_PCA_LIBPCAZK)');
        }
        $this->markTestSkipped('needs libpcazk (ATLAS_PCA_LIBPCAZK)');
    }

    private static function gateOnly(string $stem): bool
    {
        foreach (self::GATE_ONLY as $g) {
            if (str_starts_with($stem, $g)) {
                return true;
            }
        }
        return false;
    }

    public function testThePairingVerdictsAgreeWithTheReference(): void
    {
        $this->assertNotSame('', ZkNative::version());
        $cases = Base::cases(self::FILE, 'verifyPolicyVmProof', 0);
        $checked = 0;
        foreach (['verifyPolicyVmProof/bn/' => ZkNative::CURVE_BN254, 'verifyPolicyVmProof/bls/' => ZkNative::CURVE_BLS12_381] as $prefix => $curve) {
            $defaultKey = null;
            foreach ($cases as $c) {
                if ($c->get('name') === $prefix . 'valid') {
                    $defaultKey = $c->get('args')[1]->get('verificationKey');
                }
            }
            $this->assertInstanceOf(Obj::class, $defaultKey, "$prefix: no valid case");
            foreach ($cases as $c) {
                $name = (string) $c->get('name');
                if (!str_starts_with($name, $prefix)) {
                    continue;
                }
                $stem = substr($name, strlen($prefix));
                $env = $c->get('args')[0];
                $opts = $c->get('args')[1] ?? null;
                $vk = ($opts instanceof Obj ? $opts->get('verificationKey') : null) ?? $defaultKey;
                $proof = Js::stringify($env instanceof Obj ? $env->get('proof') : null);
                $signals = Js::stringify($env instanceof Obj ? $env->get('publicSignals') : null);
                $compat = ZkNative::verify($curve, Js::stringify($vk), $proof, $signals)['ok'];
                $strict = ZkNative::verify($curve, Js::stringify($vk), $proof, $signals, true)['ok'];
                if ($c->get('out') === true) {
                    $this->assertTrue($compat, "$name: the default mode must accept");
                    $this->assertSame(!str_starts_with($stem, 'quirk'), $strict, "$name: strict mode verdict");
                } elseif (!self::gateOnly($stem)) {
                    $this->assertFalse($compat || $strict, "$name: must be refused in both modes");
                } else {
                    continue;
                }
                $checked++;
            }
        }
        $this->assertGreaterThan(120, $checked);
    }

    /** The key's curve name alone picks the curve in the default mode, read as the reference verifier reads it (aliases included). */
    public function testTheKeyNamesItsCurve(): void
    {
        $cases = Base::cases(self::FILE, 'verifyPolicyVmProof', 0);
        $checked = 0;
        foreach (['verifyPolicyVmProof/bn/valid' => ['bn128', 'BN254', 'alt_bn128', 'Bn-128'], 'verifyPolicyVmProof/bls/valid' => ['bls12381', 'bls12-381', 'BLS12_381']] as $name => $aliases) {
            foreach ($cases as $c) {
                if ($c->get('name') !== $name) {
                    continue;
                }
                $key = json_decode(Js::stringify($c->get('args')[1]->get('verificationKey')), true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
                $proof = Js::stringify($c->get('args')[0]->get('proof'));
                $signals = Js::stringify($c->get('args')[0]->get('publicSignals'));
                foreach ($aliases as $alias) {
                    $vk = json_encode(['curve' => $alias] + $key, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                    $this->assertSame(['ok' => true, 'reason' => null], ZkNative::verify(ZkNative::CURVE_FROM_KEY, $vk, $proof, $signals), "$name as $alias");
                    $checked++;
                }
                foreach (['secp256k1', '', '--'] as $unknown) {
                    $vk = json_encode(['curve' => $unknown] + $key, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                    $r = ZkNative::verify(ZkNative::CURVE_FROM_KEY, $vk, $proof, $signals);
                    $this->assertFalse($r['ok'], "$name as '$unknown'");
                    $this->assertStringContainsString('curve', (string) $r['reason'], "$name as '$unknown'");
                }
                // the other curve's name over this key's points is never a valid proof
                $vk = json_encode(['curve' => str_contains($name, '/bn/') ? 'bls12381' : 'bn128'] + $key, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                $this->assertFalse(ZkNative::verify(ZkNative::CURVE_FROM_KEY, $vk, $proof, $signals)['ok'], "$name under the other curve's name");
            }
        }
        $this->assertSame(7, $checked);
    }

    public function testStrictModeNeedsAnExplicitCurve(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ZkNative::verify(ZkNative::CURVE_FROM_KEY, '{}', '{}', '[]', true);
    }

    public function testUsageErrorsAreNeverVerdicts(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ZkNative::verify(7, '{}', '{}', '[]');
    }

    public function testAMissingLibraryIsNotAVerdict(): void
    {
        $this->assertTrue(is_subclass_of(ZkBackendMissing::class, \RuntimeException::class));
        $this->assertSame(['ok' => false, 'reason' => 'bad_json'], ZkNative::verify(ZkNative::CURVE_BN254, '', '{}', '[]'));
    }
}
