<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Zk.php';

use Atlas\Pca\Assurance;
use Atlas\Pca\Js;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Zk;
use Atlas\Pca\ZkBackendMissing;
use Atlas\Pca\ZkCeremony;
use Atlas\Pca\ZkNative;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The zk compliance module (attested-VM statements, the Groth16 / Policy VM verifier and its gates, public-input derivation, the
 * SNARK backends, circuit provenance and ceremony transcripts) against the TS reference: every case of test-data/ref-zk.json.gz.
 * Argument conventions: {"$bigint"} is a \GMP, {"$num"} a non-finite double, {"$bytes": {"$seed": label}} the 32-byte secret
 * sha256("atlas-pca-conformance/" . label), {"$expectThunk": X} a closure returning X ("throw": one that throws), "$absent" an
 * argument that is not given. The cases that reach the pairing check need libpcazk: without it they are skipped, and
 * ATLAS_PCA_LIBPCAZK_REQUIRED=1 makes its absence a failure.
 */
final class RefZkDifferentialTest extends TestCase
{
    private const FILE = 'ref-zk.json.gz';
    private const TOTAL = 1429;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function rv(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::rv(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        $k = $v->keys();
        if ($k === ['$bigint']) {
            return gmp_init((string) $v->get('$bigint'), 10);
        }
        if ($k === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        if ($k === ['$bytes'] && $v->get('$bytes') instanceof Obj) {
            return hash('sha256', 'atlas-pca-conformance/' . $v->get('$bytes')->get('$seed'), true);
        }
        $o = new Obj();
        foreach ($k as $x) {
            $o->set($x, self::rv($v->get($x)));
        }
        return $o;
    }

    /** An empty hash-halves array is an empty JSON object in the reference ({}), which a PHP array cannot express. */
    private static function objectMembers(array $o): array
    {
        return array_map(static fn(mixed $v): mixed => $v === [] ? new Obj() : $v, $o);
    }

    private static function expectOf(mixed $e): mixed
    {
        if ($e === '$absent') {
            return Zk::NO_EXPECT;
        }
        if ($e instanceof Obj && $e->has('$expectThunk')) {
            $x = $e->get('$expectThunk');
            return $x === 'throw' ? static fn() => throw new \RuntimeException('thunk') : static fn() => $x;
        }
        return $e;
    }

    /** The top-level members of an options object as a PHP array (revived), with `expect` turned into its source. */
    private static function opts(mixed $o, bool $thunks = true): array
    {
        $out = [];
        foreach ($o instanceof Obj ? $o->keys() : [] as $k) {
            $out[$k] = self::rv($o->get($k));
            if ($k === 'expect' && $thunks) {
                $out[$k] = self::expectOf($o->get($k) instanceof Obj && $o->get($k)->has('$expectThunk') ? $o->get($k) : $out[$k]);
            }
        }
        return $out;
    }

    /** @return ?array{level:string,vendor?:string,ceremony?:string} */
    private static function label(object $o): ?array
    {
        $l = Assurance::labelOf($o);
        return $l === null ? null : array_filter(['level' => $l->level, 'vendor' => $l->vendor, 'ceremony' => $l->ceremony], static fn($v): bool => $v !== null);
    }

    private static function big(mixed $v): mixed
    {
        return is_array($v) ? array_map(self::big(...), $v) : Obj::of(['$bigint' => $v]);
    }

    /** `$f($a[0])` or `$f($a[0], $a[1])` as the case gives them (revived). */
    private static function quant(callable $f, array $a): mixed
    {
        $x = self::rv($a[0] ?? null);
        return array_key_exists(1, $a) ? $f($x, self::rv($a[1])) : $f($x);
    }

    private static function arg(array $a, int $i): mixed
    {
        return ($a[$i] ?? null) === '$absent' ? null : ($a[$i] ?? null);
    }

    private static function relative(string $path): string
    {
        return substr($path, strlen(dirname(__DIR__)) + 1);
    }

    /** Runs a mapper that may reach the pairing check; without the library the case is skipped (never decided). */
    private static function native(callable $f): mixed
    {
        try {
            return $f();
        } catch (ZkBackendMissing) {
            return [Base::SKIP, 'needs libpcazk'];
        }
    }

    private static function backend(callable $make, array $a): mixed
    {
        return self::native(static function () use ($make, $a): array {
            $b = $make(self::opts($a[0]));
            $in = $a[1];
            return ['verified' => $b->verify(['proof' => $in->get('proof'), 'publicInputs' => $in->get('publicInputs'), 'ctx' => $in->get('ctx')]), 'label' => self::label($b)];
        });
    }

    private const SNARK = ['groth16' => 'createGroth16SnarkBackend', 'policyvm' => 'createPolicyVmSnarkBackend', 'policyvm-bls' => 'createPolicyVmSnarkBackendBls12381',
        'policyvm-bound' => 'createPolicyVmBoundSnarkBackend'];

    private static function zkVerifier(array $a): mixed
    {
        $s = $a[0];
        $snark = $s->get('snark');
        if ($snark instanceof Obj && !ZkNative::available()) {
            return [Base::SKIP, 'needs libpcazk'];
        }
        $opts = ['now' => static fn() => Js::num($s->get('nowMs'))];
        foreach (['trustedProverKeys', 'policyCommitments', 'revokedProverKeys', 'clockSkewMs'] as $k) {
            if ($s->has($k)) {
                $opts[$k] = self::rv($s->get($k));
            }
        }
        if ($snark instanceof Obj) {
            $opts['snarkBackend'] = Zk::{self::SNARK[$snark->get('kind')]}(self::opts($snark->get('opts'), false));
        }
        $hook = Zk::createZkVerifier($opts);
        $result = $hook($a[1]);
        if (isset($result['reason'])) {
            $result['reason'] = preg_replace('/(zk verification error \(fail closed\)): .*$/s', '$1', $result['reason']);
        }
        return ['result' => $result, 'label' => self::label($hook)];
    }

    /** The prover contract: the bundled sample proof carries exactly the recorded public signals and verifies under the bundled key. */
    private static function proveContract(): mixed
    {
        $sample = Js::parse((string) file_get_contents(Zk::policyVmSampleProofPath()));
        return self::native(static function () use ($sample): array {
            if (!Zk::verifyPolicyVmProof($sample)) {
                throw new \RuntimeException('the bundled sample proof does not verify under the bundled key');
            }
            return ['publicSignals' => $sample->get('publicSignals'), 'verifiesUnder' => 'VK_BN', 'sampleProofCircuit' => $sample->get('circuit')];
        });
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $paths = ['DEFAULT_VKEY_PATH' => 'defaultVkeyPath', 'DEFAULT_WASM_PATH' => 'defaultWasmPath', 'DEFAULT_ZKEY_PATH' => 'defaultZkeyPath',
            'POLICYVM_VKEY_PATH' => 'policyVmVkeyPath', 'POLICYVM_SAMPLE_PROOF_PATH' => 'policyVmSampleProofPath', 'POLICYVM_WASM_PATH' => 'policyVmWasmPath',
            'POLICYVM_ZKEY_PATH' => 'policyVmZkeyPath', 'POLICYVM_BLS12381_VKEY_PATH' => 'policyVmBls12381VkeyPath',
            'POLICYVM_BLS12381_SAMPLE_PROOF_PATH' => 'policyVmBls12381SampleProofPath', 'POLICYVM_BOUND_VKEY_PATH' => 'policyVmBoundVkeyPath',
            'POLICYVM_BOUND_SAMPLE_PROOF_PATH' => 'policyVmBoundSampleProofPath', 'POLICYVM_BOUND_WASM_PATH' => 'policyVmBoundWasmPath',
            'POLICYVM_BOUND_ZKEY_PATH' => 'policyVmBoundZkeyPath'];
        $map = [
            'constants' => static fn(array $a) => [
                'ZK_PROVER_BINDING_REF' => Zk::ZK_PROVER_BINDING_REF, 'POLICYVM_PUBLIC_SIGNAL' => Zk::POLICYVM_PUBLIC_SIGNAL,
                'POLICYVM_PUBLIC_SIGNAL_COUNT' => Zk::POLICYVM_PUBLIC_SIGNAL_COUNT, 'POLICYVM_BOUND_PUBLIC_SIGNAL' => Zk::POLICYVM_BOUND_PUBLIC_SIGNAL,
                'POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT' => Zk::POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT, 'POLICYVM_BOUND_RISK_FIELDS' => Zk::POLICYVM_BOUND_RISK_FIELDS,
                'POLICYVM_REVERSIBILITY_ORDER' => Zk::POLICYVM_REVERSIBILITY_ORDER,
                'paths' => array_map(static fn(string $m): string => self::relative(Zk::$m()), $paths),
            ],
            'policyCommitment' => static fn(array $a) => Zk::policyCommitment($a[0]),
            'pinnedPolicyCommitment' => static fn(array $a) => Zk::pinnedPolicyCommitment($a[0]),
            'actionCommitment' => static fn(array $a) => Zk::actionCommitment($a[0]),
            'proverKeyBinding' => static fn(array $a) => Zk::proverKeyBinding($a[0], $a[1], $a[2]),
            'commitmentField' => static fn(array $a) => Zk::commitmentField($a[0]),
            'policyVmStructHash' => static fn(array $a) => Zk::policyVmStructHash(self::rv($a[0])),
            'policyVmRiskHash' => static fn(array $a) => Zk::policyVmRiskHash(self::rv($a[0])),
            'quantizeActionStruct' => static fn(array $a) => self::big(self::quant(Zk::quantizeActionStruct(...), $a)),
            'quantizePlanStruct' => static fn(array $a) => self::big(self::quant(Zk::quantizePlanStruct(...), $a)),
            'quantizePolicyStruct' => static fn(array $a) => self::big(self::quant(Zk::quantizePolicyStruct(...), $a)),
            'quantizePolicyVmInputs' => static fn(array $a) => array_map(self::big(...), self::quant(Zk::quantizePolicyVmInputs(...), $a)),
            'policyVmCommitmentFromAction' => static fn(array $a) => self::quant(Zk::policyVmCommitmentFromAction(...), $a),
            'decodePolicyVmPublic' => static fn(array $a) => self::objectMembers(Zk::decodePolicyVmPublic($a[0])),
            'decodePolicyVmBoundPublic' => static fn(array $a) => self::objectMembers(Zk::decodePolicyVmBoundPublic($a[0])),
            'policyVmContextMatches' => static fn(array $a) => Zk::policyVmContextMatches($a[0], self::expectOf(array_key_exists(1, $a) ? $a[1] : '$absent'), ($a[2] ?? null) === 'bound'),
            'isCanonicalGroth16Envelope' => static fn(array $a) => Zk::isCanonicalGroth16Envelope($a[0], $a[1]),
            'verifyPolicyVmProof' => static fn(array $a) => self::native(static fn(): bool => Zk::verifyPolicyVmProof($a[0], self::opts($a[1] ?? null))),
            'createZkVerifier' => static fn(array $a) => self::zkVerifier($a),
            'createAttestedComplianceProver' => static function (array $a) {
                $p = Zk::createAttestedComplianceProver(self::rv($a[0]));
                return ['publicKey' => $p->publicKey, 'statement' => $p->prove($a[1])];
            },
            'circuitVersion' => static fn(array $a) => Zk::circuitVersion($a[0] ?? null),
            'provePolicyVmCompliance' => static fn(array $a) => self::proveContract(),
            'vkId' => static fn(array $a) => ZkCeremony::vkId($a[0]),
            'circuitProvenance' => static fn(array $a) => ZkCeremony::circuitProvenance($a[0]),
            'checkCircuitProvenance' => static fn(array $a) => ZkCeremony::checkCircuitProvenance(self::arg($a, 0), $a[1]),
            'transcriptSha256' => static fn(array $a) => ZkCeremony::transcriptSha256($a[0]),
            'checkTranscript' => static fn(array $a) => ZkCeremony::checkTranscript(self::arg($a, 0), self::arg($a, 1)),
            'ceremonyOf' => static fn(array $a) => ZkCeremony::ceremonyOf(self::arg($a, 0), self::arg($a, 1)),
        ];
        foreach (self::SNARK as $make) {
            $map[$make] = static fn(array $a) => self::backend(Zk::$make(...), $a);
        }
        Base::run($file, $fn, $k, $map);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
    }

    public function testTheLibraryIsPresentWhereRequired(): void
    {
        if (getenv('ATLAS_PCA_LIBPCAZK_REQUIRED') !== '1') {
            $this->markTestSkipped('libpcazk is optional here');
        }
        $this->assertTrue(ZkNative::available(), 'libpcazk is required here (ATLAS_PCA_LIBPCAZK)');
        $bls = Js::parse((string) file_get_contents(Zk::policyVmBls12381SampleProofPath()));
        $this->assertTrue(Zk::verifyPolicyVmProof($bls));
        $this->assertInstanceOf(Num::class, new Num('1'));
    }
}
