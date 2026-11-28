<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Zk.php';

use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\Zk;
use Atlas\Pca\ZkBackendMissing;
use Atlas\Pca\ZkClosureBackend;
use Atlas\Pca\ZkNative;
use PHPUnit\Framework\TestCase;

/**
 * The zk compliance module's gates: the attested-VM verifier hook (statement checks, prover attestation, the backend path, the
 * clock), the Policy VM / compliance envelope gates in front of the pairing check, the BigInt and quantizer conversions, the
 * context pins, backend labels, circuit versions and the prover's argument handling. A gate that passes is observed as the key
 * load of a nonexistent verificationKeyPath ("zk: cannot read ..."), which happens before libpcazk is touched.
 */
final class PqSurvivorKill14ZkTest extends TestCase
{
    private const NOW = 1800000000000;
    private const NOKEY = '/nonexistent/zk14-vk.json';
    private const ACTION = ['verb' => 'read', 'resource' => '/r'];

    private static function kp(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/zk14/prover', true));
    }

    /** A signed attested-VM statement over ACTION, policy G and plan R (fields overridden / dropped as given). */
    private static function statement(array $over = [], array $drop = []): Obj
    {
        $b = array_merge(['v' => 1, 'mode' => 'attested-vm', 'action_commit' => Zk::actionCommitment(['action' => self::ACTION]), 'policy_commit' => 'G',
            'plan_commit' => 'R', 'released' => true, 'r' => 0, 'issued_at' => self::NOW - 1000, 'expires_at' => self::NOW + 60000,
            'prover' => self::kp()->public], $over);
        foreach ($drop as $k) {
            unset($b[$k]);
        }
        $body = Sign::n($b);
        $body->set('sig', Pca::b64u(self::kp()->sign(Zk::STATEMENT_DOMAIN . Json::canonicalizeNative($body))));
        return $body;
    }

    private static function ctx(mixed $proof): array
    {
        return ['pcactn' => ['action' => self::ACTION, 'plan' => ['root' => 'R'], 'zk_compliance' => $proof], 'grant' => ['id' => 'G']];
    }

    private static function refusal(string $reason): array
    {
        return ['enforced' => true, 'ok' => false, 'reason' => $reason];
    }

    private const OK = ['enforced' => true, 'ok' => true];

    private static function hw(mixed $result, string $level = 'hardware', ?string $vendor = 'acme', ?array &$seen = null): \Closure
    {
        $f = static function (array $a) use ($result, &$seen): mixed {
            $seen = $a;
            return $result instanceof \Closure ? $result() : $result;
        };
        Assurance::setLabel($f, new AssuranceLabel($level, $vendor));
        return $f;
    }

    private const HW_OK = ['ok' => true, 'bound' => true, 'measured' => ['runtime_measurement' => 'm1']];

    private static function attested(mixed $hwResult, ?array &$seen = null): \Closure
    {
        return Zk::createZkVerifier(['trustedProverKeys' => [self::kp()->public], 'now' => static fn(): int => self::NOW, 'proverAttestation' => [
            'hardwareVerifier' => self::hw($hwResult, 'hardware', 'acme', $seen), 'expectedBinding' => static fn(string $p): array => ['bind' => $p],
            'measurements' => ['m1']]]);
    }

    private function refuses(string $class, string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $message], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail("expected $class: $message");
    }

    private static function sample(): Obj
    {
        return Js::parse((string) file_get_contents(Zk::policyVmSampleProofPath()));
    }

    /** A canonical 17-signal risk-bound envelope (riskHi 7, riskLo 8) over the sample's BN254 proof points. */
    private static function bound(): Obj
    {
        $e = new Obj();
        $e->set('system', 'groth16-bn254');
        $e->set('circuit', 'pca-policyvm-v2');
        $e->set('proof', self::sample()->get('proof'));
        $e->set('publicSignals', ['1', '2', '3', '4', '5', '6', '0', '1', '1', '7', '8', '1', '1000', '0', '0', '0', '5']);
        return $e;
    }

    /** The 15 v1 context-test signals: now = $now, the rest small canonical decimals. */
    private static function ps(mixed $now = '1000', mixed $r = '0'): array
    {
        return ['1', '2', '3', '4', '5', '6', $r, '1', '1', '1', $now, '0', '0', '0', '5'];
    }

    private static function corpusArgs(string $name): array
    {
        foreach (gzfile(Base::path('ref-zk.json.gz')) as $l) {
            $l = rtrim($l, "\r\n");
            if (str_contains($l, '"name":"' . $name . '"')) {
                return (new Parser(str_ends_with($l, ',') ? substr($l, 0, -1) : $l, PHP_INT_MAX))->run()->get('args');
            }
        }
        throw new \LogicException("no corpus case $name");
    }

    private function emptyFile(): string
    {
        $p = (string) tempnam(sys_get_temp_dir(), 'zk14');
        $this->assertSame('', (string) file_get_contents($p));
        return $p;
    }

    // ---- the attested-VM hook ----------------------------------------------------------------------------------------------------

    /** The hook accepts a valid statement and refuses each broken window / binding with its exact reason. */
    public function testStatementWindowGates(): void
    {
        $hook = Zk::createZkVerifier(['trustedProverKeys' => [self::kp()->public], 'now' => static fn(): int => self::NOW]);
        $this->assertSame(self::OK, $hook(self::ctx(self::statement())));
        $this->assertSame(self::OK, $hook(self::ctx(self::statement(['issued_at' => self::NOW, 'expires_at' => self::NOW]))), 'a zero-width window is valid');
        $bad = self::refusal('malformed statement validity window');
        $this->assertSame($bad, $hook(self::ctx(self::statement([], ['issued_at']))));
        $this->assertSame($bad, $hook(self::ctx(self::statement([], ['expires_at']))));
        $this->assertSame($bad, $hook(self::ctx(self::statement(['issued_at' => self::NOW, 'expires_at' => self::NOW - 1]))));
    }

    /** A clock that throws is a fail-closed refusal carrying its message, or "unknown" when it has none. */
    public function testHookErrorsFailClosed(): void
    {
        foreach (['boom' => 'boom', '' => 'unknown'] as $msg => $want) {
            $hook = Zk::createZkVerifier(['trustedProverKeys' => [self::kp()->public], 'now' => static fn(): int => throw new \RuntimeException((string) $msg)]);
            $this->assertSame(self::refusal('zk verification error (fail closed): ' . $want), $hook(self::ctx(self::statement())));
        }
    }

    /** Without a `now` option the wall clock is read in epoch milliseconds, floored. */
    public function testDefaultClockIsFlooredEpochMilliseconds(): void
    {
        $hook = Zk::createZkVerifier(['trustedProverKeys' => [self::kp()->public]]);
        $one = self::statement(['issued_at' => self::NOW, 'expires_at' => self::NOW]);
        try {
            Zk::$clockHook = static fn(): float => 1800000000.0007;
            $this->assertSame(self::OK, $hook(self::ctx($one)));
            Zk::$clockHook = static fn(): float => 1800000000.0017;
            $this->assertSame(self::refusal('compliance statement expired'), $hook(self::ctx($one)));
            Zk::$clockHook = null;
            $this->assertSame(self::OK, $hook(self::ctx(self::statement(['issued_at' => 0, 'expires_at' => 4102444800000]))), 'the real clock');
            $this->assertSame(self::refusal('compliance statement not yet valid'), $hook(self::ctx(self::statement(['issued_at' => 4102444800000, 'expires_at' => 4102444800001]))));
        } finally {
            Zk::$clockHook = null;
        }
    }

    /** The hardware verifier gets exactly {document, ctx, nowMs, expected}; a full valid result passes. */
    public function testProverAttestationAcceptsAndPassesItsArguments(): void
    {
        $seen = null;
        $hook = self::attested(self::HW_OK, $seen);
        $ctx = self::ctx(self::statement());
        $this->assertSame(self::OK, $hook($ctx));
        $p = self::kp()->public;
        $this->assertSame(['document' => ['attestor' => $p, 'mode' => 'hardware'], 'ctx' => $ctx, 'nowMs' => self::NOW, 'expected' => ['bind' => $p]], $seen);
        $this->assertEquals(new AssuranceLabel('attested_vm_hw', 'hardware-bound:acme'), Assurance::labelOf($hook));
    }

    /** Each defect of the hardware evidence is refused with its own reason. */
    public function testProverAttestationRefusals(): void
    {
        $ctx = self::ctx(self::statement());
        $cases = [
            [null, 'prover hardware evidence invalid: no result'],
            [['ok' => false], 'prover hardware evidence invalid: no reason given'],
            [['ok' => false, 'reason' => 'stale quote'], 'prover hardware evidence invalid: stale quote'],
            [['ok' => 'yes', 'bound' => true, 'measured' => ['runtime_measurement' => 'm1']], 'prover hardware evidence invalid: no reason given'],
            [['ok' => true, 'measured' => ['runtime_measurement' => 'm1']], 'prover hardware evidence does not bind the prover key'],
            [['ok' => true, 'bound' => 1, 'measured' => ['runtime_measurement' => 'm1']], 'prover hardware evidence does not bind the prover key'],
            [['ok' => true, 'bound' => true, 'measured' => ['runtime_measurement' => 7]], 'prover hardware evidence carries no measured identity'],
            [['ok' => true, 'bound' => true, 'measured' => ['runtime_measurement' => 'm2']], 'prover VM measurement is not allowlisted'],
        ];
        foreach ($cases as [$hw, $why]) {
            $this->assertSame(self::refusal($why), self::attested($hw)($ctx), $why);
        }
    }

    /** The prover-attestation option is validated at construction: label level, allowlist shape, expectedBinding. */
    public function testProverAttestationConfigGates(): void
    {
        $lbl = 'createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label';
        $ms = 'createZkVerifier: proverAttestation.measurements must be a non-empty allowlist';
        $eb = 'createZkVerifier: proverAttestation.expectedBinding must be a function';
        $make = static fn(array $pa): \Closure => static fn() => Zk::createZkVerifier(['proverAttestation' => $pa]);
        $good = ['hardwareVerifier' => self::hw(self::HW_OK), 'expectedBinding' => static fn() => null, 'measurements' => ['m1']];
        $this->refuses(\TypeError::class, $lbl, $make(['hardwareVerifier' => static fn() => null] + $good));
        $this->refuses(\TypeError::class, $lbl, $make(['hardwareVerifier' => self::hw(self::HW_OK, 'software')] + $good));
        foreach (['x', ['k' => 'm1'], [], [''], [1], ['m1', '']] as $bad) {
            $this->refuses(\TypeError::class, $ms, $make(['measurements' => $bad] + $good));
        }
        $this->refuses(\TypeError::class, $eb, $make(array_diff_key($good, ['expectedBinding' => 1])));
        $this->refuses(\TypeError::class, $eb, $make(['expectedBinding' => 'not a function'] + $good));
        $multi = Zk::createZkVerifier(['proverAttestation' => ['hardwareVerifier' => self::hw(self::HW_OK, 'multi_root', null)] + $good]);
        $this->assertEquals(new AssuranceLabel('attested_vm_hw', 'hardware-bound:multi_root'), Assurance::labelOf($multi));
        $this->assertEquals(new AssuranceLabel('attested_vm'), Assurance::labelOf(Zk::createZkVerifier([])));
        // with a SNARK backend the prover-attestation option is ignored, even a malformed one
        $b = new ZkClosureBackend(static fn(array $in): bool => true);
        $this->assertInstanceOf(\Closure::class, Zk::createZkVerifier(['snarkBackend' => $b, 'proverAttestation' => ['hardwareVerifier' => static fn() => null]]));
    }

    /** The backend path: exactly {proof, publicInputs{action, policy, plan}, ctx}; one distinct expected policy is the one sent. */
    public function testSnarkBackendPath(): void
    {
        $seen = [];
        $verdict = true;
        $b = new ZkClosureBackend(static function (array $in) use (&$seen, &$verdict): bool {
            $seen[] = $in;
            return $verdict;
        });
        $label = new AssuranceLabel('groth16');
        Assurance::setLabel($b, $label);
        $proof = ['any' => 1];
        $ctx = self::ctx($proof);
        $want = static fn(string $policy): array => ['proof' => $proof, 'publicInputs' => ['action_commit' => Zk::actionCommitment(['action' => self::ACTION]),
            'policy_commit' => $policy, 'plan_commit' => 'R'], 'ctx' => $ctx];
        $hook = Zk::createZkVerifier(['snarkBackend' => $b, 'policyCommitments' => ['P', 'P']]);
        $this->assertSame($label, Assurance::labelOf($hook));
        $this->assertSame(self::OK, $hook($ctx));
        $this->assertSame($want('P'), $seen[0]);
        $this->assertSame(self::OK, Zk::createZkVerifier(['snarkBackend' => $b, 'policyCommitments' => [5, 'P']])($ctx));
        $this->assertSame($want('P'), $seen[1], 'non-string commitments are dropped');
        $this->assertSame(self::OK, Zk::createZkVerifier(['snarkBackend' => $b, 'policyCommitments' => ['P', 'Q']])($ctx));
        $this->assertSame($want('G'), $seen[2], 'two distinct expected policies: the grant\'s own');
        $verdict = false;
        $this->assertSame(self::refusal('snark backend rejected the proof'), $hook($ctx));
        $this->assertEquals(new AssuranceLabel('unknown'), Assurance::labelOf(Zk::createZkVerifier(['snarkBackend' => new ZkClosureBackend(static fn(array $in): bool => true)])));
    }

    /** createAttestedComplianceProver takes a KeyPair as is; a non-compliant action is refused naming the decision's reasons. */
    public function testAttestedProver(): void
    {
        $kp = self::kp();
        $this->assertSame($kp->public, Zk::createAttestedComplianceProver($kp)->publicKey);
        $args = self::corpusArgs('createAttestedComplianceProver/non-compliant-refused');
        $p = Zk::createAttestedComplianceProver(hash('sha256', 'atlas-pca-conformance/zk/prover', true));
        try {
            $p->prove($args[1]);
            $this->fail('a non-compliant action must be refused');
        } catch (\RuntimeException $e) {
            $m = $e->getMessage();
            $this->assertStringStartsWith('createAttestedComplianceProver: action is not compliant, nothing to prove (', $m);
            $this->assertStringEndsWith(')', $m);
            $this->assertStringContainsString('no predicate permits', $m);
        }
    }

    // ---- envelopes and the Groth16 gates --------------------------------------------------------------------------------------------

    /** A canonical envelope given as plain PHP arrays is normalised and accepted like the parsed one. */
    public function testCanonicalEnvelopeFromArrays(): void
    {
        $text = (string) file_get_contents(Zk::policyVmSampleProofPath());
        $this->assertTrue(Zk::isCanonicalGroth16Envelope(Js::parse($text), 'bn254'));
        $this->assertTrue(Zk::isCanonicalGroth16Envelope(json_decode($text, true), 'bn254'));
        $this->assertFalse(Zk::isCanonicalGroth16Envelope([], 'bn254'));
        $this->assertFalse(Zk::isCanonicalGroth16Envelope('x', 'bn254'));
    }

    /** Circuit and system tags: an unknown circuit or system is refused before the key is loaded. */
    public function testPolicyVmTagGates(): void
    {
        $opts = ['verificationKeyPath' => self::NOKEY];
        $this->refuses(\RuntimeException::class, 'zk: cannot read ' . self::NOKEY, static fn() => Zk::verifyPolicyVmProof(self::sample(), $opts));
        $c = self::sample();
        $c->set('circuit', 'pca-other');
        $this->assertFalse(Zk::verifyPolicyVmProof($c, $opts));
        $s = self::sample();
        $s->set('system', 'groth16-other');
        $this->assertFalse(Zk::verifyPolicyVmProof($s, $opts));
        $this->refuses(\RuntimeException::class, 'zk: cannot read ' . self::NOKEY, static fn() => Zk::verifyPolicyVmProof(self::bound(), $opts));
    }

    /** The risk-hash pin: both halves must match, and only the risk-bound circuit can carry it. */
    public function testRiskHashPin(): void
    {
        $pin = static fn(string $hi, string $lo): array => ['verificationKeyPath' => self::NOKEY, 'expectRiskHash' => ['hi' => $hi, 'lo' => $lo]];
        $this->refuses(\RuntimeException::class, 'zk: cannot read ' . self::NOKEY, static fn() => Zk::verifyPolicyVmProof(self::bound(), $pin('7', '8')));
        $this->assertFalse(Zk::verifyPolicyVmProof(self::bound(), $pin('7', '9')));
        $this->assertFalse(Zk::verifyPolicyVmProof(self::bound(), $pin('6', '8')));
        $this->assertFalse(Zk::verifyPolicyVmProof(self::sample(), $pin('7', '8')));
    }

    /** A verifier-side error inside the pairing step (a key that cannot be serialised) is a refusal, never an acceptance. */
    public function testPairingErrorIsARefusal(): void
    {
        $this->assertFalse(Zk::verifyPolicyVmProof(self::sample(), ['verificationKey' => new \stdClass()]));
    }

    /** A missing libpcazk is never a verdict: it surfaces as ZkBackendMissing; with the library the bundled keys verify the samples. */
    public function testMissingBackendIsNotAVerdict(): void
    {
        $bls = Js::parse((string) file_get_contents(Zk::policyVmBls12381SampleProofPath()));
        if (!ZkNative::available()) {
            foreach ([self::sample(), $bls] as $env) {
                try {
                    Zk::verifyPolicyVmProof($env);
                    $this->fail('expected ZkBackendMissing');
                } catch (ZkBackendMissing $e) {
                    $this->assertNotSame('', $e->getMessage());
                }
            }
            return;
        }
        $this->assertTrue(Zk::verifyPolicyVmProof(self::sample()));
        $this->assertTrue(Zk::verifyPolicyVmProof($bls));
    }

    // ---- context pins ------------------------------------------------------------------------------------------------------------

    /** The 15-signal layout is the default; a non-string context signal is a refusal. */
    public function testContextLayoutAndSignalShape(): void
    {
        $this->assertTrue(Zk::policyVmContextMatches(self::ps()));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps(1000)));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps(), 5));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps(), static fn() => throw new \RuntimeException('x')));
    }

    /** Pins: exact values up to 2^53 - 1, ranges with min == max, half-open ranges and non-canonical signals refuse, a null pin throws. */
    public function testContextPins(): void
    {
        $this->assertTrue(Zk::policyVmContextMatches(self::ps('9007199254740991'), ['now' => 9007199254740991]));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps('9007199254740994'), ['now' => 9007199254740994.0]), 'a pin above 2^53 is not exact');
        $this->assertTrue(Zk::policyVmContextMatches(self::ps(), ['now' => ['min' => 1000, 'max' => 1000]]));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps(), ['now' => ['max' => 2000]]));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps(), ['now' => ['min' => 0]]));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps('1000', 5), ['r' => 5]));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps('1000', 'abc'), ['r' => 'abc']));
        $this->assertFalse(Zk::policyVmContextMatches(self::ps('1000', '01'), ['r' => 1]));
        $this->refuses(\TypeError::class, "Cannot read properties of null (reading 'min')", static fn() => Zk::policyVmContextMatches(self::ps(), ['r' => null]));
    }

    /** decode reads nothing from a non-list. */
    public function testDecodeOfANonList(): void
    {
        $this->assertSame(['actionHash' => [], 'policyHash' => [], 'planHash' => []], Zk::decodePolicyVmPublic('x'));
    }

    // ---- BigInt conversion and struct hashes ------------------------------------------------------------------------------------------

    /** The reference's BigInt conversions: signs, prefixes in either case, booleans, lists, and the exact refusals. */
    public function testBigIntConversions(): void
    {
        $h = static fn(mixed $v): array => Zk::policyVmStructHash([$v]);
        foreach ([['+5', 5], ['0o17', 15], ['0b101', 5], ['0X1F', 31], ['0x1f', 31], ['0O17', 15], ['0B101', 5], [false, 0], [true, 1], [[7], 7], ["\xFF", 0], ['', 0]] as [$in, $n]) {
            $this->assertSame($h($n), $h($in), var_export($in, true));
        }
        $this->assertNotSame($h(0), $h(1));
        $this->refuses(\RangeException::class, 'The number Infinity cannot be converted to a BigInt because it is not an integer', static fn() => $h(INF));
        $this->refuses(\RangeException::class, 'The number 1.5 cannot be converted to a BigInt because it is not an integer', static fn() => $h(1.5));
        $this->refuses(\InvalidArgumentException::class, 'Cannot convert abc to a BigInt', static fn() => $h('abc'));
        $this->refuses(\TypeError::class, 'Cannot convert null to a BigInt', static fn() => $h(null));
        $this->refuses(\TypeError::class, 'Cannot convert the value to a BigInt', static fn() => $h(['a' => 1]));
    }

    /** Struct and risk hashes take lists only. */
    public function testStructHashShapes(): void
    {
        $this->refuses(\TypeError::class, 'policyVmStructHash: fields must be a list', static fn() => Zk::policyVmStructHash('x'));
        $this->refuses(\TypeError::class, 'policyVmStructHash: fields must be a list', static fn() => Zk::policyVmStructHash(['a' => 1]));
        $risk = 'policyVmRiskHash: need exactly 5 risk fields';
        $this->refuses(\InvalidArgumentException::class, $risk, static fn() => Zk::policyVmRiskHash('x'));
        $this->refuses(\InvalidArgumentException::class, $risk, static fn() => Zk::policyVmRiskHash(['a' => 1, 'b' => 2, 'c' => 3, 'd' => 4, 'e' => 5]));
        $this->assertSame(Zk::policyVmStructHash([1, 2, 3, 4, 5]), Zk::policyVmRiskHash([1, 2, 3, 4, 5]));
    }

    /** A commitment that is not base64url is refused. */
    public function testCommitmentFieldRefusesNonBase64url(): void
    {
        $this->refuses(\InvalidArgumentException::class, 'commitmentField: not base64url', static fn() => Zk::commitmentField('!!'));
    }

    // ---- quantizers --------------------------------------------------------------------------------------------------------------

    private const CAT = ['verbCodes' => ['v' => 1], 'resourceCodes' => ['r' => 2]];

    /** The action quantizer: shape, string verb, reversibility classes and the paramScalar rules. */
    public function testActionQuantizer(): void
    {
        $q = static fn(mixed $params, mixed $extra = []): array => Zk::quantizeActionStruct(['verb' => 'v', 'resource' => 'r', 'params' => $params] + $extra, self::CAT + ['paramScalarField' => 'n']);
        $this->assertSame(['1', '2', '0', '0'], $q(['n' => 0]));
        $this->assertSame(['1', '2', '0', '7'], $q(['n' => 7]));
        $this->assertSame(['1', '2', '2', '7'], $q(['n' => 7], ['reversibility_class' => 'irreversible']));
        $this->assertSame(['1', '2', '0', '3'], Zk::quantizeActionStruct(['verb' => 'v', 'resource' => 'r', 'params' => ['toString' => 3]], self::CAT + ['paramScalarField' => 'toString']));
        $this->assertSame(['1', '2', '0', '0'], Zk::quantizeActionStruct(['verb' => 'v', 'resource' => 'r'], self::CAT + ['paramScalarField' => 'toString']));
        $must = 'policyvm quantize: paramScalar must be a non-negative integer';
        foreach ([INF, 1.5, -0.0, -1] as $bad) {
            $this->refuses(\InvalidArgumentException::class, $must, static fn() => $q(['n' => $bad]));
        }
        $this->refuses(\InvalidArgumentException::class, 'policyvm quantize: paramScalar is not a non-negative integer', static fn() => $q(['n' => true]));
        $this->refuses(\InvalidArgumentException::class, 'policyvm quantize: action is missing', static fn() => Zk::quantizeActionStruct(null, self::CAT));
        $this->refuses(\InvalidArgumentException::class, 'policyvm quantize: verb must be a string', static fn() => Zk::quantizeActionStruct(['verb' => 5, 'resource' => 'r'], self::CAT));
        $this->refuses(\InvalidArgumentException::class, 'policyvm quantize: unknown reversibility class "5"', static fn() => $q(['n' => 1], ['reversibility_class' => 5]));
        $this->refuses(\InvalidArgumentException::class, 'policyvm quantize: unknown reversibility class "foo"', static fn() => $q(['n' => 1], ['reversibility_class' => 'foo']));
    }

    /** strictCatalog: true refuses a name outside the maps for plans and policies; the policy's missing revMax is "undefined". */
    public function testPlanAndPolicyQuantizers(): void
    {
        $plan = ['verb' => 'zz', 'resource' => 'r', 'semanticDist' => 0, 'planSalt' => 0];
        $this->refuses(\InvalidArgumentException::class, 'policyvm quantize: verb "zz" is not in the catalog (strict)', static fn() => Zk::quantizePlanStruct($plan, self::CAT + ['strictCatalog' => true]));
        $this->assertCount(4, Zk::quantizePlanStruct($plan, self::CAT));
        $w = ['alpha' => 1, 'beta' => 1, 'gamma' => 1, 'delta' => 1, 'epsilon' => 1, 'zeta' => 1];
        $policy = ['weights' => $w, 'theta1' => 1, 'theta2' => 1, 'kappa' => 1, 'budgetB' => 1, 'policyVerb' => 'zz', 'policyResource' => 'r',
            'policyParamBound' => 1, 'expiresAt' => 1, 'notBefore' => 1, 'maxBlast' => 1, 'maxDepth' => 1, 'rateMax' => 1, 'allocParent' => 1];
        $this->refuses(\InvalidArgumentException::class, 'policyvm quantize: verb "zz" is not in the catalog (strict)', static fn() => Zk::quantizePolicyStruct($policy, self::CAT + ['strictCatalog' => true]));
        $this->refuses(\InvalidArgumentException::class, 'policyvm quantize: unknown revMax class "undefined"', static fn() => Zk::quantizePolicyStruct($policy, self::CAT));
    }

    // ---- SNARK backends --------------------------------------------------------------------------------------------------------------

    private static function complianceEnv(string $policy, string $plan, string $action, string $z = '1'): Obj
    {
        $proof = self::sample()->get('proof');
        if ($z !== '1') {
            $a = $proof->get('pi_a');
            $a[2] = $z;
            $proof->set('pi_a', $a);
        }
        $e = new Obj();
        $e->set('system', 'groth16-bn254');
        $e->set('circuit', 'pca-compliance-v1');
        $e->set('proof', $proof);
        $e->set('publicSignals', ['1', '2', '3', $policy, $plan, $action, '1']);
        return $e;
    }

    /** The compliance backend binds signals 3, 4, 5 to the policy, plan and action commitments and needs a canonical envelope. */
    public function testComplianceBackendBindings(): void
    {
        $pi = ['policy_commit' => Pca::b64u('policy'), 'plan_commit' => Pca::b64u('plan'), 'action_commit' => Pca::b64u('action')];
        [$fp, $fl, $fa] = [Zk::commitmentField($pi['policy_commit']), Zk::commitmentField($pi['plan_commit']), Zk::commitmentField($pi['action_commit'])];
        $this->assertCount(3, array_unique([$fp, $fl, $fa]));
        $b = Zk::createGroth16SnarkBackend(['verificationKeyPath' => self::NOKEY]);
        $v = static fn(Obj $env): bool => $b->verify(['proof' => $env, 'publicInputs' => $pi, 'ctx' => null]);
        $this->refuses(\RuntimeException::class, 'zk: cannot read ' . self::NOKEY, static fn() => $v(self::complianceEnv($fp, $fl, $fa)));
        $this->assertFalse($v(self::complianceEnv('9', $fl, $fa)));
        $this->assertFalse($v(self::complianceEnv($fp, '9', $fa)));
        $this->assertFalse($v(self::complianceEnv($fp, $fl, '9')));
        $this->assertFalse($v(self::complianceEnv($fp, $fl, $fa, '2')), 'a non-affine point is not canonical');
        $x = self::complianceEnv($fp, $fl, $fa);
        $x->set('publicSignals', 'x');
        $this->assertFalse($v($x));
        $this->assertEquals(new AssuranceLabel('groth16', null, false, 'single-party'), Assurance::labelOf($b));
    }

    /** The ceremony label pins the backend's own circuit: a multi-party transcript of another circuit is single-party. */
    public function testCeremonyLabelPinsTheCircuit(): void
    {
        [$vk, $ev] = self::corpusArgs('ceremonyOf/multi-party');
        $this->assertSame('multi-party', Assurance::labelOf(Zk::createPolicyVmSnarkBackend(['verificationKey' => $vk, 'ceremony' => $ev]))->ceremony);
        $this->assertSame('single-party', Assurance::labelOf(Zk::createGroth16SnarkBackend(['verificationKey' => $vk, 'ceremony' => $ev]))->ceremony);
    }

    /** The Policy VM backend: each pinned struct hash must match both halves; `expect` is forwarded; the label needs all three pins. */
    public function testPolicyVmBackendPins(): void
    {
        $ps = self::sample()->get('publicSignals');
        $pinned = static fn(array $p): \Atlas\Pca\ZkSnarkBackend => Zk::createPolicyVmSnarkBackend(['verificationKeyPath' => self::NOKEY] + $p);
        $this->refuses(\RuntimeException::class, 'zk: cannot read ' . self::NOKEY, static fn() => $pinned(['expectActionHash' => ['hi' => $ps[0], 'lo' => $ps[1]]])->verify(['proof' => self::sample()]));
        $this->assertFalse($pinned(['expectActionHash' => ['hi' => $ps[0], 'lo' => '9']])->verify(['proof' => self::sample()]));
        $this->assertFalse($pinned(['expectActionHash' => ['hi' => '9', 'lo' => $ps[1]]])->verify(['proof' => self::sample()]));
        $this->assertFalse($pinned(['expectPolicyHash' => ['hi' => $ps[2], 'lo' => '9']])->verify(['proof' => self::sample()]));
        $vk = new Obj();
        $vk->set('protocol', 'groth16');
        $this->assertFalse(Zk::createPolicyVmSnarkBackend(['verificationKey' => $vk, 'expect' => ['now' => '1']])->verify(['proof' => self::sample()]), 'expect is forwarded');
        $h = ['hi' => '1', 'lo' => '2'];
        $snark = static fn(array $o): AssuranceLabel => Assurance::labelOf(Zk::createPolicyVmSnarkBackend($o));
        $this->assertEquals(new AssuranceLabel('policyvm_snark', null, false, 'single-party'), $snark(['expectActionHash' => $h, 'expectPolicyHash' => $h, 'expectPlanHash' => $h]));
        $unbound = new AssuranceLabel('unknown', 'policyvm-unbound', false, 'single-party');
        $this->assertEquals($unbound, $snark(['expectPlanHash' => $h]));
        $this->assertEquals($unbound, $snark(['expectActionHash' => $h, 'expectPlanHash' => $h]));
        $this->assertEquals($unbound, $snark(['expectPolicyHash' => $h, 'expectPlanHash' => $h]));
    }

    /** The risk-bound backend: v2 only, all four pins checked and needed for the label, expectRiskHash forwarded unless null. */
    public function testBoundBackend(): void
    {
        $nokey = Zk::createPolicyVmBoundSnarkBackend(['verificationKeyPath' => self::NOKEY]);
        $this->refuses(\RuntimeException::class, 'zk: cannot read ' . self::NOKEY, static fn() => $nokey->verify(['proof' => self::bound()]));
        $this->assertFalse($nokey->verify(['proof' => self::sample()]));
        $this->assertFalse(Zk::createPolicyVmBoundSnarkBackend(['verificationKeyPath' => self::NOKEY, 'expectPlanHash' => ['hi' => '5', 'lo' => '9']])->verify(['proof' => self::bound()]));
        $vk = new Obj();
        $vk->set('protocol', 'groth16');
        $this->assertFalse(Zk::createPolicyVmBoundSnarkBackend(['verificationKey' => $vk, 'expectRiskHash' => false])->verify(['proof' => self::bound()]), 'a falsy risk pin is still forwarded');
        $h = ['hi' => '1', 'lo' => '2'];
        $lbl = static fn(array $o): AssuranceLabel => Assurance::labelOf(Zk::createPolicyVmBoundSnarkBackend($o));
        $this->assertEquals(new AssuranceLabel('policyvm_snark', null, false, 'single-party'), $lbl(['expectActionHash' => $h, 'expectPolicyHash' => $h, 'expectPlanHash' => $h, 'expectRiskHash' => $h]));
        $this->assertEquals(new AssuranceLabel('unknown', 'policyvm-unbound', false, 'single-party'), $lbl(['expectPolicyHash' => $h, 'expectPlanHash' => $h, 'expectRiskHash' => $h]));
    }

    // ---- circuit versions and proving ----------------------------------------------------------------------------------------------

    /** An unknown circuit id is refused naming it as the reference prints it. */
    public function testCircuitVersionRefusals(): void
    {
        $this->assertSame('pca-policyvm-v1', Zk::circuitVersion('pca-policyvm-v1')['circuit']);
        foreach ([['"nope"', 'nope'], ['null', null], ['true', true], ['5', 5], ['undefined', []], ['undefined', ['a' => 1]]] as [$want, $id]) {
            $this->refuses(\InvalidArgumentException::class, 'circuitVersion: unknown circuit ' . $want, static fn() => Zk::circuitVersion($id));
        }
    }

    /** readFile names the path it cannot read. */
    public function testReadFileRefusal(): void
    {
        $this->refuses(\RuntimeException::class, 'zk: cannot read /nonexistent/zk14', static fn() => (new \ReflectionMethod(Zk::class, 'readFile'))->invoke(null, '/nonexistent/zk14'));
    }

    /** The provers read the given wasm / zkey (empty files are refused by the native layer before libpcazk is loaded). */
    public function testProversUseTheGivenFiles(): void
    {
        $w = $this->emptyFile();
        $z = $this->emptyFile();
        $empty = 'zk native: the wasm, the zkey and the input must not be empty';
        $paths = ['wasmPath' => $w, 'zkeyPath' => $z];
        $inp = ['policy_commit' => Pca::b64u('p'), 'plan_commit' => Pca::b64u('l'), 'action_commit' => Pca::b64u('a'), 'verb' => 'x', 'resource' => 'y'];
        try {
            $this->refuses(\InvalidArgumentException::class, $empty, static fn() => Zk::proveGroth16Compliance($inp, $paths));
            $this->refuses(\InvalidArgumentException::class, 'commitmentField: not base64url', static fn() => Zk::proveGroth16Compliance(['policy_commit' => '!!'] + $inp, $paths));
            $this->refuses(\InvalidArgumentException::class, $empty, static fn() => Zk::provePolicyVmCompliance(null, $paths));
            $this->refuses(\InvalidArgumentException::class, $empty, static fn() => Zk::provePolicyVmCompliance(['a' => 'b'], $paths));
            $this->refuses(\InvalidArgumentException::class, $empty, static fn() => Zk::provePolicyVmBoundCompliance(['a' => 'b'], $paths));
        } finally {
            unlink($w);
            unlink($z);
        }
    }
}
