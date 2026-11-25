<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Assurance.php';
require_once __DIR__ . '/Decide.php';
require_once __DIR__ . '/ZkCeremony.php';
require_once __DIR__ . '/ZkNative.php';

/** A SNARK backend of the zk compliance hook: decides one proof for the commitments of one action. */
interface ZkSnarkBackend
{
    /** @param array{proof:mixed,publicInputs:mixed,ctx:mixed} $input */
    public function verify(array $input): bool;
}

/** A backend built by one of the factories of {@see Zk}. */
final class ZkClosureBackend implements ZkSnarkBackend
{
    public function __construct(private readonly \Closure $f)
    {
    }

    public function verify(array $input): bool
    {
        return ($this->f)($input);
    }
}

/** The attested-VM prover: runs the policy decision and signs a compliance statement for an action that passes it. */
final class ZkComplianceProver
{
    public readonly string $publicKey;

    public function __construct(private readonly KeyPair $key)
    {
        $this->publicKey = $key->public;
    }

    /**
     * `$opts` = {pcactn, decideInput, issued_at, expires_at}. Throws when the decision does not release (nothing to prove).
     * Returns the signed statement {v, mode, action_commit, policy_commit, plan_commit, released, r, issued_at, expires_at, prover, sig}.
     */
    public function prove(mixed $opts): Obj
    {
        $in = Js::opt($opts, 'decideInput');
        $decision = Decide::decide($in);
        if (($decision['releaseGuardianShare'] ?? null) !== true) {
            throw new \RuntimeException('createAttestedComplianceProver: action is not compliant, nothing to prove (' . implode('; ', $decision['reasons'] ?? []) . ')');
        }
        $pcactn = Js::opt($opts, 'pcactn');
        $root = Js::opt(Js::opt($pcactn, 'plan'), 'root');
        $body = Sign::n([
            'v' => 1, 'mode' => 'attested-vm', 'action_commit' => Zk::actionCommitment($pcactn), 'policy_commit' => Zk::policyCommitment(Js::opt($in, 'grant')),
            'plan_commit' => is_string($root) ? $root : '', 'released' => true, 'r' => $decision['r'],
            'issued_at' => Js::opt($opts, 'issued_at'), 'expires_at' => Js::opt($opts, 'expires_at'), 'prover' => $this->publicKey,
        ]);
        $body->set('sig', Pca::b64u($this->key->sign(Zk::STATEMENT_DOMAIN . Json::canonicalizeNative($body))));
        return $body;
    }
}

/**
 * Zero-knowledge compliance: (a) attested-VM compliance statements (an Ed25519-signed statement over the action, policy and plan
 * commitments) and the verifier hook that accepts them; (b) Groth16 verification of snarkjs proofs of the compliance circuit
 * (`pca-compliance-v1`, BN254), the Policy VM circuit (`pca-policyvm-v1`, BN254 and BLS12-381, keys bundled under circuits/) and its
 * risk-bound form (`pca-policyvm-v2`, BN254); (c) the public-input derivation (commitment field elements, struct and risk hashes,
 * the quantizers); (d) the context pins and the canonical envelope gate.
 *
 * The pairing check and the prover run in libpcazk ({@see ZkNative}); every gate in front of it (shape, circuit and system tags,
 * signal count, allow bit, pins, canonical decimals) is decided here. Big integers: a JavaScript `bigint` argument is a \GMP object
 * here, a `number` is an int / float / Num, and uint64 results are decimal strings. Needs ext-gmp.
 */
final class Zk
{
    public const STATEMENT_DOMAIN = "atlas-pca/zk-compliance/v1\0";
    public const ZK_PROVER_BINDING_REF = 'atlas-pca/zk-prover/v1';
    public const POLICYVM_PUBLIC_SIGNAL = ['actionHi' => 0, 'actionLo' => 1, 'policyHi' => 2, 'policyLo' => 3, 'planHi' => 4, 'planLo' => 5,
        'r' => 6, 't' => 7, 'admit' => 8, 'allow' => 9, 'now' => 10, 'blast' => 11, 'delegationDepth' => 12, 'recentCount' => 13, 'allocChild' => 14];
    public const POLICYVM_PUBLIC_SIGNAL_COUNT = 15;
    public const POLICYVM_BOUND_PUBLIC_SIGNAL = ['actionHi' => 0, 'actionLo' => 1, 'policyHi' => 2, 'policyLo' => 3, 'planHi' => 4, 'planLo' => 5,
        'r' => 6, 't' => 7, 'admit' => 8, 'riskHi' => 9, 'riskLo' => 10, 'allow' => 11, 'now' => 12, 'blast' => 13, 'delegationDepth' => 14,
        'recentCount' => 15, 'allocChild' => 16];
    public const POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT = 17;
    public const POLICYVM_BOUND_RISK_FIELDS = ['revScore', 'taint', 'conf', 'age', 'rFloorIn'];
    public const POLICYVM_REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'];
    /** "No expectation given" for {@see policyVmContextMatches} (a null expectation is a refusal, as in the reference). */
    public const NO_EXPECT = "\0no-expect";

    private const BN254_FR = '21888242871839275222246405745257275088548364400416034343698204186575808495617';
    private const BN254_FQ = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
    private const BLS12381_FQ = '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab';
    private const BLS12381_FR = '0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001';
    private const CANON_DEC = '/\A(0|[1-9][0-9]*)\z/';
    private const COMPLIANCE_SIGNAL_COUNT = 7;
    private const OBJECT_PROTOTYPE = ['constructor', 'toString', 'toLocaleString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
        '__proto__', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__'];

    // ---- paths (the bundled keys live in the package's circuits/ directory; build outputs under circuits/build are the caller's) ----

    private static function circuits(): string
    {
        return dirname(__DIR__) . '/circuits';
    }

    private static function build(): string
    {
        return self::circuits() . '/build';
    }

    public static function defaultVkeyPath(): string
    {
        return self::build() . '/verification_key.json';
    }

    public static function defaultWasmPath(): string
    {
        return self::build() . '/compliance_js/compliance.wasm';
    }

    public static function defaultZkeyPath(): string
    {
        return self::build() . '/compliance_final.zkey';
    }

    public static function policyVmVkeyPath(): string
    {
        return self::circuits() . '/policyvm_vkey.json';
    }

    public static function policyVmSampleProofPath(): string
    {
        return self::circuits() . '/policyvm_sample_proof.json';
    }

    public static function policyVmWasmPath(): string
    {
        return self::build() . '/policyvm_js/policyvm.wasm';
    }

    public static function policyVmZkeyPath(): string
    {
        return self::build() . '/policyvm_final.zkey';
    }

    public static function policyVmBls12381VkeyPath(): string
    {
        return self::circuits() . '/policyvm_bls12381_vkey.json';
    }

    public static function policyVmBls12381SampleProofPath(): string
    {
        return self::circuits() . '/policyvm_bls12381_sample_proof.json';
    }

    public static function policyVmBoundVkeyPath(): string
    {
        return self::build() . '/policyvm_bound_vkey.json';
    }

    public static function policyVmBoundSampleProofPath(): string
    {
        return self::build() . '/policyvm_bound_sample_proof.json';
    }

    public static function policyVmBoundWasmPath(): string
    {
        return self::build() . '/policyvm_bound_js/policyvm_bound.wasm';
    }

    public static function policyVmBoundZkeyPath(): string
    {
        return self::build() . '/policyvm_bound_final.zkey';
    }

    private static function readFile(string $path): string
    {
        $s = is_file($path) ? file_get_contents($path) : false;
        return $s !== false ? $s : throw new \RuntimeException("zk: cannot read $path");
    }

    private static function readJson(string $path): mixed
    {
        return Js::parse(self::readFile($path));
    }

    /** @return \Closure():mixed the key of `$opts` (verificationKey, else the file at verificationKeyPath, else `$default`), read once */
    private static function lazyVkey(mixed $opts, string $default): \Closure
    {
        $cached = Js::opt($opts, 'verificationKey');
        $path = Js::opt($opts, 'verificationKeyPath');
        return static function () use (&$cached, $path, $default): mixed {
            return $cached ??= self::readJson(is_string($path) ? $path : $default);
        };
    }

    // ---- JavaScript value helpers -----------------------------------------------------------------------------------------------

    private static function need(): void
    {
        if (!extension_loaded('gmp')) {
            throw new \RuntimeException('zk: ext-gmp is required');
        }
    }

    /** Element `$i` of a list, or NO_EXPECT when it is absent (the reference's undefined). */
    private static function at(mixed $list, int $i): mixed
    {
        if ($list === null) {
            throw new \TypeError("Cannot read properties of null (reading '$i')");
        }
        return is_array($list) && array_is_list($list) && array_key_exists($i, $list) ? $list[$i] : self::NO_EXPECT;
    }

    /** A JavaScript number as an exact integer, or null when it is not an integer. */
    private static function intOfNumber(mixed $v): ?\GMP
    {
        $f = Js::num($v);
        if ($f === null || !is_finite($f) || floor($f) !== $f) {
            return null;
        }
        return gmp_init(sprintf('%.0f', $f), 10);
    }

    /** The reference's `BigInt(text)`: decimal with an optional sign, or 0x / 0o / 0b digits; white space trimmed; empty is zero. */
    private static function bigOfString(string $s): \GMP
    {
        $t = (string) preg_replace('/\A[\s\x{A0}\x{FEFF}\p{Zs}\x{2028}\x{2029}]+|[\s\x{A0}\x{FEFF}\p{Zs}\x{2028}\x{2029}]+\z/u', '', $s);
        if ($t === '') {
            return gmp_init(0);
        }
        if (preg_match('/\A[+-]?[0-9]+\z/', $t) === 1) {
            return gmp_init(ltrim($t, '+'), 10);
        }
        foreach (['x' => [16, '0-9a-fA-F'], 'o' => [8, '0-7'], 'b' => [2, '01']] as $p => [$base, $set]) {
            if (preg_match('/\A0[' . $p . strtoupper($p) . ']([' . $set . ']+)\z/', $t, $m) === 1) {
                return gmp_init($m[1], $base);
            }
        }
        throw new \InvalidArgumentException('Cannot convert ' . $s . ' to a BigInt');
    }

    /** The reference's `BigInt(value)` over a number, a bigint (\GMP), a string, a boolean or a list (through its text form). */
    private static function big(mixed $v): \GMP
    {
        self::need();
        if ($v instanceof \GMP) {
            return $v;
        }
        if (is_bool($v)) {
            return gmp_init($v ? 1 : 0);
        }
        if (is_string($v)) {
            return self::bigOfString($v);
        }
        if (Js::isNum($v)) {
            return self::intOfNumber($v) ?? throw new \RangeException('The number ' . Js::str($v) . ' cannot be converted to a BigInt because it is not an integer');
        }
        if (is_array($v) && array_is_list($v)) {
            return self::bigOfString(Js::str($v));
        }
        throw new \TypeError('Cannot convert ' . ($v === null ? 'null' : 'the value') . ' to a BigInt');
    }

    private static function u64Max(): \GMP
    {
        return gmp_sub(gmp_pow(2, 64), 1);
    }

    /** A uint64 from a number (an integer) or a bigint; anything else, a string included, refuses. */
    private static function toU64(mixed $v, string $what): \GMP
    {
        self::need();
        $b = $v instanceof \GMP ? $v : (Js::isNum($v) ? self::intOfNumber($v) : null);
        if ($b === null || gmp_sign($b) < 0 || gmp_cmp($b, self::u64Max()) > 0) {
            throw new \InvalidArgumentException("policyvm quantize: $what is not a uint64");
        }
        return $b;
    }

    /** @param list<\GMP> $xs @return list<string> */
    private static function decimals(array $xs): array
    {
        return array_map(static fn(\GMP $x): string => gmp_strval($x), $xs);
    }

    // ---- commitments and the attested-VM statement ----------------------------------------------------------------------------------

    /** The policy commitment of a grant: its `id` when that is a string, else the digest of its canonical JSON. */
    public static function policyCommitment(mixed $grant): string
    {
        $id = Js::opt($grant, 'id');
        return is_string($id) ? $id : Pca::hashCanonical($grant);
    }

    /** The same value under the name a relying party pins. */
    public static function pinnedPolicyCommitment(mixed $grant): string
    {
        return self::policyCommitment($grant);
    }

    /** The digest of the PCActn's `action` (of null when there is none). */
    public static function actionCommitment(mixed $pcactn): string
    {
        return Pca::hashCanonical(Js::opt($pcactn, 'action'));
    }

    /** The binding a prover's hardware evidence must carry. @return array{holderPub:mixed,grantRef:string,epoch:mixed,nonce:mixed} */
    public static function proverKeyBinding(mixed $proverPublicKey, mixed $epoch, mixed $nonce): array
    {
        return ['holderPub' => $proverPublicKey, 'grantRef' => self::ZK_PROVER_BINDING_REF, 'epoch' => $epoch, 'nonce' => $nonce];
    }

    /** An attested-VM prover over an Ed25519 key (a KeyPair or its 32-byte seed). */
    public static function createAttestedComplianceProver(KeyPair|string $attestorSecret): ZkComplianceProver
    {
        return new ZkComplianceProver($attestorSecret instanceof KeyPair ? $attestorSecret : new KeyPair($attestorSecret));
    }

    /** A base64url commitment (bytes of any length) as a BN254 scalar-field element, in decimal. Throws for text that is not strict base64url. */
    public static function commitmentField(mixed $b64uCommit): string
    {
        self::need();
        $bytes = Pca::unb64u($b64uCommit) ?? throw new \InvalidArgumentException('commitmentField: not base64url');
        return gmp_strval(gmp_mod($bytes === '' ? gmp_init(0) : gmp_import($bytes), gmp_init(self::BN254_FR, 10)));
    }

    /**
     * The zk compliance hook `fn(mixed $ctx): array{enforced:true,ok:bool,reason?:string}` over `$ctx` = {pcactn, grant}; total (a
     * failure of any kind is a refusal). Options: trustedProverKeys (list), policyCommitments (list, else the grant's own),
     * revokedProverKeys (list), snarkBackend (ZkSnarkBackend: then the proof is the backend's), proverAttestation
     * ({hardwareVerifier: callable(array{document,ctx,nowMs,expected}): mixed with a hardware or multi_root assurance label,
     * expectedBinding: callable(string): mixed, measurements: non-empty list of strings}), now (callable(): int|float, epoch ms),
     * clockSkewMs. The returned closure carries its assurance label ({@see Assurance::labelOf}).
     * @param array<string,mixed> $opts
     */
    public static function createZkVerifier(array $opts): \Closure
    {
        $backend = ($opts['snarkBackend'] ?? null) instanceof ZkSnarkBackend ? $opts['snarkBackend'] : null;
        $pa = $backend !== null ? null : ($opts['proverAttestation'] ?? null);
        $hwLabel = null;
        if ($pa !== null) {
            $hwLabel = Assurance::labelOf($pa['hardwareVerifier'] ?? null);
            if ($hwLabel === null || !in_array($hwLabel->level, ['hardware', 'multi_root'], true)) {
                throw new \TypeError('createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label');
            }
            $ms = $pa['measurements'] ?? null;
            if (!is_array($ms) || !array_is_list($ms) || $ms === [] || array_filter($ms, static fn($m): bool => !is_string($m) || $m === '') !== []) {
                throw new \TypeError('createZkVerifier: proverAttestation.measurements must be a non-empty allowlist');
            }
            if (!is_callable($pa['expectedBinding'] ?? null) || !is_callable($pa['hardwareVerifier'])) {
                throw new \TypeError('createZkVerifier: proverAttestation.expectedBinding must be a function');
            }
        }
        $label = $backend !== null
            ? (Assurance::labelOf($backend) ?? new AssuranceLabel('unknown'))
            : ($hwLabel !== null ? new AssuranceLabel('attested_vm_hw', 'hardware-bound:' . ($hwLabel->vendor ?? $hwLabel->level)) : new AssuranceLabel('attested_vm'));
        $strings = static fn(mixed $l): ?array => is_array($l) && array_is_list($l) ? array_values(array_filter($l, 'is_string')) : null;
        $trusted = $strings($opts['trustedProverKeys'] ?? null) ?? [];
        $revoked = $strings($opts['revokedProverKeys'] ?? null) ?? [];
        $expectedPolicy = $strings($opts['policyCommitments'] ?? null);
        $clock = is_callable($opts['now'] ?? null) ? $opts['now'] : static fn(): int => (int) floor(microtime(true) * 1000);
        $skewIn = Js::num($opts['clockSkewMs'] ?? null);
        $skew = $skewIn !== null && is_finite($skewIn) ? max(0.0, $skewIn) : 0.0;
        $fail = static fn(string $reason): array => ['enforced' => true, 'ok' => false, 'reason' => $reason];
        $hook = static function (mixed $ctx) use ($backend, $pa, $trusted, $revoked, $expectedPolicy, $clock, $skew, $fail): array {
            try {
                $pcactn = Js::opt($ctx, 'pcactn');
                $proof = Js::opt($pcactn, 'zk_compliance');
                if ($proof === null) {
                    return $fail('no zk_compliance proof present');
                }
                $actionCommit = self::actionCommitment($pcactn);
                $root = Js::opt(Js::opt($pcactn, 'plan'), 'root');
                $planCommit = is_string($root) ? $root : '';
                $wantPolicy = $expectedPolicy ?? [self::policyCommitment(Js::opt($ctx, 'grant'))];
                if ($backend !== null) {
                    $distinct = array_values(array_unique($expectedPolicy ?? []));
                    $policyCommit = count($distinct) === 1 ? $distinct[0] : self::policyCommitment(Js::opt($ctx, 'grant'));
                    $ok = $backend->verify(['proof' => $proof, 'publicInputs' => ['action_commit' => $actionCommit, 'policy_commit' => $policyCommit, 'plan_commit' => $planCommit], 'ctx' => $ctx]);
                    return $ok ? ['enforced' => true, 'ok' => true] : $fail('snark backend rejected the proof');
                }
                $st = $proof;
                if (Js::num(Js::opt($st, 'v')) !== 1.0 || Js::opt($st, 'mode') !== 'attested-vm') {
                    return $fail('unrecognized compliance statement');
                }
                if (Js::opt($st, 'released') !== true) {
                    return $fail('statement does not assert release');
                }
                $prover = Js::opt($st, 'prover');
                if (!is_string($prover) || !in_array($prover, $trusted, true)) {
                    return $fail('prover key is not trusted');
                }
                if (in_array($prover, $revoked, true)) {
                    return $fail('prover key is revoked');
                }
                $sig = Js::opt($st, 'sig');
                $body = Sign::n($st);
                $body = $body instanceof Obj ? $body->without('sig') : $body;
                if (!is_string($sig) || !Pca::verifyEd25519B64u($prover, self::STATEMENT_DOMAIN . Json::canonicalizeNative($body), $sig)) {
                    return $fail('compliance statement signature does not verify');
                }
                $iat = Js::num(Js::opt($st, 'issued_at'));
                $exp = Js::num(Js::opt($st, 'expires_at'));
                if ($iat === null || $exp === null || !is_finite($iat) || !is_finite($exp) || $exp < $iat) {
                    return $fail('malformed statement validity window');
                }
                $nowMs = $clock();
                if ($nowMs + $skew < $iat) {
                    return $fail('compliance statement not yet valid');
                }
                if ($nowMs - $skew > $exp) {
                    return $fail('compliance statement expired');
                }
                if (Js::opt($st, 'action_commit') !== $actionCommit) {
                    return $fail('statement does not bind to this action');
                }
                if (Js::opt($st, 'plan_commit') !== $planCommit) {
                    return $fail('statement does not bind to this plan commitment');
                }
                $pc = Js::opt($st, 'policy_commit');
                if (!is_string($pc) || !in_array($pc, $wantPolicy, true)) {
                    return $fail('statement policy commitment is not an expected policy');
                }
                if ($pa !== null) {
                    $expected = ($pa['expectedBinding'])($prover);
                    $hw = ($pa['hardwareVerifier'])(['document' => ['attestor' => $prover, 'mode' => 'hardware'], 'ctx' => $ctx, 'nowMs' => $nowMs, 'expected' => $expected]);
                    if (!Js::truthy($hw) || Js::opt($hw, 'ok') !== true) {
                        $why = Js::opt($hw, 'reason');
                        return $fail('prover hardware evidence invalid: ' . (Js::truthy($hw) ? ($why === null ? 'no reason given' : Js::str($why)) : 'no result'));
                    }
                    if (Js::opt($hw, 'bound') !== true) {
                        return $fail('prover hardware evidence does not bind the prover key');
                    }
                    $measurement = Js::opt(Js::opt($hw, 'measured'), 'runtime_measurement');
                    if (!is_string($measurement)) {
                        return $fail('prover hardware evidence carries no measured identity');
                    }
                    if (!in_array($measurement, $pa['measurements'], true)) {
                        return $fail('prover VM measurement is not allowlisted');
                    }
                }
                return ['enforced' => true, 'ok' => true];
            } catch (\Throwable $e) {
                return $fail('zk verification error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()));
            }
        };
        Assurance::setLabel($hook, $label);
        return $hook;
    }

    // ---- the canonical envelope gate ------------------------------------------------------------------------------------------------

    private static function canonDecBelow(mixed $v, \GMP $bound): bool
    {
        return is_string($v) && strlen($v) <= 120 && preg_match(self::CANON_DEC, $v) === 1 && gmp_cmp(gmp_init($v, 10), $bound) < 0;
    }

    /** @param list<string> $keys */
    private static function sameKeys(Obj $o, array $keys): bool
    {
        $k = $o->keys();
        sort($k, SORT_STRING);
        sort($keys, SORT_STRING);
        return $k === $keys;
    }

    private static function obj(mixed $v): ?Obj
    {
        if ($v instanceof Obj) {
            return $v;
        }
        if (is_array($v) && $v !== [] && !array_is_list($v)) {
            $n = Sign::n($v);
            return $n instanceof Obj ? $n : null;
        }
        return null;
    }

    /**
     * Is `$env` exactly {system, circuit, proof, publicSignals} with a snarkjs Groth16 proof in canonical form for `$curve`
     * ("bn254", anything else is BLS12-381): decimal strings without leading zeros, at most 120 digits, below the field modulus
     * (the base field for point coordinates, the scalar field for the signals), affine points (z = "1", G2 z = ["1", "0"])?
     */
    public static function isCanonicalGroth16Envelope(mixed $env, mixed $curve): bool
    {
        self::need();
        $e = self::obj($env);
        if ($e === null || !self::sameKeys($e, ['system', 'circuit', 'proof', 'publicSignals'])) {
            return false;
        }
        $bn = $curve === 'bn254';
        $fq = gmp_init($bn ? self::BN254_FQ : self::BLS12381_FQ, 0);
        $fr = gmp_init($bn ? self::BN254_FR : self::BLS12381_FR, 0);
        $ps = $e->get('publicSignals');
        if (!is_array($ps) || !array_is_list($ps)) {
            return false;
        }
        foreach ($ps as $x) {
            if (!self::canonDecBelow($x, $fr)) {
                return false;
            }
        }
        $pr = self::obj($e->get('proof'));
        if ($pr === null || !self::sameKeys($pr, ['pi_a', 'pi_b', 'pi_c', 'protocol', 'curve'])) {
            return false;
        }
        if ($pr->get('protocol') !== 'groth16' || $pr->get('curve') !== ($bn ? 'bn128' : 'bls12381')) {
            return false;
        }
        $list = static fn(mixed $a, int $n): bool => is_array($a) && array_is_list($a) && count($a) === $n;
        $g1 = static fn(mixed $a): bool => $list($a, 3) && self::canonDecBelow($a[0], $fq) && self::canonDecBelow($a[1], $fq) && $a[2] === '1';
        if (!$g1($pr->get('pi_a')) || !$g1($pr->get('pi_c'))) {
            return false;
        }
        $b = $pr->get('pi_b');
        if (!$list($b, 3)) {
            return false;
        }
        foreach ([$b[0], $b[1]] as $row) {
            if (!$list($row, 2) || !self::canonDecBelow($row[0], $fq) || !self::canonDecBelow($row[1], $fq)) {
                return false;
            }
        }
        return $list($b[2], 2) && $b[2][0] === '1' && $b[2][1] === '0';
    }

    // ---- struct hashes and quantization ----------------------------------------------------------------------------------------------

    /**
     * SHA-256 over the fields as 8-byte big-endian uint64 values, split into two 128-bit halves (decimal). Each field goes through the
     * reference's BigInt conversion (numbers must be integers; strings may be decimal or 0x / 0o / 0b). Throws outside [0, 2^64).
     * @return array{hi:string,lo:string}
     */
    public static function policyVmStructHash(mixed $fields): array
    {
        self::need();
        if (!is_array($fields) || !array_is_list($fields)) {
            throw new \TypeError('policyVmStructHash: fields must be a list');
        }
        $bytes = '';
        foreach ($fields as $f) {
            $v = self::big($f);
            if (gmp_sign($v) < 0 || gmp_cmp($v, self::u64Max()) > 0) {
                throw new \RangeException('policyVmStructHash: field out of uint64 range');
            }
            $bytes .= str_pad(gmp_sign($v) === 0 ? '' : gmp_export($v), 8, "\0", STR_PAD_LEFT);
        }
        $d = hash('sha256', $bytes, true);
        return ['hi' => gmp_strval(gmp_import(substr($d, 0, 16))), 'lo' => gmp_strval(gmp_import(substr($d, 16)))];
    }

    /** The struct hash of the five risk fields (revScore, taint, conf, age, rFloorIn). @return array{hi:string,lo:string} */
    public static function policyVmRiskHash(mixed $fields): array
    {
        if (!is_array($fields) || !array_is_list($fields) || count($fields) !== count(self::POLICYVM_BOUND_RISK_FIELDS)) {
            throw new \InvalidArgumentException('policyVmRiskHash: need exactly 5 risk fields');
        }
        return self::policyVmStructHash($fields);
    }

    private static function contentAddressU64(string $domain, string $value): \GMP
    {
        return gmp_import(substr(hash('sha256', "atlas-pca/policyvm-quantize/$domain:" . Js::utf8($value), true), 0, 8));
    }

    private static function codeFor(string $domain, mixed $value, mixed $map, bool $strict): \GMP
    {
        if (!is_string($value)) {
            throw new \InvalidArgumentException("policyvm quantize: $domain must be a string");
        }
        if (Js::has($map, $value)) {
            return self::toU64(Js::opt($map, $value), "$domain code");
        }
        if ($strict) {
            throw new \InvalidArgumentException("policyvm quantize: $domain \"$value\" is not in the catalog (strict)");
        }
        self::need();
        return self::contentAddressU64($domain, $value);
    }

    private static function paramScalarFrom(mixed $params, mixed $field): \GMP
    {
        self::need();
        if (!is_string($field) || $field === '') {
            return gmp_init(0);
        }
        if (Js::isObj($params) && !Js::has($params, $field) && in_array($field, self::OBJECT_PROTOTYPE, true)) {
            throw new \InvalidArgumentException('policyvm quantize: paramScalar is not a non-negative integer'); // an inherited member, never a number
        }
        $v = Js::opt($params, $field);
        if ($v === null) {
            return gmp_init(0);
        }
        if ($v instanceof \GMP) {
            return self::toU64($v, 'paramScalar');
        }
        if (Js::isNum($v)) {
            $f = Js::num($v);
            if (!is_finite($f) || floor($f) !== $f || $f < 0 || ($f === 0.0 && fdiv(1.0, $f) < 0)) {
                throw new \InvalidArgumentException('policyvm quantize: paramScalar must be a non-negative integer');
            }
            return self::toU64($v, 'paramScalar');
        }
        if (is_string($v) && preg_match('/\A[0-9]+\z/', $v) === 1) {
            return self::toU64(gmp_init($v, 10), 'paramScalar');
        }
        throw new \InvalidArgumentException('policyvm quantize: paramScalar is not a non-negative integer');
    }

    private static function reversibilityIndex(mixed $rc, string $what): \GMP
    {
        self::need();
        $idx = is_string($rc) ? array_search($rc, self::POLICYVM_REVERSIBILITY_ORDER, true) : false;
        if ($idx === false) {
            throw new \InvalidArgumentException("policyvm quantize: unknown $what class \"" . ($rc === self::NO_EXPECT ? 'undefined' : Js::str($rc)) . '"');
        }
        return gmp_init($idx);
    }

    private static function quantOpts(mixed $opts): mixed
    {
        return $opts === null ? throw new \TypeError("Cannot read properties of null (reading 'strictCatalog')") : $opts;
    }

    /** @return list<\GMP> */
    private static function actionStruct(mixed $action, mixed $opts): array
    {
        $opts = self::quantOpts($opts);
        if (!($action instanceof Obj) && !is_array($action)) {
            throw new \InvalidArgumentException('policyvm quantize: action is missing');
        }
        $strict = Js::opt($opts, 'strictCatalog') === true;
        $verb = self::codeFor('verb', Js::opt($action, 'verb'), Js::opt($opts, 'verbCodes'), $strict);
        $resource = self::codeFor('resource', Js::opt($action, 'resource'), Js::opt($opts, 'resourceCodes'), $strict);
        $rev = self::reversibilityIndex(Js::opt($action, 'reversibility_class') ?? 'reversible', 'reversibility');
        return [$verb, $resource, $rev, self::paramScalarFrom(Js::opt($action, 'params'), Js::opt($opts, 'paramScalarField'))];
    }

    /** @return list<\GMP> */
    private static function planStruct(mixed $plan, mixed $opts): array
    {
        $opts = self::quantOpts($opts);
        $strict = Js::opt($opts, 'strictCatalog') === true;
        return [
            self::codeFor('verb', Js::get($plan, 'verb'), Js::opt($opts, 'verbCodes'), $strict),
            self::codeFor('resource', Js::opt($plan, 'resource'), Js::opt($opts, 'resourceCodes'), $strict),
            self::toU64(Js::opt($plan, 'semanticDist'), 'semanticDist'),
            self::toU64(Js::opt($plan, 'planSalt'), 'planSalt'),
        ];
    }

    /** @return list<\GMP> */
    private static function policyStruct(mixed $policy, mixed $opts): array
    {
        $opts = self::quantOpts($opts);
        $strict = Js::opt($opts, 'strictCatalog') === true;
        $w = Js::get($policy, 'weights');
        $out = [];
        foreach (['alpha' => 'wAlpha', 'beta' => 'wBeta', 'gamma' => 'wGamma', 'delta' => 'wDelta', 'epsilon' => 'wEpsilon', 'zeta' => 'wZeta'] as $k => $what) {
            $out[] = self::toU64(Js::get($w, $k), $what);
        }
        foreach (['theta1', 'theta2', 'kappa', 'budgetB'] as $k) {
            $out[] = self::toU64(Js::opt($policy, $k), $k);
        }
        $out[] = self::codeFor('verb', Js::opt($policy, 'policyVerb'), Js::opt($opts, 'verbCodes'), $strict);
        $out[] = self::codeFor('resource', Js::opt($policy, 'policyResource'), Js::opt($opts, 'resourceCodes'), $strict);
        foreach (['policyParamBound', 'expiresAt', 'notBefore', 'maxBlast', 'maxDepth'] as $k) {
            $out[] = self::toU64(Js::opt($policy, $k), $k);
        }
        $out[] = self::reversibilityIndex(Js::has($policy, 'revMax') ? Js::opt($policy, 'revMax') : self::NO_EXPECT, 'revMax');
        $out[] = self::toU64(Js::opt($policy, 'rateMax'), 'rateMax');
        $out[] = self::toU64(Js::opt($policy, 'allocParent'), 'allocParent');
        return $out;
    }

    /**
     * The action as the circuit's four uint64 fields [verb, resource, reversibility, paramScalar] (decimal strings). Verb and resource
     * come from the catalog maps of `$opts` (verbCodes, resourceCodes) or are content-addressed; `strictCatalog` refuses a name
     * outside the maps; `paramScalarField` names the param that feeds the fourth field.
     * @return list<string>
     */
    public static function quantizeActionStruct(mixed $action, mixed $opts = []): array
    {
        return self::decimals(self::actionStruct($action, $opts));
    }

    /** The plan node {verb, resource, semanticDist, planSalt} as four uint64 fields. @return list<string> */
    public static function quantizePlanStruct(mixed $plan, mixed $opts = []): array
    {
        return self::decimals(self::planStruct($plan, $opts));
    }

    /** The policy ({weights, theta1, theta2, kappa, budgetB, policyVerb, policyResource, ...}) as its twenty uint64 fields. @return list<string> */
    public static function quantizePolicyStruct(mixed $policy, mixed $opts = []): array
    {
        return self::decimals(self::policyStruct($policy, $opts));
    }

    /** `{action, plan?, policy?}` quantized together. @return array{action:list<string>,plan?:list<string>,policy?:list<string>} */
    public static function quantizePolicyVmInputs(mixed $inp, mixed $opts = []): array
    {
        $out = ['action' => self::quantizeActionStruct(Js::get($inp, 'action'), $opts)];
        if (Js::truthy(Js::opt($inp, 'plan'))) {
            $out['plan'] = self::quantizePlanStruct(Js::opt($inp, 'plan'), $opts);
        }
        if (Js::truthy(Js::opt($inp, 'policy'))) {
            $out['policy'] = self::quantizePolicyStruct(Js::opt($inp, 'policy'), $opts);
        }
        return $out;
    }

    /** The struct hash of the quantized action: the value a relying party pins as `expectActionHash`. @return array{hi:string,lo:string} */
    public static function policyVmCommitmentFromAction(mixed $action, mixed $opts = []): array
    {
        return self::policyVmStructHash(self::actionStruct($action, $opts));
    }

    // ---- public signals --------------------------------------------------------------------------------------------------------------

    /** @param array<string,int> $layout */
    private static function decode(mixed $ps, array $layout, bool $risk): array
    {
        $s = static fn(string $k): mixed => self::at($ps, $layout[$k]);
        $halves = static function (string $name) use ($s): array {
            return array_filter(['hi' => $s($name . 'Hi'), 'lo' => $s($name . 'Lo')], static fn($v): bool => $v !== self::NO_EXPECT);
        };
        $out = ['actionHash' => $halves('action'), 'policyHash' => $halves('policy'), 'planHash' => $halves('plan')];
        if ($risk) {
            $out['riskHash'] = $halves('risk');
        }
        foreach (['r', 't', 'admit', 'allow', 'now', 'blast', 'delegationDepth', 'recentCount', 'allocChild'] as $k) {
            if ($s($k) !== self::NO_EXPECT) {
                $out[$k] = $s($k);
            }
        }
        return $out;
    }

    /** The 15 public signals of `pca-policyvm-v1` by name (a signal the list lacks is left out). Throws for null. */
    public static function decodePolicyVmPublic(mixed $publicSignals): array
    {
        return self::decode($publicSignals, self::POLICYVM_PUBLIC_SIGNAL, false);
    }

    /** The 17 public signals of `pca-policyvm-v2` by name, with `riskHash`. */
    public static function decodePolicyVmBoundPublic(mixed $publicSignals): array
    {
        return self::decode($publicSignals, self::POLICYVM_BOUND_PUBLIC_SIGNAL, true);
    }

    private static function pinBig(mixed $v): ?\GMP
    {
        try {
            if (Js::isNum($v)) {
                $f = Js::num($v);
                if (!is_finite($f) || floor($f) !== $f || abs($f) > 9007199254740991.0) {
                    return null;
                }
            }
            return self::big($v);
        } catch (\Throwable) {
            return null;
        }
    }

    private static function signalMatchesPin(mixed $signal, mixed $pin): bool
    {
        if (!is_string($signal) || preg_match(self::CANON_DEC, $signal) !== 1) {
            return false;
        }
        $x = gmp_init($signal, 10);
        if ($pin === null) {
            throw new \TypeError("Cannot read properties of null (reading 'min')");
        }
        if ($pin instanceof Obj || is_array($pin)) {
            $lo = Js::has($pin, 'min') ? self::pinBig(Js::opt($pin, 'min')) : null;
            $hi = Js::has($pin, 'max') ? self::pinBig(Js::opt($pin, 'max')) : null;
            return $lo !== null && $hi !== null && gmp_cmp($lo, $hi) <= 0 && gmp_cmp($x, $lo) >= 0 && gmp_cmp($x, $hi) <= 0;
        }
        $want = self::pinBig($pin);
        return $want !== null && gmp_cmp($x, $want) === 0;
    }

    /**
     * Do the context signals (now, blast, delegationDepth, recentCount, allocChild) lie below 2^64 and match the caller's pins?
     * `$expect` is NO_EXPECT (no pins), an object / array of pins {now?, blast?, delegationDepth?, recentCount?, allocChild?, r?, t?,
     * requireAdmit?, requireTier1?} or a \Closure returning one; a pin is a number, a \GMP, a decimal string or {min, max}.
     * `$bound` selects the 17-signal layout. Any odd shape is a refusal.
     */
    public static function policyVmContextMatches(mixed $ps, mixed $expect = self::NO_EXPECT, bool $bound = false): bool
    {
        self::need();
        $P = $bound ? self::POLICYVM_BOUND_PUBLIC_SIGNAL : self::POLICYVM_PUBLIC_SIGNAL;
        $limit = gmp_pow(2, 64);
        foreach (['now', 'blast', 'delegationDepth', 'recentCount', 'allocChild'] as $k) {
            $sig = self::at($ps, $P[$k]);
            if (!is_string($sig) || $sig === self::NO_EXPECT || preg_match(self::CANON_DEC, $sig) !== 1 || gmp_cmp(gmp_init($sig, 10), $limit) >= 0) {
                return false;
            }
        }
        if ($expect === self::NO_EXPECT) {
            return true;
        }
        if ($expect instanceof \Closure) {
            try {
                $expect = $expect();
            } catch (\Throwable) {
                return false;
            }
        }
        if (!($expect instanceof Obj) && !is_array($expect)) {
            return false;
        }
        foreach (['now', 'blast', 'delegationDepth', 'recentCount', 'allocChild', 'r', 't'] as $k) {
            if (Js::has($expect, $k) && !self::signalMatchesPin(self::at($ps, $P[$k]), Js::opt($expect, $k))) {
                return false;
            }
        }
        if (Js::truthy(Js::opt($expect, 'requireAdmit')) && self::at($ps, $P['admit']) !== '1') {
            return false;
        }
        return !(Js::truthy(Js::opt($expect, 'requireTier1')) && self::at($ps, $P['t']) !== '1');
    }

    // ---- Groth16 verification ----------------------------------------------------------------------------------------------------

    /** The pairing check in the mode the reference verifier has; a verifier error is a refusal, a missing library is not a verdict.
     * The curve is the one the key names (the library reads the name as the reference verifier does). */
    private static function pairing(mixed $vkey, mixed $ps, mixed $proof): bool
    {
        try {
            return ZkNative::verify(ZkNative::CURVE_FROM_KEY, Js::stringify($vkey), Js::stringify($proof), Js::stringify($ps))['ok'];
        } catch (ZkBackendMissing $e) {
            throw $e;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Verify a Policy VM proof envelope {system, circuit, proof, publicSignals}: `pca-policyvm-v1` on BN254 or BLS12-381, or the
     * risk-bound `pca-policyvm-v2` on BN254. Gates, in order: shape, circuit, system, signal count, the allow bit, the risk-hash pin,
     * the canonical envelope, the context bounds and pins, then the pairing check under `verificationKey` (else the file at
     * `verificationKeyPath`, else the bundled key of the circuit and curve). Options: verificationKey, verificationKeyPath, expect
     * (see {@see policyVmContextMatches}), expectRiskHash ({hi, lo}). Throws {@see ZkBackendMissing} without libpcazk.
     * @param array<string,mixed> $opts
     */
    public static function verifyPolicyVmProof(mixed $env, array $opts = []): bool
    {
        $p = self::obj($env);
        if ($p === null) {
            return false;
        }
        $boundCircuit = $p->get('circuit') === 'pca-policyvm-v2';
        if ($p->get('circuit') !== 'pca-policyvm-v1' && !$boundCircuit) {
            return false;
        }
        $isBls = $p->get('system') === 'groth16-bls12-381';
        if ($p->get('system') !== 'groth16-bn254' && !($isBls && !$boundCircuit)) {
            return false; // the risk-bound circuit is BN254 only
        }
        $L = $boundCircuit ? self::POLICYVM_BOUND_PUBLIC_SIGNAL : self::POLICYVM_PUBLIC_SIGNAL;
        $ps = $p->get('publicSignals');
        if (!is_array($ps) || !array_is_list($ps) || count($ps) !== ($boundCircuit ? self::POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT : self::POLICYVM_PUBLIC_SIGNAL_COUNT)
            || $p->get('proof') === null) {
            return false;
        }
        if ($ps[$L['allow']] !== '1') {
            return false;
        }
        if (array_key_exists('expectRiskHash', $opts)) {
            $want = $opts['expectRiskHash'];
            if (!$boundCircuit || $ps[$L['riskHi']] !== Js::get($want, 'hi') || $ps[$L['riskLo']] !== Js::get($want, 'lo')) {
                return false;
            }
        }
        if (!self::isCanonicalGroth16Envelope($p, $isBls ? 'bls12-381' : 'bn254')) {
            return false;
        }
        if (!self::policyVmContextMatches($ps, array_key_exists('expect', $opts) ? $opts['expect'] : self::NO_EXPECT, $boundCircuit)) {
            return false;
        }
        $default = $boundCircuit ? self::policyVmBoundVkeyPath() : ($isBls ? self::policyVmBls12381VkeyPath() : self::policyVmVkeyPath());
        $vkey = ($opts['verificationKey'] ?? null) ?? self::readJson(is_string($opts['verificationKeyPath'] ?? null) ? $opts['verificationKeyPath'] : $default);
        return self::pairing($vkey, $ps, $p->get('proof'));
    }

    private static function ceremonyLabel(mixed $opts, string $circuit): string
    {
        $c = Js::opt($opts, 'ceremony');
        if (!Js::truthy($c)) {
            return ZkCeremony::ceremonyOf(Js::opt($opts, 'verificationKey'), $c);
        }
        $ev = ['circuit' => $circuit];
        foreach (['transcript', 'sha256', 'r1csSha256'] as $k) {
            if (Js::has($c, $k)) {
                $ev[$k] = Js::opt($c, $k);
            }
        }
        return ZkCeremony::ceremonyOf(Js::opt($opts, 'verificationKey'), $ev);
    }

    private static function halvesMatch(array $ps, int $hi, int $lo, mixed $want): bool
    {
        return !Js::truthy($want) || (self::at($ps, $hi) === Js::opt($want, 'hi') && self::at($ps, $lo) === Js::opt($want, 'lo'));
    }

    private static function expectOpts(mixed $opts, mixed $vkey): array
    {
        return ['verificationKey' => $vkey] + (Js::has($opts, 'expect') ? ['expect' => Js::opt($opts, 'expect')] : []);
    }

    /**
     * A backend for the first compliance circuit (`pca-compliance-v1`, BN254): the proof's sha signals must equal the field elements
     * of the action, policy and plan commitments it is asked about. Options: verificationKey / verificationKeyPath (default
     * circuits/build/verification_key.json), ceremony ({transcript, sha256}). Label: `groth16` with the ceremony kind.
     * @param array<string,mixed> $opts
     */
    public static function createGroth16SnarkBackend(array $opts = []): ZkSnarkBackend
    {
        $getVkey = self::lazyVkey($opts, self::defaultVkeyPath());
        $b = new ZkClosureBackend(static function (array $in) use ($getVkey): bool {
            $env = self::obj($in['proof'] ?? null);
            if ($env === null || $env->get('system') !== 'groth16-bn254' || $env->get('circuit') !== 'pca-compliance-v1') {
                return false;
            }
            $ps = $env->get('publicSignals');
            $g16 = $env->get('proof');
            if (!is_array($ps) || !array_is_list($ps) || count($ps) !== self::COMPLIANCE_SIGNAL_COUNT || $g16 === null || $ps[6] !== '1') {
                return false;
            }
            $pi = $in['publicInputs'] ?? null;
            foreach ([3 => 'policy_commit', 4 => 'plan_commit', 5 => 'action_commit'] as $i => $k) {
                if ($ps[$i] !== self::commitmentField(Js::opt($pi, $k))) {
                    return false;
                }
            }
            if (!self::isCanonicalGroth16Envelope($env, 'bn254')) {
                return false;
            }
            return ZkNative::verify(ZkNative::CURVE_FROM_KEY, Js::stringify($getVkey()), Js::stringify($g16), Js::stringify($ps))['ok'];
        });
        Assurance::setLabel($b, new AssuranceLabel('groth16', null, false, self::ceremonyLabel($opts, 'pca-compliance-v1')));
        return $b;
    }

    private static function policyVmBackend(array $opts, string $defaultKey): ZkSnarkBackend
    {
        $getVkey = self::lazyVkey($opts, $defaultKey);
        $b = new ZkClosureBackend(static function (array $in) use ($getVkey, $opts): bool {
            $env = $in['proof'] ?? null;
            if (Js::opt($env, 'circuit') !== 'pca-policyvm-v1') {
                return false;
            }
            $ps = Js::opt($env, 'publicSignals');
            if (is_array($ps) && array_is_list($ps)) {
                $P = self::POLICYVM_PUBLIC_SIGNAL;
                foreach (['action' => 'expectActionHash', 'policy' => 'expectPolicyHash', 'plan' => 'expectPlanHash'] as $n => $k) {
                    if (!self::halvesMatch($ps, $P[$n . 'Hi'], $P[$n . 'Lo'], $opts[$k] ?? null)) {
                        return false;
                    }
                }
            }
            return self::verifyPolicyVmProof($env, self::expectOpts($opts, $getVkey()));
        });
        $ceremony = self::ceremonyLabel($opts, 'pca-policyvm-v1');
        $pinned = Js::truthy($opts['expectActionHash'] ?? null) && Js::truthy($opts['expectPolicyHash'] ?? null) && Js::truthy($opts['expectPlanHash'] ?? null);
        Assurance::setLabel($b, $pinned ? new AssuranceLabel('policyvm_snark', null, false, $ceremony) : new AssuranceLabel('unknown', 'policyvm-unbound', false, $ceremony));
        return $b;
    }

    /**
     * A backend for the Policy VM circuit on BN254. Options: verificationKey / verificationKeyPath (default the bundled key), expect,
     * ceremony, expectActionHash / expectPolicyHash / expectPlanHash ({hi, lo}: the struct hashes the proof must carry). Label:
     * `policyvm_snark` only when all three hashes are pinned, else `unknown` (vendor `policyvm-unbound`).
     * @param array<string,mixed> $opts
     */
    public static function createPolicyVmSnarkBackend(array $opts = []): ZkSnarkBackend
    {
        return self::policyVmBackend($opts, self::policyVmVkeyPath());
    }

    /** The same on BLS12-381 (default key: the bundled BLS12-381 key). @param array<string,mixed> $opts */
    public static function createPolicyVmSnarkBackendBls12381(array $opts = []): ZkSnarkBackend
    {
        return self::policyVmBackend($opts, self::policyVmBls12381VkeyPath());
    }

    /**
     * A backend for the risk-bound Policy VM circuit (`pca-policyvm-v2`, BN254), with `expectRiskHash` beside the three struct hashes
     * (all four pinned for the `policyvm_snark` label). Default key: circuits/build/policyvm_bound_vkey.json.
     * @param array<string,mixed> $opts
     */
    public static function createPolicyVmBoundSnarkBackend(array $opts = []): ZkSnarkBackend
    {
        $getVkey = self::lazyVkey($opts, self::policyVmBoundVkeyPath());
        $names = ['action' => 'expectActionHash', 'policy' => 'expectPolicyHash', 'plan' => 'expectPlanHash', 'risk' => 'expectRiskHash'];
        $b = new ZkClosureBackend(static function (array $in) use ($getVkey, $opts, $names): bool {
            $env = $in['proof'] ?? null;
            $ps = Js::opt($env, 'publicSignals');
            if (Js::opt($env, 'circuit') !== 'pca-policyvm-v2' || !is_array($ps) || !array_is_list($ps)) {
                return false;
            }
            $P = self::POLICYVM_BOUND_PUBLIC_SIGNAL;
            foreach ($names as $n => $k) {
                if (!self::halvesMatch($ps, $P[$n . 'Hi'], $P[$n . 'Lo'], $opts[$k] ?? null)) {
                    return false;
                }
            }
            return self::verifyPolicyVmProof($env, self::expectOpts($opts, $getVkey()) + (array_key_exists('expectRiskHash', $opts) && $opts['expectRiskHash'] !== null ? ['expectRiskHash' => $opts['expectRiskHash']] : []));
        });
        $ceremony = self::ceremonyLabel($opts, 'pca-policyvm-v2');
        $pinned = array_filter($names, static fn(string $k): bool => !Js::truthy($opts[$k] ?? null)) === [];
        Assurance::setLabel($b, $pinned ? new AssuranceLabel('policyvm_snark', null, false, $ceremony) : new AssuranceLabel('unknown', 'policyvm-unbound', false, $ceremony));
        return $b;
    }

    /**
     * The pinned version of a circuit from the bundled circuit-versions.json: {circuit, sourceSha256, circom, circomlib}. Throws for an
     * unknown id.
     * @return array{circuit:string,sourceSha256:mixed,circom:mixed,circomlib:mixed}
     */
    public static function circuitVersion(mixed $id): array
    {
        $v = self::readJson(self::circuits() . '/circuit-versions.json');
        $circuits = Js::opt($v, 'circuits');
        if (!is_string($id) || !Js::has($circuits, $id) || !Js::truthy(Js::opt($circuits, $id))) {
            throw new \InvalidArgumentException('circuitVersion: unknown circuit ' . (is_string($id) || $id === null || is_bool($id) || Js::isNum($id) ? Js::stringify($id) : 'undefined'));
        }
        return ['circuit' => $id, 'sourceSha256' => Js::opt(Js::opt($circuits, $id), 'source_sha256'), 'circom' => Js::opt($v, 'circom'), 'circomlib' => Js::opt($v, 'circomlib')];
    }

    // ---- proving (libpcazk: circom witness wasm + snarkjs zkey) ----------------------------------------------------------------------

    /** @param array<string,mixed> $input @return array{system:string,circuit:string,proof:mixed,publicSignals:mixed} */
    private static function fullProve(array $input, string $wasmPath, string $zkeyPath, string $circuit): array
    {
        $text = [];
        foreach ($input as $k => $v) {
            $text[(string) $k] = $v instanceof \GMP ? gmp_strval($v) : Js::str($v);
        }
        $out = Js::parse(ZkNative::prove(ZkNative::CURVE_BN254, self::readFile($wasmPath), self::readFile($zkeyPath), Js::stringify($text === [] ? new Obj() : $text)));
        return ['system' => 'groth16-bn254', 'circuit' => $circuit, 'proof' => Js::opt($out, 'proof'), 'publicSignals' => Js::opt($out, 'publicSignals')];
    }

    private static function witness(mixed $witness): array
    {
        $o = self::obj($witness);
        $out = [];
        foreach ($o?->keys() ?? [] as $k) {
            $out[$k] = $o->get($k);
        }
        return $out;
    }

    /**
     * Prove the first compliance circuit. `$inp` = {action_commit, policy_commit, plan_commit, verb, resource, planVerb, policySalt,
     * planSalt, actionSalt, risk, budget}; `$opts` = {wasmPath?, zkeyPath?} (defaults under circuits/build).
     * @param array<string,mixed> $opts
     */
    public static function proveGroth16Compliance(mixed $inp, array $opts = []): array
    {
        $input = [];
        foreach (['verb', 'resource', 'planVerb', 'policySalt', 'planSalt', 'actionSalt', 'risk', 'budget'] as $k) {
            $input[$k] = Js::opt($inp, $k);
        }
        $input += ['shaPolicy' => self::commitmentField(Js::opt($inp, 'policy_commit')), 'shaPlan' => self::commitmentField(Js::opt($inp, 'plan_commit')),
            'shaAction' => self::commitmentField(Js::opt($inp, 'action_commit')), 'allow' => '1'];
        return self::fullProve($input, $opts['wasmPath'] ?? self::defaultWasmPath(), $opts['zkeyPath'] ?? self::defaultZkeyPath(), 'pca-compliance-v1');
    }

    /** Prove the Policy VM circuit over a full witness (name => number, \GMP or decimal string). @param array<string,mixed> $opts */
    public static function provePolicyVmCompliance(mixed $witness, array $opts = []): array
    {
        return self::fullProve(self::witness($witness), $opts['wasmPath'] ?? self::policyVmWasmPath(), $opts['zkeyPath'] ?? self::policyVmZkeyPath(), 'pca-policyvm-v1');
    }

    /** Prove the risk-bound Policy VM circuit over a full witness. @param array<string,mixed> $opts */
    public static function provePolicyVmBoundCompliance(mixed $witness, array $opts = []): array
    {
        return self::fullProve(self::witness($witness), $opts['wasmPath'] ?? self::policyVmBoundWasmPath(), $opts['zkeyPath'] ?? self::policyVmBoundZkeyPath(), 'pca-policyvm-v2');
    }
}
