<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';

/**
 * What a hook, hardware verifier or SNARK backend declares about itself (T8, B7). `level` is the attestation level
 * (`software` < `hardware` < `multi_root`), the zk system (`groth16`, `policyvm_snark`, `stark`, `zkvm`, `attested_vm`,
 * `attested_vm_hw`) or the threshold scheme (`multisig`, `frost`, `frost_dkg`, `mpc`); `vendor` a vendor or root id; `awaitingAudit`
 * marks crypto awaiting audit (not production); `ceremony` (`single-party` | `multi-party`) tells how a SNARK verifying key was set up.
 */
final class AssuranceLabel
{
    public function __construct(
        public readonly string $level,
        public readonly ?string $vendor = null,
        public readonly bool $awaitingAudit = false,
        public readonly ?string $ceremony = null,
    ) {
    }
}

/** Implemented by a verifier, hook or backend that declares its own assurance label. */
interface AssuranceLabeler
{
    public function assurance(): AssuranceLabel;
}

/**
 * A high-assurance policy. Every listed dimension must be met by a PASSING check; otherwise the `assurance` check fails.
 * `attestation`: minimum level (`software` < `hardware` < `multi_root`). `zk`: `attested_vm` accepts any enforced statement;
 * `attested_vm_hardware` a statement whose prover key is bound to hardware evidence (or any real proof); `proof` a
 * cryptographic proof; `snark` only Groth16 / Policy-VM SNARK. `signature` `'pq'`: the leaf signature and every capability in
 * the chain use a hybrid or pure post-quantum suite. `threshold`: the accepted threshold schemes (null: not required).
 * `allowAwaitingAudit` accepts passing evidence awaiting audit (FROST, DKG, MPC) outside an explicit `threshold` list.
 */
final class AssuranceRequirement
{
    /** @param list<string>|null $threshold */
    public function __construct(
        public readonly ?string $attestation = null,
        public readonly ?string $zk = null,
        public readonly ?string $signature = null,
        public readonly ?array $threshold = null,
        public readonly bool $allowAwaitingAudit = false,
        /** Set by {@see fromJson} when the policy carried a key or value this verifier does not understand; {@see Assurance::unmet} refuses it. */
        public readonly ?string $invalid = null,
    ) {
    }

    private const KNOWN = ['attestation', 'zk', 'signature', 'threshold', 'allowAwaitingAudit', 'allowPreview'];

    /** Read a requirement from parsed JSON (an Obj) or a PHP array. */
    public static function fromJson(mixed $v): self
    {
        $get = static fn(string $k): mixed => $v instanceof Obj ? $v->get($k) : (is_array($v) ? ($v[$k] ?? null) : null);
        $keys = $v instanceof Obj ? $v->keys() : (is_array($v) ? array_map('strval', array_keys($v)) : []);
        $has = static fn(string $k): bool => $v instanceof Obj ? $v->has($k) : (is_array($v) && array_key_exists($k, $v));
        $thr = $get('threshold');
        // A policy often arrives as JSON: anything not understood is refused, never dropped (fail closed).
        $invalid = null;
        foreach ($keys as $k) {
            if (!in_array($k, self::KNOWN, true)) {
                $invalid = "assurance: unknown requirement $k (fail closed)";
                break;
            }
        }
        $ok = [
            'attestation' => in_array($get('attestation'), ['software', 'hardware', 'multi_root'], true),
            'zk' => in_array($get('zk'), ['attested_vm', 'attested_vm_hardware', 'proof', 'snark'], true),
            'signature' => $get('signature') === 'pq',
            'threshold' => is_array($thr) && array_is_list($thr) && count(array_filter($thr, static fn(mixed $x): bool => is_string($x) && in_array($x, ['multisig', 'frost', 'frost_dkg', 'mpc'], true))) === count($thr),
        ];
        foreach ($ok as $k => $good) {
            if ($invalid === null && $has($k) && !$good) {
                try {
                    $enc = Json::canonicalizeLenient($get($k));
                } catch (JsonError) {
                    $enc = 'null';
                }
                $invalid = "assurance: unknown $k requirement $enc (fail closed)";
            }
        }
        return new self($ok['attestation'] ? $get('attestation') : null, $ok['zk'] ? $get('zk') : null,
            $ok['signature'] ? 'pq' : null, $ok['threshold'] ? array_values($thr) : null,
            $get('allowAwaitingAudit') === true || $get('allowPreview') === true, $invalid);
    }
}

/**
 * Assurance labels (T8, B7). A check's status (`pass`, `fail`, `not-enforced`, `unsupported`) says WHETHER it held; the assurance
 * report says WHAT a pass rests on: software or hardware attestation, a SNARK proof or an attested-VM statement, a post-quantum or
 * an Ed25519 signature, independent multisig shares or a FROST (awaiting audit) aggregate. It also names the features this verifier does
 * not implement (`unsupported`: a bond reference), which are reported and never count as a pass.
 *
 * Labels come from the VERIFIER'S configuration, never from the presented evidence: a hook or verifier carries its label
 * ({@see AssuranceLabeler}, or {@see setLabel} on any object including a closure); an unlabelled one is `unknown` and satisfies no
 * requirement. A requirement ({@see AssuranceRequirement}) turns the report into a gate: when the evidence is weaker, missing,
 * failed, unlabelled, awaiting-audit, degraded or unsupported, the `assurance` check fails and the request is denied. Mirrors the reference
 * assurance module; assurance-vectors.json pins the report and every reason.
 *
 * A report is an ordered array `check name => entry`; an entry is `['outcome' => string, 'level'?, 'vendor'?, 'awaiting_audit'? => true,
 * 'ceremony'?, 'suites'? => list<string>, 't'?, 'reason'?, 'degraded'? => true]`.
 */
final class Assurance
{
    /** @var \WeakMap<object, AssuranceLabel>|null */
    private static ?\WeakMap $labels = null;

    private const ATT_RANK = ['unknown' => 0, 'software' => 1, 'hardware' => 2, 'multi_root' => 3];
    private const ZK_RANK = ['unknown' => 0, 'attested_vm' => 1, 'attested_vm_hw' => 1, 'stark' => 2, 'zkvm' => 2, 'groth16' => 3, 'policyvm_snark' => 3];
    private const ZK_NEED = ['attested_vm' => 1, 'attested_vm_hardware' => 1, 'proof' => 2, 'snark' => 3];
    private const AWAITING_AUDIT_SCHEMES = ['frost', 'frost_dkg', 'mpc'];

    /** Attach an assurance label to a verifier hook, a hardware verifier or a SNARK backend (any object, closures included). Returns `$target`. */
    public static function setLabel(object $target, AssuranceLabel $label): object
    {
        self::$labels ??= new \WeakMap();
        self::$labels[$target] = $label;
        return $target;
    }

    /** The label of `$target` (null: unlabelled). */
    public static function labelOf(mixed $target): ?AssuranceLabel
    {
        if (!is_object($target)) {
            return null;
        }
        if ($target instanceof AssuranceLabeler) {
            return $target->assurance();
        }
        return self::$labels !== null && isset(self::$labels[$target]) ? self::$labels[$target] : null;
    }

    public static function isAwaitingAuditScheme(string $s): bool
    {
        return in_array($s, self::AWAITING_AUDIT_SCHEMES, true);
    }

    /** Classify one signature suite (absent or null = Ed25519): `ed25519`, `hybrid`, `pq`, or `unknown` for an unregistered suite. */
    public static function signatureLevel(mixed $alg): string
    {
        $a = $alg ?? 'ed25519';
        if ($a === 'ed25519') {
            return 'ed25519';
        }
        if (!is_string($a) || !in_array($a, Pca::REGISTERED_SUITES, true)) {
            return 'unknown';
        }
        return str_starts_with($a, 'hybrid-') ? 'hybrid' : 'pq';
    }

    /** The weakest level in a chain: any unknown suite, then any Ed25519-only signer, then any hybrid, else pure PQ. @param list<string> $levels */
    private static function weakest(array $levels): string
    {
        foreach (['unknown', 'ed25519', 'hybrid'] as $l) {
            if (in_array($l, $levels, true)) {
                return $l;
            }
        }
        return $levels !== [] ? 'pq' : 'unknown';
    }

    /**
     * The attestation level an N-of-M multi-root policy guarantees: the fewest hardware roots any accepted subset can contain (all
     * required roots, filled up to `$threshold` with the weakest optional ones). Two or more hardware roots is `multi_root`, one is
     * `hardware`, none is the weakest level among the roots that could make up the quorum.
     *
     * @param list<array{verifier:mixed, required?:bool}> $roots
     */
    public static function multiRootLevel(array $roots, int $threshold): string
    {
        $rank = static fn(array $r): int => self::ATT_RANK[self::labelOf($r['verifier'] ?? null)?->level ?? 'unknown'] ?? 0;
        $req = array_values(array_filter($roots, static fn(array $r): bool => ($r['required'] ?? false) === true));
        $opt = array_values(array_filter($roots, static fn(array $r): bool => ($r['required'] ?? false) !== true));
        usort($opt, static fn(array $a, array $b): int => $rank($a) <=> $rank($b)); // stable since PHP 8.0
        $chosen = array_merge($req, array_slice($opt, 0, max(0, $threshold - count($req))));
        $hw = count(array_filter($chosen, static fn(array $r): bool => $rank($r) >= self::ATT_RANK['hardware']));
        if ($hw >= 2) {
            return 'multi_root';
        }
        if ($hw === 1) {
            return 'hardware';
        }
        $min = $chosen === [] ? PHP_INT_MAX : min(array_map($rank, $chosen)); // the minimum of nothing is +Infinity
        return $min >= self::ATT_RANK['software'] ? 'software' : 'unknown';
    }

    /**
     * Build the per-check assurance report (pure; never throws on odd input).
     *
     * @param array<string,string> $checks check name => `pass` | `fail` | `not-enforced` | `unsupported`, in decision order
     * @param Obj|null $pcactn the presented PCActn (its `alg`, the cap_chain algs and `bond_ref` are read)
     * @param array{attestation?:mixed, zk?:mixed, threshold?:mixed, revocation?:mixed} $hooks the verifier's hooks (labels are read off them)
     * @param mixed $attestationHook the attestation verifier actually used; it wins over `$hooks['attestation']`
     * @param array<string,string> $degraded passing checks that rest on a compatibility mode: check name => why
     * @return array<string,array<string,mixed>>
     */
    public static function report(array $checks, ?Obj $pcactn = null, array $hooks = [], mixed $attestationHook = null, ?float $thresholdT = null,
                                  bool $allowUnboundPq = false, array $degraded = []): array
    {
        $out = [];
        foreach ($checks as $name => $status) {
            $name = (string)$name;
            $e = ['outcome' => $status];
            if ($status === 'unsupported') {
                $e['reason'] = "$name is not implemented by this verifier";
            }
            if ($status === 'pass') {
                $hook = match ($name) {
                    'attestation' => $attestationHook ?? ($hooks['attestation'] ?? null),
                    'zk_compliance' => $hooks['zk'] ?? null,
                    'threshold' => $hooks['threshold'] ?? null,
                    'revocation' => $hooks['revocation'] ?? null,
                    default => null,
                };
                $label = self::labelOf($hook);
                if ($name === 'attestation' || $name === 'zk_compliance' || ($name === 'threshold' && $hook !== null)) {
                    $e['level'] = $label === null || $label->level === '' ? 'unknown' : $label->level;
                    if ($label?->vendor !== null) {
                        $e['vendor'] = $label->vendor;
                    }
                    if ($name === 'zk_compliance' && $label?->ceremony !== null) {
                        $e['ceremony'] = $label->ceremony;
                    }
                    if ($label?->awaitingAudit === true || ($name === 'threshold' && self::isAwaitingAuditScheme($e['level']))) {
                        $e['awaiting_audit'] = true;
                    }
                    if ($name === 'threshold' && $thresholdT !== null) {
                        $e['t'] = floor($thresholdT) === $thresholdT && abs($thresholdT) < 1e15 ? (int)$thresholdT : $thresholdT;
                    }
                } elseif ($label !== null) {
                    $e['level'] = $label->level;
                    if ($label->vendor !== null) {
                        $e['vendor'] = $label->vendor;
                    }
                    if ($label->awaitingAudit) {
                        $e['awaiting_audit'] = true;
                    }
                }
                if ($name === 'leaf_signature' && $pcactn !== null) {
                    $alg = $pcactn->get('alg') ?? 'ed25519';
                    $e['suites'] = [self::str($alg)];
                    $e['level'] = $allowUnboundPq && $alg !== 'ed25519' ? 'unbound_pq' : self::signatureLevel($alg);
                }
                if ($name === 'cap_chain' && $pcactn !== null && is_array($pcactn->get('cap_chain'))) {
                    $algs = array_map(static fn(mixed $c): mixed => ($c instanceof Obj ? $c->get('alg') : null) ?? 'ed25519', $pcactn->get('cap_chain'));
                    $e['suites'] = array_map([self::class, 'str'], $algs);
                    $e['level'] = $allowUnboundPq && count(array_filter($algs, static fn(mixed $a): bool => $a !== 'ed25519')) > 0
                        ? 'unbound_pq' : self::weakest(array_map([self::class, 'signatureLevel'], $algs));
                }
            }
            $out[$name] = $e;
        }
        foreach ($degraded as $name => $why) {
            if (($out[$name]['outcome'] ?? null) === 'pass') {
                $out[$name]['degraded'] = true;
                $out[$name]['reason'] = $why;
            }
        }
        // Features this verifier does not implement: reported, never a pass.
        if ($pcactn !== null && $pcactn->has('bond_ref')) {
            $out['bond'] = ['outcome' => 'unsupported', 'reason' => 'bond verification is not implemented by this verifier'];
        }
        return $out;
    }

    /** A suite value as JavaScript's `String()` renders the common cases. */
    private static function str(mixed $v): string
    {
        $r = match (true) { // assigned, not returned: coverage attributes a returned match to its arms, never to this line
            is_string($v) => $v,
            $v instanceof Num => $v->lexeme,
            is_bool($v) => $v ? 'true' : 'false',
            default => 'null',
        };
        return $r;
    }

    /**
     * Refresh a report after more checks were decided (the replay counter, default-deny of required checks): a check that is no longer `pass` loses its
     * level, a new check is added, `unsupported` stays. Returns the refreshed report (the input is not mutated).
     * @param array<string,array<string,mixed>> $report
     * @param array<string,string> $checks name => `pass` | `fail` | `not-enforced` | ...
     * @return array<string,array<string,mixed>>
     */
    public static function refresh(array $report, array $checks): array
    {
        foreach ($checks as $name => $status) {
            $was = $report[$name] ?? null;
            if (($was['outcome'] ?? null) === 'unsupported') {
                continue;
            }
            if ($status !== 'pass') {
                $report[$name] = ['outcome' => $status];
            } elseif ($was === null || $was['outcome'] !== 'pass') {
                $report[$name] = ['outcome' => 'pass'];
            }
        }
        return $report;
    }

    /**
     * Check a report against a requirement. Returns the reason of the first unmet dimension (prefixed `assurance: `), or null when
     * every listed dimension is met. Missing, failed, not-enforced, unlabelled, weaker, awaiting-audit, degraded and unsupported evidence
     * never meet a requirement.
     *
     * @param array<string,array<string,mixed>> $report
     */
    public static function unmet(array $report, AssuranceRequirement $req): ?string
    {
        if ($req->invalid !== null) {
            return $req->invalid;
        }
        foreach ([['attestation', $req->attestation, ['software', 'hardware', 'multi_root']], ['zk', $req->zk, array_keys(self::ZK_NEED)], ['signature', $req->signature, ['pq']]] as [$k, $val, $known]) {
            if ($val !== null && !in_array($val, $known, true)) {
                return "assurance: unknown $k requirement " . json_encode($val, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . ' (fail closed)';
            }
        }
        if ($req->threshold !== null && count(array_diff($req->threshold, ['multisig', 'frost', 'frost_dkg', 'mpc'])) > 0) {
            return 'assurance: unknown threshold requirement ' . json_encode(array_values($req->threshold), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . ' (fail closed)';
        }
        foreach ($report as $name => $e) {
            if ($e['outcome'] === 'unsupported') {
                return "assurance: unsupported: $name (" . (($e['reason'] ?? '') === '' ? 'not implemented' : $e['reason'])
                    . '); a high-assurance policy never accepts it';
            }
        }
        foreach ($report as $name => $e) {
            if ($e['outcome'] === 'pass' && ($e['degraded'] ?? false) === true) {
                return "assurance: $name rests on a degraded compatibility mode (" . (($e['reason'] ?? '') === '' ? 'degraded' : $e['reason'])
                    . '); a high-assurance policy never accepts it';
            }
        }
        $need = static function (string $name, string $what) use ($report): array|string {
            if (!isset($report[$name])) {
                return "assurance: $what required but there is no $name evidence";
            }
            if ($report[$name]['outcome'] !== 'pass') {
                return "assurance: $what required but the $name check is " . $report[$name]['outcome'];
            }
            return $report[$name];
        };
        $lv = static fn(array $e): string => ($e['level'] ?? '') === '' ? 'unknown' : $e['level'];
        if ($req->attestation !== null) {
            $e = $need('attestation', $req->attestation . ' attestation');
            if (is_string($e)) {
                return $e;
            }
            if ((self::ATT_RANK[$lv($e)] ?? 0) < (self::ATT_RANK[$req->attestation] ?? 99)) {
                return "assurance: {$req->attestation} attestation required but the evidence is " . $lv($e);
            }
        }
        if ($req->zk !== null) {
            $e = $need('zk_compliance', "zk compliance ({$req->zk})");
            if (is_string($e)) {
                return $e;
            }
            if ($req->zk === 'attested_vm_hardware' && in_array($e['level'] ?? '', ['attested_vm', 'unknown', ''], true)) {
                return "assurance: zk compliance ({$req->zk}) required but the prover key is not bound to hardware evidence";
            }
            if ((self::ZK_RANK[$lv($e)] ?? 0) < (self::ZK_NEED[$req->zk] ?? 99)) {
                return "assurance: zk compliance ({$req->zk}) required but the evidence is " . $lv($e);
            }
        }
        if ($req->signature === 'pq') {
            foreach (['leaf_signature', 'cap_chain'] as $name) {
                $e = $need($name, 'post-quantum signatures');
                if (is_string($e)) {
                    return $e;
                }
                if (!in_array($e['level'] ?? null, ['pq', 'hybrid'], true)) {
                    return "assurance: post-quantum signatures required but $name is " . $lv($e);
                }
            }
        }
        if ($req->threshold !== null) {
            $list = implode(' | ', $req->threshold);
            $e = $need('threshold', "threshold ($list)");
            if (is_string($e)) {
                return $e;
            }
            if (($e['level'] ?? '') === '') {
                return "assurance: threshold ($list) required but no threshold verifier enforced it";
            }
            if (!in_array($e['level'], $req->threshold, true)) {
                return "assurance: threshold ($list) required but the scheme is {$e['level']}";
            }
        }
        if (!$req->allowAwaitingAudit) {
            foreach ($report as $name => $e) {
                if ($e['outcome'] !== 'pass' || (($e['awaiting_audit'] ?? $e['preview'] ?? false) !== true)) {
                    continue;
                }
                if ($name === 'threshold' && $req->threshold !== null && in_array($e['level'] ?? '', $req->threshold, true)) {
                    continue;
                }
                return "assurance: $name rests on crypto awaiting audit (" . $lv($e) . '); set allowAwaitingAudit or list the scheme to accept it';
            }
        }
        return null;
    }
}
