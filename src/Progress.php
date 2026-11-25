<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Ha.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/LedgerLog.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';

/** A denial of a progress step: `code` is the reference's step denial (`unknown-potential`, `embedder-mismatch`, `bad-potential`, ...). */
final class ProgressError extends \RuntimeException
{
    public readonly string $codeName;

    public function __construct(public readonly string $denial, string $message)
    {
        $this->codeName = $denial;
        parent::__construct($message);
    }
}

/** What a trusted state source hands back: `{state, state_digest, source, evidence?}` (null, or a throw, is a refusal). */
interface ProgressStateSource
{
    public function id(): string;

    /** @param Obj $req `{action_digest, goal_commitment, prior_digest}` @return mixed the observation Obj (anything else is refused) */
    public function observe(Obj $req): mixed;
}

/**
 * The verifier-held registry of version-pinned potentials. A potential is a callable `(objective, state): int` that maps to a
 * NON-NEGATIVE SAFE INTEGER (anything else is `bad-potential`). Lookups are by own id only, ids cannot be shadowed once registered, and the
 * registry can be frozen; an id that is not registered fails closed.
 */
final class PotentialRegistry
{
    /** @var array<string,array{0:string,1:callable,2:string}> */
    private array $m = [];
    private bool $frozen = false;

    public function register(mixed $id, mixed $fn, mixed $embedder = ''): self
    {
        if ($this->frozen) {
            throw new \RuntimeException('registry is frozen');
        }
        if (!is_string($id) || $id === '' || Js::len($id) > 128) {
            throw new \TypeError('potential id: 1..128 chars');
        }
        if (!is_callable($fn)) {
            throw new \TypeError('potential must be a function');
        }
        if (!is_string($embedder)) {
            throw new \TypeError('embedder must be a string');
        }
        if (isset($this->m['k' . $id])) {
            throw new \RuntimeException("potential $id already registered");
        }
        $this->m['k' . $id] = [$id, $fn, $embedder];
        return $this;
    }

    /** @return ?array{fn:callable,embedder:string} */
    public function get(mixed $id): ?array
    {
        $e = is_string($id) ? ($this->m['k' . $id] ?? null) : null;
        return $e === null ? null : ['fn' => $e[1], 'embedder' => $e[2]];
    }

    public function has(mixed $id): bool
    {
        return is_string($id) && isset($this->m['k' . $id]);
    }

    /** Registered ids, sorted by UTF-16 code units. @return list<string> */
    public function ids(): array
    {
        $ids = array_map(static fn(array $e): string => $e[0], array_values($this->m));
        usort($ids, static fn(string $a, string $b): int => Jsx::cmp($a, $b));
        return $ids;
    }

    public function freeze(): self
    {
        $this->frozen = true;
        return $this;
    }

    /** Build from `[id, callable | ['fn' => callable, 'embedder' => ?]]` pairs (a plain record's own entries). @param list<array{0:mixed,1:mixed}> $rec */
    public static function from(array $rec): self
    {
        $r = new self();
        foreach ($rec as [$id, $v]) {
            if (is_callable($v)) {
                $r->register($id, $v);
            } else {
                $e = $v['embedder'] ?? '';
                $r->register($id, $v['fn'] ?? null, $e ?? '');
            }
        }
        return $r;
    }

    /** A fresh, mutable registry holding the three built-in potentials. */
    public static function defaults(): self
    {
        return (new self())->register('l1-feature-v1', [Progress::class, 'l1FeaturePotential'])
            ->register('dag-remaining-v1', [Progress::class, 'dagRemainingPotential'])
            ->register('dag-weighted-v1', [Progress::class, 'dagWeightedPotential']);
    }
}

/** The in-memory state source for tests and demos: the "world" is a value changed through `apply`. */
final class InMemoryStateSource implements ProgressStateSource
{
    private mixed $cur;
    private int $n = 0;
    /** @var list<Obj> */
    public array $requests = [];

    public function __construct(mixed $initial, private readonly string $sourceId = 'in-memory')
    {
        $this->cur = Progress::snapshot($initial);
    }

    public function id(): string
    {
        return $this->sourceId;
    }

    public function apply(mixed $next): void
    {
        $this->cur = Progress::snapshot($next);
    }

    public function observe(Obj $req): Obj
    {
        $this->requests[] = $req;
        $state = Progress::snapshot($this->cur);
        return Obj::of(['state' => $state, 'state_digest' => Progress::stateDigest($state), 'source' => $this->sourceId,
            'evidence' => Obj::of(['kind' => 'in-memory', 'n' => $this->n++, 'prior' => $req->get('prior_digest'), 'action' => $req->get('action_digest')])]);
    }
}

/**
 * A state source whose observations carry a VERIFIABLE SIGNED attestation: it wraps an observer of the real post-action state and
 * signs the {source, goal, action, prior to state} statement. Pair it with {@see Progress::attestedStateVerifier}.
 */
final class AttestedStateSource implements ProgressStateSource
{
    public readonly string $publicKey;
    /** @var list<Obj> */
    private array $atts = [];

    /** @param callable(Obj):mixed $observeState */
    public function __construct(private readonly mixed $sourceId, private readonly KeyPair $signer, private readonly mixed $observeState, private readonly mixed $alg = null)
    {
        if (!is_string($sourceId) || $sourceId === '') {
            throw new \RuntimeException('AttestedStateSource: id is required');
        }
        if (!is_callable($observeState)) {
            throw new \RuntimeException('AttestedStateSource: observeState must be a function');
        }
        if (Pq::resolveSigAlg($alg) === null) {
            throw new \RuntimeException("AttestedStateSource: unknown signature alg '" . Jsx::str($alg) . "'");
        }
        $this->publicKey = $signer->public;
    }

    public function id(): string
    {
        return $this->sourceId;
    }

    /** @return list<Obj> the signed attestations emitted so far */
    public function attestations(): array
    {
        return $this->atts;
    }

    public function observe(Obj $req): Obj
    {
        $state = Progress::snapshot(($this->observeState)($req));
        $digest = Progress::stateDigest($state);
        $stmt = Obj::of(['source' => $this->sourceId, 'goal_commitment' => $req->get('goal_commitment'), 'action_digest' => $req->get('action_digest'),
            'prior_digest' => $req->get('prior_digest'), 'state_digest' => $digest]);
        $fields = Pq::signSuiteArtifact($this->alg, $this->signer, null, Progress::attestationMessage($stmt, $this->alg, null));
        $att = Jsx::spread($stmt);
        foreach ($fields as $k => $v) {
            $att->set($k, $v);
        }
        $this->atts[] = $att;
        return Obj::of(['state' => $state, 'state_digest' => $digest, 'source' => $this->sourceId, 'evidence' => $att]);
    }
}

/**
 * Proof of progress toward a committed goal: a goal (objective, potential id, embedder, metric, epsilon, exploration budget) is hashed
 * into a commitment; each step is a hash-chained body binding goal, action digest, before and after state digests, sequence and previous
 * step; the verifier recomputes the integer potential and the mode (progress, or exploration charged to a budget). Steps may be signed by
 * the holder; post-states may carry a source's signed attestation; the trajectory head may be anchored in the transparency ledger. Hashes
 * are the STRICT canonical hash. Values are the parsed-JSON model.
 */
final class Progress
{
    public const VERSION = 2;
    public const SIG_DOMAIN = 'atlas-pca/progress-step/v2';
    public const TRAJECTORY_ANCHOR_DOMAIN = 'atlas-pca/trajectory-anchor/v1';
    public const STATE_ATTESTATION_DOMAIN = "atlas-pca/progress-state-attestation/v1\0";
    private const GENESIS = 'genesis';

    // ---- helpers ------------------------------------------------------------------------------------------------------------

    private static function isObj(mixed $x): bool
    {
        return $x instanceof Obj;
    }

    private static function isStr(mixed $x): bool
    {
        return is_string($x);
    }

    private static function assertInt(mixed $n, string $what): void
    {
        if (!Ha::safeInt($n)) {
            throw new \TypeError("$what: safe integer required");
        }
    }

    /** The number as an int when it is a safe integer (the potentials are exact), else as given. */
    private static function intOf(mixed $n): mixed
    {
        return Ha::safeInt($n) ? (int)Js::num($n) : $n;
    }

    /** A deep, canonical, detached copy of a state or objective. */
    public static function snapshot(mixed $v): mixed
    {
        return Json::parseLax(Json::canonicalizeNative($v));
    }

    /** The identity of a value in a JS Set (SameValueZero): "1" and 1 are different, objects are only equal to themselves. */
    private static function setKey(mixed $v): string
    {
        if (is_string($v)) {
            return 's' . $v;
        }
        $f = Js::num($v);
        if ($f !== null) {
            return is_nan($f) ? 'nNaN' : ($f == 0.0 ? 'n0' : 'n' . sprintf('%.17g', $f));
        }
        if (is_bool($v)) {
            return $v ? 'b1' : 'b0';
        }
        if ($v === null) {
            return 'null';
        }
        if ($v instanceof Undef) {
            return 'undef';
        }
        return 'o' . (is_object($v) ? spl_object_id($v) : spl_object_id(new \stdClass()));
    }

    // ---- potentials ---------------------------------------------------------------------------------------------------------

    /** L1 distance in a committed feature space: objective `{target: int[]}`, state `{x: int[]}`. */
    public static function l1FeaturePotential(mixed $objective, mixed $state): int|float
    {
        $t = Jsx::get($objective, 'target');
        $x = Jsx::get($state, 'x');
        if (!is_array($t) || !array_is_list($t) || !is_array($x) || !array_is_list($x) || count($t) !== count($x)) {
            throw new \TypeError('l1-feature-v1: bad shape');
        }
        $d = 0.0;
        foreach ($t as $i => $ti) {
            self::assertInt($ti, 'target');
            self::assertInt($x[$i], 'x');
            $d += abs((float)Js::num($ti) - (float)Js::num($x[$i]));
            self::assertInt($d, 'distance');
        }
        return (int)$d;
    }

    /** Task-set remaining work: objective `{tasks: [{id, cost}]}`, state `{done: string[]}`. */
    public static function dagRemainingPotential(mixed $objective, mixed $state): int|float
    {
        $tasks = Jsx::get($objective, 'tasks');
        $done = Jsx::get($state, 'done');
        if (!is_array($tasks) || !array_is_list($tasks) || !is_array($done) || !array_is_list($done)) {
            throw new \TypeError('dag-remaining-v1: bad shape');
        }
        $ids = [];
        foreach ($tasks as $t) {
            $ids[self::setKey(Jsx::rd($t, 'id'))] = true;
        }
        if (count($ids) !== count($tasks)) {
            throw new \TypeError('dag-remaining-v1: duplicate task id');
        }
        $doneSet = [];
        foreach ($done as $d) {
            $doneSet[self::setKey($d)] = true;
        }
        foreach ($done as $d) {
            if (!isset($ids[self::setKey($d)])) {
                throw new \TypeError('dag-remaining-v1: unknown task ' . Jsx::str($d));
            }
        }
        $rem = 0.0;
        foreach ($tasks as $t) {
            $c = Jsx::get($t, 'cost');
            self::assertInt($c, 'cost');
            if (Js::num($c) < 0) {
                throw new \TypeError('negative cost');
            }
            if (!isset($doneSet[self::setKey(Jsx::get($t, 'id'))])) {
                $rem += (float)Js::num($c);
            }
            self::assertInt($rem, 'remaining');
        }
        return (int)$rem;
    }

    /**
     * Weighted-DAG remaining cost with dependency integrity: objective `{tasks: [{id, cost, deps?}]}` (ids unique, deps known, graph
     * acyclic), state `{done}` (unique, dependency-closed). The value is the cost of the tasks not done.
     */
    public static function dagWeightedPotential(mixed $objective, mixed $state): int|float
    {
        $tasks = Jsx::get($objective, 'tasks');
        $done = Jsx::get($state, 'done');
        if (!is_array($tasks) || !array_is_list($tasks) || !is_array($done) || !array_is_list($done)) {
            throw new \TypeError('dag-weighted-v1: bad shape');
        }
        $byId = [];
        foreach ($tasks as $t) {
            $id = Jsx::get($t, 'id');
            if (!self::isObj($t) || !is_string($id) || $id === '') {
                throw new \TypeError('dag-weighted-v1: bad task');
            }
            if (isset($byId['k' . $id])) {
                throw new \TypeError('dag-weighted-v1: duplicate task id');
            }
            $c = $t->get('cost');
            self::assertInt($c, 'cost');
            if (Js::num($c) < 0) {
                throw new \TypeError('negative cost');
            }
            $deps = Jsx::get($t, 'deps');
            $deps = $deps === null || $deps instanceof Undef ? [] : $deps;
            if (!is_array($deps) || !array_is_list($deps) || !Js::isStrList($deps)) {
                throw new \TypeError('dag-weighted-v1: bad deps');
            }
            $byId['k' . $id] = ['id' => $id, 'cost' => (float)Js::num($c), 'deps' => $deps];
        }
        $indeg = [];
        $rev = [];
        foreach ($byId as $k => $t) {
            $uniq = array_values(array_unique($t['deps']));
            $indeg[$k] = count($uniq);
            foreach ($uniq as $d) {
                if ($d === $t['id'] || !isset($byId['k' . $d])) {
                    throw new \TypeError("dag-weighted-v1: bad dependency $d");
                }
                $rev['k' . $d][] = $k;
            }
        }
        $q = array_keys(array_filter($indeg, static fn(int $n): bool => $n === 0));
        $seen = 0;
        while ($q !== []) {
            $id = array_pop($q);
            $seen++;
            foreach ($rev[$id] ?? [] as $n) {
                $indeg[$n]--;
                if ($indeg[$n] === 0) {
                    $q[] = $n;
                }
            }
        }
        if ($seen !== count($byId)) {
            throw new \TypeError('dag-weighted-v1: cycle');
        }
        $doneSet = [];
        foreach ($done as $d) {
            if (!is_string($d) || !isset($byId['k' . $d])) {
                throw new \TypeError('dag-weighted-v1: unknown task ' . Jsx::str($d));
            }
            if (isset($doneSet[$d])) {
                throw new \TypeError('dag-weighted-v1: duplicate done');
            }
            $doneSet[$d] = true;
        }
        foreach (array_keys($doneSet) as $d) {
            foreach ($byId['k' . $d]['deps'] as $dep) {
                if (!isset($doneSet[$dep])) {
                    throw new \TypeError("dag-weighted-v1: $d done before dependency $dep");
                }
            }
        }
        $rem = 0.0;
        foreach ($byId as $t) {
            if (!isset($doneSet[$t['id']])) {
                $rem += $t['cost'];
            }
            self::assertInt($rem, 'remaining');
        }
        return (int)$rem;
    }

    /** The frozen registry of the built-ins, used when none is supplied. */
    public static function defaultPotentials(): PotentialRegistry
    {
        static $r = null;
        return $r ??= PotentialRegistry::defaults()->freeze();
    }

    /** @param mixed $r a {@see PotentialRegistry}, a list of `[id, spec]` record entries, or null for the defaults */
    public static function registryOf(mixed $r): PotentialRegistry
    {
        if ($r === null) {
            return self::defaultPotentials();
        }
        return $r instanceof PotentialRegistry ? $r : PotentialRegistry::from($r);
    }

    // ---- goal commitment ----------------------------------------------------------------------------------------------------

    private static function validateGoal(mixed $goal): void
    {
        if (!self::isObj($goal)) {
            throw new \TypeError('goal must be an object');
        }
        $eps = Jsx::get($goal, 'epsilon');
        $bud = Jsx::get($goal, 'explorationBudget');
        self::assertInt($eps, 'epsilon');
        self::assertInt($bud, 'explorationBudget');
        if (Js::num($eps) < 1) {
            throw new \RangeException('epsilon must be >= 1');
        }
        if (Js::num($bud) < 0) {
            throw new \RangeException('explorationBudget must be >= 0');
        }
        $p = Jsx::get($goal, 'potential');
        if (!is_string($p) || $p === '') {
            throw new \TypeError('potential id required');
        }
        if (!is_string(Jsx::get($goal, 'metric'))) {
            throw new \TypeError('metric must be a string');
        }
        $e = Jsx::get($goal, 'embedder');
        if (!($e instanceof Undef) && !is_string($e)) {
            throw new \TypeError('embedder must be a string');
        }
    }

    /** The commitment hash of a goal: binds objective, potential id, embedder, metric, epsilon and budget. */
    public static function goalDigest(mixed $goal): string
    {
        self::validateGoal($goal);
        $e = Jsx::get($goal, 'embedder');
        return Pca::hashCanonical(Obj::of(['t' => 'pca-goal', 'v' => new Num((string)self::VERSION), 'objective' => Jsx::get($goal, 'objective'), 'potential' => $goal->get('potential'),
            'embedder' => $e instanceof Undef ? '' : $e, 'metric' => $goal->get('metric'), 'epsilon' => $goal->get('epsilon'),
            'explorationBudget' => $goal->get('explorationBudget')]));
    }

    /** @return array{goal:mixed,commitment:string} the goal as a detached canonical snapshot and its commitment */
    public static function commitGoal(mixed $goal): array
    {
        $c = self::goalDigest($goal);
        return ['goal' => self::snapshot($goal), 'commitment' => $c];
    }

    /** A goal is bound iff it hashes to the commitment the grant carries. Never throws. */
    public static function verifyGoalCommitment(mixed $goal, mixed $commitment): bool
    {
        try {
            return self::goalDigest($goal) === $commitment;
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- steps --------------------------------------------------------------------------------------------------------------

    public static function bodyDigest(Obj $body): string
    {
        $o = Obj::of(['t' => 'pca-progress-step', 'v' => new Num((string)self::VERSION)]);
        foreach ($body->keys() as $k) {
            $o->set($k, $body->get($k));
        }
        return Pca::hashCanonical($o);
    }

    public static function stateDigest(mixed $state): string
    {
        return Pca::hashCanonical(Obj::of(['t' => 'pca-state', 'state' => $state]));
    }

    /** The head to publish or anchor: the digest of the last step ('genesis' when empty). */
    public static function trajectoryHead(mixed $steps): mixed
    {
        return is_array($steps) && $steps !== [] ? Jsx::rd($steps[count($steps) - 1], 'digest') : self::GENESIS;
    }

    public static function progressStepDigest(mixed $step): mixed
    {
        $d = Jsx::rd($step, 'digest');
        return $d instanceof Undef ? null : $d; // undefined is null on the JSON wire
    }

    // ---- anchoring ----------------------------------------------------------------------------------------------------------

    /** The salted commitment of a trajectory head, the opaque leaf appended to the transparency ledger. */
    public static function trajectoryAnchorCommit(mixed $salt, mixed $head): string
    {
        if (!is_string($salt) || $salt === '' || !is_string($head) || $head === '') {
            throw new \TypeError('trajectoryAnchorCommit: salt and head must be non-empty strings');
        }
        return Pca::hashCanonical(Obj::of(['t' => self::TRAJECTORY_ANCHOR_DOMAIN, 'salt' => $salt, 'head' => $head]));
    }

    /** True iff `salt` and `head` reproduce the anchored commit. Never throws. */
    public static function verifyTrajectoryAnchor(mixed $commit, mixed $salt, mixed $head): bool
    {
        try {
            return self::trajectoryAnchorCommit($salt, $head) === $commit;
        } catch (\Throwable) {
            return false;
        }
    }

    /** Anchor the trajectory head into `$ledger` as a salted commitment (the salt defaults to 16 random bytes). @return array<string,mixed> */
    public static function anchorTrajectoryHead(TransparencyLedger $ledger, mixed $steps, ?string $salt = null): array
    {
        $head = self::trajectoryHead($steps);
        $salt ??= Pca::b64u(random_bytes(16));
        $commit = self::trajectoryAnchorCommit($salt, $head);
        $r = $ledger->appendCommitment($commit);
        return ['head' => $head, 'salt' => $salt, 'commit' => $commit, 'index' => $r['index'], 'ledgerHead' => $ledger->head()];
    }

    // ---- potentials in use, mode and charge -----------------------------------------------------------------------------------

    /** @return array{fn:callable,embedder:string} */
    private static function resolve(mixed $goal, PotentialRegistry $reg): array
    {
        $spec = $reg->get(Jsx::get($goal, 'potential'));
        if ($spec === null) {
            throw new ProgressError('unknown-potential', 'unknown potential ' . Jsx::str(Jsx::get($goal, 'potential')));
        }
        $e = Jsx::get($goal, 'embedder');
        if ($spec['embedder'] !== ($e instanceof Undef || $e === null ? '' : $e)) {
            throw new ProgressError('embedder-mismatch', 'embedder mismatch');
        }
        return $spec;
    }

    public static function potentialIn(mixed $goal, PotentialRegistry $reg, mixed $state): int|float
    {
        $spec = self::resolve($goal, $reg);
        try {
            $p = ($spec['fn'])(Jsx::get($goal, 'objective'), $state);
            self::assertInt($p, 'potential');
        } catch (\Throwable $e) {
            throw new ProgressError('bad-potential', $e->getMessage());
        }
        if (Js::num($p) < 0) {
            throw new ProgressError('bad-potential', 'potential must be >= 0');
        }
        return self::intOf($p);
    }

    private static function denialOf(\Throwable $e): string
    {
        return $e instanceof ProgressError ? $e->denial : 'bad-potential';
    }

    /** @return array{mode:string,charge:int|float} progress when after <= before - epsilon (or the goal is reached), else exploration charged the shortfall */
    public static function classifyIn(int|float $pb, int|float $pa, mixed $epsilon): array
    {
        $required = $pb - (float)Js::num($epsilon);
        if ($pa <= $required || ($pa == 0 && $pb > 0)) {
            return ['mode' => 'progress', 'charge' => 0];
        }
        $charge = $pa - $required;
        try {
            self::assertInt($charge, 'charge');
        } catch (\Throwable $e) {
            throw new ProgressError('bad-potential', $e->getMessage());
        }
        return ['mode' => 'exploration', 'charge' => self::intOf($charge)];
    }

    /** Negative authority: only `true` allows; a throw or anything else denies. */
    public static function guardAllows(callable $g, Obj $t): bool
    {
        try {
            return $g($t) === true;
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- state attestations -------------------------------------------------------------------------------------------------

    /** The suite-bound body of a state attestation: `alg` and `pq_pk` enter it for the post-quantum suites. */
    public static function attestationMessage(mixed $a, mixed $alg, mixed $pqPk): string
    {
        $body = Obj::of(['source' => Jsx::get($a, 'source'), 'goal_commitment' => Jsx::get($a, 'goal_commitment'), 'action_digest' => Jsx::get($a, 'action_digest'),
            'prior_digest' => Jsx::get($a, 'prior_digest'), 'state_digest' => Jsx::get($a, 'state_digest')]);
        $suite = Pq::resolveSigAlg($alg);
        if ($suite !== null && $suite['alg'] !== 'ed25519') {
            $body->set('alg', $suite['alg']);
            $body->set('pq_pk', $pqPk ?? Jsx::$U);
        }
        return self::STATE_ATTESTATION_DOMAIN . Json::canonicalizeNative($body);
    }

    /**
     * Verify a state attestation's signature under a TRUSTED source key, bound to its exact statement; `$pin` is `{pqPins?}`
     * (a post-quantum attestation needs its key pinned; there is no unbound-key opt-out). Never throws.
     */
    public static function verifyStateAttestation(mixed $att, mixed $trustedPublicKey, mixed $pin = null): bool
    {
        try {
            if (!self::isObj($att) || !is_string(Jsx::get($att, 'sig')) || !is_string(Jsx::get($att, 'source'))) {
                return false;
            }
            if (!is_string($trustedPublicKey) || $trustedPublicKey === '') {
                return false;
            }
            $alg = Jsx::get($att, 'alg');
            if ($alg === null) { // an explicit null is no known suite; only an absent `alg` is ed25519
                return false;
            }
            $alg = $alg instanceof Undef ? null : $alg;
            if (Pq::resolveSigAlg($alg) === null) {
                return false;
            }
            $pk = Jsx::get($att, 'pq_pk');
            $pk = $pk instanceof Undef ? null : $pk;
            $msg = self::attestationMessage($att, $alg, $pk);
            $pqSig = Jsx::get($att, 'pq_sig');
            $s = ['sig' => $att->get('sig'), 'pq_sig' => $pqSig instanceof Undef ? null : $pqSig];
            $suite = Pq::resolveSigAlg($alg);
            if ($suite['alg'] === 'ed25519') {
                return Pca::verifyWithSuite('ed25519', ['edPub' => $trustedPublicKey], $msg, $s);
            }
            $pins = Jsx::get($pin, 'pqPins');
            $key = Pca::resolvePqVerifyKey($trustedPublicKey, $pk, ['pqPins' => $pins instanceof Undef ? null : $pins]);
            return $key !== null && Pca::verifyWithSuite($suite['alg'], ['edPub' => $trustedPublicKey, 'pq' => $key], $msg, $s);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * The verifier hook for attested state: per step it needs a trusted key for `step.state_source`, an attestation of the same
     * transition from that source, the step's `evidence_digest` to commit to exactly that attestation, and a valid signature.
     * @param mixed $opts `{trustedKeys, pqPins?, attestations}` @return \Closure(mixed):bool
     */
    public static function attestedStateVerifier(mixed $opts): \Closure
    {
        $byKey = [];
        foreach (Jsx::iter(Jsx::get($opts, 'attestations') instanceof Undef || Jsx::get($opts, 'attestations') === null ? [] : Jsx::get($opts, 'attestations')) as $att) {
            if (self::isObj($att) && is_string($att->get('action_digest')) && is_string($att->get('prior_digest')) && is_string($att->get('state_digest'))) {
                $byKey[$att->get('action_digest') . "\0" . $att->get('prior_digest') . "\0" . $att->get('state_digest')] = $att;
            }
        }
        return static function (mixed $step) use ($opts, $byKey): bool {
            try {
                $tk = Jsx::get($opts, 'trustedKeys');
                $ss = Jsx::get($step, 'state_source');
                $pub = is_string($ss) ? Jsx::get($tk, $ss) : Jsx::$U;
                if (!is_string($pub) || $pub === '') {
                    return false;
                }
                $a = Jsx::get($step, 'action_digest');
                $b = Jsx::get($step, 'before_digest');
                $c = Jsx::get($step, 'after_digest');
                $att = is_string($a) && is_string($b) && is_string($c) ? ($byKey[$a . "\0" . $b . "\0" . $c] ?? null) : null;
                if ($att === null || $att->get('source') !== Jsx::get($step, 'state_source')) {
                    return false;
                }
                if (Pca::hashCanonical(Obj::of(['t' => 'pca-evidence', 'e' => $att])) !== Jsx::get($step, 'evidence_digest')) {
                    return false;
                }
                return self::verifyStateAttestation($att, $pub, $opts);
            } catch (\Throwable) {
                return false;
            }
        };
    }

    // ---- verifier side -----------------------------------------------------------------------------------------------------------

    /** @return array{ok:false,reason:string} */
    private static function fail(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    private static function isStep(mixed $s): bool
    {
        if (!self::isObj($s)) {
            return false;
        }
        foreach (['goal_commitment', 'before_digest', 'after_digest', 'action_digest', 'state_source', 'evidence_digest', 'prev', 'digest'] as $k) {
            if (!is_string($s->get($k))) {
                return false;
            }
        }
        foreach (['seq', 'potential_before', 'potential_after', 'charge'] as $k) {
            if (!Ha::safeInt($s->get($k))) {
                return false;
            }
        }
        return Js::num($s->get('seq')) >= 0 && in_array($s->get('mode'), ['progress', 'exploration'], true) && $s->has('before') && $s->has('after');
    }

    private static function sameNum(mixed $a, mixed $b): bool
    {
        $x = Js::num($a);
        $y = Js::num($b);
        return $x !== null && $y !== null && $x == $y;
    }

    /** A verifier option: the member's value, or `Jsx::$U` when absent. */
    private static function opt(mixed $opts, string $k): mixed
    {
        return $opts instanceof Obj && $opts->has($k) ? $opts->get($k) : (Jsx::init() ?? Jsx::$U);
    }

    /**
     * The stateless re-check of one step against the committed goal: pure and deterministic, never throws. Nothing the step claims is
     * trusted. The checks run in this order and the first failure wins: goal commitment, shape, goal, `expectedSeq`, `expectedPrev`,
     * `expectedActionDigest`, `expectedBeforeDigest`, `expectedAfterDigest`, the body digest, the state digests, the potentials, their values,
     * the mode, the charge, `trustedStateSources`, attested state (required unless `requireAttestedState` is false), the guard, the
     * attestation hook. @param mixed $opts an Obj of options (`registry`, `guard` and `attestation` hold a registry, a callable) @return array<string,mixed>
     */
    public static function verifyProgressStep(mixed $goal, mixed $commitment, mixed $step, mixed $opts = null): array
    {
        try {
            if (!self::verifyGoalCommitment($goal, $commitment)) {
                return self::fail('goal-mismatch');
            }
            if (!self::isStep($step)) {
                return self::fail('malformed');
            }
            if ($step->get('goal_commitment') !== $commitment) {
                return self::fail('goal-mismatch');
            }
            $x = self::opt($opts, 'expectedSeq');
            if (!($x instanceof Undef) && !self::sameNum($step->get('seq'), $x)) {
                return self::fail('seq-mismatch');
            }
            $x = self::opt($opts, 'expectedPrev');
            if (!($x instanceof Undef) && $step->get('prev') !== $x) {
                return self::fail('chain-break');
            }
            $x = self::opt($opts, 'expectedActionDigest');
            if (!($x instanceof Undef) && $step->get('action_digest') !== $x) {
                return self::fail('action-mismatch');
            }
            $x = self::opt($opts, 'expectedBeforeDigest');
            if (!($x instanceof Undef) && $step->get('before_digest') !== $x) {
                return self::fail('state-mismatch');
            }
            $x = self::opt($opts, 'expectedAfterDigest');
            if (!($x instanceof Undef) && $step->get('after_digest') !== $x) {
                return self::fail('state-mismatch');
            }
            if (self::bodyDigest($step->without('digest')) !== $step->get('digest')) {
                return self::fail('digest-mismatch');
            }
            if (self::stateDigest($step->get('before')) !== $step->get('before_digest') || self::stateDigest($step->get('after')) !== $step->get('after_digest')) {
                return self::fail('state-digest-mismatch');
            }
            $reg = self::registryOf(($r = self::opt($opts, 'registry')) instanceof Undef ? null : $r);
            try {
                $pb = self::potentialIn($goal, $reg, $step->get('before'));
                $pa = self::potentialIn($goal, $reg, $step->get('after'));
                $cls = self::classifyIn($pb, $pa, $goal->get('epsilon'));
            } catch (\Throwable $e) {
                return self::fail(self::denialOf($e));
            }
            if (!self::sameNum($pb, $step->get('potential_before')) || !self::sameNum($pa, $step->get('potential_after'))) {
                return self::fail('potential-mismatch');
            }
            if ($step->get('mode') !== $cls['mode']) {
                return self::fail('mode-mismatch');
            }
            if (!self::sameNum($cls['charge'], $step->get('charge'))) {
                return self::fail('charge-mismatch');
            }
            $trusted = self::opt($opts, 'trustedStateSources');
            if (Jsx::truthy($trusted) && !in_array($step->get('state_source'), Jsx::iter($trusted), true)) {
                return self::fail('untrusted-state-source');
            }
            if (self::opt($opts, 'requireAttestedState') !== false && $step->get('state_source') === '') {
                return self::fail('untrusted-state-source');
            }
            $g = self::opt($opts, 'guard');
            if (is_callable($g) && !self::guardAllows($g, Obj::of(['seq' => $step->get('seq'), 'before' => $step->get('before'), 'after' => $step->get('after'),
                    'action_digest' => $step->get('action_digest')]))) {
                return self::fail('prohibited');
            }
            $att = self::opt($opts, 'attestation');
            if (is_callable($att)) {
                try {
                    $ok = $att($step) === true;
                } catch (\Throwable) {
                    $ok = false;
                }
                if (!$ok) {
                    return self::fail('attestation-failed');
                }
            }
            return ['ok' => true, 'charge' => $cls['charge']];
        } catch (\Throwable) {
            return self::fail('malformed');
        }
    }

    /**
     * Verify a whole trajectory: goal binding, every step re-checked and hash-chained, states contiguous, the start state when given
     * (`initialDigest` wins over `initial`), per-step action binding when given, and the strict invariant sum(charge) <= budget.
     * @return array<string,mixed> `{ok: true, spent, remaining, reached, finalPotential (-1 when empty), steps, head}` or `{ok: false, reason, at}`
     */
    public static function verifyTrajectory(mixed $goal, mixed $commitment, mixed $steps, mixed $opts = null): array
    {
        if (!self::verifyGoalCommitment($goal, $commitment)) {
            return ['ok' => false, 'reason' => 'goal-mismatch', 'at' => -1];
        }
        if (!is_array($steps) || !array_is_list($steps)) {
            return ['ok' => false, 'reason' => 'malformed', 'at' => -1];
        }
        $eds = self::opt($opts, 'expectedActionDigests');
        $hasEds = Jsx::truthy($eds);
        if ($hasEds && count(Jsx::iter($eds)) !== count($steps)) {
            return ['ok' => false, 'reason' => 'action-mismatch', 'at' => min(count(Jsx::iter($eds)), count($steps))];
        }
        $initial = self::opt($opts, 'initial');
        $initialDigest = self::opt($opts, 'initialDigest');
        try {
            $anchor = $initialDigest !== null && !($initialDigest instanceof Undef) ? $initialDigest : ($initial instanceof Undef ? null : self::stateDigest($initial));
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'malformed', 'at' => -1];
        }
        $prev = self::GENESIS;
        $spent = 0;
        $final = -1;
        if ($steps === [] && !($initial instanceof Undef)) {
            try {
                $r = self::opt($opts, 'registry');
                $final = self::potentialIn($goal, self::registryOf($r instanceof Undef ? null : $r), $initial);
            } catch (\Throwable $e) {
                return ['ok' => false, 'reason' => self::denialOf($e), 'at' => -1];
            }
        }
        $budget = Js::num($goal->get('explorationBudget'));
        foreach ($steps as $i => $s) {
            $o = $opts instanceof Obj ? Jsx::spread($opts) : new Obj();
            $o->set('expectedSeq', $i);
            $o->set('expectedPrev', $prev);
            if ($hasEds) {
                $o->set('expectedActionDigest', array_values(Jsx::iter($eds))[$i] ?? Jsx::$U);
            } else {
                $o = $o->without('expectedActionDigest');
            }
            $r = self::verifyProgressStep($goal, $commitment, $s, $o);
            if (!$r['ok']) {
                return ['ok' => false, 'reason' => $r['reason'], 'at' => $i];
            }
            if ($anchor !== null && $s->get('before_digest') !== $anchor) {
                return ['ok' => false, 'reason' => 'discontinuous-state', 'at' => $i];
            }
            $spent += $r['charge'];
            if (!Ha::safeInt($spent) || $spent > $budget) {
                return ['ok' => false, 'reason' => 'budget-exceeded', 'at' => $i];
            }
            $anchor = $s->get('after_digest');
            $prev = $s->get('digest');
            $final = self::intOf($s->get('potential_after'));
        }
        return ['ok' => true, 'spent' => $spent, 'remaining' => $budget - $spent, 'reached' => $final === 0, 'finalPotential' => $final,
            'steps' => count($steps), 'head' => $prev];
    }

    // ---- signed steps -----------------------------------------------------------------------------------------------------------

    private static function sigMessage(Obj $step, mixed $holder): string
    {
        return Json::canonicalizeNative(Obj::of(['d' => self::SIG_DOMAIN, 'b' => Obj::of(['holder' => $holder, 'goal_commitment' => $step->get('goal_commitment'),
            'action_digest' => $step->get('action_digest'), 'before_digest' => $step->get('before_digest'), 'after_digest' => $step->get('after_digest'),
            'seq' => $step->get('seq'), 'prev' => $step->get('prev'), 'step_digest' => $step->get('digest')])]));
    }

    /** Sign a step: Ed25519 over the domain-separated binding. `$holderPublicKey` is committed in the message as given. */
    public static function signProgressStep(Obj $step, KeyPair $secret, string $holderPublicKey): Obj
    {
        return Obj::of(['step' => $step, 'holder' => $holderPublicKey, 'sig' => Pca::b64u($secret->sign(self::sigMessage($step, $holderPublicKey)))]);
    }

    private static function verifyB64u(mixed $pub, string $msg, mixed $sig): bool
    {
        try {
            $p = is_string($pub) ? Pca::unb64u($pub) : null;
            $s = is_string($sig) ? Pca::unb64u($sig) : null;
            return $p !== null && $s !== null && strlen($p) === 32 && strlen($s) === 64 && sodium_crypto_sign_verify_detached($s, $msg, $p);
        } catch (\Throwable) {
            return false;
        }
    }

    private static function signedShape(mixed $sp): bool
    {
        return self::isObj($sp) && is_string($sp->get('holder')) && is_string($sp->get('sig')) && self::isStep($sp->get('step'));
    }

    /**
     * Verify a signed step offline: shape, the expected holder, the expected action, the goal, the signature, then the full step re-check.
     * `$opts` carries the required `expectedActionDigest` and `expectedHolder`. @return array<string,mixed>
     */
    public static function verifySignedProgressStep(mixed $goal, mixed $commitment, mixed $signed, mixed $opts): array
    {
        try {
            if (!self::signedShape($signed)) {
                return self::fail('malformed');
            }
            if ($signed->get('holder') !== self::opt($opts, 'expectedHolder')) {
                return self::fail('holder-mismatch');
            }
            $step = $signed->get('step');
            if ($step->get('action_digest') !== self::opt($opts, 'expectedActionDigest')) {
                return self::fail('action-mismatch');
            }
            if ($step->get('goal_commitment') !== $commitment) {
                return self::fail('goal-mismatch');
            }
            if (!self::verifyB64u($signed->get('holder'), self::sigMessage($step, $signed->get('holder')), $signed->get('sig'))) {
                return self::fail('bad-signature');
            }
            return self::verifyProgressStep($goal, $commitment, $step, $opts);
        } catch (\Throwable) {
            return self::fail('malformed');
        }
    }

    /** Verify the signature of every step, then the whole trajectory. `$opts` carries the required `expectedActionDigests` and `expectedHolder`. @return array<string,mixed> */
    public static function verifySignedTrajectory(mixed $goal, mixed $commitment, mixed $signed, mixed $opts): array
    {
        if (!is_array($signed) || !array_is_list($signed)) {
            return ['ok' => false, 'reason' => 'malformed', 'at' => -1];
        }
        $eds = self::opt($opts, 'expectedActionDigests');
        if (!is_array($eds) || !array_is_list($eds)) {
            throw new \TypeError('expectedActionDigests is required');
        }
        if (count($eds) !== count($signed)) {
            return ['ok' => false, 'reason' => 'action-mismatch', 'at' => min(count($eds), count($signed))];
        }
        foreach ($signed as $i => $sp) {
            try {
                if (!self::signedShape($sp)) {
                    return ['ok' => false, 'reason' => 'malformed', 'at' => $i];
                }
                if ($sp->get('holder') !== self::opt($opts, 'expectedHolder')) {
                    return ['ok' => false, 'reason' => 'holder-mismatch', 'at' => $i];
                }
                if ($sp->get('step')->get('action_digest') !== $eds[$i]) {
                    return ['ok' => false, 'reason' => 'action-mismatch', 'at' => $i];
                }
                if (!self::verifyB64u($sp->get('holder'), self::sigMessage($sp->get('step'), $sp->get('holder')), $sp->get('sig'))) {
                    return ['ok' => false, 'reason' => 'bad-signature', 'at' => $i];
                }
            } catch (\Throwable) {
                return ['ok' => false, 'reason' => 'malformed', 'at' => $i];
            }
        }
        $rest = $opts instanceof Obj ? $opts->without('expectedHolder') : $opts;
        return self::verifyTrajectory($goal, $commitment, array_map(static fn(Obj $s): mixed => $s->get('step'), $signed), $rest);
    }
}

/**
 * The stateful tracker of one trajectory: holds the last state, chain head and exploration spent. A step that would push the spent
 * total over the budget is REFUSED (no proof, no state change): the step-up or denial mechanism.
 */
final class ProgressTracker
{
    private int $seq = 0;
    private mixed $head = 'genesis';
    private int|float $spentTotal = 0;
    private mixed $cur;
    private string $curDigest;
    /** @var list<Obj> */
    private array $log = [];
    private readonly PotentialRegistry $reg;
    public readonly mixed $goal;

    /** @param ?callable(Obj):mixed $guard allows a transition by returning true */
    public function __construct(mixed $goal, public readonly mixed $commitment, mixed $initial, mixed $registry = null, private readonly mixed $guard = null)
    {
        if (!Progress::verifyGoalCommitment($goal, $commitment)) {
            throw new \RuntimeException('goal does not match commitment');
        }
        $this->goal = Progress::snapshot($goal);
        $this->reg = Progress::registryOf($registry);
        $this->cur = Progress::snapshot($initial);
        $this->curDigest = Progress::stateDigest($this->cur);
        Progress::potentialIn($this->goal, $this->reg, $this->cur); // fail fast: unknown id, embedder or a bad initial state
    }

    public function spent(): int|float
    {
        return $this->spentTotal;
    }

    public function remaining(): int|float
    {
        return Js::num($this->goal->get('explorationBudget')) - $this->spentTotal;
    }

    public function state(): mixed
    {
        return $this->cur;
    }

    public function currentStateDigest(): string
    {
        return $this->curDigest;
    }

    public function reached(): bool
    {
        return Progress::potentialIn($this->goal, $this->reg, $this->cur) === 0;
    }

    /** @return list<Obj> */
    public function steps(): array
    {
        return $this->log;
    }

    /** Attempt a step to a self-reported `after`; no state change on denial. @return array<string,mixed> */
    public function step(mixed $after, mixed $actionDigest): array
    {
        return $this->advance($after, $actionDigest, '', '');
    }

    /** Observe the post-action state from a trusted source and step to it; no state change on any denial. @return array<string,mixed> */
    public function stepObserved(ProgressStateSource $source, mixed $actionDigest): array
    {
        try {
            $obs = $source->observe(Obj::of(['action_digest' => $actionDigest, 'goal_commitment' => $this->commitment, 'prior_digest' => $this->curDigest]));
            if (!($obs instanceof Obj) || $obs->get('source') !== $source->id() || $obs->get('state_digest') !== Progress::stateDigest($obs->get('state'))) {
                return ['ok' => false, 'reason' => 'state-source-mismatch', 'stepUp' => false];
            }
            $ev = $obs->get('evidence');
            return $this->advance($obs->get('state'), $actionDigest, $source->id(), Pca::hashCanonical(Obj::of(['t' => 'pca-evidence', 'e' => $ev])));
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'state-source-mismatch', 'stepUp' => false];
        }
    }

    private function advance(mixed $afterIn, mixed $actionDigest, string $stateSource, string $evidenceDigest): array
    {
        if (!is_string($actionDigest) || $actionDigest === '') {
            return ['ok' => false, 'reason' => 'malformed', 'stepUp' => false];
        }
        try {
            $after = Progress::snapshot($afterIn);
            $afterDigest = Progress::stateDigest($after);
            $pb = Progress::potentialIn($this->goal, $this->reg, $this->cur);
            $pa = Progress::potentialIn($this->goal, $this->reg, $after);
            $cls = Progress::classifyIn($pb, $pa, $this->goal->get('epsilon'));
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => $e instanceof ProgressError ? $e->denial : 'bad-potential', 'stepUp' => false];
        }
        if (is_callable($this->guard) && !Progress::guardAllows($this->guard, Obj::of(['seq' => $this->seq, 'before' => $this->cur, 'after' => $after, 'action_digest' => $actionDigest]))) {
            return ['ok' => false, 'reason' => 'prohibited', 'stepUp' => false];
        }
        $next = $this->spentTotal + $cls['charge'];
        if (!Ha::safeInt($next) || $next > Js::num($this->goal->get('explorationBudget'))) {
            return ['ok' => false, 'reason' => 'exploration-exhausted', 'stepUp' => true];
        }
        $body = Obj::of(['goal_commitment' => $this->commitment, 'seq' => $this->seq, 'before' => $this->cur, 'after' => $after, 'before_digest' => $this->curDigest,
            'after_digest' => $afterDigest, 'action_digest' => $actionDigest, 'mode' => $cls['mode'], 'potential_before' => $pb, 'potential_after' => $pa,
            'charge' => $cls['charge'], 'state_source' => $stateSource, 'evidence_digest' => $evidenceDigest, 'prev' => $this->head]);
        $step = Jsx::spread($body);
        $step->set('digest', Progress::bodyDigest($body));
        $this->log[] = $step;
        $this->seq++;
        $this->head = $step->get('digest');
        $this->spentTotal = $next;
        $this->cur = $after;
        $this->curDigest = $afterDigest;
        return ['ok' => true, 'step' => $step, 'spent' => $this->spentTotal, 'remaining' => $this->remaining()];
    }
}
