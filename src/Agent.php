<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Escalation.php';
require_once __DIR__ . '/CaveatLang.php';
require_once __DIR__ . '/Workflow.php';

/**
 * The agent / issuer side of PCA: produce the proofs this package's verifier checks. Same wire as the TypeScript reference
 * (mintGrant, delegate, buildPCActn, signEscalationAnswer, signDischarge, signPassport, signWorkflow, ...), BYTE-exact wherever
 * the algorithm is deterministic (Ed25519, canonical JSON, digests, chain structure); the shared producer vectors
 * (producer-vectors.json: fixed keys, nonces and timestamps) pin it.
 *
 * Inputs may be plain PHP arrays (associative arrays become JSON objects, lists become arrays; int and float become numbers) or
 * the verifier's own {@see Obj} / {@see Num}; every producer returns an {@see Obj}. Signing is Ed25519 (libsodium) and, through
 * OpenSSL >= 3.5 libcrypto over FFI (what the verifier already uses), ML-DSA-65 / 87 and SLH-DSA-SHA2-128f / 256s with their
 * hybrid and nested-hybrid suites ({@see PqKeyPair}). PHP's own openssl_* functions expose none of these key types. Where the runtime lacks
 * FFI or OpenSSL 3.5, and for FN-DSA and LESS, asking for the suite throws {@see UnsupportedSigner} (`unsupported_suite: <alg>`).
 */
final class UnsupportedSigner extends \RuntimeException
{
}

/** An Ed25519 identity. `public` is the base64url key id every artifact names. */
final class KeyPair
{
    public readonly string $public;
    private string $secret;

    public function __construct(private string $seed)
    {
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('an Ed25519 seed is 32 bytes');
        }
        $kp = sodium_crypto_sign_seed_keypair($seed);
        $this->secret = sodium_crypto_sign_secretkey($kp);
        $this->public = Pca::b64u(sodium_crypto_sign_publickey($kp));
    }

    public static function generate(): self
    {
        return new self(random_bytes(32));
    }

    public static function fromSeedB64u(string $seed): self
    {
        $raw = Pca::unb64u($seed, 32);
        if ($raw === null) {
            throw new \InvalidArgumentException('an Ed25519 seed is 32 canonical base64url bytes');
        }
        return new self($raw);
    }

    public function sign(string $msg): string
    {
        return sodium_crypto_sign_detached($msg, $this->secret);
    }

    public function __debugInfo(): array
    {
        return ['public' => $this->public]; // never print the secret
    }
}

/**
 * A post-quantum key pair for the PQ half of a suite, generated through OpenSSL >= 3.5 libcrypto (FFI, see {@see OpensslPq}).
 * `family` is "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f" or "SLH-DSA-SHA2-256s"; `public` is the base64url `pq_pk`.
 */
final class PqKeyPair
{
    public readonly string $public;
    private \FFI\CData $pkey;

    public function __construct(public readonly string $family)
    {
        $g = OpensslPq::generate($family);
        if ($g === null) {
            throw new UnsupportedSigner("unsupported_suite: $family (needs the FFI extension and OpenSSL >= 3.5 libcrypto)");
        }
        [$this->pkey, $pub] = $g;
        $this->public = Pca::b64u($pub);
    }

    public function __destruct()
    {
        OpensslPq::free($this->pkey);
    }

    public function sign(string $msg): string
    {
        return OpensslPq::sign($this->family, $this->pkey, $msg) ?? throw new UnsupportedSigner("unsupported_suite: {$this->family} (signing failed)");
    }
}

/** One signed action: the PCActn, the headers to send and the plan node it was built for. */
final class Action
{
    /** @param array<string,string> $headers */
    public function __construct(public readonly Obj $pcactn, public readonly array $headers, public readonly string $nodeId)
    {
    }
}

final class Sign
{
    public const HEADER = 'PCA-Action';
    public const DEFAULT_TTL_MS = 20 * 60000;
    private const GOAL_DOMAIN = "atlas-pca/goal/v1\0";

    /** The risk policy a grant carries when the issuer sets none of its own. */
    public static function defaultRiskPolicy(): array
    {
        return ['weights' => ['alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05],
            'theta1' => 0.25, 'theta2' => 0.6, 'kappa' => 1, 'lambda' => 0.0005, 'rho' => 0.5, 'bMax' => 1];
    }

    /** Plain PHP value -> the verifier's value model (Obj for associative arrays, Num for numbers). */
    public static function n(mixed $v): mixed
    {
        if (is_int($v)) {
            return new Num((string)$v);
        }
        if (is_float($v)) {
            if (!is_finite($v)) {
                throw new \InvalidArgumentException('non-finite number');
            }
            return new Num(floor($v) === $v && abs($v) < 1e15 ? sprintf('%.0f', $v) : json_encode($v, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map([self::class, 'n'], $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string)$k, self::n($x));
            }
            return $o;
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::n($v->get($k)));
            }
            return $o;
        }
        return $v;
    }

    /** The inverse of {@see n}: Obj to an associative array, Num to int or float (e.g. to hand a parsed vector to {@see mintGrant}). */
    public static function plain(mixed $v): mixed
    {
        if ($v instanceof Num) {
            return $v->isInt() ? $v->int() : $v->float();
        }
        if ($v instanceof Obj) {
            $a = [];
            foreach ($v->keys() as $k) {
                $a[$k] = self::plain($v->get($k));
            }
            return $a === [] ? new Obj() : $a;
        }
        return is_array($v) ? array_map([self::class, 'plain'], $v) : $v;
    }

    private static function obj(mixed $v): Obj
    {
        $n = self::n($v);
        if (!($n instanceof Obj)) {
            throw new \InvalidArgumentException('expected a JSON object');
        }
        return $n;
    }

    /** Strict canonical bytes: throws {@see JsonError} on a value outside the strict profile (the verifiers would refuse it). */
    private static function canon(mixed $v): string
    {
        return Json::canonicalizeStrict($v);
    }

    /** suite => [PQ family, hybrid, nested] for the suites this module can sign (absent: ed25519 alone). */
    private const PQ_SUITES = [
        'ml-dsa-65' => ['ML-DSA-65', false, false], 'hybrid-ed25519-ml-dsa-65' => ['ML-DSA-65', true, false],
        'hybrid-nested-ed25519-ml-dsa-65' => ['ML-DSA-65', true, true], 'ml-dsa-87' => ['ML-DSA-87', false, false],
        'hybrid-ed25519-ml-dsa-87' => ['ML-DSA-87', true, false], 'slh-dsa-sha2-128f' => ['SLH-DSA-SHA2-128f', false, false],
        'hybrid-ed25519-slh-dsa-sha2-128f' => ['SLH-DSA-SHA2-128f', true, false], 'slh-dsa-sha2-256s' => ['SLH-DSA-SHA2-256s', false, false],
        'hybrid-ed25519-slh-dsa-sha2-256s' => ['SLH-DSA-SHA2-256s', true, false],
    ];

    /** @return array{0:string,1:?string} [sig, pq_sig] (base64url) of `$msg` under the suite; fail closed. */
    private static function parts(?string $alg, KeyPair $ed, ?PqKeyPair $pq, string $msg): array
    {
        if ($alg === null || $alg === 'ed25519') {
            return [Pca::b64u($ed->sign($msg)), null];
        }
        if (!isset(self::PQ_SUITES[$alg])) {
            if (in_array($alg, Pca::REGISTERED_SUITES, true)) {
                throw new UnsupportedSigner("unsupported_suite: $alg");
            }
            throw new \InvalidArgumentException("unknown signature alg '$alg'");
        }
        [$family, $hybrid, $nested] = self::PQ_SUITES[$alg];
        if ($pq === null || $pq->family !== $family) {
            throw new \InvalidArgumentException("$alg needs a $family key pair");
        }
        if (!$hybrid) {
            return [Pca::b64u($pq->sign($msg)), null];
        }
        $e = $ed->sign($msg);
        return [Pca::b64u($e), Pca::b64u($pq->sign($nested ? $msg . $e : $msg))];
    }

    /** body + `alg`/`pq_pk` for a non-default suite (both are signed). */
    private static function bind(Obj $b, ?string $alg, ?PqKeyPair $pq): Obj
    {
        $b = $b->without('sig', 'pq_sig', 'alg', 'pq_pk');
        if ($alg !== null && $alg !== 'ed25519') {
            if (!isset(self::PQ_SUITES[$alg])) {
                self::parts($alg, KeyPair::generate(), null, ''); // throws unsupported_suite / unknown alg
            }
            if ($pq === null) {
                throw new \InvalidArgumentException("$alg needs a post-quantum key pair");
            }
            $b->set('alg', $alg);
            $b->set('pq_pk', $pq->public);
        }
        return $b;
    }

    private static function finish(Obj $b, ?string $alg, KeyPair $ed, ?PqKeyPair $pq, string $msg): Obj
    {
        [$sig, $pqSig] = self::parts($alg, $ed, $pq, $msg);
        $b->set('sig', $sig);
        if ($pqSig !== null) {
            $b->set('pq_sig', $pqSig);
        }
        return $b;
    }

    private static function nonce(?string $n): string
    {
        return $n ?? Pca::b64u(random_bytes(16));
    }

    /** body + `sig` (and `alg`/`pq_pk`/`pq_sig` for a non-default suite): the signature covers utf8(domain) || strictCanonical(body). */
    public static function signArtifact(string $domain, mixed $body, KeyPair $ed, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = self::bind(self::obj($body), $alg, $pq);
        return self::finish($b, $alg, $ed, $pq, $domain . self::canon($b));
    }

    private static function signBody(KeyPair $ed, string $domain, mixed $body): string
    {
        return Pca::b64u($ed->sign($domain . self::canon($body)));
    }

    // ---- capability chain -----------------------------------------------------------------------------------------

    /** Salted commitment to the plaintext goal. */
    public static function goalCommit(string $goal, string $salt): string
    {
        return Pca::hashCanonical(self::obj(['d' => self::GOAL_DOMAIN, 'goal' => $goal, 'salt' => $salt]));
    }

    private static function seal(string $issuer, string $holder, array $caveats, ?string $parent, ?string $holderPq, KeyPair $ed, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $body = self::obj(['issuer' => $issuer, 'holder' => $holder, 'caveats' => $caveats, 'parent' => $parent]);
        if ($holderPq !== null) {
            $body->set('holder_pq', $holderPq);
        }
        $digest = Pca::hashCanonical(self::bind($body, $alg, $pq));
        [$sig, $pqSig] = self::parts($alg, $ed, $pq, Pca::CAP_DOMAIN . (Pca::unb64u($digest, 32) ?? ''));
        $cap = self::obj(['id' => $digest, 'issuer' => $issuer, 'holder' => $holder, 'caveats' => $caveats, 'body_digest' => $digest, 'sig' => $sig]);
        if ($parent !== null) {
            $cap->set('parent', $parent);
        }
        if ($holderPq !== null) {
            $cap->set('holder_pq', $holderPq);
        }
        if ($alg !== null && $alg !== 'ed25519') {
            $cap->set('alg', $alg);
            $cap->set('pq_pk', $pq->public);
            if ($pqSig !== null) {
                $cap->set('pq_sig', $pqSig);
            }
        }
        return $cap;
    }

    /** A root capability signed by the principal. `$holderPq` is the holder's PQ public key (b64u), committed as `holder_pq`. */
    public static function mintRoot(KeyPair $principal, string $holder, array $caveats, ?string $holderPq = null, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        return self::seal($principal->public, $holder, self::n($caveats), null, $holderPq === null ? null : Pca::holderPqCommitment($holderPq), $principal, $alg, $pq);
    }

    /**
     * A child capability: caveats = parent.caveats ++ added (append-only, so never wider), signed by the parent's holder.
     * `$toHolder` null keeps the holder (and its `holder_pq`); otherwise it is rebound to a sub-agent.
     */
    public static function delegate(Obj $parent, KeyPair $signer, ?string $toHolder = null, array $added = [], ?string $holderPq = null, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $ph = (string)$parent->get('holder');
        $holder = $toHolder ?? $ph;
        $hp = $holderPq !== null ? Pca::holderPqCommitment($holderPq) : ($holder === $ph ? $parent->get('holder_pq') : null);
        return self::seal($ph, $holder, [...self::n($parent->get('caveats')), ...self::n($added)], Pca::capHash($parent), $hp, $signer, $alg, $pq);
    }

    private static function riskPolicyError(mixed $p): ?string
    {
        $w = is_array($p) ? ($p['weights'] ?? null) : null;
        if (!is_array($w)) {
            return 'risk_policy.weights missing';
        }
        foreach (['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'] as $k) {
            if (!is_numeric($w[$k] ?? null) || $w[$k] < 0) {
                return "risk_policy.weights.$k must be finite and >= 0";
            }
        }
        foreach (['theta1', 'theta2', 'kappa', 'lambda', 'rho', 'bMax'] as $k) {
            if (!is_numeric($p[$k] ?? null)) {
                return "risk_policy.$k must be finite";
            }
        }
        if ($p['theta1'] < 0 || $p['theta2'] < $p['theta1']) {
            return 'risk_policy requires 0 <= theta1 <= theta2';
        }
        if ($p['kappa'] <= 0) {
            return 'risk_policy.kappa must be > 0';
        }
        if ($p['lambda'] < 0 || $p['rho'] < 0 || $p['bMax'] < 0) {
            return 'risk_policy lambda/rho/bMax must be >= 0';
        }
        return null;
    }

    /**
     * Root Intent Grant: a root capability whose first caveat is the policy envelope (`predicates`, `caveats`, `agent_binding`,
     * `risk_policy`, optional `units`/`tighten`/`actions`/...). Only the salted hash of `$goal` goes in the grant. Envelope as
     * a plain array (so the risk-policy check can read numbers). Shortcut: the optional envelope members are signed as given; the
     * verifier refuses a malformed one.
     * @return array{grant:Obj, goal_commit:string, goal_salt:string}
     */
    public static function mintGrant(KeyPair $principal, string $holder, array $envelope, string $goal, ?string $salt = null, ?string $holderPq = null, ?string $alg = null, ?PqKeyPair $pq = null): array
    {
        if ($goal === '') {
            throw new \InvalidArgumentException('mintGrant: goal required');
        }
        if (!isset($envelope['predicates'], $envelope['caveats'])) {
            throw new \InvalidArgumentException('mintGrant: envelope.predicates and envelope.caveats required');
        }
        $bad = self::riskPolicyError($envelope['risk_policy'] ?? null);
        if ($bad !== null) {
            throw new \InvalidArgumentException("mintGrant: $bad");
        }
        if (array_key_exists('model_polarity', $envelope) && $envelope['model_polarity'] !== 'legacy') {
            throw new \InvalidArgumentException("mintGrant: model_polarity must be 'legacy' when present");
        }
        $salt ??= Pca::b64u(random_bytes(16));
        $commit = self::goalCommit($goal, $salt);
        $env = ['type' => 'envelope', 'goal_commit' => $commit, 'predicates' => $envelope['predicates'], 'caveats' => $envelope['caveats'],
            'agent_binding' => $envelope['agent_binding'] ?? new Obj(), 'risk_policy' => $envelope['risk_policy']];
        foreach (['objective_risk', 'progress', 'units', 'tighten', 'model_polarity', 'template_ref', 'actions'] as $k) {
            if (isset($envelope[$k])) {
                $env[$k] = $envelope[$k];
            }
        }
        return ['grant' => self::mintRoot($principal, $holder, [$env], $holderPq, $alg, $pq), 'goal_commit' => $commit, 'goal_salt' => $salt];
    }

    // ---- plan + PCActn --------------------------------------------------------------------------------------------

    private static function sha(string $b): string
    {
        return hash('sha256', $b, true);
    }

    private static function condDigest(Obj $n): string
    {
        return Pca::b64u(self::sha(self::canon(self::obj(['pre' => $n->get('pre'), 'post' => $n->get('post')]))));
    }

    private static function leaf(Obj $n): string
    {
        $leaf = Pca::planLeaf($n->get('id'), $n, self::condDigest($n));
        return self::sha("\x00" . self::canon($leaf));
    }

    private static function split(int $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $k;
    }

    /** @param string[] $hs */
    private static function build(array $hs): string
    {
        if (count($hs) === 1) {
            return $hs[0];
        }
        $k = self::split(count($hs));
        return self::sha("\x01" . self::build(array_slice($hs, 0, $k)) . self::build(array_slice($hs, $k)));
    }

    /** @param string[] $hs */
    private static function prove(array $hs, int $idx, array &$out): void
    {
        if (count($hs) === 1) {
            return;
        }
        $k = self::split(count($hs));
        if ($idx < $k) {
            self::prove(array_slice($hs, 0, $k), $idx, $out);
            $out[] = self::obj(['side' => 'R', 'hash' => Pca::b64u(self::build(array_slice($hs, $k)))]);
        } else {
            self::prove(array_slice($hs, $k), $idx - $k, $out);
            $out[] = self::obj(['side' => 'L', 'hash' => Pca::b64u(self::build(array_slice($hs, 0, $k)))]);
        }
    }

    /** @return array{0:Obj[],1:string[]} the normalised nodes and their leaf hashes */
    private static function planHashes(array $nodes): array
    {
        if ($nodes === []) {
            throw new \InvalidArgumentException('commitPlan: empty plan');
        }
        $ns = [];
        $seen = [];
        foreach ($nodes as $raw) {
            $n = self::obj($raw);
            $id = (string)$n->get('id');
            if (isset($seen[$id])) {
                throw new \InvalidArgumentException("commitPlan: duplicate node id $id");
            }
            $seen[$id] = true;
            $ns[] = $n;
        }
        return [$ns, array_map([self::class, 'leaf'], $ns)];
    }

    /**
     * Merkle commitment of a plan (RFC 6962 shape, domain separated): `root` and `proofs` (node id => inclusion proof). A node is
     * `id`, `verb`, `resource` and optionally `params_digest`, `reversibility_class`, `pre`, `post`.
     */
    public static function commitPlan(array $nodes): Obj
    {
        [$ns, $hs] = self::planHashes($nodes);
        $proofs = new Obj();
        foreach ($ns as $i => $n) {
            $path = [];
            self::prove($hs, $i, $path);
            $proofs->set((string)$n->get('id'), self::obj(['index' => $i, 'size' => count($hs), 'path' => $path]));
        }
        return self::obj(['root' => Pca::b64u(self::build($hs)), 'proofs' => $proofs]);
    }

    /** Sign a PCActn body (without `sig`) with the leaf holder's key. */
    public static function signPcactn(mixed $body, KeyPair $leaf, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = self::bind(self::obj($body), $alg, $pq);
        return self::finish($b, $alg, $leaf, $pq, Pca::thresholdMessage($b));
    }

    /**
     * A complete signed PCActn for plan node `$nodeId` (wire format v2). `$extra` holds the optional SIGNED slots by wire name
     * (nonce, caution, rationale_commitment, progress_step, prohibition_evidence, tool_binding, intent, intent_session, fresh_at;
     * also provenance / attestation / freshness / risk_claim to replace the empty stubs).
     * @param Obj[] $chain
     */
    public static function buildPcactn(Obj $grant, array $chain, array $plan, string $nodeId, int $counter, KeyPair $signer, string $aud,
                                       mixed $params = null, ?int $iat = null, ?int $exp = null, int $ttlMs = self::DEFAULT_TTL_MS, array $extra = [], ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        if ($aud === '') {
            throw new \InvalidArgumentException('buildPcactn: aud (audience) is required');
        }
        [$ns, $hs] = self::planHashes($plan);
        $idx = null;
        foreach ($ns as $i => $n) {
            if ($n->get('id') === $nodeId) {
                $idx = $i;
            }
        }
        if ($idx === null) {
            throw new \InvalidArgumentException("buildPcactn: unknown plan node $nodeId");
        }
        $node = $ns[$idx];
        $digest = Pca::paramsDigest($params === null ? null : self::n($params));
        if (is_string($node->get('params_digest')) && $node->get('params_digest') !== $digest) {
            throw new \InvalidArgumentException("buildPcactn: params do not match plan node $nodeId's params_digest");
        }
        $path = [];
        self::prove($hs, $idx, $path);
        $iat ??= (int)(microtime(true) * 1000);
        $body = self::obj([
            'ver' => 2,
            'action' => ['verb' => $node->get('verb'), 'resource' => $node->get('resource'), 'params_digest' => $digest,
                'reversibility_class' => $node->get('reversibility_class') ?? Pca::DEFAULT_REV],
            'grant_ref' => $grant->get('id'),
            'cap_chain' => $chain,
            'plan' => ['root' => Pca::b64u(self::build($hs)), 'inclusion_proof' => self::obj(['index' => $idx, 'size' => count($hs), 'path' => $path]),
                'node_id' => $nodeId, 'conditions_digest' => self::condDigest($node)],
            'attestation' => ['quote_digest' => '', 'epoch' => 0, 'model_id' => 'unattested', 'measurement' => '', 'operator' => 'unattested'],
            'provenance' => ['causal_hash' => '', 'taint_level' => 0, 'trusted_refs' => []],
            'freshness' => ['beacon_ref' => '', 'epoch' => 0, 'accumulator_witness' => ''],
            'counter' => $counter,
            'risk_claim' => ['r' => 0, 'inputs' => new Obj()],
            'aud' => $aud,
            'iat' => $iat,
            'exp' => $exp ?? $iat + $ttlMs,
        ]);
        foreach ($extra as $k => $v) {
            if ($v !== null) {
                $body->set((string)$k, self::n($v));
            }
        }
        return self::signPcactn($body, $signer, $alg, $pq);
    }

    private static function enc(mixed $v): string
    {
        return Pca::b64u(self::canon(self::n($v)));
    }

    /**
     * HTTP headers the native middleware reads: `PCA-Action` (base64url of the PCActn JSON) and, when given, `PCA-Discharges`
     * (base64url JSON array), `PCA-Narrow` and `PCA-Escalation-Answer`.
     * @return array<string,string>
     */
    public static function headers(Obj $pcactn, array $discharges = [], ?Obj $narrow = null, ?Obj $escalationAnswer = null): array
    {
        $h = [self::HEADER => self::enc($pcactn)];
        if ($discharges !== []) {
            $h['PCA-Discharges'] = self::enc($discharges);
        }
        if ($narrow !== null) {
            $h['PCA-Narrow'] = self::enc($narrow);
        }
        if ($escalationAnswer !== null) {
            $h['PCA-Escalation-Answer'] = self::enc($escalationAnswer);
        }
        return $h;
    }

    // ---- escalation answer, discharge, narrow ---------------------------------------------------------------------

    /**
     * The approving principal's signed answer ('allow' or 'deny') to an escalation request (an Obj carrying `policy_digest`,
     * `action_digest`, `history_head` and, K7, the `render_digest` the approver saw).
     */
    public static function signEscalationAnswer(KeyPair $principal, Obj $request, string $decision, int $iat, int $expiresAt, ?string $nonce = null, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        if ($decision !== 'allow' && $decision !== 'deny') {
            throw new \InvalidArgumentException("decision must be 'allow' or 'deny'");
        }
        $b = self::obj(['v' => 1, 'kind' => 'pca-escalation-answer', 'principal' => $principal->public,
            'policy_digest' => $request->get('policy_digest'), 'action_digest' => $request->get('action_digest'),
            'history_head' => $request->get('history_head'), 'decision' => $decision, 'iat' => $iat, 'expires_at' => $expiresAt,
            'nonce' => self::nonce($nonce)]);
        if (is_string($request->get('render_digest'))) {
            $b->set('render_digest', $request->get('render_digest'));
        }
        return self::signArtifact(Escalation::ANSWER_DOMAIN, $b, $principal, $alg, $pq);
    }

    /** A third-party caveat: the verifier's pin labelled `$issuer` (of class `$issuerClass`) must sign a discharge satisfying `$require`. */
    public static function needsDischargeCaveat(string $id, string $issuer, string $issuerClass, array $require, string $bind = 'chain_hop', int $ttlMs = 300000): array
    {
        return ['type' => 'needs_discharge', 'id' => $id, 'issuer' => $issuer, 'issuer_class' => $issuerClass, 'bind' => $bind, 'ttl_ms' => $ttlMs, 'require' => $require];
    }

    /** No hop may be appended below the hop that carries it. */
    public static function sealedCaveat(): array
    {
        return ['type' => 'sealed'];
    }

    /** A lifetime use count (1..256) backed by the verifier's replay store, expiring at `$until` (epoch ms). */
    public static function maxUsesCaveat(string $id, int $n, int $until): array
    {
        return ['type' => 'max_uses', 'id' => $id, 'n' => $n, 'until' => $until];
    }

    /** The pinned third party's discharge (`$capHash` = capHash of the hop carrying the caveat; bind 'action' also needs `$actionDigest`). */
    public static function signDischarge(KeyPair $issuer, string $caveatId, string $issuerLabel, string $capHash, mixed $claims, int $iat, int $notAfter,
                                         string $bind = 'chain_hop', ?string $actionDigest = null, ?string $nonce = null, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = self::obj(['v' => 1, 'kind' => 'pca-discharge', 'caveat_id' => $caveatId, 'issuer' => $issuerLabel, 'cap_hash' => $capHash, 'bind' => $bind,
            'claims' => self::n($claims), 'iat' => $iat, 'not_after' => $notAfter, 'nonce' => self::nonce($nonce)]);
        if ($actionDigest !== null) {
            $b->set('action_digest', $actionDigest);
        }
        return self::signArtifact('atlas-pca/discharge/v1' . "\0", $b, $issuer, $alg, $pq);
    }

    /** The leaf holder's self-attenuation, presented beside the PCActn. */
    public static function signNarrow(KeyPair $holder, string $leafCapHash, array $caveats, int $iat, int $notAfter, ?string $actionDigest = null, ?string $nonce = null, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = self::obj(['v' => 1, 'kind' => 'pca-narrow', 'cap_hash' => $leafCapHash, 'holder' => $holder->public, 'caveats' => self::n($caveats),
            'iat' => $iat, 'not_after' => $notAfter, 'nonce' => self::nonce($nonce)]);
        if ($actionDigest !== null) {
            $b->set('action_digest', $actionDigest);
        }
        return self::signArtifact('atlas-pca/narrow/v1' . "\0", $b, $holder, $alg, $pq);
    }

    // ---- passport -------------------------------------------------------------------------------------------------

    /** Content address of the identity fields. */
    public static function passportFingerprint(mixed $p): string
    {
        $p = self::obj($p);
        return Pca::hashCanonical(self::obj(['d' => 'atlas-pca/passport/v1', 'model_id' => $p->get('model_id'), 'weights_digest' => $p->get('weights_digest'),
            'system_prompt_digest' => $p->get('system_prompt_digest'), 'tool_manifest_digest' => $p->get('tool_manifest_digest'),
            'runtime_measurement' => $p->get('runtime_measurement'), 'operator' => $p->get('operator'), 'hardware_rooted' => $p->get('hardware_rooted')]));
    }

    /** Fill `id` from the content fingerprint of the identity. */
    public static function issuePassport(mixed $identity): Obj
    {
        $p = self::obj($identity)->without('id');
        $p->set('id', self::passportFingerprint($p));
        return $p;
    }

    /** Sign a passport for the agent key `$subject`. Fail closed: a hardware_rooted passport needs `$evidence`. */
    public static function signPassport(Obj $passport, KeyPair $issuer, string $subject, int $exp, ?int $iat = null, ?int $nbf = null, mixed $evidence = null, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        if ($passport->get('id') !== self::passportFingerprint($passport)) {
            throw new \InvalidArgumentException('signPassport: passport.id is not the fingerprint of its identity (use issuePassport)');
        }
        if ($passport->get('hardware_rooted') === true && $evidence === null) {
            throw new \InvalidArgumentException('signPassport: hardware_rooted requires attestation evidence (fail closed)');
        }
        $at = $passport->get('issued_at');
        $iat ??= $at instanceof Num ? $at->int() : (int)$at;
        $nbf ??= $iat;
        if ($exp <= $nbf) {
            throw new \InvalidArgumentException('signPassport: exp must be after nbf');
        }
        $b = self::obj(['typ' => 'atlas-pca/passport', 'ver' => 1, 'passport' => $passport, 'iss' => $issuer->public, 'sub' => $subject,
            'iat' => $iat, 'nbf' => $nbf, 'exp' => $exp]);
        if ($evidence !== null) {
            $ev = self::obj($evidence);
            if (!$ev->has('at')) {
                $ev->set('at', self::n($iat));
            }
            $b->set('evidence', $ev);
        }
        return self::signArtifact('atlas-pca/passport-sig/v1' . "\0", $b, $issuer, $alg, $pq);
    }

    // ---- workflow, receipts, read grants, aggregate grants, fresh_at ----------------------------------------------

    private static function signedByPrincipal(mixed $body, KeyPair $ed, string $domain, string $what): Obj
    {
        $b = self::obj($body);
        if ($b->get('principal') !== $ed->public) {
            throw new \InvalidArgumentException("$what: principal is not the signer");
        }
        return self::obj(['body' => $b, 'sig' => self::signBody($ed, $domain, $b)]);
    }

    /** The principal's signed workflow commitment `{body, sig}`; `body.principal` must be the signer. */
    public static function signWorkflow(KeyPair $principal, mixed $body): Obj
    {
        return self::signedByPrincipal($body, $principal, "atlas-pca/workflow/v1\0", 'signWorkflow');
    }

    /** The principal's signed read grant `{body, sig}`. */
    public static function signReadGrant(KeyPair $principal, mixed $body): Obj
    {
        return self::signedByPrincipal($body, $principal, "atlas-pca/read-grant/v1\0", 'signReadGrant');
    }

    /** The principal's signed aggregate-read grant `{body, sig}`. */
    public static function signAggregateGrant(KeyPair $principal, mixed $body): Obj
    {
        return self::signedByPrincipal($body, $principal, "atlas-pca/aggregate-grant/v1\0", 'signAggregateGrant');
    }

    /** A receipt output for `$value` (string, bool or integer); `$num` carries the integer an edge may compare. */
    public static function wfOutput(string|int|bool $value, array $labels = [], ?string $unit = null, bool $num = false): Obj
    {
        sort($labels, SORT_STRING);
        return self::obj(['digest' => Workflow::valueDigest(self::n($value)), 'num' => $num && is_int($value) ? self::n($value) : null, 'unit' => $unit, 'labels' => $labels]);
    }

    /** The resource server's signed receipt for a workflow step; `$prev` is the previous receipt of the workflow. */
    public static function signStepReceipt(KeyPair $rs, mixed $workflow, string $step, string $outcome, string $paramsDigest, mixed $outputs, int $issuedAt, ?Obj $prev = null): Obj
    {
        $prevSeq = $prev?->get('seq');
        $base = self::obj(['v' => 1, 'wf' => Workflow::workflowDigest(self::obj($workflow)), 'step' => $step,
            'seq' => $prev === null ? 0 : ($prevSeq instanceof Num ? $prevSeq->int() : (int)$prevSeq) + 1,
            'prev' => $prev === null ? null : Workflow::receiptRef($prev), 'outcome' => $outcome, 'params_digest' => $paramsDigest,
            'outputs' => self::n($outputs), 'issued_at' => $issuedAt, 'signer' => $rs->public]);
        $base->set('sig', self::signBody($rs, "atlas-pca/wf-receipt/v1\0", $base));
        return $base;
    }

    /** A signed consistency token: the high-water mark of the verifier-side state a write produced. */
    public static function signFreshAt(KeyPair $signer, string $scope, mixed $state, int $issuedAt): Obj
    {
        $s = self::obj($state);
        $base = self::obj(['v' => 1, 'scope' => $scope, 'revocation_epoch' => $s->get('revocation_epoch'), 'ledger_tree_size' => $s->get('ledger_tree_size'),
            'budget_version' => $s->get('budget_version'), 'policy_revision' => $s->get('policy_revision'), 'policy_digest' => $s->get('policy_digest'),
            'issued_at' => $issuedAt, 'signer' => $signer->public]);
        $base->set('sig', self::signBody($signer, "atlas-pca/fresh-at/v1\0", $base));
        return $base;
    }
}

/**
 * An agent holding a grant (or a delegated chain): keeps the replay counter, picks nonces and builds the headers. Persist the
 * counter (`$onCounter`) if the process can restart: a lower counter is refused as a replay.
 */
final class Agent
{
    private ?array $plan = null;

    /** @param Obj[]|null $chain  @param ?callable(int):void $onCounter */
    public function __construct(
        public readonly KeyPair $key,
        public readonly Obj $grant,
        public readonly string $aud,
        public readonly ?array $chain = null,
        private int $counter = 0,
        private readonly mixed $clock = null,
        private readonly mixed $onCounter = null,
        public int $ttlMs = Sign::DEFAULT_TTL_MS,
        public readonly ?string $alg = null,
        public readonly ?PqKeyPair $pq = null,
    ) {
    }

    /** @return Obj[] */
    public function chain(): array
    {
        return $this->chain ?? [$this->grant];
    }

    /** Commit to a multi-step plan; `act` then signs against the matching node (and its Merkle proof). */
    public function usePlan(array $nodes): self
    {
        $this->plan = $nodes;
        return $this;
    }

    /** Build and sign the PCActn for one action. Without a committed plan it commits a one-node plan for the action. */
    public function act(string $verb, string $resource, mixed $params = null, array $extra = []): Action
    {
        if ($this->plan !== null) {
            $nodeId = null;
            foreach ($this->plan as $n) {
                $o = Sign::n($n);
                if ($o->get('verb') === $verb && $o->get('resource') === $resource) {
                    $nodeId = (string)$o->get('id');
                    break;
                }
            }
            if ($nodeId === null) {
                throw new \InvalidArgumentException("act: no node of the committed plan matches $verb $resource");
            }
            $plan = $this->plan;
        } else {
            $nodeId = 'n1';
            $plan = [['id' => $nodeId, 'verb' => $verb, 'resource' => $resource, 'params_digest' => Pca::paramsDigest($params === null ? null : Sign::n($params))]];
        }
        $n = ++$this->counter;
        if ($this->onCounter !== null) {
            ($this->onCounter)($n);
        }
        $extra += ['nonce' => Pca::b64u(random_bytes(16))];
        $now = $this->clock !== null ? ($this->clock)() : (int)(microtime(true) * 1000);
        $p = Sign::buildPcactn($this->grant, $this->chain(), $plan, $nodeId, $n, $this->key, $this->aud, $params, $now, null, $this->ttlMs, $extra, $this->alg, $this->pq);
        return new Action($p, Sign::headers($p), $nodeId);
    }

    /** A sub-agent signing with `$to`, holding this chain plus one narrower hop (caveats are only ever appended). */
    public function delegate(KeyPair $to, array $caveats = []): self
    {
        $chain = $this->chain();
        $cap = Sign::delegate($chain[count($chain) - 1], $this->key, $to->public, $caveats, null, $this->alg, $this->pq);
        return new self($to, $this->grant, $this->aud, [...$chain, $cap], 0, $this->clock, null, $this->ttlMs, $this->alg, $this->pq);
    }
}
