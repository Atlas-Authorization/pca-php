<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Ha.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/LedgerLog.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';

/** Single-use store for server-issued attestation nonces: `consume` is true for the first call with a nonce and false for every later one. */
interface AttestationNonceStore
{
    public function consume(mixed $nonce): bool;
}

/**
 * The in-memory, single-process nonce store. A consumed nonce is NEVER re-accepted inside the retention window; the store is bounded by
 * `max` entries and, when full of still-retained nonces, REFUSES new ones (fail closed) rather than evict a live one. Only integer epoch
 * milliseconds are accepted from the clock; anything else refuses the nonce.
 */
final class MemoryNonceStore implements AttestationNonceStore
{
    /** @var array<string,int|float> nonce => time consumed (insertion order is time order) */
    private array $seen = [];
    private readonly int|float $max;
    private readonly int|float $retention;
    private readonly mixed $clock;

    /** @param mixed $opts `{retentionMs?, now?}` ({@see Obj} or array); `now` is a callable returning epoch ms */
    public function __construct(mixed $max = Attestation::DEFAULT_MAX_NONCES, mixed $opts = null)
    {
        $m = $max === null ? (float)Attestation::DEFAULT_MAX_NONCES : Js::num($max);
        if ($m === null || !Ha::safeInt($m) || $m < 1) {
            throw new \TypeError('memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)');
        }
        $r = Jsx::get($opts, 'retentionMs');
        $ret = $r === null || $r instanceof Undef ? (float)Attestation::DEFAULT_NONCE_RETENTION_MS : Js::num($r);
        if ($ret === null || !Ha::safeInt($ret) || $ret <= 0) {
            throw new \TypeError('memoryNonceStore: retentionMs must be a positive integer (ms)');
        }
        $this->max = $m;
        $this->retention = $ret;
        $now = Jsx::get($opts, 'now');
        $this->clock = is_callable($now) ? $now : static fn() => (int)(microtime(true) * 1000);
    }

    public function consume(mixed $nonce): bool
    {
        if (!is_string($nonce)) {
            return false;
        }
        $t = ($this->clock)();
        $tf = Js::num($t);
        if ($tf === null || !Ha::safeInt($tf)) {
            return false;
        }
        $k = 'k' . $nonce;
        if (isset($this->seen[$k])) {
            if ($tf - $this->seen[$k] < $this->retention) {
                return false;
            }
            unset($this->seen[$k]);
        }
        if (count($this->seen) >= $this->max) {
            foreach ($this->seen as $key => $at) {
                if ($tf - $at < $this->retention) {
                    break;
                }
                unset($this->seen[$key]);
            }
            if (count($this->seen) >= $this->max) {
                return false;
            }
        }
        $this->seen[$k] = $tf;
        return true;
    }
}

/** A software attestor for dev and CI: signs documents with its key (and, for the post-quantum suites, its PQ key). */
final class DevAttestor
{
    public readonly string $publicKey;
    private readonly ?string $pqPk;

    public function __construct(private readonly KeyPair $secret, private readonly mixed $alg = null, private readonly ?PqKeyPair $pq = null)
    {
        $this->publicKey = $secret->public;
        if (Pq::resolveSigAlg($alg) === null) {
            throw new \RuntimeException("createDevAttestor: unknown signature alg '" . Jsx::str($alg) . "'");
        }
        $this->pqPk = Pq::suitePqPublicKey($alg, $pq);
    }

    /** Sign a SOFTWARE-mode document over the claims; when holder_pub, grant_ref and epoch are all given, the document is bound to them and the nonce. */
    public function attest(mixed $claims): Obj
    {
        $body = Obj::of(['model_id' => Jsx::rd($claims, 'model_id'), 'weights_digest' => Jsx::get($claims, 'weights_digest'),
            'runtime_measurement' => Jsx::get($claims, 'runtime_measurement'), 'operator' => Jsx::get($claims, 'operator'), 'nonce' => Jsx::get($claims, 'nonce'),
            'issued_at' => Jsx::get($claims, 'issued_at'), 'expires_at' => Jsx::get($claims, 'expires_at'), 'attestor' => $this->publicKey, 'mode' => 'software']);
        foreach (['system_prompt_digest', 'tool_manifest_digest'] as $k) {
            $v = Jsx::get($claims, $k);
            if (!($v instanceof Undef)) {
                $body->set($k, $v);
            }
        }
        $hp = Jsx::get($claims, 'holder_pub');
        $gr = Jsx::get($claims, 'grant_ref');
        $ep = Jsx::get($claims, 'epoch');
        if (!($hp instanceof Undef) && !($gr instanceof Undef) && !($ep instanceof Undef)) {
            $body->set('binding', Attestation::bindingB64u(Obj::of(['holderPub' => $hp, 'grantRef' => $gr, 'epoch' => $ep, 'nonce' => Jsx::get($claims, 'nonce')])));
        }
        $signed = Jsx::spread($body);
        $suite = Pq::resolveSigAlg($this->alg);
        if ($suite['alg'] !== 'ed25519') {
            $signed->set('alg', $suite['alg']);
            $signed->set('pq_pk', $this->pqPk ?? Jsx::$U);
        }
        $fields = Pq::signSuiteArtifact($this->alg, $this->secret, $this->pq, Attestation::message($signed));
        foreach ($fields as $k => $v) {
            $signed->set($k, $v);
        }
        return $signed;
    }
}

/**
 * Software attestation: signed documents, the binding hash, the document registry, the nonce entropy gate, the agent-binding match, the
 * verifier and its hook, the multi-root N-of-M verifier, and evidence anchoring. Values are the parsed-JSON model.
 */
final class Attestation
{
    public const BIND_DOMAIN = "atlas-pca/attest-bind/v1\0";
    public const ANCHOR_DOMAIN = "atlas-pca/attest-anchor/v1\0";
    public const MAX_AGE_MS = 300000;
    public const DEFAULT_NONCE_RETENTION_MS = 3600000;
    public const DEFAULT_MAX_NONCES = 100000;
    public const MIN_NONCE_BYTES = 16;
    private const DOC_DOMAIN = "atlas-pca/attest/v1\0";

    // ---- the binding ------------------------------------------------------------------------------------------------------------

    private static function lp(string $s): string
    {
        return pack('N', strlen($s)) . $s;
    }

    /**
     * SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)): the 64-byte report_data a quote is bound to.
     * Throws on malformed expected fields.
     */
    public static function binding(mixed $exp): string
    {
        $holder = Jsx::get($exp, 'holderPub');
        $grant = Jsx::get($exp, 'grantRef');
        $nonce = Jsx::get($exp, 'nonce');
        $epoch = Jsx::get($exp, 'epoch');
        if (!Jsx::truthy($exp) || !is_string($holder) || $holder === '') {
            throw new \TypeError('binding: holderPub required');
        }
        if (!is_string($grant) || $grant === '') {
            throw new \TypeError('binding: grantRef required');
        }
        if (!is_string($nonce) || $nonce === '') {
            throw new \TypeError('binding: nonce required');
        }
        if (!Ha::safeInt($epoch) || Js::num($epoch) < 0) {
            throw new \TypeError('binding: epoch must be a non-negative safe integer');
        }
        return hash('sha512', self::BIND_DOMAIN . self::lp($holder) . self::lp($grant) . pack('J', (int)Js::num($epoch)) . self::lp($nonce), true);
    }

    public static function bindingB64u(mixed $exp): string
    {
        return Pca::b64u(self::binding($exp));
    }

    /** The signed message of a document body: the domain then the strict canonical bytes (both signatures are excluded from the body). */
    public static function message(mixed $body): string
    {
        return self::DOC_DOMAIN . Json::canonicalizeNative($body);
    }

    public static function attestationDigest(mixed $doc): string
    {
        return Pca::hashCanonical($doc);
    }

    // ---- registry, nonce entropy, small predicates ---------------------------------------------------------------------------------

    /**
     * A resolver over known documents: it returns the document whose `nonce` equals the PCActn's `attestation.quote_digest` (later
     * duplicates overwrite earlier ones). @return \Closure(mixed):mixed the document, or null
     */
    public static function registry(mixed $docs): \Closure
    {
        $by = [];
        foreach (is_array($docs) && array_is_list($docs) ? $docs : [] as $d) {
            $n = Jsx::get($d, 'nonce');
            if (Jsx::truthy($d) && is_string($n)) {
                $by['k' . $n] = $d;
            }
        }
        return static function (mixed $ctx) use ($by): mixed {
            $k = Jsx::get(Jsx::get(Jsx::get($ctx, 'pcactn'), 'attestation'), 'quote_digest');
            return is_string($k) ? ($by['k' . $k] ?? null) : null;
        };
    }

    /** Whether `$nonce` plausibly carries `minBytes` (at least 16) bytes of entropy: hex or base64url, at least 8 distinct characters. */
    public static function nonceEntropyOk(mixed $nonce, mixed $minBytes = self::MIN_NONCE_BYTES): bool
    {
        if (!is_string($nonce)) {
            return false;
        }
        $mb = Jsx::toNum($minBytes);
        $need = is_nan($mb) ? NAN : max($mb, (float)self::MIN_NONCE_BYTES);
        $hex = preg_match('/\A[0-9a-fA-F]+\z/', $nonce) === 1;
        $b64 = preg_match('/\A[A-Za-z0-9_-]+\z/', $nonce) === 1;
        if (!$hex && !$b64) {
            return false;
        }
        $bytes = $hex ? strlen($nonce) / 2 : floor(strlen($nonce) * 3 / 4);
        if ($bytes < $need) {
            return false;
        }
        return count(array_unique(str_split($nonce))) >= 8;
    }

    /** True iff the grant's agent_binding constrains anything (an attestation is then REQUIRED). */
    public static function requiresAttestation(mixed $binding): bool
    {
        $b = $binding === null || $binding instanceof Undef ? new Obj() : $binding;
        $ne = static fn(mixed $x): bool => is_array($x) && array_is_list($x) && $x !== [];
        $mm = Jsx::get($b, 'min_measurement');
        $op = Jsx::get($b, 'operator');
        return $ne(Jsx::get($b, 'model_allowlist')) || (!($mm instanceof Undef) && $mm !== '') || (is_string($op) && $op !== '') || $ne(Jsx::get($b, 'weights_allowlist'))
            || $ne(Jsx::get($b, 'system_prompt_allowlist')) || $ne(Jsx::get($b, 'tool_manifest_allowlist')) || Jsx::get($b, 'require_hardware') === true
            || Jsx::get($b, 'require_measured_weights') === true;
    }

    /** True iff `doc.nonce` is the nonce the PCActn declares in `attestation.quote_digest`. */
    public static function nonceBinds(mixed $doc, mixed $ctx): bool
    {
        $n = Jsx::get($doc, 'nonce');
        return is_string($n) && $n === Jsx::get(Jsx::get(Jsx::get($ctx, 'pcactn'), 'attestation'), 'quote_digest');
    }

    // ---- agent-binding match ---------------------------------------------------------------------------------------------------------

    /** SameValueZero equality (a JS `includes`): numbers by value, strings, booleans and null by identity, objects only to themselves. */
    private static function szEq(mixed $a, mixed $b): bool
    {
        $x = Js::num($a);
        $y = Js::num($b);
        if ($x !== null || $y !== null) {
            return $x !== null && $y !== null && ($x == $y || (is_nan($x) && is_nan($y)));
        }
        return $a === $b;
    }

    private static function includes(mixed $list, mixed $x): bool
    {
        foreach ($list as $e) {
            if (self::szEq($e, $x)) {
                return true;
            }
        }
        return false;
    }

    private static function nonEmptyList(mixed $x): array
    {
        return is_array($x) && array_is_list($x) ? $x : [];
    }

    private static function measuredSvn(mixed $runtime): ?float
    {
        if (!is_string($runtime) || preg_match('/\A(?:0|[1-9][0-9]*)\z/', $runtime) !== 1) {
            return null;
        }
        $n = (float)$runtime;
        return $n <= 9007199254740991.0 ? $n : null;
    }

    /** `{svn: n}` exactly, with n a safe non-negative integer JSON number (not -0). */
    private static function svnBound(mixed $mm): ?float
    {
        if (!($mm instanceof Obj) || $mm->keys() !== ['svn']) {
            return null;
        }
        $n = Js::num($mm->get('svn'));
        return $n !== null && is_finite($n) && $n == floor($n) && abs($n) <= 9007199254740991.0 && $n >= 0 && !($n == 0.0 && fdiv(1.0, $n) < 0) ? $n : null;
    }

    /** Match a measured identity against the grant's agent_binding: the reason on failure (the first failing constraint), else null. */
    public static function matchAgentBinding(mixed $id, mixed $binding): ?string
    {
        $b = $binding === null || $binding instanceof Undef ? new Obj() : $binding;
        $model = Jsx::rd($id, 'model_id');
        $weights = Jsx::get($id, 'weights_digest');
        $runtime = Jsx::get($id, 'runtime_measurement');
        $ml = self::nonEmptyList(Jsx::get($b, 'model_allowlist'));
        if ($ml !== [] && !self::includes($ml, $model)) {
            return 'model_id ' . Jsx::str($model) . ' not in model_allowlist';
        }
        $mm = Jsx::get($b, 'min_measurement');
        $svn = null;
        if ($mm instanceof Undef || $mm === '') {
            $kind = 'none';
        } elseif (is_string($mm)) {
            $kind = 'eq';
        } elseif (($svn = self::svnBound($mm)) === null) {
            $kind = 'bad';
        } else {
            $kind = 'svn';
        }
        if ($kind === 'bad') {
            return 'min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)';
        }
        if ($kind === 'eq' && $runtime !== $mm) {
            return 'runtime_measurement does not match required min_measurement';
        }
        if ($kind === 'svn') {
            $got = self::measuredSvn($runtime);
            if ($got === null) {
                return 'runtime_measurement ' . Jsx::str($runtime) . ' is not an integer SVN (required min svn ' . Js::str($mm->get('svn')) . ')';
            }
            if ($got < $svn) {
                return 'runtime_measurement svn ' . IntentWb::jsNumStr($got) . ' is below required min svn ' . Js::str($mm->get('svn'));
            }
        }
        $op = Jsx::get($b, 'operator');
        if (is_string($op) && $op !== '' && Jsx::get($id, 'operator') !== $op) {
            return 'operator ' . Jsx::str(Jsx::get($id, 'operator')) . ' is not the bound operator';
        }
        if (Jsx::get($b, 'require_measured_weights') === true && Jsx::get($id, 'weights_measured') !== true) {
            return 'weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)';
        }
        $wl = self::nonEmptyList(Jsx::get($b, 'weights_allowlist'));
        if ($wl !== [] && !self::includes($wl, $weights)) {
            return 'weights_digest not in weights_allowlist (model swap / fine-tune?)';
        }
        $sp = Jsx::get($id, 'system_prompt_digest');
        $sl = self::nonEmptyList(Jsx::get($b, 'system_prompt_allowlist'));
        if ($sl !== [] && (!is_string($sp) || !self::includes($sl, $sp))) {
            return 'system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)';
        }
        $tm = Jsx::get($id, 'tool_manifest_digest');
        $tl = self::nonEmptyList(Jsx::get($b, 'tool_manifest_allowlist'));
        if ($tl !== [] && (!is_string($tm) || !self::includes($tl, $tm))) {
            return 'tool_manifest_digest not in tool_manifest_allowlist (tools changed?)';
        }
        return null;
    }

    // ---- verification ------------------------------------------------------------------------------------------------------------------

    private static function nonceAgeReason(mixed $issued, float $now, float $skew, float $maxAge): ?string
    {
        $i = Js::num($issued);
        if ($i === null || !is_finite($i)) {
            return 'server nonce issue time unknown (cannot establish freshness)';
        }
        if (!(is_finite($now) && is_finite($skew) && $now + $skew >= $i)) {
            return 'nonce issued in the future';
        }
        if (!($now - $i <= $maxAge + $skew)) {
            return 'attestation nonce expired (stale quote)';
        }
        return null;
    }

    private static function window(float $now, float $skew, mixed $iat, mixed $exp): string
    {
        $i = Js::num($iat);
        $e = Js::num($exp);
        if ($i === null || $e === null || !is_finite($i) || !is_finite($e) || $e < $i) {
            return 'malformed';
        }
        if (!(is_finite($now) && is_finite($skew))) {
            return 'expired';
        }
        return !($now + $skew >= $i) ? 'notyet' : (!($now - $skew <= $e) ? 'expired' : 'valid');
    }

    private static function algKnown(mixed $alg): bool
    {
        return $alg instanceof Undef || ($alg !== null && Pq::resolveSigAlg($alg) !== null);
    }

    private static function trustedSet(mixed $keys): array
    {
        return Jsx::iter($keys);
    }

    /**
     * The core verification. Stages in this order, the first failure wins: a document is present, the binding is constructible, the
     * PCActn's grant_ref, epoch and quote_digest and the document nonce match `expected`, hardware is required but missing, then
     * either the hardware path (nonce age, verifier ok, bound, measured) or the software path (mode, trusted attestor, known alg,
     * signature, binding present and equal, validity window, nonce age when issued-at is supplied), then the agent_binding match.
     * @param mixed $in `{document, ctx, expected, nowMs, trustedAttestorKeys, pqPins?, hardware?, maxNonceAgeMs?, clockSkewMs?}`; `hardware` is a callable
     * `(Obj{document, ctx, nowMs, expected}): mixed`; there is no unbound-key opt-out @return array<string,mixed> `{ok, present, bound, reason?, identity?}`
     */
    public static function verifyAttestation(mixed $in): array
    {
        $doc = Jsx::get($in, 'document');
        $present = $doc instanceof Obj || (is_array($doc) && array_is_list($doc));
        $fail = static fn(string $reason): array => ['ok' => false, 'present' => $present, 'bound' => false, 'reason' => $reason];
        try {
            $ctx = Jsx::get($in, 'ctx');
            $expected = Jsx::get($in, 'expected');
            $nowV = Jsx::get($in, 'nowMs');
            $now = Js::num($nowV);
            if ($now === null || !is_finite($now)) {
                return $fail('verifier clock is not a finite time (fail closed)');
            }
            $trusted = self::trustedSet(Jsx::get($in, 'trustedAttestorKeys'));
            $cs = Js::num(Jsx::get($in, 'clockSkewMs'));
            $skew = $cs !== null && is_finite($cs) ? max(0.0, $cs) : 0.0;
            $ma = Js::num(Jsx::get($in, 'maxNonceAgeMs'));
            $maxAge = min($ma !== null && is_finite($ma) && $ma > 0 ? $ma : (float)self::MAX_AGE_MS, (float)self::MAX_AGE_MS);
            $hw = Jsx::get($in, 'hardware');
            $hasHw = is_callable($hw);
            $expectedBinding = '';
            $env = null;
            $envRead = false;
            $getEnv = static function () use (&$env, &$envRead, $ctx): ?Obj {
                if (!$envRead) {
                    $env = Authorize::readEnvelope(Jsx::rd($ctx, 'grant'));
                    $envRead = true;
                }
                return $env;
            };
            $agentBinding = static fn() => ($e = $getEnv()) === null ? Jsx::$U : Jsx::get($e, 'agent_binding');
            $hwRes = null;
            $win = null;
            $d = $doc;
            $stages = ['KPresent', 'KBindingConstructible', 'KGrantRef', 'KEpoch', 'KQuote', 'KDocNonce', 'KReqHwVerifier', 'KReqHwMode'];
            $stages = [...$stages, ...($hasHw ? ['KHwNonceAge', 'KHwOk', 'KHwBound', 'KHwMeasured']
                : ['KSoftMode', 'KAttestorTrusted', 'KAlgKnown', 'KSigOk', 'KBindingPresent', 'KBindingEq', 'KWindowWellFormed', 'KNotYetValid', 'KExpired', 'KSoftNonceAge']), 'KAgentBinding'];
            $pc = Jsx::get($ctx, 'pcactn');
            $att = Jsx::get($pc, 'attestation');
            $identity = null;
            foreach ($stages as $k) {
                switch ($k) {
                    case 'KPresent':
                        [$holds, $why] = [$present, 'no attestation document for this action'];
                        break;
                    case 'KBindingConstructible':
                        try {
                            $expectedBinding = self::bindingB64u($expected);
                            [$holds, $why] = [true, ''];
                        } catch (\Throwable $e) {
                            [$holds, $why] = [false, 'attestation binding not constructible: ' . ($e->getMessage() === '' ? 'invalid' : $e->getMessage())];
                        }
                        break;
                    case 'KGrantRef':
                        [$holds, $why] = [self::szEq(Jsx::get($pc, 'grant_ref'), Jsx::rd($expected, 'grantRef')), 'attestation binding: PCActn grant_ref differs from expected grant'];
                        break;
                    case 'KEpoch':
                        [$holds, $why] = [self::szEq(Jsx::get($att, 'epoch'), Jsx::get($expected, 'epoch')), 'attestation binding: PCActn attestation epoch differs from expected epoch'];
                        break;
                    case 'KQuote':
                        [$holds, $why] = [Jsx::get($att, 'quote_digest') === Jsx::get($expected, 'nonce'), 'attestation nonce does not bind to this PCActn'];
                        break;
                    case 'KDocNonce':
                        [$holds, $why] = [Jsx::get($d, 'nonce') === Jsx::get($expected, 'nonce'), 'attestation nonce does not match the server-issued nonce'];
                        break;
                    case 'KReqHwVerifier':
                        [$holds, $why] = [Jsx::get($agentBinding(), 'require_hardware') !== true || $hasHw, 'agent_binding.require_hardware: no hardware verifier is configured (fail closed)'];
                        break;
                    case 'KReqHwMode':
                        [$holds, $why] = [Jsx::get($agentBinding(), 'require_hardware') !== true || Jsx::get($d, 'mode') === 'hardware',
                            'agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)'];
                        break;
                    case 'KHwNonceAge':
                        $r = self::nonceAgeReason(Jsx::get($expected, 'nonceIssuedAt'), $now, $skew, $maxAge);
                        [$holds, $why] = [$r === null, $r ?? ''];
                        break;
                    case 'KHwOk':
                        $hwRes = $hw(Obj::of(['document' => $doc, 'ctx' => $ctx, 'nowMs' => $nowV, 'expected' => $expected]));
                        $rr = Jsx::rd($hwRes, 'reason');
                        [$holds, $why] = [Jsx::truthy(Jsx::get($hwRes, 'ok')), 'hardware attestation rejected: ' . ($rr === null || $rr instanceof Undef ? 'invalid' : Jsx::str($rr))];
                        break;
                    case 'KHwBound':
                        [$holds, $why] = [Jsx::get($hwRes, 'bound') === true, 'hardware verifier did not confirm report_data binding'];
                        break;
                    case 'KHwMeasured':
                        [$holds, $why] = [Jsx::truthy(Jsx::get($hwRes, 'measured')), 'hardware verifier returned no measured identity'];
                        break;
                    case 'KSoftMode':
                        [$holds, $why] = [Jsx::get($d, 'mode') === 'software', 'document mode ' . Jsx::str(Jsx::get($d, 'mode')) . ' needs a hardwareVerifier'];
                        break;
                    case 'KAttestorTrusted':
                        $a = Jsx::get($d, 'attestor');
                        [$holds, $why] = [is_string($a) && self::includes($trusted, $a), 'attestor key is not trusted'];
                        break;
                    case 'KAlgKnown':
                        [$holds, $why] = [self::algKnown(Jsx::get($d, 'alg')), 'attestation declares an unknown signature alg'];
                        break;
                    case 'KSigOk':
                        $sig = Jsx::get($d, 'sig');
                        $ok = false;
                        if (is_string($sig)) {
                            $body = Jsx::spread($d);
                            $body = $body->without('sig', 'pq_sig');
                            $ok = self::verifyPinnedSuite(Jsx::get($d, 'alg'), Jsx::get($d, 'attestor'), Jsx::get($d, 'pq_pk'), self::message($body), $sig, Jsx::get($d, 'pq_sig'),
                                Jsx::get($in, 'pqPins'));
                        }
                        [$holds, $why] = [$ok, 'attestation signature does not verify'];
                        break;
                    case 'KBindingPresent':
                        $bnd = Jsx::get($d, 'binding');
                        [$holds, $why] = [is_string($bnd) && $bnd !== '', 'attestation is not bound (binding absent)'];
                        break;
                    case 'KBindingEq':
                        [$holds, $why] = [Jsx::get($d, 'binding') === $expectedBinding, 'attestation binding mismatch (holder/grant/epoch/nonce)'];
                        break;
                    case 'KWindowWellFormed':
                        $win ??= self::window($now, $skew, Jsx::get($d, 'issued_at'), Jsx::get($d, 'expires_at'));
                        [$holds, $why] = [$win !== 'malformed', 'malformed attestation validity window'];
                        break;
                    case 'KNotYetValid':
                        $win ??= self::window($now, $skew, Jsx::get($d, 'issued_at'), Jsx::get($d, 'expires_at'));
                        [$holds, $why] = [$win !== 'notyet', 'attestation not yet valid'];
                        break;
                    case 'KExpired':
                        $win ??= self::window($now, $skew, Jsx::get($d, 'issued_at'), Jsx::get($d, 'expires_at'));
                        [$holds, $why] = [$win !== 'expired', 'attestation expired'];
                        break;
                    case 'KSoftNonceAge':
                        $ni = Jsx::get($expected, 'nonceIssuedAt');
                        if (Js::num($ni) === null) {
                            [$holds, $why] = [true, ''];
                        } else {
                            $r = self::nonceAgeReason($ni, $now, $skew, $maxAge);
                            [$holds, $why] = [$r === null, $r ?? ''];
                        }
                        break;
                    default: // KAgentBinding
                        $identity = $hasHw ? Jsx::get($hwRes, 'measured') : self::softwareIdentity($d);
                        $reason = self::matchAgentBinding($identity, $agentBinding());
                        [$holds, $why] = [$reason === null, $reason ?? ''];
                }
                if (!$holds) {
                    return $fail($why);
                }
            }
            return ['ok' => true, 'present' => true, 'bound' => true, 'identity' => $identity];
        } catch (\Throwable $e) {
            return $fail('attestation verification error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()));
        }
    }

    private static function softwareIdentity(mixed $d): Obj
    {
        $o = Obj::of(['model_id' => Jsx::get($d, 'model_id'), 'weights_digest' => Jsx::get($d, 'weights_digest'), 'runtime_measurement' => Jsx::get($d, 'runtime_measurement'),
            'operator' => Jsx::get($d, 'operator')]);
        foreach (['system_prompt_digest', 'tool_manifest_digest'] as $k) {
            if (is_string(Jsx::get($d, $k))) {
                $o->set($k, $d->get($k));
            }
        }
        return $o;
    }

    /** A signature under a suite with the attestor's identity key; a post-quantum suite needs its key PINNED (`pqPins`), never taken from the document. */
    private static function verifyPinnedSuite(mixed $alg, mixed $identity, mixed $artifactPk, string $msg, mixed $sig, mixed $pqSig, mixed $pqPins): bool
    {
        $suite = $alg instanceof Undef ? Pq::resolveSigAlg(null) : ($alg === null ? null : Pq::resolveSigAlg($alg)); // only an ABSENT alg is ed25519
        if ($suite === null) {
            return false;
        }
        $s = ['sig' => $sig, 'pq_sig' => $pqSig instanceof Undef ? null : $pqSig];
        if ($suite['alg'] === 'ed25519') {
            return Pca::verifyWithSuite('ed25519', ['edPub' => $identity], $msg, $s);
        }
        $pk = Pca::resolvePqVerifyKey($identity, $artifactPk instanceof Undef ? null : $artifactPk, ['pqPins' => $pqPins instanceof Undef ? null : $pqPins]);
        return $pk !== null && Pca::verifyWithSuite($suite['alg'], ['edPub' => $identity, 'pq' => $pk], $msg, $s);
    }

    /**
     * The verifier hook over {@see verifyAttestation}. The expected binding comes from `expectedBinding` (a server-issued nonce); with
     * neither it nor the loud `insecure_selfDeclaredNonce` opt-out the hook fails closed. With a `nonceStore`, the nonce is consumed once,
     * only after the attestation verified and is bound.
     * @param mixed $opts `{trustedAttestorKeys, nonceStore?, minNonceBytes?, hardware?, resolveDocument?, expectedBinding?, insecure_selfDeclaredNonce?, maxNonceAgeMs?, now?, clockSkewMs?, pqPins?}`
     * @return \Closure(mixed):array<string,mixed> `{enforced: true, ok, reason?, present, bound}`
     */
    public static function createAttestationVerifier(mixed $opts): \Closure
    {
        $tk = Jsx::get($opts, 'trustedAttestorKeys');
        $trusted = is_array($tk) && array_is_list($tk) ? $tk : [];
        $resolve = Jsx::get($opts, 'resolveDocument');
        $clock = Jsx::get($opts, 'now');
        $eb = Jsx::get($opts, 'expectedBinding');
        $store = Jsx::get($opts, 'nonceStore');
        $hw = Jsx::get($opts, 'hardware');
        $insecure = Jsx::get($opts, 'insecure_selfDeclaredNonce') === true;
        return static function (mixed $ctx) use ($opts, $trusted, $resolve, $clock, $eb, $store, $hw, $insecure): array {
            $fin = static function (array $v): array {
                $o = ['enforced' => true, 'ok' => $v['ok']];
                if (($v['reason'] ?? '') !== '') {
                    $o['reason'] = $v['reason'];
                }
                return $o + ['present' => $v['present'], 'bound' => $v['bound']];
            };
            try {
                $document = is_callable($resolve) ? $resolve($ctx) : null;
                $expected = null;
                if (is_callable($eb)) {
                    $expected = $eb($ctx);
                } elseif ($insecure) {
                    $pc = Jsx::get($ctx, 'pcactn');
                    $chain = Jsx::get($pc, 'cap_chain');
                    $leaf = is_array($chain) && array_is_list($chain) && $chain !== [] ? $chain[count($chain) - 1] : Jsx::get($ctx, 'grant');
                    $h = Jsx::get($leaf, 'holder');
                    $expected = Obj::of(['holderPub' => is_string($h) ? $h : '', 'grantRef' => Jsx::get($pc, 'grant_ref'), 'epoch' => Jsx::get(Jsx::get($pc, 'attestation'), 'epoch'),
                        'nonce' => Jsx::get(Jsx::get($pc, 'attestation'), 'quote_digest')]);
                }
                $present = Jsx::truthy($document);
                if (!Jsx::truthy($expected)) {
                    return $fin(['ok' => false, 'present' => $present, 'bound' => false, 'reason' => 'no server-issued attestation nonce/binding available (fail closed)']);
                }
                if (!$insecure && !self::nonceEntropyOk(Jsx::get($expected, 'nonce'), ($m = Jsx::get($opts, 'minNonceBytes')) instanceof Undef ? self::MIN_NONCE_BYTES : $m)) {
                    return $fin(['ok' => false, 'present' => $present, 'bound' => false,
                        'reason' => 'attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)']);
                }
                $in = Obj::of(['document' => $document, 'ctx' => $ctx, 'expected' => $expected, 'nowMs' => is_callable($clock) ? $clock() : (int)(microtime(true) * 1000),
                    'trustedAttestorKeys' => $trusted, 'pqPins' => Jsx::get($opts, 'pqPins'), 'hardware' => $hw, 'maxNonceAgeMs' => Jsx::get($opts, 'maxNonceAgeMs'),
                    'clockSkewMs' => Jsx::get($opts, 'clockSkewMs')]);
                $v = self::verifyAttestation($in);
                if ($v['ok'] && $v['bound'] && $store instanceof AttestationNonceStore) {
                    if (!$store->consume(Jsx::get($expected, 'nonce'))) {
                        return $fin(['ok' => false, 'present' => $v['present'], 'bound' => false, 'reason' => 'attestation nonce already consumed (replay)']);
                    }
                }
                return $fin($v);
            } catch (\Throwable $e) {
                return $fin(['ok' => false, 'present' => false, 'bound' => false, 'reason' => 'attestation verification error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage())]);
            }
        };
    }

    // ---- multi-root N-of-M ---------------------------------------------------------------------------------------------------------------

    private const IDENT_FIELDS = ['model_id', 'weights_digest', 'runtime_measurement', 'operator', 'system_prompt_digest', 'tool_manifest_digest'];

    /**
     * A hardware verifier that enforces an N-of-M policy over independent attestation roots: a root passes when it is ok, bound and
     * measured; a REQUIRED root that does not pass denies; fewer than `threshold` passing roots denies; passing roots that disagree on a
     * measured field deny. Throws at construction on an empty root set, a threshold outside [1, roots], a missing or duplicate id.
     * @param mixed $policy `{threshold, roots: [{id, verifier: callable, required?, suite?}]}` (a root is an Obj or an array)
     * @return \Closure(mixed):array<string,mixed> the verifier: `{ok, bound, measured, hostAsserted?}` or `{ok: false, reason}`
     */
    public static function createMultiRootVerifier(mixed $policy): \Closure
    {
        $roots = Jsx::get($policy, 'roots');
        $thr = Jsx::get($policy, 'threshold');
        if (!is_array($roots) || !array_is_list($roots) || $roots === []) {
            throw new \TypeError('createMultiRootVerifier: at least one attestation root is required');
        }
        $t = Js::num($thr);
        if ($t === null || !is_finite($t) || $t != floor($t) || $t < 1 || $t > count($roots)) {
            throw new \TypeError('createMultiRootVerifier: threshold must be an integer in [1, roots.length]');
        }
        $ids = [];
        foreach ($roots as $r) {
            $id = Jsx::truthy($r) ? Jsx::get($r, 'id') : null;
            if (!is_string($id) || $id === '') {
                throw new \TypeError('createMultiRootVerifier: each root needs a non-empty id');
            }
            if (isset($ids[$id])) {
                throw new \TypeError("createMultiRootVerifier: duplicate root id '$id'");
            }
            $ids[$id] = true;
        }
        $threshold = (int)$t;
        return static function (mixed $input) use ($roots, $threshold): array {
            try {
                $passed = [];
                $results = [];
                $host = new Obj();
                $done = null;
                foreach ($roots as $i => $root) {
                    $id = Jsx::get($root, 'id');
                    try {
                        $res = (Jsx::get($root, 'verifier'))($input);
                    } catch (\Throwable $e) {
                        $res = Obj::of(['ok' => false, 'reason' => "root '$id' threw (fail closed): " . ($e->getMessage() === '' ? 'unknown' : $e->getMessage())]);
                    }
                    $results[$i] = $res;
                    $isObj = $res instanceof Obj || (is_array($res) && array_is_list($res));
                    $passes = $isObj && Jsx::get($res, 'ok') === true && Jsx::get($res, 'bound') === true && Jsx::truthy(Jsx::get($res, 'measured'));
                    if ($passes) {
                        $passed[] = [$i, Jsx::get($res, 'measured')];
                        $ha = Jsx::get($res, 'hostAsserted');
                        if (Jsx::truthy($ha)) {
                            foreach (Jsx::keys($ha) as $k) {
                                $host->set($id . '.' . $k, Jsx::get($ha, $k));
                            }
                        }
                    } elseif (Jsx::get($root, 'required') === true) {
                        $done = ['req', $i];
                        break;
                    }
                }
                if ($done !== null) {
                    $ri = $results[$done[1]];
                    $isObj = $ri instanceof Obj || (is_array($ri) && array_is_list($ri));
                    $rs = $isObj ? Jsx::get($ri, 'reason') : null;
                    $why = !$isObj ? "root '" . Jsx::get($roots[$done[1]], 'id') . "' returned a malformed result (fail closed)" : ($rs === null || $rs instanceof Undef ? 'invalid' : Jsx::str($rs));
                    return ['ok' => false, 'reason' => "required attestation root '" . Jsx::get($roots[$done[1]], 'id') . "' failed: $why"];
                }
                if (count($passed) < $threshold) {
                    return ['ok' => false, 'reason' => 'multi-root attestation below threshold (' . count($passed) . "/$threshold independent roots corroborated)"];
                }
                $merged = [];
                foreach (self::IDENT_FIELDS as $f => $name) {
                    $chosen = null;
                    $who = -1;
                    foreach ($passed as [$i, $m]) {
                        $v = Jsx::get($m, $name);
                        if (!is_string($v) || $v === '') {
                            continue;
                        }
                        if ($chosen === null) {
                            [$chosen, $who] = [$v, $i];
                        } elseif ($chosen !== $v) {
                            return ['ok' => false, 'reason' => "multi-root attestation identity conflict: roots '" . Jsx::get($roots[$who], 'id') . "' and '"
                                . Jsx::get($roots[$i], 'id') . "' disagree on $name"];
                        }
                    }
                    $merged[$name] = $chosen ?? '';
                }
                $wm = false;
                foreach ($passed as [$i, $m]) {
                    if ($merged['weights_digest'] !== '' && Jsx::get($m, 'weights_measured') === true && Jsx::get($m, 'weights_digest') === $merged['weights_digest']) {
                        $wm = true;
                    }
                }
                $measured = Obj::of(['model_id' => $merged['model_id'], 'weights_digest' => $merged['weights_digest'], 'weights_measured' => $wm,
                    'runtime_measurement' => $merged['runtime_measurement'], 'operator' => $merged['operator']]);
                foreach (['system_prompt_digest', 'tool_manifest_digest'] as $k) {
                    if ($merged[$k] !== '') {
                        $measured->set($k, $merged[$k]);
                    }
                }
                $out = ['ok' => true, 'bound' => true, 'measured' => $measured];
                if ($host->keys() !== []) {
                    $out['hostAsserted'] = $host;
                }
                return $out;
            } catch (\Throwable $e) {
                return ['ok' => false, 'reason' => 'multi-root attestation error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage())];
            }
        };
    }

    // ---- accountability anchoring ---------------------------------------------------------------------------------------------------------

    /** The domain-separated digest of a verified attestation: the opaque leaf appended to the transparency ledger. */
    public static function evidenceDigest(mixed $ev): string
    {
        $b = Jsx::rd($ev, 'binding');
        $id = Jsx::rd($ev, 'identity');
        $sp = Jsx::get($id, 'system_prompt_digest');
        $tm = Jsx::get($id, 'tool_manifest_digest');
        $roots = Jsx::get($ev, 'rootIds');
        $rs = $roots === null || $roots instanceof Undef ? [] : Jsx::iter($roots);
        usort($rs, static fn($a, $b2): int => Jsx::cmp(Jsx::str($a), Jsx::str($b2)));
        $suite = Jsx::get($ev, 'suite');
        return Pca::hashCanonical(Obj::of(['domain' => self::ANCHOR_DOMAIN, 'holder' => Jsx::get($b, 'holderPub'), 'grant' => Jsx::get($b, 'grantRef'), 'epoch' => Jsx::get($b, 'epoch'),
            'nonce' => Jsx::get($b, 'nonce'), 'model_id' => Jsx::get($id, 'model_id'), 'weights_digest' => Jsx::get($id, 'weights_digest'),
            'weights_measured' => Jsx::get($id, 'weights_measured') === true, 'runtime_measurement' => Jsx::get($id, 'runtime_measurement'), 'operator' => Jsx::get($id, 'operator'),
            'system_prompt_digest' => $sp === null || $sp instanceof Undef ? '' : $sp, 'tool_manifest_digest' => $tm === null || $tm instanceof Undef ? '' : $tm, 'roots' => $rs,
            'suite' => $suite === null || $suite instanceof Undef ? '' : $suite, 'verified_at' => Jsx::get($ev, 'verifiedAt')]));
    }

    /**
     * Anchor a VERIFIED attestation into the transparency ledger for accountability: append the evidence digest and, with a guardian
     * secret, sign the new tree head. When `required`, a missing ledger or guardian secret, or a failed signature, throws.
     * @param ?TransparencyLedger $ledger @param ?callable():mixed $now @return array{index:int,commit:string,sth?:Obj}
     */
    public static function anchorEvidence(mixed $ev, ?TransparencyLedger $ledger, ?KeyPair $guardian = null, ?string $alg = null, ?PqKeyPair $pq = null,
                                          mixed $instanceId = null, mixed $now = null, bool $required = false): array
    {
        $fail = static function (string $m): never {
            throw new \RuntimeException("attestation anchoring (fail closed): $m");
        };
        if ($ledger === null) {
            $fail('no transparency ledger available');
        }
        if ($required && $guardian === null) {
            $fail('required anchoring needs a guardian secret to sign the tree head');
        }
        $commit = self::evidenceDigest($ev);
        $prev = $ledger->head()['root'];
        $index = $ledger->appendCommitment($commit)['index'];
        $head = $ledger->head();
        $out = ['index' => $index, 'commit' => $commit];
        if ($guardian !== null) {
            $t = is_callable($now) ? $now() : (int)(microtime(true) * 1000);
            try {
                $out['sth'] = TransparencyLedger::signTreeHead($guardian, Obj::of(['instance_id' => $instanceId ?? '', 'principal' => $ledger->principal, 'size' => $head['size'],
                    'root' => $head['root'], 'prev_root' => $prev, 'timestamp' => $t]), $alg, $pq);
            } catch (\Throwable $e) {
                if ($required) {
                    $fail('tree-head signing failed: ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()));
                }
            }
        }
        return $out;
    }
}
