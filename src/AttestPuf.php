<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Attestation.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';

/** A source of PUF responses: one byte per bit (0 / 1), noisy within a bound. */
interface PufProvider
{
    public function id(): string;

    public function response(string $challenge): string;
}

/** A deterministic simulated PUF, for tests only: a pure function of (seed, challenge), so it is trivially clonable. */
final class SimulatedPuf implements PufProvider
{
    /** @var array<int,true> */
    private array $flips = [];

    /** @param iterable<int> $flip bit positions to toggle (out-of-range positions are ignored) */
    public function __construct(private string $id, private string $seed, private int $length, iterable $flip = [])
    {
        foreach ($flip as $p) {
            $this->flips[$p] = true;
        }
    }

    public function id(): string
    {
        return $this->id;
    }

    public function response(string $challenge): string
    {
        $stream = '';
        $blocks = intdiv(intdiv($this->length + 7, 8) + 31, 32);
        for ($b = 0; $b < $blocks; $b++) {
            $stream .= hash('sha256', $this->seed . $challenge . pack('N', $b), true);
        }
        $bits = AttestPuf::bitsOf($stream, $this->length);
        foreach (array_keys($this->flips) as $p) {
            if ($p >= 0 && $p < $this->length) {
                $bits[$p] = $bits[$p] === "\0" ? "\1" : "\0";
            }
        }
        return implode('', $bits);
    }
}

/**
 * A PUF provider backed by a TPM 2.0 Endorsement Key read through an injected tpm2-tools runner: the runner is
 * `callable(string $command, list<string> $args): Obj|null` returning `{status, stdout (raw bytes), stderr?, error?}`.
 * Fail closed: a runner that throws or returns nothing, a spawn error, a non-zero status or a short EK public all refuse.
 */
final class TpmEkPufProvider implements PufProvider
{
    private string $id;
    private int $length;
    private \Closure $run;
    private string $tool;
    /** @var list<string> */
    private array $args;
    private int $minEkBytes;

    /** @param mixed $opts `{id, length, run?, tool?, ekHandle?, args?, minEkBytes?}` */
    public function __construct(mixed $opts)
    {
        $id = Jsx::get($opts, 'id');
        if (!is_string($id) || $id === '') {
            throw new \TypeError('TpmEkPufProvider: id must be a non-empty string');
        }
        $length = Jsx::get($opts, 'length');
        if (!AttestPuf::isInteger($length) || Js::num($length) < 1) {
            throw new \RangeException('TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)');
        }
        $min = Jsx::get($opts, 'minEkBytes');
        if (!($min instanceof Undef) && (!AttestPuf::isInteger($min) || Js::num($min) < 1)) {
            throw new \RangeException('TpmEkPufProvider: minEkBytes must be a positive integer');
        }
        $this->id = $id;
        $this->length = (int)Js::num($length);
        $run = Jsx::get($opts, 'run');
        $this->run = is_callable($run) ? \Closure::fromCallable($run) : \Closure::fromCallable([self::class, 'defaultRunner']);
        $tool = Jsx::get($opts, 'tool');
        $this->tool = is_string($tool) && $tool !== '' ? $tool : 'tpm2_readpublic';
        $handle = Jsx::get($opts, 'ekHandle');
        $handle = is_string($handle) && $handle !== '' ? $handle : '0x81010001';
        $args = Jsx::get($opts, 'args');
        $this->args = is_array($args) && array_is_list($args) ? $args : ['-c', $handle, '-f', 'der', '-o', '/dev/stdout', '-Q'];
        $this->minEkBytes = $min instanceof Undef ? 64 : (int)Js::num($min);
    }

    public function id(): string
    {
        return $this->id;
    }

    /**
     * The default runner: spawns the tool without a shell, 15 s timeout, 1 MiB output cap. Never throws for a tool or TPM failure; a
     * spawn failure is `{status: null, error}`.
     */
    public static function defaultRunner(string $command, array $args): Obj
    {
        $p = @proc_open([$command, ...$args], [0 => ['file', PrivateFile::nullDevice(), 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($p)) {
            return Obj::of(['status' => null, 'stdout' => '', 'error' => "$command: spawn failed"]);
        }
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = '';
        $err = '';
        $code = null;
        $deadline = microtime(true) + 15.0;
        while (true) {
            $st = proc_get_status($p);
            if (!$st['running'] && $code === null) {
                $code = $st['exitcode'];
            }
            $r = [$pipes[1], $pipes[2]];
            $w = $e = null;
            if (@stream_select($r, $w, $e, 0, 100000) > 0) {
                foreach ($r as $s) {
                    $chunk = (string)fread($s, 65536);
                    if ($s === $pipes[1]) {
                        $out .= $chunk;
                    } else {
                        $err .= $chunk;
                    }
                }
            }
            if ($code !== null && feof($pipes[1]) && feof($pipes[2])) {
                break;
            }
            if (strlen($out) > (1 << 20) || microtime(true) > $deadline) {
                proc_terminate($p, 9);
                proc_close($p);
                return Obj::of(['status' => null, 'stdout' => '', 'error' => "$command: ETIMEDOUT"]);
            }
        }
        proc_close($p);
        $res = Obj::of(['status' => $code, 'stdout' => $out]);
        if ($err !== '') {
            $res->set('stderr', $err);
        }
        return $res;
    }

    /** The device-unique, stable EK public area (public material only). */
    public function readEkPublic(): string
    {
        try {
            $res = ($this->run)($this->tool, $this->args);
        } catch (\Throwable $e) {
            throw new \RuntimeException('TpmEkPufProvider: tpm2-tools invocation threw (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()));
        }
        if (!($res instanceof Obj)) {
            throw new \RuntimeException('TpmEkPufProvider: command runner returned no result (fail closed)');
        }
        $error = Jsx::get($res, 'error');
        if (is_string($error) && $error !== '') {
            throw new \RuntimeException("TpmEkPufProvider: tpm2-tools unavailable (fail closed): $error");
        }
        $status = Jsx::get($res, 'status');
        if (!(Js::isNum($status) && Js::num($status) === 0.0)) {
            $stderr = Jsx::get($res, 'stderr');
            throw new \RuntimeException("TpmEkPufProvider: '{$this->tool}' exited with status " . Jsx::str($status) . ' (fail closed)'
                . (Jsx::truthy($stderr) ? ': ' . trim(Jsx::str($stderr)) : ''));
        }
        $ek = Jsx::get($res, 'stdout');
        $n = is_string($ek) ? strlen($ek) : 0;
        if ($n < $this->minEkBytes) {
            throw new \RuntimeException("TpmEkPufProvider: EK public too short ($n < {$this->minEkBytes} bytes) \u{2014} TPM unavailable or wrong handle (fail closed)");
        }
        return $ek;
    }

    public function response(string $challenge): string
    {
        $secret = hash_hkdf('sha256', $this->readEkPublic(), 32, $challenge, AttestPuf::TPM_EK_PUF_DOMAIN);
        $stream = '';
        $blocks = max(1, intdiv(intdiv($this->length + 7, 8) + 31, 32));
        for ($b = 0; $b < $blocks; $b++) {
            $stream .= hash('sha256', $secret . pack('N', $b), true);
        }
        return implode('', AttestPuf::bitsOf($stream, $this->length));
    }
}

/** The enrollment registry of PUF identities by provider id; revoking an id hides it and re-registering never un-revokes. */
final class PufEnrollmentRegistry
{
    /** @var array<string,mixed> */
    private array $by = [];
    /** @var array<string,true> */
    private array $revoked = [];

    public function __construct(mixed $enrollments = [])
    {
        foreach (is_array($enrollments) && array_is_list($enrollments) ? $enrollments : [] as $e) {
            $this->register($e);
        }
    }

    public function register(mixed $e): void
    {
        $id = Jsx::get($e, 'providerId');
        if (Jsx::truthy($e) && is_string($id)) {
            $this->by['k' . $id] = $e;
        }
    }

    public function lookup(string $id): mixed
    {
        return isset($this->revoked['k' . $id]) ? null : ($this->by['k' . $id] ?? null);
    }

    public function revoke(string $id): void
    {
        $this->revoked['k' . $id] = true;
    }

    public function isRevoked(string $id): bool
    {
        return isset($this->revoked['k' . $id]);
    }
}

/**
 * The PUF unclonable attestation root: a repetition-code fuzzy extractor (code-offset secure sketch + HKDF-SHA256), simulated and
 * TPM-EK providers, enrollment (the device key is the extracted secret: Ed25519 or ML-DSA), the device attestor, the verifier and the
 * enrollment registry. A response is a string with ONE 0 / 1 byte per bit. The root is software-assured: the identity it yields has
 * `weights_measured: false`.
 */
final class AttestPuf
{
    public const PUF_EXTRACT_INFO = 'atlas-pca/puf-extract/v1';
    public const PUF_ATTEST_DOMAIN = "atlas-pca/attest-puf/v1\0";
    public const PUF_KEY_BYTES = 32;
    public const TPM_EK_PUF_DOMAIN = 'atlas-pca/puf-tpm-ek/v1';
    private const PQ_FAMILIES = ['ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128f', 'SLH-DSA-SHA2-256s'];

    /** Number.isInteger. */
    public static function isInteger(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f);
    }

    /** The first `$n` bits of `$bytes`, least significant bit first, as a list of "\0" / "\1" bytes. @return list<string> */
    public static function bitsOf(string $bytes, int $n): array
    {
        $out = [];
        for ($i = 0; $i < $n; $i++) {
            $out[] = ((ord($bytes[$i >> 3]) >> ($i & 7)) & 1) === 1 ? "\1" : "\0";
        }
        return $out;
    }

    public static function repetitionCorrectionBound(mixed $rep): int|float
    {
        return floor((Js::num($rep) - 1) / 2);
    }

    private static function assertBits(string $b, string $where): void
    {
        if (strlen($b) !== 0 && strspn($b, "\0\1") !== strlen($b)) {
            throw new \RangeException("$where: response must be a 0/1 bit array");
        }
    }

    private static function packBits(string $bits): string
    {
        $out = array_fill(0, intdiv(strlen($bits) + 7, 8), 0);
        for ($i = 0, $n = strlen($bits); $i < $n; $i++) {
            $out[$i >> 3] |= (ord($bits[$i]) & 1) << ($i & 7);
        }
        return pack('C*', ...$out);
    }

    private static function extractKey(string $bits, string $salt): string
    {
        return hash_hkdf('sha256', self::packBits($bits), self::PUF_KEY_BYTES, self::PUF_EXTRACT_INFO, $salt);
    }

    private static function xor(string $a, string $b): string
    {
        return $a ^ $b; // 0/1 bytes: the XOR of two bit strings
    }

    private static function repEncode(string $msg, int $rep): string
    {
        return implode('', array_map(static fn(string $c): string => str_repeat($c, $rep), str_split($msg)));
    }

    private static function repDecode(string $code, int $rep): string
    {
        $out = '';
        for ($i = 0, $k = intdiv(strlen($code), $rep); $i < $k; $i++) {
            $out .= substr_count(substr($code, $i * $rep, $rep), "\1") * 2 > $rep ? "\1" : "\0";
        }
        return $out;
    }

    /**
     * Enroll a response into a stable key and public helper data. `$randomBytes(n)` supplies the random codeword message (called first,
     * for `messageBits` bytes, each masked to its low bit) and the 32-byte salt. @return array{key:string,helper:Obj}
     */
    public static function fuzzyEnroll(string $bits, mixed $params, \Closure $randomBytes): array
    {
        $rep = Jsx::get($params, 'rep');
        $mb = Jsx::get($params, 'messageBits');
        if (!self::isInteger($rep) || Js::num($rep) < 1 || fmod(Js::num($rep), 2.0) === 0.0) {
            throw new \RangeException('fuzzyEnroll: rep must be an odd positive integer');
        }
        if (!self::isInteger($mb) || Js::num($mb) < 1) {
            throw new \RangeException('fuzzyEnroll: messageBits must be a positive integer');
        }
        $rep = (int)Js::num($rep);
        $mb = (int)Js::num($mb);
        $n = $rep * $mb;
        if (strlen($bits) !== $n) {
            throw new \RangeException('fuzzyEnroll: response length ' . strlen($bits) . " != rep*messageBits $n");
        }
        self::assertBits($bits, 'fuzzyEnroll');
        $mr = $randomBytes($mb);
        $m = '';
        for ($i = 0; $i < $mb; $i++) {
            $m .= ($i < strlen($mr) ? ord($mr[$i]) & 1 : 0) === 1 ? "\1" : "\0";
        }
        $sketch = self::xor(self::repEncode($m, $rep), $bits);
        $salt = $randomBytes(32);
        return ['key' => self::extractKey($bits, $salt), 'helper' => Obj::of([
            'sketch' => Pca::b64u(self::packBits($sketch)), 'salt' => Pca::b64u($salt), 'rep' => $rep, 'messageBits' => $mb, 'n' => $n,
        ])];
    }

    /** Reproduce the key from a noisy response: bit-identical within the correction bound, a different key beyond it. Throws on malformed input. */
    public static function fuzzyReproduce(string $bits, mixed $helper): string
    {
        $rep = Jsx::get($helper, 'rep');
        $mb = Jsx::get($helper, 'messageBits');
        if (!Jsx::truthy($helper) || !self::isInteger($rep) || !self::isInteger($mb) || Js::num($rep) < 1 || fmod(Js::num($rep), 2.0) === 0.0) {
            throw new \RangeException('fuzzyReproduce: malformed helper params');
        }
        $rep = (int)Js::num($rep);
        $mb = (int)Js::num($mb);
        $n = $rep * $mb;
        $hn = Jsx::get($helper, 'n');
        if (!Js::isNum($hn) || Js::num($hn) !== (float)$n) {
            throw new \RangeException('fuzzyReproduce: helper.n inconsistent with rep*messageBits');
        }
        if (strlen($bits) !== $n) {
            throw new \RangeException('fuzzyReproduce: response length ' . strlen($bits) . " != $n");
        }
        self::assertBits($bits, 'fuzzyReproduce');
        $sk = Jsx::get($helper, 'sketch');
        $sa = Jsx::get($helper, 'salt');
        if (!is_string($sk) || !is_string($sa)) {
            throw new \RangeException('fuzzyReproduce: helper data missing sketch or salt');
        }
        $packed = Pca::unb64u($sk);
        $salt = Pca::unb64u($sa);
        if ($packed === null || $salt === null) {
            throw new \RangeException('fuzzyReproduce: helper sketch or salt is not canonical base64url');
        }
        if (strlen($packed) !== intdiv($n + 7, 8)) {
            throw new \RangeException('fuzzyReproduce: helper sketch has the wrong length');
        }
        if (strlen($salt) !== 32) {
            throw new \RangeException('fuzzyReproduce: helper salt has the wrong length');
        }
        $sketch = implode('', self::bitsOf($packed, $n));
        $c = self::repEncode(self::repDecode(self::xor($bits, $sketch), $rep), $rep);
        return self::extractKey(self::xor($c, $sketch), $salt);
    }

    /** @param string|null $seed 32 bytes @param iterable<int> $flip */
    public static function createSimulatedPuf(string $id, string $seed, int $length, iterable $flip = []): PufProvider
    {
        return new SimulatedPuf($id, $seed, $length, $flip);
    }

    // ---- the PUF-derived signing key ----------------------------------------------------------------

    private static function assertSuite(mixed $alg): string
    {
        if ($alg === 'ed25519' || $alg === 'ml-dsa-65' || $alg === 'ml-dsa-87') {
            return $alg;
        }
        throw new \RangeException("PUF root: unsupported derived suite '" . Jsx::str($alg) . "' (use ed25519, ml-dsa-65 or ml-dsa-87)");
    }

    /** @return array{publicKey:string,sign:\Closure(string):array} */
    private static function signerFromSeed(string $alg, string $seed): array
    {
        if ($alg === 'ed25519') {
            $kp = new KeyPair($seed);
            return ['publicKey' => $kp->public, 'sign' => static fn(string $m): array => Pq::signWithSuite('ed25519', $kp, null, $m)];
        }
        $kp = $alg === 'ml-dsa-65' ? Pq::mlDsa65Keygen($seed) : Pq::mlDsa87Keygen($seed);
        return ['publicKey' => $kp->public, 'sign' => static fn(string $m): array => Pq::signWithSuite($alg, null, $kp, $m)];
    }

    private static function statementMessage(mixed $body): string
    {
        return self::PUF_ATTEST_DOMAIN . Json::canonicalizeNative($body);
    }

    /**
     * Enroll a device: read its response under `$challenge`, run the fuzzy extractor, derive the key and return the PUBLIC enrollment
     * `{providerId, challenge, alg, publicKey, helper, helperCommitment}`. `$opts` is `{rep, messageBits, alg?}` (default ml-dsa-65).
     */
    public static function enrollPuf(PufProvider $provider, string $challenge, mixed $opts, ?\Closure $randomBytes = null): Obj
    {
        $alg = Jsx::get($opts, 'alg');
        $alg = self::assertSuite($alg instanceof Undef || $alg === null ? 'ml-dsa-65' : $alg);
        $r = self::fuzzyEnroll($provider->response($challenge), $opts, $randomBytes ?? static fn(int $n): string => random_bytes($n));
        $signer = self::signerFromSeed($alg, $r['key']);
        return Obj::of(['providerId' => $provider->id(), 'challenge' => Pca::b64u($challenge), 'alg' => $alg, 'publicKey' => $signer['publicKey'],
            'helper' => $r['helper'], 'helperCommitment' => Pca::hashCanonical(Sign::n($r['helper']))]);
    }

    /**
     * The device-side attestor: each `attest($claims)` reproduces the key from a fresh reading and signs the statement
     * `{provider_id, measurement, weights_digest?, binding, alg, sig}`. `$claims` is `{measurement, weights_digest?, holder_pub, grant_ref, epoch, nonce}`.
     * @return \Closure(mixed):Obj
     */
    public static function createPufAttestor(PufProvider $provider, mixed $enrollment): \Closure
    {
        $alg = self::assertSuite(Jsx::get($enrollment, 'alg'));
        $challenge = Pca::unb64u(Jsx::get($enrollment, 'challenge'));
        if ($challenge === null) {
            throw new \RangeException('Unknown letter: challenge is not canonical base64url');
        }
        return static function (mixed $claims) use ($provider, $enrollment, $alg, $challenge): Obj {
            $key = self::fuzzyReproduce($provider->response($challenge), Jsx::get($enrollment, 'helper'));
            $signer = self::signerFromSeed($alg, $key);
            $binding = Attestation::bindingB64u(Obj::of(['holderPub' => Jsx::get($claims, 'holder_pub'), 'grantRef' => Jsx::get($claims, 'grant_ref'),
                'epoch' => Jsx::get($claims, 'epoch'), 'nonce' => Jsx::get($claims, 'nonce')]));
            $body = Obj::of(['provider_id' => $provider->id(), 'measurement' => Jsx::get($claims, 'measurement'), 'binding' => $binding, 'alg' => $alg]);
            $w = Jsx::get($claims, 'weights_digest');
            if (!($w instanceof Undef)) {
                $body->set('weights_digest', $w);
            }
            $parts = $signer['sign'](self::statementMessage($body));
            $out = Jsx::spread($body);
            $out->set('sig', $parts['sig']);
            if (isset($parts['pq_sig'])) {
                $out->set('pq_sig', $parts['pq_sig']);
            }
            return $out;
        };
    }

    public static function createPufEnrollmentRegistry(mixed $enrollments = []): PufEnrollmentRegistry
    {
        return new PufEnrollmentRegistry($enrollments);
    }

    /** Default identity of a verified statement: `weights_measured` is ALWAYS false (the PUF roots a device identity, not a measurement). */
    private static function defaultIdentity(mixed $st): Obj
    {
        $w = Jsx::get($st, 'weights_digest');
        return Obj::of(['model_id' => '', 'weights_digest' => is_string($w) ? $w : '', 'weights_measured' => false,
            'runtime_measurement' => Jsx::get($st, 'measurement'), 'operator' => '']);
    }

    /**
     * The verifier. Throws at construction without a non-empty `policy.measurements` or a `resolveEnrollment` callable. Checks, first
     * failure wins: evidence, revocation, enrollment (and expiry), helper commitment, suite (and PQ requirement), the signature under
     * the ENROLLED key, the binding, the policy.
     * @param mixed $opts `{resolveEnrollment, policy: {measurements, weightsMeasurements?, deriveIdentity?}, requirePq?, isRevoked?, resolveEvidence?}`
     * @return \Closure(mixed):array<string,mixed> `verify(Obj{document, ctx, nowMs, expected})`: `{ok, bound, measured, hostAsserted}` or `{ok: false, reason}`
     */
    public static function createPufVerifier(mixed $opts): \Closure
    {
        $policy = Jsx::get($opts, 'policy');
        $ms = Jsx::get($policy, 'measurements');
        if (!Jsx::truthy($policy) || !is_array($ms) || !array_is_list($ms) || $ms === []) {
            throw new \TypeError('createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
        }
        $resolveEnrollment = Jsx::get($opts, 'resolveEnrollment');
        if (!is_callable($resolveEnrollment)) {
            throw new \TypeError('createPufVerifier: resolveEnrollment is required');
        }
        $wm = Jsx::get($policy, 'weightsMeasurements');
        $weights = is_array($wm) && array_is_list($wm) ? $wm : null;
        $requirePq = Jsx::get($opts, 'requirePq') === true;
        $isRevoked = Jsx::get($opts, 'isRevoked');
        $resolveEvidence = Jsx::get($opts, 'resolveEvidence');
        $derive = Jsx::get($policy, 'deriveIdentity');
        return static function (mixed $input) use ($ms, $weights, $requirePq, $isRevoked, $resolveEvidence, $resolveEnrollment, $derive): array {
            $fail = static fn(string $reason): array => ['ok' => false, 'reason' => $reason];
            try {
                if (!is_callable($resolveEvidence)) {
                    return $fail('no PUF evidence resolver configured (fail closed)');
                }
                $doc = Jsx::get($input, 'document');
                $ctx = Jsx::get($input, 'ctx');
                $st = $resolveEvidence($doc, $ctx);
                if (!($st instanceof Obj) || !is_string($st->get('provider_id')) || !is_string($st->get('alg'))) {
                    return $fail('no PUF attestation statement for this action');
                }
                $pid = $st->get('provider_id');
                if (is_callable($isRevoked) && $isRevoked($pid)) {
                    return $fail("PUF enrollment for provider '$pid' is revoked");
                }
                $enr = $resolveEnrollment($pid, $doc, $ctx);
                if (!Jsx::truthy($enr)) {
                    return $fail("no PUF enrollment registered for provider '$pid'");
                }
                $notAfter = Jsx::get($enr, 'notAfter');
                if (!($notAfter instanceof Undef) && !(Js::isNum($pn = Jsx::get($input, 'nowMs')) && is_finite((float)Js::num($pn)) && Jsx::lt($pn, $notAfter))) {
                    return $fail('PUF enrollment has expired');
                }
                $hc = Jsx::get($enr, 'helperCommitment');
                if (!is_string($hc) || $hc !== Pca::hashCanonical(Sign::n(Jsx::get($enr, 'helper')))) {
                    return $fail('PUF enrollment helper commitment mismatch (helper tampered)');
                }
                $alg = $st->get('alg');
                if ($alg !== Jsx::get($enr, 'alg')) {
                    return $fail("PUF statement suite '$alg' does not match the enrolled suite '" . Jsx::str(Jsx::get($enr, 'alg')) . "'");
                }
                $suite = Pq::resolveSigAlg($alg);
                if ($suite === null) {
                    return $fail("PUF statement declares an unknown signature alg '$alg'");
                }
                if ($requirePq && !in_array($suite['family'] ?? null, self::PQ_FAMILIES, true)) {
                    return $fail("PQ required: PUF-derived suite '" . $suite['alg'] . "' is classical");
                }
                $pk = Jsx::get($enr, 'publicKey');
                $pq = Pca::resolvePqVerifyKey('', null, ['trustedPk' => is_string($pk) ? $pk : null]);
                $keys = ['edPub' => $pk instanceof Undef ? null : $pk];
                if ($pq !== null) {
                    $keys['pq'] = $pq;
                }
                $message = self::statementMessage($st->without('sig', 'pq_sig'));
                if (!Pca::verifyWithSuite($suite['alg'], $keys, $message, ['sig' => $st->get('sig'), 'pq_sig' => $st->get('pq_sig')])) {
                    return $fail('PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)');
                }
                $expected = Jsx::get($input, 'expected');
                if (!Jsx::truthy($expected)) {
                    return $fail('no expected attestation binding supplied');
                }
                try {
                    $want = Attestation::bindingB64u($expected);
                } catch (\Throwable $e) {
                    return $fail('binding not constructible: ' . ($e->getMessage() === '' ? 'invalid' : $e->getMessage()));
                }
                $b = $st->get('binding');
                if (!is_string($b) || $b !== $want) {
                    return $fail('PUF statement binding mismatch (holder/grant/epoch/nonce)');
                }
                if (!in_array($st->get('measurement'), $ms, true)) {
                    return $fail('measurement not in policy allowlist');
                }
                if ($weights !== null && $weights !== [] && (!is_string($st->get('weights_digest')) || !in_array($st->get('weights_digest'), $weights, true))) {
                    return $fail('measured weights digest not in policy allowlist');
                }
                return ['ok' => true, 'bound' => true, 'measured' => is_callable($derive) ? $derive($st, $enr) : self::defaultIdentity($st),
                    'hostAsserted' => Obj::of(['provider_id' => $pid, 'suite' => $suite['alg']])];
            } catch (\Throwable $e) {
                return $fail('puf verification error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()));
            }
        };
    }
}
