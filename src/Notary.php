<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Grants.php';
require_once __DIR__ . '/Jsx.php';

/**
 * External-fact attestation for proof-carrying actions: a notary witnesses one HTTP request/response and signs a canonical record
 * of it; the response body is committed as a salted Merkle tree so one field can be disclosed while the rest stay hidden, and the
 * disclosure is bound to a PCActn (the reference's pca-notary). Trust boundary: a trusted or semi-trusted notary (NOT trustless
 * zkTLS). Everything fails closed. Keys: a notary key is `Obj|array{publicKey, secretKey}` (raw bytes as {@see Bytes} or PHP strings;
 * a 32-byte secret is a seed) and a public key is a base64url string, {@see Bytes}, or such a pair.
 */
final class Notary
{
    public const BODY_COMMIT_ALG = 'salted-merkle-sha256-v1';
    public const NOTARY_DOMAIN = "atlas-pca/notary/v1\0";
    public const ATTESTED_FACT_CAVEAT = 'attested_fact';

    private static function safeInteger(mixed $v): bool
    {
        return K3Sig::anySafeInt($v);
    }

    private static function finite(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f);
    }

    private static function canonicalEqual(mixed $a, mixed $b): bool
    {
        try {
            return Pca::hashCanonical($a) === Pca::hashCanonical($b);
        } catch (\Throwable) {
            return false;
        }
    }

    /** @return list<mixed> */
    private static function normalizePath(mixed $path): array
    {
        if (is_string($path)) {
            return [$path];
        }
        if (is_array($path) && array_is_list($path)) {
            return $path;
        }
        throw new \TypeError('path must be a string or an array');
    }

    /** @return list<Obj> */
    private static function flatten(mixed $value, array $prefix): array
    {
        if (is_array($value) && array_is_list($value)) {
            if ($value === []) {
                return [Obj::of(['path' => $prefix, 'value' => []])];
            }
            $out = [];
            foreach ($value as $i => $x) {
                array_push($out, ...self::flatten($x, [...$prefix, $i]));
            }
            return $out;
        }
        if ($value instanceof Obj) {
            $keys = $value->keys();
            usort($keys, static fn(string $a, string $b): int => strcmp($a, $b)); // UTF-8 byte order
            if ($keys === []) {
                return [Obj::of(['path' => $prefix, 'value' => new Obj()])];
            }
            $out = [];
            foreach ($keys as $k) {
                array_push($out, ...self::flatten($value->get($k), [...$prefix, $k]));
            }
            return $out;
        }
        return [Obj::of(['path' => $prefix, 'value' => $value])];
    }

    /** @return list<Obj> */
    private static function chunkString(string $s, float $size): array
    {
        $chars = preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if ($chars === []) {
            return [Obj::of(['path' => ['#chunk', 0], 'value' => ''])];
        }
        $step = is_infinite($size) ? count($chars) : (int)$size;
        $out = [];
        foreach (array_chunk($chars, $step) as $idx => $c) {
            $out[] = Obj::of(['path' => ['#chunk', $idx], 'value' => implode('', $c)]);
        }
        return $out;
    }

    private static function leafObject(mixed $path, mixed $value, mixed $salt): Obj
    {
        return Obj::of(['p' => $path, 'v' => $value, 's' => $salt]);
    }

    private static function headersDigest(mixed $headers): string
    {
        $norm = new Obj();
        if ($headers instanceof Obj) {
            foreach ($headers->keys() as $k) {
                $norm->set(mb_strtolower($k), $headers->get($k));
            }
        }
        return Pca::hashCanonical($norm);
    }

    /** A public key as base64url: a b64u string, raw bytes ({@see Bytes}), or a key pair `{publicKey}`. */
    public static function toPubB64u(mixed $key): string
    {
        if (is_string($key)) {
            return $key;
        }
        if ($key instanceof Bytes) {
            return Pca::b64u($key->raw);
        }
        $pk = Js::opt($key, 'publicKey');
        if ($pk !== null && ($key instanceof Obj || is_array($key))) {
            $raw = Bytes::of($pk);
            if ($raw !== null) {
                return Pca::b64u($raw);
            }
        }
        throw new \TypeError('not a public key');
    }

    // ---- attestation --------------------------------------------------------------------------------------------------

    /** The bytes the notary signs: `NOTARY_DOMAIN || sha256(canonical(session))`. */
    public static function notaryMessage(mixed $session): string
    {
        return self::NOTARY_DOMAIN . hash('sha256', Json::canonicalizeNative($session), true);
    }

    private static function sign(string $secret, string $msg): string
    {
        if (strlen($secret) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            $secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($secret));
        }
        return sodium_crypto_sign_detached($msg, $secret);
    }

    /**
     * Witness a request/response: the signed attestation plus the prover's private witness (the per-leaf openings).
     *
     * @param ?callable(int):string $randomBytes
     * @return Obj `{attestation, witness}`
     */
    public static function notarizeResponse(mixed $request, mixed $response, mixed $notaryKey, mixed $observedAt = null, mixed $textChunkSize = null, ?callable $randomBytes = null): Obj
    {
        $randomBytes ??= random_bytes(...);
        if (!($request instanceof Obj) || !is_string($request->get('method')) || $request->get('method') === '') {
            throw new \TypeError('notarizeResponse: request.method is required');
        }
        if (!is_string($request->get('url')) || $request->get('url') === '') {
            throw new \TypeError('notarizeResponse: request.url is required');
        }
        if (!($response instanceof Obj) || !self::safeInteger($response->get('status'))) {
            throw new \TypeError('notarizeResponse: response.status must be an integer');
        }
        $body = $response->get('body');
        $size = Js::isNum($textChunkSize) ? Js::num($textChunkSize) : null;
        $bare = is_string($body) && $size !== null && $size >= 1 ? self::chunkString($body, is_infinite($size) ? $size : floor($size)) : self::flatten($body, []);
        $leaves = [];
        foreach ($bare as $l) {
            $leaves[] = Obj::of(['path' => $l->get('path'), 'value' => $l->get('value'), 'salt' => Pca::b64u($randomBytes(16))]);
        }
        $root = Pca::merkleRoot(array_map(static fn(Obj $l) => self::leafObject($l->get('path'), $l->get('value'), $l->get('salt')), $leaves));
        $session = Obj::of([
            'v' => 1, 'method' => mb_strtoupper($request->get('method')), 'url' => $request->get('url'),
            'requestHeadersDigest' => self::headersDigest($request->get('headers')), 'responseStatus' => $response->get('status'),
            'responseBodyCommit' => Obj::of(['alg' => self::BODY_COMMIT_ALG, 'root' => $root, 'size' => count($leaves)]),
            'observedAt' => $observedAt ?? self::clockMs(),
        ]);
        $pub = Bytes::of(Js::opt($notaryKey, 'publicKey'));
        $sec = Bytes::of(Js::opt($notaryKey, 'secretKey'));
        if ($pub === null || $sec === null) {
            throw new \TypeError('notarizeResponse: a notary key pair is required');
        }
        $att = Obj::of(['session' => $session, 'notary' => Pca::b64u($pub), 'sig' => Pca::b64u(self::sign($sec, self::notaryMessage($session)))]);
        return Obj::of(['attestation' => $att, 'witness' => Obj::of(['session' => $session, 'leaves' => $leaves])]);
    }

    /** Reveal ONE response field (by path) with its Merkle inclusion proof. Throws if the path names no committed leaf. */
    public static function discloseField(mixed $attestation, mixed $witness, mixed $path): Obj
    {
        $want = self::normalizePath($path);
        $leaves = $witness->get('leaves');
        if (!is_array($leaves)) { // witness.leaves.findIndex(...) in the reference: an engine TypeError when the witness carries no leaf list
            throw new \TypeError($leaves === null ? "Cannot read properties of undefined (reading 'findIndex')" : 'witness.leaves.findIndex is not a function');
        }
        $idx = -1;
        foreach ($leaves as $i => $l) {
            if (self::canonicalEqual($l->get('path'), $want)) {
                $idx = $i;
                break;
            }
        }
        if ($idx < 0) {
            throw new \InvalidArgumentException('discloseField: no committed field at path');
        }
        $leaf = $leaves[$idx];
        $proof = Grants::merkleProof(array_map(static fn(Obj $l) => self::leafObject($l->get('path'), $l->get('value'), $l->get('salt')), $leaves), $idx);
        return Obj::of(['path' => $leaf->get('path'), 'value' => $leaf->get('value'), 'salt' => $leaf->get('salt'), 'proof' => $proof]);
    }

    // ---- verification (fail closed) -----------------------------------------------------------------------------------

    private static function validCommit(mixed $c): bool
    {
        return $c instanceof Obj && $c->get('alg') === self::BODY_COMMIT_ALG && is_string($c->get('root')) && Pca::unb64u($c->get('root'), 32) !== null
            && self::safeInteger($c->get('size')) && (float)K3Sig::num($c->get('size')) >= 1;
    }

    private static function validSession(mixed $s): bool
    {
        return $s instanceof Obj && K3Sig::isNumber($s->get('v'), 1.0) && is_string($s->get('method')) && is_string($s->get('url'))
            && is_string($s->get('requestHeadersDigest'))
            && self::safeInteger($s->get('responseStatus')) && !K3Sig::isNegZero($s->get('responseStatus'))
            && self::safeInteger($s->get('observedAt')) && !K3Sig::isNegZero($s->get('observedAt'))
            && self::validCommit($s->get('responseBodyCommit'));
    }

    /** The attestation is structurally valid, signed by the TRUSTED notary key, and the signature verifies. */
    public static function verifyNotaryAttestation(mixed $attestation, mixed $notaryKey): bool
    {
        try {
            if (!($attestation instanceof Obj) || !self::validSession($attestation->get('session'))) {
                return false;
            }
            if (!is_string($attestation->get('notary')) || !is_string($attestation->get('sig'))) {
                return false;
            }
            if ($attestation->get('notary') !== self::toPubB64u($notaryKey)) {
                return false;
            }
            return Pca::verifyEd25519B64u($attestation->get('notary'), self::notaryMessage($attestation->get('session')), $attestation->get('sig'));
        } catch (\Throwable) {
            return false;
        }
    }

    /** The attestation is authentic AND the disclosed leaf is included under the attested body root. */
    public static function verifyDisclosedField(mixed $attestation, mixed $disclosure, mixed $notaryKey): bool
    {
        try {
            if (!self::verifyNotaryAttestation($attestation, $notaryKey)) {
                return false;
            }
            if (!($disclosure instanceof Obj) || !K3Sig::isList($disclosure->get('path')) || !is_string($disclosure->get('salt'))) {
                return false;
            }
            $proof = $disclosure->get('proof');
            if (!($proof instanceof Obj) || !K3Sig::isList($proof->get('path'))) {
                return false;
            }
            $commit = $attestation->get('session')->get('responseBodyCommit');
            $ps = K3Sig::num($proof->get('size'));
            if (!Js::isNum($proof->get('size')) || $ps === null || $ps !== K3Sig::num($commit->get('size'))) {
                return false;
            }
            return Pca::verifyInclusion($commit->get('root'), $proof, self::leafObject($disclosure->get('path'), $disclosure->get('value'), $disclosure->get('salt')));
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- PCA binding --------------------------------------------------------------------------------------------------

    /** A stable digest of the attested fact (independent of any PCActn binding). */
    public static function factRef(mixed $attestation): string
    {
        return Pca::hashCanonical(Obj::of(['fact' => 'atlas-pca-notary/v1', 'session' => Jsx::rd($attestation, 'session'), 'notary' => Jsx::rd($attestation, 'notary'), 'sig' => Jsx::rd($attestation, 'sig')]));
    }

    /** A new attestation stamped with the digest of the PCActn the fact is FOR. */
    public static function bindFactToPcActn(mixed $attestation, mixed $pcActn): Obj
    {
        $o = Jsx::spread($attestation);
        $o->set('fact_binding', Obj::of(['pcactn_digest' => Pca::hashCanonical($pcActn)]));
        return $o;
    }

    /** Bound in BOTH directions: the fact names the action AND the action's provenance.trusted_refs commits to the fact. */
    public static function factMatchesPcActn(mixed $attestation, mixed $pcActn): bool
    {
        try {
            $binding = $attestation->get('fact_binding');
            if (!($binding instanceof Obj) || !is_string($binding->get('pcactn_digest'))) {
                return false;
            }
            if ($binding->get('pcactn_digest') !== Pca::hashCanonical($pcActn)) {
                return false;
            }
            $prov = $pcActn->get('provenance');
            $refs = $prov instanceof Obj ? $prov->get('trusted_refs') : null;
            return K3Sig::isList($refs) && in_array(self::factRef($attestation), $refs, true);
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- policy caveat ------------------------------------------------------------------------------------------------

    /** @param array{url?:mixed, bindToPcActn?:mixed} $opt members present in the array are set (absent = not set) */
    public static function requireAttestedFact(mixed $notary, mixed $path, mixed $equals, array $opt = []): Obj
    {
        if (!(is_array($path) && array_is_list($path))) {
            throw new \TypeError('requireAttestedFact: path must be an array of segments');
        }
        $cv = Obj::of(['type' => self::ATTESTED_FACT_CAVEAT, 'notary' => self::toPubB64u($notary), 'path' => Jsx::iter($path), 'equals' => $equals]);
        foreach (['url', 'bindToPcActn'] as $k) {
            if (array_key_exists($k, $opt)) {
                $cv->set($k, $opt[$k]);
            }
        }
        return $cv;
    }

    /** `$key` is listed in `$ring`, not revoked, and `$observedAt` lies in its [notBefore, notAfter) window. */
    public static function notaryKeyUsable(mixed $ring, mixed $key, mixed $observedAt): bool
    {
        if (!K3Sig::isList($ring) || !self::safeInteger($observedAt)) {
            return false;
        }
        $entries = array_values(array_filter($ring, static fn($e): bool => $e instanceof Obj && $e->has('key') && AnalyzerJs::strictEq($e->get('key'), $key)));
        if ($entries === []) {
            return false;
        }
        $obs = (float)K3Sig::num($observedAt);
        $inWindow = false;
        foreach ($entries as $e) {
            if ($e->get('revoked') === true) {
                return false;
            }
            $inWindow = $inWindow || ((!$e->has('notBefore') || $obs >= Jsx::toNum($e->get('notBefore'))) && (!$e->has('notAfter') || $obs < Jsx::toNum($e->get('notAfter'))));
        }
        return $inWindow;
    }

    /**
     * Admit an action only when the notarized field verifies and satisfies the caveat; every step fails closed.
     *
     * @param list<mixed> $policyArg `[]` = no policy argument, `[policy]` = given (a present null is refused)
     * @return array<string,mixed>
     */
    public static function evaluateAttestedFactCaveat(mixed $caveat, mixed $evidence, array $policyArg = [], ?int $now = null): array
    {
        try {
            if (!($caveat instanceof Obj) || $caveat->get('type') !== self::ATTESTED_FACT_CAVEAT) {
                return ['ok' => false, 'reason' => 'not an attested_fact caveat'];
            }
            if (!is_string($caveat->get('notary')) || !K3Sig::isList($caveat->get('path'))) {
                return ['ok' => false, 'reason' => 'caveat is malformed (notary/path)'];
            }
            if ($evidence === null) {
                throw new \TypeError('evidence is required');
            }
            $ev = $evidence instanceof Obj ? $evidence : new Obj();
            $attestation = $ev->get('attestation');
            $disclosure = $ev->get('disclosure');
            $pcActn = $ev->get('pcActn');
            $pol = $policyArg === [] ? new Obj() : $policyArg[0];
            if ($pol === null) {
                throw new \TypeError('policy is null');
            }
            if (!($pol instanceof Obj)) {
                $pol = new Obj();
            }
            if (!self::verifyNotaryAttestation($attestation, $caveat->get('notary'))) {
                return ['ok' => false, 'reason' => 'notary attestation does not verify (fail closed)'];
            }
            $obsAt = $attestation->get('session')->get('observedAt');
            if ($pol->has('keyring') && !self::notaryKeyUsable($pol->get('keyring'), $attestation->get('notary'), $obsAt)) {
                return ['ok' => false, 'reason' => 'notary key is not trusted for this observation time (unlisted, revoked or out of window)'];
            }
            if ($pol->has('maxAgeMs')) {
                $clock = $pol->get('now') ?? $now ?? self::clockMs();
                if (!self::finite($pol->get('maxAgeMs')) || !self::finite($clock)) {
                    return ['ok' => false, 'reason' => 'attestation is stale or from the future'];
                }
                $age = (float)Js::num($clock) - (float)Js::num($obsAt);
                if (!(is_finite($age) && $age >= 0 && $age <= (float)Js::num($pol->get('maxAgeMs')))) {
                    return ['ok' => false, 'reason' => 'attestation is stale or from the future'];
                }
            }
            if ($caveat->has('url') && $attestation->get('session')->get('url') !== $caveat->get('url')) {
                return ['ok' => false, 'reason' => 'attested session URL does not match the caveat'];
            }
            if (!self::verifyDisclosedField($attestation, $disclosure, $caveat->get('notary'))) {
                return ['ok' => false, 'reason' => 'disclosed field does not verify under the attested root'];
            }
            if (!self::canonicalEqual($disclosure->get('path'), $caveat->get('path'))) {
                return ['ok' => false, 'reason' => 'disclosed field is not the path the caveat requires'];
            }
            if (!$caveat->has('equals') || !self::canonicalEqual($disclosure->get('value'), $caveat->get('equals'))) {
                return ['ok' => false, 'reason' => 'disclosed field value does not satisfy the caveat'];
            }
            if (Js::truthy($caveat->get('bindToPcActn'))) {
                if (!Js::truthy($pcActn)) {
                    return ['ok' => false, 'reason' => 'caveat requires PCActn binding but no PCActn was supplied'];
                }
                if (!self::factMatchesPcActn($attestation, $pcActn)) {
                    return ['ok' => false, 'reason' => 'fact is not bound to this PCActn'];
                }
            }
            return ['ok' => true, 'trust' => 'notary-trusted'];
        } catch (\Throwable $e) { // fail closed
            return ['ok' => false, 'reason' => 'attested_fact evaluation error (fail closed): ' . ($e->getMessage() !== '' ? $e->getMessage() : 'unknown')];
        }
    }

    public static function isAttestedFactCaveat(mixed $cv): bool
    {
        return $cv instanceof Obj && $cv->get('type') === self::ATTESTED_FACT_CAVEAT && is_string($cv->get('notary')) && K3Sig::isList($cv->get('path'));
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    /** The wall clock in whole epoch milliseconds (Date.now() of the reference). */
    private static function clockMs(): int
    {
        return (int)((self::$clockHook !== null ? (self::$clockHook)() : microtime(true)) * 1000);
    }
}
