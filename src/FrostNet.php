<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/FrostPq.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';

/** Two different messages from one signer for the same (session, round): the fields name the offender and both digests. */
final class EquivocationError extends \RuntimeException
{
    public function __construct(public readonly string $sessionId, public readonly int $round, public readonly int $identifier, public readonly string $previousDigest,
        public readonly string $offendingDigest)
    {
        parent::__construct("equivocation: signer $identifier sent two different messages for session '$sessionId' round $round");
    }
}

/** Refuses a second DIFFERENT message from one signer for the same (session, round, identifier); an identical repeat is idempotent. */
final class EquivocationGuard
{
    /** @var array<string,string> */
    private array $seen = [];

    private static function posInt(mixed $x): ?int
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0 ? (int)$f : null;
    }

    public function observe(mixed $sessionId, mixed $round, mixed $identifier, mixed $message): void
    {
        if (!is_string($sessionId) || $sessionId === '') {
            throw new \RuntimeException('EquivocationGuard: session_id must be a non-empty string');
        }
        $r = self::posInt($round);
        if ($r === null || $r < 1) {
            throw new \RuntimeException('EquivocationGuard: round must be a positive integer');
        }
        $id = self::posInt($identifier);
        if ($id === null || $id <= 0) {
            throw new \RuntimeException('EquivocationGuard: identifier must be a positive integer');
        }
        $key = "$sessionId\0$r\0$id";
        $digest = Pca::b64u(hash('sha256', Json::canonicalizeNative($message), true));
        $prev = $this->seen[$key] ?? null;
        if ($prev === null) {
            $this->seen[$key] = $digest;
            return;
        }
        if ($prev !== $digest) {
            throw new EquivocationError($sessionId, $r, $id, $prev, $digest);
        }
    }

    /** Drop the memory of a finished session. */
    public function forget(string $sessionId): void
    {
        foreach (array_keys($this->seen) as $k) {
            if (str_starts_with((string)$k, "$sessionId\0")) {
                unset($this->seen[$k]);
            }
        }
    }
}

/**
 * Networked FROST signing, the verification half that needs no signer state: the allow token a policy authority signs for one action and one group key, the
 * equivocation guard and the strict decoders of the wire commitments and verification shares.
 */
final class FrostNet
{
    public const ALLOW_TOKEN_TYP = 'pca.frost.allow.v1';
    public const SIGNER_POP_DST = 'pca.frost.signer-pop.v1';
    public const MAX_FROST_SIGNING_SET = 256;

    /** base64url(sha256(message)): the action a token authorizes. Throws unless `$message` is bytes (a string). */
    public static function frostActionDigest(mixed $message): string
    {
        if (!is_string($message)) {
            throw new \TypeError('frostActionDigest: message must be bytes');
        }
        return Pca::b64u(hash('sha256', $message, true));
    }

    /**
     * The policy authority's allow token `{body: {typ, action_digest, group_pk, nonce, not_before?, expires_at?}, authority, sig}`. `$opts`: `message?` (bytes) or
     * `frostActionDigest?`, `groupPublicKey` (raw), `nonce?` (random when absent), `notBefore?`, `expiresAt?`. Throws without a message or digest.
     * @param string $policySecretKey the 32-byte Ed25519 seed
     * @param ?\Closure $random returns the 32 bytes of a default nonce (a test seam; random_bytes when absent)
     */
    public static function issueAllowToken(string $policySecretKey, mixed $opts, ?\Closure $random = null): Obj
    {
        $fad = Jsx::get($opts, 'frostActionDigest');
        $msg = Jsx::get($opts, 'message');
        $digest = !($fad instanceof Undef) && $fad !== null ? $fad : (Jsx::truthy($msg) || is_string($msg) ? self::frostActionDigest($msg) : null);
        if (!Jsx::truthy($digest)) {
            throw new \RuntimeException('issueAllowToken: provide message or frostActionDigest');
        }
        $gpk = Jsx::get($opts, 'groupPublicKey');
        if (!is_string($gpk)) {
            throw new \TypeError('b64u: expected bytes');
        }
        $nonce = Jsx::get($opts, 'nonce');
        $body = Obj::of(['typ' => self::ALLOW_TOKEN_TYP, 'action_digest' => $digest, 'group_pk' => Pca::b64u($gpk),
            'nonce' => $nonce instanceof Undef || $nonce === null ? Pca::b64u($random !== null ? $random() : random_bytes(32)) : $nonce]);
        foreach (['notBefore' => 'not_before', 'expiresAt' => 'expires_at'] as $in => $out) {
            $v = Jsx::get($opts, $in);
            if (!($v instanceof Undef)) {
                $body->set($out, $v);
            }
        }
        $kp = new KeyPair($policySecretKey);
        return Obj::of(['body' => $body, 'authority' => $kp->public, 'sig' => Pca::b64u($kp->sign(Json::canonicalizeNative($body)))]);
    }

    /**
     * Verify an allow token: shape, typ, a canonical signature by the trusted policy authority, the group key, the action digest of `message` and the window.
     * Never throws. `$expect`: `{policyAuthorityPublicKey, groupPublicKey, message}` (raw bytes) and `now`. @return array{ok:bool,reason?:string}
     */
    public static function verifyAllowToken(mixed $token, array $expect): array
    {
        $no = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            if (!Jsx::truthy($token) || !($token instanceof Obj || is_array($token))) {
                return $no('allow token missing or malformed');
            }
            $body = Jsx::get($token, 'body');
            if (!Jsx::truthy($body) || !($body instanceof Obj || is_array($body))) {
                return $no('allow token has no body');
            }
            $typ = Jsx::get($body, 'typ');
            if ($typ !== self::ALLOW_TOKEN_TYP) {
                return $no('allow token wrong typ (' . Jsx::str($typ) . ')');
            }
            $sig = Jsx::get($token, 'sig');
            if (!is_string($sig)) {
                return $no('allow token missing signature');
            }
            $sb = Pca::decodeB64uStrict($sig, 64);
            if ($sb === null) {
                return $no('allow token signature not canonical base64url');
            }
            $apk = $expect['policyAuthorityPublicKey'];
            if (!is_string($apk) || strlen($apk) !== 32 || !Pca::verifyEd25519B64u(Pca::b64u($apk), Json::canonicalizeNative($body), Pca::b64u($sb))) {
                return $no('allow token not signed by the trusted policy authority');
            }
            if (Jsx::get($body, 'group_pk') !== Pca::b64u($expect['groupPublicKey'])) {
                return $no('allow token authorizes a different group key');
            }
            if (Jsx::get($body, 'action_digest') !== self::frostActionDigest($expect['message'])) {
                return $no('allow token authorizes a different action digest');
            }
            $now = Js::num($expect['now']);
            if ($now === null || !is_finite($now)) {
                return $no('invalid verification time');
            }
            $nb = Jsx::get($body, 'not_before');
            if (!($nb instanceof Undef) && Jsx::lt($now, $nb)) {
                return $no('allow token not yet valid');
            }
            $ex = Jsx::get($body, 'expires_at');
            if (!($ex instanceof Undef) && !Jsx::lt($now, $ex) && !is_nan(Jsx::toNum($ex))) {
                return $no('allow token expired');
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return $no('allow token verification error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()));
        }
    }

    /** A member of a JSON object (Obj) or of an associative PHP array; JS `undefined` when absent. */
    private static function field(mixed $o, string $k): mixed
    {
        Jsx::init();
        return is_array($o) && !array_is_list($o) ? ($o[$k] ?? Jsx::$U) : Jsx::get($o, $k);
    }

    private static function wireId(mixed $x): ?int
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0 && $f > 0 ? (int)$f : null;
    }

    /** A wire commitment `{identifier, hiding, binding}` as `{identifier, hiding, binding}` with the two 32-byte encodings decoded. Throws on any deviation. */
    public static function decodeCommitment(mixed $w): array
    {
        if (!Jsx::truthy($w) || !($w instanceof Obj || is_array($w))) {
            throw new \RuntimeException('bad commitment');
        }
        $hiding = Pca::decodeB64uStrict(Jsx::get($w, 'hiding'), 32);
        $binding = Pca::decodeB64uStrict(Jsx::get($w, 'binding'), 32);
        $id = self::wireId(Jsx::get($w, 'identifier'));
        if ($id === null) {
            throw new \RuntimeException('bad commitment identifier');
        }
        if ($hiding === null || $binding === null) {
            throw new \RuntimeException('bad commitment point encoding');
        }
        return ['identifier' => $id, 'hiding' => $hiding, 'binding' => $binding];
    }

    /** @return list<array{identifier:int,hiding:string,binding:string}> */
    public static function decodeCommitments(mixed $list): array
    {
        if (!is_array($list) || !array_is_list($list)) {
            throw new \RuntimeException('commitments must be a list');
        }
        if (count($list) > self::MAX_FROST_SIGNING_SET) {
            throw new \RuntimeException('commitments list exceeds the maximum signing set');
        }
        return array_map(self::decodeCommitment(...), $list);
    }

    /** @return list<array{identifier:int,publicKey:string}> */
    public static function decodeVerificationShares(mixed $list): array
    {
        if (!is_array($list) || !array_is_list($list)) {
            throw new \RuntimeException('verification_shares must be a list');
        }
        if (count($list) > self::MAX_FROST_SIGNING_SET) {
            throw new \RuntimeException('verification_shares list exceeds the maximum signing set');
        }
        return array_map(static function (mixed $v): array {
            if (!Jsx::truthy($v) || !($v instanceof Obj || is_array($v))) {
                throw new \RuntimeException('bad verification share');
            }
            $pk = Pca::decodeB64uStrict(Jsx::get($v, 'publicKey'), 32);
            $id = self::wireId(Jsx::get($v, 'identifier'));
            if ($id === null) {
                throw new \RuntimeException('bad verification-share identifier');
            }
            if ($pk === null) {
                throw new \RuntimeException('bad verification-share key encoding');
            }
            return ['identifier' => $id, 'publicKey' => $pk];
        }, $list);
    }

    // ---- signer proof of possession (Schnorr over Ed25519, bound to the group key and the identifier) ----------------------------

    private static function popChallenge(string $groupPublicKey, int $identifier, string $pk, string $r): string
    {
        $e = Frost::bytesToScalar(hash('sha512', self::SIGNER_POP_DST . $groupPublicKey . Frost::scalarOfId($identifier) . $pk . $r, true));
        return $e === str_repeat("\0", 32) ? Frost::scalarOfId(1) : $e;
    }

    /**
     * A proof that the signer holds the secret behind its verification share: `{identifier, publicKey, R, s}` (base64url) with s = k + e*x.
     * `$opts['nonce']` fixes k (reproducible vectors only); a missing or zero-reducing nonce draws a random one.
     * @param string $share the 32-byte secret signing share @param array{groupPublicKey:mixed,nonce?:mixed} $opts
     */
    public static function createSignerPoP(mixed $identifier, mixed $share, array $opts): Obj
    {
        $id = self::wireId($identifier);
        if ($id === null) {
            throw new \RuntimeException('createSignerPoP: identifier must be a positive integer');
        }
        if (!is_string($share) || strlen($share) !== 32) {
            throw new \RuntimeException('createSignerPoP: share must be 32 bytes');
        }
        $gpk = $opts['groupPublicKey'] ?? null;
        if (!is_string($gpk) || strlen($gpk) !== 32) {
            throw new \RuntimeException('createSignerPoP: groupPublicKey must be 32 bytes');
        }
        $x = Frost::bytesToScalar($share);
        $pk = Frost::mulBase($x);
        $nonce = $opts['nonce'] ?? null;
        $k = is_string($nonce) && $nonce !== '' ? Frost::bytesToScalar($nonce) : str_repeat("\0", 32);
        while ($k === str_repeat("\0", 32)) {
            $k = Frost::bytesToScalar(random_bytes(32));
        }
        $r = Frost::mulBase($k);
        $e = self::popChallenge($gpk, $id, $pk, $r);
        return Obj::of(['identifier' => $identifier, 'publicKey' => Pca::b64u($pk), 'R' => Pca::b64u($r), 's' => Pca::b64u(Frost::sAdd($k, Frost::sMul($e, $x)))]);
    }

    /** Verify a proof of possession: g^s = R + e*pk with a canonical s and safe points. Never throws. */
    public static function verifySignerPoP(mixed $pop, mixed $expect): bool
    {
        try {
            if (!Jsx::truthy($pop) || !($pop instanceof Obj || is_array($pop))) {
                return false;
            }
            $id = self::wireId(Jsx::get($pop, 'identifier'));
            if ($id === null) {
                return false;
            }
            $gpk = Jsx::get($expect, 'groupPublicKey');
            if (!is_string($gpk) || strlen($gpk) !== 32) {
                return false;
            }
            $pk = Pca::decodeB64uStrict(Jsx::get($pop, 'publicKey'), 32);
            $rb = Pca::decodeB64uStrict(Jsx::get($pop, 'R'), 32);
            $sb = Pca::decodeB64uStrict(Jsx::get($pop, 's'), 32);
            if ($pk === null || $rb === null || $sb === null) {
                return false;
            }
            Frost::decodeSafePoint($pk);
            Frost::decodeSafePoint($rb);
            if (!Frost::isCanonicalScalar($sb)) {
                return false;
            }
            $e = self::popChallenge($gpk, $id, $pk, $rb);
            return hash_equals(Frost::mulBase($sb), Frost::add($rb, Frost::mulPoint($pk, $e)));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Admit a signer set only with a valid proof of possession per verification share (a rogue key cannot enroll). Throws PoPError.
     * @param mixed $enrollments `[{identifier, publicKey (raw), pop}]` @return list<array{identifier:int,publicKey:string}>
     */
    public static function enrollVerificationShares(mixed $enrollments, mixed $expect): array
    {
        if (!is_array($enrollments) || !array_is_list($enrollments) || $enrollments === []) {
            throw new PoPError('enrollVerificationShares: no signer enrollments');
        }
        $gpk = Jsx::get($expect, 'groupPublicKey');
        if (!is_string($gpk) || strlen($gpk) !== 32) {
            throw new PoPError('enrollVerificationShares: groupPublicKey must be 32 bytes');
        }
        $out = [];
        $seen = [];
        foreach ($enrollments as $e) {
            $id = Jsx::truthy($e) ? self::wireId(self::field($e, 'identifier')) : null;
            if ($id === null) {
                throw new PoPError('enrollVerificationShares: enrollment with invalid identifier');
            }
            if (isset($seen[$id])) {
                throw new PoPError("enrollVerificationShares: duplicate enrollment for signer $id", $id);
            }
            $seen[$id] = true;
            $pk = self::field($e, 'publicKey');
            if (!is_string($pk) || strlen($pk) !== 32) {
                throw new PoPError("enrollVerificationShares: signer $id verification share must be 32 bytes", $id);
            }
            $pop = self::field($e, 'pop');
            $pid = Jsx::truthy($pop) ? Jsx::get($pop, 'identifier') : null;
            if (!Jsx::truthy($pop) || !Js::isNum($pid) || self::wireId($pid) !== $id || Jsx::get($pop, 'publicKey') !== Pca::b64u($pk)) {
                throw new PoPError("enrollVerificationShares: signer $id missing or mismatched proof-of-possession (rogue key rejected)", $id);
            }
            if (!self::verifySignerPoP($pop, Obj::of(['groupPublicKey' => $gpk]))) {
                throw new PoPError("enrollVerificationShares: signer $id invalid proof-of-possession (rogue key rejected)", $id);
            }
            $out[] = ['identifier' => $id, 'publicKey' => $pk];
        }
        return $out;
    }
}

/** A refused signer enrollment; carries the offending identifier when known. */
final class PoPError extends \RuntimeException
{
    public function __construct(string $message, public readonly ?int $identifier = null)
    {
        parent::__construct($message);
    }
}
