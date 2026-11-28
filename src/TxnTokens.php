<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Jose.php';

/** A verifier configured without a required security component (code 'replay_store_required'). */
final class TxnTokenError extends \InvalidArgumentException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * OAuth Transaction Tokens as a chain-of-custody PROFILE of a PCA capability chain: the chain projected into the RFC 8693
 * nested `sub` / `act` idiom, carried with the action (`tctx`) in an EdDSA Transaction Token (draft-ietf-oauth-transaction-
 * tokens-11 by default, or the legacy shape). The token is the interop envelope, never the credential: the PCActn's signed
 * chain stays the authority. Mirrors @atlasauth/pca-txn-tokens. Options are an Obj or an assoc array with the reference's
 * camelCase names.
 */
final class TxnTokens
{
    public const TXN_TOKEN_TYP = 'txn_token+jwt';
    public const TXN_TOKEN_TYP_DRAFT_11 = 'txntoken+jwt';
    public const DEFAULT_TTL_SEC = 120;
    public const MAX_TOKEN_CHARS = 16384;
    private const PCA_ACTION_KEYS = ['verb', 'resource', 'aud'];

    private static function nonEmpty(mixed $s): bool
    {
        return is_string($s) && $s !== '';
    }

    /** RFC 8693 section 4.1 nesting, descending the chain: sub = root issuer, then one `act` level per hop holder. */
    public static function subActChain(mixed $chain): array
    {
        if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
            throw new \TypeError('subActChain: chain must be a non-empty CapabilityChain');
        }
        $act = null;
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            $holder = Js::opt($chain[$i], 'holder');
            if (!self::nonEmpty($holder)) {
                throw new \TypeError("subActChain: hop $i has no holder");
            }
            $act = $act === null ? ['sub' => $holder] : ['sub' => $holder, 'act' => $act];
        }
        $iss = Js::opt($chain[0], 'issuer');
        if (!self::nonEmpty($iss)) {
            throw new \TypeError('subActChain: root hop has no issuer (principal)');
        }
        return ['sub' => $iss, 'act' => $act];
    }

    /** The number of nested `act` levels. */
    public static function actDepth(mixed $claim): int
    {
        if (!($claim instanceof Obj) && !is_array($claim)) {
            throw new \TypeError('actDepth: expected a sub/act claim object');
        }
        $depth = 0;
        for ($cur = Js::opt($claim, 'act'); Js::truthy($cur); $cur = Js::opt($cur, 'act')) {
            $depth++;
        }
        return $depth;
    }

    /** The RFC 8693 order of an `act` chain (most recent actor outermost); `sub` unchanged. */
    public static function toRfc8693Act(mixed $claim): array|Obj
    {
        if ($claim === null) {
            throw new \TypeError('toRfc8693Act: claim is null');
        }
        $actors = [];
        for ($c = Js::opt($claim, 'act'); Js::truthy($c); $c = Js::opt($c, 'act')) {
            $actors[] = Js::opt($c, 'sub');
        }
        $act = null;
        foreach ($actors as $s) {
            $n = [];
            if ($s !== null) {
                $n['sub'] = $s;
            }
            if ($act !== null) {
                $n['act'] = $act;
            }
            $act = $n === [] ? new Obj() : $n;
        }
        $out = [];
        if (Js::opt($claim, 'sub') !== null) {
            $out['sub'] = Js::opt($claim, 'sub');
        }
        if ($act !== null) {
            $out['act'] = $act;
        }
        return $out === [] ? new Obj() : $out;
    }

    private static function uuid4(): string
    {
        $b = self::randomBytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    private static function draft(mixed $profile, string $fn): bool
    {
        if ($profile !== null && $profile !== 'legacy' && $profile !== 'draft-11') {
            throw new \TypeError("$fn: profile must be legacy or draft-11");
        }
        return ($profile ?? 'draft-11') === 'draft-11';
    }

    /**
     * Mint a signed Transaction Token. Options: chain, action {verb, resource, aud}, issuer, issuerKey (32-byte Ed25519 seed or
     * an Ed25519 private JWK), profile ('draft-11' default | 'legacy'), scope, reqWl, txn, trustDomain, ttlSec.
     */
    public static function toTransactionToken(mixed $a): string
    {
        $issuer = Js::opt($a, 'issuer');
        $action = Js::opt($a, 'action');
        if (!self::nonEmpty($issuer)) {
            throw new \TypeError('toTransactionToken: `issuer` is required');
        }
        foreach (self::PCA_ACTION_KEYS as $k) {
            if (!is_string(Js::opt($action, $k))) {
                throw new \TypeError('toTransactionToken: `action` must have string verb, resource and aud');
            }
        }
        $custody = self::subActChain(Js::opt($a, 'chain'));
        $ttl = Js::opt($a, 'ttlSec') ?? self::DEFAULT_TTL_SEC;
        $t = Js::num($ttl);
        if ($t === null || !is_finite($t) || $t <= 0) {
            throw new \InvalidArgumentException('toTransactionToken: ttlSec must be > 0');
        }
        $now = self::now();
        $key = Js::opt($a, 'issuerKey');
        if (is_string($key) && strlen($key) !== 32) {
            throw new \TypeError('toTransactionToken: a raw Ed25519 secret key must be 32 bytes');
        }
        $draft = self::draft(Js::opt($a, 'profile'), 'toTransactionToken');
        $tctx = Obj::of(['verb' => Js::opt($action, 'verb'), 'resource' => Js::opt($action, 'resource'), 'aud' => Js::opt($action, 'aud')]);
        $claims = new Obj();
        $claims->set('tctx', $tctx);
        if ($custody['act'] !== null) {
            $claims->set('act', $custody['act']);
        }
        $exp = $now + (is_int($ttl) ? $ttl : ($ttl instanceof Num && $ttl->isInt() ? $ttl->int() : $t));
        if ($draft) {
            if (!self::nonEmpty(Js::opt($a, 'scope'))) {
                throw new \TypeError('toTransactionToken: draft-11 requires `scope`');
            }
            if (!self::nonEmpty(Js::opt($a, 'reqWl'))) {
                throw new \TypeError('toTransactionToken: draft-11 requires `reqWl`');
            }
            $td = Js::opt($a, 'trustDomain') ?? Js::opt($action, 'aud');
            if (!self::nonEmpty($td)) {
                throw new \TypeError('toTransactionToken: draft-11 requires a non-empty trust domain (aud)');
            }
            foreach (['txn' => Js::opt($a, 'txn') ?? self::uuid4(), 'scope' => Js::opt($a, 'scope'), 'req_wl' => Js::opt($a, 'reqWl'),
                'iat' => $now, 'iss' => $issuer, 'sub' => $custody['sub'], 'aud' => $td, 'exp' => $exp] as $k => $v) {
                $claims->set($k, $v);
            }
            return Jose::signJwt($claims, ['alg' => 'EdDSA', 'typ' => self::TXN_TOKEN_TYP_DRAFT_11], $key);
        }
        foreach (['iat' => $now, 'iss' => $issuer, 'sub' => $custody['sub'], 'aud' => Js::opt($action, 'aud'), 'exp' => $exp, 'jti' => self::uuid4()] as $k => $v) {
            $claims->set($k, $v);
        }
        return Jose::signJwt($claims, ['alg' => 'EdDSA', 'typ' => self::TXN_TOKEN_TYP], $key);
    }

    private static function normalizeAct(mixed $node, bool $present): ?array
    {
        if (!$present) {
            return null;
        }
        if (!($node instanceof Obj)) {
            throw new \InvalidArgumentException('transaction token: malformed `act` claim');
        }
        if (!self::nonEmpty($node->get('sub'))) {
            throw new \InvalidArgumentException('transaction token: `act.sub` must be a non-empty string');
        }
        $inner = self::normalizeAct($node->get('act'), $node->has('act'));
        return $inner === null ? ['sub' => $node->get('sub')] : ['sub' => $node->get('sub'), 'act' => $inner];
    }

    /**
     * Verify a Transaction Token and return {chain, action?, tctx, claims}. Options: profile, audience, clockToleranceSec,
     * nowMs, seenTxn (callable(string $id, mixed $exp): bool, true when already seen), replayCheck ('unchecked').
     * Throws on any refusal; the replay identifier is consumed last, so a token refused for another reason never burns it.
     */
    public static function fromTransactionToken(mixed $jwt, mixed $verifyKey, mixed $o = null): array
    {
        $draft = self::draft(Js::opt($o, 'profile'), 'fromTransactionToken');
        $audience = Js::opt($o, 'audience');
        if ($draft && !self::nonEmpty($audience)) {
            throw new \TypeError('fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)');
        }
        $seen = Js::opt($o, 'seenTxn');
        if (!is_callable($seen) && Js::opt($o, 'replayCheck') !== 'unchecked') {
            throw new TxnTokenError('replay_store_required', "fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'");
        }
        if (is_string($jwt) && Js::len($jwt) > self::MAX_TOKEN_CHARS) {
            throw new \InvalidArgumentException('transaction token: token exceeds the size limit');
        }
        Jose::assertCanonicalCompactJws($jwt);
        if (is_string($verifyKey) && strlen($verifyKey) !== 32) {
            throw new \TypeError('fromTransactionToken: a raw Ed25519 public key must be 32 bytes');
        }
        $opts = [
            'algorithms' => ['EdDSA'], 'typ' => $draft ? self::TXN_TOKEN_TYP_DRAFT_11 : self::TXN_TOKEN_TYP,
            'requiredClaims' => $draft ? ['iat', 'exp', 'aud', 'sub', 'txn', 'scope', 'req_wl'] : ['exp'],
        ];
        if ($audience !== null) {
            $opts['audience'] = $audience;
        }
        if (Js::opt($o, 'clockToleranceSec') !== null) {
            $opts['clockTolerance'] = Js::opt($o, 'clockToleranceSec');
        }
        if (Js::opt($o, 'nowMs') !== null) {
            $opts['nowMs'] = Js::opt($o, 'nowMs');
        }
        [$payload] = Jose::jwtVerify($jwt, $verifyKey, $opts);
        if ($draft) {
            foreach (['txn', 'scope', 'req_wl'] as $k) {
                if (!self::nonEmpty($payload->get($k))) {
                    throw new \InvalidArgumentException("transaction token: `$k` must be a non-empty string");
                }
            }
        }
        $sub = $payload->get('sub');
        if (!self::nonEmpty($sub)) {
            throw new \InvalidArgumentException('transaction token: missing `sub` (root principal)');
        }
        $raw = $payload->get('tctx');
        if (!($raw instanceof Obj)) {
            throw new \InvalidArgumentException('transaction token: missing or malformed `tctx`');
        }
        $action = null;
        if (!$draft || array_intersect(self::PCA_ACTION_KEYS, $raw->keys()) !== []) {
            $action = new Obj();
            foreach (self::PCA_ACTION_KEYS as $k) {
                if (!is_string($raw->get($k))) {
                    throw new \InvalidArgumentException('transaction token: missing or malformed `tctx`');
                }
                $action->set($k, $raw->get($k));
            }
        }
        if ($draft && $payload->has('rctx') && !($payload->get('rctx') instanceof Obj)) {
            throw new \InvalidArgumentException('transaction token: malformed `rctx`');
        }
        $act = self::normalizeAct($payload->get('act'), $payload->has('act'));
        if (is_callable($seen)) {
            $id = $draft ? $payload->get('txn') : $payload->get('jti');
            if (!self::nonEmpty($id)) {
                throw new \InvalidArgumentException('transaction token: no transaction identifier to check for replay');
            }
            if ($seen($id, $payload->get('exp'))) {
                throw new \InvalidArgumentException('transaction token: replayed (transaction identifier already seen)');
            }
        }
        $out = ['chain' => $act === null ? ['sub' => $sub] : ['sub' => $sub, 'act' => $act]];
        if ($action !== null) {
            $out['action'] = $action;
        }
        $out['tctx'] = $raw;
        $out['claims'] = $payload;
        return $out;
    }

    /** @internal Test seams: when set, the clock (epoch seconds, as time()) and the random source (as random_bytes) are read from them. */
    public static ?\Closure $clockHook = null;
    public static ?\Closure $randomHook = null;

    private static function now(): int
    {
        return self::$clockHook !== null ? (self::$clockHook)() : time();
    }

    private static function randomBytes(int $n): string
    {
        return self::$randomHook !== null ? (self::$randomHook)($n) : random_bytes($n);
    }
}
