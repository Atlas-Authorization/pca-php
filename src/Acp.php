<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Payments.php';
require_once __DIR__ . '/WhatwgUrl.php';

/** A delegated payment token cannot be minted because the request exceeds the proof's authority (or the input is malformed). */
final class AcpAuthorityError extends \RuntimeException
{
}

/**
 * Agentic Commerce Protocol (ACP) and x402 for PCA: delegated one-time payment tokens minted FROM a PCActn (the proof's spend cap,
 * merchant and category allowlists and human-present requirement gate issuance), their settlement-time verification, the x402 v1
 * challenge and the injectable settle flow, x402 v2 (requirements, headers, negotiation), its HTTP transport and Stripe Shared Payment
 * Granted Tokens. Mirrors @atlasauth/pca-acp.
 *
 * Values are the parsed-JSON model (Obj, lists, strings, Num / int / float, bool, null); options accept an Obj or a PHP associative array
 * with the reference's camelCase names; results are Obj. Inputs follow JavaScript semantics where the reference does, so a hostile
 * option is refused exactly as the reference refuses it. No network is performed: the verifier, the settle step and the single-use
 * store are injected. A store is any object with `claim(string $jti, float $expiresAtMs): mixed` (only the boolean true admits), or an
 * option member holding a Closure under `claim`.
 *
 * Where the reference awaits, these functions are synchronous. A settle step that returns null yields no receipt. A token or proof
 * refused at mint throws AcpAuthorityError; x402 header and parseStripeSpt problems throw \TypeError.
 *
 * shortcut: Date handling is limited to the one conversion the reference makes (epoch ms to an ISO string, see toAcpAllowance).
 * shortcut: a settle step returning null is "no receipt" (the reference tells undefined from null apart).
 */
final class Acp
{
    public const ACP_DELEGATED_TOKEN_VERSION = 1;
    public const ACP_DELEGATED_TOKEN_TYPE = 'acp-delegated-payment';
    public const SPEND_CAP_CAVEAT = 'max_amount';
    public const MERCHANT_ALLOW_CAVEAT = 'merchant_allow';
    public const MERCHANT_CATEGORY_CAVEAT = 'merchant_category';
    public const HUMAN_PRESENT_CAVEAT = 'human_present';
    public const X402_VERSION_1 = 1;
    public const X402_VERSION_2 = 2;
    public const X402_SUPPORTED_VERSIONS = [2, 1];
    public const X402_V2_PAYMENT_REQUIRED_HEADER = 'PAYMENT-REQUIRED';
    public const X402_PAYMENT_SIGNATURE_HEADER = 'PAYMENT-SIGNATURE';
    public const X402_PAYMENT_RESPONSE_HEADER = 'PAYMENT-RESPONSE';
    public const X402_HTTP_STATUS = ['payment_required' => 402, 'malformed' => 400, 'failed' => 402, 'internal_error' => 500, 'settled' => 200];
    public const STRIPE_SPT_OBJECT = 'shared_payment.granted_token';
    /** An option that was not passed (the reference's `undefined`, distinct from null). */
    public const UNDEF = Payments::UNDEF;
    private const U = Payments::UNDEF;
    private const SPT_REASONS = ['consumed', 'expired', 'resolved', 'revoked'];

    // ---- JavaScript semantics ----------------------------------------------------------------------------------------------

    private static function p(mixed $o, string $k): mixed
    {
        return Payments::p($o, $k);
    }

    /** typeof v === 'string' (the undefined sentinel is not a string). */
    private static function isStr(mixed $v): bool
    {
        return is_string($v) && $v !== self::U;
    }

    private static function f(mixed $v): float
    {
        return (float)Js::num($v);
    }

    private static function negZero(mixed $v): bool
    {
        return Js::isNum($v) && self::f($v) === 0.0 && fdiv(1.0, self::f($v)) < 0;
    }

    /** Integer minor units: floats, NaN, zero, negatives and unsafe integers are refused. */
    private static function isAmount(mixed $v): bool
    {
        return Payments::safeInt($v) && self::f($v) > 0;
    }

    private static function isInt(mixed $v): bool
    {
        return Payments::safeInt($v) && !self::negZero($v);
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function nn(mixed $v, mixed $default): mixed
    {
        return $v === null || $v === self::U ? $default : $v;
    }

    private static function numIs(mixed $v, int $n): bool
    {
        return Js::isNum($v) && self::f($v) === (float)$n;
    }

    private static function obj(array $a): Obj
    {
        return Payments::obj($a);
    }

    /** `o.k` for an options object: a TypeError for null, UNDEF for a missing member or a non-object. */
    private static function o(mixed $o, string $k): mixed
    {
        return Payments::p($o, $k);
    }

    // ---- caveat vocabulary --------------------------------------------------------------------------------------------------

    public static function spendCapCaveat(mixed $max, mixed $currency = self::U): Obj
    {
        $o = Obj::of(['type' => self::SPEND_CAP_CAVEAT, 'max' => $max]);
        if ($currency !== self::U) {
            $o->set('currency', $currency);
        }
        return $o;
    }

    public static function merchantAllowCaveat(mixed $merchants): Obj
    {
        return Obj::of(['type' => self::MERCHANT_ALLOW_CAVEAT, 'merchants' => Payments::spread($merchants)]);
    }

    public static function merchantCategoryCaveat(mixed $categories): Obj
    {
        return Obj::of(['type' => self::MERCHANT_CATEGORY_CAVEAT, 'categories' => Payments::spread($categories)]);
    }

    public static function humanPresentCaveat(mixed $required = true): Obj
    {
        return Obj::of(['type' => self::HUMAN_PRESENT_CAVEAT, 'required' => $required]);
    }

    /** @return list<string> */
    private static function stringArray(mixed $v, string $label): array
    {
        if (!Js::isStrList($v)) {
            throw new AcpAuthorityError("malformed $label caveat: expected a string[] (fail closed)");
        }
        return $v;
    }

    /**
     * Collapse a leaf capability's cumulative caveat list into its effective payment authority: the tightest cap, intersected
     * allowlists, a sticky human-present requirement. A malformed PAYMENT caveat throws (fail closed); other caveat types are ignored.
     * @return Obj {maxAmount?, currency?, merchants: list|null, categories: list|null, humanPresentRequired}
     */
    public static function extractPaymentAuthority(mixed $caveats): Obj
    {
        if (self::isStr($caveats)) {
            $items = []; // each character has no `type`: nothing to read
        } elseif (self::isList($caveats)) {
            $items = $caveats;
        } else {
            throw new \TypeError('caveats is not iterable');
        }
        $maxAmount = self::U;
        $currency = self::U;
        $merchants = null;
        $categories = null;
        $human = false;
        foreach ($items as $c) {
            $type = self::p($c, 'type');
            if ($type === self::SPEND_CAP_CAVEAT) {
                $max = self::p($c, 'max');
                if (!Js::isNum($max) || !Payments::safeInt($max) || self::f($max) < 0 || self::negZero($max)) {
                    throw new AcpAuthorityError('malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)');
                }
                $maxAmount = $maxAmount === self::U || self::f($max) < self::f($maxAmount) ? $max : $maxAmount;
                $cur = self::p($c, 'currency');
                if ($cur !== self::U) {
                    if (!self::isStr($cur) || $cur === '') {
                        throw new AcpAuthorityError('malformed max_amount caveat: currency must be a non-empty string (fail closed)');
                    }
                    if ($currency !== self::U && $currency !== $cur) {
                        throw new AcpAuthorityError("conflicting spend-cap currencies \"$currency\" vs \"$cur\" (fail closed)");
                    }
                    $currency = $cur;
                }
            } elseif ($type === self::MERCHANT_ALLOW_CAVEAT) {
                $list = self::stringArray(self::p($c, 'merchants'), 'merchant_allow');
                $merchants = $merchants === null ? array_values(array_unique($list))
                    : array_values(array_filter($merchants, static fn(string $m): bool => in_array($m, $list, true)));
            } elseif ($type === self::MERCHANT_CATEGORY_CAVEAT) {
                $list = self::stringArray(self::p($c, 'categories'), 'merchant_category');
                $categories = $categories === null ? array_values(array_unique($list))
                    : array_values(array_filter($categories, static fn(string $m): bool => in_array($m, $list, true)));
            } elseif ($type === self::HUMAN_PRESENT_CAVEAT) {
                $req = self::p($c, 'required');
                if (!is_bool($req)) {
                    throw new AcpAuthorityError('malformed human_present caveat: required must be a boolean (fail closed)');
                }
                $human = $human || $req;
            }
        }
        return self::obj(['maxAmount' => $maxAmount, 'currency' => $currency, 'merchants' => $merchants, 'categories' => $categories,
            'humanPresentRequired' => $human]);
    }

    /**
     * Check a concrete purchase request against a payment authority. Pure and fail-closed: an over-cap amount, a forbidden currency,
     * a merchant or category outside the allowlist or a missing human-present signal returns {ok: false, reason}.
     */
    public static function checkPaymentAuthority(mixed $authority, mixed $request): Obj
    {
        $amount = self::p($request, 'amount');
        $currency = self::p($request, 'currency');
        $merchant = self::p($request, 'merchant');
        if (!self::isAmount($amount)) {
            return self::obj(['ok' => false, 'reason' => 'amount must be a positive integer in minor units']);
        }
        if (!self::isStr($currency) || $currency === '') {
            return self::obj(['ok' => false, 'reason' => 'currency must be a non-empty string']);
        }
        if (!self::isStr($merchant) || $merchant === '') {
            return self::obj(['ok' => false, 'reason' => 'merchant must be a non-empty string']);
        }
        $aCur = self::p($authority, 'currency');
        if ($aCur !== self::U && $aCur !== $currency) {
            return self::obj(['ok' => false, 'reason' => "currency \"$currency\" is not the authorized currency \"" . Payments::s($aCur) . '"']);
        }
        $cap = self::p($authority, 'maxAmount');
        if ($cap !== self::U && !(self::isInt($cap) && self::f($cap) >= 0)) {
            return self::obj(['ok' => false, 'reason' => 'authorized spend cap is not a non-negative integer (fail closed)']);
        }
        if ($cap !== self::U && Payments::gt($amount, $cap)) {
            return self::obj(['ok' => false, 'reason' => 'amount ' . Payments::s($amount) . ' exceeds the authorized spend cap ' . Payments::s($cap)]);
        }
        $merchants = self::p($authority, 'merchants');
        if ($merchants !== null) {
            if (!self::isList($merchants)) {
                throw new \TypeError('authority.merchants.includes is not a function');
            }
            if (!in_array($merchant, $merchants, true)) {
                return self::obj(['ok' => false, 'reason' => "merchant \"$merchant\" is not in the authorized allowlist"]);
            }
        }
        $categories = self::p($authority, 'categories');
        if ($categories !== null) {
            if (!self::isList($categories)) {
                throw new \TypeError('authority.categories.includes is not a function');
            }
            $category = self::p($request, 'category');
            if ($category === self::U) {
                return self::obj(['ok' => false, 'reason' => 'the proof constrains merchant categories but no category was supplied']);
            }
            if (!in_array($category, $categories, true)) {
                return self::obj(['ok' => false, 'reason' => 'category "' . Payments::s($category) . '" is not in the authorized allowlist']);
            }
        }
        if (Payments::truthy(self::p($authority, 'humanPresentRequired')) && self::p($request, 'humanPresent') !== true) {
            return self::obj(['ok' => false, 'reason' => 'the proof requires a human-present charge but humanPresent was not asserted']);
        }
        return self::obj(['ok' => true]);
    }

    // ---- delegated payment token -------------------------------------------------------------------------------------------

    private static function leafCapability(mixed $pcActn): mixed
    {
        $chain = self::p($pcActn, 'cap_chain');
        if (!self::isList($chain) || $chain === []) {
            throw new AcpAuthorityError('PCActn carries no capability chain (fail closed)');
        }
        return $chain[count($chain) - 1];
    }

    private static function authorityRef(mixed $pcActn): Obj
    {
        $leaf = self::leafCapability($pcActn);
        $digest = Payments::hash($pcActn);
        $action = self::p($pcActn, 'action');
        return self::obj([
            'digest' => $digest,
            'aud' => self::p($pcActn, 'aud'),
            'grant_ref' => self::p($pcActn, 'grant_ref'),
            'leaf_holder' => self::p($leaf, 'holder'),
            'verb' => self::p($action, 'verb'),
            'resource' => self::p($action, 'resource'),
            'params_digest' => self::p($action, 'params_digest'),
        ]);
    }

    /**
     * Mint a one-time ACP delegated payment token (a compact JWS) FROM a PCActn, bound to session, merchant, amount, currency and
     * expiry and carrying the proof's authority BY REFERENCE (`pca.digest`). The proof's caveats gate issuance: an over-authority
     * request, an expiry in the past or one that would outlive the proof throws AcpAuthorityError.
     * `$opts`: amount, currency, merchant, session, expiresAt, paymentMethod, signingKey (a private OKP Ed25519 JWK, a 32-byte seed
     * or a 64-byte libsodium secret key), alg (default EdDSA), category, humanPresent, issuer, kid, jti, now.
     */
    public static function mintDelegatedPaymentToken(mixed $pcActn, mixed $opts): string
    {
        $nowO = self::o($opts, 'now');
        $now = Payments::fin($nowO) ? $nowO : Payments::now();
        $authority = self::extractPaymentAuthority(self::p(self::leafCapability($pcActn), 'caveats'));
        $req = ['amount' => self::o($opts, 'amount'), 'currency' => self::o($opts, 'currency'), 'merchant' => self::o($opts, 'merchant')];
        foreach (['category', 'humanPresent'] as $k) {
            if (self::o($opts, $k) !== self::U) {
                $req[$k] = self::o($opts, $k);
            }
        }
        $check = self::checkPaymentAuthority($authority, self::obj($req));
        if ($check->get('ok') !== true) {
            $reason = $check->get('reason');
            throw new AcpAuthorityError('refused: ' . (Payments::truthy($reason) ? $reason : 'request exceeds the proof authority'));
        }
        $expiresAt = self::o($opts, 'expiresAt');
        if (!Payments::fin($expiresAt)) {
            throw new AcpAuthorityError('refused: expiresAt must be a finite epoch-ms timestamp');
        }
        if (!(self::f($expiresAt) > self::f($now))) {
            throw new AcpAuthorityError('refused: expiresAt is not in the future');
        }
        $pcExp = self::p($pcActn, 'exp');
        if (!(Payments::fin($pcExp) && !Payments::gt($expiresAt, $pcExp))) {
            throw new AcpAuthorityError('refused: token expiry ' . Payments::s($expiresAt) . " would outlive the proof's exp " . Payments::s($pcExp));
        }
        $session = self::o($opts, 'session');
        if (!Payments::truthy($session)) {
            throw new AcpAuthorityError('refused: a session id is required');
        }
        $pca = self::authorityRef($pcActn);
        $jti = self::o($opts, 'jti');
        if ($jti === null || $jti === self::U) {
            $seed = Payments::spreadObj($pcActn);
            $seed->set('nonce', 'acp:' . Payments::s($session) . ':' . Payments::s(self::o($opts, 'merchant')) . ':' . Payments::s(self::o($opts, 'amount'))
                . ':' . Payments::s(self::o($opts, 'currency')) . ':' . Payments::s($expiresAt) . ':' . $pca->get('digest'));
            $jti = Payments::hash($seed);
        }
        $claims = self::obj([
            'typ' => self::ACP_DELEGATED_TOKEN_TYPE,
            'ver' => self::ACP_DELEGATED_TOKEN_VERSION,
            'jti' => $jti,
            'session' => $session,
            'merchant' => self::o($opts, 'merchant'),
            'amount' => self::o($opts, 'amount'),
            'currency' => self::o($opts, 'currency'),
            'iat' => $now,
            'exp' => $expiresAt,
            'paymentMethod' => Payments::spreadObj(self::o($opts, 'paymentMethod')),
            'humanPresent' => self::o($opts, 'humanPresent') === true,
            'category' => self::o($opts, 'category'),
            'iss' => self::o($opts, 'issuer'),
            'pca' => $pca,
        ]);
        $algO = self::o($opts, 'alg');
        $alg = $algO === null || $algO === self::U ? 'EdDSA' : $algO;
        if (!self::isStr($alg)) {
            throw new \TypeError('"alg" must be a string');
        }
        $key = self::o($opts, 'signingKey');
        $kid = self::o($opts, 'kid');
        $header = self::obj(['alg' => $alg, 'typ' => self::ACP_DELEGATED_TOKEN_TYPE, 'kid' => $kid]);
        $prot = Jose::b64u(Js::utf8(Js::stringify($header)));
        $body = Jose::b64u(Js::utf8(Js::stringify($claims)));
        return "$prot.$body." . Jose::b64u(Jose::jwsSign($alg, $key === self::U ? null : $key, "$prot.$body"));
    }

    private static function isPaymentMethod(mixed $v): bool
    {
        return $v instanceof Obj && self::isStr($v->get('type'));
    }

    private static function lossy(string $b): string
    {
        if (preg_match('//u', $b) === 1) {
            return $b;
        }
        $old = mb_substitute_character();
        mb_substitute_character(0xFFFD);
        $r = mb_convert_encoding($b, 'UTF-8', 'UTF-8');
        mb_substitute_character($old);
        return $r;
    }

    private static function parseClaims(string $payload): ?Obj
    {
        try {
            $c = Js::parse(self::lossy($payload));
        } catch (\Throwable) {
            return null;
        }
        if (!($c instanceof Obj)) {
            return null;
        }
        if ($c->get('typ') !== self::ACP_DELEGATED_TOKEN_TYPE || !self::numIs($c->get('ver'), self::ACP_DELEGATED_TOKEN_VERSION)) {
            return null;
        }
        foreach (['jti', 'session', 'merchant', 'currency'] as $k) {
            if (!is_string($c->get($k)) || $c->get($k) === '') {
                return null;
            }
        }
        if (!self::isAmount($c->get('amount')) || !Payments::fin($c->get('iat')) || !Payments::fin($c->get('exp'))
            || !is_bool($c->get('humanPresent')) || !self::isPaymentMethod($c->get('paymentMethod'))) {
            return null;
        }
        $p = $c->get('pca');
        if (!($p instanceof Obj)) {
            return null;
        }
        foreach (['digest', 'aud', 'grant_ref', 'leaf_holder', 'verb', 'resource', 'params_digest'] as $k) {
            if (!is_string($p->get($k))) {
                return null;
            }
        }
        return $c;
    }

    private static function hasClaim(mixed $s): bool
    {
        return (is_object($s) && !($s instanceof Obj) && method_exists($s, 'claim')) || Js::opt($s, 'claim') instanceof \Closure;
    }

    private static function claimStore(mixed $s, string $jti, float $exp): mixed
    {
        if (is_object($s) && !($s instanceof Obj) && method_exists($s, 'claim')) {
            return $s->claim($jti, $exp);
        }
        $f = Js::opt($s, 'claim');
        if ($f instanceof \Closure) {
            return $f($jti, $exp);
        }
        throw new \TypeError('singleUse.claim is not a function');
    }

    /** The verdict Obj: {ok, reason?, claims?, pcaResult?}. */
    private static function verdict(bool $ok, ?string $reason = null, ?Obj $claims = null, ?Obj $pcaResult = null): Obj
    {
        return self::obj(['ok' => $ok, 'reason' => $reason ?? self::U, 'claims' => $claims ?? self::U, 'pcaResult' => $pcaResult ?? self::U]);
    }

    private static function verifyBinding(mixed $token, mixed $opts): Obj
    {
        $algO = self::o($opts, 'alg');
        $alg = $algO === null || $algO === self::U ? 'EdDSA' : $algO;
        $nowO = self::o($opts, 'now');
        $now = Payments::fin($nowO) ? $nowO : Payments::now();
        try {
            Jose::assertCanonicalCompactJws($token); // canonical-spelling gate BEFORE the signature check
            if (!self::isStr($alg)) {
                throw new \TypeError('"alg" must be a string');
            }
            $key = self::o($opts, 'verifyKey');
            [$bytes] = Jose::compactVerify($token, $key === self::U ? null : $key, [$alg]);
            $claims = self::parseClaims($bytes);
        } catch (\Throwable $e) {
            return self::verdict(false, 'token signature did not verify: ' . $e->getMessage());
        }
        if ($claims === null) {
            return self::verdict(false, 'token payload is not a well-formed delegated payment token');
        }
        $em = self::o($opts, 'expectedMerchant');
        if (!self::isStr($em) || $claims->get('merchant') !== $em) {
            return self::verdict(false, 'token merchant "' . $claims->get('merchant') . '" does not match expected "' . Payments::s($em) . '"', $claims);
        }
        $amount = self::o($opts, 'amount');
        if (!self::isAmount($amount)) {
            return self::verdict(false, 'settlement amount must be a positive integer in minor units', $claims);
        }
        if (!(self::f($amount) <= self::f($claims->get('amount')))) {
            return self::verdict(false, 'settlement amount ' . Payments::s($amount) . " exceeds the token's authorized amount " . Payments::s($claims->get('amount')), $claims);
        }
        if (!(self::f($now) <= self::f($claims->get('exp')))) {
            return self::verdict(false, 'the delegated payment token has expired', $claims);
        }
        $es = self::o($opts, 'expectedSession');
        if ($es !== self::U && !(self::isStr($es) && $claims->get('session') === $es)) {
            return self::verdict(false, 'token session "' . $claims->get('session') . '" does not match expected "' . Payments::s($es) . '"', $claims);
        }
        $ec = self::o($opts, 'expectedCurrency');
        if ($ec !== self::U && !(self::isStr($ec) && $claims->get('currency') === $ec)) {
            return self::verdict(false, 'token currency "' . $claims->get('currency') . '" does not match expected "' . Payments::s($ec) . '"', $claims);
        }
        $grant = self::o($opts, 'grant');
        $pcActn = self::o($opts, 'pcActn');
        if ($grant !== self::U && $pcActn === self::U) {
            return self::verdict(false, 'a grant was supplied without the pcActn to re-verify (fail closed)', $claims);
        }
        if ($pcActn !== self::U) {
            if (Payments::hash($pcActn) !== $claims->get('pca')->get('digest')) {
                return self::verdict(false, 'pcactn_digest mismatch: the supplied proof is not the one that minted this token', $claims);
            }
            if ($grant !== self::U) {
                // audience tri-state of the core: a string, an explicit null (opt-out) or omitted (fails closed)
                $aud = self::o($opts, 'audience');
                $audience = $aud === null ? Audience::Any : (self::isStr($aud) ? $aud : null);
                $roots = self::o($opts, 'authorizedPlanRoots');
                $roots = $roots === self::U ? null : (Js::isStrList($roots) ? $roots : []);
                $r = Pca::verifyPcactnCore($pcActn, $grant, (int)floor(self::f($now)), $audience, null, null, null, null, $roots,
                    self::o($opts, 'insecureSkipPlanRootCheck') === true);
                $res = self::obj(['allow' => $r['allow'], 'checks' => Obj::of($r['checks'] ?? []), 'reason' => $r['reason'] ?? null]);
                if ($r['allow'] !== true) {
                    $why = $r['reason'] ?? null;
                    return self::verdict(false, 'bound proof failed to verify: ' . (Payments::truthy($why) ? $why : 'denied'), $claims, $res);
                }
                return self::verdict(true, null, $claims, $res);
            }
        }
        return self::verdict(true, null, $claims);
    }

    /**
     * Verify a delegated payment token at settlement: the signature, then the merchant, amount, expiry, session and currency bindings
     * and, with a `pcActn`, the proof's digest (end to end with a `grant`). Strict by default: a `singleUse` store and an
     * `expectedCurrency` are required, and after every other check the token's `jti` is claimed once. Fails CLOSED on every mismatch,
     * an already redeemed token or an unavailable store.
     */
    public static function verifyDelegatedPaymentToken(mixed $token, mixed $opts): Obj
    {
        $su = self::o($opts, 'singleUse');
        if (self::o($opts, 'strict') !== false) {
            if (!Payments::truthy($su) || !self::hasClaim($su)) {
                return self::verdict(false, 'strict settlement requires a singleUse store (fail closed)');
            }
            $cur = self::o($opts, 'expectedCurrency');
            if (!self::isStr($cur) || $cur === '') {
                return self::verdict(false, 'strict settlement requires expectedCurrency (fail closed)');
            }
        }
        $res = self::verifyBinding($token, $opts);
        if ($res->get('ok') !== true || $su === self::U) {
            return $res;
        }
        $claims = $res->get('claims');
        try {
            $first = self::claimStore($su, $claims->get('jti'), self::f($claims->get('exp'))) === true;
        } catch (\Throwable) {
            return self::verdict(false, 'single-use store unavailable (fail closed)', $claims);
        }
        return $first ? $res : self::verdict(false, 'the delegated payment token was already redeemed', $claims);
    }

    // ---- x402 v1 ------------------------------------------------------------------------------------------------------------

    /** The HTTP 402 challenge for a protected resource (x402 v1). Throws \TypeError on anything the v1 wire makes invalid. */
    public static function x402Challenge(mixed $resource, mixed $opts): Obj
    {
        $amount = self::o($opts, 'amount');
        if (!self::isAmount($amount)) {
            throw new \TypeError('x402Challenge: amount must be a positive integer in atomic/minor units');
        }
        $payTo = self::o($opts, 'payTo');
        $currency = self::o($opts, 'currency');
        if (!self::isStr($payTo) || $payTo === '') {
            throw new \TypeError('x402Challenge: payTo is required');
        }
        if (!self::isStr($currency) || $currency === '') {
            throw new \TypeError('x402Challenge: currency (the x402 asset) is required');
        }
        $timeout = self::nn(self::o($opts, 'maxTimeoutSeconds'), 60);
        if (!Payments::safeInt($timeout) || self::f($timeout) <= 0) {
            throw new \TypeError('x402Challenge: maxTimeoutSeconds must be a positive integer');
        }
        $requirement = Obj::of([
            'maxTimeoutSeconds' => $timeout,
            'scheme' => self::nn(self::o($opts, 'scheme'), 'exact'),
            'network' => self::nn(self::o($opts, 'network'), 'base-sepolia'),
            'maxAmountRequired' => Payments::s($amount),
            'resource' => $resource,
            'description' => self::nn(self::o($opts, 'description'), 'Payment required for ' . Payments::s($resource)),
            'payTo' => $payTo,
            'asset' => $currency,
            'mimeType' => self::nn(self::o($opts, 'mimeType'), 'application/json'),
        ]);
        return Obj::of([
            'status' => 402,
            'headers' => Obj::of(['Content-Type' => 'application/json']),
            'body' => Obj::of(['x402Version' => 1, 'error' => self::nn(self::o($opts, 'error'), 'X-PAYMENT header is required'), 'accepts' => [$requirement]]),
        ]);
    }

    /**
     * Gate an x402 settlement on a verified, PCActn-bound payment. `$opts['verify']` (payload to {ok, reason?, claims?}) is required; a
     * refusal answers a fresh 402 (fail closed), otherwise the optional `$opts['settle']` step (payload, claims to receipt) runs and its
     * non-null return value becomes the receipt.
     */
    public static function x402Settle(mixed $payload, mixed $opts): Obj
    {
        $norm = self::normalizeX402Payload($payload);
        if ($norm->get('ok') !== true) {
            return self::obj(['settled' => false, 'status' => 402, 'reason' => $norm->get('reason')]);
        }
        $verify = self::o($opts, 'verify');
        if (!is_callable($verify)) {
            throw new \TypeError('opts.verify is not a function');
        }
        $v = $verify($payload);
        if (!Payments::truthy(self::p($v, 'ok'))) {
            $claims = self::p($v, 'claims');
            return self::obj(['settled' => false, 'status' => 402, 'reason' => self::nn(self::p($v, 'reason'), 'payment verification failed'),
                'claims' => Payments::truthy($claims) ? $claims : self::U]);
        }
        $claims = self::p($v, 'claims');
        if ($claims === self::U) {
            return self::obj(['settled' => false, 'status' => 402, 'reason' => 'verifier admitted the payment but returned no claims (fail closed)']);
        }
        $settle = self::o($opts, 'settle');
        $receipt = null;
        if (Payments::truthy($settle)) {
            if (!is_callable($settle)) {
                throw new \TypeError('opts.settle is not a function');
            }
            $receipt = $settle($payload, $claims);
        }
        return self::obj(['settled' => true, 'status' => 200, 'claims' => $claims, 'receipt' => $receipt ?? self::U]);
    }

    /**
     * Adapt verifyDelegatedPaymentToken into the `verify` step of x402Settle: it reads the token from the payload of either version
     * and verifies its binding and bound proof. Strict by default: `expectedMerchant` and `amount` must come from the server (the
     * payload's own are never read) and a store and currency are required.
     */
    public static function acpX402Verifier(mixed $opts): \Closure
    {
        return static function (mixed $payload) use ($opts): Obj {
            $norm = self::normalizeX402Payload($payload);
            if ($norm->get('ok') !== true) {
                return self::obj(['ok' => false, 'reason' => $norm->get('reason')]);
            }
            $offered = self::o($opts, 'offered');
            if (self::numIs($norm->get('version'), 2) && $offered !== self::U && !self::x402AcceptedMatches($offered, $norm->get('accepted'))) {
                return self::obj(['ok' => false, 'reason' => 'x402 v2 payload.accepted is not one of the requirements this server offered']);
            }
            $em = self::o($opts, 'expectedMerchant');
            $amt = self::o($opts, 'amount');
            if (self::o($opts, 'strict') !== false && ($em === self::U || $amt === self::U)) {
                return self::obj(['ok' => false, 'reason' => 'strict settlement requires the server to supply expectedMerchant and amount (fail closed)']);
            }
            $merchant = self::nn($em, $norm->has('merchant') ? $norm->get('merchant') : self::U);
            if (!self::isStr($merchant) || $merchant === '') {
                return self::obj(['ok' => false, 'reason' => 'x402 payload has no merchant to check the token against']);
            }
            $amount = self::nn($amt, $norm->has('amount') ? $norm->get('amount') : self::U);
            if (!Js::isNum($amount) || !self::isAmount($amount)) {
                return self::obj(['ok' => false, 'reason' => 'x402 payload has no amount to check the token against']);
            }
            $o2 = Obj::of(['expectedMerchant' => $merchant, 'amount' => $amount, 'verifyKey' => self::o($opts, 'verifyKey')]);
            foreach (['alg', 'now', 'expectedSession', 'expectedCurrency', 'pcActn', 'grant', 'audience', 'authorizedPlanRoots',
                'insecureSkipPlanRootCheck', 'singleUse', 'strict'] as $k) {
                if (self::o($opts, $k) !== self::U) {
                    $o2->set($k, self::o($opts, $k));
                }
            }
            $res = self::verifyDelegatedPaymentToken($norm->get('token'), $o2);
            $claims = $res->get('claims');
            return self::obj(['ok' => $res->get('ok'), 'reason' => $res->has('reason') ? $res->get('reason') : self::U,
                'claims' => Payments::truthy($claims) ? $claims : self::U]);
        };
    }

    // ---- ACP delegate_payment allowance --------------------------------------------------------------------------------------

    /** Epoch ms to the Date#toISOString form, or null when the time value is out of range. */
    private static function isoFromMs(float $ms): ?string
    {
        if (!is_finite($ms) || abs($ms) > 8.64e15) {
            return null;
        }
        $t = (int)$ms; // truncation toward zero
        $days = intdiv($t, 86400000);
        $rem = $t % 86400000;
        if ($rem < 0) {
            $rem += 86400000;
            $days--;
        }
        $z = $days + 719468;
        $era = intdiv($z >= 0 ? $z : $z - 146096, 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $y = $yoe + $era * 400;
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $m = $mp < 10 ? $mp + 3 : $mp - 9;
        if ($m <= 2) {
            $y++;
        }
        $year = $y >= 0 && $y <= 9999 ? sprintf('%04d', $y) : sprintf('%s%06d', $y < 0 ? '-' : '+', abs($y));
        return sprintf('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', $year, $m, $d, intdiv($rem, 3600000), intdiv($rem % 3600000, 60000),
            intdiv($rem % 60000, 1000), $rem % 1000);
    }

    /**
     * Map VERIFIED token claims to the ACP delegate_payment `allowance`. Throws AcpAuthorityError when a claim cannot be expressed in
     * the ACP shape (currency not three letters, merchant over 256 characters, expiry not a date).
     */
    public static function toAcpAllowance(mixed $claims): Obj
    {
        $amount = self::p($claims, 'amount');
        if (!self::isAmount($amount)) {
            throw new AcpAuthorityError('allowance: amount must be a positive integer in minor units');
        }
        $cur = self::p($claims, 'currency');
        $currency = self::isStr($cur) ? mb_strtolower($cur, 'UTF-8') : '';
        if (preg_match('/\A[a-z]{3}\z/', $currency) !== 1) {
            throw new AcpAuthorityError('allowance: currency must be a three-letter ISO-4217 code');
        }
        $merchant = self::p($claims, 'merchant');
        if (!self::isStr($merchant) || $merchant === '' || Js::len($merchant) > 256) {
            throw new AcpAuthorityError('allowance: merchant_id must be 1 to 256 characters');
        }
        $session = self::p($claims, 'session');
        if (!self::isStr($session) || $session === '') {
            throw new AcpAuthorityError('allowance: checkout_session_id is required');
        }
        $exp = self::p($claims, 'exp');
        $at = Payments::fin($exp) ? self::isoFromMs(self::f($exp)) : null;
        if ($at === null) {
            throw new AcpAuthorityError('allowance: expiry is not a valid time');
        }
        return Obj::of(['reason' => 'one_time', 'max_amount' => $amount, 'currency' => $currency, 'checkout_session_id' => $session,
            'merchant_id' => $merchant, 'expires_at' => $at]);
    }

    // ---- x402 v2 ------------------------------------------------------------------------------------------------------------

    private static function caip2(mixed $v): bool
    {
        return self::isStr($v) && preg_match('/\A[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}\z/', $v) === 1;
    }

    private static function atomic(mixed $v): bool
    {
        return self::isStr($v) && preg_match('/\A(?:0|[1-9][0-9]*)\z/', $v) === 1;
    }

    private static function printable(mixed $v): bool
    {
        return self::isStr($v) && Js::len($v) <= 32 && preg_match('/\A[\x20-\x7e]*\z/', $v) === 1;
    }

    private static function nonEmpty(mixed $v): bool
    {
        return self::isStr($v) && $v !== '';
    }

    private static function absoluteHttp(mixed $u): bool
    {
        $r = self::isStr($u) ? WhatwgUrl::parse($u) : null;
        return $r !== null && in_array($r['scheme'], ['http', 'https'], true);
    }

    /** @return list<string> problems with a ResourceInfo (empty = valid) */
    public static function resourceInfoProblems(mixed $r): array
    {
        if (!Js::isObj($r)) {
            return ['resource must be an object'];
        }
        $p = [];
        if (!self::absoluteHttp(self::p($r, 'url'))) {
            $p[] = 'resource.url must be an absolute http(s) URL';
        }
        foreach (['description', 'mimeType'] as $k) {
            $v = self::p($r, $k);
            if ($v !== self::U && !self::isStr($v)) {
                $p[] = "resource.$k must be a string";
            }
        }
        $sn = self::p($r, 'serviceName');
        if ($sn !== self::U && !self::printable($sn)) {
            $p[] = 'resource.serviceName must be printable ASCII up to 32 characters';
        }
        $tags = self::p($r, 'tags');
        if ($tags !== self::U) {
            $ok = self::isList($tags) && count($tags) <= 5;
            foreach (($ok ? $tags : []) as $t) {
                $ok = $ok && self::printable($t);
            }
            if (!$ok) {
                $p[] = 'resource.tags must be up to 5 printable ASCII strings of up to 32 characters';
            }
        }
        $icon = self::p($r, 'iconUrl');
        if ($icon !== self::U && !(self::absoluteHttp($icon) && Js::len($icon) <= 2048)) {
            $p[] = 'resource.iconUrl must be an absolute http(s) URL up to 2048 characters';
        }
        return $p;
    }

    /** @return list<string> problems with one v2 PaymentRequirements (empty = valid) */
    public static function requirementV2Problems(mixed $q): array
    {
        if (!Js::isObj($q)) {
            return ['requirements must be an object'];
        }
        $p = [];
        if (!self::nonEmpty(self::p($q, 'scheme'))) {
            $p[] = 'scheme is required';
        }
        if (!self::caip2(self::p($q, 'network'))) {
            $p[] = 'network must be a CAIP-2 identifier';
        }
        $amount = self::p($q, 'amount');
        if (!self::atomic($amount) || $amount === '0') {
            $p[] = 'amount must be a positive decimal string of atomic units';
        }
        if (!self::nonEmpty(self::p($q, 'asset'))) {
            $p[] = 'asset is required';
        }
        if (!self::nonEmpty(self::p($q, 'payTo'))) {
            $p[] = 'payTo is required';
        }
        $t = self::p($q, 'maxTimeoutSeconds');
        if (!Js::isNum($t) || !Payments::safeInt($t) || self::f($t) <= 0) {
            $p[] = 'maxTimeoutSeconds must be a positive integer';
        }
        $extra = self::p($q, 'extra');
        if ($extra !== self::U && !Js::isObj($extra)) {
            $p[] = 'extra must be an object';
        }
        return $p;
    }

    /** @return list<string> problems with a v2 PaymentRequired (empty = valid) */
    public static function paymentRequiredV2Problems(mixed $pr): array
    {
        if (!Js::isObj($pr)) {
            return ['PaymentRequired must be an object'];
        }
        $p = [];
        if (!self::numIs(self::p($pr, 'x402Version'), 2)) {
            $p[] = 'x402Version must be 2';
        }
        $err = self::p($pr, 'error');
        if ($err !== self::U && !self::isStr($err)) {
            $p[] = 'error must be a string';
        }
        array_push($p, ...self::resourceInfoProblems(self::p($pr, 'resource')));
        $acc = self::p($pr, 'accepts');
        if (!self::isList($acc) || $acc === []) {
            $p[] = 'accepts must be a non-empty array';
        } else {
            foreach ($acc as $i => $q) {
                foreach (self::requirementV2Problems($q) as $m) {
                    $p[] = "accepts[$i].$m";
                }
            }
        }
        $ext = self::p($pr, 'extensions');
        if ($ext !== self::U) {
            if (!Js::isObj($ext)) {
                $p[] = 'extensions must be an object';
            } else {
                foreach (self::keysOf($ext) as $k) {
                    $v = self::p($ext, $k);
                    if (!Js::isObj($v) || !Js::isObj(self::p($v, 'info')) || !Js::isObj(self::p($v, 'schema'))) {
                        $p[] = "extensions.$k needs info and schema objects";
                    }
                }
            }
        }
        return $p;
    }

    /** @return list<string> the own keys of an object in JS order */
    private static function keysOf(mixed $o): array
    {
        $keys = $o instanceof Obj ? $o->keys() : array_map('strval', array_keys((array)$o));
        return Js::ownKeys($keys);
    }

    private static function b64Encode(mixed $v): string
    {
        return base64_encode(Js::utf8(Js::stringify($v)));
    }

    /** Decode like Node's Buffer.from(v, 'base64') behind the shape gate, then JSON.parse it. */
    private static function b64Decode(mixed $value, string $name): mixed
    {
        if (!self::isStr($value) || preg_match('/\A[A-Za-z0-9+\/]+={0,2}\z/', $value) !== 1) {
            throw new \TypeError("x402: $name is not base64");
        }
        $s = rtrim($value, '=');
        if (strlen($s) % 4 === 1) {
            $s = substr($s, 0, -1);
        }
        $bytes = base64_decode($s . str_repeat('=', (4 - strlen($s) % 4) % 4), false);
        try {
            return Js::parse(self::lossy($bytes === false ? '' : $bytes));
        } catch (\Throwable) {
            throw new \TypeError("x402: $name is not JSON");
        }
    }

    public static function encodePaymentRequiredHeader(mixed $pr): string
    {
        $problems = self::paymentRequiredV2Problems($pr);
        if ($problems !== []) {
            throw new \TypeError('x402: ' . implode('; ', $problems));
        }
        return self::b64Encode($pr);
    }

    public static function decodePaymentRequiredHeader(mixed $value): mixed
    {
        $doc = self::b64Decode($value, 'PAYMENT-REQUIRED');
        $problems = self::paymentRequiredV2Problems($doc);
        if ($problems !== []) {
            throw new \TypeError('x402: ' . implode('; ', $problems));
        }
        return $doc;
    }

    /** The v2 402 challenge: JSON body plus the base64 PAYMENT-REQUIRED header; refuses anything the v2 spec makes invalid. */
    public static function x402ChallengeV2(mixed $resource, mixed $opts): Obj
    {
        $amount = self::o($opts, 'amount');
        if (!Js::isNum($amount) || !Payments::safeInt($amount) || self::f($amount) <= 0) {
            throw new \TypeError('x402Challenge: amount must be a positive integer in atomic units');
        }
        $info = self::isStr($resource) ? Obj::of(['url' => $resource]) : Payments::spreadObj($resource);
        $req = self::obj([
            'scheme' => self::nn(self::o($opts, 'scheme'), 'exact'),
            'network' => self::o($opts, 'network'),
            'amount' => Payments::s($amount),
            'asset' => self::o($opts, 'asset'),
            'payTo' => self::o($opts, 'payTo'),
            'maxTimeoutSeconds' => self::nn(self::o($opts, 'maxTimeoutSeconds'), 60),
            'extra' => self::o($opts, 'extra'),
        ]);
        $body = self::obj([
            'x402Version' => 2,
            'error' => self::nn(self::o($opts, 'error'), 'PAYMENT-SIGNATURE header is required'),
            'resource' => $info,
            'accepts' => [$req],
            'extensions' => self::o($opts, 'extensions'),
        ]);
        $header = self::encodePaymentRequiredHeader($body); // validates
        return Obj::of(['status' => 402, 'headers' => Obj::of(['Content-Type' => 'application/json', self::X402_V2_PAYMENT_REQUIRED_HEADER => $header]),
            'body' => $body]);
    }

    /**
     * Version negotiation: the highest version both sides speak, or null (answer 402 v1 with an error, never guess). `$offered` is what
     * the client says it speaks; omitted or empty means [1] only. An explicit null throws, as the reference does.
     */
    public static function x402Negotiate(mixed $offered = self::U, mixed $supported = self::U): ?int
    {
        $sup = $supported === self::U ? self::X402_SUPPORTED_VERSIONS : $supported;
        if (!self::isList($sup)) {
            throw new \TypeError('supported.filter is not a function');
        }
        $mine = [];
        foreach ($sup as $v) {
            if (self::numIs($v, 1) || self::numIs($v, 2)) {
                $mine[] = (int)self::f($v);
            }
        }
        if ($offered === null) {
            throw new \TypeError("Cannot read properties of null (reading 'length')");
        }
        if ($offered === self::U || $offered === []) {
            $theirs = [1];
        } elseif (self::isList($offered)) {
            $theirs = $offered;
        } else {
            throw new \TypeError('offered.includes is not a function');
        }
        rsort($mine);
        foreach ($mine as $v) {
            foreach ($theirs as $t) {
                if (self::numIs($t, $v)) {
                    return $v;
                }
            }
        }
        return null;
    }

    private static function stable(mixed $v): string
    {
        if (!($v instanceof Obj) && !is_array($v)) {
            return Js::stringify($v);
        }
        if (self::isList($v)) {
            return '[' . implode(',', array_map(static fn(mixed $x): string => self::stable($x), $v)) . ']';
        }
        $keys = $v instanceof Obj ? $v->keys() : array_map('strval', array_keys($v));
        $parts = [];
        foreach (Payments::jsSort($keys) as $k) {
            $parts[] = Js::stringify($k) . ':' . self::stable(self::p($v, $k));
        }
        return '{' . implode(',', $parts) . '}';
    }

    /** True when `$accepted` (echoed by the client in its v2 payload) is exactly one of the requirements the server offered. */
    public static function x402AcceptedMatches(mixed $offered, mixed $accepted): bool
    {
        if (self::requirementV2Problems($accepted) !== []) {
            return false;
        }
        if (!self::isList($offered)) {
            throw new \TypeError('offered.some is not a function');
        }
        $a = self::stable($accepted);
        foreach ($offered as $o) {
            if (self::stable($o) === $a) {
                return true;
            }
        }
        return false;
    }

    /**
     * Read a client payload of either version. v1: the token, merchant and amount are top-level members. v2: the delegated token is
     * `payload.token` and the echoed `accepted` must be a valid v2 requirement (the merchant is never read from a v2 payload and the
     * amount only from `accepted.amount`).
     * @return Obj {ok: true, version, token, merchant?, amount?, accepted?} or {ok: false, reason}
     */
    public static function normalizeX402Payload(mixed $raw): Obj
    {
        if (!Js::isObj($raw)) {
            return self::obj(['ok' => false, 'reason' => 'x402 payment payload is not an object']);
        }
        $ver = self::p($raw, 'x402Version');
        if (self::numIs($ver, 2)) {
            $inner = self::p($raw, 'payload');
            if (!Js::isObj($inner) || !self::isStr(self::p($inner, 'token')) || self::p($inner, 'token') === '') {
                return self::obj(['ok' => false, 'reason' => 'x402 v2 payload is missing payload.token']);
            }
            $problems = self::requirementV2Problems(self::p($raw, 'accepted'));
            if ($problems !== []) {
                return self::obj(['ok' => false, 'reason' => 'x402 v2 payload.accepted is invalid: ' . implode('; ', $problems)]);
            }
            $accepted = self::p($raw, 'accepted');
            $amount = (float)self::p($accepted, 'amount');
            return self::obj(['ok' => true, 'version' => 2, 'token' => self::p($inner, 'token'), 'accepted' => $accepted,
                'amount' => Payments::safeInt($amount) ? Payments::num($amount) : self::U]);
        }
        if ($ver !== self::U && !self::numIs($ver, 1)) {
            return self::obj(['ok' => false, 'reason' => 'unsupported x402Version ' . Payments::s($ver)]);
        }
        $token = self::p($raw, 'token');
        if (!self::isStr($token)) {
            return self::obj(['ok' => false, 'reason' => 'x402 payment payload is missing a token']);
        }
        $merchant = self::p($raw, 'merchant');
        $amount = self::p($raw, 'amount');
        return self::obj(['ok' => true, 'version' => 1, 'token' => $token, 'merchant' => self::isStr($merchant) ? $merchant : self::U,
            'amount' => Js::isNum($amount) ? $amount : self::U]);
    }

    // ---- x402 v2 HTTP transport ---------------------------------------------------------------------------------------------

    /** @return list<string> problems with a v2 PaymentPayload (empty = valid) */
    public static function paymentPayloadV2Problems(mixed $p): array
    {
        if (!Js::isObj($p)) {
            return ['PaymentPayload must be an object'];
        }
        $out = [];
        if (!self::numIs(self::p($p, 'x402Version'), 2)) {
            $out[] = 'x402Version must be 2';
        }
        if (self::p($p, 'resource') !== self::U) {
            array_push($out, ...self::resourceInfoProblems(self::p($p, 'resource')));
        }
        foreach (self::requirementV2Problems(self::p($p, 'accepted')) as $m) {
            $out[] = "accepted.$m";
        }
        if (!Js::isObj(self::p($p, 'payload'))) {
            $out[] = 'payload must be an object';
        }
        $ext = self::p($p, 'extensions');
        if ($ext !== self::U && !Js::isObj($ext)) {
            $out[] = 'extensions must be an object';
        }
        return $out;
    }

    /** @return list<string> problems with a SettlementResponse (empty = valid); a success must not carry an errorReason, a failure must */
    public static function settlementResponseProblems(mixed $r): array
    {
        if (!Js::isObj($r)) {
            return ['SettlementResponse must be an object'];
        }
        $out = [];
        $success = self::p($r, 'success');
        $tx = self::p($r, 'transaction');
        $er = self::p($r, 'errorReason');
        if (!is_bool($success)) {
            $out[] = 'success must be a boolean';
        }
        if (!self::isStr($tx)) {
            $out[] = 'transaction must be a string';
        } elseif ($success === true && $tx === '') {
            $out[] = 'a successful settlement needs a transaction';
        }
        if (!self::caip2(self::p($r, 'network'))) {
            $out[] = 'network must be a CAIP-2 identifier';
        }
        if ($er !== self::U && !self::isStr($er)) {
            $out[] = 'errorReason must be a string';
        }
        if ($success === true && $er !== self::U) {
            $out[] = 'errorReason must be omitted on success';
        }
        if ($success === false && (!self::isStr($er) || $er === '')) {
            $out[] = 'errorReason is required on failure';
        }
        $payer = self::p($r, 'payer');
        if ($payer !== self::U && !self::isStr($payer)) {
            $out[] = 'payer must be a string';
        }
        $amount = self::p($r, 'amount');
        if ($amount !== self::U && !self::atomic($amount)) {
            $out[] = 'amount must be a decimal string of atomic units';
        }
        $ext = self::p($r, 'extensions');
        if ($ext !== self::U && !Js::isObj($ext)) {
            $out[] = 'extensions must be an object';
        }
        return $out;
    }

    /** @param list<string> $problems */
    private static function encodeHeader(mixed $v, array $problems): string
    {
        if ($problems !== []) {
            throw new \TypeError('x402: ' . implode('; ', $problems));
        }
        return self::b64Encode($v);
    }

    /** Encode a PaymentPayload for the PAYMENT-SIGNATURE request header (validates first; throws \TypeError). */
    public static function encodePaymentSignatureHeader(mixed $p): string
    {
        return self::encodeHeader($p, self::paymentPayloadV2Problems($p));
    }

    public static function decodePaymentSignatureHeader(mixed $value): mixed
    {
        $doc = self::b64Decode($value, 'PAYMENT-SIGNATURE');
        $problems = self::paymentPayloadV2Problems($doc);
        if ($problems !== []) {
            throw new \TypeError('x402: ' . implode('; ', $problems));
        }
        return $doc;
    }

    public static function encodePaymentResponseHeader(mixed $r): string
    {
        return self::encodeHeader($r, self::settlementResponseProblems($r));
    }

    public static function decodePaymentResponseHeader(mixed $value): mixed
    {
        $doc = self::b64Decode($value, 'PAYMENT-RESPONSE');
        $problems = self::settlementResponseProblems($doc);
        if ($problems !== []) {
            throw new \TypeError('x402: ' . implode('; ', $problems));
        }
        return $doc;
    }

    /**
     * Server side: read the client's PAYMENT-SIGNATURE header (case-insensitive, first value of a list). A missing header is 402
     * (answer with a PAYMENT-REQUIRED challenge); a present but undecodable or invalid one is 400. Never throws.
     */
    public static function readPaymentSignature(mixed $headers): Obj
    {
        $v = self::U;
        if (Js::isObj($headers)) {
            foreach (self::keysOf($headers) as $k) {
                if (mb_strtolower($k, 'UTF-8') === mb_strtolower(self::X402_PAYMENT_SIGNATURE_HEADER, 'UTF-8')) {
                    $val = self::p($headers, $k);
                    $v = self::isList($val) ? ($val === [] ? self::U : $val[0]) : $val;
                    break;
                }
            }
        }
        if ($v === self::U || $v === '') {
            return self::obj(['ok' => false, 'status' => self::X402_HTTP_STATUS['payment_required'], 'reason' => 'PAYMENT-SIGNATURE header is required']);
        }
        try {
            return self::obj(['ok' => true, 'payload' => self::decodePaymentSignatureHeader($v)]);
        } catch (\Throwable $e) {
            return self::obj(['ok' => false, 'status' => self::X402_HTTP_STATUS['malformed'], 'reason' => $e->getMessage()]);
        }
    }

    /**
     * Server side: the status and PAYMENT-RESPONSE header for a settlement outcome (a success is 200 and needs the transaction; a
     * failure is 402 with success false, the reason and an empty transaction unless one was broadcast). Throws \TypeError if the
     * response would be invalid.
     */
    public static function x402SettlementResponse(mixed $outcome, mixed $network): Obj
    {
        $settled = Payments::truthy(self::p($outcome, 'settled'));
        if ($settled) {
            $body = self::obj(['success' => true, 'transaction' => self::p($outcome, 'transaction'), 'network' => $network,
                'payer' => self::p($outcome, 'payer'), 'amount' => self::p($outcome, 'amount')]);
        } else {
            $body = self::obj(['success' => false, 'errorReason' => self::p($outcome, 'reason'),
                'transaction' => self::nn(self::p($outcome, 'transaction'), ''), 'network' => $network, 'payer' => self::p($outcome, 'payer')]);
        }
        return Obj::of(['status' => $settled ? self::X402_HTTP_STATUS['settled'] : self::X402_HTTP_STATUS['failed'],
            'headers' => Obj::of([self::X402_PAYMENT_RESPONSE_HEADER => self::encodePaymentResponseHeader($body)])]);
    }

    /** Client side: the request header to attach on the retry, from a payload built for an offered requirement. */
    public static function x402PaymentSignatureHeaders(mixed $p): Obj
    {
        return Obj::of([self::X402_PAYMENT_SIGNATURE_HEADER => self::encodePaymentSignatureHeader($p)]);
    }

    // ---- Stripe Shared Payment Granted Tokens --------------------------------------------------------------------------------

    private static function isCurrency(mixed $v): bool
    {
        return self::isStr($v) && preg_match('/\A[a-z]{3}\z/', $v) === 1;
    }

    /** @return list<string> problems with a Shared Payment Granted Token object (empty = well formed) */
    public static function stripeSptProblems(mixed $t): array
    {
        if (!Js::isObj($t)) {
            return ['the token must be an object'];
        }
        $p = [];
        if (self::p($t, 'object') !== self::STRIPE_SPT_OBJECT) {
            $p[] = 'object must be "' . self::STRIPE_SPT_OBJECT . '"';
        }
        $id = self::p($t, 'id');
        if (!self::isStr($id) || preg_match('/\Aspt_[A-Za-z0-9_]+\z/', $id) !== 1) {
            $p[] = 'id must be an spt_ identifier';
        }
        if (!self::isInt(self::p($t, 'created'))) {
            $p[] = 'created must be an integer timestamp';
        }
        if (!is_bool(self::p($t, 'livemode'))) {
            $p[] = 'livemode must be a boolean';
        }
        $da = self::p($t, 'deactivated_at');
        if ($da !== null && !self::isInt($da)) {
            $p[] = 'deactivated_at must be null or an integer timestamp';
        }
        $dr = self::p($t, 'deactivated_reason');
        if ($dr !== null && !(self::isStr($dr) && in_array($dr, self::SPT_REASONS, true))) {
            $p[] = 'deactivated_reason must be null or one of consumed, expired, resolved, revoked';
        }
        $u = self::p($t, 'usage_limits');
        if (!Js::isObj($u)) {
            $p[] = 'usage_limits is required';
        } else {
            if (!self::isCurrency(self::p($u, 'currency'))) {
                $p[] = 'usage_limits.currency must be a lowercase three-letter code';
            }
            $ma = self::p($u, 'max_amount');
            if (!self::isInt($ma) || self::f($ma) < 0) {
                $p[] = 'usage_limits.max_amount must be a non-negative integer in minor units';
            }
            $ea = self::p($u, 'expires_at');
            if ($ea !== self::U && $ea !== null && !self::isInt($ea)) {
                $p[] = 'usage_limits.expires_at must be an integer timestamp';
            }
        }
        $ud = self::p($t, 'usage_details');
        if ($ud !== null && $ud !== self::U) {
            $c = Js::isObj($ud) ? self::p($ud, 'amount_captured') : self::U;
            if (!Js::isObj($c) || !self::isInt(self::p($c, 'value')) || self::f(self::p($c, 'value')) < 0 || !self::isCurrency(self::p($c, 'currency'))) {
                $p[] = 'usage_details.amount_captured needs a non-negative integer value and a lowercase currency';
            }
        }
        foreach (['payment_method_details', 'agent_details', 'shared_metadata'] as $k) {
            $v = self::p($t, $k);
            if ($v !== null && $v !== self::U && !Js::isObj($v)) {
                $p[] = "$k must be null or an object";
            }
        }
        $pmd = self::p($t, 'payment_method_details');
        if (Js::isObj($pmd) && !self::isStr(self::p($pmd, 'type'))) {
            $p[] = 'payment_method_details.type must be a string';
        }
        return $p;
    }

    /** Parse a Shared Payment Granted Token; throws \TypeError listing every problem. */
    public static function parseStripeSpt(mixed $t): mixed
    {
        $problems = self::stripeSptProblems($t);
        if ($problems !== []) {
            throw new \TypeError('stripe spt: ' . implode('; ', $problems));
        }
        return $t;
    }

    /**
     * Can this token still be used for this capture? Refuses a malformed token, a deactivated or expired one, the wrong mode, a
     * different currency, a non-integer amount and one above max_amount minus what was already captured.
     * @param mixed $use {now (epoch s), amount (minor units), currency, livemode? (default true)}
     */
    public static function stripeSptUsable(mixed $t, mixed $use): Obj
    {
        $problems = self::stripeSptProblems($t);
        if ($problems !== []) {
            return self::obj(['ok' => false, 'reason' => 'malformed token: ' . $problems[0]]);
        }
        $now = self::p($use, 'now');
        $amount = self::p($use, 'amount');
        if (!self::isInt($now) || !self::isInt($amount) || self::f($amount) <= 0) {
            return self::obj(['ok' => false, 'reason' => 'now and amount must be integers and the amount positive']);
        }
        if (self::nn(self::p($use, 'livemode'), true) !== self::p($t, 'livemode')) {
            return self::obj(['ok' => false, 'reason' => 'the token is in the wrong mode']);
        }
        $dr = self::p($t, 'deactivated_reason');
        if ($dr !== null) {
            return self::obj(['ok' => false, 'reason' => "the token is deactivated ($dr)"]);
        }
        $da = self::p($t, 'deactivated_at');
        if ($da !== null && !(self::f($da) > self::f($now))) {
            return self::obj(['ok' => false, 'reason' => 'the token is deactivated']);
        }
        $lim = self::p($t, 'usage_limits');
        $ea = self::p($lim, 'expires_at');
        if (Js::isNum($ea) && !(self::f($now) < self::f($ea))) {
            return self::obj(['ok' => false, 'reason' => 'the token has expired']);
        }
        $cur = self::p($use, 'currency');
        if (!self::isStr($cur)) {
            throw new \TypeError('use.currency.toLowerCase is not a function');
        }
        if (self::p($lim, 'currency') !== mb_strtolower($cur, 'UTF-8')) {
            return self::obj(['ok' => false, 'reason' => 'the capture currency differs from the token currency']);
        }
        $ud = self::p($t, 'usage_details');
        $captured = $ud === null || $ud === self::U ? self::U : self::p($ud, 'amount_captured');
        if ($captured !== self::U && self::p($captured, 'currency') !== self::p($lim, 'currency')) {
            return self::obj(['ok' => false, 'reason' => 'the captured amount is in another currency']);
        }
        $remaining = self::f(self::p($lim, 'max_amount')) - ($captured !== self::U ? self::f(self::p($captured, 'value')) : 0.0);
        if (!(self::f($amount) <= $remaining)) {
            return self::obj(['ok' => false, 'reason' => 'the amount ' . Payments::s($amount) . ' exceeds the remaining ' . Js::str($remaining)]);
        }
        return self::obj(['ok' => true]);
    }

    /**
     * The usage_limits to request for a PCA authority: lowercase currency, integer minor units, expiry in whole seconds (rounded down).
     * @param mixed $authority {maxAmount, currency, expiresAtMs?}
     */
    public static function stripeUsageLimitsFor(mixed $authority): Obj
    {
        $ma = self::p($authority, 'maxAmount');
        $cur = self::p($authority, 'currency');
        $exp = self::p($authority, 'expiresAtMs');
        if (!self::isInt($ma) || self::f($ma) <= 0) {
            throw new \TypeError('stripe spt: maxAmount must be a positive integer in minor units');
        }
        if (!self::isStr($cur) || preg_match('/\A[A-Za-z]{3}\z/', $cur) !== 1) {
            throw new \TypeError('stripe spt: currency must be a three-letter code');
        }
        if ($exp !== self::U && !(Payments::fin($exp) && self::f($exp) > 0)) {
            throw new \TypeError('stripe spt: expiresAtMs must be a positive epoch-ms time');
        }
        return self::obj(['currency' => strtolower($cur), 'max_amount' => $ma,
            'expires_at' => $exp === self::U ? self::U : Payments::num(floor(self::f($exp) / 1000))]);
    }

    /**
     * A Shared Payment Token may be no wider than the delegated payment token (and so the PCA proof) it serves: same currency,
     * max_amount not above the delegated amount, and an expiry present and not after the delegated token's.
     * @param mixed $claims {amount, currency, exp}
     */
    public static function stripeSptWithinClaims(mixed $t, mixed $claims): Obj
    {
        $problems = self::stripeSptProblems($t);
        if ($problems !== []) {
            return self::obj(['ok' => false, 'reason' => 'malformed token: ' . $problems[0]]);
        }
        $lim = self::p($t, 'usage_limits');
        $cur = self::p($claims, 'currency');
        if (!self::isStr($cur)) {
            throw new \TypeError('claims.currency.toLowerCase is not a function');
        }
        if (self::p($lim, 'currency') !== mb_strtolower($cur, 'UTF-8')) {
            return self::obj(['ok' => false, 'reason' => 'the token currency differs from the delegated currency']);
        }
        $amount = self::p($claims, 'amount');
        // Number.isFinite(claims.amount): a number that is finite (a string, array, null, NaN or Infinity never passes)
        if (!(Js::isNum($amount) && is_finite((float)Js::num($amount)) && Payments::le(self::p($lim, 'max_amount'), $amount))) {
            return self::obj(['ok' => false, 'reason' => 'max_amount ' . Payments::s(self::p($lim, 'max_amount')) . ' exceeds the delegated amount ' . Payments::s($amount)]);
        }
        $ea = self::p($lim, 'expires_at');
        if (!Js::isNum($ea)) {
            return self::obj(['ok' => false, 'reason' => 'the token has no expiry']);
        }
        $exp = self::p($claims, 'exp');
        if (!(Js::isNum($exp) && is_finite((float)Js::num($exp)) && Payments::le(self::f($ea) * 1000, $exp))) {
            return self::obj(['ok' => false, 'reason' => 'the token outlives the delegated payment token']);
        }
        return self::obj(['ok' => true]);
    }
}
