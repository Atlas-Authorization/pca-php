<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Oidc.php';
require_once __DIR__ . '/Agent.php';

/** Any ID-JAG verification failure; codeName is an OIDC code (config, invalid_token, signature, issuer, audience, expired, ...) or one of actor, scope, grant. */
final class IdJagVerificationError extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}

/**
 * ID-JAG / OAuth Cross-App-Access bridge (draft-ietf-oauth-identity-assertion-authz-grant): a JWT the enterprise IdP mints so
 * one app may act, for a named user, against ANOTHER app (`sub` the human, `act.sub` the agent, `aud` the single resource app,
 * `scope` the authority). verifyIdJag checks one (on top of Oidc::verifyIdToken), idJagToCapability projects it onto a signed
 * root capability, tokenExchangeRequest / jwtBearerAssertion build the two XAA request shapes. Mirrors @atlasauth/pca-idjag.
 * Options use the reference's camelCase names; consumeJti is a callable(string $jti, $exp): bool, true for a fresh jti.
 */
final class Idjag
{
    public const MAX_ID_JAG_CHARS = 16384;
    public const IDJAG_AUTHORITY_CAVEAT = 'idjag_authority';
    public const IDJAG_PROVENANCE_CAVEAT = 'idjag_provenance';
    public const GRANT_TYPE_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    public const GRANT_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    public const TOKEN_TYPE_ID_JAG = 'urn:ietf:params:oauth:token-type:id-jag';
    public const TOKEN_TYPE_ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';
    public const TOKEN_TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';
    public const TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';
    public const CLIENT_ASSERTION_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    /** JavaScript's \s, as bytes (works on WTF-8 text too). */
    private const JS_WS = '/(?:[\t\n\x0B\f\r ]|\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF)+/';

    private static function isOpts(mixed $o): bool
    {
        return $o instanceof Obj || (is_array($o) && ($o === [] || !array_is_list($o)));
    }

    private static function nonEmpty(mixed $v): bool
    {
        return is_string($v) && $v !== '';
    }

    private static function fail(string $code, string $msg, ?\Throwable $prev = null): IdJagVerificationError
    {
        return new IdJagVerificationError($code, $msg, $prev);
    }

    /** @return list<string> */
    private static function cleanStrings(array $xs): array
    {
        return array_values(array_filter($xs, static fn(mixed $s): bool => self::nonEmpty($s)));
    }

    /** @return ?list<string> */
    private static function parseScopes(mixed $scope, mixed $scopes): ?array
    {
        if (is_string($scope)) {
            return self::cleanStrings(preg_split(self::JS_WS, $scope) ?: []);
        }
        if (is_array($scope) && array_is_list($scope)) {
            return self::cleanStrings($scope);
        }
        if (is_array($scopes) && array_is_list($scopes)) {
            return self::cleanStrings($scopes);
        }
        return null;
    }

    /**
     * Verify an ID-JAG; the grant {iss, sub, actor, agent, audience, scopes, iat, exp, jti?, nonce?, cnf?, oidcClaims}. Fails
     * closed with IdJagVerificationError. Strict draft mode (default) also needs clientId and consumeJti; pass strictDraft:
     * false to opt out. Options: issuer, audience, nonce, requiredScopes, clockToleranceSec, maxTokenAgeSec, algorithms,
     * key | jwksUri | discover (+ fetch), strictDraft, clientId, consumeJti, now (epoch seconds).
     */
    public static function verifyIdJag(mixed $jwt, mixed $opts): array
    {
        if (!self::nonEmpty($jwt)) {
            throw self::fail('invalid_token', 'verifyIdJag: jwt must be a non-empty string');
        }
        if (Js::len($jwt) > self::MAX_ID_JAG_CHARS) {
            throw self::fail('invalid_token', 'verifyIdJag: jwt exceeds the size limit');
        }
        if (!self::isOpts($opts)) {
            throw self::fail('config', 'verifyIdJag: opts is required');
        }
        $o = static fn(string $k): mixed => Js::opt($opts, $k);
        if (!self::nonEmpty($o('issuer'))) {
            throw self::fail('config', 'verifyIdJag: opts.issuer is required');
        }
        $audience = $o('audience');
        if (!self::nonEmpty($audience)) {
            throw self::fail('config', 'verifyIdJag: opts.audience is required (ID-JAG is single-audience)');
        }
        $strict = $o('strictDraft') !== false;
        $consume = $o('consumeJti');
        if ($strict && !(is_callable($consume) && !is_string($consume))) {
            throw self::fail('config', 'verifyIdJag: strictDraft requires opts.consumeJti (single-use store)');
        }
        if ($strict && !self::nonEmpty($o('clientId'))) {
            throw self::fail('config', 'verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)');
        }
        // every crypto + registered-claim check is the OIDC verifier's; its code is kept so callers see one error family
        $baseOpts = [];
        foreach (['nonce', 'clockToleranceSec', 'maxTokenAgeSec', 'algorithms', 'key', 'jwksUri', 'discover', 'fetch', 'now'] as $k) {
            if ($o($k) !== null) {
                $baseOpts[$k] = $o($k);
            }
        }
        $baseOpts['issuer'] = $o('issuer');
        $baseOpts['audience'] = $audience;
        try {
            $base = Oidc::verifyIdToken($jwt, $baseOpts);
        } catch (OidcVerificationError $e) {
            throw self::fail($e->codeName, $e->getMessage(), $e);
        } catch (\Throwable $e) { // e.g. a failed discovery: one error family
            throw self::fail('invalid_token', 'ID-JAG verification failed', $e);
        }
        $aud = $base['aud'];
        $audList = is_array($aud) && array_is_list($aud) ? $aud : [$aud];
        if (count($audList) !== 1 || $audList[0] !== $audience) {
            throw self::fail('audience', 'ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)');
        }
        // the signature is verified, so the payload is authentic: read the claims the OIDC projection does not surface
        try {
            $jws = Jose::assertCanonicalCompactJws($jwt);
            [$header, $raw] = [$jws['header'], $jws['payload']];
        } catch (\Throwable $e) {
            throw self::fail('invalid_token', 'ID-JAG payload could not be decoded', $e);
        }
        $act = $raw->get('act');
        if (!($act instanceof Obj) || !self::nonEmpty($act->get('sub'))) {
            throw self::fail('actor', 'ID-JAG is missing a well-formed "act" (agent) claim with a string "sub"');
        }
        $actor = unserialize(serialize($act));
        $scopes = self::parseScopes($raw->get('scope'), $raw->get('scopes'));
        if ($scopes === null) {
            throw self::fail('scope', 'ID-JAG is missing the "scope" (or "scopes") claim');
        }
        $req = $o('requiredScopes');
        if (is_array($req) && array_is_list($req)) {
            foreach ($req as $r) {
                if (!in_array($r, $scopes, true)) {
                    throw self::fail('scope', 'ID-JAG does not grant the required scope "' . IntentWb::jsStr($r) . '"');
                }
            }
        }
        $jti = self::nonEmpty($raw->get('jti')) ? $raw->get('jti') : null;
        if ($strict) {
            if ($header->get('typ') !== 'oauth-id-jag+jwt') {
                throw self::fail('grant', 'ID-JAG header typ must be "oauth-id-jag+jwt"');
            }
            if (!self::nonEmpty($raw->get('client_id'))) {
                throw self::fail('grant', 'ID-JAG is missing "client_id"');
            }
            if ($raw->get('client_id') !== $o('clientId')) {
                throw self::fail('grant', 'ID-JAG client_id does not match the expected client');
            }
            if ($jti === null) {
                throw self::fail('grant', 'ID-JAG is missing "jti"');
            }
            try {
                $fresh = $consume($jti, $base['exp']) === true;
            } catch (\Throwable) {
                $fresh = false; // a failing store is never a pass
            }
            if (!$fresh) {
                throw self::fail('grant', 'ID-JAG jti was already used or the single-use store failed');
            }
        }
        $grant = ['iss' => $base['iss'], 'sub' => $base['sub'], 'actor' => $actor, 'agent' => $actor->get('sub'), 'audience' => $audience,
            'scopes' => $scopes, 'iat' => $base['iat'], 'exp' => $base['exp']];
        if ($jti !== null) {
            $grant['jti'] = $jti;
        }
        foreach (['nonce', 'cnf'] as $k) {
            if (array_key_exists($k, $base)) {
                $grant[$k] = $base[$k];
            }
        }
        $grant['oidcClaims'] = $base;
        return $grant;
    }

    /** The PCA principal of a verified grant (Oidc::oidcPrincipal over its oidcClaims). */
    public static function idJagToPcaPrincipal(mixed $grant, mixed $opts = null): array
    {
        if (!self::isOpts($grant)) {
            throw new \TypeError('idJagToPcaPrincipal: grant is required');
        }
        return Oidc::oidcPrincipal(Js::opt($grant, 'oidcClaims'), $opts ?? []);
    }

    /**
     * Project a verified grant onto a signed ROOT capability (authority = scopes, holder = the agent key, subject = the human,
     * plus a provenance caveat): {capability, principal, scopes}. Options: principalSecret (a 32-byte Ed25519 seed or a
     * KeyPair), principalPublic (b64u; must equal the key's public key and any cnf-bound key), holder (b64u), optional alg /
     * pq (the root hop's suite, as Agent::mintRoot), extraCaveats.
     */
    public static function idJagToCapability(mixed $grant, mixed $opts): array
    {
        if (!self::isOpts($grant)) {
            throw new \TypeError('idJagToCapability: grant is required');
        }
        if (!self::isOpts($opts)) {
            throw new \TypeError('idJagToCapability: opts is required');
        }
        $o = static fn(string $k): mixed => Js::opt($opts, $k);
        $g = static fn(string $k): mixed => Js::opt($grant, $k);
        $secret = $o('principalSecret');
        if (!($secret instanceof KeyPair) && !is_string($secret)) {
            throw new \TypeError('idJagToCapability: opts.principalSecret must be a Uint8Array');
        }
        if (!self::nonEmpty($o('principalPublic'))) {
            throw new \TypeError('idJagToCapability: opts.principalPublic is required');
        }
        if (!self::nonEmpty($o('holder'))) {
            throw new \TypeError('idJagToCapability: opts.holder (the agent key) is required');
        }
        $principal = self::idJagToPcaPrincipal($grant, ['principalPublic' => $o('principalPublic')]);
        $scopes = Js::spread($g('scopes'));
        $authority = Obj::of(['type' => self::IDJAG_AUTHORITY_CAVEAT, 'scopes' => $scopes, 'aud' => $g('audience')]);
        $provenance = Obj::of(['type' => self::IDJAG_PROVENANCE_CAVEAT, 'iss' => $g('iss'), 'sub' => $g('sub'), 'agent' => $g('agent'),
            'aud' => $g('audience'), 'iat' => $g('iat'), 'exp' => $g('exp')]);
        if ($g('jti') !== null) {
            $provenance->set('jti', $g('jti'));
        }
        $extra = $o('extraCaveats');
        $caveats = [$authority, $provenance, $principal['subjectCaveat'], ...($extra === null ? [] : Js::spread($extra))];
        $kp = $secret instanceof KeyPair ? $secret : new KeyPair($secret);
        if ($kp->public !== $o('principalPublic')) {
            throw new \InvalidArgumentException('idJagToCapability: opts.principalSecret does not belong to opts.principalPublic');
        }
        $capability = Sign::mintRoot($kp, $o('holder'), $caveats, null, $o('alg'), $o('pq'));
        return ['capability' => $capability, 'principal' => $principal, 'scopes' => $scopes];
    }

    public static function isIdJagAuthorityCaveat(mixed $cv): bool
    {
        return Js::isObj($cv) && Js::opt($cv, 'type') === self::IDJAG_AUTHORITY_CAVEAT && Js::isStrList(Js::opt($cv, 'scopes'))
            && self::nonEmpty(Js::opt($cv, 'aud'));
    }

    public static function isIdJagProvenanceCaveat(mixed $cv): bool
    {
        if (!Js::isObj($cv) || Js::opt($cv, 'type') !== self::IDJAG_PROVENANCE_CAVEAT) {
            return false;
        }
        foreach (['iss', 'sub', 'agent', 'aud'] as $k) {
            if (!is_string(Js::opt($cv, $k))) {
                return false;
            }
        }
        return Js::isNum(Js::opt($cv, 'iat')) && Js::isNum(Js::opt($cv, 'exp'));
    }

    private static function findCaveat(mixed $cap, string $type): mixed
    {
        if (!Js::isObj($cap) || Js::opt($cap, 'caveats') === null) {
            return null;
        }
        $cavs = Js::opt($cap, 'caveats');
        if (!is_array($cavs) || !array_is_list($cavs)) {
            throw new \TypeError('caveats.find is not a function');
        }
        foreach ($cavs as $c) {
            if (Js::isObj($c) && Js::opt($c, 'type') === $type) {
                return $c;
            }
        }
        return null;
    }

    /** The authority caveat of a root capability, or null when absent or malformed. */
    public static function readIdJagAuthority(mixed $cap): mixed
    {
        $cv = self::findCaveat($cap, self::IDJAG_AUTHORITY_CAVEAT);
        return $cv !== null && self::isIdJagAuthorityCaveat($cv) ? $cv : null;
    }

    /** The provenance caveat of a root capability, or null when absent or malformed. */
    public static function readIdJagProvenance(mixed $cap): mixed
    {
        $cv = self::findCaveat($cap, self::IDJAG_PROVENANCE_CAVEAT);
        return $cv !== null && self::isIdJagProvenanceCaveat($cv) ? $cv : null;
    }

    // ---- XAA request shapes ----

    /** application/x-www-form-urlencoded byte serializer (URLSearchParams): alphanumerics and `*-._` stay, space is `+`. */
    private static function formEncode(string $s): string
    {
        $enc = preg_replace_callback('/[^A-Za-z0-9*\-._ ]/', static fn(array $m): string => sprintf('%%%02X', ord($m[0])), Js::utf8($s));
        return str_replace(' ', '+', (string)$enc);
    }

    /** @param array<string,mixed> $params */
    private static function formRequest(string $url, array $params): array
    {
        $clean = [];
        foreach ($params as $k => $v) {
            if (self::nonEmpty($v)) {
                $clean[(string)$k] = $v;
            }
        }
        $p = new Obj();
        $body = [];
        foreach (Js::ownKeys(array_map('strval', array_keys($clean))) as $k) {
            $p->set($k, $clean[$k]);
            $body[] = self::formEncode($k) . '=' . self::formEncode($clean[$k]);
        }
        return ['url' => $url, 'method' => 'POST', 'headers' => ['content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json'],
            'params' => $p, 'body' => implode('&', $body)];
    }

    private static function scopeParam(mixed $scope): ?string
    {
        if ($scope === null) {
            return null;
        }
        if (is_array($scope) && array_is_list($scope)) {
            $parts = $scope;
        } elseif (is_string($scope)) {
            $parts = preg_split(self::JS_WS, $scope) ?: [];
        } else {
            throw new \TypeError('scope.split is not a function');
        }
        $parts = self::cleanStrings($parts);
        return $parts === [] ? null : implode(' ', $parts);
    }

    /**
     * `...extra` of a JS object spread: an object's members, a list's / string's indexed elements, nothing for the rest.
     * @param array<string,mixed> $params
     */
    private static function spreadInto(array &$params, mixed $extra): void
    {
        if ($extra instanceof Obj) {
            foreach ($extra->keys() as $k) {
                $params[$k] = $extra->get($k);
            }
        } elseif (is_array($extra)) {
            foreach ($extra as $k => $v) {
                $params[(string)$k] = $v;
            }
        } elseif (is_string($extra)) {
            foreach (Js::spread($extra) as $i => $ch) {
                $params[(string)$i] = $ch;
            }
        }
    }

    /**
     * The RFC 8693 token-exchange POST that OBTAINS an ID-JAG from the IdP. Options: tokenEndpoint, subjectToken (required);
     * subjectTokenType, actorToken, actorTokenType, audience, resource, scope (string | list), requestedTokenType, clientId,
     * extra. {url, method, headers, params, body}.
     */
    public static function tokenExchangeRequest(mixed $opts): array
    {
        if (!self::isOpts($opts)) {
            throw new \TypeError('tokenExchangeRequest: opts is required');
        }
        $o = static fn(string $k): mixed => Js::opt($opts, $k);
        if (!self::nonEmpty($o('tokenEndpoint'))) {
            throw new \TypeError('tokenExchangeRequest: opts.tokenEndpoint is required');
        }
        if (!self::nonEmpty($o('subjectToken'))) {
            throw new \TypeError('tokenExchangeRequest: opts.subjectToken is required');
        }
        $actor = $o('actorToken');
        $params = ['grant_type' => self::GRANT_TYPE_TOKEN_EXCHANGE, 'subject_token' => $o('subjectToken'),
            'subject_token_type' => $o('subjectTokenType') ?? self::TOKEN_TYPE_ID_TOKEN,
            'requested_token_type' => $o('requestedTokenType') ?? self::TOKEN_TYPE_ID_JAG];
        foreach (['audience' => 'audience', 'resource' => 'resource'] as $k => $p) {
            if ($o($k) !== null) {
                $params[$p] = $o($k);
            }
        }
        $scope = self::scopeParam($o('scope'));
        if ($scope !== null) {
            $params['scope'] = $scope;
        }
        if (self::nonEmpty($actor)) {
            $params['actor_token'] = $actor;
            $params['actor_token_type'] = $o('actorTokenType') ?? self::TOKEN_TYPE_JWT;
        }
        if ($o('clientId') !== null) {
            $params['client_id'] = $o('clientId');
        }
        self::spreadInto($params, $o('extra'));
        return self::formRequest($o('tokenEndpoint'), $params);
    }

    /**
     * The RFC 7523 jwt-bearer form of an ID-JAG being REDEEMED at the target app. Options: tokenEndpoint, assertion (required);
     * scope, clientId, clientAssertion, extra. {grantType, assertion, scope?, request}.
     */
    public static function jwtBearerAssertion(mixed $opts): array
    {
        if (!self::isOpts($opts)) {
            throw new \TypeError('jwtBearerAssertion: opts is required');
        }
        $o = static fn(string $k): mixed => Js::opt($opts, $k);
        if (!self::nonEmpty($o('tokenEndpoint'))) {
            throw new \TypeError('jwtBearerAssertion: opts.tokenEndpoint is required');
        }
        if (!self::nonEmpty($o('assertion'))) {
            throw new \TypeError('jwtBearerAssertion: opts.assertion is required');
        }
        $scope = self::scopeParam($o('scope'));
        $ca = $o('clientAssertion');
        $params = ['grant_type' => self::GRANT_TYPE_JWT_BEARER, 'assertion' => $o('assertion')];
        if ($scope !== null) {
            $params['scope'] = $scope;
        }
        if ($o('clientId') !== null) {
            $params['client_id'] = $o('clientId');
        }
        if (self::nonEmpty($ca)) {
            $params['client_assertion_type'] = self::CLIENT_ASSERTION_TYPE_JWT_BEARER;
            $params['client_assertion'] = $ca;
        }
        self::spreadInto($params, $o('extra'));
        $out = ['grantType' => self::GRANT_TYPE_JWT_BEARER, 'assertion' => $o('assertion')];
        if ($scope !== null) {
            $out['scope'] = $scope;
        }
        $out['request'] = self::formRequest($o('tokenEndpoint'), $params);
        return $out;
    }
}
