<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/Oidc.php';
require_once __DIR__ . '/WhatwgUrl.php';

/**
 * Signed A2A Agent Cards and NANDA-style AgentFacts attested by PCA, the well-known hosting handlers and the registry entry
 * (the package surface of the reference). Values are the parsed-JSON model (Obj, lists, string, Num / int / float, bool, null);
 * options accept an Obj or a PHP assoc array keyed by the reference's names. Results are PHP assoc arrays (Obj where a map may be
 * empty). Everything fails closed: a missing signature, an unresolvable key, a tampered body, a bad or expired attestation or an
 * attestation about another subject is refused.
 *
 * shortcut: validity windows read ISO 8601 only (YYYY[-MM[-DD]] with optional THH:mm[:ss[.fff]] and Z or +HH:mm; no offset = UTC);
 * the legacy free-form spellings a JavaScript runtime also accepts are refused as not a valid date. Widen if issuers need them.
 * shortcut: a private JWK given as a single verification key is checked for Ed25519 d/x agreement only; EC / RSA private
 * members are dropped without a consistency check (the public members decide the verification).
 */
final class Agentcard
{
    public const DEFAULT_ALG = 'EdDSA';
    public const AGENT_FACTS_CONTEXT = ['https://www.w3.org/ns/did/v1', 'https://nanda.ai/agentfacts/v1'];
    public const PCA_ATTESTOR_ID = 'did:atlas:pca-attestor';
    public const WELL_KNOWN_AGENT_CARD_PATH = '/.well-known/agent-card.json';
    public const WELL_KNOWN_AGENT_FACTS_PATH = '/.well-known/agent-facts.json';
    private const PCA_PASSPORT_HEADER = 'pca_passport';
    private const ATTESTATION_DOMAIN = 'atlas-pca/agentfacts/attestation/v1';
    private const MAX_DEPTH = 64;

    // ---- small JS-model helpers ----

    private static ?\stdClass $undef = null;

    /** The reference's `undefined` (a member that is absent), distinct from null. */
    private static function undef(): \stdClass
    {
        return self::$undef ??= new \stdClass();
    }

    private static function g(mixed $o, string $k): mixed
    {
        return Js::has($o, $k) ? Js::opt($o, $k) : self::undef();
    }

    private static function isU(mixed $v): bool
    {
        return $v === self::undef();
    }

    private static function nullish(mixed $v): bool
    {
        return $v === null || $v === self::undef();
    }

    /** A JSON object as an Obj (copy); anything else is the TypeError a property read or spread would raise. */
    private static function obj(mixed $v): Obj
    {
        if ($v instanceof Obj) {
            $c = new Obj();
            foreach ($v->keys() as $k) {
                $c->set($k, $v->get($k));
            }
            return $c;
        }
        if (is_array($v) && !array_is_list($v)) {
            return Obj::of($v);
        }
        throw new \TypeError('value is not an object');
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    // ---- RFC 8785 canonical bytes ----

    /** JCS bytes of a JSON value (UTF-16 key order, ECMAScript numbers); throws on a non-finite number, a lone surrogate or nesting over 64. */
    public static function jcsBytes(mixed $value): string
    {
        return self::jcs($value, 1);
    }

    private static function jcs(mixed $v, int $depth): string
    {
        if ($v === null) {
            return 'null';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (Js::isNum($v)) {
            $f = Js::num($v);
            if ($f === null || !is_finite($f)) {
                throw new \TypeError('jcs: non-finite number');
            }
            return Js::stringify($v);
        }
        if (is_string($v)) {
            if (Json::hasLoneSurrogate($v)) {
                throw new \TypeError('jcs: lone surrogate in string');
            }
            return Js::stringify($v);
        }
        if (!is_array($v) && !($v instanceof Obj)) {
            throw new \TypeError('jcs: unsupported type ' . get_debug_type($v));
        }
        if ($depth > self::MAX_DEPTH) {
            throw new \TypeError('jcs: nesting too deep');
        }
        if (self::isList($v)) {
            return '[' . implode(',', array_map(fn($x) => self::jcs($x, $depth + 1), $v)) . ']';
        }
        $o = self::obj($v);
        $keys = $o->keys();
        $units = [];
        foreach ($keys as $k) { // default sort = UTF-16 code unit order; a lone surrogate key throws below either way
            $u = @mb_convert_encoding($k, 'UTF-16BE', 'UTF-8');
            $units[$k] = is_string($u) ? $u : $k;
        }
        usort($keys, static fn(string $a, string $b): int => strcmp($units[$a], $units[$b]));
        $parts = [];
        foreach ($keys as $k) {
            if (Json::hasLoneSurrogate($k)) {
                throw new \TypeError('jcs: lone surrogate in key');
            }
            $parts[] = Js::stringify($k) . ':' . self::jcs($o->get($k), $depth + 1);
        }
        return '{' . implode(',', $parts) . '}';
    }

    // ---- A2A 1.0 AgentCard schema check ----

    /** @return list<string> the problems with a card against the A2A 1.0 AgentCard message (empty = conforms) */
    public static function validateAgentCard1(mixed $card): array
    {
        $p = [];
        if (!Js::isObj($card)) {
            return ['$: the agent card must be an object'];
        }
        $isStr = static fn(mixed $v): bool => is_string($v);
        $reqStr = function (mixed $o, string $k, string $at) use (&$p, $isStr): void {
            $v = self::g($o, $k);
            if (!$isStr($v) || $v === '') {
                $p[] = "$at.$k: required non-empty string";
            }
        };
        $optStr = function (mixed $o, string $k, string $at) use (&$p, $isStr): void {
            $v = self::g($o, $k);
            if (!self::isU($v) && !$isStr($v)) {
                $p[] = "$at.$k: must be a string";
            }
        };
        $optBool = function (mixed $o, string $k, string $at) use (&$p): void {
            $v = self::g($o, $k);
            if (!self::isU($v) && !is_bool($v)) {
                $p[] = "$at.$k: must be a boolean";
            }
        };
        $strArray = function (mixed $v, string $at, bool $nonEmpty) use (&$p): void {
            if (!Js::isStrList($v)) {
                $p[] = "$at: must be an array of strings";
            } elseif ($nonEmpty && count($v) === 0) {
                $p[] = "$at: must not be empty";
            }
        };
        $objArray = function (mixed $o, string $k, string $at, bool $required, bool $nonEmpty, callable $each) use (&$p): void {
            $v = self::g($o, $k);
            if (self::isU($v)) {
                if ($required) {
                    $p[] = "$at.$k: required array";
                }
                return;
            }
            if (!self::isList($v)) {
                $p[] = "$at.$k: must be an array";
                return;
            }
            if ($nonEmpty && count($v) === 0) {
                $p[] = "$at.$k: must not be empty";
            }
            foreach ($v as $i => $e) {
                if (Js::isObj($e)) {
                    $each($e, "{$at}.{$k}[{$i}]");
                } else {
                    $p[] = "{$at}.{$k}[{$i}]: must be an object";
                }
            }
        };

        $reqStr($card, 'name', '$');
        $reqStr($card, 'description', '$');
        $reqStr($card, 'version', '$');
        $optStr($card, 'documentationUrl', '$');
        $optStr($card, 'iconUrl', '$');
        $objArray($card, 'supportedInterfaces', '$', true, true, function ($e, $at) use ($reqStr, $optStr): void {
            $reqStr($e, 'url', $at);
            $reqStr($e, 'protocolBinding', $at);
            $reqStr($e, 'protocolVersion', $at);
            $optStr($e, 'tenant', $at);
        });
        $prov = self::g($card, 'provider');
        if (!self::isU($prov)) {
            if (!Js::isObj($prov)) {
                $p[] = '$.provider: must be an object';
            } else {
                $reqStr($prov, 'url', '$.provider');
                $reqStr($prov, 'organization', '$.provider');
            }
        }
        $cap = self::g($card, 'capabilities');
        if (!Js::isObj($cap)) {
            $p[] = '$.capabilities: required object';
        } else {
            $optBool($cap, 'streaming', '$.capabilities');
            $optBool($cap, 'pushNotifications', '$.capabilities');
            $optBool($cap, 'extendedAgentCard', '$.capabilities');
            $objArray($cap, 'extensions', '$.capabilities', false, false, function ($e, $at) use (&$p, $optStr, $optBool): void {
                $optStr($e, 'uri', $at);
                $optStr($e, 'description', $at);
                $optBool($e, 'required', $at);
                $pa = self::g($e, 'params');
                if (!self::isU($pa) && !Js::isObj($pa)) {
                    $p[] = "$at.params: must be an object";
                }
            });
        }
        $ss = self::g($card, 'securitySchemes');
        if (!self::isU($ss) && !Js::isObj($ss)) {
            $p[] = '$.securitySchemes: must be an object';
        }
        $sr = self::g($card, 'securityRequirements');
        if (!self::isU($sr) && !self::isList($sr)) {
            $p[] = '$.securityRequirements: must be an array';
        }
        foreach (['defaultInputModes', 'defaultOutputModes'] as $k) {
            $v = self::g($card, $k);
            if (self::isU($v)) {
                $p[] = "\$.$k: required array of strings";
            } else {
                $strArray($v, "\$.$k", true);
            }
        }
        $objArray($card, 'skills', '$', true, false, function ($e, $at) use (&$p, $reqStr, $strArray): void {
            $reqStr($e, 'id', $at);
            $reqStr($e, 'name', $at);
            $reqStr($e, 'description', $at);
            $tags = self::g($e, 'tags');
            if (self::isU($tags)) {
                $p[] = "$at.tags: required array of strings";
            } else {
                $strArray($tags, "$at.tags", false);
            }
            foreach (['examples', 'inputModes', 'outputModes'] as $k) {
                $v = self::g($e, $k);
                if (!self::isU($v)) {
                    $strArray($v, "$at.$k", false);
                }
            }
            $r = self::g($e, 'securityRequirements');
            if (!self::isU($r) && !self::isList($r)) {
                $p[] = "$at.securityRequirements: must be an array";
            }
        });
        $objArray($card, 'signatures', '$', false, false, function ($e, $at) use (&$p, $reqStr): void {
            $reqStr($e, 'protected', $at);
            $reqStr($e, 'signature', $at);
            $h = self::g($e, 'header');
            if (!self::isU($h) && !Js::isObj($h)) {
                $p[] = "$at.header: must be an object";
            }
        });
        return $p;
    }

    // ---- keys + detached JWS core (shared by the card, the facts and the A2A package) ----

    private static function isJwk(mixed $k): bool
    {
        return Js::isObj($k) && Js::has($k, 'kty');
    }

    /**
     * Sign `$payload` as a detached JWS. `$o`: alg, kid (a present null is written), header (extra protected members), standardPayload
     * (A2A 1.0 section 8.4: typ JOSE and a base64url payload in the signing input, instead of b64:false).
     * @internal
     * @return array{protected:string,signature:string}
     */
    public static function signDetached(string $payload, mixed $key, array $o = []): array
    {
        $alg = $o['alg'] ?? self::DEFAULT_ALG;
        $std = ($o['standardPayload'] ?? false) === true;
        $h = new Obj();
        $h->set('alg', $alg);
        if ($std) {
            $h->set('typ', 'JOSE');
        } else {
            $h->set('b64', false);
            $h->set('crit', ['b64']);
        }
        if (array_key_exists('kid', $o)) {
            $h->set('kid', $o['kid']);
        }
        foreach ($o['header'] ?? [] as $k => $v) {
            if (!self::isU($v)) {
                $h->set((string)$k, $v);
            }
        }
        if (!is_string($alg) || $alg === '') {
            throw new JoseError('"alg" (Algorithm) Header Parameter missing or invalid');
        }
        $prot = Jose::b64u(Js::utf8(Js::stringify($h)));
        $sig = Jose::jwsSign($alg, $key, $prot . '.' . ($std ? Jose::b64u($payload) : $payload));
        return ['protected' => $prot, 'signature' => Jose::b64u($sig)];
    }

    /**
     * Key material for verification: ['resolver', Closure] (a JWKS), ['key', raw|PubKey] or ['none'] (a key no signature can
     * verify under, as the reference's non-JWK key), or ['error', message].
     * @internal
     */
    public static function resolveVerifyKey(mixed $opts): array
    {
        try {
            $jwks = Js::opt($opts, 'jwks');
            if (Js::truthy($jwks)) {
                return ['resolver', Oidc::createLocalJwkSet($jwks)];
            }
            if (Js::has($opts, 'key')) {
                $key = Js::opt($opts, 'key');
                if (!self::isJwk($key)) {
                    return ['none'];
                }
                if (Js::opt($key, 'kty') === 'oct') {
                    if (!is_string(Js::opt($key, 'k'))) {
                        throw new JoseError('missing "k" in the oct JWK');
                    }
                    return ['none']; // a symmetric key never verifies a public-key algorithm
                }
                return ['key', self::publicOf($key)];
            }
            return ['error', 'no verification key or JWKS supplied'];
        } catch (\Throwable $e) {
            return ['error', 'could not resolve verification key: ' . $e->getMessage()];
        }
    }

    /** The verification key of a (possibly private) JWK: a private member is dropped, an Ed25519 d must agree with x. */
    private static function publicOf(mixed $jwk): string|Attest\PubKey
    {
        $o = self::obj($jwk);
        if ($o->has('d') && $o->get('kty') === 'OKP' && $o->get('crv') === 'Ed25519') {
            $seed = is_string($o->get('d')) ? Jose::lenientB64d($o->get('d')) : '';
            $x = is_string($o->get('x')) ? Jose::lenientB64d($o->get('x')) : '';
            if (strlen($seed) !== 32 || sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)) !== $x) {
                throw new JoseError('invalid Ed25519 key: d does not match x');
            }
        }
        [, $k] = Jose::publicKeyFromJwk($o->without('d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'));
        return $k;
    }

    /**
     * Verify a detached JWS over `$payload`: the canonical-spelling gate first, then the JOSE checks (crit, alg, key) and the signature.
     * Never throws.
     * @internal
     * @param array{0:string,1?:mixed} $key from resolveVerifyKey
     * @return array{ok:bool,reason?:string,protectedHeader?:Obj}
     */
    public static function verifyDetached(string $payload, mixed $sig, array $key): array
    {
        $prot = Js::opt($sig, 'protected');
        $sg = Js::opt($sig, 'signature');
        if (!Js::isObj($sig) || !is_string($prot) || !is_string($sg)) {
            return ['ok' => false, 'reason' => 'signature is malformed'];
        }
        try {
            $h = Jose::assertCanonicalJwsSegments($prot, $sg); // canonical-spelling gate BEFORE any signature check
            $raw = $h->get('b64') === false;
            $b64 = true;
            if ($h->has('crit')) {
                $c = $h->get('crit');
                if (!self::isList($c) || $c === [] || array_filter($c, static fn(mixed $x): bool => !is_string($x) || $x === '') !== []) {
                    throw new JoseError('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
                }
                foreach ($c as $n) {
                    if ($n !== 'b64') {
                        throw new JoseError("Extension Header Parameter \"$n\" is not recognized");
                    }
                    if (!$h->has($n)) {
                        throw new JoseError("Extension Header Parameter \"$n\" is missing");
                    }
                }
                if (in_array('b64', $c, true)) {
                    $b64 = $h->get('b64');
                    if (!is_bool($b64)) {
                        throw new JoseError('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
                    }
                }
            }
            if ($b64 === $raw) {
                throw new JoseError('JWS payload does not match the b64 header'); // b64:false without crit, as the library refuses
            }
            $alg = $h->get('alg');
            if (!is_string($alg) || $alg === '') {
                throw new JoseError('JWS "alg" (Algorithm) Header Parameter missing or invalid');
            }
            if ($key[0] === 'resolver') {
                $jwk = ($key[1])($h);
                $k = self::publicOf($jwk);
            } elseif ($key[0] === 'key') {
                $k = $key[1];
            } else {
                throw new JoseError('Invalid key for this operation');
            }
            if (!Jose::jwsVerify($alg, $k, Jose::lenientB64d($sg), $prot . '.' . ($raw ? $payload : Jose::b64u($payload)))) {
                throw new JoseError('signature verification failed');
            }
            return ['ok' => true, 'protectedHeader' => $h];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => $e->getMessage()];
        }
    }

    // ---- 1. signed Agent Card ----

    /** `'model_id' in p` then the reference's id / uri pick: a bare reference keeps its own uri, a full passport takes `$uri`. */
    private static function passportRefFrom(mixed $p, mixed $uri): Obj
    {
        if (!Js::isObj($p)) {
            throw new \TypeError("Cannot use 'in' operator on a non-object");
        }
        $o = new Obj();
        if (Js::has($p, 'id')) {
            $o->set('id', Js::opt($p, 'id'));
        }
        if (Js::has($p, 'model_id')) {
            if (!self::isU($uri)) {
                $o->set('uri', $uri);
            }
        } elseif (Js::has($p, 'uri')) {
            $o->set('uri', Js::opt($p, 'uri'));
        } elseif (!self::isU($uri)) {
            $o->set('uri', $uri);
        }
        return $o;
    }

    /**
     * An unsigned Agent Card from a PCA passport (or a bare {id, uri?} reference): the card points at the passport (`pcaPassport`)
     * and, when given, the live proof endpoint (`pcaProof`). Options: name, skills, url, description, version, passportUri, pcaProofRef.
     */
    public static function buildAgentCard(mixed $passport, mixed $opts): Obj
    {
        $card = new Obj();
        $name = self::g($opts, 'name');
        if (!self::isU($name)) {
            $card->set('name', $name);
        }
        foreach (['description', 'url', 'version', 'skills'] as $k) {
            $v = self::g($opts, $k);
            if (!self::isU($v)) {
                $card->set($k, $v);
            }
        }
        $card->set('pcaPassport', self::passportRefFrom($passport, self::g($opts, 'passportUri')));
        $pr = self::g($opts, 'pcaProofRef');
        if (!self::isU($pr)) {
            $card->set('pcaProof', $pr);
        }
        return $card;
    }

    /** The bytes a card signature covers: the card without `signatures`, as RFC 8785 requires. @internal */
    public static function cardSigningBytes(mixed $card): string
    {
        return self::jcsBytes(self::obj($card)->without('signatures'));
    }

    /**
     * Sign an A2A Agent Card: a passport reference is embedded (`pcaPassport`) and committed in the protected header (`pca_passport`),
     * the canonical card (minus `signatures`) is signed and the detached signature appended. Options: alg, passport, kid,
     * profile ('pca-detached' | 'a2a-1.0', which needs a kid), schema ('a2a-1.0'). Throws on any problem.
     */
    public static function issueSignedAgentCard(mixed $card, mixed $signingKey, mixed $opts = null): Obj
    {
        $card = self::obj($card);
        $op = Js::opt($opts, 'passport');
        if (Js::truthy($op)) {
            if (!Js::isObj($op)) {
                throw new \TypeError("Cannot use 'in' operator on a non-object");
            }
            $passport = new Obj();
            if (!Js::has($op, 'id')) {
                throw new \TypeError('jcs: unsupported type undefined'); // {id: undefined} has no canonical form
            }
            $passport->set('id', Js::opt($op, 'id'));
            if (Js::has($op, 'uri')) {
                $uri = Js::opt($op, 'uri');
                $passport->set('uri', $uri);
            }
        } else {
            $passport = $card->get('pcaPassport');
        }
        $toSign = $card;
        if (Js::truthy($passport)) {
            $toSign->set('pcaPassport', $passport);
        }
        if (Js::opt($opts, 'schema') === 'a2a-1.0') {
            $problems = self::validateAgentCard1($toSign);
            if ($problems !== []) {
                throw new \RuntimeException('issueSignedAgentCard: the card does not match the A2A 1.0 schema: ' . implode('; ', $problems));
            }
        }
        $payload = self::cardSigningBytes($toSign);
        $spec = Js::opt($opts, 'profile') === 'a2a-1.0';
        $kid = Js::opt($opts, 'kid');
        if ($spec && (!is_string($kid) || $kid === '')) {
            throw new \RuntimeException("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid");
        }
        $so = [];
        if ($spec) {
            $so['standardPayload'] = true;
        }
        if (Js::has($opts, 'alg') && Js::opt($opts, 'alg') !== null) {
            $so['alg'] = Js::opt($opts, 'alg');
        }
        if (Js::has($opts, 'kid')) {
            $so['kid'] = $kid;
        }
        if (Js::truthy($passport)) {
            $id = Js::isObj($passport) ? self::g($passport, 'id') : self::undef();
            $so['header'] = [self::PCA_PASSPORT_HEADER => $id];
        }
        $signature = self::signDetached($payload, $signingKey, $so);
        $existing = $toSign->get('signatures') === null ? [] : Js::spread($toSign->get('signatures'));
        $out = self::obj($toSign);
        $out->set('signatures', [...$existing, Obj::of($signature)]);
        return $out;
    }

    /**
     * Validate a card against its signature(s). Fail-closed: no signatures, an unresolvable key or ANY signature that does not verify
     * over the canonical card (minus `signatures`) refuses. Options: jwks, key, alg, schema. On success: passportRef (from the
     * verified protected header), passport and pcaProof (from the card body).
     * @return array<string,mixed>
     */
    public static function verifyAgentCard(mixed $card, mixed $opts): array
    {
        if (!($card instanceof Obj) && !is_array($card)) {
            return ['ok' => false, 'reason' => 'agent card is not an object'];
        }
        $signatures = Js::opt($card, 'signatures');
        if (!self::isList($signatures) || count($signatures) === 0) {
            return ['ok' => false, 'reason' => 'agent card carries no signatures'];
        }
        if (Js::opt($opts, 'schema') === 'a2a-1.0') {
            $problems = self::validateAgentCard1($card);
            if ($problems !== []) {
                return ['ok' => false, 'reason' => 'agent card does not match the A2A 1.0 schema: ' . implode('; ', $problems)];
            }
        }
        $key = self::resolveVerifyKey($opts);
        if ($key[0] === 'error') {
            return ['ok' => false, 'reason' => $key[1]];
        }
        try {
            $payload = self::cardSigningBytes($card);
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'agent card has no canonical form: ' . $e->getMessage()];
        }
        $passportRef = null;
        foreach ($signatures as $i => $sig) {
            if (!Js::truthy($sig)) {
                return ['ok' => false, 'reason' => "signature $i is missing"];
            }
            $r = self::verifyDetached($payload, $sig, $key);
            if (!$r['ok']) {
                return ['ok' => false, 'reason' => "signature $i did not verify: " . $r['reason']];
            }
            $ref = $r['protectedHeader']->get(self::PCA_PASSPORT_HEADER);
            if (is_string($ref) && $passportRef === null) {
                $passportRef = $ref;
            }
        }
        $out = ['ok' => true];
        if ($passportRef !== null) {
            $out['passportRef'] = $passportRef;
        }
        if (Js::truthy(Js::opt($card, 'pcaPassport'))) {
            $out['passport'] = Js::opt($card, 'pcaPassport');
        }
        if (Js::truthy(Js::opt($card, 'pcaProof'))) {
            $out['pcaProof'] = Js::opt($card, 'pcaProof');
        }
        return $out;
    }

    // ---- dates ----

    private static function daysFromCivil(int $y, int $m, int $d): int
    {
        $y -= $m <= 2 ? 1 : 0;
        $era = intdiv($y >= 0 ? $y : $y - 399, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    /** Date.parse for the ISO 8601 spellings (epoch milliseconds); null (NaN) for anything else. */
    public static function dateParse(mixed $s): ?float
    {
        if (!is_string($s)
            || preg_match('/\A([+-]\d{6}|\d{4})(?:-(\d{2})(?:-(\d{2}))?)?(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:\d{2})?)?\z/', $s, $m) !== 1) {
            return null;
        }
        $m += array_fill(0, 9, '');
        if ($m[1] === '-000000') {
            return null;
        }
        $y = (int)$m[1];
        $mo = $m[2] !== '' ? (int)$m[2] : 1;
        $d = $m[3] !== '' ? (int)$m[3] : 1;
        $hh = (int)$m[4];
        $mi = (int)$m[5];
        $ss = (int)$m[6];
        $ms = $m[7] !== '' ? (int)substr($m[7] . '00', 0, 3) : 0;
        if ($mo < 1 || $mo > 12 || $d < 1 || $d > 31 || $mi > 59 || $ss > 59 || $hh > 24 || ($hh === 24 && ($mi || $ss || $ms))) {
            return null;
        }
        $off = 0;
        if ($m[8] !== '' && $m[8] !== 'Z') {
            $oh = (int)substr($m[8], 1, 2);
            $om = (int)substr($m[8], 4, 2);
            if ($oh > 23 || $om > 59) {
                return null;
            }
            $off = ($oh * 60 + $om) * ($m[8][0] === '+' ? 1 : -1);
        }
        $t = (self::daysFromCivil($y, $mo, $d) * 86400 + $hh * 3600 + $mi * 60 + $ss) * 1000 + $ms - $off * 60000;
        return abs($t) <= 8.64e15 ? (float)$t : null;
    }

    /** new Date(ms).toISOString(); a RangeError (RangeException) outside the Date range. @internal */
    public static function isoFromMs(float $ms): string
    {
        if (!is_finite($ms) || abs($ms) > 8.64e15) {
            throw new \RangeException('Invalid time value');
        }
        $t = (int)$ms;
        $days = intdiv($t - (($t % 86400000 + 86400000) % 86400000), 86400000);
        $rem = $t - $days * 86400000;
        $z = $days + 719468;
        $era = intdiv($z >= 0 ? $z : $z - 146096, 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $mo = $mp < 10 ? $mp + 3 : $mp - 9;
        $y = $yoe + $era * 400 + ($mo <= 2 ? 1 : 0);
        $ys = $y >= 0 && $y <= 9999 ? sprintf('%04d', $y) : sprintf('%s%06d', $y < 0 ? '-' : '+', abs($y));
        return sprintf('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', $ys, $mo, $d, intdiv($rem, 3600000), intdiv($rem, 60000) % 60, intdiv($rem, 1000) % 60, $rem % 1000);
    }

    private static function nowMs(mixed $v): float
    {
        if (self::nullish($v)) {
            return floor(microtime(true) * 1000);
        }
        $f = Js::num($v);
        if ($f === null) {
            throw new \TypeError('now must be a number');
        }
        return $f;
    }

    // ---- 2. AgentFacts ----

    private static function statementBytes(mixed $a): string
    {
        $o = new Obj();
        $o->set('d', self::ATTESTATION_DOMAIN);
        foreach (['issuer', 'subject', 'attests', 'validFrom'] as $k) {
            if (!Js::has($a, $k)) {
                throw new \TypeError("canonicalBytes: unsupported type undefined ($k)");
            }
            $o->set($k, Js::opt($a, $k));
        }
        $o->set('validUntil', Js::opt($a, 'validUntil'));
        return Json::canonicalizeNative($o);
    }

    /** @return Obj the signed attestation: the statement plus its detached signature */
    private static function signAttestation(Obj $statement, mixed $key, mixed $opts): Obj
    {
        $so = ['header' => ['attestor' => $statement->get('issuer')]];
        if (Js::has($opts, 'alg') && Js::opt($opts, 'alg') !== null) {
            $so['alg'] = Js::opt($opts, 'alg');
        }
        if (Js::has($opts, 'kid')) {
            $so['kid'] = Js::opt($opts, 'kid');
        }
        $sig = self::signDetached(self::statementBytes($statement), $key, $so);
        $out = self::obj($statement);
        $out->set('signature', Obj::of($sig));
        return $out;
    }

    /** `x.id`: a TypeError for null, and no value (undefined, which has no canonical form) when the member is absent. */
    private static function idOf(mixed $x): mixed
    {
        $v = Js::get($x, 'id');
        if (!Js::has($x, 'id')) {
            throw new \TypeError('canonicalBytes: unsupported type undefined (id)');
        }
        return $v;
    }

    private static function statement(mixed $issuer, mixed $subject, mixed $opts): Obj
    {
        $vf = Js::opt($opts, 'validFrom');
        $st = new Obj();
        $st->set('issuer', $issuer);
        $st->set('subject', $subject);
        if (Js::has($opts, 'attests')) {
            $st->set('attests', Js::opt($opts, 'attests'));
        }
        $st->set('validFrom', $vf ?? self::isoFromMs(self::nowMs(Js::opt($opts, 'now'))));
        if (Js::has($opts, 'validUntil')) {
            $st->set('validUntil', Js::opt($opts, 'validUntil'));
        }
        return $st;
    }

    /**
     * An AgentFacts document with PCA as the third-party attestor: `selfAsserted` claims travel unsigned, the `attests` claims are a
     * signed statement. Options: attestorKey, attests, selfAsserted, attestorId, agentId, alg, kid, validFrom, validUntil, now, context.
     */
    public static function issueAgentFacts(mixed $passport, mixed $opts): Obj
    {
        $agentId = Js::opt($opts, 'agentId') ?? self::idOf($passport);
        $st = self::statement(Js::opt($opts, 'attestorId') ?? self::PCA_ATTESTOR_ID, $agentId, $opts);
        $att = self::signAttestation($st, Js::opt($opts, 'attestorKey'), $opts);
        $out = new Obj();
        $out->set('@context', Js::opt($opts, 'context') ?? self::AGENT_FACTS_CONTEXT);
        $out->set('id', $agentId);
        $out->set('type', 'AgentFacts');
        $out->set('selfAsserted', Js::opt($opts, 'selfAsserted') ?? new Obj());
        $out->set('attestations', [$att]);
        return $out;
    }

    /** A copy of an AgentFacts document with one more attestation (several attestors vouch for different claims). Options as issueAgentFacts. */
    public static function addAttestation(mixed $facts, mixed $opts): Obj
    {
        $st = self::statement(Js::opt($opts, 'attestorId') ?? self::PCA_ATTESTOR_ID, self::idOf($facts), $opts);
        $att = self::signAttestation($st, Js::opt($opts, 'attestorKey'), $opts);
        $out = self::obj($facts);
        $out->set('attestations', [...Js::spread($out->get('attestations')), $att]);
        return $out;
    }

    /** @return array{issuer:string,ok:bool,reason:string} */
    private static function missingCheck(mixed $a): array
    {
        $i = Js::opt($a, 'issuer');
        return ['issuer' => is_string($i) ? $i : '<unknown>', 'ok' => false, 'reason' => 'no verification key or JWKS supplied'];
    }

    private static function verifyOne(mixed $a, mixed $docId, bool $docHas, float $now, ?array $key): array
    {
        $i = Js::opt($a, 'issuer');
        $issuer = is_string($i) ? $i : '<unknown>';
        $fail = static fn(string $r): array => ['issuer' => $issuer, 'ok' => false, 'reason' => $r];
        if (!Js::truthy($a) || !is_string(Js::opt($a, 'subject')) || !Js::isObj(Js::opt($a, 'attests')) || !is_string(Js::opt($a, 'validFrom'))) {
            return $fail('attestation is malformed');
        }
        if (Js::opt($a, 'subject') !== $docId) {
            return $fail("attestation subject '" . Js::opt($a, 'subject') . "' does not match agent id '" . ($docHas ? Js::str($docId) : 'undefined') . "'");
        }
        $from = self::dateParse(Js::opt($a, 'validFrom'));
        if ($from === null) {
            return $fail('attestation validFrom is not a valid date');
        }
        if (!(is_finite($now) && $now >= $from)) {
            return $fail('attestation is not yet valid');
        }
        if (Js::has($a, 'validUntil')) {
            $until = self::dateParse(Js::opt($a, 'validUntil'));
            if ($until === null) {
                return $fail('attestation validUntil is not a valid date');
            }
            if (!(is_finite($now) && $now <= $until)) {
                return $fail('attestation has expired');
            }
        }
        if ($key === null) {
            return $fail('no verification key or JWKS supplied');
        }
        $r = self::verifyDetached(self::statementBytes($a), Js::opt($a, 'signature'), $key);
        if (!$r['ok']) {
            return $fail('signature did not verify: ' . $r['reason']);
        }
        return ['issuer' => $issuer, 'ok' => true, 'attests' => Js::opt($a, 'attests')];
    }

    /**
     * Verify an AgentFacts document, failing closed: an attestation about another subject, outside its validity window or whose
     * detached signature does not verify refuses and fails the whole document. The result separates the claims a third party attests
     * from those only self-asserted. Options: jwks, key, alg, now (epoch ms).
     * @return array<string,mixed>
     */
    public static function verifyAgentFacts(mixed $facts, mixed $opts): array
    {
        $sa = Js::get($facts, 'selfAsserted');
        $selfAsserted = Js::isObj($sa) ? self::obj($sa) : new Obj();
        $now = self::nowMs(Js::opt($opts, 'now'));
        $docHas = Js::has($facts, 'id');
        $docId = Js::opt($facts, 'id');
        $base = ['ok' => false];
        if ($docHas) {
            $base['agentId'] = $docId;
        }
        $base += ['attestations' => [], 'attested' => new Obj(), 'selfAsserted' => $selfAsserted, 'claims' => new Obj()];
        $list = Js::opt($facts, 'attestations');
        if (!self::isList($list)) {
            return ['reason' => 'agent facts has no attestations array'] + $base;
        }
        $key = null;
        if (count($list) > 0) {
            $key = self::resolveVerifyKey($opts);
            if ($key[0] === 'error') {
                return ['reason' => $key[1], 'attestations' => array_map(self::missingCheck(...), $list)] + $base;
            }
        }
        $checks = [];
        $attested = new Obj();
        $allOk = true;
        foreach ($list as $a) {
            $c = self::verifyOne($a, $docId, $docHas, $now, $key);
            $checks[] = $c;
            if (!$c['ok']) {
                $allOk = false;
                continue;
            }
            foreach (Js::ownKeys(self::obj($c['attests'])->keys()) as $k) {
                $attested->set($k, Js::opt($c['attests'], $k));
            }
        }
        $claims = new Obj();
        foreach (Js::ownKeys($selfAsserted->keys()) as $k) {
            $claims->set($k, 'self-asserted');
        }
        foreach (Js::ownKeys($attested->keys()) as $k) {
            $claims->set($k, 'attested'); // attested wins on overlap
        }
        $out = ['ok' => $allOk];
        if (!$allOk) {
            $out['reason'] = 'one or more attestations did not verify';
        }
        if ($docHas) {
            $out['agentId'] = $docId;
        }
        return $out + ['attestations' => $checks, 'attested' => $attested, 'selfAsserted' => $selfAsserted, 'claims' => $claims];
    }

    // ---- 3. well-known hosting ----

    private static function jsonResponse(mixed $value): array
    {
        return ['status' => 200, 'headers' => Obj::of(['content-type' => 'application/json', 'cache-control' => 'no-store']), 'body' => Js::stringify($value)];
    }

    private static function normalizePath(string $path): string
    {
        $q = strpos($path, '?');
        $p = $q === false ? $path : substr($path, 0, $q);
        return strlen($p) > 1 && str_ends_with($p, '/') ? substr($p, 0, -1) : $p;
    }

    /** @return \Closure(string):?array a handler serving the card at the well-known path; null for any other path */
    public static function agentCardHandler(mixed $card, ?string $path = null): \Closure
    {
        return self::handler($card, $path ?? self::WELL_KNOWN_AGENT_CARD_PATH);
    }

    /** @return \Closure(string):?array a handler serving the AgentFacts document at the well-known path; null for any other path */
    public static function agentFactsHandler(mixed $facts, ?string $path = null): \Closure
    {
        return self::handler($facts, $path ?? self::WELL_KNOWN_AGENT_FACTS_PATH);
    }

    private static function handler(mixed $value, string $path): \Closure
    {
        $target = self::normalizePath($path);
        $response = self::jsonResponse($value);
        return static fn(string $reqPath): ?array => self::normalizePath($reqPath) === $target ? $response : null;
    }

    // ---- 4. registry entry ----

    /** `new URL(path, serviceUrl).toString()` for an absolute path; null where the platform URL class would refuse. */
    private static function wellKnownUrl(mixed $serviceUrl, string $path): ?string
    {
        $r = WhatwgUrl::parse($serviceUrl);
        if ($r === null) {
            return null;
        }
        $text = str_replace(["\t", "\n", "\r"], '', (string)preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', (string)$serviceUrl));
        $special = isset($r['origin']);
        if (!$special && preg_match('#\A[A-Za-z][A-Za-z0-9+.\-]*://#', $text) !== 1) {
            return null; // an opaque path cannot be a base
        }
        $after = substr($text, strpos($text, ':') + 1);
        if ($special && $r['scheme'] !== 'file') {
            $body = (string)preg_replace('#\A[/\\\\]+#', '', $after);
        } else {
            $body = str_starts_with($after, '//') ? substr($after, 2) : '/'; // file: without an authority has no host
        }
        $auth = preg_split($special ? '#[/\\\\?\#]#' : '#[/?\#]#', $body, 2)[0];
        $userinfo = '';
        if (str_contains($auth, '@') && $r['scheme'] !== 'file') {
            $ui = substr($auth, 0, (int)strrpos($auth, '@'));
            $c = strpos($ui, ':');
            $user = $c === false ? $ui : substr($ui, 0, $c);
            $pw = $c === false ? '' : substr($ui, $c + 1);
            $enc = " \"#<>`{}?/:;=@[\\]^|";
            if ($user !== '' || $pw !== '') {
                $userinfo = WhatwgUrl::pct($user, $enc) . ($pw !== '' ? ':' . WhatwgUrl::pct($pw, $enc) : '') . '@';
            }
        }
        return $r['scheme'] . '://' . $userinfo . $r['host'] . $path;
    }

    /**
     * The entry for an A2A registry or NANDA index from a signed card and an AgentFacts document, with the claim names a third party
     * attests apart from those only self-asserted. Purely structural: a registry re-verifies on ingest.
     */
    public static function toRegistryEntry(mixed $card, mixed $facts): Obj
    {
        $attested = [];
        $list = Js::get($facts, 'attestations');
        foreach ($list === null ? [] : Js::spread($list) as $a) {
            $at = Js::opt($a, 'attests');
            if (Js::truthy($a) && Js::isObj($at)) {
                foreach (Js::ownKeys(self::obj($at)->keys()) as $k) {
                    $attested[$k] = true;
                }
            }
        }
        $sa = Js::opt($facts, 'selfAsserted');
        $selfOnly = [];
        if (Js::isObj($sa)) {
            foreach (Js::ownKeys(self::obj($sa)->keys()) as $k) {
                if (!isset($attested[$k])) {
                    $selfOnly[] = $k;
                }
            }
        }
        $url = Js::get($card, 'url');
        $cardUrl = is_string($url) ? self::wellKnownUrl($url, self::WELL_KNOWN_AGENT_CARD_PATH) : null;
        $out = new Obj();
        if (Js::has($facts, 'id')) {
            $out->set('id', Js::opt($facts, 'id'));
        }
        if (Js::has($card, 'name')) {
            $out->set('name', Js::opt($card, 'name'));
        }
        foreach (['url', 'version', 'skills'] as $k) {
            if (Js::has($card, $k)) {
                $out->set($k, Js::opt($card, $k));
            }
        }
        if (Js::truthy(Js::opt($card, 'pcaPassport'))) {
            $out->set('passport', Js::opt($card, 'pcaPassport'));
        }
        if (Js::truthy(Js::opt($card, 'pcaProof'))) {
            $out->set('pcaProof', Js::opt($card, 'pcaProof'));
        }
        $out->set('card', $card);
        if ($cardUrl !== null) {
            $out->set('agentCardUrl', $cardUrl);
        }
        $out->set('facts', $facts);
        $out->set('attestedClaims', array_map('strval', array_keys($attested)));
        $out->set('selfAssertedClaims', $selfOnly);
        return $out;
    }
}
