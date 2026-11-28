<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jose.php';

use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\PubKey;

/** A malformed Disclosure structure found while processing an SD-JWT payload (RFC 9901 section 7.1). */
final class SdJwtProcessingError extends \RuntimeException
{
}

/**
 * SD-JWT serialization of a PCA PCActn: issue (`<issuer JWT>~<D1>~...~<Dn>~`), holder presentation with an optional KB-JWT,
 * fail-closed verification (canonical compact-JWS gate, JOSE checks, recursive `_sd` / `...` processing, key binding), and
 * verifyRecovered, which rebuilds the PCActn from the recovered claims and runs the core verifier.
 *
 * Keys are raw binary strings: an Ed25519 32-byte seed signs, a 32-byte public key verifies; a public JWK (Obj or array) or a
 * PubKey also verifies. The PCActn's own `sig` stays the source of truth; the SD-JWT only re-expresses it.
 */
final class Sdjwt
{
    public const SD_ALG = 'sha-256';
    public const PCA_SD_JWT_TYP = 'pca+sd-jwt';
    public const KB_JWT_TYP = 'kb+jwt';
    public const DEFAULT_SIGNING_ALG = 'EdDSA';
    public const PCA_CAPABILITY_CLAIMS = ['action', 'grant_ref', 'cap_chain', 'plan', 'attestation', 'provenance', 'freshness', 'counter', 'risk_claim',
        'nonce', 'caution', 'rationale_commitment', 'progress_step', 'prohibition_evidence', 'tool_binding', 'alg', 'pq_pk', 'sig', 'pq_sig', 'threshold',
        'zk_compliance', 'bond_ref'];

    private const STANDARD_MAPPED = ['aud', 'iat', 'exp'];
    private const CLEAR_DISCRIMINATOR = 'ver';
    /** RFC 9901 section 9.7: never accepted behind a Disclosure. */
    private const CRITICAL_CLAIMS = ['iss', 'aud', 'exp', 'nbf', 'cnf', 'status'];
    private const RESERVED_CLAIMS = ['iss', 'sub', 'aud', 'iat', 'exp', '_sd', '_sd_alg', 'cnf'];

    // ---- helpers ----------------------------------------------------------------------------------------------------

    /** Node's 'ascii' encoding of a JS string: the low byte of each UTF-16 code unit. */
    private static function ascii(string $s): string
    {
        if (preg_match('/[\x80-\xFF]/', $s) !== 1) {
            return $s;
        }
        $u = (string)mb_convert_encoding($s, 'UTF-16LE', 'UTF-8');
        $out = '';
        for ($i = 0, $n = strlen($u); $i < $n; $i += 2) {
            $out .= $u[$i];
        }
        return $out;
    }

    /** base64url(SHA-256(ASCII(input))): the Disclosure digest and the KB `sd_hash`. */
    private static function sha(string $s): string
    {
        return Jose::b64u(hash('sha256', self::ascii($s), true));
    }

    private static function isJwk(mixed $v): bool
    {
        return Js::isObj($v) && is_string(Js::opt($v, 'kty'));
    }

    // ---- keys -------------------------------------------------------------------------------------------------------

    public static function ed25519PublicJwk(mixed $raw): Obj
    {
        $b = Bytes::of($raw);
        if ($b === null || strlen($b) !== 32) {
            throw new \InvalidArgumentException('pca-sdjwt: Ed25519 public key must be 32 bytes');
        }
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Jose::b64u($b)]);
    }

    /** A raw 32-byte Ed25519 seed (the PCA secret key) as a signing key. */
    public static function importEd25519PrivateKey(mixed $rawSeed): string
    {
        $b = Bytes::of($rawSeed);
        if ($b === null || strlen($b) !== 32) {
            throw new \InvalidArgumentException('pca-sdjwt: Ed25519 private seed must be 32 bytes');
        }
        return $b;
    }

    /** A raw 32-byte Ed25519 public key as a verification key. */
    public static function importEd25519PublicKey(mixed $raw): string
    {
        $b = Bytes::of($raw);
        if ($b === null || strlen($b) !== 32) {
            throw new \InvalidArgumentException('pca-sdjwt: Ed25519 public key must be 32 bytes');
        }
        return $b;
    }

    // ---- issuance ---------------------------------------------------------------------------------------------------

    private static function leafHolderJwk(Obj $pcActn): Obj
    {
        $chain = $pcActn->get('cap_chain');
        $leaf = is_array($chain) && array_is_list($chain) && $chain !== [] ? $chain[count($chain) - 1] : null;
        $h = Js::opt($leaf, 'holder');
        if (!is_string($h) || $h === '') {
            throw new \InvalidArgumentException('pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing');
        }
        return self::ed25519PublicJwk(Jose::lenientB64d($h));
    }

    private static function resolveCnfJwk(Obj $pcActn, mixed $kb): Obj|array
    {
        if (!Js::has($kb, 'holderPublicKey')) {
            return self::leafHolderJwk($pcActn);
        }
        $hp = Js::opt($kb, 'holderPublicKey');
        if (Bytes::of($hp) !== null) {
            return self::ed25519PublicJwk($hp);
        }
        if (self::isJwk($hp)) {
            return $hp;
        }
        throw new \InvalidArgumentException('pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key');
    }

    private static function numericDate(mixed $ms, string $label, bool $ceil): float
    {
        $f = Js::num($ms);
        if ($f === null || !is_finite($f)) {
            throw new \InvalidArgumentException("pca-sdjwt: PCActn.$label must be a finite number (epoch ms)");
        }
        return $ceil ? ceil($f / 1000) : floor($f / 1000);
    }

    /**
     * Serialize a signed PCActn as an SD-JWT. Options: issuerKey (required), disclosable (claim names behind a Disclosure,
     * default PCA_CAPABILITY_CLAIMS; others go in the clear), keyBinding ({holderPublicKey?}: embeds `cnf`, default the leaf
     * holder), iss, sub, typ, signingAlg.
     */
    public static function issuePcaSdJwt(mixed $pcActn, mixed $options): string
    {
        if (!($pcActn instanceof Obj)) {
            throw new \InvalidArgumentException('pca-sdjwt: pcActn must be an object');
        }
        $chain = $pcActn->get('cap_chain');
        if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
            throw new \InvalidArgumentException('pca-sdjwt: pcActn.cap_chain must be a non-empty array');
        }
        $root = $chain[0];
        $leaf = $chain[count($chain) - 1];
        if (!Js::truthy($root) || !is_string(Js::opt($root, 'issuer'))) {
            throw new \InvalidArgumentException('pca-sdjwt: cap_chain root issuer is missing');
        }
        if (!Js::truthy($leaf) || !is_string(Js::opt($leaf, 'holder'))) {
            throw new \InvalidArgumentException('pca-sdjwt: cap_chain leaf holder is missing');
        }
        $aud = $pcActn->get('aud');
        if (!is_string($aud) || $aud === '') {
            throw new \InvalidArgumentException('pca-sdjwt: pcActn.aud is required');
        }
        $iss = Js::opt($options, 'iss') ?? Js::opt($root, 'issuer');
        $sub = Js::opt($options, 'sub') ?? Js::opt($leaf, 'holder');
        $iat = self::numericDate($pcActn->get('iat'), 'iat', false);
        $exp = self::numericDate($pcActn->get('exp'), 'exp', true);
        if ($exp <= $iat) {
            $exp = $iat + 1; // exp stays strictly after iat even for a sub-second lifetime
        }
        $disclosable = Js::spread(Js::opt($options, 'disclosable') ?? self::PCA_CAPABILITY_CLAIMS);

        // iat_ms / exp_ms carry the exact signed epoch-ms values so verifyRecovered can rebuild the byte-identical PCActn
        $payload = Obj::of(['iss' => $iss, 'sub' => $sub, 'aud' => $aud, 'iat' => $iat, 'exp' => $exp]);
        if ($pcActn->has(self::CLEAR_DISCRIMINATOR)) {
            $payload->set(self::CLEAR_DISCRIMINATOR, $pcActn->get(self::CLEAR_DISCRIMINATOR));
        }
        $payload->set('iat_ms', $pcActn->get('iat'));
        $payload->set('exp_ms', $pcActn->get('exp'));
        $payload->set('_sd_alg', self::SD_ALG);
        $encoded = [];
        $sd = [];
        foreach (Js::ownKeys($pcActn->keys()) as $key) {
            if (in_array($key, self::STANDARD_MAPPED, true) || $key === self::CLEAR_DISCRIMINATOR) {
                continue;
            }
            $value = $pcActn->get($key);
            if (in_array($key, $disclosable, true)) {
                $e = Jose::b64u(Js::stringify([Jose::b64u(random_bytes(16)), $key, $value]));
                $encoded[] = $e;
                $sd[] = self::sha($e);
            } else {
                $payload->set($key, $value);
            }
        }
        if ($sd !== []) {
            $payload->set('_sd', $sd);
        }
        $kb = Js::opt($options, 'keyBinding');
        if (Js::truthy($kb)) {
            $payload->set('cnf', Obj::of(['jwk' => self::resolveCnfJwk($pcActn, $kb)]));
        }
        $header = Obj::of(['alg' => Js::opt($options, 'signingAlg') ?? self::DEFAULT_SIGNING_ALG, 'typ' => Js::opt($options, 'typ') ?? self::PCA_SD_JWT_TYP]);
        $jwt = Jose::signJwt($payload, $header, Js::opt($options, 'issuerKey'));
        return implode('', array_map(static fn(string $p): string => "$p~", [$jwt, ...$encoded]));
    }

    // ---- parsing ----------------------------------------------------------------------------------------------------

    /** @return array{jwt: string, disclosures: list<string>, kbJwt: ?string, head: string, payload: Obj} */
    private static function parse(mixed $sdjwt): array
    {
        if (!is_string($sdjwt) || $sdjwt === '') {
            throw new \InvalidArgumentException('pca-sdjwt: empty SD-JWT');
        }
        $segments = explode('~', $sdjwt);
        if (count($segments) < 2) {
            throw new \InvalidArgumentException('pca-sdjwt: malformed SD-JWT (missing ~ separator)');
        }
        $jwt = $segments[0];
        if ($jwt === '') {
            throw new \InvalidArgumentException('pca-sdjwt: empty issuer JWT');
        }
        $last = $segments[count($segments) - 1];
        $disclosures = array_slice($segments, 1, count($segments) - 2);
        if (in_array('', $disclosures, true)) {
            throw new \InvalidArgumentException('pca-sdjwt: empty disclosure segment'); // `a~~b` is an aliasing vector
        }
        // canonical-spelling gate before any JOSE work: one accepted string form per issuer JWT / KB-JWT
        $gate = Jose::assertCanonicalCompactJws($jwt);
        if ($last !== '') {
            Jose::assertCanonicalCompactJws($last);
            return ['jwt' => $jwt, 'disclosures' => $disclosures, 'kbJwt' => $last, 'head' => substr($sdjwt, 0, strlen($sdjwt) - strlen($last)), 'payload' => $gate['payload']];
        }
        return ['jwt' => $jwt, 'disclosures' => $disclosures, 'kbJwt' => null, 'head' => $sdjwt, 'payload' => $gate['payload']];
    }

    /** @return list<mixed> */
    private static function decodeDisclosure(string $encoded): array
    {
        try {
            $parsed = Jose::decodeCanonicalJsonSegment($encoded);
        } catch (\Throwable) {
            throw new \InvalidArgumentException('pca-sdjwt: disclosure is not canonical base64url strict JSON');
        }
        if (!is_array($parsed) || !array_is_list($parsed) || (count($parsed) !== 2 && count($parsed) !== 3)) {
            throw new \InvalidArgumentException('pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair');
        }
        if (!is_string($parsed[0])) {
            throw new \InvalidArgumentException('pca-sdjwt: disclosure salt must be a string');
        }
        return $parsed;
    }

    // ---- presentation -----------------------------------------------------------------------------------------------

    /** @return list<string> every digest referenced by `_sd` arrays or `{"...": digest}` entries inside `$node` */
    private static function collectDigests(mixed $node): array
    {
        $out = [];
        $visit = static function (mixed $n) use (&$visit, &$out): void {
            if (is_array($n) && array_is_list($n)) {
                array_map($visit, $n);
            } elseif ($n instanceof Obj) {
                foreach (Js::ownKeys($n->keys()) as $k) {
                    $v = $n->get($k);
                    if ($k === '_sd' && is_array($v) && array_is_list($v)) {
                        array_push($out, ...array_values(array_filter($v, 'is_string')));
                    } elseif ($k === '...' && is_string($v)) {
                        $out[] = $v;
                    } else {
                        $visit($v);
                    }
                }
            }
        };
        $visit($node);
        return $out;
    }

    /**
     * A holder presentation disclosing only `$selectClaims` (by claim name, with every Disclosure nested in a selected value);
     * any existing KB-JWT is stripped. Options: keyBinding {holderKey, audience, nonce?, iat? (unix s, default now), alg?}
     * appends a fresh KB-JWT over the new presentation.
     */
    public static function present(mixed $sdjwt, mixed $selectClaims, mixed $options = null): string
    {
        $parsed = self::parse($sdjwt);
        $keep = $selectClaims === null ? [] : Js::spread($selectClaims);
        $byDigest = [];
        foreach ($parsed['disclosures'] as $e) {
            $byDigest[self::sha($e)] = $e;
        }
        $kept = [];
        $include = static function (string $digest) use (&$include, &$kept, $byDigest): void {
            if (!array_key_exists($digest, $byDigest) || isset($kept[$digest])) {
                return;
            }
            $kept[$digest] = true;
            $parts = self::decodeDisclosure($byDigest[$digest]);
            foreach (self::collectDigests($parts[count($parts) - 1]) as $d) {
                $include($d);
            }
        };
        $payload = $parsed['payload'];
        $sd = $payload->get('_sd');
        foreach (is_array($sd) && array_is_list($sd) ? $sd : [] as $digest) {
            if (!is_string($digest) || !array_key_exists($digest, $byDigest)) {
                continue;
            }
            $parts = self::decodeDisclosure($byDigest[$digest]);
            if (count($parts) === 3 && is_string($parts[1]) && in_array($parts[1], $keep, true)) {
                $include($digest);
            }
        }
        // clear claims holding selectively-disclosable parts (an array with `...` entries, say)
        foreach (Js::ownKeys($payload->keys()) as $key) {
            if ($key !== '_sd' && in_array($key, $keep, true)) {
                foreach (self::collectDigests($payload->get($key)) as $d) {
                    $include($d);
                }
            }
        }
        $keptEnc = array_values(array_filter($parsed['disclosures'], static fn(string $e) => isset($kept[self::sha($e)])));
        $head = implode('~', [$parsed['jwt'], ...$keptEnc]) . '~';
        $kb = Js::opt($options, 'keyBinding');
        if (!Js::truthy($kb)) {
            return $head;
        }
        $kbPayload = Obj::of(['iat' => Js::opt($kb, 'iat') ?? floor(self::clock())]);
        if (Js::has($kb, 'audience')) {
            $kbPayload->set('aud', Js::opt($kb, 'audience'));
        }
        $kbPayload->set('sd_hash', self::sha($head));
        if (Js::has($kb, 'nonce')) {
            $kbPayload->set('nonce', Js::opt($kb, 'nonce'));
        }
        $kbHeader = Obj::of(['alg' => Js::opt($kb, 'alg') ?? self::DEFAULT_SIGNING_ALG, 'typ' => self::KB_JWT_TYP]);
        return $head . Jose::signJwt($kbPayload, $kbHeader, Js::opt($kb, 'holderKey'));
    }

    // ---- verification -----------------------------------------------------------------------------------------------

    private static function thumbX(mixed $k): ?string
    {
        if ($k instanceof PubKey) {
            $x = $k->details['ec']['x'] ?? null;
            $size = ['P-256' => 32, 'P-384' => 48, 'P-521' => 66][Common::jwkCurve($k) ?? ''] ?? null;
            return is_string($x) && $size !== null ? Jose::b64u(str_pad($x, $size, "\0", STR_PAD_LEFT)) : null;
        }
        if (Bytes::of($k) !== null) {
            return Jose::b64u((string)Bytes::of($k));
        }
        if (self::isJwk($k)) {
            $x = Js::opt($k, 'x');
            return is_string($x) ? $x : null;
        }
        throw new \InvalidArgumentException('pca-sdjwt: keyBindingKey must be raw bytes, a JWK or a public key');
    }

    /** ECMAScript ToNumber for the relational comparisons the reference makes with option values. */
    private static function jsNum(mixed $v): float
    {
        return match (true) {
            $v === null => 0.0,
            is_bool($v) => $v ? 1.0 : 0.0,
            Js::isNum($v) => (float)Js::num($v),
            is_string($v) => IntentWb::jsNumber($v),
            default => NAN,
        };
    }

    /** @return array{processed: Obj, disclosed: Obj} */
    private static function processDisclosures(Obj $payload, array &$byDigest): array
    {
        $seen = [];
        $claim = static function (string $d) use (&$seen, &$byDigest): ?string {
            if (isset($seen[$d])) {
                throw new SdJwtProcessingError('a digest appears more than once in the payload');
            }
            $seen[$d] = true;
            return array_key_exists($d, $byDigest) ? $d : null;
        };
        $disclosedTop = new Obj();
        $walk = static function (mixed $node, bool $top) use (&$walk, $claim, &$byDigest, $disclosedTop): mixed {
            if (is_array($node) && array_is_list($node)) {
                $out = [];
                foreach ($node as $el) {
                    if ($el instanceof Obj && $el->keys() === ['...']) {
                        $digest = $el->get('...');
                        if (!is_string($digest)) {
                            throw new SdJwtProcessingError("an array '...' entry must reference a string digest");
                        }
                        $d = $claim($digest);
                        if ($d === null) {
                            continue; // undisclosed element or decoy
                        }
                        if (count($byDigest[$d]['parts']) !== 2) {
                            throw new SdJwtProcessingError('an array-element disclosure must be [salt, value]');
                        }
                        $byDigest[$d]['used'] = true;
                        $out[] = $walk($byDigest[$d]['parts'][1], false);
                    } else {
                        $out[] = $walk($el, false);
                    }
                }
                return $out;
            }
            if ($node instanceof Obj) {
                $out = new Obj();
                foreach (Js::ownKeys($node->keys()) as $key) {
                    if ($key !== '_sd') {
                        $out->set($key, $walk($node->get($key), false));
                    }
                }
                if ($node->has('_sd')) {
                    $sd = $node->get('_sd');
                    if (!Js::isStrList($sd)) {
                        throw new SdJwtProcessingError('_sd must be an array of strings');
                    }
                    foreach ($sd as $digest) {
                        $d = $claim($digest);
                        if ($d === null) {
                            continue; // decoy or undisclosed claim
                        }
                        $parts = $byDigest[$d]['parts'];
                        if (count($parts) !== 3) {
                            throw new SdJwtProcessingError('an object-property disclosure must be [salt, name, value]');
                        }
                        $name = $parts[1];
                        if (!is_string($name)) {
                            throw new SdJwtProcessingError('disclosure claim name must be a string');
                        }
                        if ($name === '_sd' || $name === '...') {
                            throw new SdJwtProcessingError("disclosure claim name '$name' is reserved");
                        }
                        if ($out->has($name)) {
                            throw new SdJwtProcessingError("disclosure claim '$name' collides with an existing claim");
                        }
                        if ($top && in_array($name, self::CRITICAL_CLAIMS, true)) {
                            throw new SdJwtProcessingError("'$name' is security-critical and must not be selectively disclosable");
                        }
                        $byDigest[$d]['used'] = true;
                        $value = $walk($parts[2], false);
                        $out->set($name, $value);
                        if ($top) {
                            $disclosedTop->set($name, $value);
                        }
                    }
                }
                return $out;
            }
            return $node;
        };
        $processed = $walk($payload, true)->without('_sd_alg');
        foreach ($byDigest as $d) {
            if (!$d['used']) {
                throw new SdJwtProcessingError('a presented disclosure is not referenced by any digest in the payload');
            }
        }
        return ['processed' => $processed, 'disclosed' => $disclosedTop];
    }

    private static function fail(string $reason): Obj
    {
        return Obj::of(['ok' => false, 'reason' => $reason]);
    }

    /**
     * Verify a PCA SD-JWT, fail closed: {ok: true, payload, processed, protectedHeader, disclosed, claims, keyBinding} or
     * {ok: false, reason}. Options: issuerKey (required), requiredDisclosures, expectedAudience (issuer JWT and KB-JWT),
     * expectedKbAudience, keyBindingKey (requires a KB-JWT bound to that cnf key), expectedNonce, requireKeyBinding,
     * algorithms / kbAlgorithms (default ['EdDSA']), now (unix ms), kbMaxAgeSec, clockToleranceSec.
     */
    public static function verifyPcaSdJwt(mixed $sdjwt, mixed $options): Obj
    {
        try {
            return self::verifyUnchecked($sdjwt, $options);
        } catch (\Throwable $e) {
            return self::fail($e->getMessage());
        }
    }

    private static function verifyUnchecked(mixed $sdjwt, mixed $options): Obj
    {
        // a non-finite clock, tolerance or window would slip past the date checks
        foreach (['now', 'clockToleranceSec', 'kbMaxAgeSec'] as $nk) {
            if (Js::has($options, $nk) && !(Js::isNum(Js::opt($options, $nk)) && is_finite((float)Js::num(Js::opt($options, $nk))))) {
                return self::fail('now, clockToleranceSec and kbMaxAgeSec must be finite');
            }
        }
        // new Date(now) is invalid beyond +-8.64e15 ms, which the signature library reads as no clock at all: refuse it like a non-finite one
        if (Js::has($options, 'now') && !(abs((float)Js::num(Js::opt($options, 'now'))) <= 8.64e15)) {
            return self::fail('now is not a representable time');
        }
        $parsed = self::parse($sdjwt);
        $o = ['algorithms' => Js::opt($options, 'algorithms') ?? [self::DEFAULT_SIGNING_ALG]];
        if (Js::has($options, 'expectedAudience')) {
            $o['audience'] = Js::opt($options, 'expectedAudience');
        }
        if (Js::has($options, 'now')) {
            $o['nowMs'] = Js::opt($options, 'now') ?? 0; // new Date(null) is the epoch
        }
        if (Js::has($options, 'clockToleranceSec')) {
            $ct = Js::opt($options, 'clockToleranceSec');
            if (!is_string($ct) && !Js::isNum($ct)) {
                throw new \TypeError('Invalid clockTolerance option type');
            }
            $o['clockTolerance'] = $ct;
        }
        [$payload, $protectedHeader] = Jose::jwtVerify($parsed['jwt'], Js::opt($options, 'issuerKey'), $o);

        // `_sd_alg` defaults to sha-256 when absent; any other value is unsupported
        if ($payload->has('_sd_alg') && $payload->get('_sd_alg') !== self::SD_ALG) {
            return self::fail('unsupported _sd_alg (require "' . self::SD_ALG . '")');
        }
        $byDigest = [];
        foreach ($parsed['disclosures'] as $e) {
            $digest = self::sha($e);
            if (array_key_exists($digest, $byDigest)) {
                return self::fail('duplicate disclosure');
            }
            $byDigest[$digest] = ['parts' => self::decodeDisclosure($e), 'used' => false];
        }
        try {
            ['processed' => $processed, 'disclosed' => $disclosed] = self::processDisclosures($payload, $byDigest);
        } catch (SdJwtProcessingError $e) {
            return self::fail(str_contains($e->getMessage(), 'not referenced') ? 'a presented disclosure does not match any _sd digest (tampered)' : $e->getMessage());
        }
        foreach (Js::spread(Js::opt($options, 'requiredDisclosures') ?? []) as $required) {
            $r = Js::str($required);
            if (!$disclosed->has($r)) {
                return self::fail("required disclosure '$r' was not presented");
            }
        }

        // key binding
        $cnf = $payload->get('cnf');
        $cnfJwk = $cnf instanceof Obj && self::isJwk($cnf->get('jwk')) ? $cnf->get('jwk') : null;
        $keyBinding = Obj::of(['presented' => $parsed['kbJwt'] !== null, 'verified' => false]);
        if ($parsed['kbJwt'] !== null) {
            if ($cnfJwk === null) {
                return self::fail('KB-JWT presented but issuer JWT has no cnf key');
            }
            if (Js::has($options, 'keyBindingKey')) {
                $want = self::thumbX(Js::opt($options, 'keyBindingKey'));
                $have = self::thumbX($cnfJwk);
                if ($want === null || $have === null || $want !== $have) {
                    return self::fail('cnf key does not match the expected keyBindingKey');
                }
            }
            $kbAlgorithms = Js::opt($options, 'kbAlgorithms') ?? [self::DEFAULT_SIGNING_ALG];
            $ko = ['algorithms' => $kbAlgorithms];
            $kbAud = Js::opt($options, 'expectedKbAudience');
            if ($kbAud !== null || Js::has($options, 'expectedAudience')) {
                $ko['audience'] = $kbAud ?? Js::opt($options, 'expectedAudience');
            }
            foreach (['nowMs', 'clockTolerance'] as $k) {
                if (array_key_exists($k, $o)) {
                    $ko[$k] = $o[$k];
                }
            }
            try {
                // the cnf key as an imported public key (a private member never takes part in verification)
                $k = Jose::publicKeyFromJwk(Obj::of(['kty' => Js::opt($cnfJwk, 'kty')] + self::members($cnfJwk, ['crv', 'x', 'y', 'n', 'e'])))[1];
                [$kbPayload, $kbHeader] = Jose::jwtVerify($parsed['kbJwt'], $k, $ko);
            } catch (\Throwable $e) {
                return self::fail('KB-JWT signature/claims invalid: ' . $e->getMessage());
            }
            if ($kbHeader->get('typ') !== self::KB_JWT_TYP) {
                return self::fail('KB-JWT typ must be "' . self::KB_JWT_TYP . '"');
            }
            $iat = $kbPayload->get('iat');
            if (!Js::isNum($iat)) {
                return self::fail('KB-JWT iat is required');
            }
            if (Js::has($options, 'kbMaxAgeSec')) {
                if (!is_finite((float)Js::num($iat))) {
                    return self::fail('KB-JWT iat is not a finite number');
                }
                $now = Js::opt($options, 'now') ?? floor(self::clock() * 1000);
                $nowSec = floor(self::jsNum($now) / 1000);
                if (!($nowSec - Js::num($iat) <= self::jsNum(Js::opt($options, 'kbMaxAgeSec')))) {
                    return self::fail('KB-JWT is older than the accepted window');
                }
                if (!(Js::num($iat) - $nowSec <= self::jsNum(Js::opt($options, 'clockToleranceSec') ?? 0))) {
                    return self::fail('KB-JWT iat is in the future');
                }
            }
            $aud = $kbPayload->get('aud');
            if (!is_string($aud) && !(is_array($aud) && array_is_list($aud))) {
                return self::fail('KB-JWT aud is required');
            }
            if ($kbPayload->get('sd_hash') !== self::sha($parsed['head'])) {
                return self::fail('KB-JWT sd_hash does not cover this presentation');
            }
            $nonce = $kbPayload->has('nonce') ? $kbPayload->get('nonce') : JsUndefined::U;
            if (Js::has($options, 'expectedNonce') && $nonce !== Js::opt($options, 'expectedNonce')) {
                return self::fail('KB-JWT nonce does not match');
            }
            $keyBinding->set('verified', true);
            if (is_string($aud)) {
                $keyBinding->set('aud', $aud);
            }
            if (is_string($nonce)) {
                $keyBinding->set('nonce', $nonce);
            }
        } elseif (Js::has($options, 'keyBindingKey') || Js::truthy(Js::opt($options, 'requireKeyBinding'))) {
            return self::fail('key binding required but no KB-JWT was presented');
        }

        // recovered capability claims = clear (non-reserved) and disclosed, from the processed payload
        $claims = new Obj();
        foreach ($processed->keys() as $key) {
            if (!in_array($key, self::RESERVED_CLAIMS, true)) {
                $claims->set($key, $processed->get($key));
            }
        }
        return Obj::of(['ok' => true, 'payload' => $payload, 'processed' => $processed, 'protectedHeader' => $protectedHeader, 'disclosed' => $disclosed,
            'claims' => $claims, 'keyBinding' => $keyBinding]);
    }

    /** @return array<string, mixed> the members of `$o` present among `$names` */
    private static function members(mixed $o, array $names): array
    {
        $out = [];
        foreach ($names as $n) {
            if (Js::has($o, $n)) {
                $out[$n] = Js::opt($o, $n);
            }
        }
        return $out;
    }

    // ---- recovery through the core ----------------------------------------------------------------------------------

    private static function deny(string $reason): array
    {
        return ['allow' => false, 'checks' => [], 'reason' => $reason];
    }

    /**
     * Rebuild the PCActn from a successful verifyPcaSdJwt result and run the core verifier (chain, plan, `sig`). Fail closed:
     * a withheld required claim, missing or inconsistent iat_ms / exp_ms, or an iss / sub that disagrees with the chain is
     * a denial. Core options: grant (the verifier's OWN stored grant), audience (string, or Audience::Any to accept any; omitted or null = deny),
     * nowEpoch (ms, default now), authorizedPlanRoots, insecureSkipPlanRootCheck, allowedSuites.
     * @return array{allow: bool, checks: array, reason?: string}
     */
    public static function verifyRecovered(Obj $res, mixed $coreOpts): array
    {
        $c = $res->get('claims');
        $p = $res->get('processed');
        if (!($c instanceof Obj) || !($p instanceof Obj)) {
            throw new \InvalidArgumentException('pca-sdjwt: verifyRecovered needs a successful verifyPcaSdJwt result');
        }
        $iatMs = $c->get('iat_ms');
        $expMs = $c->get('exp_ms');
        if (!Js::isNum($iatMs) || !Js::isNum($expMs)) {
            return self::deny('pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn');
        }
        $i = (float)Js::num($iatMs);
        $x = (float)Js::num($expMs);
        if (!Js::isNum($p->get('iat')) || floor($i / 1000) !== (float)Js::num($p->get('iat'))) {
            return self::deny('pca-sdjwt: iat_ms disagrees with iat');
        }
        if (!Js::isNum($p->get('exp')) || max(ceil($x / 1000), floor($i / 1000) + 1) !== (float)Js::num($p->get('exp'))) {
            return self::deny('pca-sdjwt: exp_ms disagrees with exp');
        }
        $rest = $c->without('iat_ms', 'exp_ms');
        foreach (['action', 'cap_chain', 'plan', 'sig', 'grant_ref', 'counter'] as $k) {
            if (!$rest->has($k)) {
                return self::deny("pca-sdjwt: required claim '$k' was not disclosed");
            }
        }
        if (!is_string($p->get('aud'))) {
            return self::deny('pca-sdjwt: aud must be a string');
        }
        $chain = $rest->get('cap_chain');
        if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
            return self::deny('pca-sdjwt: cap_chain is empty');
        }
        $member = static fn(mixed $o, string $k): mixed => Js::has($o, $k) ? Js::opt($o, $k) : (Js::get($o, $k) ?? JsUndefined::U);
        if ($member($p, 'iss') !== $member($chain[0], 'issuer')) {
            return self::deny('pca-sdjwt: iss does not match the chain root issuer');
        }
        if ($member($p, 'sub') !== $member($chain[count($chain) - 1], 'holder')) {
            return self::deny('pca-sdjwt: sub does not match the chain leaf holder');
        }
        $pc = $p->has('ver') ? $rest : $rest->without('ver');
        if ($p->has('ver')) {
            $pc->set('ver', $p->get('ver'));
        }
        $pc->set('aud', $p->get('aud'));
        $pc->set('iat', $iatMs);
        $pc->set('exp', $expMs);
        $aud = Js::has($coreOpts, 'audience') ? Js::opt($coreOpts, 'audience') : null;
        if ($aud === null) {
            // fail closed: a PCActn with a signed aud needs the verifier's audience, or the explicit Audience::Any opt-out
            return self::deny('audience: PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or Audience::Any to accept any)');
        }
        if (!is_string($aud) && $aud !== Audience::Any) {
            return self::deny('audience: the verifier audience must be a string or Audience::Any');
        }
        $now = Js::opt($coreOpts, 'nowEpoch');
        $roots = Js::opt($coreOpts, 'authorizedPlanRoots');
        $suites = Js::opt($coreOpts, 'allowedSuites');
        return Pca::verifyPcactnCore($pc, Js::opt($coreOpts, 'grant'), $now === null ? (int)floor(self::clock() * 1000) : (int)Js::num($now), $aud,
            is_array($suites) ? $suites : null, authorizedPlanRoots: is_array($roots) ? $roots : null,
            insecureSkipPlanRootCheck: Js::opt($coreOpts, 'insecureSkipPlanRootCheck') === true);
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
