<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/WhatwgUrl.php';

/**
 * W3C VC bridge for a PCA agent passport: did:key (Ed25519, base58btc multibase), the passport as an SD-JWT VC (`vc+sd-jwt`,
 * the four digest fields selectively disclosable), and RFC 9421 HTTP message signatures with the Web Bot Auth extension.
 * Keys are raw binary strings: a 32-byte Ed25519 seed signs, a 32-byte public key verifies.
 */
final class Vc
{
    public const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
    public const AGENT_PASSPORT_CONTEXT = 'https://atlasauth.net/credentials/agent-passport/v1';
    public const AGENT_PASSPORT_VC_TYPE = 'AgentPassportCredential';
    private const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    private const MAX_BASE58_INPUT = 1024;
    private const SD_DIGEST_FIELDS = ['weights_digest', 'system_prompt_digest', 'tool_manifest_digest', 'runtime_measurement'];
    private const SIG_LABEL = 'sig1';

    // ---- base58btc / did:key ----------------------------------------------------------------------------------------

    public static function base58btcEncode(mixed $bytes): string
    {
        $b = Bytes::of($bytes);
        if ($b === null) {
            throw new \TypeError('base58btcEncode: bytes expected');
        }
        $n = strlen($b);
        $zeros = 0;
        while ($zeros < $n && $b[$zeros] === "\0") {
            $zeros++;
        }
        $digits = [];
        for ($i = $zeros; $i < $n; $i++) {
            $carry = ord($b[$i]);
            foreach ($digits as $j => $d) {
                $carry += $d << 8;
                $digits[$j] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
            while ($carry > 0) {
                $digits[] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
        }
        $out = str_repeat('1', $zeros);
        for ($i = count($digits) - 1; $i >= 0; $i--) {
            $out .= self::B58[$digits[$i]];
        }
        return $out;
    }

    public static function base58btcDecode(mixed $str): Bytes
    {
        if (!is_string($str)) {
            throw new \TypeError('base58btcDecode: string expected');
        }
        if (Js::len($str) > self::MAX_BASE58_INPUT) {
            throw new \InvalidArgumentException('pca-vc: base58btc input too long');
        }
        $n = strlen($str);
        $zeros = 0;
        while ($zeros < $n && $str[$zeros] === '1') {
            $zeros++;
        }
        $bytes = [];
        for ($i = $zeros; $i < $n; $i++) {
            $carry = strpos(self::B58, $str[$i]);
            if ($carry === false) {
                throw new \InvalidArgumentException('pca-vc: invalid base58btc character');
            }
            foreach ($bytes as $j => $v) {
                $carry += $v * 58;
                $bytes[$j] = $carry & 0xff;
                $carry >>= 8;
            }
            while ($carry > 0) {
                $bytes[] = $carry & 0xff;
                $carry >>= 8;
            }
        }
        return new Bytes(str_repeat("\0", $zeros) . implode('', array_map('chr', array_reverse($bytes))));
    }

    public static function didKeyFromEd25519(mixed $publicKey): string
    {
        $b = Bytes::of($publicKey);
        if ($b === null || strlen($b) !== 32) {
            throw new \InvalidArgumentException('pca-vc: Ed25519 public key must be 32 bytes');
        }
        return 'did:key:z' . self::base58btcEncode("\xed\x01" . $b);
    }

    public static function ed25519FromDidKey(mixed $did): Bytes
    {
        if (!is_string($did)) {
            throw new \TypeError('did.startsWith is not a function');
        }
        $prefix = 'did:key:z';
        if (!str_starts_with($did, $prefix)) {
            throw new \InvalidArgumentException('pca-vc: not a did:key:z… identifier');
        }
        if (Js::len($did) > strlen($prefix) + 64) {
            throw new \InvalidArgumentException('pca-vc: did:key is not an Ed25519 (0xed01) key'); // exactly 48 base58 chars
        }
        $mc = self::base58btcDecode(substr($did, strlen($prefix)))->raw;
        if (strlen($mc) !== 34 || $mc[0] !== "\xed" || $mc[1] !== "\x01") {
            throw new \InvalidArgumentException('pca-vc: did:key is not an Ed25519 (0xed01) key');
        }
        return new Bytes(substr($mc, 2));
    }

    // ---- the agent-passport JSON-LD context -------------------------------------------------------------------------

    /** The JSON-LD context document served at AGENT_PASSPORT_CONTEXT. */
    public static function contextDoc(): Obj
    {
        $v = 'https://atlasauth.net/credentials/agent-passport/v1#';
        $x = 'http://www.w3.org/2001/XMLSchema#';
        $t = static fn(string $id, string $type): array => ['@id' => $v . $id, '@type' => $x . $type];
        $inner = ['@protected' => true, 'id' => '@id', 'type' => '@type', 'passport_id' => $t('passportId', 'string'), 'model_id' => $t('modelId', 'string'),
            'operator' => $t('operator', 'string'), 'hardware_rooted' => $t('hardwareRooted', 'boolean'), 'weights_measured' => $t('weightsMeasured', 'boolean'),
            'issued_at' => $t('issuedAt', 'integer'), 'weights_digest' => $t('weightsDigest', 'string'), 'system_prompt_digest' => $t('systemPromptDigest', 'string'),
            'tool_manifest_digest' => $t('toolManifestDigest', 'string'), 'runtime_measurement' => $t('runtimeMeasurement', 'string'),
            '_sd' => ['@id' => $v . 'selectiveDisclosureDigest', '@container' => '@set']];
        return Js::parse(json_encode(['@context' => ['@protected' => true, 'AgentPassportCredential' => ['@id' => $v . 'AgentPassportCredential', '@context' => $inner]]],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /** sha-256 hex over the sorted-key JSON of the context document (pin it when caching the document). */
    public static function contextDigest(): string
    {
        return hash('sha256', Json::canonicalizeLenient(self::contextDoc()));
    }

    public static function resolveAgentPassportContext(mixed $iri): ?Obj
    {
        return $iri === self::AGENT_PASSPORT_CONTEXT ? self::contextDoc() : null;
    }

    // ---- passport <-> SD-JWT VC -------------------------------------------------------------------------------------

    private static function sha(string $ascii): string
    {
        return Jose::b64u(hash('sha256', $ascii, true));
    }

    /**
     * Issue a passport as an SD-JWT VC. Args: issuerKey (32-byte Ed25519 seed), issuerDid, subjectDid, ttlSec (sets exp),
     * now (unix ms clock for iat; default the system clock).
     */
    public static function passportToVC(mixed $passport, mixed $args): string
    {
        $disclosures = [];
        $sd = [];
        foreach (self::SD_DIGEST_FIELDS as $field) {
            Js::get($passport, $field);
            if (!Js::has($passport, $field)) {
                continue;
            }
            $d = Jose::b64u(Js::utf8(Js::stringify([Jose::b64u(random_bytes(16)), $field, Js::opt($passport, $field)])));
            $disclosures[] = $d;
            $sd[] = self::sha($d);
        }
        $cs = new Obj();
        if (Js::has($args, 'subjectDid')) {
            $cs->set('id', Js::opt($args, 'subjectDid'));
        }
        foreach (['passport_id' => 'id', 'model_id' => 'model_id', 'operator' => 'operator', 'hardware_rooted' => 'hardware_rooted', 'issued_at' => 'issued_at',
            'weights_measured' => 'weights_measured'] as $k => $f) {
            if (Js::has($passport, $f)) {
                $cs->set($k, Js::opt($passport, $f));
            }
        }
        if ($sd !== []) {
            $cs->set('_sd', $sd);
        }
        $vc = Obj::of(['@context' => [self::VC_CONTEXT, self::AGENT_PASSPORT_CONTEXT], 'type' => ['VerifiableCredential', self::AGENT_PASSPORT_VC_TYPE],
            'credentialSubject' => $cs]);
        $payload = Obj::of(['vc' => $vc]);
        if ($sd !== []) {
            $payload->set('_sd_alg', 'sha-256');
        }
        foreach (['iss' => 'issuerDid', 'sub' => 'subjectDid'] as $claim => $a) {
            if (Js::has($args, $a)) {
                $payload->set($claim, Js::opt($args, $a));
            }
        }
        $clock = Js::opt($args, 'now');
        $now = floor((float)($clock === null ? floor(microtime(true) * 1000) : Js::num($clock)) / 1000);
        $payload->set('iat', $now);
        if (Js::has($args, 'ttlSec')) {
            $ttl = Js::opt($args, 'ttlSec');
            if (is_string($ttl)) { // now + "x" is a string: jose reads it as a time span
                $payload->set('exp', $now + Jose::secs(Js::str($now) . $ttl));
            } else {
                $exp = $now + (float)($ttl === null ? 0 : (is_bool($ttl) ? (int)$ttl : Js::num($ttl) ?? NAN));
                if (!is_finite($exp)) {
                    throw new \TypeError('Invalid setExpirationTime input');
                }
                $payload->set('exp', $exp);
            }
        }
        $jwt = Jose::signJwt($payload, Obj::of(['alg' => 'EdDSA', 'typ' => 'vc+sd-jwt']), self::seed(Js::opt($args, 'issuerKey')));
        return implode('', array_map(static fn(string $p): string => "$p~", [$jwt, ...$disclosures]));
    }

    private static function seed(mixed $k): string
    {
        $b = Bytes::of($k);
        if ($b !== null && strlen($b) < 32) { // the PKCS#8 wrapper the runtime builds around a short seed is truncated DER
            throw new NodeArgError('error:0680008E:asn1 encoding routines::not enough data', 'ERR_OSSL_ASN1_NOT_ENOUGH_DATA');
        }
        if ($b === null || strlen($b) !== 32) {
            throw new \InvalidArgumentException('pca-vc: the signing key must be a 32-byte Ed25519 seed');
        }
        return $b;
    }

    private static function asString(mixed $v, string $label): string
    {
        if (!is_string($v)) {
            throw new \InvalidArgumentException("pca-vc: expected string for $label");
        }
        return $v;
    }

    /**
     * Verify a passport SD-JWT VC under `$issuerVerifyKey` (raw 32-byte Ed25519 public key, public JWK or PubKey). Options:
     * expectedIssuerDid, nowMs (verification clock, default the system clock). Returns {passport, issuerDid, subjectDid};
     * throws on any refusal.
     */
    public static function verifyPassportVC(mixed $vc, mixed $issuerVerifyKey, mixed $options = []): Obj
    {
        if (!is_string($vc)) {
            throw new \TypeError('vc.split is not a function');
        }
        $parts = explode('~', $vc);
        $jwt = $parts[0];
        if ($jwt === '') {
            throw new \InvalidArgumentException('pca-vc: empty SD-JWT');
        }
        $disclosures = array_values(array_filter(array_slice($parts, 1), static fn(string $p) => $p !== ''));
        Jose::assertCanonicalCompactJws($jwt);
        foreach ($disclosures as $d) {
            Jose::decodeCanonicalBase64url($d);
        }
        $o = ['algorithms' => ['EdDSA']];
        if (Js::opt($options, 'nowMs') !== null) {
            $o['nowMs'] = Js::opt($options, 'nowMs');
        }
        [$payload, $header] = Jose::jwtVerify($jwt, $issuerVerifyKey instanceof Bytes ? $issuerVerifyKey->raw : $issuerVerifyKey, $o);
        if ($header->get('typ') !== 'vc+sd-jwt') {
            throw new \InvalidArgumentException("pca-vc: header typ must be 'vc+sd-jwt'");
        }
        $vcClaim = $payload->get('vc');
        if (!($vcClaim instanceof Obj)) {
            throw new \InvalidArgumentException('pca-vc: missing vc claim');
        }
        $ctx = $vcClaim->get('@context');
        if (!is_array($ctx) || !array_is_list($ctx) || ($ctx[0] ?? null) !== self::VC_CONTEXT) {
            throw new \InvalidArgumentException('pca-vc: @context must begin with ' . self::VC_CONTEXT);
        }
        if (count($ctx) !== 2 || $ctx[1] !== self::AGENT_PASSPORT_CONTEXT) {
            throw new \InvalidArgumentException('pca-vc: @context must be exactly [' . self::VC_CONTEXT . ', ' . self::AGENT_PASSPORT_CONTEXT . ']');
        }
        $types = $vcClaim->get('type');
        if (!is_array($types) || !array_is_list($types) || !in_array('VerifiableCredential', $types, true) || !in_array(self::AGENT_PASSPORT_VC_TYPE, $types, true)) {
            throw new \InvalidArgumentException('pca-vc: type must include VerifiableCredential and ' . self::AGENT_PASSPORT_VC_TYPE);
        }
        $cs = $vcClaim->get('credentialSubject');
        if (!($cs instanceof Obj)) {
            throw new \InvalidArgumentException('pca-vc: missing credentialSubject');
        }
        if ($cs->has('_sd_alg')) {
            throw new \InvalidArgumentException('pca-vc: _sd_alg must be a top-level claim');
        }
        if ($payload->has('_sd_alg') && $payload->get('_sd_alg') !== 'sha-256') {
            throw new \InvalidArgumentException('pca-vc: unsupported _sd_alg (require sha-256)');
        }
        $sdRaw = $cs->get('_sd');
        $sdList = is_array($sdRaw) && array_is_list($sdRaw) ? array_values(array_filter($sdRaw, 'is_string')) : [];
        $recovered = [];
        $seen = [];
        foreach ($disclosures as $d) {
            $digest = self::sha($d);
            if (!in_array($digest, $sdList, true)) {
                throw new \InvalidArgumentException('pca-vc: disclosure does not match any _sd digest');
            }
            if (isset($seen[$digest])) {
                throw new \InvalidArgumentException('pca-vc: duplicate disclosure');
            }
            $seen[$digest] = true;
            try {
                $decoded = Js::parseNoDuplicates(Jose::lenientB64d($d)); // a repeated member is refused (JSON.parse keeps the last); numbers stay as written
            } catch (\Throwable) {
                throw new \InvalidArgumentException('pca-vc: malformed disclosure');
            }
            if (!is_array($decoded) || !array_is_list($decoded) || count($decoded) !== 3) {
                throw new \InvalidArgumentException('pca-vc: malformed disclosure');
            }
            $name = self::asString($decoded[1], 'disclosure name');
            if (!in_array($name, self::SD_DIGEST_FIELDS, true)) {
                throw new \InvalidArgumentException("pca-vc: unexpected disclosure claim '$name'");
            }
            if (array_key_exists($name, $recovered)) {
                throw new \InvalidArgumentException("pca-vc: disclosure claim '$name' appears more than once");
            }
            $recovered[$name] = self::asString($decoded[2], 'disclosure value');
        }
        $hw = $cs->get('hardware_rooted');
        if (!is_bool($hw)) {
            throw new \InvalidArgumentException('pca-vc: expected boolean for hardware_rooted');
        }
        $passport = Obj::of(['id' => self::asString($cs->get('passport_id'), 'passport_id'), 'model_id' => self::asString($cs->get('model_id'), 'model_id'),
            'operator' => self::asString($cs->get('operator'), 'operator'), 'hardware_rooted' => $hw]);
        if (!Js::isNum($cs->get('issued_at'))) {
            throw new \InvalidArgumentException('pca-vc: expected number for issued_at');
        }
        $passport->set('issued_at', $cs->get('issued_at'));
        if ($cs->has('weights_measured')) {
            if (!is_bool($cs->get('weights_measured'))) {
                throw new \InvalidArgumentException('pca-vc: expected boolean for weights_measured');
            }
            $passport->set('weights_measured', $cs->get('weights_measured'));
        }
        foreach (self::SD_DIGEST_FIELDS as $f) {
            if (array_key_exists($f, $recovered)) {
                $passport->set($f, $recovered[$f]);
            }
        }
        $issuerDid = self::asString($payload->get('iss'), 'iss');
        $subjectDid = self::asString($cs->get('id'), 'credentialSubject.id');
        if ($payload->get('sub') !== $subjectDid) {
            throw new \InvalidArgumentException('pca-vc: sub does not match credentialSubject.id');
        }
        if (Js::has($options, 'expectedIssuerDid') && $issuerDid !== Js::opt($options, 'expectedIssuerDid')) {
            throw new \InvalidArgumentException('pca-vc: iss does not match expectedIssuerDid');
        }
        return Obj::of(['passport' => $passport, 'issuerDid' => $issuerDid, 'subjectDid' => $subjectDid]);
    }

    // ---- RFC 9421 HTTP message signatures ---------------------------------------------------------------------------

    private static function trim(string $s): string
    {
        $ws = '(?:' . IntentWb::JS_WS . ')+';
        return (string)preg_replace('/\A' . $ws . '|' . $ws . '\z/', '', $s);
    }

    /** new URL(url).host, or a TypeError like the platform's. */
    private static function host(mixed $url): string
    {
        $u = WhatwgUrl::parse($url);
        if ($u === null) {
            throw new NodeTypeError('Invalid URL', 'ERR_INVALID_URL');
        }
        return $u['host'];
    }

    /** @return array<string, mixed> header names lowercased (a later duplicate wins) */
    private static function normalizeHeaders(mixed $headers): array
    {
        if ($headers === null) {
            throw new \TypeError('Cannot convert undefined or null to object');
        }
        $out = [];
        $keys = $headers instanceof Obj ? Js::ownKeys($headers->keys()) : (is_array($headers) && !array_is_list($headers) ? array_map('strval', array_keys($headers)) : []);
        foreach ($keys as $k) {
            $out['h' . mb_strtolower($k, 'UTF-8')] = Js::opt($headers, $k);
        }
        return $out;
    }

    private static function componentValue(string $name, mixed $method, mixed $url, array $headers): string
    {
        if ($name === '@method') {
            if (!is_string($method)) {
                throw new \TypeError('method.toUpperCase is not a function');
            }
            return mb_strtoupper($method, 'UTF-8');
        }
        if ($name === '@target-uri') {
            return Js::str($url);
        }
        if ($name === '@authority') {
            return self::host($url);
        }
        if (!array_key_exists('h' . $name, $headers)) {
            throw new \InvalidArgumentException("pca-vc: covered header '$name' absent from request");
        }
        $v = $headers['h' . $name];
        if (!is_string($v)) {
            throw new \TypeError('v.trim is not a function');
        }
        return self::trim($v);
    }

    private static function signatureBase(array $components, string $sigParams, mixed $method, mixed $url, array $headers): string
    {
        $lines = array_map(static fn(string $c): string => "\"$c\": " . self::componentValue($c, $method, $url, $headers), $components);
        $lines[] = "\"@signature-params\": $sigParams";
        return implode("\n", $lines);
    }

    /**
     * Sign a request (RFC 9421, label sig1, every header covered). Args: method, url, headers, key (32-byte Ed25519 seed),
     * keyid, created (unix s, default now), signatureAgent (Web Bot Auth key-directory URL: emitted as `Signature-Agent`,
     * covered, and tagged `web-bot-auth`). Returns {signatureInput, signature, signatureAgent?}.
     */
    public static function signRequestMessage(mixed $args): Obj
    {
        $method = Js::opt($args, 'method');
        $url = Js::opt($args, 'url');
        $created = Js::opt($args, 'created') ?? floor(microtime(true));
        $headers = self::normalizeHeaders(Js::opt($args, 'headers'));
        if (!array_key_exists('hhost', $headers)) {
            $headers['hhost'] = self::host($url);
        }
        $agent = Js::has($args, 'signatureAgent');
        if ($agent) {
            $headers['hsignature-agent'] = '"' . Js::str(Js::opt($args, 'signatureAgent')) . '"';
        }
        $names = array_map(static fn(string $k): string => substr($k, 1), array_keys($headers));
        usort($names, static fn(string $a, string $b): int => strcmp(mb_convert_encoding($a, 'UTF-16BE', 'UTF-8'), mb_convert_encoding($b, 'UTF-16BE', 'UTF-8')));
        $components = ['@method', '@target-uri', ...$names];
        $inner = '(' . implode(' ', array_map(static fn(string $c): string => "\"$c\"", $components)) . ')';
        $params = ';created=' . Js::str($created) . ';keyid="' . Js::str(Js::opt($args, 'keyid')) . '";alg="ed25519"';
        if ($agent) {
            $params .= ';tag="web-bot-auth"';
        }
        $sigParams = $inner . $params;
        $base = self::signatureBase($components, $sigParams, $method, $url, $headers);
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::seed(Js::opt($args, 'key'))));
        $out = Obj::of(['signatureInput' => self::SIG_LABEL . '=' . $sigParams,
            'signature' => self::SIG_LABEL . '=:' . base64_encode(sodium_crypto_sign_detached(Js::utf8($base), $sk)) . ':']);
        if ($agent) {
            $out->set('signatureAgent', '"' . Js::str(Js::opt($args, 'signatureAgent')) . '"');
        }
        return $out;
    }

    /** @return list<string> */
    private static function parseComponents(string $sigParams): array
    {
        $open = strpos($sigParams, '(');
        $close = strpos($sigParams, ')');
        if ($open !== 0 || $close === false) {
            throw new \InvalidArgumentException('pca-vc: malformed @signature-params');
        }
        $inner = self::trim(substr($sigParams, 1, $close - 1));
        if ($inner === '') {
            return [];
        }
        return array_map(static function (string $tok): string {
            if (preg_match('/\A"((?:(?![\n\r]|\xE2\x80[\xA8\xA9])[\s\S])*)"\z/', $tok, $m) !== 1) {
                throw new \InvalidArgumentException('pca-vc: malformed component identifier');
            }
            return $m[1];
        }, preg_split('/(?:' . IntentWb::JS_WS . ')+/', $inner) ?: []);
    }

    /** Buffer.from(s, 'base64'): both alphabets, anything else skipped, decoding stops at the first '='. */
    private static function nodeB64(string $s): string
    {
        $s = substr($s, 0, strcspn($s, '='));
        $t = strtr((string)preg_replace('/[^A-Za-z0-9+\/\-_]/', '', $s), '-_', '+/');
        if (strlen($t) % 4 === 1) {
            $t = substr($t, 0, -1);
        }
        return (string)base64_decode($t . str_repeat('=', (4 - strlen($t) % 4) % 4));
    }

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

    /**
     * Verify an RFC 9421 request signature under a raw 32-byte Ed25519 public key. Args: method, url, headers, signatureInput,
     * signature, signatureAgent (the received header, used when covered), requiredComponents, maxAgeSec (created must be
     * present, no older, at most 5 s ahead), nowSec. False on any failure.
     */
    public static function verifyRequestSignature(mixed $args, mixed $verifyKey): bool
    {
        try {
            $input = Js::opt($args, 'signatureInput');
            if (!is_string($input)) {
                return false;
            }
            $eq = strpos($input, '=');
            if ($eq === false) {
                return false;
            }
            $sigParams = substr($input, $eq + 1);
            $components = self::parseComponents($sigParams);
            foreach (Js::spread(Js::opt($args, 'requiredComponents') ?? []) as $need) {
                if (!in_array($need, $components, true)) {
                    return false;
                }
            }
            if (preg_match('/;alg="([^"]*)"/', $sigParams, $am) === 1 && $am[1] !== 'ed25519') {
                return false;
            }
            if (Js::has($args, 'maxAgeSec')) {
                if (preg_match('/;created=([0-9]+)/', $sigParams, $cm) !== 1) {
                    return false;
                }
                $now = Js::opt($args, 'nowSec') ?? floor(microtime(true));
                $now = self::jsNum($now);
                $c = (float)$cm[1];
                if (!is_finite($now) || !is_finite($c) || !($now - $c <= self::jsNum(Js::opt($args, 'maxAgeSec'))) || !($c - $now <= 5)) {
                    return false;
                }
            }
            $url = Js::opt($args, 'url');
            $headers = self::normalizeHeaders(Js::opt($args, 'headers'));
            if (!array_key_exists('hhost', $headers)) {
                $headers['hhost'] = self::host($url);
            }
            if (in_array('signature-agent', $components, true) && !array_key_exists('hsignature-agent', $headers)) {
                if (!Js::has($args, 'signatureAgent')) {
                    return false;
                }
                $headers['hsignature-agent'] = Js::opt($args, 'signatureAgent');
            }
            $base = self::signatureBase($components, $sigParams, Js::opt($args, 'method'), $url, $headers);
            $sig = Js::opt($args, 'signature');
            if (!is_string($sig)) {
                return false;
            }
            $sigEq = strpos($sig, '=');
            if ($sigEq === false) {
                return false;
            }
            if (preg_match('/\A:((?:(?![\n\r]|\xE2\x80[\xA8\xA9])[\s\S])*):\z/', self::trim(substr($sig, $sigEq + 1)), $m) !== 1) {
                return false;
            }
            $sigBytes = self::nodeB64($m[1]);
            $pk = Bytes::of($verifyKey);
            return $pk !== null && strlen($pk) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES && strlen($sigBytes) === SODIUM_CRYPTO_SIGN_BYTES
                && sodium_crypto_sign_verify_detached($sigBytes, Js::utf8($base), $pk);
        } catch (\Throwable) {
            return false;
        }
    }
}
