<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Cert.php';
require_once __DIR__ . '/HardwareVerifier.php';

use Atlas\Pca\Obj;

/**
 * Google Cloud Confidential Space attestation-token verifier (the native counterpart of `createGcpConfidentialSpaceVerifier`).
 * The token's signing key must be anchored to a CONFIGURED anchor (a pinned JWKS, an SPKI SHA-256 pin or an `x5c` chain to a
 * root); the JWS (RS256 / ES256) is verified under it, then `iss` / time window, `submods.confidential_space`, `swname` /
 * `swversion`, `hwmodel`, `dbgstat`, the `eat_nonce` binding and the NON-EMPTY `image_digest` allowlist. Fails closed with the
 * reference's reason strings.
 */
final class Gcp implements HardwareVerifier
{
    public const SUITE = 'gcp-confidential-space-jwt';
    public const DEFAULT_ISSUER = 'https://confidentialcomputing.googleapis.com';
    private const DBGSTAT_DISABLED = 'disabled-since-boot';

    public static function teeTypeOfHwmodel(string $hwmodel): ?string
    {
        if (in_array($hwmodel, ['GCP_AMD_SEV', 'GCP_AMD_SEV_SNP', 'GCP_AMD_SEV_ES'], true)) {
            return 'sev-snp';
        }
        if ($hwmodel === 'GCP_INTEL_TDX') {
            return 'tdx';
        }
        $up = strtoupper($hwmodel);
        if (str_starts_with($up, 'GCP_AMD_SEV')) {
            return 'sev-snp';
        }
        if (str_starts_with($up, 'GCP_INTEL_TDX')) {
            return 'tdx';
        }
        return null;
    }

    private static function ktyName(PubKey $k): string
    {
        return ['ec' => 'EC', 'rsa' => 'RSA'][$k->type] ?? $k->type;
    }

    /** A public key from a JWK (RSA n/e, EC x/y, or the leaf of an x5c chain); throws on anything unusable, null when it carries none. */
    private static function jwkKey(mixed $jwk): ?PubKey
    {
        $n = Common::g($jwk, 'n');
        $e = Common::g($jwk, 'e');
        if (is_string($n) && is_string($e)) {
            return Common::loadPublicKey(Common::rsaSpki(Common::nodeB64Decode($n), Common::nodeB64Decode($e)));
        }
        $crv = Common::g($jwk, 'crv');
        $x = Common::g($jwk, 'x');
        $y = Common::g($jwk, 'y');
        if (Common::g($jwk, 'kty') === 'EC' && is_string($crv) && is_string($x) && is_string($y)) {
            if (!in_array($crv, ['P-256', 'P-384', 'P-521'], true)) {
                throw new \ValueError("unsupported curve $crv");
            }
            return Common::loadPublicKey(Common::ecSpki($crv, Common::nodeB64Decode($x), Common::nodeB64Decode($y)));
        }
        $x5c = Common::g($jwk, 'x5c');
        if (Common::isList($x5c) && count($x5c) > 0 && is_string($x5c[0])) {
            return (new Cert(Common::nodeB64Decode($x5c[0])))->publicKey();
        }
        return null;
    }

    /** @return array<string,mixed> */
    private static function keyFromJwk(mixed $jwk): array
    {
        try {
            $key = self::jwkKey($jwk);
        } catch (\Throwable $e) {
            return ['reason' => 'JWKS key is not a usable public key: ' . $e->getMessage()];
        }
        if ($key === null) {
            return ['reason' => 'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate'];
        }
        return ['key' => $key];
    }

    /** @return list<string> */
    private static function lowerList(mixed $v): array
    {
        return array_map(static fn($s) => strtolower((string)$s), Common::isList($v) ? $v : []);
    }

    /** A JWK's `x5c` chain to a configured root PEM / SPKI anchor; a failure reason or null. */
    public static function verifyJwkX5cChain(mixed $x5c, mixed $anchors, float $nowMs, float $skewMs): ?string
    {
        if (!Common::isList($x5c) || count($x5c) === 0) {
            return 'empty x5c certificate chain';
        }
        $certs = [];
        foreach ($x5c as $i => $b64) {
            if (!is_string($b64) || $b64 === '') {
                return "empty x5c entry at index $i";
            }
            try {
                $cert = new Cert(Common::nodeB64Decode($b64));
            } catch (\Throwable $e) {
                return "malformed x5c certificate at index $i: " . $e->getMessage();
            }
            if (!Der::x509ValidAt($cert->raw, $nowMs, $skewMs)) {
                return "x5c certificate at index $i is outside its validity window";
            }
            $certs[] = $cert;
        }
        for ($i = 0; $i < count($certs) - 1; $i++) {
            if (!$certs[$i]->verify($certs[$i + 1]->publicKey())) {
                return "x5c link $i is not signed by the certificate above it";
            }
        }
        $pins = array_flip(self::lowerList(Common::g($anchors, 'trustedKeySpki')));
        foreach ($certs as $c) {
            if (isset($pins[Common::spkiSha($c->publicKey(), 'sha256')])) {
                return null;
            }
        }
        $top = $certs[count($certs) - 1];
        $roots = Common::g($anchors, 'rootCertsPem');
        foreach (Common::isList($roots) ? $roots : [] as $pem) {
            try {
                $rootKey = Cert::fromPem((string)$pem)->publicKey();
            } catch (\Throwable) {
                $k = @openssl_pkey_get_public((string)$pem);
                if ($k === false) {
                    continue;
                }
                $det = openssl_pkey_get_details($k) ?: [];
                $pemOut = (string)($det['key'] ?? '');
                $der = Common::nodeB64Decode(preg_replace('/-----[A-Z ]+-----|\s+/', '', $pemOut) ?? '');
                try {
                    $rootKey = Common::loadPublicKey($der);
                } catch (\Throwable) {
                    continue;
                }
            }
            if ($top->verify($rootKey)) {
                return null;
            }
        }
        return 'x5c chain does not anchor in a configured GCP trust root';
    }

    /** @return list<mixed> */
    private static function keysOf(mixed $jwks): array
    {
        $keys = Common::g($jwks, 'keys');
        if (!Common::isList($keys)) {
            return [];
        }
        return array_map(static fn($k) => Common::isObj($k) ? $k : new Obj(), $keys);
    }

    /** @return array<string,mixed> */
    private static function resolveTrustedSigningKey(array $header, mixed $evidenceJwks, mixed $anchors, float $nowMs, float $skewMs): array
    {
        $trustedKeys = self::keysOf(Common::g($anchors, 'trustedJwks'));
        $evidenceKeys = self::keysOf($evidenceJwks);
        $kid = $header['kid'] ?? null;
        $hasKid = is_string($kid) && $kid !== '';
        $pick = static function (array $keys) use ($hasKid, $kid) {
            if ($hasKid) {
                foreach ($keys as $k) {
                    if (Common::g($k, 'kid') === $kid) {
                        return $k;
                    }
                }
                return null;
            }
            return count($keys) === 1 ? $keys[0] : null;
        };
        $jwk = $pick($evidenceKeys);
        $fromTrusted = false;
        if ($jwk === null) {
            $jwk = $pick($trustedKeys);
            $fromTrusted = $jwk !== null;
        }
        $hx = $header['x5c'] ?? null;
        $hasHx = Common::isList($hx) && count($hx) > 0;
        if ($jwk === null && $hasKid && $hasHx) {
            $jwk = Obj::of(['x5c' => $hx, 'kid' => $kid]);
        } elseif ($jwk === null && !$hasKid && $hasHx) {
            $jwk = Obj::of(['x5c' => $hx]);
        }
        if ($jwk === null) {
            return ['reason' => $hasKid ? "no JWKS key matches the token kid '$kid' (untrusted signer)" : 'no kid on the token and no unambiguous single signing key available'];
        }
        $built = self::keyFromJwk($jwk);
        if (isset($built['reason'])) {
            return $built;
        }
        $key = $built['key'];
        $spki = Common::spkiSha($key, 'sha256');
        if ($fromTrusted) {
            return ['key' => $key];
        }
        $pins = array_flip(self::lowerList(Common::g($anchors, 'trustedKeySpki')));
        if (isset($pins[$spki])) {
            return ['key' => $key];
        }
        foreach ($trustedKeys as $tk) {
            $tb = self::keyFromJwk($tk);
            if (isset($tb['reason'])) {
                continue;
            }
            if (Common::spkiSha($tb['key'], 'sha256') === $spki) {
                return ['key' => $key];
            }
        }
        $x5c = Common::g($jwk, 'x5c');
        $roots = Common::g($anchors, 'rootCertsPem');
        if (Common::isList($x5c) && count($x5c) > 0 && ((Common::isList($roots) && count($roots) > 0) || count($pins) > 0)) {
            $err = self::verifyJwkX5cChain($x5c, $anchors, $nowMs, $skewMs);
            return $err === null ? ['key' => $key] : ['reason' => "signing key not trusted: $err"];
        }
        return ['reason' => 'signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)'];
    }

    private static function verifyJwsSignature(array $parsed, PubKey $key): ?string
    {
        $alg = $parsed['header']['alg'];
        if ($alg === 'RS256') {
            if ($key->type !== 'rsa') {
                return 'RS256 token but signing key is ' . self::ktyName($key) . ' (not RSA)';
            }
            return Common::rsaPkcs1Verify($key, $parsed['signature'], $parsed['signingInput'], 'sha256') ? null : 'JWS RS256 signature does not verify under the Confidential Space signing key';
        }
        if ($alg === 'ES256') {
            if ($key->type !== 'ec' || Common::jwkCurve($key) !== 'P-256') {
                return 'ES256 token but signing key is ' . self::ktyName($key) . '/' . (Common::jwkCurve($key) ?? 'undefined') . ' (not EC P-256)';
            }
            if (strlen($parsed['signature']) !== 64) {
                return 'ES256 signature is ' . strlen($parsed['signature']) . ' bytes (expected 64: r‖s)';
            }
            return Common::ecdsaVerifyRaw($key, $parsed['signature'], $parsed['signingInput'], 'sha256') ? null : 'JWS ES256 signature does not verify under the Confidential Space signing key';
        }
        return "unsupported JWS alg '$alg' (Confidential Space uses RS256)";
    }

    /** @return list<string> */
    private static function nonceCandidates(mixed $v): array
    {
        if (is_string($v)) {
            return $v !== '' ? [$v] : [];
        }
        $arr = Common::asStrList($v);
        return $arr === null ? [] : array_values(array_filter($arr, static fn($s) => $s !== ''));
    }

    // ---- the verifier -----------------------------------------------------------------------------------------------------------

    /** @var array<string,mixed> */
    private array $policy;
    private mixed $anchors;
    /** @var array<string,true> */
    private array $issuers = [];
    private float $skew;
    /** @var array<string,true> */
    private array $images = [];
    /** @var array<string,true>|null */
    private ?array $teeTypes = null;
    private string $swName;
    /** @var array<string,true>|null */
    private ?array $swVersions = null;
    /** @var callable */
    private $resolve;

    public function __construct(mixed $config, callable $resolve)
    {
        $ti = Common::g($config, 'trustedIssuers');
        if (!Common::isList($ti) || count($ti) === 0) {
            throw new AttestConstructError('createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs');
        }
        foreach ($ti as $iss) {
            if (!is_string($iss) || $iss === '') {
                throw new AttestConstructError('createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string');
            }
        }
        $anchors = Common::g($config, 'trustAnchors');
        $a = Common::isObj($anchors) ? $anchors : new Obj();
        $tj = Common::g($a, 'trustedJwks');
        $tjKeys = Common::g($tj, 'keys');
        $spki = Common::g($a, 'trustedKeySpki');
        $roots = Common::g($a, 'rootCertsPem');
        $count = (Common::isObj($tj) && Common::isList($tjKeys) ? count($tjKeys) : 0) + (Common::isList($spki) ? count($spki) : 0) + (Common::isList($roots) ? count($roots) : 0);
        if ($count === 0) {
            throw new AttestConstructError('createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted');
        }
        $polIn = Common::g($config, 'policy');
        $policy = Common::members($polIn);
        if (!Common::isObj($polIn) || !Common::isList($policy['imageDigests'] ?? null) || count($policy['imageDigests']) === 0) {
            throw new AttestConstructError('createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)');
        }
        $att = $policy['allowedTeeTypes'] ?? null;
        if (Common::isList($att) && count($att) === 0) {
            throw new AttestConstructError('createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty');
        }
        $this->anchors = $a;
        $this->policy = $policy;
        foreach ($ti as $iss) {
            $this->issuers[$iss] = true;
        }
        $skew = Common::numOf(Common::g($config, 'clockSkewMs'));
        $this->skew = $skew !== null ? max(0.0, $skew) : 0.0;
        foreach ($policy['imageDigests'] as $x) {
            $this->images[strtolower((string)$x)] = true;
        }
        $this->teeTypes = Common::isList($att) ? array_fill_keys(array_map('strval', $att), true) : null;
        $this->swName = is_string($policy['expectedSwName'] ?? null) ? $policy['expectedSwName'] : 'CONFIDENTIAL_SPACE';
        $asv = $policy['allowedSwVersions'] ?? null;
        $this->swVersions = Common::isList($asv) ? array_fill_keys(array_map('strval', $asv), true) : null;
        $this->resolve = $resolve;
    }

    public function verify(mixed $document, mixed $expected, mixed $nowMs): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        $policy = $this->policy;
        try {
            $evidence = ($this->resolve)($document);
            if (!is_array($evidence) || !is_string($evidence['token'] ?? null) || $evidence['token'] === '') {
                return $fail('no GCP Confidential Space token for this action');
            }
            try {
                $parsed = Common::parseJws($evidence['token'], 'parseGcpCsJwt');
            } catch (\TypeError $e) {
                return $fail('Confidential Space token parse failed: ' . $e->getMessage());
            }
            $alg = $parsed['header']['alg'];
            if ($alg !== 'RS256' && $alg !== 'ES256') {
                return $fail("unsupported JWS alg '$alg' (Confidential Space uses RS256)");
            }
            $now = (float)Common::numOf($nowMs);
            $resolved = self::resolveTrustedSigningKey($parsed['header'], $evidence['jwks'] ?? null, $this->anchors, $now, $this->skew);
            if (!isset($resolved['key'])) {
                return $fail('Confidential Space signing key invalid: ' . $resolved['reason']);
            }
            $sigErr = self::verifyJwsSignature($parsed, $resolved['key']);
            if ($sigErr !== null) {
                return $fail($sigErr);
            }
            $payload = $parsed['payload'];
            $iss = Common::asStr($payload->get('iss'));
            if ($iss === null || $iss === '' || !isset($this->issuers[$iss])) {
                return $fail("token iss '" . ($iss ?? 'undefined') . "' is not a configured trusted Google attestation issuer");
            }
            $nowSec = floor($now / 1000);
            $skewSec = ceil($this->skew / 1000);
            $exp = Common::numOf($payload->get('exp'));
            $iat = Common::numOf($payload->get('iat'));
            $nbf = Common::numOf($payload->get('nbf'));
            if ($exp === null) {
                return $fail('token has no exp (cannot bound validity — fail closed)');
            }
            if ($nowSec - $skewSec > $exp) {
                return $fail('Confidential Space token expired');
            }
            if ($nbf !== null && $nowSec + $skewSec < $nbf) {
                return $fail('Confidential Space token not yet valid (nbf)');
            }
            if ($iat !== null && $nowSec + $skewSec < $iat) {
                return $fail('Confidential Space token issued in the future (iat)');
            }
            $submods = $payload->get('submods') instanceof Obj ? $payload->get('submods') : null;
            $cs = $submods !== null && $submods->get('confidential_space') instanceof Obj ? $submods->get('confidential_space') : null;
            if ($cs === null) {
                return $fail('token carries no submods.confidential_space (not a Confidential Space token)');
            }
            $swname = Common::asStr($payload->get('swname'));
            if ($swname !== $this->swName) {
                return $fail("unexpected swname '" . ($swname ?? 'undefined') . "' (expected '" . $this->swName . "')");
            }
            if ($this->swVersions !== null) {
                $v = $payload->get('swversion');
                $versions = Common::asStrList($v) ?? (Common::asStr($v) !== null && $v !== '' ? [$v] : []);
                $any = false;
                foreach ($versions as $x) {
                    $any = $any || isset($this->swVersions[$x]);
                }
                if (!$any) {
                    return $fail('swversion not in policy allowlist');
                }
            }
            $hwmodel = Common::asStr($payload->get('hwmodel'));
            if ($hwmodel === null || $hwmodel === '') {
                return $fail('token carries no hwmodel claim');
            }
            $teeType = self::teeTypeOfHwmodel($hwmodel);
            if ($teeType === null) {
                return $fail("unrecognized hwmodel '$hwmodel' (not a known AMD SEV-SNP / Intel TDX model)");
            }
            if ($this->teeTypes !== null && !isset($this->teeTypes[$teeType])) {
                return $fail("attestation type '$teeType' (hwmodel '$hwmodel') is not in the policy allowlist");
            }
            $dbgstat = Common::asStr($payload->get('dbgstat'));
            if (($policy['allowDebug'] ?? null) !== true && $dbgstat !== self::DBGSTAT_DISABLED) {
                return $fail("token dbgstat '" . ($dbgstat ?? 'undefined') . "' is not '" . self::DBGSTAT_DISABLED . "' (debug build — no confidentiality)");
            }
            if ($expected === null) {
                return $fail('no expected attestation binding supplied');
            }
            try {
                $bindingBytes = Common::transformBinding(Common::attestationBinding($expected), $policy['nonceHash'] ?? null);
            } catch (\TypeError $e) {
                return $fail('binding not constructible: ' . $e->getMessage());
            }
            $candidates = self::nonceCandidates($payload->get('eat_nonce'));
            if ($candidates === []) {
                return $fail('token carries no eat_nonce claim to bind the PCA challenge');
            }
            $bound = false;
            foreach ($candidates as $cand) {
                $b = Common::decodeClaimBytes($cand);
                if ($b !== null && $b === $bindingBytes) {
                    $bound = true;
                    break;
                }
            }
            if (!$bound) {
                return $fail('eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)');
            }
            $container = $submods->get('container') instanceof Obj ? $submods->get('container') : new Obj();
            $imageDigest = Common::firstString($container, ['image_digest']);
            if ($imageDigest === null) {
                return $fail('token carries no submods.container.image_digest to measure the workload');
            }
            if (!isset($this->images[strtolower($imageDigest)])) {
                return $fail('workload image_digest not in policy allowlist');
            }
            $host = ['attestation_type' => $teeType, 'hwmodel' => $hwmodel, 'image_digest' => $imageDigest];
            $imageRef = Common::firstString($container, ['image_reference']);
            if ($imageRef !== null) {
                $host['image_reference'] = $imageRef;
            }
            return ['ok' => true, 'bound' => true, 'measured' => ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false,
                'runtime_measurement' => $imageDigest, 'operator' => ''], 'hostAsserted' => $host];
        } catch (\Throwable $e) {
            return $fail('gcp-confidential-space verification error (fail closed): ' . $e->getMessage());
        }
    }
}
