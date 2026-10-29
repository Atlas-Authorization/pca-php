<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Cert.php';
require_once __DIR__ . '/HardwareVerifier.php';

use Atlas\Pca\Obj;

/**
 * Microsoft Azure Attestation (MAA) JWT verifier (the native counterpart of `createAzureMaaVerifier`). The token-signing `x5c`
 * chain is verified link by link to a CONFIGURED trust anchor (an SPKI SHA-256 pin or an external root certificate), the JWS
 * (ES256 / RS256) under the leaf key, the `iss` / time window, the isolation-type claims (`sevsnpvm` / `tdxvm`), the PCA binding
 * and the NON-EMPTY measurement allowlist. Fails closed with the reference's reason strings.
 */
final class Maa implements HardwareVerifier
{
    public const SUITE = 'azure-maa-jwt';
    private const SEV_REPORTDATA = ['x-ms-sevsnpvm-reportdata'];
    private const TDX_MRTD = ['tdx_mrtd', 'x-ms-tdx-mrtd'];
    private const TDX_REPORTDATA = ['tdx_report_data', 'x-ms-tdx-report-data', 'x-ms-tdx-reportdata'];
    private const TDX_RTMR0 = ['tdx_rtmr0', 'x-ms-tdx-rtmr0'];
    /** name, claim, host key */
    private const SEV_TCB = [
        ['bootloader', 'x-ms-sevsnpvm-bootloader-svn', 'bootloader_svn'],
        ['snp', 'x-ms-sevsnpvm-snpfw-svn', 'snpfw_svn'],
        ['microcode', 'x-ms-sevsnpvm-microcode-svn', 'microcode_svn'],
        ['tee', 'x-ms-sevsnpvm-tee-svn', 'tee_svn'],
    ];

    private static function kty(PubKey $k): string
    {
        return ['ec' => 'EC', 'rsa' => 'RSA'][$k->type] ?? $k->type;
    }

    private static function ktyCrv(PubKey $k): string
    {
        return self::kty($k) . '/' . (Common::jwkCurve($k) ?? 'undefined');
    }

    /**
     * An `x5c` chain (base64 DER, leaf first) to a configured trust anchor; every certificate valid at `now` (+- skew).
     * @return array<string,mixed>
     */
    public static function verifyX5cChain(mixed $x5c, mixed $anchors, float $nowMs, float $skewMs = 0): array
    {
        try {
            if (!Common::isList($x5c) || count($x5c) === 0) {
                return ['ok' => false, 'reason' => 'empty x5c certificate chain'];
            }
            $skew = max(0.0, $skewMs);
            $certs = [];
            foreach ($x5c as $i => $b64) {
                if (!is_string($b64) || $b64 === '') {
                    return ['ok' => false, 'reason' => "empty x5c entry at index $i"];
                }
                $der = Common::nodeB64Decode($b64);
                try {
                    $cert = new Cert($der);
                } catch (\Throwable $e) {
                    // the reference wraps the entry as PEM: bytes that are not even a DER SEQUENCE fail as "no start line"
                    $why = $der === '' || $der[0] !== "\x30" ? 'error:0480006C:PEM routines::no start line' : $e->getMessage();
                    return ['ok' => false, 'reason' => "malformed x5c certificate at index $i: $why"];
                }
                if (!Der::x509ValidAt($cert->raw, $nowMs, $skew)) {
                    return ['ok' => false, 'reason' => "x5c certificate at index $i is outside its validity window"];
                }
                $certs[] = $cert;
            }
            $fingerprints = [];
            $rootKeys = [];
            $fps = Common::g($anchors, 'rootSpkiSha256');
            foreach (Common::isList($fps) ? $fps : [] as $fp) {
                if (is_string($fp) && $fp !== '') {
                    $fingerprints[strtolower($fp)] = true;
                }
            }
            $pems = Common::g($anchors, 'rootCertsPem');
            foreach (Common::isList($pems) ? $pems : [] as $pem) {
                $rc = Cert::fromPem((string)$pem);
                $rootKeys[] = $rc->publicKey();
                $fingerprints[Common::spkiSha($rc->publicKey(), 'sha256')] = true;
            }
            if ($fingerprints === [] && $rootKeys === []) {
                return ['ok' => false, 'reason' => 'no MAA trust anchor configured (fail closed)'];
            }
            $anchorIdx = -1;
            foreach ($certs as $j => $c) {
                if (isset($fingerprints[Common::spkiSha($c->publicKey(), 'sha256')])) {
                    $anchorIdx = $j;
                    break;
                }
            }
            if ($anchorIdx >= 0) {
                for ($i = 0; $i < $anchorIdx; $i++) {
                    if (!$certs[$i]->verify($certs[$i + 1]->publicKey())) {
                        return ['ok' => false, 'reason' => "x5c link $i is not signed by the certificate above it"];
                    }
                }
                return ['ok' => true, 'leaf' => $certs[0]];
            }
            for ($i = 0; $i < count($certs) - 1; $i++) {
                if (!$certs[$i]->verify($certs[$i + 1]->publicKey())) {
                    return ['ok' => false, 'reason' => "x5c link $i is not signed by the certificate above it"];
                }
            }
            $top = $certs[count($certs) - 1];
            foreach ($rootKeys as $k) {
                if ($top->verify($k)) {
                    return ['ok' => true, 'leaf' => $certs[0]];
                }
            }
            return ['ok' => false, 'reason' => 'x5c chain does not anchor in a configured MAA trust root'];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'x5c chain verification error (fail closed): ' . $e->getMessage()];
        }
    }

    private static function verifyJwsSignature(array $parsed, Cert $leaf): ?string
    {
        $alg = $parsed['header']['alg'];
        $key = $leaf->publicKey();
        if ($alg === 'ES256') {
            if ($key->type !== 'ec' || Common::jwkCurve($key) !== 'P-256') {
                return 'ES256 token but signing key is ' . self::ktyCrv($key) . ' (not EC P-256)';
            }
            if (strlen($parsed['signature']) !== 64) {
                return 'ES256 signature is ' . strlen($parsed['signature']) . ' bytes (expected 64: r‖s)';
            }
            return Common::ecdsaVerifyRaw($key, $parsed['signature'], $parsed['signingInput'], 'sha256') ? null : 'JWS ES256 signature does not verify under the MAA signing key';
        }
        if ($alg === 'RS256') {
            if ($key->type !== 'rsa') {
                return 'RS256 token but signing key is ' . self::kty($key) . ' (not RSA)';
            }
            return Common::rsaPkcs1Verify($key, $parsed['signature'], $parsed['signingInput'], 'sha256') ? null : 'JWS RS256 signature does not verify under the MAA signing key';
        }
        return "unsupported JWS alg '$alg' (MAA uses ES256 / RS256)";
    }

    /** @return array<string,mixed> */
    private static function resolveSigningX5c(array $header, mixed $jwks): array
    {
        $keys = Common::g($jwks, 'keys');
        if (Common::isList($keys) && count($keys) > 0) {
            $kid = $header['kid'] ?? null;
            if (!is_string($kid) || $kid === '') {
                $only = count($keys) === 1 ? $keys[0] : null;
                if ($only === null) {
                    return ['reason' => 'token has no kid and the JWKS publishes multiple keys (ambiguous)'];
                }
                $x5c = Common::g($only, 'x5c');
                return Common::isList($x5c) && count($x5c) > 0 ? ['x5c' => $x5c] : ['reason' => 'JWKS key carries no x5c chain'];
            }
            $match = null;
            foreach ($keys as $k) {
                if (Common::isObj($k) && Common::g($k, 'kid') === $kid) {
                    $match = $k;
                    break;
                }
            }
            if ($match === null) {
                return ['reason' => "no JWKS key matches the token kid '$kid' (untrusted signer)"];
            }
            $x5c = Common::g($match, 'x5c');
            if (!Common::isList($x5c) || count($x5c) === 0) {
                return ['reason' => "JWKS key '$kid' carries no x5c chain"];
            }
            return ['x5c' => $x5c];
        }
        $hx = $header['x5c'] ?? null;
        if (Common::isList($hx) && count($hx) > 0) {
            return ['x5c' => $hx];
        }
        return ['reason' => 'no signing x5c available (no JWKS and no header x5c)'];
    }

    /** @param mixed $v list of strings @return list<string> */
    private static function lower(mixed $v): array
    {
        return array_map(static fn($x) => strtolower((string)$x), is_array($v) ? $v : []);
    }

    // ---- the verifier ---------------------------------------------------------------------------------------------------------

    /** @var array<string,mixed> */
    private array $policy;
    private mixed $anchors;
    private bool $hasSev;
    private bool $hasTdx;
    /** @var array<string,true> */
    private array $issuers = [];
    private float $skew;
    /** @var callable */
    private $resolve;

    public function __construct(mixed $config, callable $resolve)
    {
        $ti = Common::g($config, 'trustedIssuers');
        if (!Common::isList($ti) || count($ti) === 0) {
            throw new AttestConstructError('createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs');
        }
        foreach ($ti as $iss) {
            if (!is_string($iss) || $iss === '') {
                throw new AttestConstructError('createAzureMaaVerifier: every trusted issuer must be a non-empty URL string');
            }
        }
        $anchors = Common::g($config, 'trustAnchors');
        $a = Common::isObj($anchors) ? $anchors : new Obj();
        $certs = Common::g($a, 'rootCertsPem');
        $fps = Common::g($a, 'rootSpkiSha256');
        $count = (Common::isList($certs) ? count($certs) : 0) + (Common::isList($fps) ? count($fps) : 0);
        if ($count === 0) {
            throw new AttestConstructError('createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted');
        }
        $policyIn = Common::g($config, 'policy');
        $policy = Common::members($policyIn);
        $hasSev = Common::isList($policy['sevSnpMeasurements'] ?? null) && count($policy['sevSnpMeasurements']) > 0;
        $hasTdx = Common::isList($policy['tdxMrtds'] ?? null) && count($policy['tdxMrtds']) > 0;
        if (!Common::isObj($policyIn) || (!$hasSev && !$hasTdx)) {
            throw new AttestConstructError('createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)');
        }
        if (array_key_exists('sevSnpMinTcb', $policy)) {
            $m = $policy['sevSnpMinTcb'];
            if (!Common::isObj($m)) {
                throw new AttestConstructError('createAzureMaaVerifier: policy.sevSnpMinTcb must be an object');
            }
            foreach (Common::members($m) as $k => $v) {
                $known = false;
                foreach (self::SEV_TCB as [$name]) {
                    $known = $known || $name === (string)$k;
                }
                if (!$known) {
                    throw new AttestConstructError("createAzureMaaVerifier: policy.sevSnpMinTcb.$k is not a known field (bootloader | snp | microcode | tee)");
                }
                if (!(Common::isInt($v) && Common::numOf($v) >= 0)) {
                    throw new AttestConstructError("createAzureMaaVerifier: policy.sevSnpMinTcb.$k must be a non-negative integer");
                }
            }
        }
        $this->anchors = $a;
        $this->policy = $policy;
        $this->hasSev = $hasSev;
        $this->hasTdx = $hasTdx;
        foreach ($ti as $iss) {
            $this->issuers[$iss] = true;
        }
        $skew = Common::numOf(Common::g($config, 'clockSkewMs'));
        $this->skew = $skew !== null ? max(0.0, $skew) : 0.0;
        $this->resolve = $resolve;
    }

    public function verify(mixed $document, mixed $expected, mixed $nowMs): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        $policy = $this->policy;
        try {
            $evidence = ($this->resolve)($document);
            if (!is_array($evidence) || !is_string($evidence['token'] ?? null) || $evidence['token'] === '') {
                return $fail('no Azure MAA token for this action');
            }
            try {
                $parsed = Common::parseJws($evidence['token'], 'parseMaaJwt');
            } catch (\TypeError $e) {
                return $fail('MAA token parse failed: ' . $e->getMessage());
            }
            $alg = $parsed['header']['alg'];
            if ($alg !== 'ES256' && $alg !== 'RS256') {
                return $fail("unsupported JWS alg '$alg' (MAA uses ES256 / RS256)");
            }
            $signing = self::resolveSigningX5c($parsed['header'], $evidence['jwks'] ?? null);
            if (!isset($signing['x5c'])) {
                return $fail($signing['reason'] ?? 'no signing x5c available');
            }
            $now = (float)Common::numOf($nowMs);
            $chain = self::verifyX5cChain($signing['x5c'], $this->anchors, $now, $this->skew);
            if (!$chain['ok'] || !isset($chain['leaf'])) {
                return $fail('MAA signing chain invalid: ' . ($chain['reason'] ?? 'untrusted'));
            }
            $sigErr = self::verifyJwsSignature($parsed, $chain['leaf']);
            if ($sigErr !== null) {
                return $fail($sigErr);
            }

            $payload = $parsed['payload'];
            $iss = Common::asStr($payload->get('iss'));
            if ($iss === null || $iss === '' || !isset($this->issuers[$iss])) {
                return $fail("token iss '" . ($iss === null ? 'undefined' : $iss) . "' is not a configured trusted MAA instance");
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
                return $fail('MAA token expired');
            }
            if ($nbf !== null && $nowSec + $skewSec < $nbf) {
                return $fail('MAA token not yet valid (nbf)');
            }
            if ($iat !== null && $nowSec + $skewSec < $iat) {
                return $fail('MAA token issued in the future (iat)');
            }

            $isolation = $payload->get('x-ms-isolation-tee');
            $tee = $isolation instanceof Obj ? $isolation : $payload;
            $itype = Common::asStr($tee->get('x-ms-attestation-type')) ?? Common::asStr($payload->get('x-ms-attestation-type'));
            if ($itype !== 'sevsnpvm' && $itype !== 'tdxvm') {
                return $fail("unexpected x-ms-attestation-type '" . ($itype ?? 'undefined') . "' (expected sevsnpvm | tdxvm)");
            }

            if ($expected === null) {
                return $fail('no expected attestation binding supplied');
            }
            if (($policy['runtimeUserDataBinding'] ?? null) === true) {
                try {
                    $rawBinding = Common::attestationBinding($expected);
                } catch (\TypeError $e) {
                    return $fail('binding not constructible: ' . $e->getMessage());
                }
                $runtime = $payload->get('x-ms-runtime');
                if (!($runtime instanceof Obj)) {
                    return $fail('token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)');
                }
                $userData = Common::asStr($runtime->get('user-data'));
                if ($userData === null || $userData === '') {
                    return $fail('x-ms-runtime carries no user-data to bind the PCA challenge');
                }
                $ud = Common::decodeClaimBytes($userData);
                if ($ud === null || $ud !== $rawBinding) {
                    return $fail('runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)');
                }
            } else {
                try {
                    $bindingBytes = Common::transformBinding(Common::attestationBinding($expected), $policy['reportDataHash'] ?? null);
                } catch (\TypeError $e) {
                    return $fail('binding not constructible: ' . $e->getMessage());
                }
                $rdClaim = Common::firstString($tee, $itype === 'sevsnpvm' ? self::SEV_REPORTDATA : self::TDX_REPORTDATA);
                if ($rdClaim === null) {
                    return $fail('token carries no report-data claim to bind the PCA challenge');
                }
                $rd = Common::decodeClaimBytes($rdClaim);
                if ($rd === null) {
                    return $fail('report-data claim is not decodable (hex/base64)');
                }
                if ($rd !== $bindingBytes) {
                    return $fail('report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)');
                }
            }

            if ($itype === 'sevsnpvm') {
                if (!$this->hasSev) {
                    return $fail('sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)');
                }
                $measurement = Common::firstString($tee, ['x-ms-sevsnpvm-launchmeasurement']);
                if ($measurement === null) {
                    return $fail('sevsnpvm token carries no launch-measurement claim');
                }
                $mHex = strtolower($measurement);
                if (!in_array($mHex, self::lower($policy['sevSnpMeasurements']), true)) {
                    return $fail('SEV-SNP launch measurement not in policy allowlist');
                }
                if (($policy['allowDebug'] ?? null) !== true && $tee->get('x-ms-sevsnpvm-is-debuggable') === true) {
                    return $fail('SEV-SNP guest is debuggable (no confidentiality)');
                }
                $hostData = Common::firstString($tee, ['x-ms-sevsnpvm-hostdata']);
                $hdList = $policy['sevSnpHostData'] ?? null;
                if (Common::isList($hdList) && count($hdList) > 0 && ($hostData === null || !in_array(strtolower($hostData), self::lower($hdList), true))) {
                    return $fail('SEV-SNP host-data not in policy allowlist');
                }
                $tcbReported = [];
                $floors = $policy['sevSnpMinTcb'] ?? null;
                foreach (self::SEV_TCB as [$name, $claim, $hostKey]) {
                    $raw = $tee->get($claim);
                    $isSvn = Common::isInt($raw) && Common::numOf($raw) >= 0;
                    if ($isSvn) {
                        $tcbReported[$hostKey] = Common::numStr((float)Common::numOf($raw));
                    }
                    $floor = Common::isObj($floors) ? Common::g($floors, $name) : null;
                    if ($floor === null) {
                        continue;
                    }
                    if (!$isSvn) {
                        return $fail("SEV-SNP $name SVN claim '$claim' is missing or not a non-negative integer (policy requires a minimum)");
                    }
                    if (Common::numOf($raw) < Common::numOf($floor)) {
                        return $fail("SEV-SNP $name SVN " . Common::numStr((float)Common::numOf($raw)) . ' is below the policy minimum ' . Common::numStr((float)Common::numOf($floor)));
                    }
                }
                $host = ['attestation_type' => 'sevsnpvm'] + $tcbReported;
                if ($hostData !== null) {
                    $host['host_data'] = strtolower($hostData);
                }
                return ['ok' => true, 'bound' => true, 'measured' => ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false,
                    'runtime_measurement' => $mHex, 'operator' => ''], 'hostAsserted' => $host];
            }

            if (!$this->hasTdx) {
                return $fail('tdxvm token but policy configures no TDX MRTD allowlist (fail closed)');
            }
            $mrtd = Common::firstString($tee, self::TDX_MRTD);
            if ($mrtd === null) {
                return $fail('tdxvm token carries no MRTD claim');
            }
            $mrtdHex = strtolower($mrtd);
            if (!in_array($mrtdHex, self::lower($policy['tdxMrtds']), true)) {
                return $fail('TDX MRTD not in policy allowlist');
            }
            $tdDebug = $tee->get('tdx_td_attributes_debug');
            $dbgstat = Common::asStr($tee->get('dbgstat'));
            if (($policy['allowDebug'] ?? null) !== true && ($tdDebug === true || ($dbgstat !== null && $dbgstat !== 'disabled'))) {
                return $fail('TDX guest is debuggable (no confidentiality)');
            }
            $tcbStatus = Common::asStr($tee->get('attester_tcb_status'));
            if ($tcbStatus !== null) {
                $ok = $policy['tdxAllowedTcbStatuses'] ?? ['UpToDate', 'SWHardeningNeeded'];
                if (!in_array($tcbStatus, is_array($ok) ? $ok : [], true)) {
                    return $fail("TDX platform TCB status '$tcbStatus' is not accepted by policy");
                }
            }
            $rtmr0 = Common::firstString($tee, self::TDX_RTMR0);
            $rtList = $policy['tdxRtmrs'] ?? null;
            if (Common::isList($rtList) && count($rtList) > 0 && ($rtmr0 === null || !in_array(strtolower($rtmr0), self::lower($rtList), true))) {
                return $fail('TDX RTMR0 not in policy allowlist');
            }
            $host = ['attestation_type' => 'tdxvm'];
            if ($tcbStatus !== null && $tcbStatus !== '') {
                $host['tcb_status'] = $tcbStatus;
            }
            if ($rtmr0 !== null) {
                $host['rtmr0'] = strtolower($rtmr0);
            }
            return ['ok' => true, 'bound' => true, 'measured' => ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false,
                'runtime_measurement' => $mrtdHex, 'operator' => ''], 'hostAsserted' => $host];
        } catch (\Throwable $e) {
            return $fail('azure-maa verification error (fail closed): ' . $e->getMessage());
        }
    }
}
