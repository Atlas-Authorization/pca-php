<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Cert.php';
require_once __DIR__ . '/HardwareVerifier.php';
require_once __DIR__ . '/JsJson.php';

/**
 * AMD SEV-SNP attestation verifier (the native counterpart of `createAmdSnpVerifier`). Parses and verifies a genuine
 * SEV-SNP ATTESTATION_REPORT: the VCEK -> ASK -> ARK chain to a PINNED per-family ARK, the ECDSA-P384 / SHA-384 report
 * signature under the VCEK, the VCEK <-> report binding (CHIP_ID + reported-TCB SPLs), the PCA nonce binding (direct
 * `report-data`, or Azure `azure-runtime-data`), and the acceptance policy. Fails closed; the reason strings are those of the
 * reference implementation.
 */
final class Amd implements HardwareVerifier
{
    public const SUITE = 'amd-sev-snp-ecdsa-p384';
    public const ARK_SPKI_SHA384 = [
        'milan' => '1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e',
        'genoa' => '32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880',
        'turin' => '3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5',
    ];
    private const P384_N = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973';
    private const DEBUG_BIT = 1 << 19;
    private const VERSION = 0x000, GUEST_SVN = 0x004, POLICY = 0x008, VMPL = 0x030, SIGNATURE_ALGO = 0x034;
    private const CURRENT_TCB = 0x038, REPORT_DATA = 0x050, MEASUREMENT = 0x090, HOST_DATA = 0x0C0, REPORTED_TCB = 0x180;
    private const CHIP_ID = 0x1A0, COMMITTED_TCB = 0x1E0, LAUNCH_TCB = 0x1F0;
    private const SIGNED_END = 0x2A0, SIG_R = 0x2A0, SIG_S = 0x2E8, REPORT_LEN = 0x4A0;
    private const OID_HWID = '1.3.6.1.4.1.3704.1.4';
    private const OID_BL_SPL = '1.3.6.1.4.1.3704.1.3.1';
    private const OID_TEE_SPL = '1.3.6.1.4.1.3704.1.3.2';
    private const OID_SNP_SPL = '1.3.6.1.4.1.3704.1.3.3';
    private const OID_UCODE_SPL = '1.3.6.1.4.1.3704.1.3.8';
    private const HWID_LEN = 64;

    private static function u32(string $b, int $o): int
    {
        return (int)unpack('V', substr($b, $o, 4))[1];
    }

    private static function u64(string $b, int $o): \GMP
    {
        return gmp_init(bin2hex(strrev(substr($b, $o, 8))), 16);
    }

    /** Parse the report layout. Throws \ValueError when the buffer cannot hold the signed region and the r / s fields. @return array<string,mixed> */
    public static function parseReport(string $b): array
    {
        $min = self::SIG_S + 72;
        if (strlen($b) < $min) {
            throw new \ValueError('parseSevSnpReport: report too short (' . strlen($b) . " < $min)");
        }
        return [
            'version' => self::u32($b, self::VERSION), 'guest_svn' => self::u32($b, self::GUEST_SVN), 'policy' => self::u64($b, self::POLICY),
            'vmpl' => self::u32($b, self::VMPL), 'signature_algo' => self::u32($b, self::SIGNATURE_ALGO),
            'current_tcb' => self::u64($b, self::CURRENT_TCB), 'report_data' => substr($b, self::REPORT_DATA, 64),
            'measurement' => substr($b, self::MEASUREMENT, 48), 'host_data' => substr($b, self::HOST_DATA, 32),
            'reported_tcb' => self::u64($b, self::REPORTED_TCB), 'chip_id' => substr($b, self::CHIP_ID, 64),
            'committed_tcb' => self::u64($b, self::COMMITTED_TCB), 'launch_tcb' => self::u64($b, self::LAUNCH_TCB),
            'sig_r' => substr($b, self::SIG_R, 72), 'sig_s' => substr($b, self::SIG_S, 72), 'signed' => substr($b, 0, self::SIGNED_END),
        ];
    }

    private static function leInt(string $b): \GMP
    {
        return gmp_init(bin2hex(strrev($b)) ?: '0', 16);
    }

    /** ECDSA-P384 / SHA-384 over the signed region, AMD's little-endian r || s. Never throws. */
    public static function verifyReportSignature(array $report, PubKey $vcek): bool
    {
        try {
            $r = self::leInt($report['sig_r']);
            $s = self::leInt($report['sig_s']);
            $n = gmp_init(self::P384_N, 16);
            if (gmp_cmp($r, 0) <= 0 || gmp_cmp($r, $n) >= 0 || gmp_cmp($s, 0) <= 0 || gmp_cmp($s, $n) >= 0) {
                return false;
            }
            $be = static fn(\GMP $x): string => hex2bin(str_pad(gmp_strval($x, 16), 96, '0', STR_PAD_LEFT));
            return Common::ecdsaVerifyDer($vcek, Common::dssSignature($be($r), $be($s)), $report['signed'], 'sha384');
        } catch (\Throwable) {
            return false;
        }
    }

    /** One DER INTEGER, minimally encoded, 0..255: the number, or a failure string. */
    private static function decodeSpl(string $v): int|string
    {
        if (strlen($v) < 3 || ord($v[0]) !== 0x02) {
            return 'is not a DER INTEGER';
        }
        $ln = ord($v[1]);
        if ($ln < 1 || $ln > 2 || strlen($v) !== 2 + $ln) {
            return 'has a wrong-length INTEGER';
        }
        $c0 = ord($v[2]);
        if (($c0 & 0x80) !== 0) {
            return 'is negative';
        }
        if ($ln === 2) {
            if ($c0 !== 0x00) {
                return 'is out of range (> 255)';
            }
            if ((ord($v[3]) & 0x80) === 0) {
                return 'is a non-minimal INTEGER';
            }
            return ord($v[3]);
        }
        return $c0;
    }

    /** Bind the VCEK certificate body to the report: hwID == chip_id and the four SPL extensions == REPORTED_TCB bytes. */
    public static function checkVcekReportBinding(string $vcekTbs, array $report): ?string
    {
        try {
            $exts = Der::parseTbsExtensions($vcekTbs);
        } catch (DerError $e) {
            return 'VCEK extensions malformed: ' . $e->getMessage();
        }
        $hw = $exts[self::OID_HWID] ?? null;
        if ($hw === null) {
            return 'VCEK certificate has no CHIP_ID (hwID) extension';
        }
        if ($hw->critical) {
            return 'VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)';
        }
        if (strlen($hw->value) !== self::HWID_LEN) {
            return 'VCEK CHIP_ID (hwID) extension is ' . strlen($hw->value) . ' bytes, expected ' . self::HWID_LEN;
        }
        if ($hw->value !== $report['chip_id']) {
            return 'VCEK CHIP_ID does not match report chip_id';
        }
        $t = $report['reported_tcb'];
        $byteAt = static fn(int $i): int => (int)gmp_intval(gmp_and(gmp_div_q($t, gmp_pow(2, 8 * $i)), 255));
        foreach ([[self::OID_BL_SPL, 'bootloader', $byteAt(0)], [self::OID_TEE_SPL, 'tee', $byteAt(1)], [self::OID_SNP_SPL, 'snp', $byteAt(6)],
            [self::OID_UCODE_SPL, 'microcode', $byteAt(7)]] as [$oid, $name, $want]) {
            $ext = $exts[$oid] ?? null;
            if ($ext === null) {
                return "VCEK certificate has no $name SPL extension";
            }
            if ($ext->critical) {
                return "VCEK $name SPL extension is marked critical (the AMD profile is non-critical)";
            }
            $got = self::decodeSpl($ext->value);
            if (is_string($got)) {
                return "VCEK $name SPL extension $got";
            }
            if ($got !== $want) {
                return "VCEK $name SPL $got does not match report reported_tcb ($want) — TCB downgrade?";
            }
        }
        return null;
    }

    /** VCEK -> ASK -> ARK, the ARK pinned by its SPKI SHA-384 (never taken from the supplied chain). @return array<string,mixed> */
    public static function verifyCertChain(string $vcekDer, string $askArkPem, ?string $trustAnchor, mixed $nowMs, mixed $clockSkewMs = null): array
    {
        try {
            if (!Common::isNum($nowMs)) {
                return ['ok' => false, 'reason' => 'nowMs (verifier clock) is required for the AMD chain validity check'];
            }
            $now = (float)Common::numOf($nowMs);
            $skewIn = $clockSkewMs ?? 0;
            if (!Common::isNum($skewIn) || Common::numOf($skewIn) < 0) {
                return ['ok' => false, 'reason' => 'clockSkewMs must be a non-negative number'];
            }
            $skew = (float)Common::numOf($skewIn);
            $vcek = new Cert($vcekDer);
            $pems = Common::pemBlocks($askArkPem);
            if (count($pems) !== 2) {
                return ['ok' => false, 'reason' => 'ASK+ARK chain must contain exactly two certificates (ASK then ARK)'];
            }
            $ask = Cert::fromPem($pems[0]);
            $ark = Cert::fromPem($pems[1]);
            if ($ark->subject() !== $ark->issuer() || !$ark->verifySelf()) {
                return ['ok' => false, 'reason' => 'second certificate of the chain is not a self-signed ARK (chain out of order?)'];
            }
            if ($ask->subject() === $ask->issuer()) {
                return ['ok' => false, 'reason' => 'first certificate of the chain is self-signed, not an ASK (chain out of order?)'];
            }
            if ($ask->subject() !== $vcek->issuer()) {
                return ['ok' => false, 'reason' => 'ASK subject does not match the VCEK issuer'];
            }
            $pin = strtolower($trustAnchor ?? self::ARK_SPKI_SHA384['milan']);
            if (Common::spkiSha($ark->publicKey(), 'sha384') !== $pin) {
                return ['ok' => false, 'reason' => 'ARK does not match the pinned AMD trust anchor'];
            }
            if ($ask->issuer() !== $ark->subject() || !$ask->verify($ark->publicKey())) {
                return ['ok' => false, 'reason' => 'ASK is not signed by ARK'];
            }
            if (!$vcek->verify($ask->publicKey())) {
                return ['ok' => false, 'reason' => 'VCEK is not signed by ASK'];
            }
            $ders = [['VCEK', $vcekDer, $vcek], ['ASK', $ask->raw, $ask], ['ARK', $ark->raw, $ark]];
            $roleErr = Der::checkChainRoles(array_map(static fn($d) => $d[1], $ders));
            if ($roleErr !== null) {
                return ['ok' => false, 'reason' => "AMD chain role check failed: $roleErr"];
            }
            foreach ($ders as [$label, $der, $cert]) {
                $exts = Der::parseCertExtensions($der);
                foreach ($exts as $oid => $ext) {
                    if ($ext->critical && !in_array((string)$oid, Der::RECOGNISED_CRITICAL, true)) {
                        return ['ok' => false, 'reason' => "$label certificate has an unrecognised critical extension $oid"];
                    }
                }
                $bc = $exts['2.5.29.19'] ?? null;
                if ($label !== 'VCEK' && !($bc !== null && $bc->critical === true)) {
                    return ['ok' => false, 'reason' => "$label certificate BasicConstraints is not marked critical"];
                }
                [$lo, $hi] = Der::derValidityMs($cert->raw);
                if ($lo === null || $hi === null) {
                    return ['ok' => false, 'reason' => "$label certificate validity is unparseable"];
                }
                if ($now + $skew < $lo) {
                    return ['ok' => false, 'reason' => "$label certificate is not yet valid"];
                }
                if ($now - $skew > $hi) {
                    return ['ok' => false, 'reason' => "$label certificate has expired"];
                }
            }
            $pk = $vcek->publicKey();
            if ($pk->type !== 'ec' || Common::nodeCurve($pk) !== 'secp384r1') {
                throw new \TypeError('VCEK is not EC secp384r1 (got ' . $pk->type . '/' . (Common::nodeCurve($pk) ?? 'undefined') . ')');
            }
            $key = Common::ecKeyFromPoint('P-384', Common::ecPoint($pk, 'P-384'));
            return ['ok' => true, 'vcek' => $key, 'vcekTbs' => Der::tbsOfCertificate($vcekDer)];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'AMD chain verification error: ' . $e->getMessage()];
        }
    }

    /** @param list<string> $v */
    private static function lowerList(array $v): array
    {
        return array_map(static fn($x) => strtolower((string)$x), $v);
    }

    private static function fmtNum(mixed $v): string
    {
        $f = Common::numOf($v);
        return $f !== null ? Common::numStr($f) : Common::jsStr($v);
    }

    /** @param array<string,mixed> $policy */
    public static function checkPolicy(array $report, array $policy): ?string
    {
        if (($policy['requireEcdsaP384'] ?? null) !== false && $report['signature_algo'] !== 1) {
            return 'unexpected signature_algo ' . $report['signature_algo'];
        }
        if (($policy['allowDebug'] ?? null) !== true && gmp_cmp(gmp_and($report['policy'], self::DEBUG_BIT), 0) !== 0) {
            return 'guest policy has the DEBUG bit set (host can inspect the guest)';
        }
        $mg = $policy['minGuestSvn'] ?? null;
        if (Common::isNum($mg) && $report['guest_svn'] < Common::numOf($mg)) {
            return 'guest_svn ' . $report['guest_svn'] . ' below minimum ' . self::fmtNum($mg);
        }
        if (($policy['minReportedTcb'] ?? null) instanceof \GMP && gmp_cmp($report['reported_tcb'], $policy['minReportedTcb']) < 0) {
            return 'reported_tcb below minimum (rollback?)';
        }
        if (($policy['minCommittedTcb'] ?? null) instanceof \GMP && gmp_cmp($report['committed_tcb'], $policy['minCommittedTcb']) < 0) {
            return 'committed_tcb below minimum (rollback?)';
        }
        if (($policy['minLaunchTcb'] ?? null) instanceof \GMP && gmp_cmp($report['launch_tcb'], $policy['minLaunchTcb']) < 0) {
            return 'launch_tcb below minimum';
        }
        $want = $policy['requireVmpl'] ?? null;
        $want ??= 0;
        if ($want !== 'any' && !(Common::isNum($want) && (float)$report['vmpl'] === Common::numOf($want))) {
            return 'vmpl ' . $report['vmpl'] . ' is not the required ' . self::fmtNum($want);
        }
        $meas = $policy['measurements'] ?? null;
        if (is_array($meas) && count($meas) > 0 && !in_array(bin2hex($report['measurement']), self::lowerList($meas), true)) {
            return 'measurement not in policy allowlist';
        }
        $hd = $policy['hostData'] ?? null;
        if (is_array($hd) && count($hd) > 0 && !in_array(bin2hex($report['host_data']), self::lowerList($hd), true)) {
            return 'host_data not in policy allowlist';
        }
        $ci = $policy['chipIds'] ?? null;
        if (is_array($ci) && count($ci) > 0 && !in_array(bin2hex($report['chip_id']), self::lowerList($ci), true)) {
            return 'chip_id not in policy allowlist';
        }
        return null;
    }

    /** @return array<string,mixed> */
    public static function defaultIdentity(array $report): array
    {
        return ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => bin2hex($report['measurement']),
            'operator' => bin2hex($report['chip_id'])];
    }

    /** Parse and verify a genuine report end to end, offline. Fails closed with a reason. @return array<string,mixed> */
    public static function verifyGenuineReport(string $report, string $vcekDer, string $askArkPem, ?string $trustAnchor, mixed $nowMs,
                                               mixed $clockSkewMs = null, mixed $expected = null, ?array $policy = null): array
    {
        try {
            try {
                $rep = self::parseReport($report);
            } catch (\ValueError $e) {
                return ['ok' => false, 'reason' => 'report parse failed: ' . $e->getMessage()];
            }
            if (strlen($report) !== self::REPORT_LEN) {
                return ['ok' => false, 'reason' => 'report length ' . strlen($report) . ' is not the canonical ' . self::REPORT_LEN];
            }
            if (trim(substr($report, self::SIG_S + 72), "\0") !== '' || trim(substr($report, self::SIG_R + 48, 24), "\0") !== ''
                || trim(substr($report, self::SIG_S + 48, 24), "\0") !== '') {
                return ['ok' => false, 'reason' => 'report signature block has non-zero reserved bytes'];
            }
            $chain = self::verifyCertChain($vcekDer, $askArkPem, $trustAnchor, $nowMs, $clockSkewMs);
            if (!$chain['ok'] || !isset($chain['vcek'], $chain['vcekTbs'])) {
                return ['ok' => false, 'reason' => 'cert chain invalid: ' . ($chain['reason'] ?? 'undefined')];
            }
            if (!self::verifyReportSignature($rep, $chain['vcek'])) {
                return ['ok' => false, 'reason' => 'report signature does not verify under VCEK'];
            }
            $bindErr = self::checkVcekReportBinding($chain['vcekTbs'], $rep);
            if ($bindErr !== null) {
                return ['ok' => false, 'reason' => $bindErr];
            }
            if ($expected !== null && Common::attestationBinding($expected) !== $rep['report_data']) {
                return ['ok' => false, 'reason' => 'report_data does not bind holder/grant/epoch/nonce'];
            }
            if ($policy !== null) {
                $polErr = self::checkPolicy($rep, $policy);
                if ($polErr !== null) {
                    return ['ok' => false, 'reason' => $polErr];
                }
            }
            return ['ok' => true, 'report' => $rep, 'measured' => self::defaultIdentity($rep)];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'genuine verification error (fail closed): ' . $e->getMessage()];
        }
    }

    /** The Azure binding: report_data[0:32] = sha256(runtime-data JSON), [32:64] = 0, and its 64-byte `user-data` = the PCA binding. */
    public static function checkAzureRuntimeDataBinding(string $reportData, string $runtimeData, mixed $expected): ?string
    {
        if (strlen($reportData) !== 64) {
            return 'report_data is not 64 bytes';
        }
        if (trim(substr($reportData, 32), "\0") !== '') {
            return 'report_data[32:64] is not zero (not an Azure runtime-data hash)';
        }
        if (hash('sha256', $runtimeData, true) !== substr($reportData, 0, 32)) {
            return 'sha256(runtime data) does not equal the quote report_data';
        }
        try {
            $parsed = JsJson::parse($runtimeData);
        } catch (JsError) {
            return 'runtime data is not valid JSON';
        }
        if (!($parsed instanceof \Atlas\Pca\Obj)) {
            return 'runtime data is not a JSON object';
        }
        $ud = $parsed->get('user-data');
        if (!is_string($ud) || strlen($ud) !== 128 || !Common::isHex($ud)) {
            return 'runtime data carries no 64-byte hex user-data';
        }
        try {
            $want = Common::attestationBinding($expected);
        } catch (\TypeError $e) {
            return 'binding not constructible: ' . $e->getMessage();
        }
        if (hex2bin($ud) !== $want) {
            return 'runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)';
        }
        return null;
    }

    // ---- the verifier -----------------------------------------------------------------------------------------------------

    private string $pin;
    private string $family;
    private string $binding;
    /** @var array<string,mixed> */
    private array $policy = [];
    private mixed $skew;
    /** @var callable(mixed): mixed */
    private $resolve;

    /** @param callable(mixed): mixed $resolve maps the passport / PCActn document to the vendor evidence (see Factory::evidenceFor) */
    public function __construct(mixed $config, callable $resolve)
    {
        $pol = Common::g($config, 'policy');
        $policy = Common::members($pol);
        foreach (['minReportedTcb', 'minCommittedTcb', 'minLaunchTcb'] as $k) {
            if (array_key_exists($k, $policy)) {
                $policy[$k] = Common::bigInt($policy[$k]);
            }
        }
        $family = Common::g($config, 'family');
        $pin = is_string($family) ? (self::ARK_SPKI_SHA384[$family] ?? null) : null;
        $override = Common::g($config, 'trustAnchorArkSpkiSha384');
        if ($override !== null && is_string($family) && isset(self::ARK_SPKI_SHA384[$family])) {
            $pin = $override; // conformance harness only: the synthetic chains are rooted in a test ARK
        }
        if ($pin === null || $pin === '') {
            throw new AttestConstructError("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'");
        }
        $this->pin = (string)$pin;
        $this->family = (string)$family;
        $binding = Common::g($config, 'binding');
        if ($binding !== 'report-data' && $binding !== 'azure-runtime-data') {
            throw new AttestConstructError("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'");
        }
        $this->binding = $binding;
        $meas = $policy['measurements'] ?? null;
        if (!Common::isList($meas) || count($meas) === 0) {
            throw new AttestConstructError('createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
        }
        $this->policy = $policy;
        $this->skew = Common::g($config, 'clockSkewMs');
        $this->resolve = $resolve;
    }

    public function verify(mixed $document, mixed $expected, mixed $nowMs): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            $ev = ($this->resolve)($document);
            if (!is_array($ev) || !is_string($ev['report'] ?? null) || !is_string($ev['vcekDer'] ?? null) || !is_string($ev['askArkPem'] ?? null)) {
                return $fail('no AMD SEV-SNP evidence for this action');
            }
            if ($expected === null) {
                return $fail('no expected attestation binding supplied');
            }
            $direct = $this->binding === 'report-data';
            $r = self::verifyGenuineReport($ev['report'], $ev['vcekDer'], $ev['askArkPem'], $this->pin, $nowMs, $this->skew,
                $direct ? $expected : null, $this->policy);
            if (!$r['ok'] || !isset($r['report'], $r['measured'])) {
                return $fail('SEV-SNP report invalid: ' . ($r['reason'] ?? 'unknown'));
            }
            if (!$direct) {
                $rd = $ev['runtimeData'] ?? null;
                if (!is_string($rd)) {
                    return $fail('azure-runtime-data binding needs the runtime-data JSON bytes');
                }
                $why = self::checkAzureRuntimeDataBinding($r['report']['report_data'], $rd, $expected);
                if ($why !== null) {
                    return $fail($why);
                }
            }
            return ['ok' => true, 'bound' => true, 'measured' => $r['measured'],
                'hostAsserted' => ['attestation_type' => 'amd-sev-snp', 'family' => $this->family, 'measurement' => bin2hex($r['report']['measurement'])]];
        } catch (\Throwable $e) {
            return $fail('amd-snp verification error (fail closed): ' . $e->getMessage());
        }
    }
}
