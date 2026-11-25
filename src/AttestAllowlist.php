<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';

/**
 * Signed, versioned, expiring measurement-allowlist manifests for the hardware-attestation verifiers: verify (issuer keys registered by the
 * verifier, the algorithm registered FOR the issuer so there is no downgrade, a hybrid needs both signatures, a validity window with optional
 * skew, a version floor and a rollback high-water mark), durable verify (the high-water mark in an {@see AtomicKv}), operator tools (create,
 * sign, revoke) and the projection into the exact policy shapes of the hardware verifiers. Values are the parsed-JSON model; every refusal of
 * verify is a typed `{ok: false, code, reason}`, never an exception.
 */
final class AttestAllowlist
{
    public const KINDS = ['tdx-mrtd', 'tdx-rtmr', 'sev-snp-measurement', 'gcp-image-digest', 'nvidia-measurement', 'nvidia-driver-version',
        'maa-signing-spki', 'maa-chain-root-spki', 'maa-chain-intermediate-spki', 'attest-corroboration'];
    public const DOMAIN = "pca-attest-allowlist/v1\n";
    private const BODY_KEYS = ['version', 'issuedAt', 'notBefore', 'expiresAt', 'entries'];
    private const ENTRY_KEYS = ['kind', 'value', 'label', 'notAfter', 'revoked'];
    private const MANIFEST_KEYS = ['body', 'issuer', 'alg', 'sig', 'pq_sig'];
    private const MAX_ENTRIES = 10000;
    private const FAMILY_KEY = ['ML-DSA-65' => 'mlDsaPub', 'SLH-DSA-SHA2-128f' => 'slhDsaPub', 'ML-DSA-87' => 'mlDsa87Pub', 'SLH-DSA-SHA2-256s' => 'slhDsa256sPub',
        'FN-DSA-512' => 'fnDsa512Pub', 'FN-DSA-1024' => 'fnDsa1024Pub'];

    private static function isRecord(mixed $x): bool
    {
        return $x instanceof Obj;
    }

    /** @param list<string> $allowed */
    private static function onlyKeys(Obj $r, array $allowed): bool
    {
        foreach ($r->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                return false;
            }
        }
        return true;
    }

    private static function isSafeInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0;
    }

    private static function isEpoch(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && self::isSafeInt($x) && $f >= 0 && !($f === 0.0 && fdiv(1.0, $f) < 0);
    }

    private static function valueError(string $kind, string $value, string $label): ?string
    {
        $hex = static fn(int $n): bool => preg_match('/\A[0-9a-f]{' . $n . '}\z/', $value) === 1;
        switch ($kind) {
            case 'tdx-mrtd':
            case 'tdx-rtmr':
            case 'sev-snp-measurement':
            case 'nvidia-measurement':
                return $hex(96) ? null : "$kind must be 96 lowercase hex chars";
            case 'gcp-image-digest':
                return preg_match('/\Asha256:[0-9a-f]{64}\z/', $value) === 1 ? null : 'gcp-image-digest must be sha256:<64 lowercase hex>';
            case 'nvidia-driver-version':
                return preg_match('/\A[0-9]{1,6}(\.[0-9]{1,6}){1,3}\z/', $value) === 1 && strlen($value) <= 16 ? null : 'nvidia-driver-version must be a dotted version of at most 16 chars';
            case 'maa-signing-spki':
                if (!$hex(64)) {
                    return 'maa-signing-spki must be 64 lowercase hex chars';
                }
                return preg_match('/\Ahttps:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?\z/', $label) === 1 ? null : 'maa-signing-spki label must be the https issuer URL (no path, no trailing slash)';
            case 'maa-chain-root-spki':
            case 'maa-chain-intermediate-spki':
                return $hex(64) ? null : "$kind must be 64 lowercase hex chars";
            default: // attest-corroboration
                if (!$hex(64)) {
                    return 'attest-corroboration must be a 64 lowercase hex evidence digest';
                }
                return preg_match('/\Avantages=[1-9][0-9]{0,2};method=[\x20-\x7e]{1,150}\z/', $label) === 1 ? null : 'attest-corroboration label must be vantages=<n>;method=<text>';
        }
    }

    /** Strictly validate and copy an untrusted body; numbers become native ints. Throws a TypeError describing the first violation. */
    private static function parseBody(mixed $x): Obj
    {
        if (!self::isRecord($x) || !self::onlyKeys($x, self::BODY_KEYS)) {
            throw new \TypeError('body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries');
        }
        $version = Jsx::get($x, 'version');
        $issuedAt = Jsx::get($x, 'issuedAt');
        $notBefore = Jsx::get($x, 'notBefore');
        $expiresAt = Jsx::get($x, 'expiresAt');
        $entries = Jsx::get($x, 'entries');
        if (!Js::isNum($version) || !self::isSafeInt($version) || Js::num($version) < 1) {
            throw new \TypeError('version must be a positive integer');
        }
        if (!self::isEpoch($issuedAt) || !self::isEpoch($notBefore) || !self::isEpoch($expiresAt)) {
            throw new \TypeError('issuedAt/notBefore/expiresAt must be integer epoch ms');
        }
        if (!(Js::num($notBefore) < Js::num($expiresAt))) {
            throw new \TypeError('notBefore must be before expiresAt');
        }
        if (!(Js::num($issuedAt) <= Js::num($expiresAt))) {
            throw new \TypeError('issuedAt must not be after expiresAt');
        }
        if (!is_array($entries) || !array_is_list($entries) || count($entries) > self::MAX_ENTRIES) {
            throw new \TypeError('entries must be an array (bounded)');
        }
        $seen = [];
        $out = [];
        foreach ($entries as $i => $e) {
            if (!self::isRecord($e) || !self::onlyKeys($e, self::ENTRY_KEYS)) {
                throw new \TypeError("entry $i: unexpected shape");
            }
            $kind = Jsx::get($e, 'kind');
            $value = Jsx::get($e, 'value');
            $label = Jsx::get($e, 'label');
            $notAfter = Jsx::get($e, 'notAfter');
            $revoked = Jsx::get($e, 'revoked');
            if (!is_string($kind) || !in_array($kind, self::KINDS, true)) {
                throw new \TypeError("entry $i: unknown kind");
            }
            if (!is_string($value) || !is_string($label)) {
                throw new \TypeError("entry $i: value and label must be strings");
            }
            $ll = Js::len($label);
            if ($ll < 1 || $ll > 200 || preg_match('/[\x00-\x1f\x7f]/', $label) === 1) {
                throw new \TypeError("entry $i: label must be 1..200 printable chars");
            }
            $ve = self::valueError($kind, $value, $label);
            if ($ve !== null) {
                throw new \TypeError("entry $i: $ve");
            }
            if (!($notAfter instanceof Undef) && !self::isEpoch($notAfter)) {
                throw new \TypeError("entry $i: notAfter must be integer epoch ms");
            }
            if (!($revoked instanceof Undef) && $revoked !== true) {
                throw new \TypeError("entry $i: revoked, when present, must be true");
            }
            $dup = $kind . "\0" . ($kind === 'maa-signing-spki' ? $label . "\0" : '') . $value;
            if (isset($seen[$dup])) {
                throw new \TypeError("entry $i: duplicate $kind value");
            }
            $seen[$dup] = true;
            $o = Obj::of(['kind' => $kind, 'value' => $value, 'label' => $label]);
            if (!($notAfter instanceof Undef)) {
                $o->set('notAfter', (int)Js::num($notAfter));
            }
            if ($revoked === true) {
                $o->set('revoked', true);
            }
            $out[] = $o;
        }
        return Obj::of(['version' => (int)Js::num($version), 'issuedAt' => (int)Js::num($issuedAt), 'notBefore' => (int)Js::num($notBefore),
            'expiresAt' => (int)Js::num($expiresAt), 'entries' => $out]);
    }

    private static function signedBytes(Obj $body): string
    {
        return self::DOMAIN . Json::canonicalizeNative($body);
    }

    /** @return array{ok:false,code:string,reason:string} */
    private static function fail(string $code, string $reason): array
    {
        return ['ok' => false, 'code' => $code, 'reason' => $reason];
    }

    /** The verifier-registered key material of an issuer for `$alg`: the Ed25519 key and the PQ key of the suite's family, minted pinned. */
    private static function registeredKeys(array $suite, mixed $k): array
    {
        $out = [];
        $ed = Jsx::rd($k, 'edPub');
        if (!($ed instanceof Undef)) {
            $out['edPub'] = $ed;
        }
        $slot = self::FAMILY_KEY[$suite['family'] ?? ''] ?? 'lessCat1Pub';
        $pk = Jsx::rd($k, $slot);
        if ($suite['needsPqPk'] && !($pk instanceof Undef)) {
            $pq = Pca::resolvePqVerifyKey('', null, ['trustedPk' => is_string($pk) ? $pk : null]);
            if ($pq !== null) {
                $out['pq'] = $pq;
            }
        }
        return $out;
    }

    /**
     * Verify a signed manifest. `$opts`: `{issuerKeys: {<id>: {alg, keys: {edPub?, mlDsaPub?, slhDsaPub?, mlDsa87Pub?, slhDsa256sPub?, ...}, notAfter?}},
     * nowMs, minVersion?, lastSeenVersion?, lastSeenDigest?, clockSkewMs?, maxLifetimeMs?}`. Never throws.
     * @return array<string,mixed> `{ok: true, body, issuer, alg, version, digest}` or `{ok: false, code, reason}`
     */
    public static function verify(mixed $manifest, mixed $opts): array
    {
        try {
            if (!self::isRecord($manifest) || !self::onlyKeys($manifest, self::MANIFEST_KEYS)) {
                return self::fail('malformed', 'manifest has an unexpected shape');
            }
            $nowMs = Jsx::get($opts, 'nowMs');
            if (!self::isSafeInt($nowMs)) {
                return self::fail('malformed', 'nowMs must be an integer');
            }
            $now = Js::num($nowMs);
            $issuer = Jsx::get($manifest, 'issuer');
            $alg = Jsx::get($manifest, 'alg');
            $sig = Jsx::get($manifest, 'sig');
            $pqSig = Jsx::get($manifest, 'pq_sig');
            if (!is_string($issuer) || $issuer === '' || Js::len($issuer) > 200) {
                return self::fail('malformed', 'issuer must be a string');
            }
            if (!is_string($alg) || !Pq::isKnownSigAlg($alg)) {
                return self::fail('malformed', 'unknown signature alg');
            }
            if (!is_string($sig)) {
                return self::fail('malformed', 'sig must be a string');
            }
            if (!($pqSig instanceof Undef) && !is_string($pqSig)) {
                return self::fail('malformed', 'pq_sig must be a string');
            }
            $suite = Pq::resolveSigAlg($alg);
            if ($suite['needsPqSig'] === ($pqSig instanceof Undef)) {
                return self::fail('malformed', 'pq_sig presence does not match the suite');
            }
            try {
                $body = self::parseBody(Jsx::get($manifest, 'body'));
            } catch (\Throwable $e) {
                return self::fail('malformed', $e->getMessage() === '' ? 'invalid body' : $e->getMessage());
            }
            $issuerKeys = Jsx::get($opts, 'issuerKeys');
            if ($issuerKeys === null || $issuerKeys instanceof Undef) {
                throw new \TypeError('cannot convert undefined or null to object');
            }
            if (!($issuerKeys instanceof Obj) || !$issuerKeys->has($issuer)) {
                return self::fail('unknown-issuer', "issuer '$issuer' is not registered");
            }
            $reg = $issuerKeys->get($issuer);
            $regAlg = Jsx::rd($reg, 'alg');
            if ($regAlg !== $alg) {
                return self::fail('alg-mismatch', "issuer is registered for '" . Jsx::str($regAlg) . "', manifest claims '$alg'");
            }
            $regNotAfter = Jsx::get($reg, 'notAfter');
            if (!($regNotAfter instanceof Undef) && Jsx::gt($nowMs, $regNotAfter)) {
                return self::fail('issuer-expired', 'issuer key is past its notAfter');
            }
            $keys = self::registeredKeys($suite, Jsx::get($reg, 'keys'));
            $parts = ['sig' => $sig];
            if (!($pqSig instanceof Undef)) {
                $parts['pq_sig'] = $pqSig;
            }
            if (!Pca::verifyWithSuite($alg, $keys, self::signedBytes($body), $parts)) {
                return self::fail('bad-signature', 'signature does not verify under the registered issuer key');
            }
            $skewV = Jsx::get($opts, 'clockSkewMs');
            if (!($skewV instanceof Undef) && !(Js::isNum($skewV) && is_finite(Js::num($skewV)))) {
                return self::fail('malformed', 'clockSkewMs must be a finite number');
            }
            $lifeV = Jsx::get($opts, 'maxLifetimeMs');
            if (!($lifeV instanceof Undef) && !(Js::isNum($lifeV) && is_finite(Js::num($lifeV)))) {
                return self::fail('malformed', 'maxLifetimeMs must be a finite number');
            }
            $minV = Jsx::get($opts, 'minVersion');
            if (!($minV instanceof Undef) && !(Js::isNum($minV) && self::isSafeInt($minV))) {
                return self::fail('malformed', 'minVersion must be an integer');
            }
            $lastV = Jsx::get($opts, 'lastSeenVersion');
            if (!($lastV instanceof Undef) && !(Js::isNum($lastV) && self::isSafeInt($lastV))) {
                return self::fail('malformed', 'lastSeenVersion must be an integer');
            }
            $skew = max(0.0, $skewV instanceof Undef ? 0.0 : Js::num($skewV));
            $notBefore = Js::num($body->get('notBefore')) ?? (float)$body->get('notBefore'); // a parsed number is a Num
            $expiresAt = Js::num($body->get('expiresAt')) ?? (float)$body->get('expiresAt');
            $version = $body->get('version');
            if ($now + $skew < $notBefore) {
                return self::fail('not-yet-valid', 'manifest is not yet valid');
            }
            if ($now - $skew > $expiresAt) {
                return self::fail('expired', 'manifest has expired');
            }
            if (!($lifeV instanceof Undef) && $expiresAt - $notBefore > Js::num($lifeV)) {
                return self::fail('lifetime-too-long', 'manifest lifetime exceeds maxLifetimeMs');
            }
            if (!($minV instanceof Undef) && $version < Js::num($minV)) {
                return self::fail('below-min-version', "version $version < minVersion " . Jsx::str($minV));
            }
            $digest = Pca::hashCanonical(Sign::n($body));
            if (!($lastV instanceof Undef)) {
                if ($version < Js::num($lastV)) {
                    return self::fail('rollback', "version $version is older than last seen " . Jsx::str($lastV));
                }
                $lastD = Jsx::get($opts, 'lastSeenDigest');
                if ($version == Js::num($lastV) && !($lastD instanceof Undef) && $lastD !== $digest) {
                    return self::fail('conflict', 'same version as last seen but a different body');
                }
            }
            return ['ok' => true, 'body' => $body, 'issuer' => $issuer, 'alg' => $alg, 'version' => $version, 'digest' => $digest];
        } catch (\Throwable $e) {
            return self::fail('malformed', $e->getMessage() === '' ? 'verification error' : $e->getMessage());
        }
    }

    /** `{version, digest}` of a persisted high-water mark, or null when it is not a well-formed one. */
    private static function parseHighWater(mixed $x): ?array
    {
        if (!($x instanceof Obj)) {
            return null;
        }
        $v = $x->get('version');
        $d = $x->get('digest');
        $f = Js::num($v);
        if (!Js::isNum($v) || !self::isSafeInt($v) || ($f === 0.0 && fdiv(1.0, $f) < 0) || !is_string($d) || preg_match('/\A[A-Za-z0-9_-]{43}\z/', $d) !== 1) {
            return null;
        }
        return ['version' => (int)$f, 'digest' => $d];
    }

    /**
     * {@see verify} with the rollback high-water mark `allowlist/<issuer>` kept in `$kv` as a JSON `{version, digest}`: a corrupt record is
     * `malformed`, a lower version is a `rollback`, the same version with another digest a `conflict`, and an accepted manifest atomically
     * advances the mark (append-only: a record already at or above its version is kept).
     * @return array<string,mixed>
     */
    public static function verifyDurable(mixed $manifest, mixed $opts, AtomicKv $kv): array
    {
        try {
            $issuer = Jsx::get($manifest, 'issuer');
            if (!self::isRecord($manifest) || !is_string($issuer) || Js::len($issuer) > 200) {
                return self::fail('malformed', 'issuer must be a string');
            }
            $key = "allowlist/$issuer";
            $raw = $kv->get($key);
            $prior = $raw === null ? null : self::parseHighWater(Json::parseLax($raw));
            if ($raw !== null && $prior === null) {
                return self::fail('malformed', 'persisted allowlist high-water mark is corrupt');
            }
            $o = Jsx::spread($opts);
            if ($prior !== null) {
                $o->set('lastSeenVersion', $prior['version']);
                $o->set('lastSeenDigest', $prior['digest']);
            }
            $v = self::verify($manifest, $o);
            if ($v['ok'] !== true) {
                return $v;
            }
            $now = null; // the record seen at update time: ['missing'] | ['corrupt'] | ['val', version, digest]
            $kv->update($key, static function (?string $cur) use (&$now, $v): ?string {
                $c = $cur === null ? null : self::parseHighWater(Json::parseLax($cur));
                $now = $cur === null ? ['missing'] : ($c === null ? ['corrupt'] : ['val', $c['version'], $c['digest']]);
                if ($now[0] === 'corrupt' || ($now[0] === 'val' && $now[1] >= $v['version'])) {
                    return null;
                }
                return Json::canonicalizeNative(Obj::of(['version' => $v['version'], 'digest' => $v['digest']]));
            });
            if ($now === null) {
                $s = ($t = $kv->get($key)) === null ? null : self::parseHighWater(Json::parseLax($t));
                if ($s === null) {
                    return self::fail('rollback', 'a newer manifest was accepted concurrently');
                }
                $now = ['val', $s['version'], $s['digest']];
            }
            // the decision of the durable step over what is stored now (after our own update)
            $after = $now[0] === 'corrupt' ? $now : ($now[0] === 'val' && $now[1] >= $v['version'] ? $now : ['val', $v['version'], $v['digest']]);
            if ($after[0] !== 'val' || $after[1] > $v['version']) {
                return self::fail('rollback', 'a newer manifest was accepted concurrently');
            }
            if ($after[1] === $v['version'] && $after[2] !== $v['digest']) {
                return self::fail('conflict', 'same version as the stored high-water mark but a different body');
            }
            return $v;
        } catch (\Throwable $e) {
            return self::fail('malformed', $e->getMessage() === '' ? 'durable verification error' : $e->getMessage());
        }
    }

    /** Validate operator input and return a canonical body. Throws on any violation. */
    public static function create(mixed $input): Obj
    {
        return self::parseBody($input);
    }

    /**
     * Sign a body under `$alg` with the issuer's key material. Throws on an invalid body, an unknown alg or missing key material.
     * @return Obj `{body, issuer, alg, sig, pq_sig?}`
     */
    public static function sign(mixed $body, string $issuer, mixed $alg, ?KeyPair $ed, ?PqKeyPair $pq): Obj
    {
        $clean = self::parseBody($body);
        $parts = Pq::signWithSuite($alg, $ed, $pq, self::signedBytes($clean));
        $out = Obj::of(['body' => $clean, 'issuer' => $issuer, 'alg' => $alg, 'sig' => $parts['sig']]);
        if (isset($parts['pq_sig'])) {
            $out->set('pq_sig', $parts['pq_sig']);
        }
        return $out;
    }

    /**
     * The next body that revokes `rev` (`{kind, value, label?}`): flips an existing entry to a tombstone or adds one, with version + 1 and the
     * given times. The result must be re-signed. Throws when the result is not a valid body.
     */
    public static function revokeEntry(mixed $prev, mixed $rev, mixed $times): Obj
    {
        $kind = Jsx::get($rev, 'kind');
        $value = Jsx::get($rev, 'value');
        $label = Jsx::get($rev, 'label');
        $entries = [];
        $hit = null;
        $es = Jsx::rd($prev, 'entries');
        if (!is_array($es) || !array_is_list($es)) {
            throw new \TypeError('prev.entries.map is not a function');
        }
        foreach ($es as $e) {
            $c = Jsx::spread($e);
            $entries[] = $c;
            if ($hit === null && Jsx::get($c, 'kind') === $kind && Jsx::get($c, 'value') === $value && ($kind !== 'maa-signing-spki' || Jsx::get($c, 'label') === $label)) {
                $hit = $c;
            }
        }
        if ($hit !== null) {
            $hit->set('revoked', true);
        } else {
            $entries[] = Obj::of(['kind' => $kind, 'value' => $value, 'label' => $label instanceof Undef || $label === null ? 'revoked' : $label, 'revoked' => true]);
        }
        $pv = Jsx::get($prev, 'version');
        $b = Obj::of(['version' => Js::isNum($pv) ? Js::num($pv) + 1 : Jsx::str($pv) . '1']);
        foreach (Jsx::spread($times)->keys() as $k) {
            $b->set($k, Jsx::get($times, $k));
        }
        $b->set('entries', $entries);
        return self::parseBody($b);
    }

    /** Zero-padded 16-byte-slot hex of a dotted driver version (`NvidiaCcPolicy.driverVersions`). */
    public static function driverVersionSlotHex(mixed $version): string
    {
        if (!is_string($version) || preg_match('/\A[0-9]{1,6}(\.[0-9]{1,6}){1,3}\z/', $version) !== 1 || strlen($version) > 16) {
            throw new \TypeError('invalid driver version');
        }
        return str_pad(bin2hex($version), 32, '0');
    }

    /**
     * Project a VERIFIED manifest (an `ok` result of {@see verify}) into policy arrays at `nowMs`: revoked entries and entries past their own
     * `notAfter` are excluded, a value revoked under any label is excluded everywhere in its kind.
     * @param mixed $verified `{body, ...}` @param mixed $opts `{nowMs}`
     * @return array<string,mixed>
     */
    public static function project(mixed $verified, mixed $opts): array
    {
        $body = Jsx::rd($verified, 'body');
        $out = ['tdxMrtds' => [], 'tdxRtmrs' => [], 'sevSnpMeasurements' => [], 'imageDigests' => [], 'nvidiaMeasurements' => [],
            'nvidiaDriverVersions' => [], 'nvidiaCcDriverVersions' => [], 'maaSigningSpkis' => new Obj(), 'maaChainRootSpkis' => [],
            'maaChainIntermediateSpkis' => [], 'corroboration' => [], 'revoked' => [], 'expired' => [],
            'version' => Jsx::rd($body, 'version'), 'manifestExpiresAt' => Jsx::rd($body, 'expiresAt')];
        $now = Js::num(Jsx::get($opts, 'nowMs'));
        $entries = Jsx::rd($body, 'entries');
        if (!is_array($entries)) {
            throw new \TypeError('entries is not iterable');
        }
        $denied = [];
        foreach ($entries as $e) {
            if (Jsx::get($e, 'revoked') === true) {
                $denied[Jsx::str(Jsx::rd($e, 'kind')) . "\0" . Jsx::str(Jsx::get($e, 'value'))] = true;
                $out['revoked'][] = Obj::of(['kind' => Jsx::get($e, 'kind'), 'value' => Jsx::get($e, 'value'), 'label' => Jsx::get($e, 'label')]);
            }
        }
        $map = ['tdx-mrtd' => 'tdxMrtds', 'tdx-rtmr' => 'tdxRtmrs', 'sev-snp-measurement' => 'sevSnpMeasurements', 'gcp-image-digest' => 'imageDigests',
            'nvidia-measurement' => 'nvidiaMeasurements', 'maa-chain-root-spki' => 'maaChainRootSpkis', 'maa-chain-intermediate-spki' => 'maaChainIntermediateSpkis'];
        foreach ($entries as $e) {
            if (Jsx::get($e, 'revoked') === true) {
                continue;
            }
            $kind = Jsx::get($e, 'kind');
            $value = Jsx::get($e, 'value');
            if (isset($denied[Jsx::str($kind) . "\0" . Jsx::str($value)])) {
                continue;
            }
            $na = Jsx::get($e, 'notAfter');
            if (!($na instanceof Undef) && !($now !== null && is_finite($now) && $now <= Js::num($na))) {
                $out['expired'][] = Obj::of(['kind' => $kind, 'value' => $value, 'label' => Jsx::get($e, 'label')]);
                continue;
            }
            if (is_string($kind) && isset($map[$kind])) {
                $out[$map[$kind]][] = $value;
            } elseif ($kind === 'nvidia-driver-version') {
                $out['nvidiaDriverVersions'][] = $value;
                $out['nvidiaCcDriverVersions'][] = self::driverVersionSlotHex($value);
            } elseif ($kind === 'maa-signing-spki') {
                $l = Jsx::str(Jsx::get($e, 'label'));
                $cur = $out['maaSigningSpkis']->has($l) ? $out['maaSigningSpkis']->get($l) : [];
                $cur[] = $value;
                $out['maaSigningSpkis']->set($l, $cur);
            } elseif ($kind === 'attest-corroboration') {
                $out['corroboration'][] = Obj::of(['value' => $value, 'label' => Jsx::get($e, 'label')]);
            }
        }
        return $out;
    }

    /** @return list<mixed> a copy of the list member `$k` of a projection */
    private static function list(mixed $p, string $k): array
    {
        $v = Jsx::rd($p, $k);
        return is_array($v) ? array_values($v) : [];
    }

    /** Fields for `createAzureMaaVerifier({policy})`; empty lists are omitted. */
    public static function azureMaaPolicyFields(mixed $p): Obj
    {
        $o = new Obj();
        foreach (['tdxMrtds', 'sevSnpMeasurements', 'tdxRtmrs'] as $k) {
            if (self::list($p, $k) !== []) {
                $o->set($k, self::list($p, $k));
            }
        }
        return $o;
    }

    /** Fields for `createIntelDcapVerifier({policy})`: `mrtds` is always present. */
    public static function intelDcapPolicyFields(mixed $p): Obj
    {
        $o = Obj::of(['mrtds' => self::list($p, 'tdxMrtds')]);
        if (self::list($p, 'tdxRtmrs') !== []) {
            $o->set('rtmrs', self::list($p, 'tdxRtmrs'));
        }
        return $o;
    }

    public static function sevSnpPolicyFields(mixed $p): Obj
    {
        return Obj::of(['measurements' => self::list($p, 'sevSnpMeasurements')]);
    }

    public static function gcpCsPolicyFields(mixed $p): Obj
    {
        return Obj::of(['imageDigests' => self::list($p, 'imageDigests')]);
    }

    /** Fields for `NvidiaCcPolicy` (the driver gate is omitted when no driver entries exist). */
    public static function nvidiaCcPolicyFields(mixed $p): Obj
    {
        $o = Obj::of(['measurements' => self::list($p, 'nvidiaMeasurements')]);
        if (self::list($p, 'nvidiaCcDriverVersions') !== []) {
            $o->set('driverVersions', self::list($p, 'nvidiaCcDriverVersions'));
        }
        return $o;
    }
}
