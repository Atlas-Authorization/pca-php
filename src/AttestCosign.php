<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Agent.php';

/**
 * Post-quantum co-signature of a verified attestation verdict (the reference's pqcosign): once the classical hardware step passed, the
 * verdict's security-relevant fields are bound under an ML-DSA / SLH-DSA suite (or a hybrid with Ed25519), so downstream trust in the
 * verdict record rests on a post-quantum primitive. The AMD hardware root itself stays classical. PQ signing and verification need the
 * FFI extension and an OpenSSL >= 3.5 libcrypto (see PqKeyPair); without them signing throws and verification is false (fail closed).
 */
final class AttestCosign
{
    public const DOMAIN = 'atlas-pca/attest-cosign/v1';
    public const DEFAULT_SUITE = 'ml-dsa-65';
    public const SUITES = ['ml-dsa-65', 'ml-dsa-87', 'slh-dsa-sha2-128f', 'slh-dsa-sha2-256s', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65',
        'hybrid-ed25519-ml-dsa-87', 'hybrid-ed25519-slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-256s'];
    /** suite => [OpenSSL family, hybrid, nested] */
    private const SHAPE = [
        'ml-dsa-65' => ['ML-DSA-65', false, false], 'ml-dsa-87' => ['ML-DSA-87', false, false],
        'slh-dsa-sha2-128f' => ['SLH-DSA-SHA2-128f', false, false], 'slh-dsa-sha2-256s' => ['SLH-DSA-SHA2-256s', false, false],
        'hybrid-ed25519-ml-dsa-65' => ['ML-DSA-65', true, false], 'hybrid-nested-ed25519-ml-dsa-65' => ['ML-DSA-65', true, true],
        'hybrid-ed25519-ml-dsa-87' => ['ML-DSA-87', true, false], 'hybrid-ed25519-slh-dsa-sha2-128f' => ['SLH-DSA-SHA2-128f', true, false],
        'hybrid-ed25519-slh-dsa-sha2-256s' => ['SLH-DSA-SHA2-256s', true, false],
    ];

    public static function isSuite(mixed $x): bool
    {
        return is_string($x) && in_array($x, self::SUITES, true);
    }

    private static function def(mixed $v): mixed
    {
        return $v instanceof Undef ? null : $v;
    }

    private static function canonicalMeasured(mixed $m): mixed
    {
        $o = new Obj();
        foreach (['model_id', 'weights_digest'] as $k) {
            $v = Jsx::rd($m, $k);
            if (!($v instanceof Undef)) {
                $o->set($k, $v);
            }
        }
        $wm = Jsx::get($m, 'weights_measured');
        $o->set('weights_measured', is_bool($wm) ? $wm : null);
        foreach (['runtime_measurement', 'operator'] as $k) {
            $v = Jsx::get($m, $k);
            if (!($v instanceof Undef)) {
                $o->set($k, $v);
            }
        }
        foreach (['system_prompt_digest', 'tool_manifest_digest'] as $k) {
            $v = Jsx::get($m, $k);
            $o->set($k, is_string($v) ? $v : null);
        }
        return $o;
    }

    /** The exact bytes the co-signature covers: the verdict's fields in a fixed order, the domain first, JSON.stringify form. */
    public static function canonicalVerdictBytes(mixed $verdict, mixed $cosignedAt): string
    {
        $measured = Jsx::get($verdict, 'measured');
        $measurement = Jsx::get($verdict, 'measurement');
        $nonce = Jsx::get($verdict, 'nonce');
        $iat = Jsx::get($verdict, 'iat');
        $issuer = Jsx::get($verdict, 'issuer');
        $tier = Jsx::get($verdict, 'tier');
        $c = new Obj();
        $c->set('typ', self::DOMAIN);
        if (!($tier instanceof Undef)) {
            $c->set('tier', $tier);
        }
        $c->set('trustworthy', Jsx::get($verdict, 'trustworthy') === true);
        $c->set('measurement', is_string($measurement) ? $measurement : null);
        $c->set('measured', $measured instanceof Undef ? null : self::canonicalMeasured($measured));
        $c->set('nonce', is_string($nonce) ? $nonce : null);
        $c->set('iat', Js::isNum($iat) && is_finite((float)Js::num($iat)) ? $iat : null);
        $c->set('issuer', is_string($issuer) ? $issuer : null);
        $c->set('cosignedAt', $cosignedAt);
        return Js::utf8(Js::stringify($c));
    }

    /** The verdict (tier, trustworthy, measured identity, measurement, nonce, iat, issuer) of an appraisal result and the EAT claims. */
    public static function verdictFromAppraisal(mixed $result, mixed $claims): Obj
    {
        $v = new Obj();
        $v->set('tier', self::def(Jsx::get($result, 'tier')));
        $v->set('trustworthy', self::def(Jsx::get($result, 'trustworthy')));
        $measured = Jsx::get($claims, 'measured');
        if (!($measured instanceof Undef)) {
            $v->set('measured', $measured);
        }
        $rm = Jsx::get($measured instanceof Undef || $measured === null ? new Obj() : $measured, 'runtime_measurement');
        $has = Js::truthy($rm) && ((is_string($rm) && $rm !== '') || (is_array($rm) && $rm !== []));
        $measurement = $has ? $rm : Jsx::get(Jsx::get($claims, 'sevsnp') instanceof Undef ? new Obj() : Jsx::get($claims, 'sevsnp'), 'measurement');
        if (is_string($measurement) && $measurement !== '') {
            $v->set('measurement', $measurement);
        }
        $nonce = Jsx::get($claims, 'eat_nonce');
        if (is_string($nonce)) {
            $v->set('nonce', $nonce);
        }
        $iat = Jsx::get($claims, 'iat');
        if (Js::isNum($iat) && is_finite((float)Js::num($iat))) {
            $v->set('iat', $iat);
        }
        $iss = Jsx::get($claims, 'iss');
        if (is_string($iss)) {
            $v->set('issuer', $iss);
        }
        return $v;
    }

    /**
     * Co-sign a verdict. Options: `suite` (default ml-dsa-65; a pure-classical or unknown suite is refused), `pq` (a PqKeyPair of the
     * suite's family), `ed` (a KeyPair, hybrids only), `now` (epoch ms).
     * @return Obj {verdict, cosig:{cosignedAt, sig, pq_sig?}, suite, signer_pub:{pq, ed?}}
     */
    public static function coSign(mixed $verdict, mixed $opts): Obj
    {
        $suite = Js::opt($opts, 'suite') ?? self::DEFAULT_SUITE;
        if (!self::isSuite($suite)) {
            throw new \RangeException('coSignAttestation: ' . Js::str($suite) . ' is not an accepted post-quantum co-sign suite');
        }
        [$family, $hybrid, $nested] = self::SHAPE[$suite];
        $pq = Js::opt($opts, 'pq');
        if (!($pq instanceof PqKeyPair) || $pq->family !== $family) {
            throw new \TypeError("coSignAttestation: suite '$suite' requires $family key material");
        }
        $ed = Js::opt($opts, 'ed');
        if ($hybrid && !($ed instanceof KeyPair)) {
            throw new \TypeError("coSignAttestation: hybrid suite '$suite' requires edSecret");
        }
        $now = Js::opt($opts, 'now');
        $at = Js::isNum($now) && is_finite((float)Js::num($now)) ? $now : (int)(microtime(true) * 1000);
        $msg = self::canonicalVerdictBytes($verdict, $at);
        $pub = Obj::of(['pq' => $pq->public]);
        if ($hybrid) {
            $pub->set('ed', $ed->public);
            $edSig = $ed->sign($msg);
            $cosig = Obj::of(['cosignedAt' => $at, 'sig' => Pca::b64u($edSig), 'pq_sig' => Pca::b64u($pq->sign($nested ? $msg . $edSig : $msg))]);
        } else {
            $cosig = Obj::of(['cosignedAt' => $at, 'sig' => Pca::b64u($pq->sign($msg))]);
        }
        return Obj::of(['verdict' => $verdict, 'cosig' => $cosig, 'suite' => $suite, 'signer_pub' => $pub]);
    }

    private static function signerMatches(mixed $expected, Obj $got): bool
    {
        $expPq = is_string($expected) ? $expected : Js::opt($expected, 'pq');
        if (!is_string($expPq) || !hash_equals($expPq, (string)$got->get('pq'))) {
            return false;
        }
        if (!is_string($expected) && is_string(Js::opt($expected, 'ed'))) {
            return is_string($got->get('ed') ?? null) && hash_equals(Js::opt($expected, 'ed'), $got->get('ed'));
        }
        return true;
    }

    /**
     * Verify a co-signed verdict. Options: `expectedSigner` (the PQ public key, or {pq, ed?}), `maxAgeMs`, `now`. Never throws.
     * @return Obj {ok, reason?, suite?, verdict?, signer_pub?, cosignedAt?, ageMs?}
     */
    public static function verify(mixed $cosigned, mixed $opts = null): Obj
    {
        try {
            if (!($cosigned instanceof Obj)) {
                return Obj::of(['ok' => false, 'reason' => 'co-signed attestation is not an object']);
            }
            $verdict = $cosigned->get('verdict');
            if (!($verdict instanceof Obj) || !is_string($verdict->get('tier')) || !is_bool($verdict->get('trustworthy'))) {
                return Obj::of(['ok' => false, 'reason' => 'verdict is missing or has a non-string tier / non-boolean trustworthy']);
            }
            $cosig = $cosigned->get('cosig');
            if (!($cosig instanceof Obj) || !Js::isNum($cosig->get('cosignedAt')) || !is_finite((float)Js::num($cosig->get('cosignedAt'))) || !is_string($cosig->get('sig'))) {
                return Obj::of(['ok' => false, 'reason' => 'cosig is missing or has a non-numeric cosignedAt / non-string sig']);
            }
            $suite = $cosigned->get('suite');
            if (!self::isSuite($suite)) {
                return Obj::of(['ok' => false, 'reason' => "suite '" . Js::str($suite) . "' is not an accepted post-quantum co-sign suite"]);
            }
            $sp = $cosigned->get('signer_pub');
            if (!($sp instanceof Obj) || !is_string($sp->get('pq')) || $sp->get('pq') === '') {
                return Obj::of(['ok' => false, 'reason' => 'signer_pub is missing or has no post-quantum public key']);
            }
            $signerPub = Obj::of(['pq' => $sp->get('pq')]);
            if (is_string($sp->get('ed')) && $sp->get('ed') !== '') {
                $signerPub->set('ed', $sp->get('ed'));
            }
            $nowOpt = Js::opt($opts, 'now');
            $now = Js::isNum($nowOpt) && is_finite((float)Js::num($nowOpt)) ? (float)Js::num($nowOpt) : microtime(true) * 1000;
            $at = (float)Js::num($cosig->get('cosignedAt'));
            $ageMs = $now - $at;
            $partial = Obj::of(['ok' => false, 'suite' => $suite, 'verdict' => $verdict, 'signer_pub' => $signerPub, 'cosignedAt' => $cosig->get('cosignedAt'),
                'ageMs' => IntentWb::isSafeInt($ageMs) ? (int)$ageMs : $ageMs]);
            $fail = static function (string $why) use ($partial): Obj {
                $partial->set('reason', $why);
                return $partial;
            };
            $expected = Js::opt($opts, 'expectedSigner');
            if (Js::has($opts, 'expectedSigner') && $expected === null) {
                throw new \TypeError("Cannot read properties of null (reading 'pq')");
            }
            if (Js::has($opts, 'expectedSigner') && !self::signerMatches($expected, $signerPub)) {
                return $fail('co-signer public key does not match the expected signer');
            }
            $maxAge = Js::opt($opts, 'maxAgeMs');
            if (Js::has($opts, 'maxAgeMs')) {
                if (!Js::isNum($maxAge) || !is_finite((float)Js::num($maxAge)) || Js::num($maxAge) <= 0) {
                    return $fail('invalid maxAgeMs');
                }
                if (!($at <= $now)) {
                    return $fail('co-sign timestamp is in the future');
                }
                if (!($ageMs <= Js::num($maxAge))) {
                    return $fail('co-signature is stale (older than maxAgeMs)');
                }
            }
            $msg = self::canonicalVerdictBytes($verdict, $cosig->get('cosignedAt'));
            [, $hybrid, $nested] = self::SHAPE[$suite];
            $ok = self::verifyParts($suite, $hybrid, $nested, $signerPub, $msg, $cosig);
            if (!$ok) {
                return $fail('post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)');
            }
            $partial->set('ok', true);
            return $partial;
        } catch (\Throwable $e) {
            return Obj::of(['ok' => false, 'reason' => 'co-signature verification error (fail closed): ' . $e->getMessage()]);
        }
    }

    private static function verifyParts(string $suite, bool $hybrid, bool $nested, Obj $signerPub, string $msg, Obj $cosig): bool
    {
        $pqSig = $cosig->has('pq_sig') ? $cosig->get('pq_sig') : null;
        if ($hybrid && (!is_string($pqSig))) {
            return false;
        }
        return Pca::verifySuiteUnderKey($suite, $signerPub->has('ed') ? (string)$signerPub->get('ed') : null, (string)$signerPub->get('pq'), $msg, $cosig->get('sig'), $pqSig);
    }
}
