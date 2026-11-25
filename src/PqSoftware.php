<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Attestation.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';

/**
 * The post-quantum software / HSM attestation root: a statement of a measured workload and the holder / grant / epoch / nonce binding,
 * signed under a post-quantum or hybrid suite. `alg`, `pq_pk` and `attestor_ed25519` are signed into the body, so a downgrade or key swap
 * invalidates it; a hybrid needs BOTH signatures. The root is software, not silicon: the identity it yields has `weights_measured: false`.
 */
final class PqSoftware
{
    public const DOMAIN = "atlas-pca/attest-pq/v1\0";
    private const PQ_FAMILIES = ['ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128f', 'SLH-DSA-SHA2-256s'];

    /** True iff the suite carries a post-quantum component (the FN-DSA and LESS suites are not counted by this root). */
    private static function hasPq(array $suite): bool
    {
        return in_array($suite['family'] ?? null, self::PQ_FAMILIES, true);
    }

    private static function message(mixed $body): string
    {
        return self::DOMAIN . Json::canonicalizeNative($body);
    }

    /**
     * Build an attestor from the HSM-held key material (provided, never generated here). The suite MUST carry a PQ component; a hybrid
     * additionally needs the Ed25519 key. @return array{pqPublicKey:string,ed25519PublicKey:?string,attest:\Closure(mixed):Obj}
     */
    public static function createAttestor(mixed $alg, ?KeyPair $ed, ?PqKeyPair $pq): array
    {
        $suite = Pq::resolveSigAlg($alg);
        if ($suite === null) {
            throw new \RangeException("createPqSoftwareAttestor: unknown signature alg '" . Jsx::str($alg) . "'");
        }
        if (!self::hasPq($suite)) {
            throw new \RangeException("createPqSoftwareAttestor: '" . $suite['alg'] . "' is classical; the PQ root requires a post-quantum suite");
        }
        $pk = Pq::suitePqPublicKey($suite['alg'], $pq);
        if ($suite['needsPqPk'] && $pk === null) {
            throw new \TypeError("createPqSoftwareAttestor: '" . $suite['alg'] . "' requires the matching PQ key material");
        }
        if ($suite['hasEd25519'] && $ed === null) {
            throw new \TypeError("createPqSoftwareAttestor: hybrid suite '" . $suite['alg'] . "' requires edSecret");
        }
        $edPub = $ed?->public;
        $attest = static function (mixed $claims) use ($suite, $ed, $pq, $pk, $edPub): Obj {
            $binding = Attestation::bindingB64u(Obj::of(['holderPub' => Jsx::get($claims, 'holder_pub'), 'grantRef' => Jsx::get($claims, 'grant_ref'),
                'epoch' => Jsx::get($claims, 'epoch'), 'nonce' => Jsx::get($claims, 'nonce')]));
            $body = Obj::of(['measurement' => Jsx::get($claims, 'measurement'), 'binding' => $binding, 'alg' => $suite['alg']]);
            if ($pk !== null) {
                $body->set('pq_pk', $pk);
            }
            if ($edPub !== null) {
                $body->set('attestor_ed25519', $edPub);
            }
            foreach (['weights_digest', 'system_prompt_digest', 'tool_manifest_digest', 'model_id', 'operator'] as $k) {
                $v = Jsx::get($claims, $k);
                if (!($v instanceof Undef)) {
                    $body->set($k, $v);
                }
            }
            $parts = Pq::signWithSuite($suite['alg'], $ed, $pq, self::message($body));
            $out = Jsx::spread($body);
            $out->set('sig', $parts['sig']);
            if (isset($parts['pq_sig'])) {
                $out->set('pq_sig', $parts['pq_sig']);
            }
            return $out;
        };
        return ['pqPublicKey' => $pk ?? '', 'ed25519PublicKey' => $edPub, 'attest' => $attest];
    }

    /** The default identity of a verified statement; `weights_measured` is ALWAYS false. */
    private static function defaultIdentity(mixed $st): Obj
    {
        $s = static fn(string $k): string => is_string($v = Jsx::get($st, $k)) ? $v : '';
        $o = Obj::of(['model_id' => $s('model_id'), 'weights_digest' => $s('weights_digest'), 'weights_measured' => false,
            'runtime_measurement' => Jsx::get($st, 'measurement'), 'operator' => $s('operator')]);
        foreach (['system_prompt_digest', 'tool_manifest_digest'] as $k) {
            if (is_string(Jsx::get($st, $k))) {
                $o->set($k, $st->get($k));
            }
        }
        return $o;
    }

    /**
     * The verifier over trusted HSM-root keys. The checks run in this order, the first failure wins: the suite and the PQ, hybrid and
     * allowed-suite requirements, the trusted attestor keys, the signature over the canonical body, the binding, then the policy.
     * Throws at construction without a non-empty measurement allowlist or a trusted PQ key.
     * @param mixed $opts `{trustedPqPublicKeys, trustedEd25519PublicKeys?, requirePq?, requireHybrid?, allowedSuites?, policy: {measurements, weightsMeasurements?}, resolveEvidence?: callable}`
     * @return \Closure(mixed):array<string,mixed> `verify(Obj{document, ctx, nowMs, expected})`: `{ok, bound, measured, hostAsserted}` or `{ok: false, reason}`
     */
    public static function createVerifier(mixed $opts): \Closure
    {
        $policy = Jsx::get($opts, 'policy');
        $ms = Jsx::get($policy, 'measurements');
        if (!Jsx::truthy($policy) || !is_array($ms) || !array_is_list($ms) || $ms === []) {
            throw new \TypeError('createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
        }
        $wm = Jsx::get($policy, 'weightsMeasurements');
        $weights = is_array($wm) && array_is_list($wm) ? $wm : null;
        $tp = Jsx::get($opts, 'trustedPqPublicKeys');
        $trustedPq = is_array($tp) && array_is_list($tp) ? $tp : [];
        if ($trustedPq === []) {
            throw new \TypeError('createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)');
        }
        $te = Jsx::get($opts, 'trustedEd25519PublicKeys');
        $trustedEd = is_array($te) && array_is_list($te) ? $te : [];
        $requirePq = Jsx::get($opts, 'requirePq') !== false;
        $requireHybrid = Jsx::get($opts, 'requireHybrid') === true;
        $as = Jsx::get($opts, 'allowedSuites');
        $allowed = $as instanceof Undef ? null : (is_array($as) && array_is_list($as) ? $as : []);
        $resolve = Jsx::get($opts, 'resolveEvidence');
        return static function (mixed $input) use ($ms, $weights, $trustedPq, $trustedEd, $requirePq, $requireHybrid, $allowed, $resolve, $policy): array {
            $fail = static fn(string $reason): array => ['ok' => false, 'reason' => $reason];
            try {
                if (!is_callable($resolve)) {
                    return $fail('no PQ-software evidence resolver configured (fail closed)');
                }
                $st = $resolve(Jsx::get($input, 'document'), Jsx::get($input, 'ctx'));
                if (!($st instanceof Obj) || !is_string($st->get('alg'))) {
                    return $fail('no PQ-software attestation statement for this action');
                }
                $suite = Pq::resolveSigAlg($st->get('alg'));
                if ($suite === null) {
                    return $fail("PQ statement declares an unknown signature alg '" . $st->get('alg') . "'");
                }
                $hasPq = self::hasPq($suite);
                if ($requirePq && !$hasPq) {
                    return $fail("PQ required: a classical-only suite '" . $suite['alg'] . "' is not accepted by the post-quantum root");
                }
                if ($requireHybrid && !($suite['hasEd25519'] && $hasPq)) {
                    return $fail("hybrid required: suite '" . $suite['alg'] . "' is not a classical+PQ hybrid");
                }
                if ($allowed !== null && !in_array($suite['alg'], $allowed, true)) {
                    return $fail("suite '" . $suite['alg'] . "' is not in the allowed-suites list");
                }
                $pqPk = $st->get('pq_pk');
                if ($suite['needsPqPk'] && (!is_string($pqPk) || !in_array($pqPk, $trustedPq, true))) {
                    return $fail('PQ attestor key is not trusted');
                }
                $edPk = $st->get('attestor_ed25519');
                if ($suite['hasEd25519'] && (!is_string($edPk) || !in_array($edPk, $trustedEd, true))) {
                    return $fail('hybrid Ed25519 attestor key is not trusted');
                }
                $body = $st->without('sig', 'pq_sig');
                $message = self::message($body);
                $pq = $suite['needsPqPk'] ? Pca::resolvePqVerifyKey('', null, ['trustedPk' => is_string($pqPk) && in_array($pqPk, $trustedPq, true) ? $pqPk : null]) : null;
                $keys = ['edPub' => $edPk instanceof Undef ? null : $edPk];
                if ($pq !== null) {
                    $keys['pq'] = $pq;
                }
                $sig = $st->get('sig');
                $pqSig = $st->get('pq_sig');
                if (!Pca::verifyWithSuite($suite['alg'], $keys, $message, ['sig' => $sig, 'pq_sig' => $pqSig])) {
                    return $fail('PQ attestation signature does not verify');
                }
                $expected = Jsx::get($input, 'expected');
                if (!Jsx::truthy($expected)) {
                    return $fail('no expected attestation binding supplied');
                }
                try {
                    $want = Attestation::bindingB64u($expected);
                } catch (\Throwable $e) {
                    return $fail('binding not constructible: ' . ($e->getMessage() === '' ? 'invalid' : $e->getMessage()));
                }
                $b = $st->get('binding');
                if (!is_string($b) || $b === '') {
                    return $fail('PQ statement is not bound (binding absent)');
                }
                if ($b !== $want) {
                    return $fail('PQ statement binding mismatch (holder/grant/epoch/nonce)');
                }
                if (!in_array($st->get('measurement'), $ms, true)) {
                    return $fail('measurement not in policy allowlist');
                }
                if ($weights !== null && $weights !== [] && (!is_string($st->get('weights_digest')) || !in_array($st->get('weights_digest'), $weights, true))) {
                    return $fail('measured weights digest not in policy allowlist');
                }
                $derive = Jsx::get($policy, 'deriveIdentity');
                return ['ok' => true, 'bound' => true, 'measured' => is_callable($derive) ? $derive($st) : self::defaultIdentity($st),
                    'hostAsserted' => Obj::of(['suite' => $suite['alg']])];
            } catch (\Throwable $e) {
                return $fail('pq-software verification error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()));
            }
        };
    }
}
