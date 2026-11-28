<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/FheSeal.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';

/**
 * Origin authentication of an encrypted risk claim (scheme-independent): the encryptor signs the ciphertext, the binding to one action,
 * the gate policy, a context and a one-time nonce; the verifier checks the signature, the context, the binding, the policy and a replay
 * guard BEFORE spending any evaluator work; the key holder signs the verdict over the exact claim and gate output it opened. A claim and
 * an attestation are parsed JSON objects (Obj).
 */
final class FheOrigin
{
    private const CLAIM_DOMAIN = "atlas-pca-fhe/signed-claim/v1\0";
    private const VERDICT_DOMAIN = "atlas-pca-fhe/verdict-attestation/v1\0";
    private const NONCE_BYTES = 16;
    private const MAX_CONTEXT_LEN = 512;

    private static function bytesDigest(string $s): string
    {
        return Pca::b64u(hash('sha256', $s, true));
    }

    private static function prefixed(string $domain, Obj $body): string
    {
        return $domain . Json::canonicalizeNative($body);
    }

    private static function one(): Num
    {
        return new Num('1');
    }

    private static function isObject(mixed $o): bool
    {
        return $o instanceof Obj || is_array($o);
    }

    private static function claimStatement(Obj $claim, string $context, string $nonce, string $signer): string
    {
        $b = new Obj();
        $b->set('v', self::one());
        $b->set('context', $context);
        $b->set('nonce', $nonce);
        $b->set('signer', $signer);
        $b->set('binding', $claim->get('binding'));
        $b->set('policy', Pca::hashCanonical($claim->get('policy')));
        $b->set('enc_inputs', self::bytesDigest((string) $claim->get('encInputs')));
        return self::prefixed(self::CLAIM_DOMAIN, $b);
    }

    /** The content digest of a signed claim (what the key holder's attestation commits to). */
    public static function signedClaimDigest(mixed $signed): string
    {
        return Pca::hashCanonical($signed);
    }

    /** @return array{0:string,1:string} [public key, secret key] of a 32-byte Ed25519 seed */
    private static function keypair(string $seed): array
    {
        if (strlen($seed) !== 32) {
            throw new \InvalidArgumentException('signing key must be a 32-byte Ed25519 secret key');
        }
        $kp = sodium_crypto_sign_seed_keypair($seed);
        return [sodium_crypto_sign_publickey($kp), sodium_crypto_sign_secretkey($kp)];
    }

    /** Signs an encrypted risk claim; a fresh random one-time nonce unless one is supplied (tests and replay of recorded vectors). */
    public static function signRiskClaim(Obj $claim, string $signerSecretKey, string $context, ?string $nonce = null): Obj
    {
        $units = intdiv(strlen((string) mb_convert_encoding($context, 'UTF-16BE', 'UTF-8')), 2); // JavaScript string length
        if ($context === '' || $units > self::MAX_CONTEXT_LEN) {
            throw new \InvalidArgumentException('context must be a non-empty string of at most ' . self::MAX_CONTEXT_LEN . ' characters');
        }
        $nonce ??= random_bytes(self::NONCE_BYTES);
        if (strlen($nonce) === 0 || trim($nonce, "\0") === '') {
            throw new \RuntimeException('signRiskClaim: random source returned all zeros (RNG failure)');
        }
        [$pub, $sk] = self::keypair($signerSecretKey);
        $signer = Pca::b64u($pub);
        $n = Pca::b64u($nonce);
        $o = new Obj();
        $o->set('claim', $claim);
        $o->set('context', $context);
        $o->set('nonce', $n);
        $o->set('signer', $signer);
        $o->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::claimStatement($claim, $context, $n, $signer), $sk)));
        return $o;
    }

    /** A bounded set of nonces already seen: claim(key) is false when the key was seen or the window is full. @return \Closure(string):bool */
    public static function memoryNonceGuard(int $maxEntries = 100000): \Closure
    {
        $seen = [];
        return static function (string $key) use (&$seen, $maxEntries): bool {
            if (isset($seen[$key]) || count($seen) >= $maxEntries) {
                return false;
            }
            $seen[$key] = true;
            return true;
        };
    }

    /**
     * Evaluator: verify the signed claim, then run the gate. The ciphertext is not loaded into SEAL unless the signature, signer, context, binding,
     * policy and nonce all check out; there is no unsigned entry on the claim path. Returns ['ok' => true, 'gate' => FheEncryptedGate, 'claimDigest']
     * or ['ok' => false, 'reason']. Never throws.
     *
     * @param list<string> $trustedSigners
     * @param \Closure(string):bool $nonces
     * @return array{ok:true,gate:FheEncryptedGate,claimDigest:string}|array{ok:false,reason:string}
     */
    public static function evalSignedRiskClaim(string $publicKey, string $galoisKeys, mixed $signed, array $trustedSigners, string $context, mixed $binding, mixed $policy, \Closure $nonces): array
    {
        $chk = self::verifySignedRiskClaim($signed, $trustedSigners, $context, $binding, $policy, $nonces);
        if ($chk['ok'] !== true) {
            return $chk;
        }
        try {
            $p = $chk['claim']->get('policy');
            $ints = static fn(mixed $l): array => array_map(static fn($n): int => $n->int(), $l);
            $gate = FheSeal::evalRiskGate($publicKey, $galoisKeys, $chk['claim']->get('encInputs'), new FheRiskPolicy($p->get('scale')->int(), $p->get('dim')->int(),
                $ints($p->get('weightsScaled')), $ints($p->get('kappaWeightsScaled')), $p->get('budgetScaled')->int(), (float)Js::num($p->get('kappa'))));
            return ['ok' => true, 'gate' => $gate, 'claimDigest' => $chk['digest']];
        } catch (\Throwable $e) {
            return self::fail('evaluation failed: ' . ($e->getMessage() !== '' ? $e->getMessage() : 'unknown error'));
        }
    }

    /** @return array{ok:false,reason:string} */
    private static function fail(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    /**
     * Verifies a signed claim; never throws (a malformed or hostile input is a not-ok result). `$nonces` is the replay guard
     * (memoryNonceGuard); the other arguments are what the verifier expects: trusted encryptor keys, the grant context, the
     * action binding and the gate policy.
     *
     * @param list<string> $trustedSigners
     * @param \Closure(string):bool $nonces
     * @return array{ok:true,claim:Obj,digest:string}|array{ok:false,reason:string}
     */
    public static function verifySignedRiskClaim(mixed $s, array $trustedSigners, string $context, mixed $binding, mixed $policy, \Closure $nonces): array
    {
        try {
            if (!($s instanceof Obj)) {
                return self::fail('claim is not signed: malformed envelope');
            }
            $claim = $s->get('claim');
            if (!is_string($s->get('context')) || !is_string($s->get('nonce')) || !is_string($s->get('signer')) || !is_string($s->get('sig'))
                || !($claim instanceof Obj) || !is_string($claim->get('encInputs')) || !self::isObject($claim->get('binding')) || !self::isObject($claim->get('policy'))) {
                return self::fail('claim is not signed: malformed envelope');
            }
            $ctx = $s->get('context');
            $nonce = $s->get('nonce');
            $signer = $s->get('signer');
            $sig = $s->get('sig');
            if (Pca::unb64u($nonce, self::NONCE_BYTES) === null) {
                return self::fail('malformed nonce');
            }
            if (Pca::unb64u($signer, 32) === null || Pca::unb64u($sig, 64) === null) {
                return self::fail('malformed signer key or signature');
            }
            if (!in_array($signer, $trustedSigners, true)) {
                return self::fail('signer is not a trusted encryptor');
            }
            if (!Pca::verifyEd25519B64u($signer, self::claimStatement($claim, $ctx, $nonce, $signer), $sig)) {
                return self::fail('signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)');
            }
            if ($ctx !== $context) {
                return self::fail('context mismatch: claim was signed for a different grant/policy');
            }
            if (Pca::hashCanonical($claim->get('binding')) !== Pca::hashCanonical($binding)) {
                return self::fail('binding mismatch: claim is bound to a different action');
            }
            if (Pca::hashCanonical($claim->get('policy')) !== Pca::hashCanonical($policy)) {
                return self::fail('policy mismatch: claim was signed for a different gate policy');
            }
            if (!$nonces($signer . ':' . $nonce)) {
                return self::fail('replay: nonce already used (or the replay window is full)');
            }
            return ['ok' => true, 'claim' => $claim, 'digest' => self::signedClaimDigest($s)];
        } catch (\Throwable) {
            return self::fail('claim could not be verified (malformed)');
        }
    }

    private static function verdictStatement(string $claimDigest, mixed $gateDigest, bool $admit, string $holder): string
    {
        $b = new Obj();
        $b->set('v', self::one());
        $b->set('claim', $claimDigest);
        $b->set('gate', $gateDigest);
        $b->set('admit', $admit);
        $b->set('holder', $holder);
        return self::prefixed(self::VERDICT_DOMAIN, $b);
    }

    /** The key holder's signed attestation of the verdict it opened, bound to the exact claim and gate output. */
    public static function attestVerdict(string $holderSecretKey, Obj $signed, Obj $gate, bool $admit): Obj
    {
        $gd = new Obj();
        $gd->set('encRiskRaw', self::bytesDigest((string) $gate->get('encRiskRaw')));
        $gd->set('encSlack', self::bytesDigest((string) $gate->get('encSlack')));
        $claimDigest = self::signedClaimDigest($signed);
        [$pub, $sk] = self::keypair($holderSecretKey);
        $holder = Pca::b64u($pub);
        $o = new Obj();
        $o->set('claimDigest', $claimDigest);
        $o->set('gateDigest', $gd);
        $o->set('admit', $admit);
        $o->set('holder', $holder);
        $o->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::verdictStatement($claimDigest, $gd, $admit, $holder), $sk)));
        return $o;
    }

    /**
     * Verifies an attestation: trusted holder, signature, the expected claim digest and (when given) the expected gate output.
     *
     * @param list<string> $trustedHolders
     * @return array{ok:true,admit:bool}|array{ok:false,reason:string}
     */
    public static function verifyVerdictAttestation(mixed $a, array $trustedHolders, string $claimDigest, ?Obj $gate = null): array
    {
        try {
            if (!($a instanceof Obj)) {
                return self::fail('malformed attestation');
            }
            $gd = $a->get('gateDigest');
            if (!is_string($a->get('claimDigest')) || !is_string($a->get('holder')) || !is_string($a->get('sig')) || !is_bool($a->get('admit'))
                || !($gd instanceof Obj) || !is_string($gd->get('encRiskRaw')) || !is_string($gd->get('encSlack'))) {
                return self::fail('malformed attestation');
            }
            $holder = $a->get('holder');
            if (!in_array($holder, $trustedHolders, true)) {
                return self::fail('attestation holder is not trusted');
            }
            if (Pca::unb64u($holder, 32) === null || Pca::unb64u($a->get('sig'), 64) === null) {
                return self::fail('malformed holder key or signature');
            }
            if (!Pca::verifyEd25519B64u($holder, self::verdictStatement($a->get('claimDigest'), $gd, $a->get('admit'), $holder), $a->get('sig'))) {
                return self::fail('attestation signature does not verify');
            }
            if ($a->get('claimDigest') !== $claimDigest) {
                return self::fail('attestation is for a different claim');
            }
            if ($gate !== null
                && ($gd->get('encRiskRaw') !== self::bytesDigest((string) $gate->get('encRiskRaw')) || $gd->get('encSlack') !== self::bytesDigest((string) $gate->get('encSlack')))) {
                return self::fail('attestation is for a different gate output');
            }
            return ['ok' => true, 'admit' => $a->get('admit')];
        } catch (\Throwable) {
            return self::fail('attestation could not be verified (malformed)');
        }
    }
}
