<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';

/**
 * K4 (verification side): risk-priced escalation (pricing config, decision, calibration from signed answers), the network-token
 * binding and the ERC-7715 granted-permission check. Replays packages/pca/conformance/k4-vectors.json.
 * Signatures are Ed25519 (strict) over the UTF-8 bytes of hashCanonical({"kind": kind, "body": body}) (the digest string); body is the
 * signed object without its `sig`. Escalation is integer-only (GMP). Total: never throws. JSON values are Obj / list / string / Num.
 */
final class K4
{
    public const PPM = 1000000;
    public const MAX_MULTIPLIER_PPM = 100 * self::PPM;
    public const BINDING_KIND = 'pca.network_token_binding';

    private static function int(mixed $x): ?int
    {
        return K3Sig::anySafeInt($x) ? (int)K3Sig::num($x) : null;
    }

    private static function minor(mixed $x): ?int
    {
        return K3Sig::isSafeInt($x) ? (int)K3Sig::num($x) : null;
    }

    private static function s(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : null;
    }

    /** null when the key or signature does not decode; else the strict verification result. */
    private static function sigOk(mixed $pub, string $kind, Obj $obj): ?bool
    {
        $sig = $obj->get('sig');
        if (!is_string($pub) || !is_string($sig) || Pca::unb64u($pub) === null || Pca::unb64u($sig) === null) {
            return null;
        }
        $digest = Pca::hashCanonical(Obj::of(['kind' => $kind, 'body' => $obj->without('sig')]));
        return Pca::verifyEd25519B64u($pub, $digest, $sig);
    }

    private static function luhn(string $d): bool
    {
        $sum = 0;
        $dbl = false;
        for ($i = strlen($d) - 1; $i >= 0; $i--) {
            $n = ord($d[$i]) - 48;
            if ($dbl) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $dbl = !$dbl;
        }
        return $sum % 10 === 0;
    }

    public static function looksLikePan(string $s): bool
    {
        preg_match_all('/[0-9]+/', (string)preg_replace('/[\s\-]/', '', $s), $m);
        foreach ($m[0] as $r) {
            if (strlen($r) >= 13 && strlen($r) <= 19 && self::luhn($r)) {
                return true;
            }
        }
        return false;
    }

    public static function tokenRefError(mixed $ref): ?string
    {
        if (!is_string($ref) || preg_match('/\A[A-Za-z0-9_.:\-]{8,128}\z/D', $ref) !== 1) {
            return 'token_ref_malformed';
        }
        return self::looksLikePan($ref) ? 'token_ref_looks_like_pan' : null;
    }

    /** null = valid, else the reason. */
    public static function verifyBinding(mixed $b, mixed $grant, string $holder, string $issuerNonce, ?string $provider = null): ?string
    {
        try {
            if (!($b instanceof Obj) || $b->get('kind') !== self::BINDING_KIND) {
                return 'binding_malformed';
            }
            if (($e = self::tokenRefError($b->get('token_ref'))) !== null) {
                return $e;
            }
            $p = $b->get('provider');
            if (!is_string($p) || $p === '' || ($provider !== null && $p !== $provider)) {
                return 'provider_mismatch';
            }
            if ($b->get('grant_digest') !== Pca::hashCanonical($grant)) {
                return 'grant_digest_mismatch';
            }
            if ($b->get('holder') !== $holder) {
                return 'holder_mismatch';
            }
            if ($b->get('issuer_nonce') !== $issuerNonce) {
                return 'issuer_nonce_mismatch';
            }
            $proof = $b->get('binding_proof');
            if (Pca::unb64u($holder) === null || !is_string($proof) || Pca::unb64u($proof) === null) {
                return 'binding_malformed';
            }
            $body = Obj::of(['kind' => self::BINDING_KIND, 'v' => new Num('1'), 'provider' => $p, 'token_ref' => $b->get('token_ref'),
                'grant_digest' => $b->get('grant_digest'), 'issuer_nonce' => $b->get('issuer_nonce'), 'holder' => $b->get('holder')]);
            return Pca::verifyEd25519B64u($holder, Pca::hashCanonical($body), $proof) ? null : 'binding_proof_invalid';
        } catch (\Throwable) {
            return 'binding_malformed';
        }
    }

    public static function pricingConfigError(mixed $c): ?string
    {
        try {
            if (!($c instanceof Obj) || self::int($c->get('v')) !== 1 || !is_string($c->get('principal')) || !is_string($c->get('currency')) || !is_string($c->get('sig'))) {
                return 'config_malformed';
            }
            foreach (['interruptionCost', 'maxInterruptionCost', 'hardCeilingLoss', 'epoch'] as $k) {
                if (self::minor($c->get($k)) === null) {
                    return 'config_amounts_invalid';
                }
            }
            if (self::minor($c->get('interruptionCost')) > self::minor($c->get('maxInterruptionCost'))) {
                return 'config_cost_above_max';
            }
            $st = self::int($c->get('tightenStepPpm'));
            if ($st === null || $st < 0 || $st > self::MAX_MULTIPLIER_PPM) {
                return 'config_step_invalid';
            }
            $r = self::sigOk($c->get('principal'), 'pca.escalation_pricing', $c);
            return $r === null ? 'config_malformed' : ($r ? null : 'config_signature_invalid');
        } catch (\Throwable) {
            return 'config_malformed';
        }
    }

    /** @return array{ask: bool, reason: string} */
    public static function decide(mixed $config, mixed $cal, mixed $a): array
    {
        $ask = static fn (string $r): array => ['ask' => true, 'reason' => $r];
        if (($e = self::pricingConfigError($config)) !== null) {
            return $ask($e);
        }
        if (!($a instanceof Obj) || $a->get('currency') !== $config->get('currency')) {
            return $ask('currency_mismatch');
        }
        $loss = self::minor($a->get('loss'));
        $p = self::int($a->get('pBadUpperPpm'));
        if ($loss === null || $p === null || $p < 0 || $p > self::PPM) {
            return $ask('risk_input_invalid');
        }
        $m = self::int(self::s($cal, 'multiplierPpm'));
        if ($m === null || $m < self::PPM || $m > self::MAX_MULTIPLIER_PPM) {
            return $ask('calibration_invalid');
        }
        if ($loss > self::minor($config->get('hardCeilingLoss'))) {
            return $ask('above_hard_ceiling');
        }
        $one = gmp_mul(self::PPM, self::PPM);
        $capped = gmp_mul($p, $m);
        if (gmp_cmp($capped, $one) > 0) {
            $capped = $one;
        }
        if (gmp_cmp(gmp_mul($capped, $loss), gmp_mul((int)self::minor($config->get('interruptionCost')), $one)) > 0) {
            return $ask('expected_loss_exceeds_interruption_cost');
        }
        return ['ask' => false, 'reason' => 'expected_loss_within_interruption_cost'];
    }

    private static function answerOk(mixed $a, string $principal): bool
    {
        try {
            return $a instanceof Obj && self::int($a->get('v')) === 1 && $a->get('principal') === $principal
                && is_string($a->get('nonce')) && K3Sig::utf16Len($a->get('nonce')) >= 8 && is_string($a->get('action_digest'))
                && in_array($a->get('answer'), ['approve', 'deny'], true) && self::sigOk($principal, 'pca.escalation_answer', $a) === true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Fold principal-signed answers into the calibration; the multiplier can only rise.
     * @param list<string> $seen
     * @param array<string,mixed> $risks action digest => risk
     * @return array{mult: int, seen: list<string>}
     */
    public static function updateCalibration(mixed $config, int $mult, array $seen, array $answers, array $risks): array
    {
        if (self::pricingConfigError($config) !== null) {
            return ['mult' => $mult, 'seen' => $seen];
        }
        $start = $mult;
        $step = (int)self::int($config->get('tightenStepPpm'));
        foreach ($answers as $a) {
            if (!self::answerOk($a, $config->get('principal')) || in_array($a->get('nonce'), $seen, true)) {
                continue;
            }
            $seen[] = $a->get('nonce');
            $risk = $risks[$a->get('action_digest')] ?? null;
            if ($a->get('answer') !== 'deny' || $risk === null) {
                continue;
            }
            if (!self::decide($config, Obj::of(['multiplierPpm' => new Num((string)$mult)]), $risk)['ask']) {
                $mult = min(self::MAX_MULTIPLIER_PPM, $mult + $step);
            }
        }
        return ['mult' => max($mult, $start), 'seen' => $seen];
    }

    private static function lower(mixed $v): string
    {
        return is_string($v) ? strtolower($v) : "\0";
    }

    /**
     * null when what the wallet granted is within the request and the grant. $g = Obj {grantDigest, expiresAtSec}.
     * @param list<string> $allowedManagers
     * @param (callable(string): ?string)|null $contextOwner
     */
    public static function verifyGranted(mixed $g, mixed $sent, mixed $got, array $allowedManagers, ?callable $contextOwner = null): ?string
    {
        try {
            if (!($got instanceof Obj) || !($got->get('permission') instanceof Obj)) {
                return 'response_malformed';
            }
            $ctx = $got->get('context');
            if (!is_string($ctx) || preg_match('/\A0x[0-9a-fA-F]+\z/D', $ctx) !== 1) {
                return 'context_malformed';
            }
            $owner = $contextOwner === null ? null : $contextOwner($ctx);
            if ($owner !== null && $owner !== $g->get('grantDigest')) {
                return 'context_bound_to_other_grant';
            }
            $m = $got->get('delegationManager');
            if (!is_string($m) || preg_match('/\A0x[0-9a-fA-F]{40}\z/D', $m) !== 1 || !in_array(strtolower($m), array_map('strtolower', $allowedManagers), true)) {
                return 'delegation_manager_not_allowed';
            }
            if (self::lower($got->get('chainId')) !== self::lower($sent->get('chainId'))) {
                return 'chain_mismatch';
            }
            if (self::lower($got->get('to')) !== self::lower($sent->get('to'))) {
                return 'recipient_mismatch';
            }
            if ($sent->get('from') !== null && self::lower($got->get('from')) !== self::lower($sent->get('from'))) {
                return 'from_mismatch';
            }
            $perm = $got->get('permission');
            $sperm = $sent->get('permission');
            if ($perm->get('type') !== $sperm->get('type') || !in_array($perm->get('type'), ['native-token-allowance', 'erc20-token-allowance'], true)) {
                return 'permission_type_mismatch';
            }
            $d = $perm->get('data');
            if (!($d instanceof Obj)) {
                return 'response_malformed';
            }
            $sd = $sperm->get('data');
            $tok = static fn (Obj $o): string => is_string($o->get('tokenAddress')) ? strtolower($o->get('tokenAddress')) : '';
            if ($tok($d) !== $tok($sd)) {
                return 'token_mismatch';
            }
            $al = $d->get('allowance');
            if (!is_string($al) || preg_match('/\A0x(0|[1-9a-fA-F][0-9a-fA-F]*)\z/D', $al) !== 1) {
                return 'amount_malformed';
            }
            if (gmp_cmp(gmp_init(substr($al, 2), 16), gmp_init(substr((string)$sd->get('allowance'), 2), 16)) > 0) {
                return 'amount_widened';
            }
            if ($perm->get('isAdjustmentAllowed') !== $sperm->get('isAdjustmentAllowed') && $perm->get('isAdjustmentAllowed') === true) {
                return 'adjustment_widened';
            }
            $rules = $got->get('rules');
            if (!K3Sig::isList($rules)) {
                return 'expiry_missing';
            }
            $expiry = null;
            foreach ($rules as $rule) {
                if (!($rule instanceof Obj) || $rule->get('type') !== 'expiry') {
                    return 'unknown_rule_type';
                }
                if ($expiry !== null) {
                    return 'duplicate_expiry';
                }
                $ts = self::int(self::s($rule->get('data'), 'timestamp'));
                if ($ts === null) {
                    return 'expiry_malformed';
                }
                $expiry = $ts;
            }
            if ($expiry === null) {
                return 'expiry_missing';
            }
            return $expiry > (int)self::int($g->get('expiresAtSec')) ? 'expiry_extended' : null;
        } catch (\Throwable) {
            return 'response_malformed';
        }
    }
}
