<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Wallet.php';
require_once __DIR__ . '/WalletOmega.php';

/**
 * Risk-priced escalation of the wallet: ask a human iff pBadUpper * loss > interruptionCost, in integer arithmetic (probabilities in
 * ppm, money in minor units; no floats, no randomness, no clock; the products need ext-gmp). Every input is explicit and comes from a
 * principal-SIGNED configuration; anything missing, out of range or unsigned means ASK. The only learned component is a per-principal
 * multiplier that scales P(bad) UP, so it can only add asks; asking less needs a principal-signed autonomy raise. Signing needs the
 * principal's 32-byte Ed25519 seed (the reference's pca-wallet escalation-pricing).
 */
final class WalletPricing
{
    public const PPM = 1000000;
    public const MAX_MULTIPLIER_PPM = 100 * self::PPM;

    private static function isMinor(mixed $n): bool
    {
        return WalletOmega::isSafeInt($n) && Js::num($n) >= 0;
    }

    private static function negZero(mixed $n): bool
    {
        $f = Js::num($n);
        return $f !== null && $f === 0.0 && fdiv(1.0, $f) < 0;
    }

    private static function isOne(mixed $v): bool
    {
        return Js::isNum($v) && Js::num($v) === 1.0;
    }

    private static function msg(string $kind, mixed $body): string
    {
        return Pca::hashCanonical(Obj::of(['kind' => $kind, 'body' => $body]));
    }

    private static function secretKey(string $seed): string
    {
        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
    }

    private static function sig(string $secret, string $kind, mixed $body): string
    {
        return Pca::b64u(sodium_crypto_sign_detached(self::msg($kind, $body), self::secretKey($secret)));
    }

    private static function unb(mixed $s): string
    {
        $raw = Pca::unb64u($s);
        if ($raw === null) {
            throw new \InvalidArgumentException('bad base64url');
        }
        return $raw;
    }

    private static function verify(mixed $principal, string $kind, mixed $body, mixed $sig): bool
    {
        $pk = self::unb($principal);
        $sg = self::unb($sig);
        if (strlen($pk) !== 32 || strlen($sg) !== 64) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sg, self::msg($kind, $body), $pk);
        } catch (\SodiumException) {
            return false;
        }
    }

    /** A copy of a dict without the `sig` member. */
    private static function withoutSig(mixed $o): Obj
    {
        $out = new Obj();
        foreach (Wallet::dictKeys($o) as $k) {
            if ($k !== 'sig') {
                $out->set($k, Js::opt($o, $k));
            }
        }
        return $out;
    }

    private static function copyWith(mixed $o, string $k, mixed $v): Obj
    {
        $out = new Obj();
        foreach (Wallet::dictKeys($o) as $key) {
            $out->set($key, Js::opt($o, $key));
        }
        $out->set($k, $v);
        return $out;
    }

    public static function signPricingConfig(mixed $body, string $principalSecret): Obj
    {
        return self::copyWith($body, 'sig', self::sig($principalSecret, 'pca.escalation_pricing', $body));
    }

    /** Why a signed pricing configuration is refused, or null (a pure function of its content). */
    public static function pricingConfigError(mixed $c): ?string
    {
        try {
            if (!Wallet::isDict($c)) {
                return 'config_malformed';
            }
            if (!self::isOne(Js::opt($c, 'v')) || !is_string(Js::opt($c, 'principal')) || !is_string(Js::opt($c, 'currency')) || !is_string(Js::opt($c, 'sig'))) {
                return 'config_malformed';
            }
            if (!(self::isMinor(Js::opt($c, 'interruptionCost')) && self::isMinor(Js::opt($c, 'maxInterruptionCost'))
                && self::isMinor(Js::opt($c, 'hardCeilingLoss')) && self::isMinor(Js::opt($c, 'epoch')))) {
                return 'config_amounts_invalid';
            }
            if (Js::num(Js::opt($c, 'interruptionCost')) > Js::num(Js::opt($c, 'maxInterruptionCost'))) {
                return 'config_cost_above_max';
            }
            $step = Js::opt($c, 'tightenStepPpm');
            if (!WalletOmega::isSafeInt($step) || Js::num($step) < 0 || Js::num($step) > self::MAX_MULTIPLIER_PPM) {
                return 'config_step_invalid';
            }
            return self::verify(Js::opt($c, 'principal'), 'pca.escalation_pricing', self::withoutSig($c), Js::opt($c, 'sig')) ? null : 'config_signature_invalid';
        } catch (\Throwable) { // any decoding or hashing failure is a malformed configuration
            return 'config_malformed';
        }
    }

    public static function freshCalibration(): array
    {
        return ['multiplierPpm' => self::PPM, 'seen' => []];
    }

    /**
     * Pure and total: ['ask' => bool, 'reason' => string]. Anything unverifiable or out of range asks.
     * @return array{ask:bool,reason:string}
     */
    public static function decideEscalation(mixed $config, mixed $cal, mixed $a): array
    {
        $e = self::pricingConfigError($config);
        if ($e !== null) {
            return ['ask' => true, 'reason' => $e];
        }
        if (!Wallet::isDict($a) || Js::opt($a, 'currency') !== Js::opt($config, 'currency')) {
            return ['ask' => true, 'reason' => 'currency_mismatch'];
        }
        $loss = Js::opt($a, 'loss');
        $p = Js::opt($a, 'pBadUpperPpm');
        if (!self::isMinor($loss) || self::negZero($loss) || !WalletOmega::isSafeInt($p) || Js::num($p) < 0 || self::negZero($p) || Js::num($p) > self::PPM) {
            return ['ask' => true, 'reason' => 'risk_input_invalid'];
        }
        $mult = Wallet::isDict($cal) ? Js::opt($cal, 'multiplierPpm') : null;
        if (!(WalletOmega::isSafeInt($mult) && Js::num($mult) >= self::PPM && Js::num($mult) <= self::MAX_MULTIPLIER_PPM)) {
            return ['ask' => true, 'reason' => 'calibration_invalid'];
        }
        if (Js::num($loss) > Js::num(Js::opt($config, 'hardCeilingLoss'))) {
            return ['ask' => true, 'reason' => 'above_hard_ceiling'];
        }
        $ppm2 = gmp_mul(self::PPM, self::PPM);
        $pe = gmp_mul((int)Js::num($p), (int)Js::num($mult));
        $capped = gmp_cmp($pe, $ppm2) > 0 ? $ppm2 : $pe;
        $lhs = gmp_mul($capped, (int)Js::num($loss));
        $rhs = gmp_mul(gmp_mul((int)Js::num(Js::opt($config, 'interruptionCost')), self::PPM), self::PPM);
        if (gmp_cmp($lhs, $rhs) > 0) {
            return ['ask' => true, 'reason' => 'expected_loss_exceeds_interruption_cost'];
        }
        return ['ask' => false, 'reason' => 'expected_loss_within_interruption_cost'];
    }

    public static function signAnswer(mixed $body, string $principalSecret): Obj
    {
        return self::copyWith($body, 'sig', self::sig($principalSecret, 'pca.escalation_answer', $body));
    }

    private static function answerOk(mixed $a, mixed $principal): bool
    {
        try {
            if (!Wallet::isDict($a) || !self::isOne(Js::opt($a, 'v')) || Js::opt($a, 'principal') !== $principal) {
                return false;
            }
            $nonce = Js::opt($a, 'nonce');
            $ad = Js::opt($a, 'action_digest');
            if (!is_string($nonce) || Js::len($nonce) < 8 || !is_string($ad) || !in_array(Js::opt($a, 'answer'), ['approve', 'deny'], true)) {
                return false;
            }
            return self::verify($principal, 'pca.escalation_answer', self::withoutSig($a), Wallet::req($a, 'sig'));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Fold signed answers into the calibration. A DENY the principal gave to an action that the CURRENT pricing would have
     * auto-approved is a miss and adds `tightenStepPpm` (capped); anything else changes nothing. The multiplier never decreases.
     * `$risks` maps an action digest to its risk input.
     */
    public static function updateCalibration(mixed $config, mixed $cal, mixed $answers, mixed $risks): mixed
    {
        if (self::pricingConfigError($config) !== null) {
            return $cal;
        }
        $mult = Wallet::reqNum($cal, 'multiplierPpm');
        $seen = [];
        $order = [];
        foreach (Wallet::req($cal, 'seen') as $s) {
            $seen[(string)$s] = true;
            $order[] = $s;
        }
        foreach ($answers as $a) {
            if (!self::answerOk($a, Js::opt($config, 'principal')) || isset($seen[(string)Js::opt($a, 'nonce')])) {
                continue;
            }
            $seen[(string)Js::opt($a, 'nonce')] = true;
            $order[] = Js::opt($a, 'nonce');
            $digest = (string)Js::opt($a, 'action_digest');
            $risk = Js::has($risks, $digest) ? Js::opt($risks, $digest) : Jsx::$U;
            if (Js::opt($a, 'answer') !== 'deny' || $risk instanceof Undef) {
                continue;
            }
            if (!self::decideEscalation($config, ['multiplierPpm' => (int)$mult, 'seen' => []], $risk)['ask']) {
                $mult = min((float)self::MAX_MULTIPLIER_PPM, $mult + Wallet::reqNum($config, 'tightenStepPpm'));
            }
        }
        return ['multiplierPpm' => max($mult, Wallet::reqNum($cal, 'multiplierPpm')), 'seen' => $order];
    }

    public static function signAutonomyRaise(mixed $b, string $secret): Obj
    {
        return self::copyWith($b, 'sig', self::sig($secret, 'pca.autonomy_raise', $b));
    }

    /**
     * A higher interruption cost means fewer asks. Needs the principal's signature, a strictly newer epoch and a cost within
     * `maxInterruptionCost`; throws otherwise.
     */
    public static function applyAutonomyRaise(mixed $config, mixed $raise, string $principalSecret): Obj
    {
        $ok = false;
        try {
            $ok = self::isOne(Js::opt($raise, 'v')) && Js::opt($raise, 'principal') === Wallet::req($config, 'principal')
                && self::verify(Wallet::req($config, 'principal'), 'pca.autonomy_raise', self::withoutSig($raise), Wallet::req($raise, 'sig'));
        } catch (\Throwable) {
            $ok = false;
        }
        if (!$ok) {
            throw new \InvalidArgumentException('applyAutonomyRaise: signature or principal invalid');
        }
        if (!(Wallet::reqNum($raise, 'epoch') > Wallet::reqNum($config, 'epoch'))) {
            throw new \InvalidArgumentException('applyAutonomyRaise: epoch must advance');
        }
        $cost = Js::opt($raise, 'newInterruptionCost');
        if (!self::isMinor($cost) || Js::num($cost) > Wallet::reqNum($config, 'maxInterruptionCost')) {
            throw new \InvalidArgumentException('applyAutonomyRaise: above the configured maximum');
        }
        $body = self::withoutSig($config);
        $body->set('interruptionCost', $cost);
        $body->set('epoch', Js::opt($raise, 'epoch'));
        return self::signPricingConfig($body, $principalSecret);
    }
}
