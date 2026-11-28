<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/WalletPricing.php';

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\WalletPricing;
use PHPUnit\Framework\TestCase;

/** WalletPricing: limits that hold at exactly the maximum, and which signed answers may tighten the calibration. */
final class RestSurvivorKill36bWalletPricingTest extends TestCase
{
    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/wallet-pricing-36b', true);
    }

    private static function pk(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed())));
    }

    private static function config(int $cost = 100, int $max = 1000, int $step = 1000000): Obj
    {
        return WalletPricing::signPricingConfig(Obj::of(['v' => 1, 'principal' => self::pk(), 'currency' => 'USD', 'interruptionCost' => $cost,
            'maxInterruptionCost' => $max, 'hardCeilingLoss' => 1000000, 'epoch' => 1, 'tightenStepPpm' => $step]), self::seed());
    }

    /** @param array<string,mixed> $over */
    private static function answer(array $over = [], bool $sign = true): Obj
    {
        $body = Obj::of($over + ['v' => 1, 'principal' => self::pk(), 'nonce' => 'abcdefgh', 'action_digest' => 'd1', 'answer' => 'deny']);
        return $sign ? WalletPricing::signAnswer($body, self::seed()) : $body;
    }

    private static function risks(): array
    {
        return ['d1' => ['currency' => 'USD', 'loss' => 0, 'pBadUpperPpm' => 0]];
    }

    /** An interruption cost equal to its maximum and a step equal to MAX_MULTIPLIER_PPM are in range. */
    public function testLimitsHoldAtExactlyTheMaximum(): void
    {
        self::assertNull(WalletPricing::pricingConfigError(self::config(500, 500)));
        self::assertNull(WalletPricing::pricingConfigError(self::config(100, 1000, WalletPricing::MAX_MULTIPLIER_PPM)));
        self::assertSame('config_cost_above_max', WalletPricing::pricingConfigError(self::config(501, 500)));
        self::assertSame('config_step_invalid', WalletPricing::pricingConfigError(self::config(100, 1000, WalletPricing::MAX_MULTIPLIER_PPM + 1)));
    }

    /** A valid signed deny (8-character nonce) of an auto-approved action tightens by the step. */
    public function testValidDenyTightens(): void
    {
        $r = WalletPricing::updateCalibration(self::config(), WalletPricing::freshCalibration(), [self::answer()], self::risks());
        self::assertSame(['multiplierPpm' => 2000000.0, 'seen' => ['abcdefgh']], $r);
    }

    /** A signed answer with the wrong version, another principal or no signature changes nothing. */
    public function testInvalidAnswersAreIgnored(): void
    {
        foreach ([self::answer(['v' => 2]), self::answer(['principal' => 'someone-else']), self::answer([], false)] as $i => $a) {
            $r = WalletPricing::updateCalibration(self::config(), WalletPricing::freshCalibration(), [$a], self::risks());
            self::assertSame(['multiplierPpm' => 1000000.0, 'seen' => []], $r, "answer $i");
        }
    }

    /** Tightening caps the multiplier at MAX_MULTIPLIER_PPM (as a float, like every multiplier the fold returns). */
    public function testTighteningIsCapped(): void
    {
        $r = WalletPricing::updateCalibration(self::config(), ['multiplierPpm' => 99500000, 'seen' => []], [self::answer()], self::risks());
        self::assertSame(['multiplierPpm' => 100000000.0, 'seen' => ['abcdefgh']], $r);
    }

    /** A fractional stored multiplier is not a valid calibration, so a deny cannot tighten it (the reference never truncates it). */
    public function testFractionalMultiplierDoesNotTighten(): void
    {
        $r = WalletPricing::updateCalibration(self::config(), ['multiplierPpm' => 1500000.5, 'seen' => []], [self::answer()], self::risks());
        self::assertSame(['multiplierPpm' => 1500000.5, 'seen' => ['abcdefgh']], $r);
    }

    /** A malformed (fractional) seen entry is carried through without a PHP conversion notice. */
    public function testFractionalSeenEntryRaisesNoNotice(): void
    {
        $errors = [];
        set_error_handler(static function (int $no, string $msg) use (&$errors): bool {
            $errors[] = $msg;
            return true;
        });
        try {
            $r = WalletPricing::updateCalibration(self::config(), ['multiplierPpm' => 1000000, 'seen' => [1.5]], [], self::risks());
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $errors);
        self::assertSame(['multiplierPpm' => 1000000.0, 'seen' => [1.5]], $r);
    }
}
