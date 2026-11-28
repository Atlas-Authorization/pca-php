<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\JsonError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Passport;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/Passport.php: the fingerprint guard, the clock-skew coercion, scalar equality and the binding allowlists. */
final class CoreSurvivorKill1PassportTest extends TestCase
{
    private const T = 1800000000000;

    private static function signed(): Obj
    {
        $pp = Sign::issuePassport(['model_id' => 'm', 'operator' => 'op', 'hardware_rooted' => false]);
        return Sign::signPassport($pp, new KeyPair(str_repeat("\x01", 32)), (new KeyPair(str_repeat("\x02", 32)))->public, self::T + 60000, self::T);
    }

    private static function opts(array $over): array
    {
        return $over + ['trustedIssuers' => [(new KeyPair(str_repeat("\x01", 32)))->public], 'now' => self::T, 'revocation' => static fn() => false];
    }

    /** A passport without hardware_rooted has no fingerprint (an undefined member does not canonicalize). */
    public function testFingerprintNeedsHardwareRooted(): void
    {
        try {
            Passport::fingerprint(Obj::of(['model_id' => 'm', 'operator' => 'op']));
            self::fail('expected JsonError');
        } catch (JsonError $e) {
            self::assertSame('canonicalize: unsupported type undefined', $e->getMessage());
        }
    }

    /** A non-number, non-string skew is no skew (0); a float skew is a real tolerance. Both at exactly exp. */
    public function testSkewCoercion(): void
    {
        $atExp = self::T + 60000;
        self::assertSame(['ok' => false, 'reason' => 'expired'], Passport::verify(self::signed(), self::opts(['now' => $atExp, 'clockSkewMs' => true])));
        self::assertTrue(Passport::verify(self::signed(), self::opts(['now' => $atExp, 'clockSkewMs' => 1000.0]))['ok']);
    }

    /** Numbers compare by value: equal is in the list, unequal is not. */
    public function testNumericAllowlistMembership(): void
    {
        self::assertSame(['ok' => true, 'reasons' => []], Passport::matchesBinding(['model_id' => 5], ['model_allowlist' => [5]]));
        self::assertSame(['ok' => false, 'reasons' => ["model_id '6' not in allowlist"]], Passport::matchesBinding(['model_id' => 6], ['model_allowlist' => [5]]));
    }

    /** null equals null; a list never equals anything, not even an equal list. */
    public function testScalarEquality(): void
    {
        self::assertSame(['ok' => true, 'reasons' => []], Passport::matchesBinding(['operator' => null], ['operator' => null]));
        self::assertSame(['ok' => false, 'reasons' => ["operator 'x' != required 'x'"]], Passport::matchesBinding(['operator' => ['x']], ['operator' => ['x']]));
    }

    /** An allowlist that is not a list is refused with its own TypeError. */
    public function testObjectAllowlistIsRefused(): void
    {
        try {
            Passport::trustScore(['operator' => 'x'], ['knownOperators' => ['a' => 'x']]);
            self::fail('expected TypeError');
        } catch (\TypeError $e) {
            self::assertSame('allowlist is not a list', $e->getMessage());
        }
    }

    /** A truthy model allowlist that is neither a string nor a non-empty list is ignored. */
    public function testNonListModelAllowlistIsIgnored(): void
    {
        self::assertSame(['ok' => true, 'reasons' => []], Passport::matchesBinding(['model_id' => 'm'], ['model_allowlist' => true]));
    }

    /** min_measurement as a one-member PHP object array {svn: n}. */
    public function testMinMeasurementAsAssocArray(): void
    {
        self::assertSame(['ok' => true, 'reasons' => []], Passport::matchesBinding(['runtime_measurement' => '5'], ['min_measurement' => ['svn' => 5]]));
        self::assertSame(['ok' => true, 'reasons' => []], Passport::matchesBinding(['runtime_measurement' => '0'], ['min_measurement' => ['svn' => 0]]));
    }
}
