<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Erc7715;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Mutation kills for Erc7715: chainId coercion, array options, list-shaped wallet fields, lowercasing, and the grant-expiry bound. */
final class SigSurvivorKill29Erc7715Test extends TestCase
{
    private const SESSION = '0x1111111111111111111111111111111111111111';
    private const FROM = '0x2222222222222222222222222222222222222222';
    private const MGR = '0x3333333333333333333333333333333333333333';
    private const G = ['grantDigest' => 'gd1', 'capMinor' => 1000, 'expiresAtSec' => 1_800_086_400];

    protected function tearDown(): void
    {
        Erc7715::$functionHook = null;
    }

    private static function opts(array $extra = []): array
    {
        return $extra + ['sessionAccount' => self::SESSION, 'baseUnitsPerMinor' => '1', 'chainId' => 1];
    }

    private static function req(): array
    {
        return Erc7715::grantToPermissionRequest(self::G, self::opts());
    }

    private static function got(array $set = []): array
    {
        $r = self::req();
        return $set + ['permission' => $r['permission'], 'context' => '0xab', 'delegationManager' => self::MGR, 'chainId' => $r['chainId'],
            'to' => self::SESSION, 'rules' => $r['rules']];
    }

    private static function supported(array $entry): Obj
    {
        return Obj::of(['native-token-allowance' => Obj::of($entry + ['chainIds' => ['0x1'], 'ruleTypes' => ['expiry']])]);
    }

    private function threw(string $class, string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class);
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected $class: $message");
    }

    /** chainId may be an int, a decimal string or a GMP; anything else (a float, a non-numeric string) is a TypeError by name. */
    public function testChainIdCoercion(): void
    {
        $this->assertSame('0x5', Erc7715::grantToPermissionRequest(self::G, self::opts(['chainId' => gmp_init(5)]))['chainId']);
        $this->assertSame('0x5', Erc7715::grantToPermissionRequest(self::G, self::opts(['chainId' => '5']))['chainId']);
        $msg = 'grantToPermissionRequest: chainId must be an integer';
        $this->threw(\TypeError::class, $msg, fn () => Erc7715::grantToPermissionRequest(self::G, self::opts(['chainId' => 1.5])));
        $this->threw(\TypeError::class, $msg, fn () => Erc7715::grantToPermissionRequest(self::G, self::opts(['chainId' => 'abc'])));
    }

    /** Options as a PHP assoc array: `from` is read only when present. */
    public function testArrayOptionsAndFrom(): void
    {
        $r = self::req();
        $this->assertSame(['chainId', 'to', 'permission', 'rules'], array_keys($r));
        $f = Erc7715::grantToPermissionRequest(self::G, self::opts(['from' => self::FROM]));
        $this->assertSame(['chainId', 'from', 'to', 'permission', 'rules'], array_keys($f));
        $this->assertSame(self::FROM, $f['from']);
    }

    /** chainIds, rules and ruleTypes must be lists: an assoc array never satisfies a request. */
    public function testWalletFieldsMustBeLists(): void
    {
        $r = self::req();
        $this->assertTrue(Erc7715::supportsRequest(self::supported([]), $r), 'control');
        $this->assertFalse(Erc7715::supportsRequest(self::supported(['chainIds' => ['a' => '0x1']]), $r));
        $this->assertFalse(Erc7715::supportsRequest(self::supported(['ruleTypes' => ['a' => 'expiry']]), $r));
        $assocRules = $r;
        $assocRules['rules'] = ['a' => $r['rules'][0]];
        $this->assertFalse(Erc7715::supportsRequest(self::supported([]), $assocRules));
    }

    /** Lowercasing is Unicode-aware with mbstring and plain ASCII lowercasing without it. */
    public function testLowercasing(): void
    {
        $r = self::req();
        $r['chainId'] = '0XABC';
        $this->assertTrue(Erc7715::supportsRequest(self::supported(['chainIds' => ['0xabc']]), $r));
        Erc7715::$functionHook = static fn (string $f): bool => false;
        $this->assertTrue(Erc7715::supportsRequest(self::supported(['chainIds' => ['0xabc']]), $r), 'the ASCII fallback still lowercases');
        $r['chainId'] = 'É';
        $this->assertFalse(Erc7715::supportsRequest(self::supported(['chainIds' => ['é']]), $r), 'the ASCII fallback leaves non-ASCII alone');
        Erc7715::$functionHook = null;
        if (function_exists('mb_strtolower')) {
            $this->assertTrue(Erc7715::supportsRequest(self::supported(['chainIds' => ['é']]), $r), 'as String#toLowerCase');
        }
    }

    /** The trusted managers must be a list; a granted expiry is bounded only by a safe-integer grant expiry. */
    public function testVerifyGrantedPermissionBounds(): void
    {
        $ok = ['allowedManagers' => [self::MGR]];
        $this->assertNull(Erc7715::verifyGrantedPermission(self::G, self::req(), self::got(), $ok), 'control');
        $this->assertSame('response_malformed', Erc7715::verifyGrantedPermission(self::G, self::req(), self::got(), ['allowedManagers' => ['a' => self::MGR]]));
        $early = self::got(['rules' => [['type' => 'expiry', 'data' => ['timestamp' => 1]]]]);
        $this->assertNull(Erc7715::verifyGrantedPermission(self::G, self::req(), $early, $ok), 'control');
        $this->assertSame('expiry_extended', Erc7715::verifyGrantedPermission(['grantDigest' => 'gd1', 'expiresAtSec' => 1.5], self::req(), $early, $ok));
    }
}
