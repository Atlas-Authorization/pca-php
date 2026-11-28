<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/../src/K4.php';

use Atlas\Pca\Json;
use Atlas\Pca\K4;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/K4.php: a grant expiry that is a number but not a safe integer bounds nothing. */
final class GuardSurvivorKill33K4Test extends TestCase
{
    private const MGR = '0xabababababababababababababababababababab';

    private static function o(array $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    private static function granted(mixed $grantExpiry, int $ts): ?string
    {
        $perm = ['type' => 'erc20-token-allowance', 'isAdjustmentAllowed' => true,
            'data' => ['tokenAddress' => '0x2222222222222222222222222222222222222222', 'allowance' => '0x989680']];
        $base = ['chainId' => '0x2105', 'to' => '0x1111111111111111111111111111111111111111', 'permission' => $perm,
            'rules' => [['type' => 'expiry', 'data' => ['timestamp' => $ts]]]];
        $got = $base + ['context' => '0xabc123', 'dependencies' => [], 'delegationManager' => self::MGR];
        return K4::verifyGranted(self::o(['grantDigest' => 'gd1', 'expiresAtSec' => $grantExpiry]), self::o($base), self::o($got), [self::MGR],
            static fn (string $c): ?string => $c === '0xabc123' ? 'gd1' : null);
    }

    /** A fractional grant expiry is not a safe integer: even an expiry before the epoch is refused as extended. */
    public function testFractionalGrantExpiryBoundsNothing(): void
    {
        $this->assertNull(self::granted(0, -5), 'control: an integer grant expiry bounds the granted one');
        $this->assertSame('expiry_extended', self::granted(1.5, -5));
        $this->assertSame('expiry_extended', self::granted(1.5, 0));
    }
}
