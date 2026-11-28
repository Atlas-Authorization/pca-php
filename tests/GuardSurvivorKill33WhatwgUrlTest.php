<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/WhatwgUrl.php';

use Atlas\Pca\WhatwgUrl;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/WhatwgUrl.php: the WHATWG IPv4 number parser, IPv6 compression and the opaque-host forbidden set. */
final class GuardSurvivorKill33WhatwgUrlTest extends TestCase
{
    public function testIpv4Hosts(): void
    {
        $this->assertSame('0.0.0.0', WhatwgUrl::domainToASCII('0x'));              // a bare 0x prefix is the number 0
        $this->assertSame('0.0.0.1', WhatwgUrl::domainToASCII('0000000000000001')); // leading zeros never count toward the size cap
        $this->assertSame('0.0.0.1', WhatwgUrl::domainToASCII('1.'));              // a trailing dot is dropped before the number test
        $this->assertSame('255.0.0.1', WhatwgUrl::domainToASCII('255.0.0.1'));     // 255 is a valid leading part
        $this->assertSame('', WhatwgUrl::domainToASCII('256.0.0.1'));              // control: 256 is not
    }

    public function testIpv6Compression(): void
    {
        $h = static fn(string $u): ?string => WhatwgUrl::parse($u)['host'] ?? null;
        $this->assertSame('[1::2:3:4:5:6]', $h('http://[1:0:0:2:3:4:5:6]/'));   // a run of two zeros compresses
        $this->assertSame('[1::2:0:0:3:4]', $h('http://[1:0:0:2:0:0:3:4]/'));   // of two equal runs the first compresses
        $this->assertSame('[1:0:2:3:4:5:6:7]', $h('http://[1:0:2:3:4:5:6:7]/')); // a single zero never does
    }

    public function testOpaqueHostRefusesForbiddenCodePoints(): void
    {
        $this->assertNull(WhatwgUrl::parse('foo://a<b/'));
        $this->assertSame('ab', WhatwgUrl::parse('foo://ab/')['host'], 'control');
    }
}
