<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetLaunch;
use PHPUnit\Framework\TestCase;

/** The bind-first port line a node prints, read in any key order and refused when malformed (parsed in-process so mutation tools see it). */
final class MpcNetLaunchPortTest extends TestCase
{
    public function testAcceptsEitherKeyOrder(): void
    {
        $this->assertSame(4321, MpcNetLaunch::parseListening("{\"id\":0,\"listening\":4321}\n", 0));
        $this->assertSame(4321, MpcNetLaunch::parseListening("{\"listening\":4321,\"id\":0}\n", 0));
        $this->assertSame(1, MpcNetLaunch::parseListening("{\"listening\":1}\n", 3));
        $this->assertSame(65535, MpcNetLaunch::parseListening("{\"listening\":65535}\n", 3));
    }

    public function testRefusesBadValues(): void
    {
        foreach (['"5"', '0', '65536', '-1', '5.5', '5.0', 'true', 'null', '[5]'] as $v) {
            $this->assertNull(MpcNetLaunch::parseListening("{\"listening\":$v}\n", 0), $v);
        }
        $this->assertNull(MpcNetLaunch::parseListening("not json\n5\n[]\n", 0));
    }

    public function testAnIdMismatchIsIgnoredAndALaterLineStillCounts(): void
    {
        $this->assertNull(MpcNetLaunch::parseListening("{\"id\":1,\"listening\":4321}\n", 0));
        $this->assertNull(MpcNetLaunch::parseListening("{\"id\":\"0\",\"listening\":4321}\n", 0));
        $this->assertSame(7, MpcNetLaunch::parseListening("{\"id\":1,\"listening\":4321}\nbanner\n{\"id\":0,\"listening\":7}\n", 0));
    }

    public function testAPartialLastLineIsNotYetAPort(): void
    {
        $this->assertNull(MpcNetLaunch::parseListening("{\"id\":0,\"listening\":4321}", 0));
        $this->assertNull(MpcNetLaunch::parseListening('', 0));
        $this->assertSame(4321, MpcNetLaunch::parseListening("{\"id\":0,\"listening\":4321}\n{\"ok\":tr", 0));
    }
}
