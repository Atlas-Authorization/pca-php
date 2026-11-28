<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentMap;
use Atlas\Pca\IntentV2;
use PHPUnit\Framework\TestCase;

/** Group 30b mutation kill for src/IntentMap.php: both ends of commitMap's leaf-count bound, inclusive. */
final class IntentSurvivorKill30bIntentMapTest extends TestCase
{
    public function testLeafCountBounds(): void
    {
        $this->assertFalse(IntentMap::leafCountOk(3));
        $this->assertTrue(IntentMap::leafCountOk(4));
        $this->assertTrue(IntentMap::leafCountOk(IntentV2::MAX_MAP_LEAVES));
        $this->assertFalse(IntentMap::leafCountOk(IntentV2::MAX_MAP_LEAVES + 1));
        $this->assertTrue(IntentMap::leafCountOk(5, 5));
        $this->assertFalse(IntentMap::leafCountOk(6, 5));
    }
}
