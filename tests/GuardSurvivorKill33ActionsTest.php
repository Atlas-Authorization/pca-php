<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Actions.php: traitObj is part of the public surface (the JSON form of a registry trait). */
final class GuardSurvivorKill33ActionsTest extends TestCase
{
    public function testTraitObjIsPublicAndCarriesTheTrait(): void
    {
        $reg = Actions::coreRegistry();
        $t = reset($reg);
        $this->assertIsArray($t);
        $o = Actions::traitObj($t);
        $this->assertSame(['id', 'implies', 'floor', 'card_phrase'], $o->keys());
        $this->assertSame([$t['id'], $t['implies'], $t['card_phrase']], [$o->get('id'), $o->get('implies'), $o->get('card_phrase')]);
        $this->assertSame($t['floor']['rev'], $o->get('floor')->get('rev'));
    }
}
