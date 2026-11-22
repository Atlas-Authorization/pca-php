<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Refusals;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Refusals::explainRefusal: the leading-name lookup, the embedded `name:` fallback and its order. */
final class K05KillRefusalsTest extends TestCase
{
    public function testLeadingNameWithoutAColonIsFoundByTheHead(): void
    {
        // no `replay:` in the text: only the anchored head lookup finds it
        $this->assertSame('replay', Refusals::explainRefusal('replay')['check']);
        $this->assertSame('grant_ref_bound', Refusals::explainRefusal('grant_ref_bound')['check']);
    }

    public function testTheHeadIsAnchoredAtTheStart(): void
    {
        $this->assertSame('unknown', Refusals::explainRefusal('1replay')['check']);
    }

    public function testTheFallbackNeedsTheColon(): void
    {
        $this->assertSame('unknown', Refusals::explainRefusal('denied by replay')['check']);
    }

    public function testTheFallbackTakesTheFirstTableRow(): void
    {
        // both `audience:` and `replay:` appear; the table lists audience first
        $this->assertSame('audience', Refusals::explainRefusal('x replay: a audience: b')['check']);
    }
}
