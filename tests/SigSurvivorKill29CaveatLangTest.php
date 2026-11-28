<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\CaveatLang;
use Atlas\Pca\ChainView;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Mutation kills for CaveatLang: the hop of a caveat no hop introduced, and dischargeRequests skipping (not stopping at) other caveats. */
final class SigSurvivorKill29CaveatLangTest extends TestCase
{
    /** A caller-supplied view whose hops report no caveats: the leaf's caveats are attributed to the last hop. */
    private static function view(array $caveats): ChainView
    {
        return new ChainView(2, Obj::of(['caveats' => $caveats]), static fn (int $i): string => "h$i", static fn (int $i): int => 0);
    }

    private static function needsDischarge(string $id): Obj
    {
        return Json::parseLax('{"type":"needs_discharge","id":"' . $id . '","issuer":"bank","issuer_class":"org","bind":"chain_hop","ttl_ms":60000,'
            . '"require":[{"claim":"kyc","op":"eq","value":"ok"}]}');
    }

    public function testAnUnattributedCaveatBelongsToTheLastHop(): void
    {
        $b = CaveatLang::boundCaveats(null, self::view(['x']));
        $this->assertSame([['caveat' => 'x', 'hop' => 1, 'cap_hash' => 'h1']], $b);
    }

    public function testDischargeRequestsSkipOtherCaveats(): void
    {
        $r = CaveatLang::dischargeRequests(null, self::view(['x', Obj::of(['type' => 'budget_alloc']), self::needsDischarge('c1')]), null);
        $this->assertCount(1, $r);
        $this->assertSame('c1', $r[0]->get('caveat_id'));
        $this->assertSame('h1', $r[0]->get('cap_hash'));
    }
}
