<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\CaveatLang;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** dischargeRequests (caveat-lang.ts): one request per well-formed needs_discharge caveat of the leaf. */
final class DischargeRequestsTest extends TestCase
{
    private function caveat(string $id, string $bind): Obj
    {
        return Json::parseLax('{"type":"needs_discharge","id":"' . $id . '","issuer":"bank","issuer_class":"org","bind":"' . $bind . '","ttl_ms":60000,"require":[{"claim":"kyc","op":"eq","value":"ok"}]}');
    }

    public function testOneRequestPerNeedsDischargeCaveat(): void
    {
        $g = Sign::mintRoot(KeyPair::generate(), KeyPair::generate()->public, [$this->caveat('c1', 'chain_hop'), $this->caveat('c2', 'action'), ['type' => 'budget_alloc', 'limit' => 5]]);
        $r = CaveatLang::dischargeRequests($g, null, 'dig');
        self::assertCount(2, $r);
        self::assertSame(['v', 'kind', 'caveat_id', 'issuer', 'cap_hash', 'bind', 'require', 'ttl_ms'], $r[0]->keys());
        self::assertSame('c1', $r[0]->get('caveat_id'));
        self::assertSame(['v', 'kind', 'caveat_id', 'issuer', 'cap_hash', 'bind', 'action_digest', 'require', 'ttl_ms'], $r[1]->keys());
        self::assertSame('dig', $r[1]->get('action_digest'));
        self::assertArrayNotHasKey('action_digest', array_flip(CaveatLang::dischargeRequests($g, null, null)[1]->keys()));
        self::assertSame(\Atlas\Pca\Pca::capHash($g), $r[0]->get('cap_hash'));
    }

    public function testMalformedNeedsDischargeIsSkipped(): void
    {
        $bad = Json::parseLax('{"type":"needs_discharge","id":"c1"}');
        $g = Sign::mintRoot(KeyPair::generate(), KeyPair::generate()->public, [$bad]);
        self::assertSame([], CaveatLang::dischargeRequests($g, null, null));
    }
}
