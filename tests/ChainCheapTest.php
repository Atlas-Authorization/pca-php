<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** verifyChainCheap / holderPqKey (capability.ts): the pre-authentication necessary-condition check and the holder PQ key choke point. */
final class ChainCheapTest extends TestCase
{
    public function testCheapCheckAcceptsAGoodChainAndAgreesWithTheFullVerifier(): void
    {
        $root = new KeyPair(str_repeat("\1", 32));
        $mid = new KeyPair(str_repeat("\2", 32));
        $g = Sign::mintRoot($root, $mid->public, []);
        $c = Sign::delegate($g, $mid, KeyPair::generate()->public, []);
        self::assertSame(['ok' => true, 'pqHops' => 0], Pca::verifyChainCheap([$g, $c], $root->public));
        self::assertSame(['ok' => true, 'pqHops' => 0], Pca::verifyChainCheap([$g, $c]));
        self::assertSame('hop 0: root issuer is not the expected principal', Pca::verifyChainCheap([$g, $c], $mid->public)['reason']);
        self::assertSame('empty chain', Pca::verifyChainCheap([])['reason']);
        self::assertSame('empty chain', Pca::verifyChainCheap('x')['reason']);
        self::assertSame('hop 1: broken parent link', Pca::verifyChainCheap([$g, $g])['reason']);
        self::assertSame('chain too long (max 16 hops)', Pca::verifyChainCheap(array_fill(0, 17, $g))['reason']);
        self::assertSame('hop 0: malformed capability', Pca::verifyChainCheap([5])['reason']);
        $bad = $g->without('sig');
        $bad->set('sig', Pca::b64u(str_repeat("\0", 64)));
        self::assertSame('hop 0: bad signature (not signed by expected key)', Pca::verifyChainCheap([$bad])['reason']);
        self::assertSame("hop 0: signature suite 'ed25519' is not allowed by this verifier's suite policy", Pca::verifyChainCheap([$g], null, ['ml-dsa-65'])['reason']);
        self::assertTrue(Pca::verifyChainCheap([$g], null, ['ed25519'])['ok']);
    }

    public function testHybridHopsCountAsPqAndAreOnlyCheckedOnTheirEdHalf(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $root = new KeyPair(str_repeat("\1", 32));
        $pq = new PqKeyPair('ML-DSA-65', str_repeat("\3", 32));
        $g = Sign::mintRoot($root, KeyPair::generate()->public, [], null, 'hybrid-ed25519-ml-dsa-65', $pq);
        self::assertSame(['ok' => true, 'pqHops' => 1], Pca::verifyChainCheap([$g], $root->public));
    }

    public function testHolderPqKey(): void
    {
        $pk = Pca::b64u(str_repeat("\2", 1952));
        self::assertNull(Pca::holderPqKey(null, 'h', $pk, Pca::holderPqCommitment($pk)));
        self::assertNull(Pca::holderPqKey('ed25519', 'h', $pk, Pca::holderPqCommitment($pk)));
        self::assertNull(Pca::holderPqKey('nope', 'h', $pk, Pca::holderPqCommitment($pk)));
        self::assertNotNull(Pca::holderPqKey('ml-dsa-65', 'h', $pk, Pca::holderPqCommitment($pk)));
        self::assertNull(Pca::holderPqKey('ml-dsa-65', 'h', $pk, Pca::holderPqCommitment('other')));
        self::assertNull(Pca::holderPqKey('ml-dsa-65', 'h', $pk, null));
    }
}
