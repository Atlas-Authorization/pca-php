<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ChainCompact.php';
require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\CaveatLang;
use Atlas\Pca\ChainCompact;
use Atlas\Pca\ChainMemo;
use Atlas\Pca\ChainView;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** chain-compact.ts: the hop Merkle root, compact shape check, the verifier memo and the ChainView it feeds the caveat language. */
final class ChainCompactTest extends TestCase
{
    private KeyPair $root;
    /** @var list<Obj> */
    private array $chain;

    protected function setUp(): void
    {
        $this->root = new KeyPair(str_repeat("\1", 32));
        $mid = new KeyPair(str_repeat("\2", 32));
        $leaf = new KeyPair(str_repeat("\3", 32));
        $g = Sign::mintRoot($this->root, $mid->public, [Obj::of(['type' => 'delegation_depth', 'max' => new Num('5')])]);
        $c = Sign::delegate($g, $mid, $leaf->public, [Obj::of(['type' => 'delegation_depth', 'max' => new Num('4')])]);
        $this->chain = [$g, $c];
    }

    public function testCompactFoldsAndShapeCheck(): void
    {
        $c = ChainCompact::compactChain($this->chain);
        self::assertSame(['v', 'kind', 'depth', 'hops_root', 'leaf'], $c->keys());
        self::assertSame(ChainCompact::hopsRoot($this->chain), $c->get('hops_root'));
        self::assertSame(43, strlen($c->get('hops_root')));
        self::assertNull(ChainCompact::compactChainShapeError($c));
        self::assertNotSame(ChainCompact::hopsRoot($this->chain), ChainCompact::hopsRoot(array_reverse($this->chain)));
        self::assertNotSame(ChainCompact::hopsRoot($this->chain), ChainCompact::hopsRoot([$this->chain[0]]));
        self::assertSame('not an object', ChainCompact::compactChainShapeError(5));
        foreach ([[], array_fill(0, 17, $this->chain[0])] as $bad) {
            try {
                ChainCompact::compactChain($bad);
                self::fail('1..16 hops');
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        $d = Obj::of(['v' => $c->get('v'), 'kind' => $c->get('kind'), 'depth' => new Num('17'), 'hops_root' => $c->get('hops_root'), 'leaf' => $c->get('leaf')]);
        self::assertSame('depth must be 1..16', ChainCompact::compactChainShapeError($d));
        $k = Obj::of(['v' => $c->get('v'), 'kind' => 'x', 'depth' => $c->get('depth'), 'hops_root' => $c->get('hops_root'), 'leaf' => $c->get('leaf')]);
        self::assertSame('not a pca-chain-compact v1', ChainCompact::compactChainShapeError($k));
    }

    public function testMemoResolveGivesAViewThatMatchesTheFullChain(): void
    {
        $memo = new ChainMemo();
        $compact = $memo->rememberVerified($this->chain, $this->root->public, 1000);
        self::assertSame(1, $memo->size());
        $r = $memo->resolve($compact, 2000);
        self::assertTrue($r['ok']);
        $full = CaveatLang::chainView($this->chain[1], $this->chain);
        self::assertSame($full->n, $r['view']->n);
        for ($i = 0; $i < $full->n; $i++) {
            self::assertSame($full->hash($i), $r['view']->hash($i));
            self::assertSame($full->count($i), $r['view']->count($i));
        }
        self::assertEquals(CaveatLang::boundCaveats($this->chain[1], $this->chain), CaveatLang::boundCaveats($this->chain[1], $r['view']));
        self::assertSame($r['view'], CaveatLang::chainView(null, $r['view']));
        self::assertInstanceOf(ChainView::class, ChainCompact::viewOfChain($this->chain[1], $this->chain));
    }

    public function testMemoFailsClosed(): void
    {
        $memo = new ChainMemo(1, 10);
        try {
            $memo->rememberVerified($this->chain, Pca::b64u(str_repeat("\9", 32)), 1000);
            self::fail('a chain that does not verify is not remembered');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('does not verify', $e->getMessage());
        }
        self::assertSame(0, $memo->size());
        $compact = $memo->rememberVerified($this->chain, $this->root->public, 1000);
        $other = new ChainMemo();
        self::assertFalse($other->resolve($compact, 1000)['ok']);
        self::assertTrue($memo->resolve($compact, 1010)['ok']);
        self::assertSame('the memoized chain has expired (present the full chain)', $memo->resolve($compact, 1011)['reason']);
        self::assertSame(0, $memo->size());
        $compact = $memo->rememberVerified($this->chain, $this->root->public, 5000);
        try {
            $memo->rememberVerified([$this->chain[0]], $this->root->public, 5001);
            self::fail('a full memo never evicts a live entry');
        } catch (\RuntimeException) {
            self::assertTrue(true);
        }
        $bad = Obj::of(['v' => $compact->get('v'), 'kind' => $compact->get('kind'), 'depth' => $compact->get('depth'), 'hops_root' => $compact->get('hops_root'), 'leaf' => $this->chain[0]]);
        self::assertSame('the leaf is not the memoized last hop', $memo->resolve($bad, 5001)['reason']);
        self::assertTrue($memo->forget($compact->get('hops_root')));
        self::assertFalse($memo->forget($compact->get('hops_root')));
        self::assertFalse($memo->resolve($compact, 5001)['ok']);
    }
}
