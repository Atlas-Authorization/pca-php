<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ChainCompact.php';
require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\ChainCompact;
use Atlas\Pca\ChainMemo;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/ChainCompact.php: chain shape refusals, rememberVerified's refusal texts, prune's boundary and resolve's fail-closed answers. */
final class GuardSurvivorKill33ChainCompactTest extends TestCase
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
        $this->chain = [$g, Sign::delegate($g, $mid, $leaf->public, [Obj::of(['type' => 'delegation_depth', 'max' => new Num('4')])])];
    }

    /** A non-array or a non-list chain is refused with the shape error, never folded. */
    public function testCompactChainRefusesNonListShapes(): void
    {
        foreach (['x', [1 => $this->chain[0]], ['a' => $this->chain[0], 'b' => $this->chain[1]]] as $bad) {
            try {
                ChainCompact::compactChain($bad);
                $this->fail('a non-list chain was folded');
            } catch (\InvalidArgumentException $e) {
                $this->assertSame('compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops', $e->getMessage());
            }
        }
    }

    /** A depth that is a plain PHP number (not a JSON Num) is a shape error, not a crash. */
    public function testPlainNumberDepthIsAShapeError(): void
    {
        $c = ChainCompact::compactChain($this->chain);
        foreach ([2, 2.0] as $d) {
            $x = Obj::of(['v' => $c->get('v'), 'kind' => $c->get('kind'), 'depth' => $d, 'hops_root' => $c->get('hops_root'), 'leaf' => $c->get('leaf')]);
            $this->assertSame('depth must be 1..' . Pca::MAX_CHAIN, ChainCompact::compactChainShapeError($x));
        }
    }

    public function testRememberVerifiedRefusalTexts(): void
    {
        $memo = new ChainMemo();
        try {
            $memo->rememberVerified($this->chain, $this->root->public, PHP_INT_MAX);
            $this->fail('an unsafe clock was accepted');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('rememberVerified: the clock is not a safe integer', $e->getMessage());
        }
        $other = Pca::b64u(str_repeat("\x09", 32));
        $reason = Pca::verifyChain($this->chain, $other, true)[0];
        $this->assertIsString($reason);
        $this->assertNotSame('', $reason);
        $this->assertNotSame('invalid', $reason);
        try {
            $memo->rememberVerified($this->chain, $other, 1000);
            $this->fail('a chain that does not verify was remembered');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('rememberVerified: the chain does not verify: ' . $reason, $e->getMessage());
        }
        $this->assertSame(0, $memo->size());
    }

    /** An entry is live through its expiry instant and pruned only after it. */
    public function testPruneKeepsAnEntryAtItsExpiryInstant(): void
    {
        $memo = new ChainMemo(null, 10);
        $memo->rememberVerified($this->chain, $this->root->public, 1000);
        $memo->prune(1010);
        $this->assertSame(1, $memo->size());
        $memo->prune(1011);
        $this->assertSame(0, $memo->size());
    }

    public function testResolveFailsClosedWithExactAnswers(): void
    {
        $memo = new ChainMemo();
        $c = $memo->rememberVerified($this->chain, $this->root->public, 1000);
        $this->assertSame(['ok' => false, 'reason' => 'the verifier clock is not a safe integer (fail closed)'], $memo->resolve($c, PHP_INT_MAX));
        // a leaf that cannot be hashed throws inside resolve: answered as an error, never ok
        $leaf = Obj::of(['n' => NAN]);
        $msg = null;
        try {
            Pca::capHash($leaf);
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
        }
        $this->assertIsString($msg, 'control: a NaN member cannot be hashed');
        $this->assertNotSame('', $msg);
        $bad = Obj::of(['v' => $c->get('v'), 'kind' => $c->get('kind'), 'depth' => $c->get('depth'), 'hops_root' => $c->get('hops_root'), 'leaf' => $leaf]);
        $this->assertSame(['ok' => false, 'reason' => 'compact chain error (fail closed): ' . $msg], $memo->resolve($bad, 1000));
    }
}
