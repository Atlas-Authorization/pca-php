<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Decide;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Decide::deriveDecideInput: the grant is the verifier's own and required; the action, node id and chain come from the PCActn. */
final class DecideDeriveInputTest extends TestCase
{
    private static function pcactn(): Obj
    {
        return Obj::of(['action' => Obj::of(['verb' => 'pay', 'resource' => 'invoice:1', 'reversibility_class' => 'irreversible']),
            'plan' => Obj::of(['node_id' => 'n1']), 'cap_chain' => [Obj::of(['id' => 'g0'])]]);
    }

    public function testTheGrantIsRequired(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Decide::deriveDecideInput(self::pcactn(), ['risk' => new Obj(), 'now' => new Num('1')]);
    }

    public function testDerivesTheDecideInput(): void
    {
        $grant = Obj::of(['id' => 'g0']);
        $params = Obj::of(['amount' => new Num('5')]);
        $in = Decide::deriveDecideInput(self::pcactn(), ['grant' => $grant, 'params' => $params, 'risk' => new Obj(), 'budget' => new Obj(), 'now' => new Num('7')]);
        $this->assertSame($grant, $in->get('grant'));
        $this->assertSame($grant, $in->get('trustedRoot'));
        $this->assertSame('n1', $in->get('nodeId'));
        $this->assertCount(1, $in->get('chain'));
        $act = $in->get('action')->get('action');
        $this->assertSame(['verb', 'resource', 'params', 'reversibility_class'], $act->keys());
        $this->assertSame($params, $act->get('params'));
        $this->assertFalse($in->has('plan'));
        $this->assertFalse($in->has('pqPins'));
        $this->assertFalse($in->get('action')->has('subject'));
    }

    public function testAnExplicitChainWinsAndParamsDefaultToAnEmptyObject(): void
    {
        $chain = [Obj::of(['id' => 'x'])];
        $in = Decide::deriveDecideInput(self::pcactn(), ['grant' => new Obj(), 'chain' => $chain, 'now' => new Num('1')]);
        $this->assertSame($chain, $in->get('chain'));
        $this->assertSame([], $in->get('action')->get('action')->get('params')->keys());
    }
}
