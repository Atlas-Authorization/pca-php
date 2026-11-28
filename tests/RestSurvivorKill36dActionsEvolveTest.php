<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsEvolve.php';

use Atlas\Pca\ActionKitError;
use Atlas\Pca\ActionsEvolve;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/ActionsEvolve.php: the duplicate-def refusal text, the caller's registry, string verbs, the evolution error prefix. */
final class RestSurvivorKill36dActionsEvolveTest extends TestCase
{
    /** @param array<string,string> $over member => JSON */
    private static function def(array $over = []): Obj
    {
        $d = Json::parseLax('{"v":1,"kind":"pca-action-def","verb":"bank.transfer.send","title":"Send","effects":["pay"],'
            . '"resource":{"type":"bank.account","id":"*","scope":"one"},"params":{"a":{"type":"string"}},"reversibility":"irreversible",'
            . '"idempotency":{"mode":"natural"},"review":{"state":"authored"}}');
        self::assertInstanceOf(Obj::class, $d);
        foreach ($over as $k => $json) {
            $d->set($k, Json::parseLax($json));
        }
        return $d;
    }

    /** A pack that lists one verb twice is not an evolution: the reason names the verb, behind the evolution-error prefix. */
    public function testDuplicateVerbIsRefusedWithItsName(): void
    {
        $d = self::def();
        $this->assertSame("evolution error: verb 'bank.transfer.send' appears twice", ActionsEvolve::evolutionError('acme', [$d, $d], [], [], []));
        try {
            ActionsEvolve::evolutionRecords('acme', [], [$d, $d]);
            $this->fail('no ActionKitError');
        } catch (ActionKitError $e) {
            $this->assertSame('duplicate_def', $e->codeName);
            $this->assertSame("verb 'bank.transfer.send' appears twice", $e->getMessage());
        }
    }

    /** A changed def is diffed under the CALLER's registry: one that lacks the def's traits refuses, the core one does not. */
    public function testChangedDefIsDiffedUnderTheGivenRegistry(): void
    {
        $prev = self::def();
        $next = self::def(['params' => '{"a":{"type":"string"},"b":{"type":"string"}}']);
        $this->assertCount(1, ActionsEvolve::evolutionRecords('acme', [$prev], [$next]));
        try {
            ActionsEvolve::evolutionRecords('acme', [$prev], [$next], []);
            $this->fail('the empty registry was not used');
        } catch (ActionKitError $e) {
            $this->assertSame('unknown_trait', $e->codeName);
        }
    }

    /** A verb that looks like a number stays a string in its record (PHP turns such array keys into ints). */
    public function testNumericLookingVerbStaysAString(): void
    {
        $recs = ActionsEvolve::evolutionRecords('acme', [], [self::def(['verb' => '"7"'])]);
        $this->assertCount(1, $recs);
        $this->assertSame('7', $recs[0]->get('verb'));
        $this->assertSame('added', $recs[0]->get('class'));
    }
}
