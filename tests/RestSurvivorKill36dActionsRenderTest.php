<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsRender.php';

use Atlas\Pca\ActionKitError;
use Atlas\Pca\ActionsRender;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/ActionsRender.php: the verb-mismatch refusal text, alias precedence, the unreviewed default and the caller's registry. */
final class RestSurvivorKill36dActionsRenderTest extends TestCase
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

    /** A PCActn for another verb is refused before anything is rendered, naming both verbs. */
    public function testVerbMismatchNamesBothVerbs(): void
    {
        $pcactn = Obj::of(['action' => Obj::of(['verb' => 'bank.transfer.other'])]);
        try {
            ActionsRender::renderDigestForAction(self::def(), new Obj(), $pcactn);
            $this->fail('no ActionKitError');
        } catch (ActionKitError $e) {
            $this->assertSame('render_verb_mismatch', $e->codeName);
            $this->assertSame("the PCActn is for 'bank.transfer.other', the definition for 'bank.transfer.send'", $e->getMessage());
        }
    }

    /** An alias never takes over a name another def owns as its verb. */
    public function testAliasDoesNotShadowAVerb(): void
    {
        $own = self::def();
        $other = self::def(['verb' => '"bank.transfer.other"', 'aliases' => '["bank.transfer.send"]']);
        $render = ActionsRender::renderersFromDefs([$own, $other]);
        $this->assertSame('bank.transfer.send', $render('bank.transfer.send', '', new Obj())->get('verb'));
        $render2 = ActionsRender::renderersFromDefs([$other, $own]);
        $this->assertSame('bank.transfer.send', $render2('bank.transfer.send', '', new Obj())->get('verb'));
    }

    /** By default a def is priced as unreviewed (top traits), not with its own hint traits. */
    public function testFacadeDefaultsToUnreviewed(): void
    {
        $d = self::def();
        $unrev = ActionsRender::specOfDef($d, null, null, false)->get('traits');
        $rev = ActionsRender::specOfDef($d, null, null, true)->get('traits');
        $this->assertNotSame($unrev, $rev);
        $this->assertSame($unrev, ActionsRender::specOfDef($d)->get('traits'));
        $this->assertSame($unrev, ActionsRender::facadeSpecs([$d])[0]->get('traits'));
    }

    /** The caller's registry is the one used: one that lacks the def's traits refuses the facade row and has no top traits. */
    public function testCallerRegistryIsUsed(): void
    {
        $d = self::def();
        try {
            ActionsRender::specOfDef($d, []);
            $this->fail('the empty registry was not used');
        } catch (ActionKitError $e) {
            $this->assertSame('unknown_trait', $e->codeName);
        }
        $this->assertNotSame([], ActionsRender::provenanceInfoOf($d)->get('traits'));
        $this->assertSame([], ActionsRender::provenanceInfoOf($d, [])->get('traits'));
        $f = ActionsRender::provenanceActions([$d], []);
        $info = $f(Obj::of(['verb' => 'bank.transfer.send']));
        $this->assertInstanceOf(Obj::class, $info);
        $this->assertSame([], $info->get('traits'));
    }
}
