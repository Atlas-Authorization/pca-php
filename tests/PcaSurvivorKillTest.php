<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Targeted kills for Pca.php survivors of the 0.4.2 Infection run. */
final class PcaSurvivorKillTest extends TestCase
{
    public function testMerkleRootOfNothingThrowsItsOwnMessage(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('empty leaf set');
        Pca::merkleRoot([]);
    }

    /** The registry order has unimplemented suites (fn-dsa) between implemented ones: the list must stay a list. */
    public function testSupportedSuitesIsAList(): void
    {
        $s = Pca::supportedSuites();
        $this->assertTrue(array_is_list($s));
        $this->assertContains('ed25519', $s);
        $this->assertNotContains('fn-dsa-512', $s);
    }

    private static function ctx(array $recent): Obj
    {
        return Obj::of(['recent_action_times' => array_map(fn($t) => new \Atlas\Pca\Num((string) $t), $recent)]);
    }

    /** A `rate` caveat needs BOTH max and per_secs: either one missing is unsatisfied (never "no recent actions, under the limit"). */
    public function testRateCaveatNeedsMaxAndWindow(): void
    {
        $now = 1000000;
        $ctx = self::ctx([]);
        $ctx->set('now', new \Atlas\Pca\Num((string) $now));
        $ok = Pca::evaluateCaveats([Json::parseLax('{"type":"rate","max":5,"per_secs":60}')], $ctx);
        $this->assertSame(['ok' => true, 'failed' => []], $ok);
        foreach (['{"type":"rate","max":5}', '{"type":"rate","per_secs":60}', '{"type":"rate","max":5,"per_secs":0}',
                     '{"type":"rate","max":5,"per_secs":"60"}', '{"type":"rate","max":"5","per_secs":60}', '{"type":"rate"}'] as $cv) {
            $this->assertSame(['ok' => false, 'failed' => ['rate']], Pca::evaluateCaveats([Json::parseLax($cv)], $ctx), $cv);
        }
    }

    public function testReversibilityMaxNeedsTwoStrings(): void
    {
        $cv = Json::parseLax('{"type":"reversibility_max","class":"reversible"}');
        $this->assertSame(['ok' => true, 'failed' => []], Pca::evaluateCaveats([$cv], Obj::of(['now' => new \Atlas\Pca\Num('1'), 'reversibility_class' => 'reversible'])));
        foreach ([null, 5, 'unknown'] as $cur) {
            $ctx = Obj::of(['now' => new \Atlas\Pca\Num('1')]);
            if ($cur !== null) {
                $ctx->set('reversibility_class', $cur);
            }
            $this->assertSame(['ok' => false, 'failed' => ['reversibility_max']], Pca::evaluateCaveats([$cv], $ctx));
        }
        $bad = Json::parseLax('{"type":"reversibility_max","class":5}');
        $this->assertSame(['ok' => false, 'failed' => ['reversibility_max']], Pca::evaluateCaveats([$bad], Obj::of(['now' => new \Atlas\Pca\Num('1'), 'reversibility_class' => 'reversible'])));
    }

    /** A root hop naming a string suite outside the registry is refused, not an undefined-index lookup. */
    public function testRootWithUnregisteredSuiteIsRefusedCleanly(): void
    {
        $v = null;
        foreach (Corpus::core()->get('vectors') as $x) {
            if ($x->get('name') === 'valid-in-plan-action') {
                $v = $x;
            }
        }
        $this->assertNotNull($v);
        $hop = $v->get('grant')->without();
        $hop->set('alg', 'not-a-suite');
        $res = Pca::verifyChain([$hop], $hop->get('issuer'), true);
        $this->assertFalse($res[1]);
        $this->assertNotSame('', $res[0]);
    }
}
