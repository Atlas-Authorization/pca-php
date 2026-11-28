<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentJit;
use Atlas\Pca\IntentLearner;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 37 survivor kills for the JIT delta: cell keys keep verb and cell apart, and the minted cell count sums every verb. */
final class RestSurvivorKill37IntentJitTest extends TestCase
{
    private static function cat(int $n): Obj
    {
        $vals = [];
        for ($i = 0; $i < $n; $i++) {
            $vals[] = Obj::of(['kind' => 'exact', 'value' => 'v' . $i]);
        }
        return Obj::of(['kind' => 'cat', 'path' => 'action.params.s' . $n, 'values' => $vals]);
    }

    private static function vs(string $verb, array $dims): Obj
    {
        return Obj::of(['verb' => $verb, 'reversibility' => 'reversible', 'weight' => 1, 'dims' => $dims]);
    }

    /** A learner over the given verb spaces whose grant is every cell (tau 0) or no cell (tau 2). */
    private static function learner(array $verbs, float $tau): IntentLearner
    {
        $l = new IntentLearner(Obj::of(['v' => 1, 'approximate' => [], 'verbs' => $verbs]), []);
        $l->tau = $tau;
        return $l;
    }

    /**
     * Cells of different verbs never alias: verb 'a1,' cell [2] is not verb 'a' cell [1,2], and verb 'z' cell [i,j] is not verb 'a'
     * cell [i,j], so every granted cell of 'a' is new.
     */
    public function testDeltaKeysSeparateVerbAndCell(): void
    {
        $prev = self::learner([self::vs('a1,', [self::cat(3)]), self::vs('z', [self::cat(2), self::cat(3)])], 0.0);
        $next = self::learner([self::vs('a', [self::cat(2), self::cat(3)])], 0.0);
        $this->assertSame(['a' => [1, 1, 1, 1, 1, 1]], IntentJit::deltaCells($prev, $next));
        $this->assertSame([], IntentJit::deltaCells($next, $next), 'control: nothing is new over itself');
    }

    /** A delta spanning two verbs counts the new cells of both (2 + 3), not only the last verb's. */
    public function testMintDeltaCountsEveryVerb(): void
    {
        $verbs = [self::vs('x.do', [self::cat(2)]), self::vs('y.do', [self::cat(3)])];
        $prev = self::learner($verbs, 2.0);
        $next = self::learner($verbs, 0.0);
        $this->assertSame(['x.do' => [1, 1], 'y.do' => [1, 1, 1]], IntentJit::deltaCells($prev, $next));
        $principal = new KeyPair(hash('sha256', 'atlas-pca-conformance/group37-principal', true));
        $b = static fn(string $s): string => Pca::b64u(hash('sha256', $s, true));
        $r = IntentJit::mintDelta($prev, $next, null, $principal, $principal->public, $b('session'), 0, $b('root'), $b('map'));
        $this->assertNotNull($r);
        $this->assertSame(5, $r['cells']);
        $this->assertInstanceOf(Obj::class, $r['grant']);
    }
}
