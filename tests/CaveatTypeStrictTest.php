<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Regression (found by the 0.4.1 mutation pass): evaluateCaveats matched the caveat `type` with PHP's loose `switch`, so
 * `{"type": true, ...}` hit the first case (`true == 'expires'`) and was evaluated as an `expires` caveat (satisfied
 * whenever now < at). The reference (envelopeCaveatEvaluator / agentNativeCaveatEvaluator, packages/pca/src) switches on
 * the type with `===`: a non-string type is an unknown caveat, unsatisfied (fail closed), reported as '<malformed>'.
 */
final class CaveatTypeStrictTest extends TestCase
{
    public function testNonStringTypeIsUnsatisfied(): void
    {
        $ctx = Obj::of([
            'now' => new Num('1000'),
            'delegation_depth' => new Num('0'),
            'blast_radius' => new Num('0'),
            'reversibility_class' => 'reversible',
            'recent_action_times' => [],
            'action' => Obj::of(['params' => Obj::of(['amount' => new Num('0')])]),
        ]);
        $body = ['at' => new Num('2000'), 'max' => new Num('5'), 'per_secs' => new Num('1'), 'limit' => new Num('1'), 'usd' => new Num('1'), 'class' => 'irreversible'];
        $stringable = new class {
            public function __toString(): string
            {
                return 'expires';
            }
        };
        foreach ([true, 1, 0, 0.0, null, [], $stringable, new Num('1')] as $type) {
            $r = Pca::evaluateCaveats([Obj::of(['type' => $type] + $body)], $ctx);
            $this->assertSame(['ok' => false, 'failed' => ['<malformed>']], $r, var_export($type, true));
        }
        // control: the same body under a real type is satisfied
        $this->assertSame(['ok' => true, 'failed' => []], Pca::evaluateCaveats([Obj::of(['type' => 'expires'] + $body)], $ctx));
    }
}
