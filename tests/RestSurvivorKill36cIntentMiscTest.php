<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentMisc.php';
require_once __DIR__ . '/Vectors.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\IntentMisc;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/IntentMisc.php: safe-integer test, byte length of a non-string, null equality and the signed-body sig shape. */
final class RestSurvivorKill36cIntentMiscTest extends TestCase
{
    /** A fraction above 1e15 is not a safe integer (its floor differs), whatever round() does with it. */
    public function testFractionAboveE15IsNotSafeInt(): void
    {
        $this->assertFalse(IntentMisc::isSafeInt(1000000000000000.5));
        $this->assertTrue(IntentMisc::isSafeInt(1000000000000000.0), 'control');
    }

    /** utf8Len of a number is the byte length of its decimal text. */
    public function testUtf8LenOfInteger(): void
    {
        $this->assertSame(5, IntentMisc::utf8Len(12345));
        $this->assertSame(2, IntentMisc::utf8Len("\u{e9}"));
    }

    /** null equals only null: null vs a string or an object is unequal. */
    public function testNullEqualsOnlyNull(): void
    {
        $this->assertTrue(IntentMisc::scalarEq(null, null), 'control');
        $this->assertFalse(IntentMisc::scalarEq(null, 'x'));
        $this->assertFalse(IntentMisc::scalarEq(new Obj(), null));
    }

    /** A sig whose alg member is present but undefined is not a registered suite: the shape is refused. */
    public function testSigAlgPresentButUndefinedIsRefused(): void
    {
        $body = null;
        foreach (Vectors::load('producer-vectors.json')->get('cases') as $c) {
            if ($c->get('name') === 'intent-required') {
                $body = $c->get('args')->get('body');
            }
        }
        $this->assertInstanceOf(Obj::class, $body);
        $ok = $body->without();
        $ok->set('sig', Obj::of(['alg' => 'ed25519', 'kid' => 'k', 'value' => 'v']));
        $this->assertNull(IntentMisc::intentRequiredShapeError($ok), 'control');
        $bad = $body->without();
        $bad->set('sig', Obj::of(['alg' => AnalyzerJs::undef(), 'kid' => 'k', 'value' => 'v']));
        $this->assertSame('sig must be {alg, kid, value, pq_value?}', IntentMisc::intentRequiredShapeError($bad));
    }
}
