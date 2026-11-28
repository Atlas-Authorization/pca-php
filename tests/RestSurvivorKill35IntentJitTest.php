<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentJit;
use Atlas\Pca\IntentV2;
use Atlas\Pca\JsonError;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the lazy-elicitation (JIT intent) helpers. */
final class RestSurvivorKill35IntentJitTest extends TestCase
{
    private static function vs(): Obj
    {
        return Obj::of(['verb' => 'v', 'dims' => [Obj::of(['kind' => 'num', 'path' => 'n']),
            Obj::of(['kind' => 'cat', 'path' => 'c', 'values' => [Obj::of(['value' => 'a']), Obj::of(['value' => 'a'])]])]]);
    }

    private static function action(): Obj
    {
        return Obj::of(['verb' => 'v', 'resource' => 'r', 'params_digest' => 'd', 'reversibility_class' => 'reversible']);
    }

    /** A conform reason that is present but null reads as null, not undefined. */
    public function testNullConformReason(): void
    {
        $r = IntentJit::decideVisit(Obj::of(['conform' => Obj::of(['ok' => false, 'code' => 'x', 'reason' => null])]));
        $this->assertSame(['kind' => 'schema_violation', 'reason' => 'x: null'], $r);
    }

    /** cellCoords refuses a missing verb space and a categorical index outside the values. */
    public function testCellCoordsRefusals(): void
    {
        try {
            IntentJit::cellCoords('x', [0]);
            $this->fail('no TypeError');
        } catch (\TypeError $e) {
            $this->assertSame('cellCoords: no verb space', $e->getMessage());
        }
        $this->expectException(\OutOfRangeException::class);
        IntentJit::cellCoords(Obj::of(['dims' => [Obj::of(['kind' => 'cat', 'path' => 'c', 'values' => []])]]), [5]);
    }

    /** cellFromCoords: non-object coordinates, a non-number at either end of a numeric range, the first end's value, the first matching category. */
    public function testCellFromCoords(): void
    {
        $this->assertNull(IntentJit::cellFromCoords(self::vs(), 5));
        $this->assertNull(IntentJit::cellFromCoords(self::vs(), Obj::of(['n' => [0, 'x'], 'c' => ['a']])));
        $this->assertNull(IntentJit::cellFromCoords(self::vs(), Obj::of(['n' => ['x', 0], 'c' => ['a']])));
        $this->assertSame([1, 0], IntentJit::cellFromCoords(self::vs(), Obj::of(['n' => [1, 1.0], 'c' => ['a']])));
    }

    /** The action digest refuses a null action and an action without a verb. */
    public function testActionDigestRefusals(): void
    {
        try {
            IntentJit::intentActionDigest(null);
            $this->fail('no TypeError');
        } catch (\TypeError $e) {
            $this->assertSame("Cannot read properties of null (reading 'verb')", $e->getMessage());
        }
        $this->expectException(JsonError::class);
        IntentJit::intentActionDigest(self::action()->without('verb'));
    }

    /** A supplied verifier is used; a result without ok refuses as is. */
    public function testSuppliedVerifier(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'mine'], IntentJit::walletCheckIntentRequired(new Obj(), new Obj(), static fn(): array => ['ok' => false, 'reason' => 'mine']));
        $this->assertSame(['reason' => 'z'], IntentJit::walletCheckIntentRequired(new Obj(), new Obj(), static fn(): array => ['reason' => 'z']));
    }

    /** A matching PCActn digest with a different action digest is about another action. */
    public function testActionDigestMismatch(): void
    {
        $pcactn = Obj::of(['action' => self::action()]);
        $body = Obj::of(['session' => 's', 'map_digest' => 'm', 'pcactn_digest' => IntentV2::hashCanonical($pcactn), 'action_digest' => 'wrong']);
        $w = Obj::of(['session' => 's', 'mapDigest' => 'm', 'pcactn' => $pcactn]);
        $this->assertSame(['ok' => false, 'reason' => 'the question is about another action'],
            IntentJit::walletCheckIntentRequired($body, $w, static fn(): array => ['ok' => true]));
    }
}
