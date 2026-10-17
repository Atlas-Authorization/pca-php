<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Regression (same class as the caveat-type fix in CaveatTypeStrictTest): IntentV2::paramValueViolation and
 * IntentV2::monitorStates dispatched the declared param `type` / the monitor `kind` with PHP's loose `switch`, so
 * `{"type": true}` was treated as a `string` declaration (any string value conformed, also through the public
 * conformAction and the `intent_schema` primitive) and `{"kind": true}` as `requires_prior`. The reference
 * (action-schema.ts paramValueViolation, intent-acc.ts monitorStates) switches with `===`: a non-string type is
 * `bad_type: unknown declared type`, a non-string kind has no states.
 */
final class IntentV2TypeStrictTest extends TestCase
{
    public function testNonStringParamTypeIsUnknown(): void
    {
        foreach ([true, 1, 0, null, [], new Num('1')] as $type) {
            $r = IntentV2::paramValueViolation(Obj::of(['type' => $type]), 'anything');
            $this->assertSame(['code' => 'bad_type', 'reason' => 'unknown declared type'], $r, var_export($type, true));
        }
        // control: a real string declaration accepts the value
        $this->assertNull(IntentV2::paramValueViolation(Obj::of(['type' => 'string']), 'anything'));
    }

    public function testNonStringMonitorKindHasNoStates(): void
    {
        foreach ([true, 1, 0, null, [], new Num('1')] as $kind) {
            $this->assertSame([], IntentV2::monitorStates(Obj::of(['kind' => $kind])), var_export($kind, true));
        }
        $this->assertSame(['unmet', 'met'], IntentV2::monitorStates(Obj::of(['kind' => 'requires_prior'])));
    }
}
