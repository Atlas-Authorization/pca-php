<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use PHPUnit\Framework\TestCase;

/** Round r9 mutation kills for src/IntentV2Schema.php. */
final class R9SchemaKillTest extends TestCase
{
    public function testConformActionToleratesAVerbEntryWithoutParams(): void
    {
        $doc = Json::parseLax('{"verbs":[{"verb":"x"}]}');
        $none = IntentV2::conformAction($doc, 'x', Json::parseLax('{}'));
        self::assertTrue($none['ok']);
        $extra = IntentV2::conformAction($doc, 'x', Json::parseLax('{"a":1}'));
        self::assertSame(['ok' => false, 'code' => 'undeclared_param', 'path' => 'action.params.a',
            'reason' => "parameter 'action.params.a' is not declared for 'x'"], $extra);
        // a verb entry whose params is not an object declares nothing either
        $bad = Json::parseLax('{"verbs":[{"verb":"x","params":5}]}');
        self::assertSame('undeclared_param', IntentV2::conformAction($bad, 'x', Json::parseLax('{"a":1}'))['code']);
    }

    public function testAccumulationParamsToleratesAVerbEntryWithoutParams(): void
    {
        self::assertSame([], IntentV2::accumulationParams(Json::parseLax('{"verb":"x"}'), 'usd'));
        self::assertSame([], IntentV2::accumulationParams(Json::parseLax('{"verb":"x","params":5}'), 'usd'));
        self::assertSame([], IntentV2::accumulationParams(IntentV2::undef(), 'usd'));
    }
}
