<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Obligations.php';

use Atlas\Pca\Json;
use Atlas\Pca\Obligations;
use PHPUnit\Framework\TestCase;

/** collectObligations (obligations.ts): rules whose `when` is true or undecidable add their duties; malformed rules refuse. */
final class ObligationsCollectTest extends TestCase
{
    private static function rules(string $json): mixed
    {
        return Json::parseLax($json);
    }

    public function testTrueAndUndecidableAddWhileFalseDoesNot(): void
    {
        $ctx = Json::parseLax('{"action":{"verb":"pay"}}');
        $rules = self::rules('[{"id":"r1","when":{"field":"action.verb","op":"eq","value":"pay"},"obligations":[{"kind":"log","params":{"sink":"s1"}}]},'
            . '{"id":"r2","when":{"field":"action.verb","op":"eq","value":"read"},"obligations":[{"kind":"notify","params":{"to":"ops"}}]},'
            . '{"id":"r3","when":{"field":"env.risk","op":"gte","value":3},"obligations":[{"kind":"require_receipt"}]}]');
        $r = Obligations::collect($rules, $ctx);
        self::assertTrue($r['ok']);
        self::assertSame(['log', 'require_receipt'], array_map(static fn($o) => $o->get('kind'), $r['obligations']));
    }

    public function testAbsentAndRefusals(): void
    {
        self::assertSame(['ok' => true, 'obligations' => []], Obligations::collect(Obligations::absent(), null));
        self::assertSame(['ok' => false, 'reason' => 'obligation rules must be an array'], Obligations::collect(Json::parseLax('{}'), null));
        self::assertSame('obligation rule 0 is malformed', Obligations::collect(self::rules('[{"id":"a"}]'), null)['reason']);
        self::assertSame("obligation rule id 'a' is a duplicate", Obligations::collect(self::rules(
            '[{"id":"a","when":{"all_of":[]},"obligations":[{"kind":"require_receipt"}]},{"id":"a","when":{"all_of":[]},"obligations":[{"kind":"require_receipt"}]}]'), null)['reason']);
        self::assertSame("obligation rule 'a': obligations must not be empty", Obligations::collect(self::rules('[{"id":"a","when":{"all_of":[]},"obligations":[]}]'), null)['reason']);
        self::assertStringStartsWith("obligation rule 'a': ", Obligations::collect(self::rules('[{"id":"a","when":{"all_of":[]},"obligations":[{"kind":"nope"}]}]'), null)['reason']);
    }
}
