<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsCompat.php';
require_once __DIR__ . '/../src/Actions.php';
require_once __DIR__ . '/../src/Catalog.php';

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsCompat;
use Atlas\Pca\Catalog;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** compat.ts: the migration shims from the old catalog vocabulary to ActionDefs. */
final class ActionsCompatTest extends TestCase
{
    public function testReversibilityAndUnits(): void
    {
        self::assertSame('reversible', ActionsCompat::normalizeReversibility('read'));
        self::assertSame('rate_limited', ActionsCompat::normalizeReversibility('costly'));
        self::assertSame('irreversible', ActionsCompat::normalizeReversibility('anything else'));
        self::assertSame('irreversible', ActionsCompat::normalizeReversibility(null));
        self::assertSame('costly', ActionsCompat::legacyOperationsClass('rate_limited'));
        self::assertSame('reversible', ActionsCompat::legacyOperationsClass('reversible'));
        self::assertSame('irreversible', ActionsCompat::maxRevOf('reversible', 'irreversible'));
        self::assertSame('rate_limited', ActionsCompat::maxRevOf('rate_limited', 'reversible'));
        self::assertSame('{"kind":"count"}', Json::canonicalizeLenient(ActionsCompat::unitTagOf(Json::parseLax('{"kind":"count"}'))));
        $m = ActionsCompat::unitTagOf(Json::parseLax('{"kind":"money","ccy":"USD","exp":2}'));
        self::assertSame('{"currency":"USD","exponent":2,"kind":"money"}', Json::canonicalizeLenient($m));
        self::assertNull(ActionsCompat::unitTagOf(Json::parseLax('{"kind":"money","ccy":{"param":"c"}}')));
    }

    public function testBlast(): void
    {
        self::assertSame(['radius' => 'one', 'ppm' => 50000], ActionsCompat::blastOfFloat(0.05));
        self::assertSame(['radius' => 'bounded', 'ppm' => 200000], ActionsCompat::blastOfFloat(0.2));
        self::assertSame(['radius' => 'global', 'ppm' => 900000], ActionsCompat::blastOfFloat(0.9));
        self::assertSame(['radius' => 'global', 'ppm' => 1000000], ActionsCompat::blastOfFloat('nonsense'), 'a non-number is the worst case');
        self::assertSame(['radius' => 'tenant', 'ppm' => 900000], ActionsCompat::blastExactOfFloat(0.9));
        self::assertSame(['radius' => 'one', 'ppm' => 10000], ActionsCompat::blastExactOfFloat(0.01));
        self::assertSame(['radius' => 'global', 'ppm' => 1000000], ActionsCompat::blastExactOfFloat(5));
        self::assertSame(['radius' => 'one', 'ppm' => 0], ActionsCompat::blastOfFloat(-3));
    }

    public function testCatalogEntriesBecomeValidDefs(): void
    {
        foreach (Catalog::BUILTIN_ACTIONS as $spec) {
            $def = ActionsCompat::fromCatalogSpec($spec);
            self::assertNull(Actions::validateDef($def), $spec['verb']);
            self::assertSame($spec['verb'], $def->get('verb'));
            self::assertSame('authored', $def->get('review')->get('state'));
        }
        $charge = ActionsCompat::fromCatalogSpec(Catalog::BUILTIN_ACTIONS[0]);
        self::assertSame(['pay'], $charge->get('effects'));
        self::assertTrue($charge->get('params')->has('idempotency_key'));
        self::assertSame('key_param', $charge->get('idempotency')->get('mode'));
        $list = ActionsCompat::fromCatalog([['connector' => 'x', 'action' => 'list_things', 'verb' => 'x.list_things', 'description' => 'd', 'reversibility' => 'reversible', 'blastRadius' => 0.1, 'resource' => 'a/b']]);
        self::assertSame(['read'], $list[0]->get('effects'));
        self::assertSame('one', $list[0]->get('resource')->get('scope'));
        $long = ActionsCompat::fromCatalogSpec(['connector' => 'x', 'action' => 'purge_all', 'verb' => 'x.purge_all', 'description' => str_repeat('a', 130), 'reversibility' => 'irreversible', 'blastRadius' => 1]);
        self::assertSame(120, mb_strlen((string)$long->get('title')));
        self::assertSame(['delete'], $long->get('effects'));
    }
}
