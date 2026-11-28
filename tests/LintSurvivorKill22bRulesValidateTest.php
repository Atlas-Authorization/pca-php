<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsRulesValidate;
use Atlas\Pca\Json;
use Atlas\Pca\JsUndefined;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsRules.php';

/** rules.required dedupes like the reference's Set (SameValueZero); the legacy zone ids do not depend on the runtime's zone list. */
final class LintSurvivorKill22bRulesValidateTest extends TestCase
{
    private const D = '{"verb":"v","params":{"a":{"type":"string"}}}';
    private const DISTINCT = 'rules.required is a list of distinct parameter names';

    protected function tearDown(): void
    {
        ActionsRulesValidate::$zoneListHook = null;
        self::resetZones();
    }

    private static function resetZones(): void
    {
        (new \ReflectionProperty(ActionsRulesValidate::class, 'zones'))->setValue(null, null);
    }

    private static function req(string $required): ?string
    {
        return ActionsRulesValidate::error(Json::parseLax(self::D), Json::parseLax('{"required":' . $required . '}'));
    }

    private static function reqRaw(array $required): ?string
    {
        return ActionsRulesValidate::error(Json::parseLax(self::D), Obj::of(['required' => $required]));
    }

    public function testRequiredDedupesBySameValueZero(): void
    {
        // two objects or two arrays are never the same value: the names check refuses them instead
        $this->assertSame("rules.required: 'v' has no parameter '[object Object]'", self::req('[{}, {}]'));
        $this->assertSame("rules.required: 'v' has no parameter ''", self::req('[[], []]'));
        $this->assertSame(self::DISTINCT, self::req('["a", "a"]'));
        $this->assertSame(self::DISTINCT, self::req('[1, 1.0]'));
        $this->assertSame(self::DISTINCT, self::req('[0, -0]'));
        $this->assertSame(self::DISTINCT, self::req('[true, true]'));
        $this->assertSame(self::DISTINCT, self::req('[null, null]'));
        $this->assertSame(self::DISTINCT, self::reqRaw([NAN, NAN]));
        $this->assertSame(self::DISTINCT, self::reqRaw([JsUndefined::U, JsUndefined::U]));
        // values of different types never collide
        $this->assertSame("rules.required: 'v' has no parameter '1'", self::req('["1", 1]'));
        $this->assertSame("rules.required: 'v' has no parameter 'true'", self::req('[true, "true"]'));
        $this->assertSame("rules.required: 'v' has no parameter 'true'", self::req('[true, false]'));
        $this->assertSame("rules.required: 'v' has no parameter 'null'", self::req('[null, "null"]'));
        $this->assertSame("rules.required: 'v' has no parameter 'null'", self::reqRaw([null, JsUndefined::U]));
        $this->assertSame("rules.required: 'v' has no parameter 's:a'", self::req('["s:a", "a"]'));
        $this->assertNull(self::req('["a"]'));
    }

    public function testLegacyZonesAreKnownWhateverTheRuntimeLists(): void
    {
        ActionsRulesValidate::$zoneListHook = static fn(): array => ['Europe/Paris'];
        self::resetZones();
        $this->assertSame('EST', ActionsRulesValidate::canonicalZone('est'));
        $this->assertSame('MST', ActionsRulesValidate::canonicalZone('mst'));
        $this->assertSame('HST', ActionsRulesValidate::canonicalZone('Hst'));
        $this->assertSame('Europe/Paris', ActionsRulesValidate::canonicalZone('europe/PARIS'));
        $this->assertSame('UTC', ActionsRulesValidate::canonicalZone('utc'));
        $this->assertNull(ActionsRulesValidate::canonicalZone('Nowhere/Else'));
    }

    public function testTheRuntimeSpellingOfALegacyZoneWins(): void
    {
        ActionsRulesValidate::$zoneListHook = static fn(): array => ['est'];
        self::resetZones();
        $this->assertSame('est', ActionsRulesValidate::canonicalZone('EST'));
        $this->assertSame('MST', ActionsRulesValidate::canonicalZone('MST'));
    }
}
