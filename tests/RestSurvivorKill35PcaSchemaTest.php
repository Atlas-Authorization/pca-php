<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\PcaSchema;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the structural PCA schema validator. */
final class RestSurvivorKill35PcaSchemaTest extends TestCase
{
    private static function errors(Obj $schema, mixed $value): array
    {
        return PcaSchema::validate($schema, $value)->get('errors');
    }

    /** The published schemas are parsed once and shared; named() is public and refuses an unknown name. */
    public function testSchemasAreCachedAndNamed(): void
    {
        $this->assertSame(PcaSchema::allSchemas(), PcaSchema::allSchemas());
        $this->assertSame('PCActn', PcaSchema::named('PCActn')->get('title'));
        try {
            PcaSchema::named('Nope');
            $this->fail('an unknown schema resolved');
        } catch (\OutOfBoundsException $e) {
            $this->assertSame('unknown schema Nope', $e->getMessage());
        }
    }

    /** jsonTypeOf is public; an infinite float is a number, never an integer. */
    public function testJsonTypeOf(): void
    {
        $this->assertSame('number', PcaSchema::jsonTypeOf(INF));
        $this->assertSame('integer', PcaSchema::jsonTypeOf(5));
        $this->assertSame('number', PcaSchema::jsonTypeOf(1.5));
    }

    /** integer admits whole ints and floats of either sign and +0.0, but not -0.0 or infinity. */
    public function testIntegerType(): void
    {
        $s = Obj::of(['type' => 'integer']);
        foreach ([5, 0, -3, 5.0, -3.0, 0.0] as $v) {
            $this->assertSame([], self::errors($s, $v), var_export($v, true));
        }
        $this->assertCount(1, self::errors($s, -0.0));
        $this->assertSame(['(root): expected type integer, got number'], self::errors($s, INF));
    }

    /** An unknown type name never matches; a non-string type name is labelled by its JS string form. */
    public function testUnknownAndNonStringTypeNames(): void
    {
        $this->assertSame(['(root): expected type frob, got integer'], self::errors(Obj::of(['type' => 'frob']), 5));
        $this->assertSame(['(root): expected type string|true, got integer'], self::errors(Obj::of(['type' => ['string', true]]), 5));
    }

    /** enum [null] admits null (JS null === null). */
    public function testEnumNullMatchesNull(): void
    {
        $this->assertSame([], self::errors(Obj::of(['enum' => [null]]), null));
        $this->assertCount(1, self::errors(Obj::of(['enum' => [null]]), 0));
    }

    /** A null schema node and a non-string required key throw; a non-object properties value constrains nothing. */
    public function testMalformedSchemaNodes(): void
    {
        try {
            PcaSchema::validate(null, 1);
            $this->fail('a null schema validated');
        } catch (\TypeError $e) {
            $this->assertSame('schema node is null', $e->getMessage());
        }
        try {
            PcaSchema::validate(Obj::of(['required' => [5]]), Obj::of([]));
            $this->fail('a numeric required key validated');
        } catch (\TypeError $e) {
            $this->assertSame('unhashable required key', $e->getMessage());
        }
        $this->assertSame([], self::errors(Obj::of(['properties' => 'x']), Obj::of(['a' => 1])));
        $this->assertSame([], self::errors(Obj::of(['properties' => [1]]), Obj::of(['a' => 1])));
    }
}
