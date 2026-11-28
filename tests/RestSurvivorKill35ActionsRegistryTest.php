<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsRegistry;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the registry's rule 22 engine. */
final class RestSurvivorKill35ActionsRegistryTest extends TestCase
{
    /** rule22Engine is public and hands out both halves; schemaError refuses a non-object and passes a sound document. */
    public function testRule22EngineHalves(): void
    {
        $eng = ActionsRegistry::rule22Engine();
        $this->assertSame(['schemaError', 'decide'], array_keys($eng));
        $this->assertSame('bad_registry: not an object', ($eng['schemaError'])('x'));
        $this->assertSame('bad_registry: not an object', ($eng['schemaError'])(null));
        $this->assertNull(($eng['schemaError'])(Obj::of(['verbs' => []])));
        $this->assertSame('deny', ($eng['decide'])(Obj::of(['verbs' => []]), 'v', Obj::of([]), []));
    }
}
