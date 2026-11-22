<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PolicyClasses.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\PolicyClasses;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for PolicyClasses::listError: the class-count message, the object check and the digest bound. */
final class K05KillPolicyClassesTest extends TestCase
{
    private static function cls(string $digest = 'd'): Obj
    {
        return Obj::of(['class' => 'org', 'revision' => new Num('0'), 'digest' => $digest, 'decision' => 'allow']);
    }

    public function testListError(): void
    {
        self::assertSame('more than 5 policy classes', PolicyClasses::listError(array_fill(0, 6, self::cls())));
        self::assertSame('policy_classes[0] must be an object', PolicyClasses::listError(['x']));
        self::assertNull(PolicyClasses::listError([self::cls(str_repeat('d', 128))]));
        self::assertSame('policy_classes[0].digest invalid', PolicyClasses::listError([self::cls(str_repeat('d', 129))]));
    }
}
