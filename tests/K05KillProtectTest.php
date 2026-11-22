<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\Obj;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\Protect;
use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for Protect::protect: option validation messages, and the operation / revocation closures it hands to
 * AuthorizeOptions (read through the middleware's private `authorize`, the only place they live).
 */
final class K05KillProtectTest extends TestCase
{
    private static function opts(array $o = []): array
    {
        $f = new HttpFactory();
        return $o + [
            'audience' => 'aud',
            'grants' => [],
            'operation' => static fn () => ['verb' => 'v', 'resource' => 'r', 'params' => ['a' => 1]],
            'responseFactory' => $f,
            'streamFactory' => $f,
        ];
    }

    private static function az(Protect $p): AuthorizeOptions
    {
        return (new \ReflectionProperty(PcaMiddleware::class, 'authorize'))->getValue($p->middleware);
    }

    private function refused(array $o, string $msg): void
    {
        try {
            Protect::protect(self::opts($o));
            $this->fail("accepted: $msg");
        } catch (\InvalidArgumentException $e) {
            $this->assertSame("Protect::protect: $msg", $e->getMessage());
        }
    }

    public function testOptionValidationMessages(): void
    {
        $this->refused(['audience' => ''], "'audience' must be a non-empty string");
        $this->refused(['audience' => 5], "'audience' must be a non-empty string");
        $this->refused(['isRevoked' => 5], "'isRevoked' must be callable");
        $this->refused(['grants' => 5], "'grants' must be a list of grants or a callable");
    }

    public function testOperationParamsBecomeAnObjectOnlyWhenNotAList(): void
    {
        $op = static fn (mixed $params) => self::az(Protect::protect(self::opts([
            'operation' => static fn () => ['verb' => 'v', 'resource' => 'r', 'params' => $params],
        ])))->operation;
        $empty = ($op([]))(null);
        $this->assertInstanceOf(Obj::class, $empty['params']);
        $this->assertSame([], $empty['params']->keys());
        $this->assertSame([1, 2], ($op([1, 2]))(null)['params']);
        $map = ($op(['a' => 1]))(null)['params'];
        $this->assertInstanceOf(Obj::class, $map);
        $this->assertSame(['a'], $map->keys());
    }

    public function testRevocationClosure(): void
    {
        $p = Protect::protect(self::opts());
        $isRevoked = self::az($p)->isRevoked;
        $this->assertTrue($isRevoked(null, null)); // not a grant: refused, never read
        $this->assertFalse($isRevoked(null, Obj::of(['id' => 'g1'])));
        $p->revoke('g1');
        $this->assertTrue($isRevoked(null, Obj::of(['id' => 'g1'])));
        $p->revoke('1');
        // the id is read as a string: 1.5 is "1.5", not the revoked "1"
        $this->assertFalse($isRevoked(null, Obj::of(['id' => 1.5])));
    }
}
