<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Scitt.php';

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Scitt;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Scitt.php: the codec and builder refusals keep their exact errors, and a non-string statement never verifies. */
final class GuardSurvivorKill33ScittTest extends TestCase
{
    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e::class . ': ' . $e->getMessage();
        }
        return 'no error';
    }

    /** Each refusal is the reference's TypeError text, not a PHP type error further on. */
    public function testRefusalTexts(): void
    {
        $this->assertSame(32, strlen(Scitt::leafHash('x')), 'control');
        $this->assertSame('TypeError: expected bytes', self::thrown(fn() => Scitt::leafHash(5)));
        $this->assertSame('TypeError: cbor: unsupported value', self::thrown(fn() => Scitt::encode(new \stdClass())));
        $this->assertSame('TypeError: cbor: input must be bytes', self::thrown(fn() => Scitt::decode(5)));
        $this->assertSame('TypeError: siblingSides: index and size must be numbers', self::thrown(fn() => Scitt::siblingSides('x', 2)));
        $this->assertSame(['R'], Scitt::siblingSides(0, 2), 'control: numbers are accepted');
    }

    /** An unsupported alg is refused before anything is signed, for statements and receipts alike. */
    public function testUnsupportedAlgIsRefused(): void
    {
        $this->assertSame('TypeError: cbor: unsupported value',
            self::thrown(fn() => Scitt::signStatement(Obj::of(['a' => 'b']), Obj::of(['alg' => 'none', 'issuer' => 'i']))));
        $this->assertSame('TypeError: cbor: unsupported value',
            self::thrown(fn() => Scitt::buildReceipt(Pca::b64u(str_repeat("\0", 32)), null, Obj::of(['alg' => 'none']))));
    }

    /** A statement that is not a byte string never verifies against a receipt. */
    public function testNonStringStatementIsRefused(): void
    {
        $this->assertFalse(Scitt::verifyReceipt('x', 123, Obj::of(['treeRoot' => Pca::b64u(str_repeat("\0", 32))])));
    }
}
