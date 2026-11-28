<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcBeaver;
use Atlas\Pca\MpcField;
use Atlas\Pca\MpcFieldRng;
use Atlas\Pca\MpcSharing;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcBeaver: the triple count of genTriples and the party-count refusals of beaverMul (each triple part checked). */
final class MpcSurvivorKill34MpcBeaverTest extends TestCase
{
    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame($class, $e::class, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("expected $class: $msg");
    }

    /** @return list<\GMP> */
    private static function sv(int ...$v): array
    {
        return array_map(static fn(int $x): \GMP => gmp_init($x), $v);
    }

    /** genTriples returns exactly $count valid triples (c = a*b), each shared among n parties; zero asks for none. */
    public function testGenTriplesReturnsExactlyCountValidTriples(): void
    {
        $t = MpcBeaver::genTriples(3, 2, new MpcFieldRng(gmp_init(34)));
        $this->assertCount(3, $t);
        foreach ($t as $tr) {
            $this->assertCount(2, $tr['a']);
            $a = MpcSharing::reconstruct($tr['a']);
            $b = MpcSharing::reconstruct($tr['b']);
            $this->assertSame(gmp_strval(MpcField::fmul($a, $b)), gmp_strval(MpcSharing::reconstruct($tr['c'])));
        }
        $this->assertSame([], MpcBeaver::genTriples(0, 2, new MpcFieldRng(gmp_init(34))));
    }

    /** Operands with different party counts are refused before any triple is touched. */
    public function testOperandPartyCountsMustMatch(): void
    {
        $tr = MpcBeaver::genTriple(2, new MpcFieldRng(gmp_init(7)));
        self::refuses(\InvalidArgumentException::class, 'beaverMul: operand party counts differ', static fn() => MpcBeaver::beaverMul(self::sv(1, 2), self::sv(3), $tr));
    }

    /** A triple whose a, b or c part has another party count than the operands is refused with the triple message (every part checked). */
    public function testEveryTriplePartMustMatchThePartyCount(): void
    {
        $tr = MpcBeaver::genTriple(2, new MpcFieldRng(gmp_init(7)));
        $x = self::sv(1, 2);
        $y = self::sv(3, 4);
        $msg = 'beaverMul: triple party count differs from the operands';
        foreach (['a', 'b', 'c'] as $k) {
            $bad = $tr;
            $bad[$k] = self::sv(5);
            self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcBeaver::beaverMul($x, $y, $bad));
        }
        // control: the well-formed triple multiplies (1+2)*(3+4) = 21
        $this->assertSame('21', gmp_strval(MpcSharing::reconstruct(MpcBeaver::beaverMul($x, $y, $tr))));
    }
}
