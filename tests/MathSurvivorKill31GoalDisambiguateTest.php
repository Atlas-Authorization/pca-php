<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalDisambiguate.php';

use Atlas\Pca\GoalDisambiguate;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of disambiguate.ts: the engine's Math.log2 bit for bit, the binary entropy edges, question risk and mass. */
final class MathSurvivorKill31GoalDisambiguateTest extends TestCase
{
    private static function call(string $fn, float $x): float
    {
        return (new \ReflectionMethod(GoalDisambiguate::class, $fn))->invoke(null, $x);
    }

    private static function bits(float $x): string
    {
        return bin2hex(pack('E', $x));
    }

    private static function mk(int $hi, int $lo): float
    {
        return unpack('E', pack('N2', $hi, $lo))[1];
    }

    /** Math.log2 as node computes it, including subnormals, the exact-one shortcut neighbours and both sides of the sqrt(2) split. */
    public function testLog2MatchesTheEngine(): void
    {
        $want = [
            [5e-324, -1074.0], [1.5e-323, -1072.415037499279], [1e300, 996.5784284662087], [1.0, 0.0],
            [self::mk(0x3ff00000, 1), 3.203426503814917e-16], [self::mk(0x3fefffff, 0), -6.879307674667236e-7], [self::mk(0x3ff00001, 0), 0.000001375860550841138],
            [3.0, 1.584962500721156], [0.3, -1.7369655941662063], [1.7, 0.765534746362977], [0.6, -0.7369655941662062], [0.1, -3.321928094887362],
            [0.7071056365966796, -0.5000023352844389], [4.315832689171653e-05, -14.500001537131968],
        ];
        foreach ($want as [$x, $y]) {
            self::assertSame(self::bits($y), self::bits(self::call('log2', $x)), "log2($x)");
        }
    }

    /** The binary entropy is +0 at 0 and 1 (not -0) and 1 at one half. */
    public function testBinaryEntropyEdges(): void
    {
        self::assertSame(self::bits(0.0), self::bits(self::call('h2', 0.0)));
        self::assertSame(self::bits(0.0), self::bits(self::call('h2', 1.0)));
        self::assertSame(1.0, self::call('h2', 0.5));
    }

    /** @return array{0:list<mixed>,1:Obj} the readings and ontology of the first questions corpus case */
    private static function corpus(): array
    {
        foreach (Base::cases('ref-goal-nversion.json.gz', 'questions', 0) as $c) {
            if ($c->get('name') === 'questions/27') {
                return $c->get('args');
            }
        }
        self::fail('no corpus case questions/27');
    }

    /** @return list<float> */
    private static function scores(array $opts): array
    {
        [$readings] = self::corpus();
        return array_map(fn(Obj $q) => $q->get('score'), GoalDisambiguate::questions($readings, $opts));
    }

    /** An unknown effect class and a non-string one both default to risk 10 (an even split scores risk x mass). */
    public function testDefaultRisk(): void
    {
        foreach (['weird', 5] as $cls) {
            [, $ont] = self::corpus();
            foreach ($ont->get('verbs') as $v) {
                $v->set('cls', $cls);
            }
            self::assertSame(array_fill(0, 5, 10.0), self::scores(['ont' => $ont]), "cls $cls");
        }
    }

    /** A caller's riskOf (a JSON number) and massOf multiply the entropy. */
    public function testCustomRiskAndMass(): void
    {
        [, $ont] = self::corpus();
        $s = self::scores(['ont' => $ont, 'riskOf' => static fn(mixed $a): Num => new Num('3'), 'massOf' => static fn(mixed $a): int => 2]);
        self::assertSame(array_fill(0, 5, 6.0), $s);
    }
}
