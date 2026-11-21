<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalKernel.php';

use Atlas\Pca\GoalIrError;
use Atlas\Pca\GoalKernel as K;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The goal kernel against the TS reference: test-data/ref-goal-kernel.json.gz. One case per goal; for it the typecheck, compile and
 * render tapes and, per probe, the reference-semantics and compiled-policy tapes (decision, witness, witness check), each compared
 * byte for byte as harness text.
 */
final class RefGoalKernelDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-kernel.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        self::assertSame('kernel', $fn);
        $bad = [];
        $n = 0;
        foreach (Base::cases($file, $fn, $k) as $c) {
            $n++;
            $name = (string) $c->get('name');
            $args = $c->get('args');
            $want = $c->get('out');
            $g = K::tapeFromText($args[0]);
            $o = K::tapeFromText($args[1]);
            foreach (['typecheck', 'compile', 'render'] as $op) {
                $got = K::tapeToText(K::kernelCall($op, $g, $o));
                if ($got !== $want->get($op)) {
                    $bad[] = "$name $op: " . substr($got, 0, 120) . ' != ' . substr((string) $want->get($op), 0, 120);
                }
            }
            $probes = $want->get('probes');
            self::assertCount(count($args[2]), $probes);
            foreach ($args[2] as $i => [$a, $h]) {
                $at = K::tapeFromText($a);
                $ht = K::tapeFromText($h);
                foreach (['decideg', 'decidep'] as $j => $op) {
                    $got = K::tapeToText(K::kernelCall($op, $g, $o, $at, $ht));
                    if ($got !== $probes[$i][$j]) {
                        $bad[] = "$name#$i $op: $got != {$probes[$i][$j]}";
                    }
                }
            }
        }
        self::assertGreaterThan(0, $n);
        self::assertSame([], array_slice($bad, 0, 25), count($bad) . ' divergent tape(s)');
    }

    public function testTapeTextRoundTrip(): void
    {
        foreach (Base::cases(self::FILE, 'kernel', 0) as $c) {
            foreach ([$c->get('args')[0], $c->get('args')[1], $c->get('out')->get('compile')] as $x) {
                self::assertSame($x, K::tapeToText(K::tapeFromText($x)));
            }
        }
        self::assertSame([['k', 5], ['i', -3], ['s', ''], ['s', "h\u{1f600}"]], K::tapeFromText('k5 i-3 s s68.1f600'));
    }

    public function testMalformedInputIsRefused(): void
    {
        self::assertSame([['i', 9]], K::kernelCall('typecheck', [['i', 7]], []));
        self::assertSame([['i', 9]], K::kernelCall('render', []));
        try {
            K::kernelCall('typecheck', [['k', 1.5]], []);
            self::fail('a fractional token must be refused');
        } catch (GoalIrError) {
        }
        try {
            K::kernelCall('typecheck', [['i', 2 ** 60]], []);
            self::fail('an unsafe integer must be refused');
        } catch (GoalIrError) {
        }
        $this->expectException(\InvalidArgumentException::class);
        K::kernelCall('nope', [], []);
    }
}
