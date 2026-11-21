<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Decide;
use Atlas\Pca\MpcParty;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The Policy VM decision (Decide::decide) against the TS reference: test-data/ref-decide-java.json.gz (reasons compared in order). */
final class RefDecideDifferentialTest extends TestCase
{
    private const FILE = 'ref-decide-java.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, ['decide' => static fn(array $a) => Decide::decide($a[0])]);
    }

    public function testEvaluatePartyDistillsTheDecision(): void
    {
        $v = MpcParty::evaluateParty(null); // no grant: denied, the worst vector
        $this->assertSame(['allow' => 0, 't' => 3, 'rQuant' => 100], $v);
    }
}
