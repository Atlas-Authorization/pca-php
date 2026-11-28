<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Dlp;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The data-flow governance (DLP) evaluation against the TS reference: test-data/ref-dlp.json.gz. */
final class RefDlpDifferentialTest extends TestCase
{
    private const FILE = 'ref-dlp.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'evaluateDlp' => fn(array $a) => Dlp::evaluateDlp($a[0], $a[1]),
            'defaultDlpPolicy' => fn(array $a) => Dlp::defaultDlpPolicy($a[0]),
        ]);
    }
}
