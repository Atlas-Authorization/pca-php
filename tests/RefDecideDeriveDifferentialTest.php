<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Decide.php';

use Atlas\Pca\Decide;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * How a verifier assembles the Policy VM input from a PCActn and its own context, and the decision on that input, against the TS
 * reference: every case of test-data/ref-decide-derive.json.gz. A refusal that carries a code (`grant_required`) must carry the same code.
 */
final class RefDecideDeriveDifferentialTest extends TestCase
{
    private const FILE = 'ref-decide-derive.json.gz';
    private const TOTAL = 240;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'deriveDecideInput' => static fn(array $a) => Decide::deriveDecideInput($a[0], $a[1]),
            'deriveThenDecide' => static function (array $a) {
                $input = Decide::deriveDecideInput($a[0], $a[1]);
                return ['input' => $input, 'decision' => Decide::decide($input)];
            },
        ]);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
    }
}
