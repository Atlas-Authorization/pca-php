<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentStatement;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Intent statements against the TS reference: test-data/ref-intent-statement.json.gz (sign output, verdicts, ref, goal strings). */
final class RefIntentStatementDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-statement.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'signIntent' => fn(array $a) => IntentStatement::signIntent($a[0], (string)Pca::unb64u($a[1], 32)),
            'verifyIntent' => function (array $a): array {
                $r = IntentStatement::verifyIntent($a[0], $a[1] ?? null);
                // the strict-canonical error text after the fixed prefix is the reference's own wording
                return str_starts_with((string)($r['reason'] ?? ''), 'malformed intent statement') ? ['ok' => false, 'reason' => 'malformed intent statement'] : $r;
            },
            'intentRef' => fn(array $a) => IntentStatement::intentRef($a[0]),
            'intentGoal' => fn(array $a) => IntentStatement::intentGoal($a[0], $a[1] ?? null),
            'parseIntentGoal' => fn(array $a) => IntentStatement::parseIntentGoal($a[0]),
        ]);
    }
}
