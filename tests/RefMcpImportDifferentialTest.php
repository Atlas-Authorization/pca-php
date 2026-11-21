<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Mcp;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/Mcp.php';

/** importActionDefsFromMcp (import, then the default rule-based suggestions) against the TS reference: test-data/ref-mcp-import.json.gz. */
final class RefMcpImportDifferentialTest extends TestCase
{
    private const FILE = 'ref-mcp-import.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'importActionDefsFromMcp' => fn(array $a) => Mcp::importActionDefsFromMcp($a[0], $a[1]),
        ]);
    }

    public function testTheDefaultSuggestionsMarkTheDefsSuggestedNotConfirmed(): void
    {
        $r = Mcp::importActionDefsFromMcp([\Atlas\Pca\Obj::of(['name' => 'send_mail', 'inputSchema' => \Atlas\Pca\Obj::of(['type' => 'object',
            'properties' => \Atlas\Pca\Obj::of(['to' => \Atlas\Pca\Obj::of(['type' => 'string'])])])])], \Atlas\Pca\Obj::of(['ns' => 'mcp']));
        self::assertCount(1, $r->get('defs'));
        self::assertSame('mcp.mail.send', $r->get('defs')[0]->get('verb'));
        self::assertSame('suggested', $r->get('defs')[0]->get('review')->get('state'));
        self::assertFalse($r->get('defs')[0]->get('review')->has('attestation'));
        self::assertSame([], $r->get('todo'));
    }
}
