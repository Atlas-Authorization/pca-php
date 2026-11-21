<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Mcp;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The MCP adapter against the TS reference: test-data/ref-mcp.json.gz (step-up client, iss table, tool-result meta, header, v1 action
 * schema draft with its decisions and the closed-world tool-call check). The reference's withPCA / pcaFetch need a live agent and
 * fetch, so they have no vectors: the request reader and the denied result are checked below.
 */
final class RefMcpDifferentialTest extends TestCase
{
    private const FILE = 'ref-mcp.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn(array $a) => ['MCP_CLIENT_REVISIONS' => Mcp::MCP_CLIENT_REVISIONS, 'MCP_AUTH_CLIENT_ROWS' => Mcp::mcpAuthClientRows()],
            'parseChallenges' => fn(array $a) => Mcp::parseChallenges($a[0]),
            'pcaNeedProblem' => fn(array $a) => Mcp::pcaNeedProblem($a[0]),
            'planStepUp' => fn(array $a) => Mcp::planStepUp($a[0], $a[1], $a[2]),
            'checkAuthorizationResponseIss' => fn(array $a) => Mcp::checkAuthorizationResponseIss($a[0]),
            'guardToolResult' => fn(array $a) => Mcp::guardToolResult($a[0], $a[1]),
            'pcaHeaders' => fn(array $a) => ['PCA-Action' => Mcp::pcaHeaders($a[0])['PCA-Action']],
            'draftActionSchemaFromMcp' => fn(array $a) => Mcp::draftActionSchemaFromMcp($a[0], $a[1]),
            'applySchemaDecisions' => fn(array $a) => Mcp::applySchemaDecisions($a[0], $a[1]),
            'verbOfTool' => fn(array $a) => Mcp::verbOfTool($a[0], $a[1]),
            'conformToolCall' => fn(array $a) => Mcp::conformToolCall($a[0], $a[1], $a[2]),
        ]);
    }

    public function testToolCallReaderReadsOnlyToolsCall(): void
    {
        $c = Mcp::toolCallOf('{"jsonrpc":"2.0","method":"tools/call","params":{"name":"pay","arguments":{"a":1}}}');
        $this->assertSame('pay', $c['name']);
        $this->assertSame(['a'], $c['arguments']->keys());
        $none = Mcp::toolCallOf('{"method":"tools/call","params":{"name":"pay","arguments":[1]}}');
        $this->assertSame([], $none['arguments']->keys()); // arguments that are not an object count as none
        foreach (['{"method":"tools/list"}', '{"method":"tools/call","params":{"name":5}}', 'not json', '[]', null] as $bad) {
            $this->assertNull(Mcp::toolCallOf($bad));
        }
    }

    public function testDeniedResultIsAnErrorTextItem(): void
    {
        $r = Mcp::deniedResult('no');
        $this->assertTrue($r->get('isError'));
        $this->assertSame('no', $r->get('content')[0]->get('text'));
    }
}
