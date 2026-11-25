<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Adapters.php';
require_once __DIR__ . '/../src/PolicyTemplates.php';

use Atlas\Pca\Adapters;
use Atlas\Pca\ArgProvenance;
use Atlas\Pca\KeyPair;
use Atlas\Pca\PcaHeaderError;
use Atlas\Pca\Pca;
use Atlas\Pca\PolicyTemplates;
use PHPUnit\Framework\TestCase;

/** adapters.ts: header helpers, message segments, the provenance record helpers and bridgeToolCall. */
final class AdaptersTest extends TestCase
{
    private const NOW = 1800000000000;

    private function agent(): \Atlas\Pca\AgentHandle
    {
        return PolicyTemplates::fromTemplate('read-only', new KeyPair(str_repeat("\1", 32)), 'look', 'rs', null, self::NOW);
    }

    public function testHeaderRoundTripAndStrictness(): void
    {
        $h = Adapters::pcaHeaders('{"a":1}');
        self::assertSame(['PCA-Action' => Pca::b64u('{"a":1}')], $h);
        self::assertSame('{"a":1}', Adapters::decodePcaHeader($h['PCA-Action']));
        foreach (['', 'abc=', 'ab+c', "a b", 5, Pca::b64u("\xff\xfe")] as $bad) {
            try {
                Adapters::decodePcaHeader($bad);
                self::fail('accepted ' . var_export($bad, true));
            } catch (PcaHeaderError $e) {
                self::assertSame('invalid_pca_header', $e->errorCode);
            }
        }
        self::assertSame([], Adapters::provenanceHeaders(null));
        self::assertSame(8192, Adapters::PROV_HEADER_MAX);
    }

    public function testMessageSegments(): void
    {
        self::assertSame([], Adapters::messageSegments('hi'));
        self::assertSame([], Adapters::messageSegments(['role' => 'assistant', 'content' => 'x']));
        self::assertSame([['origin' => 'principal', 'source' => 'user', 'content' => 'hello']], Adapters::messageSegments(['role' => 'user', 'content' => 'hello']));
        self::assertSame([['origin' => 'principal', 'source' => 'user', 'content' => '']], Adapters::messageSegments(['role' => 'user']));
        self::assertSame([['origin' => 'tool', 'source' => 'search', 'content' => 'r']], Adapters::messageSegments(['role' => 'tool', 'name' => 'search', 'content' => 'r']));
        $mixed = Adapters::messageSegments(['role' => 'user', 'content' => [['type' => 'text', 'text' => 'a'], ['type' => 'tool_result', 'tool_use_id' => 'tu1', 'content' => 'out'],
            ['type' => 'text', 'text' => 'b'], 'plain']]);
        self::assertSame(['principal', 'tool'], array_column($mixed, 'origin'));
        self::assertSame("a\nb\nplain", $mixed[0]['content']);
        self::assertSame(['tu1', 'out'], [$mixed[1]['source'], $mixed[1]['content']]);
        self::assertSame('tool', Adapters::messageSegments(['role' => 'weird', 'content' => 'z'])[0]['origin']);
    }

    public function testRecordHelpersAreNoOpsWithoutARecorderAndFeedOneWithIt(): void
    {
        Adapters::recordPrincipal(null, 'x');
        Adapters::recordInput(null, 'x');
        Adapters::recordMessages(null, [['role' => 'user', 'content' => 'x']]);
        $a = $this->agent();
        $rec = $a->provenance;
        self::assertNotNull($rec);
        Adapters::recordInput($a, 'Pay the invoice');
        Adapters::recordToolResult($a, 'search', 'result text');
        $before = $rec->forAction(['verb' => 'github.read', 'resource' => 'r', 'params' => []]);
        self::assertSame(3, count($before->get('receipts')));
        Adapters::recordMessages($a, [['role' => 'user', 'content' => 'one'], ['role' => 'assistant', 'content' => 'ok']]);
        Adapters::recordMessages($a, [['role' => 'user', 'content' => 'one'], ['role' => 'assistant', 'content' => 'ok'], ['role' => 'user', 'content' => 'two']]);
        $after = $rec->forAction(['verb' => 'github.read', 'resource' => 'r', 'params' => []]);
        self::assertSame(6, count($after->get('receipts')), 'the earlier three, then one and two recorded once each, then the new action');
        $f = Adapters::withPrincipalInput($a, static fn(string $q): string => "ran $q");
        self::assertSame('ran again', $f('again'));
    }

    public function testBridgeToolCall(): void
    {
        $a = $this->agent();
        self::assertNull(Adapters::bridgeToolCall($a, ['name' => 'unknown', 'arguments' => []], static fn() => null));
        $c = Adapters::bridgeToolCall($a, ['name' => 'read', 'arguments' => ['path' => 'a']], static fn(array $call) => ['verb' => 'github.read', 'resource' => 'repo/' . $call['name']], 'other-rs');
        self::assertSame('other-rs', $c['pcactn']->get('aud'));
        self::assertArrayHasKey('PCA-Action', $c['headers']);
        self::assertSame($c['encoded'], Adapters::decodePcaHeader($c['headers']['PCA-Action']));
    }
}
