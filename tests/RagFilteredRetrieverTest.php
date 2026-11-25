<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Rag.php';
require_once __DIR__ . '/../src/PcaTesting.php';
require_once __DIR__ . '/../src/Payments.php';
require_once __DIR__ . '/../src/PqThreshold.php';

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Payments;
use Atlas\Pca\PcaTesting;
use Atlas\Pca\PqThreshold;
use Atlas\Pca\Rag;
use PHPUnit\Framework\TestCase;

/** withPcaFilter (pca-rag), testAgent / makePCActn (pca-testing) and two small constants. */
final class RagFilteredRetrieverTest extends TestCase
{
    public function testWrapperFiltersLikeFilterDocumentsAndRecordsRetrievals(): void
    {
        $doc = Json::parseLax((string)gzdecode((string)file_get_contents(__DIR__ . '/../test-data/ref-rag.json.gz')));
        $case = array_values(array_filter($doc->get('cases'), static fn(Obj $c) => $c->get('fn') === 'filterDocuments'))[0];
        [$principal, $docs, $policy] = $case->get('args');
        $expected = Rag::filterDocuments($principal, $docs, $policy);
        $f = Rag::withPcaFilter(static fn(string $q, ?int $k): array => $docs, $principal, $policy);
        self::assertNull($f->lastDecision());
        self::assertEquals($expected['documents'], $f->retrieve('anything'));
        self::assertEquals($expected['decision'], $f->lastDecision());
        self::assertSame([], Rag::withPcaFilter(static fn() => 'not a list', $principal, $policy)->retrieve('q'));
    }

    public function testTestAgentAndMakePcactn(): void
    {
        $a = PcaTesting::testAgent();
        $r = PcaTesting::makePCActn($a, 'stripe.refund', 'ch_12345678', ['amount' => 100], null, 1800000000000);
        self::assertSame('ins_test', $r['pcactn']->get('aud'));
        self::assertSame($r['encoded'], \Atlas\Pca\Json::canonicalizeLenient($r['pcactn']));
        $r2 = PcaTesting::makePCActn($a, 'stripe.refund', 'ch_12345678', ['amount' => 100], 7, 1800000000000);
        self::assertSame('7', $r2['pcactn']->get('counter')->lexeme);
        $b = PcaTesting::testAgent(['aud' => 'other', 'limits' => [], 'permissions' => ['github' => ['read']]]);
        self::assertSame('other', PcaTesting::makePCActn($b, 'github.read', 'r', null, null, 1800000000000)['pcactn']->get('aud'));
    }

    public function testConstants(): void
    {
        self::assertSame(1, preg_match(Payments::MCC_TRAIT_RE, 'mcc.c5734'));
        self::assertSame(0, preg_match(Payments::MCC_TRAIT_RE, 'mcc.c573'));
        self::assertSame(PqThreshold::PQ_QUORUM_ALG, PqThreshold::HYBRID_PQ_ALG);
    }
}
