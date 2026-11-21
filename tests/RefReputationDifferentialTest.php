<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Reputation.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Reputation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Reputation and coverage pricing against the TS reference: every case of test-data/ref-reputation.json.gz (the validator and the
 * fail-closed edges), the reputation cases of test-data/ref-core-sweep-java.json.gz (scoring, priceCoverage, the signed coverage
 * quote) and the disputesFromSettlements cases of test-data/ref-core-research-java.json.gz; those two corpora are shared by several
 * modules, each replays its own functions and asserts their counts. Keys are seed labels: the underwriter is
 * sha256("atlas-pca-conformance/sweep/underwriter"), the guardian "atlas-pca-conformance/research/guardian"; "@u" / "@g" stand for
 * their public keys. {"$num": ...} is that non-finite double; a null `now` of verifyCoverageQuote is NaN.
 */
final class RefReputationDifferentialTest extends TestCase
{
    private const FILE = 'ref-reputation.json.gz';
    private const TOTAL = 85;
    private const SHARED = ['ref-core-sweep-java.json.gz' => ['reputation' => 48, 'priceCoverage' => 226, 'issueCoverageQuote' => 43, 'verifyCoverageQuote' => 27],
        'ref-core-research-java.json.gz' => ['disputesFromSettlements' => 42]];

    public static function provide(): array
    {
        $out = Base::datasets(self::FILE);
        foreach (self::SHARED as $file => $fns) {
            foreach (Base::datasets($file) as $k => $v) {
                if (isset($fns[$v[1]])) {
                    $out["$file $k"] = $v;
                }
            }
        }
        return $out;
    }

    private static function key(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $label, true));
    }

    /** {"$num"} to the double, everywhere. */
    private static function un(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::un(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if ($v->keys() === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::un($v->get($k)));
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['MAX_REPUTATION_RECORDS' => Reputation::MAX_REPUTATION_RECORDS, 'COVERAGE_QUOTE_DOMAIN' => Reputation::COVERAGE_QUOTE_DOMAIN],
            'validateReputationInput' => static fn(array $a) => Reputation::validateReputationInput(self::un($a[0])),
            'reputation' => static fn(array $a) => Reputation::reputation(self::un($a[0])),
            'priceCoverage' => static fn(array $a) => Reputation::priceCoverage($a[0], $a[1], $a[2]),
            'issueCoverageQuote' => static fn(array $a) => Reputation::issueCoverageQuote($a[0], $a[1], self::key('sweep/underwriter'), $a[2], $a[3], $a[4]),
            'verifyCoverageQuote' => static fn(array $a) => Reputation::verifyCoverageQuote($a[0], $a[1] === '@u' ? self::key('sweep/underwriter')->public : $a[1], $a[2] ?? NAN),
            'disputesFromSettlements' => static fn(array $a) => Reputation::disputesFromSettlements($a[0], $a[1] === '@g' ? self::key('research/guardian')->public : $a[1],
                static fn(string $id): ?string => $a[2]->has($id) ? $a[2]->get($id) : null, $a[3]),
        ]);
    }

    public function testTheRecordCapIsEnforced(): void
    {
        $event = Obj::of(['outcome' => 'auto']);
        $over = Obj::of(['subject' => 's', 'events' => array_fill(0, Reputation::MAX_REPUTATION_RECORDS + 1, $event)]);
        $this->assertSame('too many records', Reputation::validateReputationInput($over));
        $at = Obj::of(['subject' => 's', 'events' => array_fill(0, Reputation::MAX_REPUTATION_RECORDS, $event)]);
        $this->assertNull(Reputation::validateReputationInput($at));
    }

    public function testCorporaHaveTheExpectedCaseTotals(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
        foreach (self::SHARED as $file => $fns) {
            $have = array_fill_keys(array_keys($fns), 0);
            foreach (gzfile(Base::path($file)) as $line) {
                foreach ($have as $fn => $_) {
                    $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
                }
            }
            $this->assertSame($fns, $have, $file);
        }
    }
}
