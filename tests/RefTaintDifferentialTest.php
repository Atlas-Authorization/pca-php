<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Taint.php';

use Atlas\Pca\InMemoryTaintRegistry;
use Atlas\Pca\Obj;
use Atlas\Pca\Taint;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The information-flow taint lattice, the trusted-input registry, classifyRef and computeTaint against the TS reference: every case of
 * test-data/ref-taint.json.gz. A registry spec is {records: [[digest, label]...]} (junk records are part of the test), {mode: "throws"}
 * (lookup always throws), {mode: "fixed", fixed} (lookup returns `fixed` for every digest) or null (no registry); a graph spec is null,
 * {nodes: [id...]} or {nodes, throws: true}.
 */
final class RefTaintDifferentialTest extends TestCase
{
    private const FILE = 'ref-taint.json.gz';
    private const FNS = ['constants' => 1, 'isTaintLevel' => 24, 'labelRank' => 27, 'taintValue' => 27, 'joinLabel' => 400, 'joinLabels' => 25,
        'registry' => 9, 'classifyRef' => 841, 'computeTaint' => 990];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** An absent registry: the reference reads a member of undefined the moment a string ref is looked up. */
    private static function noRegistry(): object
    {
        return new class {
            public function lookup(string $digest): mixed
            {
                throw new \TypeError('Cannot read properties of undefined (reading \'lookup\')');
            }
        };
    }

    private static function registry(mixed $rs): ?object
    {
        if ($rs === null) {
            return null;
        }
        if ($rs->get('mode') === 'fixed') {
            $fixed = $rs->get('fixed');
            return new class($fixed) {
                public function __construct(private readonly mixed $fixed)
                {
                }

                public function lookup(string $digest): mixed
                {
                    return $this->fixed;
                }
            };
        }
        if ($rs->get('mode') === 'throws') {
            return new class {
                public function lookup(string $digest): mixed
                {
                    throw new \RuntimeException('registry boom');
                }
            };
        }
        $r = new InMemoryTaintRegistry();
        foreach ($rs->get('records') ?? [] as [$d, $l]) {
            $r->record($d, $l);
        }
        return $r;
    }

    private static function graph(mixed $gs): ?object
    {
        if ($gs === null || $gs === false) {
            return null;
        }
        $nodes = $gs->get('nodes') ?? [];
        $throws = $gs->get('throws') === true;
        return new class($nodes, $throws) {
            public function __construct(private readonly array $nodes, private readonly bool $throws)
            {
            }

            public function node(string $id): mixed
            {
                if ($this->throws) {
                    throw new \RuntimeException('graph boom');
                }
                return in_array($id, $this->nodes, true) ? Obj::of(['id' => $id]) : null;
            }
        };
    }

    private static function registryOps(array $ops): array
    {
        $r = new InMemoryTaintRegistry();
        $out = [];
        foreach ($ops as $op) {
            $a = array_slice($op, 1);
            $out[] = match ($op[0]) {
                'lookup' => $r->lookup($a[0]),
                'size' => $r->size(),
                'emptyLookup' => null,
                'record' => $r->record($a[0], $a[1]) ? null : null,
                'recordTrusted' => $r->recordTrusted($a[0]) ? null : null,
                'recordFirstParty' => $r->recordFirstParty($a[0]) ? null : null,
                'recordTool' => $r->recordTool($a[0], $a[1]) ? null : null,
                'recordWeb' => $r->recordWeb($a[0]) ? null : null,
                default => throw new \LogicException('op'),
            };
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['TAINT_LEVELS' => Taint::LEVELS, 'BOTTOM' => Taint::bottom(), 'TOP' => Taint::top()],
            'isTaintLevel' => static fn(array $a) => Taint::isLevel($a[0]),
            'labelRank' => static fn(array $a) => Taint::labelRank($a[0]),
            'taintValue' => static fn(array $a) => Taint::taintValue($a[0]),
            'joinLabel' => static fn(array $a) => Taint::joinLabel($a[0], $a[1]),
            'joinLabels' => static fn(array $a) => Taint::joinLabels($a[0]),
            'registry' => static fn(array $a) => self::registryOps($a[0]),
            'classifyRef' => static fn(array $a) => Taint::classifyRef($a[0], self::registry($a[1]->get('registry')) ?? self::noRegistry(), self::graph($a[1]->get('graph'))),
            'computeTaint' => static fn(array $a) => Taint::computeTaint($a[0], self::registry($a[1]->get('registry')), self::graph($a[1]->get('graph'))),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
