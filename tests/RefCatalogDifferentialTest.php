<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Catalog.php';

use Atlas\Pca\Catalog;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The connector action catalog against the TS reference: every case of test-data/ref-catalog.json.gz. Specs are plain PHP arrays in
 * this SDK, so a corpus object becomes an array and a number a float ({"$num": ...} is that non-finite double). A catalog is driven
 * through one scenario per case: one result per op, {"$err": true} for an op that refuses. An op whose lookup argument is missing or
 * not a string finds nothing (the typed lookups take strings).
 */
final class RefCatalogDifferentialTest extends TestCase
{
    private const FILE = 'ref-catalog.json.gz';
    private const TOTAL = 75;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function plain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
            }
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::plain($v->get($k));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::plain(...), $v) : ($v instanceof Num ? $v->float() : $v);
    }

    /** @param list<mixed> $ops */
    private static function script(Catalog $cat, array $ops): array
    {
        $out = [];
        foreach ($ops as $op) {
            try {
                $str = static fn(int $i): bool => is_string($op[$i] ?? null);
                $out[] = match ($op[0]) {
                    'get' => $str(1) ? $cat->get($op[1]) : null,
                    'forConnector' => $cat->forConnector($op[1]),
                    'all' => $cat->all(),
                    'resolve' => $str(1) && $str(2) ? $cat->resolve($op[1], $op[2]) : null,
                    'resolveAction' => Catalog::resolveAction($cat, $op[1]),
                    'digest' => Catalog::catalogDigest($cat),
                    'assertPinned' => Catalog::assertCatalogPinned($cat, $op[1] === '$self' ? Catalog::catalogDigest($cat) : $op[1]) ?? true,
                    'extend' => (static function () use ($cat, $op): array {
                        $e = Catalog::extendCatalog($cat, self::plain($op[1]));
                        return ['all' => $e->all(), 'digest' => Catalog::catalogDigest($e)];
                    })(),
                };
            } catch (\Throwable) {
                $out[] = Obj::of(['$err' => true]);
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'defineAction' => static fn(array $a) => Catalog::defineAction(self::plain($a[0])),
            'uncataloguedSpec' => static fn(array $a) => Catalog::uncataloguedSpec($a[0]),
            'builtin' => static fn(array $a) => ['actions' => Catalog::BUILTIN_ACTIONS, 'digest' => Catalog::catalogDigest(Catalog::defaultCatalog()), 'blast' => Catalog::BLAST],
            'catalog' => static fn(array $a) => self::script(Catalog::buildCatalog($a[0] === null ? null : self::plain($a[0])), $a[1]),
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
