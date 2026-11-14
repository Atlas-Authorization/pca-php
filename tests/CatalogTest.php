<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Catalog.php';

use Atlas\Pca\Catalog;
use PHPUnit\Framework\TestCase;

/** The built-in action catalog is the reference's catalog, entry for entry. */
final class CatalogTest extends TestCase
{
    private const KEYS = ['connector', 'action', 'verb', 'reversibility', 'blastRadius', 'amountField', 'description', 'aliases', 'traits'];

    public function testShape(): void
    {
        $verbs = array_column(Catalog::BUILTIN_ACTIONS, 'verb');
        self::assertSame(count($verbs), count(array_unique($verbs)));
        self::assertCount(21, $verbs);
        foreach (Catalog::BUILTIN_ACTIONS as $a) {
            self::assertContains($a['reversibility'], ['reversible', 'rate_limited', 'irreversible'], $a['verb']);
            self::assertTrue($a['blastRadius'] >= 0 && $a['blastRadius'] <= 1, $a['verb']);
        }
        $c = new Catalog();
        self::assertSame('stripe.refund', $c->resolve('stripe', 'issue_refund')['verb']);
        self::assertSame('stripe.refund', $c->resolve('stripe', 'refund')['verb']);
        self::assertNull($c->resolve('stripe', 'nope'));
        self::assertNull($c->resolve('gmail', 'issue_refund'));
    }

    public function testMatchesReference(): void
    {
        // the reference catalog sits in a parent directory (the monorepo, or the corpus the CI lays out): a missing file fails
        $ts = null;
        for ($d = __DIR__; $ts === null && dirname($d) !== $d; $d = dirname($d)) {
            $ts = is_file("$d/packages/pca/src/catalog-builtin.generated.ts") ? "$d/packages/pca/src/catalog-builtin.generated.ts" : null;
        }
        self::assertNotNull($ts, 'the reference catalog packages/pca/src/catalog-builtin.generated.ts was not found above the tests');
        $src = (string)file_get_contents($ts);
        self::assertSame(1, preg_match('/=\s*(\[.*\]);\s*$/s', $src, $m), 'catalog array not found');
        // one object literal per line with bare keys: quote the known keys, drop the trailing comma
        $text = preg_replace('/([{,] )(' . implode('|', self::KEYS) . '): /', '$1"$2": ', $m[1]);
        $ref = json_decode((string)preg_replace('/,\s*\]$/', ']', $text), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame($ref, Catalog::BUILTIN_ACTIONS);
    }
}
