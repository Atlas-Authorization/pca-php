<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Catalog.php';

use Atlas\Pca\Catalog;
use PHPUnit\Framework\TestCase;

/** Group 36a mutation kills for src/Catalog.php: extensions may only tighten (named refusal), and non-string verbs are read as text. */
final class RestSurvivorKill36aCatalogTest extends TestCase
{
    /** A lower or unknown reversibility class over an existing verb is refused, naming the verb; a tighter spec replaces it. */
    public function testLessCautiousExtensionIsRefusedNamingTheVerb(): void
    {
        $base = Catalog::defaultCatalog();
        foreach (['reversible', 'weird'] as $class) {
            try {
                Catalog::extendCatalog($base, [['verb' => 'stripe.charge', 'reversibility' => $class, 'blastRadius' => 0.9]]);
                self::fail("reversibility $class loosened stripe.charge");
            } catch (\InvalidArgumentException $e) {
                self::assertSame("extendCatalog: 'stripe.charge' would be less cautious than the existing entry", $e->getMessage());
            }
        }
        $t = Catalog::extendCatalog($base, [['verb' => 'stripe.charge', 'reversibility' => 'irreversible', 'blastRadius' => 1]]);
        self::assertSame(1, $t->get('stripe.charge')['blastRadius']);
    }

    /** A numeric verb is looked up and ordered by its text (String(verb)), never a type error. */
    public function testNumericVerbsAreReadAsText(): void
    {
        $base = Catalog::defaultCatalog();
        $t = Catalog::extendCatalog($base, [['verb' => 5, 'reversibility' => 'irreversible', 'blastRadius' => 1]]);
        self::assertCount(count($base->all()) + 1, $t->all());
        $d = Catalog::catalogDigest(Catalog::buildCatalog([['verb' => 5], ['verb' => 6]]));
        self::assertSame($d, Catalog::catalogDigest(Catalog::buildCatalog([['verb' => 6], ['verb' => 5]])));
        self::assertNotSame($d, Catalog::catalogDigest(Catalog::buildCatalog([['verb' => 5], ['verb' => 7]])));
    }
}
