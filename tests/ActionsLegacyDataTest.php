<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsBuiltin.php';

use Atlas\Pca\ActionsBuiltin;
use PHPUnit\Framework\TestCase;

/** The recorded data of the migration from the old catalog and ontologies: what each built-in verb said before, and how every disagreement was settled. */
final class ActionsLegacyDataTest extends TestCase
{
    public function testTheLegacyCatalogCoversEveryBuiltInVerb(): void
    {
        $verbs = array_map(static fn($d): string => $d->get('verb'), ActionsBuiltin::builtinDefs());
        sort($verbs);
        $have = array_keys(ActionsBuiltin::LEGACY_CATALOG);
        sort($have);
        $this->assertSame($verbs, $have);
        $this->assertCount(21, ActionsBuiltin::LEGACY_CATALOG);
        $this->assertSame(['reversibility' => 'rate_limited', 'blastRadius' => 0.9], ActionsBuiltin::LEGACY_CATALOG['stripe.refund']);
        $this->assertSame(['reversibility' => 'reversible', 'blastRadius' => 0.05], ActionsBuiltin::LEGACY_CATALOG['http.get']);
    }

    public function testTheOntologyAndTheResolutionsAreRecorded(): void
    {
        $this->assertSame(['stripe.refund' => 'irreversible', 'stripe.charge' => 'irreversible', 'stripe.payout' => 'irreversible'], ActionsBuiltin::LEGACY_ONTOLOGY_EFFECT);
        $this->assertCount(13, ActionsBuiltin::RESOLUTIONS);
        foreach (ActionsBuiltin::RESOLUTIONS as $r) {
            $this->assertSame(['verb', 'field', 'was', 'now', 'reason'], array_keys($r));
        }
        // where two sources disagreed on a class the stricter one was taken
        $this->assertSame('irreversible', ActionsBuiltin::RESOLUTIONS[0]['now']);
    }
}
