<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalOntologies;
use Atlas\Pca\GoalOntology;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The goal ontology against the TS reference: test-data/ref-goal-ontology.json.gz (verb resolution, IR projection, the
 * well-formedness checker, template instantiation, slot typing, locale-aware amount parsing and the shipped ontology data).
 * A shipped ontology travels by name; a hand-written one inline. A null slot value is the reference's undefined.
 */
final class RefGoalOntologyDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-ontology.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function ont(mixed $x): mixed
    {
        return is_string($x) && GoalOntologies::shippedOntology($x) !== null ? GoalOntologies::shippedOntology($x) : $x;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'shippedOntology' => fn(array $a) => GoalOntologies::shippedOntology($a[0]),
            'shippedCatalog' => fn(array $a) => GoalOntologies::shippedCatalog($a[0]),
            'ontologyDigest' => fn(array $a) => GoalOntology::ontologyDigest(self::ont($a[0])),
            'resolveVerb' => fn(array $a) => GoalOntology::resolveVerb(self::ont($a[0]), $a[1]),
            'goalCcy' => fn(array $a) => GoalOntology::goalCcy($a[0]),
            'goalAnchors' => fn(array $a) => GoalOntology::goalAnchors($a[0]),
            'toIrOntology' => fn(array $a) => GoalOntology::toIrOntology(self::ont($a[0]), $a[1] ?? null),
            'ontologyForGoal' => fn(array $a) => GoalOntology::ontologyForGoal(self::ont($a[0]), $a[1], $a[2] ?? null),
            'checkOntology' => fn(array $a) => GoalOntology::checkOntology(self::ont($a[0])),
            'instantiateTemplate' => fn(array $a) => GoalOntology::instantiateTemplate(self::ont($a[0]), $a[1], $a[2], $a[3]),
            'slotLits' => fn(array $a) => GoalOntology::slotLits(self::ont($a[0]), $a[1], ($a[2] ?? null) === null ? AnalyzerJs::undef() : $a[2]),
            'parseHumanAmount' => fn(array $a) => GoalOntology::parseHumanAmount($a[0], $a[1], $a[2] ?? null),
            'parseMoney' => fn(array $a) => GoalOntology::parseMoney($a[0], $a[1], $a[2] ?? null),
        ]);
    }
}
