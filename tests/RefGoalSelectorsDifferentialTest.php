<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalCompiler;
use Atlas\Pca\GoalOntologies;
use Atlas\Pca\GoalOntology;
use Atlas\Pca\GoalSelectors as S;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/GoalSelectors.php';
require_once __DIR__ . '/../src/GoalCompiler.php';
require_once __DIR__ . '/../src/GoalOntology.php';

/**
 * The goal selectors against the TS reference: the verbs of a class selector, role resolution, expansion of a selector goal against
 * the pinned catalog, selector typing, role keys, the policy card and the carrier form. A shipped domain's catalog and ontology
 * travel by name (the first corpus) or may be given inline (the second corpus, which also holds a hand-written catalog with confirmed
 * verbs, the selector typing refusals, the catalog of a pack of defs and the compile of a selector goal). ref-goal-selectors.json.gz
 * is the same corpus as the second one, byte for byte.
 */
final class RefGoalSelectorsDifferentialTest extends TestCase
{
    private const FILE_A = 'ref-goal-selectors-py.json.gz';
    private const FILE_B = 'ref-goal-selectors-java.json.gz';

    public static function provide(): array
    {
        $out = [];
        foreach ([self::FILE_A, self::FILE_B] as $f) {
            foreach (Base::datasets($f) as $k => $v) {
                $out["$f $k"] = $v;
            }
        }
        return $out;
    }

    private static function dom(mixed $d): mixed
    {
        return GoalOntology::toIrOntology(GoalOntologies::shippedOntology($d));
    }

    private static function refOnt(mixed $x): mixed
    {
        return is_string($x) && GoalOntologies::shippedOntology($x) !== null ? GoalOntology::toIrOntology(GoalOntologies::shippedOntology($x)) : $x;
    }

    private static function refCat(mixed $x): mixed
    {
        return is_string($x) && GoalOntologies::shippedCatalog($x) !== null ? GoalOntologies::shippedCatalog($x) : $x;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $maps = [
            self::FILE_A => [
                'selCatalogOfDomain' => fn(array $a) => S::selCatalogOfDomain($a[0]),
                'selCatalogDigest' => fn(array $a) => S::selCatalogDigest($a[0]),
                'selGoalDigest' => fn(array $a) => S::selGoalDigest($a[0]),
                'classVerbs' => fn(array $a) => S::classVerbs($a[0], $a[1], $a[2]),
                'allowClassVerbs' => fn(array $a) => S::allowClassVerbs($a[0], $a[1], $a[2]),
                'floatClassVerbs' => fn(array $a) => S::floatClassVerbs($a[0], $a[1], $a[2]),
                'resolveRole' => fn(array $a) => S::resolveRole(self::dom($a[0]), $a[1], $a[2], $a[3]),
                'expandSelGoal' => fn(array $a) => S::expandSelGoal($a[0], self::dom($a[1]), $a[2]),
                'selReasons' => fn(array $a) => S::selReasons($a[0], self::dom($a[1]), $a[2]),
                'withRoleParams' => fn(array $a) => S::withRoleParams($a[0], $a[1]),
                'selCarrier' => fn(array $a) => S::selCarrier($a[0]),
                'encodeSelCatalog' => fn(array $a) => S::encodeSelCatalog($a[0]),
                'renderSelCard' => fn(array $a) => S::renderSelCard($a[0], self::dom($a[1]), $a[2]),
                'traitClosure' => fn(array $a) => S::traitClosure($a[0]),
            ],
            self::FILE_B => [
                'selCatalogDigest' => fn(array $a) => S::selCatalogDigest(self::refCat($a[0])),
                'selGoalDigest' => fn(array $a) => S::selGoalDigest($a[0]),
                'classVerbs' => fn(array $a) => S::classVerbs(self::refCat($a[0]), $a[1], $a[2]),
                'allowClassVerbs' => fn(array $a) => S::allowClassVerbs(self::refCat($a[0]), $a[1], $a[2]),
                'floatClassVerbs' => fn(array $a) => S::floatClassVerbs(self::refCat($a[0]), $a[1], $a[2]),
                'resolveRole' => fn(array $a) => S::resolveRole(self::refOnt($a[0]), self::refCat($a[1]), $a[2], $a[3]),
                'expandSelGoal' => fn(array $a) => S::expandSelGoal($a[0], self::refOnt($a[1]), self::refCat($a[2])),
                'selReasons' => fn(array $a) => S::selReasons($a[0], self::refOnt($a[1]), self::refCat($a[2])),
                'compileSelGoal' => fn(array $a) => S::compileSelGoal($a[0], self::refOnt($a[1]), self::refCat($a[2]), GoalCompiler::compileGoal(...)),
                'withRoleParams' => fn(array $a) => S::withRoleParams($a[0], self::refCat($a[1])),
                'renderSelCard' => fn(array $a) => S::renderSelCard($a[0], self::refOnt($a[1]), self::refCat($a[2])),
                'selCarrier' => fn(array $a) => S::selCarrier($a[0]),
                'encodeSelCatalog' => fn(array $a) => S::encodeSelCatalog(self::refCat($a[0])),
                'traitClosure' => fn(array $a) => S::traitClosure($a[0]),
                'catalogOfDomain' => fn(array $a) => S::selCatalogOfDomain($a[0]),
                'catalogOfDefs' => fn(array $a) => S::selCatalogOfDefs($a[0]),
            ],
        ];
        Base::run($file, $fn, $k, $maps[$file]);
    }
}
