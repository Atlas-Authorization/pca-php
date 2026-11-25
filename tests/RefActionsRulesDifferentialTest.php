<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsRules;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsRules.php';

/** Business rules (validation, compile, evaluate, explain, lint, diff, signed review) against the TS reference: test-data/ref-actions-rules-py.json.gz. */
final class RefActionsRulesDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-rules-py.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'resolveParamRef' => fn(array $a) => ActionsRules::resolveParamRef($a[0], $a[1], $a[2]),
            'moneyOf' => fn(array $a) => ActionsRules::moneyOf($a[0]),
            'minorUnits' => fn(array $a) => ActionsRules::minorUnits($a[0], $a[1], $a[2]),
            'knownTimeZone' => fn(array $a) => ActionsRules::knownTimeZone($a[0]),
            'businessRulesError' => fn(array $a) => ActionsRules::businessRulesError($a[0], $a[1]),
            'businessRulesDigest' => fn(array $a) => ActionsRules::businessRulesDigest($a[0], $a[1]),
            'compileBusinessRules' => fn(array $a) => ActionsRules::compileBusinessRules($a[0], $a[1]),
            'clockAt' => fn(array $a) => ActionsRules::clockAt($a[0], $a[1]),
            'evaluateBusinessRules' => fn(array $a) => ActionsRules::evaluateBusinessRules($a[0], $a[1]),
            'runRuleExamples' => fn(array $a) => ActionsRules::runRuleExamples($a[0], $a[1]),
            'formatMoney' => fn(array $a) => ActionsRules::formatMoney((int)$a[0]->int(), $a[1], (int)$a[2]->int()),
            'explainBusinessRules' => fn(array $a) => ActionsRules::explainBusinessRules($a[0], $a[1]),
            'lintBusinessRules' => fn(array $a) => ActionsRules::lintBusinessRules($a[0], $a[1]),
            'diffBusinessRules' => fn(array $a) => ActionsRules::diffBusinessRules($a[0], $a[1], $a[2]),
            'rulesReviewMessage' => fn(array $a) => Base::outBytes(ActionsRules::rulesReviewMessage($a[0])),
            'signRulesReview' => fn(array $a) => ActionsRules::signRulesReview($a[0], Base::bytes($a[1])),
            'rulesReviewError' => fn(array $a) => ActionsRules::rulesReviewError($a[0], $a[1], $a[2], $a[3]),
        ]);
    }
}
