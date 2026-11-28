<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Explain;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The decision / verification / chain explainer against the TS reference: test-data/ref-explain.json.gz (explanations compared as their JSON). */
final class RefExplainDifferentialTest extends TestCase
{
    private const FILE = 'ref-explain.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'cleanText' => fn(array $a) => Explain::cleanText(...$a),
            'explainVerification' => fn(array $a) => Explain::explainVerification(...$a),
            'explainVerificationText' => fn(array $a) => Explain::verificationToText(Explain::explainVerification(...$a)),
            'explainDecision' => fn(array $a) => Explain::explainDecision(...$a),
            'explainDecisionText' => fn(array $a) => Explain::decisionToText(Explain::explainDecision(...$a)),
            'explainChain' => fn(array $a) => Explain::explainChain(...$a),
            'explainChainText' => fn(array $a) => Explain::chainToText(Explain::explainChain(...$a)),
            'consts' => fn(array $a) => ['VERIFY_CHECK_ORDER' => Explain::VERIFY_CHECK_ORDER, 'MAX_TEXT' => Explain::MAX_TEXT],
        ]);
    }
}
