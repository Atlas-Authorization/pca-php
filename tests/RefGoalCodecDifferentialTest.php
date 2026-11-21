<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalCard;
use Atlas\Pca\GoalCodec;
use Atlas\Pca\GoalDigests;
use Atlas\Pca\GoalFmt;
use Atlas\Pca\GoalNormalize;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/GoalCodec.php';
require_once __DIR__ . '/../src/GoalDigests.php';
require_once __DIR__ . '/../src/GoalNormalize.php';
require_once __DIR__ . '/../src/GoalFmt.php';
require_once __DIR__ . '/../src/GoalCard.php';

/**
 * The goal token-tape codec, content digests, canonical order, formatting and policy card against the TS reference: the codec
 * half of test-data/ref-goal.json.gz (the rest of that corpus is replayed by the semantics, compiler, binding and signing test).
 */
final class RefGoalCodecDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal.json.gz';
    private const FNS = ['encodeGoal', 'decodeGoal', 'encodeOntology', 'encodeAct', 'encodeHist', 'decodePolicy', 'goalDigest', 'nlDigest',
        'modelSetDigest', 'approvalDigest', 'canonicalizeGoal', 'stable', 'fmtMoney', 'fmtQuantity', 'fmtValue', 'fmtAct', 'renderCard', 'renderCond'];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), fn($d) => in_array($d[1], self::FNS, true), ARRAY_FILTER_USE_BOTH);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'encodeGoal' => fn(array $a) => GoalCodec::encodeGoal($a[0]),
            'decodeGoal' => fn(array $a) => GoalCodec::decodeGoal($a[0]),
            'encodeOntology' => fn(array $a) => GoalCodec::encodeOntology($a[0]),
            'encodeAct' => fn(array $a) => GoalCodec::encodeAct($a[0]),
            'encodeHist' => fn(array $a) => GoalCodec::encodeHist($a[0]),
            'decodePolicy' => fn(array $a) => GoalCodec::decodePolicy($a[0]),
            'goalDigest' => fn(array $a) => GoalDigests::goalDigest($a[0]),
            'nlDigest' => fn(array $a) => GoalDigests::nlDigest($a[0]),
            'modelSetDigest' => fn(array $a) => GoalDigests::modelSetDigest($a[0]),
            'approvalDigest' => fn(array $a) => GoalDigests::approvalDigest($a[0]),
            'canonicalizeGoal' => fn(array $a) => GoalNormalize::canonicalizeGoal($a[0]),
            'stable' => fn(array $a) => GoalNormalize::stable($a[0]),
            'fmtMoney' => fn(array $a) => GoalFmt::fmtMoney($a[0], $a[1]),
            'fmtQuantity' => fn(array $a) => GoalFmt::fmtQuantity($a[0]),
            'fmtValue' => fn(array $a) => GoalFmt::fmtValue($a[0]),
            'fmtAct' => fn(array $a) => GoalFmt::fmtAct($a[0]),
            'renderCard' => fn(array $a) => GoalCard::renderCard($a[0]),
            'renderCond' => fn(array $a) => GoalCard::cond($a[0]),
        ]);
    }
}
