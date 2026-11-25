<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Evidence;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The dispute evidence bundle (shape, normal form, commitments-only form, digest, reference, cap reader, trust validators) against the TS reference: test-data/ref-evidence.json.gz. */
final class RefEvidenceDifferentialTest extends TestCase
{
    private const FILE = 'ref-evidence.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'bundleShapeError' => fn(array $a) => Evidence::bundleShapeError($a[0]),
            'normalizeBundle' => fn(array $a) => Evidence::normalizeBundle($a[0]),
            'buildEvidenceBundle' => fn(array $a) => Evidence::buildEvidenceBundle($a[0]),
            'commitmentForm' => fn(array $a) => Evidence::commitmentForm($a[0]),
            'evidenceDigest' => fn(array $a) => Evidence::evidenceDigest($a[0]),
            'evidenceRef' => fn(array $a) => Evidence::evidenceRef($a[0]),
            'evidenceAnchorCommit' => fn(array $a) => Evidence::evidenceAnchorCommit($a[0]),
            'anchorCommit' => fn(array $a) => Evidence::anchorCommit($a[0], $a[1]),
            'capOf' => fn(array $a) => Evidence::capOf($a[0], $a[1], $a[2]),
            'principalsTrustError' => fn(array $a) => Evidence::principalsTrustError(...$a),
            'accTrustError' => fn(array $a) => Evidence::accTrustError(...$a),
            'consts' => fn(array $a) => ['EVIDENCE_DOMAIN' => Evidence::EVIDENCE_DOMAIN, 'EVIDENCE_REPORT_DOMAIN' => Evidence::EVIDENCE_REPORT_DOMAIN,
                'EVIDENCE_CONTENT_TYPE' => Evidence::EVIDENCE_CONTENT_TYPE],
        ]);
    }
}
