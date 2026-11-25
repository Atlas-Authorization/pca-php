<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Compliance;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The compliance evidence module against the TS reference: test-data/ref-compliance.json.gz (reports compared text for text). */
final class RefComplianceDifferentialTest extends TestCase
{
    private const FILE = 'ref-compliance.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** A non-finite float is the oracle's {"$num": ...}. */
    private static function norm(mixed $v): mixed
    {
        if (is_float($v) && !is_finite($v)) {
            return Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]);
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::norm($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::norm(...), $v) : $v;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn(array $a) => ['COMPLIANCE_FRAMEWORKS' => Compliance::COMPLIANCE_FRAMEWORKS, 'CONTROL_MAPPINGS' => Compliance::controlMappingTable()],
            'controlMappings' => fn(array $a) => Compliance::controlMappings(...$a),
            'toAuditEvent' => fn(array $a) => self::norm(Compliance::toAuditEvent(...$a)),
            'toComplianceReport' => fn(array $a) => self::norm(Compliance::toComplianceReport(...$a)),
            'renderJson' => fn(array $a) => Compliance::renderJson(...$a),
            'renderMarkdown' => fn(array $a) => Compliance::renderMarkdown(...$a),
            'frameworkReport' => fn(array $a) => self::norm(Compliance::frameworkReport(...$a)),
            'frameworkReportToMarkdown' => fn(array $a) => Compliance::frameworkReportToMarkdown(...$a),
        ]);
    }
}
