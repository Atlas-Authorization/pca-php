<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The rule-14 action-schema base corpus against the TS reference (test-data/base-actionschema.json.gz): the v1 and v2 document shape (signed and unsigned),
 * the confirmation block, the floors block, the parameter value domain over every type and every format, and the format checkers. A malformed-schema refusal
 * that wraps a canonicalization error is compared by its prefix.
 */
final class RefBaseActionSchemaDifferentialTest extends TestCase
{
    private const FILE = 'base-actionschema.json.gz';
    private const FNS = ['shape' => 10502, 'pvv' => 3027, 'format' => 1788, 'confirmation' => 425, 'floors' => 391, 'shapeUnsigned' => 6];
    private const WRAP = 'malformed schema: canonicalize:';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** {"$num": ...} to the double, at any depth. */
    private static function un(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::un(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if ($v->keys() === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::un($v->get($k)));
        }
        return $o;
    }

    private static function wrapped(Obj $c, mixed $have): mixed
    {
        $want = $c->get('out');
        if (is_string($want) && str_starts_with($want, self::WRAP)) {
            $c->set('out', self::WRAP);
            return is_string($have) && str_starts_with($have, self::WRAP) ? self::WRAP : $have;
        }
        return $have;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'shape' => static fn(array $a, Obj $c) => self::wrapped($c, IntentV2::actionSchemaShapeError(self::un($a[0]))),
            'shapeUnsigned' => static fn(array $a, Obj $c) => self::wrapped($c, IntentV2::actionSchemaShapeError(self::un($a[0]), false)),
            'confirmation' => static fn(array $a) => IntentV2::confirmationShapeError(self::un($a[0])),
            'floors' => static fn(array $a) => IntentV2::schemaFloorsError(self::un($a[0])),
            'pvv' => static fn(array $a) => IntentV2::paramValueViolation(self::un($a[0]), self::un($a[1])),
            'format' => static function (array $a) {
                $chk = is_string($a[0]) ? IntentV2::formatCheck($a[0]) : null;
                return $chk === null ? 'unknown' : (bool)$chk($a[1]);
            },
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
