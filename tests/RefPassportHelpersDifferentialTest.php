<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Passport.php';

use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\Obj;
use Atlas\Pca\Passport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The passport helpers (binding match, trust score, assurance label) against the TS reference: the matchesBinding, trustScore and
 * passportAssurance cases of test-data/ref-passport.json.gz, reason texts and their order included.
 */
final class RefPassportHelpersDifferentialTest extends TestCase
{
    private const FILE = 'ref-passport.json.gz';
    private const FNS = ['matchesBinding' => 267, 'trustScore' => 67, 'passportAssurance' => 8];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => isset(self::FNS[$d[1]]));
    }

    /** {"$num": "NaN"} (a double JSON cannot carry) becomes the float, at any depth. */
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

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'matchesBinding' => static fn(array $a) => Passport::matchesBinding(self::un($a[0]), self::un($a[1])),
            'trustScore' => static fn(array $a) => Passport::trustScore($a[0], $a[1]),
            'passportAssurance' => static function (array $a) {
                if ($a[1] === 'no-verifier') {
                    return Passport::passportAssurance($a[0]);
                }
                $verifier = new \stdClass();
                if ($a[1] instanceof Obj) {
                    Assurance::setLabel($verifier, new AssuranceLabel($a[1]->get('level'), $a[1]->get('vendor')));
                }
                return Passport::passportAssurance($a[0], $verifier);
            },
        ]);
    }

    public function testCorpusHasTheExpectedCases(): void
    {
        $n = [];
        foreach (Base::datasets(self::FILE) as [, $fn, $k]) {
            if (isset(self::FNS[$fn])) {
                $n[$fn] = ($n[$fn] ?? 0) + count(Base::cases(self::FILE, $fn, $k));
            }
        }
        $this->assertEquals(self::FNS, $n);
    }
}
