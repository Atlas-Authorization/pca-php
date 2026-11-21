<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentClopper;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The exact Clopper-Pearson bound against the TS reference: test-data/ref-intent-stats.json.gz ({$bigint} = GMP; the metrics functions belong to the metrics module). */
final class RefIntentClopperDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-stats.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function big(mixed $x): mixed
    {
        if ($x instanceof Obj) {
            if ($x->keys() === ['$bigint']) {
                return gmp_init($x->get('$bigint'));
            }
            return array_combine($x->keys(), array_map(fn($k) => self::big($x->get($k)), $x->keys()));
        }
        return $x instanceof \Atlas\Pca\Num ? ($x->isInt() ? $x->int() : $x->float()) : $x;
    }

    private static function out(mixed $x): mixed
    {
        if ($x instanceof \GMP) {
            return Obj::of(['$bigint' => gmp_strval($x)]);
        }
        if (is_array($x) && !array_is_list($x)) {
            $o = new Obj();
            foreach ($x as $k => $v) {
                $o->set((string)$k, self::out($v));
            }
            return $o;
        }
        return is_int($x) && ($x > 9007199254740991 || $x < -9007199254740991) ? Obj::of(['$bigint' => (string)$x]) : $x;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $skip = static fn() => [Base::SKIP, 'metrics module'];
        Base::run($file, $fn, $k, [
            'binomialCdf' => fn(array $a, Obj $c) => RefIntentRound::close(IntentClopper::binomialCdf(...array_map(WalletOmega::plain(...), $a)), $c),
            'doubleToDyadic' => fn(array $a) => self::out(IntentClopper::doubleToDyadic($a[0])),
            'cdfRecNumerator' => fn(array $a) => self::out(IntentClopper::cdfRecNumerator((int)Js::num($a[0]), (int)Js::num($a[1]), self::big($a[2]))),
            'cdfExceeds' => function (array $a) {
                $al = self::big($a[3]);
                return IntentClopper::cdfExceeds((int)Js::num($a[0]), (int)Js::num($a[1]), self::big($a[2]), $al);
            },
            'clopperPearsonUpper' => fn(array $a) => IntentClopper::clopperPearsonUpper(...$a),
            'clopperPearsonCertified' => function (array $a) {
                $r = IntentClopper::clopperPearsonCertified(...$a);
                $r['upperUnits'] = Obj::of(['$bigint' => (string)$r['upperUnits']]);
                $r['lowerUnits'] = Obj::of(['$bigint' => (string)$r['lowerUnits']]);
                return $r;
            },
            'hoeffdingHalfWidth' => $skip, 'wilsonInterval' => $skip,
        ]);
    }
}
