<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentProvenance;
use Atlas\Pca\Js;
use Atlas\Pca\Num;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Provenance banner / friction floor / within-grant regret against the TS reference: test-data/ref-intent-provenance.json.gz. */
final class RefIntentProvenanceDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-provenance.json.gz';
    private const A = 'action.params.';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function amt(mixed $o): float
    {
        $v = Js::opt(Js::opt($o, 'values'), self::A . 'amount');
        return Js::isNum($v) ? (float)Js::num($v) : 0.0;
    }

    /** The oracle's named predicates / utilities bound to Closures. */
    private static function bind(mixed $c): array
    {
        $adm = [
            'all' => fn($x) => true,
            'none' => fn($x) => false,
            'amountLe50' => fn($x) => self::amt($x) <= 50,
            'verbRefund' => fn($x) => Js::opt($x, 'verb') === 'stripe.refund',
        ];
        $util = [
            'amount' => fn($x) => self::amt($x),
            'negAmount' => fn($x) => -self::amt($x),
            'zero' => fn($x) => 0.0,
            'nan' => fn($x) => NAN,
            'amountPlusPrefer' => fn($x) => self::amt($x) + (Js::opt(Js::opt($x, 'values'), self::A . 'recipient') === 'bob' ? 1000 : 0),
        ];
        return ['feasible' => Js::opt($c, 'feasible'), 'chosen' => Js::opt($c, 'chosen'),
            'admits' => $adm[Js::opt($c, 'admits')], 'utility' => $util[Js::opt($c, 'utility')]];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'provenanceBanner' => fn(array $a) => IntentProvenance::provenanceBanner($a[0], $a[1] ?? 'value'),
            'isTainted' => fn(array $a) => IntentProvenance::isTainted($a[0]),
            'provenanceFriction' => fn(array $a) => IntentProvenance::provenanceFriction($a[0], $a[1], $a[2]),
            'regret' => function (array $a): array {
                $r = IntentProvenance::withinGrantRegret(self::bind($a[0]));
                return $r;
            },
            'report' => function (array $a) {
                $scale = $a[1] ?? 1;
                return IntentProvenance::regretReport(array_map(self::bind(...), $a[0]), $scale instanceof Num ? $scale->float() : $scale);
            },
        ]);
    }
}
