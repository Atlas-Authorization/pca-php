<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Invariants;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The deterministic invariant-harness exports against the TS reference: test-data/ref-invariants.json.gz. */
final class RefInvariantsDifferentialTest extends TestCase
{
    private const FILE = 'ref-invariants.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function model(Obj $m): Obj
    {
        $o = new Obj();
        $o->set('principalSeed', Base::bytes($m->get('principalSeed')));
        $o->set('holder0Seed', Base::bytes($m->get('holder0Seed')));
        $o->set('rootSpecs', $m->get('rootSpecs'));
        $o->set('hops', array_map(static fn(Obj $h) => Obj::of(['holderSeed' => Base::bytes($h->get('holderSeed')), 'addedSpecs' => $h->get('addedSpecs')]), $m->get('hops')));
        $o->set('predicates', $m->get('predicates'));
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'keyPairFromSeed' => function (array $a) {
                $p = Invariants::keyPairFromSeed(Base::bytes($a[0]));
                return Obj::of(['secretKey' => Base::outBytes($p['secretKey']), 'publicKey' => Base::outBytes($p['publicKey']), 'pub' => $p['pub']]);
            },
            'buildChain' => function (array $a) {
                $c = Invariants::buildChain(self::model($a[0]));
                return Obj::of(['caps' => $c['caps'], 'predicates' => $c['predicates'], 'rootIssuer' => $c['rootIssuer'], 'holders' => $c['holders']]);
            },
            'worsen' => fn(array $a) => Invariants::worsen($a[0], $a[1]),
            'consts' => fn(array $a) => ['DEFAULT_SEED' => Invariants::DEFAULT_SEED, 'DEFAULT_NUM_RUNS' => Invariants::DEFAULT_NUM_RUNS, 'INVARIANT_NAMES' => Invariants::INVARIANT_NAMES],
        ]);
    }
}
