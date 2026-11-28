<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentMultiAgg;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Multi-principal aggregation over Intent Maps against the TS reference: test-data/ref-intent-multi-agg.json.gz (unanimity / quorum /
 * weighted rules, vetoers, replay verification and tampering, lifting onto a common refinement, cross-organisation aggregation, the omega
 * key). The oracle passes its `orgs` argument as the options object, so it never names an org; the same here.
 */
final class RefIntentMultiAggDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-multi-agg.json.gz';
    private const REFERENCE_ERR = '/^(aggregateIntentMaps|ruleOf|liftIntentMap|crossOrgAggregate|commonRefinement|pca-intent|refineOmega)/';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        $p = static fn($x) => WalletOmega::plain($x);
        Base::run($file, $fn, $k, [
            'aggregateScenario' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(self::aggregateScenario($p($a[0]), $p($a[1]), $p($a[2]), $p($a[3] ?? null), $p($a[4] ?? null)), $c),
            'aggregateTwoOmegas' => static fn(array $a) => IntentMultiAgg::aggregateIntentMaps(
                [self::buildMap($p($a[0]), null, $p($a[2])[0]->get('observations'), $p($a[2])[0]->get('ref')), self::buildMap($p($a[1]), null, [], $p($a[2])[1]->get('ref'))], $p($a[3])),
            'aggregateOfAggregate' => static function (array $a) use ($p) {
                $maps = self::maps($p($a[0]), $p($a[1]));
                $agg = IntentMultiAgg::aggregateIntentMaps($maps, $p($a[2]));
                return IntentMultiAgg::aggregateIntentMaps([$agg, $maps[0]], $p($a[2]));
            },
            'liftOfAggregate' => static function (array $a) use ($p) {
                $maps = self::maps($p($a[0]), $p($a[1]));
                return IntentMultiAgg::liftIntentMap(IntentMultiAgg::aggregateIntentMaps(array_slice($maps, 0, 1), $p($a[2])), $p($a[0]));
            },
            'crossScenario' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(self::crossScenario($p($a[0]), $p($a[1]), $p($a[2] ?? null), count($a) === 2), $c),
            'liftScenario' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(
                IntentMultiAgg::liftIntentMap(self::buildMap($p($a[0]), $p($a[1]), $p($a[2]), $a[3]), $p($a[4])), $c),
            'omegaKey' => static fn(array $a) => IntentMultiAgg::omegaKey($p($a[0])),
        ]);
    }

    private static function buildMap(mixed $omega, mixed $opts, array $observations, mixed $ref): Obj
    {
        $l = IntentMapKit::createLearner($omega, $opts);
        foreach ($observations as $x) {
            $src = $x->get('source');
            $l->observe(Obj::of(['verb' => $x->get('verb'), 'values' => $x->get('values')]), (int)\Atlas\Pca\Js::num($x->get('y')), is_string($src) ? $src : 'elicitation', $x->get('region'));
        }
        return IntentMapKit::emitIntentMap($l, is_string($ref) ? $ref : null);
    }

    /** @return list<Obj> */
    private static function maps(mixed $omega, array $principals): array
    {
        return array_map(static fn($pr) => self::buildMap($omega, null, $pr->get('observations'), $pr->get('ref')), $principals);
    }

    /** The oracle's problem normaliser: reference-defined messages stay, any other message is "error". */
    private static function norm(array $r): array
    {
        $ps = [];
        foreach ($r['problems'] as $p) {
            $q = preg_replace('/replay failed: [^;]*/', 'replay failed', $p);
            if (preg_match('/^recompute failed: (.*)$/s', $q, $m)) {
                if (preg_match(self::REFERENCE_ERR, $m[1]) !== 1) {
                    $q = 'recompute failed: error';
                }
            } elseif (preg_match('/^(input |aggregate does not|recompute failed)/', $q) !== 1 && preg_match('/^replay failed/', $q) !== 1) {
                $q = preg_match(self::REFERENCE_ERR, $q) === 1 ? $q : 'error';
            }
            $ps[] = $q;
        }
        return ['ok' => $r['ok'], 'problems' => $ps];
    }

    /** The six fixed tamperings of the oracle, each verified by `$verify` over a deep copy. */
    private static function tampered(Obj $agg, \Closure $verify): array
    {
        $muts = [
            static fn(Obj $m) => $m,
            static function (Obj $m) { $x = $m->get('metrics'); $x->set('residual_risk_ppm', $x->get('residual_risk_ppm') + 7); return $m; },
            static function (Obj $m) { $c = $m->get('cells')[0]; $c->set('in_grant', !$c->get('in_grant')); return $m; },
            static function (Obj $m) { $m->set('aggregation', null); return $m; },
            static function (Obj $m) { $a = $m->get('aggregation'); $a->set('rule', 'quorum'); $a->set('k', 1); return $m; },
            static function (Obj $m) { $m->get('aggregation')->set('vetoers', []); return $m; },
        ];
        return array_map(static fn($f) => self::norm($verify($f(WalletOmega::plain($agg)))), $muts);
    }

    private static function aggregateScenario(mixed $omega, array $principals, mixed $rule, mixed $orgs, mixed $mapOpts): array
    {
        $orgs ??= new Obj();
        $maps = array_map(static fn($pr) => self::buildMap($omega, $mapOpts, $pr->get('observations'), $pr->get('ref')), $principals);
        $agg = IntentMultiAgg::aggregateIntentMaps($maps, $rule, $orgs);
        $tampered = self::tampered($agg, static fn($m) => IntentMultiAgg::verifyAggregate($m, $maps, $orgs));
        $vet = Js::opt($rule, 'vetoers');
        return ['aggregate' => $agg, 'digest' => IntentMapKit::intentMapDigest($agg), 'rule' => IntentMultiAgg::ruleOf($agg),
            'verify' => self::norm(IntentMultiAgg::verifyAggregate($agg, $maps, $orgs)), 'tampered' => $tampered,
            'wrongInputs' => self::norm(IntentMultiAgg::verifyAggregate($agg, array_slice($maps, 0, -1), $orgs)),
            'combined' => Js::opt($rule, 'kind') === 'unanimity' && $vet === null ? IntentMultiAgg::combineIntentMaps($maps, $orgs) : null];
    }

    private static function crossScenario(array $specs, mixed $rule, mixed $orgs, bool $tamperedInput): array
    {
        $orgs ??= new Obj();
        $maps = array_map(static fn($s) => self::buildMap($s->get('omega'), $s->get('mapOpts') ?? new Obj(), $s->get('observations'), $s->get('ref')), $specs);
        if ($tamperedInput) {
            $r = $maps[0]->get('metrics');
            $r->set('residual_risk_ppm', $r->get('residual_risk_ppm') + 9);
            return ['aggregate' => IntentMultiAgg::crossOrgAggregate($maps, $rule)['aggregate']];
        }
        $r = IntentMultiAgg::crossOrgAggregate($maps, $rule, $orgs);
        $tampered = self::tampered($r['aggregate'], static fn($m) => IntentMultiAgg::verifyCrossOrgAggregate($m, $maps, $orgs));
        return ['aggregate' => $r['aggregate'], 'lifted' => $r['lifted'], 'omega' => $r['omega'], 'digest' => IntentMapKit::intentMapDigest($r['aggregate']),
            'verify' => self::norm(IntentMultiAgg::verifyCrossOrgAggregate($r['aggregate'], $maps, $orgs)), 'tampered' => $tampered,
            'wrong' => self::norm(IntentMultiAgg::verifyCrossOrgAggregate($r['aggregate'], array_slice($maps, 1), $orgs))];
    }
}
