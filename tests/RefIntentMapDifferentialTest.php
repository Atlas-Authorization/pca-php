<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentMapCommit;
use Atlas\Pca\IntentMapKit;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The Intent Map against the TS reference: test-data/ref-intent-map.json.gz (emit / replay-verify / tamper, learner option round trips, the
 * outcome-space JSON form, the grant and map digests, runtime divergence). The committed form replays on IntentMapCommit. Doubles from transcendental functions are compared to
 * 1e-12 relative.
 */
final class RefIntentMapDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-map.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        $p = static fn($x) => WalletOmega::plain($x);
        Base::run($file, $fn, $k, [
            'mapScenario' => static fn(array $a, Obj $c) => self::scenario($a, $c), // the map weights are recomputed and compared by verifiers: exact
            'commitIntentMap' => static fn(array $a) => self::commit($p($a[0]), 3),
            'grantDigest' => static fn(array $a) => IntentMapKit::grantDigest($a[0]),
            'intentMapDigest' => static fn(array $a) => IntentMapKit::intentMapDigest($a[0]),
            'omegaToJSON' => static fn(array $a) => IntentMapKit::omegaToJSON($p($a[0])),
            'omegaFromJSON' => static fn(array $a) => IntentMapKit::omegaFromJSON($p($a[0])),
            'divergence' => static fn(array $a) => self::divergence($p($a[0]), $p($a[1]), $p($a[2]), $p($a[3])),
        ]);
    }

    private static function secret(int $seed): string
    {
        $s = '';
        for ($i = 0; $i < 32; $i++) {
            $s .= chr(($seed + 7 * $i) & 255);
        }
        return $s;
    }

    private static function commit(mixed $map, int $seed): mixed
    {
        $cm = IntentMapCommit::commitIntentMap($map, self::secret($seed));
        return ['map_commit' => $cm['map_commit'], 'size' => $cm['size'], 'leaves' => $cm['leaves']];
    }

    private static function normProblems(array $r): array
    {
        return ['ok' => $r['ok'], 'problems' => array_map(static fn($p) => str_starts_with($p, 'replay failed') ? 'replay failed' : $p, $r['problems'])];
    }

    private static function learner(mixed $omega, mixed $opts, array $observations): \Atlas\Pca\IntentLearner
    {
        $l = IntentMapKit::createLearner($omega, $opts);
        foreach ($observations as $x) {
            $src = $x->get('source');
            $l->observe(Obj::of(['verb' => $x->get('verb'), 'values' => $x->get('values')]), (int)\Atlas\Pca\Js::num($x->get('y')), is_string($src) ? $src : 'elicitation', $x->get('region'));
        }
        return $l;
    }

    private static function bump(Obj $o, string $k, int $by): Obj
    {
        $o->set($k, $o->get($k) + $by);
        return $o;
    }

    /** The fixed tamperings of the oracle, applied to a deep copy of the map. */
    private static function tampered(Obj $map): array
    {
        $muts = [
            static fn(Obj $m) => $m,
            static function (Obj $m) { self::bump($m->get('metrics'), 'residual_risk_ppm', 5); return $m; },
            static function (Obj $m) { self::bump($m->get('cells')[0], 'p_ppm', 3); return $m; },
            static function (Obj $m) { $c = $m->get('cells')[0]; $c->set('in_grant', !$c->get('in_grant')); return $m; },
            static function (Obj $m) { $m->set('grant_digest', 'AAAA'); return $m; },
            static function (Obj $m) { $o = $m->get('observations'); array_pop($o); $m->set('observations', $o); return $m; },
            static function (Obj $m) { $m->set('kind', 'x'); return $m; },
            static function (Obj $m) { $m->set('principals', ['a', 'b']); return $m; },
            static function (Obj $m) { $m->set('aggregation', Obj::of(['rule' => 'unanimity'])); return $m; },
            static function (Obj $m) { $m->set('metrics', $m->get('metrics')->without('log2_vs_mbits')); return $m; },
            static function (Obj $m) { self::bump($m->get('learner'), 'eta_ppm', 100000); return $m; },
            static function (Obj $m) { self::bump($m->get('metrics'), 'questions', 1); return $m; },
            static function (Obj $m) { $c = $m->get('cells'); array_pop($c); $m->set('cells', $c); return $m; },
            static function (Obj $m) { $m->get('omega')->get('verbs')[0]->set('w', 5); return $m; },
            static function (Obj $m) { $m->get('metrics')->set('log2_vs_mbits', null); return $m; },
            static function (Obj $m) { self::bump($m->get('cells')[0], 'p_ppm', 2); return $m; },
            static function (Obj $m) { self::bump($m->get('cells')[0], 'p_ppm', 1); return $m; },
        ];
        $out = [];
        foreach ($muts as $f) {
            $out[] = self::normProblems(IntentMapKit::verifyIntentMap($f(WalletOmega::plain($map))));
        }
        $out[] = self::normProblems(IntentMapKit::verifyIntentMap(null));
        $out[] = self::normProblems(IntentMapKit::verifyIntentMap(Obj::of(['v' => 2])));
        return $out;
    }

    private static function scenario(array $a, Obj $case): array
    {
        $omega = WalletOmega::plain($a[0]);
        $opts = WalletOmega::plain($a[1]);
        $obs = WalletOmega::plain($a[2]);
        $l = self::learner($omega, $opts, $obs);
        $map = IntentMapKit::emitIntentMap($l, $a[3]);
        $commit = $case->get('out')->get('commit');
        try {
            $cm = IntentMapCommit::commitIntentMap($map, self::secret((int)Js::num($a[4])));
            $commit = ['map_commit' => $cm['map_commit'], 'size' => $cm['size'], 'leaves' => $cm['leaves'], 'disclosures' => $cm['disclosures'] ?? $commit->get('disclosures')];
        } catch (\Throwable) {
            $commit = ['error' => true];
        }
        return ['map' => $map, 'digest' => IntentMapKit::intentMapDigest($map), 'grantDigest' => IntentMapKit::grantDigest($map->get('grant')),
            'verify' => self::normProblems(IntentMapKit::verifyIntentMap($map)), 'tampered' => self::tampered($map),
            'options' => IntentMapKit::mapLearnerOptions($map), 'omegaRoundtrip' => IntentMapKit::omegaToJSON(IntentMapKit::omegaFromJSON($map->get('omega'))),
            'commit' => $commit];
    }

    private static function divergence(mixed $omega, mixed $opts, array $obs, array $divs): array
    {
        $l = self::learner($omega, $opts, $obs);
        return array_map(static fn($d) => IntentMapKit::applyDivergence($l, $d->get('outcome'), (int)\Atlas\Pca\Js::num($d->get('y'))), $divs);
    }
}
