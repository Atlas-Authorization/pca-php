<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentRuntime.php';
require_once __DIR__ . '/../src/SemanticThreshold.php';

use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\IntentRuntime;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use Atlas\Pca\SemanticThreshold;
use Atlas\Pca\Undef;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The learner-bound runtime scenarios of test-data/ref-intent-routing.json.gz against the TS reference: optimistic bond sizing, routing an action through a
 * learner (deny / allow / optimistic / just-in-time consent), the same after a runtime veto, the intent conformance attestation with its tampering variants and
 * its re-verification, and the just-in-time consent request and decision. The semantic-judge functions of the same corpus are replayed by the semantic
 * threshold test. Non-finite numbers are compared as the string "inf" (the corpus's form).
 */
final class RefIntentRoutingDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-routing.json.gz';
    private const FNS = ['bondAmount' => 270, 'routeScenario' => 49, 'routeVetoScenario' => 1, 'conformanceScenario' => 28, 'jitScenario' => 13];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => isset(self::FNS[$d[1]]));
    }

    private static function conv(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF,
                };
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::conv($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::conv(...), $v) : $v;
    }

    /** A native result in the corpus's form: undefined members dropped, non-finite numbers as "inf". */
    private static function form(mixed $x): mixed
    {
        if (is_float($x) && !is_finite($x)) {
            return 'inf';
        }
        if ($x instanceof Obj) {
            $o = new Obj();
            foreach ($x->keys() as $k) {
                if (!($x->get($k) instanceof Undef)) {
                    $o->set($k, self::form($x->get($k)));
                }
            }
            return $o;
        }
        return is_array($x) ? array_map(static fn($e) => self::form($e), $x) : $x;
    }

    private static function learner(mixed $omega, mixed $mapOpts, mixed $observations): \Atlas\Pca\IntentLearner
    {
        $l = IntentMapKit::createLearner($omega, $mapOpts);
        foreach ($observations as $x) {
            $l->observe(Obj::of(['verb' => Js::opt($x, 'verb'), 'values' => Js::opt($x, 'values')]), (int)Js::num(Js::opt($x, 'y')), (string)Js::opt($x, 'source'));
        }
        return $l;
    }

    private static function verbSpace(\Atlas\Pca\IntentLearner $l, mixed $o): mixed
    {
        return IntentOmega::verbSpace($l->omega, Js::opt($o, 'verb'));
    }

    private static function clone(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::clone($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::clone(...), $v) : $v;
    }

    private static function verify(): \Closure
    {
        return static fn($verdicts, $opts) => SemanticThreshold::verifyThreshold($verdicts, $opts);
    }

    private static function conformance(array $a): Obj
    {
        $l = self::learner($a[0], $a[1], $a[2]);
        $oc = $a[3];
        $verdicts = $a[5];
        $copts = self::conv($a[6]);
        $input = IntentRuntime::judgeInputOf(self::verbSpace($l, $oc), $oc, $l->acceptance($oc), $a[4]);
        $att = IntentRuntime::intentConformanceAttestation($input, $verdicts, $copts, self::verify());
        $muts = [
            static fn(Obj $x): Obj => $x,
            static function (Obj $x): Obj {
                $x->set('ok', !$x->get('ok'));
                return $x;
            },
            static function (Obj $x): Obj {
                $x->set('aggregate_score_ppm', Js::num($x->get('aggregate_score_ppm')) + 1);
                return $x;
            },
            static function (Obj $x): Obj {
                $d = $x->get('verdict_digests');
                array_pop($d);
                $x->set('verdict_digests', $d);
                return $x;
            },
            static function (Obj $x): Obj {
                $x->set('k', Js::num($x->get('k')) + 1);
                return $x;
            },
            static function (Obj $x): Obj {
                $x->set('reason', 'x');
                return $x;
            },
        ];
        $tampered = array_map(static fn(callable $f) => IntentRuntime::verifyIcAtt($f(self::clone($att)), $input, $verdicts, $copts, self::verify()), $muts);
        $tampered[] = IntentRuntime::verifyIcAtt($att, $input, array_slice($verdicts, 1), $copts, self::verify());
        return Obj::of(['input' => $input, 'att' => $att, 'digest' => IntentRuntime::icAttDigest($att),
            'verify' => IntentRuntime::verifyIcAtt($att, $input, $verdicts, $copts, self::verify()), 'tampered' => $tampered,
            'check' => IntentRuntime::checkIntentConformance(static fn() => $verdicts, $input, $copts, self::verify())]);
    }

    private static function jit(array $a): Obj
    {
        $l = self::learner($a[0], $a[1], $a[2]);
        $oc = $a[3];
        $c = $a[5];
        $req = IntentRuntime::jitConsentRequest(self::verbSpace($l, $oc), $oc, $l->acceptance($oc), Js::opt($c, 'intentRef'), Js::opt($c, 'mapDigest'));
        $digest = IntentRuntime::jitConsentDigest($req);
        $result = IntentRuntime::recordJitDecision($l, $req, $a[4]);
        return Obj::of(['req' => $req, 'digest' => $digest, 'result' => $result, 'metrics' => $l->metrics(), 'route' => IntentRuntime::routeAction($l, $oc, new Obj())]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'bondAmount' => static fn(array $a) => self::form(IntentRuntime::bondAmount($a[0], self::conv($a[1]))),
            'routeScenario' => static function (array $a) {
                $a = WalletOmega::plain($a);
                $l = self::learner($a[0], $a[1], $a[2]);
                return self::form(array_map(static fn($x) => IntentRuntime::routeAction($l, $x, $a[4]), $a[3]));
            },
            'routeVetoScenario' => static function (array $a) {
                $a = WalletOmega::plain($a);
                $l = self::learner($a[0], $a[1], $a[2]);
                foreach ($a[3] as $x) {
                    $l->observe(Obj::of(['verb' => Js::opt($x, 'verb'), 'values' => Js::opt($x, 'values')]), 0, 'runtime');
                }
                return self::form(array_map(static fn($x) => IntentRuntime::routeAction($l, $x, $a[4]), $a[3]));
            },
            'conformanceScenario' => static fn(array $a) => self::form(self::conformance(WalletOmega::plain($a))),
            'jitScenario' => static fn(array $a) => self::form(self::jit(WalletOmega::plain($a))),
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
