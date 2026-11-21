<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AnalyzerCore;
use Atlas\Pca\AnalyzerCoverage;
use Atlas\Pca\AnalyzerExposure;
use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\AnalyzerNarrowing;
use Atlas\Pca\AnalyzerResidual;
use Atlas\Pca\AnalyzerValidate;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The policy analyzer against the TS reference: test-data/ref-analyzer.json.gz. Keys are labels: the Ed25519 seed of a label is
 * sha256("atlas-pca-conformance/" + label) and "$key:LABEL" stands for its b64u public key. A non-finite number is {"$num": ...}.
 */
final class RefAnalyzerDifferentialTest extends TestCase
{
    private const FILE = 'ref-analyzer.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    private static function pub(string $label): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed($label))));
    }

    private static function keyed(mixed $v): mixed
    {
        if (is_string($v)) {
            return str_starts_with($v, '$key:') ? self::pub(substr($v, 5)) : $v;
        }
        return self::map($v, self::keyed(...));
    }

    /** {"$num": "Infinity"} back to the number. */
    private static function revive(mixed $v): mixed
    {
        if ($v instanceof Obj && $v->keys() === ['$num'] && is_string($v->get('$num'))) {
            return match ($v->get('$num')) {
                'Infinity' => INF,
                '-Infinity' => -INF,
                default => NAN,
            };
        }
        return self::map($v, self::revive(...));
    }

    /** A non-finite float is the oracle's {"$num": ...}. */
    private static function norm(mixed $v): mixed
    {
        if (is_float($v) && !is_finite($v)) {
            return Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]);
        }
        return self::map($v, self::norm(...));
    }

    private static function map(mixed $v, callable $f): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, $f($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map($f, $v) : $v;
    }

    private static function probesJson(mixed $inp): Obj
    {
        $p = AnalyzerCore::collectProbes($inp);
        $o = new Obj();
        foreach ($p->keys() as $k) {
            if ($k !== 'fields') {
                $o->set($k, $p->get($k));
                continue;
            }
            $fs = [];
            foreach ($p->get('fields') as $f) {
                $vals = [];
                foreach ($f->get('values') as $x) {
                    $vals[] = $x === AnalyzerCore::absent() ? Obj::of(['$absent' => true]) : $x;
                }
                $fs[] = Obj::of(['path' => $f->get('path'), 'values' => $vals]);
            }
            $o->set('fields', $fs);
        }
        return $o;
    }

    private static function reps(mixed $inp): array
    {
        $p = AnalyzerCore::collectProbes($inp);
        if (AnalyzerCore::productSize($p) > 400) {
            throw new \InvalidArgumentException('grid too large for the corpus');
        }
        $out = [];
        foreach (AnalyzerCore::representatives($p) as $r) {
            $o = Obj::of(['verb' => $r->get('verb'), 'resource' => $r->get('resource'), 'assignments' => AnalyzerJs::copy($r->get('assignments')), 'action' => AnalyzerCore::repToAction($r)]);
            if ($r->get('revClass') !== null) {
                $o->set('revClass', $r->get('revClass'));
            }
            $out[] = $o;
        }
        return $out;
    }

    private static function vetoApplies(mixed $veto, mixed $x): bool
    {
        $a = AnalyzerJs::copy($x);
        if ($x->get('params') === null) {
            $a->set('params', new Obj());
        }
        return AnalyzerCore::vetoApplies($veto, Obj::of([
            'action' => $a,
            'subject' => $x->get('subject') ?? new Obj(),
            'env' => $x->get('env') ?? new Obj(),
        ]));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $n = fn(callable $f) => fn(array $a) => self::norm($f(...$a));
        Base::run($file, $fn, $k, [
            'analyzeCaveats' => $n(AnalyzerCore::analyzeCaveats(...)),
            'numericConjunctionSatisfiable' => $n(AnalyzerCore::numericConjunctionSatisfiable(...)),
            'predicateNumericSatisfiable' => $n(AnalyzerCore::predicateNumericSatisfiable(...)),
            'tightenInterval' => fn(array $a) => self::norm(AnalyzerCore::tightenInterval($a[0] ?? null ?: AnalyzerCore::fullInterval(), $a[1] ?? null, $a[2] ?? null)),
            'intervalEmpty' => fn(array $a) => AnalyzerCore::intervalEmpty($a[0] ?? null ?: AnalyzerCore::fullInterval()),
            'fieldProbes' => $n(AnalyzerCore::fieldProbes(...)),
            'vetoesFromConstitution' => $n(AnalyzerCore::vetoesFromConstitution(...)),
            'toModel' => $n(AnalyzerCore::toModel(...)),
            'collectProbes' => fn(array $a) => self::probesJson($a[0]),
            'representatives' => fn(array $a) => self::reps($a[0]),
            'decideAction' => fn(array $a) => self::norm(AnalyzerCore::decideAction(AnalyzerCore::toModel($a[0]), $a[1])),
            'witnessOf' => fn(array $a) => self::norm(AnalyzerCoverage::witnessOf(AnalyzerCore::toModel($a[0]), $a[1])),
            'admitsConcrete' => $n(AnalyzerCore::admitsConcrete(...)),
            'vetoApplies' => function (array $a, Obj $c) {
                if ($c->get('name') === 'unless-object') {
                    return AnalyzerCore::vetoApplies($a[0], Obj::of(['action' => $a[1], 'subject' => new Obj(), 'env' => new Obj()]));
                }
                return self::vetoApplies($a[0], $a[1]);
            },
            'reachable' => $n(AnalyzerCore::reachable(...)),
            'alwaysDenies' => $n(AnalyzerCore::alwaysDenies(...)),
            'alwaysAllows' => $n(AnalyzerCore::alwaysAllows(...)),
            'subsumes' => $n(AnalyzerCore::subsumes(...)),
            'disjoint' => $n(AnalyzerCore::disjoint(...)),
            'equivalent' => $n(AnalyzerCore::equivalent(...)),
            'intentConformance' => $n(AnalyzerCore::intentConformance(...)),
            'thresholdsOf' => fn(array $a) => self::norm(AnalyzerExposure::thresholdsOf(AnalyzerCore::toModel($a[0]), $a[1])),
            'maxExposure' => $n(AnalyzerExposure::maxExposure(...)),
            'escalationSurface' => $n(AnalyzerExposure::escalationSurface(...)),
            'delegationEnvelope' => $n(AnalyzerExposure::delegationEnvelope(...)),
            'diffPolicies' => $n(AnalyzerExposure::diffPolicies(...)),
            'diffGate' => fn(array $a) => self::norm(AnalyzerExposure::diffGate(self::revive($a[0]), $a[1] ?? null)),
            'findWithBackend' => fn(array $a) => self::norm(AnalyzerExposure::findWithBackend(
                Obj::of(['name' => $a[1]->get('name'), 'find' => static fn($q) => $a[1]->get('result')]),
                $a[0],
            )),
            'dagExposure' => $n(AnalyzerExposure::dagExposure(...)),
            'residual' => $n(AnalyzerResidual::residual(...)),
            'residualPolicy' => $n(AnalyzerResidual::residualPolicy(...)),
            'evaluateResidual' => $n(AnalyzerResidual::evaluateResidual(...)),
            'whatMayIDo' => $n(AnalyzerResidual::whatMayIDo(...)),
            'toFilter' => fn(array $a) => self::norm(AnalyzerResidual::toFilter(AnalyzerResidual::residual($a[0], $a[1], $a[2] ?? null), $a[3] ?? null)),
            'toUcast' => $n(AnalyzerResidual::toUcast(...)),
            'evalFilter' => $n(AnalyzerResidual::evalFilter(...)),
            'evalUcast' => $n(AnalyzerResidual::evalUcast(...)),
            'suggestNarrowing' => $n(AnalyzerNarrowing::suggestNarrowing(...)),
            'signAccessRequest' => fn(array $a) => self::norm(AnalyzerNarrowing::signAccessRequest($a[0], self::seed($a[1]), self::pub($a[1]))),
            'verifyAccessRequest' => fn(array $a) => self::norm(AnalyzerNarrowing::verifyAccessRequest($a[0], isset($a[1]) ? self::keyed($a[1]) : null)),
            'coverage' => $n(AnalyzerCoverage::coverage(...)),
            'coverageGate' => $n(AnalyzerCoverage::coverageGate(...)),
            'minimalFlip' => $n(AnalyzerCoverage::minimalFlip(...)),
            'verbShapes' => $n(AnalyzerValidate::verbShapes(...)),
            'verbShapesFromActionDefs' => $n(AnalyzerValidate::verbShapesFromActionDefs(...)),
            'validatePolicyAgainstSchema' => $n(AnalyzerValidate::validatePolicyAgainstSchema(...)),
            'policyTestsDoc' => $n(AnalyzerValidate::policyTestsDoc(...)),
            'runPolicyTests' => $n(AnalyzerValidate::runPolicyTests(...)),
            'generateBoundaryTests' => $n(AnalyzerValidate::generateBoundaryTests(...)),
            'decideAll' => $n(AnalyzerValidate::decideAll(...)),
            'signPolicyTests' => fn(array $a) => self::norm(AnalyzerValidate::signPolicyTests($a[0], self::seed($a[1]), self::pub($a[1]))),
            'verifyPolicyTests' => fn(array $a) => self::norm(AnalyzerValidate::verifyPolicyTests($a[0], self::keyed($a[1]))),
        ]);
    }
}
