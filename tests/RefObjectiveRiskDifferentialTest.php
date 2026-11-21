<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ObjectiveRisk.php';

use Atlas\Pca\ByoEmbedder;
use Atlas\Pca\InMemoryInverseRegistry;
use Atlas\Pca\Js;
use Atlas\Pca\NativeHashEmbedder;
use Atlas\Pca\Obj;
use Atlas\Pca\ObjectiveRisk;
use Atlas\Pca\ObjectiveRiskContext;
use Atlas\Pca\ObjEmbedder;
use Atlas\Pca\ResourceGraph;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The objective risk functional against the TS reference: every case of test-data/ref-objective-risk.json.gz (canonical action, inverse
 * registry and reversibility, resource graph and blast radius, native and BYO embedders, goal commitment and distance, calibration,
 * harm currency, objectiveRisk and its dispute oracle). {"$num": ...} is a non-finite double, in arguments and in results. The specs
 * (registry, graph, embedder, context) are the generator's JSON descriptions of the objects the reference builds.
 */
final class RefObjectiveRiskDifferentialTest extends TestCase
{
    private const FILE = 'ref-objective-risk.json.gz';
    private const FNS = ['constants' => 1, 'canonicalAction' => 39, 'canonicalActionJson' => 23, 'canonicalActionDigest' => 23, 'registryDigest' => 8,
        'registryOps' => 3, 'reversibility' => 224, 'graphBuild' => 17, 'graphNode' => 102, 'graphReachable' => 1190, 'blastRadius' => 1190, 'nativeEmbed' => 98,
        'byoModelId' => 18, 'byoEmbed' => 39, 'validateVector' => 17, 'commitGoal' => 36, 'verifyGoalCommitment' => 88, 'vectorDistance' => 168,
        'committedDistanceChecked' => 40, 'committedDistance' => 40, 'conformanceCheck' => 10, 'calibrationDigest' => 13, 'calibrate' => 154,
        'conformalThreshold' => 121, 'harmReport' => 108, 'objectiveRisk' => 178, 'objectiveRiskOracle' => 104];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function un(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::un($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::un(...), $v) : $v;
    }

    private static function out(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::out($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::out(...), $v);
        }
        return is_float($v) && !is_finite($v) ? Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]) : $v;
    }

    private static function registry(Obj $s): InMemoryInverseRegistry
    {
        $r = new InMemoryInverseRegistry($s->get('trusted') ?? []);
        foreach ($s->get('entries') ?? [] as [$verb, $e]) {
            $r->register($verb, $e);
        }
        return $r;
    }

    private static function graph(Obj $s): ResourceGraph
    {
        $g = new ResourceGraph();
        foreach ($s->get('nodes') ?? [] as $n) {
            $g->addNode($n);
        }
        foreach ($s->get('edges') ?? [] as $e) {
            $g->addEdge($e);
        }
        return $g;
    }

    private static function infer(Obj $i, mixed $dims): \Closure
    {
        return static function (string $json) use ($i, $dims) {
            if ($i->get('throws') === true) {
                throw new \RuntimeException('infer boom');
            }
            if ($i->get('notArray') === true) {
                return 'x';
            }
            if ($i->get('byLen') === true) {
                $n = $dims instanceof \Atlas\Pca\Num || is_int($dims) || is_float($dims) ? (int)Js::num($dims) : 4;
                return array_map(static fn(int $k): int => Js::len($json) + $k, range(0, $n - 1));
            }
            return $i->get('vector');
        };
    }

    private static function byo(mixed $d, mixed $claimed, Obj $infer): ByoEmbedder
    {
        return new ByoEmbedder($d, self::infer($infer, \Atlas\Pca\Jsx::get($d, 'dims')), is_string($claimed) ? $claimed : null);
    }

    private static function embedder(Obj $s): ObjEmbedder
    {
        $scheme = $s->get('scheme');
        if ($scheme === 'native') {
            return new NativeHashEmbedder($s->get('config'));
        }
        if ($scheme === 'fixed') {
            return new class($s->get('modelId'), $s->get('config'), $s->get('dims'), $s->get('vector')) implements ObjEmbedder {
                public function __construct(private readonly mixed $id, private readonly mixed $cfg, private readonly mixed $d, private readonly mixed $vec)
                {
                }

                public function modelId(): mixed
                {
                    return $this->id;
                }

                public function config(): mixed
                {
                    return $this->cfg;
                }

                public function dims(): mixed
                {
                    return $this->d;
                }

                public function embed(Obj $action): mixed
                {
                    return $this->vec;
                }
            };
        }
        return self::byo($s->get('descriptor'), $s->get('claimedModelId'), $s->get('infer'));
    }

    private static function ctx(Obj $c): ObjectiveRiskContext
    {
        $scope = $c->get('scope');
        $cal = $c->get('calibration');
        return new ObjectiveRiskContext(self::registry($c->get('registry')), $c->get('authorizedKinds'), self::graph($c->get('graph')),
            $scope instanceof Obj ? $scope : null, self::embedder($c->get('embedder')), $c->get('goal'), $c->get('commitments'), $c->get('denominations'),
            $c->get('weights'), $c->get('taint'), $c->get('age'), $c->get('attestedUncertainty'), is_array($cal) ? $cal : null);
    }

    private static function scope(mixed $s): ?Obj
    {
        $s = self::un($s); // a maxDepth of {"$num":"Infinity"} is the double
        return $s instanceof Obj ? $s : null;
    }

    private static function eps(mixed $e): mixed
    {
        return $e === null ? ObjectiveRisk::DEFAULT_EPSILON : $e;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['METRIC' => ObjectiveRisk::METRIC, 'DEFAULT_EPSILON' => ObjectiveRisk::DEFAULT_EPSILON, 'NATIVE_SCHEME' => ObjectiveRisk::NATIVE_SCHEME,
                'DEFAULT_MAX_PARAM_LEAVES' => ObjectiveRisk::DEFAULT_MAX_PARAM_LEAVES, 'DEFAULT_NATIVE_CONFIG' => ObjectiveRisk::defaultNativeConfig()],
            'canonicalAction' => static fn(array $a) => ObjectiveRisk::canonicalAction(self::un($a[0])),
            'canonicalActionJson' => static fn(array $a) => ObjectiveRisk::canonicalActionJson(self::un($a[0])),
            'canonicalActionDigest' => static fn(array $a) => ObjectiveRisk::canonicalActionDigest(self::un($a[0])),
            'registryDigest' => static fn(array $a) => self::registry($a[0])->digest(),
            'registryOps' => static function (array $a) {
                $r = new InMemoryInverseRegistry($a[0]);
                $out = [];
                foreach ($a[1] as $op) {
                    $out[] = match ($op[0]) {
                        'register' => $r->register($op[1], $op[2]) ? null : null,
                        'lookup' => $r->lookup($op[1]),
                        'trustedVerifiers' => $r->trustedVerifiers(),
                        default => $r->digest(),
                    };
                }
                return $out;
            },
            'reversibility' => static fn(array $a) => ObjectiveRisk::reversibility($a[0], self::registry($a[1]), $a[2]),
            'graphBuild' => static function (array $a) {
                $g = self::graph(self::un($a[0]));
                return ['size' => $g->size(), 'digest' => $g->digest()];
            },
            'graphReachable' => static fn(array $a) => self::graph(self::un($a[0]))->reachable($a[1], self::scope($a[2])),
            'graphNode' => static fn(array $a) => self::graph($a[0])->node($a[1]),
            'blastRadius' => static fn(array $a) => self::out(ObjectiveRisk::blastRadius($a[0], self::graph($a[1]), self::scope($a[2]))),
            'nativeEmbed' => static function (array $a) {
                $e = new NativeHashEmbedder(self::un($a[0]));
                return ['modelId' => $e->modelId(), 'dims' => $e->dims(), 'config' => $e->config(), 'vector' => $e->embed($a[1])];
            },
            'byoModelId' => static fn(array $a) => ObjectiveRisk::byoModelId(self::un($a[0])),
            'byoEmbed' => static function (array $a) {
                $e = self::byo(self::un($a[0]), $a[1], $a[2]);
                return ['modelId' => $e->modelId(), 'dims' => $e->dims(), 'vector' => $e->embed($a[3])];
            },
            'validateVector' => static fn(array $a) => ObjectiveRisk::validateVector(self::un($a[0]), self::un($a[1])),
            'conformanceCheck' => static fn(array $a) => ObjectiveRisk::conformanceCheck(self::embedder($a[0]), $a[1]),
            'commitGoal' => static fn(array $a) => ObjectiveRisk::commitGoal(self::embedder($a[0]), $a[1], self::eps(self::un($a[2]))),
            'verifyGoalCommitment' => static function (array $a, Obj $c) {
                $r = ObjectiveRisk::verifyGoalCommitment(self::un($a[0]), self::embedder($a[1]));
                $want = $c->get('out');
                // an engine message of the reference ("Cannot read properties ...") is only compared as "some reason"
                return is_string($want) && str_starts_with($want, 'Cannot read properties') && is_string($r) && $r !== '' ? $want : $r;
            },
            'vectorDistance' => static fn(array $a) => self::out(ObjectiveRisk::vectorDistance(self::un($a[0]), self::un($a[1]), self::eps(self::un($a[2])))),
            'committedDistanceChecked' => static fn(array $a) => ObjectiveRisk::committedDistanceChecked($a[0], $a[1], self::embedder($a[2])),
            'committedDistance' => static fn(array $a) => ObjectiveRisk::committedDistance($a[0], $a[1], self::embedder($a[2])),
            'calibrate' => static fn(array $a) => ObjectiveRisk::calibrate(self::un($a[0]), self::un($a[1])),
            'conformalThreshold' => static fn(array $a) => self::out(ObjectiveRisk::conformalThreshold(self::un($a[0]), self::un($a[1]))),
            'calibrationDigest' => static fn(array $a) => ObjectiveRisk::calibrationDigest(self::un($a[0])),
            'harmReport' => static fn(array $a) => ObjectiveRisk::harmReport(self::un($a[0]), self::un($a[1])),
            'objectiveRisk' => static fn(array $a) => self::out(ObjectiveRisk::objectiveRisk(self::un($a[0]), self::ctx(self::un($a[1])))),
            'objectiveRiskOracle' => static fn(array $a) => self::out(ObjectiveRisk::objectiveRiskOracle(self::ctx(self::un($a[0])), $a[1], $a[2])),
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
