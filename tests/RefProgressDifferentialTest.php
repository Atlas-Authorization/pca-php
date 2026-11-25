<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Progress.php';

use Atlas\Pca\AttestedStateSource;
use Atlas\Pca\InMemoryStateSource;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PotentialRegistry;
use Atlas\Pca\Progress;
use Atlas\Pca\ProgressStateSource;
use Atlas\Pca\ProgressTracker;
use Atlas\Pca\TransparencyLedger;
use Atlas\Pca\Jsx;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Proof of progress against the TS reference: every case of test-data/ref-progress.json.gz (potentials and their registry, goal
 * commitment, state and step digests, trajectory anchors, state attestations, attested sources, the tracker, step and trajectory
 * verification, signed steps). The specs (potential kinds, registries, guards, attestation hooks, sources) are the generator's JSON
 * descriptions of the host objects the reference is given. Keys are the seeds "progress/<label>".
 * RULING: `allowUnboundPq` is not ported; the cases the reference accepts only through it (4 of verifyStateAttestation) must be REFUSED.
 */
final class RefProgressDifferentialTest extends TestCase
{
    private const FILE = 'ref-progress.json.gz';
    private const UNBOUND_ONLY = 4;
    private const FNS = ['constants' => 1, 'l1FeaturePotential' => 20, 'dagRemainingPotential' => 21, 'dagWeightedPotential' => 24, 'registryOps' => 7,
        'goalDigest' => 31, 'commitGoal' => 31, 'verifyGoalCommitment' => 53, 'stateDigest' => 14, 'trajectoryHead' => 6, 'trajectoryAnchorCommit' => 8,
        'verifyTrajectoryAnchor' => 17, 'tracker' => 40, 'attestedSource' => 8, 'progressStepDigest' => 37, 'verifyProgressStep' => 147, 'verifyTrajectory' => 130,
        'anchorTrajectoryHead' => 10, 'attestedStateVerifier' => 15, 'verifyStateAttestation' => 55, 'signProgressStep' => 7, 'verifySignedProgressStep' => 26,
        'verifySignedTrajectory' => 15];

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

    private static function err(\Throwable $e): Obj
    {
        return Obj::of(['$err' => $e->getMessage()]);
    }

    /** A secret as raw bytes: {$bytes: {$seed: label}}, {$seed: label} (sha256("atlas-pca-conformance/" . label)) or base64url text. */
    private static function secret(mixed $v): string
    {
        if ($v instanceof Obj && $v->keys() === ['$bytes']) {
            $v = $v->get('$bytes');
        }
        if ($v instanceof Obj && $v->has('$seed')) {
            return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
        }
        return (string)Pca::unb64u((string)$v);
    }

    private static function kind(string $k): \Closure
    {
        return match (true) {
            $k === 'l1-feature-v1' => static fn($o, $s) => Progress::l1FeaturePotential($o, $s),
            $k === 'dag-remaining-v1' => static fn($o, $s) => Progress::dagRemainingPotential($o, $s),
            $k === 'dag-weighted-v1' => static fn($o, $s) => Progress::dagWeightedPotential($o, $s),
            str_starts_with($k, 'const:') => static fn($o, $s) => (float)substr($k, 6),
            $k === 'v' => static fn($o, $s) => Jsx::get($s, 'v'),
            $k === 'throws' => static function ($o, $s) {
                throw new \RuntimeException('potential boom');
            },
            $k === 'negative' => static fn($o, $s) => -1,
            $k === 'frac' => static fn($o, $s) => 0.5,
            $k === 'nan' => static fn($o, $s) => NAN,
            $k === 'big' => static fn($o, $s) => 9007199254740992.0,
            default => throw new \RuntimeException('bad potential kind ' . $k),
        };
    }

    /** The registry input a spec denotes: null (the default), a registry, or a plain record's `[id, spec]` entries. */
    private static function registry(mixed $s): mixed
    {
        if ($s === null) {
            return null;
        }
        if ($s->get('mode') === 'record') {
            $entries = [];
            foreach ($s->get('potentials') as $p) {
                $v = count($p) > 2 ? ['fn' => self::kind($p[1]), 'embedder' => $p[2]] : self::kind($p[1]);
                $found = false;
                foreach ($entries as &$e) { // Object.fromEntries: a later entry for the same key replaces the earlier one in place
                    if ($e[0] === $p[0]) {
                        $e[1] = $v;
                        $found = true;
                    }
                }
                unset($e);
                if (!$found) {
                    $entries[] = [$p[0], $v];
                }
            }
            return $entries;
        }
        $r = new PotentialRegistry();
        foreach ($s->get('potentials') as $p) {
            count($p) > 2 ? $r->register($p[0], self::kind($p[1]), $p[2]) : $r->register($p[0], self::kind($p[1]));
        }
        return $r;
    }

    private static function guard(mixed $g): ?\Closure
    {
        if ($g === null) {
            return null;
        }
        return match (true) {
            $g === 'allow' => static fn($t) => true,
            $g === 'deny' => static fn($t) => false,
            $g === 'throws' => static function ($t) {
                throw new \RuntimeException('guard boom');
            },
            $g === 'truthy' => static fn($t) => 'yes',
            str_starts_with($g, 'action:') => static fn(Obj $t) => $t->get('action_digest') !== substr($g, 7),
            str_starts_with($g, 'seq:') => static fn(Obj $t) => (float)\Atlas\Pca\Js::num($t->get('seq')) !== (float)substr($g, 4),
            str_starts_with($g, 'after-v:') => static function (Obj $t) use ($g): bool {
                $v = \Atlas\Pca\Js::num(Jsx::get($t->get('after'), 'v'));
                return $v === null || $v != (float)substr($g, 8);
            },
            default => throw new \RuntimeException('bad guard ' . $g),
        };
    }

    private static function attestation(mixed $a): ?\Closure
    {
        if ($a === null) {
            return null;
        }
        if ($a instanceof Obj) {
            return Progress::attestedStateVerifier($a->get('attested'));
        }
        return match ($a) {
            'allow' => static fn($s) => true,
            'deny' => static fn($s) => false,
            'throws' => static function ($s) {
                throw new \RuntimeException('att boom');
            },
            default => static fn($s) => 'yes',
        };
    }

    private static function opts(mixed $opts): Obj
    {
        $o = $opts instanceof Obj ? Jsx::spread($opts) : new Obj();
        if ($o->has('registry')) {
            $o->set('registry', self::registry($o->get('registry')));
        }
        if ($o->has('guard')) {
            $o->set('guard', self::guard($o->get('guard')));
        }
        if ($o->has('attestation')) {
            $o->set('attestation', self::attestation($o->get('attestation')));
        }
        return $o;
    }

    private static function source(Obj $s): array
    {
        $kind = $s->get('kind');
        $id = $s->get('id');
        $initial = $s->get('initial');
        if ($kind === 'attested') {
            $world = new \stdClass();
            $world->v = Progress::snapshot($initial);
            $alg = $s->get('alg');
            $inner = new AttestedStateSource($id, new KeyPair(self::secret($s->get('signerSecret'))), static fn() => $world->v, $alg ?: null);
            return [$inner, static function ($n) use ($world): void {
                $world->v = Progress::snapshot($n);
            }];
        }
        $mem = new InMemoryStateSource($initial, (string)$id);
        $wrap = new class($id, $mem, (string)$kind) implements ProgressStateSource {
            public function __construct(private readonly string $sid, private readonly InMemoryStateSource $mem, private readonly string $kind)
            {
            }

            public function id(): string
            {
                return $this->sid;
            }

            public function observe(Obj $req): mixed
            {
                if ($this->kind === 'throws') {
                    throw new \RuntimeException('source boom');
                }
                if ($this->kind === 'null') {
                    return null;
                }
                $ob = $this->mem->observe($req);
                if ($this->kind === 'liar-digest') {
                    $ob->set('state_digest', str_repeat('x', 43));
                }
                if ($this->kind === 'liar-source') {
                    $ob->set('source', 'someone-else');
                }
                return $ob;
            }
        };
        return [$kind === 'memory' ? $mem : $wrap, static function ($n) use ($mem): void {
            $mem->apply($n);
        }];
    }

    private static function registryOps(array $ops): array
    {
        $r = null;
        $out = [];
        foreach ($ops as $op) {
            $a = array_slice($op, 1);
            try {
                $out[] = match ($op[0]) {
                    'new' => (function () use (&$r) {
                        $r = new PotentialRegistry();
                        return null;
                    })(),
                    'defaults' => (function () use (&$r) {
                        $r = PotentialRegistry::defaults();
                        return null;
                    })(),
                    'default-frozen' => (function () use (&$r) {
                        $r = Progress::defaultPotentials();
                        return null;
                    })(),
                    'from' => (function () use (&$r, $a) {
                        $pairs = [];
                        foreach ($a[0]->keys() as $id) {
                            $v = $a[0]->get($id);
                            $pairs[] = [$id, is_string($v) ? self::kind($v) : ['fn' => self::kind($v->get('fn')), 'embedder' => $v->get('embedder')]];
                        }
                        $r = PotentialRegistry::from($pairs);
                        return null;
                    })(),
                    'register' => (function () use (&$r, $a) {
                        count($a) > 2 ? $r->register($a[0], self::kind($a[1]), $a[2]) : $r->register($a[0], self::kind($a[1]));
                        return null;
                    })(),
                    'get' => (function () use (&$r, $a) {
                        $s = $r->get($a[0]);
                        return $s === null ? null : Obj::of(['embedder' => $s['embedder']]);
                    })(),
                    'has' => $r->has($a[0]),
                    'ids' => $r->ids(),
                    'freeze' => (function () use (&$r) {
                        $r->freeze();
                        return null;
                    })(),
                    default => throw new \RuntimeException('bad op'),
                };
            } catch (\Throwable $e) {
                $out[] = self::err($e);
            }
        }
        return $out;
    }

    private static function tracker(array $a): array
    {
        [$goal, $commitment, $initial, $prs, $gd, $sources, $ops] = $a;
        $srcs = array_map(static fn($s) => self::source($s), $sources);
        $t = new ProgressTracker($goal, $commitment ?? Progress::goalDigest($goal), $initial, self::registry($prs), self::guard($gd));
        $out = [];
        foreach ($ops as $op) {
            try {
                $out[] = match ($op[0]) {
                    'step' => $t->step($op[1], $op[2]),
                    'stepObserved' => $t->stepObserved($srcs[(int)$op[1]->int()][0], $op[2]),
                    'apply' => (function () use ($srcs, $op) {
                        ($srcs[(int)$op[1]->int()][1])($op[2]);
                        return null;
                    })(),
                    'steps' => $t->steps(),
                    'state' => $t->state(),
                    'currentStateDigest' => $t->currentStateDigest(),
                    'spent' => $t->spent(),
                    'remaining' => $t->remaining(),
                    'reached' => $t->reached(),
                    default => null,
                };
            } catch (\Throwable $e) {
                $out[] = self::err($e);
            }
        }
        return $out;
    }

    private static function attestedSource(array $a): array
    {
        [$inner] = self::source($a[0]);
        $obs = [];
        foreach ($a[1] as $req) {
            try {
                $obs[] = $inner->observe($req);
            } catch (\Throwable $e) {
                $obs[] = self::err($e);
            }
        }
        return ['observations' => $obs, 'attestations' => $inner instanceof AttestedStateSource ? $inner->attestations() : null];
    }

    /** The unbound-key opt-out is not ported: a case only that opt-out accepts must be refused. */
    private static function unboundRuling(array $a, Obj $c, bool $have): mixed
    {
        $pin = $a[2] ?? null;
        $alg = $a[0] instanceof Obj ? $a[0]->get('alg') : null;
        $classical = $alg === null || $alg === 'ed25519'; // an Ed25519 attestation needs no PQ key: the opt-out changes nothing for it
        if (!$classical && $pin instanceof Obj && $pin->get('allowUnboundPq') === true && $c->get('out') === true) {
            Assert::assertFalse($have, 'allowUnboundPq is not ported: the native verifier refuses what only that opt-out accepts');
            return true;
        }
        return $have;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['PROGRESS_VERSION' => Progress::VERSION, 'PROGRESS_SIG_DOMAIN' => Progress::SIG_DOMAIN,
                'TRAJECTORY_ANCHOR_DOMAIN' => Progress::TRAJECTORY_ANCHOR_DOMAIN, 'STATE_ATTESTATION_DOMAIN' => Progress::STATE_ATTESTATION_DOMAIN],
            'l1FeaturePotential' => static fn(array $a) => Progress::l1FeaturePotential($a[0], $a[1]),
            'dagRemainingPotential' => static fn(array $a) => Progress::dagRemainingPotential($a[0], $a[1]),
            'dagWeightedPotential' => static fn(array $a) => Progress::dagWeightedPotential($a[0], $a[1]),
            'registryOps' => static fn(array $a) => self::registryOps($a[0]),
            'goalDigest' => static fn(array $a) => Progress::goalDigest($a[0]),
            'commitGoal' => static fn(array $a) => Progress::commitGoal($a[0]),
            'verifyGoalCommitment' => static fn(array $a) => Progress::verifyGoalCommitment($a[0], $a[1]),
            'stateDigest' => static fn(array $a) => Progress::stateDigest(self::un($a[0])),
            'trajectoryHead' => static fn(array $a) => Progress::trajectoryHead($a[0]),
            'progressStepDigest' => static fn(array $a) => Progress::progressStepDigest($a[0]),
            'trajectoryAnchorCommit' => static fn(array $a) => Progress::trajectoryAnchorCommit($a[0], $a[1]),
            'verifyTrajectoryAnchor' => static fn(array $a) => Progress::verifyTrajectoryAnchor($a[0], $a[1], $a[2]),
            'anchorTrajectoryHead' => static function (array $a) {
                $l = new TransparencyLedger('p');
                foreach ($a[2] as $c) {
                    $l->appendCommitment($c);
                }
                return Progress::anchorTrajectoryHead($l, $a[0], $a[1]);
            },
            'verifyStateAttestation' => static fn(array $a, Obj $c) => self::unboundRuling($a, $c, Progress::verifyStateAttestation($a[0], $a[1], $a[2] ?? null)),
            'attestedStateVerifier' => static fn(array $a) => Progress::attestedStateVerifier($a[0])($a[1]),
            'attestedSource' => static fn(array $a) => self::attestedSource($a),
            'tracker' => static fn(array $a) => self::tracker($a),
            'verifyProgressStep' => static fn(array $a) => Progress::verifyProgressStep($a[0], $a[1], $a[2], self::opts($a[3])),
            'verifyTrajectory' => static fn(array $a) => Progress::verifyTrajectory($a[0], $a[1], $a[2], self::opts($a[3])),
            'verifySignedProgressStep' => static fn(array $a) => Progress::verifySignedProgressStep($a[0], $a[1], $a[2], self::opts($a[3])),
            'verifySignedTrajectory' => static fn(array $a) => Progress::verifySignedTrajectory($a[0], $a[1], $a[2], self::opts($a[3])),
            'signProgressStep' => static fn(array $a) => Progress::signProgressStep($a[0], new KeyPair(self::secret($a[1])), $a[2]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        $unbound = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
            $unbound += str_starts_with($line, '{"fn":"verifyStateAttestation"') && str_contains($line, '"allowUnboundPq":true') && str_contains($line, '"out":true') ? 1 : 0;
        }
        $this->assertSame(self::FNS, $have);
        $this->assertSame(self::UNBOUND_ONLY, $unbound);
    }
}
