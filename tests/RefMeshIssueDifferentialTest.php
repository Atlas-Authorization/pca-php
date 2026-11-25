<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/MeshIssue.php';
require_once __DIR__ . '/../src/MeshWitness.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryMeshWitnessStore;
use Atlas\Pca\MeshDomain;
use Atlas\Pca\MeshIssue;
use Atlas\Pca\MeshWitness;
use Atlas\Pca\MeshWitnessStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The issuing side of the mesh and its federation half against the TS reference: every case of test-data/ref-mesh-issue.json.gz (the
 * caveat conjunction, size and latency models, the worked example, the domain / witness scripts, capability translation, the federated
 * budget tree, cross-reference commitments). A secret is {"$seed": label} = sha256("atlas-pca-conformance/" . label); a script's domain
 * and witness labels are seeds under "mesh-issue/d/" and "mesh-issue/w/". An infinite result is {"$num": "Infinity"}. One op of a script
 * that refuses is {"$err": message}: a witness refusal is compared by its text, any other refusal only as a refusal.
 */
final class RefMeshIssueDifferentialTest extends TestCase
{
    private const FILE = 'ref-mesh-issue.json.gz';
    private const TOTAL = 787;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $label, true));
    }

    private static function key(mixed $v): KeyPair
    {
        if (!($v instanceof Obj) || $v->keys() !== ['$seed'] || !is_string($v->get('$seed'))) {
            throw new \InvalidArgumentException('not a private key');
        }
        return self::seed($v->get('$seed'));
    }

    /** Non-finite doubles in the oracle's form. */
    private static function fin(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::fin(...), $v);
        }
        return is_float($v) && !is_finite($v) ? Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]) : $v;
    }

    private static function cap(string $label): Obj
    {
        return Obj::of(['id' => $label, 'issuer' => "iss-$label", 'holder' => 'h', 'caveats' => [Obj::of(['type' => 'scope', 'actions' => [$label]])]]);
    }

    /** A refusal of one op: the witness's own text is kept, any other message is engine text. */
    private static function err(mixed $v): mixed
    {
        if ($v instanceof Obj && $v->keys() === ['$err']) {
            return Obj::of(['$err' => is_string($v->get('$err')) && str_starts_with($v->get('$err'), 'witness: ') ? $v->get('$err') : 'Error']);
        }
        return $v;
    }

    private static function get(array $m, mixed $k): mixed
    {
        if (!is_string($k) || !array_key_exists($k, $m)) {
            throw new \InvalidArgumentException('unknown name');
        }
        return $m[$k];
    }

    private static function int(mixed $v): int
    {
        if (!($v instanceof Num) || (float)(int)$v->float() !== $v->float()) {
            throw new \InvalidArgumentException('not an integer');
        }
        return (int)$v->float();
    }

    /** @param list<mixed> $ops */
    private static function script(array $ops): array
    {
        $doms = $ws = $heads = $binds = $stores = [];
        $out = [];
        foreach ($ops as $op) {
            try {
                $v = null;
                switch ($op[0]) {
                    case 'domain':
                        $doms[$op[1]] = new MeshDomain($op[1], self::seed('mesh-issue/d/' . $op[2]));
                        $v = $doms[$op[1]]->id;
                        break;
                    case 'witness':
                        $ws[$op[1]] = new MeshWitness(self::seed('mesh-issue/w/' . $op[2]));
                        $v = $ws[$op[1]]->id;
                        break;
                    case 'witnessOpts':
                        $x = $op[3] instanceof Obj ? $op[3] : new Obj();
                        $clock = $x->get('clock');
                        $ws[$op[1]] = new MeshWitness(self::seed('mesh-issue/w/' . $op[2]), is_string($x->get('store')) ? self::get($stores, $x->get('store')) : null,
                            $clock === null ? null : static fn(): float => $clock->float(), $x->get('skew')?->float());
                        $v = $ws[$op[1]]->id;
                        break;
                    case 'store':
                        $stores[$op[1]] = new MemoryMeshWitnessStore();
                        $v = true;
                        break;
                    case 'failStore':
                        $stores[$op[1]] = new class (self::int($op[2])) implements MeshWitnessStore {
                            private MemoryMeshWitnessStore $inner;
                            private int $saves = 0;

                            public function __construct(private readonly int $failAfter)
                            {
                                $this->inner = new MemoryMeshWitnessStore();
                            }

                            public function load(): ?Obj
                            {
                                return $this->inner->load();
                            }

                            public function save(Obj $state): void
                            {
                                if ($this->saves++ >= $this->failAfter) {
                                    throw new \RuntimeException('disk');
                                }
                                $this->inner->save($state);
                            }
                        };
                        $v = true;
                        break;
                    case 'storeLoad':
                        $v = self::get($stores, $op[1])->load();
                        break;
                    case 'record':
                        $v = new Num((string)self::get($doms, $op[1])->record(self::cap($op[2])));
                        break;
                    case 'revoke':
                        self::get($doms, $op[1])->revoke($op[2]);
                        break;
                    case 'publish':
                        $v = self::get($doms, $op[1])->publishHead(array_map(static fn($w) => self::get($ws, $w), $op[4]), $op[3], $op[5] === null ? null : self::int($op[5]));
                        $heads[$op[2]] = $v;
                        break;
                    case 'fork':
                        $h = self::get($heads, $op[2])->without();
                        $h->set($op[3], $op[4]);
                        $heads[$op[1]] = $h;
                        break;
                    case 'forkHead':
                        $h = self::get($heads, $op[2])->without();
                        $hh = $h->get('head')->without();
                        $hh->set($op[3], $op[4]);
                        $h->set('head', $hh);
                        $heads[$op[1]] = $h;
                        break;
                    case 'cosign':
                        $w = self::get($ws, $op[1]);
                        $h = self::get($heads, $op[2]);
                        $dom = $h->get('head') instanceof Obj ? $h->get('head')->get('domain') : null;
                        $d = null;
                        foreach ($doms as $x) {
                            $d ??= $x->id === $dom ? $x : null;
                        }
                        if ($d === null) {
                            throw new \InvalidArgumentException('no such domain');
                        }
                        $consistency = $op[3];
                        if ($op[3] === 'domain') {
                            $prev = $w->lastSeen($dom);
                            $consistency = $prev ? $d->consistencyProof(self::int($prev->get('size')), self::int($h->get('head')->get('size'))) : null;
                        }
                        $req = Obj::of(['head' => $h]);
                        if ($consistency !== null) {
                            $req->set('consistency', $consistency);
                        }
                        $req->set('rev_ids', $op[4] === 'domain' ? $d->revocationSetCopy()->list() : $op[4]);
                        $v = $w->cosign($req);
                        break;
                    case 'lastSeen':
                        $v = self::get($ws, $op[1])->lastSeen(is_string($op[2]) && isset($doms[$op[2]]) ? $doms[$op[2]]->id : $op[2]);
                        break;
                    case 'export':
                        $v = self::get($ws, $op[1])->exportState();
                        break;
                    case 'import':
                        self::get($ws, $op[1])->importState($op[2] instanceof Obj && $op[2]->has('$export') ? self::get($ws, $op[2]->get('$export'))->exportState() : $op[2]);
                        break;
                    case 'restart':
                        $ws[$op[1]] = new MeshWitness(self::seed('mesh-issue/w/' . $op[3]), self::get($stores, $op[2]));
                        $v = $ws[$op[1]]->exportState();
                        break;
                    case 'consistency':
                        $v = self::get($doms, $op[1])->consistencyProof(self::int($op[2]), $op[3] === null ? null : self::int($op[3]));
                        break;
                    case 'enroll':
                        $v = self::get($doms, $op[1])->enroll($op[3], $op[4]);
                        $binds[$op[2]] = $v;
                        break;
                    case 'evidence':
                        $v = self::get($doms, $op[1])->evidence(self::cap($op[2]), self::get($heads, $op[3]), $op[4] === null ? null : self::get($binds, $op[4]));
                        break;
                    default:
                        throw new \InvalidArgumentException('op');
                }
                $out[] = $v;
            } catch (\Throwable $e) {
                $out[] = self::err(Obj::of(['$err' => $e->getMessage()]));
            }
        }
        return $out;
    }

    private static function example(mixed $now): array
    {
        $ex = $now === null ? MeshIssue::buildMeshExample() : MeshIssue::buildMeshExample(self::int($now));
        return ['trust' => $ex['trust'], 'proof' => $ex['proof'], 'evidence' => $ex['evidence'], 'chain' => $ex['chain'], 'heads' => $ex['heads'], 'bindings' => $ex['bindings'],
            'domains' => array_map(static fn(MeshDomain $d): string => $d->id, $ex['domains']), 'witnesses' => array_map(static fn(MeshWitness $w): string => $w->id, $ex['witnesses'])];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['DEFAULT_MAX_HEAD_AGE_MS' => MeshIssue::DEFAULT_MAX_HEAD_AGE_MS, 'DEFAULT_MAX_CLOCK_SKEW_MS' => MeshIssue::DEFAULT_MAX_CLOCK_SKEW_MS,
                'DEFAULT_MAX_CHAIN_LENGTH' => MeshIssue::DEFAULT_MAX_CHAIN_LENGTH],
            'keyRevocationId' => static fn(array $a) => MeshIssue::keyRevocationId($a[0]),
            'effectiveAuthority' => static fn(array $a) => MeshIssue::effectiveAuthority($a[0]),
            'buildMeshExample' => static fn(array $a) => self::example($a[0]),
            'demonstrateForkRejection' => static fn(array $a) => MeshIssue::demonstrateForkRejection(),
            'meshProofSize' => static fn(array $a) => MeshIssue::meshProofSize($a[0]),
            'revocationLatencyBound' => static fn(array $a) => self::fin(MeshIssue::revocationLatencyBound($a[0])),
            'meshIssue' => static function (array $a, Obj $c) {
                $c->set('out', array_map(self::err(...), $c->get('out')));
                return self::script($a[0]);
            },
            'translateCapability' => static function (array $a) {
                $x = $a[1];
                return MeshIssue::translateCapability($a[0], $x->get('fromGuardian'), $x->get('toGuardian'), self::key($x->get('bridgeSecret')), $x->get('issued_at'),
                    $x->has('additionalCaveats') ? $x->get('additionalCaveats') : MeshIssue::UNSET, $x->get('pqPins'));
            },
            'verifyTranslatedCapability' => static fn(array $a) => count($a) > 1 ? MeshIssue::verifyTranslatedCapability($a[0], $a[1]) : MeshIssue::verifyTranslatedCapability($a[0]),
            'translatedEffectiveAuthority' => static fn(array $a) => MeshIssue::translatedEffectiveAuthority($a[0]),
            'createFederatedBudget' => static fn(array $a) => MeshIssue::createFederatedBudget($a[0]),
            'allocateSub' => static fn(array $a) => MeshIssue::allocateSub($a[0], $a[1]),
            'spendFederated' => static fn(array $a) => MeshIssue::spendFederated($a[0], $a[1], $a[2]),
            'federatedSafetyBound' => static fn(array $a) => self::fin(MeshIssue::federatedSafetyBound($a[0])),
            'meshActionDigest' => static fn(array $a) => MeshIssue::meshActionDigest($a[0]),
            'crossReferenceCommit' => static fn(array $a) => MeshIssue::crossReferenceCommit($a[0]),
            'anchorCrossReference' => static fn(array $a) => MeshIssue::anchorCrossReference(self::key($a[0]), $a[1], $a[2]),
            'verifyCrossReference' => static fn(array $a) => MeshIssue::verifyCrossReference($a[0], $a[1]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
    }
}
