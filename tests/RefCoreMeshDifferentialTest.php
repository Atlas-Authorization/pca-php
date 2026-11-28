<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryMeshWitnessStore;
use Atlas\Pca\MeshDomain;
use Atlas\Pca\MeshWitness;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\RevocationSet;
use Atlas\Pca\SignersMore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/MeshWitness.php';

/**
 * The issuing side of the mesh against the TS reference: the domain's evidence, enroll and pin proofs (ref-core-mesh-domain-java), proof assembly and
 * action signing over scripted multi-domain sequences (ref-core-mesh-proof-java) and the witness with its durable store (the `meshWitness` cases of
 * ref-core-stores-java).
 */
final class RefCoreMeshDifferentialTest extends TestCase
{
    public static function provide(): array
    {
        $out = [];
        foreach (['ref-core-mesh-domain-java.json.gz', 'ref-core-mesh-proof-java.json.gz', 'ref-core-stores-java.json.gz'] as $f) {
            foreach (Base::datasets($f) as $k => $v) {
                if (in_array($v[1], ['meshDomain', 'meshProof', 'meshWitness'], true)) {
                    $out["$f $k"] = $v;
                }
            }
        }
        return $out;
    }

    private static function key(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $label, true));
    }

    private static function cap(string $label): Obj
    {
        return Obj::of(['id' => $label, 'issuer' => "iss-$label", 'holder' => 'h', 'caveats' => [Obj::of(['type' => 'scope', 'actions' => [$label]])]]);
    }

    private static function err(\Throwable $e, bool $byMessage): Obj
    {
        return Obj::of(['$err' => $byMessage ? $e->getMessage() : 'Error']);
    }

    private static function thr(mixed $x): ?int
    {
        return $x === null ? null : (int)$x->int();
    }

    /** @param list<mixed> $ops */
    private static function domainScript(array $ops, string $prefix): array
    {
        $doms = $ws = $heads = $binds = [];
        $out = [];
        foreach ($ops as $op) {
            try {
                $v = null;
                switch ($op[0]) {
                    case 'domain':
                        $d = new MeshDomain($op[1], self::key($prefix . $op[2]));
                        $doms[$op[1]] = $d;
                        $v = $d->id;
                        break;
                    case 'witness':
                        $w = new MeshWitness(self::key($prefix . $op[2]));
                        $ws[$op[1]] = $w;
                        $v = $w->id;
                        break;
                    case 'record':
                        $v = new Num((string)$doms[$op[1]]->record(self::cap($op[2])));
                        break;
                    case 'revoke':
                        $doms[$op[1]]->revoke($op[2]);
                        break;
                    case 'publish':
                        $h = $doms[$op[1]]->publishHead(array_map(static fn($w) => $ws[$w], $op[4]), $op[3], self::thr($op[5]));
                        $heads[$op[2]] = $v = $h;
                        break;
                    case 'fork':
                        $h = $heads[$op[2]]->without();
                        $h->set($op[3], $op[4]);
                        $heads[$op[1]] = $h;
                        break;
                    case 'enroll':
                        $b = $doms[$op[1]]->enroll($op[3], $op[4]);
                        $binds[$op[2]] = $v = $b;
                        break;
                    case 'evidence':
                        $v = $doms[$op[1]]->evidence(self::cap($op[2]), $heads[$op[3]] ?? null, ($op[4] ?? null) === null ? null : ($binds[$op[4]] ?? null));
                        break;
                    case 'pinProof':
                        $v = $doms[$op[1]]->pinProof(is_string($op[2]) ? $heads[$op[2]]->get('head') : $op[2], $heads[$op[3]]);
                        break;
                    case 'nonMembership':
                        if (!is_string($op[2])) {
                            throw new \TypeError('not a string');
                        }
                        $v = $doms[$op[1]]->revocationSetCopy()->nonMembershipProof($op[2]);
                        break;
                    default:
                        throw new \InvalidArgumentException('op');
                }
                $out[] = $v;
            } catch (\Throwable $e) {
                $out[] = self::err($e, false);
            }
        }
        return $out;
    }

    /** @param list<mixed> $ops */
    private static function proofScript(array $ops): array
    {
        $doms = $ws = $store = [];
        $out = [];
        foreach ($ops as $op) {
            try {
                $v = null;
                switch ($op[0]) {
                    case 'domain':
                        $d = new MeshDomain($op[1], self::key('mesh-proof/' . $op[2]));
                        $doms[$op[1]] = $d;
                        $v = $d->id;
                        break;
                    case 'witness':
                        $w = new MeshWitness(self::key('mesh-proof/' . $op[2]));
                        $ws[$op[1]] = $w;
                        $v = $w->id;
                        break;
                    case 'record':
                        $v = new Num((string)$doms[$op[1]]->record(self::cap($op[2])));
                        break;
                    case 'revoke':
                        $doms[$op[1]]->revoke($op[2]);
                        break;
                    case 'publish':
                        $store[$op[2]] = $v = $doms[$op[1]]->publishHead(array_map(static fn($w) => $ws[$w], $op[4]), $op[3], self::thr($op[5]));
                        break;
                    case 'subcos':
                        $h = $store[$op[2]]->without();
                        $h->set('cosigs', array_map(static fn($i) => $store[$op[2]]->get('cosigs')[(int)$i->int()], $op[3]));
                        $store[$op[1]] = $h;
                        break;
                    case 'fork':
                        $h = $store[$op[2]]->without();
                        $h->set($op[3], $op[4]);
                        $store[$op[1]] = $h;
                        break;
                    case 'forkHead':
                        $h = $store[$op[2]]->without();
                        $hh = $h->get('head')->without();
                        $hh->set($op[3], $op[4]);
                        $h->set('head', $hh);
                        $store[$op[1]] = $h;
                        break;
                    case 'enroll':
                        $store[$op[2]] = $v = $doms[$op[1]]->enroll($op[3], $op[4]);
                        break;
                    case 'ev':
                        $store[$op[2]] = $v = $doms[$op[1]]->evidence(self::cap($op[3]), $store[$op[4]], $op[5] === null ? null : $store[$op[5]]);
                        break;
                    case 'setEv':
                        $e = $store[$op[2]]->without();
                        $val = $op[4];
                        if ($val instanceof Obj && $val->has('$del')) {
                            $e = $e->without($op[3]);
                        } elseif ($op[3] === 'head' && is_string($val) && isset($store[$val])) {
                            $e->set('head', $store[$val]);
                        } else {
                            $e->set($op[3], $val);
                        }
                        $store[$op[1]] = $e;
                        break;
                    case 'pinProofAs':
                        $pin = $op[3];
                        $store[$op[2]] = $v = $doms[$op[1]]->pinProof(is_string($pin) ? $store[$pin]->get('head') : $pin, $store[$op[4]]);
                        break;
                    case 'assemble':
                        $pins = $op[5] === null ? [] : array_map(static fn($n) => $store[$n] ?? null, $op[5]);
                        $v = SignersMore::assembleMeshProof(array_map([self::class, 'cap'], $op[1]), array_map(static fn($n) => $store[$n] ?? null, $op[2]), $op[3],
                            self::key('mesh-proof/' . $op[4]), $pins);
                        break;
                    case 'sign':
                        $v = SignersMore::signMeshAction(array_map([self::class, 'cap'], $op[1]), $op[2], self::key('mesh-proof/' . $op[3]));
                        break;
                    default:
                        throw new \InvalidArgumentException('op');
                }
                $out[] = $v;
            } catch (\Throwable $e) {
                $out[] = self::err($e, false);
            }
        }
        return $out;
    }

    /** @param list<mixed> $ops */
    public static function witnessScript(array $ops): array
    {
        $stores = $ws = $doms = [];
        $out = [];
        foreach ($ops as $op) {
            try {
                $v = null;
                switch ($op[0]) {
                    case 'store':
                        $stores[$op[1]] = new MemoryMeshWitnessStore();
                        $v = true;
                        break;
                    case 'witness':
                        $w = new MeshWitness(self::key($op[3]), $op[2] === null ? null : $stores[$op[2]]);
                        $ws[$op[1]] = $w;
                        $v = $w->id;
                        break;
                    case 'witnessClock':
                        $now = (float)$op[3]->float();
                        $ws[$op[1]] = new MeshWitness(self::key($op[2]), null, static fn() => $now, $op[4] === null ? null : (float)$op[4]->float());
                        $v = true;
                        break;
                    case 'restart':
                        $w = new MeshWitness(self::key($op[3]), $stores[$op[2]]);
                        $ws[$op[1]] = $w;
                        $v = $w->exportState();
                        break;
                    case 'domain':
                        $d = new MeshDomain($op[1], self::key($op[2]));
                        $doms[$op[1]] = $d;
                        $v = $d->id;
                        break;
                    case 'record':
                        $v = new Num((string)$doms[$op[1]]->record(Obj::of(['id' => $op[2], 'caveats' => [Obj::of(['type' => 'scope', 'actions' => [$op[2]]])]])));
                        break;
                    case 'revoke':
                        $doms[$op[1]]->revoke($op[2]);
                        break;
                    case 'publish':
                        $v = $doms[$op[1]]->publishHead(array_map(static fn($w) => $ws[$w], $op[3]), $op[2], self::thr($op[4]));
                        break;
                    case 'lastSeen':
                        $v = $ws[$op[1]]->lastSeen($op[2]);
                        break;
                    case 'export':
                        $v = $ws[$op[1]]->exportState();
                        break;
                    case 'import':
                        $ws[$op[1]]->importState($op[2]);
                        break;
                    case 'load':
                        $v = $stores[$op[1]]->load();
                        break;
                    case 'save':
                        $stores[$op[1]]->save($op[2]);
                        break;
                    case 'domainId':
                        $v = $doms[$op[1]]->id;
                        break;
                    default:
                        throw new \InvalidArgumentException('op');
                }
                $out[] = $v;
            } catch (\Throwable $e) {
                $out[] = self::err($e, true);
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'meshDomain' => fn(array $a) => self::domainScript($a[0], 'mesh-domain/'),
            'meshProof' => fn(array $a) => self::proofScript($a[0]),
            'meshWitness' => fn(array $a) => self::witnessScript($a[0]),
        ]);
    }

    public function testNonMembershipProofsVerify(): void
    {
        $s = new RevocationSet(['b', 'd', 'f', 'h', 'j']);
        foreach (['a', 'c', 'e', 'g', 'i', 'k', '', 'key:x'] as $id) {
            $this->assertTrue(\Atlas\Pca\Mesh::nonMembership($s->root(), $s->nonMembershipProof($id), $id), $id);
        }
        foreach (['b', 'd', 'j'] as $id) {
            try {
                $s->nonMembershipProof($id);
                $this->fail('a revoked id has no non-membership proof');
            } catch (\InvalidArgumentException) {
            }
        }
        $this->assertSame('0', (new RevocationSet())->nonMembershipProof('a')->get('size')->lexeme);
    }
}
