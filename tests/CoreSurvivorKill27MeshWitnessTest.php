<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/MeshWitness.php';

use Atlas\Pca\FileMeshWitnessStore;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\LedgerProofs;
use Atlas\Pca\Mesh;
use Atlas\Pca\MeshDomain;
use Atlas\Pca\MeshWitness;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RevocationSet;
use PHPUnit\Framework\TestCase;

/** Witness store, revocation set and witness/domain refusal paths: damaged state files, short writes, clock and revocation-list rules. */
final class CoreSurvivorKill27MeshWitnessTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k27-mw-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
    }

    protected function tearDown(): void
    {
        FileMeshWitnessStore::$writeHook = null;
        self::rm($this->dir);
    }

    private static function rm(string $p): void
    {
        if (is_dir($p)) {
            foreach (array_diff(scandir($p) ?: [], ['.', '..']) as $f) {
                self::rm($p . DIRECTORY_SEPARATOR . $f);
            }
            @rmdir($p);
        } elseif (file_exists($p)) {
            @unlink($p);
        }
    }

    private static function kp(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/k27-mesh/' . $label, true));
    }

    /** @return array{0:string,1:string,2:list<string>} exception class, message, PHP warnings raised */
    private static function runWitness(callable $f): array
    {
        $w = [];
        set_error_handler(static function (int $no, string $msg) use (&$w): bool {
            $w[] = $msg;
            return true;
        });
        try {
            $f();
            $r = ['none', ''];
        } catch (\Throwable $e) {
            $r = [get_class($e), $e->getMessage()];
        } finally {
            restore_error_handler();
        }
        $r[] = $w;
        return $r;
    }

    private function file(string $text): FileMeshWitnessStore
    {
        $p = $this->dir . DIRECTORY_SEPARATOR . 'w-' . bin2hex(random_bytes(4)) . '.json';
        file_put_contents($p, $text);
        return new FileMeshWitnessStore($p);
    }

    /** A missing file is a first run; a saved state reads back. */
    public function testFileStoreRoundTrip(): void
    {
        $s = new FileMeshWitnessStore($this->dir . DIRECTORY_SEPARATOR . 'state.json');
        $this->assertNull($s->load());
        $st = Obj::of(['seen' => []]);
        $s->save($st);
        $this->assertSame(Js::stringify($st), Js::stringify($s->load()));
    }

    /** A damaged state file is refused with the reason that names the damage. */
    public function testFileStoreRefusesDamage(): void
    {
        $e = IntentV2::hashCanonical(new Obj());
        $x = IntentV2::hashCanonical('x');
        $json = ['RuntimeException', 'FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty', []];
        $shape = ['RuntimeException', 'FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty', []];
        $digest = ['RuntimeException', 'FileMeshWitnessStore: the state file fails its digest; refusing to start empty', []];
        $this->assertSame($json, self::runWitness(fn() => $this->file('not json')->load()));
        foreach (['[1]', '{"v":"1","state":{},"digest":"' . $e . '"}', '{"v":2,"state":{},"digest":"' . $e . '"}', '{"v":1,"state":{},"digest":5}',
            '{"v":1,"state":"x","digest":"' . $x . '"}', '{"state":{},"digest":"' . $e . '"}'] as $t) {
            $this->assertSame($shape, self::runWitness(fn() => $this->file($t)->load()), $t);
        }
        $this->assertSame($digest, self::runWitness(fn() => $this->file('{"v":1,"state":{},"digest":"wrong"}')->load()));
        $this->assertInstanceOf(Obj::class, $this->file('{"v":1,"state":{},"digest":"' . $e . '"}')->load());
    }

    /** A short write, an uncreatable temp file and a failed rename each refuse the save, and the old state survives a short write. */
    public function testFileStoreWriteFailures(): void
    {
        $p = $this->dir . DIRECTORY_SEPARATOR . 'state.json';
        $s = new FileMeshWitnessStore($p);
        $old = Obj::of(['seen' => []]);
        $s->save($old);
        FileMeshWitnessStore::$writeHook = static fn($fh, string $b): int => 0;
        $this->assertSame(['RuntimeException', "FileMeshWitnessStore: cannot write $p.tmp", []], self::runWitness(fn() => $s->save(Obj::of(['seen' => [], 'x' => 'new']))));
        FileMeshWitnessStore::$writeHook = null;
        $this->assertSame(Js::stringify($old), Js::stringify($s->load()));
        $q = $this->dir . DIRECTORY_SEPARATOR . 'missing' . DIRECTORY_SEPARATOR . 'state.json';
        $this->assertSame(['RuntimeException', "FileMeshWitnessStore: cannot write $q.tmp", []], self::runWitness(fn() => (new FileMeshWitnessStore($q))->save($old)));
        $d = $this->dir . DIRECTORY_SEPARATOR . 'adir';
        mkdir($d, 0700);
        $r = self::runWitness(fn() => (new FileMeshWitnessStore($d))->save($old));
        $this->assertSame(['RuntimeException', 'FileMeshWitnessStore: cannot replace the state file'], [$r[0], $r[1]]);
    }

    /** revoke refuses a non-string, reports new vs repeated ids; has and membershipProof are public and exact. */
    public function testRevocationSet(): void
    {
        $rs = new RevocationSet();
        $this->assertSame(['TypeError', 'revoke: id must be a string', []], self::runWitness(static fn() => $rs->revoke(5)));
        $this->assertTrue($rs->revoke('c'));
        $this->assertTrue($rs->revoke('a'));
        $this->assertFalse($rs->revoke('a'));
        $this->assertTrue($rs->has('a'));
        $this->assertFalse($rs->has('b'));
        $this->assertSame(0, $rs->membershipProof('a')->get('index')->int());
        $this->assertSame(1, $rs->membershipProof('c')->get('index')->int());
        $no = ['InvalidArgumentException', 'membershipProof: id is not revoked', []];
        $this->assertSame($no, self::runWitness(static fn() => $rs->membershipProof('b')));
        $this->assertSame($no, self::runWitness(static fn() => $rs->membershipProof('z')));
        $this->assertSame($no, self::runWitness(static fn() => (new RevocationSet())->membershipProof('a')));
    }

    /** cosign refuses a request that is not an Obj or carries no head object. */
    public function testCosignMalformedRequest(): void
    {
        $w = new MeshWitness(self::kp('w'));
        $bad = ['InvalidArgumentException', 'witness: malformed head', []];
        $this->assertSame($bad, self::runWitness(static fn() => $w->cosign(null)));
        $this->assertSame($bad, self::runWitness(static fn() => $w->cosign(Obj::of(['head' => null]))));
    }

    /** A witness refuses heads when its clock or skew is not a finite number. */
    public function testCosignClockRules(): void
    {
        $ch = (new MeshDomain('d', self::kp('d')))->publishHead([], 1000);
        $req = Obj::of(['head' => $ch, 'rev_ids' => []]);
        $future = ['InvalidArgumentException', 'witness: head timestamp is in the future', []];
        $this->assertSame((new MeshWitness(self::kp('w')))->id, (new MeshWitness(self::kp('w'), null, static fn(): float => 5000.0))->cosign($req)->get('witness'));
        $this->assertSame($future, self::runWitness(static fn() => (new MeshWitness(self::kp('w'), null, static fn(): float => INF))->cosign($req)));
        $this->assertSame($future, self::runWitness(static fn() => (new MeshWitness(self::kp('w'), null, static fn(): float => 5000.0, INF))->cosign($req)));
        $this->assertSame($future, self::runWitness(static fn() => (new MeshWitness(self::kp('w'), null, static fn(): string => '99999'))->cosign($req)));
    }

    /** The revocation list must match the head in size AND root, and may hold exactly MAX_REV_IDS entries. */
    public function testCosignRevocationList(): void
    {
        $this->assertSame(1000000, MeshWitness::MAX_REV_IDS);
        $d = new MeshDomain('d', self::kp('d'));
        $d->revoke('a');
        $ch = $d->publishHead([], 1000);
        $this->assertSame(['InvalidArgumentException', 'witness: revocation list does not match head', []],
            self::runWitness(static fn() => (new MeshWitness(self::kp('w')))->cosign(Obj::of(['head' => $ch, 'rev_ids' => ['b']]))));
        $big = array_fill(0, MeshWitness::MAX_REV_IDS, 'a');
        $this->assertSame((new MeshWitness(self::kp('w')))->id, (new MeshWitness(self::kp('w')))->cosign(Obj::of(['head' => $ch, 'rev_ids' => $big]))->get('witness'));
    }

    /** A head that drops a revocation the witness already cosigned is refused. */
    public function testCosignRefusesDroppedRevocation(): void
    {
        $w = new MeshWitness(self::kp('w'));
        $d1 = new MeshDomain('d', self::kp('d'));
        $d1->revoke('a');
        $d1->publishHead([$w], 1000);
        $d2 = new MeshDomain('d', self::kp('d'));
        $d2->revoke('b');
        $d2->revoke('c');
        $ch = $d2->publishHead([], 2000);
        $this->assertSame(['InvalidArgumentException', 'witness: revocation set drops a previously cosigned revocation', []],
            self::runWitness(static fn() => $w->cosign(Obj::of(['head' => $ch, 'rev_ids' => ['b', 'c']]))));
    }

    /** exportState lists domains in UTF-16 order whatever order they were cosigned in. */
    public function testExportStateIsSorted(): void
    {
        $a = new MeshDomain('a', self::kp('da'));
        $b = new MeshDomain('b', self::kp('db'));
        [$lo, $hi] = strcmp($a->id, $b->id) < 0 ? [$a, $b] : [$b, $a];
        $w = new MeshWitness(self::kp('w'));
        $hi->publishHead([$w], 1000);
        $lo->publishHead([$w], 1000);
        $ids = array_map(static fn(Obj $s): string => $s->get('head')->get('domain'), $w->exportState()->get('seen'));
        $this->assertSame([$lo->id, $hi->id], $ids);
    }

    /** A consistency proof between two sizes covers only the first newSize commits. */
    public function testConsistencyProofUsesThePrefix(): void
    {
        $all = LedgerProofs::consistencyProof(['c0', 'c1', 'c2', 'c3'], 1, 2);
        $this->assertSame(Js::stringify(LedgerProofs::consistencyProof(['c0', 'c1'], 1, 2)), Js::stringify($all));
        $this->assertSame([Pca::merkleRoot(['c1'])], $all->get('path'));
    }

    /** keyRevocationId is public; enroll and publishHead refuse values the canonical form cannot carry instead of signing an empty message. */
    public function testDomainSigningRefusesNonCanonical(): void
    {
        $this->assertSame('key:abc', MeshDomain::keyRevocationId('abc'));
        $d = new MeshDomain('d', self::kp('d'));
        $b = $d->enroll('agent', 'role');
        $this->assertTrue(Pca::verifyEd25519B64u($d->id, (string)Mesh::msg(Mesh::BINDING_DOMAIN, Obj::of(['agent' => 'agent', 'domain' => $d->id, 'role' => 'role'])), $b->get('sig')));
        $this->assertSame(['Atlas\Pca\JsonError', 'canonicalize: lone surrogate in string', []], self::runWitness(static fn() => $d->enroll("\xED\xA0\x80", 'role')));
        $this->assertSame(['InvalidArgumentException', 'non-finite number', []], self::runWitness(static fn() => $d->publishHead([], INF)));
    }

    /** pinProof refuses a non-numeric size and a non-string head sig; evidence refuses a cap the head never logged. */
    public function testPinProofAndEvidenceRefusals(): void
    {
        $d = new MeshDomain('d', self::kp('d'));
        $d->record(Obj::of(['id' => 'c1', 'issuer' => 'i']));
        $ch = $d->publishHead([], 1000);
        $this->assertSame(['RangeException', 'consistencyProof: invalid sizes', []], self::runWitness(static fn() => $d->pinProof(Obj::of(['size' => 'x']), $ch)));
        $odd = Obj::of(['head' => $ch->get('head'), 'sig' => 1.5]);
        $this->assertSame(['InvalidArgumentException', 'pinProof: unknown head', []], self::runWitness(static fn() => $d->pinProof(Obj::of(['size' => 0]), $odd)));
        $this->assertSame(['InvalidArgumentException', 'evidence: unknown head', []], self::runWitness(static fn() => $d->evidence(Obj::of(['id' => 'c1', 'issuer' => 'i']), $odd)));
        $this->assertSame(['InvalidArgumentException', 'evidence: capability not in this head', []], self::runWitness(static fn() => $d->evidence(Obj::of(['id' => 'c2', 'issuer' => 'i']), $ch)));
    }
}
