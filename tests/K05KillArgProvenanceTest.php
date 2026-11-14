<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ArgProvenance.php';

use Atlas\Pca\ArgProvenance;
use Atlas\Pca\JsonError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\ProvenanceRecorder;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for src/ArgProvenance.php (decision helpers, bundleSession, errorText, the recorder and clip). */
final class K05KillArgProvenanceTest extends TestCase
{
    private static function key(): KeyPair
    {
        return new KeyPair(str_repeat("\x05", 32));
    }

    private static function session(): string
    {
        return Pca::b64u(str_repeat("\x06", 32));
    }

    private static function rec(?callable $now = null): ProvenanceRecorder
    {
        return new ProvenanceRecorder('m', 'k', self::key(), self::session(), $now ?? static fn (): int => 10);
    }

    public function testPhpNumbersInSeq(): void
    {
        $r = self::rec()->principal('p');
        foreach ([2, 2.0] as $seq) {
            $x = $r->without();
            $x->set('seq', $seq);
            $this->assertNull(ArgProvenance::receiptWireError($x), var_export($seq, true));
        }
    }

    public function testReadOnlyNeedsListTraits(): void
    {
        $this->assertFalse(ArgProvenance::isReadOnlyAction(Obj::of(['effects' => ['read'], 'traits' => ['x' => 'pca.pii_access']])));
        $this->assertFalse(ArgProvenance::isReadOnlyAction(Obj::of(['effects' => ['read'], 'traits' => 'pca.pii_access'])));
        $this->assertTrue(ArgProvenance::isReadOnlyAction(Obj::of(['effects' => ['read'], 'traits' => ['pca.pii_access']])));
    }

    public function testExactlyMaxLeavesThenAnEmptyContainer(): void
    {
        $v = array_fill(0, ArgProvenance::MAX_LEAVES, 'x');
        $v[] = [];
        $this->assertCount(4096, ArgProvenance::leaves($v));
    }

    public function testObservationSourceBound(): void
    {
        $d = static fn (int $n): array => ArgProvenance::decide(Obj::of([
            'operation' => Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => Obj::of(['a' => 'x'])]),
            'mediators' => [],
            'observed' => [Obj::of(['origin' => 'tool', 'source' => str_repeat('s', $n)])],
        ]));
        $this->assertSame('escalate', $d(256)['outcome']);
        $deny = $d(257);
        $this->assertSame(['deny', 'malformed_config', 'observations must be a list of {origin, source}'],
            [$deny['outcome'], $deny['code'], $deny['reason']]);
    }

    public function testBundleSession(): void
    {
        $this->assertSame('s', ArgProvenance::bundleSession(Obj::of(['receipts' => [Obj::of(['session' => 's'])]])));
        $this->assertNull(ArgProvenance::bundleSession(Obj::of(['receipts' => ['x']])));
        $this->assertNull(ArgProvenance::bundleSession(Obj::of(['receipts' => []])));
        $this->assertNull(ArgProvenance::bundleSession('x'));
    }

    /** The reference's evaluation-error text (private; not reachable with these messages through decide). */
    public function testErrorText(): void
    {
        $m = new \ReflectionMethod(ArgProvenance::class, 'errorText');
        $t = static fn (\Throwable $e): string => $m->invoke(null, $e);
        $this->assertSame('negative zero is not allowed', $t(new \RuntimeException('negative zero is not allowed')));
        $this->assertSame('canonicalize: negative zero', $t(new JsonError('negative zero is not allowed')));
        $this->assertSame('canonicalize: integer outside the safe range (|n| > 2^53-1)', $t(new JsonError('integer outside the safe range')));
        $this->assertSame('canonicalize: non-integer number has more than 15 significant digits', $t(new JsonError('more than 15 significant digits')));
        $this->assertSame('canonicalize: other', $t(new JsonError('other')));
        $this->assertSame('canonicalize: x', $t(new JsonError('canonicalize: x')));
    }

    public function testRecorderConstruction(): void
    {
        $m256 = str_repeat('m', 256);
        $this->assertSame($m256, (new ProvenanceRecorder($m256, 'k', self::key(), self::session()))->pin->get('mediator'));
        try {
            new ProvenanceRecorder(str_repeat('m', 257), 'k', self::key(), self::session());
            $this->fail('a 257-byte mediator was accepted');
        } catch (\InvalidArgumentException) {
        }
        // the default clock is epoch milliseconds
        $r = new ProvenanceRecorder('m', 'k', self::key());
        $t0 = (int)(microtime(true) * 1000);
        $at = $r->principal('x')->get('issued_at')->int();
        $t1 = (int)(microtime(true) * 1000);
        $this->assertGreaterThanOrEqual($t0, $at);
        $this->assertLessThanOrEqual($t1, $at);
        $this->assertCount(1, $r->receipts());
        // the first receipt never goes below 0
        $this->assertSame(0, self::rec(static fn (): int => -5)->principal('x')->get('issued_at')->int());
        $this->assertSame(0, self::rec(static fn (): int => 0)->principal('x')->get('issued_at')->int());
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ProvenanceRecorder: ml-dsa-65 needs a post-quantum key pair');
        new ProvenanceRecorder('m', 'k', self::key(), self::session(), null, 'ml-dsa-65');
    }

    public function testOperationPartsNeedsObjectParams(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('provenance: the operation params must be a JSON object');
        ProvenanceRecorder::operationParts(['verb' => 'v', 'resource' => 'r', 'params' => 'x']);
    }

    public function testForActionNeedsVerbAndResource(): void
    {
        foreach ([['verb' => 'v', 'resource' => 5], ['resource' => 'r']] as $op) {
            try {
                self::rec()->forAction($op);
                $this->fail('accepted ' . json_encode($op));
            } catch (\InvalidArgumentException $e) {
                $this->assertSame('provenance: the operation needs a verb and a resource', $e->getMessage());
            }
        }
    }

    public function testFullSessionMessage(): void
    {
        $r = self::rec();
        for ($i = 0; $i < ArgProvenance::MAX_RECEIPTS - 1; $i++) {
            $r->principal('x');
        }
        $r->forAction(['verb' => 'v', 'resource' => 'r']);
        $this->expectException(\LengthException::class);
        $this->expectExceptionMessage("provenance: the session holds 256 receipts; start a new session with the principal's message");
        $r->forAction(['verb' => 'v', 'resource' => 'r']);
    }

    public function testClipEdges(): void
    {
        // 256 UTF-8 bytes ending in U+00D8 (UTF-16 unit 00 D8) or with it second to last: no clip
        $a = str_repeat('a', 254) . "\u{D8}";
        $this->assertSame($a, ProvenanceRecorder::clip($a));
        $b = str_repeat('a', 253) . "\u{D8}a";
        $this->assertSame($b, ProvenanceRecorder::clip($b));
        // 257 bytes ending in U+1F400 (low surrogate DC00): clipped to 127 units
        $this->assertSame(str_repeat('a', 127), ProvenanceRecorder::clip(str_repeat('a', 253) . "\u{1F400}"));
        // the cut lands on low surrogate DD00 (U+1F500): back off one unit, 32 whole characters
        $g = "\u{1F500}";
        $this->assertSame(str_repeat($g, 32), ProvenanceRecorder::clip(str_repeat($g, 50) . str_repeat("\u{e9}", 30) . 'x'));
    }
}
