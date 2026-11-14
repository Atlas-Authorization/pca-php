<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ArgProvenance;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Gcp;
use Atlas\Pca\Attest\Nvidia;
use Atlas\Pca\Attest\Xml;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Ledger;
use Atlas\Pca\Mesh;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\ProvenanceGate;
use Atlas\Pca\ProvenanceRecorder;
use Atlas\Pca\SafeRegex;
use PHPUnit\Framework\TestCase;

/**
 * Batch 3 (run 42472274001): deadline tests for the Merkle-proof loops whose mutants stop advancing (a shift that no longer
 * shifts, a block size that no longer grows), over real RFC 6962 / 9162 trees of 1 to 9 leaves built here, plus two kills.
 * Each loop call runs in a forked copy under K05Deadline's 3 s limit; the parent repeats it for the exact result and for coverage.
 */
final class K05KillBatch3Test extends TestCase
{
    private const MAX = 9;

    private static function mth(array $d): string
    {
        $n = count($d);
        if ($n === 1) {
            return hash('sha256', "\x00" . $d[0], true);
        }
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return hash('sha256', "\x01" . self::mth(array_slice($d, 0, $k)) . self::mth(array_slice($d, $k)), true);
    }

    /** RFC 6962 section 2.1.1 audit path of leaf $m, leaf level first. */
    private static function path(int $m, array $d): array
    {
        $n = count($d);
        if ($n === 1) {
            return [];
        }
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $m < $k
            ? [...self::path($m, array_slice($d, 0, $k)), self::mth(array_slice($d, $k))]
            : [...self::path($m - $k, array_slice($d, $k)), self::mth(array_slice($d, 0, $k))];
    }

    /** RFC 6962 section 2.1.2 SUBPROOF. */
    private static function sub(int $m, array $d, bool $b): array
    {
        $n = count($d);
        if ($m === $n) {
            return $b ? [] : [self::mth($d)];
        }
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $m <= $k
            ? [...self::sub($m, array_slice($d, 0, $k), $b), self::mth(array_slice($d, $k))]
            : [...self::sub($m - $k, array_slice($d, $k), false), self::mth(array_slice($d, 0, $k))];
    }

    private static function leaves(int $n): array
    {
        return array_map(static fn(int $i): string => "leaf-$i", range(0, $n - 1));
    }

    /** @return list<array{0: string, 1: string, 2: Obj}> [old root, new root, proof] for every 1 <= m < n <= MAX */
    private static function consistencyCases(): array
    {
        $out = [];
        for ($n = 2; $n <= self::MAX; $n++) {
            $d = self::leaves($n);
            for ($m = 1; $m < $n; $m++) {
                $path = array_map([Pca::class, 'b64u'], self::sub($m, $d, true));
                $out[] = [Pca::b64u(self::mth(array_slice($d, 0, $m))), Pca::b64u(self::mth($d)),
                    Obj::of(['oldSize' => new Num((string)$m), 'newSize' => new Num((string)$n), 'path' => $path])];
            }
        }
        return $out;
    }

    public function testLedgerConsistencyLoopsAdvanceAndVerify(): void
    {
        $cases = self::consistencyCases();
        $run = static function () use ($cases): bool {
            foreach ($cases as [$old, $new, $proof]) {
                if (!Ledger::verifyConsistency($old, $new, $proof)) {
                    return false;
                }
            }
            return true;
        };
        $this->assertSame('ok', K05Deadline::run(static function () use ($run): void {
            if (!$run()) {
                throw new \RuntimeException('a real consistency proof was refused');
            }
        }));
        $this->assertTrue($run());
    }

    public function testMeshConsistencyLoopsAdvanceAndVerify(): void
    {
        $cases = self::consistencyCases();
        $m = new \ReflectionMethod(Mesh::class, 'consistency');
        $run = static function () use ($cases, $m): bool {
            foreach ($cases as [$old, $new, $proof]) {
                if ($m->invoke(null, $old, $new, $proof) !== true) {
                    return false;
                }
            }
            return true;
        };
        $this->assertSame('ok', K05Deadline::run(static function () use ($run): void {
            if (!$run()) {
                throw new \RuntimeException('a real consistency proof was refused');
            }
        }));
        $this->assertTrue($run());
    }

    public function testRfc9162InclusionLoopsAdvanceAndVerify(): void
    {
        $run = static function (): bool {
            for ($n = 1; $n <= self::MAX; $n++) {
                $d = self::leaves($n);
                $root = self::mth($d);
                for ($i = 0; $i < $n; $i++) {
                    if (!ProvenanceGate::verifyRfc9162Inclusion(ProvenanceGate::rfc9162LeafHash($d[$i]), new Num((string)$i), new Num((string)$n), self::path($i, $d), $root)) {
                        return false;
                    }
                }
            }
            return true;
        };
        $this->assertSame('ok', K05Deadline::run(static function () use ($run): void {
            if (!$run()) {
                throw new \RuntimeException('a real inclusion proof was refused');
            }
        }));
        $this->assertTrue($run());
    }

    public function testPackAndTreeSplitLoopsAdvance(): void
    {
        $run = static function (): void {
            for ($n = 1; $n <= self::MAX; $n++) {
                $ds = array_map(static fn(int $i): string => hash('sha256', "def-$i"), range(0, $n - 1));
                $root = Actions::packRoot($ds);
                foreach ($ds as $d) {
                    $proof = Actions::packProof($ds, $d);
                    if (!Actions::verifyPackProof($root, $proof, $d)) {
                        throw new \RuntimeException("pack proof of $d in $n refused");
                    }
                }
                Pca::merkleRoot(self::leaves($n));
                for ($i = 0; $i < $n; $i++) {
                    Pca::pathShape($i, $n);
                }
            }
        };
        $this->assertSame('ok', K05Deadline::run($run));
        $run();
        $this->assertSame(['R', 'R', 'R'], Pca::pathShape(0, 8));
    }

    /** A pack proof against the RFC 6962 audit path of the same pack built here: sides, hashes, order, for 1 to 9 defs. */
    public function testPackProofIsTheRfc6962AuditPath(): void
    {
        $check = static function (): void {
            for ($n = 1; $n <= self::MAX; $n++) {
                $ds = array_map(static fn(int $i): string => hash('sha256', "pack-def-$i"), range(0, $n - 1));
                sort($ds, SORT_STRING);
                $leaves = array_map(static fn(string $d): string => IntentV2::canonicalize(Actions::packLeaf($d)), $ds);
                foreach ($ds as $i => $d) {
                    $p = Actions::packProof($ds, $d);
                    $want = self::path($i, $leaves);
                    $have = array_map(static fn(Obj $s): string => Pca::unb64u($s->get('hash'), 32), $p->get('path'));
                    if ($have !== $want || (string)$p->get('index')->lexeme !== (string)$i || (string)$p->get('size')->lexeme !== (string)$n) {
                        throw new \RuntimeException("pack proof of $i in $n differs from the audit path");
                    }
                    $sides = implode('', array_map(static fn(Obj $s): string => $s->get('side'), $p->get('path')));
                    if ($sides !== implode('', Pca::pathShape($i, $n))) {
                        throw new \RuntimeException("pack proof sides of $i in $n differ");
                    }
                }
            }
        };
        $this->assertSame('ok', K05Deadline::run($check, 2.0));
        $check();
    }

    public function testTokenSearchMovesPastARefusedOccurrence(): void
    {
        $this->assertSame('ok', K05Deadline::run(static function (): void {
            ArgProvenance::occursAsToken('ba', 'a');
            ArgProvenance::occursAsToken('xaay a', 'a');
        }));
        $this->assertFalse(ArgProvenance::occursAsToken('ba', 'a'));
        $this->assertTrue(ArgProvenance::occursAsToken('xaay a', 'a'));
    }

    /** A digest that exists by name but that the crypto provider refuses queues OpenSSL errors; the call must leave none behind. */
    public function testEcdsaVerifyDerDrainsTheErrorsAnUnsupportedDigestQueues(): void
    {
        $pub = Common::loadPublicKey(K05KillAttestGcp1Test::spki(K05KillAttestGcp1Test::key('top')));
        while (openssl_error_string() !== false) {
        }
        $this->assertFalse(Common::ecdsaVerifyDer($pub, 'not a der signature', 'data', 'md4'));
        $this->assertFalse(openssl_error_string(), 'the errors the refused digest queued are drained');
    }

    /**
     * openssl_pkey_get_public() reads an array argument as [key, passphrase], so without the string cast an array entry whose first
     * member is a good key PEM would anchor the chain; with it the entry is the text 'Array' and is skipped like any non-PEM.
     */
    public function testAnArrayRootIsNotAnAnchor(): void
    {
        $T = K05KillAttestGcp1Test::key('top');
        $R = K05KillAttestGcp1Test::key('root');
        $chain = [base64_encode(K05KillAttestGcp1Test::cert('root', 'top', $T, $R))];
        $pem = K05KillAttestGcp1Test::spkiPem($R);
        $this->assertNull(Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [$pem]], (float)K05KillAttestGcp1Test::NOW, 0.0), 'control');
        set_error_handler(static fn(int $no, string $msg): bool => $no === E_WARNING && str_contains($msg, 'Array to string'));
        try {
            $r = Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [[$pem, '']]], (float)K05KillAttestGcp1Test::NOW, 0.0);
        } finally {
            restore_error_handler();
        }
        $this->assertSame('x5c chain does not anchor in a configured GCP trust root', $r);
    }

    /** The measurement-block cursor must move past each block: a one-byte value (block size 4) and a 48-byte value (size 51). */
    public function testNvidiaMeasurementBlocksAdvance(): void
    {
        $block = static fn(int $index, string $d): string => chr($index) . "\0" . pack('v', 3 + strlen($d)) . "\0" . pack('v', strlen($d)) . $d;
        $records = $block(0, "\xAA") . $block(1, str_repeat("\xBB", 48));
        $tx = chr(0x11) . "\xE0\0\0" . str_repeat("\x07", 32) . "\0"
            . chr(0x11) . "\x60\0\0" . chr(2) . substr(pack('V', strlen($records)), 0, 3) . $records . str_repeat("\x09", 32) . pack('v', 0) . str_repeat("\xEE", 96);
        $parse = static function () use ($tx): void {
            try {
                Nvidia::parseEvidence($tx);
            } catch (\ValueError) {
                // a later structural refusal (the opaque data is empty) is fine: only the block walk must end
            }
        };
        $this->assertSame('ok', K05Deadline::run($parse));
        $parse();
        $this->assertTrue(true);
    }

    /** The source clip must shrink the text on every pass: a clip that keeps all of it never reaches 256 bytes and never returns. */
    public function testSourceClipLoopShrinksTheText(): void
    {
        $long = str_repeat('a', 300) . "\u{1F600}" . str_repeat('b', 300);
        $this->assertSame('ok', K05Deadline::run(static function () use ($long): void {
            ProvenanceRecorder::clip($long);
            ProvenanceRecorder::clip(str_repeat("\u{1F600}", 200));
        }));
        $this->assertLessThanOrEqual(256, strlen(ProvenanceRecorder::clip($long)));
        $this->assertLessThanOrEqual(256, strlen(ProvenanceRecorder::clip(str_repeat("\u{1F600}", 200))));
    }

    /** The safe-regex source scan must move past a plain '(' that is not at offset 0: a cursor reset to 1 meets it again for ever. */
    public function testSafeRegexScanMovesPastAGroupOpener(): void
    {
        $this->assertSame('ok', K05Deadline::run(static function (): void {
            SafeRegex::isSafeRegexSource('ab(c)');
            SafeRegex::isSafeRegexSource('(a)(b)');
        }));
        $this->assertIsBool(SafeRegex::isSafeRegexSource('ab(c)'));
        $this->assertIsBool(SafeRegex::isSafeRegexSource('(a)(b)'));
    }

    /** Base64 decoding of the empty string must end: a loop condition that holds at i == n never leaves the loop. */
    public function testNodeBase64DecodeOfTheEmptyStringEnds(): void
    {
        $this->assertSame('ok', K05Deadline::run(static function (): void {
            Common::nodeB64Decode('');
        }));
        $this->assertSame('', Common::nodeB64Decode(''));
    }

    /** The XML parse loop must stop at the end of the text: a bound that admits i == n re-reads the end for ever. */
    public function testXmlParseEndsAtTheEndOfTheText(): void
    {
        $this->assertSame('ok', K05Deadline::run(static function (): void {
            Xml::parse('<a/>');
            Xml::parse('<a>x</a>');
        }));
        $this->assertSame('a', Xml::parse('<a/>')->root->qname);
    }
}
