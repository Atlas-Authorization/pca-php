<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PqQuorum.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\PqQuorum;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Post-quantum quorum sets, quorum proofs and rotation chains against the TS reference: every case of
 * test-data/ref-pq-threshold-quorum.json.gz. A secret is {"$seed": label} = sha256("atlas-pca-conformance/" . label) (for ML-DSA: the
 * key generation seed); bytes are {"$bytes": base64url}. Needs ML-DSA and SLH-DSA (ext-ffi and an OpenSSL >= 3.5 libcrypto): where
 * PCA_REQUIRE_PQ is 1 a missing backend fails, elsewhere the cases that name a post-quantum suite are skipped by the harness.
 * PHP has one string type: a message the corpus gives as JSON text (not bytes) is passed as a non-string, which the native refuses
 * exactly as the reference refuses text.
 */
final class RefPqQuorumDifferentialTest extends TestCase
{
    private const FILE = 'ref-pq-threshold-quorum.json.gz';
    private const TOTAL = 389;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(mixed $v): string
    {
        if (!($v instanceof Obj) || $v->keys() !== ['$seed'] || !is_string($v->get('$seed'))) {
            throw new \InvalidArgumentException('not a seed');
        }
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    /** The key bag {edSecret?, mlDsa?, mlDsa87?} as the native's (Ed25519 key pair, PQ key pairs...). @return array{0: ?KeyPair, 1: list<PqKeyPair>} */
    private static function keys(mixed $k): array
    {
        if (!($k instanceof Obj)) {
            throw new \InvalidArgumentException('no key material');
        }
        $pq = [];
        foreach (['mlDsa' => 'ML-DSA-65', 'mlDsa87' => 'ML-DSA-87'] as $m => $family) {
            if ($k->has($m)) {
                $pq[] = new PqKeyPair($family, self::seed($k->get($m)));
            }
        }
        return [$k->has('edSecret') ? new KeyPair(self::seed($k->get('edSecret'))) : null, $pq];
    }

    /** {"$bytes"} to raw bytes; anything else (JSON text included) is not bytes. */
    private static function bytes(mixed $v): mixed
    {
        return $v instanceof Obj && $v->keys() === ['$bytes'] ? Pca::unb64u($v->get('$bytes')) : (is_string($v) ? null : $v);
    }

    public function testThePostQuantumBackendIsPresentWhereRequired(): void
    {
        if (getenv('PCA_REQUIRE_PQ') === '1') {
            $this->assertTrue(Pca::suiteAvailable('ml-dsa-65') && Pca::suiteAvailable('ml-dsa-87') && Pca::suiteAvailable('slh-dsa-sha2-128f') && Pca::suiteAvailable('slh-dsa-sha2-256s'),
                'OpenSSL >= 3.5 over FFI is required here');
        }
        $this->assertTrue(true);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['PQ_QUORUM_MAX_SIGNERS' => PqQuorum::PQ_QUORUM_MAX_SIGNERS, 'PQ_QUORUM_MAX_CHAIN' => PqQuorum::PQ_QUORUM_MAX_CHAIN],
            'buildQuorumSet' => static fn(array $a) => count($a) > 2 ? PqQuorum::buildQuorumSet($a[0], $a[1], $a[2]) : PqQuorum::buildQuorumSet($a[0], $a[1]),
            'loadQuorumSet' => static fn(array $a) => PqQuorum::loadQuorumSet($a[0]),
            'quorumMessage' => static fn(array $a) => Base::outBytes(PqQuorum::quorumMessage($a[0], $a[1], $a[2])),
            // the reference hashes a JSON string as its UTF-8 bytes, which is what a PHP string is
            'quorumActionDigest' => static fn(array $a) => PqQuorum::quorumActionDigest($a[0] instanceof Obj ? Pca::unb64u($a[0]->get('$bytes')) : $a[0]),
            'signQuorumShare' => static function (array $a) {
                [$ed, $pq] = self::keys($a[4]);
                return PqQuorum::signQuorumShare($a[0], $a[1], $a[2], $a[3], $ed, ...$pq);
            },
            'assembleQuorumProof' => static fn(array $a) => PqQuorum::assembleQuorumProof($a[0], $a[1]),
            'verifyQuorum' => static fn(array $a) => PqQuorum::verifyQuorum($a[0]),
            'verifyQuorumApproval' => static fn(array $a) => PqQuorum::verifyQuorumApproval($a[0], $a[1], self::bytes($a[2]), $a[3], $a[4] ?? null),
            'rotationActionDigest' => static fn(array $a) => PqQuorum::rotationActionDigest($a[0], $a[1]),
            'buildRotationCert' => static fn(array $a) => PqQuorum::buildRotationCert($a[0], $a[1], $a[2], $a[3]),
            'signRotationShare' => static function (array $a) {
                [$ed, $pq] = self::keys($a[4]);
                return PqQuorum::signRotationShare($a[0], $a[1], $a[2], $a[3], $ed, ...$pq);
            },
            'verifyRotationChain' => static fn(array $a) => PqQuorum::verifyRotationChain($a[0], $a[1], $a[2]),
            'isRotationFork' => static fn(array $a) => PqQuorum::isRotationFork($a[0], $a[1]),
            'quorumProofSize' => static fn(array $a) => count($a) > 1 ? PqQuorum::quorumProofSize($a[0], $a[1] ?? 'not a list') : PqQuorum::quorumProofSize($a[0]),
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
