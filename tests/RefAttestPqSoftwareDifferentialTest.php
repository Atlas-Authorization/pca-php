<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PqSoftware.php';

use Atlas\Pca\Jsx;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\PqSoftware;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The post-quantum software attestation root against the TS reference: every case of test-data/ref-attest-pq-software.json.gz (statement
 * minting under the PQ and hybrid suites, attestor construction, the verifier). A key spec is `{alg, edSecret?, seed?}` (seed labels:
 * sha256("atlas-pca-conformance/" . label) is the ML-DSA keygen seed). SLH-DSA statements are verify-only inputs. A reason that starts with
 * "pq-software verification error (fail closed):" carries the reference's own exception text: only the prefix is compared.
 */
final class RefAttestPqSoftwareDifferentialTest extends TestCase
{
    private const FILE = 'ref-attest-pq-software.json.gz';
    private const FAIL_CLOSED = 'pq-software verification error (fail closed):';
    private const FNS = ['constants' => 1, 'attest' => 29, 'buildAttestor' => 9, 'verifyPq' => 90, 'buildVerifier' => 8];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function secret(mixed $v): string
    {
        if ($v instanceof Obj && $v->has('$seed')) {
            return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
        }
        return (string)Pca::unb64u((string)$v);
    }

    /** The key material of a spec; a seed minted for the ML-DSA-65 key but declared under ML-DSA-87 is the wrong family (as in the reference). */
    private static function keys(Obj $spec): array
    {
        $alg = $spec->get('alg');
        $ed = $spec->has('edSecret') ? new KeyPair(self::secret($spec->get('edSecret'))) : null;
        $pq = null;
        if ($spec->has('seed') && is_string($alg)) {
            $label = (string)($spec->get('seed') instanceof Obj ? $spec->get('seed')->get('$seed') : '');
            $family = str_contains($alg, 'ml-dsa-65') ? 'ML-DSA-65' : (str_contains($alg, 'ml-dsa-87') ? (str_contains($label, 'ml-dsa-65') ? 'ML-DSA-65' : 'ML-DSA-87') : null);
            $pq = $family === null ? null : new PqKeyPair($family, self::secret($spec->get('seed')));
        }
        return [$alg instanceof \Atlas\Pca\Undef ? null : $alg, $ed, $pq];
    }

    private static function attestor(Obj $spec): array
    {
        [$alg, $ed, $pq] = self::keys($spec);
        return PqSoftware::createAttestor($alg, $ed, $pq);
    }

    private static function verifier(Obj $c, bool $seam, mixed $evidence): \Closure
    {
        $cfg = new Obj();
        foreach (['trustedPqPublicKeys', 'trustedEd25519PublicKeys', 'policy', 'requirePq', 'requireHybrid', 'allowedSuites'] as $k) {
            if ($c->has($k)) {
                $cfg->set($k, $c->get($k));
            }
        }
        if ($seam) {
            $cfg->set('resolveEvidence', static fn() => $evidence);
        }
        return PqSoftware::createVerifier($cfg);
    }

    private static function failClosed(array $have, mixed $want): array
    {
        $w = $want instanceof Obj ? $want->get('reason') : null;
        if (is_string($have['reason'] ?? null) && is_string($w) && str_starts_with($have['reason'], self::FAIL_CLOSED) && str_starts_with($w, self::FAIL_CLOSED)) {
            $have['reason'] = $w;
        }
        return $have;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['PQ_ATTEST_DOMAIN' => PqSoftware::DOMAIN],
            'attest' => static function (array $a) {
                $t = self::attestor($a[0]);
                $o = Obj::of(['pqPublicKey' => $t['pqPublicKey']]);
                if ($t['ed25519PublicKey'] !== null) {
                    $o->set('ed25519PublicKey', $t['ed25519PublicKey']);
                }
                $o->set('statement', $t['attest']($a[1]));
                return $o;
            },
            'buildAttestor' => static function (array $a) {
                $t = self::attestor($a[0]);
                $o = Obj::of(['pqPublicKey' => $t['pqPublicKey']]);
                if ($t['ed25519PublicKey'] !== null) {
                    $o->set('ed25519PublicKey', $t['ed25519PublicKey']);
                }
                return $o;
            },
            'verifyPq' => static function (array $a, Obj $c) {
                $sc = $a[0];
                $v = self::verifier($sc->get('config'), $sc->get('config')->get('noEvidenceSeam') !== true, $sc->get('evidence'));
                $in = $sc->get('input');
                $r = $v(Obj::of(['document' => new Obj(), 'ctx' => new Obj(), 'nowMs' => $in->get('nowMs'), 'expected' => $in->get('expected')]));
                return self::failClosed($r, $c->get('out'));
            },
            'buildVerifier' => static function (array $a) {
                self::verifier($a[0], $a[0]->get('noEvidenceSeam') !== true, null);
                return ['built' => true];
            },
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
