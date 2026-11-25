<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SafetyCertificate.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\SafetyCertificate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The safety certificate against the TS reference: every case of test-data/ref-safety-certificate.json.gz. A secret is
 * {"$bytes": {"$seed": label}} = sha256("atlas-pca-conformance/" . label) (an Ed25519 seed, or the ML-DSA-65 key generation seed of
 * a suite's `pqSeed`); {"$num": ...} is that non-finite double, in arguments and in results. The two cases that verify a post-quantum
 * certificate under `allowUnboundPq` are skipped: this SDK has no such switch (a certificate's own key is never enough).
 */
final class RefSafetyCertificateDifferentialTest extends TestCase
{
    private const FILE = 'ref-safety-certificate.json.gz';
    private const TOTAL = 262;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(mixed $v): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$bytes')->get('$seed'), true);
    }

    /** {"$num"} to the double, everywhere. */
    private static function un(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::un(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if ($v->keys() === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::un($v->get($k)));
        }
        return $o;
    }

    /** Non-finite doubles in the oracle's form. */
    private static function out(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::out(...), $v);
        }
        return is_float($v) && !is_finite($v) ? Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]) : $v;
    }

    private static function unbound(mixed $opts): bool
    {
        return $opts instanceof Obj && $opts->get('allowUnboundPq') === true;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['MAX_SAFETY_CHECKS' => SafetyCertificate::MAX_SAFETY_CHECKS, 'SAFETY_CERT_DOMAIN' => SafetyCertificate::SAFETY_CERT_DOMAIN,
                'SAFETY_CERT_SCOPE' => SafetyCertificate::SAFETY_CERT_SCOPE, 'SAFETY_CERT_VERSION' => SafetyCertificate::SAFETY_CERT_VERSION],
            'safetyCertificateBound' => static fn(array $a) => self::out(SafetyCertificate::safetyCertificateBound(self::un($a[0]))),
            'safetyCertificateStatement' => static fn(array $a) => SafetyCertificate::safetyCertificateStatement(self::un($a[0])),
            'validateSafetyChecks' => static fn(array $a) => SafetyCertificate::validateSafetyChecks(self::un($a[0])),
            'safetyCertificateMessage' => static fn(array $a) => Base::outBytes(SafetyCertificate::safetyCertificateMessage(self::un($a[0]))),
            'issueSafetyCertificate' => static function (array $a) {
                $x = $a[0];
                $suite = $x->get('suite');
                $opt = static fn(string $k): mixed => $x->has($k) ? self::un($x->get($k)) : SafetyCertificate::UNSET;
                return SafetyCertificate::issueSafetyCertificate(self::un($x->get('policy')), new KeyPair(self::seed($x->get('guardianSecret'))), self::un($x->get('issuedAt')),
                    $opt('checks'), $opt('grantRef'), $opt('instance'), $suite?->get('alg'), $suite?->has('pqSeed') ? new PqKeyPair('ML-DSA-65', self::seed($suite->get('pqSeed'))) : null);
            },
            'verifySafetyCertificate' => static fn(array $a) => self::unbound($a[1])
                ? [Base::SKIP, 'no allowUnboundPq in this SDK']
                : self::out(SafetyCertificate::verifySafetyCertificate(self::un($a[0]), self::un($a[1]))),
            'encodeSafetyCertificate' => static fn(array $a) => SafetyCertificate::encodeSafetyCertificate(self::un($a[0])),
            'decodeSafetyCertificate' => static fn(array $a) => SafetyCertificate::decodeSafetyCertificate($a[0]),
            'safetyCertificateForCompliance' => static fn(array $a) => self::unbound($a[1])
                ? [Base::SKIP, 'no allowUnboundPq in this SDK']
                : SafetyCertificate::safetyCertificateForCompliance(self::un($a[0]), self::un($a[1])),
        ]);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = $unbound = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
            $unbound += str_contains($line, '"allowUnboundPq":true') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
        $this->assertSame(2, $unbound, 'the cases skipped for allowUnboundPq');
    }
}
