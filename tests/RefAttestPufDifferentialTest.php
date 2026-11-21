<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestPuf.php';

use Atlas\Pca\AttestPuf;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PufEnrollmentRegistry;
use Atlas\Pca\PufProvider;
use Atlas\Pca\TpmEkPufProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The PUF attestation root against the TS reference: every case of test-data/ref-attest-puf.json.gz (constants, the correction bound,
 * the simulated PUF, the fuzzy extractor, the TPM-EK provider over an injected runner, enrollment, the device attestor, the registry,
 * the verifier). Bit vectors are strings with one 0 / 1 byte per bit; a `{"$seed": label}` is sha256("atlas-pca-conformance/" . label).
 * A reference throw requires only a refusal; the fuzzyEnroll / fuzzyReproduce / enrollPuf / pufAttest / registry results are wrapped
 * `{ok, value}` exactly where the case's expected result is.
 */
final class RefAttestPufDifferentialTest extends TestCase
{
    private const FILE = 'ref-attest-puf.json.gz';
    private const FNS = ['constants' => 1, 'repetitionCorrectionBound' => 12, 'simulatedPufResponse' => 30, 'fuzzyEnroll' => 23, 'fuzzyReproduce' => 80,
        'tpmEk' => 30, 'enrollPuf' => 13, 'pufAttest' => 22, 'registry' => 10, 'verifyPuf' => 52, 'buildVerifier' => 5];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(mixed $v): string
    {
        if ($v instanceof Obj && $v->has('$seed')) {
            return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
        }
        return (string)Pca::unb64u((string)$v);
    }

    private static function puf(Obj $s): PufProvider
    {
        return AttestPuf::createSimulatedPuf((string)$s->get('id'), self::seed($s->get('seed')), (int)Js::num($s->get('length')), $s->has('flip') ? array_map(static fn($n) => (int)Js::num($n), $s->get('flip')) : []);
    }

    /** The reference's randomBytes callback: the first call returns r1 (cut to n), the second r2. */
    private static function rnd(array $r): \Closure
    {
        $i = 0;
        return static function (int $n) use ($r, &$i): string {
            return substr(Base::bytes($r[$i++]), 0, $n);
        };
    }

    private static function wrap(Obj $c, mixed $v): mixed
    {
        $w = $c->get('out');
        return $w instanceof Obj && $w->has('ok') && $w->has('value') ? Obj::of(['ok' => true, 'value' => $v]) : $v;
    }

    private static function tpm(Obj $a): Obj
    {
        $calls = [];
        $spec = $a->get('run');
        $runner = static function (string $cmd, array $args) use (&$calls, $spec) {
            $calls[] = [$cmd, $args];
            if ($spec === 'undefined') {
                return null;
            }
            if ($spec instanceof Obj && $spec->has('$throws')) {
                throw new \Exception((string)$spec->get('$throws'));
            }
            $r = new Obj();
            foreach ($spec->keys() as $k) {
                $v = $spec->get($k);
                // a stdout that is not bytes (a plain JSON string) is not a byte array in the reference
                $r->set($k, $k === 'stdout' ? (($v instanceof Obj && $v->keys() === ['$bytes']) ? Base::bytes($v) : null) : $v);
            }
            return $r;
        };
        $opts = $a->get('opts');
        try {
            $cfg = new Obj();
            if ($opts instanceof Obj) {
                foreach ($opts->keys() as $k) {
                    $cfg->set($k, $opts->get($k));
                }
                $cfg->set('run', $runner);
            } else {
                $cfg = $opts;
            }
            $p = new TpmEkPufProvider($cfg);
            $out = Obj::of(['ok' => true, 'value' => Base::outBytes($a->get('op') === 'readEkPublic' ? $p->readEkPublic() : $p->response($a->has('challenge') ? Base::bytes($a->get('challenge')) : hash('sha256', 'attest-puf-oracle-randomness/challenge', true)))]);
        } catch (\Throwable $e) {
            $out = Obj::of(['ok' => false, 'error' => $e->getMessage()]);
        }
        $out->set('calls', $calls);
        return $out;
    }

    private static function verifier(Obj $sc): \Closure
    {
        $c = $sc->get('config');
        $pc = $c->get('policy');
        $policy = new Obj();
        if ($pc instanceof Obj) {
            foreach (['measurements', 'weightsMeasurements'] as $k) {
                if ($pc->has($k)) {
                    $policy->set($k, $pc->get($k));
                }
            }
            if ($pc->get('identity') === 'custom') {
                $policy->set('deriveIdentity', static fn(Obj $st, Obj $enr) => Obj::of(['model_id' => 'm-custom',
                    'weights_digest' => $st->has('weights_digest') && $st->get('weights_digest') !== null ? $st->get('weights_digest') : '',
                    'weights_measured' => true, 'runtime_measurement' => $st->get('measurement'), 'operator' => $enr->get('providerId')]));
            }
        }
        $cfg = new Obj();
        if ($pc instanceof Obj) {
            $cfg->set('policy', $policy);
        }
        if ($c->has('requirePq')) {
            $cfg->set('requirePq', $c->get('requirePq'));
        }
        $by = [];
        foreach ($sc->has('enrollments') ? $sc->get('enrollments') : [] as $e) {
            $by['k' . $e->get('providerId')] = $e;
        }
        if ($c->get('noResolveEnrollment') !== true) {
            $cfg->set('resolveEnrollment', static fn(string $id) => $by['k' . $id] ?? null);
        }
        if ($c->get('noEvidenceSeam') !== true) {
            $ev = $sc->get('evidence');
            $cfg->set('resolveEvidence', static fn() => $ev);
        }
        if ($sc->has('revoked')) {
            $rv = $sc->get('revoked');
            $cfg->set('isRevoked', static fn(string $id) => in_array($id, $rv, true));
        }
        return AttestPuf::createPufVerifier($cfg);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['PUF_EXTRACT_INFO' => AttestPuf::PUF_EXTRACT_INFO, 'PUF_ATTEST_DOMAIN' => AttestPuf::PUF_ATTEST_DOMAIN,
                'PUF_KEY_BYTES' => AttestPuf::PUF_KEY_BYTES, 'TPM_EK_PUF_DOMAIN' => AttestPuf::TPM_EK_PUF_DOMAIN],
            'repetitionCorrectionBound' => static fn(array $a) => AttestPuf::repetitionCorrectionBound($a[0]),
            'simulatedPufResponse' => static fn(array $a) => Base::outBytes(self::puf($a[0])->response(Base::bytes($a[1]))),
            'fuzzyEnroll' => static function (array $a, Obj $c) {
                $r = AttestPuf::fuzzyEnroll(Base::bytes($a[0]), $a[1], self::rnd($a[2]));
                return self::wrap($c, Obj::of(['keySha256' => hash('sha256', $r['key']), 'helper' => $r['helper']]));
            },
            'fuzzyReproduce' => static fn(array $a, Obj $c) => self::wrap($c, Obj::of(['keySha256' => hash('sha256', AttestPuf::fuzzyReproduce(Base::bytes($a[0]), $a[1]))])),
            'tpmEk' => static fn(array $a) => self::tpm($a[0]),
            'enrollPuf' => static fn(array $a, Obj $c) => self::wrap($c, AttestPuf::enrollPuf(self::puf($a[0]), Base::bytes($a[1]), $a[2], self::rnd($a[3]))),
            'pufAttest' => static fn(array $a, Obj $c) => self::wrap($c, AttestPuf::createPufAttestor(self::puf($a[0]), $a[1])($a[2])),
            'registry' => static function (array $a, Obj $c) {
                $sc = $a[0];
                $r = new PufEnrollmentRegistry($sc->get('enrollments'));
                $out = [];
                foreach ($sc->get('ops') as $op) {
                    $key = $op->keys()[0];
                    $out[] = match ($key) {
                        'register' => $r->register($op->get('register')),
                        'lookup' => $r->lookup($op->get('lookup')),
                        'revoke' => $r->revoke($op->get('revoke')),
                        default => $r->isRevoked($op->get('isRevoked')),
                    };
                }
                return self::wrap($c, $out);
            },
            'verifyPuf' => static function (array $a) {
                $sc = $a[0];
                $in = $sc->get('input');
                $r = (self::verifier($sc))(Obj::of(['document' => new Obj(), 'ctx' => new Obj(), 'nowMs' => $in->get('nowMs'), 'expected' => $in->has('expected') ? $in->get('expected') : \Atlas\Pca\Jsx::$U]));
                return $r;
            },
            'buildVerifier' => static function (array $a, Obj $c) {
                $cfg = new Obj();
                if ($a[0]->has('policy')) {
                    $cfg->set('policy', $a[0]->get('policy'));
                }
                if ($a[0]->get('noResolveEnrollment') !== true) {
                    $cfg->set('resolveEnrollment', static fn() => null);
                }
                AttestPuf::createPufVerifier($cfg);
                return self::wrap($c, ['built' => true]);
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
