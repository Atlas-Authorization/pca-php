<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Passport.php';

use Atlas\Pca\Sign;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Passport;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The rest of the agent passport against the TS reference (the binding match, trust score and assurance label are replayed by RefPassportHelpersDifferentialTest):
 * the cases of test-data/ref-passport.json.gz for the fingerprint, issuing, the registry, the evidence binding, signing under three suites and verification (time,
 * revocation and hardware order, PQ pins, the evidence age rule). A refusal is compared by its reason code. RULING: `allowUnboundPq` is not ported, so the case the
 * reference accepts only through it must be REFUSED (counted).
 */
final class RefPassportDifferentialTest extends TestCase
{
    private const FILE = 'ref-passport.json.gz';
    private const FNS = ['passportFingerprint' => 13, 'issuePassport' => 12, 'registry' => 4, 'passportEvidenceBinding' => 5, 'signPassport' => 30, 'verifyPassport' => 109, 'constants' => 1];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => isset(self::FNS[$d[1]]));
    }

    private static function secret(mixed $v): string
    {
        $v = $v instanceof Obj && $v->keys() === ['$bytes'] ? $v->get('$bytes') : $v;
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    private static function int(mixed $x): ?int
    {
        return $x === null || $x instanceof \Atlas\Pca\Undef ? null : (int)Js::num($x);
    }

    private static function sign(Obj $passport, Obj $o): Obj
    {
        $su = $o->has('suite') ? $o->get('suite') : null;
        $alg = $su instanceof Obj ? $su->get('alg') : null;
        $pq = $su instanceof Obj && $su->has('pqSeed') ? new PqKeyPair('ML-DSA-65', self::secret($su->get('pqSeed'))) : null;
        return Sign::signPassport($passport, new KeyPair(self::secret($o->get('issuerSecret'))), $o->get('subject'), $o->has('exp') ? $o->get('exp') : null,
            $o->has('iat') ? $o->get('iat') : null, $o->has('nbf') ? $o->get('nbf') : null, $o->has('evidence') ? $o->get('evidence') : null, $alg, $pq);
    }

    private static function verify(mixed $sp, Obj $o): array
    {
        $opts = [];
        foreach (['trustedIssuers', 'now', 'clockSkewMs', 'subject', 'maxEvidenceAgeMs', 'pqPins'] as $k) {
            if ($o->has($k)) {
                $v = $o->get($k);
                $opts[$k] = $v instanceof Obj && $v->keys() === ['$num'] ? ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')] : $v;
            }
        }
        $rev = $o->has('revocation') ? $o->get('revocation') : 'none';
        if ($rev instanceof Obj) {
            $opts['revocation'] = static function (array $x) use ($rev): bool {
                if ($rev->has('revoked')) {
                    return $rev->get('revoked') === true;
                }
                return in_array($x['id'], $rev->get('revokedIds'), true);
            };
        } elseif ($rev === 'throws') {
            $opts['revocation'] = static function (array $x): bool {
                throw new \RuntimeException('revocation source down');
            };
        }
        if ($o->has('hardware')) {
            $hw = $o->get('hardware');
            $opts['attest'] = static function ($doc, array $expected) use ($hw) {
                if ($hw->has('throws')) {
                    throw new \RuntimeException((string)$hw->get('throws'));
                }
                return $hw->get('result');
            };
        }
        $r = Passport::verify($sp, $opts);
        unset($r['detail']);
        return $r;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'passportFingerprint' => static fn(array $a) => Sign::passportFingerprint($a[0]),
            'issuePassport' => static fn(array $a) => Sign::issuePassport($a[0]),
            'registry' => static function (array $a) {
                $r = Passport::buildRegistry($a[0]);
                return array_map(static fn(array $op) => $op[0] === 'get' ? $r['get']($op[1]) : ($op[0] === 'has' ? $r['has']($op[1]) : $r['all']()), $a[1]);
            },
            'passportEvidenceBinding' => static fn(array $a) => Passport::evidenceBinding($a[0], $a[1], $a[2]),
            'signPassport' => static fn(array $a) => self::sign($a[0], $a[1]),
            'verifyPassport' => static function (array $a, Obj $c) {
                $have = self::verify($a[0], $a[1]);
                $want = $c->get('out');
                if ($want instanceof Obj) {
                    $c->set('out', $want->without('detail'));
                }
                if ($a[1]->get('allowUnboundPq') === true && $want instanceof Obj && $want->get('ok') === true) {
                    Assert::assertFalse($have['ok'], 'allowUnboundPq is not ported: the native verifier refuses what only that opt-out accepts');
                    return [Base::SKIP, 'allowUnboundPq ruling'];
                }
                return $have;
            },
            'constants' => static fn(array $a) => ['PASSPORT_SIG_DOMAIN' => Passport::SIG_DOMAIN, 'PASSPORT_VERSION' => Passport::VERSION, 'DEFAULT_PASSPORT_EVIDENCE_AGE_MS' => Passport::DEFAULT_EVIDENCE_AGE_MS],
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        $unbound = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                if (str_starts_with($line, '{"fn":"' . $fn . '"')) {
                    $have[$fn]++;
                    $unbound += $fn === 'verifyPassport' && str_contains($line, '"allowUnboundPq":true') && str_contains($line, '"out":{"ok":true') ? 1 : 0;
                }
            }
        }
        $this->assertSame(self::FNS, $have);
        $this->assertSame(1, $unbound, 'the verifyPassport cases refused for allowUnboundPq');
    }
}
