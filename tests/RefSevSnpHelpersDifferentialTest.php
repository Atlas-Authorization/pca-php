<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attest/SevSnp.php';

use Atlas\Pca\Attest\Amd;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\SevSnp;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The pure AMD SEV-SNP helpers against the TS reference: every case of test-data/ref-sevsnp-helpers.json.gz (hex, PEM splitting, the report
 * parser, the P-384 key and signature helpers, the report signature, the policy gate, the default identity, the KDS VCEK fetch over an
 * injected transport, and the certificate helpers over forged VCEK certificates). {"$bytes": b64u} is bytes, {"$bigint": decimal} a u64.
 * A reason after "VCEK extensions malformed:" is compared by prefix only.
 */
final class RefSevSnpHelpersDifferentialTest extends TestCase
{
    private const FILE = 'ref-sevsnp-helpers.json.gz';
    private const MALFORMED = 'VCEK extensions malformed:';
    private const FNS = ['toHex' => 4, 'splitPemCertificates' => 15, 'parseReport' => 17, 'ecdsaP384PublicKey' => 11, 'signatureToCompact' => 10, 'verifyReportSignature' => 13,
        'checkPolicy' => 57, 'deriveIdentity' => 8, 'fetchVcek' => 14, 'extractTbsCertificate' => 16, 'extractVcekPublicKey' => 7, 'checkVcekReportBinding' => 75, 'constants' => 1];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function bytes(mixed $v): string
    {
        return (string)Base::bytes($v);
    }

    private static function out(string $raw): Obj
    {
        return Base::outBytes($raw);
    }

    private static function big(\GMP $g): Obj
    {
        return Obj::of(['$bigint' => gmp_strval($g)]);
    }

    /** A policy spec as the PHP policy array: {$bigint} is a GMP, {$num} a float, an empty object an empty array. */
    private static function plain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bigint']) {
                return gmp_init($v->get('$bigint'));
            }
            if ($v->keys() === ['$num']) {
                return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
            }
            $a = [];
            foreach ($v->keys() as $k) {
                $a[$k] = self::plain($v->get($k));
            }
            return $a;
        }
        if ($v instanceof Num) {
            return $v->isInt() ? $v->int() : $v->float();
        }
        return is_array($v) ? array_map(self::plain(...), $v) : $v;
    }

    private static function parsed(string $b): Obj
    {
        $r = SevSnp::parseReport($b);
        $o = new Obj();
        foreach ($r as $k => $v) {
            if ($k === 'signed' || $k === 'raw' || $k === 'sig_r' || $k === 'sig_s') {
                continue;
            }
            $o->set($k, match (true) {
                $v instanceof \GMP => self::big($v),
                is_string($v) => self::out($v),
                is_array($v) && $k === 'signature' => Obj::of(['r' => self::out($v['r']), 's' => self::out($v['s'])]),
                is_array($v) => Obj::of($v),
                default => $v,
            });
        }
        $o->set('signed_len', strlen($r['signed']));
        $o->set('signed_sha256', hash('sha256', $r['signed']));
        $o->set('raw_len', strlen($r['raw']));
        return $o;
    }

    private static function fetchVcek(array $a): mixed
    {
        $op = $a[2];
        $seen = [];
        $opts = [];
        foreach (['product', 'baseUrl'] as $k) {
            if ($op->has($k)) {
                $opts[$k] = $op->get($k);
            }
        }
        $status = (int)$op->get('status')->int();
        if ($op->get('noFetch') !== true) {
            $body = self::bytes($op->get('body'));
            $opts['fetch'] = static function (string $u) use (&$seen, $status, $body): array {
                $seen[] = $u;
                return ['ok' => $status >= 200 && $status < 300, 'status' => $status, 'body' => $body];
            };
        }
        $r = SevSnp::fetchVcek(self::bytes($a[0]), gmp_init($a[1]->get('$bigint')), $opts);
        return Obj::of(['url' => $seen[0], 'bytes' => self::out($r)]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'toHex' => static fn(array $a) => SevSnp::toHex(self::bytes($a[0])),
            'splitPemCertificates' => static fn(array $a) => SevSnp::splitPemCertificates($a[0]),
            'parseReport' => static fn(array $a) => self::parsed(self::bytes($a[0])),
            'ecdsaP384PublicKey' => static fn(array $a) => Obj::of(['point' => self::out(SevSnp::ecdsaP384PublicKey(self::bytes($a[0])))]),
            'signatureToCompact' => static fn(array $a) => self::out(SevSnp::signatureToCompact(self::bytes($a[0]->get('r')), self::bytes($a[0]->get('s')))),
            'verifyReportSignature' => static function (array $a) {
                $report = Amd::parseReport(self::bytes($a[0]));
                return Amd::verifyReportSignature($report, Common::ecKeyFromPoint('P-384', SevSnp::ecdsaP384PublicKey(self::bytes($a[1]))));
            },
            'checkPolicy' => static fn(array $a) => Amd::checkPolicy(Amd::parseReport(self::bytes($a[0])), self::plain($a[1])),
            'deriveIdentity' => static fn(array $a) => SevSnp::deriveIdentity(Amd::parseReport(self::bytes($a[0])), $a[1] === true),
            'fetchVcek' => static fn(array $a) => self::fetchVcek($a),
            'extractTbsCertificate' => static fn(array $a) => self::out(SevSnp::extractTbsCertificate(self::bytes($a[0]))),
            'extractVcekPublicKey' => static function (array $a) {
                $r = SevSnp::extractVcekPublicKey(self::bytes($a[0]));
                return Obj::of(['point' => self::out($r['point']), 'tbs' => self::out($r['tbs'])]);
            },
            'checkVcekReportBinding' => static function (array $a, Obj $c) {
                $r = Amd::checkVcekReportBinding(self::bytes($a[0]), Amd::parseReport(self::bytes($a[1])));
                $w = $c->get('out');
                return is_string($r) && is_string($w) && str_starts_with($r, self::MALFORMED) && str_starts_with($w, self::MALFORMED) ? $w : $r;
            },
            'constants' => static fn(array $a) => ['SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384' => SevSnp::SIG_ALGO_ECDSA_P384_SHA384,
                'SEV_SNP_POLICY_DEBUG_BIT' => self::big(gmp_init(SevSnp::POLICY_DEBUG_BIT)), 'AMD_MILAN_ARK_SPKI_SHA384' => SevSnp::milanArkSpkiSha384()],
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
