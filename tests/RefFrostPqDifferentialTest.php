<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostPq.php';

use Atlas\Pca\Frost;
use Atlas\Pca\FrostPq;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Undef;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The post-quantum companions of a networked FROST group against the TS reference: the PQ cases of test-data/ref-frost-net.json.gz (the group-algorithm registry,
 * the signer-set digest, the co-sign representative, the hybrid co-sign signing and verification, the PQ quorum block). The Ed25519 half of a signing case is
 * freshly random, so such a case reports whether it verifies. A refusal flagged `reasonOpen` is compared without its text. The rest of the corpus (the allow
 * token, signer proof of possession, equivocation guard, signer service, coordinator, nonce store) is not replayed here.
 */
final class RefFrostPqDifferentialTest extends TestCase
{
    private const FILE = 'ref-frost-net.json.gz';
    private const FNS = ['resolveFrostGroupAlg' => 16, 'frostSignerSetDigest' => 17, 'frostCosignRepresentative' => 13, 'verifyHybridFrostCosign' => 60, 'signHybridFrostCosign' => 18,
        'pqQuorumRepresentative' => 4, 'signPqQuorum' => 7, 'normalizePqQuorumPool' => 6, 'verifyPqQuorum' => 36];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => isset(self::FNS[$d[1]]));
    }

    private static function seed(mixed $v): string
    {
        $v = $v instanceof Obj && $v->keys() === ['$bytes'] ? $v->get('$bytes') : $v;
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    /** `{"$num": ...}` to the double, bytes `{"$bytes": ...}` left as they are. */
    private static function conv(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF,
                };
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::conv($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::conv(...), $v) : $v;
    }

    private static function bytes(mixed $v): mixed
    {
        return $v instanceof Obj && $v->keys() === ['$bytes'] ? Base::bytes($v) : $v;
    }

    /** The dealer share of participant `id` for a `{"$share": descriptor}`. */
    private static function share(Obj $d): string
    {
        $coeffs = $d->get('coefficients');
        $kg = Frost::trustedDealerKeygen((int)Js::num($d->get('t')), (int)Js::num($d->get('n')), self::seed($d->get('secret')),
            $coeffs === null ? null : array_map(self::seed(...), $coeffs), $d->get('identifiers') === null ? null : array_map(static fn($x) => (int)Js::num($x), $d->get('identifiers')));
        foreach ($kg['participantShares'] as $p) {
            if ($p['identifier'] === (int)Js::num($d->get('id'))) {
                return $p['share'];
            }
        }
        throw new \LogicException('no such share');
    }

    private static function sign(array $a): Obj
    {
        $quorum = array_map(static fn(Obj $p): array => ['identifier' => (int)Js::num($p->get('identifier')), 'share' => self::share($p->get('share')->get('$share')),
            'publicKey' => Base::bytes($p->get('publicKey'))], $a[1]);
        $o = $a[3];
        $opts = [];
        if ($o->has('groupAlg')) {
            $opts['groupAlg'] = $o->get('groupAlg');
        }
        if ($o->has('threshold')) {
            $opts['threshold'] = (int)Js::num($o->get('threshold'));
        }
        if ($o->has('guardianMlDsaSeed')) {
            try {
                $opts['guardianMlDsa'] = new PqKeyPair('ML-DSA-65', self::seed($o->get('guardianMlDsaSeed')));
            } catch (\Atlas\Pca\UnsupportedSigner) {
                // no ML-DSA on this runtime: the classical suite never reads the guardian key, and a hybrid case still refuses below
            }
        } elseif ($o->has('guardianMlDsa')) {
            $opts['guardianMlDsa'] = $o->get('guardianMlDsa');
        }
        $gpk = Base::bytes($a[0]);
        $msg = Base::bytes($a[2]);
        $r = FrostPq::signHybridCosign($gpk, $quorum, $msg, $opts);
        $out = Obj::of(['sigLength' => strlen((string)Pca::unb64u($r['sig'])), 'sigVerifies' => Pca::verifyWithSuite('ed25519', ['edPub' => Pca::b64u($gpk)], $msg, ['sig' => $r['sig']])]);
        foreach (['groupAlg', 'pq_pk', 'pq_sig'] as $k) {
            if (isset($r[$k])) {
                $out->set($k, $r[$k]);
            }
        }
        return $out;
    }

    /** An open reason is not compared: the text is dropped from both sides. */
    private static function open(Obj $c, array $have): array
    {
        $w = $c->get('out');
        if ($w instanceof Obj && $w->get('reasonOpen') === true) {
            $c->set('out', $w->without('reason', 'reasonOpen'));
            unset($have['reason']);
        }
        return $have;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'resolveFrostGroupAlg' => static fn(array $a) => FrostPq::resolveGroupAlg($a === [] ? \Atlas\Pca\Jsx::$U : $a[0]),
            'frostSignerSetDigest' => static fn(array $a) => Base::outBytes(FrostPq::signerSetDigest(self::conv($a[0]))),
            'frostCosignRepresentative' => static fn(array $a) => Base::outBytes(FrostPq::cosignRepresentative($a[0], self::bytes($a[1]), self::conv($a[2]), $a[3])),
            'verifyHybridFrostCosign' => static fn(array $a, Obj $c) => self::open($c, FrostPq::verifyHybridCosign($a[0], self::bytes($a[1]), $a[2], self::conv($a[3]), $a[4])),
            'signHybridFrostCosign' => static fn(array $a) => self::sign($a),
            'pqQuorumRepresentative' => static fn(array $a) => Base::outBytes(FrostPq::pqQuorumRepresentative(self::bytes($a[0]))),
            'signPqQuorum' => static fn(array $a) => FrostPq::signPqQuorum(self::bytes($a[0]), array_map(static fn($s) => new PqKeyPair('ML-DSA-65', self::seed($s)), $a[1]), $a[2]),
            'normalizePqQuorumPool' => static function (array $a) {
                return FrostPq::normalizePqQuorumPool(array_map(static fn($p) => $p instanceof Obj && $p->keys() === ['$bytes'] ? ['bytes' => Base::bytes($p)] : $p, $a[0]));
            },
            'verifyPqQuorum' => static fn(array $a, Obj $c) => self::open($c, FrostPq::verifyPqQuorum($a[0], self::bytes($a[1]), $a[2], self::conv($a[3]))),
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
