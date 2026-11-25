<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Frost;
use Atlas\Pca\GroupDescriptor;
use Atlas\Pca\HybridThreshold;
use Atlas\Pca\Mldsa;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\PqThreshold;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The post-quantum threshold step-up against the TS reference: test-data/ref-pq-threshold.json.gz (signer-set commitment, signed group
 * descriptor, ML-DSA-65 quorum, standalone hybrid verifier) and ref-pq-threshold-java-extra.json.gz (hybrid signing with a real FROST
 * quorum, folding, the threshold hook, the step-up verifier). Needs ML-DSA-65 (ext-ffi + OpenSSL >= 3.5 libcrypto). The loader resolves the
 * seed labels the corpora carry ({"$bytes": {"$seed": label}}). The step-up case compares
 * the verdict and the quorum verdict (the reference's per-check table is the reference core's own).
 */
final class RefPqThresholdDifferentialTest extends TestCase
{
    private const MAIN = 'ref-pq-threshold.json.gz';
    private const EXTRA = 'ref-pq-threshold-java-extra.json.gz';

    public static function provideMain(): array
    {
        return Base::datasets(self::MAIN);
    }

    public static function provideExtra(): array
    {
        return Base::datasets(self::EXTRA);
    }

    protected function setUp(): void
    {
        if (!Mldsa::available()) {
            $this->markTestSkipped('needs ext-ffi and an OpenSSL >= 3.5 libcrypto (ML-DSA-65)');
        }
    }

    /** {"$bytes"} becomes Bytes, everywhere (the reference wrapper's `un`). */
    private static function dec(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return new Bytes((string) Pca::unb64u($v->get('$bytes')));
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::dec($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::dec(...), $v) : $v;
    }

    private static function raw(mixed $v): string
    {
        $b = Bytes::of(self::dec($v));
        if ($b === null) {
            throw new \InvalidArgumentException('expected bytes');
        }
        return $b;
    }

    private static function obj(mixed $v): Obj
    {
        if (!($v instanceof Obj)) {
            throw new \InvalidArgumentException('expected an object');
        }
        return $v;
    }

    private static function int(mixed $v): int
    {
        if ($v instanceof Num && $v->isInt()) {
            return $v->int();
        }
        throw new \InvalidArgumentException('expected an integer');
    }

    #[DataProvider('provideMain')]
    public function testMainAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'signerSetCommitment' => static fn(array $a) => GroupDescriptor::signerSetCommitment(self::dec($a[0])),
            'issueGroupDescriptor' => static function (array $a): array {
                $in = self::obj($a[0]);
                return GroupDescriptor::issueGroupDescriptor(self::dec($in->get('authoritySeed')), $in->get('groupPublicKey'), $in->get('t'), self::dec($in->get('participants')));
            },
            'verifyGroupDescriptor' => static function (array $a): array {
                $e = self::obj($a[1]);
                return GroupDescriptor::verifyGroupDescriptor($a[0], self::dec($e->get('trustedAuthorities')), self::dec($e->get('groupKey')), $e->get('t'), $e->get('signerSetCommitment'));
            },
            'normalizePqQuorumPool' => static function (array $a): array {
                $p = PqThreshold::normalizePqQuorumPool(self::dec($a[0]));
                sort($p, SORT_STRING);
                return $p;
            },
            'pqQuorumRepresentative' => static fn(array $a) => Base::outBytes(PqThreshold::pqQuorumRepresentative(self::raw($a[0]))),
            'verifyPqQuorum' => static fn(array $a) => PqThreshold::verifyPqQuorum($a[0], self::raw($a[1]), PqThreshold::normalizePqQuorumPool(self::dec($a[2])), $a[3]),
            'verifyHybridThreshold' => static fn(array $a) => PqThreshold::verifyHybridThreshold($a[0], self::dec($a[1]), self::dec($a[2])),
        ]);
    }

    /** The reference's step-up case also returns its core's per-check table; only the verdicts are compared. */
    private static function verdictOnly(Obj $c): void
    {
        $out = $c->get('out');
        if ($out instanceof Obj && $out->has('allow')) {
            $c->set('out', Obj::of(['allow' => $out->get('allow'), 'pq' => $out->get('pq')]));
        }
    }

    /** The reference's hybridSign case: sign with a real FROST quorum and ML-DSA co-signers, then verify what was produced. */
    private static function hybridSign(Obj $x): Obj
    {
        $t = self::int($x->get('t'));
        $n = self::int($x->get('n'));
        $coeffs = array_map(self::raw(...), $x->get('coefficients'));
        $kg = Frost::trustedDealerKeygen($t, $n, self::raw($x->get('secret')), $coeffs);
        $byId = [];
        foreach ($kg['participantShares'] as $p) {
            $byId[$p['identifier']] = $p;
        }
        $quorum = [];
        foreach ($x->get('quorum') as $id) {
            $quorum[] = $byId[self::int($id)] ?? throw new \InvalidArgumentException('unknown participant');
        }
        $pqKeys = array_map(static fn($s) => new PqKeyPair('ML-DSA-65', self::raw($s)), $x->get('pqSeeds'));
        $signers = array_map(static fn($i) => $pqKeys[self::int($i)], $x->get('pq'));
        $gpk = Pca::b64u($kg['groupPublicKey']);
        $signT = $x->has('signT') && $x->get('signT') !== null ? self::int($x->get('signT')) : $t;
        $pqT = $x->has('pqT') && $x->get('pqT') !== null ? self::int($x->get('pqT')) : null;
        $artifact = HybridThreshold::hybridThresholdSign(self::obj($x->get('action')), $x->get('groupAsString') === true ? $gpk : new Bytes($kg['groupPublicKey']), $quorum, $signT, $signers, $pqT);
        $parts = array_map(static fn(array $p) => ['identifier' => $p['identifier'], 'publicKey' => Pca::b64u($p['publicKey'])], $kg['participantShares']);
        $desc = GroupDescriptor::issueGroupDescriptor(self::raw($x->get('authSeed')), $gpk, $t, $parts);
        $verdict = PqThreshold::verifyHybridThreshold($x->get('action'), $artifact, [
            'groupKey' => $gpk, 'pqPublicKeys' => array_map(static fn(PqKeyPair $k) => $k->public, $pqKeys), 't' => $t, 'pqT' => $pqT ?? count($signers),
            'groupDescriptor' => $desc, 'trustedAuthorities' => [$desc['authority']],
        ]);
        $frost = $artifact['frost'];
        $frost['sigLen'] = strlen($frost['sig']);
        unset($frost['sig']);
        $artifact['frost'] = $frost;
        return Obj::of(['artifact' => $artifact, 'verdict' => $verdict]);
    }

    #[DataProvider('provideExtra')]
    public function testExtraAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'fold' => static fn(array $a) => HybridThreshold::foldHybridStepUp(self::dec($a[0]), self::dec($a[1])),
            'hook' => static fn(array $a) => HybridThreshold::createHybridThresholdVerifier(self::dec($a[0]))(self::dec($a[1])),
            'stepUp' => static function (array $a, Obj $c): array {
                self::verdictOnly($c);
                $r = HybridThreshold::verifyHybridStepUp(self::dec($a[0]), self::dec($a[1]));
                return ['allow' => $r['allow'], 'pq' => $r['pq']];
            },
            'hybridSign' => static fn(array $a) => self::hybridSign(self::obj($a[0])),
        ]);
    }
}
