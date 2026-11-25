<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestCosign;
use Atlas\Pca\AttestEat;
use Atlas\Pca\AttestEatProvenance;
use Atlas\Pca\SigstoreBundle;
use Atlas\Pca\KeyPair;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * EAT build / verify / freshness / channel binding / RATS appraisal / tolerant SEV-SNP parse / AMD delegation against the TS reference:
 * test-data/ref-attest-eat.json.gz (the artifact discharge is replayed by RefAttestEatDischargeTest). Signing keys come from
 * the corpus's throwaway seeds; the co-signature keys are "$seed:<label>" placeholders (sha256("atlas-pca-conformance/" + label)). Ed25519 tokens are exact; ES256 tokens are verify-only.
 */
final class RefAttestEatDifferentialTest extends TestCase
{
    private const FILE = 'ref-attest-eat.json.gz';

    public static function provide(): array
    {
        return Base::datasetsWithGen(self::FILE);
    }

    /** {"$bytes"} to raw bytes, recursively. */
    private static function rev(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return Base::bytes($v);
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::rev($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::rev(...), $v) : $v;
    }

    /** A key spec: signing {alg: EdDSA, seed} to the 32-byte seed; verifying {alg: EdDSA, pub} to the raw key, {alg: ES256, x, y} to a JWK. */
    private static function key(mixed $spec): mixed
    {
        if (!($spec instanceof Obj) || !$spec->has('alg')) {
            return $spec;
        }
        if ($spec->has('seed')) {
            return Pca::unb64u($spec->get('seed'));
        }
        if ($spec->get('alg') === 'EdDSA') {
            return Pca::unb64u($spec->get('pub'));
        }
        return Obj::of(['kty' => 'EC', 'crv' => 'P-256', 'x' => $spec->get('x'), 'y' => $spec->get('y')]);
    }

    private static function withKey(mixed $o, string $member): mixed
    {
        if (!($o instanceof Obj)) {
            return $o;
        }
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $k === $member ? self::key($o->get($k)) : $o->get($k));
        }
        return $c;
    }


    /** A seed placeholder to bytes: "$seed:<label>" or "$seedcat:<label>,<label>...:<length>" (the labels' digests joined, cut to length). */
    private static function seedOf(string $p): string
    {
        if (!str_starts_with($p, '$seed')) {
            return Pca::unb64u($p) ?? throw new \InvalidArgumentException('seed placeholder expected'); // the corpus loader already resolved a {"$seed"} label to base64url
        }
        $d = static fn(string $l): string => hash('sha256', 'atlas-pca-conformance/' . $l, true);
        if (str_starts_with($p, '$seedcat:')) {
            [$labels, $len] = explode(':', substr($p, 9));
            return substr(implode('', array_map($d, explode(',', $labels))), 0, (int)$len);
        }
        if (!str_starts_with($p, '$seed:')) {
            throw new \InvalidArgumentException('seed placeholder expected');
        }
        return $d(substr($p, 6));
    }

    private const FAMILY = ['ml-dsa-65' => 'ML-DSA-65', 'ml-dsa-87' => 'ML-DSA-87', 'slh-dsa-sha2-128f' => 'SLH-DSA-SHA2-128f', 'slh-dsa-sha2-256s' => 'SLH-DSA-SHA2-256s'];

    private static function coSign(mixed $verdict, Obj $op): Obj
    {
        $key = $op->get('key');
        $opts = new Obj();
        foreach (['suite', 'now'] as $k) {
            if ($op->has($k)) {
                $opts->set($k, $op->get($k));
            }
        }
        if ($key instanceof Obj && $key->has('pq')) {
            $pq = $key->get('pq');
            $opts->set('pq', new PqKeyPair(self::FAMILY[$pq->get('prim')], self::seedOf($pq->get('seed'))));
        }
        if ($key instanceof Obj && $key->has('ed')) {
            $opts->set('ed', new KeyPair(self::seedOf($key->get('ed'))));
        }
        return AttestCosign::coSign($verdict, $opts);
    }

    private static function admission(array $a, Obj $c): Obj
    {
        return AttestEat::eatAdmissionEvidence($a[0], self::withKey(self::rev($a[1]), 'verifyKey'));
    }

    private static function proj(Obj $r, array $keys): Obj
    {
        $o = new Obj();
        foreach ($keys as $k) {
            if ($r->has($k)) {
                $o->set($k, $r->get($k));
            }
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        if ($fn === '') {
            Base::missingGen($file);
        }
        Base::run($file, $fn, $k, [
            'issueArtifactDischarge' => static function (array $a) { // the same replay as the discharge corpus: the issuer seed arrives resolved (a base64url of sha256(label)), the nonce is the oracle's
                $o = $a[0];
                $i = ['bundle' => $o->get('bundle'), 'roots' => SigstoreBundle::parseTrustedRoot($o->get('roots')), 'policy' => $o->get('policy'),
                    'request' => $o->get('request'), 'now' => $o->get('now')->int(), 'issuerKey' => new KeyPair((string) Pca::unb64u($o->get('issuerKey')->get('seed')))];
                if ($o->has('runtime')) {
                    $i['runtime'] = $o->get('runtime');
                }
                if ($o->get('ttl_ms') !== null) {
                    $i['ttl_ms'] = $o->get('ttl_ms')->int();
                }
                return AttestEatProvenance::issueArtifactDischarge($i, static fn(): string => substr(hash('sha256', 'eat-oracle-nonce/0', true), 0, 16));
            },
            'deriveChannelCnf' => fn(array $a) => AttestEat::deriveChannelCnf(...$a),
            'bindChannel' => fn(array $a) => AttestEat::bindChannel(...$a),
            'buildEAT' => fn(array $a) => AttestEat::buildEat(self::withKey($a[0], 'key')),
            'verifyEAT' => fn(array $a) => AttestEat::verifyEat($a[0], self::key($a[1]), $a[2] ?? new Obj()),
            // a clock case runs under the generator's frozen clock (the corpus header's clockMs), then compares normally
            'verifyFreshness' => fn(array $a, Obj $c) => AttestEat::verifyFreshness($a[0], Base::withClock(self::FILE, $c, $a[1] ?? null)),
            'verifyChannelBinding' => fn(array $a) => AttestEat::verifyChannelBinding(...$a),
            'appraise' => fn(array $a) => AttestEat::appraise(...$a),
            'parseReportTolerant' => function (array $a): Obj {
                $r = AttestEat::parseReportTolerant(self::rev($a[0]));
                $out = self::proj($r, ['ok', 'version', 'known', 'degraded', 'notes']);
                $out->set('hasReport', $r->has('report'));
                if ($r->has('evidence')) {
                    $out->set('evidence', $r->get('evidence'));
                }
                if ($r->has('report')) {
                    $out->set('measured', AttestEat::measuredFromReport($r->get('report')));
                }
                return $out;
            },
            'verifyAmdAttestation' => fn(array $a) => self::proj(AttestEat::verifyAmdAttestation(self::rev($a[0]), self::rev($a[1])),
                ['ok', 'hardwareRoot', 'reason', 'evidence', 'measured']),
            'constants' => fn() => [Base::SKIP, 'covered by testConstants'],
            'ed25519Jkt' => fn(array $a) => AttestEat::ed25519Jkt($a[0]),
            'eatAdmissionEvidence' => fn(array $a, Obj $c) => self::admission($a, $c),
            'runtimeDigestFromEat' => fn(array $a) => AttestEat::runtimeDigestFromEat($a[0], $a[1] ?? null),
            'canonicalVerdictBytes' => fn(array $a) => Base::outBytes(AttestCosign::canonicalVerdictBytes($a[0], $a[1])),
            'verdictFromAppraisal' => fn(array $a) => AttestCosign::verdictFromAppraisal($a[0], $a[1]),
            'isPqCoSignSuite' => fn(array $a) => AttestCosign::isSuite($a[0]),
            'coSignAttestation' => fn(array $a) => self::coSign($a[0], $a[1]),
            'verifyCoSignedAttestation' => fn(array $a, Obj $c) => AttestCosign::verify($a[0], Base::withClock(self::FILE, $c, $a[1] ?? null)),
            'verifyFreshAttestedEAT' => function (array $a) {
                $o = self::withKey(self::rev($a[1]), 'verifyKey');
                $rawAmd = $a[1] instanceof Obj ? $a[1]->get('amd') : null;
                if ($rawAmd instanceof Obj && is_string($rawAmd->get('rawReport')) && $o->get('amd') instanceof Obj) { // before decoding, a bare string is a JS string, not a Uint8Array
                    $o->get('amd')->set('rawReport', new Obj());
                }
                return AttestEat::verifyFreshAttestedEat($a[0], $o);
            },
        ]);
    }

    public function testConstants(): void
    {
        $this->assertSame('eat+jwt', AttestEat::EAT_TYP);
        $this->assertSame(0x2A0, AttestEat::AMD_SEV_SNP_SIGNED_REGION_END);
        $this->assertSame([2, 3, 5], AttestEat::KNOWN_REPORT_VERSIONS);
        $this->assertSame('atlas-pca/attest-cosign/v1', AttestCosign::DOMAIN);
        $this->assertSame('ml-dsa-65', AttestCosign::DEFAULT_SUITE);
        $this->assertCount(9, AttestCosign::SUITES);
    }
}
