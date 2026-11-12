<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attest/Factory.php';
require_once __DIR__ . '/../src/PcaMiddleware.php';

use Atlas\Pca\Attest\Amd;
use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Factory;
use Atlas\Pca\Attest\Gcp;
use Atlas\Pca\Attest\Intel;
use Atlas\Pca\Attest\Maa;
use Atlas\Pca\Attest\Ocsp;
use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\Sign;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** The parity audit items: PCActn features this verifier lacks, budget monotonicity, the guards' suite policy, and the attestation edges. */
final class K05ParityAuditTest extends TestCase
{
    private const NOW = 1_800_000_000_000;
    private const ZK = 'zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof';
    private const PLAN = [['id' => 'a', 'verb' => 'v', 'resource' => 'r']];

    /** @return array{0: Obj, 1: Obj} grant, signed PCActn */
    private static function signed(array $extra = []): array
    {
        $k = KeyPair::generate();
        $grant = Sign::mintRoot(KeyPair::generate(), $k->public, []);
        return [$grant, Sign::buildPcactn($grant, [$grant], self::PLAN, 'a', 1, $k, 'aud', null, self::NOW, null, 1000, $extra)];
    }

    private static function call(array $signed, mixed ...$o): array
    {
        [$grant, $p] = $signed;
        $f = new HttpFactory();
        $h = new class implements RequestHandlerInterface {
            public int $calls = 0;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;
                return new Response(200);
            }
        };
        $mw = new PcaMiddleware('aud', static fn() => $grant, static fn() => self::NOW, $f, $f, ...$o);
        $res = $mw->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => Pca::b64u(Json::canonicalizeStrict($p))]), $h);
        return [$res->getStatusCode(), $h->calls, json_decode((string)$res->getBody(), true)];
    }

    // ---- zk_compliance and bond_ref ------------------------------------------------------------------------------------------

    public function testACarriedZkProofFailsAtTheCore(): void
    {
        [$g, $p] = self::signed();
        $this->assertTrue(Pca::verifyPcactnCore($p, $g, self::NOW, 'aud', insecureSkipPlanRootCheck: true)['allow']);
        [$g, $p] = self::signed(['zk_compliance' => ['proof' => 'x']]);
        $r = Pca::verifyPcactnCore($p, $g, self::NOW, 'aud', insecureSkipPlanRootCheck: true);
        $this->assertSame([false, false, self::ZK, [self::ZK]], [$r['allow'], $r['checks']['zk_compliance'], $r['reason'], $r['reasons']]);
        // an earlier failure stays the reason; the zk failure is still listed
        $r = Pca::verifyPcactnCore($p, $g, self::NOW, 'other', insecureSkipPlanRootCheck: true);
        $this->assertStringStartsWith('audience:', $r['reason']);
        $this->assertContains(self::ZK, $r['reasons']);
    }

    public function testSignatureOnlyGuardsRefuseWhatTheyCannotVerify(): void
    {
        $this->assertSame([200, 1], array_slice(self::call(self::signed(), signatureOnly: true), 0, 2));
        [$st, $calls, $b] = self::call(self::signed(['zk_compliance' => ['proof' => 'x']]), signatureOnly: true);
        $this->assertSame([403, 0, self::ZK], [$st, $calls, $b['error_description']]);
        [$st, $calls, $b] = self::call(self::signed(['bond_ref' => 'b']), signatureOnly: true);
        $this->assertSame([403, 0, Authorize::BOND_UNSUPPORTED], [$st, $calls, $b['error_description']]);
    }

    // ---- allowedSuites ---------------------------------------------------------------------------------------------------------

    public function testTheMiddlewareForwardsAllowedSuites(): void
    {
        $s = self::signed();
        $this->assertSame([200, 1], array_slice(self::call($s, signatureOnly: true, allowedSuites: ['ed25519']), 0, 2));
        [$st, $calls, $b] = self::call($s, signatureOnly: true, allowedSuites: ['ml-dsa-65']);
        $this->assertSame([403, 0, false], [$st, $calls, $b['checks']['chain']]);
        $opts = new AuthorizeOptions(new MemoryStateStore(), static fn() => false, plan: 'single-step',
            operation: static fn() => ['verb' => 'v', 'resource' => 'r', 'params' => new Obj()]);
        $chainOf = static fn(array $r): ?string => $r[2]['checks']['chain'] ?? null;
        $this->assertNotSame('fail', $chainOf(self::call($s, authorize: $opts)));
        $this->assertSame('fail', $chainOf(self::call($s, authorize: $opts, allowedSuites: ['ml-dsa-65'])));
    }

    // ---- budget_alloc --------------------------------------------------------------------------------------------------------

    /** A chain whose hops each add a `budget_alloc` of the next limit (and, after the root, an unrelated caveat before it). @return list<Obj> */
    private static function budgetChain(mixed ...$limits): array
    {
        $k = KeyPair::generate();
        $ba = static fn(mixed $l): array => ['type' => 'budget_alloc', 'limit' => $l];
        $chain = [Sign::mintRoot(KeyPair::generate(), $k->public, [$ba(array_shift($limits))])];
        foreach ($limits as $l) {
            $chain[] = Sign::delegate($chain[count($chain) - 1], $k, null, [['type' => 'other'], $ba($l)]);
        }
        return $chain;
    }

    public function testAllocationsAreMonotoneDownTheChain(): void
    {
        $check = static fn(array $c): array => Pca::verifyChain($c, $c[0]->get('issuer'), true);
        foreach ([[10], [10, 10], [10, 4, 0], [1.5, 1.5]] as $i => $ok) {
            $this->assertSame(['', true], $check(self::budgetChain(...$ok)), "ok $i");
        }
        $tail = "the parent's carried allocation";
        $this->assertSame(["budget_alloc caveat 2: allocation 100 widens $tail 10 (monotone: a child can only allocate <= its parent)", false], $check(self::budgetChain(10, 100)));
        $this->assertSame(["budget_alloc caveat 4: allocation 1.5 widens $tail 1 (monotone: a child can only allocate <= its parent)", false], $check(self::budgetChain(3, 1, 1.5)));
        foreach ([-1, 'x'] as $bad) {
            $this->assertSame(['budget_alloc caveat 2: limit must be a finite number >= 0', false], $check(self::budgetChain(1, $bad)));
        }
        $this->assertSame(['budget_alloc caveat 0: limit must be a finite number >= 0', false], $check(self::budgetChain(null)));
    }

    // ---- GCP: the key beside an x5c ------------------------------------------------------------------------------------------

    private static function ecKey(): \OpenSSLAsymmetricKey
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        try {
            $k = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            self::assertNotFalse($k, 'EC keygen: ' . openssl_error_string() . ' / ' . json_encode(error_get_last()));
            return $k;
        } finally {
            unlink($cnf);
        }
    }

    /** @return array{0: list<string>, 1: string, 2: string} the x5c (leaf, CA), the CA's SPKI SHA-256, the CA's PEM */
    private static function leafAndPin(\OpenSSLAsymmetricKey $leafKey, ?\OpenSSLAsymmetricKey $caKey = null): array
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n[leaf]\nbasicConstraints=critical,CA:FALSE\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n");
        try {
            $caKey ??= self::ecKey();
            $opt = static fn(string $x): array => ['config' => $cnf, 'digest_alg' => 'sha256', 'x509_extensions' => $x];
            $ca = openssl_csr_sign(openssl_csr_new(['commonName' => 'k05 ca'], $caKey, $opt('ca')), null, $caKey, 2, $opt('ca'), 1);
            $leaf = openssl_csr_sign(openssl_csr_new(['commonName' => 'k05 leaf'], $leafKey, $opt('leaf')), $ca, $caKey, 2, $opt('leaf'), 2);
            openssl_x509_export($ca, $caPem);
            openssl_x509_export($leaf, $leafPem);
            $b64 = static fn(string $pem): string => preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem);
            return [[$b64($leafPem), $b64($caPem)], Common::spkiSha(Cert::fromPem($caPem)->publicKey(), 'sha256'), $caPem];
        } finally {
            unlink($cnf);
        }
    }

    private static function jwk(\OpenSSLAsymmetricKey $k, array $x5c): Obj
    {
        $ec = openssl_pkey_get_details($k)['ec'];
        $c = static fn(string $v): string => Pca::b64u(str_pad($v, 32, "\0", STR_PAD_LEFT));
        return Obj::of(['kid' => 'k', 'kty' => 'EC', 'crv' => 'P-256', 'x' => $c($ec['x']), 'y' => $c($ec['y']), 'x5c' => $x5c]);
    }

    public function testGcpBindsTheKeyToItsX5cLeaf(): void
    {
        $leafKey = self::ecKey();
        [$x5c, $pin, $root] = self::leafAndPin($leafKey);
        $resolve = new \ReflectionMethod(Gcp::class, 'resolveTrustedSigningKey');
        $run = static fn(Obj $jwk, Obj $anchors): array => $resolve->invoke(null, ['kid' => 'k'], Obj::of(['keys' => [$jwk]]), $anchors, time() * 1000.0, 0.0);
        foreach ([Obj::of(['rootCertsPem' => [$root]]), Obj::of(['trustedKeySpki' => [$pin]])] as $i => $anchors) {
            $this->assertSame(['reason' => 'signing key not trusted: the JWK key is not the key of its x5c leaf'], $run(self::jwk(self::ecKey(), $x5c), $anchors), "forgery $i");
            $this->assertArrayHasKey('key', $run(self::jwk($leafKey, $x5c), $anchors), "honest $i");
        }
    }

    // ---- Intel: the signed body ----------------------------------------------------------------------------------------------

    private static function rawSig(\OpenSSLAsymmetricKey $k, string $data): string
    {
        openssl_sign($data, $der, $k, OPENSSL_ALGO_SHA256);
        $o = 2; // SEQUENCE header (a P-256 ECDSA signature is always short form)
        $out = '';
        for ($i = 0; $i < 2; $i++) {
            $n = ord($der[$o + 1]);
            $out .= str_pad(ltrim(substr($der, $o + 2, $n), "\0"), 32, "\0", STR_PAD_LEFT);
            $o += 2 + $n;
        }
        return bin2hex($out);
    }

    public function testIntelReadsTheSignedBodyNeverALaterDuplicate(): void
    {
        $k = self::ecKey();
        $pub = Common::loadPublicKey(base64_decode(preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details($k)['key'])));
        $signed = new \ReflectionMethod(Intel::class, 'verifySignedJson');
        foreach (['tcbInfo', 'enclaveIdentity'] as $name) {
            $raw = '{"status":"Revoked","n":1}';
            $sig = self::rawSig($k, $raw);
            $honest = $signed->invoke(null, "{\"$name\":$raw,\"signature\":\"$sig\"}", $name, $pub);
            $forged = $signed->invoke(null, "{\"$name\":$raw,\"$name\":{\"status\":\"UpToDate\",\"n\":2},\"signature\":\"$sig\"}", $name, $pub);
            $this->assertSame('Revoked', Common::g($honest['body'], 'status'), $name);
            $this->assertSame('Revoked', Common::g($forged['body'], 'status'), $name);
            $this->assertSame(1.0, Common::numOf(Common::g($forged['body'], 'n')), $name);
            // bad JSON after the signed member is still the reference's refusal
            $this->assertSame(['error' => "$name document is not valid JSON"], $signed->invoke(null, "{\"$name\":$raw,}", $name, $pub));
        }
    }

    // ---- AMD ARK pin ---------------------------------------------------------------------------------------------------------

    public function testTheAmdArkPinIsNeverTakenFromConfig(): void
    {
        $hex = str_repeat('ab', 48);
        $cfg = Json::parseLax('{"family":"genoa","binding":"report-data","policy":{"measurements":["' . $hex . '"]},"trustAnchorArkSpkiSha384":"' . str_repeat('cd', 48) . '"}');
        $pin = new \ReflectionProperty(Amd::class, 'pin');
        $table = (new \ReflectionClass(Amd::class))->getConstant('ARK_SPKI_SHA384');
        $this->assertSame($table['genoa'], $pin->getValue(Factory::verifierFromConfig('amd-sev-snp', $cfg)));
        $this->assertSame($table['genoa'], $pin->getValue(new Amd($cfg, static fn() => null)));
        $this->assertSame(str_repeat('cd', 48), $pin->getValue(Factory::vectorVerifier('amd-sev-snp', $cfg)));
        // no override in the row: the built-in pin; the harness never rescues an unknown family
        $plain = $cfg->without('trustAnchorArkSpkiSha384');
        $this->assertSame($table['genoa'], $pin->getValue(Factory::vectorVerifier('amd-sev-snp', $plain)));
        $unknown = $cfg->without('family');
        $unknown->set('family', 'nope');
        $this->expectException(AttestConstructError::class);
        Factory::vectorVerifier('amd-sev-snp', $unknown);
    }

    // ---- mixed allowlists ----------------------------------------------------------------------------------------------------

    public function testOneNonStringEntryRefusesEveryVerification(): void
    {
        $this->assertSame(['ab', 'cd'], Common::lowerStrict(['AB', 'cd']));
        $this->assertSame(['ab'], Common::lowerStrict([3 => 'AB']));
        $sites = [
            static fn(array $l) => (new \ReflectionMethod(Intel::class, 'lowerList'))->invoke(null, $l),
            static fn(array $l) => (new \ReflectionMethod(Maa::class, 'lower'))->invoke(null, $l),
            static fn(array $l) => (new \ReflectionMethod(Amd::class, 'lowerList'))->invoke(null, $l),
            static fn(array $l) => Amd::checkPolicy(['signature_algo' => 1, 'policy' => gmp_init(0), 'guest_svn' => 0, 'vmpl' => 0, 'measurement' => 'x', 'host_data' => 'x', 'chip_id' => 'x'], ['hostData' => $l]),
        ];
        foreach ($sites as $i => $site) {
            try {
                $site(['78', new Num('1')]);
                $this->fail("site $i kept a mixed list");
            } catch (\TypeError $e) {
                $this->assertSame('x.toLowerCase is not a function', $e->getMessage(), "site $i");
            }
        }
    }

    public function testGcpAllowlists(): void
    {
        $base = '{"trustedIssuers":["https://x"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":%s,"allowedTeeTypes":["T",1],"allowedSwVersions":["7",8]}}';
        $v = Factory::verifierFromConfig('gcp-confidential-space', Json::parseLax(sprintf($base, '["sha256:AB"]')));
        $prop = static fn(string $n) => (new \ReflectionProperty(Gcp::class, $n))->getValue($v);
        // a Set of the list as given: 1 and 8 can never match the claim "1" or "8"
        $this->assertSame(['T' => true], $prop('teeTypes'));
        $this->assertSame([7 => true], $prop('swVersions'));
        $this->assertSame(['sha256:ab' => true], $prop('images'));
        $this->expectException(AttestConstructError::class);
        Factory::verifierFromConfig('gcp-confidential-space', Json::parseLax(sprintf($base, '["sha256:ab",1]')));
    }

    // ---- OCSP under an RSASSA-PSS key ----------------------------------------------------------------------------------------

    public function testOcspRefusesAnRsaPssKey(): void
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        $priv = openssl_pkey_new(['config' => $cnf, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        unlink($cnf);
        $spki = base64_decode(preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details($priv)['key']));
        // the same key under id-RSASSA-PSS (absent parameters): the AlgorithmIdentifier is two bytes shorter
        $rsaAlg = hex2bin('300d06092a864886f70d0101010500');
        $this->assertSame(4, strpos($spki, $rsaAlg));
        $rest = substr($spki, 4 + strlen($rsaAlg));
        $body = hex2bin('300b06092a864886f70d01010a') . $rest;
        $pssSpki = "\x30\x82" . pack('n', strlen($body)) . $body;
        $rsa = Common::loadPublicKey($spki);
        $pss = Common::loadPublicKey($pssSpki);
        $this->assertSame([false, true], [Common::isRsaPss($rsa), Common::isRsaPss($pss)]);
        $this->assertSame('rsa', $pss->type);

        $data = 'tbs';
        $verify = new \ReflectionMethod(Ocsp::class, 'verifySig');
        openssl_sign($data, $pkcs1, $priv, OPENSSL_ALGO_SHA256);
        $sha256Rsa = '1.2.840.113549.1.1.11';
        $this->assertTrue($verify->invoke(null, $sha256Rsa, $data, $pkcs1, $rsa));
        $this->assertFalse($verify->invoke(null, $sha256Rsa, $data, $pkcs1, $pss));
        $this->assertFalse($verify->invoke(null, $sha256Rsa, $data, self::pssSign($data, $priv), $pss));
    }

    /** The JWS RS256 and CRL paths share rsaPkcs1Verify: under an rsa-pss key neither a PKCS#1 nor a PSS signature passes as PKCS#1. */
    public function testPkcs1IsRefusedUnderAnRsaPssKey(): void
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        $priv = openssl_pkey_new(['config' => $cnf, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        unlink($cnf);
        $spki = base64_decode(preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details($priv)['key']));
        $body = hex2bin('300b06092a864886f70d01010a') . substr($spki, 4 + 15);
        $rsa = Common::loadPublicKey($spki);
        $pss = Common::loadPublicKey("\x30\x82" . pack('n', strlen($body)) . $body);
        $der = static function (int $tag, string $v): string {
            $n = strlen($v);
            return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
        };
        $alg = $der(0x30, hex2bin('06092a864886f70d01010b0500'));
        $tbs = $der(0x30, $alg . $der(0x30, '') . $der(0x17, '200101000000Z') . $der(0x17, '400101000000Z'));
        $crl = static fn(string $sig): string => $der(0x30, $tbs . $alg . $der(0x03, "\0" . $sig));
        openssl_sign($tbs, $pkcs1, $priv, OPENSSL_ALGO_SHA256);
        $pssSig = self::pssSign($tbs, $priv);
        $now = 1700000000000.0;
        $jws = new \ReflectionMethod(Gcp::class, 'verifyJwsSignature');
        $token = static fn(string $sig): array => ['header' => ['alg' => 'RS256'], 'signature' => $sig, 'signingInput' => $tbs];
        $refused = 'JWS RS256 signature does not verify';

        $this->assertTrue(Common::rsaPkcs1Verify($rsa, $pkcs1, $tbs, 'sha256'));
        $this->assertTrue(Intel::verifyCrl($crl($pkcs1), $rsa, $now)['ok']);
        $this->assertNull($jws->invoke(null, $token($pkcs1), $rsa));
        foreach ([$pkcs1, $pssSig] as $sig) {
            $this->assertFalse(Common::rsaPkcs1Verify($pss, $sig, $tbs, 'sha256'));
            $this->assertSame(['ok' => false, 'reason' => 'CRL signature does not verify under the issuer'], Intel::verifyCrl($crl($sig), $pss, $now));
            $this->assertStringStartsWith($refused, (string)$jws->invoke(null, $token($sig), $pss));
        }
    }

    /** EMSA-PSS (RFC 8017 9.1.1), SHA-256, 32-byte salt, 2048-bit modulus: ext-openssl cannot produce it. */
    private static function pssSign(string $data, \OpenSSLAsymmetricKey $priv): string
    {
        $salt = random_bytes(32);
        $h = hash('sha256', "\0\0\0\0\0\0\0\0" . hash('sha256', $data, true) . $salt, true);
        $db = str_repeat("\0", 256 - 32 - 32 - 2) . "\x01" . $salt;
        $mask = '';
        for ($c = 0; strlen($mask) < strlen($db); $c++) {
            $mask .= hash('sha256', $h . pack('N', $c), true);
        }
        $masked = $db ^ substr($mask, 0, strlen($db));
        $masked[0] = chr(ord($masked[0]) & 0x7F);
        openssl_private_encrypt($masked . $h . "\xBC", $sig, $priv, OPENSSL_NO_PADDING);
        return $sig;
    }

    // ---- OCSP SingleResponse strictness ---------------------------------------------------------------------------------------

    private static function der(int $tag, string $content = ''): string
    {
        $n = strlen($content);
        return chr($tag) . ($n < 128 ? chr($n) : ($n < 256 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $content;
    }

    private static function genTime(int $offsetSeconds): string
    {
        return self::der(0x18, gmdate('YmdHis', time() + $offsetSeconds) . 'Z');
    }

    /** A leaf, its CA, and a function signing an OCSPResponse under the CA over SingleResponses `[certStatus, extras, serial override]`. */
    private static function ocspFixture(): array
    {
        $caKey = self::ecKey();
        [$x5c, , $caPem] = self::leafAndPin(self::ecKey(), $caKey);
        $cert = new Cert(base64_decode($x5c[0]));
        $issuer = Cert::fromPem($caPem);
        $bits = (new \ReflectionMethod(Ocsp::class, 'spkiKeyBits'))->invoke(null, $issuer->spkiDer);
        $alg = self::der(0x30, hex2bin('0609608648016503040201') . self::der(0x05));
        $single = static fn(string $status, string $extras, ?string $serial = null): string => self::der(0x30,
            self::der(0x30, $alg . self::der(0x04, hash('sha256', $issuer->subjectDer, true)) . self::der(0x04, hash('sha256', $bits, true)) . self::der(0x02, $serial ?? $cert->serial))
            . $status . self::genTime(-3600) . $extras);
        $response = static function (array $singles) use ($caKey, $bits): string {
            $tbs = self::der(0x30, self::der(0xA2, self::der(0x04, sha1($bits, true))) . self::genTime(-60) . self::der(0x30, implode('', $singles)));
            openssl_sign($tbs, $sig, $caKey, OPENSSL_ALGO_SHA256);
            $basic = self::der(0x30, $tbs . self::der(0x30, hex2bin('06082a8648ce3d040302')) . self::der(0x03, "\0" . $sig));
            return self::der(0x30, self::der(0x0A, "\0") . self::der(0xA0, self::der(0x30, hex2bin('06092b0601050507300101') . self::der(0x04, $basic))));
        };
        return [static fn(array $singles): array => Ocsp::verifyResponse($response($singles), $cert, $issuer, [$cert, $issuer], time() * 1000.0), $single];
    }

    public function testOcspReadsASingleResponseStrictly(): void
    {
        [$verify, $single] = self::ocspFixture();
        $good = self::der(0x80);
        $future = self::der(0xA0, self::genTime(3600));
        $past = self::der(0xA0, self::genTime(-1800));
        $ext = self::der(0xA1, self::der(0x30));
        $bad = static fn(string $why): array => ['ok' => false, 'reason' => $why];
        $issuerOk = ['ok' => true, 'status' => 'good', 'responder' => 'issuer'];

        // certStatus: exact tags
        $this->assertSame($issuerOk, $verify([$single($good, '')]));
        $this->assertSame(array_replace($issuerOk, ['status' => 'unknown']), $verify([$single(self::der(0x82), '')]));
        $this->assertSame(array_replace($issuerOk, ['status' => 'revoked']), $verify([$single(self::der(0xA1, self::genTime(-7200)), '')]));
        foreach ([0xA0, 0xA2, 0x81, 0x40, 0x02] as $tag) {
            $this->assertSame($bad('malformed certStatus'), $verify([$single(self::der($tag), '')]), dechex($tag));
        }
        $this->assertSame($bad('unrecognised certStatus'), $verify([$single(self::der(0x83), '')]));
        $this->assertSame($bad('malformed revoked certStatus'), $verify([$single(self::der(0xA1), '')]));

        // after thisUpdate: an optional [0], then an optional [1], nothing else
        foreach (['' => '', 'next' => $future, 'ext' => $ext, 'next+ext' => $future . $ext] as $name => $extras) {
            $this->assertSame($issuerOk, $verify([$single($good, $extras)]), "accepted $name");
        }
        $this->assertSame($bad('response is stale (past nextUpdate)'), $verify([$single($good, $past)]));
        $rejected = $bad('OCSP response rejected: SingleResponse is malformed');
        foreach (['past under [2]' => self::der(0xA2, self::genTime(-1800)), 'ext+next' => $ext . $future, 'next twice' => $future . $future,
            'ext twice' => $ext . $ext, 'three' => $future . $ext . $ext, 'junk' => self::der(0x05)] as $name => $extras) {
            $this->assertSame($rejected, $verify([$single($good, $extras)]), $name);
        }
        // every SingleResponse, matching or not
        $this->assertSame($rejected, $verify([$single($good, ''), $single($good, self::der(0xA2), "\x7F")]));
        $this->assertSame($issuerOk, $verify([$single($good, ''), $single($good, '', "\x7F")]));

        // nextUpdate holds exactly one GeneralizedTime
        $nextBad = $bad('OCSP response rejected: nextUpdate is malformed');
        foreach ([self::der(0xA0), self::der(0xA0, self::genTime(3600) . self::genTime(3600)), self::der(0xA0, self::der(0x17, '500101000000Z'))] as $i => $next) {
            $this->assertSame($nextBad, $verify([$single($good, $next)]), "next $i");
        }
    }

    // ---- real Intel collateral ------------------------------------------------------------------------------------------------

    /** A copy of the real TDX vector row with `$edit` applied to its collateral member / policy. */
    private static function intelRow(?string $member = null, ?string $name = null, mixed $floor = null): Obj
    {
        $row = Json::parseLax(Json::canonicalizeLenient(Vectors::realTdxRow()));
        if ($member !== null) {
            $c = $row->get('evidence')->get('collateral');
            $t = str_replace(',"signature":', ",\"$name\":{},\"signature\":", $c->get($member), $count);
            self::assertSame(1, $count);
            $c->set($member, $t);
        }
        if ($floor !== null) {
            $row->get('config')->get('policy')->set('collateral', Obj::of(['minTcbEvaluationDataNumber' => $floor]));
        }
        return $row;
    }

    public function testRealCollateralIgnoresALaterDuplicateMember(): void
    {
        $honest = Factory::runAttestationVector(self::intelRow());
        $this->assertTrue($honest['ok']);
        $this->assertEquals($honest, Factory::runAttestationVector(self::intelRow('tcbInfoJson', 'tcbInfo')));
        $this->assertEquals($honest, Factory::runAttestationVector(self::intelRow('qeIdentityJson', 'enclaveIdentity')));
    }

    public function testTheEvaluationNumberFloorCoercesLikeTheReference(): void
    {
        foreach (['999999', new Num('999999')] as $i => $floor) {
            $r = Factory::runAttestationVector(self::intelRow(floor: $floor));
            $this->assertFalse($r['ok'], "floor $i");
            $this->assertStringContainsString('tcbEvaluationDataNumber below policy minimum', $r['reason'], "floor $i");
        }
        foreach (['1', true, 'abc'] as $i => $floor) { // 1 and true are below the real number; "abc" is NaN, and NaN refuses nothing in the reference
            $this->assertTrue(Factory::runAttestationVector(self::intelRow(floor: $floor))['ok'], "low floor $i");
        }
    }
}
