<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Gcp;
use Atlas\Pca\Attest\PubKey;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for Attest/Gcp.php (Google Confidential Space). Expectations follow packages/pca/src/attest-gcp-confidential-space.ts.
 * Keys and certificates are generated at load (P-256 / P-384 / RSA) and the certificates are built and signed by hand. The helpers
 * are public static so the Maa kill test shares them.
 */
final class K05KillAttestGcp1Test extends TestCase
{
    public const ISS = 'https://confidentialcomputing.googleapis.com';
    public const N = 1_800_000_000;           // "now" in seconds (Jan 2027)
    public const NOW = 1_800_000_000_000;      // and in ms
    public const NB = 1735689600;              // 2025-01-01T00:00:00Z
    public const NA = 2051222400;              // 2035-01-01T00:00:00Z
    private const GONE = "\0gone";

    // ------------------------------------------------------------------------------------------------------------- fixtures

    public static function key(string $name): \OpenSSLAsymmetricKey
    {
        static $keys = [];
        if (!isset($keys[$name])) {
            $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
            file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
            $o = ['config' => $cnf, 'private_key_bits' => 2048];
            if ($name === 'rsa') {
                $o['private_key_type'] = OPENSSL_KEYTYPE_RSA;
            } else {
                $o['private_key_type'] = OPENSSL_KEYTYPE_EC;
                $o['curve_name'] = $name === 'p384' ? 'secp384r1' : 'prime256v1';
            }
            $keys[$name] = openssl_pkey_new($o);
            unlink($cnf);
        }
        return $keys[$name];
    }

    public static function spki(\OpenSSLAsymmetricKey $k): string
    {
        return (string)base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details($k)['key']));
    }

    public static function spkiHex(\OpenSSLAsymmetricKey $k): string
    {
        return hash('sha256', self::spki($k));
    }

    public static function pub(\OpenSSLAsymmetricKey $k): PubKey
    {
        return Common::loadPublicKey(self::spki($k));
    }

    public static function b64u(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    /** @return array<string,string> */
    public static function jwk(\OpenSSLAsymmetricKey $k, ?string $kid = null): array
    {
        $ec = openssl_pkey_get_details($k)['ec'];
        $j = ['kty' => 'EC', 'crv' => 'P-256', 'x' => self::b64u(str_pad($ec['x'], 32, "\0", STR_PAD_LEFT)), 'y' => self::b64u(str_pad($ec['y'], 32, "\0", STR_PAD_LEFT))];
        return $kid === null ? $j : ['kid' => $kid] + $j;
    }

    public static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    public static function dn(string $cn): string
    {
        return self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, self::tlv(0x06, "\x55\x04\x03"), self::tlv(0x0C, $cn))));
    }

    public static function bcCa(): string
    {
        return self::tlv(0x30, self::tlv(0x06, "\x55\x1d\x13"), self::tlv(0x04, self::tlv(0x30, self::tlv(0x01, "\xff"))));
    }

    /** @param list<string> $exts */
    public static function cert(string $issuerCn, string $subjectCn, \OpenSSLAsymmetricKey $subject, \OpenSSLAsymmetricKey $signer, array $exts = [], int $nb = self::NB, int $na = self::NA, string $serial = "\x01"): string
    {
        $alg = self::tlv(0x30, self::tlv(0x06, "\x2a\x86\x48\xce\x3d\x04\x03\x02"));
        $val = self::tlv(0x30, self::tlv(0x17, gmdate('ymdHis', $nb) . 'Z'), self::tlv(0x17, gmdate('ymdHis', $na) . 'Z'));
        $e = $exts === [] ? [] : [self::tlv(0xa3, self::tlv(0x30, ...$exts))];
        $tbs = self::tlv(0x30, self::tlv(0xa0, self::tlv(0x02, "\x02")), self::tlv(0x02, $serial), $alg, self::dn($issuerCn), $val, self::dn($subjectCn), self::spki($subject), ...$e);
        openssl_sign($tbs, $sig, $signer, OPENSSL_ALGO_SHA256);
        return self::tlv(0x30, $tbs, $alg, self::tlv(0x03, "\0" . $sig));
    }

    public static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    public static function spkiPem(\OpenSSLAsymmetricKey $k): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode(self::spki($k)), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** ES256 raw r||s from an openssl DER signature. */
    private static function rawSig(string $der): string
    {
        $o = 2;
        $rl = ord($der[$o + 1]);
        $r = substr($der, $o + 2, $rl);
        $o += 2 + $rl;
        $sl = ord($der[$o + 1]);
        $s = substr($der, $o + 2, $sl);
        return str_pad(ltrim($r, "\0"), 32, "\0", STR_PAD_LEFT) . str_pad(ltrim($s, "\0"), 32, "\0", STR_PAD_LEFT);
    }

    /** @param array<string,mixed> $header @param array<string,mixed> $payload */
    public static function token(array $header, array $payload, \OpenSSLAsymmetricKey $signer): string
    {
        $si = self::b64u((string)json_encode($header)) . '.' . self::b64u((string)json_encode($payload));
        openssl_sign($si, $sig, $signer, OPENSSL_ALGO_SHA256);
        return $si . '.' . self::b64u(self::rawSig($sig));
    }

    /** @return array{holderPub:string,grantRef:string,epoch:int,nonce:string} */
    public static function expected(): array
    {
        return ['holderPub' => 'h', 'grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n'];
    }

    private static function call(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Gcp::class, $m))->invoke(null, ...$a);
    }

    // ------------------------------------------------------------------------------------------------------------- the verifier harness

    /**
     * @param array<string,mixed> $payload overrides (value GONE removes the claim)
     * @param array<string,mixed> $policy overrides @param array<string,mixed> $cfg overrides
     * @return array<string,mixed>
     */
    private function runCase(array $payload = [], array $policy = [], array $cfg = [], mixed $now = self::NOW, array $header = [], bool $withExpected = true): array
    {
        $base = [
            'iss' => self::ISS, 'exp' => self::N + 600, 'swname' => 'CONFIDENTIAL_SPACE', 'hwmodel' => 'GCP_AMD_SEV_SNP', 'dbgstat' => 'disabled-since-boot',
            'eat_nonce' => bin2hex(Common::attestationBinding(self::expected())),
            'submods' => ['confidential_space' => new \stdClass(), 'container' => ['image_digest' => 'sha256:abc']],
        ];
        $p = array_replace($base, $payload);
        foreach ($p as $k => $v) {
            if ($v === self::GONE) {
                unset($p[$k]);
            }
        }
        $tok = self::token($header + ['alg' => 'ES256'], $p, self::key('sig'));
        return $this->runToken($tok, $policy, $cfg, $now, $withExpected);
    }

    /** @return array<string,mixed> */
    private function runToken(string $tok, array $policy = [], array $cfg = [], mixed $now = self::NOW, bool $withExpected = true): array
    {
        $config = array_replace([
            'trustedIssuers' => [self::ISS], 'trustAnchors' => ['trustedKeySpki' => [self::spkiHex(self::key('sig'))]],
            'policy' => array_replace(['imageDigests' => ['sha256:abc']], $policy),
        ], $cfg);
        $ev = ['token' => $tok, 'jwks' => ['keys' => [self::jwk(self::key('sig'))]]];
        $v = new Gcp($config, static fn($d) => $ev);
        return $v->verify(null, $withExpected ? self::expected() : null, $now);
    }

    private function reason(array $r): string
    {
        $this->assertFalse($r['ok']);
        return $r['reason'];
    }

    public function testTheHarnessAcceptsAGoodToken(): void
    {
        $this->assertSame([
            'ok' => true, 'bound' => true,
            'measured' => ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => 'sha256:abc', 'operator' => ''],
            'hostAsserted' => ['attestation_type' => 'sev-snp', 'hwmodel' => 'GCP_AMD_SEV_SNP', 'image_digest' => 'sha256:abc'],
        ], $this->runCase());
        $r = $this->runCase(['submods' => ['confidential_space' => new \stdClass(), 'container' => ['image_digest' => 'sha256:abc', 'image_reference' => 'r/i:1']]]);
        $this->assertSame(['attestation_type' => 'sev-snp', 'hwmodel' => 'GCP_AMD_SEV_SNP', 'image_digest' => 'sha256:abc', 'image_reference' => 'r/i:1'], $r['hostAsserted']);
    }

    // ------------------------------------------------------------------------------------------------------------- teeTypeOfHwmodel

    public function testTeeTypeOfHwmodel(): void
    {
        foreach (['GCP_AMD_SEV' => 'sev-snp', 'GCP_AMD_SEV_SNP' => 'sev-snp', 'GCP_AMD_SEV_ES' => 'sev-snp', 'GCP_INTEL_TDX' => 'tdx',
                  'gcp_amd_sev_snp' => 'sev-snp', 'Gcp_Amd_Sev' => 'sev-snp', 'gcp_intel_tdx' => 'tdx', 'Gcp_Intel_Tdx_2' => 'tdx', 'GCP_AMD_SEVX' => 'sev-snp'] as $m => $want) {
            $this->assertSame($want, Gcp::teeTypeOfHwmodel((string)$m), (string)$m);
        }
        foreach (['', 'GCP_INTEL', 'GCP_AMD', 'xGCP_AMD_SEV', 'AMD_SEV', 'GCP_ARM'] as $m) {
            $this->assertNull(Gcp::teeTypeOfHwmodel($m), $m);
        }
    }

    // ------------------------------------------------------------------------------------------------------------- keyFromJwk

    public function testKeyFromJwk(): void
    {
        $none = ['reason' => 'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate'];
        $s = self::jwk(self::key('sig'));
        $good = self::call('keyFromJwk', $s);
        $this->assertSame(['key'], array_keys($good));
        $this->assertSame(self::spki(self::key('sig')), $good['key']->spki);
        // a key that is only an RSA n or only an e is not an RSA key
        $this->assertSame($none, self::call('keyFromJwk', ['kid' => 'k', 'n' => 'AQAB']));
        $this->assertSame($none, self::call('keyFromJwk', ['kid' => 'k', 'e' => 'AQAB']));
        // EC needs kty, crv, x and y together
        $this->assertSame($none, self::call('keyFromJwk', ['x' => 'AA', 'y' => 'AA']));
        $this->assertSame($none, self::call('keyFromJwk', ['crv' => 'P-256', 'x' => $s['x'], 'y' => $s['y']]));
        $this->assertSame($none, self::call('keyFromJwk', ['y' => 'AA']));
        $this->assertSame($none, self::call('keyFromJwk', ['kty' => 'EC', 'crv' => 'P-256', 'x' => $s['x']]));
        // an empty x5c is no certificate
        $this->assertSame($none, self::call('keyFromJwk', ['kid' => 'k', 'x5c' => []]));
        $this->assertSame($none, self::call('keyFromJwk', ['kid' => 'k']));
        // a curve outside P-256 / P-384 / P-521 (the message is this SDK's own; Node reports its OpenSSL text)
        $this->assertSame(['reason' => 'JWKS key is not a usable public key: unsupported curve P-192'], self::call('keyFromJwk', ['kty' => 'EC', 'crv' => 'P-192', 'x' => 'AA', 'y' => 'AA']));
        // a certificate that does not parse: the reason is the prefix followed by the parser's message
        try {
            new Cert(Common::nodeB64Decode('AAAA'));
            $this->fail('parsed');
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
        }
        $this->assertNotSame('', $msg);
        $this->assertSame(['reason' => 'JWKS key is not a usable public key: ' . $msg], self::call('keyFromJwk', ['x5c' => ['AAAA']]));
        // a P-384 key is accepted by the EC branch
        $k = self::key('p384');
        $ec = openssl_pkey_get_details($k)['ec'];
        $r = self::call('keyFromJwk', ['kty' => 'EC', 'crv' => 'P-384', 'x' => self::b64u(str_pad($ec['x'], 48, "\0", STR_PAD_LEFT)), 'y' => self::b64u(str_pad($ec['y'], 48, "\0", STR_PAD_LEFT))]);
        $this->assertSame(self::spki($k), $r['key']->spki);
    }

    // ------------------------------------------------------------------------------------------------------------- verifyJwkX5cChain

    public function testJwkX5cChainShapes(): void
    {
        $S = self::key('sig');
        $R = self::key('root');
        $anchors = ['trustedKeySpki' => [self::spkiHex($S)]];
        $good = base64_encode(self::cert('root', 'sig', $S, $R));
        foreach (['abc', [], 5, null] as $bad) {
            $this->assertSame('empty x5c certificate chain', Gcp::verifyJwkX5cChain($bad, $anchors, (float)self::NOW, 0.0), json_encode($bad));
        }
        $this->assertSame('empty x5c entry at index 0', Gcp::verifyJwkX5cChain([5], $anchors, (float)self::NOW, 0.0));
        $this->assertSame('empty x5c entry at index 0', Gcp::verifyJwkX5cChain([''], $anchors, (float)self::NOW, 0.0));
        $this->assertSame('empty x5c entry at index 1', Gcp::verifyJwkX5cChain([$good, ''], $anchors, (float)self::NOW, 0.0));
        $this->assertSame('empty x5c entry at index 1', Gcp::verifyJwkX5cChain([$good, 7], $anchors, (float)self::NOW, 0.0));
        foreach (['AAAA' => 0, 'MIIB' => 0] as $junk => $i) {
            try {
                new Cert(Common::nodeB64Decode($junk));
                $this->fail('parsed');
            } catch (\Throwable $e) {
                $msg = $e->getMessage();
            }
            $this->assertSame("malformed x5c certificate at index 0: $msg", Gcp::verifyJwkX5cChain([$junk], $anchors, (float)self::NOW, 0.0));
            $this->assertSame("malformed x5c certificate at index 1: $msg", Gcp::verifyJwkX5cChain([$good, $junk], $anchors, (float)self::NOW, 0.0));
        }
        $this->assertSame('x5c certificate at index 0 is outside its validity window', Gcp::verifyJwkX5cChain([$good], $anchors, (float)(self::NA * 1000 + 1), 0.0));
        $short = base64_encode(self::cert('root', 'x', $S, $R, [], self::NB, self::NB + 10));
        $this->assertSame('x5c certificate at index 1 is outside its validity window', Gcp::verifyJwkX5cChain([$good, $short], $anchors, (float)self::NOW, 0.0));
        $this->assertNull(Gcp::verifyJwkX5cChain([$good], $anchors, (float)(self::NA * 1000), 0.0));
    }

    public function testJwkX5cChainChecksEveryLink(): void
    {
        $A = self::key('sig');
        $B = self::key('top');
        $R = self::key('root');
        // A's certificate is signed by R, not by B: the link between them is broken
        $chain = [base64_encode(self::cert('top', 'a', $A, $R)), base64_encode(self::cert('top', 'top', $B, $B, [self::bcCa()]))];
        $this->assertSame('x5c link 0 is not signed by the certificate above it', Gcp::verifyJwkX5cChain($chain, ['trustedKeySpki' => [self::spkiHex($B)]], (float)self::NOW, 0.0));
        // the second link of three
        $L = self::key('leaf');
        $three = [base64_encode(self::cert('a', 'l', $L, $A)), base64_encode(self::cert('top', 'a', $A, $R, [self::bcCa()])), base64_encode(self::cert('top', 'top', $B, $B, [self::bcCa()]))];
        $this->assertSame('x5c link 1 is not signed by the certificate above it', Gcp::verifyJwkX5cChain($three, ['trustedKeySpki' => [self::spkiHex($B)]], (float)self::NOW, 0.0));
        // a well linked pair verifies against a pin of the top key
        $ok = [base64_encode(self::cert('top', 'a', $A, $B)), base64_encode(self::cert('top', 'top', $B, $B, [self::bcCa()]))];
        $this->assertNull(Gcp::verifyJwkX5cChain($ok, ['trustedKeySpki' => [strtoupper(self::spkiHex($B))]], (float)self::NOW, 0.0));
        $this->assertSame('x5c chain does not anchor in a configured GCP trust root', Gcp::verifyJwkX5cChain($ok, ['trustedKeySpki' => [self::spkiHex($R)]], (float)self::NOW, 0.0));
    }

    public function testJwkX5cChainRoots(): void
    {
        $T = self::key('top');
        $R = self::key('root');
        $O = self::key('other');
        $chain = [base64_encode(self::cert('root', 'top', $T, $R))];
        $noAnchor = 'x5c chain does not anchor in a configured GCP trust root';
        $rootPem = self::pem(self::cert('root', 'root', $R, $R));
        $this->assertNull(Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [$rootPem]], (float)self::NOW, 0.0));
        // a bare public key (SPKI PEM) is a root too, after an entry that is neither
        $this->assertNull(Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => ['garbage', self::spkiPem($R)]], (float)self::NOW, 0.0));
        $this->assertNull(Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [self::spkiPem($R)]], (float)self::NOW, 0.0));
        // an SPKI PEM of another key does not anchor; entries that are no PEM at all are skipped
        $this->assertSame($noAnchor, Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [self::spkiPem($O)]], (float)self::NOW, 0.0));
        $this->assertSame($noAnchor, Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => ['garbage', 5, 'x']], (float)self::NOW, 0.0));
        $this->assertSame($noAnchor, Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [5, self::spkiPem($O)]], (float)self::NOW, 0.0));
        $this->assertSame($noAnchor, Gcp::verifyJwkX5cChain($chain, [], (float)self::NOW, 0.0));
        $this->assertSame($noAnchor, Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [self::pem(self::cert('o', 'o', $O, $O))]], (float)self::NOW, 0.0));
    }

    // ------------------------------------------------------------------------------------------------------------- resolveTrustedSigningKey

    /** @return array<string,mixed> */
    private static function res(array $header, mixed $jwks, mixed $anchors): array
    {
        return self::call('resolveTrustedSigningKey', $header, $jwks, $anchors, (float)self::NOW, 0.0);
    }

    public function testASigningKeyFromTheHeaderChain(): void
    {
        $S = self::key('sig');
        $R = self::key('root');
        $x5c = [base64_encode(self::cert('root', 'sig', $S, $R))];
        $pin = ['trustedKeySpki' => [self::spkiHex($S)]];
        // with a kid, without one: the header chain's leaf is the key (and its pin makes it trusted)
        foreach ([['alg' => 'ES256', 'kid' => 'k', 'x5c' => $x5c], ['alg' => 'ES256', 'x5c' => $x5c]] as $h) {
            $r = self::res($h, null, $pin);
            $this->assertSame(['key'], array_keys($r));
            $this->assertSame(self::spki($S), $r['key']->spki);
        }
        // an empty header chain is no chain
        $this->assertSame(['reason' => "no JWKS key matches the token kid 'k' (untrusted signer)"], self::res(['alg' => 'ES256', 'kid' => 'k', 'x5c' => []], null, $pin));
        $this->assertSame(['reason' => 'no kid on the token and no unambiguous single signing key available'], self::res(['alg' => 'ES256', 'x5c' => []], null, $pin));
        $this->assertSame(['reason' => "no JWKS key matches the token kid 'k' (untrusted signer)"], self::res(['alg' => 'ES256', 'kid' => 'k'], null, $pin));
        $this->assertSame(['reason' => 'no kid on the token and no unambiguous single signing key available'], self::res(['alg' => 'ES256'], null, $pin));
        // a JWKS key that is found wins over the header chain (which would be another key)
        $rootCert = [base64_encode(self::cert('root', 'root', $R, $R))];
        $r = self::res(['alg' => 'ES256', 'kid' => 'k', 'x5c' => $rootCert], ['keys' => [self::jwk($S, 'k')]], $pin);
        $this->assertSame(self::spki($S), $r['key']->spki);
        $r = self::res(['alg' => 'ES256', 'x5c' => $rootCert], ['keys' => [self::jwk($S)]], $pin);
        $this->assertSame(self::spki($S), $r['key']->spki);
    }

    public function testAHeaderChainKeyIsNotTrustedByTheTrustedJwksLookup(): void
    {
        $S = self::key('sig');
        $R = self::key('root');
        $x5c = [base64_encode(self::cert('root', 'sig', $S, $R))];
        $notAnchored = ['reason' => 'signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)'];
        $trustedOther = ['trustedJwks' => ['keys' => [self::jwk($R, 'other')]]];
        // nothing trusts the chain's leaf and no root / pin is configured to check the chain against
        $this->assertSame($notAnchored, self::res(['alg' => 'ES256', 'kid' => 'k', 'x5c' => $x5c], null, $trustedOther));
        $this->assertSame($notAnchored, self::res(['alg' => 'ES256', 'kid' => 'k', 'x5c' => $x5c], null, $trustedOther + ['rootCertsPem' => []]));
        $two = ['trustedJwks' => ['keys' => [self::jwk($R, 'a'), self::jwk(self::key('other'), 'b')]], 'trustedKeySpki' => []];
        $this->assertSame($notAnchored, self::res(['alg' => 'ES256', 'x5c' => $x5c], null, $two));
        // a trusted JWK that is the key itself trusts it
        $r = self::res(['alg' => 'ES256', 'kid' => 'k'], null, ['trustedJwks' => ['keys' => [self::jwk($S, 'k')]]]);
        $this->assertSame(self::spki($S), $r['key']->spki);
        $r = self::res(['alg' => 'ES256'], null, ['trustedJwks' => ['keys' => [self::jwk($S)]]]);
        $this->assertSame(self::spki($S), $r['key']->spki);
        // an empty x5c on a key with coordinates is not a chain to check
        $withEmpty = self::jwk($S, 'k') + ['x5c' => []];
        $this->assertSame($notAnchored, self::res(['alg' => 'ES256', 'kid' => 'k'], ['keys' => [$withEmpty]], ['rootCertsPem' => ['x']]));
        $this->assertSame($notAnchored, self::res(['alg' => 'ES256', 'kid' => 'k'], ['keys' => [$withEmpty]], $trustedOther));
    }

    public function testAJwksKeyThatIsNotAnObjectIsAnEmptyKey(): void
    {
        $this->assertSame(['reason' => 'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate'], self::res(['alg' => 'ES256'], ['keys' => [null]], ['trustedKeySpki' => ['aa']]));
        $this->assertSame(['reason' => 'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate'], self::res(['alg' => 'ES256'], ['keys' => ['str']], ['trustedKeySpki' => ['aa']]));
        $this->assertSame(['reason' => 'no kid on the token and no unambiguous single signing key available'], self::res(['alg' => 'ES256'], ['keys' => [null, null]], ['trustedKeySpki' => ['aa']]));
    }

    public function testAnUnusableTrustedJwkIsSkippedAndTheNextOneUsed(): void
    {
        $S = self::key('sig');
        $anchors = ['trustedJwks' => ['keys' => [['kid' => 'bad'], self::jwk($S, 'good')]]];
        $r = self::res(['alg' => 'ES256', 'kid' => 'k'], ['keys' => [self::jwk($S, 'k')]], $anchors);
        $this->assertSame(self::spki($S), $r['key']->spki);
        // an evidence JWK that is not usable is reported, not skipped
        $this->assertSame(['reason' => 'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate'], self::res(['alg' => 'ES256', 'kid' => 'k'], ['keys' => [['kid' => 'k']]], $anchors));
    }

    public function testAnX5cLeafMustBeAnchoredAndBeTheJwkKey(): void
    {
        $S = self::key('sig');
        $R = self::key('root');
        $O = self::key('other');
        $rootPem = self::pem(self::cert('root', 'root', $R, $R));
        $viaRoot = ['kid' => 'k', 'x5c' => [base64_encode(self::cert('root', 'sig', $S, $R))]];
        // roots and pins both configured (the pin is another key): the chain is checked against the root
        $r = self::res(['alg' => 'ES256', 'kid' => 'k'], ['keys' => [$viaRoot]], ['rootCertsPem' => [$rootPem], 'trustedKeySpki' => [str_repeat('0', 64)]]);
        $this->assertSame(self::spki($S), $r['key']->spki);
        $r = self::res(['alg' => 'ES256', 'kid' => 'k'], ['keys' => [$viaRoot]], ['rootCertsPem' => [$rootPem]]);
        $this->assertSame(self::spki($S), $r['key']->spki);
        // a chain the root did not sign
        $viaOther = ['kid' => 'k', 'x5c' => [base64_encode(self::cert('o', 'sig', $S, $O))]];
        $this->assertSame(['reason' => 'signing key not trusted: x5c chain does not anchor in a configured GCP trust root'], self::res(['alg' => 'ES256', 'kid' => 'k'], ['keys' => [$viaOther]], ['rootCertsPem' => [$rootPem]]));
        // a key with coordinates beside a genuine chain of another key
        $borrowed = $viaRoot + self::jwk($O);
        $this->assertSame(['reason' => 'signing key not trusted: the JWK key is not the key of its x5c leaf'], self::res(['alg' => 'ES256', 'kid' => 'k'], ['keys' => [$borrowed]], ['rootCertsPem' => [$rootPem]]));
    }

    // ------------------------------------------------------------------------------------------------------------- JWS signature / nonce helpers

    public function testEs256NeedsAnEcP256Key(): void
    {
        $parsed = ['header' => ['alg' => 'ES256'], 'signature' => str_repeat("\x01", 64), 'signingInput' => 'x'];
        $this->assertSame('ES256 token but signing key is EC/P-384 (not EC P-256)', self::call('verifyJwsSignature', $parsed, self::pub(self::key('p384'))));
        $this->assertSame('ES256 token but signing key is RSA/undefined (not EC P-256)', self::call('verifyJwsSignature', $parsed, self::pub(self::key('rsa'))));
        $short = ['signature' => str_repeat("\x01", 63)] + $parsed;
        $this->assertSame('ES256 signature is 63 bytes (expected 64: r‖s)', self::call('verifyJwsSignature', $short, self::pub(self::key('sig'))));
        $this->assertSame('JWS ES256 signature does not verify under the Confidential Space signing key', self::call('verifyJwsSignature', $parsed, self::pub(self::key('sig'))));
        $this->assertSame('RS256 token but signing key is EC (not RSA)', self::call('verifyJwsSignature', ['header' => ['alg' => 'RS256']] + $parsed, self::pub(self::key('sig'))));
    }

    public function testNonceCandidatesDropEmptyStringsAndKeepAList(): void
    {
        $this->assertSame(['a'], self::call('nonceCandidates', ['', 'a']));
        $this->assertSame(['a'], self::call('nonceCandidates', ['a', '']));
        $this->assertSame(['b'], self::call('nonceCandidates', ['', '', 'b']));
        $this->assertSame(['a', 'b'], self::call('nonceCandidates', ['a', 'b']));
        $this->assertSame(['x'], self::call('nonceCandidates', 'x'));
        $this->assertSame([], self::call('nonceCandidates', ''));
        $this->assertSame([], self::call('nonceCandidates', 5));
        $this->assertSame([], self::call('nonceCandidates', ['a', 5]));
        $this->assertSame([], self::call('nonceCandidates', null));
    }

    // ------------------------------------------------------------------------------------------------------------- the constructor

    /** @return array<string,mixed> */
    private static function cfg(array $o = []): array
    {
        return array_replace(['trustedIssuers' => [self::ISS], 'trustAnchors' => ['trustedKeySpki' => ['aa']], 'policy' => ['imageDigests' => ['sha256:abc']]], $o);
    }

    private function refuses(array $cfg, string $why): void
    {
        try {
            new Gcp($cfg, static fn($d) => null);
            $this->fail("built from $why");
        } catch (AttestConstructError $e) {
            $this->assertSame($why, $e->getMessage());
        }
    }

    public function testEveryTrustedIssuerMustBeANonEmptyString(): void
    {
        $why = 'createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string';
        $this->refuses(self::cfg(['trustedIssuers' => [5]]), $why);
        $this->refuses(self::cfg(['trustedIssuers' => ['']]), $why);
        $this->refuses(self::cfg(['trustedIssuers' => [self::ISS, 5]]), $why);
        $this->refuses(self::cfg(['trustedIssuers' => [self::ISS, '']]), $why);
        $this->assertInstanceOf(Gcp::class, new Gcp(self::cfg(), static fn($d) => null));
    }

    public function testTheAnchorCountAddsKeysPinsAndRoots(): void
    {
        $f = static fn($d) => null;
        $this->assertInstanceOf(Gcp::class, new Gcp(self::cfg(['trustAnchors' => ['trustedKeySpki' => ['aa'], 'rootCertsPem' => ['x']]]), $f));
        $this->assertInstanceOf(Gcp::class, new Gcp(self::cfg(['trustAnchors' => ['trustedJwks' => ['keys' => [['kid' => 'a']]], 'trustedKeySpki' => ['aa']]]), $f));
        $this->assertInstanceOf(Gcp::class, new Gcp(self::cfg(['trustAnchors' => ['trustedJwks' => ['keys' => 'x'], 'trustedKeySpki' => ['aa']]]), $f));
        $this->assertInstanceOf(Gcp::class, new Gcp(self::cfg(['trustAnchors' => ['trustedJwks' => ['foo' => 1], 'rootCertsPem' => ['x']]]), $f));
        $this->assertInstanceOf(Gcp::class, new Gcp(self::cfg(['trustAnchors' => ['trustedJwks' => ['keys' => [['kid' => 'a']]]]]), $f));
        $why = 'createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted';
        $this->refuses(self::cfg(['trustAnchors' => ['trustedJwks' => ['keys' => []]]]), $why);
        $this->refuses(self::cfg(['trustAnchors' => ['trustedJwks' => ['keys' => 'x']]]), $why);
    }

    public function testThePolicyNeedsANonEmptyImageAllowlist(): void
    {
        $why = 'createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)';
        $this->refuses(self::cfg(['policy' => ['x' => 1]]), $why);
        $this->refuses(self::cfg(['policy' => ['imageDigests' => 'abc']]), $why);
        $this->refuses(self::cfg(['policy' => ['imageDigests' => []]]), $why);
        $this->refuses(self::cfg(['policy' => null]), $why);
        $this->refuses(self::cfg(['policy' => ['imageDigests' => ['a'], 'allowedTeeTypes' => []]]), 'createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty');
    }

    // ------------------------------------------------------------------------------------------------------------- the verifier

    public function testNoUsableTokenIsRefused(): void
    {
        $no = 'no GCP Confidential Space token for this action';
        foreach ([[], ['token' => 5], ['token' => ''], ['token' => null], null, 'x'] as $ev) {
            $v = new Gcp(self::cfg(), static fn($d) => $ev);
            $this->assertSame(['ok' => false, 'reason' => $no], $v->verify(null, self::expected(), self::NOW), json_encode($ev));
        }
    }

    public function testAnUnsupportedAlgIsRefusedBeforeAnyKeyLookup(): void
    {
        $si = self::b64u('{"alg":"HS256"}') . '.' . self::b64u('{"iss":"x"}');
        $tok = $si . '.' . self::b64u('sig');
        $cfg = self::cfg(['trustAnchors' => ['trustedKeySpki' => [str_repeat('0', 64)]]]);
        $v = new Gcp($cfg, static fn($d) => ['token' => $tok]);
        $this->assertSame(['ok' => false, 'reason' => "unsupported JWS alg 'HS256' (Confidential Space uses RS256)"], $v->verify(null, self::expected(), self::NOW));
    }

    public function testAMissingClockStillVerifies(): void
    {
        $this->assertTrue($this->runCase([], [], [], null)['ok']);
    }

    public function testTheTimeWindowAtItsEdges(): void
    {
        $N = self::N;
        $exp = 'Confidential Space token expired';
        // [clockSkewMs, exp, ok]
        foreach ([[0, $N, true], [0, $N - 1, false], [-5, $N - 1, false], [1000, $N - 1, true], [1000, $N - 2, false], [1001, $N - 2, true], [1001, $N - 3, false],
                  [1, $N - 1, true], [1, $N - 2, false], [400, $N - 1, true], [400, $N - 2, false], [1500, $N - 2, true], [1500, $N - 3, false]] as [$skew, $e, $ok]) {
            $r = $this->runCase(['exp' => $e], [], ['clockSkewMs' => $skew]);
            $this->assertSame($ok, $r['ok'], "skew $skew exp " . ($e - $N));
            if (!$ok) {
                $this->assertSame($exp, $r['reason'], "skew $skew exp " . ($e - $N));
            }
        }
        // a clock with a fraction of a second: the second is the floor
        $this->assertTrue($this->runCase(['exp' => $N], [], [], self::NOW + 600)['ok']);
        $this->assertSame($exp, $this->reason($this->runCase(['exp' => $N - 1], [], [], self::NOW + 600)));
        $this->assertTrue($this->runCase(['exp' => $N], [], [], self::NOW + 999)['ok']);
        // nbf and iat may lead the clock by the skew, no more
        $this->assertTrue($this->runCase(['nbf' => $N + 1], [], ['clockSkewMs' => 1000])['ok']);
        $this->assertSame('Confidential Space token not yet valid (nbf)', $this->reason($this->runCase(['nbf' => $N + 2], [], ['clockSkewMs' => 1000])));
        $this->assertTrue($this->runCase(['iat' => $N + 1], [], ['clockSkewMs' => 1000])['ok']);
        $this->assertSame('Confidential Space token issued in the future (iat)', $this->reason($this->runCase(['iat' => $N + 2], [], ['clockSkewMs' => 1000])));
        $this->assertTrue($this->runCase(['nbf' => $N, 'iat' => $N])['ok']);
        $this->assertSame('Confidential Space token not yet valid (nbf)', $this->reason($this->runCase(['nbf' => $N + 1])));
        $this->assertSame('Confidential Space token issued in the future (iat)', $this->reason($this->runCase(['iat' => $N + 1])));
        $this->assertSame('token has no exp (cannot bound validity — fail closed)', $this->reason($this->runCase(['exp' => self::GONE])));
    }

    public function testTheSubmodsClaimsMustBeObjects(): void
    {
        $no = 'token carries no submods.confidential_space (not a Confidential Space token)';
        $this->assertSame($no, $this->reason($this->runCase(['submods' => 'abc'])));
        $this->assertSame($no, $this->reason($this->runCase(['submods' => [1, 2]])));
        $this->assertSame($no, $this->reason($this->runCase(['submods' => self::GONE])));
        $this->assertSame($no, $this->reason($this->runCase(['submods' => ['confidential_space' => 'x', 'container' => ['image_digest' => 'sha256:abc']]])));
        $this->assertSame($no, $this->reason($this->runCase(['submods' => ['confidential_space' => [1], 'container' => ['image_digest' => 'sha256:abc']]])));
        $this->assertSame($no, $this->reason($this->runCase(['submods' => ['container' => ['image_digest' => 'sha256:abc']]])));
    }

    public function testTheSwVersionAllowlistComparesStrings(): void
    {
        $no = 'swversion not in policy allowlist';
        $p = ['allowedSwVersions' => ['5', '1.0']];
        $this->assertSame($no, $this->reason($this->runCase(['swversion' => 5], $p)));
        $this->assertSame($no, $this->reason($this->runCase(['swversion' => 1], $p)));
        $this->assertSame($no, $this->reason($this->runCase(['swversion' => ''], $p)));
        $this->assertSame($no, $this->reason($this->runCase(['swversion' => self::GONE], $p)));
        $this->assertSame($no, $this->reason($this->runCase(['swversion' => ['9', 5]], $p)));
        $this->assertSame($no, $this->reason($this->runCase(['swversion' => '9'], $p)));
        $this->assertTrue($this->runCase(['swversion' => '5'], $p)['ok']);
        $this->assertTrue($this->runCase(['swversion' => '1.0'], $p)['ok']);
        $this->assertTrue($this->runCase(['swversion' => ['9', '1.0']], $p)['ok']);
    }

    public function testTheImageDigestIsComparedCaseInsensitively(): void
    {
        $r = $this->runCase(['submods' => ['confidential_space' => new \stdClass(), 'container' => ['image_digest' => 'SHA256:ABC']]]);
        $this->assertTrue($r['ok']);
        $this->assertSame('SHA256:ABC', $r['measured']['runtime_measurement']);
        $this->assertSame('SHA256:ABC', $r['hostAsserted']['image_digest']);
        $r = $this->runCase(['submods' => ['confidential_space' => new \stdClass(), 'container' => ['image_digest' => 'sha256:def']]], ['imageDigests' => ['SHA256:DEF']]);
        $this->assertTrue($r['ok']);
        $this->assertSame('workload image_digest not in policy allowlist', $this->reason($this->runCase(['submods' => ['confidential_space' => new \stdClass(), 'container' => ['image_digest' => 'sha256:zzz']]])));
        $this->assertSame('token carries no submods.container.image_digest to measure the workload', $this->reason($this->runCase(['submods' => ['confidential_space' => new \stdClass(), 'container' => 'x']])));
        $this->assertSame('token carries no submods.container.image_digest to measure the workload', $this->reason($this->runCase(['submods' => ['confidential_space' => new \stdClass()]])));
    }

    public function testAnErrorInsideTheVerifierFailsClosedWithItsMessage(): void
    {
        $v = new Gcp(self::cfg(), static function ($d) { throw new \RuntimeException('boom'); });
        $this->assertSame(['ok' => false, 'reason' => 'gcp-confidential-space verification error (fail closed): boom'], $v->verify(null, self::expected(), self::NOW));
    }

    public function testTheNonceBindsUnderAnyOfTheCandidates(): void
    {
        $good = bin2hex(Common::attestationBinding(self::expected()));
        $this->assertTrue($this->runCase(['eat_nonce' => ['zz', $good, 'ab']])['ok']);
        $this->assertTrue($this->runCase(['eat_nonce' => ['', $good]])['ok']);
        $this->assertSame('eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)', $this->reason($this->runCase(['eat_nonce' => ['zz', 'ab']])));
        $this->assertSame('token carries no eat_nonce claim to bind the PCA challenge', $this->reason($this->runCase(['eat_nonce' => ['', '']])));
        $this->assertSame('no expected attestation binding supplied', $this->reason($this->runCase([], [], [], self::NOW, [], false)));
    }
}
