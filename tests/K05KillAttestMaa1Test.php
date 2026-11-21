<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Maa;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for Attest/Maa.php (Microsoft Azure Attestation). Expectations follow packages/pca/src/attest-azure-maa.ts. Keys, certificates
 * and tokens come from the helpers of K05KillAttestGcp1Test (hand-built, signed at load).
 */
final class K05KillAttestMaa1Test extends TestCase
{
    private const ISS = 'https://maa.example';
    private const PEM_NO_START = 'error:0480006C:PEM routines::no start line';
    private const GONE = "\0gone";

    private static function k(string $n): \OpenSSLAsymmetricKey
    {
        return K05KillAttestGcp1Test::key($n);
    }

    private static function c(string $iss, string $sub, string $subject, string $signer, array $exts = []): string
    {
        return K05KillAttestGcp1Test::cert($iss, $sub, self::k($subject), self::k($signer), $exts);
    }

    private static function b(string $der): string
    {
        return base64_encode($der);
    }

    private static function call(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Maa::class, $m))->invoke(null, ...$a);
    }

    private static function chain(mixed $x5c, mixed $anchors, float $now = K05KillAttestGcp1Test::NOW, ?float $skew = 0.0): array
    {
        return $skew === null ? Maa::verifyX5cChain($x5c, $anchors, $now) : Maa::verifyX5cChain($x5c, $anchors, $now, $skew);
    }

    private static function failWith(string $why): array
    {
        return ['ok' => false, 'reason' => $why];
    }

    private static function certMsg(string $der): string
    {
        try {
            new Cert($der);
        } catch (\Throwable $e) {
            return $e->getMessage();
        }
        return '';
    }

    // ------------------------------------------------------------------------------------------------------------- verifyX5cChain: shape

    public function testAChainThatIsNotAListOrIsEmpty(): void
    {
        $fp = ['rootSpkiSha256' => [K05KillAttestGcp1Test::spkiHex(self::k('sig'))]];
        foreach (['abc', [], 5, null] as $bad) {
            $this->assertSame(self::failWith('empty x5c certificate chain'), self::chain($bad, $fp), json_encode($bad));
        }
    }

    public function testEmptyAndMalformedEntries(): void
    {
        $fp = ['rootSpkiSha256' => [K05KillAttestGcp1Test::spkiHex(self::k('sig'))]];
        $good = self::b(self::c('root', 'sig', 'sig', 'root'));
        $this->assertSame(self::failWith('empty x5c entry at index 0'), self::chain([5], $fp));
        $this->assertSame(self::failWith('empty x5c entry at index 0'), self::chain([''], $fp));
        $this->assertSame(self::failWith('empty x5c entry at index 1'), self::chain([$good, ''], $fp));
        $this->assertSame(self::failWith('empty x5c entry at index 1'), self::chain([$good, 7], $fp));
        // bytes that are not a DER SEQUENCE fail as the reference's PEM wrapper does; a SEQUENCE that is broken reports its own parse error
        $noSeq = [base64_encode("\x31\x30\x00") => self::PEM_NO_START, '!!!!' => self::PEM_NO_START];
        foreach ($noSeq as $b64 => $why) {
            $this->assertSame(self::failWith("malformed x5c certificate at index 0: $why"), self::chain([(string)$b64], $fp), (string)$b64);
            $this->assertSame(self::failWith("malformed x5c certificate at index 1: $why"), self::chain([$good, (string)$b64], $fp), (string)$b64);
        }
        foreach (["\x30\x31\x00", "\x30\x30\x00", "\x30\x03\x01\x02\x03"] as $der) {
            $own = self::certMsg($der);
            $this->assertNotSame('', $own);
            $this->assertNotSame(self::PEM_NO_START, $own);
            $this->assertSame(self::failWith("malformed x5c certificate at index 0: $own"), self::chain([base64_encode($der)], $fp), bin2hex($der));
            $this->assertSame(self::failWith("malformed x5c certificate at index 1: $own"), self::chain([$good, base64_encode($der)], $fp), bin2hex($der));
        }
    }

    public function testTheValidityWindowAndTheSkew(): void
    {
        $S = self::k('sig');
        $anchors = ['rootSpkiSha256' => [K05KillAttestGcp1Test::spkiHex($S)]];
        $der = self::c('root', 'sig', 'sig', 'root');
        $x5c = [self::b($der)];
        $late = (float)(K05KillAttestGcp1Test::NA * 1000 + 1);
        $early = (float)(K05KillAttestGcp1Test::NB * 1000 - 1);
        $out = self::failWith('x5c certificate at index 0 is outside its validity window');
        // the last instant is inside; one millisecond later is outside, with the default skew and with an explicit 0
        $this->assertTrue(self::chain($x5c, $anchors, (float)(K05KillAttestGcp1Test::NA * 1000), 0.0)['ok']);
        $this->assertSame($out, self::chain($x5c, $anchors, $late, 0.0));
        $this->assertSame($out, self::chain($x5c, $anchors, $late, null));
        $this->assertSame($out, self::chain($x5c, $anchors, $late, -5.0));
        $this->assertSame($out, self::chain($x5c, $anchors, $early, 0.0));
        $this->assertSame($out, self::chain($x5c, $anchors, $early, null));
        // the skew widens it on both sides
        $this->assertTrue(self::chain($x5c, $anchors, $late, 1.0)['ok']);
        $this->assertTrue(self::chain($x5c, $anchors, $early, 1.0)['ok']);
        $this->assertSame($out, self::chain($x5c, $anchors, $late + 1, 1.0));
        $second = self::b(K05KillAttestGcp1Test::cert('root', 'x', $S, self::k('root'), [], K05KillAttestGcp1Test::NB, K05KillAttestGcp1Test::NB + 10));
        $this->assertSame(self::failWith('x5c certificate at index 1 is outside its validity window'), self::chain([$x5c[0], $second], $anchors));
    }

    // ------------------------------------------------------------------------------------------------------------- verifyX5cChain: anchors

    public function testNoAnchorFailsClosed(): void
    {
        $x5c = [self::b(self::c('root', 'sig', 'sig', 'root'))];
        $none = self::failWith('no MAA trust anchor configured (fail closed)');
        foreach ([null, [], ['rootSpkiSha256' => [], 'rootCertsPem' => []], ['rootSpkiSha256' => ['']], ['rootSpkiSha256' => [5]], ['rootSpkiSha256' => ['', 5, null]]] as $a) {
            $this->assertSame($none, self::chain($x5c, $a), json_encode($a));
        }
        // a blank fingerprint is no anchor, a real one beside it still is
        $hex = K05KillAttestGcp1Test::spkiHex(self::k('sig'));
        $this->assertTrue(self::chain($x5c, ['rootSpkiSha256' => ['', strtoupper($hex)]])['ok']);
        $this->assertSame(self::failWith('x5c chain does not anchor in a configured MAA trust root'), self::chain($x5c, ['rootSpkiSha256' => [str_repeat('0', 64)]]));
    }

    public function testAnUnparseableRootFailsClosed(): void
    {
        $x5c = [self::b(self::c('root', 'sig', 'sig', 'root'))];
        $this->assertSame(self::failWith('x5c chain verification error (fail closed): ' . self::PEM_NO_START), self::chain($x5c, ['rootCertsPem' => ['garbage']]));
        // a root that is not even a string is refused in the same way, not with a type error
        $r = self::chain($x5c, ['rootCertsPem' => [5]]);
        $this->assertFalse($r['ok']);
        $this->assertStringStartsWith('x5c chain verification error (fail closed): ', $r['reason']);
        $this->assertStringNotContainsString('must be of type', $r['reason']);
    }

    // ------------------------------------------------------------------------------------------------------------- verifyX5cChain: links

    public function testAChainIsCutAtTheFirstPinnedCertificate(): void
    {
        $ca1 = self::b(self::c('ca2', 'ca1', 'top', 'root', [K05KillAttestGcp1Test::bcCa()]));   // signed by root, NOT by ca2
        $ca2 = self::b(self::c('ca2', 'ca2', 'other', 'other', [K05KillAttestGcp1Test::bcCa()]));
        $leafDer = self::c('ca1', 'leaf', 'leaf', 'top');
        $anchors = ['rootSpkiSha256' => [K05KillAttestGcp1Test::spkiHex(self::k('top')), K05KillAttestGcp1Test::spkiHex(self::k('other'))]];
        $r = self::chain([self::b($leafDer), $ca1, $ca2], $anchors);
        $this->assertSame(['ok', 'leaf'], array_keys($r));
        $this->assertTrue($r['ok']);
        $this->assertInstanceOf(Cert::class, $r['leaf']);
        $this->assertSame($leafDer, $r['leaf']->raw);
        // below the pinned certificate every link is checked
        $badLeaf = self::b(self::c('ca1', 'leaf', 'leaf', 'root'));
        $this->assertSame(self::failWith('x5c link 0 is not signed by the certificate above it'), self::chain([$badLeaf, $ca1, $ca2], $anchors));
        $this->assertSame(self::failWith('x5c link 0 is not signed by the certificate above it'), self::chain([$badLeaf, $ca1], ['rootSpkiSha256' => [K05KillAttestGcp1Test::spkiHex(self::k('top'))]]));
    }

    public function testAChainToARootCertificateChecksEveryLinkTheRootAndTheProfile(): void
    {
        $rootPem = K05KillAttestGcp1Test::pem(self::c('root', 'root', 'root', 'root'));
        $anchors = ['rootCertsPem' => [$rootPem]];
        $top = self::b(self::c('root', 'top', 'top', 'root', [K05KillAttestGcp1Test::bcCa()]));
        $leafDer = self::c('top', 'leaf', 'leaf', 'top');
        $r = self::chain([self::b($leafDer), $top], $anchors);
        $this->assertSame(['ok', 'leaf'], array_keys($r));
        $this->assertTrue($r['ok']);
        $this->assertSame($leafDer, $r['leaf']->raw);
        // a leaf the chain's top did not sign
        $this->assertSame(self::failWith('x5c link 0 is not signed by the certificate above it'), self::chain([self::b(self::c('top', 'leaf', 'leaf', 'root')), $top], $anchors));
        // a top the configured root did not sign
        $other = self::b(self::c('o', 'top', 'top', 'other', [K05KillAttestGcp1Test::bcCa()]));
        $this->assertSame(self::failWith('x5c chain does not anchor in a configured MAA trust root'), self::chain([self::b($leafDer), $other], $anchors));
        // a leaf that asserts CA:TRUE
        $caLeaf = self::b(self::c('top', 'leaf', 'leaf', 'top', [K05KillAttestGcp1Test::bcCa()]));
        $this->assertSame(self::failWith('x5c chain profile: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)'), self::chain([$caLeaf, $top], $anchors));
    }

    // ------------------------------------------------------------------------------------------------------------- resolveSigningX5c

    public function testTheSigningChainComesFromTheJwksOrTheHeader(): void
    {
        $h = ['alg' => 'ES256'];
        $amb = ['reason' => 'token has no kid and the JWKS publishes multiple keys (ambiguous)'];
        $noX5c = ['reason' => 'JWKS key carries no x5c chain'];
        $this->assertSame(['x5c' => ['A', 'B']], self::call('resolveSigningX5c', $h, ['keys' => [['x5c' => ['A', 'B']]]]));
        $this->assertSame($noX5c, self::call('resolveSigningX5c', $h, ['keys' => [['x5c' => []]]]));
        $this->assertSame($noX5c, self::call('resolveSigningX5c', $h, ['keys' => [['x5c' => 'abc']]]));
        $this->assertSame($noX5c, self::call('resolveSigningX5c', $h, ['keys' => [['kid' => 'a']]]));
        $this->assertSame($amb, self::call('resolveSigningX5c', $h, ['keys' => [['x5c' => ['A']], ['x5c' => ['B']]]]));
        $this->assertSame($amb, self::call('resolveSigningX5c', ['alg' => 'ES256', 'kid' => ''], ['keys' => [['x5c' => ['A']], ['x5c' => ['B']]]]));
        // with a kid the first key of that kid is the one
        $dup = ['keys' => [['kid' => 'z', 'x5c' => ['no']], ['kid' => 'a', 'x5c' => ['one']], ['kid' => 'a', 'x5c' => ['two']]]];
        $this->assertSame(['x5c' => ['one']], self::call('resolveSigningX5c', ['alg' => 'ES256', 'kid' => 'a'], $dup));
        $this->assertSame(['reason' => "no JWKS key matches the token kid 'q' (untrusted signer)"], self::call('resolveSigningX5c', ['alg' => 'ES256', 'kid' => 'q'], $dup));
        $this->assertSame(['reason' => "JWKS key 'a' carries no x5c chain"], self::call('resolveSigningX5c', ['alg' => 'ES256', 'kid' => 'a'], ['keys' => [['kid' => 'a', 'x5c' => []]]]));
        // no usable JWKS: the header chain, if it has a certificate
        $none = ['reason' => 'no signing x5c available (no JWKS and no header x5c)'];
        $this->assertSame($none, self::call('resolveSigningX5c', ['alg' => 'ES256', 'x5c' => []], null));
        $this->assertSame($none, self::call('resolveSigningX5c', $h, null));
        $this->assertSame($none, self::call('resolveSigningX5c', ['alg' => 'ES256', 'x5c' => []], ['keys' => []]));
        $this->assertSame(['x5c' => ['H']], self::call('resolveSigningX5c', ['alg' => 'ES256', 'x5c' => ['H']], null));
        $this->assertSame(['x5c' => ['H']], self::call('resolveSigningX5c', ['alg' => 'ES256', 'x5c' => ['H']], ['keys' => []]));
    }

    // ------------------------------------------------------------------------------------------------------------- the constructor

    /** @return array<string,mixed> */
    private static function cfg(array $o = []): array
    {
        return array_replace(['trustedIssuers' => [self::ISS], 'trustAnchors' => ['rootSpkiSha256' => ['aa']], 'policy' => ['tdxMrtds' => ['aa']]], $o);
    }

    private function refuses(array $cfg, string $why): void
    {
        try {
            new Maa($cfg, static fn($d) => null);
            $this->fail("built from $why");
        } catch (AttestConstructError $e) {
            $this->assertSame($why, $e->getMessage());
        }
    }

    public function testTheConstructorChecks(): void
    {
        $f = static fn($d) => null;
        $this->assertInstanceOf(Maa::class, new Maa(self::cfg(), $f));
        $this->assertInstanceOf(Maa::class, new Maa(self::cfg(['trustAnchors' => ['rootCertsPem' => ['x'], 'rootSpkiSha256' => ['aa']]]), $f));
        $this->refuses(self::cfg(['trustAnchors' => ['rootCertsPem' => [], 'rootSpkiSha256' => []]]), 'createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted');
        $why = 'createAzureMaaVerifier: every trusted issuer must be a non-empty URL string';
        $this->refuses(self::cfg(['trustedIssuers' => [5]]), $why);
        $this->refuses(self::cfg(['trustedIssuers' => [self::ISS, '']]), $why);
        $pol = 'createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)';
        $this->refuses(self::cfg(['policy' => ['sevSnpMeasurements' => [], 'tdxMrtds' => []]]), $pol);
        $this->refuses(self::cfg(['policy' => ['x' => 1]]), $pol);
        $this->refuses(self::cfg(['policy' => null]), $pol);
        $this->refuses(self::cfg(['policy' => ['tdxMrtds' => ['aa'], 'sevSnpMinTcb' => 5]]), 'createAzureMaaVerifier: policy.sevSnpMinTcb must be an object');
        $this->refuses(self::cfg(['policy' => ['tdxMrtds' => ['aa'], 'sevSnpMinTcb' => null]]), 'createAzureMaaVerifier: policy.sevSnpMinTcb must be an object');
        $this->refuses(self::cfg(['policy' => ['tdxMrtds' => ['aa'], 'sevSnpMinTcb' => ['nope' => 1]]]), 'createAzureMaaVerifier: policy.sevSnpMinTcb.nope is not a known field (bootloader | snp | microcode | tee)');
        $this->refuses(self::cfg(['policy' => ['tdxMrtds' => ['aa'], 'sevSnpMinTcb' => ['snp' => -1]]]), 'createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer');
        $this->assertInstanceOf(Maa::class, new Maa(self::cfg(['policy' => ['tdxMrtds' => ['aa'], 'sevSnpMinTcb' => ['snp' => 0, 'tee' => 3]]]), $f));
    }

    // ------------------------------------------------------------------------------------------------------------- the verifier harness

    private static function binding(): string
    {
        return bin2hex(Common::attestationBinding(K05KillAttestGcp1Test::expected()));
    }

    /**
     * @param array<string,mixed> $payload overrides (GONE removes) @param array<string,mixed> $policy overrides @param array<string,mixed> $cfg overrides
     * @return array<string,mixed>
     */
    private function runCase(array $payload = [], array $policy = [], array $cfg = [], mixed $now = K05KillAttestGcp1Test::NOW, ?array $expected = [], string $leaf = 'sig'): array
    {
        $base = [
            'iss' => self::ISS, 'exp' => K05KillAttestGcp1Test::N + 600, 'x-ms-attestation-type' => 'sevsnpvm',
            'x-ms-sevsnpvm-reportdata' => self::binding(), 'x-ms-sevsnpvm-launchmeasurement' => 'aabbcc',
        ];
        $p = array_replace($base, $payload);
        foreach ($p as $k => $v) {
            if ($v === self::GONE) {
                unset($p[$k]);
            }
        }
        $der = self::c('root', $leaf, $leaf, 'root');
        $tok = K05KillAttestGcp1Test::token(['alg' => 'ES256', 'x5c' => [self::b($der)]], $p, self::k('sig'));
        $config = array_replace([
            'trustedIssuers' => [self::ISS], 'trustAnchors' => ['rootSpkiSha256' => [K05KillAttestGcp1Test::spkiHex(self::k($leaf))]],
            'policy' => array_replace(['sevSnpMeasurements' => ['aabbcc']], $policy),
        ], $cfg);
        $v = new Maa($config, static fn($d) => ['token' => $tok]);
        return $v->verify(null, $expected === [] ? K05KillAttestGcp1Test::expected() : $expected, $now);
    }

    private function reason(array $r): string
    {
        $this->assertFalse($r['ok']);
        return $r['reason'];
    }

    public function testTheHarnessAcceptsAGoodSevToken(): void
    {
        $this->assertSame([
            'ok' => true, 'bound' => true,
            'measured' => ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => 'aabbcc', 'operator' => ''],
            'hostAsserted' => ['attestation_type' => 'sevsnpvm'],
        ], $this->runCase());
    }

    // ------------------------------------------------------------------------------------------------------------- the verifier: token shape

    public function testNoUsableTokenIsRefused(): void
    {
        foreach ([[], ['token' => 5], ['token' => ''], ['token' => null], null, 'x'] as $ev) {
            $v = new Maa(self::cfg(), static fn($d) => $ev);
            $this->assertSame(self::failWith('no Azure MAA token for this action'), $v->verify(null, K05KillAttestGcp1Test::expected(), K05KillAttestGcp1Test::NOW), json_encode($ev));
        }
    }

    public function testAnUnsupportedAlgIsRefusedBeforeAnyChainWork(): void
    {
        $tok = K05KillAttestGcp1Test::b64u('{"alg":"HS256"}') . '.' . K05KillAttestGcp1Test::b64u('{"iss":"x"}') . '.' . K05KillAttestGcp1Test::b64u('sig');
        $v = new Maa(self::cfg(), static fn($d) => ['token' => $tok]);
        $this->assertSame(self::failWith("unsupported JWS alg 'HS256' (MAA uses ES256 / RS256)"), $v->verify(null, K05KillAttestGcp1Test::expected(), K05KillAttestGcp1Test::NOW));
    }

    public function testAMissingClockFailsTheCertificateWindowNotTheTypes(): void
    {
        $this->assertSame('MAA signing chain invalid: x5c certificate at index 0 is outside its validity window', $this->reason($this->runCase([], [], [], null)));
    }

    public function testTheJwsSignatureNeedsTheRightKeyType(): void
    {
        $sig = K05KillAttestGcp1Test::b64u(str_repeat("\x01", 64));
        $mk = static function (string $alg, string $keyName) use ($sig): string {
            $der = K05KillAttestGcp1Test::cert('root', 'k', self::k($keyName), self::k('root'));
            $si = K05KillAttestGcp1Test::b64u((string)json_encode(['alg' => $alg, 'x5c' => [base64_encode($der)]])) . '.' . K05KillAttestGcp1Test::b64u((string)json_encode(['iss' => self::ISS]));
            return $si . '.' . $sig;
        };
        $go = function (string $tok, string $keyName): array {
            $cfg = self::cfg(['trustAnchors' => ['rootSpkiSha256' => [K05KillAttestGcp1Test::spkiHex(self::k($keyName))]]]);
            return (new Maa($cfg, static fn($d) => ['token' => $tok]))->verify(null, K05KillAttestGcp1Test::expected(), K05KillAttestGcp1Test::NOW);
        };
        $this->assertSame(self::failWith('ES256 token but signing key is EC/P-384 (not EC P-256)'), $go($mk('ES256', 'p384'), 'p384'));
        $this->assertSame(self::failWith('ES256 token but signing key is RSA/undefined (not EC P-256)'), $go($mk('ES256', 'rsa'), 'rsa'));
        $this->assertSame(self::failWith('RS256 token but signing key is EC (not RSA)'), $go($mk('RS256', 'sig'), 'sig'));
        $this->assertSame(self::failWith('JWS ES256 signature does not verify under the MAA signing key'), $go($mk('ES256', 'sig'), 'sig'));
        $this->assertSame(self::failWith('JWS RS256 signature does not verify under the MAA signing key'), $go($mk('RS256', 'rsa'), 'rsa'));
    }

    public function testAnErrorInsideTheVerifierFailsClosedWithItsMessage(): void
    {
        $v = new Maa(self::cfg(), static function ($d) { throw new \RuntimeException('boom'); });
        $this->assertSame(self::failWith('azure-maa verification error (fail closed): boom'), $v->verify(null, K05KillAttestGcp1Test::expected(), K05KillAttestGcp1Test::NOW));
    }

    // ------------------------------------------------------------------------------------------------------------- the verifier: time

    public function testTheTimeWindowAtItsEdges(): void
    {
        $N = K05KillAttestGcp1Test::N;
        // [clockSkewMs, exp, ok]
        foreach ([[0, $N, true], [0, $N - 1, false], [-5, $N - 1, false], [1000, $N - 1, true], [1000, $N - 2, false], [1001, $N - 2, true], [1001, $N - 3, false],
                  [1, $N - 1, true], [1, $N - 2, false], [400, $N - 1, true], [400, $N - 2, false], [1500, $N - 2, true], [1500, $N - 3, false]] as [$skew, $e, $ok]) {
            $r = $this->runCase(['exp' => $e], [], ['clockSkewMs' => $skew]);
            $this->assertSame($ok, $r['ok'], "skew $skew exp " . ($e - $N));
            if (!$ok) {
                $this->assertSame('MAA token expired', $r['reason'], "skew $skew exp " . ($e - $N));
            }
        }
        $this->assertTrue($this->runCase(['nbf' => $N + 1], [], ['clockSkewMs' => 1000])['ok']);
        $this->assertSame('MAA token not yet valid (nbf)', $this->reason($this->runCase(['nbf' => $N + 2], [], ['clockSkewMs' => 1000])));
        $this->assertTrue($this->runCase(['iat' => $N + 1], [], ['clockSkewMs' => 1000])['ok']);
        $this->assertSame('MAA token issued in the future (iat)', $this->reason($this->runCase(['iat' => $N + 2], [], ['clockSkewMs' => 1000])));
        $this->assertTrue($this->runCase(['nbf' => $N, 'iat' => $N])['ok']);
        $this->assertSame('MAA token not yet valid (nbf)', $this->reason($this->runCase(['nbf' => $N + 1])));
        $this->assertSame('MAA token issued in the future (iat)', $this->reason($this->runCase(['iat' => $N + 1])));
        $this->assertSame('token has no exp (cannot bound validity — fail closed)', $this->reason($this->runCase(['exp' => self::GONE])));
    }

    // ------------------------------------------------------------------------------------------------------------- the verifier: isolation type and binding

    public function testTheAttestationTypeIsReadFromTheIsolationObjectFirst(): void
    {
        $tee = ['x-ms-attestation-type' => 'sevsnpvm', 'x-ms-sevsnpvm-reportdata' => self::binding(), 'x-ms-sevsnpvm-launchmeasurement' => 'aabbcc'];
        $pol = ['sevSnpMeasurements' => ['aabbcc'], 'tdxMrtds' => ['aabb']];
        $r = $this->runCase(['x-ms-attestation-type' => 'tdxvm', 'x-ms-isolation-tee' => $tee], $pol);
        $this->assertTrue($r['ok']);
        $this->assertSame('sevsnpvm', $r['hostAsserted']['attestation_type']);
        // the top-level type is the fallback when the isolation object has none
        unset($tee['x-ms-attestation-type']);
        $r = $this->runCase(['x-ms-attestation-type' => 'sevsnpvm', 'x-ms-isolation-tee' => $tee], $pol);
        $this->assertTrue($r['ok']);
        $this->assertSame("unexpected x-ms-attestation-type 'undefined' (expected sevsnpvm | tdxvm)", $this->reason($this->runCase(['x-ms-attestation-type' => self::GONE])));
        $this->assertSame("unexpected x-ms-attestation-type 'foo' (expected sevsnpvm | tdxvm)", $this->reason($this->runCase(['x-ms-attestation-type' => 'foo'])));
    }

    public function testABindingThatCannotBeBuiltIsReportedWithItsMessage(): void
    {
        $r = $this->runCase([], [], [], K05KillAttestGcp1Test::NOW, ['grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n']);
        $this->assertSame(self::failWith('binding not constructible: binding: holderPub required'), $r);
        $r = $this->runCase([], [], [], K05KillAttestGcp1Test::NOW, ['holderPub' => 'h', 'grantRef' => 'g', 'epoch' => -1, 'nonce' => 'n']);
        $this->assertSame(self::failWith('binding not constructible: binding: epoch must be a non-negative safe integer'), $r);
        $this->assertSame(self::failWith('no expected attestation binding supplied'), $this->runCase([], [], [], K05KillAttestGcp1Test::NOW, null));
    }

    // ------------------------------------------------------------------------------------------------------------- the verifier: SEV-SNP claims

    public function testTheSevMeasurementIsComparedCaseInsensitively(): void
    {
        $r = $this->runCase(['x-ms-sevsnpvm-launchmeasurement' => 'AABBCC']);
        $this->assertTrue($r['ok']);
        $this->assertSame('aabbcc', $r['measured']['runtime_measurement']);
        $this->assertTrue($this->runCase(['x-ms-sevsnpvm-launchmeasurement' => 'aabbcc'], ['sevSnpMeasurements' => ['AABBCC']])['ok']);
        $this->assertSame('SEV-SNP launch measurement not in policy allowlist', $this->reason($this->runCase(['x-ms-sevsnpvm-launchmeasurement' => 'aabbcd'])));
        $this->assertSame('sevsnpvm token carries no launch-measurement claim', $this->reason($this->runCase(['x-ms-sevsnpvm-launchmeasurement' => self::GONE])));
        $this->assertSame('sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)', $this->reason($this->runCase([], ['sevSnpMeasurements' => [], 'tdxMrtds' => ['aa']])));
    }

    public function testTheSevHostDataAllowlist(): void
    {
        $no = 'SEV-SNP host-data not in policy allowlist';
        // an empty list is no restriction
        $r = $this->runCase([], ['sevSnpHostData' => []]);
        $this->assertTrue($r['ok']);
        $this->assertSame(['attestation_type' => 'sevsnpvm'], $r['hostAsserted']);
        $this->assertSame($no, $this->reason($this->runCase([], ['sevSnpHostData' => ['abcd']])));
        $this->assertSame($no, $this->reason($this->runCase(['x-ms-sevsnpvm-hostdata' => 'ffff'], ['sevSnpHostData' => ['abcd']])));
        // both sides compare in lower case, and the reported value is lower case
        $r = $this->runCase(['x-ms-sevsnpvm-hostdata' => 'ABCD'], ['sevSnpHostData' => ['abcd']]);
        $this->assertTrue($r['ok']);
        $this->assertSame(['attestation_type' => 'sevsnpvm', 'host_data' => 'abcd'], $r['hostAsserted']);
        $this->assertTrue($this->runCase(['x-ms-sevsnpvm-hostdata' => 'abcd'], ['sevSnpHostData' => ['ABCD']])['ok']);
        $r = $this->runCase(['x-ms-sevsnpvm-hostdata' => 'ABCD']);
        $this->assertSame('abcd', $r['hostAsserted']['host_data']);
    }

    // ------------------------------------------------------------------------------------------------------------- the verifier: TDX claims

    /** @return array<string,mixed> */
    private static function tdx(array $o = []): array
    {
        return array_replace([
            'x-ms-attestation-type' => 'tdxvm', 'x-ms-sevsnpvm-reportdata' => self::GONE, 'x-ms-sevsnpvm-launchmeasurement' => self::GONE,
            'tdx_report_data' => self::binding(), 'tdx_mrtd' => 'AABB',
        ], $o);
    }

    public function testTheTdxClaims(): void
    {
        $pol = ['tdxMrtds' => ['aabb'], 'tdxRtmrs' => ['ccdd']];
        $cfgPol = static fn(array $p): array => ['policy' => $p];
        $r = $this->runCase(self::tdx(['tdx_rtmr0' => 'CCDD', 'attester_tcb_status' => 'UpToDate']), [], $cfgPol($pol));
        $this->assertSame([
            'ok' => true, 'bound' => true,
            'measured' => ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => 'aabb', 'operator' => ''],
            'hostAsserted' => ['attestation_type' => 'tdxvm', 'tcb_status' => 'UpToDate', 'rtmr0' => 'ccdd'],
        ], $r);
        $this->assertSame('TDX RTMR0 not in policy allowlist', $this->reason($this->runCase(self::tdx(['tdx_rtmr0' => 'eeee']), [], $cfgPol($pol))));
        $this->assertSame('TDX RTMR0 not in policy allowlist', $this->reason($this->runCase(self::tdx(), [], $cfgPol($pol))));
        $this->assertSame('TDX MRTD not in policy allowlist', $this->reason($this->runCase(self::tdx(['tdx_mrtd' => 'ffff']), [], $cfgPol($pol))));
        $this->assertSame("TDX platform TCB status 'OutOfDate' is not accepted by policy", $this->reason($this->runCase(self::tdx(['attester_tcb_status' => 'OutOfDate']), [], $cfgPol($pol))));
        $r = $this->runCase(self::tdx(), [], $cfgPol(['tdxMrtds' => ['aabb']]));
        $this->assertSame(['attestation_type' => 'tdxvm'], $r['hostAsserted']);
        $this->assertSame('tdxvm token but policy configures no TDX MRTD allowlist (fail closed)', $this->reason($this->runCase(self::tdx(), [], $cfgPol(['sevSnpMeasurements' => ['aabbcc']]))));
    }
}
