<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Ocsp;
use Atlas\Pca\Attest\OcspError;
use Atlas\Pca\Attest\Tlv;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for Atlas\Pca\Attest\Ocsp (PCA 0.5 mutation baseline). A small PKI (root, CA, leaf, delegated responders, rogue and
 * look-alike certificates) and real DER OCSPResponses are generated at load; the private DER/time helpers are reached through
 * reflection. Every reason string is the reference's (packages/pca/src/attest-nvidia-ocsp.ts).
 */
final class K05KillAttestOcsp1Test extends TestCase
{
    private const SIGNING = '1.3.6.1.5.5.7.3.9';
    private const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
    private const NO_MATCH = 'no SingleResponse matches the certificate (serial / issuer hashes differ)';

    // ---- DER building ---------------------------------------------------------------------------------------------------------

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        $len = $n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n));
        return chr($tag) . $len . $v;
    }

    private static function oid(string $dotted): string
    {
        $a = array_map('intval', explode('.', $dotted));
        $out = chr(40 * $a[0] + $a[1]);
        foreach (array_slice($a, 2) as $x) {
            $b = chr($x & 0x7F);
            $x >>= 7;
            while ($x > 0) {
                $b = chr(0x80 | ($x & 0x7F)) . $b;
                $x >>= 7;
            }
            $out .= $b;
        }
        return self::tlv(0x06, $out);
    }

    private static function dn(string $cn): string
    {
        return self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, self::oid('2.5.4.3'), self::tlv(0x0C, $cn))));
    }

    private static function ext(string $id, string $value): string
    {
        return self::tlv(0x30, self::oid($id), self::tlv(0x04, $value));
    }

    /** @param list<string> $oids */
    private static function ekuExt(array $oids): string
    {
        return self::ext('2.5.29.37', self::tlv(0x30, ...array_map([self::class, 'oid'], $oids)));
    }

    private static function key(string $name): \OpenSSLAsymmetricKey
    {
        static $keys = [];
        if (!isset($keys[$name])) {
            $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
            file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
            $keys[$name] = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            unlink($cnf);
        }
        return $keys[$name];
    }

    private static function spki(\OpenSSLAsymmetricKey $k): string
    {
        return (string)base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details($k)['key']));
    }

    /** The 65-byte EC point of a P-256 SubjectPublicKeyInfo (what the CertID key hash covers). */
    private static function keyBits(string $spkiDer): string
    {
        return substr($spkiDer, -65);
    }

    private static function now(): int
    {
        return gmmktime(12, 0, 0, 6, 1, 2026);
    }

    private static function gt(int $s, string $frac = ''): string
    {
        return gmdate('YmdHis', $s) . ($frac === '' ? '' : '.' . $frac) . 'Z';
    }

    private static function ut(int $s): string
    {
        return gmdate('ymdHis', $s) . 'Z';
    }

    private static function ms(int $y, int $mo, int $d, int $h = 0, int $mi = 0, int $s = 0): int
    {
        return gmmktime($h, $mi, $s, $mo, $d, $y) * 1000;
    }

    /** @param array<string,mixed> $o */
    private static function certDer(array $o): string
    {
        $alg = self::tlv(0x30, self::oid('1.2.840.10045.4.3.2'));
        $val = $o['validity'] ?? self::tlv(0x30, self::tlv(0x17, '250101000000Z'), self::tlv(0x17, '350101000000Z'));
        $exts = $o['exts'] ?? [];
        $e = $exts === [] ? [] : [self::tlv(0xA3, self::tlv(0x30, ...$exts))];
        $spki = $o['spki'] ?? self::spki($o['key']);
        $tbs = self::tlv(0x30, self::tlv(0xA0, self::tlv(0x02, "\x02")), self::tlv(0x02, $o['serial'] ?? "\x01"), $alg, $o['issuer'], $val, $o['subject'], $spki, ...$e);
        openssl_sign($tbs, $sig, $o['signer'], OPENSSL_ALGO_SHA256);
        return self::tlv(0x30, $tbs, $alg, self::tlv(0x03, "\0" . $sig));
    }

    /** @return array<string,mixed> */
    private static function world(): array
    {
        static $w = null;
        if ($w !== null) {
            return $w;
        }
        $k = [];
        foreach (['root', 'ca', 'leaf', 'resp', 'resp2', 'rogue', 'dev', 'mid'] as $n) {
            $k[$n] = self::key($n);
        }
        $rootDn = self::dn('root');
        $caDn = self::dn('ca');
        $leafDn = self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, self::oid('2.5.4.6'), self::tlv(0x13, 'US'))), self::tlv(0x31, self::tlv(0x30, self::oid('2.5.4.3'), self::tlv(0x0C, 'leaf'))));
        $ad = static fn(string $method, int $tag, string $v): string => self::tlv(0x30, self::oid($method), self::tlv($tag, $v));
        $aia = self::ext('1.3.6.1.5.5.7.1.1', self::tlv(
            0x30,
            $ad('1.3.6.1.5.5.7.48.2', 0x86, 'http://ca/x'),
            $ad('1.3.6.1.5.5.7.48.1', 0x86, 'http://ocsp/a'),
            $ad('1.3.6.1.5.5.7.48.1', 0x82, 'ocsp.example'),
            $ad('1.3.6.1.5.5.7.48.1', 0x86, 'http://ocsp/b'),
            $ad('1.3.6.1.5.5.7.48.2', 0x86, 'http://ca/y'),
        ));
        $root = new Cert(self::certDer(['issuer' => $rootDn, 'subject' => $rootDn, 'key' => $k['root'], 'signer' => $k['root'], 'serial' => "\x01\x00\x01"]));
        $ca = new Cert(self::certDer(['issuer' => $rootDn, 'subject' => $caDn, 'key' => $k['ca'], 'signer' => $k['root'], 'serial' => "\x0A\x0B"]));
        $leaf = new Cert(self::certDer(['issuer' => $caDn, 'subject' => $leafDn, 'key' => $k['leaf'], 'signer' => $k['ca'], 'serial' => "\x01\x02\x03", 'exts' => [$aia]]));
        return $w = compact('k', 'rootDn', 'caDn', 'leafDn', 'root', 'ca', 'leaf');
    }

    /** A delegated responder certificate (subject "resp", signed by the CA, with the OCSPSigning EKU, valid 2025-2035) with overrides. @param array<string,mixed> $o */
    private static function dcert(array $o = []): Cert
    {
        $w = self::world();
        return new Cert(self::certDer($o + [
            'issuer' => $w['caDn'], 'subject' => self::dn('resp'), 'key' => $w['k']['resp'], 'signer' => $w['k']['ca'],
            'serial' => "\x07", 'exts' => [self::ekuExt([self::SIGNING])],
        ]));
    }

    private static function valid(int $nb, int $na): string
    {
        return self::tlv(0x30, self::tlv(0x17, self::ut($nb)), self::tlv(0x17, self::ut($na)));
    }

    // ---- OCSP building --------------------------------------------------------------------------------------------------------

    /** @param array<string,mixed> $o */
    private static function single(Cert $cert, Cert $issuer, array $o = []): string
    {
        $hname = $o['hash'] ?? 'sha1';
        $cid = $o['cid'] ?? self::tlv(
            0x30,
            self::tlv(0x30, self::oid($o['hashOid'] ?? '1.3.14.3.2.26'), "\x05\x00"),
            self::tlv(0x04, hash($hname, $issuer->subjectDer, true)),
            self::tlv(0x04, hash($hname, self::keyBits($issuer->spkiDer), true)),
            self::tlv(0x02, $o['serial'] ?? $cert->serial),
        );
        $status = match ($o['status'] ?? 'good') {
            'good' => "\x80\x00",
            'unknown' => "\x82\x00",
            default => self::tlv(0xA1, self::tlv(0x18, '20250101000000Z')),
        };
        $now = self::now();
        $parts = [$cid, $status, $o['thisTlv'] ?? self::tlv(0x18, $o['this'] ?? self::gt($now - 3600))];
        $next = array_key_exists('next', $o) ? $o['next'] : self::gt($now + 86400);
        if ($next !== null) {
            $parts[] = self::tlv(0xA0, self::tlv(0x18, $next));
        }
        return self::tlv(0x30, ...($o['singleParts'] ?? $parts));
    }

    private static function ridTlv(Cert $c, string $kind = 'name'): string
    {
        return $kind === 'name' ? self::tlv(0xA1, $c->subjectDer) : self::tlv(0xA2, self::tlv(0x04, sha1(self::keyBits($c->spkiDer), true)));
    }

    /** @param array<string,mixed> $o */
    private static function tbs(Cert $cert, Cert $issuer, array $o): string
    {
        if (isset($o['tbsParts'])) {
            return self::tlv(0x30, ...$o['tbsParts']);
        }
        $parts = [];
        if ($o['version'] ?? false) {
            $parts[] = self::tlv(0xA0, self::tlv(0x02, "\x00"));
        }
        $parts[] = self::ridTlv($o['ridCert'] ?? $issuer, $o['rid'] ?? 'name');
        $parts[] = $o['producedTlv'] ?? self::tlv(0x18, $o['produced'] ?? self::gt(self::now() - 3600));
        $parts[] = $o['responsesTlv'] ?? self::tlv(0x30, ...($o['singles'] ?? [self::single($cert, $issuer, $o)]));
        return self::tlv(0x30, ...$parts);
    }

    /** @param array<string,mixed> $o */
    private static function resp(array $o = []): string
    {
        $w = self::world();
        $tbs = $o['tbs'] ?? self::tbs($o['cert'] ?? $w['leaf'], $o['issuer'] ?? $w['ca'], $o);
        openssl_sign($tbs, $sig, $o['signer'] ?? $w['k']['ca'], OPENSSL_ALGO_SHA256);
        $bk = $o['bk'] ?? [$tbs, self::tlv(0x30, self::oid($o['sigOid'] ?? '1.2.840.10045.4.3.2')), self::tlv(0x03, "\0" . ($o['sig'] ?? $sig))];
        if (($o['certs'] ?? []) !== []) {
            $bk[] = self::tlv(0xA0, self::tlv(0x30, ...$o['certs']));
        }
        $basic = $o['basic'] ?? self::tlv(0x30, ...$bk);
        $rbk = $o['rbk'] ?? [self::oid('1.3.6.1.5.5.7.48.1.1'), self::tlv(0x04, $basic)];
        return self::tlv(0x30, ...($o['outer'] ?? ["\x0A\x01\x00", self::tlv(0xA0, self::tlv(0x30, ...$rbk))]));
    }

    /** @param array<string,mixed> $o */
    private static function runCase(string $der, array $o = []): array
    {
        $w = self::world();
        $args = [$der, $o['cert'] ?? $w['leaf'], $o['issuer'] ?? $w['ca'], $o['chain'] ?? [$w['leaf'], $w['ca'], $w['root']], (float)($o['now'] ?? self::now() * 1000)];
        if (array_key_exists('maxAge', $o) || array_key_exists('skew', $o)) {
            $args[] = isset($o['maxAge']) ? (float)$o['maxAge'] : null;
        }
        if (array_key_exists('skew', $o)) {
            $args[] = (float)$o['skew'];
        }
        return Ocsp::verifyResponse(...$args);
    }

    private static function good(string $responder = 'issuer', string $status = 'good'): array
    {
        return ['ok' => true, 'status' => $status, 'responder' => $responder];
    }

    private static function failWith(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    private static function rej(string $message): array
    {
        return self::failWith('OCSP response rejected: ' . $message);
    }

    private static function priv(string $name, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Ocsp::class, $name))->invoke(null, ...$args);
    }

    // ---- time readers ----------------------------------------------------------------------------------------------------------

    public function testTimeInRange(): void
    {
        $true = [
            ['240229000000Z', true], ['20240229000001Z', false], ['960229000000Z', true], ['000229000000Z', true],
            ['20240131000000Z', false], ['20241201000000Z', false], ['20240101000059Z', false], ['20240101005900Z', false],
            ['20240101235959Z', false], ['20240229000000.5Z', false],
        ];
        foreach ($true as [$t, $utc]) {
            $this->assertTrue(self::priv('timeInRange', $t, $utc), "$t");
        }
        $false = [
            ['zzz', true], ['zzz', false], ['250229000000Z', true], ['21000229000000Z', false], ['20250229000000Z', false],
            ['20241301000000Z', false], ['20240001000000Z', false], ['20240100000000Z', false], ['20240230000000Z', false],
            ['20240101240000Z', false], ['20240101006000Z', false], ['20240101000060Z', false], ['250229000000Z', false],
            ['20240431000000Z', false], ['20240229000000Z', true],
        ];
        foreach ($false as [$t, $utc]) {
            $this->assertFalse(self::priv('timeInRange', $t, $utc), "$t");
        }
    }

    public function testGenTimeMs(): void
    {
        $cases = [
            ['250102033005Z', self::ms(2025, 1, 2, 3, 30, 5)], ['960102033005Z', self::ms(1996, 1, 2, 3, 30, 5)],
            ['500102033005Z', self::ms(1950, 1, 2, 3, 30, 5)], ['490102033005Z', self::ms(2049, 1, 2, 3, 30, 5)],
            ['000102033005Z', self::ms(2000, 1, 2, 3, 30, 5)], ['20250102033005Z', self::ms(2025, 1, 2, 3, 30, 5)],
            ['20250102033005.25Z', self::ms(2025, 1, 2, 3, 30, 5) + 250], ['20250102033005.5Z', self::ms(2025, 1, 2, 3, 30, 5) + 500],
            ['20250102033005.257Z', self::ms(2025, 1, 2, 3, 30, 5) + 257], ['20250102033005.2579Z', self::ms(2025, 1, 2, 3, 30, 5) + 257],
            ['20250102033005.05Z', self::ms(2025, 1, 2, 3, 30, 5) + 50], ['20250102033005.001Z', self::ms(2025, 1, 2, 3, 30, 5) + 1],
        ];
        foreach ($cases as [$t, $want]) {
            $this->assertSame($want, self::priv('genTimeMs', $t), $t);
        }
        try {
            self::priv('genTimeMs', '2025');
            $this->fail('expected OcspError');
        } catch (OcspError $e) {
            $this->assertSame('response times are not parseable', $e->getMessage());
        }
    }

    public function testAllTimesWellFormed(): void
    {
        $utc = static fn(string $t): string => "\x17" . chr(strlen($t)) . $t;
        $gen = static fn(string $t): string => "\x18" . chr(strlen($t)) . $t;
        $goodU = $utc('240229000000Z');
        $badU = $utc('250229000000Z');
        $goodG = $gen('20240229000000Z');
        $badG = $gen('20250229000000Z');
        $this->assertTrue(self::priv('allTimesWellFormed', $goodU, 0, strlen($goodU)));
        $this->assertTrue(self::priv('allTimesWellFormed', $goodG, 0, strlen($goodG)));
        $this->assertFalse(self::priv('allTimesWellFormed', $badU, 0, strlen($badU)));
        $this->assertFalse(self::priv('allTimesWellFormed', $badG, 0, strlen($badG)));
        $nested = self::tlv(0x30, $badU);
        $this->assertFalse(self::priv('allTimesWellFormed', $nested, 0, strlen($nested)));
        $deep = self::tlv(0xA0, self::tlv(0x30, $goodU, $badG));
        $this->assertFalse(self::priv('allTimesWellFormed', $deep, 0, strlen($deep)));
        $both = $goodU . $goodG . self::tlv(0x30, $goodU, $goodG);
        $this->assertTrue(self::priv('allTimesWellFormed', $both, 0, strlen($both)));
        $octet = "\x04" . chr(strlen($badU) - 2) . substr($badU, 2); // a time's bytes under a non-time tag are never read as a time
        $this->assertTrue(self::priv('allTimesWellFormed', $octet, 0, strlen($octet)));
        $der = "\x04\x03\x01\x02\x03";
        try {
            self::priv('allTimesWellFormed', $der, 0, 2);
            $this->fail('expected OcspError');
        } catch (OcspError $e) {
            $this->assertSame('element overruns its parent', $e->getMessage());
        }
    }

    // ---- DER helpers -----------------------------------------------------------------------------------------------------------

    public function testChildren(): void
    {
        $der = "\x04\x03\x01\x02\x03";
        $this->assertEquals([[new Tlv(0x04, 2, 5), 0]], self::priv('children', $der, new Tlv(0x30, 0, 5)));
        try {
            self::priv('children', $der, new Tlv(0x30, 0, 2));
            $this->fail('expected OcspError');
        } catch (OcspError $e) {
            $this->assertSame('element overruns its parent', $e->getMessage());
        }
    }

    public function testStripZeros(): void
    {
        $this->assertSame("\x01", self::priv('stripZeros', "\x00\x00\x00\x01"));
        $this->assertSame("\x01", self::priv('stripZeros', "\x00\x01"));
        $this->assertSame("\x01\x02", self::priv('stripZeros', "\x00\x01\x02"));
        $this->assertSame("\x01", self::priv('stripZeros', "\x00\x00\x01"));
        $this->assertSame("\x00", self::priv('stripZeros', "\x00\x00"));
        $this->assertSame("\x00", self::priv('stripZeros', "\x00"));
        $this->assertSame("\x05\x00", self::priv('stripZeros', "\x05\x00"));
        $this->assertSame("\x01\x00\x00", self::priv('stripZeros', "\x01\x00\x00"));
    }

    public function testSpkiKeyBits(): void
    {
        // a third element after the BIT STRING must not leak into the key bits
        $spki = self::tlv(0x30, self::tlv(0x30, self::oid('1.2.3')), self::tlv(0x03, "\0ABCD"), self::tlv(0x04, str_repeat('X', 40)));
        $this->assertSame('ABCD', self::priv('spkiKeyBits', $spki));
        foreach ([self::tlv(0x30, self::tlv(0x30, self::oid('1.2.3'))), self::tlv(0x30, self::tlv(0x30), self::tlv(0x04, 'x'))] as $bad) {
            try {
                self::priv('spkiKeyBits', $bad);
                $this->fail('expected OcspError');
            } catch (OcspError $e) {
                $this->assertSame('malformed SubjectPublicKeyInfo', $e->getMessage());
            }
        }
    }

    public function testVerifySigDirect(): void
    {
        $w = self::world();
        $pub = $w['ca']->publicKey();
        openssl_sign('data', $sig, $w['k']['ca'], OPENSSL_ALGO_SHA256);
        $ec = '1.2.840.10045.4.3.2';
        $this->assertTrue(self::priv('verifySig', $ec, 'data', $sig, $pub));
        $this->assertFalse(self::priv('verifySig', $ec, 'datb', $sig, $pub));
        $this->assertFalse(self::priv('verifySig', '1.2.3', 'data', $sig, $pub));
        $this->assertFalse(self::priv('verifySig', '1.2.840.113549.1.1.11', 'data', $sig, $pub));
    }

    public function testEkuOf(): void
    {
        $w = self::world();
        $two = self::dcert(['exts' => [self::ekuExt([self::SERVER_AUTH, self::SIGNING])]]);
        $this->assertSame([self::SERVER_AUTH, self::SIGNING], self::priv('ekuOf', $two));
        $this->assertSame([self::SIGNING], self::priv('ekuOf', self::dcert()));
        $this->assertNull(self::priv('ekuOf', $w['ca']));
        $this->assertNull(self::priv('ekuOf', self::dcert(['exts' => [self::ext('2.5.29.37', self::tlv(0x04, ''))]])));
    }

    public function testCertOcspUrls(): void
    {
        $w = self::world();
        $this->assertSame(['http://ocsp/a', 'http://ocsp/b'], Ocsp::certOcspUrls($w['leaf']));
        $this->assertSame([], Ocsp::certOcspUrls($w['ca']));
    }

    // ---- verifyResponse: envelope ----------------------------------------------------------------------------------------------

    public function testHappyPaths(): void
    {
        $this->assertSame(self::good(), self::runCase(self::resp()));
        $this->assertSame(self::good('issuer', 'unknown'), self::runCase(self::resp(['status' => 'unknown'])));
        $this->assertSame(self::good('issuer', 'revoked'), self::runCase(self::resp(['status' => 'revoked'])));
        $this->assertSame(self::good(), self::runCase(self::resp(['rid' => 'key'])));
        $this->assertSame(self::good(), self::runCase(self::resp(['version' => true])));
        // leading zeros of the CertID serial are not significant
        $this->assertSame(self::good(), self::runCase(self::resp(['serial' => "\x00\x00" . self::world()['leaf']->serial])));
    }

    public function testEnvelopeRefusals(): void
    {
        $this->assertSame(self::rej('OCSPResponse is not a SEQUENCE'), self::runCase(self::tlv(0x04, "\x0A\x01\x00")));
        $this->assertSame(self::rej('responseStatus is not an ENUMERATED'), self::runCase(self::tlv(0x30)));
        $this->assertSame(self::rej('responseStatus is not an ENUMERATED'), self::runCase(self::tlv(0x30, "\x02\x01\x00")));
        $this->assertSame(self::failWith('OCSP responseStatus is 1 (not successful)'), self::runCase(self::tlv(0x30, "\x0A\x01\x01")));
        $this->assertSame(self::failWith('OCSP responseStatus is 3 (not successful)'), self::runCase(self::tlv(0x30, "\x0A\x01\x03")));
        $this->assertSame(self::failWith('successful response carries no responseBytes'), self::runCase(self::tlv(0x30, "\x0A\x01\x00")));
        $this->assertSame(self::failWith('successful response carries no responseBytes'), self::runCase(self::tlv(0x30, "\x0A\x01\x00", self::tlv(0x30))));
        $basicOid = self::oid('1.3.6.1.5.5.7.48.1.1');
        $this->assertSame(self::rej('responseBytes is not a SEQUENCE'), self::runCase(self::tlv(0x30, "\x0A\x01\x00", self::tlv(0xA0, self::tlv(0x04)))));
        $this->assertSame(self::rej('responseBytes is malformed'), self::runCase(self::tlv(0x30, "\x0A\x01\x00", self::tlv(0xA0, self::tlv(0x30, $basicOid, self::tlv(0x02, "\x00"))))));
        $this->assertSame(self::rej('responseBytes is malformed'), self::runCase(self::tlv(0x30, "\x0A\x01\x00", self::tlv(0xA0, self::tlv(0x30, self::tlv(0x02, "\x00"), self::tlv(0x04))))));
        $this->assertSame(self::rej('responseBytes is malformed'), self::runCase(self::tlv(0x30, "\x0A\x01\x00", self::tlv(0xA0, self::tlv(0x30, $basicOid)))));
        $this->assertSame(self::failWith('responseType is not id-pkix-ocsp-basic'), self::runCase(self::resp(['rbk' => [self::oid('1.2.3'), self::tlv(0x04, "\x30\x00")]])));
        $this->assertSame(self::rej('BasicOCSPResponse is not a SEQUENCE'), self::runCase(self::resp(['basic' => self::tlv(0x04)])));
    }

    public function testBasicResponseShape(): void
    {
        $w = self::world();
        $tbs = self::tbs($w['leaf'], $w['ca'], []);
        $alg = self::tlv(0x30, self::oid('1.2.840.10045.4.3.2'));
        $sig = self::tlv(0x03, "\0abc");
        $int = self::tlv(0x02, "\x05");
        $msg = 'BasicOCSPResponse is malformed';
        $this->assertSame(self::rej($msg), self::runCase(self::resp(['bk' => [$tbs, $alg]])));
        $this->assertSame(self::rej($msg), self::runCase(self::resp(['bk' => [$tbs, $int, $sig]])));
        $this->assertSame(self::rej($msg), self::runCase(self::resp(['bk' => [$int, $alg, $sig]])));
        $this->assertSame(self::rej($msg), self::runCase(self::resp(['bk' => [$tbs, $alg, self::tlv(0x04, "\0abc")]])));
        $bad = self::tlv(0x30, self::tlv(0x18, '20250229000000Z'));
        $this->assertSame(self::failWith('response carries a malformed (out-of-range) ASN.1 time'), self::runCase(self::resp(['bk' => [$bad, $alg, $sig]])));
        $this->assertSame(self::failWith('unsupported OCSP signature algorithm 1.2.3'), self::runCase(self::resp(['sigOid' => '1.2.3'])));
    }

    // ---- verifyResponse: ResponseData ------------------------------------------------------------------------------------------

    public function testResponseDataShape(): void
    {
        $w = self::world();
        $rid = self::ridTlv($w['ca']);
        $prod = self::tlv(0x18, self::gt(self::now() - 3600));
        $resps = self::tlv(0x30, self::single($w['leaf'], $w['ca']));
        $t = static fn(array $parts): array => self::runCase(self::resp(['tbsParts' => $parts]));
        $this->assertSame(self::rej('responderID is malformed'), $t([]));
        $this->assertSame(self::rej('responderID is malformed'), $t([self::tlv(0xA0, self::tlv(0x02, "\x00"))]));
        $this->assertSame(self::rej('responderID is malformed'), $t([self::tlv(0xA3, $w['ca']->subjectDer), $prod, $resps]));
        $this->assertSame(self::rej('producedAt is malformed'), $t([$rid]));
        $this->assertSame(self::rej('producedAt is malformed'), $t([$rid, self::tlv(0x17, self::ut(self::now() - 3600)), $resps]));
        $this->assertSame(self::rej('responses is malformed'), $t([$rid, $prod]));
        $this->assertSame(self::rej('responses is malformed'), $t([$rid, $prod, self::tlv(0x04)]));
        $this->assertSame(self::good(), $t([$rid, $prod, $resps]));
    }

    public function testSingleResponseShape(): void
    {
        $w = self::world();
        $ok = self::single($w['leaf'], $w['ca']);
        $mk = static fn(string ...$singles): array => self::runCase(self::resp(['singles' => $singles]));
        $id = self::tlv(0x30, self::tlv(0x30, self::oid('1.3.14.3.2.26'), "\x05\x00"), self::tlv(0x04, 'a'), self::tlv(0x04, 'b'), self::tlv(0x02, "\x01"));
        $now = self::now();
        $this->assertSame(self::rej('SingleResponse is malformed'), $mk(self::tlv(0x30, $id, "\x80\x00")));
        $this->assertSame(self::rej('SingleResponse is malformed'), $mk(self::tlv(0x30, self::tlv(0x04, 'x'), "\x80\x00", self::tlv(0x18, self::gt($now)))));
        $this->assertSame(self::rej('CertID is malformed'), $mk(self::tlv(0x30, self::tlv(0x30, self::tlv(0x30, self::oid('1.3.14.3.2.26')), self::tlv(0x04, 'a'), self::tlv(0x04, 'b')), "\x80\x00", self::tlv(0x18, self::gt($now)))));
        // a single response with an unknown hash is skipped, the next one still matches
        $unknown = self::single($w['leaf'], $w['ca'], ['hashOid' => '1.2.840.113549.2.5']);
        $this->assertSame(self::good(), $mk($unknown, $ok));
        $this->assertSame(self::failWith('no SingleResponse matches the certificate (serial / issuer hashes differ)'), $mk($unknown));
        $this->assertSame(self::failWith('ambiguous: multiple SingleResponses match the certificate'), $mk($ok, $ok));
    }

    // ---- verifyResponse: freshness ----------------------------------------------------------------------------------------------

    public function testFreshnessBoundaries(): void
    {
        $now = self::now();
        // thisUpdate == now is accepted with the default skew, 1 ms later is in the future
        $this->assertSame(self::good(), self::runCase(self::resp(['this' => self::gt($now)])));
        $this->assertSame(self::failWith('response thisUpdate is in the future'), self::runCase(self::resp(['this' => self::gt($now, '001')])));
        // an explicit skew widens by exactly its value (and never narrows)
        $this->assertSame(self::good(), self::runCase(self::resp(['this' => self::gt($now + 1)]), ['skew' => 1000]));
        $this->assertSame(self::failWith('response thisUpdate is in the future'), self::runCase(self::resp(['this' => self::gt($now + 1, '001')]), ['skew' => 1000]));
        // producedAt
        $this->assertSame(self::good(), self::runCase(self::resp(['produced' => self::gt($now)])));
        $this->assertSame(self::failWith('response producedAt is in the future'), self::runCase(self::resp(['produced' => self::gt($now, '001')])));
        $this->assertSame(self::good(), self::runCase(self::resp(['produced' => self::gt($now + 1)]), ['skew' => 1000]));
        $this->assertSame(self::failWith('response producedAt is in the future'), self::runCase(self::resp(['produced' => self::gt($now + 1, '001')]), ['skew' => 1000]));
        // thisUpdate malformed tag
        $this->assertSame(self::rej('thisUpdate is malformed'), self::runCase(self::resp(['thisTlv' => self::tlv(0x17, self::ut($now - 3600))])));
    }

    public function testNextUpdateAndAge(): void
    {
        $now = self::now();
        // nextUpdate == thisUpdate == now: neither invalid nor stale
        $this->assertSame(self::good(), self::runCase(self::resp(['this' => self::gt($now), 'next' => self::gt($now)])));
        $this->assertSame(self::failWith('response nextUpdate is invalid'), self::runCase(self::resp(['this' => self::gt($now), 'next' => self::gt($now - 1)])));
        $this->assertSame(self::failWith('response is stale (past nextUpdate)'), self::runCase(self::resp(['this' => self::gt($now - 100), 'next' => self::gt($now - 50)])));
        // age: exactly the maximum is accepted; without a nextUpdate the explicit maximum applies
        $old = self::resp(['this' => self::gt($now - 100), 'next' => null]);
        $this->assertSame(self::good(), self::runCase($old, ['maxAge' => 100000]));
        $this->assertSame(self::failWith('response is older than the maximum accepted age'), self::runCase($old, ['maxAge' => 99999]));
        $this->assertSame(self::good(), self::runCase($old));
        $this->assertSame(self::failWith('response is older than the maximum accepted age'), self::runCase(self::resp(['this' => self::gt($now - 8 * 86400), 'next' => null])));
    }

    // ---- verifyResponse: the responder -----------------------------------------------------------------------------------------

    public function testIssuerResponderIdentity(): void
    {
        $w = self::world();
        $noEmbedded = self::failWith('no embedded responder certificate verifies the response');
        // the responderID names someone else: signed by the CA key, but not the issuer's response
        $this->assertSame($noEmbedded, self::runCase(self::resp(['ridCert' => $w['leaf']])));
        $this->assertSame($noEmbedded, self::runCase(self::resp(['ridCert' => $w['leaf'], 'rid' => 'key'])));
        // the responderID names the issuer but the signature is not the issuer's
        $this->assertSame(self::failWith('OCSP response signature does not verify under the issuer key'), self::runCase(self::resp(['signer' => $w['k']['rogue']])));
        $this->assertSame(self::failWith('OCSP response signature does not verify under the issuer key'), self::runCase(self::resp(['rid' => 'key', 'signer' => $w['k']['rogue']])));
    }

    public function testSignatureIsExactlyTheBitString(): void
    {
        $w = self::world();
        // embedded certificates after the signature must not be read as part of it
        $this->assertSame(self::good(), self::runCase(self::resp(['certs' => [self::dcert()->raw]])));
        $this->assertSame(self::good(), self::runCase(self::resp(['certs' => [self::dcert()->raw, $w['ca']->raw]])));
    }

    public function testDelegatedResponder(): void
    {
        $w = self::world();
        $resp = self::dcert();
        $mk = static fn(array $certs, array $o = []): string => self::resp($o + ['ridCert' => $resp, 'signer' => $w['k']['resp'], 'certs' => array_map(static fn(Cert $c): string => $c->raw, $certs)]);
        $delegated = self::good('delegated');
        $this->assertSame($delegated, self::runCase($mk([$resp])));
        // an unrelated certificate first: skipped, the next one is used
        $other = self::dcert(['subject' => self::dn('other'), 'key' => $w['k']['resp2']]);
        $this->assertSame($delegated, self::runCase($mk([$other, $resp])));
        $this->assertSame(self::failWith('embedded certificates do not match the responderID'), self::runCase($mk([$other])));
        $this->assertSame(self::failWith('no embedded responder certificate verifies the response'), self::runCase($mk([])));
        // the responder certificate is not the one that signed
        $wrongKey = self::dcert(['key' => $w['k']['resp2']]);
        $this->assertSame(self::failWith('OCSP response signature does not verify under the delegated responder key'), self::runCase($mk([$wrongKey])));
        $this->assertSame($delegated, self::runCase($mk([$wrongKey, $resp])));
        // an OCSPSigning EKU is required
        $serverOnly = self::dcert(['exts' => [self::ekuExt([self::SERVER_AUTH])]]);
        $noEku = self::dcert(['exts' => []]);
        $lacks = self::failWith('delegated responder certificate lacks the id-kp-OCSPSigning EKU');
        $this->assertSame($lacks, self::runCase($mk([$serverOnly])));
        $this->assertSame($lacks, self::runCase($mk([$noEku])));
        $this->assertSame($delegated, self::runCase($mk([$serverOnly, $resp])));
        $this->assertSame($delegated, self::runCase($mk([$noEku, $resp])));
    }

    public function testDelegatedResponderValidityWindow(): void
    {
        $w = self::world();
        $now = self::now();
        $mk = static function (Cert $c, array $o = []) use ($w): string {
            return self::resp($o + ['ridCert' => $c, 'signer' => $w['k']['resp'], 'certs' => [$c->raw]]);
        };
        $window = self::failWith('delegated responder certificate is outside its validity window');
        $good = self::dcert();
        $expired = self::dcert(['validity' => self::valid($now - 86400, $now - 1)]);
        $future = self::dcert(['validity' => self::valid($now + 10, $now + 86400)]);
        $this->assertSame($window, self::runCase($mk($expired)));
        $this->assertSame($window, self::runCase($mk($future)));
        $this->assertSame(self::good('delegated'), self::runCase(self::resp(['ridCert' => $good, 'signer' => $w['k']['resp'], 'certs' => [$expired->raw, $good->raw]])));
        // both bounds are inclusive
        $this->assertSame(self::good('delegated'), self::runCase($mk(self::dcert(['validity' => self::valid($now, $now + 86400)]))));
        $this->assertSame(self::good('delegated'), self::runCase($mk(self::dcert(['validity' => self::valid($now - 86400, $now)]))));
        // the clock skew moves notBefore earlier by its value
        $soon = self::dcert(['validity' => self::valid($now + 500, $now + 86400)]);
        $this->assertSame(self::good('delegated'), self::runCase($mk($soon), ['skew' => 600000]));
        $this->assertSame($window, self::runCase($mk($soon), ['skew' => 400000]));
        // a bound that is not a well-formed time fails closed
        // (a UTF8String is no time tag: the response-wide time scan leaves it alone, the validity reader does not take it)
        $badNb = self::dcert(['validity' => self::tlv(0x30, self::tlv(0x0C, '250101000000Z'), self::tlv(0x17, '350101000000Z'))]);
        $badNa = self::dcert(['validity' => self::tlv(0x30, self::tlv(0x17, '250101000000Z'), self::tlv(0x0C, '350101000000Z'))]);
        $this->assertSame($window, self::runCase($mk($badNb)));
        $this->assertSame($window, self::runCase($mk($badNa)));
    }

    public function testDelegatedResponderIsSignedByTheChain(): void
    {
        $w = self::world();
        $notSigned = self::failWith('delegated responder certificate is not signed by the supplied NVIDIA chain');
        $mk = static fn(Cert $c): string => self::resp(['ridCert' => $c, 'signer' => $w['k']['resp'], 'certs' => [$c->raw]]);
        // the issuer name is right, the signature is not
        $this->assertSame($notSigned, self::runCase($mk(self::dcert(['signer' => $w['k']['rogue']]))));
        // the signature is right, the issuer name is not
        $this->assertSame($notSigned, self::runCase($mk(self::dcert(['issuer' => self::dn('notca')]))));
        // chain handling: signed by the issuer when the issuer is not in the chain at all
        $this->assertSame(self::good('delegated'), self::runCase($mk(self::dcert()), ['chain' => []]));
        // ... and then a certificate of the (unrelated) chain does not count
        $rogueCa = new Cert(self::certDer(['issuer' => self::dn('rogueca'), 'subject' => self::dn('rogueca'), 'key' => $w['k']['rogue'], 'signer' => $w['k']['rogue']]));
        $byRogue = self::dcert(['issuer' => self::dn('rogueca'), 'signer' => $w['k']['rogue']]);
        $this->assertSame($notSigned, self::runCase($mk($byRogue), ['chain' => [$rogueCa]]));
        // at or above the issuer counts, below it does not
        $byRoot = self::dcert(['issuer' => $w['rootDn'], 'signer' => $w['k']['root']]);
        $this->assertSame(self::good('delegated'), self::runCase($mk($byRoot), ['chain' => [$w['ca'], $w['root']]]));
        $this->assertSame($notSigned, self::runCase($mk($byRoot), ['chain' => [$w['ca']]]));
        $byLeaf = self::dcert(['issuer' => $w['leafDn'], 'signer' => $w['k']['leaf']]);
        $this->assertSame($notSigned, self::runCase($mk($byLeaf)));
        // the first occurrence of the issuer in the chain decides
        $dev = new Cert(self::certDer(['issuer' => $w['caDn'], 'subject' => self::dn('dev'), 'key' => $w['k']['dev'], 'signer' => $w['k']['ca']]));
        $byDev = self::dcert(['issuer' => self::dn('dev'), 'signer' => $w['k']['dev']]);
        $this->assertSame(self::good('delegated'), self::runCase($mk($byDev), ['chain' => [$w['ca'], $dev, $w['ca']]]));
        $this->assertSame($notSigned, self::runCase($mk($byDev), ['chain' => [$w['ca'], $w['root']]]));
    }

    public function testLaterCandidatesAreNotEvaluatedAfterAHit(): void
    {
        $w = self::world();
        $bogusSpki = self::tlv(0x30, self::tlv(0x30, self::oid('1.2.3.4')), self::tlv(0x03, "\0\x01\x02"));
        // a later chain member whose key cannot be loaded: reached only if the signer loop did not stop at the CA
        $weirdCa = new Cert(self::certDer(['issuer' => $w['rootDn'], 'subject' => $w['caDn'], 'spki' => $bogusSpki, 'signer' => $w['k']['root'], 'serial' => "\x0C"]));
        $resp = self::dcert();
        $der = self::resp(['ridCert' => $resp, 'signer' => $w['k']['resp'], 'certs' => [$resp->raw]]);
        $this->assertSame(self::good('delegated'), self::runCase($der, ['chain' => [$w['ca'], $weirdCa]]));
        // a later embedded candidate whose key cannot be loaded: reached only if the candidate loop did not stop at the first hit
        $bogus = self::dcert(['spki' => $bogusSpki, 'serial' => "\x08"]);
        $der = self::resp(['ridCert' => $resp, 'signer' => $w['k']['resp'], 'certs' => [$resp->raw, $bogus->raw]]);
        $this->assertSame(self::good('delegated'), self::runCase($der));
    }

    // ---- checkNvidiaChain ------------------------------------------------------------------------------------------------------

    public function testChainTooShort(): void
    {
        $w = self::world();
        $this->assertSame(['ok' => false, 'reason' => 'chain too short for OCSP'], Ocsp::checkNvidiaChain([], ['x'], 1.0));
        $this->assertSame(['ok' => false, 'reason' => 'chain too short for OCSP'], Ocsp::checkNvidiaChain([$w['leaf']], ['x'], 1.0));
        $this->assertSame(['ok' => false, 'reason' => 'no OCSP responses supplied'], Ocsp::checkNvidiaChain([$w['leaf'], $w['ca']], [], 1.0));
    }

    /** @return array<string,mixed> */
    private static function chainResponses(): array
    {
        $w = self::world();
        return [
            'leaf' => self::resp(),
            'leafRevoked' => self::resp(['status' => 'revoked']),
            'leafUnknown' => self::resp(['status' => 'unknown']),
            'leafStale' => self::resp(['this' => self::gt(self::now() - 100), 'next' => self::gt(self::now() - 10)]),
            'unrelated' => self::resp(['serial' => "\x77\x77"]),
            'ca' => self::resp(['cert' => $w['ca'], 'issuer' => $w['root'], 'signer' => $w['k']['root']]),
        ];
    }

    public function testChainResults(): void
    {
        $w = self::world();
        $r = self::chainResponses();
        $now = (float)(self::now() * 1000);
        $chain = [$w['leaf'], $w['ca'], $w['root']];
        $this->assertSame(
            ['ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 1, 'statuses' => [0 => 'good', 1 => 'absent']],
            Ocsp::checkNvidiaChain($chain, [$r['leaf']], $now),
        );
        $this->assertSame(
            ['ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 2, 'statuses' => [0 => 'good', 1 => 'good']],
            Ocsp::checkNvidiaChain($chain, [$r['leaf'], $r['ca']], $now),
        );
        $this->assertSame(
            ['ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 1, 'statuses' => [0 => 'good']],
            Ocsp::checkNvidiaChain([$w['ca'], $w['root']], [$r['ca']], $now),
        );
        $this->assertSame(
            ['ok' => false, 'reason' => 'duplicate OCSP responses for chain certificate #0', 'statuses' => [0 => 'good', 1 => 'absent']],
            Ocsp::checkNvidiaChain($chain, [$r['leaf'], $r['leaf']], $now),
        );
        $this->assertSame(
            ['ok' => false, 'reason' => "chain certificate 'C=US, CN=leaf' is revoked (OCSP)", 'statuses' => [0 => 'revoked', 1 => 'absent']],
            Ocsp::checkNvidiaChain($chain, [$r['leafRevoked']], $now),
        );
        $this->assertSame(
            ['ok' => false, 'reason' => "OCSP response #0 for 'C=US, CN=leaf' rejected: response is stale (past nextUpdate)", 'statuses' => [0 => 'absent', 1 => 'absent']],
            Ocsp::checkNvidiaChain($chain, [$r['leafStale']], $now),
        );
        $this->assertSame(
            ['ok' => false, 'reason' => 'OCSP response #0 rejected: ' . self::NO_MATCH, 'statuses' => [0 => 'absent', 1 => 'absent']],
            Ocsp::checkNvidiaChain($chain, [$r['unrelated']], $now),
        );
        $this->assertSame(
            ['ok' => false, 'reason' => 'OCSP response #1 rejected: ' . self::NO_MATCH, 'statuses' => [0 => 'good', 1 => 'absent']],
            Ocsp::checkNvidiaChain($chain, [$r['leaf'], $r['unrelated']], $now),
        );
    }

    public function testRequiredCertificatesNeedAGoodResponse(): void
    {
        $w = self::world();
        $r = self::chainResponses();
        $now = (float)(self::now() * 1000);
        $chain = [$w['leaf'], $w['ca'], $w['root']];
        $this->assertSame(
            ['ok' => false, 'reason' => "no GOOD OCSP response for required certificate 'C=US, CN=leaf' (status: absent)", 'statuses' => [0 => 'absent', 1 => 'good']],
            Ocsp::checkNvidiaChain($chain, [$r['ca']], $now),
        );
        $this->assertSame(
            ['ok' => false, 'reason' => "no GOOD OCSP response for required certificate 'C=US, CN=leaf' (status: unknown)", 'statuses' => [0 => 'unknown', 1 => 'absent']],
            Ocsp::checkNvidiaChain($chain, [$r['leafUnknown']], $now),
        );
    }

    public function testOneResponseMatchingTwoChainCertificates(): void
    {
        $w = self::world();
        $k = $w['k'];
        $m = self::dn('M');
        // c0 and c1 share a serial; c1 and c2 share a subject and key, so one CertID speaks for both c0 (issuer c1) and c1 (issuer c2)
        $c0 = new Cert(self::certDer(['issuer' => $m, 'subject' => self::dn('A'), 'key' => $k['leaf'], 'signer' => $k['mid'], 'serial' => "\x05"]));
        $c1 = new Cert(self::certDer(['issuer' => $w['rootDn'], 'subject' => $m, 'key' => $k['mid'], 'signer' => $k['root'], 'serial' => "\x05"]));
        $c2 = new Cert(self::certDer(['issuer' => $w['rootDn'], 'subject' => $m, 'key' => $k['mid'], 'signer' => $k['root'], 'serial' => "\x09"]));
        $der = self::resp(['cert' => $c0, 'issuer' => $c1, 'signer' => $k['mid']]);
        $this->assertSame(
            ['ok' => false, 'reason' => 'OCSP response #0 matches more than one chain certificate', 'statuses' => [0 => 'good', 1 => 'absent', 2 => 'absent']],
            Ocsp::checkNvidiaChain([$c0, $c1, $c2, $w['root']], [$der], (float)(self::now() * 1000)),
        );
    }
}
