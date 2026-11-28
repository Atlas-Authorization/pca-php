<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Ocsp;
use Atlas\Pca\Attest\OcspError;
use Atlas\Pca\Attest\Tlv;
use PHPUnit\Framework\TestCase;

/** Group 8 survivor kills for Atlas\Pca\Attest\Ocsp (PCA 0.6); helpers copied from BaseKillAttestOcsp1Test. */
final class HwSurvivorKill8OcspKillTest extends TestCase
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

    // ---- group 8 helpers ------------------------------------------------------------------------------------------------------

    private static function len(int $n): string
    {
        return $n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : ($n < 0x10000 ? "\x82" . pack('n', $n) : "\x83" . substr(pack('N', $n), 1)));
    }

    /** `$levels` nested SEQUENCEs around an empty one. */
    private static function nested(int $levels): string
    {
        $sizes = [2];
        for ($i = 1; $i < $levels; $i++) {
            $inner = $sizes[$i - 1];
            $sizes[$i] = 1 + strlen(self::len($inner)) + $inner;
        }
        $out = [];
        for ($i = $levels - 1; $i >= 1; $i--) {
            $out[] = "\x30" . self::len($sizes[$i - 1]);
        }
        $out[] = "\x30\x00";
        return implode('', $out);
    }

    private static function flat(int $n): string
    {
        return "\x30" . self::len($n * 2) . str_repeat("\x05\x00", $n);
    }

    private static function nonceExt(string $inner): string
    {
        return self::tlv(0x30, self::oid('1.3.6.1.5.5.7.48.1.2'), self::tlv(0x04, $inner));
    }

    /** A good-status response for the leaf whose tbsResponseData carries the given responseExtensions [1] element. */
    private static function withExts(string $a1): string
    {
        $w = self::world();
        $parts = [self::ridTlv($w['ca']), self::tlv(0x18, self::gt(self::now() - 3600)), self::tlv(0x30, self::single($w['leaf'], $w['ca'])), $a1];
        return self::resp(['tbsParts' => $parts]);
    }

    /** @return array<string,mixed> */
    private static function withNonce(string $der, string $nonce): array
    {
        $w = self::world();
        return Ocsp::verifyResponse($der, $w['leaf'], $w['ca'], [$w['leaf'], $w['ca'], $w['root']], (float)(self::now() * 1000), null, 0.0, $nonce);
    }

    /** A revoked response for the leaf whose RevokedInfo is `A1 { time, $tail }`. */
    private static function revoked(string $tail): string
    {
        $w = self::world();
        $cid = self::tlv(
            0x30,
            self::tlv(0x30, self::oid('1.3.14.3.2.26'), "\x05\x00"),
            self::tlv(0x04, sha1($w['ca']->subjectDer, true)),
            self::tlv(0x04, sha1(self::keyBits($w['ca']->spkiDer), true)),
            self::tlv(0x02, $w['leaf']->serial),
        );
        $single = self::tlv(0x30, $cid, self::tlv(0xA1, self::tlv(0x18, '20250101000000Z'), $tail), self::tlv(0x18, self::gt(self::now() - 3600)));
        return self::resp(['singles' => [$single]]);
    }

    /** @return array<string,mixed> */
    private static function detail(string $der): array
    {
        $w = self::world();
        return Ocsp::verifyResponse($der, $w['leaf'], $w['ca'], [$w['leaf'], $w['ca'], $w['root']], (float)(self::now() * 1000), null, 0.0, null, true);
    }

    // ---- DER walks ------------------------------------------------------------------------------------------------------------

    public function testWellFormedBerRefusesNestingPastTheDepthCap(): void
    {
        $ok = self::nested(101);
        $deep = self::nested(102);
        $this->assertTrue(self::priv('wellFormedBer', $ok, 0, strlen($ok)));
        $this->assertFalse(self::priv('wellFormedBer', $deep, 0, strlen($deep)));
    }

    public function testAsn1TimesWellFormedDepthAndNodeCaps(): void
    {
        $this->assertTrue(Ocsp::asn1TimesWellFormed(self::nested(101)));
        $this->assertFalse(Ocsp::asn1TimesWellFormed(self::nested(102)));
        $this->assertTrue(Ocsp::asn1TimesWellFormed(self::flat(9999)));
        $this->assertFalse(Ocsp::asn1TimesWellFormed(self::flat(10000)));
    }

    public function testAsn1TimesWellFormedUnreadableDerIsFalse(): void
    {
        $this->assertFalse(Ocsp::asn1TimesWellFormed(''));
        $this->assertFalse(Ocsp::asn1TimesWellFormed("\x30\x05\x01"));
    }

    // ---- verifyResponse -------------------------------------------------------------------------------------------------------

    public function testNonFiniteInputsAreRefusedIndividually(): void
    {
        $w = self::world();
        $chain = [$w['leaf'], $w['ca'], $w['root']];
        $want = ['ok' => false, 'reason' => 'nowMs and clockSkewMs must be finite and maxAgeMs a number'];
        $this->assertSame($want, Ocsp::verifyResponse('', $w['leaf'], $w['ca'], $chain, INF));
        $this->assertSame($want, Ocsp::verifyResponse('', $w['leaf'], $w['ca'], $chain, 1.0e12, null, INF));
        $this->assertSame($want, Ocsp::verifyResponse('', $w['leaf'], $w['ca'], $chain, 1.0e12, NAN));
        $this->assertSame(['ok' => false, 'reason' => 'response is not valid DER'], Ocsp::verifyResponse('', $w['leaf'], $w['ca'], $chain, 1.0e12, INF));
    }

    public function testATruncatedNestedChildOfAnOtherwiseCompleteTopElementIsNotValidDer(): void
    {
        $der = "\x30\x04\x0A\x01\x00\x05";
        $r = self::runCase($der);
        $this->assertSame(self::failWith('response is not valid DER'), $r);
    }

    public function testBasicResponseTruncatedInsideItsOctetStringIsNotRescuedByTrailingSiblings(): void
    {
        $w = self::world();
        $tbs = self::tbs($w['leaf'], $w['ca'], []);
        openssl_sign($tbs, $sig, $w['k']['ca'], OPENSSL_ALGO_SHA256);
        $b = self::tlv(0x30, $tbs, self::tlv(0x30, self::oid('1.2.840.10045.4.3.2')), self::tlv(0x03, "\0" . $sig), "\xA0\x02\x30\x00");
        $oid = self::oid('1.3.6.1.5.5.7.48.1.1');
        $this->assertSame(self::good(), self::runCase(self::resp(['rbk' => [$oid, self::tlv(0x04, $b)]])));
        $split = self::resp(['rbk' => [$oid, self::tlv(0x04, substr($b, 0, -4)), "\xA0\x02\x30\x00"]]);
        $this->assertSame(self::failWith('BasicOCSPResponse is not valid DER'), self::runCase($split));
    }

    // ---- nonce echo -----------------------------------------------------------------------------------------------------------

    public function testNonceControlEchoedInsideAnOctetString(): void
    {
        $der = self::withExts(self::tlv(0xA1, self::tlv(0x30, self::nonceExt(self::tlv(0x04, 'abc')))));
        $this->assertSame(self::good(), self::withNonce($der, 'abc'));
        $this->assertSame(self::failWith('response nonce does not match the request nonce'), self::withNonce($der, 'abd'));
    }

    public function testAnExtensionWithOnlyAnOidIsNotANonceEcho(): void
    {
        $oidOnly = self::tlv(0x30, self::oid('1.3.6.1.5.5.7.48.1.2'));
        $der = self::withExts(self::tlv(0xA1, self::tlv(0x30, $oidOnly)));
        $this->assertSame(self::failWith('response does not echo the nonce'), self::withNonce($der, 'abc'));
    }

    public function testAnExtensionWhoseFirstElementIsNotAnOidIsSkipped(): void
    {
        $odd = self::tlv(0x30, self::tlv(0x04, ''), self::tlv(0x04, 'abc'));
        $der = self::withExts(self::tlv(0xA1, self::tlv(0x30, $odd)));
        $this->assertSame(self::failWith('response does not echo the nonce'), self::withNonce($der, 'abc'));
    }

    public function testTheFirstNonceExtensionWinsAcrossExtensionsAndSequences(): void
    {
        $first = self::nonceExt(self::tlv(0x04, 'good'));
        $second = self::nonceExt(self::tlv(0x04, 'other'));
        $third = self::nonceExt(self::tlv(0x04, 'third'));
        $der = self::withExts(self::tlv(0xA1, self::tlv(0x30, $first, $second), self::tlv(0x30, $third)));
        $this->assertSame(self::good(), self::withNonce($der, 'good'));
    }

    public function testANonceValueIsUnwrappedOnlyWhenItIsExactlyOneOctetString(): void
    {
        $notOctet = self::withExts(self::tlv(0xA1, self::tlv(0x30, self::nonceExt("\x02\x01A"))));
        $this->assertSame(self::failWith('response nonce does not match the request nonce'), self::withNonce($notOctet, 'A'));
        $this->assertSame(self::good(), self::withNonce($notOctet, "\x02\x01A"));
        $trailing = self::withExts(self::tlv(0xA1, self::tlv(0x30, self::nonceExt("\x04\x01A\xFF"))));
        $this->assertSame(self::good(), self::withNonce($trailing, "\x04\x01A\xFF"));
        $this->assertSame(self::failWith('response nonce does not match the request nonce'), self::withNonce($trailing, 'A'));
    }

    // ---- revoked detail -------------------------------------------------------------------------------------------------------

    public function testRevokedWithAnEmptyReasonWrapperReadsNoReasonAndRaisesNoWarning(): void
    {
        $warnings = [];
        set_error_handler(static function (int $no, string $str) use (&$warnings): bool {
            $warnings[] = $str;
            return true;
        });
        try {
            $r = self::detail(self::revoked("\xA0\x00"));
        } finally {
            restore_error_handler();
        }
        $this->assertSame([], $warnings);
        $this->assertTrue($r['ok']);
        $this->assertSame('revoked', $r['status']);
        $this->assertSame(self::ms(2025, 1, 1), $r['revokedAt']);
        $this->assertArrayNotHasKey('revocationReason', $r);
    }

    public function testRevokedReasonIsReadOnlyFromAnEnumerated(): void
    {
        $r = self::detail(self::revoked(self::tlv(0xA0, "\x02\x01\x05")));
        $this->assertSame('revoked', $r['status']);
        $this->assertArrayNotHasKey('revocationReason', $r);
        $r = self::detail(self::revoked(self::tlv(0xA0, "\x0A\x01\x05")));
        $this->assertSame(5, $r['revocationReason']);
    }

    public function testRevocationReasonIsAlwaysAnInteger(): void
    {
        set_error_handler(static fn(int $no, string $str): bool => true);
        try {
            $r = self::detail(self::revoked(self::tlv(0xA0, "\x0A\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00")));
        } finally {
            restore_error_handler();
        }
        $this->assertSame('revoked', $r['status']);
        $this->assertIsInt($r['revocationReason']);
    }

    // ---- checkNvidiaChain -----------------------------------------------------------------------------------------------------

    public function testRequireGoodIndexZeroIsAcceptedAndChecksThatCertificate(): void
    {
        $w = self::world();
        $chain = [$w['leaf'], $w['ca'], $w['root']];
        $r = Ocsp::checkNvidiaChain($chain, [self::resp()], (float)(self::now() * 1000), null, ['requireGood' => [0]]);
        $this->assertSame(['ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 1, 'statuses' => [0 => 'good', 1 => 'absent']], $r);
        $r = Ocsp::checkNvidiaChain($chain, [self::resp()], (float)(self::now() * 1000), null, ['requireGood' => [1]]);
        $this->assertFalse($r['ok']);
        $this->assertStringContainsString("(status: absent)", $r['reason']);
    }

    public function testRequireGoodIndexMustBeANumber(): void
    {
        $w = self::world();
        $chain = [$w['leaf'], $w['ca'], $w['root']];
        $now = (float)(self::now() * 1000);
        foreach ([['0', 'string'], [null, 'NULL'], [true, 'boolean'], [[0], 'array']] as [$bad, $type]) {
            $r = Ocsp::checkNvidiaChain($chain, ['x'], $now, null, ['requireGood' => [$bad]]);
            $this->assertSame(['ok' => false, 'reason' => "requireGood index $type is not a non-root chain certificate"], $r);
        }
        foreach ([2, -1] as $bad) {
            $r = Ocsp::checkNvidiaChain($chain, ['x'], $now, null, ['requireGood' => [$bad]]);
            $this->assertFalse($r['ok']);
            $this->assertSame("requireGood index $bad is not a non-root chain certificate", $r['reason']);
        }
    }

    public function testClockSkewOptionIsCoercedToANumber(): void
    {
        $w = self::world();
        $r = Ocsp::checkNvidiaChain([$w['leaf'], $w['ca'], $w['root']], [self::resp()], (float)(self::now() * 1000), null, ['clockSkewMs' => '1000']);
        $this->assertTrue($r['ok']);
    }

    public function testDefaultClockSkewIsExactlyZero(): void
    {
        $w = self::world();
        $chain = [$w['leaf'], $w['ca'], $w['root']];
        $now = (float)(self::now() * 1000);
        $exact = Ocsp::checkNvidiaChain($chain, [self::resp(['this' => self::gt(self::now())])], $now);
        $this->assertSame(['ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => 1, 'statuses' => [0 => 'good', 1 => 'absent']], $exact);
        $late = Ocsp::checkNvidiaChain($chain, [self::resp(['this' => self::gt(self::now(), '001')])], $now);
        $this->assertFalse($late['ok']);
        $this->assertStringStartsWith("OCSP response #0 for '", $late['reason']);
        $this->assertStringEndsWith("' rejected: response thisUpdate is in the future", $late['reason']);
    }

    // ---- buildRequest ---------------------------------------------------------------------------------------------------------

    public function testDerLengthEncodingBoundaries(): void
    {
        $cases = [
            [127, "\x04\x7F"], [128, "\x04\x81\x80"], [255, "\x04\x81\xFF"], [256, "\x04\x82\x01\x00"], [300, "\x04\x82\x01\x2C"],
            [65535, "\x04\x82\xFF\xFF"], [65536, "\x04\x83\x01\x00\x00"], [70000, "\x04\x83\x01\x11\x70"],
        ];
        foreach ($cases as [$n, $header]) {
            $out = (string)self::priv('der', 0x04, str_repeat('a', $n));
            $this->assertSame(bin2hex($header), bin2hex(substr($out, 0, strlen($header))), "n=$n");
            $this->assertSame(strlen($header) + $n, strlen($out), "n=$n");
        }
    }

    public function testBuildRequestRefusesAnUnsupportedHash(): void
    {
        $w = self::world();
        try {
            Ocsp::buildRequest($w['leaf'], $w['ca'], null, 'md5');
            $this->fail('expected RangeException');
        } catch (\RangeException $e) {
            $this->assertSame('unsupported CertID hash md5', $e->getMessage());
        }
    }
}
