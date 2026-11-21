<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\CertError;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\JsError;
use Atlas\Pca\Attest\PubKey;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for the shared helpers in Attest/Common.php: PubKey::bits, JSON accessors, the attestation binding, the JavaScript
 * BigInt / Buffer / trim emulations, compact JWS parsing, PEM and DER readers, EC / RSA key builders, raw ECDSA and RSASSA-PSS
 * verification (over signatures made here with keys generated at load, including hand-forged encodings). Expectations follow
 * packages/pca/src/attest-common.ts and the RFC 8017 EMSA-PSS-VERIFY steps.
 */
final class K05KillAttestCommon1Test extends TestCase
{
    private const DSA_SPKI = 'MIIBtzCCASwGByqGSM44BAEwggEfAoGBANvPRYeDqfaPE3CrwwLpkSucIhLX3/OqQpxPt2nZ/1VDrUWMQx2tjZy/v29Q9iymi77naMoy1vQIUZQPpsCvpapSCxeupKj1T1hpSGsQf9HNscaMPf39e0qQBidoY4d71cEyS9Pl0QIUxQ1EdkdEM/upLsjiu3wlToMEeDD0c7rFAhUAs39pjOFphkDg0rncI+yv6z6sYVECgYEA1JGVIhXfK84GP79xlwYr318qsdCPa+/gUApzqY5IgNVcVjNLoTFpXzGC1umQR+rDjqgz0Sn9fACF9Syq30JAYkocu+9m4oasrmg1kV3KYXvDoGgGYTX3Dy+MhLiys1kUq1OEpmUKmySkl+XJlIl9TiVzzV+T9oKD3cgEQ5mOd6gDgYQAAoGAdAnUN23NNDBSMFNlcbAj5thlbf4slwzoknQiYOUZE2swezKoSI7CTvVJXkJmTO2NJkOZIiWgo4di/i2rK+MLHRClKcrkikdPRYG1P9RpGlZhWHzvAbrXkVOw0HYag2RhWmenmjgN05tw4wPhZoT1kjYcrl+Fra6ouI+GcZ4/7Yo=';
    private const DH_SPKI = 'MIICJDCCARcGCSqGSIb3DQEDATCCAQgCggEBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKrKpo//////////8CAQIDggEFAAKCAQB2rHm+KjmO/R+5S406c7t0CkDXsUwW3wi4MubEJyTcXR+9YCTeyhSRfCjDNytjSiXmOlhwqmrxOw/OvplZBy9jvqTrTRKrAI+tc/7eEiZMPHjKjd3H2zsYg2KaI1QLw5KWcSiErrtckMMClw9fslcUqedz+QEPETX3N4Yol84pzgs43adHP6r47z+rXXKFspqSdxjIaUamDJmKXl/zG5zJ7C2RQNRHvqXO4JRcfsrVIGtUstBkrjAZb0jeelRcxImF/vMrHiA2P63GqLPdiGnOdLV7V9wbGzHXcS9Pc4N3Z7F8qcdYPjTXD1Ztrd2K6auZ0V3RClBDkUhXnXVlFAhl';
    private const FALLBACK = 'error:1E08010C:DECODER routines::unsupported';

    // ------------------------------------------------------------------------------------------------------------- builders

    private static function priv(string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Common::class, $method))->invoke(null, ...$args);
    }

    private static function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('nothing was thrown');
    }

    /** Runs $f with every PHP warning turned into an exception (a mutant that reads past the end warns instead of failing). */
    private static function strictly(callable $f): mixed
    {
        set_error_handler(static function (int $no, string $str): bool {
            throw new \ErrorException($str, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    private static function cnf(): string
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        return $cnf;
    }

    private static function derOfPem(string $pem): string
    {
        return (string)base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem));
    }

    /** @return array{key: \OpenSSLAsymmetricKey, spki: string, x: string, y: string} */
    private static function ec(string $curve): array
    {
        static $keys = [];
        if (!isset($keys[$curve])) {
            $cnf = self::cnf();
            $k = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
            unlink($cnf);
            $d = openssl_pkey_get_details($k);
            $keys[$curve] = ['key' => $k, 'spki' => self::derOfPem($d['key']), 'x' => $d['ec']['x'], 'y' => $d['ec']['y']];
        }
        return $keys[$curve];
    }

    private static function anyKey(): \OpenSSLAsymmetricKey
    {
        return self::ec('prime256v1')['key'];
    }

    /** A PubKey whose fields are set by hand (the OpenSSL handle is never used by the functions that return before it). */
    private static function fake(string $type, ?string $curve = null, array $details = [], ?string $n = null, ?string $e = null): PubKey
    {
        return new PubKey(self::anyKey(), '', $type, $curve, $details, $n, $e);
    }

    /** @return array{key: \OpenSSLAsymmetricKey, n: string, e: string, d: \GMP, bits: int, spki: string} */
    private function rsa(int $bits): array
    {
        static $keys = [];
        if (!isset($keys[$bits])) {
            for ($try = 0; $try < 40; $try++) {
                $cnf = self::cnf();
                $k = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
                unlink($cnf);
                if ($k === false) {
                    continue;
                }
                $d = openssl_pkey_get_details($k);
                if (strlen(gmp_strval(gmp_import($d['rsa']['n']), 2)) === $bits) {
                    $keys[$bits] = ['key' => $k, 'n' => $d['rsa']['n'], 'e' => $d['rsa']['e'], 'd' => gmp_import($d['rsa']['d']), 'bits' => $bits, 'spki' => self::derOfPem($d['key'])];
                    break;
                }
            }
        }
        if (!isset($keys[$bits])) {
            $this->markTestSkipped("no $bits-bit RSA key could be generated here");
        }
        return $keys[$bits];
    }

    private static function b64u(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    // ------------------------------------------------------------------------------------------------------------- PubKey / accessors

    public function testPubKeyBitsIsAnIntWithAZeroDefault(): void
    {
        $this->assertSame(256, self::fake('ec', null, ['bits' => '256'])->bits());
        $this->assertSame(521, self::fake('ec', null, ['bits' => 521])->bits());
        $this->assertSame(0, self::fake('ec')->bits());
    }

    public function testHasAndMembersAndIsList(): void
    {
        $this->assertTrue(Common::has(['a' => 1], 'a'));
        $this->assertFalse(Common::has(['a' => 1], 'b'));
        $this->assertTrue(Common::has(['a' => null], 'a'));
        $this->assertFalse(Common::has('a', 'a'));
        $this->assertTrue(Common::has(Obj::of(['a' => 1]), 'a'));
        $this->assertFalse(Common::has(Obj::of(['a' => 1]), 'b'));
        $this->assertSame(['a' => 1, 'b' => 2], Common::members(Obj::of(['a' => 1, 'b' => 2])));
        $this->assertSame(['x' => 1], Common::members(['x' => 1]));
        $this->assertSame([], Common::members([1, 2]));
        $this->assertSame([], Common::members('s'));
        $this->assertSame(['a', 'b'], Common::asStrList(['a', 'b']));
        $this->assertSame([], Common::asStrList([]));
        $this->assertNull(Common::asStrList(['a', 1]));
        $this->assertNull(Common::asStrList([1]));
        $this->assertNull(Common::asStrList(['a' => 'b']));
    }

    public function testNumOfAndIsIntKeepFloatSemantics(): void
    {
        $this->assertSame(5.0, Common::numOf(5));
        $this->assertSame(1.5, Common::numOf(new Num('1.5')));
        $this->assertNull(Common::numOf(INF));
        $this->assertNull(Common::numOf('5'));
        $this->assertTrue(Common::isInt(new Num('3')));
        $this->assertTrue(Common::isInt(3.0));
        $this->assertFalse(Common::isInt(new Num('3.5')));
        $this->assertFalse(Common::isInt(2.5));
        $this->assertFalse(Common::isInt(null));
    }

    public function testToHexAndOpensslErrorArePublic(): void
    {
        $this->assertSame('6162', Common::toHex('ab'));
        Common::opensslError();
        $this->assertSame('', Common::opensslError());
    }

    public function testOpensslErrorReturnsTheLastQueuedError(): void
    {
        Common::opensslError();
        @openssl_pkey_get_public('garbage');
        $this->assertNotSame('', Common::opensslError());
        $this->assertSame('', Common::opensslError());
    }

    // ------------------------------------------------------------------------------------------------------------- the binding

    private static function bind(string $h, string $g, int $epoch, string $n): string
    {
        return hash('sha512', "atlas-pca/attest-bind/v1\0" . pack('N', strlen($h)) . $h . pack('N', strlen($g)) . $g . pack('J', $epoch) . pack('N', strlen($n)) . $n, true);
    }

    public function testBindingPrefersCamelCaseAndFallsBackToSnakeCase(): void
    {
        $both = ['holderPub' => 'hc', 'holder_pub' => 'hs', 'grantRef' => 'gc', 'grant_ref' => 'gs', 'epoch' => 7, 'nonce' => 'nn'];
        $this->assertSame(self::bind('hc', 'gc', 7, 'nn'), Common::attestationBinding($both));
        $snake = ['holder_pub' => 'hs', 'grant_ref' => 'gs', 'epoch' => 7, 'nonce' => 'nn'];
        $this->assertSame(self::bind('hs', 'gs', 7, 'nn'), Common::attestationBinding($snake));
        $this->assertSame(hash('sha256', self::bind('hs', 'gs', 7, 'nn'), true), Common::challengeSha256($snake));
    }

    public function testBindingEncodesALoneSurrogateAsReplacementCharacter(): void
    {
        $exp = ['holderPub' => "a\xED\xA0\x80b", 'grantRef' => "g\xED\xBF\xBF", 'epoch' => 1, 'nonce' => "\xED\xA0\x80"];
        $this->assertSame(self::bind("a\xEF\xBF\xBDb", "g\xEF\xBF\xBD", 1, "\xEF\xBF\xBD"), Common::attestationBinding($exp));
    }

    public function testBindingEpochBounds(): void
    {
        $base = ['holderPub' => 'h', 'grantRef' => 'g', 'nonce' => 'n'];
        $this->assertSame(self::bind('h', 'g', 9007199254740991, 'n'), Common::attestationBinding($base + ['epoch' => 9007199254740991]));
        $this->assertSame(self::bind('h', 'g', 9007199254740991, 'n'), Common::attestationBinding($base + ['epoch' => new Num('9007199254740991')]));
        $this->assertSame(self::bind('h', 'g', 0, 'n'), Common::attestationBinding($base + ['epoch' => 0]));
        foreach ([9007199254740992.0, -1, 1.5, '1', null] as $bad) {
            $e = self::thrown(static fn() => Common::attestationBinding($base + ['epoch' => $bad]));
            $this->assertInstanceOf(\TypeError::class, $e);
            $this->assertSame('binding: epoch must be a non-negative safe integer', $e->getMessage());
        }
    }

    // ------------------------------------------------------------------------------------------------------------- JS emulations

    public function testNodeBase64DecodeDropsTheLoneTrailingSextet(): void
    {
        $this->assertSame('ABC', Common::nodeB64Decode('QUJDR'));
        $this->assertSame('', Common::nodeB64Decode('Q'));
        $this->assertSame('AB', Common::nodeB64Decode('QUI'));
        $this->assertSame('A', Common::nodeB64Decode('QQ'));
        $this->assertSame('A', Common::nodeB64Decode('QQ==QQ'));
        $this->assertSame("\xFF\xEF", Common::nodeB64Decode('_-8'));
        $this->assertSame('ABC', Common::nodeB64Decode("Q U\nJD"));
        $this->assertSame('ABCDEF', Common::nodeB64Decode('QUJD!@#REVG'));
        $this->assertSame('', Common::nodeB64Decode(''));
    }

    public function testJsTrimIsTheEcmaScriptWhitespaceSet(): void
    {
        $this->assertSame('x', Common::jsTrim("\u{FEFF} \u{A0}x\u{2003}\u{3000}"));
        $this->assertSame('x', Common::jsTrim("\x0Cx\x0B"));
        $this->assertSame("\0x\0", Common::jsTrim("\0x\0"));
        $this->assertSame('a b', Common::jsTrim(" a b\n"));
        $this->assertSame("\xFF", Common::jsTrim(" \xFF "));
    }

    private static function bi(mixed $v): string
    {
        return gmp_strval(Common::bigInt($v));
    }

    public function testBigIntBooleansNumbersAndStrings(): void
    {
        $this->assertSame('1', self::bi(true));
        $this->assertSame('0', self::bi(false));
        $this->assertSame('5', self::bi(5));
        $this->assertSame('-5', self::bi(new Num('-5')));
        $this->assertSame('3', self::bi(3.0));
        $this->assertSame('100000000000000000000', self::bi(1e20));
        $this->assertSame('12', self::bi(new Num('12')));
        $this->assertSame('12345678901234567890', self::bi(new Num('12345678901234567890')));
        $this->assertSame('1', self::bi(new Num('1.0')));
        $this->assertSame('1000', self::bi(new Num('1e3')));
        $this->assertSame('0', self::bi(''));
        $this->assertSame('0', self::bi("  \u{FEFF}\n"));
        $this->assertSame('42', self::bi(' 42 '));
        $this->assertSame('-7', self::bi('-7'));
        $this->assertSame('5', self::bi('+5'));
        $this->assertSame('31', self::bi('0x1f'));
        $this->assertSame('31', self::bi('0X1F'));
        $this->assertSame('16', self::bi('0x10'));
        $this->assertSame('255', self::bi('0xff'));
        $this->assertSame('15', self::bi('0o17'));
        $this->assertSame('15', self::bi('0O17'));
        $this->assertSame('5', self::bi('0b101'));
        $this->assertSame('3', self::bi('0B11'));
    }

    public function testBigIntErrorTexts(): void
    {
        $cases = [
            [null, 'Cannot convert null to a BigInt'],
            [new Num('1.5'), 'The number 1.5 cannot be converted to a BigInt because it is not an integer'],
            [2.5, 'The number 2.5 cannot be converted to a BigInt because it is not an integer'],
            [INF, 'The number Infinity cannot be converted to a BigInt because it is not an integer'],
            [NAN, 'The number NaN cannot be converted to a BigInt because it is not an integer'],
            ['abc', 'Cannot convert abc to a BigInt'],
            [' abc', 'Cannot convert  abc to a BigInt'],
            ['1.5', 'Cannot convert 1.5 to a BigInt'],
            ['-0x1', 'Cannot convert -0x1 to a BigInt'],
            ['0xzz', 'Cannot convert 0xzz to a BigInt'],
            ['0o8', 'Cannot convert 0o8 to a BigInt'],
            ['0b2', 'Cannot convert 0b2 to a BigInt'],
            [[1, 2], 'Cannot convert 1,2 to a BigInt'],
            [Obj::of(['a' => 1]), 'Cannot convert [object Object] to a BigInt'],
        ];
        foreach ($cases as [$v, $msg]) {
            $e = self::thrown(static fn() => Common::bigInt($v));
            $this->assertInstanceOf(JsError::class, $e);
            $this->assertSame($msg, $e->getMessage());
        }
    }

    public function testIsHex(): void
    {
        $this->assertTrue(Common::isHex('ab'));
        $this->assertTrue(Common::isHex('ABcd01'));
        $this->assertFalse(Common::isHex('abc'));
        $this->assertFalse(Common::isHex(''));
        $this->assertFalse(Common::isHex('zz'));
        $this->assertFalse(Common::isHex("ab\n\n"));
    }

    // ------------------------------------------------------------------------------------------------------------- compact JWS

    public function testParseJwsEmptyTokenTexts(): void
    {
        foreach ([null, '', 123] as $tok) {
            $e = self::thrown(static fn() => Common::parseJws($tok, 'maa'));
            $this->assertInstanceOf(\TypeError::class, $e);
            $this->assertSame('maa: empty token', $e->getMessage());
        }
    }

    public function testParseJwsScrubsInvalidUtf8IntoValidText(): void
    {
        $tok = self::b64u('{"alg":"ES256"}') . '.' . self::b64u("{\"a\":\"\xFF\",\"b\":\"é\"}") . '.' . self::b64u('sig');
        $r = Common::parseJws($tok, 'maa');
        $this->assertSame('ES256', $r['header']['alg']);
        $a = $r['payload']->get('a');
        $this->assertTrue(mb_check_encoding($a, 'UTF-8'));
        $this->assertNotSame("\xFF", $a);
        $this->assertSame('é', $r['payload']->get('b'));
        $this->assertSame('sig', $r['signature']);
    }

    // ------------------------------------------------------------------------------------------------------------- PEM

    public function testPemToDer(): void
    {
        $this->assertSame("\x01\x02", Common::pemToDer("-----BEGIN CERTIFICATE-----\nAQI=\n-----END CERTIFICATE-----"));
        foreach (['junk', '-----BEGIN CERTIFICATE----------END CERTIFICATE-----'] as $bad) {
            $e = self::thrown(static fn() => Common::pemToDer($bad));
            $this->assertInstanceOf(\InvalidArgumentException::class, $e);
            $this->assertSame('pemToDer: no certificate found', $e->getMessage());
        }
    }

    // ------------------------------------------------------------------------------------------------------------- loadPublicKey

    public function testPemOfSpkiWrapsAt64Columns(): void
    {
        $spki = self::ec('prime256v1')['spki'];
        $b64 = base64_encode($spki);
        $this->assertGreaterThan(64, strlen($b64));
        $this->assertSame("-----BEGIN PUBLIC KEY-----\n" . implode("\n", str_split($b64, 64)) . "\n-----END PUBLIC KEY-----\n", self::priv('pemOfSpki', $spki));
    }

    public function testLoadPublicKeyRefusesGarbageWithTheOpenSslText(): void
    {
        foreach (['garbage', "\x30\x00", ''] as $bad) {
            Common::opensslError();
            if (@openssl_pkey_get_public(self::priv('pemOfSpki', $bad)) !== false) {
                continue;
            }
            $why = Common::opensslError();
            $expected = $why !== '' ? $why : self::FALLBACK;
            $e = self::thrown(static fn() => Common::loadPublicKey($bad));
            $this->assertInstanceOf(CertError::class, $e);
            $this->assertSame($expected, $e->getMessage());
        }
    }

    public function testLoadPublicKeyDrainsStaleErrorsBeforeLoading(): void
    {
        $spki = self::ec('prime256v1')['spki'];
        $residue = static function (): array {
            $all = [];
            while (($m = openssl_error_string()) !== false) {
                $all[] = $m;
            }
            return $all;
        };
        $residue();
        Common::loadPublicKey($spki);
        $clean = $residue();   // what a load leaves behind by itself (nothing on newer PHP, a PEM probe on 8.1)
        @openssl_pkey_get_public('garbage');
        Common::loadPublicKey($spki);
        $this->assertSame($clean, $residue(), 'the stale error queued before the load is drained, not left behind');
    }

    public function testLoadPublicKeyTypes(): void
    {
        $ec = Common::loadPublicKey(self::ec('secp384r1')['spki']);
        $this->assertSame('ec', $ec->type);
        $this->assertSame('secp384r1', $ec->curve);
        $rsa = Common::loadPublicKey($this->rsa(1024)['spki']);
        $this->assertSame('rsa', $rsa->type);
        $this->assertNull($rsa->curve);
        $this->assertSame($this->rsa(1024)['n'], $rsa->rsaN);
        $dsa = Common::loadPublicKey((string)base64_decode(self::DSA_SPKI));
        $this->assertSame('dsa', $dsa->type);
        $this->assertNull($dsa->rsaN);
    }

    public function testLoadPublicKeyDhType(): void
    {
        try {
            $dh = Common::loadPublicKey((string)base64_decode(self::DH_SPKI));
        } catch (CertError $e) {
            $this->markTestSkipped('this OpenSSL build cannot load a DH SubjectPublicKeyInfo: ' . $e->getMessage());
        }
        $this->assertSame('dh', $dh->type);
    }

    // ------------------------------------------------------------------------------------------------------------- DER reader

    public function testTlvBoundaries(): void
    {
        $t = static fn(string $b, int $off = 0) => self::priv('tlv', $b, $off);
        $this->assertNull(self::strictly(static fn() => $t("\x30")));
        $this->assertNull(self::strictly(static fn() => $t('')));
        $this->assertSame([0x30, 2, 2], self::strictly(static fn() => $t("\x30\x00")));
        $this->assertSame([0x30, 3, 3], self::strictly(static fn() => $t("\x30\x81\x00")));
        $this->assertSame([0x30, 3, 6], self::strictly(static fn() => $t("\x30\x81\x03abc")));
        $this->assertSame([0x30, 6, 7], self::strictly(static fn() => $t("\x30\x84\x00\x00\x00\x01X")));
        $this->assertNull(self::strictly(static fn() => $t("\x30\x80abc")));
        $this->assertNull(self::strictly(static fn() => $t("\x30\x85\x00\x00\x00\x00\x01X")));
        $this->assertNull(self::strictly(static fn() => $t("\x30\x82\x01")));
        $this->assertNull(self::strictly(static fn() => $t("\x30\x05ab")));
        $this->assertSame([0x30, 2, 4], self::strictly(static fn() => $t("\x30\x02ab")));
    }

    /** @param array<string,mixed> $o */
    private static function spkiRsa(array $o = []): string
    {
        $n = self::tlv($o['nTag'] ?? 2, $o['nBytes'] ?? "\x00\xC5\x01\x02");
        $e = self::tlv($o['eTag'] ?? 2, $o['eBytes'] ?? "\x01\x00\x01");
        $content = $n . $e . ($o['seqTrail'] ?? '');
        $seq = chr($o['seqTag'] ?? 0x30) . chr(strlen($content) + ($o['declMore'] ?? 0)) . $content;
        $bits = self::tlv($o['bitsTag'] ?? 3, "\x00" . $seq);
        $alg = self::tlv($o['algTag'] ?? 0x30, self::tlv($o['oidTag'] ?? 6, $o['oid'] ?? "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01") . "\x05\x00");
        return self::tlv($o['outerTag'] ?? 0x30, $alg . $bits) . ($o['trail'] ?? '');
    }

    public function testRsaNeParsesTrimsAndChecksEveryTag(): void
    {
        $this->assertSame(["\xC5\x01\x02", "\x01\x00\x01"], self::priv('rsaNe', self::spkiRsa()));
        $this->assertSame(["\xC5\x01\x02", "\x01\x00\x01"], self::priv('rsaNe', self::spkiRsa(['oid' => "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0A"])));
        $this->assertSame(["\xC5\x01\x02", "\x01\x00\x01"], self::priv('rsaNe', self::spkiRsa(['eBytes' => "\x00\x01\x00\x01"])));
        $this->assertSame(["\xC5\x01\x02", "\x01\x00\x01"], self::priv('rsaNe', self::spkiRsa(['seqTrail' => "\x05\x00"])));
        $bad = [
            'outer tag' => ['outerTag' => 0x31],
            'algorithm tag' => ['algTag' => 0x31],
            'oid tag' => ['oidTag' => 0x07],
            'oid value' => ['oid' => "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B"],
            'bit string tag' => ['bitsTag' => 0x04],
            'key sequence tag' => ['seqTag' => 0x31],
            'modulus tag' => ['nTag' => 0x03],
            'exponent tag' => ['eTag' => 0x03],
        ];
        foreach ($bad as $why => $opts) {
            $this->assertNull(self::strictly(static fn() => self::priv('rsaNe', self::spkiRsa($opts))), $why);
        }
    }

    public function testRsaNeReadsOnlyTheBitStringContent(): void
    {
        // the key sequence claims one byte more than the bit string holds; the byte after the SPKI must not be read into it
        $this->assertNull(self::strictly(static fn() => self::priv('rsaNe', self::spkiRsa(['declMore' => 1, 'trail' => "\x00"]))));
    }

    public function testRsaNeTruncatedInputsAreNullWithoutWarnings(): void
    {
        foreach (['', "\x30", "\x30\x00", "\x30\x02\x30\x00", "\x30\x06\x30\x04\x06\x02\x2A\x86"] as $b) {
            $this->assertNull(self::strictly(static fn() => self::priv('rsaNe', $b)));
        }
        // no bit string after the algorithm; an empty bit string
        $alg0 = self::tlv(0x30, self::tlv(6, "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01") . "\x05\x00");
        $this->assertNull(self::strictly(static fn() => self::priv('rsaNe', self::tlv(0x30, $alg0))));
        $this->assertNull(self::strictly(static fn() => self::priv('rsaNe', self::tlv(0x30, $alg0, self::tlv(3, "\x00")))));
        // a modulus with no exponent after it
        $n = self::tlv(2, "\x00\xC5");
        $seq = self::tlv(0x30, $n);
        $alg = self::tlv(0x30, self::tlv(6, "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01") . "\x05\x00");
        $spki = self::tlv(0x30, $alg . self::tlv(3, "\x00" . $seq));
        $this->assertNull(self::strictly(static fn() => self::priv('rsaNe', $spki)));
    }

    // ------------------------------------------------------------------------------------------------------------- curves and points

    public function testJwkCurveNames(): void
    {
        $this->assertSame('P-256', Common::jwkCurve(self::fake('ec', 'prime256v1')));
        $this->assertSame('P-384', Common::jwkCurve(self::fake('ec', 'secp384r1')));
        $this->assertSame('P-521', Common::jwkCurve(self::fake('ec', 'secp521r1')));
        $this->assertNull(Common::jwkCurve(self::fake('rsa')));
        $this->assertSame('brainpoolP256r1', Common::jwkCurve(self::fake('ec', 'brainpoolP256r1')));
    }

    public function testEcPointPadsCoordinatesToTheCurveSize(): void
    {
        $d = ['ec' => ['x' => "\x01", 'y' => "\x02"]];
        $this->assertSame("\x04" . str_repeat("\0", 31) . "\x01" . str_repeat("\0", 31) . "\x02", Common::ecPoint(self::fake('ec', 'prime256v1', $d), 'P-256'));
        $this->assertSame("\x04" . str_repeat("\0", 47) . "\x01" . str_repeat("\0", 47) . "\x02", Common::ecPoint(self::fake('ec', 'secp384r1', $d), 'P-384'));
        $ec = self::ec('prime256v1');
        $real = Common::ecPoint(Common::loadPublicKey($ec['spki']), 'P-256');
        $this->assertSame(65, strlen($real));
        $this->assertSame("\x04", $real[0]);
    }

    public function testEcPointRefusals(): void
    {
        $e = self::thrown(static fn() => Common::ecPoint(self::fake('rsa'), 'P-256'));
        $this->assertInstanceOf(\TypeError::class, $e);
        $this->assertSame('public key is not EC (got rsa)', $e->getMessage());
        $e = self::thrown(static fn() => Common::ecPoint(self::fake('ec', 'prime256v1', ['ec' => ['x' => 'a', 'y' => 'b']]), 'P-384'));
        $this->assertSame('public key is not on P-384 (got P-256)', $e->getMessage());
    }

    public function testEcKeyFromPointRoundTripsAndRefusesOffCurvePoints(): void
    {
        foreach ([['P-256', 'prime256v1', 32], ['P-384', 'secp384r1', 48]] as [$crv, $name, $c]) {
            $ec = self::ec($name);
            $point = "\x04" . str_pad($ec['x'], $c, "\0", STR_PAD_LEFT) . str_pad($ec['y'], $c, "\0", STR_PAD_LEFT);
            $k = Common::ecKeyFromPoint($crv, $point);
            $this->assertSame($ec['spki'], $k->spki);
            $this->assertSame($name, $k->curve);
            $off = substr($point, 0, -1) . chr(ord($point[-1]) ^ 1);
            $e = self::thrown(static fn() => Common::ecKeyFromPoint($crv, $off));
            $this->assertInstanceOf(\ValueError::class, $e);
        }
    }

    private static function ecDer(string $curveOid, string $x, string $y): string
    {
        $alg = self::tlv(0x30, self::tlv(6, "\x2A\x86\x48\xCE\x3D\x02\x01"), self::tlv(6, $curveOid));
        return self::tlv(0x30, $alg, self::tlv(3, "\x00\x04" . $x . $y));
    }

    public function testEcSpkiPadsAndTrimsCoordinates(): void
    {
        $o256 = "\x2A\x86\x48\xCE\x3D\x03\x01\x07";
        $o384 = "\x2B\x81\x04\x00\x22";
        $o521 = "\x2B\x81\x04\x00\x23";
        $z = static fn(int $n, string $last) => str_repeat("\0", $n - 1) . $last;
        $this->assertSame(self::ecDer($o256, $z(32, "\x01"), $z(32, "\x02")), Common::ecSpki('P-256', "\x01", "\x02"));
        $this->assertSame(self::ecDer($o384, $z(48, "\x01"), $z(48, "\x02")), Common::ecSpki('P-384', "\x01", "\x02"));
        $this->assertSame(self::ecDer($o521, $z(66, "\x01"), $z(66, "\x02")), Common::ecSpki('P-521', "\x01", "\x02"));
        $five = str_repeat("\x05", 32);
        $this->assertSame(self::ecDer($o256, $five, $five), Common::ecSpki('P-256', "\0\0" . $five, "\0\0\0" . $five));
        foreach ([['P-256', 'prime256v1', 32], ['P-384', 'secp384r1', 48], ['P-521', 'secp521r1', 66]] as [$crv, $name, $c]) {
            $ec = self::ec($name);
            $this->assertSame($ec['spki'], Common::ecSpki($crv, $ec['x'], $ec['y']));
        }
    }

    // ------------------------------------------------------------------------------------------------------------- ECDSA / RSA PKCS#1

    private static function rawSig(string $der, int $half): string
    {
        $i = (ord($der[1]) & 0x80) !== 0 ? 2 + (ord($der[1]) & 0x7F) : 2;
        $rl = ord($der[$i + 1]);
        $r = substr($der, $i + 2, $rl);
        $i += 2 + $rl;
        $sl = ord($der[$i + 1]);
        $s = substr($der, $i + 2, $sl);
        return str_pad(ltrim($r, "\0"), $half, "\0", STR_PAD_LEFT) . str_pad(ltrim($s, "\0"), $half, "\0", STR_PAD_LEFT);
    }

    public function testEcdsaVerifyRawOnEveryCurve(): void
    {
        foreach ([['prime256v1', 32, 'sha256'], ['secp384r1', 48, 'sha384'], ['secp521r1', 66, 'sha512']] as [$name, $half, $hash]) {
            $ec = self::ec($name);
            $pub = Common::loadPublicKey($ec['spki']);
            openssl_sign('data', $der, $ec['key'], $hash);
            $raw = self::rawSig($der, $half);
            $this->assertSame(2 * $half, strlen($raw));
            $this->assertTrue(Common::ecdsaVerifyRaw($pub, $raw, 'data', $hash), $name);
            $this->assertFalse(Common::ecdsaVerifyRaw($pub, $raw, 'other', $hash), $name);
            $this->assertFalse(Common::ecdsaVerifyRaw($pub, substr($raw, 1), 'data', $hash), $name);
            $this->assertFalse(Common::ecdsaVerifyRaw($pub, $raw . "\0", 'data', $hash), $name);
            $this->assertFalse(Common::ecdsaVerifyRaw($pub, str_repeat("\0", 2 * $half), 'data', $hash), $name);
            $this->assertFalse(Common::ecdsaVerifyRaw($pub, str_repeat("\0", $half) . substr($raw, $half), 'data', $hash), $name);
            $this->assertFalse(Common::ecdsaVerifyRaw($pub, substr($raw, 0, $half) . str_repeat("\0", $half), 'data', $hash), $name);
            $this->assertTrue(Common::ecdsaVerifyDer($pub, $der, 'data', $hash), $name);
        }
    }

    public function testEcdsaRefusesNonEcKeys(): void
    {
        $rsa = self::fake('rsa');
        $this->assertFalse(Common::ecdsaVerifyDer($rsa, 'x', 'y', 'sha256'));
        $this->assertFalse(Common::ecdsaVerifyRaw($rsa, str_repeat("\1", 64), 'y', 'sha256'));
        $this->assertFalse(Common::rsaPssVerify(self::fake('ec', 'prime256v1'), 'x', 'y', 'sha256', 'sha256', 32));
        $this->assertFalse(Common::rsaPkcs1Verify(self::fake('ec', 'prime256v1'), 'x', 'y', 'sha256'));
    }

    public function testEcdsaVerifyDerLeavesNoErrorQueued(): void
    {
        $pub = Common::loadPublicKey(self::ec('prime256v1')['spki']);
        Common::opensslError();
        $this->assertFalse(Common::ecdsaVerifyDer($pub, 'not a der signature', 'data', 'sha256'));
        $this->assertFalse(openssl_error_string());
    }

    public function testRsaPkcs1VerifyAndItsErrorQueue(): void
    {
        $k = $this->rsa(1024);
        $pub = Common::loadPublicKey($k['spki']);
        openssl_sign('data', $sig, $k['key'], 'sha256');
        $this->assertTrue(Common::rsaPkcs1Verify($pub, $sig, 'data', 'sha256'));
        $this->assertFalse(Common::rsaPkcs1Verify($pub, $sig, 'other', 'sha256'));
        Common::opensslError();
        $this->assertFalse(Common::rsaPkcs1Verify($pub, str_repeat("\1", 10), 'data', 'sha256'));
        $this->assertFalse(openssl_error_string());
    }

    public function testDerLenForms(): void
    {
        $this->assertSame("\0", Common::derLen(0));
        $this->assertSame("\x7F", Common::derLen(127));
        $this->assertSame("\x81\x80", Common::derLen(128));
        $this->assertSame("\x81\xFF", Common::derLen(255));
        $this->assertSame("\x82\x01\x00", Common::derLen(256));
        $this->assertSame("\x30\x07\x02\x01\x01\x02\x02\x00\x80", Common::dssSignature("\x01", "\x80"));
    }

    // ------------------------------------------------------------------------------------------------------------- RSASSA-PSS

    private static function mgf(string $seed, int $len): string
    {
        $out = '';
        for ($c = 0; strlen($out) < $len; $c++) {
            $out .= hash('sha256', $seed . pack('N', $c), true);
        }
        return substr($out, 0, $len);
    }

    public function testMgf1TruncatesToTheRequestedLength(): void
    {
        $got = self::priv('mgf1', 'seed', 40, 'sha256');
        $this->assertSame(40, strlen($got));
        $this->assertSame(substr(hash('sha256', 'seed' . pack('N', 0), true) . hash('sha256', 'seed' . pack('N', 1), true), 0, 40), $got);
        $this->assertSame(hash('sha256', 'seed' . pack('N', 0), true), self::priv('mgf1', 'seed', 32, 'sha256'));
        $this->assertSame('', self::priv('mgf1', 'seed', 0, 'sha256'));
    }

    /**
     * EMSA-PSS-ENCODE with sha256 / MGF1-sha256, with knobs to forge malformed encodings.
     * @param array{bits: int} $k
     * @param array<string,mixed> $o db, hashSalt, sep, padByte, trailer
     */
    private static function pssEm(array $k, string $msg, string $salt, array $o = []): string
    {
        $emBits = $k['bits'] - 1;
        $emLen = intdiv($emBits + 7, 8);
        $mHash = hash('sha256', $msg, true);
        $padLen = $emLen - 32 - strlen($salt) - 2;
        $db = $o['db'] ?? (str_repeat("\0", $padLen) . ($o['sep'] ?? "\x01") . $salt);
        if (isset($o['padByte'])) {
            $db[1] = $o['padByte'];
        }
        $h = hash('sha256', str_repeat("\0", 8) . $mHash . ($o['hashSalt'] ?? $salt), true);
        $masked = $db ^ self::mgf($h, strlen($db));
        $z = 8 * $emLen - $emBits;
        if ($z > 0) {
            $masked[0] = chr(ord($masked[0]) & (0xFF >> $z));
        }
        return $masked . $h . chr($o['trailer'] ?? 0xBC);
    }

    /** @param array{n: string, d: \GMP, bits: int} $k */
    private static function rsaSign(array $k, string $em): string
    {
        $s = gmp_powm(gmp_import($em), $k['d'], gmp_import($k['n']));
        return str_pad(gmp_export($s), intdiv($k['bits'] + 7, 8), "\0", STR_PAD_LEFT);
    }

    /** @param array{key: \OpenSSLAsymmetricKey, n: string, e: string, bits: int} $k */
    private static function pubOf(array $k): PubKey
    {
        return new PubKey($k['key'], '', 'rsa', null, [], $k['n'], $k['e']);
    }

    private static function emLen(array $k): int
    {
        return intdiv($k['bits'] - 1 + 7, 8);
    }

    /** @return list<int> */
    private static function bitSizes(): array
    {
        return [1024, 1025, 1026];
    }

    public function testPssAcceptsGenuineSignaturesForEveryModulusSize(): void
    {
        foreach (self::bitSizes() as $bits) {
            $k = $this->rsa($bits);
            $pub = self::pubOf($k);
            foreach ([32, 20, 1, 0] as $saltLen) {
                $salt = $saltLen > 0 ? random_bytes($saltLen) : '';
                $sig = self::rsaSign($k, self::pssEm($k, 'msg', $salt));
                $this->assertTrue(Common::rsaPssVerify($pub, $sig, 'msg', 'sha256', 'sha256', $saltLen), "$bits/$saltLen");
                $this->assertFalse(Common::rsaPssVerify($pub, $sig, 'other', 'sha256', 'sha256', $saltLen), "$bits/$saltLen other message");
                $this->assertFalse(Common::rsaPssVerify($pub, $sig, 'msg', 'sha256', 'sha256', $saltLen + 1), "$bits/$saltLen other salt length");
            }
            $this->assertFalse(Common::rsaPssVerify($pub, self::rsaSign($k, self::pssEm($k, 'msg', random_bytes(32))), 'msg', 'sha256', 'sha256', -1), "$bits negative salt");
        }
    }

    public function testPssAcceptsTheLargestSalt(): void
    {
        foreach (self::bitSizes() as $bits) {
            $k = $this->rsa($bits);
            $max = self::emLen($k) - 32 - 2;
            $salt = random_bytes($max);
            $sig = self::rsaSign($k, self::pssEm($k, 'msg', $salt));
            $this->assertTrue(Common::rsaPssVerify(self::pubOf($k), $sig, 'msg', 'sha256', 'sha256', $max), (string)$bits);
            $this->assertFalse(Common::rsaPssVerify(self::pubOf($k), $sig, 'msg', 'sha256', 'sha256', $max + 1), (string)$bits);
        }
    }

    public function testPssRejectsASaltOneByteTooLong(): void
    {
        // emLen = hLen + sLen + 1: the encoding has no room for the 0x01 separator, so the last byte of the data block is read as it
        $k = $this->rsa(1024);
        $sLen = self::emLen($k) - 32 - 1;
        $db = "\0" . random_bytes($sLen - 2) . "\x01";
        $sig = self::rsaSign($k, self::pssEm($k, 'msg', '', ['db' => $db, 'hashSalt' => $db]));
        $this->assertFalse(Common::rsaPssVerify(self::pubOf($k), $sig, 'msg', 'sha256', 'sha256', $sLen));
    }

    public function testPssRejectsMalformedEncodings(): void
    {
        $k = $this->rsa(1024);
        $pub = self::pubOf($k);
        $salt = random_bytes(32);
        $this->assertTrue(Common::rsaPssVerify($pub, self::rsaSign($k, self::pssEm($k, 'msg', $salt)), 'msg', 'sha256', 'sha256', 32));
        $this->assertFalse(Common::rsaPssVerify($pub, self::rsaSign($k, self::pssEm($k, 'msg', $salt, ['trailer' => 0xBD])), 'msg', 'sha256', 'sha256', 32), 'trailer');
        $this->assertFalse(Common::rsaPssVerify($pub, self::rsaSign($k, self::pssEm($k, 'msg', $salt, ['padByte' => "\x07"])), 'msg', 'sha256', 'sha256', 32), 'padding');
        $this->assertFalse(Common::rsaPssVerify($pub, self::rsaSign($k, self::pssEm($k, 'msg', $salt, ['sep' => "\x02"])), 'msg', 'sha256', 'sha256', 32), 'separator');
    }

    public function testPssRejectsSetBitsAboveTheEncodedMessage(): void
    {
        foreach ([1024, 1026] as $bits) {
            $k = $this->rsa($bits);
            $z = 8 * self::emLen($k) - ($bits - 1);
            $this->assertGreaterThan(0, $z);
            $sig = null;
            for ($i = 0; $i < 300 && $sig === null; $i++) {
                $em = self::pssEm($k, 'msg', random_bytes(32));
                $em[0] = chr(ord($em[0]) | (0x80 >> ($z - 1)));
                if (gmp_cmp(gmp_import($em), gmp_import($k['n'])) < 0) {
                    $sig = self::rsaSign($k, $em);
                }
            }
            if ($sig === null) {
                $this->markTestSkipped('no forged encoding below the modulus');
            }
            $this->assertFalse(Common::rsaPssVerify(self::pubOf($k), $sig, 'msg', 'sha256', 'sha256', 32), (string)$bits);
        }
    }

    public function testPssRejectsOutOfRangeSignatures(): void
    {
        $k = $this->rsa(1025);
        $pub = self::pubOf($k);
        $sig = self::rsaSign($k, self::pssEm($k, 'msg', random_bytes(32)));
        $this->assertTrue(Common::rsaPssVerify($pub, $sig, 'msg', 'sha256', 'sha256', 32));
        // longer or shorter than the modulus is refused even when the number it carries is the genuine one
        $this->assertFalse(Common::rsaPssVerify($pub, "\0" . $sig, 'msg', 'sha256', 'sha256', 32));
        $this->assertFalse(Common::rsaPssVerify($pub, substr($sig, 1), 'msg', 'sha256', 'sha256', 32));
        // the genuine number plus the modulus is the same residue but out of range
        $c2 = gmp_add(gmp_import($sig), gmp_import($k['n']));
        $big = str_pad(gmp_export($c2), 129, "\0", STR_PAD_LEFT);
        $this->assertSame(129, strlen($big));
        $this->assertFalse(Common::rsaPssVerify($pub, $big, 'msg', 'sha256', 'sha256', 32));
        // the modulus itself
        $this->assertFalse(Common::rsaPssVerify($pub, str_pad($k['n'], 129, "\0", STR_PAD_LEFT), 'msg', 'sha256', 'sha256', 32));
    }

    public function testPssRefusesKeysWithoutRsaParameters(): void
    {
        $sig = str_repeat("\1", 128);
        $this->assertFalse(Common::rsaPssVerify(self::fake('rsa', null, [], null, "\x01\x00\x01"), $sig, 'm', 'sha256', 'sha256', 32));
        $this->assertFalse(Common::rsaPssVerify(self::fake('rsa', null, [], "\xC5\x01", null), $sig, 'm', 'sha256', 'sha256', 32));
        $this->assertFalse(Common::rsaPssVerify(self::fake('rsa', null, [], '', "\x01\x00\x01"), "\1", 'm', 'sha256', 'sha256', 32));
        $this->assertFalse(Common::rsaPssVerify(self::fake('rsa', null, [], null, null), $sig, 'm', 'sha256', 'sha256', 32));
    }
}
