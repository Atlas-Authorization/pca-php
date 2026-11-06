<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\CertError;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\JsError;
use Atlas\Pca\Attest\JsJson;
use Atlas\Pca\Attest\Xml;
use Atlas\Pca\Attest\XmlElement;
use Atlas\Pca\Attest\XmlError;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use PHPUnit\Framework\TestCase;

/**
 * The issuer check against Node's X509Certificate checkIssued and parser, on really signed P-384 certificates generated at load.
 * Rows and verdicts are the ones read from Node 26 for the Ruby SDK (test/kill/bo_node_x509_checks.rb); those marked `stricter`
 * are ones Node takes and this SDK refuses, on purpose. Also: deep nesting in the JSON and DER decoders.
 */
final class K05NodeX509Test extends TestCase
{
    private const AK = "\x55\x1d\x23";
    private const SK = "\x55\x1d\x0e";

    private static function key(string $name): \OpenSSLAsymmetricKey
    {
        static $keys = [];
        if (!isset($keys[$name])) {
            $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
            file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
            $keys[$name] = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
            unlink($cnf);
        }
        return $keys[$name];
    }

    private static function spki(\OpenSSLAsymmetricKey $k): string
    {
        return (string)base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details($k)['key']));
    }

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : ($n < 0x10000 ? "\x82" . pack('n', $n) : "\x83" . substr(pack('N', $n), 1)))) . $v;
    }

    private static function b(int ...$bytes): string { return pack('C*', ...$bytes); }
    private static function oid(string $b): string { return self::tlv(0x06, $b); }
    private static function dn(string $cn, int $str = 0x0c): string { return self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, self::oid("\x55\x04\x03"), self::tlv($str, $cn)))); }
    private static function ext(string $id, string $v): string { return self::tlv(0x30, self::oid($id), self::tlv(0x04, $v)); }
    private static function upName(): string { return self::dn('up'); }
    private static function root(): string { return self::dn('root'); }
    private static function other(): string { return self::dn('nope'); }
    private static function keyid(): string { return self::tlv(0x80, self::b(7, 7, 7, 7)); }
    private static function skid(): string { return self::ext(self::SK, self::tlv(0x04, self::b(7, 7, 7, 7))); }
    private static function ak(string ...$m): string { return self::ext(self::AK, self::tlv(0x30, ...$m)); }
    private static function dir(string $n): string { return self::tlv(0xa4, $n); }
    private static function names(string ...$g): string { return self::tlv(0xa1, ...$g); }
    private static function ser(int ...$x): string { return self::tlv(0x82, self::b(...$x)); }
    private static function dns(): string { return self::tlv(0x82, 'a.example'); }
    private static function oe(string $oid, string $v): string { return self::tlv(0x30, self::oid($oid), self::tlv(0x04, $v)); }
    private static function x(int $last, string $v): string { return self::oe(self::b(0x55, 0x1d, $last), $v); }
    private static function u8(string $s): string { return self::tlv(0x0c, $s); }
    private static function uri(): string { return self::tlv(0x86, 'https://a'); }
    private static function cnOid(): string { return self::oid(self::b(0x55, 4, 3)); }
    private static function rdn(string ...$a): string { return self::tlv(0x31, ...$a); }
    private static function atv(string ...$a): string { return self::tlv(0x30, ...$a); }
    private static function nm(string ...$r): string { return self::tlv(0x30, ...$r); }
    private static function val(int $tag, int ...$bytes): string { return self::nm(self::rdn(self::atv(self::cnOid(), self::tlv($tag, self::b(...$bytes))))); }

    /** @param list<string> $exts */
    private static function cert(string $iss, string $sub, array $exts, string $serial, ?\OpenSSLAsymmetricKey $subjectKey = null, ?\OpenSSLAsymmetricKey $signer = null): string
    {
        $alg = self::tlv(0x30, self::oid(self::b(0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3)));
        $val = self::tlv(0x30, self::tlv(0x17, '250101000000Z'), self::tlv(0x17, '350101000000Z'));
        $e = $exts === [] ? [] : [self::tlv(0xa3, self::tlv(0x30, ...$exts))];
        $tbs = self::tlv(0x30, self::tlv(0xa0, self::tlv(0x02, self::b(2))), self::tlv(0x02, $serial), $alg, $iss, $val, $sub, self::spki($subjectKey ?? self::key('up')), ...$e);
        openssl_sign($tbs, $sig, $signer ?? self::key('root'), OPENSSL_ALGO_SHA384);
        return self::tlv(0x30, $tbs, $alg, self::tlv(0x03, "\0" . $sig));
    }

    /** @param list<string> $childExts @param list<string>|null $upExts */
    private static function issued(array $childExts, ?array $upExts = null): bool
    {
        $u = new Cert(self::cert(self::root(), self::upName(), $upExts ?? [self::skid()], self::b(0x11)));
        $leaf = new Cert(self::cert(self::upName(), self::dn('leaf'), $childExts, self::b(0x22), self::key('leaf'), self::key('up')));
        self::assertTrue($leaf->verify($u->publicKey()), 'not really signed');
        return $leaf->checkIssued($u);
    }

    private static function withNames(string ...$g): bool { return self::issued([self::ak(self::keyid(), self::tlv(0xa1, ...$g))]); }
    private static function later(string $n): bool { return self::withNames(self::dir(self::root()), self::dir($n)); }

    public function testAkidKeyIdSerialAndFirstDirectoryName(): void
    {
        $good = [
          [], [self::ak(self::keyid())], [self::ak()], [self::ak(self::keyid(), self::names(self::dir(self::root())), self::ser(0x11))], [self::ak(self::names(self::dir(self::root())), self::ser(0x11))],
          [self::ak(self::keyid(), self::ser(0x11))], [self::ak(self::keyid(), self::names(self::dns()), self::ser(0x11))], [self::ak(self::keyid(), self::names(self::dir(self::root()), self::dir(self::other())))],
          [self::ak(self::keyid(), self::tlv(0xa1))], [self::ext(self::AK, self::tlv(0x30, self::keyid()) . self::b(5, 0))]
        ];
        $bad = [
          [self::ak(self::tlv(0x80, self::b(8, 8, 8, 8)))], [self::ak(self::keyid(), self::ser(0x12))], [self::ak(self::keyid(), self::ser(0, 0x11))], [self::ak(self::keyid(), self::ser())],
          [self::ak(self::keyid(), self::ser(0xff, 0x80))], [self::ak(self::keyid(), self::names(self::dir(self::other())))], [self::ak(self::keyid(), self::names(self::dir(self::other())), self::ser(0x11))],
          [self::ak(self::keyid(), self::names(self::dns(), self::dir(self::other())))], [self::ak(self::keyid(), self::names(self::dir(self::other()), self::dir(self::root())))],
          [self::ak(self::keyid(), self::b(0xa1, 2, 0x30, 5))], [self::ak(self::keyid(), self::names(self::tlv(0x89, self::b(1))))], [self::ak(self::keyid(), self::names(self::tlv(0x8f, self::b(1))))],
          [self::ak(self::keyid(), self::names(self::tlv(0xa4, self::tlv(0x04, self::b(1)))))], [self::ak(self::keyid(), self::names(self::dir(self::root()), self::tlv(0xa4, self::tlv(0x04, self::b(1)))))],
          [self::ak(self::keyid(), self::names(self::tlv(0xa4, self::tlv(0x30, self::tlv(0x04, self::b(1))))))], [self::ak(self::keyid(), self::names(self::tlv(0xa4, self::root(), self::root())))],
          [self::ak(self::ser(0x11), self::keyid())], [self::ak(self::names(self::dir(self::root())), self::keyid())], [self::ak(self::ser(0x11), self::names(self::dir(self::root())))], [self::ak(self::keyid(), self::keyid())],
          [self::ak(self::tlv(0x04, self::b(1)))], [self::ak(self::tlv(0xa0, self::b(1)))], [self::ext(self::AK, self::tlv(0x04, self::b(1)))], [self::ak(self::keyid()), self::ak(self::keyid())],
          [self::ext(self::AK, '')], [self::ext(self::SK, self::tlv(0x30))], [self::skid(), self::skid()],
          # Node reads these two as the same name (X509_NAME_cmp); bytes stay stricter here
          [self::ak(self::keyid(), self::names(self::dir(self::dn('root', 0x13))))], [self::ak(self::keyid(), self::names(self::dir(self::dn('ROOT'))))]
        ];
        foreach ($good as $i => $c) {
            $this->assertTrue(self::issued($c), "good $i");
        }
        foreach ($bad as $i => $c) {
            $this->assertFalse(self::issued($c), "bad $i");
        }
    }

    public function testALaterAkidDirectoryNameDecodesInFull(): void
    {
        $this->assertTrue(self::withNames(self::dir(self::root())));
        $this->assertFalse(self::withNames(self::dir(self::other())));
        $good = [
          self::nm(), self::nm(self::rdn()), self::dn('later'), self::val(0x0c), self::val(0x13, 0xc3, 0xa9), self::val(0x16, 0xe9), self::val(0x14, 0xe9),
          self::nm(self::rdn(self::atv(self::oid(self::b(0x55, 4, 6)), self::u8('b')), self::atv(self::cnOid(), self::u8('a')))), self::nm(self::rdn(self::atv(self::cnOid(), self::u8('a'))), self::rdn(self::atv(self::cnOid(), self::u8('b'))))
        ];
        $bad = [
          self::nm(self::tlv(0x30)), self::nm(self::rdn(self::tlv(0x04, self::b(1)))), self::nm(self::rdn(self::atv(self::cnOid()))), self::nm(self::rdn(self::atv())), self::nm(self::rdn(self::atv(self::tlv(0x04, self::b(1)), self::u8('x')))),
          self::nm(self::rdn(self::atv(self::cnOid(), self::u8('x'), self::u8('y')))), self::nm(self::rdn(self::atv(self::tlv(0x06), self::u8('x')))), self::nm(self::rdn(self::atv(self::tlv(0x06, self::b(0x80, 1)), self::u8('x')))),
          self::nm(self::rdn(self::atv(self::tlv(0x06, self::b(0x55, 0x84)), self::u8('x')))), self::nm(self::rdn(self::atv(self::tlv(0x06, self::b(0x55, 0x80, 1)), self::u8('x')))),
          self::val(0x02, 1), self::val(0x05), self::val(0x0c, 0xc3, 0x28), self::val(0x1e, 0, 0x41, 0), self::val(0x1c, 0, 0, 0x41),
          self::nm(self::rdn(self::b(0x30, 0x09, 6, 3, 0x55, 4, 3, 0x0c, 9, 0x61, 0x61))), self::nm(self::rdn(self::atv(self::cnOid(), self::u8('x')), self::tlv(0x04, self::b(1)))),
          # stricter
          self::nm(self::rdn(self::atv(self::cnOid(), self::tlv(0x30)))), self::val(0x1e, 0, 0x41)
        ];
        foreach ($good as $i => $d) {
            $this->assertTrue(self::later($d), "good $i");
        }
        foreach ($bad as $i => $d) {
            $this->assertFalse(self::later($d), "bad $i");
        }
    }

    public function testEveryAkidGeneralNameDecodes(): void
    {
        $other = static fn(string ...$a): string => self::tlv(0xa0, ...$a);
        $good = [
          $other(self::cnOid(), self::tlv(0xa0, self::u8('x'))), self::tlv(0x81, self::b(0xe9)), self::tlv(0x82, self::b(0xe9)), self::tlv(0x82), self::tlv(0x86, self::b(0xe9)), self::tlv(0x87, self::b(1, 2, 3)), self::tlv(0x87)
        ];
        $bad = [
          $other(self::tlv(0x04, self::b(1))), $other(), $other(self::cnOid()), $other(self::tlv(0x04, self::b(1)), self::tlv(0xa0, self::u8('x'))),
          self::tlv(0x88), self::tlv(0x88, self::b(0x80, 1)), self::tlv(0xa5), self::tlv(0xa5, self::tlv(0x04, self::b(1))), self::tlv(0xa4), self::tlv(0x83, self::b(1)), self::tlv(0x84, self::b(1)), self::tlv(0x85, self::b(1)), self::tlv(0xa8),
          # stricter
          self::tlv(0x88, self::b(0x55, 4, 3)), self::tlv(0xa3), self::tlv(0xa3, self::tlv(0x02, self::b(1))), self::tlv(0xa5, self::tlv(0xa1, self::u8('x'))), self::tlv(0xa2, self::tlv(0x16, self::b(0x41))), self::tlv(0xa6), self::tlv(0xa7), self::tlv(0xa1)
        ];
        foreach ($good as $i => $g) {
            $this->assertTrue(self::withNames($g, self::dir(self::root())), "good $i");
        }
        foreach ($bad as $i => $g) {
            $this->assertFalse(self::withNames($g, self::dir(self::root())), "bad $i");
        }
    }

    public function testAnExtensionOpenSslCachesDecodesOnBothCertificates(): void
    {
        $g = self::tlv(0x82, 'a');
        $gb = self::tlv(0x82, 'b');
        $oth = static fn(string ...$a): string => self::tlv(0xa0, self::cnOid(), ...$a);
        $both = [
          # basicConstraints
          [0x13, self::tlv(0x30), true], [0x13, self::tlv(0x30, self::tlv(0x01, self::b(255))), true], [0x13, self::tlv(0x30, self::tlv(0x01, self::b(0x55))), true], [0x13, self::tlv(0x30, self::tlv(0x01, self::b(0))), true],
          [0x13, self::tlv(0x30, self::tlv(0x01, self::b(255)), self::tlv(0x02, self::b(1))), true], [0x13, self::tlv(0x30, self::tlv(0x02, self::b(1))), true], [0x13, self::tlv(0x30) . self::b(5, 0), true],
          [0x13, self::tlv(0x30, self::tlv(0x02, self::b(1)), self::tlv(0x01, self::b(255))), false], [0x13, self::tlv(0x30, self::tlv(0x01, self::b(255, 255))), false], [0x13, self::tlv(0x30, self::tlv(0x01)), false],
          [0x13, self::tlv(0x30, self::tlv(0x01, self::b(255)), self::tlv(0x02, self::b(0, 1))), false], [0x13, self::tlv(0x30, self::tlv(0x01, self::b(255)), self::tlv(0x02)), false],
          [0x13, self::tlv(0x30, self::tlv(0x01, self::b(255)), self::tlv(0x02, self::b(0xff))), false], [0x13, self::tlv(0x30, self::tlv(0x01, self::b(255)), self::tlv(0x02, self::b(1)), self::tlv(0x05)), false], [0x13, self::tlv(0x04, self::b(1)), false],
          # keyUsage
          [0x0f, self::tlv(0x03), false], [0x0f, self::tlv(0x03, self::b(0)), false], [0x0f, self::tlv(0x03, self::b(8, 0xa0)), false], [0x0f, self::tlv(0x04, self::b(0)), false], [0x0f, self::b(3, 5, 0), false], [0x0f, '', false],
          # extendedKeyUsage
          [0x25, self::tlv(0x30, self::oid(self::b(0x2b, 6, 1, 5, 5, 7, 3, 1))), true], [0x25, self::tlv(0x30), true], [0x25, self::tlv(0x30, self::tlv(0x04, self::b(1))), false], [0x25, self::tlv(0x30, self::tlv(0x06, self::b(0x80, 1))), false], [0x25, self::tlv(0x04, self::b(1)), false],
          # subjectAltName
          [0x11, self::tlv(0x30, self::uri()), true], [0x11, self::tlv(0x30), true], [0x11, self::tlv(0x30, self::uri()) . self::b(5, 0), true], [0x11, self::tlv(0x30, $oth(self::tlv(0xa0, self::u8('x')))), true],
          [0x11, self::tlv(0x30, $oth(self::tlv(0xa0, self::u8('x'), self::u8('y')))), false], [0x11, self::tlv(0x30, $oth(self::tlv(0xa0))), false], [0x11, self::tlv(0x30, $oth(self::tlv(0xa0, self::u8('x')), self::tlv(0x05))), false],
          [0x11, self::tlv(0x30, $oth(self::tlv(0xa1, self::u8('x')))), false], [0x11, self::tlv(0x30, self::tlv(0x89, self::b(1))), false], [0x11, self::tlv(0x30, self::tlv(0xa4, self::tlv(0x04, self::b(1)))), false], [0x11, self::tlv(0x04, self::b(1)), false],
          # nameConstraints
          [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x30, $g))), true], [0x1e, self::tlv(0x30), true], [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x30, $g)), self::tlv(0xa1, self::tlv(0x30, $gb))), true], [0x1e, self::tlv(0x30, self::tlv(0xa0)), true],
          [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x30, $g, self::tlv(0x80, self::b(0)), self::tlv(0x81, self::b(1))))), true],
          [0x1e, self::tlv(0x30, self::tlv(0xa1, self::tlv(0x30, $gb)), self::tlv(0xa0, self::tlv(0x30, $g))), false], [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x04, self::b(1)))), false], [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x30))), false],
          [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x30, $g, self::tlv(0x81, self::b(1)), self::tlv(0x80, self::b(0))))), false], [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x30, $g, self::tlv(0x80, self::b(0, 1))))), false],
          [0x1e, self::tlv(0x30, self::tlv(0x80, self::b(1))), false], [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x30, $g, $gb))), false], [0x1e, self::tlv(0x30, self::tlv(0xa0, $g)), false],
          [0x1e, self::tlv(0x30, self::tlv(0xa0, self::tlv(0x30, $g, self::tlv(0x80, self::b(0xff))))), false], # stricter
          # cRLDistributionPoints
          [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa0, self::uri())))), true], [0x1f, self::tlv(0x30), true], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa1, self::atv(self::cnOid(), self::u8('x')))))), true],
          [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa2, self::uri()))), true], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa0, self::uri())), self::tlv(0x81, self::b(1, 0x80)))), true],
          [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa0, self::uri())), self::tlv(0x81, self::b(0)))), true], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa0)))), true], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa1)))), true],
          [0x1f, self::tlv(0x30, self::tlv(0x30)), false], [0x1f, self::tlv(0x30, self::tlv(0x04, self::b(1))), false], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa1, self::tlv(0x04, self::b(1)))))), false],
          [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0x81, self::b(1, 0x80)))), false], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa2, self::tlv(0x89, self::b(1))))), false], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa2))), false],
          [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa2, self::uri()), self::tlv(0xa0, self::tlv(0xa0, self::uri())))), false], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0))), false], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa2, self::uri())))), false],
          [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa0, self::uri()), self::tlv(0xa0, self::uri())))), false], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa0, self::tlv(0x89, self::b(1)))))), false],
          [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa0, self::uri())), self::tlv(0x81, self::b(8, 0x80)))), false], [0x1f, self::tlv(0x30, self::tlv(0x30, self::tlv(0xa0, self::tlv(0xa0, self::uri())), self::tlv(0x81))), false]
        ];
        foreach ($both as $i => [$last, $v, $want]) {
            $e = self::x($last, $v);
            $this->assertSame($want, self::issued([$e]), "child row $i");
            $this->assertSame($want, self::issued([], [self::skid(), $e]), "issuer row $i");
        }
        // keyUsage without keyCertSign refuses only on the issuer, with keyCertSign it links on both
        $this->assertTrue(self::issued([self::x(0x0f, self::tlv(0x03, self::b(5, 0xa0)))]));
        $this->assertFalse(self::issued([], [self::skid(), self::x(0x0f, self::tlv(0x03, self::b(5, 0xa0)))]));
        $this->assertTrue(self::issued([self::x(0x0f, self::tlv(0x03, self::b(7, 0x80)))]));
        $this->assertTrue(self::issued([], [self::skid(), self::x(0x0f, self::tlv(0x03, self::b(2, 0x04)))]));
        // nsCertType, read from Node 26: any bits or none, trailing bytes ignored
        $ns = "\x60\x86\x48\x01\x86\xf8\x42\x01\x01";
        foreach ([[self::tlv(0x03, self::b(5, 0xa0)), true], [self::tlv(0x03, self::b(0)), true], [self::tlv(0x03, self::b(5, 0xa0)) . self::b(5, 0), true],
            [self::tlv(0x03), false], [self::tlv(0x03, self::b(8, 0xa0)), false], [self::tlv(0x04, self::b(0)), false], [self::b(3, 5, 0), false]] as $i => [$v, $want]) {
            $this->assertSame($want, self::issued([self::oe($ns, $v)]), "nsCertType child $i");
            $this->assertSame($want, self::issued([], [self::skid(), self::oe($ns, $v)]), "nsCertType issuer $i");
        }
        // stricter: Node links under a proxyCertInfo and a repeated unknown extension
        $pci = self::oe(self::b(0x2b, 6, 1, 5, 5, 7, 1, 14), self::tlv(0x30, self::tlv(0x30, self::oid(self::b(0x2b, 6, 1, 5, 5, 7, 21, 1)))));
        $this->assertFalse(self::issued([$pci]));
        $this->assertFalse(self::issued([], [self::skid(), $pci]));
        $this->assertFalse(self::issued([self::x(0x63, self::b(1)), self::x(0x63, self::b(1))]));
    }

    public function testTheIssuerSideDecodesAndMissingSkidOrItsOwnAkidDoNotMatter(): void
    {
        $this->assertTrue(self::issued([self::ak(self::keyid())], []));
        $this->assertTrue(self::issued([self::ak(self::keyid())], [self::ext(self::SK, self::tlv(0x04, self::b(7, 7, 7, 7)) . self::b(5, 0))]));
        $this->assertTrue(self::issued([], [self::skid(), self::ak(self::ser(0x77))]));
        foreach ([[self::ext(self::SK, self::tlv(0x30))], [self::skid(), self::skid()], [self::skid(), self::ext(self::AK, self::tlv(0x04, self::b(1)))]] as $i => $u) {
            $this->assertFalse(self::issued([], $u), "row $i");
        }
        $this->assertFalse(self::issued([self::ak(self::keyid())], [self::ext(self::SK, self::tlv(0x30))]));
    }

    public function testACertificateSerialIsAMinimalDerInteger(): void
    {
        $parse = static fn(int ...$s): Cert => new Cert(self::cert(self::root(), self::upName(), [], self::b(...$s)));
        foreach ([[1], [0x11], [0, 0x80], [0xff, 0x7f], [0x80], [0], array_fill(0, 21, 0x11)] as $s) {
            $this->assertSame(self::b(...$s), $parse(...$s)->serial);
        }
        foreach ([[0, 0x11], [0xff, 0x80], [0, 0], []] as $i => $s) {
            try {
                $parse(...$s);
                $this->fail("serial row $i parsed");
            } catch (CertError) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testXmlCharacterReferencesAreDigitsOnlyAndInRange(): void
    {
        $text = static fn(string $ref): string => Xml::parse("<a>$ref</a>")->root->textContent();
        foreach (['&#65;', '&#000065;', '&#x41;', '&#x0041;', '&#1114111;', '&#x10FFFF;', '&#x9;', '&#xA;', '&#xD;', '&#x20;', '&#xD7FF;', '&#xE000;', '&#xFFFD;', '&#x10000;'] as $ok) {
            $this->assertNotSame('', $text($ok), $ok);
        }
        $this->assertSame('AA', $text('&#000065;&#x0041;'));
        foreach (['&#+65;', '&#-65;', '&#x+41;', '&# 65;', '&#99999999999;', '&#1114112;', '&#x110000;', '&#xFFFFFFFFFFFFFFFFFFFF;', '&#;', '&#x;',
            '&#0;', '&#x0;', '&#xD800;', '&#xDFFF;', '&#55296;', '&#x8;', '&#xFFFE;', '&#xFFFF;'] as $bad) {
            try {
                $text($bad);
                $this->fail("$bad parsed");
            } catch (XmlError) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testDeepNestingIsRefusedCleanly(): void
    {
        $ok = str_repeat('[', 512) . str_repeat(']', 512);
        $this->assertIsArray(JsJson::parse($ok));
        foreach (['[' . $ok . ']', str_repeat('[', 100000), str_repeat('{"a":', 100000)] as $i => $deep) {
            try {
                JsJson::parse($deep);
                $this->fail("JsJson row $i parsed");
            } catch (JsError $e) {
                $this->assertNotSame('', $e->getMessage());
            }
            foreach ([static fn() => Json::parseLax($deep), static fn() => Json::parseStrict($deep)] as $parse) {
                try {
                    $parse();
                    $this->fail("Json row $i parsed");
                } catch (JsonError) {
                    $this->addToAssertionCount(1);
                }
            }
        }
        $this->assertInstanceOf(XmlElement::class, Xml::parse(str_repeat('<a>', 256) . str_repeat('</a>', 256))->root);
        foreach ([str_repeat('<a>', 257) . str_repeat('</a>', 257), str_repeat('<a>', 100000)] as $i => $x) {
            try {
                Xml::parse($x);
                $this->fail("Xml row $i parsed");
            } catch (XmlError $e) {
                $this->assertSame('nesting too deep', $e->getMessage());
            }
        }
        // json_decode (step-up HTTP replies) has its own depth limit
        $this->assertNull(json_decode(str_repeat('[', 100000) . str_repeat(']', 100000), true));
        $deep = '';
        for ($i = 0; $i < 5000; $i++) {
            $deep = self::tlv(0x30, $deep);
        }
        try {
            new Cert($deep);
            $this->fail('nested DER parsed as a certificate');
        } catch (CertError) {
            $this->addToAssertionCount(1);
        }
    }
}
