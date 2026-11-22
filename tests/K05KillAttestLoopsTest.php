<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\Intel;
use Atlas\Pca\Attest\JsJson;
use Atlas\Pca\Attest\Ocsp;
use Atlas\Pca\Attest\Tlv;
use Atlas\Pca\Attest\Xml;
use PHPUnit\Framework\TestCase;

/**
 * Loop-counter and loop-condition mutants of the attestation readers never stop (a counter that no longer advances, a
 * condition that holds past the end of the input). Each call runs in a forked copy under a 3 s deadline (K05Deadline): the
 * unmutated code answers at once; a mutant that spins or grows memory is a failure here, so no test ever has to run it to the
 * memory limit. The parent then repeats the call for its exact result (and for coverage, which a forked child does not report).
 */
final class K05KillAttestLoopsTest extends TestCase
{
    private static function priv(string $class, string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod($class, $method))->invoke(null, ...$args);
    }

    private function bounded(callable $fn): void
    {
        $this->assertSame('ok', K05Deadline::run($fn));
    }

    public function testNodeBase64DecodeLoopAdvances(): void
    {
        $this->bounded(static fn() => Common::nodeB64Decode('QUJD'));
        $this->assertSame('ABC', Common::nodeB64Decode('QUJD'));
    }

    public function testCommonDerLengthLoopAdvances(): void
    {
        $der = "\x30\x81\x03abc";
        $this->bounded(fn() => self::priv(Common::class, 'tlv', $der, 0));
        $this->assertSame([0x30, 3, 6], self::priv(Common::class, 'tlv', $der, 0));
    }

    public function testIntelDerLengthLoopAdvances(): void
    {
        $der = "\x30\x81\x03abc";
        $this->bounded(fn() => self::priv(Intel::class, 'tlv', $der, 0));
        $t = self::priv(Intel::class, 'tlv', $der, 0);
        $this->assertSame([0x30, 3, 6], [$t->tag, $t->start, $t->end]);
    }

    public function testDerLengthLoopsAdvance(): void
    {
        $long = "\x30\x81\x80" . str_repeat('a', 128);
        $this->bounded(static fn() => Der::readTlv($long, 0));
        $t = Der::readTlv($long, 0);
        $this->assertSame([0x30, 3, 131], [$t->tag, $t->start, $t->end]);
        $der = "\x30\x81\x03abc";
        $this->bounded(fn() => self::priv(Der::class, 'tlvAt', $der, 0));
        $u = self::priv(Der::class, 'tlvAt', $der, 0);
        $this->assertSame([0x30, 3, 6], [$u->tag, $u->start, $u->end]);
    }

    public function testOidToDottedLoopAdvances(): void
    {
        $der = "\x06\x03\x55\x04\x03";
        $this->bounded(static fn() => Der::oidToDotted($der, new Tlv(6, 2, 5)));
        $this->assertSame('2.5.4.3', Der::oidToDotted($der, new Tlv(6, 2, 5)));
    }

    public function testDnEscapeLoopAdvances(): void
    {
        $this->bounded(fn() => self::priv(Cert::class, 'escape', 'abc'));
        $this->assertSame('abc', self::priv(Cert::class, 'escape', 'abc'));
    }

    public function testXmlUnescapeAndSkipWsLoopsAdvance(): void
    {
        $this->bounded(fn() => self::priv(Xml::class, 'unescape', 'a&amp;b', false));
        $this->assertSame('a&b', self::priv(Xml::class, 'unescape', 'a&amp;b', false));
        $this->bounded(fn() => self::priv(Xml::class, 'skipWs', "  a", 0));
        $this->assertSame(2, self::priv(Xml::class, 'skipWs', "  a", 0));
        $this->assertSame(1, self::priv(Xml::class, 'skipWs', " ", 0));
    }

    public function testOcspStripZerosLoopStopsAtTheLastByte(): void
    {
        foreach (["\x05", "\x00", "\x00\x00\x05", ''] as $in) {
            $this->bounded(fn() => self::priv(Ocsp::class, 'stripZeros', $in));
        }
        $this->assertSame("\x05", self::priv(Ocsp::class, 'stripZeros', "\x05"));
        $this->assertSame("\x00", self::priv(Ocsp::class, 'stripZeros', "\x00"));
        $this->assertSame("\x05", self::priv(Ocsp::class, 'stripZeros', "\x00\x00\x05"));
    }

    public function testIntelMaskedEqLoopAdvances(): void
    {
        $this->bounded(fn() => self::priv(Intel::class, 'maskedEq', 'ab', "\xff\xff", 'ab'));
        $this->assertTrue(self::priv(Intel::class, 'maskedEq', 'ab', "\xff\xff", 'ab'));
        $this->assertFalse(self::priv(Intel::class, 'maskedEq', 'ab', "\xff\xff", 'ac'));
    }

    public function testJsJsonWhitespaceAndCommaLoopsAdvance(): void
    {
        $text = " \t\n\r[ 1 , 2 ] ";
        $this->bounded(static fn() => JsJson::parse($text));
        $this->assertSame('[1,2]', \Atlas\Pca\Json::canonicalizeLenient(JsJson::parse($text)));
    }
    public function testBasicConstraintsPathLenLoopAdvances(): void
    {
        foreach ([0, 1] as $len) {
            $ext = "\x30\x0F\x06\x03\x55\x1D\x13\x04\x08\x30\x06\x01\x01\xFF\x02\x01" . chr($len);
            $cert = "\x30\x17\x30\x15\xA3\x13\x30\x11" . $ext;
            $this->bounded(static fn() => Der::readCertRoleInfo($cert));
            $info = Der::readCertRoleInfo($cert);
            $this->assertTrue($info['hasBasicConstraints']);
            $this->assertTrue($info['ca']);
            $this->assertSame($len, $info['pathLen']);
        }
    }

    public function testPckTcbComponentIntegerLoopAdvances(): void
    {
        $oid = "\x06\x0B\x2A\x86\x48\x86\xF8\x4D\x01\x0D\x01\x02";
        $pair = static fn(int $n, string $int): string => "\x30" . chr(13 + strlen($int)) . $oid . chr($n) . $int;
        $pairs = '';
        $want = '';
        for ($i = 1; $i <= 16; $i++) {
            $v = $i === 3 ? 200 : $i * 3;
            $pairs .= $pair($i, $i === 3 ? "\x02\x02\x00\xC8" : "\x02\x01" . chr($v));
            $want .= chr($v);
        }
        $pairs .= $pair(17, "\x02\x02\x12\x34");
        $der = "\x06\x0A\x2A\x86\x48\x86\xF8\x4D\x01\x0D\x01\x04" . "\x04\x06" . 'FMSPC!' . "\x06\x0A\x2A\x86\x48\x86\xF8\x4D\x01\x0D\x01\x02"
            . "\x30\x82" . pack('n', strlen($pairs)) . $pairs;
        $this->bounded(static fn() => Intel::extractPckFmspcAndTcb($der));
        $r = Intel::extractPckFmspcAndTcb($der);
        $this->assertSame('FMSPC!', $r['fmspc']);
        $this->assertSame($want, $r['sgxTcbComponents']);
        $this->assertSame(0x1234, $r['pcesvn']);
    }

    public function testJsJsonFailKeepsItsMessageAndPosition(): void
    {
        $f = new \Atlas\Pca\Attest\JsJsonFail('why', 7, true);
        $this->assertSame('why', $f->getMessage());
        $this->assertSame(7, $f->pos);
        $this->assertTrue($f->extra);
        // NaN / Infinity members are refused at the token (V8 names the first character), never accepted
        foreach (['[NaN]' => "Unexpected token 'N'", '[Infinity]' => "Unexpected token 'I'"] as $in => $head) {
            try {
                JsJson::parse($in);
                $this->fail("accepted $in");
            } catch (\Atlas\Pca\Attest\JsError $e) {
                $this->assertStringStartsWith($head, $e->getMessage(), $in);
            }
        }
    }

    public function testXmlDeclarationScanAdvancesAndEnds(): void
    {
        $text = '<!DOCTYPE a [<!ENTITY e "x">]><a/>';
        $this->bounded(static fn() => Xml::parse($text));
        $doc = Xml::parse($text);
        $this->assertSame(['DTD / DOCTYPE is not permitted'], $doc->violations);
    }

    public function testGcpPinListWithANonStringThrowsLikeToLowerCase(): void
    {
        $m = new \ReflectionMethod(\Atlas\Pca\Attest\Gcp::class, 'lowerList');
        $this->assertSame(['ab', 'cd'], $m->invoke(null, ['AB', 'cD']));
        $this->assertSame([], $m->invoke(null, 'notalist'));
        $this->expectException(\TypeError::class);
        $m->invoke(null, ['AB', 5]);
    }

    public function testRawJsonObjectScanAdvancesPastEscapes(): void
    {
        $text = '{"tcbInfo":{"a":"x\\"y\\\\"},"signature":"s"}';
        $this->bounded(fn() => self::priv(Intel::class, 'rawJsonObject', $text, 'tcbInfo'));
        $this->assertSame('{"a":"x\\"y\\\\"}', self::priv(Intel::class, 'rawJsonObject', $text, 'tcbInfo'));
        $this->assertNull(self::priv(Intel::class, 'rawJsonObject', '{"tcbInfo":{"a":"x', 'tcbInfo'));
    }

    /** @return list<array<string,int>> */
    private static function comps(): array
    {
        return array_fill(0, 16, ['svn' => 0]);
    }

    public function testTcbLevelComponentLoopsAdvanceAndEnd(): void
    {
        $mod = ['mrsigner' => str_repeat('00', 48), 'attributes' => '0000000000000000', 'attributesMask' => 'FFFFFFFFFFFFFFFF'];
        $lvl = static fn(int $pce): array => ['tcb' => ['sgxtcbcomponents' => self::comps(), 'tdxtcbcomponents' => self::comps(), 'pcesvn' => $pce],
            'tcbStatus' => 'UpToDate', 'advisoryIDs' => []];
        $pck = ['sgx' => str_repeat("\0", 16), 'pcesvn' => 0];
        $td = static fn(int $minor): array => ['teeTcbSvn' => "\0" . chr($minor) . str_repeat("\0", 14), 'mrSignerSeam' => str_repeat("\0", 48), 'seamAttributes' => str_repeat("\0", 8)];
        $ident = $mod + ['id' => 'TDX_01', 'tcbLevels' => [['tcb' => ['isvsvn' => 0], 'tcbStatus' => 'UpToDate', 'advisoryIDs' => []]]];
        $cases = [
            [['tcbLevels' => [$lvl(0)], 'tdxModule' => $mod], 0],                                     // every component matches
            [['tcbLevels' => [$lvl(5), $lvl(0)], 'tdxModule' => $mod], 0],                            // PCESVN too low: match is false from the start
            [['tcbLevels' => [$lvl(0)], 'tdxModule' => $mod, 'tdxModuleIdentities' => [$ident]], 1],  // TDX components start at 2
        ];
        foreach ($cases as [$info, $minor]) {
            $this->bounded(fn() => self::priv(Intel::class, 'evaluateTcb', $info, $pck, $td($minor)));
        }
        $r = self::priv(Intel::class, 'evaluateTcb', $cases[1][0], $pck, $td(0));
        $this->assertSame(['platform' => 'UpToDate', 'module' => 'UpToDate', 'advisories' => []], $r);
    }
}
