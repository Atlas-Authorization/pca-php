<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestNvidia.php';
require_once __DIR__ . '/../src/AttestVendors.php';

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\AttestNvidia;
use Atlas\Pca\AttestVendors;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The vendor facade's argument coercions and default skew, and the NVIDIA golden comparison and guarded fetch helpers. */
final class AttestSurvivorKill7VendorsNvidiaTest extends TestCase
{
    /** @return array{pem:string,validTo:int} a self-signed P-256 certificate valid for one day */
    private static function cert(): array
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n[x]\nbasicConstraints=critical,CA:TRUE\n");
        try {
            $opt = ['config' => $cnf, 'digest_alg' => 'sha256', 'x509_extensions' => 'x'];
            $key = openssl_pkey_new(['config' => $cnf, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            self::assertNotFalse($key, 'EC keygen: ' . openssl_error_string());
            $x = openssl_csr_sign(openssl_csr_new(['commonName' => 'kill7'], $key, $opt), null, $key, 1, $opt, 7);
            self::assertNotFalse($x, (string)openssl_error_string());
            openssl_x509_export($x, $pem);
            return ['pem' => $pem, 'validTo' => (int)openssl_x509_parse($x)['validTo_time_t']];
        } finally {
            unlink($cnf);
        }
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'no throw';
    }

    private static function fetchOf(mixed $status, mixed $body, ?array &$seen = null): \Closure
    {
        return static function ($url, $init = null) use ($status, $body, &$seen): Obj {
            $seen[] = $url;
            return Obj::of(['status' => $status, 'body' => $body]);
        };
    }

    /** Absent quote / nowMs arguments are coerced (empty quote, clock 0) into the vendor modules' own refusals, never a type error. */
    public function testMissingArgumentsAreRefusals(): void
    {
        $r = AttestVendors::verifyGenuineTdxQuote(new Obj());
        $this->assertFalse($r['ok']);
        $this->assertIsString($r['reason']);
        $this->assertSame(['ok' => false, 'reason' => 'collateral incomplete (fail closed)'], AttestVendors::verifyIntelTdxCollateral(new Obj()));
        $this->assertSame(['ok' => false, 'reason' => 'empty x5c certificate chain'], AttestVendors::verifyX5cChain([], [], new Obj()));
        $this->assertSame('empty x5c certificate chain', AttestVendors::verifyJwkX5cChain([], [], new Obj()));
    }

    /** Without clockSkewMs there is no skew: one millisecond past notAfter is outside the validity window. */
    public function testDefaultSkewIsZero(): void
    {
        $c = self::cert();
        $x5c = [base64_encode(AttestVendors::pemToDer($c['pem']))];
        $edge = $c['validTo'] * 1000;
        $this->assertSame(['ok' => false, 'reason' => 'x5c certificate at index 0 is outside its validity window'],
            AttestVendors::verifyX5cChain($x5c, [], Obj::of(['nowMs' => $edge + 1])));
        $this->assertSame(['ok' => false, 'reason' => 'no MAA trust anchor configured (fail closed)'], AttestVendors::verifyX5cChain($x5c, [], Obj::of(['nowMs' => $edge])));
    }

    /** A report without the NVDEC opaque field is compared normally (index 35 is not skipped). */
    public function testCompareWithoutNvdecField(): void
    {
        $d = str_repeat("\x0a", 48);
        $report = ['measurements' => [['index' => 1, 'digest' => $d]], 'opaque' => []];
        $driver = ['golden' => [['index' => 0, 'active' => true, 'size' => 48, 'hashes' => [bin2hex($d)]]]];
        $this->assertSame(['ok' => true, 'checked' => 1], AttestNvidia::compareReportToRims($report, $driver, ['golden' => []]));
    }

    /** No fetch implementation is a RuntimeException naming the helper. */
    public function testFetchNeedsATransport(): void
    {
        $this->assertSame('RuntimeException: fetchNvidiaRim: no fetch implementation available', self::thrown(static fn() => AttestNvidia::fetchRim('x')));
    }

    /** HTTP 299 is a success and 199 is not; a non-string body comes back as its string form. */
    public function testStatusRangeAndBodyString(): void
    {
        $this->assertSame('5', AttestNvidia::fetchCrl('u', Obj::of(['fetch' => self::fetchOf(299, 5)])));
        $this->assertSame('RuntimeException: CRL fetch failed: HTTP 199 for u', self::thrown(static fn() => AttestNvidia::fetchCrl('u', Obj::of(['fetch' => self::fetchOf(199, 'b')]))));
    }

    /** A RIM body that is not a JSON object with a rim string is refused as such (a numeric body included). */
    public function testRimBodyWithoutRim(): void
    {
        $this->assertSame('RuntimeException: RIM fetch: response has no rim field', self::thrown(static fn() => AttestNvidia::fetchRim('x', Obj::of(['fetch' => self::fetchOf(200, 5)]))));
    }

    /** A RIM that is not valid UTF-8 is decoded with U+FFFD for each bad byte, and the caller's substitute character is restored. */
    public function testRimInvalidUtf8IsReplaced(): void
    {
        $prev = mb_substitute_character();
        mb_substitute_character(0x3F);
        try {
            $out = AttestNvidia::fetchRim('x', Obj::of(['fetch' => self::fetchOf(200, '{"rim":"' . base64_encode("a\xffb") . '"}')]));
            $this->assertSame("a\u{FFFD}b", $out);
            $this->assertSame(0x3F, mb_substitute_character());
            $this->assertSame('ok', AttestNvidia::fetchRim('x', Obj::of(['fetch' => self::fetchOf(200, '{"rim":"' . base64_encode('ok') . '"}')])));
        } finally {
            mb_substitute_character($prev);
        }
    }

    /** fetchOcsp posts to the given url as a string and returns the response body as a string. */
    public function testOcspUrlAndBodyAreStrings(): void
    {
        $c = Cert::fromPem(self::cert()['pem']);
        $seen = [];
        $r = AttestNvidia::fetchOcsp($c, $c, Obj::of(['fetch' => self::fetchOf(200, 5, $seen), 'url' => 7]));
        $this->assertSame(['7'], $seen);
        $this->assertSame('5', $r['response']);
        $this->assertIsString($r['request']);
    }
}
