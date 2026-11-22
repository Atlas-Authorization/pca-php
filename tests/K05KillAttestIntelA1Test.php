<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Intel;
use Atlas\Pca\Attest\PubKey;
use Atlas\Pca\Attest\Tlv;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for the first half (lines < 600) of Attest/Intel.php: DCAP v4 quote parser, TD report, PCK TCB extension reader, the PCK chain,
 * the genuine-quote pipeline (over a quote built and signed here with P-256 keys generated at load), DER / Date.UTC helpers, the CRL reader
 * and the signed-JSON scanner. Expectations follow packages/pca/src/attest-intel-tdx.ts and attest-intel-collateral.ts.
 */
final class K05KillAttestIntelA1Test extends TestCase
{
    private const P = "\x2A\x86\x48\x86\xF8\x4D\x01\x0D\x01";
    private const FM = "\x00\x60\x6A\x00\x00\x00";
    private const RE_SGX = 'extractPckFmspcAndTcb: ';

    // ---------------------------------------------------------------------------------------------------------- DER / key builders

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : ($n < 0x10000 ? "\x82" . pack('n', $n) : "\x83" . substr(pack('N', $n), 1)))) . $v;
    }

    private static function oid(string $b): string
    {
        return self::tlv(0x06, $b);
    }

    private static function dn(string $cn): string
    {
        return self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, self::oid("\x55\x04\x03"), self::tlv(0x0C, $cn))));
    }

    private static function utc(int $t): string
    {
        return self::tlv(0x17, gmdate('ymdHis', $t) . 'Z');
    }

    private static function ext(string $id, string $value, bool $critical = false): string
    {
        return self::tlv(0x30, self::oid($id), $critical ? self::tlv(0x01, "\xFF") : '', self::tlv(0x04, $value));
    }

    private static function config(): string
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        return $cnf;
    }

    private static function key(string $name): \OpenSSLAsymmetricKey
    {
        static $keys = [];
        if (!isset($keys[$name])) {
            $cnf = self::config();
            $keys[$name] = $name === 'rsa'
                ? openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA])
                : openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            unlink($cnf);
        }
        return $keys[$name];
    }

    private static function spki(\OpenSSLAsymmetricKey $k): string
    {
        return (string)base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details($k)['key']));
    }

    private static function point(\OpenSSLAsymmetricKey $k): string
    {
        $ec = openssl_pkey_get_details($k)['ec'];
        return str_pad($ec['x'], 32, "\0", STR_PAD_LEFT) . str_pad($ec['y'], 32, "\0", STR_PAD_LEFT);
    }

    private static function rawSig(string $msg, \OpenSSLAsymmetricKey $key): string
    {
        openssl_sign($msg, $der, $key, OPENSSL_ALGO_SHA256);
        $o = (ord($der[1]) & 0x80) !== 0 ? 2 + (ord($der[1]) & 0x7F) : 2;
        $lr = ord($der[$o + 1]);
        $r = substr($der, $o + 2, $lr);
        $o2 = $o + 2 + $lr;
        $ls = ord($der[$o2 + 1]);
        $s = substr($der, $o2 + 2, $ls);
        return str_pad(ltrim($r, "\0"), 32, "\0", STR_PAD_LEFT) . str_pad(ltrim($s, "\0"), 32, "\0", STR_PAD_LEFT);
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    private static function ms(int $y, int $mo, int $d, int $h = 0, int $mi = 0, int $s = 0): int
    {
        return gmmktime($h, $mi, $s, $mo, $d, $y) * 1000;
    }

    private static function now(): int
    {
        return self::ms(2026, 6, 1);
    }

    /** @param array<string,mixed> $o */
    private static function cert(string $iss, string $sub, \OpenSSLAsymmetricKey $subjKey, \OpenSSLAsymmetricKey $signer, int $serial, array $o = []): string
    {
        $alg = self::tlv(0x30, self::oid("\x2A\x86\x48\xCE\x3D\x04\x03\x02"));
        $nb = $o['nb'] ?? gmmktime(0, 0, 0, 1, 1, 2025);
        $na = $o['na'] ?? gmmktime(0, 0, 0, 1, 1, 2035);
        $exts = [];
        $ca = $o['ca'] ?? null;
        if ($ca !== null) {
            $exts[] = self::ext("\x55\x1D\x13", self::tlv(0x30, $ca ? self::tlv(0x01, "\xFF") : ''), true);
        }
        if ($o['ku'] ?? false) {
            $exts[] = self::ext("\x55\x1D\x0F", self::tlv(0x03, "\x02\x04"), true);
        }
        foreach ($o['exts'] ?? [] as $e) {
            $exts[] = $e;
        }
        $parts = [self::tlv(0xA0, self::tlv(0x02, "\x02")), self::tlv(0x02, chr($serial)), $alg, self::dn($iss),
            self::tlv(0x30, self::utc($nb), self::utc($na)), self::dn($sub), self::spki($subjKey)];
        if ($exts !== []) {
            $parts[] = self::tlv(0xA3, self::tlv(0x30, ...$exts));
        }
        $tbs = self::tlv(0x30, ...$parts);
        openssl_sign($tbs, $sig, $signer, OPENSSL_ALGO_SHA256);
        return self::tlv(0x30, $tbs, $alg, self::tlv(0x03, "\0" . $sig));
    }

    /** The Intel SGX extension value: FMSPC + the 16 component SVNs + PCESVN. */
    private static function sgxExt(): string
    {
        $comps = [];
        for ($n = 1; $n <= 16; $n++) {
            $comps[] = self::tlv(0x30, self::oid(self::P . "\x02" . chr($n)), self::tlv(0x02, chr($n)));
        }
        $comps[] = self::tlv(0x30, self::oid(self::P . "\x02\x11"), self::tlv(0x02, "\x07"));
        $v = self::tlv(0x30, self::tlv(0x30, self::oid(self::P . "\x04"), self::tlv(0x04, self::FM)),
            self::tlv(0x30, self::oid(self::P . "\x02"), self::tlv(0x30, ...$comps)));
        return self::ext(self::P, $v);
    }

    /**
     * @param array<string,mixed> $o rootSigner interSigner leafSigner (keys) interCa leafCa (bool) leafKey nb na sgx exts
     * @return array{root:string,inter:string,leaf:string,pin:string}
     */
    private static function chain(array $o = []): array
    {
        $root = self::key('root');
        $interCa = $o['interCa'] ?? true;
        $times = array_intersect_key($o, ['nb' => 1, 'na' => 1]);
        $rootDer = self::cert('Root', 'Root', $root, $o['rootSigner'] ?? $root, 1, ['ca' => true, 'ku' => true] + $times);
        $interDer = self::cert('Root', 'Inter', self::key('inter'), $o['interSigner'] ?? $root, 2, ['ca' => $interCa, 'ku' => $interCa] + $times);
        $exts = ($o['sgx'] ?? true) ? [self::sgxExt()] : [];
        foreach ($o['exts'] ?? [] as $e) {
            $exts[] = $e;
        }
        $leafDer = self::cert('Inter', 'Leaf', $o['leafKey'] ?? self::key('leaf'), $o['leafSigner'] ?? self::key('inter'), 3,
            ['ca' => $o['leafCa'] ?? null, 'exts' => $exts] + $times);
        return ['root' => $rootDer, 'inter' => $interDer, 'leaf' => $leafDer, 'pin' => hash('sha256', self::spki($root))];
    }

    private static function chainPem(array $c): string
    {
        return self::pem($c['leaf']) . self::pem($c['inter']) . self::pem($c['root']);
    }

    private static function priv(string $name, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Intel::class, $name))->invoke(null, ...$args);
    }

    /** Runs `$f` with every PHP warning turned into an exception. */
    private static function strict(callable $f): mixed
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

    private static function bad(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    // ---------------------------------------------------------------------------------------------------------- quote parsing

    private static function qs(): string { return str_repeat("\x01", 64); }
    private static function ak(): string { return str_repeat("\x02", 64); }
    private static function qe(): string { return str_repeat("\x03", 384); }
    private static function qes(): string { return str_repeat("\x04", 64); }
    private static function u16(int $n): string { return pack('v', $n); }
    private static function u32(int $n): string { return pack('V', $n); }

    private static function hdr(): string
    {
        return pack('vvV', 4, 2, 0x81) . str_repeat("\0", 40);
    }

    private static function tdPattern(): string
    {
        $b = '';
        for ($i = 0; $i < 584; $i++) {
            $b .= chr(($i * 7 + 3) % 251);
        }
        return $b;
    }

    private static function rawQuote(string $sigBody, string $pad = ''): string
    {
        return self::hdr() . self::tdPattern() . self::u32(strlen($sigBody)) . $sigBody . $pad;
    }

    private static function outer(string $rest, int $type = 6, ?int $size = null): string
    {
        return self::qs() . self::ak() . self::u16($type) . self::u32($size ?? strlen($rest)) . $rest;
    }

    private static function rest(string $auth = "\x05\x06", int $innerType = 5, string $pem = 'PEM', ?int $innerSize = null): string
    {
        return self::qe() . self::qes() . self::u16(strlen($auth)) . $auth . self::u16($innerType) . self::u32($innerSize ?? strlen($pem)) . $pem;
    }

    private static function perr(string $quote): string
    {
        try {
            Intel::parseQuote($quote);
        } catch (\ValueError $e) {
            return $e->getMessage();
        }
        self::fail('parseQuote did not throw');
        return '';
    }

    public function testUnpackHelpersReadZeroOnAShortRead(): void
    {
        set_error_handler(static fn(): bool => true);
        try {
            $a = self::priv('u16', 'a', 0);
            $b = self::priv('u32', 'abc', 0);
        } finally {
            restore_error_handler();
        }
        self::assertSame(0, $a);
        self::assertSame(0, $b);
        self::assertSame(0x0201, self::priv('u16', "\x01\x02\x03", 0));
        self::assertSame(0x04030201, self::priv('u32', "\x01\x02\x03\x04\x05", 0));
    }

    public function testParseQuoteHappyPathAndEveryMessage(): void
    {
        $q = self::rawQuote(self::outer(self::rest()), "\0\0");
        self::assertSame(['header' => self::hdr(), 'tdReportBody' => self::tdPattern(), 'quoteSignature' => self::qs(), 'akPubRaw' => self::ak(),
            'qeReportBody' => self::qe(), 'qeReportSignature' => self::qes(), 'qeAuthData' => "\x05\x06", 'pckChainPem' => 'PEM'], Intel::parseQuote($q));

        $p = 'parseDcapQuote: ';
        // 636 bytes (header + report + sig length = 0) is long enough; 635 is not
        self::assertSame($p . 'truncated reading quote signature', self::perr(self::rawQuote('')));
        self::assertSame($p . 'too short for header + TD report + sig length', self::perr(substr(self::rawQuote(''), 0, 635)));
        self::assertSame($p . 'too short for header + TD report + sig length', self::perr(''));
        self::assertSame($p . 'truncated reading quote signature', self::perr(self::rawQuote(substr(self::qs(), 0, 63))));
        self::assertSame($p . 'truncated reading attestation public key', self::perr(self::rawQuote(self::qs() . substr(self::ak(), 0, 63))));
        self::assertSame($p . 'truncated reading outer cert-data header', self::perr(self::rawQuote(self::qs() . self::ak())));
        self::assertSame($p . 'truncated reading outer cert-data header', self::perr(self::rawQuote(self::qs() . self::ak() . "\x06\x00\x00\x00\x00")));
        self::assertSame($p . 'truncated reading QE report', self::perr(self::rawQuote(self::qs() . self::ak() . self::u16(6) . self::u32(0))));
        self::assertSame($p . 'outer cert-data type 7 (expected QE-report-cert-data = 6)', self::perr(self::rawQuote(self::outer(self::rest(), 7))));
        self::assertSame($p . 'outer cert-data overruns signature data', self::perr(self::rawQuote(self::outer(self::rest(), 6, strlen(self::rest()) + 1))));
        self::assertSame($p . 'truncated reading QE report', self::perr(self::rawQuote(self::outer(substr(self::qe(), 0, 383)))));
        self::assertSame($p . 'truncated reading QE report signature', self::perr(self::rawQuote(self::outer(self::qe() . substr(self::qes(), 0, 63)))));
        self::assertSame($p . 'truncated reading QE auth-data size', self::perr(self::rawQuote(self::outer(self::qe() . self::qes()))));
        self::assertSame($p . 'truncated reading QE auth-data size', self::perr(self::rawQuote(self::outer(self::qe() . self::qes() . "\x02"))));
        self::assertSame($p . 'truncated reading QE auth-data', self::perr(self::rawQuote(self::outer(self::qe() . self::qes() . self::u16(5) . 'ab'))));
        self::assertSame($p . 'truncated reading inner cert-data header', self::perr(self::rawQuote(self::outer(self::qe() . self::qes() . self::u16(0)))));
        self::assertSame($p . 'truncated reading inner cert-data header', self::perr(self::rawQuote(self::outer(self::qe() . self::qes() . self::u16(0) . "\x05\x00\x00\x00\x00"))));
        self::assertSame($p . 'inner cert-data type 4 (expected PCK-cert-chain = 5)', self::perr(self::rawQuote(self::outer(self::rest("\x05\x06", 4)))));
        self::assertSame($p . 'inner cert-data overruns outer cert-data', self::perr(self::rawQuote(self::outer(self::rest("\x05\x06", 5, 'PEM', 4)))));
        self::assertSame($p . 'non-zero bytes after the signature data', self::perr(self::rawQuote(self::outer(self::rest()), "\x00\x01")));
    }

    public function testParseQuoteExactFits(): void
    {
        // an empty QE auth-data and an empty PEM: the inner header ends exactly at the signature data
        $r = Intel::parseQuote(self::rawQuote(self::outer(self::rest('', 5, ''))));
        self::assertSame('', $r['qeAuthData']);
        self::assertSame('', $r['pckChainPem']);
        // slack inside the signature data after the outer wrapper is fine
        $r = Intel::parseQuote(self::rawQuote(self::outer(self::rest('', 5, '')) . "\0\0\0"));
        self::assertSame('', $r['pckChainPem']);
        $rest = self::rest();
        $r = Intel::parseQuote(self::rawQuote(self::outer($rest, 6, strlen($rest) + 2) . 'zz'));
        self::assertSame('PEM', $r['pckChainPem']);
    }

    public function testParseTdReport(): void
    {
        $b = self::tdPattern();
        self::assertSame(['teeTcbSvn' => substr($b, 0, 16), 'mrSeam' => substr($b, 16, 48), 'mrSignerSeam' => substr($b, 64, 48),
            'tdAttributes' => substr($b, 120, 8), 'mrTd' => substr($b, 136, 48), 'rtmr0' => substr($b, 328, 48), 'reportData' => substr($b, 520, 64)], Intel::parseTdReport($b));
        self::assertSame(Intel::parseTdReport($b), Intel::parseTdReport($b . 'tail'));
        $this->expectException(\ValueError::class);
        $this->expectExceptionMessage('parseDcapTdReport: body too short (583 < 584)');
        Intel::parseTdReport(substr($b, 0, 583));
    }

    // ---------------------------------------------------------------------------------------------------------- PCK extension

    private static function comp(int $n, string $val): string
    {
        return self::tlv(0x30, self::oid(self::P . "\x02" . chr($n)), $val);
    }

    private static function leafExt(string ...$comps): string
    {
        return self::oid(self::P . "\x04") . self::tlv(0x04, self::FM) . self::oid(self::P . "\x02") . self::tlv(0x30, ...$comps);
    }

    private static function xerr(string $der): string
    {
        try {
            Intel::extractPckFmspcAndTcb($der);
        } catch (\ValueError $e) {
            return $e->getMessage();
        }
        self::fail('extractPckFmspcAndTcb did not throw');
        return '';
    }

    public function testExtractRefusals(): void
    {
        $p = self::RE_SGX;
        $fm = self::oid(self::P . "\x04");
        $tcb = self::oid(self::P . "\x02");
        $int = static fn(int $v): string => self::tlv(0x02, chr($v));
        self::assertSame($p . 'FMSPC OID not found in certificate', self::xerr(''));
        self::assertSame($p . 'TCB OID not found in certificate', self::xerr($fm . self::tlv(0x04, self::FM)));
        self::assertSame($p . 'malformed FMSPC OCTET STRING', self::xerr($fm . self::tlv(0x04, str_repeat("\0", 7))));
        self::assertSame($p . 'malformed FMSPC OCTET STRING', self::xerr($fm . "\x04"));
        self::assertSame($p . 'malformed FMSPC OCTET STRING', self::xerr($fm . self::tlv(0x05, self::FM) . $tcb . self::tlv(0x30)));
        self::assertSame($p . 'malformed TCB SEQUENCE', self::xerr($fm . self::tlv(0x04, self::FM) . $tcb . "\x30"));
        self::assertSame($p . 'malformed TCB SEQUENCE', self::xerr($fm . self::tlv(0x04, self::FM) . $tcb . self::tlv(0x31)));
        self::assertSame($p . 'TCB component missing OID', self::xerr(self::leafExt(self::tlv(0x30, "\x06\x7f"))));
        self::assertSame($p . 'TCB component missing OID', self::xerr(self::leafExt(self::tlv(0x30, $int(5), $int(1)))));
        self::assertSame($p . 'TCB component missing value', self::xerr(self::leafExt(self::tlv(0x30, "\x06\x01\x11"))));
        self::assertSame($p . 'malformed TCB component', self::xerr(self::leafExt($int(1))));
        self::assertSame($p . 'PCESVN not found in TCB extension', self::xerr(self::leafExt()));
    }

    public function testExtractValues(): void
    {
        $comps = [];
        for ($i = 1; $i <= 16; $i++) {
            $comps[] = self::comp($i, self::tlv(0x02, "\x01" . chr($i))); // 2-byte INTEGER: only the low byte is the SVN
        }
        $comps[] = self::comp(17, self::tlv(0x02, "\x01\x02\x03"));
        $comps[] = self::comp(0, self::tlv(0x02, "\x09"));
        $comps[] = self::comp(19, self::tlv(0x02, "\x09"));
        $comps[] = self::comp(18, self::tlv(0x04, str_repeat("\x07", 16)));
        self::assertSame(['fmspc' => self::FM, 'sgxTcbComponents' => pack('C*', ...range(1, 16)), 'pcesvn' => 0x0203], Intel::extractPckFmspcAndTcb(self::leafExt(...$comps)));
        // an empty INTEGER is 0: PCESVN 0 is a value, not "not found"; the unset components stay zero
        self::assertSame(['fmspc' => self::FM, 'sgxTcbComponents' => str_repeat("\0", 16), 'pcesvn' => 0],
            Intel::extractPckFmspcAndTcb(self::leafExt(self::comp(17, self::tlv(0x02, '')))));
    }

    public function testExtractReadsAtMost65Components(): void
    {
        $filler = [];
        for ($i = 0; $i < 64; $i++) {
            $filler[] = self::comp(18, self::tlv(0x04, ''));
        }
        $r = Intel::extractPckFmspcAndTcb(self::leafExt(...[...$filler, self::comp(17, self::tlv(0x02, "\x07"))]));
        self::assertSame(7, $r['pcesvn']);
        self::assertSame(self::RE_SGX . 'PCESVN not found in TCB extension',
            self::xerr(self::leafExt(...[...$filler, self::comp(18, self::tlv(0x04, '')), self::comp(17, self::tlv(0x02, "\x07"))])));
    }

    // ---------------------------------------------------------------------------------------------------------- PCK chain

    public function testPckChainAcceptsAnyOrderAndReturnsTheLeaf(): void
    {
        $c = self::chain();
        $pem = self::pem($c['root']) . self::pem($c['leaf']) . self::pem($c['inter']);
        $r = Intel::verifyPckChain($pem, $c['pin'], self::now());
        self::assertSame(['ok', 'leafKey', 'leafDer', 'leafCert', 'depth'], array_keys($r));
        self::assertTrue($r['ok']);
        self::assertSame($c['leaf'], $r['leafDer']);
        self::assertSame(3, $r['depth']);
        self::assertInstanceOf(PubKey::class, $r['leafKey']);
        self::assertSame('ec', $r['leafKey']->type);
        // the pin is compared lowercase
        self::assertTrue(Intel::verifyPckChain(self::chainPem($c), strtoupper($c['pin']), self::now())['ok']);
        // a lone self-signed root is a chain of one
        $lone = Intel::verifyPckChain(self::pem($c['root']), $c['pin'], self::now());
        self::assertTrue($lone['ok']);
        self::assertSame(1, $lone['depth']);
    }

    public function testPckChainExactRefusals(): void
    {
        $c = self::chain();
        $now = self::now();
        $pem = self::chainPem($c);
        self::assertSame(self::bad('no PEM certificates in the PCK chain'), Intel::verifyPckChain(null, $c['pin'], $now));
        self::assertSame(self::bad('no PEM certificates in the PCK chain'), Intel::verifyPckChain('no pem here', $c['pin'], $now));
        self::assertSame(self::bad('PCK chain does not terminate in a self-signed root'), Intel::verifyPckChain(self::pem($c['leaf']) . self::pem($c['inter']), $c['pin'], $now));
        // a stray certificate (not an issuer of anything, issued by nobody in the chain): the FIRST non-issuer is the leaf
        $stray = self::cert('Nowhere', 'Stray', self::key('other'), self::key('other'), 9, []);
        self::assertSame(self::bad('PCK chain is not a single connected path (orphan/duplicate certificates)'),
            Intel::verifyPckChain($pem . self::pem($stray), $c['pin'], $now));
        self::assertSame(self::bad('nowMs is not a finite number'), Intel::verifyPckChain($pem, $c['pin'], NAN));
        self::assertSame(self::bad('nowMs is not a finite number'), Intel::verifyPckChain($pem, $c['pin'], '1'));
        self::assertSame(['ok' => false, 'reason' => 'PCK chain certificate outside its validity period', 'failure' => 'validity'],
            Intel::verifyPckChain($pem, $c['pin'], self::ms(2024, 12, 31)));
        self::assertSame(self::bad('certificate at depth 0 is not signed by its issuer'),
            Intel::verifyPckChain(self::chainPem(self::chain(['leafSigner' => self::key('other')])), $c['pin'], $now));
        self::assertSame(self::bad('certificate at depth 1 is not signed by its issuer'),
            Intel::verifyPckChain(self::chainPem(self::chain(['interSigner' => self::key('other')])), $c['pin'], $now));
        self::assertSame(self::bad('root certificate is not self-signed'),
            Intel::verifyPckChain(self::chainPem(self::chain(['rootSigner' => self::key('other')])), $c['pin'], $now));
        self::assertSame(self::bad('Intel SGX Root CA does not match the pinned trust anchor'), Intel::verifyPckChain($pem, str_repeat('00', 32), $now));
        self::assertSame(self::bad('Intel SGX Root CA does not match the pinned trust anchor'), Intel::verifyPckChain($pem, null, $now));
        self::assertSame(self::bad('issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)'),
            Intel::verifyPckChain(self::chainPem(self::chain(['interCa' => false])), $c['pin'], $now));
        self::assertSame(self::bad('leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)'),
            Intel::verifyPckChain(self::chainPem(self::chain(['leafCa' => true])), $c['pin'], $now));
        $crit = self::ext("\x2A\x03\x04", "\x05\x00", true);
        self::assertSame(self::bad('PCK chain certificate at depth 0 has an unrecognised critical extension 1.2.3.4'),
            Intel::verifyPckChain(self::chainPem(self::chain(['exts' => [$crit]])), $c['pin'], $now));
        self::assertSame(self::bad('PCK leaf key is not EC (got rsa)'),
            Intel::verifyPckChain(self::chainPem(self::chain(['leafKey' => self::key('rsa')])), $c['pin'], $now));
    }

    public function testPckChainFailsClosedOnAMalformedCertificate(): void
    {
        $r = Intel::verifyPckChain("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----", 'ab', self::now());
        self::assertSame(['ok', 'reason'], array_keys($r));
        self::assertFalse($r['ok']);
        self::assertStringStartsWith('PCK chain X.509 verification error (fail closed): ', $r['reason']);
        self::assertGreaterThan(strlen('PCK chain X.509 verification error (fail closed): '), strlen($r['reason']));
    }

    public function testPckChainDefaultsNowToTheWallClock(): void
    {
        // valid from 5 days ago to 5 days ahead: now*0.999, now*1.001 and now/1000 all fall outside, the real clock inside
        $t = time();
        $c = self::chain(['nb' => $t - 5 * 86400, 'na' => $t + 5 * 86400]);
        $r = Intel::verifyPckChain(self::chainPem($c), $c['pin']);
        self::assertTrue($r['ok']);
        self::assertSame(3, $r['depth']);
    }

    public function testSignerKeyFromChain(): void
    {
        $c = self::chain();
        $pem = self::chainPem($c);
        self::assertSame(['error' => 'issuer chain certificate outside its validity period'],
            self::priv('signerKeyFromChain', $pem, $c['pin'], (float)self::ms(2024, 6, 1), []));
        self::assertSame(['error' => 'issuer chain invalid: PCK chain does not terminate in a self-signed root'],
            self::priv('signerKeyFromChain', self::pem($c['leaf']) . self::pem($c['inter']), $c['pin'], (float)self::now(), []));
        $r = self::priv('signerKeyFromChain', $pem, $c['pin'], (float)self::now(), []);
        self::assertSame(['key'], array_keys($r));
        self::assertSame('ec', $r['key']->type);
    }

    // ---------------------------------------------------------------------------------------------------------- genuine quote

    /** @return array{pem:string,pin:string} */
    private static function world(): array
    {
        static $w = null;
        if ($w === null) {
            $c = self::chain();
            $w = ['pem' => self::chainPem($c), 'pin' => $c['pin']];
        }
        return $w;
    }

    /** @param array<string,mixed> $o */
    private static function td(array $o = []): string
    {
        $b = self::tdPattern();
        if (isset($o['attr0'])) {
            $b[120] = chr($o['attr0']);
        }
        if (isset($o['rd'])) {
            $b = substr_replace($b, $o['rd'], 520, 64);
        }
        return $b;
    }

    private static function binding(string $akRaw, string $auth = 'auth-data'): string
    {
        return hash('sha256', $akRaw . $auth, true) . str_repeat("\0", 32);
    }

    /** @param array<string,mixed> $o */
    private static function quote(array $o = []): string
    {
        $akKey = self::key('ak');
        $akRaw = $o['akRaw'] ?? self::point($akKey);
        $auth = $o['auth'] ?? 'auth-data';
        $td = $o['td'] ?? self::td();
        $qeData = $o['qeData'] ?? self::binding($akRaw, $auth);
        $qe = str_repeat("\0", 384);
        $qe[48] = chr($o['qeFlags'] ?? 0);
        $qe = substr_replace($qe, $qeData, 320, 64);
        $qeSig = $o['qeSig'] ?? self::rawSig($qe, $o['qeSigner'] ?? self::key('leaf'));
        $tdSig = $o['tdSig'] ?? self::rawSig(self::hdr() . $td, $o['tdSigner'] ?? $akKey);
        $pem = $o['pem'] ?? self::world()['pem'];
        $inner = $qe . $qeSig . pack('v', strlen($auth)) . $auth . pack('v', 5) . pack('V', strlen($pem)) . $pem;
        $sigData = $tdSig . $akRaw . pack('v', 6) . pack('V', strlen($inner)) . $inner;
        return self::hdr() . $td . pack('V', strlen($sigData)) . $sigData;
    }

    /** @param array<string,mixed> $o @return array<string,mixed> */
    private static function verify(array $o = [], mixed $expected = null, ?array $policy = null): array
    {
        return Intel::verifyGenuineQuote(self::quote($o), self::world()['pin'], $expected, $policy, self::now());
    }

    public function testGenuineQuoteAccepts(): void
    {
        $td = self::td();
        $r = self::verify();
        self::assertTrue($r['ok']);
        self::assertSame(['ok', 'report', 'fmspc', 'pckTcb', 'chainDepth', 'measured'], array_keys($r));
        self::assertSame(Intel::parseTdReport($td), $r['report']);
        self::assertSame(bin2hex(self::FM), $r['fmspc']);
        self::assertSame(['fmspc' => self::FM, 'sgxTcbComponents' => pack('C*', ...range(1, 16)), 'pcesvn' => 7], $r['pckTcb']);
        self::assertSame(3, $r['chainDepth']);
        self::assertSame(['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => bin2hex(substr($td, 136, 48)), 'operator' => ''], $r['measured']);
        // a QE without the debug bit but with other attribute bits set is fine
        self::assertTrue(self::verify(['qeFlags' => 0xFD])['ok']);
    }

    public function testGenuineQuoteStageRefusals(): void
    {
        $pin = self::world()['pin'];
        self::assertSame(self::bad('quote parse failed: parseDcapQuote: too short for header + TD report + sig length'),
            Intel::verifyGenuineQuote('short', $pin, null, null, self::now()));
        self::assertSame(self::bad('PCK chain invalid: no PEM certificates in the PCK chain'), self::verify(['pem' => '']));
        self::assertSame(self::bad('PCK chain invalid: PCK chain certificate outside its validity period'),
            Intel::verifyGenuineQuote(self::quote(), $pin, null, null, self::ms(2024, 12, 31)));
        $noSgx = self::chain(['sgx' => false]);
        self::assertSame(self::bad('PCK FMSPC/TCB extraction failed: extractPckFmspcAndTcb: FMSPC OID not found in certificate'),
            Intel::verifyGenuineQuote(self::quote(['pem' => self::chainPem($noSgx)]), $noSgx['pin'], null, null, self::now()));
        self::assertSame(self::bad('QE report signature does not verify under the PCK leaf'), self::verify(['qeSigner' => self::key('other')]));
        self::assertSame(self::bad('QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)'), self::verify(['qeFlags' => 0x02]));
        self::assertSame(self::bad('QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)'), self::verify(['qeFlags' => 0x03]));
        self::assertSame(self::bad('TD quote signature does not verify under the attestation key'), self::verify(['tdSigner' => self::key('other')]));
    }

    public function testQeReportDataMustBindTheAttestationKeyAndBeZeroAfterIt(): void
    {
        $msg = 'QE report_data does not bind the attestation key (AK not endorsed by this QE)';
        $good = hash('sha256', self::point(self::key('ak')) . 'auth-data', true);
        self::assertSame(self::bad($msg), self::verify(['qeData' => str_repeat("\x01", 32) . str_repeat("\0", 32)]));
        self::assertSame(self::bad($msg), self::verify(['auth' => 'other-auth', 'qeData' => self::binding(self::point(self::key('ak')))]));
        // each byte of the second half, the first and the last included
        self::assertSame(self::bad($msg), self::verify(['qeData' => $good . "\x01" . str_repeat("\0", 31)]));
        self::assertSame(self::bad($msg), self::verify(['qeData' => $good . str_repeat("\0", 31) . "\x01"]));
        self::assertSame(self::bad($msg), self::verify(['qeData' => $good . str_repeat("\0", 15) . "\x01" . str_repeat("\0", 16)]));
        self::assertTrue(self::verify(['qeData' => $good . str_repeat("\0", 32)])['ok']);
    }

    public function testAttestationKeyMustBeAPointOnP256(): void
    {
        $bad = str_repeat("\x01", 64);
        self::assertSame(self::bad('attestation public key is not a valid P-256 point'), self::verify(['akRaw' => $bad]));
    }

    public function testExpectedBinding(): void
    {
        $exp = ['holderPub' => 'hp', 'grantRef' => 'gr', 'epoch' => 5, 'nonce' => 'n'];
        $rd = Common::attestationBinding($exp);
        self::assertTrue(self::verify(['td' => self::td(['rd' => $rd])], $exp)['ok']);
        self::assertSame(self::bad('report_data does not bind holder/grant/epoch/nonce'), self::verify([], $exp));
        self::assertSame(self::bad('report_data does not bind holder/grant/epoch/nonce'),
            self::verify(['td' => self::td(['rd' => $rd])], ['holderPub' => 'hp', 'grantRef' => 'gr', 'epoch' => 6, 'nonce' => 'n']));
        self::assertSame(self::bad('binding not constructible: binding: holderPub required'), self::verify([], ['holderPub' => '']));
    }

    public function testTdDebugAttribute(): void
    {
        $msg = 'TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)';
        self::assertSame(self::bad($msg), self::verify(['td' => self::td(['attr0' => 1])]));
        self::assertSame(self::bad($msg), self::verify(['td' => self::td(['attr0' => 0xFF])], null, []));
        self::assertTrue(self::verify(['td' => self::td(['attr0' => 1])], null, ['allowDebug' => true])['ok']);
        self::assertTrue(self::verify(['td' => self::td(['attr0' => 0xFE])])['ok']);
    }

    public function testPolicyAllowlists(): void
    {
        $td = self::td();
        $mrtd = bin2hex(substr($td, 136, 48));
        $seam = bin2hex(substr($td, 16, 48));
        $signer = bin2hex(substr($td, 64, 48));
        $rtmr = bin2hex(substr($td, 328, 48));
        $fm = bin2hex(self::FM);
        $all = ['mrtds' => [strtoupper($mrtd)], 'fmspcs' => [$fm], 'mrSeams' => [strtoupper($seam)], 'mrSignerSeams' => [$signer], 'rtmrs' => [strtoupper($rtmr)]];
        self::assertTrue(self::verify([], null, $all)['ok']);
        $wrong = str_repeat('00', 48);
        self::assertSame(self::bad('MRTD not in policy allowlist'), self::verify([], null, ['mrtds' => [$wrong]]));
        self::assertSame(self::bad('FMSPC not in policy allowlist'), self::verify([], null, ['fmspcs' => ['000000000000']]));
        self::assertSame(self::bad('MRSEAM not in policy allowlist'), self::verify([], null, ['mrSeams' => [$wrong]]));
        self::assertSame(self::bad('MRSIGNERSEAM not in policy allowlist'), self::verify([], null, ['mrSignerSeams' => [$wrong]]));
        self::assertSame(self::bad('RTMR0 not in policy allowlist'), self::verify([], null, ['rtmrs' => [$wrong]]));
        // mrtds / fmspcs / rtmrs: an EMPTY list (or a non-list) is "no restriction"
        self::assertTrue(self::verify([], null, ['mrtds' => [], 'fmspcs' => [], 'rtmrs' => []])['ok']);
        self::assertTrue(self::verify([], null, ['mrtds' => 'x', 'fmspcs' => 'x', 'mrSeams' => 'x', 'mrSignerSeams' => 'x', 'rtmrs' => 'x'])['ok']);
        // mrSeams / mrSignerSeams: an empty list allows nothing
        self::assertSame(self::bad('MRSEAM not in policy allowlist'), self::verify([], null, ['mrSeams' => []]));
        self::assertSame(self::bad('MRSIGNERSEAM not in policy allowlist'), self::verify([], null, ['mrSignerSeams' => []]));
    }

    public function testGenuineQuoteFailsClosed(): void
    {
        self::assertSame(self::bad('genuine TDX verification error (fail closed): x.toLowerCase is not a function'), self::verify([], null, ['mrtds' => [123]]));
    }

    // ---------------------------------------------------------------------------------------------------------- DER / dates

    public function testTlvReader(): void
    {
        $t = static fn(string $b, int $off = 0, ?int $limit = null): array => (static function (Tlv $x): array {
            return [$x->tag, $x->start, $x->end];
        })(self::strict(static fn() => self::priv('tlv', $b, $off, $limit)));
        $err = static function (string $b, ?int $limit = null): string {
            try {
                self::strict(static fn() => self::priv('tlv', $b, 0, $limit));
            } catch (\ValueError $e) {
                return $e->getMessage();
            }
            return 'no error';
        };
        self::assertSame([4, 2, 2], $t("\x04\x00"));
        self::assertSame('DER truncated', $err("\x04"));
        self::assertSame('DER truncated', $err(''));
        self::assertSame('DER overrun', $err("\x04\x05abcde", 4));
        self::assertSame([4, 2, 7], $t("\x04\x05abcde", 0, 7));
        self::assertSame('DER bad length', $err("\x04\x80"));
        self::assertSame('DER bad length', $err("\x04\x85\x00\x00\x00\x00\x01\xaa"));
        self::assertSame('DER bad length', $err("\x04\x84\x00\x00"));
        self::assertSame([4, 3, 3], $t("\x04\x81\x00"));
        self::assertSame([4, 3, 4], $t("\x04\x81\x01\xaa"));
        self::assertSame([4, 6, 7], $t("\x04\x84\x00\x00\x00\x01\xaa"));
        self::assertSame('DER overrun', $err("\x04\x81\x80"));
        self::assertSame([4, 4, 6], $t("zz\x04\x02ab", 2));
    }

    /** @return list<array{int,int,int,int,int,int,int}> */
    private static function dateRows(): array
    {
        return [
            [2020, 12, 1, 0, 0, 0, self::ms(2021, 1, 1)],
            [2020, 11, 1, 0, 0, 0, self::ms(2020, 12, 1)],
            [2020, 13, 1, 0, 0, 0, self::ms(2021, 2, 1)],
            [2020, 24, 1, 0, 0, 0, self::ms(2022, 1, 1)],
            [2020, 0, 1, 0, 0, 0, self::ms(2020, 1, 1)],
            [2020, -1, 1, 0, 0, 0, self::ms(2019, 12, 1)],
            [2020, -12, 1, 0, 0, 0, self::ms(2019, 1, 1)],
            [2020, -13, 1, 0, 0, 0, self::ms(2018, 12, 1)],
            [2024, 1, 29, 23, 59, 58, self::ms(2024, 2, 29, 23, 59, 58)],
            [2025, 1, 3, 4, 5, 6, self::ms(2025, 2, 3, 4, 5, 6)],
            [0, 0, 1, 0, 0, 0, self::ms(1900, 1, 1)],
            [50, 5, 7, 8, 9, 10, self::ms(1950, 6, 7, 8, 9, 10)],
            [99, 0, 1, 0, 0, 0, self::ms(1999, 1, 1)],
            [100, 0, 1, 0, 0, 0, -59011459200000],
        ];
    }

    public function testDateUtcEmulation(): void
    {
        foreach (self::dateRows() as $i => $r) {
            self::assertSame($r[6], self::priv('dateUtc', $r[0], $r[1], $r[2], $r[3], $r[4], $r[5]), "row $i");
        }
    }

    private static function derTime(int $tag, string $s): int
    {
        return self::priv('derTime', chr($tag) . chr(strlen($s)) . $s, new Tlv($tag, 2, 2 + strlen($s)));
    }

    public function testDerTime(): void
    {
        self::assertSame(self::ms(1950, 2, 3, 4, 5, 6), self::derTime(0x17, '500203040506Z'));
        self::assertSame(self::ms(2049, 2, 3, 4, 5, 6), self::derTime(0x17, '490203040506Z'));
        self::assertSame(self::ms(1999, 12, 31, 23, 59, 58), self::derTime(0x17, '991231235958Z'));
        self::assertSame(self::ms(2000, 1, 1), self::derTime(0x17, '000101000000Z'));
        self::assertSame(self::ms(2025, 2, 3, 4, 5, 6), self::derTime(0x18, '20250203040506Z'));
        self::assertSame(self::ms(2049, 12, 31, 23, 59, 59), self::derTime(0x18, '20491231235959Z'));
        foreach ([[0x17, 'xx0203040506Z', 'bad UTCTime'], [0x17, '5002030405Z', 'bad UTCTime'], [0x17, '500203040506', 'bad UTCTime'],
                  [0x18, '2025020304050Z', 'bad GeneralizedTime'], [0x18, 'xxxx0203040506Z', 'bad GeneralizedTime'],
                  [0x02, '500203040506Z', 'not a DER time'], [0x04, '20250203040506Z', 'not a DER time']] as [$tag, $s, $msg]) {
            try {
                self::derTime($tag, $s);
                self::fail("no error for $s");
            } catch (\ValueError $e) {
                self::assertSame($msg, $e->getMessage());
            }
        }
    }

    public function testNormSerial(): void
    {
        self::assertSame('ab', Intel::normSerial('00AB'));
        self::assertSame('ab', Intel::normSerial('AB'));
        self::assertSame('', Intel::normSerial('0'));
        self::assertSame('', Intel::normSerial(''));
        self::assertTrue(Intel::serialIsRevoked(['ab' => true], '00AB'));
        self::assertFalse(Intel::serialIsRevoked(['ab' => true], '00AC'));
    }

    // ---------------------------------------------------------------------------------------------------------- CRL

    private const ALG_EC = "\x2A\x86\x48\xCE\x3D\x04\x03\x02";

    /** @param array<string,mixed> $o */
    private static function crl(array $o = []): string
    {
        $alg = self::tlv(0x30, self::oid(self::ALG_EC));
        $parts = [];
        if (!($o['noVersion'] ?? false)) {
            $parts[] = self::tlv(0x02, "\x01");
        }
        $parts[] = $alg;
        $parts[] = $o['issuer'] ?? self::dn('Issuer');
        $parts[] = $o['this'] ?? self::tlv(0x17, '260101000000Z');
        $next = array_key_exists('next', $o) ? $o['next'] : self::tlv(0x17, '261231000000Z');
        if ($next !== null) {
            $parts[] = $next;
        }
        if (isset($o['revoked'])) {
            $ents = array_map(static fn(string $s): string => self::tlv(0x30, $o['entry'] ?? self::tlv(0x02, $s), self::tlv(0x17, '260301000000Z')), $o['revoked']);
            $parts[] = self::tlv(0x30, ...$ents);
        }
        $tbs = self::tlv(0x30, ...$parts);
        openssl_sign($tbs, $sig, $o['signer'] ?? self::key('root'), OPENSSL_ALGO_SHA256);
        return self::tlv(0x30, $tbs, $alg, self::tlv($o['sigTag'] ?? 0x03, "\0" . $sig) . ($o['extra'] ?? ''));
    }

    private static function issuerKey(string $name = 'root'): PubKey
    {
        return Common::loadPublicKey(self::spki(self::key($name)));
    }

    public function testCrlAcceptsAndListsRevokedSerials(): void
    {
        $der = self::crl(['revoked' => ["\x00\xAB", "\x0A\xBC"]]);
        // serials are lowercase hex without leading zeros, each mapped to true
        self::assertSame(['ok' => true, 'revoked' => ['ab' => true, 'abc' => true]], Intel::verifyCrl($der, self::issuerKey(), (float)self::now()));
        self::assertSame(['ok' => true, 'revoked' => []], Intel::verifyCrl(self::crl(['noVersion' => true]), self::issuerKey(), (float)self::now()));
        // a GeneralizedTime nextUpdate, and the revoked list after it
        $g = self::crl(['next' => self::tlv(0x18, '20271231000000Z'), 'revoked' => ["\x01"]]);
        self::assertSame(['ok' => true, 'revoked' => ['1' => true]], Intel::verifyCrl($g, self::issuerKey(), (float)self::now()));
    }

    public function testCrlWindowIsInclusive(): void
    {
        $der = self::crl();
        $k = self::issuerKey();
        $this_ = self::ms(2026, 1, 1);
        $next = self::ms(2026, 12, 31);
        self::assertTrue(Intel::verifyCrl($der, $k, (float)$this_)['ok']);
        self::assertTrue(Intel::verifyCrl($der, $k, (float)$next)['ok']);
        self::assertSame(self::bad('CRL thisUpdate is in the future'), Intel::verifyCrl($der, $k, (float)($this_ - 1)));
        self::assertSame(self::bad('CRL is stale (nextUpdate passed)'), Intel::verifyCrl($der, $k, (float)($next + 1)));
    }

    public function testCrlSignatureIsCheckedPerKeyType(): void
    {
        $now = (float)self::now();
        $msg = 'CRL signature does not verify under the issuer';
        self::assertSame(self::bad($msg), Intel::verifyCrl(self::crl(['signer' => self::key('other')]), self::issuerKey(), $now));
        // an RSA issuer
        $rsa = self::crl(['signer' => self::key('rsa')]);
        self::assertTrue(Intel::verifyCrl($rsa, self::issuerKey('rsa'), $now)['ok']);
        self::assertSame(self::bad($msg), Intel::verifyCrl($rsa, self::issuerKey(), $now));
        // any other key type verifies nothing
        $odd = new PubKey(self::key('root'), self::spki(self::key('root')), 'okp', null, []);
        self::assertSame(self::bad($msg), Intel::verifyCrl(self::crl(), $odd, $now));
    }

    public function testCrlStructureRefusals(): void
    {
        $now = (float)self::now();
        $k = self::issuerKey();
        $p = 'CRL parse failed: CRL: ';
        $alg = self::tlv(0x30, self::oid(self::ALG_EC));
        $bits = self::tlv(0x03, "\0\1");
        self::assertSame(self::bad($p . 'bad TBSCertList'), Intel::verifyCrl(self::tlv(0x30, self::tlv(0x02, "\x01"), $alg, $bits), $k, $now));
        self::assertSame(self::bad($p . 'bad signature'), Intel::verifyCrl(self::crl(['sigTag' => 0x04]), $k, $now));
        self::assertSame(self::bad($p . 'bad signature'), Intel::verifyCrl(self::crl(['extra' => "\0"]), $k, $now));
        self::assertSame(self::bad($p . 'bad issuer'), Intel::verifyCrl(self::crl(['issuer' => self::tlv(0x31)]), $k, $now));
        self::assertSame(self::bad($p . 'bad revoked entry'), Intel::verifyCrl(self::crl(['revoked' => ['x'], 'entry' => self::tlv(0x04, "\1")]), $k, $now));
        // no nextUpdate: with nothing after thisUpdate, and with a revoked list there (which is not a time)
        self::assertSame(self::bad($p . 'missing nextUpdate'), Intel::verifyCrl(self::crl(['next' => null]), $k, $now));
        self::assertSame(self::bad($p . 'missing nextUpdate'), Intel::verifyCrl(self::crl(['next' => null, 'revoked' => ["\x01"]]), $k, $now));
    }

    // ---------------------------------------------------------------------------------------------------------- signed JSON scanner

    public function testRawJsonObjectScanner(): void
    {
        $raw = static fn(string $t, string $n = 'tcbInfo'): ?string => self::strict(static fn() => self::priv('rawJsonObject', $t, $n));
        self::assertNull($raw('{"tcbInfo":'));
        self::assertNull($raw('{"tcbInfo": 5}'));
        self::assertNull($raw('{"tcbInfo": 5, "x":{}}'));
        self::assertNull($raw('{"tcbInfo":{"a":1'));
        self::assertNull($raw('{"other":{"a":1}}'));
        self::assertSame('{"a":1}', $raw(' {"tcbInfo" : {"a":1}}'));
        self::assertSame('{"a":"}"}', $raw('{"tcbInfo":{"a":"}"}}'));
        self::assertSame('{"a":"x\"}y"}', $raw('{"tcbInfo":{"a":"x\"}y"}}'));
        self::assertSame('{"a":"x\\\\"}', $raw('{"tcbInfo":{"a":"x\\\\"}}'));
        self::assertSame('{"a":{"b":1}}', $raw('{"tcbInfo":{"a":{"b":1}}}'));
        // the name is matched literally
        self::assertNull($raw('{"axb":{"k":1}}', 'a.b'));
        self::assertSame('{"k":1}', $raw('{"a.b":{"k":1}}', 'a.b'));
    }
}
