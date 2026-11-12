<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attest/Factory.php';

use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Intel;
use PHPUnit\Framework\TestCase;

/**
 * Kills the survivors of src/Attest/Intel.php from the signed-JSON reader down (date parsing, freshness, TCB / QE evaluation,
 * verifyCollateral, the verifier object). Expectations follow attest-intel-collateral.ts / attest-intel-tdx.ts. The pipeline tests
 * run on a quote, PCK chain, CRLs and signed collateral built here from throw-away P-256 keys, pinned to the throw-away root.
 */
final class K05KillAttestIntelB1Test extends TestCase
{
    // ---- builders ---------------------------------------------------------------------------------------------------------------

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

    private static function point(\OpenSSLAsymmetricKey $k): string
    {
        $ec = openssl_pkey_get_details($k)['ec'];
        return str_pad($ec['x'], 32, "\0", STR_PAD_LEFT) . str_pad($ec['y'], 32, "\0", STR_PAD_LEFT);
    }

    /** IEEE P1363 (r || s) ECDSA-SHA256 signature. */
    private static function rawSig(\OpenSSLAsymmetricKey $k, string $data): string
    {
        openssl_sign($data, $der, $k, OPENSSL_ALGO_SHA256);
        $o = 2;
        $out = '';
        for ($i = 0; $i < 2; $i++) {
            $n = ord($der[$o + 1]);
            $out .= str_pad(ltrim(substr($der, $o + 2, $n), "\0"), 32, "\0", STR_PAD_LEFT);
            $o += 2 + $n;
        }
        return $out;
    }

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    private static function dn(string $cn): string
    {
        return self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, self::tlv(0x06, "\x55\x04\x03"), self::tlv(0x0c, $cn))));
    }

    private static function ext(string $oid, string $v): string
    {
        return self::tlv(0x30, self::tlv(0x06, $oid), self::tlv(0x04, $v));
    }

    private static function ecAlg(): string
    {
        return self::tlv(0x30, self::tlv(0x06, "\x2a\x86\x48\xce\x3d\x04\x03\x02"));
    }

    /** @param list<string> $exts */
    private static function cert(string $issuerCn, string $subjectCn, string $serial, string $subjectKey, string $signerKey, array $exts): string
    {
        $val = self::tlv(0x30, self::tlv(0x17, '200101000000Z'), self::tlv(0x17, '490101000000Z'));
        $e = $exts === [] ? '' : self::tlv(0xa3, self::tlv(0x30, ...$exts));
        $tbs = self::tlv(0x30, self::tlv(0xa0, self::tlv(0x02, "\x02")), self::tlv(0x02, $serial), self::ecAlg(), self::dn($issuerCn), $val, self::dn($subjectCn), self::spki(self::key($subjectKey)), $e);
        openssl_sign($tbs, $sig, self::key($signerKey), OPENSSL_ALGO_SHA256);
        return self::tlv(0x30, $tbs, self::ecAlg(), self::tlv(0x03, "\0" . $sig));
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    /** @param list<string> $revoked serial bytes */
    private static function crl(string $issuerCn, string $signerKey, array $revoked = []): string
    {
        $rev = $revoked === [] ? '' : self::tlv(0x30, ...array_map(static fn(string $s): string => self::tlv(0x30, self::tlv(0x02, $s), self::tlv(0x17, '290101000000Z')), $revoked));
        $tbs = self::tlv(0x30, self::tlv(0x02, "\x01"), self::ecAlg(), self::dn($issuerCn), self::tlv(0x17, '291201000000Z'), self::tlv(0x17, '301201000000Z'), $rev);
        openssl_sign($tbs, $sig, self::key($signerKey), OPENSSL_ALGO_SHA256);
        return self::tlv(0x30, $tbs, self::ecAlg(), self::tlv(0x03, "\0" . $sig));
    }

    private static function put(string $s, int $off, string $b): string
    {
        return substr_replace($s, $b, $off, strlen($b));
    }

    private static function sgxExt(): string
    {
        $base = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01";
        $pairs = [];
        for ($i = 1; $i <= 16; $i++) {
            $pairs[] = self::tlv(0x30, self::tlv(0x06, $base . "\x02" . chr($i)), self::tlv(0x02, chr($i)));
        }
        $pairs[] = self::tlv(0x30, self::tlv(0x06, $base . "\x02\x11"), self::tlv(0x02, "\x07"));
        $fmspc = self::tlv(0x30, self::tlv(0x06, $base . "\x04"), self::tlv(0x04, "\x00\x80\x6F\x05\x00\x00"));
        $tcb = self::tlv(0x30, self::tlv(0x06, $base . "\x02"), self::tlv(0x30, ...$pairs));
        return self::ext($base, self::tlv(0x30, $fmspc, $tcb));
    }

    private static function bc(): string
    {
        return self::ext("\x55\x1d\x13", self::tlv(0x30, self::tlv(0x01, "\xff")));
    }

    /** @return list<array{svn:int}> */
    private static function comps(array $at = []): array
    {
        $o = [];
        for ($i = 0; $i < 16; $i++) {
            $o[] = ['svn' => $at[$i] ?? 0];
        }
        return $o;
    }

    private static function qeReport(?callable $edit = null): string
    {
        $b = str_repeat("\0", 384);
        $b = self::put($b, 16, "\x01\x02\x03\x04");
        $attr = '';
        for ($i = 0; $i < 16; $i++) {
            $attr .= chr(5 + $i);
        }
        $b = self::put($b, 48, $attr);
        $b = self::put($b, 128, str_repeat("\xA5", 32));
        $b = self::put($b, 256, pack('v', 258));
        $b = self::put($b, 258, pack('v', 300));
        return $edit === null ? $b : $edit($b);
    }

    /** @return array<string,mixed> the QE identity matching qeReport() */
    private static function qeIdent(): array
    {
        $attr = '';
        for ($i = 0; $i < 16; $i++) {
            $attr .= chr(5 + $i);
        }
        return ['id' => 'TD_QE', 'version' => 2, 'miscselect' => '01020304', 'miscselectMask' => 'FFFFFFFF', 'attributes' => bin2hex($attr),
            'attributesMask' => str_repeat('FF', 16), 'mrsigner' => str_repeat('A5', 32), 'isvprodid' => 258,
            'tcbLevels' => [['tcb' => ['isvsvn' => 400], 'tcbStatus' => 'OutOfDate', 'advisoryIDs' => []], ['tcb' => ['isvsvn' => 300], 'tcbStatus' => 'UpToDate', 'advisoryIDs' => []]]];
    }

    private static function signDoc(string $name, array $body): string
    {
        $raw = json_encode($body, JSON_UNESCAPED_SLASHES);
        return '{"' . $name . '":' . $raw . ',"signature":"' . bin2hex(self::rawSig(self::key('sig'), $raw)) . '"}';
    }

    /**
     * A complete, valid TDX quote with its collateral. Options: debug, td(callable body), qe(callable report), info(callable), ident(callable), rd (report data).
     * @param array<string,mixed> $o
     * @return array<string,mixed>
     */
    private static function fx(array $o = []): array
    {
        $body = str_repeat("\0", 584);
        $body = self::put($body, 16, str_repeat("\x20", 48));
        $ms = '';
        for ($i = 0; $i < 48; $i++) {
            $ms .= chr(0x40 + $i);
        }
        $body = self::put($body, 64, $ms);
        $body = self::put($body, 112, "\x01\x02\x03\x04\x05\x06\x07\x08");
        if (($o['debug'] ?? false) === true) {
            $body = self::put($body, 120, "\x01");
        }
        $body = self::put($body, 136, str_repeat("\xAA", 48));
        $body = self::put($body, 328, str_repeat("\xBB", 48));
        if (isset($o['rd'])) {
            $body = self::put($body, 520, $o['rd']);
        }
        if (isset($o['td'])) {
            $body = $o['td']($body);
        }
        $akRaw = self::point(self::key('ak'));
        $auth = 'auth-data';
        $qe = self::qeReport($o['qe'] ?? null);
        $qe = self::put($qe, 320, hash('sha256', $akRaw . $auth, true) . str_repeat("\0", 32));
        $leaf = self::cert('PCK CA', 'PCK', "\x03", 'pck', 'ca', [self::sgxExt()]);
        $ca = self::cert('Root', 'PCK CA', "\x02", 'ca', 'root', [self::bc()]);
        $root = self::cert('Root', 'Root', "\x01", 'root', 'root', [self::bc()]);
        $pem = self::pem($leaf) . self::pem($ca) . self::pem($root);
        $hdr = pack('vvV', 4, 2, 0x81) . str_repeat("\x07", 40);
        $outer = $qe . self::rawSig(self::key('pck'), $qe) . pack('v', strlen($auth)) . $auth . pack('vV', 5, strlen($pem)) . $pem;
        $sigData = self::rawSig(self::key('ak'), $hdr . $body) . $akRaw . pack('vV', 6, strlen($outer)) . $outer;
        $quote = $hdr . $body . pack('V', strlen($sigData)) . $sigData;

        $info = ['id' => 'TDX', 'version' => 3, 'issueDate' => '2029-12-01T00:00:00Z', 'nextUpdate' => '2030-12-01T00:00:00Z', 'fmspc' => '00806F050000',
            'tcbEvaluationDataNumber' => 17,
            'tdxModule' => ['mrsigner' => bin2hex(substr($body, 64, 48)), 'attributes' => '0102030405060708', 'attributesMask' => 'FFFFFFFFFFFFFFFF'],
            'tcbLevels' => [['tcb' => ['sgxtcbcomponents' => self::comps(), 'pcesvn' => 0, 'tdxtcbcomponents' => self::comps()], 'tcbStatus' => 'UpToDate', 'advisoryIDs' => []]]];
        if (isset($o['info'])) {
            $info = $o['info']($info);
        }
        $ident = self::qeIdent() + ['issueDate' => '2029-12-01T00:00:00Z', 'nextUpdate' => '2030-12-01T00:00:00Z', 'tcbEvaluationDataNumber' => 17];
        if (isset($o['ident'])) {
            $ident = $o['ident']($ident);
        }
        $signer = self::cert('Root', 'TCB Signing', "\x04", 'sig', 'root', []);
        $chain = self::pem($signer) . self::pem($root);
        return [
            'quote' => $quote,
            'coll' => ['tcbInfoJson' => self::signDoc('tcbInfo', $info), 'qeIdentityJson' => self::signDoc('enclaveIdentity', $ident),
                'pckCrlDer' => self::crl('PCK CA', 'ca'), 'rootCrlDer' => self::crl('Root', 'root'),
                'tcbInfoIssuerChainPem' => $chain, 'qeIdentityIssuerChainPem' => $chain],
            'pin' => hash('sha256', self::spki(self::key('root'))),
            'now' => (float)Intel::jsDateParse('2030-01-01T00:00:00Z'),
            'mrtd' => str_repeat('aa', 48),
        ];
    }

    /** @param array<string,mixed> $f @param array<string,mixed>|null $policy @return array<string,mixed> */
    private static function runCase(array $f, ?array $policy = null, bool $debug = false): array
    {
        return Intel::verifyCollateral($f['quote'], $f['coll'], $f['now'], $policy, $f['pin'], $debug);
    }

    private static function inv(string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Intel::class, $method))->invoke(null, ...$args);
    }

    private static function ms(int $y, int $mo, int $d, int $h = 0, int $mi = 0, int $s = 0, int $ms = 0): int
    {
        return gmmktime($h, $mi, $s, $mo, $d, $y) * 1000 + $ms;
    }

    // ---- pipeline ---------------------------------------------------------------------------------------------------------------

    public function testAValidQuoteAndCollateralPass(): void
    {
        // an uppercase FMSPC in the signed TCB info matches the quote's lowercase one; the TD report fields are read from their offsets
        $this->assertSame(['ok' => true, 'status' => 'UpToDate', 'advisoryIds' => []], self::runCase(self::fx()));
    }

    public function testADebugTdIsRefusedUnlessAllowed(): void
    {
        $f = self::fx(['debug' => true]);
        $this->assertSame(['ok' => false, 'reason' => 'quote invalid: TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)'], self::runCase($f));
        $this->assertSame(['ok' => true, 'status' => 'UpToDate', 'advisoryIds' => []], self::runCase($f, null, true));
    }

    public function testAnUnparseableQuoteIsReportedWithItsReason(): void
    {
        $f = self::fx();
        $f['quote'] = 'x';
        $this->assertSame(['ok' => false, 'reason' => 'quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length'], self::runCase($f));
    }

    public function testAnIssuerChainThatIsNotAStringIsRefusedAsInvalidNotAsAnError(): void
    {
        $f = self::fx();
        $f['coll']['tcbInfoIssuerChainPem'] = 7;
        $this->assertSame(['ok' => false, 'reason' => 'TCB info: issuer chain invalid: no PEM certificates in the PCK chain'], self::runCase($f));
        $f = self::fx();
        $f['coll']['qeIdentityIssuerChainPem'] = 7;
        $this->assertSame(['ok' => false, 'reason' => 'QE identity: issuer chain invalid: no PEM certificates in the PCK chain'], self::runCase($f));
    }

    public function testAnUnexpectedErrorFailsClosedWithItsMessage(): void
    {
        $f = self::fx();
        $f['coll']['rootCrlDer'] = ['x'];
        $r = self::runCase($f);
        $this->assertFalse($r['ok']);
        $this->assertSame(['ok', 'reason'], array_keys($r));
        $this->assertStringStartsWith('collateral verification error (fail closed): ', $r['reason']);
        $this->assertStringContainsString('must be of type string, array given', $r['reason']);
    }

    public function testABooleanEvaluationFloorStillApplies(): void
    {
        $half = static function (array $i): array {
            $i['tcbEvaluationDataNumber'] = 0.5;
            return $i;
        };
        $halfQe = static function (array $i): array {
            $i['tcbEvaluationDataNumber'] = 0.5;
            return $i;
        };
        $f = self::fx(['info' => $half, 'ident' => $halfQe]);
        // `true` reads as 1: 0.5 is below it
        $this->assertSame(['ok' => false, 'reason' => 'tcbEvaluationDataNumber below policy minimum'], self::runCase($f, ['minTcbEvaluationDataNumber' => true]));
        $this->assertTrue(self::runCase($f, ['minTcbEvaluationDataNumber' => false])['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'tcbEvaluationDataNumber below policy minimum'], self::runCase(self::fx(), ['minTcbEvaluationDataNumber' => 18]));
        $this->assertTrue(self::runCase(self::fx(), ['minTcbEvaluationDataNumber' => 17])['ok']);
    }

    public function testAZeroEvaluationNumberIsPresentButANegativeOrMissingOneIsNot(): void
    {
        $set = static fn(int $n): callable => static function (array $i) use ($n): array {
            $i['tcbEvaluationDataNumber'] = $n;
            return $i;
        };
        $this->assertTrue(self::runCase(self::fx(['info' => $set(0)]))['ok']);
        $this->assertTrue(self::runCase(self::fx(['ident' => $set(0)]))['ok']);
        $miss = static function (array $i): array {
            unset($i['tcbEvaluationDataNumber']);
            return $i;
        };
        $this->assertSame(['ok' => false, 'reason' => 'tcbEvaluationDataNumber missing'], self::runCase(self::fx(['info' => $miss])));
        $this->assertSame(['ok' => false, 'reason' => 'tcbEvaluationDataNumber missing'], self::runCase(self::fx(['ident' => $miss])));
        $this->assertSame(['ok' => false, 'reason' => 'tcbEvaluationDataNumber missing'], self::runCase(self::fx(['info' => $set(-1)])));
    }

    public function testTheSeamAttributesAreTheEightBytesAtOffset112(): void
    {
        $f = self::fx(['td' => static fn(string $b): string => self::put($b, 119, "\x99")]);
        $this->assertSame(['ok' => false, 'reason' => 'TCB evaluation: TD report SEAM attributes do not match the TDX module identity'], self::runCase($f));
    }

    public function testMergedAdvisoriesAreSorted(): void
    {
        $f = self::fx([
            'info' => static function (array $i): array {
                $i['tcbLevels'][0]['advisoryIDs'] = ['INTEL-SA-00002'];
                return $i;
            },
            'ident' => static function (array $i): array {
                $i['tcbLevels'][1]['advisoryIDs'] = ['INTEL-SA-00001'];
                return $i;
            },
        ]);
        $this->assertSame(['ok' => true, 'status' => 'UpToDate', 'advisoryIds' => ['INTEL-SA-00001', 'INTEL-SA-00002']], self::runCase($f));
    }

    public function testTheQeLevelsAreMatchedAgainstTheSixteenBitIsvsvn(): void
    {
        // the QE report carries ISVSVN 300: the first level (400) is above it, the second (300) is the hit
        $f = self::fx();
        $this->assertSame('UpToDate', self::runCase($f)['status']);
        $f = self::fx(['qe' => static fn(string $b): string => self::put($b, 258, pack('v', 400))]);
        $this->assertSame(['ok' => false, 'status' => 'OutOfDate', 'advisoryIds' => [], 'reason' => 'TCB status OutOfDate is not accepted by policy'], self::runCase($f));
    }

    // ---- the verifier object ----------------------------------------------------------------------------------------------------

    /** @param array<string,mixed> $pol */
    private static function ctorMessage(array $pol, array $extra = []): ?string
    {
        try {
            new Intel(['binding' => 'report-data', 'policy' => $pol] + $extra, static fn() => null);
        } catch (AttestConstructError $e) {
            return $e->getMessage();
        }
        return null;
    }

    public function testTheMrtdAllowlistIsReadAsStrings(): void
    {
        $this->assertSame('createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)', self::ctorMessage(['mrtds' => [5]]));
        $this->assertNull(self::ctorMessage(['mrtds' => [str_repeat('aB', 48)]]));
    }

    public function testTheSeamAllowlistsMustBeHexStringsOf48Bytes(): void
    {
        foreach (['mrSeams', 'mrSignerSeams'] as $name) {
            foreach ([[5], [str_repeat('zz', 48)], [str_repeat('ab', 47)]] as $i => $bad) {
                $this->assertSame("createIntelDcapVerifier: every $name entry must be 96 hex chars (48 bytes)",
                    self::ctorMessage(['mrtds' => [str_repeat('ab', 48)], $name => $bad]), "$name $i");
            }
            $this->assertNull(self::ctorMessage(['mrtds' => [str_repeat('ab', 48)], $name => [str_repeat('aB', 48)]]));
        }
    }

    public function testThePinIsLowercased(): void
    {
        $pin = new \ReflectionProperty(Intel::class, 'pin');
        $pol = ['mrtds' => [str_repeat('ab', 48)]];
        $v = new Intel(['binding' => 'report-data', 'policy' => $pol, 'trustAnchorRootCaSpkiSha256' => str_repeat('AB', 32)], static fn() => null);
        $this->assertSame(str_repeat('ab', 32), $pin->getValue($v));
        $this->assertSame(Intel::SGX_ROOT_CA_SPKI_SHA256, $pin->getValue(new Intel(['binding' => 'report-data', 'policy' => $pol], static fn() => null)));
    }

    public function testAnUnreadableClockIsTimeZeroNotNow(): void
    {
        $f = self::fx();
        $v = new Intel(['binding' => 'report-data', 'policy' => ['mrtds' => [$f['mrtd']]], 'trustAnchorRootCaSpkiSha256' => $f['pin']],
            static fn() => ['quote' => $f['quote'], 'collateral' => $f['coll']]);
        $this->assertSame(['ok' => false, 'reason' => 'DCAP quote invalid: PCK chain invalid: PCK chain certificate outside its validity period'],
            $v->verify('doc', ['holderPub' => 'h', 'grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n'], null));
    }

    public function testAResolverErrorFailsClosedWithItsMessage(): void
    {
        $v = new Intel(['binding' => 'report-data', 'policy' => ['mrtds' => [str_repeat('ab', 48)]]], static function () {
            throw new \RuntimeException('boom');
        });
        $this->assertSame(['ok' => false, 'reason' => 'intel-dcap verification error (fail closed): boom'], $v->verify('d', ['x' => 1], 1));
    }

    // ---- signed JSON ------------------------------------------------------------------------------------------------------------

    public function testTheRawJsonScannerClosesStringsAndBalancesBraces(): void
    {
        $this->assertSame('{"a":"x","b":1}', self::inv('rawJsonObject', '{"tcbInfo":{"a":"x","b":1}}', 'tcbInfo'));
        $this->assertSame('{"a":"}"}', self::inv('rawJsonObject', '{"tcbInfo":{"a":"}"}}', 'tcbInfo'));
        $this->assertSame('{"a":"x\\"}y"}', self::inv('rawJsonObject', '{"tcbInfo":{"a":"x\\"}y"}}', 'tcbInfo'));
        $this->assertSame('{"a":{"b":1}}', self::inv('rawJsonObject', '{"tcbInfo":{"a":{"b":1}}}', 'tcbInfo'));
        $this->assertNull(self::inv('rawJsonObject', '{"tcbInfo":{"a":1', 'tcbInfo'));
    }

    public function testASignedBodyIsReturnedUnderBody(): void
    {
        $k = self::key('sig');
        $pub = Common::loadPublicKey(self::spki($k));
        $doc = self::signDoc('tcbInfo', ['a' => 'x', 'n' => 1]);
        $r = self::inv('verifySignedJson', $doc, 'tcbInfo', $pub);
        $this->assertSame(['body'], array_keys($r));
        $this->assertSame('x', Common::g($r['body'], 'a'));
        $this->assertSame(['error' => 'tcbInfo signature does not verify under the TCB Signing certificate'],
            self::inv('verifySignedJson', $doc, 'tcbInfo', Common::loadPublicKey(self::spki(self::key('ak')))));
    }

    // ---- dates ------------------------------------------------------------------------------------------------------------------

    public function testDateParseReadsEveryField(): void
    {
        $p = static fn(string $s): ?int => Intel::jsDateParse($s);
        $this->assertSame(self::ms(2026, 3, 4, 5, 6, 7), $p('2026-03-04T05:06:07Z'));
        $this->assertSame(self::ms(2026, 3, 4, 5, 6, 7), $p('2026-03-04T05:06:07'));
        $this->assertSame(self::ms(2026, 3, 4), $p('2026-03-04'));
        $this->assertSame(self::ms(2026, 3, 4, 5, 6), $p('2026-03-04T05:06Z'));
        $this->assertSame(self::ms(2026, 3, 4, 5, 6, 7, 123), $p('2026-03-04T05:06:07.123Z'));
        $this->assertSame(self::ms(2026, 3, 4, 5, 6, 7, 100), $p('2026-03-04T05:06:07.1Z'));
        $this->assertSame(self::ms(2026, 3, 4, 5, 6, 7, 123), $p('2026-03-04T05:06:07.1239Z'));
        $this->assertSame(self::ms(2026, 3, 4, 5, 6, 7, 123), $p('2026-03-04T05:06:07.12345Z'));
        $this->assertSame(self::ms(2026, 3, 4, 5, 6, 7, 1), $p('2026-03-04T05:06:07.001Z'));
    }

    public function testDateParseAppliesTheZoneOffset(): void
    {
        $p = static fn(string $s): ?int => Intel::jsDateParse($s);
        $base = self::ms(2026, 3, 4, 5, 6, 7);
        $this->assertSame($base - (5 * 3600 + 30 * 60) * 1000, $p('2026-03-04T05:06:07+05:30'));
        $this->assertSame($base + (5 * 3600 + 30 * 60) * 1000, $p('2026-03-04T05:06:07-05:30'));
        $this->assertSame($base, $p('2026-03-04T05:06:07+00:00'));
        $this->assertSame($base - (23 * 3600 + 59 * 60) * 1000, $p('2026-03-04T05:06:07+23:59'));
        $this->assertNull($p('2026-03-04T05:06:07-24:00'));
        $this->assertNull($p('2026-03-04T05:06:07+24:00'));
        $this->assertNull($p('2026-03-04T05:06:07-00:60'));
    }

    public function testDateParseNeverTouchesAZoneOffsetThatIsNotThere(): void
    {
        set_error_handler(static function (int $no, string $str): bool {
            throw new \ErrorException($str, 0, $no);
        });
        try {
            $this->assertSame(self::ms(2026, 3, 4, 5, 6, 7), Intel::jsDateParse('2026-03-04T05:06:07'));
            $this->assertSame(self::ms(2026, 3, 4), Intel::jsDateParse('2026-03-04'));
        } finally {
            restore_error_handler();
        }
    }

    public function testDateParseTakesHour24OnlyAsMidnightOfTheNextDay(): void
    {
        $p = static fn(string $s): ?int => Intel::jsDateParse($s);
        $this->assertSame(self::ms(2026, 3, 5), $p('2026-03-04T24:00:00Z'));
        $this->assertSame(self::ms(2026, 3, 5), $p('2026-03-04T24:00:00.000Z'));
        $this->assertSame(self::ms(2026, 3, 5), $p('2026-03-04T24:00Z'));
        foreach (['24:00:01', '24:01:00', '24:00:00.001', '24:01:01', '25:00:00'] as $t) {
            $this->assertNull($p("2026-03-04T{$t}Z"), $t);
        }
    }

    public function testDateParseRefusesEachFieldOutOfRange(): void
    {
        $p = static fn(string $s): ?int => Intel::jsDateParse($s);
        foreach (['2026-00-10', '2026-13-10', '2026-03-00', '2026-03-32', '2026-04-31', '2026-02-29', '2026-03-04T25:00:00Z', '2026-03-04T23:60:00Z', '2026-03-04T23:59:60Z'] as $s) {
            $this->assertNull($p($s), $s);
        }
        $this->assertSame(self::ms(2026, 3, 31, 23, 59, 59), $p('2026-03-31T23:59:59Z'));
        $this->assertSame(self::ms(2026, 12, 1), $p('2026-12-01'));
        $this->assertSame(self::ms(2028, 2, 29), $p('2028-02-29'));
    }

    public function testFreshnessNeedsBothDatesAndIsInclusiveAtBothEnds(): void
    {
        $issue = '2030-01-01T00:00:00Z';
        $next = '2030-02-01T00:00:00Z';
        $i = (float)Intel::jsDateParse($issue);
        $n = (float)Intel::jsDateParse($next);
        $f = static fn(array $b, float $now): mixed => self::inv('checkFresh', $b, 'X', $now);
        $this->assertSame('X: issueDate/nextUpdate missing', $f(['issueDate' => $issue], $i));
        $this->assertSame('X: issueDate/nextUpdate missing', $f(['nextUpdate' => $next], $i));
        $this->assertSame('X: issueDate/nextUpdate missing', $f([], $i));
        $this->assertSame('X: issueDate/nextUpdate missing', $f(['issueDate' => 'nope', 'nextUpdate' => $next], $i));
        $this->assertNull($f(['issueDate' => $issue, 'nextUpdate' => $next], $i));
        $this->assertSame('X: issueDate is in the future', $f(['issueDate' => $issue, 'nextUpdate' => $next], $i - 1));
        $this->assertNull($f(['issueDate' => $issue, 'nextUpdate' => $next], $n));
        $this->assertSame('X: stale (nextUpdate passed)', $f(['issueDate' => $issue, 'nextUpdate' => $next], $n + 1));
    }

    // ---- small helpers ----------------------------------------------------------------------------------------------------------

    public function testWorstKeepsTheFirstOnATie(): void
    {
        $this->assertSame('Revoked', self::inv('worst', 'UpToDate', 'Revoked'));
        $this->assertSame('Revoked', self::inv('worst', 'Revoked', 'UpToDate'));
        $this->assertSame('OutOfDate', self::inv('worst', 'OutOfDate', 'OutOfDate'));
        // the reference's indexOf is -1 for both: the first wins
        $this->assertSame('x', self::inv('worst', 'x', 'y'));
        $this->assertSame('y', self::inv('worst', 'y', 'x'));
    }

    public function testSvnsNeedsAListOfSixteenObjects(): void
    {
        $this->assertSame(array_fill(0, 16, 3.0), self::inv('svns', array_fill(0, 16, ['svn' => 3])));
        $this->assertNull(self::inv('svns', 'x'));
        $this->assertNull(self::inv('svns', null));
        $this->assertNull(self::inv('svns', ['a' => 1]));
        $this->assertNull(self::inv('svns', array_fill(0, 15, ['svn' => 3])));
        $this->assertNull(self::inv('svns', array_fill(0, 17, ['svn' => 3])));
        $this->assertNull(self::inv('svns', array_fill(0, 16, 5)));
        $this->assertNull(self::inv('svns', array_fill(0, 16, ['svn' => 'x'])));
    }

    public function testHexBytesNeedsExactlyTheRightLengthOfHex(): void
    {
        $this->assertSame(str_repeat("\xab", 4), self::inv('hexBytes', 'abababab', 4));
        $this->assertSame(str_repeat("\xab", 4), self::inv('hexBytes', 'ABABABAB', 4));
        $this->assertNull(self::inv('hexBytes', 'ab', 4));
        $this->assertNull(self::inv('hexBytes', 'abababababab', 4));
        $this->assertNull(self::inv('hexBytes', 'zzzzzzzz', 4));
        $this->assertNull(self::inv('hexBytes', 5, 4));
        $this->assertNull(self::inv('hexBytes', null, 4));
    }

    public function testAdvisoriesKeepOnlyTheStringsAsAList(): void
    {
        $this->assertSame(['A', 'B'], self::inv('advisories', ['advisoryIDs' => ['A', 5, 'B']]));
        $this->assertSame(['A'], self::inv('advisories', ['advisoryIDs' => [5, 'A']]));
        $this->assertSame([], self::inv('advisories', ['advisoryIDs' => 'x']));
        $this->assertSame([], self::inv('advisories', []));
    }

    public function testMaskedEqComparesEveryByteOfTheValue(): void
    {
        $this->assertTrue(self::inv('maskedEq', "\x0F", "\x0F", "\x0F"));
        $this->assertTrue(self::inv('maskedEq', "\xFF", "\x0F", "\x0F"));
        $this->assertFalse(self::inv('maskedEq', "\x0F", "\xFF", "\x0E"));
        $this->assertTrue(self::inv('maskedEq', '', '', ''));
        // the last byte is judged under ITS mask byte (index 1), not the last mask byte
        $this->assertTrue(self::inv('maskedEq', "\x00\x01", "\xFF\x00\x00\xFF", "\x00\x00\x00\x00"));
        $this->assertFalse(self::inv('maskedEq', "\x00\x01", "\xFF\xFF\x00\x00", "\x00\x00\x00\x00"));
    }

    public function testTruthyIsTheReferencesTruthinessOfACollateralMember(): void
    {
        $this->assertTrue(self::inv('truthy', true));
        $this->assertTrue(self::inv('truthy', 'x'));
        $this->assertTrue(self::inv('truthy', 0));
        $this->assertTrue(self::inv('truthy', '0'));
        $this->assertFalse(self::inv('truthy', false));
        $this->assertFalse(self::inv('truthy', null));
        $this->assertFalse(self::inv('truthy', ''));
        $this->assertFalse(self::inv('truthy', []));
    }

    // ---- TCB evaluation ---------------------------------------------------------------------------------------------------------

    /** @return array<string,mixed> */
    private static function lvl(?array $sgx = null, ?array $tdx = null, mixed $pce = 0, string $status = 'UpToDate', array $adv = []): array
    {
        return ['tcb' => ['sgxtcbcomponents' => $sgx ?? self::comps(), 'tdxtcbcomponents' => $tdx ?? self::comps(), 'pcesvn' => $pce], 'tcbStatus' => $status, 'advisoryIDs' => $adv];
    }

    private static function mod(): array
    {
        return ['mrsigner' => str_repeat('00', 48), 'attributes' => '0000000000000000', 'attributesMask' => 'FFFFFFFFFFFFFFFF'];
    }

    /** @return array<string,string> */
    private static function td(int $minor = 0, int $svn0 = 0): array
    {
        return ['teeTcbSvn' => chr($svn0) . chr($minor) . str_repeat("\0", 14), 'mrSignerSeam' => str_repeat("\0", 48), 'seamAttributes' => str_repeat("\0", 8)];
    }

    /** @param array<string,mixed> $info */
    private static function evi(array $info, int $minor = 0): array
    {
        return self::inv('evaluateTcb', $info, ['sgx' => str_repeat("\0", 16), 'pcesvn' => 0], self::td($minor));
    }

    private static function ev(array $levels, int $minor = 0, array $extra = []): array
    {
        return self::evi(['tcbLevels' => $levels, 'tdxModule' => self::mod()] + $extra, $minor);
    }

    private static function ident(string $id = 'TDX_01', string $status = 'UpToDate', array $over = []): array
    {
        return $over + self::mod() + ['id' => $id, 'tcbLevels' => [['tcb' => ['isvsvn' => 0], 'tcbStatus' => $status, 'advisoryIDs' => []]]];
    }

    private const BELOW = ['error' => 'platform TCB is below every level in the TCB info'];
    private const OK = ['platform' => 'UpToDate', 'module' => 'UpToDate', 'advisories' => []];

    public function testTdxComponentsAreComparedFromTheRightIndex(): void
    {
        $this->assertSame(self::BELOW, self::ev([self::lvl(null, self::comps([0 => 1]))]));
        $this->assertSame(self::BELOW, self::ev([self::lvl(null, self::comps([1 => 1]))]));
        $this->assertSame(self::OK, self::ev([self::lvl()]));
        $ids = ['tdxModuleIdentities' => [self::ident()]];
        $this->assertSame(self::OK, self::ev([self::lvl(null, self::comps([0 => 5, 1 => 5]))], 1, $ids));
        $this->assertSame(self::BELOW, self::ev([self::lvl(null, self::comps([2 => 1]))], 1, $ids));
    }

    public function testEverySgxComponentCountsAndAMissContinuesToTheNextLevel(): void
    {
        $this->assertSame(self::BELOW, self::ev([self::lvl(self::comps([1 => 5]))]));
        $this->assertSame(self::BELOW, self::ev([self::lvl(self::comps([15 => 5]))]));
        $r = self::ev([self::lvl(self::comps([0 => 9]), null, 0, 'OutOfDate'), self::lvl(null, null, 0, 'SWHardeningNeeded', ['A'])]);
        $this->assertSame(['platform' => 'SWHardeningNeeded', 'module' => 'UpToDate', 'advisories' => ['A']], $r);
    }

    public function testMalformedLevelsAreRefusedWhicheverPartIsBad(): void
    {
        $bad = ['error' => 'malformed TCB level components'];
        $good = self::comps();
        $this->assertSame($bad, self::ev([self::lvl(array_slice($good, 0, 15))]));
        $this->assertSame($bad, self::ev([self::lvl(null, array_slice($good, 0, 15))]));
        $this->assertSame($bad, self::ev([self::lvl(null, null, 'x')]));
        $this->assertSame($bad, self::ev([self::lvl(array_slice($good, 0, 15), array_slice($good, 0, 15))]));
        $this->assertSame($bad, self::ev([self::lvl(array_slice($good, 0, 15), null, 'x')]));
        $this->assertSame(['error' => 'malformed TCB level'], self::ev([5]));
        $this->assertSame(['error' => 'malformed TCB level'], self::ev([['tcb' => 'x']]));
        $this->assertSame(['error' => 'TCB level has an unknown tcbStatus'], self::ev([self::lvl(null, null, 0, 'Bogus')]));
        $this->assertSame(['error' => 'TCB info has no tcbLevels'], self::evi(['tcbLevels' => [], 'tdxModule' => self::mod()]));
        $this->assertSame(['error' => 'TCB info has no tcbLevels'], self::evi(['tcbLevels' => 'x', 'tdxModule' => self::mod()]));
        $this->assertSame(['error' => 'TCB info missing tdxModule'], self::evi(['tcbLevels' => [self::lvl()]]));
    }

    public function testTheModuleIdentityIsFoundByIdAndTheFirstOneWins(): void
    {
        $nf = ['error' => 'TDX module identity TDX_01 not present in TCB info'];
        $this->assertSame($nf, self::ev([self::lvl()], 1));
        $this->assertSame($nf, self::ev([self::lvl()], 1, ['tdxModuleIdentities' => 'x']));
        $this->assertSame(self::OK, self::ev([self::lvl()], 1, ['tdxModuleIdentities' => [5, self::ident()]]));
        // an identity with another id in front is skipped
        $this->assertSame(self::OK, self::ev([self::lvl()], 1, ['tdxModuleIdentities' => [self::ident('TDX_02', 'OutOfDate'), self::ident()]]));
        // two identities with the id: the first
        $this->assertSame(self::OK, self::ev([self::lvl()], 1, ['tdxModuleIdentities' => [self::ident(), self::ident('TDX_01', 'OutOfDate')]]));
        $noLevels = self::ident();
        unset($noLevels['tcbLevels']);
        $this->assertSame(['error' => 'TDX module TDX_01 SVN 0 is below every known level'], self::ev([self::lvl()], 1, ['tdxModuleIdentities' => [$noLevels]]));
        $this->assertSame(['error' => 'TDX module level has an unknown tcbStatus'], self::ev([self::lvl()], 1, ['tdxModuleIdentities' => [self::ident('TDX_01', 'Bogus')]]));
    }

    public function testTheModuleLevelAdvisoriesAreReported(): void
    {
        $id = self::ident();
        $id['tcbLevels'][0]['advisoryIDs'] = ['MOD-1'];
        $this->assertSame(['platform' => 'UpToDate', 'module' => 'UpToDate', 'advisories' => ['MOD-1']], self::ev([self::lvl()], 1, ['tdxModuleIdentities' => [$id]]));
        $id['tcbLevels'][0]['tcbStatus'] = 'SWHardeningNeeded';
        $this->assertSame(['platform' => 'UpToDate', 'module' => 'SWHardeningNeeded', 'advisories' => ['MOD-1']], self::ev([self::lvl()], 1, ['tdxModuleIdentities' => [$id]]));
    }

    public function testAdvisoryIdsComeBackAsSortedStrings(): void
    {
        $r = self::ev([self::lvl(null, null, 0, 'UpToDate', ['B', '123', 'A'])]);
        $this->assertSame(['platform' => 'UpToDate', 'module' => 'UpToDate', 'advisories' => ['123', 'A', 'B']], $r);
    }

    public function testEachModuleFieldMustBeWellFormedOnItsOwn(): void
    {
        foreach (['mrsigner', 'attributes', 'attributesMask'] as $field) {
            $m = self::mod();
            $m[$field] = null;
            $this->assertSame(['error' => 'TDX module identity fields malformed'], self::evi(['tcbLevels' => [self::lvl()], 'tdxModule' => $m]), $field);
        }
        $m = self::mod();
        $m['mrsigner'] = str_repeat('01', 48);
        $this->assertSame(['error' => 'TD report MRSIGNERSEAM does not match the TDX module identity'], self::evi(['tcbLevels' => [self::lvl()], 'tdxModule' => $m]));
        $m = self::mod();
        $m['attributes'] = '0100000000000000';
        $this->assertSame(['error' => 'TD report SEAM attributes do not match the TDX module identity'], self::evi(['tcbLevels' => [self::lvl()], 'tdxModule' => $m]));
    }

    // ---- QE evaluation ----------------------------------------------------------------------------------------------------------

    public function testTheQeIdentityMatchesAndReportsItsLevel(): void
    {
        $ok = ['status' => 'UpToDate', 'advisories' => []];
        $this->assertSame($ok, self::inv('evaluateQe', self::qeIdent(), self::qeReport()));
        $id = self::qeIdent();
        $id['tcbLevels'][1]['advisoryIDs'] = ['QE-1', 7];
        $this->assertSame(['status' => 'UpToDate', 'advisories' => ['QE-1']], self::inv('evaluateQe', $id, self::qeReport()));
    }

    public function testTheQeReportFieldsAreReadAtTheirOffsets(): void
    {
        $qe = static fn(callable $edit): string => self::qeReport($edit);
        $id = self::qeIdent();
        // MISCSELECT is the four bytes at 16: the last one (19) counts, its neighbours (15, 20) do not
        $this->assertSame(['error' => 'QE MISCSELECT does not match the QE identity'], self::inv('evaluateQe', $id, $qe(static fn(string $b): string => self::put($b, 19, "\xFF"))));
        $this->assertSame(['status' => 'UpToDate', 'advisories' => []], self::inv('evaluateQe', $id, $qe(static fn(string $b): string => self::put(self::put($b, 15, "\xFF"), 20, "\xFF"))));
        // ATTRIBUTES is the sixteen bytes at 48: the last one (63) counts
        $this->assertSame(['error' => 'QE ATTRIBUTES do not match the QE identity'], self::inv('evaluateQe', $id, $qe(static fn(string $b): string => self::put($b, 63, "\xFF"))));
        $this->assertSame(['status' => 'UpToDate', 'advisories' => []], self::inv('evaluateQe', $id, $qe(static fn(string $b): string => self::put(self::put($b, 47, "\xFF"), 64, "\xFF"))));
        $this->assertSame(['error' => 'QE MRSIGNER does not match the QE identity'], self::inv('evaluateQe', $id, $qe(static fn(string $b): string => self::put($b, 159, "\x00"))));
    }

    public function testTheQeProductAndSecurityVersionsAreSixteenBitLittleEndian(): void
    {
        $id = self::qeIdent();
        $this->assertSame(['error' => 'QE ISVPRODID does not match the QE identity'], self::inv('evaluateQe', $id, self::qeReport(static fn(string $b): string => self::put($b, 256, pack('v', 2)))));
        $this->assertSame(['error' => 'QE ISVPRODID does not match the QE identity'], self::inv('evaluateQe', $id, self::qeReport(static fn(string $b): string => self::put($b, 256, pack('v', 514)))));
        $this->assertSame(['error' => 'QE ISVPRODID does not match the QE identity'], self::inv('evaluateQe', $id, self::qeReport(static fn(string $b): string => self::put($b, 256, pack('v', 130)))));
        // ISVSVN 300 hits the 300 level, ISVSVN 400 the 400 one, 299 and a high byte beyond 16 bits nothing / the same
        $this->assertSame('OutOfDate', self::inv('evaluateQe', $id, self::qeReport(static fn(string $b): string => self::put($b, 258, pack('v', 400))))['status']);
        $this->assertSame(['error' => 'QE ISVSVN is below every known level'], self::inv('evaluateQe', $id, self::qeReport(static fn(string $b): string => self::put($b, 258, pack('v', 299)))));
        $this->assertSame(['error' => 'QE ISVSVN is below every known level'], self::inv('evaluateQe', $id, self::qeReport(static fn(string $b): string => self::put($b, 258, pack('v', 44)))));
        $none = $id;
        unset($none['tcbLevels']);
        $this->assertSame(['error' => 'QE ISVSVN is below every known level'], self::inv('evaluateQe', $none, self::qeReport()));
    }

    public function testTheQeIdentityRefusalsHaveTheirExactReasons(): void
    {
        $id = self::qeIdent();
        $e = static fn(string $m): array => ['error' => $m];
        $this->assertSame($e('QE identity id is not TD_QE'), self::inv('evaluateQe', ['id' => 'X'] + $id, self::qeReport()));
        $this->assertSame($e('unsupported QE identity version'), self::inv('evaluateQe', ['version' => 1] + $id, self::qeReport()));
        $nov = $id;
        unset($nov['version']);
        $this->assertSame($e('unsupported QE identity version'), self::inv('evaluateQe', $nov, self::qeReport()));
        foreach (['miscselect', 'miscselectMask', 'attributes', 'attributesMask', 'mrsigner', 'isvprodid'] as $f) {
            $bad = $id;
            $bad[$f] = 'zz';
            $this->assertSame($e('QE identity fields malformed'), self::inv('evaluateQe', $bad, self::qeReport()), $f);
        }
        $this->assertSame($e('QE report has wrong length'), self::inv('evaluateQe', $id, str_repeat("\0", 383)));
        $this->assertSame($e('QE report has wrong length'), self::inv('evaluateQe', $id, str_repeat("\0", 385)));
        $bogus = $id;
        $bogus['tcbLevels'][1]['tcbStatus'] = 'Bogus';
        $this->assertSame($e('QE level has an unknown tcbStatus'), self::inv('evaluateQe', $bogus, self::qeReport()));
    }

    public function testTheDebugDefaultOfVerifyCollateralIsToRefuse(): void
    {
        $f = self::fx(['debug' => true]);
        $this->assertSame(['ok' => false, 'reason' => 'quote invalid: TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)'],
            Intel::verifyCollateral($f['quote'], $f['coll'], $f['now'], null, $f['pin']));
    }
}
