<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestVendors;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The public facades of the Intel TDX / DCAP / PCS-collateral, Azure MAA, Google Confidential Space and AMD SNP vendor attestation modules against the TS
 * reference: every case of test-data/ref-attest-vendors.json.gz (the 21 functions of the generator's porting contract), totals asserted. Strings over 400
 * characters are `{"$blob": id}` in the corpus (a table in its header line), bytes are `{"$bytes": b64u}`; both are decoded in arguments and expectations.
 * A text that comes from a library (an OpenSSL `error:...` line, a JSON.parse message, the P-256 library's point errors, `URI malformed`) is compared by
 * presence only. Counted deviation (asserted, never skipped): the cases whose certificate bytes are not valid DER at all only require a refusal, whatever
 * stack parses them.
 */
final class RefAttestVendorsDifferentialTest extends TestCase
{
    private const FILE = 'ref-attest-vendors.json.gz';
    private const FNS = ['constants' => 1, 'toHex' => 8, 'pemToDer' => 10, 'ecdsaP256PublicKey' => 12, 'parseDcapTdReport' => 11, 'parseDcapQuote' => 45,
        'extractPckFmspcAndTcb' => 25, 'verifyIntelPckChainX509' => 46, 'verifyGenuineTdxQuote' => 64, 'verifyCrl' => 34, 'serialIsRevoked' => 10,
        'verifySignedJson' => 31, 'decodeIssuerChainHeader' => 13, 'verifyIntelTdxCollateral' => 159, 'checkAzureRuntimeDataBinding' => 24,
        'parseMaaJwt' => 57, 'parseGcpCsJwt' => 57, 'verifyX5cChain' => 61, 'verifyJwkX5cChain' => 27, 'teeTypeOfHwModel' => 15, 'fetchMaaJwks' => 22,
        'fetchGcpConfidentialSpaceJwks' => 26];
    /** Cases whose certificate bytes are not DER at all: a refusal is all that is required. */
    private const REFUSAL_ONLY = ['verifyIntelPckChainX509/pem-malformed-block', 'verifyX5cChain/malformed-certificate', 'verifyX5cChain/malformed-base64-certificate',
        'verifyX5cChain/malformed-second-certificate', 'verifyX5cChain/anchor-malformed-pem', 'verifyJwkX5cChain/malformed-certificate'];
    private static ?Obj $blobs = null;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function blobs(): Obj
    {
        if (self::$blobs === null) {
            $h = gzopen(Base::path(self::FILE), 'rb');
            $line = (string)gzgets($h);
            gzclose($h);
            $at = strrpos($line, ',"cases":[');
            self::$blobs = Json::parseLax(substr($line, 0, $at === false ? null : $at) . '}')->get('blobs');
        }
        return self::$blobs;
    }

    /** Resolve `{"$blob"}` to its string and `{"$bytes"}` to raw bytes, everywhere; every other object stays an Obj. */
    private static function dec(mixed $x): mixed
    {
        if ($x instanceof Obj) {
            $k = $x->keys();
            if ($k === ['$blob']) {
                return self::blobs()->get($x->get('$blob'));
            }
            if ($k === ['$bytes']) {
                $v = self::dec($x->get('$bytes'));
                return Pca::unb64u((string)$v);
            }
            $o = new Obj();
            foreach ($k as $m) {
                $o->set($m, self::dec($x->get($m)));
            }
            return $o;
        }
        return is_array($x) ? array_map(self::dec(...), $x) : $x;
    }

    private static function mask(string $s): string
    {
        if (preg_match('/\A(bad point|invalid Point|URI malformed)/', $s) === 1) {
            return 'LIB';
        }
        return (string)preg_replace(['/error:[0-9A-Fa-f]{8}:[^;)]*/', '/Unexpected token [\s\S]*? is not valid JSON/', '/Unexpected end of JSON input/', '/Expected [^"]*? in JSON at position \d+/'], 'LIB', $s);
    }

    /** A comparable form: objects and associative arrays by sorted key, numbers as floats, library text masked. */
    private static function norm(mixed $x): mixed
    {
        if ($x instanceof Obj) {
            $m = [];
            foreach ($x->keys() as $k) {
                $m[$k] = self::norm($x->get($k));
            }
            ksort($m, SORT_STRING);
            return $m;
        }
        if ($x instanceof Num) {
            return $x->float();
        }
        if (is_int($x)) {
            return (float)$x;
        }
        if (is_string($x)) {
            return self::mask($x);
        }
        if (is_array($x)) {
            $m = array_map(self::norm(...), $x);
            if (!array_is_list($m)) {
                ksort($m, SORT_STRING);
            }
            return $m;
        }
        return $x;
    }

    private static function show(mixed $x): string
    {
        return substr((string)json_encode($x, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR), 0, 500);
    }

    private static function response(Obj $r): array
    {
        if ($r->has('$throws')) {
            throw new \Exception((string)$r->get('$throws'));
        }
        $b = $r->get('body');
        return ['status' => $r->has('status') ? $r->get('status') : 200, 'body' => $b instanceof Obj && $b->has('$text') ? (string)$b->get('$text') : Js::stringify($b)];
    }

    /** @return array<string,mixed> {ok, jwks | error, requests} over the scripted transport */
    private static function fetchCase(string $fn, Obj $a): array
    {
        $log = [];
        $script = $a->get('script');
        $i = 0;
        $opts = new Obj();
        if ($a->has('opts')) {
            foreach ($a->get('opts')->keys() as $k) {
                $opts->set($k, $a->get('opts')->get($k));
            }
        }
        $opts->set('fetch', static function (string $url) use ($script, &$log, &$i): array {
            $log[] = $url;
            return self::response($script[min($i++, count($script) - 1)]);
        });
        try {
            $jwks = $fn === 'fetchMaaJwks' ? AttestVendors::fetchMaaJwks($a->get('issuer'), $opts) : AttestVendors::fetchGcpConfidentialSpaceJwks($a->get('issuer'), $opts);
            return ['ok' => true, 'jwks' => $jwks, 'requests' => $log];
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage(), 'requests' => $log];
        }
    }

    private static function call(string $fn, array $a): mixed
    {
        return match ($fn) {
            'constants' => AttestVendors::constants(),
            'toHex' => AttestVendors::toHex($a[0]),
            'pemToDer' => AttestVendors::pemToDer($a[0]),
            'ecdsaP256PublicKey' => AttestVendors::ecdsaP256PublicKey($a[0]),
            'parseDcapTdReport' => AttestVendors::parseDcapTdReport($a[0]),
            'parseDcapQuote' => AttestVendors::parseDcapQuote($a[0]),
            'extractPckFmspcAndTcb' => AttestVendors::extractPckFmspcAndTcb($a[0]),
            'verifyIntelPckChainX509' => AttestVendors::verifyIntelPckChainX509($a[0]),
            'verifyGenuineTdxQuote' => AttestVendors::verifyGenuineTdxQuote($a[0]),
            'verifyCrl' => AttestVendors::verifyCrl($a[0], $a[1]->get('spkiDer'), (float)$a[2]->float()),
            'serialIsRevoked' => AttestVendors::serialIsRevoked($a[0], $a[1]),
            'verifySignedJson' => AttestVendors::verifySignedJson($a[0], $a[1], $a[2]->get('spkiDer')),
            'decodeIssuerChainHeader' => AttestVendors::decodeIssuerChainHeader($a[0]),
            'verifyIntelTdxCollateral' => AttestVendors::verifyIntelTdxCollateral($a[0]),
            'checkAzureRuntimeDataBinding' => AttestVendors::checkAzureRuntimeDataBinding($a[0], $a[1], $a[2] ?? null),
            'parseMaaJwt' => AttestVendors::parseMaaJwt($a[0]),
            'parseGcpCsJwt' => AttestVendors::parseGcpCsJwt($a[0]),
            'verifyX5cChain' => AttestVendors::verifyX5cChain($a[0], $a[1] ?? null, $a[2] ?? null),
            'verifyJwkX5cChain' => AttestVendors::verifyJwkX5cChain($a[0], $a[1] ?? null, $a[2] ?? null),
            'teeTypeOfHwModel' => AttestVendors::teeTypeOfHwModel($a[0]),
            'fetchMaaJwks', 'fetchGcpConfidentialSpaceJwks' => self::fetchCase($fn, $a[0]),
        };
    }

    /** One case: null when it agrees, else the description of the mismatch. */
    private static function check(Obj $c, ?bool &$refusalOnly): ?string
    {
        $fn = (string)$c->get('fn');
        $name = (string)$c->get('name');
        $args = self::dec($c->get('args'));
        $want = self::dec($c->get('out'));
        $threw = null;
        $have = null;
        try {
            $have = self::call($fn, $args);
        } catch (\Throwable $e) {
            $threw = $e;
        }
        $refusalOnly = in_array($name, self::REFUSAL_ONLY, true);
        if ($refusalOnly) {
            $refused = $threw !== null || (is_array($have) ? ($have['ok'] ?? null) === false : is_string($have));
            return $refused ? null : "$name: a refusal is required, have " . self::show($have);
        }
        if ($want instanceof Obj && $want->has('$throws')) {
            if ($threw === null) {
                return "$name: want throw " . $want->get('$throws') . ', have ' . self::show($have);
            }
            return self::mask($threw->getMessage()) === self::mask((string)$want->get('$throws')) ? null : "$name: want throw '" . $want->get('$throws') . "', have '" . $threw->getMessage() . "'";
        }
        if ($threw !== null) {
            return "$name: threw " . get_class($threw) . ': ' . $threw->getMessage();
        }
        return self::norm($want) === self::norm($have) ? null : "$name\n   want " . self::show(self::norm($want)) . "\n   have " . self::show(self::norm($have));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $bad = [];
        $n = 0;
        foreach (Base::cases($file, $fn, $k) as $c) {
            $n++;
            $why = self::check($c, $unused);
            if ($why !== null) {
                $bad[] = $why;
            }
        }
        $this->assertGreaterThan(0, $n);
        $this->assertSame([], array_slice($bad, 0, 25), count($bad) . " mismatches in $fn #$k");
    }

    public function testEveryFunctionIsReplayedInFull(): void
    {
        $seen = [];
        $refusalOnly = 0;
        foreach (array_keys(self::FNS) as $fn) {
            for ($k = 0; ($cases = Base::cases(self::FILE, $fn, $k)) !== []; $k++) {
                foreach ($cases as $c) {
                    $seen[$fn] = ($seen[$fn] ?? 0) + 1;
                    $refusalOnly += in_array((string)$c->get('name'), self::REFUSAL_ONLY, true) ? 1 : 0;
                }
            }
        }
        $this->assertSame(self::FNS, $seen);
        $this->assertSame(758, array_sum($seen));
        $this->assertSame(count(self::REFUSAL_ONLY), $refusalOnly, 'counted deviations: refusal-only cases (certificate bytes that are not DER)');
    }
}
