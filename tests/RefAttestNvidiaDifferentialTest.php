<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestNvidia.php';

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\Nvidia;
use Atlas\Pca\Attest\Ocsp;
use Atlas\Pca\AttestNvidia;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The NVIDIA GPU-CC attestation modules against the TS reference: every case of test-data/ref-attest-nvidia.json.gz (SPDM transcript, device chain,
 * report signature, PCA challenge, RIM ids, golden comparison, CRL and OCSP revocation, the OCSP request builder, the fetch helpers) and of
 * ref-attest-nvidia-rim.json.gz (RIM XMLDSig verification, the collateral hook). Strings over 400 characters are `{"$blob": id}` (a table in each
 * header line), hydrated in arguments and expectations; a certificate summary is `{subject, issuer, serial, notBefore, notAfter, spkiSha256, rawSha256, ca}`.
 * Library text (an OpenSSL `error:...` line, a pkijs or xmldom message) is masked in refusal reasons before comparing.
 */
final class RefAttestNvidiaDifferentialTest extends TestCase
{
    private const FILE = 'ref-attest-nvidia.json.gz';
    private const RIM_FILE = 'ref-attest-nvidia-rim.json.gz';
    private const FNS = ['constants' => 1, 'parseReport' => 66, 'formatVbiosVersion' => 9, 'spkiSha256Hex' => 3, 'parsePemChain' => 12, 'verifyDeviceChain' => 63,
        'verifySpdmSignature' => 15, 'spdmChallenge' => 10, 'rimIds' => 26, 'compareReport' => 26, 'checkRevocation' => 39, 'fetchRim' => 12, 'fetchCrl' => 4, 'ocspRequest' => 20,
        'ocspUrls' => 8, 'ocspVerify' => 81, 'ocspChain' => 30, 'fetchOcsp' => 5, 'asn1TimesWellFormed' => 37];
    private const RIM_FNS = ['verifyRim' => 108, 'collateralHook' => 55];
    /** @var array<string,Obj> */
    private static array $blobs = [];

    public static function provide(): array
    {
        return Base::datasets(self::FILE) + Base::datasets(self::RIM_FILE);
    }

    private static function blobs(string $file): Obj
    {
        if (!isset(self::$blobs[$file])) {
            $h = gzopen(Base::path($file), 'rb');
            $line = (string)gzgets($h);
            gzclose($h);
            $at = strrpos($line, ',"cases":[');
            self::$blobs[$file] = Json::parseLax(substr($line, 0, $at === false ? null : $at) . '}')->get('blobs');
        }
        return self::$blobs[$file];
    }

    private static function hydrate(string $file, mixed $x): mixed
    {
        if ($x instanceof Obj) {
            if ($x->keys() === ['$blob']) {
                return self::blobs($file)->get($x->get('$blob'));
            }
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::hydrate($file, $x->get($k)));
            }
            return $o;
        }
        return is_array($x) ? array_map(static fn($e) => self::hydrate($file, $e), $x) : $x;
    }

    private static function mask(mixed $x): mixed
    {
        if (is_string($x)) {
            return preg_replace(['/error:[0-9A-F]{8}:.*\z/s', '/OCSP response rejected:.*\z/s', '/verification error \(fail closed\):.*\z/s'],
                ['LIB', 'OCSP response rejected:', 'verification error (fail closed):'], $x);
        }
        if ($x instanceof Obj) {
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::mask($x->get($k)));
            }
            return $o;
        }
        return is_array($x) ? array_map(self::mask(...), $x) : $x;
    }

    /** Hydrate and mask the expectation of a case; return the masked native result. */
    private static function cmp(string $file, Obj $c, mixed $have): mixed
    {
        $c->set('out', self::mask(self::hydrate($file, $c->get('out'))));
        return self::mask($have);
    }

    private static function bytes(mixed $v): ?string
    {
        return $v === null || $v instanceof \Atlas\Pca\Undef ? null : (string)Base::bytes($v);
    }

    private static function ob(string $raw): Obj
    {
        return Base::outBytes($raw);
    }

    private static function openSslTime(int $ms): string
    {
        $s = intdiv($ms, 1000);
        return gmdate('M', $s) . ' ' . str_pad(gmdate('j', $s), 2, ' ', STR_PAD_LEFT) . gmdate(' H:i:s Y', $s) . ' GMT';
    }

    private static function certSummary(Cert $c): Obj
    {
        [$from, $to] = Der::derValidityMs($c->raw);
        return Obj::of(['subject' => $c->subject(), 'issuer' => $c->issuer(), 'serial' => strtoupper(bin2hex(ltrim($c->serial, "\0"))),
            'notBefore' => self::openSslTime((int)$from), 'notAfter' => self::openSslTime((int)$to), 'spkiSha256' => $c->spkiSha256(), 'rawSha256' => hash('sha256', $c->raw), 'ca' => $c->ca()]);
    }

    private static function reportSummary(array $p): Obj
    {
        $opaque = $p['opaque'];
        ksort($opaque);
        $o = new Obj();
        foreach ($opaque as $t => $v) {
            $o->set((string)$t, self::ob($v));
        }
        return Obj::of([
            'request' => Obj::of(['version' => $p['request']['version'], 'code' => $p['request']['code'], 'param1' => $p['request']['param1'], 'param2' => $p['request']['param2'],
                'nonce' => self::ob($p['request']['nonce']), 'slot' => $p['request']['slot']]),
            'response' => Obj::of(['version' => $p['response_version'], 'code' => $p['response_code'], 'numBlocks' => count($p['measurements']),
                'measurements' => array_map(static fn(array $m): Obj => Obj::of(['index' => $m['index'], 'valueType' => $m['valueType'], 'digest' => self::ob($m['digest'])]), $p['measurements']),
                'responderNonce' => self::ob($p['responder_nonce']), 'opaque' => $o, 'signature' => self::ob($p['signature'])]),
            'signedBytesLength' => strlen($p['signedBytes']), 'signedBytesSha256' => hash('sha256', $p['signedBytes']),
        ]);
    }

    private static function rimSummary(array $r): Obj
    {
        $g = $r['golden'];
        ksort($g);
        return Obj::of(['tagId' => $r['tagId'], 'product' => $r['product'], 'version' => $r['version'], 'golden' => array_values($g), 'signerSubject' => $r['signerSubject']]);
    }

    /** A rim summary (Obj) as the native rim array. */
    private static function rimOf(Obj $r): array
    {
        $golden = [];
        foreach ($r->get('golden') as $g) {
            $golden[] = ['index' => (int)Js::num($g->get('index')), 'active' => $g->get('active') === true, 'alternatives' => (int)Js::num($g->get('alternatives')),
                'size' => (int)Js::num($g->get('size')), 'hashes' => $g->get('hashes')];
        }
        return ['golden' => $golden];
    }

    private static function plain(mixed $x): mixed
    {
        if ($x instanceof \Atlas\Pca\Num) {
            return $x->isInt() && abs($x->float()) < 9e15 ? $x->int() : $x->float();
        }
        return is_array($x) ? array_map(self::plain(...), $x) : $x;
    }

    private static function chainOf(string $pem): array
    {
        return Nvidia::parsePemChain($pem);
    }

    /** A scripted transport answering `{status?, body | bodyBytes, $throws?}` and logging every call as `{url, method, contentType[, bodyBytes]}`. */
    private static function transport(Obj $r, array &$log, bool $ocsp): \Closure
    {
        return static function (string $url, ?Obj $init = null) use ($r, &$log, $ocsp): Obj {
            $e = Obj::of(['url' => $url, 'method' => $init === null ? 'GET' : $init->get('method'),
                'contentType' => $init !== null && $init->has('headers') && $init->get('headers')->has('content-type') ? $init->get('headers')->get('content-type') : null]);
            if ($ocsp) {
                $e->set('bodyBytes', $init === null ? 0 : strlen((string)$init->get('body')));
            }
            $log[] = $e;
            if ($r->has('$throws')) {
                throw new \Exception((string)$r->get('$throws'));
            }
            $raw = $r->has('bodyBytes') ? (string)Base::bytes($r->get('bodyBytes')) : ($ocsp ? '' : Js::stringify($r->get('body')));
            return Obj::of(['status' => $r->has('status') ? $r->get('status') : 200, 'body' => $raw]);
        };
    }

    private static function fetchCase(string $kind, Obj $a): Obj
    {
        $log = [];
        try {
            $r = $a->get('response');
            $opts = Obj::of(['fetch' => self::transport($r, $log, $kind === 'ocsp')]);
            if ($kind === 'rim') {
                if ($a->has('baseUrl')) {
                    $opts->set('baseUrl', $a->get('baseUrl'));
                }
                $out = Obj::of(['ok' => true, 'value' => AttestNvidia::fetchRim((string)$a->get('id'), $opts)]);
            } elseif ($kind === 'crl') {
                $out = Obj::of(['ok' => true, 'value' => self::ob(AttestNvidia::fetchCrl((string)$a->get('url'), $opts))]);
            } else {
                $o = $a->has('opts') ? $a->get('opts') : new Obj();
                if ($o->has('url')) {
                    $opts->set('url', $o->get('url'));
                }
                if ($o->has('nonce')) {
                    $opts->set('nonce', Base::bytes($o->get('nonce')));
                }
                $res = AttestNvidia::fetchOcsp(Cert::fromPem($a->get('certPem')), Cert::fromPem($a->get('issuerPem')), $opts);
                $out = Obj::of(['ok' => true, 'request' => self::ob($res['request']), 'response' => self::ob($res['response'])]);
            }
        } catch (\Throwable $e) {
            $out = Obj::of(['ok' => false, 'error' => $e->getMessage()]);
        }
        $out->set('requests', $log);
        return $out;
    }

    private static function ocspVerify(string $der, Obj $a): array|Obj
    {
        $chain = self::chainOf($a->get('chainPem'));
        $i = (int)Js::num($a->get('certIndex'));
        $j = $a->has('issuerIndex') ? (int)Js::num($a->get('issuerIndex')) : $i + 1;
        if (!isset($chain[$i]) || !isset($chain[$j])) {
            return ['ok' => false, 'reason' => 'OCSP response rejected: certificate is undefined'];
        }
        return Ocsp::verifyResponse($der, $chain[$i], $chain[$j], $chain, (float)Js::num($a->get('nowMs')), $a->has('maxAgeMs') ? (float)Js::num($a->get('maxAgeMs')) : null,
            $a->has('clockSkewMs') ? (float)Js::num($a->get('clockSkewMs')) : 0.0, self::bytes($a->has('expectedNonce') ? $a->get('expectedNonce') : null), true);
    }

    private static function hook(Obj $sc): Obj
    {
        $b = $sc->get('bundle');
        $bundle = null;
        if ($b instanceof Obj) {
            $bundle = ['driverRimXml' => $b->get('driverRimXml'), 'vbiosRimXml' => $b->get('vbiosRimXml')];
            foreach (['crls', 'ocsp'] as $k) {
                if ($b->has($k)) {
                    $bundle[$k] = array_map(static fn($x) => (string)Base::bytes($x), $b->get($k));
                }
            }
        }
        $hook = Nvidia::collateralHook($sc->get('opts'), static fn(array $ids, mixed $ev): ?array => $bundle);
        $chain = self::chainOf($sc->get('chainPem'));
        $report = Nvidia::parseEvidence((string)Base::bytes($sc->get('evidence')));
        $v = $hook(['report' => $report, 'chain' => $chain, 'leaf' => $chain[0], 'nowMs' => (float)Js::num($sc->get('nowMs')), 'evidence' => null]);
        return Obj::of(['value' => $v === '' ? '' : $v]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $h = static fn(mixed $x) => self::hydrate($file, $x);
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a, Obj $c) => self::cmp($file, $c, ['NVIDIA_SPDM_SUITE' => AttestNvidia::SPDM_SUITE, 'NVIDIA_OPAQUE' => AttestNvidia::OPAQUE,
                'NVIDIA_RIM_BASE_URL' => AttestNvidia::RIM_BASE_URL, 'NVIDIA_GH100_CRL_URLS' => AttestNvidia::GH100_CRL_URLS, 'NVIDIA_GB100_CRL_URLS' => AttestNvidia::GB100_CRL_URLS,
                'NVIDIA_OCSP_URL' => AttestNvidia::OCSP_URL, 'NVIDIA_OCSP_DEFAULT_MAX_AGE_MS' => AttestNvidia::OCSP_DEFAULT_MAX_AGE_MS]),
            'parseReport' => static fn(array $a, Obj $c) => self::cmp($file, $c, self::reportSummary(Nvidia::parseEvidence((string)Base::bytes($h($a[0]))))),
            'formatVbiosVersion' => static fn(array $a, Obj $c) => self::cmp($file, $c, Nvidia::formatVbiosVersion((string)Base::bytes($a[0]))),
            'spkiSha256Hex' => static fn(array $a, Obj $c) => self::cmp($file, $c, AttestNvidia::spkiSha256Hex($h($a[0]))),
            'parsePemChain' => static fn(array $a, Obj $c) => self::cmp($file, $c, array_map(self::certSummary(...), Nvidia::parsePemChain($h($a[0])))),
            'verifyDeviceChain' => static function (array $a, Obj $c) use ($file, $h) {
                $r = Nvidia::verifyDeviceChain($h($a[0]), $a[1], (float)Js::num($a[2]));
                return self::cmp($file, $c, $r['ok'] ? Obj::of(['ok' => true, 'leaf' => self::certSummary($r['leaf']), 'chain' => array_map(self::certSummary(...), $r['chain'])]) : $r);
            },
            'verifySpdmSignature' => static function (array $a, Obj $c) use ($file, $h) {
                $rep = Nvidia::parseEvidence((string)Base::bytes($h($a[0])));
                return self::cmp($file, $c, AttestNvidia::verifySpdmSignature($rep, Nvidia::parsePemChain($h($a[1]))[0]->publicKey()));
            },
            'spdmChallenge' => static fn(array $a, Obj $c) => self::cmp($file, $c, self::ob(AttestNvidia::spdmChallenge($a[0]))),
            'verifyRim' => static function (array $a, Obj $c) use ($file, $h) {
                $o = $a[1];
                $r = Nvidia::verifyRim($h($a[0]), $o->get('rimRootSpkiSha256'), (float)Js::num($o->get('nowMs')));
                return self::cmp($file, $c, $r['ok'] ? Obj::of(['ok' => true, 'rim' => self::rimSummary($r['rim'])]) : $r);
            },
            'rimIds' => static fn(array $a, Obj $c) => self::cmp($file, $c, Nvidia::rimIdsForReport(Nvidia::parseEvidence((string)Base::bytes($h($a[0]))))),
            'compareReport' => static fn(array $a, Obj $c) => self::cmp($file, $c, AttestNvidia::compareReportToRims(Nvidia::parseEvidence((string)Base::bytes($h($a[0]))), self::rimOf($a[1]), self::rimOf($a[2]))),
            'checkRevocation' => static function (array $a, Obj $c) use ($file, $h) {
                $req = $a[4] instanceof \Atlas\Pca\Undef ? 'cdp' : self::plain($a[4]);
                return self::cmp($file, $c, Nvidia::checkChainRevocation(Nvidia::parsePemChain($h($a[0])), array_map(static fn($x) => (string)Base::bytes($h($x)), $a[1]),
                    (float)Js::num($a[2]), $a[3], $req));
            },
            'collateralHook' => static fn(array $a, Obj $c) => self::cmp($file, $c, self::hook($h($a[0]))),
            'fetchRim' => static fn(array $a, Obj $c) => self::cmp($file, $c, self::fetchCase('rim', $a[0])),
            'fetchCrl' => static fn(array $a, Obj $c) => self::cmp($file, $c, self::fetchCase('crl', $h($a[0]))),
            'ocspRequest' => static function (array $a, Obj $c) use ($file, $h) {
                $o = $a[2];
                $nonce = $o->has('nonce') ? (string)Base::bytes($o->get('nonce')) : null;
                $req = Ocsp::buildRequest(Cert::fromPem($h($a[0])), Cert::fromPem($h($a[1])), $nonce, $o->has('hash') ? (string)$o->get('hash') : 'sha384');
                return self::cmp($file, $c, self::ob($req));
            },
            'ocspUrls' => static fn(array $a, Obj $c) => self::cmp($file, $c, Ocsp::certOcspUrls(Cert::fromPem($h($a[0])))),
            'ocspVerify' => static function (array $a, Obj $c) use ($file, $h) {
                $r = self::ocspVerify((string)Base::bytes($h($a[0])), $h($a[1]));
                if ($c->get('name') === 'ocspVerify/real-byte500-flipped') {
                    // deliberately stricter: the flip makes a SET shorter than the structure inside it. The reference's BER reader recovers and refuses later (at the embedded
                    // certificate); the native refuses the response as malformed DER up front. Both refuse; the native's exact refusal is asserted, not skipped.
                    $got = $r instanceof Obj ? $r->get('reason') : ($r['reason'] ?? null);
                    $ok = $r instanceof Obj ? $r->get('ok') : ($r['ok'] ?? null);
                    if ($ok !== false || $got !== 'BasicOCSPResponse is not valid DER') {
                        throw new \LogicException('byte500-flipped: expected the native DER refusal, got ' . json_encode($r));
                    }
                    $c->set('out', Obj::of(['ok' => false, 'reason' => 'BasicOCSPResponse is not valid DER']));
                    return Obj::of(['ok' => false, 'reason' => $got]);
                }
                return self::cmp($file, $c, $r);
            },
            'ocspChain' => static function (array $a, Obj $c) use ($file, $h) {
                $o = $a[3];
                $opts = [];
                if ($o->has('requireGood')) {
                    $opts['requireGood'] = self::plain($o->get('requireGood'));
                }
                if ($o->has('clockSkewMs')) {
                    $opts['clockSkewMs'] = (float)Js::num($o->get('clockSkewMs'));
                }
                if ($o->has('expectedNonces')) {
                    $opts['expectedNonces'] = array_map(static fn($x) => $x === null ? null : (string)Base::bytes($x), $o->get('expectedNonces'));
                }
                $r = Ocsp::checkNvidiaChain(Nvidia::parsePemChain($h($a[0])), array_map(static fn($x) => (string)Base::bytes($h($x)), $a[1]), (float)Js::num($a[2]),
                    $o->has('maxAgeMs') ? (float)Js::num($o->get('maxAgeMs')) : null, $opts);
                if (isset($r['statuses'])) {
                    $st = new Obj();
                    foreach ($r['statuses'] as $i => $s) {
                        $st->set((string)$i, $s);
                    }
                    $r['statuses'] = $st;
                }
                return self::cmp($file, $c, $r);
            },
            'fetchOcsp' => static fn(array $a, Obj $c) => self::cmp($file, $c, self::fetchCase('ocsp', $h($a[0]))),
            'asn1TimesWellFormed' => static fn(array $a, Obj $c) => self::cmp($file, $c, Ocsp::asn1TimesWellFormed((string)Base::bytes($h($a[0])))),
        ]);
    }

    /** A byte of the genuine response flipped (byte 500 sits in the embedded responder certificates) is refused, whatever the flip. */
    public function testAFlippedByteOfTheRealResponseIsRefused(): void
    {
        $base = null;
        foreach (Base::cases(self::FILE, 'ocspVerify', 0) as $c) {
            if ($c->get('name') === 'ocspVerify/real-3-identity-nonce') {
                $base = $c;
            }
        }
        $this->assertNotNull($base, 'the genuine fixture case is in the corpus');
        $der = (string)Base::bytes(self::hydrate(self::FILE, $base->get('args')[0]));
        $opts = self::hydrate(self::FILE, $base->get('args')[1]);
        $r = self::ocspVerify($der, $opts);
        $this->assertTrue((is_array($r) ? $r['ok'] : $r->get('ok')) === true, 'the unflipped response verifies');
        $this->assertGreaterThan(500, strlen($der));
        foreach ([0x01, 0x80, 0xFF] as $mask) {
            $bad = $der;
            $bad[500] = chr(ord($bad[500]) ^ $mask);
            $r = self::ocspVerify($bad, $opts);
            $this->assertFalse((is_array($r) ? $r['ok'] : $r->get('ok')) === true, "byte 500 flipped with $mask is refused");
        }
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        foreach ([self::FILE => self::FNS, self::RIM_FILE => self::RIM_FNS] as $file => $fns) {
            $have = array_fill_keys(array_keys($fns), 0);
            $h = gzopen(Base::path($file), 'rb');
            gzgets($h);
            while (($line = gzgets($h)) !== false) {
                foreach ($have as $fn => $_) {
                    $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
                }
            }
            gzclose($h);
            $this->assertSame($fns, $have, $file);
        }
    }
}
