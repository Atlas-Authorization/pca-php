<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Webbotauth;
use Atlas\Pca\WebbotauthMemoryReplayCache;
use Atlas\Pca\WebbotauthParseError;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for Web Bot Auth: the RFC 9421 signature base byte for byte (signed here with libsodium over a hand-written base),
 * the Signature-Input parser's refusals, key-directory windows, freshness windows, replay keys, the PCA proof binding,
 * Content-Digest and the directory fetch.
 */
final class AgentSurvivorKill13WebbotauthTest extends TestCase
{
    private const COMPS = '"@authority" "@method" "@path"';
    private const STD = "\"@authority\": ex.com\n\"@method\": GET\n\"@path\": /p";
    private const BS = '\\';
    /** Spellings the WHATWG parser reads as carrying userinfo (special scheme: any run of / or \ after the scheme is skipped). */
    private const CRED_URLS = ['https://u@ab/p', 'https://@ex.com/', 'https:///u@ex.com/', 'https:u@ex.com/', 'https:\\\\u@ex.com/', 'https:/\\u:p@ex.com/',
        "ht\ttps://u@ex.com/", "ht\ntps://u@ex.com/", "ht\rtps://u@ex.com/", ' https://u@ex.com/', 'HTTPS://u:@ex.com/'];

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/wba-kill13', true);
    }

    private static function pk(): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed()));
    }

    private static function sig(string $base): string
    {
        return base64_encode(sodium_crypto_sign_detached($base, sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::seed()))));
    }

    private static function key(): array
    {
        return ['secretKey' => Pca::b64u(self::seed())];
    }

    private static function params(string $comps = self::COMPS, string $extra = ''): string
    {
        return '(' . $comps . ');created=1000;keyid="k1";alg="ed25519";expires=1100' . $extra . ';tag="web-bot-auth"';
    }

    private static function base(string $lines, string $params): string
    {
        return $lines . "\n\"@signature-params\": " . $params;
    }

    /** A request whose Signature-Input is `sig1=$params` and whose signature is over `$lines` (or the given base64). */
    private static function req(string $params, string $lines = self::STD, array $extra = [], ?string $sigB64 = null, string $url = 'https://ex.com/p'): array
    {
        $sig = $sigB64 ?? self::sig(self::base($lines, $params));
        return ['method' => 'GET', 'url' => $url, 'headers' => ['Signature-Input' => 'sig1=' . $params, 'Signature' => 'sig1=:' . $sig . ':'] + $extra];
    }

    private static function opts(array $o = []): array
    {
        return $o + ['resolveKey' => static fn(string $kid): ?string => $kid === 'k1' ? self::pk() : null, 'now' => 1050];
    }

    private static function raw(string $si, string $sig = 'sig1=:AA==:', array $opts = []): array
    {
        return Webbotauth::verifySignedRequest(['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => ['Signature-Input' => $si, 'Signature' => $sig]], self::opts($opts));
    }

    private static function reason(array $r): string
    {
        return (string)($r['reason'] ?? 'VALID');
    }

    /** Runs $f and asserts it raised no PHP warning or notice. */
    private static function quiet(callable $f): mixed
    {
        $w = [];
        set_error_handler(static function (int $no, string $msg) use (&$w): bool {
            $w[] = $msg;
            return true;
        });
        try {
            $r = $f();
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $w);
        return $r;
    }

    private static function signIn(array $set): array
    {
        return $set + ['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => [], 'key' => self::key(), 'keyid' => 'k1', 'created' => 1000];
    }

    private static function sp(string $comps): string
    {
        return '(' . $comps . ');created=1000;keyid="k1";alg="ed25519";expires=1300;tag="web-bot-auth"';
    }

    // ---- replay cache capacity ----

    /** The default cache holds exactly 100000 unexpired claims and then fails closed. */
    public function testDefaultReplayCacheCapacityIsExactly100000(): void
    {
        foreach ([new WebbotauthMemoryReplayCache(), Webbotauth::memoryReplayCache()] as $c) {
            $ok = 0;
            for ($i = 0; $i < 100000; $i++) {
                $ok += $c->claim("k$i", 2000.0, 1000.0) ? 1 : 0;
            }
            self::assertSame(100000, $ok);
            try {
                $c->claim('over', 2000.0, 1000.0);
                self::fail('the 100001st claim must fail closed');
            } catch (\RuntimeException $e) {
                self::assertSame('replay cache full', $e->getMessage());
            }
        }
    }

    // ---- header normalisation and the signature base ----

    /** Header values are trimmed of Unicode whitespace (NBSP), and an invalid-UTF-8 value still loses its ASCII whitespace. */
    public function testCoveredHeaderValuesAreTrimmed(): void
    {
        $r = Webbotauth::signRequest(self::signIn(['headers' => ['x-a' => "\u{a0}v1\u{a0}", 'x-b' => " \xffv2\t"], 'coverHeaders' => ['x-a', 'x-b']]));
        $p = self::sp(self::COMPS . ' "x-a" "x-b"');
        self::assertSame('sig1=' . $p, $r['signatureInput']);
        self::assertSame('sig1=:' . self::sig(self::base(self::STD . "\n\"x-a\": v1\n\"x-b\": \xffv2", $p)) . ':', $r['signature']);
    }

    /** Header names lower-case with Unicode case mapping, and an invalid-UTF-8 name still lower-cases its ASCII letters. */
    public function testHeaderNamesLowerCase(): void
    {
        $r = Webbotauth::signRequest(self::signIn(['headers' => ['X-É' => 'v1', "X-A\xff" => 'v2'], 'coverHeaders' => ['X-É', "X-A\xff"]]));
        $p = self::sp(self::COMPS . " \"x-é\" \"x-a\xff\"");
        self::assertSame('sig1=' . $p, $r['signatureInput']);
        self::assertSame('sig1=:' . self::sig(self::base(self::STD . "\n\"x-é\": v1\n\"x-a\xff\": v2", $p)) . ':', $r['signature']);
    }

    /** @method upper-cases Unicode letters, and an invalid-UTF-8 method still upper-cases its ASCII letters. */
    public function testMethodUpperCases(): void
    {
        $p = self::sp(self::COMPS);
        $r = Webbotauth::signRequest(self::signIn(['method' => 'gét']));
        self::assertSame('sig1=:' . self::sig(self::base("\"@authority\": ex.com\n\"@method\": GÉT\n\"@path\": /p", $p)) . ':', $r['signature']);
        $r = Webbotauth::signRequest(self::signIn(['method' => "get\xff"]));
        self::assertSame('sig1=:' . self::sig(self::base("\"@authority\": ex.com\n\"@method\": GET\xff\n\"@path\": /p", $p)) . ':', $r['signature']);
    }

    /** A KeyPair signs (directory and request) exactly like the same seed given as secretKey. */
    public function testKeyPairSigns(): void
    {
        $kp = new KeyPair(self::seed());
        $r = Webbotauth::signRequest(self::signIn(['key' => $kp]));
        self::assertSame('sig1=:' . self::sig(self::base(self::STD, self::sp(self::COMPS))) . ':', $r['signature']);
        $dir = Webbotauth::buildKeyDirectory([['publicKey' => self::pk(), 'keyid' => 'd1']]);
        $out = Webbotauth::signDirectoryResponse(['keys' => [$kp], 'directory' => $dir, 'authority' => 'ex.com', 'created' => 1000]);
        $p = '("@authority";req);created=1000;expires=87400;keyid="' . Webbotauth::jwkThumbprint(self::pk()) . '";alg="ed25519";tag="http-message-signatures-directory"';
        self::assertSame('sig1=' . $p, $out['headers']->get('signature-input'));
        self::assertSame('sig1=:' . self::sig("\"@authority\";req: ex.com\n\"@signature-params\": " . $p) . ':', $out['headers']->get('signature'));
    }

    /** A key without a 32-byte secretKey seed is refused with InvalidArgumentException. */
    public function testSignerRefusesAKeyWithoutA32ByteSeed(): void
    {
        foreach ([[], ['secretKey' => 'AAAA']] as $k) {
            try {
                Webbotauth::signRequest(self::signIn(['key' => $k]));
                self::fail('must refuse');
            } catch (\InvalidArgumentException $e) {
                self::assertSame('key must carry a secretKey', $e->getMessage());
            }
        }
    }

    /** @target-uri is the plain URL; an '@' in the path is not a credential, an empty query keeps its '?'. */
    public function testTargetUriOfPlainUrls(): void
    {
        $p = self::sp('"@authority" "@target-uri"');
        foreach ([
            'https://ex.com/a@b/cd' => 'https://ex.com/a@b/cd',
            'https://ex.com/p?' => 'https://ex.com/p?',
            'https://ex.com/p?a=1' => 'https://ex.com/p?a=1',
            'https:ex.com/a@b' => 'https://ex.com/a@b',
            'https:///ex.com/a@b' => 'https://ex.com/a@b',
        ] as $url => $target) {
            $r = Webbotauth::signRequest(self::signIn(['url' => $url, 'components' => ['@authority', '@target-uri']]));
            self::assertSame('sig1=:' . self::sig("\"@authority\": ex.com\n\"@target-uri\": $target\n\"@signature-params\": $p") . ':', $r['signature'], $url);
        }
    }

    /** @target-uri over a URL with credentials (even empty ones, whatever the slashes after the scheme) or a fragment is refused. */
    public function testTargetUriRefusesCredentialsAndFragments(): void
    {
        foreach ([...self::CRED_URLS, 'https://ex.com/p#f'] as $url) {
            try {
                Webbotauth::signRequest(self::signIn(['url' => $url, 'components' => ['@authority', '@target-uri']]));
                self::fail("must refuse $url");
            } catch (WebbotauthParseError $e) {
                self::assertSame('@target-uri is not supported for a URL with credentials or a fragment', $e->getMessage(), $url);
            }
        }
    }

    /** signRequest refusals keep their exact class and message. */
    public function testSignRequestRefusals(): void
    {
        $cases = [
            [['url' => 'file:///x'], \InvalidArgumentException::class, 'unsupported URL scheme'],
            [['method' => null], \TypeError::class, 'method.toUpperCase is not a function'],
            [['components' => ['@authority', '@foo']], WebbotauthParseError::class, 'unsupported derived component "@foo"'],
            [['components' => ['a' => '@authority']], \TypeError::class, 'components is not iterable'],
            [['components' => ['@authority', 5]], \TypeError::class, 'component is not a string'],
            [['agentDirectoryUrl' => null], \TypeError::class, 'agentDirectoryUrl is not a string'],
            [['agentDirectoryUrl' => 'https://a.example', 'agentDirectoryKey' => 5], \InvalidArgumentException::class, 'signRequest: agentDirectoryKey must be a string'],
            [['coverHeaders' => [5]], \TypeError::class, 'header name is not a string'],
            [['coverHeaders' => ['X-Missing']], \InvalidArgumentException::class, 'signRequest: covered header "X-Missing" is not present in headers'],
        ];
        foreach ($cases as [$set, $class, $msg]) {
            try {
                Webbotauth::signRequest(self::signIn($set));
                self::fail("must refuse: $msg");
            } catch (\Throwable $e) {
                self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
            }
        }
    }

    // ---- verifySignedRequest ----

    /** Control: the hand-built request verifies, and the signature byte sequence may carry junk after its '=' padding or omit padding. */
    public function testValidSignatureAndSignatureByteForms(): void
    {
        $p = self::params();
        $sig = self::sig(self::base(self::STD, $p));
        $want = ['valid' => true, 'label' => 'sig1', 'keyid' => 'k1', 'covered' => ['@authority', '@method', '@path'], 'created' => 1000.0, 'expires' => 1100.0, 'tag' => 'web-bot-auth'];
        self::assertSame($want, Webbotauth::verifySignedRequest(self::req($p), self::opts()));
        self::assertSame($want, Webbotauth::verifySignedRequest(self::req($p, self::STD, [], $sig . 'AAAA'), self::opts()));
        self::assertSame($want, Webbotauth::verifySignedRequest(self::req($p, self::STD, [], rtrim($sig, '=')), self::opts()));
    }

    /** Structured-field nesting: parens and quoted strings decide where members and the label end. */
    public function testSignatureInputNesting(): void
    {
        $f = 'verification failed (fail closed): ';
        self::assertSame($f . 'expected a quoted string', self::reason(self::raw('sig1=(()x,y)')));
        self::assertSame($f . 'malformed Signature-Input member', self::reason(self::raw(')sig1=(),y', 'x=:AA==:')));
        self::assertSame($f . 'malformed Signature-Input member', self::reason(self::raw('sig1(()=()', 'x=:AA==:')));
        self::assertSame('no Signature entry for label ")sig1"', self::reason(self::raw(')sig1=()', 'x=:AA==:')));
        self::assertSame('no Signature entry for label ""ab""', self::reason(self::raw('"ab"=()', 'x=:AA==:')));
        self::assertSame('tag "undefined" does not match required "web-bot-auth"', self::reason(self::raw('sig1=("a)b")')));
    }

    /** A backslash escape inside a quoted label or component name is skipped over (it never ends the scan). */
    public function testEscapesInsideQuotedStringsAreSkipped(): void
    {
        self::assertSame('no Signature entry for label ""a' . self::BS . '"b""', self::reason(self::raw('"a' . self::BS . '"b"=()', 'x=:AA==:')));
        self::assertSame('tag "undefined" does not match required "web-bot-auth"', self::reason(self::raw('sig1=("a' . self::BS . '"b")')));
        // an empty string: the byte after its opening quote is the closing quote, never an escaped one (in all three scanners)
        self::assertSame('no Signature entry for label """"', self::reason(self::raw('""=()', 'x=:AA==:')));
        self::assertSame('tag "undefined" does not match required "web-bot-auth"', self::reason(self::raw('sig1=("")')));
        self::assertSame('could not resolve key ""', self::reason(self::raw('sig1=(' . self::COMPS . ');created=1000;keyid="";alg="ed25519";expires=1100;tag="web-bot-auth"')));
    }

    /** String escapes: a dangling backslash, an escape that eats the closing quote, and the decoded value of \" and \\. */
    public function testStringEscapes(): void
    {
        $f = 'verification failed (fail closed): ';
        $b = self::BS;
        self::assertSame($f . 'invalid escape in string', self::quiet(fn() => self::reason(self::raw('sig1=();k="ab' . $b))));
        self::assertSame($f . 'unterminated string', self::reason(self::raw('sig1=();k="a' . $b . '"')));
        $p = '(' . self::COMPS . ');created=1000;keyid="a' . $b . '"b";alg="ed25519";expires=1100;tag="web-bot-auth"';
        self::assertSame('could not resolve key "a"b"', self::reason(self::raw('sig1=' . $p)));
        $p = '(' . self::COMPS . ');created=1000;keyid="a' . $b . $b . 'b";alg="ed25519";expires=1100;tag="web-bot-auth"';
        self::assertSame('could not resolve key "a' . $b . 'b"', self::reason(self::raw('sig1=' . $p)));
    }

    /** Parameter values: an empty value and a bare flag are true, ?1 is true, ?0 is false (shown through the alg refusal). */
    public function testParameterValueTypes(): void
    {
        $si = 'sig1=(' . self::COMPS . ');tag="web-bot-auth";alg';
        self::assertSame('unsupported alg "true"', self::reason(self::raw($si . '=')));
        self::assertSame('unsupported alg "true"', self::reason(self::raw($si)));
        self::assertSame('unsupported alg "true"', self::reason(self::raw($si . '=?1')));
        self::assertSame('unsupported alg "false"', self::reason(self::raw($si . '=?0')));
    }

    /** Parameters must start with ';', an empty parameter is skipped, an empty inner-list chunk is skipped. */
    public function testParameterAndInnerListSeparators(): void
    {
        self::assertSame('verification failed (fail closed): expected parameters to start with ";"', self::reason(self::raw('sig1=(' . self::COMPS . ')x;tag="web-bot-auth"')));
        $p = self::params(self::COMPS, ';');
        self::assertTrue(Webbotauth::verifySignedRequest(self::req($p), self::opts())['valid']);
        $p = self::params('"@authority"  "@method" "@path"');
        self::assertTrue(Webbotauth::verifySignedRequest(self::req($p), self::opts())['valid']);
    }

    /** A list-valued header with a non-string element fails closed with the reference's TypeError text. */
    public function testListHeaderWithNonString(): void
    {
        $r = Webbotauth::verifySignedRequest(['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => ['x' => [1], 'Signature-Input' => 'a', 'Signature' => 'b']], self::opts());
        self::assertSame('verification failed (fail closed): x.trim is not a function', self::reason($r));
    }

    /** The dictionary-member component picks exactly member `key`, skipping members without '=' and other keys. */
    public function testDictionaryMemberSelection(): void
    {
        $p = self::params(self::COMPS . ' "x";key="k"');
        $lines = self::STD . "\n\"x\";key=\"k\": \"v\"";
        self::assertTrue(Webbotauth::verifySignedRequest(self::req($p, $lines, ['x' => 'kx, a="x", k="v"']), self::opts())['valid']);
        $f = 'verification failed (fail closed): ';
        self::assertSame($f . 'member "k" of "x" is not in canonical form', self::reason(Webbotauth::verifySignedRequest(self::req($p, $lines, ['x' => 'k="v" ;a']), self::opts())));
        self::assertSame($f . '"x" has no dictionary member "k"', self::reason(Webbotauth::verifySignedRequest(self::req($p, $lines, ['x' => 'a="x"']), self::opts())));
        self::assertSame($f . 'expected a quoted string', self::quiet(fn() => self::reason(Webbotauth::verifySignedRequest(self::req($p, $lines, ['x' => 'k=']), self::opts()))));
    }

    /** With a label option the FIRST entry of that label is used; without one the FIRST entry with the required tag. */
    public function testFirstMatchingEntryIsChosen(): void
    {
        $good = self::params();
        $sig = self::sig(self::base(self::STD, $good));
        $other = '(' . self::COMPS . ');created=1000;keyid="k1";alg="ed25519";expires=1101;tag="web-bot-auth"';
        $req = ['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => ['Signature-Input' => "sig1=$good, sig1=$other", 'Signature' => "sig1=:$sig:"]];
        self::assertTrue(Webbotauth::verifySignedRequest($req, self::opts(['label' => 'sig1']))['valid']);
        $req = ['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => ['Signature-Input' => "sig1=$good, sig2=$other", 'Signature' => "sig1=:$sig:, sig2=:AA==:"]];
        self::assertSame('sig1', Webbotauth::verifySignedRequest($req, self::opts())['label'] ?? null);
    }

    /** @authority is required by default; a non-list requiredComponents and a missing url fail closed with their texts. */
    public function testRequiredComponents(): void
    {
        $p = self::params('"@method" "@path"');
        self::assertSame('@authority is not a covered component', self::reason(Webbotauth::verifySignedRequest(self::req($p, "\"@method\": GET\n\"@path\": /p"), self::opts())));
        self::assertSame('verification failed (fail closed): requiredComponents is not iterable', self::reason(Webbotauth::verifySignedRequest(self::req(self::params()), self::opts(['requiredComponents' => 'x']))));
        $req = self::req(self::params());
        unset($req['url']);
        self::assertSame("verification failed (fail closed): Cannot read properties of undefined (reading 'indexOf')", self::reason(Webbotauth::verifySignedRequest($req, self::opts())));
    }

    /** A non-finite clock skew fails every freshness bound it touches, and maxAgeSec widens by the skew. */
    public function testFreshnessWindows(): void
    {
        self::assertSame('signature has expired', self::reason(Webbotauth::verifySignedRequest(self::req(self::params()), self::opts(['clockSkewSec' => INF]))));
        $p = '(' . self::COMPS . ');created=1000;keyid="k1";alg="ed25519";tag="web-bot-auth"';
        self::assertSame('signature created-time is in the future', self::reason(Webbotauth::verifySignedRequest(self::req($p), self::opts(['clockSkewSec' => INF, 'requireExpires' => false]))));
        self::assertTrue(Webbotauth::verifySignedRequest(self::req(self::params()), self::opts(['clockSkewSec' => 10, 'maxAgeSec' => 40]))['valid']);
    }

    /** A JWKS entry's nbf/exp window: inclusive bounds, skew widening both ways, non-finite bounds and a non-finite skew refuse. */
    public function testJwksValidityWindow(): void
    {
        $jw = static fn(array $b): array => ['jwks' => ['keys' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Pca::b64u(self::pk()), 'kid' => 'k1'] + $b]], 'now' => 1050];
        $v = static fn(array $o, string $p = ''): array => Webbotauth::verifySignedRequest(self::req($p === '' ? self::params() : $p), $o);
        self::assertTrue($v($jw([]))['valid']);
        self::assertSame('could not resolve key "k1"', self::reason($v($jw(['nbf' => -INF]))));
        self::assertSame('could not resolve key "k1"', self::reason($v($jw(['exp' => INF]))));
        self::assertTrue($v($jw(['nbf' => 1050]))['valid']);
        self::assertTrue($v($jw(['exp' => 1045]) + ['clockSkewSec' => 10])['valid']);
        $bare = '(' . self::COMPS . ');keyid="k1";alg="ed25519";tag="web-bot-auth"';
        $loose = ['clockSkewSec' => INF, 'requireExpires' => false, 'maxLifetimeSec' => INF];
        self::assertSame('could not resolve key "k1"', self::reason($v($jw(['nbf' => 0]) + $loose, $bare)));
        self::assertSame('could not resolve key "k1"', self::reason($v($jw(['exp' => 99999]) + $loose, $bare)));
        self::assertSame('verification failed (fail closed): opts.jwks.keys.find is not a function', self::reason($v(['jwks' => ['keys' => 'x'], 'now' => 1050])));
    }

    /** The replay cache is called with key "keyid|nonce" (or the signature), the bound expiry plus skew, and now. */
    public function testReplayCacheArguments(): void
    {
        $calls = [];
        $fn = static function (string $k, float $e, float $n) use (&$calls): bool {
            $calls[] = [$k, $e, $n];
            return true;
        };
        $p = self::params(self::COMPS, ';nonce="n1"');
        self::assertTrue(Webbotauth::verifySignedRequest(self::req($p), self::opts(['replayCache' => $fn, 'clockSkewSec' => 5]))['valid']);
        $obj = new class {
            public array $calls = [];

            public function claim(string $k, float $e, float $n): bool
            {
                $this->calls[] = [$k, $e, $n];
                return true;
            }
        };
        self::assertTrue(Webbotauth::verifySignedRequest(self::req($p), self::opts(['replayCache' => $obj, 'clockSkewSec' => 5]))['valid']);
        self::assertSame([['k1|n1', 1105.0, 1050.0]], $calls);
        self::assertSame([['k1|n1', 1105.0, 1050.0]], $obj->calls);

        $calls = [];
        $p = '(' . self::COMPS . ');created=1000;keyid="k1";alg="ed25519";tag="web-bot-auth"';
        $sig = self::sig(self::base(self::STD, $p));
        self::assertTrue(Webbotauth::verifySignedRequest(self::req($p), self::opts(['replayCache' => $fn, 'requireExpires' => false]))['valid']);
        $p2 = '(' . self::COMPS . ');keyid="k1";alg="ed25519";tag="web-bot-auth"';
        $sig2 = self::sig(self::base(self::STD, $p2));
        self::assertTrue(Webbotauth::verifySignedRequest(self::req($p2), self::opts(['replayCache' => $fn, 'requireExpires' => false, 'maxLifetimeSec' => INF]))['valid']);
        self::assertSame([
            ['k1|' . Pca::b64u(base64_decode($sig)), 1300.0, 1050.0],
            ['k1|' . Pca::b64u(base64_decode($sig2)), 4650.0, 1050.0],
        ], $calls);
    }

    // ---- the PCA proof binding ----

    /** decodeProofHeader: exactly MAX_ARTIFACT_BYTES decodes, one byte more is a RangeException, a non-object a TypeError. */
    public function testDecodeProofHeaderLimits(): void
    {
        $json = '{"a":"' . str_repeat('x', Pca::MAX_ARTIFACT_BYTES - 8) . '"}';
        self::assertSame(Pca::MAX_ARTIFACT_BYTES, strlen($json));
        self::assertInstanceOf(Obj::class, Webbotauth::decodeProofHeader(Pca::b64u($json)));
        try {
            Webbotauth::decodeProofHeader(Pca::b64u('{"a":"' . str_repeat('x', Pca::MAX_ARTIFACT_BYTES - 7) . '"}'));
            self::fail('oversize');
        } catch (\RangeException $e) {
            self::assertSame(Pca::ARTIFACT_SIZE_REASON, $e->getMessage());
        }
        try {
            Webbotauth::decodeProofHeader(Pca::b64u('[1]'));
            self::fail('not an object');
        } catch (\TypeError $e) {
            self::assertSame('decodePCActn: not an object', $e->getMessage());
        }
    }

    /** signRequestWithProof accepts plain-array input and headers; expectedPCActn null is "not enforced". */
    public function testProofRoundTripWithArrays(): void
    {
        $pcactn = Obj::of(['a' => 'b']);
        $s = Webbotauth::signRequestWithProof(['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => ['x-a' => 'v'], 'key' => self::key(), 'keyid' => 'k1', 'created' => 1000, 'pcactn' => $pcactn]);
        $h = [];
        foreach ($s['headers']->keys() as $k) {
            $h[$k] = $s['headers']->get($k);
        }
        $r = Webbotauth::verifySignedRequestWithProof(['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => $h + ['x-a' => 'v']], self::opts(['expectedPCActn' => null]));
        self::assertTrue($r['valid'], self::reason($r));
        self::assertSame(Pca::hashCanonical($pcactn), Pca::hashCanonical($r['pcactn']));
    }

    /** A covered but undecodable PCA-Action header names the decoder's refusal after "invalid PCActn in PCA-Action: ". */
    public function testInvalidProofHeaderReason(): void
    {
        $s = Webbotauth::signRequest(self::signIn(['headers' => ['PCA-Action' => '!!'], 'coverHeaders' => ['PCA-Action']]));
        $r = Webbotauth::verifySignedRequestWithProof(['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => ['PCA-Action' => '!!', 'Signature-Input' => $s['signatureInput'], 'Signature' => $s['signature']]], self::opts());
        self::assertSame('invalid PCActn in PCA-Action: PCA-Action is not strict unpadded base64url of UTF-8 text', self::reason($r));
    }

    // ---- Content-Digest ----

    /** contentDigestHeader drops repeats but keeps later algorithms, and names an unsupported algorithm. */
    public function testContentDigestHeader(): void
    {
        $want = 'sha-256=:' . base64_encode(hash('sha256', 'x', true)) . ':, sha-512=:' . base64_encode(hash('sha512', 'x', true)) . ':';
        self::assertSame($want, Webbotauth::contentDigestHeader('x', ['sha-256', 'sha-256', 'sha-512']));
        try {
            Webbotauth::contentDigestHeader('x', ['md5']);
            self::fail('md5');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('contentDigestHeader: unsupported algorithm md5', $e->getMessage());
        }
    }

    // ---- key directory ----

    /** Directory refusals keep their exact class and message. */
    public function testKeyDirectoryRefusals(): void
    {
        $x = Pca::b64u(self::pk());
        $cases = [
            [static fn() => Webbotauth::parseKeyDirectory('[1]'), 'directory has no keys'],
            [static fn() => Webbotauth::parseKeyDirectory('{"keys":[1]}'), 'directory contains a malformed key'],
            [static fn() => Webbotauth::parseKeyDirectory('{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","x":"' . $x . '","nbf":"x"}]}'), 'directory contains a malformed key'],
            [static fn() => Webbotauth::buildKeyDirectory([['publicKey' => 5]]), 'publicKey must be bytes'],
        ];
        foreach ($cases as [$f, $msg]) {
            try {
                $f();
                self::fail($msg);
            } catch (\InvalidArgumentException $e) {
                self::assertSame($msg, $e->getMessage());
            }
        }
        try {
            Webbotauth::resolveFromDirectory(['keys' => 'x'], 'a');
            self::fail('keys not a list');
        } catch (\TypeError $e) {
            self::assertSame('directory.keys.find is not a function', $e->getMessage());
        }
    }

    private static function signedDir(array $keys, array $vin = []): array
    {
        $dir = Webbotauth::buildKeyDirectory($keys);
        $s = Webbotauth::signDirectoryResponse(['keys' => [self::key()], 'directory' => $dir, 'authority' => 'ex.com', 'created' => 1000]);
        return $vin + ['authority' => 'ex.com', 'headers' => ['signature-input' => $s['headers']->get('signature-input'), 'signature' => $s['headers']->get('signature')], 'body' => $s['body'], 'now' => 1050];
    }

    /** Every refused entry is skipped (not the end of the scan): a later good entry still verifies. */
    public function testDirectoryBadEntriesAreSkipped(): void
    {
        $in = self::signedDir([['publicKey' => self::pk(), 'keyid' => 'd1']]);
        $tag = ';tag="http-message-signatures-directory"';
        $thumb = Webbotauth::jwkThumbprint(self::pk());
        $bad = [
            'sig2=("@authority";req);tag="x"',
            'sig3=("@authority";req);alg="rsa"' . $tag,
            'sig4=("@authority";req);created=5000;expires=6000' . $tag,
            'sig5=("@authority";req);created=1;expires=2' . $tag,
            'sig6=("@authority";req);created=1000;expires=99999999' . $tag,
            'sig7=("@authority";req);created=1000;expires=2000;keyid="' . $thumb . '"' . $tag,
        ];
        $in['headers']['signature-input'] = implode(', ', $bad) . ', ' . $in['headers']['signature-input'];
        $r = Webbotauth::verifyDirectoryResponse($in);
        self::assertTrue($r['valid'], $r['reason'] ?? '');
        self::assertCount(1, $r['keys']);
    }

    /** Directory signature refusals: their reasons, the first key with a matching thumbprint, inclusive and skewed key windows. */
    public function testDirectoryVerification(): void
    {
        $thumb = Webbotauth::jwkThumbprint(self::pk());
        $in = self::signedDir([['publicKey' => self::pk(), 'keyid' => 'd1']]);
        $bad = $in;
        $bad['headers']['signature-input'] = ['x'];
        self::assertSame('verification failed (fail closed): header or body is not a string', Webbotauth::verifyDirectoryResponse($bad)['reason']);
        $bad = $in;
        $bad['headers']['signature-input'] = 'sig1=("@authority";req);created=1000;created=1000;expires=87400;keyid="' . $thumb . '";alg="ed25519";tag="http-message-signatures-directory"';
        self::assertSame('duplicate signature parameter', Webbotauth::verifyDirectoryResponse($bad)['reason']);
        $bad['headers']['signature-input'] = 'sig1=("@authority";req);expires=87400;keyid="' . $thumb . '";alg="ed25519";tag="http-message-signatures-directory"';
        self::assertSame('created and expires are required', Webbotauth::verifyDirectoryResponse($bad)['reason']);
        self::assertSame('signature created-time is in the future', Webbotauth::verifyDirectoryResponse(['clockSkewSec' => INF] + $in)['reason']);

        $two = Webbotauth::verifyDirectoryResponse(self::signedDir([['publicKey' => self::pk(), 'keyid' => 'd1'], ['publicKey' => self::pk(), 'keyid' => 'd2']]));
        self::assertTrue($two['valid']);
        self::assertCount(1, $two['keys']);
        self::assertSame('d1', $two['keys'][0]->get('kid'));

        self::assertTrue(Webbotauth::verifyDirectoryResponse(self::signedDir([['publicKey' => self::pk(), 'keyid' => 'd1', 'nbf' => 1050]]))['valid']);
        self::assertTrue(Webbotauth::verifyDirectoryResponse(self::signedDir([['publicKey' => self::pk(), 'keyid' => 'd1', 'nbf' => 1055]], ['clockSkewSec' => 10]))['valid']);
        self::assertTrue(Webbotauth::verifyDirectoryResponse(self::signedDir([['publicKey' => self::pk(), 'keyid' => 'd1', 'exp' => 1045]], ['clockSkewSec' => 10]))['valid']);
    }

    // ---- fetchKeyDirectory ----

    private static function dirText(): string
    {
        return Js::stringify(Webbotauth::buildKeyDirectory([['publicKey' => self::pk(), 'keyid' => 'd1']]));
    }

    /** @return array{0:mixed,1:list<array{0:string,1:int}>} the result (or the Throwable) and the fetch calls */
    private static function fetch(string $url, ?array $res = null, array $opts = []): array
    {
        $calls = [];
        $res ??= ['status' => 200, 'headers' => ['content-type' => Webbotauth::DIRECTORY_CONTENT_TYPE], 'body' => self::dirText()];
        $f = static function (string $u, array $h, int $t) use (&$calls, $res): array {
            $calls[] = [$u, $t];
            return $res;
        };
        try {
            $out = Webbotauth::fetchKeyDirectory($url, $opts + ['fetch' => $f]);
        } catch (\Throwable $e) {
            $out = $e;
        }
        return [$out, $calls];
    }

    private static function msg(mixed $r): string
    {
        return $r instanceof \Throwable ? get_class($r) . ': ' . $r->getMessage() : 'OK';
    }

    /** The fetched href and timeout: '@' in the path is fine, a fragment is cut, an empty query keeps its '?', timeout 5000 / int. */
    public function testFetchHrefAndTimeout(): void
    {
        foreach ([
            'https://ex.com/a@b/cd' => 'https://ex.com/a@b/cd',
            'https://ex.com#@x' => 'https://ex.com/',
            'https://ex.com/p?' => 'https://ex.com/p?',
            'https://ex.com/p?#x' => 'https://ex.com/p?',
            'https:///ex.com/a@b' => 'https://ex.com/a@b',
        ] as $url => $href) {
            [$r, $calls] = self::fetch($url);
            self::assertSame('OK', self::msg($r), $url);
            self::assertSame([[$href, 5000]], $calls, $url);
        }
        [$r, $calls] = self::fetch('https://ex.com/p', null, ['timeoutMs' => 1500]);
        self::assertSame([['https://ex.com/p', 1500]], $calls);
        self::assertInstanceOf(Obj::class, $r);
    }

    /** fetchKeyDirectory refusals keep their exact class and message (credentials in the authority, scheme, status, type, body). */
    public function testFetchRefusals(): void
    {
        $ia = \InvalidArgumentException::class;
        foreach ([...self::CRED_URLS, 'https://u@ab/p#x'] as $url) {
            self::assertSame("$ia: directory URL must not carry credentials", self::msg(self::fetch($url)[0]), $url);
        }
        // an '@' after the authority (path, query, fragment) is not userinfo
        foreach (['https://ex.com/a@b', 'https://ex.com?a@b', 'https://ex.com#a@b', 'https:///ex.com\\a@b'] as $url) {
            self::assertSame('OK', self::msg(self::fetch($url)[0]), $url);
        }
        self::assertSame("$ia: directory URL must be an http(s) URL", self::msg(self::fetch('file:///x')[0]));
        $rt = \RuntimeException::class;
        $ct = ['content-type' => Webbotauth::DIRECTORY_CONTENT_TYPE];
        self::assertSame('OK', self::msg(self::fetch('https://ex.com/', ['status' => '200', 'headers' => $ct, 'body' => self::dirText()])[0]));
        self::assertSame("$rt: directory fetch returned status 0", self::msg(self::fetch('https://ex.com/', ['headers' => $ct, 'body' => self::dirText()])[0]));
        self::assertSame("$rt: directory has the wrong content type", self::msg(self::fetch('https://ex.com/', ['status' => 200, 'headers' => ['content-type' => 5], 'body' => self::dirText()])[0]));
        self::assertSame("$ia: directory has no keys", self::msg(self::fetch('https://ex.com/', ['status' => 200, 'headers' => $ct, 'body' => 5])[0]));
        self::assertSame("$rt: directory signature: missing signature-input or signature header", self::msg(self::fetch('https://ex.com/', null, ['requireSignature' => true])[0]));
    }

    /** A callable STRING is not used as the fetcher (the built-in fetch runs; a refused loopback connection fails closed). */
    public function testCallableStringIsNotAFetcher(): void
    {
        try {
            Webbotauth::fetchKeyDirectory('http://127.0.0.1:1/x', ['fetch' => 'strtoupper', 'allowInsecureHttp' => true, 'timeoutMs' => 1000]);
            self::fail('a refused connection must throw');
        } catch (\RuntimeException $e) {
            self::assertSame('fetch of http://127.0.0.1:1/x failed', $e->getMessage());
        }
    }

    /** The proof header is read again after verification: headers that change meanwhile fail closed, each with its own reason. */
    public function testProofHeaderReadAfterVerification(): void
    {
        $s = Webbotauth::signRequest(self::signIn(['headers' => ['PCA-Action' => 'x'], 'coverHeaders' => ['PCA-Action']]));
        $h = Obj::of(['PCA-Action' => 'x', 'Signature-Input' => $s['signatureInput'], 'Signature' => $s['signature']]);
        foreach ([[new Obj(), 'missing PCA-Action header'], [Obj::of(['x' => 5]), 'verification failed (fail closed): v.trim is not a function']] as [$swap, $want]) {
            $req = Obj::of(['method' => 'GET', 'url' => 'https://ex.com/p', 'headers' => $h]);
            $resolve = static function (string $kid) use ($req, $swap): ?string {
                $req->set('headers', $swap);
                return $kid === 'k1' ? self::pk() : null;
            };
            self::assertSame($want, self::reason(Webbotauth::verifySignedRequestWithProof($req, self::opts(['resolveKey' => $resolve]))));
        }
    }
}
