<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Jose;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Vc;
use PHPUnit\Framework\TestCase;

/** did:key, the passport SD-JWT VC refusals and the RFC 9421 request-signature verify and refusal paths. */
final class CredSurvivorKill23VcTest extends TestCase
{
    private const URL = 'https://example.com/a';
    private const C = 1_700_000_000;

    protected function tearDown(): void
    {
        Vc::$clockHook = null;
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/vc-kill23', true);
    }

    private static function pk(): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed()));
    }

    private static function sk(): string
    {
        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::seed()));
    }

    private function throws(callable $f, string $class, string $msg): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail("expected $class: $msg");
    }

    private static function passport(array $extra = []): Obj
    {
        return Obj::of(['id' => 'p1', 'model_id' => 'm', 'operator' => 'op', 'hardware_rooted' => true, 'issued_at' => 1, 'weights_digest' => 'wd'] + $extra);
    }

    private static function issue(?Obj $p = null, array $args = []): string
    {
        return Vc::passportToVC($p ?? self::passport(), $args + ['issuerKey' => self::seed(), 'issuerDid' => 'did:key:zI', 'subjectDid' => 'did:key:zS',
            'now' => self::C * 1000]);
    }

    private static function payloadOf(string $vc): Obj
    {
        return Js::parse(Jose::lenientB64d(explode('.', explode('~', $vc)[0])[1]));
    }

    private static function verify(string $vc): Obj
    {
        return Vc::verifyPassportVC($vc, self::pk(), ['nowMs' => self::C * 1000]);
    }

    /** A JWT signed by the issuer key with an arbitrary payload, plus the given disclosures. */
    private static function craft(Obj $payload, array $disclosures = []): string
    {
        $jwt = Jose::signJwt($payload, Obj::of(['alg' => 'EdDSA', 'typ' => 'vc+sd-jwt']), self::seed());
        return implode('', array_map(static fn(string $p): string => "$p~", [$jwt, ...$disclosures]));
    }

    private static function withVc(array $vc): string
    {
        return self::craft(Obj::of(['vc' => Obj::of($vc), 'iss' => 'did:key:zI', 'sub' => 'did:key:zS']));
    }

    /** Non-bytes / non-string inputs to the base58 and did:key helpers raise their own TypeErrors. */
    public function testTypeRefusals(): void
    {
        $this->throws(fn() => Vc::base58btcEncode(123), \TypeError::class, 'base58btcEncode: bytes expected');
        $this->throws(fn() => Vc::base58btcDecode(5), \TypeError::class, 'base58btcDecode: string expected');
        $this->throws(fn() => Vc::ed25519FromDidKey(5), \TypeError::class, 'did.startsWith is not a function');
        $this->throws(fn() => Vc::verifyPassportVC(5, self::pk()), \TypeError::class, 'vc.split is not a function');
    }

    /** A non-did:key identifier and an over-long did:key are refused before any base58 decoding; exactly 64 chars still decodes. */
    public function testDidKeyBounds(): void
    {
        $this->assertSame(self::pk(), Vc::ed25519FromDidKey(Vc::didKeyFromEd25519(self::pk()))->raw);
        $this->throws(fn() => Vc::ed25519FromDidKey('did:web:x'), \InvalidArgumentException::class, 'pca-vc: not a did:key:z… identifier');
        $this->throws(fn() => Vc::ed25519FromDidKey('did:key:z' . str_repeat('0', 64)), \InvalidArgumentException::class, 'pca-vc: invalid base58btc character');
        $this->throws(fn() => Vc::ed25519FromDidKey('did:key:z' . str_repeat('0', 65)), \InvalidArgumentException::class,
            'pca-vc: did:key is not an Ed25519 (0xed01) key');
    }

    /** Each disclosure salt is 128 bits (16 random bytes). */
    public function testDisclosureSaltIs16Bytes(): void
    {
        $parts = explode('~', self::issue());
        $d = Js::parse(Jose::lenientB64d($parts[1]));
        $this->assertSame('weights_digest', $d[1]);
        $this->assertSame(16, strlen(Jose::lenientB64d($d[0])));
    }

    /** iat is floor(clock ms / 1000), for a supplied clock and for the system clock. */
    public function testIatFloorsTheClock(): void
    {
        $this->assertSame((float)self::C, Js::num(self::payloadOf(self::issue(null, ['now' => self::C * 1000 + 500]))->get('iat')));
        Vc::$clockHook = static fn(): float => 1_700_000_000.9999;
        $vc = Vc::passportToVC(self::passport(), ['issuerKey' => self::seed()]);
        $this->assertSame((float)self::C, Js::num(self::payloadOf($vc)->get('iat')));
    }

    /** A string ttl is now + "x" read as a jose time span; a non-numeric ttl is refused. */
    public function testTtl(): void
    {
        $this->assertSame((float)(2 * self::C), Js::num(self::payloadOf(self::issue(null, ['ttlSec' => 's']))->get('exp')));
        $this->throws(fn() => self::issue(null, ['ttlSec' => []]), \TypeError::class, 'Invalid setExpirationTime input');
    }

    /** The issuer key must be a 32-byte seed: longer and non-bytes keys are refused with the seed message. */
    public function testSeedRefusals(): void
    {
        $m = 'pca-vc: the signing key must be a 32-byte Ed25519 seed';
        $this->throws(fn() => self::issue(null, ['issuerKey' => str_repeat("\x01", 33)]), \InvalidArgumentException::class, $m);
        $this->throws(fn() => self::issue(null, ['issuerKey' => 5]), \InvalidArgumentException::class, $m);
    }

    /** A non-string credential field is refused with its label. */
    public function testNonStringPassportId(): void
    {
        $this->assertSame('p1', self::verify(self::issue())->get('passport')->get('id'));
        $this->throws(fn() => self::verify(self::issue(self::passport(['id' => 5]))), \InvalidArgumentException::class, 'pca-vc: expected string for passport_id');
    }

    /** Empty JWT, missing vc claim, bad @context, bad type and missing credentialSubject each refuse with their own reason. */
    public function testStructureRefusals(): void
    {
        $ia = \InvalidArgumentException::class;
        $vcCtx = Vc::VC_CONTEXT;
        $ok = [Vc::VC_CONTEXT, Vc::AGENT_PASSPORT_CONTEXT];
        $types = ['VerifiableCredential', Vc::AGENT_PASSPORT_VC_TYPE];
        $this->throws(fn() => self::verify('~abc'), $ia, 'pca-vc: empty SD-JWT');
        $this->throws(fn() => self::verify(self::craft(Obj::of(['iss' => 'x']))), $ia, 'pca-vc: missing vc claim');
        $begin = 'pca-vc: @context must begin with ' . $vcCtx;
        $this->throws(fn() => self::verify(self::withVc(['@context' => $vcCtx])), $ia, $begin);
        $this->throws(fn() => self::verify(self::withVc(['@context' => new Obj()])), $ia, $begin);
        $this->throws(fn() => self::verify(self::withVc(['@context' => []])), $ia, $begin);
        $this->throws(fn() => self::verify(self::withVc(['@context' => [$vcCtx]])), $ia,
            'pca-vc: @context must be exactly [https://www.w3.org/ns/credentials/v2, https://atlasauth.net/credentials/agent-passport/v1]');
        $tm = 'pca-vc: type must include VerifiableCredential and AgentPassportCredential';
        $this->throws(fn() => self::verify(self::withVc(['@context' => $ok, 'type' => 'VerifiableCredential'])), $ia, $tm);
        $this->throws(fn() => self::verify(self::withVc(['@context' => $ok, 'type' => ['VerifiableCredential']])), $ia, $tm);
        $this->throws(fn() => self::verify(self::withVc(['@context' => $ok, 'type' => $types])), $ia, 'pca-vc: missing credentialSubject');
    }

    /** A repeated disclosure and a disclosure that is not a 3-element array are refused with their own reasons. */
    public function testDisclosureRefusals(): void
    {
        $vc = self::issue();
        $d = explode('~', $vc)[1];
        $this->throws(fn() => self::verify($vc . $d . '~'), \InvalidArgumentException::class, 'pca-vc: duplicate disclosure');
        $bad = Jose::b64u('{}');
        $cs = Obj::of(['_sd' => [Jose::b64u(hash('sha256', $bad, true))]]);
        $p = Obj::of(['vc' => Obj::of(['@context' => [Vc::VC_CONTEXT, Vc::AGENT_PASSPORT_CONTEXT], 'type' => ['VerifiableCredential', Vc::AGENT_PASSPORT_VC_TYPE],
            'credentialSubject' => $cs]), '_sd_alg' => 'sha-256']);
        $this->throws(fn() => self::verify(self::craft($p, [$bad])), \InvalidArgumentException::class, 'pca-vc: malformed disclosure');
    }

    private static function signArgs(array $extra = []): array
    {
        return $extra + ['method' => 'GET', 'url' => self::URL, 'headers' => new Obj(), 'key' => self::seed(), 'keyid' => 'k', 'created' => self::C];
    }

    /** Headers given as a PHP map (numeric names included) or as an Obj sign the same covered set; a non-map is no headers. */
    public function testHeaderShapes(): void
    {
        $a = Vc::signRequestMessage(self::signArgs(['headers' => ['Host' => 'example.com', 'X-A' => 'v', '123' => 'n']]));
        $this->assertSame('sig1=("@method" "@target-uri" "123" "host" "x-a");created=1700000000;keyid="k";alg="ed25519"', $a->get('signatureInput'));
        $o = Vc::signRequestMessage(self::signArgs(['headers' => Obj::of(['Host' => 'example.com', 'X-A' => 'v', '123' => 'n'])]));
        $this->assertSame([$a->get('signatureInput'), $a->get('signature')], [$o->get('signatureInput'), $o->get('signature')]);
        $s = Vc::signRequestMessage(self::signArgs(['headers' => 'x']));
        $this->assertSame('sig1=("@method" "@target-uri" "host");created=1700000000;keyid="k";alg="ed25519"', $s->get('signatureInput'));
        $u = Vc::signRequestMessage(self::signArgs(['headers' => Obj::of(["X-\u{c4}" => 'v'])]));
        $this->assertStringContainsString("\"x-\u{e4}\"", $u->get('signatureInput'));
    }

    /** A non-string method or header value raises the platform's TypeError; the method is uppercased Unicode-aware. */
    public function testComponentValues(): void
    {
        $this->throws(fn() => Vc::signRequestMessage(self::signArgs(['method' => 5])), \TypeError::class, 'method.toUpperCase is not a function');
        $this->throws(fn() => Vc::signRequestMessage(self::signArgs(['headers' => ['x' => 5]])), \TypeError::class, 'v.trim is not a function');
        $s = Vc::signRequestMessage(self::signArgs(['method' => "\u{e4}"]));
        $this->assertTrue(Vc::verifyRequestSignature(['method' => "\u{c4}", 'url' => self::URL, 'headers' => new Obj(), 'signatureInput' => $s->get('signatureInput'),
            'signature' => $s->get('signature')], self::pk()));
    }

    /** created defaults to floor(now). */
    public function testCreatedDefaultFloorsTheClock(): void
    {
        Vc::$clockHook = static fn(): float => 1_700_000_000.7;
        $s = Vc::signRequestMessage(['method' => 'GET', 'url' => self::URL, 'headers' => new Obj(), 'key' => self::seed(), 'keyid' => 'k']);
        $this->assertSame('sig1=("@method" "@target-uri" "host");created=1700000000;keyid="k";alg="ed25519"', $s->get('signatureInput'));
    }

    /** The raw signature over the base for one covered @method component and the given params. */
    private static function rawSig(string $sigParams): string
    {
        return base64_encode(sodium_crypto_sign_detached("\"@method\": GET\n\"@signature-params\": $sigParams", self::sk()));
    }

    private static function check(string $input, string $sig, array $extra = []): bool
    {
        return Vc::verifyRequestSignature($extra + ['method' => 'GET', 'url' => self::URL, 'headers' => [], 'signatureInput' => $input, 'signature' => $sig], self::pk());
    }

    /** Hand-signed bases: well-formed params verify; malformed params, a missing '=', a non-ed25519 alg or a wrong signature refuse. */
    public function testVerifyRefusals(): void
    {
        $p = '("@method")';
        $this->assertTrue(self::check("sig1=$p", 'sig1=:' . self::rawSig($p) . ':'));
        $this->assertTrue(self::check("sig1=$p", 'sig1=:' . rtrim(self::rawSig($p), '=') . ':'));
        $this->assertTrue(self::check("sig1=$p", 'sig1=:' . self::rawSig($p) . 'AAAA:')); // decoding stops at the first '='
        $this->assertFalse(self::check("sig1=$p", 'x:' . rtrim(self::rawSig($p), '=') . ':')); // no '=' in Signature
        $this->assertFalse(self::check("sig1=$p", 'sig1=:' . base64_encode(str_repeat("\0", 64)) . ':'));
        $this->assertFalse(self::check('x' . $p, 'sig1=:' . self::rawSig($p) . ':')); // no '=' in Signature-Input
        foreach (['("@method""', 'X"@method")', '("@method");alg="hmac-sha256"'] as $bad) {
            $this->assertFalse(self::check("sig1=$bad", 'sig1=:' . self::rawSig($bad) . ':'), $bad);
        }
    }

    /** maxAgeSec / nowSec follow Number(): null 0, booleans 0/1, numbers, numeric strings; infinite clocks refuse. */
    public function testMaxAgeNumberSemantics(): void
    {
        $p = '("@method");created=' . self::C;
        $sig = 'sig1=:' . self::rawSig($p) . ':';
        $at = fn(mixed $now, mixed $max): bool => self::check("sig1=$p", $sig, ['nowSec' => $now, 'maxAgeSec' => $max]);
        $this->assertTrue($at(self::C, null));
        $this->assertFalse($at(self::C + 1, null));
        $this->assertTrue($at(self::C + 1, true));
        $this->assertFalse($at(self::C + 1, false));
        $this->assertTrue($at(self::C, 300));
        $this->assertTrue($at(self::C, '300'));
        $this->assertFalse($at(self::C + 301, '300'));
        $this->assertFalse($at('Infinity', 'Infinity'));
        Vc::$clockHook = static fn(): float => 1_700_000_000.7;
        $this->assertTrue(self::check("sig1=$p", $sig, ['maxAgeSec' => 0]));
    }

    /** Buffer.from(s, 'base64'): a 4-char group decodes whole, a lone trailing char is dropped, decoding stops at the first '='. */
    public function testNodeB64(): void
    {
        $f = new \ReflectionMethod(Vc::class, 'nodeB64');
        $this->assertSame('ABC', $f->invoke(null, 'QUJD'));
        $this->assertSame('ABC', $f->invoke(null, 'QUJDR'));
        $this->assertSame('ABC', $f->invoke(null, 'QUJD=QUJD'));
    }
}
