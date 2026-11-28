<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\A2a;
use Atlas\Pca\Agentcard;
use Atlas\Pca\Jose;
use Atlas\Pca\JoseError;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for Agent Cards and AgentFacts: RFC 8785 bytes, the detached JWS (crit / b64 / alg gates, key resolution, the
 * Ed25519 d-x check), multi-signature passport refs, Date.parse / toISOString, the registry entry's well-known URL with userinfo,
 * well-known path matching and the AgentFacts clock.
 */
final class AgentSurvivorKill13AgentcardTest extends TestCase
{
    private static function seed(string $tag = 'a'): string
    {
        return hash('sha256', "atlas-pca-conformance/agentcard-kill13/$tag", true);
    }

    private static function jwk(string $tag = 'a', array $extra = []): Obj
    {
        $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed($tag)));
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Jose::b64u($pk)] + $extra);
    }

    private static function key(string $tag = 'a'): array
    {
        return Agentcard::resolveVerifyKey(['key' => self::jwk($tag)]);
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

    private static function throws(callable $f, string $class, string $msg): void
    {
        try {
            $f();
            self::fail("expected $class: $msg");
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
        }
    }

    // ---- RFC 8785 ----

    /** JCS: an assoc array is an object, 64 nested lists are allowed, a non-finite number and a non-JSON value are refused by name. */
    public function testJcs(): void
    {
        self::assertSame('{"a":2,"b":1}', Agentcard::jcsBytes(['b' => 1, 'a' => 2]));
        self::assertSame(str_repeat('[', 64) . str_repeat(']', 64), Agentcard::jcsBytes(array_reduce(range(1, 63), static fn($c) => [$c], [])));
        self::throws(static fn() => Agentcard::jcsBytes(INF), \TypeError::class, 'jcs: non-finite number');
        self::throws(static fn() => Agentcard::jcsBytes(new \stdClass()), \TypeError::class, 'jcs: unsupported type stdClass');
    }

    // ---- detached JWS ----

    /** signDetached is public, refuses an empty alg with its own text, and writes integer header names as strings. */
    public function testSignDetached(): void
    {
        self::throws(static fn() => Agentcard::signDetached('p', self::seed(), ['alg' => '']), JoseError::class, '"alg" (Algorithm) Header Parameter missing or invalid');
        $s = Agentcard::signDetached('p', self::seed(), ['header' => [5 => 'x']]);
        self::assertStringContainsString('"5":"x"', (string)Jose::lenientB64d($s['protected']));
        self::assertTrue(Agentcard::verifyDetached('p', Obj::of($s), self::key())['ok']);
    }

    private static function det(array $header, ?array $key = null): array
    {
        $prot = Jose::b64u((string)json_encode($header));
        return Agentcard::verifyDetached('p', Obj::of(['protected' => $prot, 'signature' => Jose::b64u(str_repeat("\0", 64))]), $key ?? self::key());
    }

    /** The crit, b64 and alg header gates, each with its own reason; a non-string protected member is malformed. */
    public function testDetachedHeaderGates(): void
    {
        $critBad = '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present';
        foreach (['b64', [], [''], [5], ['b64', '']] as $crit) {
            self::assertSame(['ok' => false, 'reason' => $critBad], self::det(['alg' => 'EdDSA', 'b64' => false, 'crit' => $crit]));
        }
        self::assertSame(['ok' => false, 'reason' => 'Extension Header Parameter "b64" is missing'], self::det(['alg' => 'EdDSA', 'crit' => ['b64']]));
        $algBad = 'JWS "alg" (Algorithm) Header Parameter missing or invalid';
        self::assertSame(['ok' => false, 'reason' => $algBad], self::det(['b64' => false, 'crit' => ['b64']], ['none']));
        self::assertSame(['ok' => false, 'reason' => $algBad], self::det(['alg' => '', 'b64' => false, 'crit' => ['b64']], ['none']));
        self::assertSame(['ok' => false, 'reason' => 'signature is malformed'], Agentcard::verifyDetached('p', Obj::of(['protected' => 5, 'signature' => 'AA']), self::key()));
    }

    /** Key resolution: a non-JWK object verifies nothing, an oct JWK needs k, a private Ed25519 JWK's d must be 32 bytes matching x. */
    public function testResolveVerifyKey(): void
    {
        self::assertSame(['none'], Agentcard::resolveVerifyKey(['key' => Obj::of(['x' => 1])]));
        self::assertSame(['error', 'could not resolve verification key: missing "k" in the oct JWK'], Agentcard::resolveVerifyKey(['key' => Obj::of(['kty' => 'oct'])]));
        $mismatch = ['error', 'could not resolve verification key: invalid Ed25519 key: d does not match x'];
        self::assertSame($mismatch, Agentcard::resolveVerifyKey(['key' => self::jwk('a', ['d' => Jose::b64u(self::seed('b'))])]));
        self::assertSame($mismatch, Agentcard::resolveVerifyKey(['key' => self::jwk('a', ['d' => 'AA'])]));
        self::assertSame('key', Agentcard::resolveVerifyKey(['key' => self::jwk('a', ['d' => Jose::b64u(self::seed('a'))])])[0]);
    }

    // ---- signed cards ----

    /** A card must be an object; a passport option must be one; a schema failure lists every problem. */
    public function testIssueRefusals(): void
    {
        self::throws(static fn() => Agentcard::issueSignedAgentCard([1], self::seed()), \TypeError::class, 'value is not an object');
        self::throws(static fn() => Agentcard::issueSignedAgentCard(Obj::of(['name' => 'n']), self::seed(), ['passport' => 'x']), \TypeError::class, "Cannot use 'in' operator on a non-object");
        $card = Obj::of(['name' => 'n']);
        self::throws(static fn() => Agentcard::issueSignedAgentCard($card, self::seed(), ['schema' => 'a2a-1.0']), \RuntimeException::class,
            'issueSignedAgentCard: the card does not match the A2A 1.0 schema: ' . implode('; ', Agentcard::validateAgentCard1($card)));
    }

    /** The A2A 1.0 schema checks tenant, pushNotifications and extendedAgentCard types. */
    public function testSchemaOptionalMembers(): void
    {
        $p = Agentcard::validateAgentCard1(Obj::of(['supportedInterfaces' => [Obj::of(['tenant' => 5])], 'capabilities' => Obj::of(['pushNotifications' => 'x', 'extendedAgentCard' => 'x'])]));
        self::assertContains('$.supportedInterfaces[0].tenant: must be a string', $p);
        self::assertContains('$.capabilities.pushNotifications: must be a boolean', $p);
        self::assertContains('$.capabilities.extendedAgentCard: must be a boolean', $p);
    }

    /** With several signatures the FIRST verified pca_passport is the ref; a bad signature's reason carries the JWS reason. */
    public function testMultiSignaturePassportRef(): void
    {
        $card = Obj::of(['name' => 'n']);
        $payload = Agentcard::cardSigningBytes($card);
        $card->set('signatures', [Obj::of(Agentcard::signDetached($payload, self::seed(), ['header' => ['pca_passport' => 'p1']])),
            Obj::of(Agentcard::signDetached($payload, self::seed(), ['header' => ['pca_passport' => 'p2']]))]);
        self::assertSame('p1', Agentcard::verifyAgentCard($card, ['key' => self::jwk()])['passportRef']);
        self::assertSame('p1', A2a::verifyAgentCard($card, ['key' => self::jwk()])->get('passportRef'));
        $bad = 'signature 0 did not verify: signature verification failed';
        self::assertSame($bad, Agentcard::verifyAgentCard($card, ['key' => self::jwk('b')])['reason']);
        self::assertSame($bad, A2a::verifyAgentCard($card, ['key' => self::jwk('b')])->get('reason'));
    }

    // ---- dates ----

    /** Date.parse of canonical ISO strings and toISOString of their milliseconds, across months, leap rules, eras and the range ends. */
    public function testIsoRoundTrip(): void
    {
        foreach ([
            ['1970-01-01T00:00:00.000Z', 0.0], ['2024-03-15T12:34:56.789Z', 1710506096789.0], ['2024-02-29T23:59:59.999Z', 1709251199999.0],
            ['2024-02-15T00:00:00.000Z', 1707955200000.0],
            ['2023-01-01T00:00:00.000Z', 1672531200000.0], ['2023-02-01T00:00:00.000Z', 1675209600000.0], ['2023-03-01T00:00:00.000Z', 1677628800000.0],
            ['2023-04-01T00:00:00.000Z', 1680307200000.0], ['2023-05-01T00:00:00.000Z', 1682899200000.0], ['2023-06-01T00:00:00.000Z', 1685577600000.0],
            ['2023-07-01T00:00:00.000Z', 1688169600000.0], ['2023-08-01T00:00:00.000Z', 1690848000000.0], ['2023-09-01T00:00:00.000Z', 1693526400000.0],
            ['2023-10-01T00:00:00.000Z', 1696118400000.0], ['2023-11-01T00:00:00.000Z', 1698796800000.0], ['2023-12-01T00:00:00.000Z', 1701388800000.0],
            ['2023-01-28T00:00:00.000Z', 1674864000000.0], ['2023-02-28T00:00:00.000Z', 1677542400000.0], ['2023-03-28T00:00:00.000Z', 1679961600000.0],
            ['2023-04-28T00:00:00.000Z', 1682640000000.0], ['2023-05-28T00:00:00.000Z', 1685232000000.0], ['2023-06-28T00:00:00.000Z', 1687910400000.0],
            ['2023-07-28T00:00:00.000Z', 1690502400000.0], ['2023-08-28T00:00:00.000Z', 1693180800000.0], ['2023-09-28T00:00:00.000Z', 1695859200000.0],
            ['2023-10-28T00:00:00.000Z', 1698451200000.0], ['2023-11-28T00:00:00.000Z', 1701129600000.0], ['2023-12-28T00:00:00.000Z', 1703721600000.0],
            ['2099-03-01T00:00:00.000Z', 4076006400000.0], ['2100-03-01T00:00:00.000Z', 4107542400000.0], ['2100-02-28T00:00:00.000Z', 4107456000000.0],
            ['2100-03-02T00:00:00.000Z', 4107628800000.0], ['2400-02-28T00:00:00.000Z', 13574476800000.0], ['2400-02-29T00:00:00.000Z', 13574563200000.0],
            ['2004-02-28T00:00:00.000Z', 1077926400000.0], ['2004-02-29T00:00:00.000Z', 1078012800000.0],
            ['0000-06-01T00:00:00.000Z', -62154086400000.0], ['0000-01-01T00:00:00.000Z', -62167219200000.0],
            ['-000001-03-01T00:00:00.000Z', -62193657600000.0], ['-000001-12-31T00:00:00.000Z', -62167305600000.0],
            ['-000400-03-01T00:00:00.000Z', -74784816000000.0], ['-000401-02-28T00:00:00.000Z', -74816524800000.0],
            ['+010000-01-01T00:00:00.000Z', 253402300800000.0], ['+275760-09-13T00:00:00.000Z', 8640000000000000.0],
            ['-271821-04-20T00:00:00.000Z', -8640000000000000.0], ['1969-12-31T23:59:59.999Z', -1.0],
            ['2023-01-31T00:00:00.000Z', 1675123200000.0], ['2023-03-31T00:00:00.000Z', 1680220800000.0], ['2023-04-30T00:00:00.000Z', 1682812800000.0],
            ['2023-05-31T00:00:00.000Z', 1685491200000.0], ['2023-06-30T00:00:00.000Z', 1688083200000.0], ['2023-07-31T00:00:00.000Z', 1690761600000.0],
            ['2023-08-31T00:00:00.000Z', 1693440000000.0], ['2023-09-30T00:00:00.000Z', 1696032000000.0], ['2023-10-31T00:00:00.000Z', 1698710400000.0],
            ['2023-11-30T00:00:00.000Z', 1701302400000.0], ['2023-12-31T00:00:00.000Z', 1703980800000.0],
            ['0000-02-29T00:00:00.000Z', -62162121600000.0], ['0000-03-01T00:00:00.000Z', -62162035200000.0],
        ] as [$iso, $ms]) {
            self::assertSame($ms, Agentcard::dateParse($iso), "parse $iso");
            self::assertSame($iso, Agentcard::isoFromMs($ms), "iso $ms");
        }
    }

    /** Date.parse of partial, fractional, 24:00, offset and out-of-range spellings. */
    public function testDateParseForms(): void
    {
        foreach ([
            ['2024', 1704067200000.0], ['2024-02', 1706745600000.0], ['2024-02-03', 1706918400000.0], ['2024-02-03T04:05', 1706933100000.0],
            ['2024-02-03T04:05:06', 1706933106000.0], ['2024-02-03T04:05:06.5Z', 1706933106500.0], ['2024-02-03T04:05:06.12Z', 1706933106120.0],
            ['2024-02-03T04:05:06.1234Z', 1706933106123.0], ['2024-02-03T04:05:06.5', 1706933106500.0],
            ['2024-01-01T24:00:00.000Z', 1704153600000.0], ['2024-01-01T24:00', 1704153600000.0], ['2024-01-01T24:00:00.001Z', null],
            ['2024-01-01T24:01', null], ['2024-01-01T24:00:01', null], ['2024-00-01', null], ['2024-13-01', null], ['2024-12-31', 1735603200000.0],
            ['2024-01-00', null], ['2024-01-32', null], ['2024-01-01T00:60', null], ['2024-01-01T00:59:60', null], ['2024-01-01T00:59:59', 1704070799000.0],
            ['2024-01-01T25:00', null], ['2024-01-01T23:00', 1704150000000.0], ['2024-01-01T01:02:03+05:30', 1704051123000.0],
            ['2024-01-01T01:02:03-05:30', 1704090723000.0], ['2024-01-01T01:02:03.123+05:30', 1704051123123.0], ['2024-01-01T01:02+23:59', 1703984580000.0],
            ['2024-01-01T01:02+24:00', null], ['2024-01-01T01:02+05:60', null], ['2024-01-01T01:02-00:00', 1704070920000.0], ['-000000-01-01', null],
            ['+002024-03-15', 1710460800000.0], ['x', null], ['2024-1-01', null], ['+275760-09-13T00:00:00.001Z', null],
            ['+275760-09-12T23:59:59.999-00:01', null], ['-271821-04-19T23:59:59.999Z', null],
        ] as [$s, $ms]) {
            self::assertSame($ms, self::quiet(static fn() => Agentcard::dateParse($s)), $s);
        }
        self::assertNull(Agentcard::dateParse(5));
    }

    // ---- AgentFacts ----

    /** Without validFrom or now the statement time is floor(wall clock in ms), read through the clock seam. */
    public function testFactsClock(): void
    {
        Agentcard::$clockHook = static fn(): float => 1000.0006;
        try {
            $f = Agentcard::issueAgentFacts(Obj::of(['id' => 'agent:1']), ['attestorKey' => self::seed(), 'attests' => Obj::of(['a' => 1])]);
        } finally {
            Agentcard::$clockHook = null;
        }
        self::assertSame('1970-01-01T00:16:40.000Z', $f->get('attestations')[0]->get('validFrom'));
    }

    /** AgentFacts refusals with their exact texts. */
    public function testFactsRefusals(): void
    {
        self::throws(static fn() => Agentcard::issueAgentFacts(Obj::of(['id' => 'agent:1']), ['attestorKey' => self::seed(), 'validFrom' => '2020-01-01T00:00:00.000Z']),
            \TypeError::class, 'canonicalBytes: unsupported type undefined (attests)');
        self::throws(static fn() => Agentcard::addAttestation(Obj::of(['type' => 'AgentFacts']), ['attestorKey' => self::seed(), 'attests' => Obj::of([])]),
            \TypeError::class, 'canonicalBytes: unsupported type undefined (id)');
        self::throws(static fn() => Agentcard::verifyAgentFacts(Obj::of(['id' => 'a']), ['now' => 'x']), \TypeError::class, 'now must be a number');
        $facts = Agentcard::issueAgentFacts(Obj::of(['id' => 'agent:1']), ['attestorKey' => self::seed(), 'attests' => Obj::of(['a' => 1]), 'validFrom' => '2020-01-01T00:00:00.000Z']);
        $v = Agentcard::verifyAgentFacts($facts, ['key' => self::jwk('b'), 'now' => 1.7e12]);
        self::assertSame('signature did not verify: signature verification failed', $v['attestations'][0]['reason']);
        self::assertTrue(Agentcard::verifyAgentFacts($facts, ['key' => self::jwk(), 'now' => 1.7e12])['ok']);
        $odd = Obj::of(['id' => 'agent:1', 'attestations' => [Obj::of(['issuer' => 'i', 'subject' => 5, 'attests' => Obj::of([]), 'validFrom' => '2020'])]]);
        self::assertSame('attestation is malformed', Agentcard::verifyAgentFacts($odd, ['key' => self::jwk(), 'now' => 1.7e12])['attestations'][0]['reason']);
    }

    // ---- hosting and the registry entry ----

    /** The well-known path "/" is kept as "/" (only a longer path drops its trailing slash). */
    public function testRootPathIsNotEmptied(): void
    {
        $h = Agentcard::agentCardHandler(Obj::of(['name' => 'n']), '/');
        self::assertNull($h(''));
        self::assertSame(200, $h('/?x=1')['status']);
    }

    /** The registry entry's card URL: new URL(path, base) with WHATWG userinfo, special-scheme slashes and opaque bases. */
    public function testRegistryCardUrl(): void
    {
        $p = Agentcard::WELL_KNOWN_AGENT_CARD_PATH;
        foreach ([
            ['https://u:p@ex.com/x', "https://u:p@ex.com$p"], ['https://u@ex.com', "https://u@ex.com$p"], ['https://:p@ex.com', "https://:p@ex.com$p"],
            ['https://@ex.com', "https://ex.com$p"], ['https://a@b@ex.com', "https://a%40b@ex.com$p"], ['https://u:p:q@ex.com', "https://u:p%3Aq@ex.com$p"],
            ['https://ab:cd@ex.com', "https://ab:cd@ex.com$p"], ["https://u\t@ex.com", "https://u@ex.com$p"], ['https:ex.com', "https://ex.com$p"],
            ['https:u@ex.com', "https://u@ex.com$p"], ['https:\\\\u@ex.com', "https://u@ex.com$p"], ['https://u@ex.com/a@b', "https://u@ex.com$p"],
            ['https://u@ex.com\\a@b', "https://u@ex.com$p"], ['foo://u@h/x', "foo://u@h$p"], ['foo:///u@h', "foo://$p"],
        ] as [$url, $want]) {
            self::assertSame($want, Agentcard::toRegistryEntry(Obj::of(['url' => $url]), new Obj())->get('agentCardUrl'), $url);
        }
        self::assertFalse(Agentcard::toRegistryEntry(Obj::of(['url' => 'foo:x']), new Obj())->has('agentCardUrl'));
    }

    /** Attested claim names are strings even when numeric. */
    public function testAttestedClaimNamesAreStrings(): void
    {
        $e = Agentcard::toRegistryEntry(new Obj(), Obj::of(['attestations' => [Obj::of(['attests' => Obj::of(['5' => true, 'a' => true])])]]));
        self::assertSame(['5', 'a'], $e->get('attestedClaims'));
    }
}
