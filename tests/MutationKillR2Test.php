<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Mldsa;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Mutation-kill suite, round 2 (Infection survivors of the 2026-10-11 run that are not equivalent). */
final class MutationKillR2Test extends TestCase
{
    private static function prim(): Obj
    {
        return Corpus::core()->get('primitives');
    }

    private static function deepCopy(mixed $v): mixed
    {
        return Json::parseLax(Json::canonicalizeStrict($v));
    }

    // ------------------------------------------------------------------ Json
    public function testCanonicalizeRefusesNonJsonPhpTypes(): void
    {
        foreach ([[5, 'int'], [1.5, 'float'], [new \stdClass(), 'stdClass']] as [$v, $type]) {
            try {
                Json::canonicalizeStrict($v);
                $this->fail("$type canonicalized");
            } catch (JsonError $e) {
                $this->assertSame('canonicalize: unsupported type ' . $type, $e->getMessage());
            }
        }
    }

    public function testSurrogatePairsDecodeAndOnlyAHighSurrogateStartsAPair(): void
    {
        $this->assertSame("\u{1F600}", Json::parseStrict('"\ud83d\ude00"'));
        $this->assertSame("\u{10000}", Json::parseStrict('"\ud800\udc00"'));
        $this->assertSame("\u{10FFFF}", Json::parseStrict('"\udbff\udfff"'));
        // a BMP escape followed by a low surrogate escape is two code units, never a pair (lax: the lone one survives)
        $this->assertSame("A\xED\xB0\x80", Json::parseLax('"\u0041\udc00"'));
        $this->assertSame("\u{E000}\xED\xB0\x80", Json::parseLax('"\ue000\udc00"'));
    }

    // ------------------------------------------------------------------ merkle / inclusion
    public function testMerkleRootIgnoresArrayKeysAndRefusesEmpty(): void
    {
        $m = self::prim()->get('merkle')[0];
        $leaves = $m->get('leaves');
        $this->assertSame($m->get('root'), Pca::merkleRoot(array_combine(array_map(fn($i) => 7 + 3 * $i, array_keys($leaves)), $leaves)));
        $this->assertSame(Pca::merkleRoot([$leaves[0]]), Pca::merkleRoot([9 => $leaves[0]]));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('empty leaf set');
        Pca::merkleRoot([]);
    }

    public function testInclusionRefusesBadSiblingHashAndUnhashableLeaf(): void
    {
        foreach (self::prim()->get('merkle') as $m) {
            foreach ($m->get('proofs') as $i => $p) {
                if (count($p->get('path')) === 0) {
                    continue;
                }
                $root = $m->get('root');
                $leaf = $m->get('leaves')[$i];
                $this->assertTrue(Pca::verifyInclusion($root, $p, $leaf));
                $bad = self::deepCopy($p);
                $bad->get('path')[0]->set('hash', 'not-b64u!');
                $this->assertFalse(Pca::verifyInclusion($root, $bad, $leaf));
                $this->assertFalse(Pca::verifyInclusion($root, $p, 1.5), 'a leaf the strict profile cannot hash');
                return;
            }
        }
        $this->fail('no merkle proof with a non-empty path');
    }

    // ------------------------------------------------------------------ chain
    private static function hopN(int $n): Obj
    {
        return Obj::of(['caveats' => array_fill(0, $n, Obj::of(['type' => 't']))]);
    }

    public function testCaveatCountOfAMalformedHopIsZeroNotNegative(): void
    {
        $h = self::hopN(256);
        $this->assertTrue(Pca::caveatLimitExceeded([$h, $h, $h, $h, Obj::of(['caveats' => 'x']), self::hopN(1)]));
    }

    public function testVerifyChainStandaloneCapsAndNonArrays(): void
    {
        $this->assertSame(['chain too long', false], Pca::verifyChain(array_fill(0, 17, self::hopN(0)), 'x', true));
        $this->assertSame([Pca::CAVEAT_LIMIT_REASON, false], Pca::verifyChain([self::hopN(257)], 'x', true));
        foreach ([null, 5, Obj::of(['a' => 1]), ['k' => self::hopN(0)]] as $chain) {
            $this->assertSame(['empty chain', false], Pca::verifyChain($chain, 'x', true));
        }
    }

    /** Every malformed-chain vector is refused with the reference's own reason (ts_reason), never by the exception backstop. */
    public function testMalformedChainReasonsMatchTheReference(): void
    {
        $n = 0;
        foreach (self::prim()->get('malformed') as $m) {
            if ($m->get('api') !== 'chain') {
                continue;
            }
            $n++;
            [$why, $ok] = Pca::verifyChain($m->get('input')->get('chain'), $m->get('input')->get('expected_root_issuer'), true);
            $this->assertFalse($ok);
            $this->assertSame($m->get('ts_reason'), $why, (string)$m->get('name'));
        }
        $this->assertGreaterThanOrEqual(30, $n);
    }

    private static function pinVector(string $name): Obj
    {
        foreach (self::prim()->get('chain_pin') as $v) {
            if ($v->get('name') === $name) {
                return self::deepCopy($v);
            }
        }
        throw new \LogicException("chain_pin $name not found");
    }

    private static function edge(): array
    {
        return json_decode(file_get_contents(__DIR__ . '/../test-data/mldsa65-edge.json'), true);
    }

    public function testStoredGrantAndPinMustAgree(): void
    {
        // 0.4.2 fail closed: with the stored grant (trustedRoot) AND a pin for the issuer, a disagreeing pin refuses; the
        // stored grant never overrides it. The refusal comes before any signature work, so no PQ backend is needed for it.
        $v = self::pinVector('chainpin-pure-pq-root-trusted-root');
        $wrong = self::pinVector('chainpin-hybrid-root-wrong-pin')->get('pq_pins');
        $right = self::pinVector('chainpin-pure-pq-root-pinned')->get('pq_pins');
        $eri = $v->get('expected_root_issuer');
        $this->assertSame(
            ["hop 0: root suite 'ml-dsa-65': the server-side PQ pin for the root issuer (policy.pqPins) does not match the stored grant's pq_pk (fail closed)", false],
            Pca::verifyChain($v->get('chain'), $eri, true, null, $wrong, $v->get('trusted_root'))
        );
        $this->assertSame(
            ["hop 0: root suite 'ml-dsa-65': the server-side PQ pin for the root issuer (policy.pqPins) does not match the stored grant's pq_pk (fail closed)", false],
            Pca::verifyChain($v->get('chain'), $eri, true, null, ['x' => 'y', $eri => 'not-the-key'], $v->get('trusted_root'))
        );
        if (Pca::suiteImplemented('ml-dsa-65')) {
            $this->assertSame(['', true], Pca::verifyChain($v->get('chain'), $eri, true, null, $right, $v->get('trusted_root')));
            $this->assertSame(['', true], Pca::verifyChain($v->get('chain'), $eri, true, null, ['someone-else' => 'k'], $v->get('trusted_root')));
        }
    }

    public function testHopSuitePolicyIsReportedBeforePqBinding(): void
    {
        $v = self::pinVector('chainpin-mixed-ed25519-root-bound-pq-hop');
        $chain = $v->get('chain');
        $chain[1]->set('pq_pk', self::edge()['pq_pk']); // ALSO breaks the holder_pq binding
        [$why, $ok] = Pca::verifyChain($chain, $v->get('expected_root_issuer'), true, ['ed25519']);
        $this->assertFalse($ok);
        $this->assertSame("hop 1: signature suite 'ml-dsa-65' is not allowed by this verifier's suite policy", $why);
        [$why] = Pca::verifyChain($chain, $v->get('expected_root_issuer'), true);
        $this->assertSame("hop 1: pq_pk does not match the signer's committed holder_pq (F-2)", $why);
    }

    /** Every protocol digest is over the STRICT canonical form: values outside it make the hop 'malformed body'. */
    public function testHopDigestsUseTheStrictProfile(): void
    {
        $deep = 1;
        for ($i = 0; $i < 33; $i++) {
            $deep = [$deep];
        }
        foreach ([new Num('9007199254740994'), new Num('1e300'), new Num('-0'), "a\xED\xA0\x80", $deep] as $k => $bad) {
            $v = self::pinVector('chainpin-mixed-ed25519-root-bound-pq-hop');
            $chain = $v->get('chain');
            $cv = $chain[1]->get('caveats');
            $cv[] = Obj::of(['type' => 'note', 'v' => $bad]);
            $chain[1]->set('caveats', $cv);
            $got = Pca::verifyChain($chain, $v->get('expected_root_issuer'), true);
            // without ML-DSA the hop's suite is refused (unsupported_suite) before its body is hashed: still fail closed
            $this->assertSame(Pca::suiteAvailable('ml-dsa-65') ? ['hop 1: malformed body', false] : ['hop 1: unsupported_suite: ml-dsa-65', false], $got, "case $k");
        }
    }

    public function testUnknownHopSuiteReasonNamesTheSuite(): void
    {
        $v = self::pinVector('chainpin-mixed-ed25519-root-bound-pq-hop');
        $chain = $v->get('chain');
        $chain[1]->set('alg', 'rsa');
        $this->assertSame(["hop 1: unknown signature alg 'rsa'", false], Pca::verifyChain($chain, $v->get('expected_root_issuer'), true));
    }

    public function testLeafSuitePolicyIsReportedBeforePqBinding(): void
    {
        foreach (Corpus::core()->get('vectors') as $v) {
            if ($v->get('name') !== 'pq-leaf-ml-dsa-65-valid') {
                continue;
            }
            $p = self::deepCopy($v->get('pcactn'));
            $p->set('pq_pk', self::edge()['pq_pk']);
            $ctx = $v->get('context');
            $r = Pca::verifyPcactnCore($p, $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'), ['ed25519']);
            $this->assertFalse($r['allow']);
            if (!Pca::suiteAvailable('ml-dsa-65')) {
                // without ML-DSA the wire stage refuses the suite first (fail closed); the ordering below needs a real verifier
                $this->assertSame('wire: unsupported_suite: ml-dsa-65', $r['reason']);
                $this->assertFalse(Pca::verifyPcactnCore($p, $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'))['allow']);
                return;
            }
            $this->assertSame("leaf_signature: leaf: signature suite 'ml-dsa-65' is not allowed by this verifier's suite policy", $r['reason']);
            $r = Pca::verifyPcactnCore($p, $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'));
            $this->assertSame("leaf_signature: leaf: pq_pk does not match the signer's committed holder_pq (F-2)", $r['reason']);
            return;
        }
        $this->fail('vector pq-leaf-ml-dsa-65-valid not found');
    }

    // ------------------------------------------------------------------ threshold shares
    /** @return array{0:string,1:string} [public b64u, secret key] of the round-6 corpus identity $label */
    private static function r6(string $label): array
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', "atlas-pca-conformance/r6/$label", true));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function signedEd25519Entry(array $signerSet): Obj
    {
        [$apub, $ask] = self::r6('agent');
        $tmsg = hash('sha256', 'php-kill-r2', true);
        $ssh = Pca::signerSetHashRaw($signerSet) ?? hash('sha256', 'unhashable', true);
        $msg = Pca::SHARE_DOMAIN_PREFIX . "agent\0" . hash('sha256', $tmsg, true) . $ssh . chr(1);
        return Obj::of([
            'role' => 'agent', 't' => new Num('1'), 'signer_set' => $signerSet, 'threshold_message' => Pca::b64u($tmsg),
            'share' => Obj::of(['role' => 'agent', 'publicKey' => $apub, 'sig' => Pca::b64u(sodium_crypto_sign_detached($msg, $ask))]),
        ]);
    }

    /** An identical duplicate member must not end validation: the members AFTER it are still checked (R6-03). */
    public function testDuplicateMemberDoesNotStopSignerSetValidation(): void
    {
        $a = Obj::of(['role' => 'agent', 'publicKey' => self::r6('agent')[0]]);
        $g = Obj::of(['role' => 'guardian', 'publicKey' => self::r6('guardian')[0]]);
        $this->assertTrue(Pca::verifyThresholdShare(self::signedEd25519Entry([$a, $a, $g])));
        $this->assertFalse(Pca::verifyThresholdShare(self::signedEd25519Entry([$a, $a, Obj::of(['role' => 'guardian', 'publicKey' => 'bad'])])));
        $this->assertFalse(Pca::verifyThresholdShare(self::signedEd25519Entry([$a, $a, Obj::of(['role' => 'stranger', 'publicKey' => self::r6('guardian')[0]])])));
    }

    /** A PQ share that names a pq_pk other than the registered one is refused even though its signature verifies (R5-A1). */
    public function testPqShareWithAForeignPqPkLabelIsRefused(): void
    {
        if (!Mldsa::available()) {
            if (getenv('PCA_REQUIRE_MLDSA') === '1') {
                $this->fail('ML-DSA unavailable');
            }
            $this->markTestSkipped('ML-DSA-65 unavailable');
        }
        $n = 0;
        foreach (self::prim()->get('threshold_set') as $e) {
            $alg = $e->get('share')->has('alg') ? $e->get('share')->get('alg') : 'ed25519';
            if (!$e->get('valid') || !in_array($alg, ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'], true)) {
                continue;
            }
            $n++;
            $bad = self::deepCopy($e);
            $bad->get('share')->set('pq_pk', self::edge()['pq_pk']);
            $this->assertTrue(Pca::verifyThresholdShare($e));
            $this->assertFalse(Pca::verifyThresholdShare($bad), (string)$e->get('name'));
        }
        $this->assertGreaterThanOrEqual(2, $n);
    }

    // ------------------------------------------------------------------ artifacts
    public function testArtifactNonObjectAndUnknownSuiteAreRefused(): void
    {
        $this->assertFalse(Pca::verifyArtifact(null, 'm'));
        $this->assertFalse(Pca::verifyArtifact('x', 'm'));
        foreach (self::prim()->get('pq_artifact') as $a) {
            if ($a->get('alg') === 'ed25519' && $a->get('valid')) {
                $msg = Pca::unb64u($a->get('message'));
                $this->assertTrue(Pca::verifyArtifact($a, $msg));
                $bad = self::deepCopy($a);
                $bad->set('alg', 'rsa');
                $this->assertFalse(Pca::verifyArtifact($bad, $msg));
                return;
            }
        }
        $this->fail('no valid ed25519 pq_artifact');
    }

    // ------------------------------------------------------------------ ML-DSA buffer edges
    public function testMldsaEmptyAndOneByteMessages(): void
    {
        if (!Mldsa::available()) {
            if (getenv('PCA_REQUIRE_MLDSA') === '1') {
                $this->fail('ML-DSA unavailable');
            }
            $this->markTestSkipped('ML-DSA-65 unavailable');
        }
        $e = self::edge();
        $pk = Pca::unb64u($e['pq_pk']);
        $this->assertTrue(Mldsa::verify($pk, '', Pca::unb64u($e['empty_sig'])));
        $this->assertTrue(Mldsa::verify($pk, 'a', Pca::unb64u($e['one_byte_sig'])));
        $this->assertFalse(Mldsa::verify($pk, '', Pca::unb64u($e['one_byte_sig'])));
        $this->assertFalse(Mldsa::verify($pk, 'a', Pca::unb64u($e['empty_sig'])));
    }

    // ------------------------------------------------------------------ middleware
    private static function vector(): array
    {
        foreach (Corpus::core()->get('vectors') as $v) {
            if ($v->get('name') === 'valid-raw-json-format-insensitive') {
                return [$v->get('pcactn_json'), $v->get('grant'), $v->get('context')->get('aud'), $v->get('context')->get('now')->int()];
            }
        }
        throw new \LogicException('vector missing');
    }

    private static function mw(?ResponseFactoryInterface $rf, ?StreamFactoryInterface $sf, ?callable $clock = null): PcaMiddleware
    {
        [$json, $grant, $aud, $now] = self::vector();
        $ref = Json::parseLax($json)->get('grant_ref');
        return new PcaMiddleware($aud, fn(string $r) => $r === $ref ? $grant : null, $clock ?? fn() => $now, $rf, $sf, signatureOnly: true);
    }

    private static function okHandler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public ?string $seen = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->seen = $request->getBody()->getContents(); // reads from the CURRENT position
                return new Response(200);
            }
        };
    }

    public function testDefaultClockIsEpochMilliseconds(): void
    {
        $m = new PcaMiddleware('aud', fn() => null, null, new HttpFactory(), new HttpFactory(), signatureOnly: true);
        $clock = (new \ReflectionProperty(PcaMiddleware::class, 'clock'))->getValue($m);
        $this->assertEqualsWithDelta((int)(microtime(true) * 1000), $clock(), 5000);
    }

    public function testFactoriesDefaultIndividually(): void
    {
        $markedRf = new class implements ResponseFactoryInterface {
            public function createResponse(int $code = 200, string $reasonPhrase = ''): ResponseInterface
            {
                return (new HttpFactory())->createResponse($code, $reasonPhrase)->withHeader('X-Rf', 'custom');
            }
        };
        $markedSf = new class implements StreamFactoryInterface {
            public function createStream(string $content = ''): StreamInterface
            {
                return Utils::streamFor('custom:' . $content);
            }

            public function createStreamFromFile(string $filename, string $mode = 'r'): StreamInterface
            {
                return Utils::streamFor('');
            }

            public function createStreamFromResource($resource): StreamInterface
            {
                return Utils::streamFor('');
            }
        };
        $req = new ServerRequest('GET', '/');
        $r = self::mw(null, $markedSf)->process($req, self::okHandler());
        $this->assertSame(401, $r->getStatusCode());
        $this->assertStringStartsWith('custom:', (string)$r->getBody(), 'the given stream factory is kept');
        $r = self::mw($markedRf, null)->process($req, self::okHandler());
        $this->assertSame('custom', $r->getHeaderLine('X-Rf'), 'the given response factory is kept');
        $this->assertStringStartsWith('{', (string)$r->getBody());
        $r = self::mw(null, null)->process($req, self::okHandler());
        $this->assertSame(401, $r->getStatusCode());
    }

    public function testMissingGrantRefIs401(): void
    {
        $r = self::mw(new HttpFactory(), new HttpFactory())->process(
            new ServerRequest('GET', '/', [PcaMiddleware::HEADER => Pca::b64u('{"ver":2}')]),
            self::okHandler()
        );
        $this->assertSame(401, $r->getStatusCode());
        $this->assertSame('PCActn has no grant_ref', json_decode((string)$r->getBody(), true)['error_description']);
    }

    public function testHeaderOfExactlyTheArtifactLimitIsVerified(): void
    {
        [$json] = self::vector();
        $padded = $json . str_repeat(' ', Pca::MAX_ARTIFACT_BYTES - strlen($json));
        $this->assertSame(Pca::MAX_ARTIFACT_BYTES, strlen($padded));
        $h = self::okHandler();
        $r = self::mw(new HttpFactory(), new HttpFactory())->process(new ServerRequest('GET', '/', [PcaMiddleware::HEADER => Pca::b64u($padded)]), $h);
        $this->assertSame(200, $r->getStatusCode());
        $r = self::mw(new HttpFactory(), new HttpFactory())->process(new ServerRequest('GET', '/', [PcaMiddleware::HEADER => Pca::b64u($padded . ' ')]), self::okHandler());
        $this->assertSame(401, $r->getStatusCode());
    }

    public function testBodyIsRewoundForTheDownstreamHandler(): void
    {
        [$json] = self::vector();
        $body = '{"pcactn":' . $json . '}';
        $h = self::okHandler();
        $r = self::mw(new HttpFactory(), new HttpFactory())->process((new ServerRequest('POST', '/'))->withBody(Utils::streamFor($body)), $h);
        $this->assertSame(200, $r->getStatusCode());
        $this->assertSame($body, $h->seen);
    }
}
