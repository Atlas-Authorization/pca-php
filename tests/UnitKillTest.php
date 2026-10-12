<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Direct unit tests of seams the conformance corpus cannot reach (mutation-kill suite; corpus pins live in CorpusTest). */
final class UnitKillTest extends TestCase
{
    private static function o(array $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION));
    }

    /** @return array{0:string,1:string} [public b64u, secret key] */
    private static function key(string $name): array
    {
        $keys = json_decode(file_get_contents(Corpus::DIR . 'keys.json'), true);
        $kp = sodium_crypto_sign_seed_keypair(Pca::unb64u($keys[$name]['seed']));
        return [$keys[$name]['public'], sodium_crypto_sign_secretkey($kp)];
    }

    private static function sign(string $name, string $msg): string
    {
        return Pca::b64u(sodium_crypto_sign_detached($msg, self::key($name)[1]));
    }

    // ------------------------------------------------------------------ caveat caps
    private static function hop(int $n): Obj
    {
        return Obj::of(['caveats' => array_fill(0, $n, Obj::of(['type' => 't']))]);
    }

    public function testCaveatLimits(): void
    {
        $this->assertFalse(Pca::caveatLimitExceeded([]));
        $this->assertFalse(Pca::caveatLimitExceeded([self::hop(256)]));
        $this->assertTrue(Pca::caveatLimitExceeded([self::hop(257)]));
        $this->assertFalse(Pca::caveatLimitExceeded([self::hop(256), self::hop(256), self::hop(256), self::hop(256)]));
        $this->assertTrue(Pca::caveatLimitExceeded([self::hop(256), self::hop(256), self::hop(256), self::hop(256), self::hop(1)]));
        $this->assertTrue(Pca::caveatLimitExceeded([self::hop(205), self::hop(205), self::hop(205), self::hop(205), self::hop(205)]));
        $this->assertFalse(Pca::caveatLimitExceeded([self::hop(205), self::hop(205), self::hop(205), self::hop(205)]));
        $this->assertFalse(Pca::caveatLimitExceeded(array_fill(0, 1100, Obj::of(['caveats' => 'not-a-list']))));
        $this->assertFalse(Pca::caveatLimitExceeded(array_fill(0, 1100, Obj::of([]))));
        $this->assertFalse(Pca::caveatLimitExceeded(['x', 5, null, self::hop(3)]));
        // total exactly 1024 across hops of 1 each is fine; the 1025th pushes it over
        $this->assertFalse(Pca::caveatLimitExceeded(array_fill(0, 1024, self::hop(1))));
        $this->assertTrue(Pca::caveatLimitExceeded(array_fill(0, 1025, self::hop(1))));
    }

    // ------------------------------------------------------------------ regex anchors / flags
    public function testNumAndB64uAnchors(): void
    {
        $this->assertTrue((new Num('5'))->isInt());
        $this->assertFalse((new Num("5\n"))->isInt());
        $this->assertFalse((new Num('5.0'))->isInt());
        $this->assertNull(Pca::unb64u("AAAA\n"));
        $this->assertNull(Pca::unb64u("\nAAAA"));
        $this->assertNotNull(Pca::unb64u('AAAA'));
        $this->assertNull(Pca::unb64u('AAAAA'));
        $this->assertNull(Pca::unb64u('AAAA', 2));
        $this->assertNull(Pca::unb64u('AAA', 1));
        $this->assertNotNull(Pca::unb64u('AAA', 2));
        $this->assertNull(Pca::unb64u('AAAA', 4));
        $this->assertNull(Pca::unb64u(5));
        $this->assertSame('', Pca::unb64u(''));
        $this->assertNull(Pca::unb64u('AB'));
    }

    public function testUtf8Validation(): void
    {
        foreach (["\"\xff\"", "{\"a\":\"\xc3\"}"] as $bad) {
            try {
                Json::parseStrict($bad);
                $this->fail('expected invalid UTF-8');
            } catch (JsonError $e) {
                $this->assertSame('invalid UTF-8', $e->getMessage());
            }
            try {
                Json::parseLax($bad);
                $this->fail('expected invalid UTF-8');
            } catch (JsonError $e) {
                $this->assertSame('invalid UTF-8', $e->getMessage());
            }
        }
    }

    public function testJsonParserEdges(): void
    {
        $this->assertSame("a\x08b", Json::parseStrict('"a\bb"'));
        $this->assertSame("\x08\x08", Json::parseStrict('"\b\b"'));
        $this->assertSame("\u{1F600}", Json::parseStrict('"\ud83d\ude00"'));
        $this->assertSame("\u{10000}", Json::parseStrict('"\ud800\udc00"'));
        $this->assertSame("\u{10FFFF}", Json::parseStrict('"\udbff\udfff"'));
        $this->assertSame("\u{FFFF}", Json::parseStrict('"\uffff"'));
        $this->assertSame("\u{7FF}", Json::parseStrict('"\u07ff"'));
        $this->assertSame("\u{800}", Json::parseStrict('"\u0800"'));
        $this->assertSame("\u{80}", Json::parseStrict('"\u0080"'));
        $this->assertSame("\u{7F}", Json::parseStrict('"\u007f"'));
        foreach (['"abc', '"', "\"a\\", '"\ud83d\ude0'] as $bad) {
            $this->expectJsonError($bad);
        }
        $this->expectJsonError('"\ud800"');
        $this->expectJsonError('"\ud83dx"');
        $this->expectJsonError('"\ud83dA"');
        $this->expectJsonError('"\ude00"');
        // a lax parse keeps a lone surrogate, which strict canonicalization refuses
        $lax = Json::parseLax('"\ud800"');
        $this->assertIsString($lax);
        $this->assertTrue(Json::hasLoneSurrogate($lax));
        $this->assertFalse(Json::hasLoneSurrogate("\u{1F600}"));
        $this->assertFalse(Json::hasLoneSurrogate('abc'));
        // control characters
        for ($c = 0; $c < 0x20; $c++) {
            $this->expectJsonError('"' . chr($c) . '"');
        }
        $this->assertSame(' ', Json::parseStrict('" "'));
        // number lexemes with a fraction use at most one dot
        $this->expectNumError('1.5.5');
        $this->assertSame('1.5', Json::canonicalizeStrict(Json::parseStrict('1.5')));
        $this->assertSame('0.000001', Json::canonicalizeStrict(Json::parseStrict('0.000001')));
        $this->expectNumError('0.0000001');
        $this->expectNumError('0.50');
    }

    private function expectJsonError(string $text): void
    {
        try {
            Json::parseStrict($text);
            $this->fail('expected JsonError for ' . json_encode($text));
        } catch (JsonError) {
            $this->addToAssertionCount(1);
        }
    }

    private function expectNumError(string $text): void
    {
        try {
            Json::canonicalizeStrict(Json::parseStrict($text));
            $this->fail('expected an error for ' . $text);
        } catch (JsonError) {
            $this->addToAssertionCount(1);
        }
    }

    public function testParseStrictRunsCanonicalChecks(): void
    {
        // number form / lone surrogate / depth are enforced at PARSE time, not only on canonicalize
        foreach (['1e5', '1.0', '-0', '01'] as $n) {
            $this->expectJsonError($n);
        }
        $this->expectJsonError(str_repeat('[', 33) . str_repeat(']', 33));
        $this->assertNotNull(Json::parseStrict(str_repeat('[', 32) . str_repeat(']', 32)));
        $this->expectJsonError('{"a":1.50}');
        $this->expectJsonError('"\ud83d"');
    }

    public function testRequireObject(): void
    {
        try {
            Json::parseStrict('[1]', true);
            $this->fail('top-level array must be refused');
        } catch (JsonError) {
            $this->addToAssertionCount(1);
        }
        $this->assertInstanceOf(Obj::class, Json::parseStrict('{}', true));
        $this->assertSame([], Json::parseStrict('[]', false));
    }

    // ------------------------------------------------------------------ merkle / inclusion
    public function testMerkleRootOfNonListLeavesAndInclusion(): void
    {
        $a = Obj::of(['k' => new Num('1')]);
        $b = Obj::of(['k' => new Num('2')]);
        $this->assertSame(Pca::merkleRoot([$a, $b]), Pca::merkleRoot([5 => $a, 9 => $b]));
        $root = Pca::merkleRoot([$a]);
        $this->assertTrue(Pca::verifyInclusion($root, self::o(['index' => 0, 'size' => 1, 'path' => []]), $a));
        $this->assertFalse(Pca::verifyInclusion($root, self::o(['index' => 1, 'size' => 1, 'path' => []]), $a));
        $this->assertFalse(Pca::verifyInclusion($root, self::o(['index' => 0, 'size' => 0, 'path' => []]), $a));
        $this->assertFalse(Pca::verifyInclusion($root, self::o(['index' => -1, 'size' => 1, 'path' => []]), $a));
        $this->assertFalse(Pca::verifyInclusion($root, self::o(['index' => 0, 'size' => 1, 'path' => 'x']), $a));
        $this->assertFalse(Pca::verifyInclusion($root, self::o(['index' => 0, 'size' => 1, 'path' => ['a' => 1]]), $a));
        $this->assertFalse(Pca::verifyInclusion($root, self::o(['index' => 0, 'size' => 1]), $a));
        $this->assertFalse(Pca::verifyInclusion($root, 'x', $a));
        $this->assertFalse(Pca::verifyInclusion($root, self::o(['index' => 0, 'size' => 1.5, 'path' => []]), $a));
        $sib = Pca::b64u(hash('sha256', "\x00" . Json::canonicalizeStrict($b), true));
        $two = Pca::merkleRoot([$a, $b]);
        $this->assertTrue(Pca::verifyInclusion($two, self::o(['index' => 0, 'size' => 2, 'path' => [['side' => 'R', 'hash' => $sib]]]), $a));
        $this->assertFalse(Pca::verifyInclusion($two, self::o(['index' => 2, 'size' => 2, 'path' => [['side' => 'R', 'hash' => $sib]]]), $a));
        $this->assertFalse(Pca::verifyInclusion($two, self::o(['index' => 0, 'size' => 2, 'path' => [['side' => 'L', 'hash' => $sib]]]), $a));
        $this->assertSame(Pca::hashCanonical(Obj::of([])), Pca::paramsDigest(null));
        $this->assertSame(Pca::hashCanonical(Obj::of(['a' => new Num('1')])), Pca::paramsDigest(Obj::of(['a' => new Num('1')])));
        $this->assertNotSame(Pca::paramsDigest(null), Pca::paramsDigest(Obj::of(['a' => new Num('1')])));
    }

    // ------------------------------------------------------------------ signer set / threshold shares
    private static function setOf(array $rows): array
    {
        return array_map(fn($r) => Obj::of($r), $rows);
    }

    private function entry(string $role, array $set, array $share, int $t = 1, string $tm = "\x01\x02"): Obj
    {
        return Obj::of(['role' => $role, 't' => new Num((string)$t), 'signer_set' => $set,
            'threshold_message' => Pca::b64u($tm), 'share' => Obj::of($share)]);
    }

    private function message(string $role, array $set, int $t, string $tm = "\x01\x02"): string
    {
        return Pca::SHARE_DOMAIN_PREFIX . $role . "\0" . hash('sha256', $tm, true) . Pca::signerSetHashRaw($set) . chr($t);
    }

    public function testSignerSetHash(): void
    {
        [$a] = self::key('agent');
        [$p] = self::key('principal');
        $set = self::setOf([['publicKey' => $p, 'role' => 'guardian'], ['publicKey' => $a, 'role' => 'agent']]);
        $sorted = [$set[1], $set[0]];
        $this->assertSame(Pca::signerSetHashRaw($sorted), Pca::signerSetHashRaw($set));
        $expect = hash('sha256', Pca::SIGNERSET_DOMAIN . '[{"publicKey":"' . $a . '","role":"agent"},{"publicKey":"' . $p . '","role":"guardian"}]', true);
        $this->assertSame($expect, Pca::signerSetHashRaw($set));
        // same role: ordered by publicKey
        $two = self::setOf([['publicKey' => max($a, $p), 'role' => 'r'], ['publicKey' => min($a, $p), 'role' => 'r']]);
        $exp2 = hash('sha256', Pca::SIGNERSET_DOMAIN . '[{"publicKey":"' . min($a, $p) . '","role":"r"},{"publicKey":"' . max($a, $p) . '","role":"r"}]', true);
        $this->assertSame($exp2, Pca::signerSetHashRaw($two));
        // pq_pk is carried when it is a string
        $withPq = self::setOf([['publicKey' => $a, 'role' => 'agent', 'pq_pk' => 'PQ']]);
        $this->assertSame(hash('sha256', Pca::SIGNERSET_DOMAIN . '[{"pq_pk":"PQ","publicKey":"' . $a . '","role":"agent"}]', true), Pca::signerSetHashRaw($withPq));
        $numPq = self::setOf([['publicKey' => $a, 'role' => 'agent', 'pq_pk' => 5]]);
        $this->assertSame(hash('sha256', Pca::SIGNERSET_DOMAIN . '[{"publicKey":"' . $a . '","role":"agent"}]', true), Pca::signerSetHashRaw($numPq));
        // malformed sets fail closed
        $this->assertNull(Pca::signerSetHashRaw('x'));
        $this->assertNull(Pca::signerSetHashRaw([1 => $set[0]]));
        $this->assertNull(Pca::signerSetHashRaw(['x']));
        $this->assertNull(Pca::signerSetHashRaw(self::setOf([['publicKey' => $a, 'role' => 5]])));
        // R6-03: key / role validity is the registry's job (verifyThresholdShare refuses the set); the hash itself covers any string set, like the reference
        $this->assertNotNull(Pca::signerSetHashRaw(self::setOf([['publicKey' => 'short', 'role' => 'agent']])));
        $this->assertNull(Pca::signerSetHashRaw(self::setOf([['role' => 'agent']])));
        $this->assertNotNull(Pca::signerSetHashRaw([]));
    }

    public function testThresholdShareRegistry(): void
    {
        [$a] = self::key('agent');
        [$p] = self::key('principal');
        $set = self::setOf([['publicKey' => $a, 'role' => 'agent']]);
        $sig = self::sign('agent', $this->message('agent', $set, 1));
        $good = ['role' => 'agent', 'publicKey' => $a, 'sig' => $sig];
        $this->assertTrue(Pca::verifyThresholdShare($this->entry('agent', $set, $good)));
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $set, ['publicKey' => $a, 'sig' => $sig]))); // R6-03: share.role is required
        $this->assertTrue(Pca::verifyThresholdShare($this->entry('agent', $set, $good + ['alg' => 'ed25519'])));
        // t range 1..3
        foreach ([0, 4] as $t) {
            $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $set, ['role' => 'agent', 'publicKey' => $a, 'sig' => self::sign('agent', $this->message('agent', $set, $t))], $t)));
        }
        foreach ([2, 3] as $t) {
            $this->assertTrue(Pca::verifyThresholdShare($this->entry('agent', $set, ['role' => 'agent', 'publicKey' => $a, 'sig' => self::sign('agent', $this->message('agent', $set, $t))], $t)));
        }
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $set, $good, 2)));
        // share names another role
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $set, ['role' => 'guardian'] + $good)));
        // two keys for one role
        $two = self::setOf([['publicKey' => $a, 'role' => 'agent'], ['publicKey' => $p, 'role' => 'agent']]);
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $two, ['role' => 'agent', 'publicKey' => $a, 'sig' => self::sign('agent', $this->message('agent', $two, 1))])));
        // same key registered twice for one role is not a conflict
        $dup = self::setOf([['publicKey' => $a, 'role' => 'agent'], ['publicKey' => $a, 'role' => 'agent']]);
        $this->assertTrue(Pca::verifyThresholdShare($this->entry('agent', $dup, ['role' => 'agent', 'publicKey' => $a, 'sig' => self::sign('agent', $this->message('agent', $dup, 1))])));
        // one key under two roles
        $dual = self::setOf([['publicKey' => $a, 'role' => 'agent'], ['publicKey' => $a, 'role' => 'guardian']]);
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $dual, ['role' => 'agent', 'publicKey' => $a, 'sig' => self::sign('agent', $this->message('agent', $dual, 1))])));
        // unregistered key / role
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $set, ['publicKey' => $p, 'sig' => self::sign('principal', $this->message('agent', $set, 1))])));
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('guardian', $set, ['publicKey' => $a, 'sig' => $sig])));
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('', $set, ['publicKey' => $a, 'sig' => $sig])));
        // malformed entry pieces
        $this->assertFalse(Pca::verifyThresholdShare('x'));
        $this->assertFalse(Pca::verifyThresholdShare(Obj::of(['role' => 5])));
        $bad = $this->entry('agent', $set, $good);
        $bad->set('t', 'x');
        $this->assertFalse(Pca::verifyThresholdShare($bad));
        $bad = $this->entry('agent', $set, $good);
        $bad->set('threshold_message', 'not*b64');
        $this->assertFalse(Pca::verifyThresholdShare($bad));
        $bad = $this->entry('agent', $set, $good);
        $bad->set('share', 'x');
        $this->assertFalse(Pca::verifyThresholdShare($bad));
        $bad = $this->entry('agent', $set, $good);
        $bad->set('signer_set', 'x');
        $this->assertFalse(Pca::verifyThresholdShare($bad));
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $set, ['publicKey' => $a, 'sig' => 'x'])));
        // a PQ alg needs a registered pq_pk; an absent registry key refuses
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $set, $good + ['alg' => 'ml-dsa-65', 'pq_pk' => 'x'])));
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $set, $good + ['alg' => 'bogus'])));
        $regPq = self::setOf([['publicKey' => $a, 'role' => 'agent', 'pq_pk' => 'REG']]);
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $regPq, $good + ['alg' => 'ml-dsa-65', 'pq_pk' => 'OTHER'])));
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $regPq, $good + ['alg' => 'ml-dsa-65', 'pq_pk' => 'REG'])));
    }

    // ------------------------------------------------------------------ PQ key resolution
    public function testPqKeyResolution(): void
    {
        $m = new \ReflectionMethod(Pca::class, 'resolvePqKey');
        $m->setAccessible(true);
        $r = fn(...$a) => $m->invoke(null, ...$a);
        $commit = Pca::holderPqCommitment('PK');
        $this->assertSame('T', $r('i', 'PK', null, null, 'T')->key);
        $this->assertNull($r('i', 'PK', null, null, ''));
        $this->assertNull($r('i', 'PK', null, null, null));
        $this->assertNull($r('i', '', null, null, null));
        $this->assertNull($r('i', 5, $commit, null, null));
        $this->assertSame('PK', $r('i', 'PK', $commit, null, null)->key);
        $this->assertSame('holder-commitment', $r('i', 'PK', $commit, null, null)->source);
        $this->assertNull($r('i', 'PK', 'wrong', null, null));
        $this->assertNull($r('i', 'PK', 5, null, null));
        $this->assertNull($r('i', 'PK', null, null, null));
        $this->assertSame('pin', $r('i', 'PK', null, ['i' => 'PK'], null)->source);
        $this->assertSame('pin', $r('i', 'PK', null, Obj::of(['i' => 'PK']), null)->source);
        $this->assertNull($r('i', 'PK', $commit, ['i' => 'OTHER'], null));
        $this->assertNull($r('i', 'PK', $commit, Obj::of(['i' => 'OTHER']), null));
        $this->assertSame('holder-commitment', $r('i', 'PK', $commit, ['j' => 'x'], null)->source);
        $this->assertSame('holder-commitment', $r('i', 'PK', $commit, Obj::of(['j' => 'x']), null)->source);
        $this->assertNull($r('i', 'PK', null, ['j' => 'PK'], null));
        $this->assertSame('holder-commitment', $r(5, 'PK', $commit, ['5' => 'x'], null)->source);
        $this->assertSame('holder-commitment', $r(null, 'PK', $commit, ['i' => 'x'], null)->source);
        $this->assertSame('trusted', $r('i', null, null, ['i' => 'X'], 'T')->source);
        // PinnedPq cannot be minted from outside Pca
        $this->expectException(\LogicException::class);
        \Atlas\Pca\PinnedPq::mint('k', 's');
    }

    public function testSuitePolicyAndBinding(): void
    {
        foreach (['suitePolicyError' => 'policy', 'pqBindingError' => 'binding'] as $n => $_) {
            $this->assertTrue(method_exists(Pca::class, $n));
        }
        $pol = new \ReflectionMethod(Pca::class, 'suitePolicyError');
        $pol->setAccessible(true);
        $msg = fn(string $a) => "H: signature suite '$a' is not allowed by this verifier's suite policy";
        $this->assertNull($pol->invoke(null, 'zzz', 'H', null));
        $this->assertNull($pol->invoke(null, null, 'H', ['ed25519']));
        $this->assertSame($msg('ed25519'), $pol->invoke(null, null, 'H', ['ml-dsa-65']));
        $this->assertSame($msg('ed25519'), $pol->invoke(null, null, 'H', []));
        $this->assertNull($pol->invoke(null, 'ml-dsa-65', 'H', ['ml-dsa-65']));
        $this->assertSame($msg('ml-dsa-65'), $pol->invoke(null, 'ml-dsa-65', 'H', ['ed25519']));
        $this->assertSame($msg('invalid'), $pol->invoke(null, 5, 'H', ['ed25519', '5']));
    }

    // ------------------------------------------------------------------ diagnostics
    public function testSupportedSuites(): void
    {
        $this->assertContains('ed25519', Pca::supportedSuites());
        $this->assertTrue(Pca::suiteAvailable('ed25519'));
        $this->assertFalse(Pca::suiteAvailable('bogus'));
        $this->assertSame(Pca::suiteAvailable('ml-dsa-65'), \Atlas\Pca\Mldsa::available());
        $this->assertSame(Pca::suiteAvailable('hybrid-ed25519-ml-dsa-65'), \Atlas\Pca\Mldsa::available());
        $this->assertSame(Pca::suiteAvailable('ml-dsa-87'), false);
    }

    // ------------------------------------------------------------------ middleware
    private function fixture(): array
    {
        $doc = Corpus::core();
        foreach ($doc->get('vectors') as $v) {
            if ($v->get('name') === 'valid-raw-json-format-insensitive') {
                return [$v->get('pcactn_json'), $v->get('grant'), $v->get('context')->get('aud'), $v->get('context')->get('now')->int()];
            }
        }
        $this->fail('fixture');
    }

    private function mw(?callable $resolver = null, ?string $aud = null): PcaMiddleware
    {
        [$json, $grant, $audience, $now] = $this->fixture();
        $ref = Json::parseLax($json)->get('grant_ref');
        $f = new HttpFactory();
        return new PcaMiddleware($aud ?? $audience, $resolver ?? fn(string $r) => $r === $ref ? $grant : null, fn() => $now, $f, $f);
    }

    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public ?ServerRequestInterface $got = null;
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->got = $request;
                return new Response(200);
            }
        };
    }

    public function testMiddlewareCarriers(): void
    {
        [$json] = $this->fixture();
        $h = $this->handler();
        $max = Pca::MAX_ARTIFACT_BYTES;
        // header over the artifact cap -> refused before parsing; exactly at the cap reaches the parser
        $r = $this->mw()->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => Pca::b64u(str_repeat(' ', $max + 1))]), $h);
        $this->assertSame(401, $r->getStatusCode());
        $this->assertSame('PCA-Action header is not a valid PCActn JSON object', json_decode((string)$r->getBody(), true)['error_description']);
        $r = $this->mw()->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => Pca::b64u(str_repeat(' ', $max))]), $h);
        $this->assertSame('PCA-Action header is not a valid PCActn JSON object', json_decode((string)$r->getBody(), true)['error_description']);
        $r = $this->mw()->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => 'not valid base64url!!']), $h);
        $this->assertSame('PCA-Action header is not valid base64url', json_decode((string)$r->getBody(), true)['error_description']);
        $r = $this->mw()->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => Pca::b64u('[1]')]), $h);
        $this->assertSame('PCA-Action header is not a valid PCActn JSON object', json_decode((string)$r->getBody(), true)['error_description']);
        // empty body
        $r = $this->mw()->process(new ServerRequest('POST', '/'), $h);
        $this->assertSame('no PCActn presented (missing PCA-Action header and request body)', json_decode((string)$r->getBody(), true)['error_description']);
        // body: top level must be an object, strict
        $r = $this->mw()->process((new ServerRequest('POST', '/'))->withBody(Utils::streamFor('[1]')), $h);
        $this->assertSame('request body is not valid strict JSON', json_decode((string)$r->getBody(), true)['error_description']);
        $r = $this->mw()->process((new ServerRequest('POST', '/'))->withBody(Utils::streamFor('{"x":1}')), $h);
        $this->assertSame("request body has no 'pcactn' field", json_decode((string)$r->getBody(), true)['error_description']);
        $r = $this->mw()->process((new ServerRequest('POST', '/'))->withBody(Utils::streamFor('{"pcactn":5}')), $h);
        $this->assertSame("'pcactn' is not a JSON object", json_decode((string)$r->getBody(), true)['error_description']);
        $r = $this->mw()->process((new ServerRequest('POST', '/'))->withBody(Utils::streamFor('{"pcactn":{"grant_ref":""}}')), $h);
        $this->assertSame('PCActn has no grant_ref', json_decode((string)$r->getBody(), true)['error_description']);
        $r = $this->mw()->process((new ServerRequest('POST', '/'))->withBody(Utils::streamFor('{"pcactn":{"grant_ref":5}}')), $h);
        $this->assertSame('PCActn has no grant_ref', json_decode((string)$r->getBody(), true)['error_description']);
        // the body stays readable downstream after the middleware consumed it
        $req = (new ServerRequest('POST', '/'))->withBody(Utils::streamFor('{"pcactn":' . $json . '}'));
        $h2 = $this->handler();
        $this->mw()->process($req, $h2);
        $this->assertSame('{"pcactn":' . $json . '}', (string)$h2->got->getBody());
        // padded base64url header is accepted too
        $padded = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);
        $h3 = $this->handler();
        $this->assertSame(200, $this->mw()->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => $padded]), $h3)->getStatusCode());
    }

    public function testMiddlewareErrorBodies(): void
    {
        [$json] = $this->fixture();
        $h = $this->handler();
        $r = $this->mw(null, 'other')->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => Pca::b64u($json)]), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame('application/json', $r->getHeaderLine('Content-Type'));
        $body = json_decode((string)$r->getBody(), true);
        $this->assertSame('insufficient_authority', $body['error']);
        $this->assertStringStartsWith('audience: ', $body['reason']);
        $this->assertArrayHasKey('checks', $body);
        $this->assertFalse($body['checks']['audience']);
        $this->assertStringContainsString('error_description="' . $body['error_description'] . '"', $r->getHeaderLine('WWW-Authenticate'));
        // quoting of backslash and double quote in the challenge, and an unescaped slash in the JSON body
        $f = new HttpFactory();
        $mw = new PcaMiddleware('a', fn() => null, fn() => 0, $f, $f);
        $q = new \ReflectionMethod($mw, 'error');
        $q->setAccessible(true);
        $resp = $q->invoke($mw, 401, 'invalid_request', 'say "hi" \\ a/b');
        $this->assertSame('PCA realm="pca", error="invalid_request", error_description="say \\"hi\\" \\\\ a/b"', $resp->getHeaderLine('WWW-Authenticate'));
        $this->assertSame('{"error":"invalid_request","error_description":"say \"hi\" \\\\ a/b"}', (string)$resp->getBody());
        $resp = $q->invoke($mw, 401, 'invalid_request', '');
        $this->assertSame('PCA realm="pca", error="invalid_request"', $resp->getHeaderLine('WWW-Authenticate'));
        $this->assertSame('{"error":"invalid_request"}', (string)$resp->getBody());
        // a verdict with an empty reason omits "reason" but keeps the checks
        $resp = $q->invoke($mw, 403, 'insufficient_authority', 'd', ['allow' => false, 'checks' => ['wire' => false], 'reason' => '']);
        $this->assertSame('{"error":"insufficient_authority","error_description":"d","checks":{"wire":false}}', (string)$resp->getBody());
        // the default clock is the wall clock: the 2027 fixture is in the future -> denied, not an exception
        $mw2 = new PcaMiddleware('rs-conformance', fn(string $ref) => $this->fixture()[1], null, $f, $f);
        $this->assertSame(403, $mw2->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => Pca::b64u($json)]), $h)->getStatusCode());
        // factories are auto-discovered when omitted
        $mw3 = new PcaMiddleware('a', fn() => null);
        $this->assertSame(401, $mw3->process(new ServerRequest('GET', '/'), $h)->getStatusCode());
        // custom attribute name
        $h4 = $this->handler();
        [$jj, $grant, $aud, $now] = $this->fixture();
        $ref = Json::parseLax($jj)->get('grant_ref');
        $mw4 = new PcaMiddleware($aud, fn(string $r) => $r === $ref ? $grant : null, fn() => $now, $f, $f, 'custom');
        $mw4->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => Pca::b64u($jj)]), $h4);
        $this->assertTrue($h4->got->getAttribute('custom')['allow']);
        $this->assertNull($h4->got->getAttribute('pca'));
    }

    public function testSignerSetSortOrder(): void
    {
        $keys = [];
        foreach (['principal', 'agent', 'subagent', 'rogue'] as $n) {
            $keys[] = self::key($n)[0];
        }
        $rows = [];
        foreach ($keys as $i => $k) {
            $rows[] = ['publicKey' => $k, 'role' => ($i % 2 === 0) ? 'b' : 'a'];
        }
        $expectRows = $rows;
        usort($expectRows, fn($x, $y) => [$x['role'], $x['publicKey']] <=> [$y['role'], $y['publicKey']]);
        $json = '[' . implode(',', array_map(fn($r) => '{"publicKey":"' . $r['publicKey'] . '","role":"' . $r['role'] . '"}', $expectRows)) . ']';
        $expect = hash('sha256', Pca::SIGNERSET_DOMAIN . $json, true);
        for ($rot = 0; $rot < 4; $rot++) {
            $rotated = array_merge(array_slice($rows, $rot), array_slice($rows, 0, $rot));
            $this->assertSame($expect, Pca::signerSetHashRaw(self::setOf($rotated)), "rotation $rot");
            $this->assertSame($expect, Pca::signerSetHashRaw(self::setOf(array_reverse($rotated))), "reverse rotation $rot");
        }
    }

    public function testSignerSetSameRoleOrderAndPublicApi(): void
    {
        [$a] = self::key('agent');
        [$p] = self::key('principal');
        [$lo, $hi] = $a < $p ? [$a, $p] : [$p, $a];
        foreach (['~', '!'] as $role) {
            foreach ([[$lo, $hi], [$hi, $lo]] as $order) {
                $set = self::setOf([['publicKey' => $order[0], 'role' => $role], ['publicKey' => $order[1], 'role' => $role]]);
                $exp = hash('sha256', Pca::SIGNERSET_DOMAIN . '[{"publicKey":"' . $lo . '","role":"' . $role . '"},{"publicKey":"' . $hi . '","role":"' . $role . '"}]', true);
                $this->assertSame($exp, Pca::signerSetHashRaw($set));
            }
        }
        // the verifier building blocks are public API
        $this->assertIsString(Pca::capHash(Obj::of(['a' => new Num('1')])));
        $this->assertSame(Pca::hashCanonical(Obj::of(['a' => new Num('1')])), Pca::capHash(Obj::of(['a' => new Num('1')])));
        [$json] = $this->fixture();
        $p2 = Json::parseStrict($json, true);
        $this->assertNull(Pca::validateWire($p2));
        $this->assertSame('PCActn is not an object', Pca::validateWire('x'));
        $this->assertSame(18 + 32, strlen(Pca::thresholdMessage($p2)));
        [$j, $grant] = $this->fixture();
        $chain = $p2->get('cap_chain');
        $r = Pca::verifyChain($chain, $grant->get('issuer'), true);
        $this->assertTrue($r[1], $r[0]);
        $this->assertSame('', $r[0]);
        $r = Pca::verifyChain([], null, false);
        $this->assertSame(['empty chain', false], [$r[0], $r[1]]);
        $r = Pca::verifyChain(['x'], null, false);
        $this->assertFalse($r[1]);
        $this->assertSame('hop 0: malformed capability', $r[0]);
        $this->assertTrue(Pca::verifyChain($chain, 'ignored', false)[1]);
        $this->assertFalse(Pca::verifyChain($chain, 'other', true)[1]);
        $this->assertSame('hop 0: root issuer is not the expected principal', Pca::verifyChain($chain, 'other', true)[0]);
    }

    public function testThresholdShareForLastRegisteredKey(): void
    {
        [$a] = self::key('agent');
        [$p] = self::key('principal');
        $two = self::setOf([['publicKey' => $a, 'role' => 'agent'], ['publicKey' => $p, 'role' => 'agent']]);
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $two, ['publicKey' => $p, 'sig' => self::sign('principal', $this->message('agent', $two, 1))])));
        $swapped = array_reverse($two);
        $this->assertFalse(Pca::verifyThresholdShare($this->entry('agent', $swapped, ['publicKey' => $a, 'sig' => self::sign('agent', $this->message('agent', $swapped, 1))])));
        // unterminated strings report the exact parser reason
        foreach (['"', '"abc', '{"a":"x'] as $bad) {
            try {
                Json::parseStrict($bad);
                $this->fail('expected an error');
            } catch (JsonError $e) {
                $this->assertStringStartsWith('unterminated string at byte ', $e->getMessage(), $bad);
            }
        }
        // sodium refusal of a length%4==1 string and a short fixed length both give null
        $this->assertNull(Pca::unb64u('AAAAA'));
        $this->assertNull(Pca::unb64u('A', 1));
        $this->assertNull(Pca::unb64u('AAAA', 2));
    }
}
