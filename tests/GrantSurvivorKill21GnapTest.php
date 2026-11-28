<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Gnap;
use Atlas\Pca\GnapError;
use Atlas\Pca\InteractionError;
use Atlas\Pca\InteractionServer;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\NodeTypeError;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** GNAP bridge: holder resolution, grant issuance, jwsd proof bounds, step-up shares, interaction helpers and the AS state machine. */
final class GrantSurvivorKill21GnapTest extends TestCase
{
    protected function tearDown(): void
    {
        Gnap::$clockHook = null;
        Gnap::$randomHook = null;
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    private static function pub(string $seed): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
    }

    /** Runs `$f` and returns the throwable it raised (fails when it returns normally). */
    private function raised(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        $this->fail('expected a throw');
    }

    private function assertThrown(string $class, string $message, callable $f): \Throwable
    {
        $e = $this->raised($f);
        $this->assertSame([$class, $message], [get_class($e), $e->getMessage()]);
        return $e;
    }

    private static function jwkKey(string $holder, mixed $proof = 'jwsd'): Obj
    {
        return Obj::of(['proof' => $proof, 'jwk' => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $holder])]);
    }

    private static function req(string $holder, array $access): Obj
    {
        return Obj::of(['access_token' => Obj::of(['access' => $access]), 'client' => Obj::of(['key' => self::jwkKey($holder)])]);
    }

    private static function holder(): string
    {
        return (new KeyPair(self::seed('g21-holder')))->public;
    }

    /** A copy of `$o` with member `$k` replaced (appended when absent). */
    private static function with(Obj $o, string $k, mixed $v): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $x) {
            $c->set($x, $x === $k ? $v : $o->get($x));
        }
        if (!$o->has($k)) {
            $c->set($k, $v);
        }
        return $c;
    }

    // ---- access rights -------------------------------------------------------------------------------------------------

    /** A non-array access and a typeless item are refused with their own GnapError reasons. */
    public function testNormalizeAccessRefusals(): void
    {
        $this->assertThrown(GnapError::class, 'access must be an array', fn() => Gnap::normalizeAccess('photos'));
        $this->assertThrown(GnapError::class, 'malformed access item (needs a non-empty string `type`)', fn() => Gnap::normalizeAccess([5]));
        $this->assertCount(1, Gnap::normalizeAccess(['photos'])); // control
    }

    /** A datatype constraint becomes a `where` list of condition objects on every location's predicate. */
    public function testAccessToPredicatesWhereConditionsAreObjects(): void
    {
        $ps = Gnap::accessToPredicates(Obj::of(['type' => 't', 'locations' => ['a', 'b'], 'datatypes' => ['x']]));
        $this->assertCount(2, $ps);
        foreach ($ps as $p) {
            $w = $p->get('where');
            $this->assertCount(1, $w);
            $this->assertInstanceOf(Obj::class, $w[0]);
            $this->assertSame(['action.params.datatype', 'in', ['x']], [$w[0]->get('field'), $w[0]->get('op'), $w[0]->get('value')]);
        }
    }

    /** A non-string granted location never matches (and never reaches a string-only prefix test). */
    public function testNonStringGrantedLocationDoesNotCover(): void
    {
        $this->assertFalse(Gnap::accessContains(Obj::of(['type' => 't', 'locations' => [5]]), Obj::of(['type' => 't', 'locations' => ['x']])));
        $this->assertTrue(Gnap::accessContains(Obj::of(['type' => 't', 'locations' => [5, 'x*']]), Obj::of(['type' => 't', 'locations' => ['xy']])));
    }

    // ---- recorded rights -----------------------------------------------------------------------------------------------

    /** A leaf `gnap_access` caveat at index 0 is the effective access; a non-object caveat is skipped. */
    public function testGrantedAccessOfReadsTheFirstLeafCaveat(): void
    {
        $leaf = Obj::of(['caveats' => [Obj::of(['type' => Gnap::GNAP_ACCESS_CAVEAT, 'access' => ['photos']])]]);
        $got = Gnap::grantedAccessOf([$leaf]);
        $this->assertCount(1, $got);
        $this->assertSame('photos', $got[0]->get('type'));
        $this->assertSame([], Gnap::grantedAccessOf([Obj::of(['caveats' => ['junk']])]));
    }

    /** The root's recorded rights come from the FIRST gnap_grant caveat; other caveats (and non-objects) are skipped. */
    public function testGrantedAccessOfReadsTheFirstRootGrantCaveat(): void
    {
        $h = self::holder();
        $root = Gnap::grantRequestToCapability(self::req($h, ['photos']), ['issuerSecret' => self::seed('g21-issuer'), 'now' => 1000])['grant'];
        $env = $root->get('caveats')[0];
        $g = static fn(string $type, string $right): Obj => Obj::of(['type' => $type, 'client_id' => 'c', 'request_digest' => 'd', 'granted_access' => [$right]]);
        $env2 = self::with($env, 'caveats', ['junk', $g('other', 'a'), $g(Gnap::GNAP_GRANT_CAVEAT, 'b'), $g(Gnap::GNAP_GRANT_CAVEAT, 'c')]);
        $got = Gnap::grantedAccessOf([self::with($root, 'caveats', [$env2])]);
        $this->assertCount(1, $got);
        $this->assertSame('b', $got[0]->get('type'));
        $ctl = Gnap::grantedAccessOf([$root]);
        $this->assertSame('photos', $ctl[0]->get('type'));
    }

    // ---- holders -------------------------------------------------------------------------------------------------------

    /** The client's OKP/Ed25519 JWK is the holder when no override is passed. */
    public function testResolveHolderFromJwkWithoutOverride(): void
    {
        $h = self::holder();
        $this->assertSame($h, Gnap::resolveHolder(Obj::of(['client' => Obj::of(['key' => self::jwkKey($h)])])));
    }

    /** Proof methods other than jwsd are refused, naming the method (or `none`). */
    public function testResolveHolderProofMethodRefusals(): void
    {
        $h = self::holder();
        $none = 'unsupported client key proof method: none (only jwsd is supported)';
        $this->assertThrown(GnapError::class, $none, fn() => Gnap::resolveHolder(Obj::of(['client' => Obj::of(['key' => []])])));
        $this->assertThrown(GnapError::class, $none, fn() => Gnap::resolveHolder(Obj::of(['client' => Obj::of(['key' => Obj::of(['jwk' => 1])])])));
        $this->assertThrown(GnapError::class, $none, fn() => Gnap::resolveHolder(Obj::of(['client' => Obj::of(['key' => self::jwkKey($h, Obj::of(['method' => 5]))])])));
        $this->assertThrown(GnapError::class, 'unsupported client key proof method: jws (only jwsd is supported)',
            fn() => Gnap::resolveHolder(Obj::of(['client' => Obj::of(['key' => self::jwkKey($h, 'jws')])])));
        $this->assertSame($h, Gnap::resolveHolder(Obj::of(['client' => Obj::of(['key' => self::jwkKey($h, Obj::of(['method' => 'jwsd']))])])));
    }

    /** No resolvable key, a non-object JWK and a bad override are refused with their own reasons. */
    public function testResolveHolderUnresolvable(): void
    {
        $cannot = 'cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override';
        $this->assertThrown(GnapError::class, $cannot, fn() => Gnap::resolveHolder(Obj::of(['client' => Obj::of([])])));
        $this->assertThrown(GnapError::class, $cannot, fn() => Gnap::resolveHolder(Obj::of(['client' => Obj::of(['key' => Obj::of(['proof' => 'jwsd', 'jwk' => 'x'])])])));
        $this->assertThrown(GnapError::class, 'holder override is not a canonical base64url Ed25519 public key',
            fn() => Gnap::resolveHolder(Obj::of([]), 'nope', true));
    }

    // ---- grant request -> capability -----------------------------------------------------------------------------------

    /** A request without access_token.access is refused with its own reason (not as a malformed access array). */
    public function testGrantRequestNeedsAccessTokenAccess(): void
    {
        $h = self::holder();
        $msg = 'grant request must carry access_token.access (single-token request)';
        $opts = ['holder' => $h, 'issuerSecret' => self::seed('g21-issuer')];
        $this->assertThrown(GnapError::class, $msg, fn() => Gnap::grantRequestToCapability(Obj::of([]), $opts));
        $this->assertThrown(GnapError::class, $msg, fn() => Gnap::grantRequestToCapability(Obj::of(['access_token' => 'x']), $opts));
        $this->assertThrown(GnapError::class, $msg, fn() => Gnap::grantRequestToCapability(Obj::of(['access_token' => Obj::of([])]), $opts));
    }

    /** No issuer secret, and a parent that is not a capability, are refused with their GnapError reasons. */
    public function testGrantRequestIssuerRefusals(): void
    {
        $r = self::req(self::holder(), ['photos']);
        $this->assertThrown(GnapError::class, "signWithSuite: 'ed25519' requires edSecret", fn() => Gnap::grantRequestToCapability($r, ['now' => 1]));
        $this->assertThrown(GnapError::class, 'delegate: parent must be a capability',
            fn() => Gnap::grantRequestToCapability($r, ['issuerSecret' => self::seed('g21-issuer'), 'parent' => 'x', 'now' => 1]));
    }

    /** `now` (ms) is floored to an integer timestamp; a non-number counts as 0; absent, it is the wall clock in ms. */
    public function testGrantRequestTimestamp(): void
    {
        $r = self::req(self::holder(), ['photos']);
        $s = self::seed('g21-issuer');
        $this->assertSame(1234, Gnap::grantRequestToCapability($r, ['issuerSecret' => $s, 'now' => 1234.7])['provenance']->get('ts'));
        $this->assertSame(0, Gnap::grantRequestToCapability($r, ['issuerSecret' => $s, 'now' => 'abc'])['provenance']->get('ts'));
        Gnap::$clockHook = static fn(): float => 1700000000.5;
        $this->assertSame(1700000000500, Gnap::grantRequestToCapability($r, ['issuerSecret' => $s])['provenance']->get('ts'));
    }

    // ---- jwsd signing --------------------------------------------------------------------------------------------------

    /** Signing refuses missing key bytes, a non-string method and a short seed, each with its own error. */
    public function testSignGnapRequestRefusals(): void
    {
        $seed = self::seed('g21-jwsd');
        $pub = self::pub($seed);
        $base = ['htm' => 'POST', 'uri' => 'https://as/x', 'created' => 1];
        $this->assertThrown(GnapError::class, 'key.publicKey must be bytes', fn() => Gnap::signGnapRequest($base + ['key' => ['secretKey' => $seed]]));
        $this->assertThrown(\TypeError::class, 'htm must be a string',
            fn() => Gnap::signGnapRequest(['htm' => 5] + $base + ['key' => ['secretKey' => $seed, 'publicKey' => $pub]]));
        $this->assertThrown(GnapError::class, 'key.secretKey must be bytes', fn() => Gnap::signGnapRequest($base + ['key' => ['publicKey' => $pub]]));
        $e = $this->assertThrown(GnapError::class, 'private key of length 32 expected, got 5',
            fn() => Gnap::signGnapRequest($base + ['key' => ['secretKey' => 'short', 'publicKey' => $pub]]));
        $this->assertSame('ERR_CRYPTO_INVALID_JWK', $e->codeName);
    }

    /** The method is upper-cased as Unicode; `created` defaults to the integer wall-clock second (floored). */
    public function testSignGnapRequestHeader(): void
    {
        $seed = self::seed('g21-jwsd');
        Gnap::$clockHook = static fn(): float => 1700000000.5;
        $p = Gnap::signGnapRequest(['htm' => 'pöst', 'uri' => 'https://as/x', 'key' => ['secretKey' => $seed, 'publicKey' => self::pub($seed)]]);
        $this->assertSame('PÖST', $p['header']->get('htm'));
        $this->assertSame(1700000000, $p['header']->get('created'));
    }

    // ---- jwsd verification ---------------------------------------------------------------------------------------------

    private static function sign(int $created): array
    {
        $seed = self::seed('g21-jwsd');
        return Gnap::signGnapRequest(['body' => 'hello', 'key' => ['secretKey' => $seed, 'publicKey' => self::pub($seed)], 'htm' => 'POST',
            'uri' => 'https://as/x', 'created' => $created]);
    }

    private static function vargs(array $p, array $over = []): array
    {
        return array_merge(['detachedJws' => $p['detachedJws'], 'body' => 'hello', 'holder' => $p['holder'], 'htm' => 'POST', 'uri' => 'https://as/x',
            'now' => 1000000, 'replayCheck' => 'unchecked'], $over);
    }

    /** `created` may be at most 60 s ahead of now: exactly +60 passes, +61 is in the future. */
    public function testCreatedFutureSkewBoundary(): void
    {
        $this->assertTrue(Gnap::verifyGnapRequest(self::vargs(self::sign(1060)))['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'created is in the future'], Gnap::verifyGnapRequest(self::vargs(self::sign(1061))));
    }

    /** An infinite or non-number maxAgeSec never admits (stale), rather than passing or crashing. */
    public function testNonFiniteMaxAgeIsStale(): void
    {
        $p = self::sign(1000);
        $stale = ['ok' => false, 'reason' => 'jwsd proof is stale'];
        $this->assertSame($stale, Gnap::verifyGnapRequest(self::vargs($p, ['maxAgeSec' => INF])));
        $this->assertSame($stale, Gnap::verifyGnapRequest(self::vargs($p, ['maxAgeSec' => 'abc'])));
        $this->assertTrue(Gnap::verifyGnapRequest(self::vargs($p, ['maxAgeSec' => 300]))['ok']);
    }

    /** Without `now` the wall clock (ms, floored to seconds) is used. */
    public function testVerifyUsesTheClockByDefault(): void
    {
        Gnap::$clockHook = static fn(): float => 1700000000.5;
        $args = array_diff_key(self::vargs(self::sign(1700000000)), ['now' => 1]);
        $this->assertTrue(Gnap::verifyGnapRequest($args)['ok']);
    }

    /** The replay store gets the proof's expiry: an integer when integral and below 9e15, else the float. */
    public function testReplayStoreExpiryValue(): void
    {
        $seenExp = function (array $p, array $over): mixed {
            $got = [];
            $over['seenProof'] = static function (string $id, mixed $exp) use (&$got): bool {
                $got[] = $exp;
                return false;
            };
            $r = Gnap::verifyGnapRequest(self::vargs($p, $over));
            $this->assertTrue($r['ok']);
            $this->assertCount(1, $got);
            return $got[0];
        };
        $p = self::sign(1000);
        $this->assertSame(1300, $seenExp($p, []));
        $this->assertSame(1300.5, $seenExp($p, ['maxAgeSec' => 300.5]));
        $this->assertSame(9.0e15, $seenExp(self::sign(0), ['now' => 0, 'maxAgeSec' => 9.0e15]));
    }

    /** The method compares as Unicode upper case on both sides (a lower-case non-ASCII header method still matches). */
    public function testHtmComparesUnicodeUpperCase(): void
    {
        $seed = self::seed('g21-jwsd');
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
        $hdr = Obj::of(['alg' => 'EdDSA', 'typ' => 'gnap-binding-jwsd', 'htm' => 'pöst', 'uri' => 'https://as/x', 'created' => 1000]);
        $prot = Pca::b64u(Js::stringify($hdr));
        $payload = Pca::b64u(Gnap::gnapContentDigest('hello'));
        $jws = "$prot.." . Pca::b64u(sodium_crypto_sign_detached("$prot.$payload", $sk));
        $p = ['detachedJws' => $jws, 'holder' => Pca::b64u(self::pub($seed))];
        $this->assertTrue(Gnap::verifyGnapRequest(self::vargs($p, ['htm' => 'pöst']))['ok']);
        $this->assertSame('htm does not match the request method', Gnap::verifyGnapRequest(self::vargs($p, ['htm' => 'GET']))['reason']);
    }

    // ---- step-up shares ------------------------------------------------------------------------------------------------

    /** A share needs t in 1..3 and a 32-byte seed; each refusal keeps its class and message. */
    public function testStepUpShareRefusals(): void
    {
        $body = Obj::of(['a' => 1]);
        $this->assertThrown(\RangeException::class, 'shareMessage: t must be 1, 2 or 3', fn() => Gnap::gnapStepUpShare($body, 'agent', self::seed('g21-a'), [], 4));
        $this->assertThrown(GnapError::class, 'private key of length 32 expected, got 5', fn() => Gnap::gnapStepUpShare($body, 'agent', 'short', [], 1));
        $this->assertInstanceOf(Obj::class, Gnap::gnapStepUpShare($body, 'agent', self::seed('g21-a'), [], 1));
    }

    /** Completing a continuation without the agent leaf seed is refused before any signing. */
    public function testCompleteContinuationNeedsLeafSecret(): void
    {
        $this->assertThrown(GnapError::class, 'agentLeafSecret must be bytes', fn() => Gnap::completeGnapContinuation(['chain' => [Obj::of(['x' => 1])]]));
    }

    // ---- interaction helpers -------------------------------------------------------------------------------------------

    /** An object start entry written as an assoc array still names its mode. */
    public function testStartNamesReadsAssocArrayEntries(): void
    {
        $this->assertSame(['redirect', 'app', null], Gnap::startNames([['mode' => 'redirect'], Obj::of(['mode' => 'app']), 5]));
    }

    /** An unknown hash method is refused as unsupported_hash, naming it. */
    public function testInteractionHashUnsupportedMethod(): void
    {
        $e = $this->assertThrown(InteractionError::class, 'hash_method md5 is not supported', fn() => Gnap::interactionHash(['hashMethod' => 'md5']));
        $this->assertSame('unsupported_hash', $e->errorCode);
    }

    /** A user code defaults to 8 symbols; 6 and 12 are allowed, a fractional length rounds up, a non-number is refused. */
    public function testNewUserCodeLengths(): void
    {
        $this->assertSame(8, strlen(Gnap::newUserCode()));
        $this->assertSame(6, strlen(Gnap::newUserCode(6)));
        $this->assertSame(12, strlen(Gnap::newUserCode(12)));
        $this->assertSame(7, strlen(Gnap::newUserCode(6.2)));
        $this->assertThrown(\RangeException::class, 'user code length 6..12', fn() => Gnap::newUserCode('abc'));
        $this->assertThrown(\RangeException::class, 'user code length 6..12', fn() => Gnap::newUserCode(13));
    }

    /** Each random byte picks symbol (byte mod 32): 0x1f is the last symbol, 0x20 wraps to the first. */
    public function testNewUserCodeSymbolMapping(): void
    {
        $asked = [];
        Gnap::$randomHook = static function (int $n) use (&$asked): string {
            $asked[] = $n;
            return str_repeat("\x1f\x20", intdiv($n, 2));
        };
        $this->assertSame('9A9A9A9A', Gnap::newUserCode());
        $this->assertSame([8], $asked);
    }

    /** A finish callback without a non-empty interact_ref and a string hash is refused up front. */
    public function testAcceptFinishNeedsRefAndHash(): void
    {
        $msg = 'hash and interact_ref are required';
        foreach ([['interact_ref' => '', 'hash' => 'h'], ['interact_ref' => 5, 'hash' => 'h'], ['interact_ref' => 'r']] as $cb) {
            $e = $this->assertThrown(InteractionError::class, $msg, fn() => Gnap::acceptFinish($cb, []));
            $this->assertSame('unknown_interaction', $e->errorCode);
        }
        $this->assertThrown(InteractionError::class, 'the callback hash does not validate', fn() => Gnap::acceptFinish(['interact_ref' => 'r', 'hash' => 'h'], []));
    }

    /** A right without actions or locations is refused, naming its type. */
    public function testAccessToNeedsRefusal(): void
    {
        $e = $this->assertThrown(InteractionError::class, 'access "photos" needs explicit actions and locations to become a need',
            fn() => Gnap::accessToNeeds([Obj::of(['type' => 'photos', 'actions' => ['read']])]));
        $this->assertSame('invalid_request', $e->errorCode);
    }

    /** The redirect finish URL keeps the query (tabs removed, fragment dropped, empty and bare segments handled) and appends hash + ref. */
    public function testFinishUrl(): void
    {
        $this->assertThrown(NodeTypeError::class, 'Invalid URL', fn() => Gnap::finishUrl('not a url', 'H', 'R'));
        $this->assertSame('https://c.example/cb?x=12&hash=H&interact_ref=R', Gnap::finishUrl("https://c.example/cb?x=1\t2", 'H', 'R'));
        $this->assertSame('https://c.example/cb?x=1&hash=H&interact_ref=R', Gnap::finishUrl('https://c.example/cb?x=1#frag', 'H', 'R'));
        $this->assertSame('https://c.example/cb?a=1&b=2&hash=H&interact_ref=R', Gnap::finishUrl('https://c.example/cb?a=1&&b=2', 'H', 'R'));
        $this->assertSame('https://c.example/cb?flag=&hash=H&interact_ref=R', Gnap::finishUrl('https://c.example/cb?flag', 'H', 'R'));
        $this->assertSame('myapp://cb/path?x=1&hash=H&interact_ref=R', Gnap::finishUrl('myapp://cb/path?x=1', 'H', 'R'));
    }

    // ---- the AS state machine ------------------------------------------------------------------------------------------

    /** Ids, nonces and refs have their full entropy; modes are a list; a ref is still live at exactly expiresAt. */
    public function testInteractionServerLifecycle(): void
    {
        $t = 1000;
        $srv = new InteractionServer(['grantEndpoint' => 'https://as/tx', 'supports' => ['redirect', 'app', 'user_code'],
            'redirectUri' => static fn(string $id): string => "https://as/i/$id", 'ttlSec' => 600, 'now' => static function () use (&$t): int {
                return $t;
            }]);
        $req = Obj::of(['start' => ['user_code'], 'finish' => Obj::of(['method' => 'push', 'uri' => 'https://c.example/cb', 'nonce' => 'abcdefgh12'])]);
        $s = $srv->start($req);
        $it = $s['interaction'];
        $this->assertSame(['user_code'], $it->modes);
        $this->assertSame(22, strlen($it->id)); // 16 bytes
        $this->assertSame(32, strlen($s['response']['finish'])); // 24 bytes
        $this->assertSame(8, strlen($s['response']['user_code']));
        $a = $srv->approve($it->id);
        $this->assertSame(24, strlen($a['interactRef'])); // 18 bytes
        $this->assertNull($srv->lookupUserCode($s['response']['user_code']));
        $t = 1600;
        $this->assertSame($it, $srv->consume($a['interactRef']));
        $this->assertNull($srv->lookupUserCode("\xff"));
    }

    /** A ref presented after expiresAt is expired. */
    public function testInteractionServerExpiry(): void
    {
        $t = 1000;
        $srv = new InteractionServer(['grantEndpoint' => 'https://as/tx', 'supports' => ['user_code'], 'ttlSec' => 600, 'now' => static function () use (&$t): int {
            return $t;
        }]);
        $s = $srv->start(Obj::of(['start' => ['user_code']]));
        $a = $srv->approve($s['interaction']->id);
        $t = 1601;
        $e = $this->assertThrown(InteractionError::class, 'the interaction expired', fn() => $srv->consume($a['interactRef']));
        $this->assertSame('expired', $e->errorCode);
    }
}
