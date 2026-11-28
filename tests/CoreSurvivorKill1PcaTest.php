<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\Agent;
use Atlas\Pca\FalconBackend;
use Atlas\Pca\Fndsa;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/Pca.php: the cheap pre-auth gates, the FN-DSA length gates, the core pq_pin and hook tri-states. */
final class CoreSurvivorKill1PcaTest extends TestCase
{
    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
    }

    /** @return array{0:Obj,1:Obj,2:KeyPair,3:KeyPair} root, child, root key, mid key */
    private static function chain(): array
    {
        $root = new KeyPair(str_repeat("\1", 32));
        $mid = new KeyPair(str_repeat("\2", 32));
        $g = Sign::mintRoot($root, $mid->public, []);
        $c = Sign::delegate($g, $mid, (new KeyPair(str_repeat("\3", 32)))->public, []);
        return [$g, $c, $root, $mid];
    }

    private static function refuse(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    /** Every cheap-chain refusal is a whole `ok:false` verdict with its exact reason (never `ok:true`, never a missing `ok`). */
    public function testCheapChainRefusalsAreWholeVerdicts(): void
    {
        [$g, $c, $root, $mid] = self::chain();
        self::assertSame(['ok' => true, 'pqHops' => 0], Pca::verifyChainCheap([$g, $c], $root->public)); // control
        self::assertSame(self::refuse('empty chain'), Pca::verifyChainCheap([]));
        self::assertSame(self::refuse('chain too long (max 16 hops)'), Pca::verifyChainCheap(array_fill(0, 17, $g)));
        // exactly MAX_CHAIN hops is not "too long": the walk runs and stops at the first broken link
        self::assertSame(self::refuse('hop 1: broken parent link'), Pca::verifyChainCheap(array_fill(0, 16, $g)));
        $many = Obj::of(['caveats' => array_fill(0, Pca::MAX_CAVEATS_PER_HOP + 1, Obj::of(['type' => 'x']))]);
        self::assertSame(self::refuse(Pca::CAVEAT_LIMIT_REASON), Pca::verifyChainCheap([$many]));
        self::assertSame(self::refuse('hop 0: malformed capability'), Pca::verifyChainCheap([5]));
        $nope = $g->without();
        $nope->set('alg', 'nope');
        self::assertSame(self::refuse("hop 0: unknown signature alg 'nope'"), Pca::verifyChainCheap([$nope]));
        self::assertSame(self::refuse("hop 0: signature suite 'ed25519' is not allowed by this verifier's suite policy"),
            Pca::verifyChainCheap([$g], null, ['ml-dsa-65']));
        $parented = $g->without();
        $parented->set('parent', 'x');
        self::assertSame(self::refuse('hop 0: root must not have a parent'), Pca::verifyChainCheap([$parented]));
        self::assertSame(self::refuse('hop 0: root issuer is not the expected principal'), Pca::verifyChainCheap([$g, $c], $mid->public));
        self::assertSame(self::refuse('hop 1: broken parent link'), Pca::verifyChainCheap([$g, $g]));
        $wrongIssuer = $c->without();
        $wrongIssuer->set('issuer', $root->public);
        self::assertSame(self::refuse("hop 1: issuer is not the parent's bound holder"), Pca::verifyChainCheap([$g, $wrongIssuer]));
        $badNum = $g->without();
        $badNum->set('caveats', [Obj::of(['type' => 'note', 'v' => new Num('-0')])]);
        self::assertSame(self::refuse('hop 0: malformed body'), Pca::verifyChainCheap([$badNum]));
        $badSig = $g->without('sig');
        $badSig->set('sig', Pca::b64u(str_repeat("\0", 64)));
        self::assertSame(self::refuse('hop 0: bad signature (not signed by expected key)'), Pca::verifyChainCheap([$badSig]));
    }

    /** An explicit suite is judged by the allowlist as itself: a named `ml-dsa-65` hop is not waved through as ed25519. */
    public function testExplicitSuiteIsPolicyCheckedAsNamed(): void
    {
        [$g] = self::chain();
        $named = $g->without();
        $named->set('alg', 'ml-dsa-65');
        self::assertSame(self::refuse("hop 0: signature suite 'ml-dsa-65' is not allowed by this verifier's suite policy"),
            Pca::verifyChainCheap([$named], null, ['ed25519']));
    }

    /** A hop whose `id` is not its body digest is refused even when its body_digest is right and the signature verifies. */
    public function testIdMustEqualTheBodyDigest(): void
    {
        [$g] = self::chain();
        $x = $g->without();
        $x->set('id', 'x');
        self::assertSame(self::refuse('hop 0: body digest mismatch'), Pca::verifyChainCheap([$x]));
    }

    /** A throw while hashing a parent becomes the `malformed capability chain:` verdict carrying the error text. */
    public function testThrowInsideTheWalkIsAMalformedChainVerdict(): void
    {
        [$g, $c] = self::chain();
        $junk = $g->without();
        $junk->set('junk', new Num('-0')); // outside the signed body, so hop 0 verifies; hashing it as hop 1's parent throws
        self::assertSame(self::refuse('malformed capability chain: negative zero is not allowed'), Pca::verifyChainCheap([$junk, $c]));
    }

    /** A registered suite this host cannot verify (FN-DSA, no backend) is refused with its unsupported_suite reason. */
    public function testUnavailableRegisteredSuiteIsUnsupported(): void
    {
        Fndsa::resetFalconBackend();
        [$g] = self::chain();
        $x = $g->without();
        $x->set('alg', 'fn-dsa-512');
        self::assertSame(self::refuse('hop 0: unsupported_suite: fn-dsa-512'), Pca::verifyChainCheap([$x]));
    }

    private static function acceptAllFalcon(): void
    {
        Fndsa::setFalconBackend(new FalconBackend(static fn(string $pk, string $msg, string $sig): bool => true));
    }

    /** A pure FN-DSA hop passes the cheap check on structure alone (no Ed25519 half), and its body has no pq_pk when it carries none. */
    public function testPurePqHopPassesOnStructureAndCountsAsPq(): void
    {
        self::acceptAllFalcon();
        $issuer = (new KeyPair(str_repeat("\4", 32)))->public;
        $holder = (new KeyPair(str_repeat("\5", 32)))->public;
        $body = Obj::of(['issuer' => $issuer, 'holder' => $holder, 'caveats' => [], 'parent' => null, 'alg' => 'fn-dsa-512']);
        $d = Pca::hashCanonical($body);
        $hop = Obj::of(['id' => $d, 'issuer' => $issuer, 'holder' => $holder, 'caveats' => [], 'alg' => 'fn-dsa-512',
            'body_digest' => $d, 'sig' => Pca::b64u(str_repeat("\7", 666))]);
        self::assertSame(['ok' => true, 'pqHops' => 1], Pca::verifyChainCheap([$hop], $issuer));
    }

    /** A hybrid hop's Ed25519 half is checked by the cheap gate: a zeroed Ed25519 sig is refused. */
    public function testHybridEdHalfIsChecked(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $root = new KeyPair(str_repeat("\1", 32));
        $pq = new PqKeyPair('ML-DSA-65', str_repeat("\3", 32));
        $g = Sign::mintRoot($root, (new KeyPair(str_repeat("\2", 32)))->public, [], null, 'hybrid-ed25519-ml-dsa-65', $pq);
        self::assertSame(['ok' => true, 'pqHops' => 1], Pca::verifyChainCheap([$g], $root->public)); // control
        $bad = $g->without('sig');
        $bad->set('sig', Pca::b64u(str_repeat("\0", 64)));
        self::assertSame(self::refuse('hop 0: bad signature (not signed by expected key)'), Pca::verifyChainCheap([$bad], $root->public));
    }

    /** FN-DSA verifies only at its exact public-key and signature lengths, and through the variant's own name. */
    public function testFnDsaLengthGates(): void
    {
        self::acceptAllFalcon();
        foreach ([['fn-dsa-512', 897, 666], ['fn-dsa-1024', 1793, 1280]] as [$alg, $pk, $sig]) {
            $k = Pca::b64u(str_repeat("\1", $pk));
            $s = Pca::b64u(str_repeat("\2", $sig));
            self::assertTrue(Pca::verifySuiteUnderKey($alg, null, $k, 'm', $s, null), $alg);
            self::assertFalse(Pca::verifySuiteUnderKey($alg, null, Pca::b64u(str_repeat("\1", $pk - 1)), 'm', $s, null), $alg);
            self::assertFalse(Pca::verifySuiteUnderKey($alg, null, $k, 'm', Pca::b64u(str_repeat("\2", $sig - 1)), null), $alg);
        }
    }

    /** verifySuiteUnderKey is for PQ suites only: a valid Ed25519 signature under alg ed25519 is still false. */
    public function testSuiteUnderKeyRefusesEd25519(): void
    {
        $kp = new KeyPair(str_repeat("\6", 32));
        $sig = Pca::b64u($kp->sign('m'));
        self::assertFalse(Pca::verifySuiteUnderKey('ed25519', $kp->public, 'x', 'm', $sig, null));
        self::assertFalse(Pca::verifySuiteUnderKey(5, $kp->public, 'x', 'm', $sig, null));
    }

    /** verifyWithSuite takes a PQ key only as a PinnedPq: a raw string key is refused even for a valid ed25519 signature. */
    public function testVerifyWithSuiteRefusesARawPqKey(): void
    {
        $kp = new KeyPair(str_repeat("\6", 32));
        $sig = Pca::b64u($kp->sign('m'));
        self::assertTrue(Pca::verifyWithSuite('ed25519', ['edPub' => $kp->public], 'm', ['sig' => $sig])); // control
        self::assertFalse(Pca::verifyWithSuite('ed25519', ['edPub' => $kp->public, 'pq' => 'raw'], 'm', ['sig' => $sig]));
    }

    /** pcactnCheapClaims refusals are whole `{check, reason}` verdicts, and each boundary holds at exactly its limit. */
    public function testCheapClaimsVerdictsAndBoundaries(): void
    {
        $o = static fn(string $aud, string $iat, string $exp): Obj => Obj::of(['aud' => $aud, 'iat' => new Num($iat), 'exp' => new Num($exp)]);
        $v = static fn(string $r): array => ['check' => 'validity', 'reason' => $r];
        self::assertSame(['check' => 'audience', 'reason' => 'aud does not match this resource server / instance'], Pca::pcactnCheapClaims($o('', '1', '2'), '', 1));
        self::assertSame($v('iat and exp must be safe-integer epoch ms'), Pca::pcactnCheapClaims(Obj::of(['aud' => 'rs', 'iat' => 'x', 'exp' => new Num('5')]), 'rs', 5));
        self::assertSame($v('the verifier clock is not a safe integer epoch-ms'), Pca::pcactnCheapClaims($o('rs', '1000', '2000'), 'rs', PHP_INT_MAX));
        self::assertSame($v('exp must be greater than iat'), Pca::pcactnCheapClaims($o('rs', '5', '5'), 'rs', 5));
        self::assertSame($v('lifetime exceeds 3600000 ms'), Pca::pcactnCheapClaims($o('rs', '0', '3600001'), 'rs', 5));
        self::assertSame($v('iat is in the future (clock skew)'), Pca::pcactnCheapClaims($o('rs', '1000', '2000'), 'rs', 1000 - 60001));
        self::assertSame($v('the PCActn has expired'), Pca::pcactnCheapClaims($o('rs', '1000', '2000'), 'rs', 2001));
        // at exactly the limit each check still passes
        self::assertNull(Pca::pcactnCheapClaims($o('rs', '9007199254739991', '9007199254740991'), 'rs', 9007199254740991));
        self::assertNull(Pca::pcactnCheapClaims($o('rs', '1000', '3601000'), 'rs', 2000));
        self::assertNull(Pca::pcactnCheapClaims($o('rs', '1000', '2000'), 'rs', 2000));
    }

    /** The wire validator spells a refused canonical number with the reference's text. */
    public function testWireSpellsRefusedNumbersLikeTheReference(): void
    {
        foreach (['-0' => 'canonicalize: negative zero',
                     '9007199254740992' => 'canonicalize: integer outside the safe range (|n| > 2^53-1)',
                     '1.2345678901234567' => 'canonicalize: non-integer number has more than 15 significant digits'] as $lex => $want) {
            $p = Obj::of(array_fill_keys(Pca::PCACTN_REQUIRED_FIELDS, 'x'));
            $p->set('ver', new Num((string) $lex));
            self::assertSame($want, Pca::validateWire($p), (string) $lex);
        }
    }

    /** The decode size cap is inclusive: a text of exactly MAX_ARTIFACT_BYTES is parsed. */
    public function testDecodeAcceptsExactlyTheCap(): void
    {
        $text = '{"a":"' . str_repeat('x', Pca::MAX_ARTIFACT_BYTES - 8) . '"}';
        self::assertSame(Pca::MAX_ARTIFACT_BYTES, strlen($text));
        self::assertSame(Pca::MAX_ARTIFACT_BYTES - 8, strlen(Pca::decodePcactn($text)->get('a')));
    }

    /** encodePcactn is public API: the lenient canonical text with sorted keys. */
    public function testEncodePcactnIsPublic(): void
    {
        self::assertSame('{"a":"x","b":"y"}', Pca::encodePcactn(Obj::of(['b' => 'y', 'a' => 'x'])));
    }

    /** @return array{0:Obj,1:Obj} */
    private static function signed(): array
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'];
        return [(new Agent($key, $grant, 'rs-test'))->act('refund', 'orders/7')->pcactn, $grant];
    }

    private static function core(Obj $p, mixed $g, mixed $pins = null, ?\Closure $th = null, ?array $hooks = null): array
    {
        return Pca::verifyPcactnCore($p, $g, $p->get('iat')->int(), 'rs-test', insecureSkipPlanRootCheck: true, thresholdHook: $th, hooks: $hooks, pqPins: $pins);
    }

    private const PIN_REASON = 'pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused';

    /** A pin for the grant issuer refuses a classical grant, from an Obj or a PHP array; a pin for someone else does not. */
    public function testPqPinRefusesAClassicalGrant(): void
    {
        [$p, $g] = self::signed();
        $iss = $g->get('issuer');
        self::assertTrue(self::core($p, $g)['allow']); // control
        foreach ([Obj::of([$iss => 'pk']), [$iss => 'pk']] as $pins) {
            $r = self::core($p, $g, $pins);
            self::assertFalse($r['allow']);
            self::assertFalse($r['checks']['pq_pin']);
            self::assertSame(self::PIN_REASON, $r['reason']);
        }
        $r = self::core($p, $g, ['someone-else' => 'pk']);
        self::assertTrue($r['allow']);
        self::assertArrayNotHasKey('pq_pin', $r['checks']);
    }

    /** A pinned grant that names a PQ suite is not refused by the pin rule; a grant that is not an object never throws there. */
    public function testPqPinSparesAPqGrantAndNonObjectGrants(): void
    {
        [$p, $g] = self::signed();
        $pq = $g->without();
        $pq->set('alg', 'ml-dsa-65');
        $pins = Obj::of([$g->get('issuer') => 'pk']);
        $r = self::core($p, $pq, $pins);
        self::assertArrayNotHasKey('pq_pin', $r['checks']);
        self::assertSame('chain: chain root is not the grant', $r['reason']);
        $r = self::core($p, 'not-a-grant', $pins);
        self::assertFalse($r['checks']['chain']);
        self::assertArrayNotHasKey('pq_pin', $r['checks']);
        self::assertSame('chain: chain root is not the grant', $r['reason']);
    }

    /** A threshold hook result without `enforced` is not enforced; an enforced result without `ok` is a refusal. */
    public function testThresholdHookMissingFieldsFailClosed(): void
    {
        [$p, $g] = self::signed();
        $r = self::core($p, $g, null, static fn($x): array => []);
        self::assertTrue($r['allow']);
        self::assertArrayNotHasKey('threshold', $r['checks']);
        self::assertSame(['threshold'], $r['not_enforced']);
        $r = self::core($p, $g, null, static fn($x): array => ['enforced' => true]);
        self::assertFalse($r['allow']);
        self::assertFalse($r['checks']['threshold']);
        self::assertSame('threshold: rejected', $r['reason']);
    }

    /** An enforced attestation hook result without `ok` is a refusal. */
    public function testAttestationHookWithoutOkRefuses(): void
    {
        [$p, $g] = self::signed();
        $r = self::core($p, $g, null, null, ['attestation' => static fn(array $x): array => ['enforced' => true]]);
        self::assertFalse($r['allow']);
        self::assertFalse($r['checks']['attestation']);
        self::assertSame('attestation: rejected', $r['reason']);
    }
}
