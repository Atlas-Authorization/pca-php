<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentOmega;
use Atlas\Pca\IntentProfile;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentProfile.php: shape bounds, signing suites, succession, scope, veto cells and the ceiling. */
final class IntentSurvivorKill30IntentProfileTest extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function seed(): string
    {
        return str_repeat("\5", 32);
    }

    private static function owner(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed())));
    }

    /** An unsigned, well-formed body; $set replaces members. */
    private static function body(array $set = [], bool $withOwner = true): Obj
    {
        $b = Obj::of(['v' => 1, 'kind' => IntentProfile::KIND, 'profile_id' => 'p1', 'version' => 1]);
        if ($withOwner) {
            $b->set('owner', self::owner());
        }
        foreach (array_merge(['scope' => new Obj(), 'standing' => Obj::of(['deny' => [], 'permit' => []]), 'prior' => Obj::of(['observations' => [], 'maps' => []]),
            'expires_at' => 100, 'revocation' => Obj::of(['epoch_uri' => 'https://e.example/r'])], $set) as $k => $v) {
            $b->set($k, $v);
        }
        return $b;
    }

    private static function shape(Obj $p): ?string
    {
        return IntentProfile::intentProfileShapeError($p, false);
    }

    private static function obs(string $verb, Obj $values, int $y = 0): Obj
    {
        return Obj::of(['verb' => $verb, 'values' => $values, 'y' => $y, 'at' => 0]);
    }

    private static function cat(): Obj
    {
        return Obj::of(['kind' => 'cat', 'path' => 'action.params.s', 'values' => [
            Obj::of(['kind' => 'exact', 'value' => 'a']), Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER])]]);
    }

    /** A profile object for the scope / standing functions (they do not re-check the shape). */
    private static function live(array $deny = [], ?Obj $scope = null, array $obs = []): Obj
    {
        return Obj::of(['expires_at' => 100, 'scope' => $scope ?? new Obj(), 'standing' => Obj::of(['deny' => $deny, 'permit' => []]),
            'prior' => Obj::of(['observations' => $obs, 'maps' => []])]);
    }

    /** scope lists hold at most 256 strings. */
    public function testScopeListBound(): void
    {
        $this->assertNull(self::shape(self::body(['scope' => Obj::of(['sites' => array_fill(0, 256, 'a')])])));
        $this->assertSame('scope.sites must be a list of strings', self::shape(self::body(['scope' => Obj::of(['sites' => array_fill(0, 257, 'a')])])));
    }

    /** At most MAX_RULES standing rules, and a verb list of strings is a valid rule verb. */
    public function testRuleBoundAndVerbList(): void
    {
        $this->assertSame(256, IntentProfile::MAX_RULES);
        $rules = array_fill(0, IntentProfile::MAX_RULES, Obj::of(['verb' => 'a']));
        $this->assertNull(self::shape(self::body(['standing' => Obj::of(['deny' => $rules, 'permit' => []])])));
        $this->assertNull(self::shape(self::body(['standing' => Obj::of(['deny' => [Obj::of(['verb' => ['a', 'b']])], 'permit' => []])])));
        $this->assertSame('standing.deny must be at most 256 predicates', self::shape(self::body(['standing' => Obj::of(['deny' => [Obj::of(['verb' => ['a', 5]])], 'permit' => []])])));
    }

    /** At most MAX_OBSERVATIONS observations. */
    public function testObservationBound(): void
    {
        $this->assertSame(2000, IntentProfile::MAX_OBSERVATIONS);
        $obs = array_fill(0, IntentProfile::MAX_OBSERVATIONS, self::obs('a', new Obj()));
        $this->assertNull(self::shape(self::body(['prior' => Obj::of(['observations' => $obs, 'maps' => []])])));
    }

    /** A present revocation key and a present prev must be 32-byte digests. */
    public function testKeyAndPrevShapes(): void
    {
        $this->assertSame('revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)',
            self::shape(self::body(['revocation' => Obj::of(['epoch_uri' => 'https://e.example/r', 'key' => 'bad'])])));
        $this->assertSame('prev must be canonical base64url (32 bytes)', self::shape(self::body(['version' => 2, 'prev' => 'bad'])));
    }

    /** A PQ-suite profile may carry pq_pk / pq_sig (only an ed25519 one may not). */
    public function testPqSuiteMayCarryPqFields(): void
    {
        $p = self::body(['alg' => 'ml-dsa-65', 'pq_pk' => 'x', 'pq_sig' => 'y', 'sig' => 'z']);
        $this->assertNull(IntentProfile::intentProfileShapeError($p));
        $e = self::body(['alg' => 'ed25519', 'pq_pk' => 'x', 'sig' => 'z']);
        $this->assertSame('an ed25519 profile must not carry pq_pk / pq_sig', IntentProfile::intentProfileShapeError($e));
    }

    /** A body that cannot be canonicalised is malformed, with the canonicaliser's reason. */
    public function testUncanonicalBody(): void
    {
        $p = self::body(['prior' => Obj::of(['observations' => [self::obs('a', Obj::of(['x' => INF]))], 'maps' => []])]);
        try {
            Json::canonicalizeNative($p);
            $this->fail('control: INF canonicalises');
        } catch (\Throwable $e) {
            $this->assertSame('malformed profile: ' . $e->getMessage(), self::shape($p));
        }
    }

    /** Signing: no suite, a suite without alg and an ed25519 suite all sign; any other alg is refused. */
    public function testSigningSuites(): void
    {
        foreach ([null, new Obj(), Obj::of(['alg' => 'ed25519'])] as $suite) {
            $this->assertSame(['ok' => true], IntentProfile::verifyIntentProfile(IntentProfile::signIntentProfile(self::body([], false), self::seed(), $suite)));
        }
        try {
            IntentProfile::signIntentProfile(self::body([], false), self::seed(), Obj::of(['alg' => 'ml-dsa-65']));
            $this->fail('no refusal');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('signIntentProfile: only Ed25519 signing is supported natively', $e->getMessage());
        }
    }

    /** A PQ-suite profile without pq_pk is malformed (its signed message has no canonical form), whether the suite is available or not. */
    public function testPqSuiteWithoutKey(): void
    {
        $p = self::body(['alg' => 'ml-dsa-65', 'sig' => 'z']);
        $this->assertSame(['ok' => false, 'reason' => 'malformed profile: canonicalize: unsupported type undefined'], IntentProfile::verifyIntentProfile($p));
        $this->assertSame(['ok' => false, 'reason' => 'profile signature invalid'],
            IntentProfile::verifyIntentProfile(self::body(['alg' => 'ml-dsa-65', 'pq_pk' => 'x', 'sig' => 'z'])));
    }

    /** Succession: the next version's prev must be the previous digest. */
    public function testSuccessionPrev(): void
    {
        $v1 = IntentProfile::signIntentProfile(self::body([], false), self::seed());
        $good = IntentProfile::signIntentProfile(self::body(['version' => 2, 'prev' => IntentProfile::intentProfileDigest($v1)], false), self::seed());
        $this->assertSame(['ok' => true], IntentProfile::verifyProfileSuccession($v1, $good));
        $bad = IntentProfile::signIntentProfile(self::body(['version' => 2, 'prev' => Pca::b64u(str_repeat("\x09", 32))], false), self::seed());
        $this->assertSame(['ok' => false, 'reason' => 'next.prev is not the digest of the previous version'], IntentProfile::verifyProfileSuccession($v1, $bad));
    }

    /** now must be a finite number below expires_at; a non-number never applies. */
    public function testNowMustBeANumber(): void
    {
        $this->assertFalse(IntentProfile::profileApplies(self::live(), Obj::of(['now' => 'x'])));
        $this->assertTrue(IntentProfile::profileApplies(self::live(), Obj::of(['now' => 0])), 'control');
    }

    /** semantics null is no semantics (never a warning); a site that is the very same object matches, as JS includes does. */
    public function testScopeMembership(): void
    {
        $this->assertFalse(IntentProfile::profileApplies(self::live([], Obj::of(['semantic_types' => ['t']])), Obj::of(['now' => 0, 'semantics' => null])));
        $x = Obj::of(['site' => 'a']);
        $this->assertTrue(IntentProfile::profileApplies(self::live([], Obj::of(['sites' => [$x]])), Obj::of(['now' => 0, 'aud' => $x])));
        $this->assertFalse(IntentProfile::profileApplies(self::live([], Obj::of(['sites' => [$x]])), Obj::of(['now' => 0, 'aud' => Obj::of(['site' => 'a'])])));
    }

    /** Veto cells: the first verb space with the verb is used. */
    public function testVetoUsesFirstVerbSpace(): void
    {
        $omega = Obj::of(['verbs' => [Obj::of(['verb' => 'x.do', 'dims' => []]), Obj::of(['verb' => 'x.do', 'dims' => [self::cat()]])]]);
        $this->assertSame([['verb' => 'x.do', 'cell' => []]], IntentProfile::profileVetoCells(self::live([], null, [self::obs('x.do', new Obj())]), $omega));
    }

    /** Veto cells are keyed by verb and cell together: x.do cell [1], x.do1 cell [] and y.do cell [1] are three cells. */
    public function testVetoKeys(): void
    {
        $omega = Obj::of(['verbs' => [Obj::of(['verb' => 'x.do', 'dims' => [self::cat()]]), Obj::of(['verb' => 'x.do1', 'dims' => []]),
            Obj::of(['verb' => 'y.do', 'dims' => [self::cat()]])]]);
        $zz = Obj::of(['action.params.s' => 'zz']);
        $p = self::live([], null, [self::obs('x.do', $zz), self::obs('x.do1', new Obj()), self::obs('y.do', $zz), self::obs('x.do', $zz)]);
        $this->assertSame([['verb' => 'x.do', 'cell' => [1]], ['verb' => 'x.do1', 'cell' => []], ['verb' => 'y.do', 'cell' => [1]]],
            IntentProfile::profileVetoCells($p, $omega));
    }

    /** The ceiling passes env from the outcome to the deny rules. */
    public function testCeilingEnv(): void
    {
        $deny = [Obj::of(['verb' => 'x.do', 'where' => [Obj::of(['field' => 'env.x', 'op' => 'eq', 'value' => 'a'])]])];
        $f = IntentProfile::profileCeiling(self::live($deny), Obj::of(['now' => 0]));
        $vs = Obj::of(['verb' => 'x.do', 'dims' => []]);
        $this->assertFalse($f($vs, Obj::of(['verb' => 'x.do', 'values' => Obj::of(['env.x' => 'a'])])));
        $this->assertTrue($f($vs, Obj::of(['verb' => 'x.do', 'values' => Obj::of(['env.x' => 'b'])])), 'control');
    }

    /** The ceiling reads an array use by its keys (an integer key included). */
    public function testCeilingArrayUse(): void
    {
        $f = IntentProfile::profileCeiling(self::live([Obj::of(['verb' => 'x.do'])]), ['now' => 0, 5 => 'x']);
        $this->assertFalse($f(Obj::of(['verb' => 'x.do', 'dims' => []]), Obj::of(['verb' => 'x.do', 'values' => new Obj()])));
    }
}
