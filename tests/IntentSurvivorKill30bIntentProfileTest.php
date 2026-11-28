<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentProfile;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 30b mutation kills for src/IntentProfile.php: the PQ-suite verify path and the revocation pin, driven through the verify / revocation seams. */
final class IntentSurvivorKill30bIntentProfileTest extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        IntentProfile::$verifyHook = null;
        IntentProfile::$revocationHook = null;
        restore_error_handler();
    }

    private static function seedBytes(): string
    {
        return str_repeat("\5", 32);
    }

    private static function ownerKey(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seedBytes())));
    }

    /** The unsigned body (BODY_KEYS only, owner included). */
    private static function profileBodyOf(): Obj
    {
        return Obj::of(['v' => 1, 'kind' => IntentProfile::KIND, 'profile_id' => 'p1', 'version' => 1, 'owner' => self::ownerKey(), 'scope' => new Obj(),
            'standing' => Obj::of(['deny' => [], 'permit' => []]), 'prior' => Obj::of(['observations' => [], 'maps' => []]), 'expires_at' => 100,
            'revocation' => Obj::of(['epoch_uri' => 'https://e.example/r'])]);
    }

    private static function pqProfile(array $pq): Obj
    {
        $p = self::profileBodyOf();
        foreach (['alg' => 'ml-dsa-65', 'sig' => 'S'] + $pq as $k => $v) {
            $p->set($k, $v);
        }
        return $p;
    }

    private static function pinOf(mixed $v): Obj
    {
        return Obj::of(['pqPins' => Obj::of([self::ownerKey() => $v])]);
    }

    /** A PQ profile verifies over the body bound to alg + pq_pk, with its own pq_pk / pq_sig and the pinned PQ key. */
    public function testPqVerifyArguments(): void
    {
        $seen = null;
        IntentProfile::$verifyHook = static function (mixed ...$a) use (&$seen): bool {
            $seen = $a;
            return true;
        };
        $r = IntentProfile::verifyIntentProfile(self::pqProfile(['pq_pk' => 'PK', 'pq_sig' => 'QS']), self::pinOf('PIN'));
        $this->assertSame(['ok' => true], $r);
        $bound = self::profileBodyOf();
        $bound->set('alg', 'ml-dsa-65');
        $bound->set('pq_pk', 'PK');
        $this->assertSame(['ml-dsa-65', self::ownerKey(), 'PK', IntentProfile::SIG_DOMAIN . Json::canonicalizeNative($bound), 'S', 'QS', 'PIN'], $seen);
    }

    /** No pq_sig, a non-string pin, no pqPins object: the verifier gets null for each. */
    public function testPqVerifyNulls(): void
    {
        $seen = [];
        IntentProfile::$verifyHook = static function (mixed ...$a) use (&$seen): bool {
            $seen[] = [$a[5], $a[6]];
            return false;
        };
        $this->assertSame(['ok' => false, 'reason' => 'profile signature invalid'], IntentProfile::verifyIntentProfile(self::pqProfile(['pq_pk' => 'PK']), self::pinOf(5)));
        IntentProfile::verifyIntentProfile(self::pqProfile(['pq_pk' => 'PK']), Obj::of(['pqPins' => 'x']));
        $this->assertSame([[null, null], [null, null]], $seen);
    }

    /** An ed25519 profile reads no pin (its verdict never sees one). */
    public function testEd25519ReadsNoPin(): void
    {
        $seen = null;
        IntentProfile::$verifyHook = static function (mixed ...$a) use (&$seen): bool {
            $seen = $a[6];
            return true;
        };
        $p = IntentProfile::signIntentProfile(self::profileBodyOf(), self::seedBytes());
        $this->assertSame(['ok' => true], IntentProfile::verifyIntentProfile($p, self::pinOf('PIN')));
        $this->assertNull($seen);
    }

    /** A PQ profile without pq_pk is malformed with the reference's reason, and the verifier is never asked. */
    public function testPqWithoutKeyIsMalformed(): void
    {
        IntentProfile::$verifyHook = static fn(mixed ...$a): bool => throw new \LogicException('verifier reached');
        $this->assertSame(['ok' => false, 'reason' => 'malformed profile: canonicalize: unsupported type undefined'],
            IntentProfile::verifyIntentProfile(self::pqProfile([])));
    }

    /** profileUsable hands the revocation check the authority and the pinned PQ key of that authority. */
    public function testRevocationGetsThePin(): void
    {
        $p = IntentProfile::signIntentProfile(self::profileBodyOf(), self::seedBytes());
        $got = [];
        IntentProfile::$revocationHook = static function (mixed $ev, array $args) use (&$got): array {
            $got[] = [$ev, $args['authority'], $args['pqPin']];
            return count($got) === 1 ? ['ok' => true] : ['ok' => false, 'reason' => 'r'];
        };
        $this->assertSame(['ok' => true], IntentProfile::profileUsable($p, ['now' => 0, 'maxAgeMs' => 10, 'revocation' => 'EV', 'pin' => self::pinOf('PIN')]));
        $this->assertSame(['ok' => false, 'reason' => 'profile revocation: r'], IntentProfile::profileUsable($p, ['now' => 0, 'maxAgeMs' => 10, 'pin' => self::pinOf(5)]));
        $this->assertSame([['EV', self::ownerKey(), 'PIN'], [null, self::ownerKey(), null]], $got);
    }
}
