<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/BreakGlass.php';

use Atlas\Pca\BreakGlass;
use Atlas\Pca\BreakGlassRegistry;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Break-glass well-formedness boundaries and registry edges (mutation kills; the vectors cover the happy flows). */
final class K05KillBreakGlassTest extends TestCase
{
    /** @return array{0:string,1:string} [secret key, b64u public key] */
    private static function key(string $byte): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat($byte, 32));
        return [sodium_crypto_sign_secretkey($kp), Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    private static function obj(array $a): Obj
    {
        $o = Json::parseLax((string)json_encode($a));
        self::assertInstanceOf(Obj::class, $o);
        return $o;
    }

    private static function signed(string $domain, array $body, string $sk): Obj
    {
        $o = self::obj($body);
        $o->set('sig', Pca::b64u(sodium_crypto_sign_detached($domain . Json::canonicalizeStrict($o), $sk)));
        return $o;
    }

    private static function grantBody(array $over = []): array
    {
        return array_merge(['v' => 1, 'id' => 'bg1', 'holder' => 'h1', 'grant_ref' => 'g', 'reason_digest' => 'r', 'max_uses' => 2,
            'issued_at' => 1000, 'expires_at' => 100000, 'review_within' => 5000, 'notify_to' => 'n', 'authority' => 'auth'], $over);
    }

    private static function reviewBody(array $over = []): array
    {
        return array_merge(['v' => 1, 'id' => 'bg1', 'outcome' => 'justified', 'notes_digest' => 'nd', 'at' => 2000, 'reviewer' => 'rev'], $over);
    }

    private static function wf(array $over): bool
    {
        return BreakGlass::wellFormed(self::obj(self::grantBody($over)));
    }

    private static function rwf(array $over): bool
    {
        return BreakGlass::reviewWellFormed(self::obj(self::reviewBody($over)));
    }

    public function testNIsAFloatEvenForAMissingMember(): void
    {
        self::assertSame(0.0, BreakGlass::n(new Obj(), 'x'));
        self::assertSame(5.0, BreakGlass::n(self::obj(['x' => 5]), 'x'));
    }

    public function testGrantWellFormedBoundaries(): void
    {
        self::assertTrue(self::wf([]));
        self::assertFalse(BreakGlass::wellFormed('x'));
        self::assertFalse(self::wf(['v' => 2]));
        foreach (['id' => 128, 'holder' => 128, 'grant_ref' => 256, 'reason_digest' => 128, 'notify_to' => 256, 'authority' => 128] as $k => $max) {
            self::assertTrue(self::wf([$k => str_repeat('a', $max)]), "$k at $max");
            self::assertFalse(self::wf([$k => str_repeat('a', $max + 1)]), "$k over $max");
        }
        self::assertFalse(self::wf(['id' => 5]));
        self::assertFalse(self::wf(['max_uses' => 1.5]));
        self::assertTrue(self::wf(['max_uses' => 1]));
        self::assertTrue(self::wf(['max_uses' => 16]));
        self::assertFalse(self::wf(['max_uses' => 17]));
        self::assertFalse(self::wf(['max_uses' => 0]));
        self::assertFalse(self::wf(['expires_at' => 1000]));
        self::assertFalse(self::wf(['expires_at' => 500]));
        self::assertTrue(self::wf(['expires_at' => 1000 + BreakGlass::MAX_WINDOW_MS]));
        self::assertFalse(self::wf(['expires_at' => 1001 + BreakGlass::MAX_WINDOW_MS]));
        self::assertFalse(self::wf(['review_within' => 0]));
        self::assertTrue(self::wf(['review_within' => 1]));
        self::assertTrue(self::wf(['review_within' => BreakGlass::MAX_REVIEW_WITHIN_MS]));
        self::assertFalse(self::wf(['review_within' => BreakGlass::MAX_REVIEW_WITHIN_MS + 1]));
    }

    public function testReviewWellFormedBoundaries(): void
    {
        self::assertTrue(self::rwf([]));
        self::assertTrue(self::rwf(['outcome' => 'unjustified']));
        self::assertFalse(BreakGlass::reviewWellFormed('x'));
        self::assertFalse(self::rwf(['v' => 2]));
        self::assertFalse(self::rwf(['outcome' => 'maybe']));
        self::assertFalse(self::rwf(['at' => 1.5]));
        self::assertFalse(self::rwf(['at' => -1]));
        foreach (['id', 'notes_digest', 'reviewer'] as $k) {
            self::assertTrue(self::rwf([$k => str_repeat('a', 128)]), "$k at 128");
            self::assertFalse(self::rwf([$k => str_repeat('a', 129)]), "$k over 128");
            self::assertFalse(self::rwf([$k => 5]), "$k not a string");
        }
    }

    public function testRegistryEdges(): void
    {
        [$ask, $apk] = self::key("\x01");
        [$rsk, $rpk] = self::key("\x02");
        $grant = self::signed(BreakGlass::DOMAIN, self::grantBody(['authority' => $apk]), $ask);
        $review = self::signed(BreakGlass::REVIEW_DOMAIN, self::reviewBody(['reviewer' => $rpk]), $rsk);
        self::assertTrue(BreakGlass::verify($grant));
        self::assertTrue(BreakGlass::verifyReview($review));

        $reg = new BreakGlassRegistry(['authorities' => [$apk], 'reviewers' => [$rpk]]);
        self::assertSame(['ok' => true, 'replaced' => true], $reg->accept($grant, 1000));
        self::assertSame(['decision' => 'allow', 'id' => 'bg1', 'use' => 1, 'remaining' => 1, 'review_due' => 7000], $reg->use('bg1', 'h1', 'd1', 2000, true));
        // a review timed exactly at the first use is in time
        self::assertSame(['ok' => true, 'replaced' => true], $reg->review($review, 'h1', 2000));

        $a128 = str_repeat('a', 128);
        $a129 = str_repeat('a', 129);
        self::assertSame(['decision' => 'deny', 'code' => 'unknown_break_glass', 'id' => $a128], $reg->use($a128, 'h1', 'd', 2000, true));
        self::assertSame(['decision' => 'deny', 'code' => 'unknown_break_glass', 'id' => 'bg1'], $reg->use('bg1', $a128, 'd', 2000, true));
        // the review was justified, so a second use (a 128-unit action digest) is still allowed
        self::assertSame(['decision' => 'allow', 'id' => 'bg1', 'use' => 2, 'remaining' => 0, 'review_due' => 7000], $reg->use('bg1', 'h1', $a128, 2100, true));
        $bad = ['decision' => 'deny', 'code' => 'bad_input'];
        self::assertSame($bad, $reg->use($a129, 'h1', 'd', 2000, true));
        self::assertSame($bad, $reg->use('bg1', $a129, 'd', 2000, true));
        self::assertSame($bad, $reg->use('bg1', 'h1', $a129, 2000, true));

        self::assertSame(['ok' => false, 'code' => 'unknown_break_glass'], $reg->review($review, $a128, 2000));
        self::assertSame(['ok' => false, 'code' => 'bad_record'], $reg->review($review, $a129, 2000));

        self::assertFalse($reg->frozen($a128, 2000));
        self::assertTrue($reg->frozen($a129, 2000));
        self::assertTrue($reg->frozen('', 2000));
        self::assertTrue($reg->frozen('h1', -1));
    }

    public function testAThrowingPolicyFailsClosed(): void
    {
        [$ask, $apk] = self::key("\x01");
        [$rsk, $rpk] = self::key("\x02");
        $grant = self::signed(BreakGlass::DOMAIN, self::grantBody(['authority' => $apk]), $ask);
        $review = self::signed(BreakGlass::REVIEW_DOMAIN, self::reviewBody(['reviewer' => $rpk]), $rsk);
        // a policy whose lists are not arrays makes in_array throw: the registry answers store_unreachable, never ok
        $reg = new BreakGlassRegistry(['authorities' => 'x', 'reviewers' => 'x']);
        self::assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept($grant, 1000));
        self::assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->review($review, 'h1', 2000));
    }

    /** frozenIn skips (continue, not break) an entry of another holder and still finds the frozen one after it. */
    public function testFrozenInSkipsAnotherHoldersEntry(): void
    {
        $m = new \ReflectionMethod(BreakGlassRegistry::class, 'frozenIn');
        $other = ['rec' => self::obj(['holder' => 'h2']), 'uses' => [], 'review' => null];
        $mine = ['rec' => self::obj(['holder' => 'h1']), 'uses' => [], 'review' => self::obj(['outcome' => 'unjustified'])];
        self::assertTrue($m->invoke(null, ['ka' => $other, 'kb' => $mine], 'h1', 0.0));
        self::assertFalse($m->invoke(null, ['ka' => $other], 'h1', 0.0));
    }

    /** A corrupted stored entry makes use() and frozen() fail closed through their catch. */
    public function testACorruptedEntryFailsClosed(): void
    {
        $reg = new BreakGlassRegistry(['authorities' => [], 'reviewers' => []]);
        (new \ReflectionProperty(BreakGlassRegistry::class, 'holders'))
            ->setValue($reg, ['kh1' => ['kbg1' => ['rec' => 'not-an-obj', 'uses' => [], 'review' => null]]]);
        self::assertSame(['decision' => 'deny', 'code' => 'store_unreachable', 'id' => 'bg1'], $reg->use('bg1', 'h1', 'd', 2000, true));
        self::assertTrue($reg->frozen('h1', 2000));
    }
}
