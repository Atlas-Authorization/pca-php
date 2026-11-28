<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Jose;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\TxnTokenError;
use Atlas\Pca\TxnTokens;
use PHPUnit\Framework\TestCase;

/** Mutation kills for TxnTokens: mint-time refusals, the uuid4 layout, exact exp arithmetic, and the verifier's claim refusals. */
final class SigSurvivorKill29TxnTokensTest extends TestCase
{
    private const LEGACY = ['profile' => 'legacy', 'replayCheck' => 'unchecked', 'nowMs' => 1_000_000];

    protected function tearDown(): void
    {
        TxnTokens::$clockHook = null;
        TxnTokens::$randomHook = null;
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/g29-txn', true);
    }

    private static function pk(): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed()));
    }

    private static function mintArgs(array $extra = []): array
    {
        return $extra + ['issuer' => 'https://as.example', 'action' => ['verb' => 'read', 'resource' => 'r', 'aud' => 'a'],
            'chain' => [['issuer' => 'root', 'holder' => 'agent']], 'issuerKey' => self::seed(), 'profile' => 'legacy'];
    }

    private static function payload(string $jwt): Obj
    {
        return Json::parseLax(Jose::lenientB64d(explode('.', $jwt)[1]));
    }

    /** A token signed under the test key with the given claims (legacy typ unless `$typ` says otherwise). */
    private static function token(array $claims, string $typ = TxnTokens::TXN_TOKEN_TYP): string
    {
        return Jose::signJwt(Obj::of($claims), ['alg' => 'EdDSA', 'typ' => $typ], self::seed());
    }

    private static function tctx(): Obj
    {
        return Obj::of(['verb' => 'read', 'resource' => 'r', 'aud' => 'a']);
    }

    private function threw(string $class, string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class);
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected $class: $message");
    }

    /** subActChain refuses a non-list or non-array chain with its own error. */
    public function testSubActChainRefusesANonList(): void
    {
        $msg = 'subActChain: chain must be a non-empty CapabilityChain';
        $this->threw(\TypeError::class, $msg, fn () => TxnTokens::subActChain('chain'));
        $this->threw(\TypeError::class, $msg, fn () => TxnTokens::subActChain(['a' => ['holder' => 'h']]));
        $this->threw(\TypeError::class, $msg, fn () => TxnTokens::subActChain([]));
    }

    /** The jti is a v4 UUID over 16 random bytes: version nibble 4, variant bits 10, the other bits as drawn. */
    public function testTheUuidLayout(): void
    {
        TxnTokens::$randomHook = static fn (int $n): string => implode('', array_map('chr', range(0, $n - 1)));
        $this->assertSame('00010203-0405-4607-8809-0a0b0c0d0e0f', self::payload(TxnTokens::toTransactionToken(self::mintArgs()))->get('jti'));
        TxnTokens::$randomHook = static fn (int $n): string => str_repeat("\xff", $n);
        $this->assertSame('ffffffff-ffff-4fff-bfff-ffffffffffff', self::payload(TxnTokens::toTransactionToken(self::mintArgs()))->get('jti'));
    }

    /** ttlSec must be a positive finite number; a raw issuer key must be 32 bytes. */
    public function testMintRefusals(): void
    {
        $this->threw(\InvalidArgumentException::class, 'toTransactionToken: ttlSec must be > 0', fn () => TxnTokens::toTransactionToken(self::mintArgs(['ttlSec' => 'x'])));
        $this->threw(\InvalidArgumentException::class, 'toTransactionToken: ttlSec must be > 0', fn () => TxnTokens::toTransactionToken(self::mintArgs(['ttlSec' => INF])));
        $this->threw(\InvalidArgumentException::class, 'toTransactionToken: ttlSec must be > 0', fn () => TxnTokens::toTransactionToken(self::mintArgs(['ttlSec' => 0])));
        $this->threw(\TypeError::class, 'toTransactionToken: a raw Ed25519 secret key must be 32 bytes',
            fn () => TxnTokens::toTransactionToken(self::mintArgs(['issuerKey' => 'short'])));
    }

    /** exp = now + ttl exactly: an integer Num ttl is added as an integer (no early float rounding), a fractional ttl as a number. */
    public function testExpIsNowPlusTtl(): void
    {
        TxnTokens::$clockHook = static fn (): int => 1;
        // 1 + (2^53 + 1) = 2^53 + 2 is exact; rounding the ttl to a float first would land on 2^53
        $p = self::payload(TxnTokens::toTransactionToken(self::mintArgs(['ttlSec' => new Num('9007199254740993')])));
        $this->assertSame('9007199254740994', $p->get('exp')->lexeme);
        $this->assertSame('1', $p->get('iat')->lexeme);
        TxnTokens::$clockHook = static fn (): int => 1000;
        $this->assertSame('1001.5', self::payload(TxnTokens::toTransactionToken(self::mintArgs(['ttlSec' => 1.5])))->get('exp')->lexeme);
        $this->assertSame('1060', self::payload(TxnTokens::toTransactionToken(self::mintArgs(['ttlSec' => 60])))->get('exp')->lexeme);
    }

    /** Without a replay store or an explicit opt-out the verifier refuses with a named configuration error. */
    public function testAReplayStoreIsRequired(): void
    {
        try {
            TxnTokens::fromTransactionToken('x', self::pk(), ['profile' => 'legacy']);
            $this->fail('expected TxnTokenError');
        } catch (TxnTokenError $e) {
            $this->assertSame('replay_store_required', $e->codeName);
            $this->assertSame("fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'", $e->getMessage());
        }
    }

    /** A token over the size limit is refused as such; one at exactly the limit is not refused for size. */
    public function testTheTokenSizeLimit(): void
    {
        $this->threw(\InvalidArgumentException::class, 'transaction token: token exceeds the size limit',
            fn () => TxnTokens::fromTransactionToken(str_repeat('a', TxnTokens::MAX_TOKEN_CHARS + 1), self::pk(), self::LEGACY));
        try {
            TxnTokens::fromTransactionToken(str_repeat('a', TxnTokens::MAX_TOKEN_CHARS), self::pk(), self::LEGACY);
            $this->fail('a bare string is not a JWS');
        } catch (\Throwable $e) {
            $this->assertNotSame('transaction token: token exceeds the size limit', $e->getMessage());
        }
    }

    /** A raw verify key must be 32 bytes. */
    public function testARawVerifyKeyMustBe32Bytes(): void
    {
        $jwt = self::token(['exp' => 2000, 'sub' => 'root', 'tctx' => self::tctx()]);
        $this->threw(\TypeError::class, 'fromTransactionToken: a raw Ed25519 public key must be 32 bytes',
            fn () => TxnTokens::fromTransactionToken($jwt, 'short', self::LEGACY));
        $this->assertSame(['sub' => 'root'], TxnTokens::fromTransactionToken($jwt, self::pk(), self::LEGACY)['chain'], 'control');
    }

    /** A signed token whose tctx or act is not an object, or (with a replay store) has no jti, is refused with its reason. */
    public function testVerifierClaimRefusals(): void
    {
        $this->threw(\InvalidArgumentException::class, 'transaction token: missing or malformed `tctx`',
            fn () => TxnTokens::fromTransactionToken(self::token(['exp' => 2000, 'sub' => 'root', 'tctx' => 'x']), self::pk(), self::LEGACY));
        $this->threw(\InvalidArgumentException::class, 'transaction token: malformed `act` claim',
            fn () => TxnTokens::fromTransactionToken(self::token(['exp' => 2000, 'sub' => 'root', 'tctx' => self::tctx(), 'act' => 'x']), self::pk(), self::LEGACY));
        $seen = ['profile' => 'legacy', 'nowMs' => 1_000_000, 'seenTxn' => static fn (string $id, mixed $exp): bool => false];
        $this->threw(\InvalidArgumentException::class, 'transaction token: no transaction identifier to check for replay',
            fn () => TxnTokens::fromTransactionToken(self::token(['exp' => 2000, 'sub' => 'root', 'tctx' => self::tctx()]), self::pk(), $seen));
        $ok = TxnTokens::fromTransactionToken(self::token(['exp' => 2000, 'sub' => 'root', 'tctx' => self::tctx(), 'jti' => 'j1']), self::pk(), $seen);
        $this->assertSame(['sub' => 'root'], $ok['chain'], 'control');
    }

    /** draft-11: a present but empty txn is refused by name. */
    public function testDraft11RefusesAnEmptyTxn(): void
    {
        $claims = ['iat' => 1000, 'exp' => 2000, 'aud' => 'td', 'sub' => 'root', 'txn' => '', 'scope' => 's', 'req_wl' => 'w', 'tctx' => self::tctx()];
        $o = ['audience' => 'td', 'replayCheck' => 'unchecked', 'nowMs' => 1_000_000];
        $this->threw(\InvalidArgumentException::class, 'transaction token: `txn` must be a non-empty string',
            fn () => TxnTokens::fromTransactionToken(self::token($claims, TxnTokens::TXN_TOKEN_TYP_DRAFT_11), self::pk(), $o));
        $claims['txn'] = 't1';
        $this->assertSame(['sub' => 'root'], TxnTokens::fromTransactionToken(self::token($claims, TxnTokens::TXN_TOKEN_TYP_DRAFT_11), self::pk(), $o)['chain'], 'control');
    }
}
