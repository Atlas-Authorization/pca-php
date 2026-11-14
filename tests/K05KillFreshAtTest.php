<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FreshAt.php';

use Atlas\Pca\FreshAt;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Mutation kills for FreshAt (token verify bounds, missing local state, wire shape). */
final class K05KillFreshAtTest extends TestCase
{
    /** A token signed by the fixed key over exactly its content, with `$over` replacing members. @return array{0: Obj, 1: string} */
    private static function token(array $over = []): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x09", 32));
        $pk = Pca::b64u(sodium_crypto_sign_publickey($kp));
        $t = Obj::of(array_merge([
            'v' => new Num('1'), 'scope' => 's', 'revocation_epoch' => new Num('5'), 'ledger_tree_size' => new Num('5'),
            'budget_version' => new Num('5'), 'policy_revision' => new Num('5'), 'policy_digest' => 'pd', 'issued_at' => new Num('1000'), 'signer' => $pk,
        ], $over));
        $t->set('sig', Pca::b64u(sodium_crypto_sign_detached(FreshAt::DOMAIN . Json::canonicalizeStrict($t), sodium_crypto_sign_secretkey($kp))));
        return [$t, $pk];
    }

    public function testVerifyBounds(): void
    {
        foreach ([[['scope' => str_repeat('s', 256)], true], [['scope' => str_repeat('s', 257)], false],
            [['policy_digest' => str_repeat('p', 128)], true], [['policy_digest' => str_repeat('p', 129)], false],
            [['revocation_epoch' => new Num('-1')], false], [[], true]] as [$over, $want]) {
            [$t, $pk] = self::token($over);
            $this->assertSame($want, FreshAt::verify($t, $pk), json_encode(array_keys($over)));
        }
    }

    public function testMissingLocalStateIsBehindOnEveryCounter(): void
    {
        [$t, $pk] = self::token();
        $o = Obj::of(['signer' => $pk, 'scope' => 's', 'now' => new Num('1000')]);
        $this->assertSame(['decision' => 'escalate', 'code' => 'stale_state',
            'behind' => ['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision']], FreshAt::check($t, null, $o));
    }

    public function testValidateWireBounds(): void
    {
        $w = static fn(array $over): Obj => Obj::of(array_merge([
            'v' => new Num('1'), 'scope' => 's', 'revocation_epoch' => new Num('0'), 'ledger_tree_size' => new Num('0'), 'budget_version' => new Num('0'),
            'policy_revision' => new Num('0'), 'policy_digest' => 'pd', 'issued_at' => new Num('0'),
            'signer' => Pca::b64u(str_repeat("\x01", 32)), 'sig' => Pca::b64u(str_repeat("\x02", 64)),
        ], $over));
        $msg = "'fresh_at' scope and policy_digest must be non-empty strings";
        $this->assertNull(FreshAt::validateWire($w([])));
        $this->assertNull(FreshAt::validateWire($w(['scope' => str_repeat('s', 256)])));
        $this->assertSame($msg, FreshAt::validateWire($w(['scope' => str_repeat('s', 257)])));
        $this->assertNull(FreshAt::validateWire($w(['policy_digest' => str_repeat('p', 128)])));
        $this->assertSame($msg, FreshAt::validateWire($w(['policy_digest' => str_repeat('p', 129)])));
        $this->assertSame($msg, FreshAt::validateWire($w(['scope' => ''])));
    }

    public function testOnlyAnObjOptionsCarryTheSigner(): void
    {
        [$t, $pk] = self::token();
        $o = new class ($pk) {
            public function __construct(private string $pk)
            {
            }

            public function get(string $k): mixed
            {
                return ['signer' => $this->pk, 'scope' => 's', 'now' => new Num('1000')][$k] ?? null;
            }
        };
        $this->assertSame(['decision' => 'deny', 'code' => 'bad_token'], FreshAt::check($t, null, $o));
    }

    public function testCheckFailsClosedOnAThrow(): void
    {
        [$t, $pk] = self::token();
        $o = Obj::of(['signer' => $pk, 'scope' => 's', 'now' => new Num('1000')]);
        $this->assertSame('escalate', FreshAt::check($t, null, $o)['decision']);
        FreshAt::$checkHook = static function (): void {
            throw new \RuntimeException('k05');
        };
        try {
            $this->assertSame(['decision' => 'deny', 'code' => 'bad_token'], FreshAt::check($t, null, $o));
        } finally {
            FreshAt::$checkHook = null;
        }
    }
}
