<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsRegistry.php';

use Atlas\Pca\ActionKitError;
use Atlas\Pca\ActionsRegistry;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for ActionsRegistry (second batch, full run): evolutionDiffDigest of a non-object, signed re-approvals with an
 * extra member or a wrong v, the shard-ref digest check, a non-object shard whose digest matches, the public digest helpers, the
 * pack def-count bound, and rule22Decide's context filter (session taint keys, non-string entries).
 */
final class K05KillActionsRegistry2Test extends TestCase
{
    /** [pack, keys, shards]: the valid signed sharded pack of K05KillActionsRegistryTest. */
    private static function sharded(): array
    {
        $json = (new \ReflectionClassConstant(K05KillActionsRegistryTest::class, 'SHARDED'))->getValue();
        return (new Parser($json, PHP_INT_MAX))->run();
    }

    private static function sk(): string
    {
        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(str_repeat("\x0b", 32)));
    }

    private static function issuer(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x0b", 32))));
    }

    /** A re-approval over `$body`, Ed25519-signed the way reapprovalValid verifies it. */
    private static function reapproval(array $body): Obj
    {
        $r = Obj::of($body);
        $sig = sodium_crypto_sign_detached(ActionsRegistry::REAPPROVAL_DOMAIN . IntentV2::canonicalize($r), self::sk());
        $r->set('sig', Obj::of(['alg' => 'ed25519', 'value' => Pca::b64u($sig)]));
        return $r;
    }

    private static function body(string $v = '1'): array
    {
        return ['v' => new Num($v), 'kind' => ActionsRegistry::REAPPROVAL_KIND, 'grant' => 'g1', 'verb' => 'a.b', 'diff' => 'd1'];
    }

    public function testEvolutionDiffDigestOfANonObjectIsAMissingMember(): void
    {
        foreach (['x', null, 5] as $r) {
            try {
                ActionsRegistry::evolutionDiffDigest($r);
                self::fail('expected a throw');
            } catch (\InvalidArgumentException $e) {
                self::assertSame('missing ns', $e->getMessage());
            }
        }
    }

    public function testASignedReapprovalWithAnExtraMemberIsInvalid(): void
    {
        $iss = self::issuer();
        self::assertTrue(ActionsRegistry::reapprovalValid(self::reapproval(self::body()), 'g1', $iss, 'a.b', 'd1'));
        self::assertFalse(ActionsRegistry::reapprovalValid(self::reapproval(self::body() + ['x' => 'y']), 'g1', $iss, 'a.b', 'd1'));
    }

    public function testASignedReapprovalWithAWrongVIsInvalid(): void
    {
        self::assertFalse(ActionsRegistry::reapprovalValid(self::reapproval(self::body('2')), 'g1', self::issuer(), 'a.b', 'd1'));
    }

    public function testABadShardRefDigestIsRefusedEvenWithAGoodUri(): void
    {
        [$pack] = self::sharded();
        self::assertNull(ActionsRegistry::packShapeError($pack));
        $pack->get('defs')->get('shards')[0]->set('digest', 'bad');
        self::assertSame('pack: bad shard digest or uri', ActionsRegistry::packShapeError($pack));
    }

    public function testANonObjectShardMatchingItsDigestIsABadShard(): void
    {
        $pack = Obj::of(['ns' => 'a', 'version' => '1.0.0', 'defs' => Obj::of(['shards' => [
            Obj::of(['name' => 's1', 'digest' => ActionsRegistry::shardDigest('x'), 'uri' => 'u'])]])]);
        try {
            ActionsRegistry::packDefs($pack, Obj::of(['s1' => 'x']));
            self::fail('expected a throw');
        } catch (ActionKitError $e) {
            self::assertSame('bad_shard', $e->codeName);
            self::assertSame("shard 's1' is not a shard of this pack", $e->getMessage());
        }
    }

    /** Called from outside the class (kills public -> protected); the values are those the valid sharded pack carries. */
    public function testTheDigestHelpersArePublicAndMatchTheSignedPack(): void
    {
        [$pack, $keys, $shards] = self::sharded();
        $v = ActionsRegistry::verifyPack($pack, $keys, $shards);
        self::assertTrue($v['ok']);
        self::assertSame('UH2GMZ7KB7LkjbUIM-UScWH8QPRtBNvjgv_6Jgtag1Y', ActionsRegistry::rulesDigest());
        self::assertSame($v['digest'], ActionsRegistry::packDigest($pack));
        self::assertSame('c7n16kAW5hY1YYv3zP4elOr8PhK8nZJOznYAtpFeKNQ', ActionsRegistry::shardDigest($shards->get('stripe-1')));
    }

    public function testThePackDefCountIsOneToAMillion(): void
    {
        $m = new \ReflectionMethod(ActionsRegistry::class, 'defCountOk');
        self::assertFalse($m->invoke(null, 0));
        self::assertTrue($m->invoke(null, 1));
        self::assertTrue($m->invoke(null, 1000000));
        self::assertFalse($m->invoke(null, 1000001));
    }

    private static function decide(array $context): string
    {
        $doc = Json::parseLax('{"verbs":[{"verb":"a.b","floors":{"risk":0,"rev":"reversible","blast_ppm":0,"esc":0,"caveats":[],'
            . '"context":["idempotency","session_taint_max:web"],"prules":[]}}]}');
        $grant = Json::parseLax('{"caveats":[],"max_esc":0,"preauth_esc":0}');
        return ActionsRegistry::rule22Decide($doc, 'a.b', $grant, $context);
    }

    /** A session-taint context key is kept by the filter (`=== 1`): without it the call escalates. */
    public function testRule22KeepsSessionTaintContextKeys(): void
    {
        self::assertSame('allow', self::decide(['idempotency', 'session_taint_max:web']));
        self::assertSame('escalate', self::decide(['idempotency']));
    }

    /** A non-string context entry is dropped before the regex (is_string short-circuits): never a TypeError deny. */
    public function testRule22DropsNonStringContextEntries(): void
    {
        self::assertSame('allow', self::decide([5, 'idempotency', 'session_taint_max:web']));
    }
}
