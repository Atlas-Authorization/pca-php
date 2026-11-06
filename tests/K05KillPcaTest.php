<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for src/Pca.php: every fail-closed catch (driven through the Pca::$faultHook seam) refuses with its exact
 * verdict, and the threshold-share type guards refuse a non-Obj that merely quacks like one (an object with get()/has()).
 */
final class K05KillPcaTest extends TestCase
{
    protected function setUp(): void
    {
        Pca::$faultHook = null;
    }

    protected function tearDown(): void
    {
        Pca::$faultHook = null;
    }

    /** Make the hook throw RuntimeException('boom') at `$tag` only. */
    private static function faultAt(string $tag): void
    {
        Pca::$faultHook = static function (string $at) use ($tag): void {
            if ($at === $tag) {
                throw new \RuntimeException('boom');
            }
        };
    }

    public function testAFailureInsideTheEd25519CheckRefuses(): void
    {
        [$pk, $sk] = self::keys();
        $sig = Pca::b64u(sodium_crypto_sign_detached('m', $sk));
        $this->assertTrue(Pca::verifyEd25519B64u($pk, 'm', $sig));
        self::faultAt('ed25519_verify');
        $this->assertFalse(Pca::verifyEd25519B64u($pk, 'm', $sig));
    }

    /** @return array{0:string,1:string} [b64u Ed25519 public key, raw secret key] (deterministic) */
    private static function keys(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\7", 32));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    /** A valid Ed25519 threshold-share entry (role agent, t = 1, a one-member signer set). */
    private static function shareEntry(): Obj
    {
        [$pk, $sk] = self::keys();
        $set = [Obj::of(['role' => 'agent', 'publicKey' => $pk])];
        $tmsg = hash('sha256', 'k05-r3-share', true);
        $msg = Pca::SHARE_DOMAIN_PREFIX . "agent\0" . hash('sha256', $tmsg, true) . Pca::signerSetHashRaw($set) . chr(1);
        return Obj::of([
            'role' => 'agent', 't' => new Num('1'), 'signer_set' => $set, 'threshold_message' => Pca::b64u($tmsg),
            'share' => Obj::of(['role' => 'agent', 'publicKey' => $pk, 'sig' => Pca::b64u(sodium_crypto_sign_detached($msg, $sk))]),
        ]);
    }

    /** A non-Obj object answering get()/has() from a real Obj. */
    private static function lookalike(Obj $o): object
    {
        return new class($o) {
            public function __construct(private Obj $o)
            {
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function has(string $k): bool
            {
                return $this->o->has($k);
            }
        };
    }

    private static function coreVector(string $name): Obj
    {
        foreach (Corpus::core()->get('vectors') as $v) {
            if ($v->get('name') === $name) {
                return $v;
            }
        }
        throw new \LogicException("vector $name not found");
    }

    public function testWireCatchReturnsTheMalformedMessage(): void
    {
        $this->assertSame('PCActn is not an object', Pca::validateWire(null));
        self::faultAt('wire');
        $this->assertSame('malformed: boom', Pca::validateWire(null));
    }

    public function testVerifyJsonAndCoreCatchesAreAWireRefusal(): void
    {
        $want = ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: malformed input (RuntimeException)'];
        self::faultAt('json');
        $this->assertSame($want, Pca::verifyJson('{}', null, 0, 'aud'));
        self::faultAt('core');
        $this->assertSame($want, Pca::verifyPcactnCore(null, null, 0, 'aud'));
    }

    /** TS pcactn.ts: a throw after every core check passed is a malformed failure, never a leftover allow. */
    public function testAFaultAfterEveryCoreCheckPassedDenies(): void
    {
        $v = self::coreVector('valid-in-plan-action');
        $ctx = $v->get('context');
        $run = fn() => Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'));
        $this->assertTrue($run()['allow'], 'control: the vector verifies');
        self::faultAt('core_done');
        $this->assertSame(['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: malformed input (RuntimeException)'], $run());
    }

    public function testPlanInclusionAndLeafSignatureCatchesFailTheirCheck(): void
    {
        $v = self::coreVector('valid-in-plan-action');
        $ctx = $v->get('context');
        $run = fn() => Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'));
        $this->assertTrue($run()['allow'], 'control: the vector verifies');
        foreach (['plan_inclusion', 'leaf_signature'] as $check) {
            self::faultAt($check);
            $r = $run();
            $this->assertFalse($r['allow'], $check);
            $this->assertFalse($r['checks'][$check], $check);
            $this->assertSame("$check: malformed: boom", $r['reason']);
            $this->assertSame(["$check: malformed: boom"], $r['reasons']);
        }
    }

    public function testThresholdShareCatchAndTypeGuards(): void
    {
        $e = self::shareEntry();
        $this->assertTrue(Pca::verifyThresholdShare($e), 'control: the share verifies');
        // the entry and the share must be real Obj values, not lookalikes
        $this->assertFalse(Pca::verifyThresholdShare(self::lookalike($e)));
        $bad = Obj::of(['role' => 'agent', 't' => $e->get('t'), 'signer_set' => $e->get('signer_set'),
            'threshold_message' => $e->get('threshold_message'), 'share' => self::lookalike($e->get('share'))]);
        $this->assertFalse(Pca::verifyThresholdShare($bad));
        self::faultAt('threshold_share');
        $this->assertFalse(Pca::verifyThresholdShare($e));
    }

    public function testArtifactAndPinnedSuiteCatchesRefuse(): void
    {
        [$pk, $sk] = self::keys();
        $msg = 'k05-r3-artifact';
        $sig = Pca::b64u(sodium_crypto_sign_detached($msg, $sk));
        $a = Obj::of(['ed_pub' => $pk, 'sig' => $sig]);
        $this->assertTrue(Pca::verifyArtifact($a, $msg), 'control');
        $this->assertTrue(Pca::verifyPinnedSuite(null, $pk, null, $msg, $sig, null, null), 'control');
        self::faultAt('artifact');
        $this->assertFalse(Pca::verifyArtifact($a, $msg));
        self::faultAt('pinned_suite');
        $this->assertFalse(Pca::verifyPinnedSuite(null, $pk, null, $msg, $sig, null, null));
    }

    public function testEvaluateCaveatsCatchFailsTheCaveat(): void
    {
        $cv = [Obj::of(['type' => 'budget_alloc', 'limit' => new Num('1')])];
        $ctx = Obj::of(['now' => new Num('1')]);
        $this->assertSame(['ok' => true, 'failed' => []], Pca::evaluateCaveats($cv, $ctx));
        self::faultAt('caveat');
        $this->assertSame(['ok' => false, 'failed' => ['budget_alloc']], Pca::evaluateCaveats($cv, $ctx));
    }
}
