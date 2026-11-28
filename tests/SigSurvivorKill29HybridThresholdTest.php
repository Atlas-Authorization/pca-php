<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\Bytes;
use Atlas\Pca\GroupDescriptor;
use Atlas\Pca\HybridThreshold;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for HybridThreshold: the signing refusals, the fold refusal, the hook's config copy, share selection and key
 * normalisation, and the step-up's audience, reason and clock handling. Nothing here needs ML-DSA: every case is decided before it.
 */
final class SigSurvivorKill29HybridThresholdTest extends TestCase
{
    private const PQ_T = 'pqT must be a positive integer'; // the first ML-DSA-side refusal: reached only once the FROST half passed

    protected function tearDown(): void
    {
        HybridThreshold::$clockHook = null;
    }

    private static function seed(string $label): string
    {
        return hash('sha256', "atlas-pca-conformance/g29-hybrid/$label", true);
    }

    /** The FROST aggregate is a plain Ed25519 signature under the group key, so a single Ed25519 key stands in for the group. */
    private static function groupKp(): string
    {
        return sodium_crypto_sign_seed_keypair(self::seed('group'));
    }

    private static function groupKey(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(self::groupKp()));
    }

    private static function aggregate(Obj $p): string
    {
        return Pca::b64u(sodium_crypto_sign_detached(Pca::thresholdMessage($p), sodium_crypto_sign_secretkey(self::groupKp())));
    }

    private static function descriptor(): array
    {
        return GroupDescriptor::issueGroupDescriptor(self::seed('authority'), self::groupKey(), 1, [['identifier' => 1, 'publicKey' => self::groupKey()]]);
    }

    private static function opts(?array $desc = null): array
    {
        $desc ??= self::descriptor();
        return ['groupKey' => self::groupKey(), 'pqPublicKeys' => [], 't' => 1, 'groupDescriptor' => $desc, 'trustedAuthorities' => [$desc['authority']]];
    }

    private static function step(array $shares): Obj
    {
        return Obj::of(['a' => 'b', 'threshold' => Obj::of(['shares' => $shares])]);
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

    public function testSignRefusals(): void
    {
        $a = Obj::of(['a' => 'b']);
        $q = [['identifier' => 1, 'share' => 's', 'publicKey' => 'p']];
        $e = \InvalidArgumentException::class;
        $this->threw($e, 'hybridThresholdSign: frost.t must be a positive integer (got 0)', fn () => HybridThreshold::hybridThresholdSign($a, self::groupKey(), $q, 0, ['x']));
        $this->threw($e, 'hybridThresholdSign: FROST quorum of 1 is below the threshold t=2', fn () => HybridThreshold::hybridThresholdSign($a, self::groupKey(), $q, 2, ['x']));
        $this->threw($e, 'hybridThresholdSign: at least one ML-DSA co-signer is required', fn () => HybridThreshold::hybridThresholdSign($a, self::groupKey(), $q, 1, []));
        $this->threw($e, 'hybridThresholdSign: FROST group public key must be 32 bytes',
            fn () => HybridThreshold::hybridThresholdSign($a, new Bytes(str_repeat("\1", 31)), $q, 1, ['x']));
        $this->threw($e, 'hybridThresholdSign: FROST group public key is not canonical b64u(32)', fn () => HybridThreshold::hybridThresholdSign($a, 'AAAA', $q, 1, ['x']));
    }

    public function testFoldNeedsAnObjectAction(): void
    {
        $this->threw(\InvalidArgumentException::class, 'foldHybridStepUp: artifact has no FROST part',
            fn () => HybridThreshold::foldHybridStepUp('x', ['frost' => ['sig' => 's']]));
    }

    /** Control: a valid aggregate passes the FROST half and the hook goes on to the ML-DSA half. A non-object step-up is refused. */
    public function testHookControlAndMalformedStepUp(): void
    {
        $hook = HybridThreshold::createHybridThresholdVerifier(self::opts());
        $p = self::step([]);
        $good = self::step([Obj::of(['publicKey' => self::groupKey(), 'sig' => self::aggregate($p)])]);
        $this->assertSame(self::PQ_T, $hook($good)['reason']);
        $this->assertSame(['enforced' => true, 'ok' => false, 'reason' => 'malformed step-up'], $hook('x'));
    }

    /** The first share under the trusted key is the aggregate; a later one is never consulted. */
    public function testTheFirstMatchingShareIsUsed(): void
    {
        $hook = HybridThreshold::createHybridThresholdVerifier(self::opts());
        $sig = self::aggregate(self::step([]));
        $bad = Pca::b64u(str_repeat("\0", 64));
        $two = self::step([Obj::of(['publicKey' => self::groupKey(), 'sig' => $sig]), Obj::of(['publicKey' => self::groupKey(), 'sig' => $bad])]);
        $this->assertSame(self::PQ_T, $hook($two)['reason']);
    }

    /** The configuration is copied deeply: later edits to an Obj config, or to an Obj nested in an array config, change nothing. */
    public function testTheConfigIsCopied(): void
    {
        $o = Obj::of(self::opts());
        $hook = HybridThreshold::createHybridThresholdVerifier($o);
        $o->set('trustedAuthorities', []);
        $this->assertSame('malformed step-up', $hook('x')['reason']);

        $desc = self::descriptor();
        $hook = HybridThreshold::createHybridThresholdVerifier(self::opts($desc));
        $desc['descriptor']->set('t', new Num('2'));
        $this->assertSame('malformed step-up', $hook('x')['reason']);
    }

    /** A trusted group key that is not a canonical b64u(32) is refused by name, even when the authority signed it. */
    public function testANonCanonicalTrustedGroupKeyIsRefused(): void
    {
        $authority = self::seed('authority');
        $ssc = GroupDescriptor::signerSetCommitment([['identifier' => 1, 'publicKey' => self::groupKey()]]);
        $bytes = (new \ReflectionMethod(GroupDescriptor::class, 'descriptorBytes'))
            ->invoke(null, GroupDescriptor::GROUP_DESCRIPTOR_VERSION, GroupDescriptor::GROUP_SUITE, 'AAAA', 1, 1, $ssc);
        $kp = sodium_crypto_sign_seed_keypair($authority);
        $desc = ['descriptor' => Obj::of(['v' => new Num('1'), 'suite' => GroupDescriptor::GROUP_SUITE, 'groupPublicKey' => 'AAAA', 't' => new Num('1'),
            'n' => new Num('1'), 'signerSetCommitment' => $ssc]), 'authority' => Pca::b64u(sodium_crypto_sign_publickey($kp)),
            'sig' => Pca::b64u(sodium_crypto_sign_detached($bytes, sodium_crypto_sign_secretkey($kp)))];
        $opts = ['groupKey' => 'AAAA'] + self::opts($desc);
        $hook = HybridThreshold::createHybridThresholdVerifier($opts);
        $this->assertSame('trusted FROST group key is not a canonical b64u(32) point', $hook(self::step([]))['reason']);
    }

    public function testStepUpNeedsAPcactn(): void
    {
        $this->threw(\InvalidArgumentException::class, 'verifyHybridStepUp: step-up has no PCActn', fn () => HybridThreshold::verifyHybridStepUp(['pq' => null], self::opts()));
    }

    /** @return array{0:Obj,1:Obj} a signed PCActn for audience rs-test and its grant */
    private static function signed(): array
    {
        $principal = new KeyPair(self::seed('principal'));
        $key = new KeyPair(self::seed('agent'));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'];
        return [(new Agent($key, $grant, 'rs-test'))->act('refund', 'orders/7')->pcactn, $grant];
    }

    /** An unusable audience is no audience (refused by the core with a reason), never a type error. */
    public function testABadAudienceIsNoAudience(): void
    {
        [$p, $g] = self::signed();
        $r = HybridThreshold::verifyHybridStepUp(['pcactn' => $p], ['grant' => $g, 'audience' => 5, 'nowEpoch' => $p->get('iat')->int()] + self::opts());
        $this->assertFalse($r['allow']);
        $this->assertSame('audience: this verifier supplied no audience (pass its audience, or Audience::Any to accept any)', $r['reason']);
    }

    /** Without nowEpoch the clock is read in whole milliseconds: inside the window the core reaches the threshold hook. */
    public function testNowDefaultsToTheClockInMilliseconds(): void
    {
        [$p, $g] = self::signed();
        $iat = $p->get('iat')->int();
        $exp = $p->get('exp')->int();
        $mid = intdiv($iat + $exp, 2);
        HybridThreshold::$clockHook = static fn (): float => $mid / 1000;
        $r = HybridThreshold::verifyHybridStepUp(['pcactn' => $p], ['grant' => $g, 'audience' => 'rs-test'] + self::opts());
        $this->assertFalse($r['allow']);
        $this->assertStringStartsWith('threshold: ', $r['reason']);
        HybridThreshold::$clockHook = null;
        $wall = HybridThreshold::verifyHybridStepUp(['pcactn' => $p], ['grant' => $g, 'audience' => 'rs-test'] + self::opts());
        $this->assertStringStartsWith('threshold: ', $wall['reason']);
    }
}
