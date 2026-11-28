<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use Atlas\Pca\VerifyVerdict;
use PHPUnit\Framework\TestCase;

/**
 * The resource-server verdict, third battery: a grant pinning an action pack, a PCActn that carries an intent session, a verified
 * narrow block adding plain caveats, and the assurance level of a hybrid post-quantum leaf signature.
 */
final class ProofSurvivorKill5cVerifyVerdictTest extends TestCase
{
    private const NOW = 1791288000000;
    private const PIN = ['pack' => ['ns' => 'stripe', 'root' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'], 'on_new_action' => 'deny'];

    private static function kp(int $b): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    private static function plan(): array
    {
        return [['id' => 'n1', 'verb' => 'v', 'resource' => 'r', 'reversibility_class' => 'reversible'], ['id' => 'n2', 'verb' => 'w', 'resource' => 'r']];
    }

    private static function envelope(array $env = []): array
    {
        return $env + ['predicates' => [['verb' => 'v', 'resource' => 'r'], ['verb' => 'w', 'resource' => 'r']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
    }

    private static function grant(array $env = []): Obj
    {
        return Sign::mintGrant(self::kp(1), self::kp(2)->public, self::envelope($env), 'g', 's')['grant'];
    }

    private static function pcactn(Obj $g, array $extra = []): Obj
    {
        return Sign::buildPcactn($g, [$g], self::plan(), 'n1', 1, self::kp(2), 'aud', null, self::NOW, self::NOW + 60000, 60000, $extra);
    }

    private static function opts(Obj $g, array $o = []): array
    {
        return $o + ['grant' => $g, 'now' => self::NOW, 'audience' => 'aud', 'hooks' => ['revocation' => static fn(): array => ['enforced' => true, 'ok' => true]],
            'context' => Sign::n(['plan' => self::plan(), 'planAuthorized' => true,
                'risk' => ['reversibility' => 1, 'blastRadius' => 0, 'confidence' => 1, 'semanticDistance' => 0, 'taint' => 0],
                'budget' => ['B' => 1, 'tau' => self::NOW, 'asOf' => self::NOW]])];
    }

    /** The reasons that begin with `$prefix`. */
    private static function starting(array $v, string $prefix): array
    {
        return array_values(array_filter($v['reasons'], static fn(string $r): bool => str_starts_with($r, $prefix)));
    }

    private static function session(): array
    {
        return ['session' => Pca::b64u(str_repeat("\x01", 32)), 'root' => Pca::b64u(str_repeat("\x02", 32)), 'seq' => 1,
            'schema' => Pca::b64u(str_repeat("\x03", 32))];
    }

    // ---- the grant's model rules run for an action pin alone, and for a grant carrying every rule

    public function testAnActionPinAloneRunsTheModelRules(): void
    {
        $g = self::grant(['actions' => self::PIN]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['audience' => 'other']));
        $this->assertStringStartsWith('audience: ', $v['reasons'][0]);
        $this->assertSame(['pin: this verifier has no action schema configured'], self::starting($v, 'pin: '));
    }

    public function testAGrantCarryingEveryModelRuleRunsThem(): void
    {
        $g = self::grant(['units' => Sign::n(['action.params.x' => ['kind' => 'count']]), 'tighten' => [], 'model_polarity' => 'legacy', 'actions' => self::PIN,
            'predicates' => [['verb' => 'v', 'resource' => 'r', 'where' => [['field' => 'env.class.label', 'op' => 'eq', 'value' => 'ok']]]]]);
        $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['audience' => 'other']));
        $this->assertStringStartsWith('audience: ', $v['reasons'][0]);
        $this->assertSame(['units: this verifier has no action schema configured'], self::starting($v, 'units: '));
    }

    // ---- a PCActn carrying intent_session runs the v2 checks, with or without model rules

    public function testAnIntentSessionRunsTheV2Checks(): void
    {
        foreach ([[], ['units' => Sign::n(['action.params.x' => ['kind' => 'count']])]] as $env) {
            $g = self::grant($env);
            $v = VerifyVerdict::verify(self::pcactn($g, ['intent_session' => self::session()]), self::opts($g, ['audience' => 'other']));
            $this->assertFalse($v['allow']);
            $this->assertStringStartsWith('audience: ', $v['reasons'][0]);
            $this->assertNotSame([], self::starting($v, 'schema: '), implode(' | ', $v['reasons']));
        }
    }

    // ---- a verified narrow block's plain caveats bind the hop

    public function testANarrowBlockAddsPlainCaveats(): void
    {
        $g = self::grant();
        foreach ([[self::NOW + 1000, 'pass'], [self::NOW - 1, 'fail']] as [$at, $want]) {
            $n = Sign::signNarrow(self::kp(2), Pca::capHash($g), [['type' => 'expires', 'at' => $at]], self::NOW - 1000, self::NOW + 60000);
            $v = VerifyVerdict::verify(self::pcactn($g), self::opts($g, ['k1' => Obj::of(['narrow' => $n])]));
            $this->assertSame($want, $v['checks']['delegated_caveats'], implode(' | ', $v['reasons']));
        }
        $this->assertContains('delegated_caveats: delegation caveat(s) not satisfied: expires', $v['reasons']);
    }

    // ---- a hybrid post-quantum leaf bound to the holder's PQ key is reported at its own level

    public function testAHybridLeafIsReportedHybrid(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->markTestSkipped('ML-DSA-65 needs OpenSSL >= 3.5 over FFI');
        }
        $pq = new PqKeyPair('ML-DSA-65', str_repeat(chr(7), 32));
        $g = Sign::mintGrant(self::kp(1), self::kp(2)->public, self::envelope(), 'g', 's', $pq->public)['grant'];
        $p = Sign::buildPcactn($g, [$g], self::plan(), 'n1', 1, self::kp(2), 'aud', null, self::NOW, self::NOW + 60000, 60000, [], 'hybrid-ed25519-ml-dsa-65', $pq);
        $v = VerifyVerdict::verify($p, self::opts($g, ['assurance' => true]));
        $this->assertTrue($v['allow'], implode(' | ', $v['reasons']));
        $this->assertSame('pass', $v['assurance']['leaf_signature']['outcome']);
        $this->assertSame('hybrid', $v['assurance']['leaf_signature']['level']); // never 'unbound_pq': the leaf is bound to holder_pq
    }
}
