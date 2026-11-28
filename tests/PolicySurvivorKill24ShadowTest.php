<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Grants;
use Atlas\Pca\K3;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Shadow;
use Atlas\Pca\ShadowLog;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24) for src/Shadow.php: diff, explanation and approval validation (with validly signed malformed bodies), the gate's limits, promotion. */
final class PolicySurvivorKill24ShadowTest extends TestCase
{
    private static function kp(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/shadow-24', true));
    }

    private static function sd(): string
    {
        return str_repeat('s', 128);
    }

    private static function ed(): string
    {
        return str_repeat('e', 128);
    }

    private static function ad(): string
    {
        return str_repeat('a', 128);
    }

    /** A diff signed by the test key over exactly its fields (malformed fields included). */
    private static function diff(array $over = []): Obj
    {
        $kp = self::kp();
        $b = Obj::of($over + ['v' => 1, 'shadow_digest' => 'sd', 'enforced_digest' => 'ed', 'action_digest' => 'ad', 'enforced' => 'deny', 'shadow' => 'allow',
            'widening' => true, 'at' => 1000, 'signer' => $kp->public]);
        $b->set('sig', Grants::signBody(Shadow::DIFF_DOMAIN, $b, $kp));
        return $b;
    }

    /** The decision-record field keeps digest, decision and diverged only. */
    public function testShadowRecordField(): void
    {
        $this->assertSame([['digest' => 'd', 'decision' => 'allow', 'diverged' => true]],
            Shadow::shadowRecordField([['digest' => 'd', 'decision' => 'allow', 'diverged' => true, 'widening' => true]]));
    }

    /** verifyShadowDiff: v must be 1, the digests at most 128 units, enforced and shadow must differ; validly signed otherwise-bad diffs are refused. */
    public function testVerifyShadowDiffShape(): void
    {
        $kp = self::kp();
        $this->assertTrue(Shadow::verifyShadowDiff(self::diff(), $kp->public), 'control');
        $this->assertFalse(Shadow::verifyShadowDiff('x'));
        $this->assertFalse(Shadow::verifyShadowDiff(self::diff(['v' => 2])));
        $this->assertFalse(Shadow::verifyShadowDiff(self::diff(['shadow' => 'deny', 'widening' => false])));
        foreach (['shadow_digest', 'enforced_digest', 'action_digest'] as $k) {
            $this->assertTrue(Shadow::verifyShadowDiff(self::diff([$k => str_repeat('x', 128)])), "$k 128");
            $this->assertFalse(Shadow::verifyShadowDiff(self::diff([$k => str_repeat('x', 129)])), "$k 129");
        }
    }

    /** @return array{0:ShadowLog,1:array<string,mixed>} a log with one widening and the gate options for it */
    private static function widening(array $opts = []): array
    {
        $kp = self::kp();
        $log = new ShadowLog($kp);
        $log->observe(self::ed(), self::ad(), 'deny', ['digest' => self::sd(), 'decision' => 'allow', 'diverged' => true, 'widening' => true], 1000);
        return [$log, $opts + ['shadow_digest' => self::sd(), 'enforced_digest' => self::ed(), 'minSamples' => 1, 'principals' => [$kp->public], 'surface' => 'equal']];
    }

    private static function explanation(array $over = []): Obj
    {
        $kp = self::kp();
        $b = Obj::of($over + ['v' => 1, 'shadow_digest' => self::sd(), 'action_digest' => self::ad(), 'reason_digest' => str_repeat('r', 128), 'principal' => $kp->public]);
        $b->set('sig', Grants::signBody(Shadow::EXPLANATION_DOMAIN, $b, $kp));
        return $b;
    }

    private static function approval(array $over = []): Obj
    {
        $kp = self::kp();
        $b = Obj::of($over + ['v' => 1, 'shadow_digest' => self::sd(), 'enforced_digest' => self::ed(), 'at' => 5, 'principal' => $kp->public]);
        $b->set('sig', Grants::signBody(Shadow::APPROVAL_DOMAIN, $b, $kp));
        return $b;
    }

    /** A valid explanation (128-unit digests) clears the widening; v = 2 or a 129-unit reason digest does not. */
    public function testExplanations(): void
    {
        [$log, $o] = self::widening();
        $this->assertSame(['ok' => true, 'samples' => 1, 'widenings' => 1, 'surface' => 'equal'], Shadow::promotionGate($log, $o + ['explanations' => [self::explanation()]]));
        $un = ['ok' => false, 'code' => 'unexplained_widening', 'reason' => "1 widening(s) without a principal's explanation", 'unexplained' => [self::ad()]];
        $this->assertSame($un, Shadow::promotionGate($log, $o));
        $this->assertSame($un, Shadow::promotionGate($log, $o + ['explanations' => [self::explanation(['v' => 2])]]));
        $this->assertSame($un, Shadow::promotionGate($log, $o + ['explanations' => [self::explanation(['reason_digest' => str_repeat('r', 129)])]]));
        $this->assertSame(['ok' => false, 'code' => 'bad_input', 'reason' => 'evaluation error (fail closed)'], Shadow::promotionGate($log, $o + ['explanations' => new Obj()]));
    }

    /** A wider surface needs a valid approval (128-unit digests); v = 2 is refused. */
    public function testApproval(): void
    {
        [$log, $o] = self::widening(['surface' => 'wider']);
        $o['explanations'] = [self::explanation()];
        $this->assertTrue(Shadow::promotionGate($log, $o + ['approval' => self::approval()])['ok']);
        $r = Shadow::promotionGate($log, $o + ['approval' => self::approval(['v' => 2])]);
        $this->assertSame([false, 'advisory_wider'], [$r['ok'], $r['code']]);
    }

    /** Gate options: digests of at most 128 units, minSamples of exactly the sample count is enough. */
    public function testGateLimits(): void
    {
        [$log, $o] = self::widening();
        $o['explanations'] = [self::explanation()];
        $this->assertTrue(Shadow::promotionGate($log, $o)['ok']);
        foreach (['shadow_digest', 'enforced_digest'] as $k) {
            $this->assertSame(['ok' => false, 'code' => 'bad_input', 'reason' => 'bad gate options'], Shadow::promotionGate($log, [$k => str_repeat('x', 129)] + $o), $k);
        }
        $this->assertSame('too_few_samples', Shadow::promotionGate($log, ['minSamples' => 2] + $o)['code']);
    }

    /** A recorded diff that no longer verifies refuses the gate even when it belongs to the pair. */
    public function testATamperedDiffIsBad(): void
    {
        $log = new ShadowLog(self::kp());
        $d = $log->observe(self::ed(), self::ad(), 'allow', ['digest' => self::sd(), 'decision' => 'deny', 'diverged' => true, 'widening' => false], 1000);
        $o = ['shadow_digest' => self::sd(), 'enforced_digest' => self::ed(), 'minSamples' => 1, 'principals' => [], 'surface' => 'equal'];
        $this->assertTrue(Shadow::promotionGate($log, $o)['ok'], 'control');
        $d->set('at', 1001);
        $this->assertSame('bad_diff', Shadow::promotionGate($log, $o)['code']);
    }

    /** An unexplained numeric action digest is reported as a string. */
    public function testNumericActionDigestStaysAString(): void
    {
        $log = new ShadowLog(self::kp());
        $log->observe(self::ed(), '123', 'deny', ['digest' => self::sd(), 'decision' => 'allow', 'diverged' => true, 'widening' => true], 1000);
        $r = Shadow::promotionGate($log, ['shadow_digest' => self::sd(), 'enforced_digest' => self::ed(), 'minSamples' => 1, 'principals' => [], 'surface' => 'equal']);
        $this->assertSame(['123'], $r['unexplained']);
    }

    /** Counters start at zero for every field. */
    public function testLogCountersStartAtZero(): void
    {
        $log = new ShadowLog(self::kp());
        $log->observe('e', 'a', 'allow', ['digest' => 'c1', 'decision' => 'deny', 'diverged' => true, 'widening' => false], 1);
        $this->assertSame(['total' => 1, 'diverged' => 1, 'widened' => 0, 'tightened' => 1, 'errors' => 0], $log->stats('c1'));
        $log->observe('e', 'a', 'allow', ['digest' => 'c2', 'decision' => 'error', 'diverged' => false, 'widening' => false], 1);
        $this->assertSame(['total' => 1, 'diverged' => 0, 'widened' => 0, 'tightened' => 0, 'errors' => 1], $log->stats('c2'));
    }

    /** Promotion needs a passing gate (its code in the message) and bumps the enforced revision as an int. */
    public function testPromote(): void
    {
        $cand = Obj::of(['rules' => 'x', 'revision' => 9]);
        $enf = Obj::of(['rules' => 'y', 'revision' => 1, 'shadow' => [K3::bundleDigest($cand)]]);
        foreach ([[[], 'undefined'], [['ok' => false, 'code' => 'too_few_samples'], 'too_few_samples']] as [$gate, $code]) {
            try {
                Shadow::promoteShadow($enf, $cand, $gate, 5000);
                $this->fail('promoted without a gate');
            } catch (\InvalidArgumentException $e) {
                $this->assertSame("promoteShadow: the gate did not pass ($code)", $e->getMessage());
            }
        }
        $this->assertSame(2, Shadow::promoteShadow($enf, $cand, ['ok' => true], 5000)->get('revision'));
    }
}
