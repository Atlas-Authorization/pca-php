<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Optimistic;
use PHPUnit\Framework\TestCase;

/** Mutation kills for Optimistic: number/bool equality, the window policy, type gates and the slash split. */
final class K05KillOptimisticTest extends TestCase
{
    private static function row(string $table, string $name): Obj
    {
        foreach (Vectors::load('optimistic-vectors.json')->get($table) as $r) {
            if ($r->get('name') === $name) {
                return $r;
            }
        }
        throw new \RuntimeException("no $table/$name");
    }

    private static function with(Obj $o, array $set): Obj
    {
        $c = $o->without();
        foreach ($set as $k => $v) {
            $c->set($k, $v);
        }
        return $c;
    }

    /** An object that answers like an Obj but is not one: every `instanceof Obj` gate must refuse it. */
    private static function wrap(Obj $o): object
    {
        return new class($o) {
            public function __construct(private Obj $o)
            {
            }

            public function has(string $k): bool
            {
                return $this->o->has($k);
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function without(string ...$d): Obj
            {
                return $this->o->without(...$d);
            }

            public function keys(): array
            {
                return $this->o->keys();
            }
        };
    }

    private static function claim(mixed $claim, mixed $digest, mixed $now = null, mixed $policy = null): string
    {
        $r = self::row('optimistic_claim', 'ok-basic');
        return Optimistic::claimCheck($claim, $digest, $r->get('signer_public'), $now ?? $r->get('server_now'), $policy);
    }

    public function testAMissingSignerKeyIsASignatureRefusal(): void
    {
        $r = self::row('optimistic_claim', 'ok-basic');
        $chk = static fn (mixed $pk): string => Optimistic::claimCheck($r->get('claim'), $r->get('pcactn_digest'), $pk, $r->get('server_now'));
        $this->assertSame('ok', $chk($r->get('signer_public')), 'control');
        // a string sig with no signer key is a signature refusal, not a malformed claim
        $this->assertSame('signature', $chk(null));
    }

    public function testNativeNumbersAndBoolsCompareByValue(): void
    {
        // the digest check passes, so the next refusal (no claimed_r) is reached
        $this->assertSame('claimed_r', self::claim(Obj::of(['pcactn_digest' => 5]), 5));
        $this->assertSame('claimed_r', self::claim(Obj::of(['pcactn_digest' => 5]), new Num('5')));
        $this->assertSame('digest', self::claim(Obj::of(['pcactn_digest' => 5]), 6));
        $this->assertSame('claimed_r', self::claim(Obj::of(['pcactn_digest' => true]), true));
        $this->assertSame('claimed_r', self::claim(Obj::of(['pcactn_digest' => false]), false));
        $this->assertSame('digest', self::claim(Obj::of(['pcactn_digest' => true]), false));
        $this->assertSame('digest', self::claim(Obj::of(['pcactn_digest' => false]), true));
        $this->assertSame('digest', self::claim(Obj::of(['pcactn_digest' => true]), 'true'));
    }

    public function testTheWindowPolicyIsReadAndValidated(): void
    {
        $r = self::row('optimistic_claim', 'ok-basic');
        $claim = $r->get('claim');
        $digest = $r->get('pcactn_digest');
        $this->assertSame('ok', self::claim($claim, $digest));
        $this->assertSame('ok', self::claim($claim, $digest, null, Optimistic::DEFAULT_WINDOW_POLICY)); // a PHP array policy
        $bad = Optimistic::DEFAULT_WINDOW_POLICY;
        $bad['minWindowMs'] = 'x';
        $this->assertSame('malformed', self::claim($claim, $digest, null, $bad));
        $this->assertSame('malformed', self::claim($claim, $digest, null, ['minWindowMs' => 1000]));
        $this->assertSame('malformed', self::claim($claim, $digest, null, Obj::of(['minWindowMs' => new Num('1000')])));
        // a policy whose minimum exceeds the claim's 60 s window
        $this->assertSame('window', self::claim($claim, $digest, null, ['minWindowMs' => 60001, 'maxWindowMs' => 86_400_000, 'defaultWindowMs' => 300_000, 'maxSkewMs' => 5000]));
        $this->assertSame('ok', self::claim($claim, $digest, null, Obj::of(['minWindowMs' => new Num('60000'), 'maxWindowMs' => new Num('60000'), 'defaultWindowMs' => new Num('60000'), 'maxSkewMs' => new Num('0')])));
    }

    public function testAnUnreadableIssuedAtIsAWindowRefusal(): void
    {
        $r = self::row('optimistic_claim', 'ok-basic');
        // server time 0: an issued_at read as 0 would sit inside the skew and fall through to the signature
        $this->assertSame('window', self::claim(self::with($r->get('claim'), ['issued_at' => 'x']), $r->get('pcactn_digest'), new Num('0')));
        $this->assertSame('window', self::claim(self::with($r->get('claim'), ['challenge_window_ms' => 'x']), $r->get('pcactn_digest')));
    }

    public function testObjectLookalikesAreMalformed(): void
    {
        $c = self::row('optimistic_claim', 'ok-basic');
        $this->assertSame('malformed', self::claim(self::wrap($c->get('claim')), $c->get('pcactn_digest')));

        $f = self::row('optimistic_fraud_proof', 'ok-policy-denied');
        $claim = $f->get('claim');
        $proof = $f->get('proof');
        $this->assertSame('ok', Optimistic::fraudProofWireCheck($claim, $proof));
        $this->assertSame('malformed', Optimistic::fraudProofWireCheck(self::wrap($claim), $proof));
        $this->assertSame('malformed', Optimistic::fraudProofWireCheck($claim, self::wrap($proof)));
        $this->assertSame('malformed', Optimistic::fraudProofWireCheck($claim, self::with($proof, ['decision' => self::wrap($proof->get('decision'))])));

        $s = self::row('optimistic_settlement', 'ok-open');
        $this->assertSame('ok', Optimistic::settlementWireCheck($s->get('record'), $s->get('guardian_public')));
        $this->assertSame('malformed', Optimistic::settlementWireCheck(self::wrap($s->get('record')), $s->get('guardian_public')));
    }

    public function testRiskUnderstatedNeedsAStrictlyHigherRisk(): void
    {
        $claim = Obj::of(['pcactn_digest' => 'd', 'bond_ref' => 'b', 'claimed_r' => new Num('0.5')]);
        $proof = fn(string $r) => Obj::of([
            'pcactn_digest' => 'd', 'bond_ref' => 'b', 'reason' => 'x', 'claimed_r' => new Num('0.5'), 'kind' => 'risk-understated',
            'r_margin' => new Num('0'),
            'decision' => Obj::of(['releaseGuardianShare' => true, 'optimisticAllowed' => true, 'r' => new Num($r)]),
        ]);
        $this->assertSame('consistency', Optimistic::fraudProofWireCheck($claim, $proof('0.5')));
        $this->assertSame('ok', Optimistic::fraudProofWireCheck($claim, $proof('0.6')));
    }

    public function testGuardianEpochUpToTheLargestSafeInteger(): void
    {
        $s = self::row('optimistic_settlement', 'ok-open');
        $rec = $s->get('record');
        $g = $s->get('guardian_public');
        // a well-shaped epoch reaches the signature (which no longer covers the edited body)
        $this->assertSame('signature', Optimistic::settlementWireCheck(self::with($rec, ['guardian_epoch' => new Num('9007199254740991')]), $g));
        $this->assertSame('shape', Optimistic::settlementWireCheck(self::with($rec, ['guardian_epoch' => new Num('9007199254740992')]), $g));
        $this->assertSame('shape', Optimistic::settlementWireCheck(self::with($rec, ['guardian_epoch' => new Num('1.5')]), $g));
    }

    public function testANullChallengerAccountNeedsAZeroRewardAndCompensation(): void
    {
        $split = fn(string $c, string $v) => Obj::of([
            'amount' => new Num('100'), 'challengerReward' => new Num($c), 'victimCompensation' => new Num($v),
            'treasuryRemainder' => new Num('100'), 'victimAccount' => 'victim', 'treasuryAccount' => 'treasury', 'challengerAccount' => null,
        ]);
        $rec = fn(Obj $sp) => Obj::of([
            'claimId' => 'c', 'action' => 'slash', 'amount' => new Num('100'), 'from' => 'escrow', 'to' => 'treasury',
            'at' => new Num('1800000000000'), 'evidenceDigest' => 'e', 'split' => $sp, 'sig' => 'AAAA',
        ]);
        // 1e-300 vanishes in the float sum (so the split adds up), yet it is not zero
        $this->assertSame('split', Optimistic::settlementWireCheck($rec($split('0', '1e-300')), 'g'));
        $this->assertSame('split', Optimistic::settlementWireCheck($rec($split('1e-300', '0')), 'g'));
        $this->assertSame('signature', Optimistic::settlementWireCheck($rec($split('0', '0')), 'g'));
    }
}
